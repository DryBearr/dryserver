//! Where this computer keeps your swarm, the same from any folder you run
//! dryserver in:
//!
//! - `~/.config/dryserver/`: config.env and secrets/, the files to keep
//!   and back up. Only you can open it.
//! - `~/.cache/dryserver/`: dryserver.iso, build.log and the package
//!   cache. All of it can be made again.
//!
//! XDG_CONFIG_HOME and XDG_CACHE_HOME move them as usual. DRYSERVER_HOME
//! puts all of it in one folder instead (config.env, secrets/ and out/),
//! for a second swarm or the test scripts. Under sudo they are the folders
//! of the user who ran sudo, never root's.
//!
//! Older versions kept these files in the folder dryserver ran from.
//! Such a folder is found (the working directory, or the one this program
//! is in) and copied here once by `dryserver init --from DIR`; until then
//! nothing starts a new swarm next to it.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::err::{Error, Result};
use crate::{admin, errf, fsx, iso};

/// Puts the config, the keys and the image in this one folder.
pub const ENV: &str = "DRYSERVER_HOME";
pub const CONFIG: &str = "config.env";
pub const SECRETS: &str = "secrets";

/// The desktop's folders.
#[derive(Debug, Clone, PartialEq)]
pub struct Layout {
    /// The folder of config.env and secrets/.
    pub home: PathBuf,
    pub config: PathBuf,
    pub secrets: PathBuf,
    /// The installer image, its build log and the package cache.
    pub out_dir: PathBuf,
}

/// What the folders are worked out from.
#[derive(Debug, Clone, Default)]
pub struct Env {
    pub dryserver_home: Option<OsString>,
    pub home: Option<OsString>,
    pub xdg_config: Option<OsString>,
    pub xdg_cache: Option<OsString>,
    /// Under sudo: the user who ran it, and that user's home folder when
    /// the system knows it.
    pub sudo: Option<(u32, Option<PathBuf>)>,
}

impl Env {
    pub fn current() -> Env {
        let var = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty());
        let sudo = if fsx::is_root() {
            std::env::var("SUDO_UID").ok().and_then(|v| v.parse::<u32>().ok()).filter(|u| *u != 0).map(|u| (u, home_of(u)))
        } else {
            None
        };
        Env { dryserver_home: var(ENV), home: var("HOME"), xdg_config: var("XDG_CONFIG_HOME"), xdg_cache: var("XDG_CACHE_HOME"), sudo }
    }
}

/// The home folder of uid, from the system's user database.
fn home_of(uid: u32) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: a plain C struct that getpwuid_r fills in.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: buf outlives the call and every pointer it fills in, which
    // are only read below while buf is alive.
    let r = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut out) };
    if r != 0 || out.is_null() || pw.pw_dir.is_null() {
        return None;
    }
    // SAFETY: pw_dir points into buf, a NUL-terminated string.
    let dir = unsafe { std::ffi::CStr::from_ptr(pw.pw_dir) };
    let p = PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes()));
    p.is_absolute().then_some(p)
}

pub fn layout(env: &Env) -> Result<Layout> {
    if let Some(h) = &env.dryserver_home {
        let h = PathBuf::from(h);
        if !h.is_absolute() {
            return Err(errf!("{ENV} must be an absolute path, not {}", h.display()));
        }
        return Ok(Layout { config: h.join(CONFIG), secrets: h.join(SECRETS), out_dir: h.join("out"), home: h });
    }
    let base = match &env.sudo {
        Some((_, Some(h))) => h.clone(),
        Some((uid, None)) => {
            return Err(errf!(
                "cannot find the home folder of user {uid}, who ran sudo. Set {ENV} to the folder that holds your swarm \
                 (dryserver where shows it, without sudo)"
            ));
        }
        None => match env.home.as_ref().map(PathBuf::from) {
            Some(h) if h.is_absolute() => h,
            _ => return Err(errf!("$HOME is not set to a folder. Set {ENV} to the folder that holds your swarm")),
        },
    };
    // Relative XDG paths are to be ignored. Under sudo only the user's own
    // count: root's would put the swarm where the user cannot open it.
    let xdg = |v: &Option<OsString>, default: &str| {
        v.as_ref()
            .map(PathBuf::from)
            .filter(|p| p.is_absolute() && (env.sudo.is_none() || p.starts_with(&base)))
            .unwrap_or_else(|| base.join(default))
    };
    let home = xdg(&env.xdg_config, ".config").join("dryserver");
    let out_dir = xdg(&env.xdg_cache, ".cache").join("dryserver");
    Ok(Layout { config: home.join(CONFIG), secrets: home.join(SECRETS), out_dir, home })
}

/// Files in secrets/ that only dryserver makes.
const MARKS: [&str; 6] =
    [iso::KEY_NAME, iso::SIGNING_KEY_NAME, iso::JOIN_SECRET, iso::BACKUP_KEY_NAME, admin::SIGNED_COPY, admin::KNOWN_HOSTS];

/// Whether dir holds a swarm the way older versions kept it: a config.env
/// dryserver wrote, or a secrets/ with dryserver's keys in it. A folder
/// with some other secrets/ or config.env does not count.
pub fn holds_swarm(dir: &Path) -> bool {
    let secrets = dir.join(SECRETS);
    MARKS.iter().any(|m| fs::symlink_metadata(secrets.join(m)).is_ok())
        || fsx::read_or_empty(dir.join(CONFIG)).lines().any(|l| l.trim_start().starts_with("COORD_LAN_IP="))
}

/// Whether the home holds a swarm already: anything at config.env, or a
/// secrets/ with anything in it.
pub fn in_use(l: &Layout) -> bool {
    fs::symlink_metadata(&l.config).is_ok() || fs::read_dir(&l.secrets).is_ok_and(|mut d| d.next().is_some())
}

/// The folders older versions may have left a swarm in: the working
/// directory and the one this program is in.
pub fn candidates() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = Vec::new();
    let exe_dir = std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf));
    for d in [std::env::current_dir().ok(), exe_dir].into_iter().flatten() {
        if !v.contains(&d) {
            v.push(d);
        }
    }
    v
}

/// The first of candidates that holds a swarm and is not the home.
pub fn stray(l: &Layout, candidates: &[PathBuf]) -> Option<PathBuf> {
    let home = fs::canonicalize(&l.home).ok();
    candidates.iter().find(|c| fs::canonicalize(c).is_ok_and(|c| Some(c) != home) && holds_swarm(c)).cloned()
}

/// A folder with a swarm the old way, beside the home, and how it stands
/// to the home.
#[derive(Debug, Clone, PartialEq)]
pub enum Stray {
    /// Nothing is in the home yet: the swarm there is to be brought over
    /// (init --from), and nothing may start a new one meanwhile.
    Waiting(PathBuf),
    /// An old copy of the swarm in the home: its keys are the ones there.
    Old(PathBuf),
    /// Another swarm: its keys differ from the home's. Which one a command
    /// is for cannot be guessed.
    Other(PathBuf),
}

/// The stray folder among candidates (see stray), and how it stands.
pub fn look(l: &Layout, candidates: &[PathBuf]) -> Option<Stray> {
    let d = stray(l, candidates)?;
    Some(if !in_use(l) {
        Stray::Waiting(d)
    } else if same_keys(&d, l) {
        Stray::Old(d)
    } else {
        Stray::Other(d)
    })
}

/// Whether every key in d's secrets/ is in the home's, byte for byte: the
/// keys are what a swarm is. One that cannot be read counts as different.
fn same_keys(d: &Path, l: &Layout) -> bool {
    [iso::KEY_NAME, iso::SIGNING_KEY_NAME, iso::JOIN_SECRET, iso::BACKUP_KEY_NAME].iter().all(|n| match fs::read(d.join(SECRETS).join(n)) {
        Err(e) => e.kind() == io::ErrorKind::NotFound,
        Ok(a) => fs::read(l.secrets.join(n)).is_ok_and(|b| a == b),
    })
}

/// Makes the home and the image folder where they are missing, for this
/// user alone (0700): under sudo they are handed to the user who ran it.
/// A home others can look into is closed.
pub fn prepare(l: &Layout) -> Result<()> {
    for d in [&l.home, &l.out_dir] {
        let made = mkdirs(d)?;
        crate::owner::fix(&made);
    }
    if let Ok(m) = fs::metadata(&l.home)
        && m.permissions().mode() & 0o077 != 0
        && (m.uid() == fsx::geteuid() || fsx::is_root())
    {
        // A home on a stick that keeps no modes refuses; that is the
        // stick's way, not a reason to stop.
        let _ = fsx::chmod(&l.home, 0o700);
    }
    Ok(())
}

/// Makes dir and its missing parents with mode 0700, and returns the ones
/// it made, top first.
fn mkdirs(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut missing = Vec::new();
    let mut d = Some(dir);
    while let Some(p) = d {
        if p.as_os_str().is_empty() || fs::symlink_metadata(p).is_ok() {
            break;
        }
        missing.push(p.to_path_buf());
        d = p.parent();
    }
    missing.reverse();
    for p in &missing {
        match fs::DirBuilder::new().mode(0o700).create(p) {
            Err(e) if e.kind() != io::ErrorKind::AlreadyExists => {
                return Err(Error::from(e).wrap(format!("mkdir {}", p.display())));
            }
            _ => {}
        }
    }
    if !dir.is_dir() {
        return Err(errf!("{} is not a folder", dir.display()));
    }
    Ok(missing)
}

/// What init copied.
#[derive(Debug, Default, PartialEq)]
pub struct Brought {
    /// Copied now.
    pub copied: Vec<PathBuf>,
    /// Already here with everything the old folder has in it (init ran
    /// before, maybe stopped half way; the build may have added keys).
    pub same: Vec<PathBuf>,
}

/// Copies the swarm in the old folder from (its config.env and secrets/)
/// into the home, each whole or not at all: it is put together beside its
/// place and renamed into it. Nothing is copied when the home holds files
/// of those names that differ; ones that hold all the old folder has are
/// left as they are, so init can run again, also after it was stopped.
/// The old folder is never changed.
pub fn bring(from: &Path, l: &Layout) -> Result<Brought> {
    let from = std::path::absolute(from)?;
    if !from.is_dir() {
        return Err(errf!("{} is not a folder", from.display()));
    }
    if !holds_swarm(&from) {
        return Err(errf!("{} holds no swarm: no config.env written by dryserver and no secrets/ with its keys", from.display()));
    }
    if fs::canonicalize(&from).ok() == fs::canonicalize(&l.home).ok() {
        return Err(errf!("{} is already where dryserver keeps your swarm", from.display()));
    }
    prepare(l)?;
    let _lock = lock_dir(&l.home)?;
    let items = [(from.join(CONFIG), l.config.clone()), (from.join(SECRETS), l.secrets.clone())];
    let mut todo = Vec::new();
    let mut done = Brought::default();
    let mut differ = Vec::new();
    for (src, dst) in items {
        match fs::symlink_metadata(&src) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(Error::from(e).wrap(format!("open {}", src.display()))),
            Ok(_) => {}
        }
        if fs::symlink_metadata(&dst).is_err() {
            todo.push((src, dst));
        } else if holds_all(&src, &dst)? {
            done.same.push(dst);
        } else {
            differ.push(dst.display().to_string());
        }
    }
    if !differ.is_empty() {
        return Err(errf!(
            "{} already there, with other contents than in {}: nothing was copied. If your swarm is the one already \
             there (dryserver where), the files in {} are an older copy. If {} is the swarm you mean, move {} away first \
             and keep {} until you are sure",
            differ.join(" and "),
            from.display(),
            from.display(),
            from.display(),
            if differ.len() == 1 { "that" } else { "those" },
            if differ.len() == 1 { "it" } else { "them" }
        ));
    }
    for (src, dst) in todo {
        let name = dst.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let stage = l.home.join(format!(".{name}.init"));
        remove_any(&stage)?;
        let res = copy_tree(&src, &stage).and_then(|_| fsx::rename(&stage, &dst));
        if let Err(e) = res {
            let _ = remove_any(&stage);
            return Err(e.wrap(format!("copy {}", src.display())));
        }
        done.copied.push(dst);
    }
    sync_dir(&l.home);
    Ok(done)
}

/// One init at a time: a lock on the home folder itself, so no lock file
/// is left in it.
fn lock_dir(d: &Path) -> Result<fs::File> {
    let f = fs::File::open(d).map_err(|e| Error::from(e).wrap(format!("open {}", d.display())))?;
    // SAFETY: flock on a valid open descriptor owned by f.
    if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&f), libc::LOCK_EX) } != 0 {
        return Err(Error::from(io::Error::last_os_error()).wrap(format!("lock {}", d.display())));
    }
    Ok(f)
}

/// Copies a file or a folder tree: folders 0700, files 0600, every file
/// on disk before it counts. Links and anything but plain files and
/// folders are refused: a swarm has none, and a link could point anywhere.
fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    let m = fs::symlink_metadata(src).map_err(|e| Error::from(e).wrap(format!("open {}", src.display())))?;
    let t = m.file_type();
    if t.is_dir() {
        fs::DirBuilder::new().mode(0o700).create(dst).map_err(|e| Error::from(e).wrap(format!("mkdir {}", dst.display())))?;
        let mut names: Vec<_> = fs::read_dir(src)
            .map_err(|e| Error::from(e).wrap(format!("open {}", src.display())))?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<io::Result<_>>()?;
        names.sort();
        for n in names {
            copy_tree(&src.join(&n), &dst.join(&n))?;
        }
        sync_dir(dst);
        Ok(())
    } else if t.is_file() {
        // In pieces: backups can be larger than memory.
        use std::os::unix::fs::OpenOptionsExt;
        let mut from = fs::File::open(src).map_err(|e| Error::from(e).wrap(format!("open {}", src.display())))?;
        let mut to = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(dst)
            .map_err(|e| Error::from(e).wrap(format!("create {}", dst.display())))?;
        to.set_permissions(fs::Permissions::from_mode(0o600)).map_err(|e| Error::from(e).wrap(format!("chmod {}", dst.display())))?;
        io::copy(&mut from, &mut to).map_err(|e| Error::from(e).wrap(format!("copy {}", src.display())))?;
        to.sync_all().map_err(|e| Error::from(e).wrap(format!("sync {}", dst.display())))
    } else {
        Err(errf!("{} is a link or a special file, not copied: copy what it points to there instead", src.display()))
    }
}

/// Whether b holds everything a does: the same bytes, or a folder with
/// each name in a that holds all it does (b may have more). Modes do not
/// count.
fn holds_all(a: &Path, b: &Path) -> Result<bool> {
    tree_eq(a, b, true)
}

/// Whether a and b hold the same: the same bytes, or folders with the same
/// names in them that hold the same. Modes do not count.
#[cfg(test)]
fn same_tree(a: &Path, b: &Path) -> Result<bool> {
    tree_eq(a, b, false)
}

fn tree_eq(a: &Path, b: &Path, more: bool) -> Result<bool> {
    let (ma, mb) = match (fs::symlink_metadata(a), fs::symlink_metadata(b)) {
        (Ok(x), Ok(y)) => (x, y),
        _ => return Ok(false),
    };
    if ma.is_file() && mb.is_file() {
        return Ok(ma.len() == mb.len() && same_bytes(a, b)?);
    }
    if !(ma.is_dir() && mb.is_dir()) {
        return Ok(false);
    }
    let names = |d: &Path| -> Result<Vec<OsString>> {
        let mut v: Vec<OsString> = fs::read_dir(d)
            .map_err(|e| Error::from(e).wrap(format!("open {}", d.display())))?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<io::Result<_>>()?;
        v.sort();
        Ok(v)
    };
    let (na, nb) = (names(a)?, names(b)?);
    if if more { !na.iter().all(|n| nb.contains(n)) } else { na != nb } {
        return Ok(false);
    }
    for n in &na {
        if !tree_eq(&a.join(n), &b.join(n), more)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether two files of the same length hold the same bytes, read in
/// pieces.
fn same_bytes(a: &Path, b: &Path) -> Result<bool> {
    use std::io::Read;
    let open = |p: &Path| fs::File::open(p).map_err(|e| Error::from(e).wrap(format!("open {}", p.display())));
    let (mut fa, mut fb) = (io::BufReader::new(open(a)?), io::BufReader::new(open(b)?));
    let (mut ba, mut bb) = (vec![0u8; 64 * 1024], vec![0u8; 64 * 1024]);
    loop {
        let n = fa.read(&mut ba)?;
        if n == 0 {
            // Same length, so b is at its end too.
            return Ok(true);
        }
        fb.read_exact(&mut bb[..n])?;
        if ba[..n] != bb[..n] {
            return Ok(false);
        }
    }
}

/// Removes a file or a whole folder, never following a link; nothing
/// there is fine.
fn remove_any(p: &Path) -> Result<()> {
    let res = match fs::symlink_metadata(p) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => Err(e),
        Ok(m) if m.is_dir() => fs::remove_dir_all(p),
        Ok(_) => fs::remove_file(p),
    };
    res.map_err(|e| Error::from(e).wrap(format!("remove {}", p.display())))
}

/// Puts a folder's list of names on disk, so a rename into it outlives a
/// power cut.
fn sync_dir(d: &Path) {
    if let Ok(f) = fs::File::open(d) {
        let _ = f.sync_all();
    }
}

/// The lines `dryserver where` prints.
pub fn describe(l: &Layout, stray: Option<&Stray>, out: &mut dyn Write) -> io::Result<()> {
    writeln!(out, "config  {}", l.config.display())?;
    writeln!(out, "keys    {}  (back this folder up)", l.secrets.display())?;
    writeln!(out, "images  {}  (made again by a build)", l.out_dir.display())?;
    match stray {
        Some(Stray::Old(d)) => {
            writeln!(out, "\nNot used: the old copy in {} (config.env, secrets/). Delete it once dryserver works from here.", d.display())
        }
        Some(Stray::Waiting(d)) => {
            writeln!(out, "\nYour swarm is still in {}. Bring it here once:\n  dryserver init --from {}", d.display(), d.display())
        }
        Some(Stray::Other(d)) => writeln!(out, "\n{}", other_swarm(l, d)),
        None => Ok(()),
    }
}

/// Why nothing runs beside another swarm, and the two ways on.
pub fn other_swarm(l: &Layout, d: &Path) -> String {
    format!(
        "{d} holds another swarm than {home} (its keys differ), and dryserver does not guess which one you mean.\n  \
         for the one in {home}: run dryserver from another folder\n  for the one in {d}: {ENV}={d} dryserver ...",
        d = d.display(),
        home = l.home.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, put};

    fn env(home: &str) -> Env {
        Env { home: Some(home.into()), ..Env::default() }
    }

    #[test]
    fn folders_from_home_xdg_and_the_override() {
        let l = layout(&env("/home/a")).unwrap();
        assert_eq!(l.home, PathBuf::from("/home/a/.config/dryserver"));
        assert_eq!(l.config, PathBuf::from("/home/a/.config/dryserver/config.env"));
        assert_eq!(l.secrets, PathBuf::from("/home/a/.config/dryserver/secrets"));
        assert_eq!(l.out_dir, PathBuf::from("/home/a/.cache/dryserver"));

        let e = Env { xdg_config: Some("/x/conf".into()), xdg_cache: Some("/x/cache".into()), ..env("/home/a") };
        let l = layout(&e).unwrap();
        assert_eq!((l.home, l.out_dir), ("/x/conf/dryserver".into(), "/x/cache/dryserver".into()));

        // Relative XDG paths are ignored, as the spec says.
        let e = Env { xdg_config: Some("conf".into()), xdg_cache: Some("./c".into()), ..env("/home/a") };
        assert_eq!(layout(&e).unwrap(), layout(&env("/home/a")).unwrap());

        // DRYSERVER_HOME: everything in one folder, also without $HOME.
        let e = Env { dryserver_home: Some("/media/stick/swarm".into()), ..Env::default() };
        let l = layout(&e).unwrap();
        assert_eq!(l.config, PathBuf::from("/media/stick/swarm/config.env"));
        assert_eq!(l.secrets, PathBuf::from("/media/stick/swarm/secrets"));
        assert_eq!(l.out_dir, PathBuf::from("/media/stick/swarm/out"));
        let e = Env { dryserver_home: Some("swarm".into()), ..env("/home/a") };
        assert!(layout(&e).unwrap_err().to_string().contains("must be an absolute path"));
    }

    #[test]
    fn no_home_is_an_error_that_names_the_way_out() {
        for e in [Env::default(), env("relative/home")] {
            let err = layout(&e).unwrap_err().to_string();
            assert!(err.contains("$HOME") && err.contains(ENV), "{err}");
        }
    }

    #[test]
    fn under_sudo_the_folders_are_the_users_not_roots() {
        // sudo sets HOME to /root: the user's own home counts.
        let e = Env { home: Some("/root".into()), sudo: Some((1000, Some("/var/home/u".into()))), ..Env::default() };
        let l = layout(&e).unwrap();
        assert_eq!((l.home, l.out_dir), ("/var/home/u/.config/dryserver".into(), "/var/home/u/.cache/dryserver".into()));
        // The user's XDG folder, kept by sudo, counts; root's does not.
        let e = Env { xdg_config: Some("/var/home/u/conf".into()), xdg_cache: Some("/root/.cache".into()), ..e };
        let l = layout(&e).unwrap();
        assert_eq!((l.home, l.out_dir), ("/var/home/u/conf/dryserver".into(), "/var/home/u/.cache/dryserver".into()));
        let e = Env { sudo: Some((1000, None)), ..env("/root") };
        let err = layout(&e).unwrap_err().to_string();
        assert!(err.contains("user 1000") && err.contains(ENV), "{err}");
    }

    #[test]
    fn the_running_users_home_is_found() {
        let me = fsx::geteuid();
        // Every user that runs the tests has an entry, home or not.
        if let Some(h) = home_of(me) {
            assert!(h.is_absolute());
        }
        assert_eq!(home_of(u32::MAX - 7), None);
    }

    fn at(dir: &Path) -> Layout {
        layout(&Env { dryserver_home: Some(dir.into()), ..Env::default() }).unwrap()
    }

    #[test]
    fn only_dryservers_own_files_count_as_a_swarm() {
        let t = TempDir::new();
        let d = t.path();
        assert!(!holds_swarm(d));
        // Another project's secrets/ and config.env are not a swarm.
        put(d, "secrets/api_key", "x");
        put(d, "config.env", "PORT=3000\n");
        assert!(!holds_swarm(d));
        put(d, "secrets/join_secret", "ab");
        assert!(holds_swarm(d));
        let t2 = TempDir::new();
        put(t2.path(), "config.env", "# dryserver config\nCOORD_LAN_IP='10.1.0.60'\n");
        assert!(holds_swarm(t2.path()));
        let t3 = TempDir::new();
        put(t3.path(), "secrets/coordinator_known_hosts", "x");
        assert!(holds_swarm(t3.path()));
    }

    #[test]
    fn a_stray_swarm_is_found_but_never_the_home_itself() {
        let t = TempDir::new();
        let old = t.join("repo");
        put(&old, "secrets/registry_ed25519", "k");
        let other = t.join("elsewhere");
        fs::create_dir_all(&other).unwrap();
        let l = at(&t.join("home"));
        assert_eq!(stray(&l, &[other.clone(), old.clone()]), Some(old.clone()));
        assert_eq!(stray(&l, std::slice::from_ref(&other)), None);
        // A missing folder is no candidate.
        assert_eq!(stray(&l, &[t.join("gone")]), None);
        // DRYSERVER_HOME set to the old folder itself: that is the home.
        assert_eq!(stray(&at(&old), std::slice::from_ref(&old)), None);
        // Also through another name for it.
        std::os::unix::fs::symlink(&old, t.join("link")).unwrap();
        assert_eq!(stray(&at(&t.join("link")), std::slice::from_ref(&old)), None);
    }

    #[test]
    fn a_stray_folder_is_waiting_an_old_copy_or_another_swarm() {
        let t = TempDir::new();
        let old = t.join("repo");
        put(&old, "config.env", "COORD_LAN_IP='10.1.0.60'\n");
        put(&old, "secrets/registry_ed25519", "reg");
        let l = at(&t.join("home"));
        let c = [old.clone()];
        assert_eq!(look(&l, &c), Some(Stray::Waiting(old.clone())));
        // Brought over: an old copy, also once the home has more keys and
        // its own config.
        bring(&old, &l).unwrap();
        put(&l.secrets, "signing_ed25519", "made here");
        put(&l.home, "config.env", "COORD_LAN_IP='10.1.0.61'\n");
        assert_eq!(look(&l, &c), Some(Stray::Old(old.clone())));
        // A folder with other keys is another swarm (the VM lab).
        let lab = t.join("lab");
        put(&lab, "secrets/registry_ed25519", "lab key");
        assert_eq!(look(&l, std::slice::from_ref(&lab)), Some(Stray::Other(lab.clone())));
        // A key the home lacks makes it another swarm too.
        let lab2 = t.join("lab2");
        put(&lab2, "secrets/registry_ed25519", "reg");
        put(&lab2, "secrets/join_secret", "j");
        assert_eq!(look(&l, std::slice::from_ref(&lab2)), Some(Stray::Other(lab2.clone())));
        // Only a config (no keys): nothing to differ, an old copy.
        let cfg_only = t.join("cfg");
        put(&cfg_only, "config.env", "COORD_LAN_IP='10.1.0.60'\n");
        assert_eq!(look(&l, std::slice::from_ref(&cfg_only)), Some(Stray::Old(cfg_only)));
        assert_eq!(look(&l, &[t.join("nothing")]), None);
    }

    #[test]
    fn in_use_means_a_config_or_secrets_with_something_in_it() {
        let t = TempDir::new();
        let l = at(t.path());
        assert!(!in_use(&l));
        fs::create_dir_all(&l.secrets).unwrap();
        assert!(!in_use(&l), "an empty secrets/ holds nothing");
        put(&l.secrets, "x", "1");
        assert!(in_use(&l));
        fs::remove_file(l.secrets.join("x")).unwrap();
        put(t.path(), "config.env", "");
        assert!(in_use(&l));
    }

    fn mode(p: &Path) -> u32 {
        fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn prepare_makes_the_folders_private_and_closes_an_open_home() {
        let t = TempDir::new();
        let e = Env { xdg_config: Some(t.join("c").into()), xdg_cache: Some(t.join("k/deep").into()), ..env("/nonexistent") };
        let l = layout(&e).unwrap();
        prepare(&l).unwrap();
        for d in [t.join("c"), l.home.clone(), t.join("k"), t.join("k/deep"), l.out_dir.clone()] {
            assert!(d.is_dir(), "{}", d.display());
            assert_eq!(mode(&d), 0o700, "{}", d.display());
        }
        fsx::chmod(&l.home, 0o755).unwrap();
        prepare(&l).unwrap();
        assert_eq!(mode(&l.home), 0o700);
        // A file where the home should be is an error, not replaced.
        let t2 = TempDir::new();
        put(t2.path(), "file", "x");
        let l = at(&t2.join("file"));
        assert!(prepare(&l).unwrap_err().to_string().contains("not a folder"));
    }

    fn old_swarm(dir: &Path) {
        put(dir, "config.env", "COORD_LAN_IP='10.1.0.60'\nWIFI_PSK='pw'\n");
        put(dir, "secrets/registry_ed25519", "private");
        put(dir, "secrets/registry_ed25519.pub", "public");
        put(dir, "secrets/backups/2026-11-01.tar.age", "backup");
    }

    #[test]
    fn bring_copies_config_and_secrets_privately_and_leaves_the_old_folder() {
        let t = TempDir::new();
        let old = t.join("repo");
        old_swarm(&old);
        fsx::chmod(old.join("secrets/registry_ed25519.pub"), 0o644).unwrap();
        let l = at(&t.join("home"));
        let b = bring(&old, &l).unwrap();
        assert_eq!(b.copied, vec![l.config.clone(), l.secrets.clone()]);
        assert!(b.same.is_empty());
        assert!(same_tree(&old.join("secrets"), &l.secrets).unwrap());
        // A file larger than a piece, and one byte off at the end.
        let big = t.join("big");
        let mut data = vec![7u8; 200 * 1024 + 3];
        put(&big, "a", &data);
        copy_tree(&big.join("a"), &big.join("b")).unwrap();
        assert!(same_bytes(&big.join("a"), &big.join("b")).unwrap());
        *data.last_mut().unwrap() = 8;
        put(&big, "c", &data);
        assert!(!same_bytes(&big.join("a"), &big.join("c")).unwrap());
        assert_eq!(fs::read_to_string(&l.config).unwrap(), fs::read_to_string(old.join("config.env")).unwrap());
        for p in [l.config.clone(), l.secrets.join("registry_ed25519"), l.secrets.join("registry_ed25519.pub")] {
            assert_eq!(mode(&p), 0o600, "{}", p.display());
        }
        assert_eq!(mode(&l.secrets), 0o700);
        assert_eq!(mode(&l.secrets.join("backups")), 0o700);
        // The old folder is as it was, and no staging is left.
        assert!(old.join("secrets/registry_ed25519").exists() && old.join("config.env").exists());
        let left: Vec<_> = fs::read_dir(&l.home).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert!(left.iter().all(|n| !n.to_string_lossy().ends_with(".init")), "{left:?}");
        // Again: all the same, nothing copied, nothing changed.
        let b = bring(&old, &l).unwrap();
        assert_eq!((b.copied.len(), b.same.len()), (0, 2));
        // Also once the keys were made here (init, a build): the home has
        // all the old folder has, and more.
        put(&l.secrets, "signing_ed25519", "new here");
        let b = bring(&old, &l).unwrap();
        assert_eq!((b.copied.len(), b.same.len()), (0, 2));
        // But a key of the old folder that is different here is no copy
        // of it.
        put(&l.secrets, "registry_ed25519", "changed");
        let err = bring(&old, &l).unwrap_err().to_string();
        assert!(err.contains("other contents") && err.contains("older copy"), "{err}");
    }

    #[test]
    fn bring_finishes_a_copy_that_was_stopped_half_way() {
        let t = TempDir::new();
        let old = t.join("repo");
        old_swarm(&old);
        let l = at(&t.join("home"));
        fs::create_dir_all(&l.home).unwrap();
        // secrets/ made it, config.env did not; a staging copy was left.
        copy_tree(&old.join("secrets"), &l.secrets).unwrap();
        put(&l.home, ".config.env.init", "half");
        let b = bring(&old, &l).unwrap();
        assert_eq!((b.copied, b.same), (vec![l.config.clone()], vec![l.secrets.clone()]));
        assert_eq!(fs::read_to_string(&l.config).unwrap(), fs::read_to_string(old.join("config.env")).unwrap());
        assert!(!l.home.join(".config.env.init").exists());
    }

    #[test]
    fn bring_never_overwrites_another_swarm() {
        let t = TempDir::new();
        let old = t.join("repo");
        old_swarm(&old);
        let l = at(&t.join("home"));
        // A config made here meanwhile (Config in the app), other keys.
        put(&l.home, "config.env", "COORD_LAN_IP='10.9.9.9'\n");
        put(&l.secrets, "registry_ed25519", "other");
        let err = bring(&old, &l).unwrap_err().to_string();
        assert!(err.contains("nothing was copied") && err.contains("config.env and") && err.contains("secrets"), "{err}");
        assert!(!holds_all(&old.join("secrets"), &l.secrets).unwrap());
        assert_eq!(fs::read_to_string(&l.config).unwrap(), "COORD_LAN_IP='10.9.9.9'\n");
        assert_eq!(fs::read_to_string(l.secrets.join("registry_ed25519")).unwrap(), "other");
        assert!(!l.secrets.join("registry_ed25519.pub").exists());
        // One of them differs: still nothing copied, the other one either.
        let t2 = TempDir::new();
        let l2 = at(&t2.join("home"));
        put(&l2.home, "config.env", "COORD_LAN_IP='10.9.9.9'\n");
        assert!(bring(&old, &l2).unwrap_err().to_string().contains("nothing was copied"));
        assert!(!l2.secrets.exists());
    }

    #[test]
    fn bring_refuses_what_is_no_swarm_the_home_itself_and_links() {
        let t = TempDir::new();
        let l = at(&t.join("home"));
        let empty = t.join("empty");
        fs::create_dir_all(&empty).unwrap();
        assert!(bring(&empty, &l).unwrap_err().to_string().contains("holds no swarm"));
        assert!(bring(&t.join("gone"), &l).unwrap_err().to_string().contains("not a folder"));
        old_swarm(&l.home);
        assert!(bring(&l.home, &l).unwrap_err().to_string().contains("already where"));

        let old = t.join("repo");
        old_swarm(&old);
        let target = t.join("target");
        put(&target, "x", "secret elsewhere");
        std::os::unix::fs::symlink(target.join("x"), old.join("secrets/link")).unwrap();
        let l2 = at(&t.join("home2"));
        let err = bring(&old, &l2).unwrap_err().to_string();
        assert!(err.contains("link") && err.contains("not copied"), "{err}");
        // Whole or nothing: no secrets/ and no staging left.
        assert!(!l2.secrets.exists() && !l2.home.join(".secrets.init").exists());
        // config.env comes first and made it: a second try after the link
        // is gone copies secrets/ too.
        fs::remove_file(old.join("secrets/link")).unwrap();
        let b = bring(&old, &l2).unwrap();
        assert_eq!(b.copied, vec![l2.secrets.clone()]);
    }

    #[test]
    fn bring_takes_a_folder_with_only_one_of_the_two() {
        let t = TempDir::new();
        let old = t.join("repo");
        put(&old, "secrets/signing_ed25519", "k");
        let l = at(&t.join("home"));
        let b = bring(&old, &l).unwrap();
        assert_eq!(b.copied, vec![l.secrets.clone()]);
        assert!(!l.config.exists());
    }

    #[test]
    fn describe_names_the_folders_and_the_stray_one() {
        let t = TempDir::new();
        let l = at(t.path());
        let mut out = Vec::new();
        describe(&l, None, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains(&l.config.display().to_string()) && s.contains("back this folder up"), "{s}");
        let said = |s: Stray| {
            let mut out = Vec::new();
            describe(&l, Some(&s), &mut out).unwrap();
            String::from_utf8(out).unwrap()
        };
        assert!(said(Stray::Waiting("/old".into())).contains("dryserver init --from /old"));
        assert!(said(Stray::Old("/old".into())).contains("Not used: the old copy in /old"));
        let o = said(Stray::Other("/lab".into()));
        assert!(o.contains("/lab holds another swarm") && o.contains("DRYSERVER_HOME=/lab dryserver"), "{o}");
    }
}
