//! Your swarm in one file, locked with a passphrase: for a second computer
//! or a stick in a drawer.
//!
//! `dryserver export` packs config.env and secrets/ (not the backups, which
//! are large and only copies) and, when it is a file in ~/.ssh, your SSH
//! key, the one that signs. `dryserver import FILE` puts it back: into an
//! empty home, or one that already holds the same swarm, never over
//! another (homedir::bring). The SSH key goes to ~/.ssh, never over a key
//! that is there and different.
//!
//! The lock is GnuPG's: AES-256, the passphrase stretched with SHA-512
//! many million times, and a check that refuses a file that was changed.
//! gpg asks for the passphrase itself (pinentry), so dryserver never sees
//! it, and the agent does not keep it. The unlocked contents exist only in
//! memory and, while they are put in place, in a private folder beside the
//! home.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::err::{Error, Result};
use crate::homedir::{self, Brought, Layout};
use crate::{bail, errf, fsx};

const FORMAT: &str = "dryserver-export-1";
/// Larger than any real swarm (keys, lists, release copies); a file over
/// this is not one.
const MAX_BYTES: usize = 64 << 20;
/// Left out of the file: copies of the coordinator's backups (large, and
/// on the coordinator anyway), and what a run leaves behind for a moment.
const SKIP_DIRS: [&str; 1] = ["backups"];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Bundle {
    format: String,
    /// When it was made, in seconds since 1970.
    made: i64,
    /// Path (config.env, secrets/...) to its contents, base64.
    files: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ssh_key: Option<SshKey>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct SshKey {
    /// Its file name in ~/.ssh.
    name: String,
    private: String,
    public: String,
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn unb64(s: &str, what: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).map_err(|_| errf!("{what} in the file is damaged"))
}

/// Whether a path from the file is one of a swarm's: config.env, or a
/// plain name under secrets/. Nothing absolute, no "..", nothing hidden
/// at the top: a file from someone else cannot write anywhere else.
fn safe(path: &str) -> bool {
    if path == homedir::CONFIG {
        return true;
    }
    let Some(rest) = path.strip_prefix("secrets/") else { return false };
    let parts: Vec<&str> = rest.split('/').collect();
    path.len() < 512
        && parts.len() <= 4
        && parts.iter().all(|p| !p.is_empty() && *p != "." && *p != ".." && !p.contains('\0') && !p.contains('\\') && p.len() < 256)
}

/// What export puts in the file.
#[derive(Debug, Default, PartialEq)]
pub struct Packed {
    pub files: Vec<String>,
    /// The SSH key file that went in, if one did.
    pub ssh_key: Option<PathBuf>,
}

/// Packs the home's swarm, with the SSH key at ssh_key when given.
fn pack(l: &Layout, ssh_key: Option<&Path>, now: i64) -> Result<(Bundle, Packed)> {
    if !homedir::in_use(l) {
        bail!("there is no swarm in {} to export (dryserver where)", l.home.display());
    }
    let mut files = BTreeMap::new();
    if fs::symlink_metadata(&l.config).is_ok() {
        files.insert(homedir::CONFIG.to_string(), b64(&read_plain(&l.config)?));
    }
    if l.secrets.is_dir() {
        walk(&l.secrets, "secrets", &mut files)?;
    }
    let mut packed = Packed { files: files.keys().cloned().collect(), ssh_key: None };
    let ssh_key = match ssh_key {
        None => None,
        Some(p) => {
            let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let public = read_plain(&PathBuf::from(format!("{}.pub", p.display())))?;
            packed.ssh_key = Some(p.to_path_buf());
            Some(SshKey { name, private: b64(&read_plain(p)?), public: b64(&public) })
        }
    };
    Ok((Bundle { format: FORMAT.into(), made: now, files, ssh_key }, packed))
}

/// A plain file's contents; a link or anything else is refused.
fn read_plain(p: &Path) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(p).map_err(|e| Error::from(e).wrap(format!("open {}", p.display())))?;
    if !m.is_file() {
        bail!("{} is a link or a special file: not exported", p.display());
    }
    fsx::read(p)
}

fn walk(dir: &Path, prefix: &str, files: &mut BTreeMap<String, String>) -> Result<()> {
    let mut names: Vec<_> = fs::read_dir(dir)
        .map_err(|e| Error::from(e).wrap(format!("open {}", dir.display())))?
        .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<io::Result<_>>()?;
    names.sort();
    for n in names {
        let p = dir.join(&n);
        let rel = format!("{prefix}/{n}");
        let m = fs::symlink_metadata(&p).map_err(|e| Error::from(e).wrap(format!("open {}", p.display())))?;
        if m.is_dir() {
            if prefix == "secrets" && SKIP_DIRS.contains(&n.as_str()) {
                continue;
            }
            walk(&p, &rel, files)?;
        } else if n.ends_with(".tmp") || n.ends_with(".lock") {
            // Left by a run for a moment; never part of the swarm.
        } else {
            if !safe(&rel) {
                bail!("{} has a name an import would refuse: rename or remove it first", p.display());
            }
            files.insert(rel, b64(&read_plain(&p)?));
        }
    }
    Ok(())
}

/// The lock: seals and opens the file's contents.
pub trait Lock {
    fn seal(&self, plain: &[u8]) -> Result<Vec<u8>>;
    fn open(&self, sealed: &[u8]) -> Result<Vec<u8>>;
}

/// GnuPG with a passphrase, asked by gpg itself.
pub struct Gpg {
    /// Its own keyring folder (tests); None: the user's.
    pub homedir: Option<PathBuf>,
    /// The passphrase from a file instead of asking (tests only).
    pub passphrase_file: Option<PathBuf>,
}

impl Gpg {
    pub fn asking() -> Gpg {
        Gpg { homedir: None, passphrase_file: None }
    }

    fn run(&self, args: &[&str], input: &[u8]) -> Result<Vec<u8>> {
        if !crate::iso::in_path("gpg") {
            bail!("gpg is not installed: it locks the file (install gnupg2 or gnupg)");
        }
        let mut c = Command::new("gpg");
        c.args(["--quiet", "--no-symkey-cache"]);
        if let Some(h) = &self.homedir {
            c.arg("--homedir").arg(h);
        }
        if let Some(f) = &self.passphrase_file {
            c.args(["--batch", "--pinentry-mode", "loopback", "--passphrase-file"]).arg(f);
        } else if std::env::var_os("GPG_TTY").is_none()
            && let Some(tty) = tty_name()
        {
            // pinentry asks on this terminal; stdin is gpg's data pipe.
            c.env("GPG_TTY", tty);
        }
        c.args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = c.spawn().map_err(|e| Error::from(e).wrap("gpg"))?;
        let mut pipe = child.stdin.take().ok_or_else(|| Error::new("gpg: no stdin"))?;
        let data = input.to_vec();
        let writer = std::thread::spawn(move || {
            let _ = pipe.write_all(&data);
        });
        let out = child.wait_with_output().map_err(|e| Error::from(e).wrap("gpg"))?;
        let _ = writer.join();
        if !out.status.success() {
            let msg = String::from_utf8_lossy(&out.stderr);
            let last = msg.lines().rfind(|l| !l.trim().is_empty()).unwrap_or("").trim();
            bail!("gpg: {}", if last.is_empty() { crate::runner::exit_text(out.status) } else { last.to_string() });
        }
        Ok(out.stdout)
    }
}

/// The terminal on stdin, for pinentry.
fn tty_name() -> Option<String> {
    // SAFETY: ttyname on a descriptor we do not close; the result is
    // copied before any other call.
    let p = unsafe { libc::ttyname(0) };
    if p.is_null() {
        return None;
    }
    // SAFETY: ttyname returned a NUL-terminated string.
    Some(unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned())
}

impl Lock for Gpg {
    fn seal(&self, plain: &[u8]) -> Result<Vec<u8>> {
        self.run(
            &[
                "--symmetric",
                "--cipher-algo",
                "AES256",
                "--s2k-mode",
                "3",
                "--s2k-digest-algo",
                "SHA512",
                "--s2k-count",
                "65011712",
                "--output",
                "-",
            ],
            plain,
        )
    }

    fn open(&self, sealed: &[u8]) -> Result<Vec<u8>> {
        self.run(&["--decrypt", "--output", "-"], sealed).map_err(|e| e.wrap("cannot open the file (wrong passphrase, or it was changed)"))
    }
}

/// Writes the locked file to out, which must not exist yet.
pub fn export(l: &Layout, ssh_key: Option<&Path>, lock: &dyn Lock, out: &Path) -> Result<Packed> {
    if fs::symlink_metadata(out).is_ok() {
        bail!("{} is there already: give another name", out.display());
    }
    let (bundle, packed) = pack(l, ssh_key, chrono::Utc::now().timestamp())?;
    let plain = serde_json::to_vec(&bundle).map_err(|e| errf!("pack: {e}"))?;
    let sealed = lock.seal(&plain)?;
    fsx::create_file(out, &sealed, 0o600)?;
    fs::File::open(out).and_then(|f| f.sync_all()).map_err(|e| Error::from(e).wrap(format!("sync {}", out.display())))?;
    Ok(packed)
}

/// What import put in place.
#[derive(Debug, Default, PartialEq)]
pub struct Unpacked {
    pub brought: Brought,
    /// Where the SSH key went, or why it did not.
    pub ssh_key: Option<std::result::Result<PathBuf, String>>,
    /// When the file was made.
    pub made: i64,
}

/// Opens the locked file and puts the swarm in the home, the SSH key in
/// ssh_dir.
pub fn import(file: &Path, l: &Layout, ssh_dir: Option<&Path>, lock: &dyn Lock) -> Result<Unpacked> {
    let sealed = fsx::read(file)?;
    if sealed.len() > MAX_BYTES {
        bail!("{} is too large to be a dryserver export", file.display());
    }
    let plain = lock.open(&sealed)?;
    let bundle: Bundle = serde_json::from_slice(&plain).map_err(|_| errf!("{} is not a dryserver export", file.display()))?;
    if bundle.format != FORMAT {
        bail!("{} is a dryserver export of another kind ({}): use the dryserver that made it", file.display(), bundle.format);
    }
    for p in bundle.files.keys() {
        if !safe(p) {
            bail!("the file names {p:?}, which is not a swarm's: nothing was imported");
        }
    }
    let stage = Stage::new(l)?;
    for (p, data) in &bundle.files {
        let dst = stage.0.join(p);
        mkdirs_private(&stage.0, fsx::dir(&dst).as_path())?;
        fsx::create_file(&dst, unb64(data, p)?, 0o600)?;
    }
    let brought = homedir::bring(&stage.0, l)?;
    let ssh_key = match (&bundle.ssh_key, ssh_dir) {
        (Some(k), Some(dir)) => Some(put_ssh_key(k, dir)),
        (Some(_), None) => Some(Err("there is no ~/.ssh to put it in ($HOME is not set)".into())),
        (None, _) => None,
    };
    Ok(Unpacked { brought, ssh_key, made: bundle.made })
}

/// A private folder beside the home for the unlocked files, removed when
/// dropped.
struct Stage(PathBuf);

impl Stage {
    fn new(l: &Layout) -> Result<Stage> {
        homedir::prepare(l)?;
        let parent = fsx::dir(&l.home);
        let p = parent.join(format!(".dryserver-import-{}", std::process::id()));
        if fs::symlink_metadata(&p).is_ok() {
            fs::remove_dir_all(&p).map_err(|e| Error::from(e).wrap(format!("remove {}", p.display())))?;
        }
        fs::DirBuilder::new().mode(0o700).create(&p).map_err(|e| Error::from(e).wrap(format!("mkdir {}", p.display())))?;
        Ok(Stage(p))
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Makes the folders from root down to dir, 0700.
fn mkdirs_private(root: &Path, dir: &Path) -> Result<()> {
    let rel = dir.strip_prefix(root).map_err(|_| errf!("{} is outside {}", dir.display(), root.display()))?;
    let mut d = root.to_path_buf();
    for c in rel.components() {
        d.push(c);
        if !d.is_dir() {
            fs::DirBuilder::new().mode(0o700).create(&d).map_err(|e| Error::from(e).wrap(format!("mkdir {}", d.display())))?;
        }
    }
    Ok(())
}

/// Puts the SSH key in dir under its own name, or dryserver_ed25519 when
/// another key has that name; never over a different key.
fn put_ssh_key(k: &SshKey, dir: &Path) -> std::result::Result<PathBuf, String> {
    let private = unb64(&k.private, "the SSH key").map_err(|e| e.to_string())?;
    let public = unb64(&k.public, "the SSH key").map_err(|e| e.to_string())?;
    let ok_name = |n: &str| !n.is_empty() && !n.contains('/') && n != "." && n != ".." && !n.starts_with('.');
    let mut names = vec!["dryserver_ed25519".to_string()];
    if ok_name(&k.name) {
        names.insert(0, k.name.clone());
    }
    if !dir.is_dir() {
        fs::DirBuilder::new().mode(0o700).create(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    }
    for n in &names {
        let (kp, pp) = (dir.join(n), dir.join(format!("{n}.pub")));
        let same = |p: &Path, want: &[u8]| fs::read(p).is_ok_and(|b| b == want);
        match (fs::symlink_metadata(&kp).is_ok(), fs::symlink_metadata(&pp).is_ok()) {
            (false, false) => {
                fsx::create_file(&kp, &private, 0o600).map_err(|e| e.to_string())?;
                fsx::create_file(&pp, &public, 0o644).map_err(|e| e.to_string())?;
                return Ok(kp);
            }
            (true, true) if same(&kp, &private) && same(&pp, &public) => return Ok(kp),
            _ => continue,
        }
    }
    Err(format!("{} has other keys under the names {}: the key in the file was not put there", dir.display(), names.join(" and ")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::homedir::Env;
    use crate::testutil::{TempDir, put};
    use std::os::unix::fs::PermissionsExt;

    /// A lock that only marks the contents: what export and import do
    /// around it, without gpg.
    struct Plain;
    impl Lock for Plain {
        fn seal(&self, plain: &[u8]) -> Result<Vec<u8>> {
            Ok([b"LOCKED".as_slice(), plain].concat())
        }
        fn open(&self, sealed: &[u8]) -> Result<Vec<u8>> {
            sealed.strip_prefix(b"LOCKED").map(<[u8]>::to_vec).ok_or_else(|| errf!("wrong passphrase"))
        }
    }

    fn at(dir: &Path) -> Layout {
        homedir::layout(&Env { dryserver_home: Some(dir.into()), ..Env::default() }).unwrap()
    }

    fn swarm(l: &Layout) {
        put(&l.home, "config.env", "COORD_LAN_IP='10.1.0.60'\nWIFI_PSK='pw'\n");
        put(&l.secrets, "registry_ed25519", "reg");
        put(&l.secrets, "signing_ed25519.pub", "ssh-ed25519 AAAA dryserver-signing\n");
        put(&l.secrets, "join_secret", "ab12");
        put(&l.secrets, "releases/1795000000.json", "{}");
        put(&l.secrets, "backups/brain-2026.tar.age", "large");
        put(&l.secrets, "release.lock", "");
        put(&l.secrets, "members.signed.json.tmp", "half");
    }

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn export_then_import_on_another_computer() {
        let t = TempDir::new();
        let desk = at(&t.join("desk"));
        swarm(&desk);
        put(&t.join("ssh"), "id_ed25519", "PRIVATE");
        put(&t.join("ssh"), "id_ed25519.pub", "ssh-ed25519 AAAA me@pc\n");
        let out = t.join("swarm.gpg");
        let p = export(&desk, Some(&t.join("ssh/id_ed25519")), &Plain, &out).unwrap();
        assert_eq!(
            p.files,
            [
                "config.env",
                "secrets/join_secret",
                "secrets/registry_ed25519",
                "secrets/releases/1795000000.json",
                "secrets/signing_ed25519.pub"
            ]
        );
        assert_eq!(p.ssh_key, Some(t.join("ssh/id_ed25519")));
        assert_eq!(mode(&out), 0o600);
        let sealed = fs::read(&out).unwrap();
        assert!(sealed.starts_with(b"LOCKED"), "the lock got the contents");
        // Never over a file that is there.
        assert!(export(&desk, None, &Plain, &out).unwrap_err().to_string().contains("there already"));

        // The laptop: nothing there yet, an SSH key of its own.
        let laptop = at(&t.join("laptop"));
        let ssh = t.join("lssh");
        put(&ssh, "id_ed25519", "LAPTOP OWN");
        put(&ssh, "id_ed25519.pub", "ssh-ed25519 BBBB laptop\n");
        let u = import(&out, &laptop, Some(&ssh), &Plain).unwrap();
        assert_eq!(u.brought.copied, vec![laptop.config.clone(), laptop.secrets.clone()]);
        assert_eq!(fs::read_to_string(&laptop.config).unwrap(), fs::read_to_string(&desk.config).unwrap());
        assert_eq!(fs::read_to_string(laptop.secrets.join("join_secret")).unwrap(), "ab12");
        assert_eq!(mode(&laptop.secrets.join("join_secret")), 0o600);
        // The backups and what a run leaves are not in it.
        assert!(!laptop.secrets.join("backups").exists() && !laptop.secrets.join("release.lock").exists());
        assert!(!laptop.secrets.join("members.signed.json.tmp").exists());
        // The laptop's own key stays; the swarm's key gets another name.
        assert_eq!(fs::read_to_string(ssh.join("id_ed25519")).unwrap(), "LAPTOP OWN");
        assert_eq!(u.ssh_key, Some(Ok(ssh.join("dryserver_ed25519"))));
        assert_eq!(fs::read_to_string(ssh.join("dryserver_ed25519")).unwrap(), "PRIVATE");
        assert_eq!(mode(&ssh.join("dryserver_ed25519")), 0o600);
        // No unlocked copy is left beside the home.
        let left: Vec<_> = fs::read_dir(t.path()).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        assert!(left.iter().all(|n| !n.starts_with(".dryserver-import")), "{left:?}");

        // Again: the same swarm and key are there, nothing changes.
        let u = import(&out, &laptop, Some(&ssh), &Plain).unwrap();
        assert_eq!((u.brought.copied.len(), u.brought.same.len()), (0, 2));
        assert_eq!(u.ssh_key, Some(Ok(ssh.join("dryserver_ed25519"))));
    }

    #[test]
    fn import_never_overwrites_another_swarm_or_key() {
        let t = TempDir::new();
        let desk = at(&t.join("desk"));
        swarm(&desk);
        put(&t.join("ssh"), "id_ed25519", "PRIVATE");
        put(&t.join("ssh"), "id_ed25519.pub", "ssh-ed25519 AAAA me@pc\n");
        let out = t.join("swarm.gpg");
        export(&desk, Some(&t.join("ssh/id_ed25519")), &Plain, &out).unwrap();
        let other = at(&t.join("other"));
        put(&other.home, "config.env", "COORD_LAN_IP='10.9.9.9'\n");
        let e = import(&out, &other, None, &Plain).unwrap_err().to_string();
        assert!(e.contains("nothing was copied"), "{e}");
        assert_eq!(fs::read_to_string(&other.config).unwrap(), "COORD_LAN_IP='10.9.9.9'\n");
        // Both names taken by other keys: the swarm comes, the key does not.
        let fresh = at(&t.join("fresh"));
        let ssh = t.join("full");
        for n in ["id_ed25519", "dryserver_ed25519"] {
            put(&ssh, n, "OTHER");
            put(&ssh, &format!("{n}.pub"), "ssh-ed25519 CCCC x\n");
        }
        let u = import(&out, &fresh, Some(&ssh), &Plain).unwrap();
        assert_eq!(u.brought.copied.len(), 2);
        let e = u.ssh_key.unwrap().unwrap_err();
        assert!(e.contains("other keys") && e.contains("not put there"), "{e}");
        assert_eq!(fs::read_to_string(ssh.join("id_ed25519")).unwrap(), "OTHER");
    }

    #[test]
    fn a_wrong_passphrase_or_a_foreign_file_imports_nothing() {
        let t = TempDir::new();
        let l = at(&t.join("home"));
        put(t.path(), "bad", "not locked");
        assert!(import(&t.join("bad"), &l, None, &Plain).unwrap_err().to_string().contains("wrong passphrase"));
        put(t.path(), "junk", "LOCKED{not json");
        assert!(import(&t.join("junk"), &l, None, &Plain).unwrap_err().to_string().contains("not a dryserver export"));
        let other = serde_json::json!({"format": "dryserver-export-9", "made": 0, "files": {}});
        put(t.path(), "newer", format!("LOCKED{other}"));
        assert!(import(&t.join("newer"), &l, None, &Plain).unwrap_err().to_string().contains("another kind"));
        assert!(!homedir::in_use(&l));
    }

    #[test]
    fn a_file_that_names_paths_outside_the_swarm_writes_nothing() {
        let t = TempDir::new();
        let l = at(&t.join("home"));
        for bad in ["../evil", "/etc/passwd", "secrets/../../x", "secrets//x", ".ssh/authorized_keys", "secrets/./x", "secrets/a\\b", ""] {
            let mut files = BTreeMap::new();
            files.insert("config.env".to_string(), b64(b"COORD_LAN_IP='1.2.3.4'\n"));
            files.insert(bad.to_string(), b64(b"x"));
            let b = Bundle { format: FORMAT.into(), made: 0, files, ssh_key: None };
            put(t.path(), "f", [b"LOCKED".as_slice(), &serde_json::to_vec(&b).unwrap()].concat());
            let e = import(&t.join("f"), &l, None, &Plain).unwrap_err().to_string();
            assert!(e.contains("not a swarm's") && e.contains("nothing was imported"), "{bad:?}: {e}");
            assert!(!homedir::in_use(&l), "{bad:?}");
            assert!(!t.path().parent().unwrap().join("evil").exists() && !t.join("x").exists());
        }
        // An SSH key name with a path in it goes in as dryserver_ed25519.
        let mut files = BTreeMap::new();
        files.insert("config.env".to_string(), b64(b"COORD_LAN_IP='1.2.3.4'\n"));
        let key = SshKey { name: "../../.bashrc".into(), private: b64(b"K"), public: b64(b"P") };
        let b = Bundle { format: FORMAT.into(), made: 0, files, ssh_key: Some(key) };
        put(t.path(), "g", [b"LOCKED".as_slice(), &serde_json::to_vec(&b).unwrap()].concat());
        let ssh = t.join("ssh");
        let u = import(&t.join("g"), &l, Some(&ssh), &Plain).unwrap();
        assert_eq!(u.ssh_key, Some(Ok(ssh.join("dryserver_ed25519"))));
        assert!(!t.join(".bashrc").exists());
    }

    #[test]
    fn nothing_to_export_and_links_are_said() {
        let t = TempDir::new();
        let l = at(&t.join("home"));
        assert!(export(&l, None, &Plain, &t.join("o")).unwrap_err().to_string().contains("no swarm"));
        swarm(&l);
        std::os::unix::fs::symlink("/etc/hostname", l.secrets.join("link")).unwrap();
        let e = export(&l, None, &Plain, &t.join("o")).unwrap_err().to_string();
        assert!(e.contains("link") && e.contains("not exported"), "{e}");
        assert!(!t.join("o").exists(), "no file when it fails");
    }

    #[test]
    fn real_gpg_locks_and_refuses_a_wrong_passphrase_or_a_change() {
        if !crate::iso::in_path("gpg") {
            return;
        }
        let t = TempDir::new();
        let gh = t.join("gnupg");
        fs::DirBuilder::new().mode(0o700).create(&gh).unwrap();
        put(t.path(), "pass", "correct horse battery staple\n");
        put(t.path(), "wrong", "wrong one\n");
        let lock = Gpg { homedir: Some(gh.clone()), passphrase_file: Some(t.join("pass")) };
        let desk = at(&t.join("desk"));
        swarm(&desk);
        let out = t.join("swarm.gpg");
        export(&desk, None, &lock, &out).unwrap();
        let sealed = fs::read(&out).unwrap();
        assert!(!sealed.windows(4).any(|w| w == b"ab12"), "the secret is not readable in the file");
        assert!(!String::from_utf8_lossy(&sealed).contains("COORD_LAN_IP"));
        let wrong = Gpg { homedir: Some(gh.clone()), passphrase_file: Some(t.join("wrong")) };
        let l2 = at(&t.join("l2"));
        let e = import(&out, &l2, None, &wrong).unwrap_err().to_string();
        assert!(e.contains("cannot open the file"), "{e}");
        assert!(!homedir::in_use(&l2));
        // One byte changed in the middle: refused.
        let mut changed = sealed.clone();
        let mid = changed.len() / 2;
        changed[mid] ^= 0x40;
        put(t.path(), "changed.gpg", &changed);
        assert!(import(&t.join("changed.gpg"), &l2, None, &lock).is_err());
        assert!(!homedir::in_use(&l2));
        let u = import(&out, &l2, None, &lock).unwrap();
        assert_eq!(u.brought.copied.len(), 2);
        assert_eq!(fs::read_to_string(l2.secrets.join("join_secret")).unwrap(), "ab12");
        // The agent gpg started for this keyring folder goes with it.
        let _ = Command::new("gpgconf").arg("--homedir").arg(&gh).args(["--kill", "gpg-agent"]).status();
    }
}
