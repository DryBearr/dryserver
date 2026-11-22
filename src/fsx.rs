//! File helpers whose errors name the operation and path, like
//! "open /etc/x: no such file or directory".

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::err::{Error, Result};

fn op_err(op: &str, path: &Path, e: io::Error) -> Error {
    Error::from(e).wrap(format!("{op} {}", path.display()))
}

pub fn read(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    let p = path.as_ref();
    fs::read(p).map_err(|e| op_err("open", p, e))
}

pub fn read_string(path: impl AsRef<Path>) -> Result<String> {
    let b = read(path)?;
    Ok(String::from_utf8_lossy(&b).into_owned())
}

/// Reads a file, "" when it cannot be read.
pub fn read_or_empty(path: impl AsRef<Path>) -> String {
    read_string(path).unwrap_or_default()
}

/// Creates or truncates path. mode applies to new files only, like
/// os.WriteFile.
pub fn write_file(path: impl AsRef<Path>, data: impl AsRef<[u8]>, mode: u32) -> Result<()> {
    let p = path.as_ref();
    let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(mode).open(p).map_err(|e| op_err("open", p, e))?;
    f.write_all(data.as_ref()).map_err(|e| op_err("write", p, e))
}

pub fn rename(from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<()> {
    let (f, t) = (from.as_ref(), to.as_ref());
    fs::rename(f, t).map_err(|e| Error::from(e).wrap(format!("rename {} {}", f.display(), t.display())))
}

pub fn mkdir_all(path: impl AsRef<Path>, mode: u32) -> Result<()> {
    let p = path.as_ref();
    if p.is_dir() {
        return Ok(());
    }
    DirBuilder::new().recursive(true).mode(mode).create(p).map_err(|e| op_err("mkdir", p, e))
}

pub fn remove(path: impl AsRef<Path>) -> Result<()> {
    let p = path.as_ref();
    fs::remove_file(p).map_err(|e| op_err("remove", p, e))
}

pub fn chmod(path: impl AsRef<Path>, mode: u32) -> Result<()> {
    let p = path.as_ref();
    fs::set_permissions(p, fs::Permissions::from_mode(mode)).map_err(|e| op_err("chmod", p, e))
}

pub fn exists(path: impl AsRef<Path>) -> bool {
    fs::metadata(path).is_ok()
}

/// Joins p under root, also when p is absolute: ("/mnt", "/etc/x") ->
/// /mnt/etc/x.
pub fn under(root: impl AsRef<Path>, p: impl AsRef<Path>) -> PathBuf {
    let p = p.as_ref();
    root.as_ref().join(p.strip_prefix("/").unwrap_or(p))
}

/// The directory part of path, "." for a bare name.
pub fn dir(path: impl AsRef<Path>) -> PathBuf {
    match path.as_ref().parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Takes an exclusive flock on path, creating it (and its directory) if
/// needed. The lock is held until the returned file is dropped.
pub fn lock(path: impl AsRef<Path>) -> Result<fs::File> {
    let p = path.as_ref();
    mkdir_all(dir(p), 0o755)?;
    let f = OpenOptions::new().read(true).write(true).create(true).truncate(false).mode(0o600).open(p).map_err(|e| op_err("open", p, e))?;
    // SAFETY: flock on a valid open descriptor owned by f.
    if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&f), libc::LOCK_EX) } != 0 {
        return Err(op_err("lock", p, io::Error::last_os_error()));
    }
    Ok(f)
}

/// Like lock, but gives up at once: None when another process holds it.
pub fn try_lock(path: impl AsRef<Path>) -> Result<Option<fs::File>> {
    let p = path.as_ref();
    mkdir_all(dir(p), 0o755)?;
    let f = OpenOptions::new().read(true).write(true).create(true).truncate(false).mode(0o600).open(p).map_err(|e| op_err("open", p, e))?;
    // SAFETY: flock on a valid open descriptor owned by f.
    if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&f), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Ok(None);
        }
        return Err(op_err("lock", p, e));
    }
    Ok(Some(f))
}

/// try_lock, waiting up to max for a holder to let go. A child that another
/// thread forked a moment ago keeps a copy of a just-closed lock open until
/// its exec, so a lock can look taken for an instant after it was released.
pub fn try_lock_for(path: impl AsRef<Path>, max: std::time::Duration) -> Result<Option<fs::File>> {
    let end = std::time::Instant::now() + max;
    loop {
        if let Some(f) = try_lock(path.as_ref())? {
            return Ok(Some(f));
        }
        if std::time::Instant::now() >= end {
            return Ok(None);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// The size of the filesystem holding path and the space on it that is
/// free for anyone (root's reserve not counted), in bytes.
pub fn space(path: impl AsRef<Path>) -> Result<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let p = path.as_ref();
    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).map_err(|_| Error::new(format!("statvfs {}: bad path", p.display())))?;
    // SAFETY: c is a valid C string and st a plain struct statvfs fills in.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return Err(op_err("statvfs", p, io::Error::last_os_error()));
    }
    let unit = st.f_frsize as u64;
    Ok((st.f_blocks as u64 * unit, st.f_bavail as u64 * unit))
}

pub fn geteuid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

pub fn is_root() -> bool {
    geteuid() == 0
}

/// Random bytes from the OS.
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).expect("no randomness from the OS");
    b
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---- the desktop's shared SSH connections ----

/// The directory for the sockets of the SSH connections the desktop
/// shares between calls (approve, apps, outside, backup-pull):
/// dryserver/ in the runtime directory, made for uid alone. None when it
/// is not safe.
///
/// Every call goes through whatever listens on the socket, signed lists,
/// releases and the tunnel's token on stdin included: a socket someone
/// else put there would get them, and could answer in the coordinator's
/// place. So the directory must be a real one (not a link), owned by uid
/// and mode 0700, and it must sit in a runtime directory nobody else can
/// rename it out of: owned by uid or root, writable by nobody else unless
/// sticky. One that is not like that is left as it is, and every call
/// connects by itself.
pub fn socket_dir(runtime: &Path, uid: u32) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let parent = fs::symlink_metadata(runtime).ok()?;
    let others_write = parent.mode() & 0o022 != 0 && parent.mode() & 0o1000 == 0;
    if !parent.is_dir() || !(parent.uid() == uid || parent.uid() == 0) || others_write {
        return None;
    }
    let dir = runtime.join("dryserver");
    match DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(_) => return None,
    }
    let m = fs::symlink_metadata(&dir).ok()?;
    (m.is_dir() && m.uid() == uid && m.mode() & 0o777 == 0o700).then_some(dir)
}

/// ssh's ControlPath option for the socket name (with one %C in it) in
/// socket_dir of runtime, the user's $XDG_RUNTIME_DIR. None without a
/// safe directory, or when the name is too long for a socket: then every
/// call connects by itself.
pub fn control_path(runtime: Option<&std::ffi::OsStr>, name: &str) -> Option<String> {
    let runtime = Path::new(runtime.filter(|d| !d.is_empty())?);
    socket_in(&socket_dir(runtime, geteuid())?, name)
}

/// The ControlPath option for name in dir. ssh puts 40 characters in
/// place of %C and binds the socket under the name plus 17 characters
/// first; a socket's name has room for 107.
pub fn socket_in(dir: &Path, name: &str) -> Option<String> {
    let path = dir.join(name).display().to_string();
    if !name.contains("%C") || name.contains('/') || path.len() - 2 + 40 + 17 > 107 {
        return None;
    }
    Some(format!("ControlPath={path}"))
}

/// A short id for a set of files (absolute paths), for socket names: a
/// connection made with one stick's keys and pinned host key is never
/// reused with another's.
pub fn paths_id(paths: &[&Path]) -> u64 {
    let mut id: u64 = 0xcbf2_9ce4_8422_2325;
    for (i, p) in paths.iter().enumerate() {
        let full = std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
        let sep: &[u8] = if i == 0 { &[] } else { &[0] };
        for b in sep.iter().chain(full.as_os_str().as_encoded_bytes()) {
            id = (id ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3);
        }
    }
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_socket_directory_is_ours_alone() {
        let me = geteuid();
        let mode = |p: &Path| fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777;
        let set = |p: &Path, m: u32| fs::set_permissions(p, fs::Permissions::from_mode(m)).unwrap();
        let t = crate::testutil::TempDir::new();
        set(t.path(), 0o700);
        let dir = t.join("dryserver");
        // Made for this user alone, and found again.
        assert_eq!(socket_dir(t.path(), me), Some(dir.clone()));
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(socket_dir(t.path(), me), Some(dir.clone()));
        // Someone else's (here: owned by another uid than asked for).
        assert_eq!(socket_dir(t.path(), me + 1), None);
        // Open to others: not shared, and left as it is.
        set(&dir, 0o755);
        assert_eq!(socket_dir(t.path(), me), None);
        assert_eq!(mode(&dir), 0o755);
        set(&dir, 0o710);
        assert_eq!(socket_dir(t.path(), me), None, "a group that may only pass through is still not alone");
        // A link to a directory that would pass: not followed.
        fs::remove_dir(&dir).unwrap();
        let elsewhere = t.join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        set(&elsewhere, 0o700);
        std::os::unix::fs::symlink(&elsewhere, &dir).unwrap();
        assert_eq!(socket_dir(t.path(), me), None);
        // A file in its place.
        fs::remove_file(&dir).unwrap();
        fs::write(&dir, "").unwrap();
        assert_eq!(socket_dir(t.path(), me), None);
        fs::remove_file(&dir).unwrap();
        // A runtime directory others may write to could have ours renamed
        // away and replaced; with the sticky bit (like /tmp) it cannot.
        set(t.path(), 0o777);
        assert_eq!(socket_dir(t.path(), me), None);
        assert!(!dir.exists(), "nothing made there");
        set(t.path(), 0o1777);
        assert_eq!(socket_dir(t.path(), me), Some(dir.clone()));
        set(t.path(), 0o700);
        // The runtime directory itself a link, or not there at all.
        let link = t.join("runtime-link");
        std::os::unix::fs::symlink(t.path(), &link).unwrap();
        assert_eq!(socket_dir(&link, me), None);
        assert_eq!(socket_dir(&t.join("missing"), me), None);
        // Without a safe directory there is no ControlPath at all.
        assert_eq!(control_path(None, "x-%C"), None);
        assert_eq!(control_path(Some("".as_ref()), "x-%C"), None);
        set(&dir, 0o750);
        assert_eq!(control_path(Some(t.path().as_os_str()), "x-%C"), None);
    }

    #[test]
    fn socket_names() {
        let run = Path::new("/run/user/1000/dryserver");
        assert_eq!(socket_in(run, "reg-%C-1").as_deref(), Some("ControlPath=/run/user/1000/dryserver/reg-%C-1"));
        // A socket's name has room for 107 bytes, and ssh adds 17 while
        // it makes one: a deep runtime directory means no sharing.
        let deep = format!("/run/user/{}/dryserver", "x".repeat(40));
        assert_eq!(socket_in(deep.as_ref(), "reg-%C-0123456789abcdef"), None);
        assert_eq!(socket_in(run, "no-percent-c"), None, "one socket for every coordinator would mix them up");
        assert_eq!(socket_in(run, "../up-%C"), None);
        // Another key or pinned host key file: another id.
        let (a, b) = (Path::new("a/known_hosts"), Path::new("b/known_hosts"));
        assert_ne!(paths_id(&[a]), paths_id(&[b]));
        assert_ne!(paths_id(&[a, b]), paths_id(&[b, a]));
        assert_eq!(paths_id(&[a]), paths_id(&[a]));
    }
}
