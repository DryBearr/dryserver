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
