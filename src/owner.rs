//! Hands files created under sudo back to the invoking user.

use std::path::Path;

/// Chowns each path (recursively) to SUDO_UID:SUDO_GID when running as root
/// via sudo, so the project directory stays usable without root. Missing
/// paths are skipped.
pub fn fix<P: AsRef<Path>>(paths: &[P]) {
    if !crate::fsx::is_root() {
        return;
    }
    let id = |k: &str| std::env::var(k).ok().and_then(|v| v.parse::<u32>().ok());
    let (Some(uid), Some(gid)) = (id("SUDO_UID"), id("SUDO_GID")) else {
        return;
    };
    for p in paths {
        walk(p.as_ref(), uid, gid);
    }
}

fn walk(p: &Path, uid: u32, gid: u32) {
    let Ok(meta) = std::fs::symlink_metadata(p) else {
        return;
    };
    let _ = std::os::unix::fs::lchown(p, Some(uid), Some(gid));
    if meta.is_dir()
        && let Ok(ents) = std::fs::read_dir(p)
    {
        for e in ents.flatten() {
            walk(&e.path(), uid, gid);
        }
    }
}
