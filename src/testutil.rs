//! Helpers shared by the unit tests.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

/// A temporary directory removed when dropped.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> TempDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "dryserver-test-{}-{n}-{}",
            std::process::id(),
            crate::fsx::hex(&crate::fsx::random_bytes(4))
        ));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn join(&self, p: impl AsRef<Path>) -> PathBuf {
        self.0.join(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Writes content to root/path, creating parent directories.
pub fn put(root: &Path, path: &str, content: impl AsRef<[u8]>) {
    let p = crate::fsx::under(root, path);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, content).unwrap();
}

/// Reads root/path, "" when missing.
pub fn get(root: &Path, path: &str) -> String {
    std::fs::read_to_string(crate::fsx::under(root, path)).unwrap_or_default()
}
