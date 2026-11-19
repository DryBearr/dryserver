//! Files embedded at build time (see build.rs).
//!
//! ARCHISO holds build.sh (run inside the Arch container), packages.extra
//! (appended to the releng package list) and overlay/ (copied over the
//! releng profile). ROOTFS holds files copied into each installed server,
//! at the same path under /; which ones get copied is decided by the
//! package bundles. Paths are relative, without a leading slash.

include!(concat!(env!("OUT_DIR"), "/assets.rs"));

#[cfg(test)]
/// The embedded rootfs file at path (with or without a leading slash).
pub fn rootfs_file(path: &str) -> Option<&'static [u8]> {
    let p = path.trim_start_matches('/');
    ROOTFS.iter().find(|(name, _)| *name == p).map(|(_, data)| *data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packages::{ESSENTIALS, OPTIONAL, SYSTEM};

    fn bundle_files() -> Vec<&'static str> {
        let mut all = vec![SYSTEM, ESSENTIALS];
        all.extend_from_slice(OPTIONAL);
        all.iter().flat_map(|b| b.files.iter().copied()).collect()
    }

    // Every file a bundle promises must exist in the embedded rootfs.
    #[test]
    fn bundle_files_exist() {
        for f in bundle_files() {
            assert!(rootfs_file(f).is_some(), "{f} missing from assets/rootfs");
        }
    }

    #[test]
    fn no_stray_rootfs_files() {
        let used = bundle_files();
        for (name, _) in ROOTFS {
            assert!(used.contains(&format!("/{name}").as_str()), "{name} is not installed by any bundle");
        }
    }

    #[test]
    fn archiso_has_build_files() {
        for want in ["build.sh", "packages.extra", "zlogin.append", "overlay/airootfs/etc/motd", "overlay/airootfs/etc/nftables.conf"] {
            assert!(ARCHISO.iter().any(|(n, _)| *n == want), "{want} not embedded");
        }
    }
}
