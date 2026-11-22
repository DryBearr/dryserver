//! What gets installed on every server: the base system plus optional tool
//! bundles picked in the config.

use crate::err::Result;
use crate::errf;

/// A group of packages with the setup they need.
#[derive(Debug, Clone, Copy)]
pub struct Bundle {
    pub id: &'static str,
    pub title: &'static str,
    pub packages: &'static [&'static str],
    /// Enabled with systemctl.
    pub services: &'static [&'static str],
    /// The admin user joins these.
    pub groups: &'static [&'static str],
    /// Run as the admin user in the installed system (via arch-chroot),
    /// after packages are installed.
    pub user_commands: &'static [&'static str],
    /// Paths inside the installed system, copied from the embedded rootfs
    /// assets.
    pub files: &'static [&'static str],
}

const EMPTY: Bundle = Bundle { id: "", title: "", packages: &[], services: &[], groups: &[], user_commands: &[], files: &[] };

/// Always installed: boot, network, mesh and SSH.
pub const SYSTEM: Bundle = Bundle {
    id: "system",
    packages: &[
        "base",
        "linux",
        // The fallback kernel: its own image and modules, so a main kernel
        // that does not boot leaves one that does (see install/boot.rs).
        "linux-lts",
        "linux-firmware",
        "intel-ucode",
        "amd-ucode",
        "cryptsetup",
        "iwd",
        "openssh",
        "wireguard-tools",
        "nftables",
        "sudo",
        "zram-generator",
        // Encrypts the coordinator's nightly backup to the admin's key.
        "age",
    ],
    services: &["systemd-networkd", "systemd-resolved", "iwd", "sshd", "nftables", "systemd-timesyncd"],
    ..EMPTY
};

/// Always installed: everyday tools for running a server.
pub const ESSENTIALS: Bundle = Bundle {
    id: "essentials",
    packages: &[
        "git",
        "cronie",
        "tmux",
        "htop",
        "btop",
        "curl",
        "wget",
        "rsync",
        "jq",
        "ripgrep",
        "fd",
        "fzf",
        "tree",
        "unzip",
        "zip",
        "less",
        "man-db",
        "man-pages",
        "bash-completion",
        "lsof",
        "strace",
        "bind",
        "inetutils",
        "tcpdump",
        "smartmontools",
        "lm_sensors",
        "arch-audit",
        "arp-scan",
    ],
    services: &["cronie"],
    files: &["/etc/skel/.tmux.conf"],
    ..EMPTY
};

/// Optional bundles, in display order. IDs are stored in config TOOLS.
pub const OPTIONAL: &[Bundle] = &[
    Bundle {
        id: "docker",
        title: "Docker + Compose",
        packages: &["docker", "docker-compose", "docker-buildx"],
        services: &["docker"],
        groups: &["docker"],
        ..EMPTY
    },
    Bundle { id: "go", title: "Go", packages: &["go", "gopls"], ..EMPTY },
    Bundle {
        id: "rust",
        title: "Rust (rustup, stable toolchain)",
        packages: &["rustup"],
        user_commands: &["rustup default stable"],
        ..EMPTY
    },
    Bundle {
        id: "cpp",
        title: "C/C++ (gcc, clang, cmake, gdb, make)",
        packages: &["base-devel", "clang", "cmake", "ninja", "gdb"],
        ..EMPTY
    },
    Bundle {
        id: "neovim",
        title: "Neovim (clipboard shared over SSH)",
        packages: &["neovim"],
        files: &["/etc/skel/.config/nvim/init.lua", "/etc/profile.d/editor.sh"],
        ..EMPTY
    },
];

/// Every optional bundle.
pub fn default_tools() -> Vec<String> {
    OPTIONAL.iter().map(|b| b.id.to_string()).collect()
}

/// The merged install list for a server.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Plan {
    pub packages: Vec<String>,
    pub services: Vec<String>,
    pub groups: Vec<String>,
    pub user_commands: Vec<String>,
    pub files: Vec<String>,
}

/// Merges SYSTEM, ESSENTIALS, the chosen bundles and extra packages.
pub fn resolve(tools: &[String], extra: &[String]) -> Result<Plan> {
    valid_tools(tools)?;
    valid_extra(extra)?;
    let mut p = Plan::default();
    let mut add = |b: &Bundle| {
        let own = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        p.packages.extend(own(b.packages));
        p.services.extend(own(b.services));
        p.groups.extend(own(b.groups));
        p.user_commands.extend(own(b.user_commands));
        p.files.extend(own(b.files));
    };
    add(&SYSTEM);
    add(&ESSENTIALS);
    for b in OPTIONAL {
        if tools.iter().any(|t| t == b.id) {
            add(b);
        }
    }
    p.packages.extend(extra.iter().cloned());
    p.packages = dedup(&p.packages);
    p.services = dedup(&p.services);
    p.groups = dedup(&p.groups);
    Ok(p)
}

pub fn valid_tools(tools: &[String]) -> Result<()> {
    for t in tools {
        if !OPTIONAL.iter().any(|b| b.id == t) {
            return Err(errf!("unknown tool {t:?}"));
        }
    }
    Ok(())
}

/// Arch package names: lowercase letters, digits and @._+-, not starting
/// with . or -.
fn valid_pkg_name(p: &str) -> bool {
    let ok = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || "@._+-".contains(c);
    match p.chars().next() {
        Some(first) if first != '.' && first != '-' => p.chars().all(ok),
        _ => false,
    }
}

pub fn valid_extra(extra: &[String]) -> Result<()> {
    for p in extra {
        if !valid_pkg_name(p) {
            return Err(errf!("{p:?} is not a valid package name"));
        }
    }
    Ok(())
}

/// Orders tool IDs like OPTIONAL so the config stays stable.
pub fn sort_tools(tools: &[String]) -> Vec<String> {
    OPTIONAL.iter().filter(|b| tools.iter().any(|t| t == b.id)).map(|b| b.id.to_string()).collect()
}

fn dedup(list: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for s in list {
        let s = s.trim();
        if !s.is_empty() && !out.iter().any(|x| x == s) {
            out.push(s.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(l: &[&str]) -> Vec<String> {
        l.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn resolve_merges_bundles() {
        let p = resolve(&v(&["docker", "rust"]), &v(&["python", "git"])).unwrap();
        for want in ["base", "linux", "linux-lts", "openssh", "age", "git", "cronie", "docker", "rustup", "python"] {
            assert!(p.packages.iter().any(|x| x == want), "missing package {want}");
        }
        for not in ["go", "neovim", "clang"] {
            assert!(!p.packages.iter().any(|x| x == not), "unselected package {not} included");
        }
        assert_eq!(p.packages.iter().filter(|x| *x == "git").count(), 1, "git listed twice");
        for s in ["sshd", "cronie", "docker"] {
            assert!(p.services.iter().any(|x| x == s), "missing service {s}");
        }
        assert_eq!(p.groups, v(&["docker"]));
        assert_eq!(p.user_commands, v(&["rustup default stable"]));
    }

    #[test]
    fn resolve_rejects() {
        assert!(resolve(&v(&["cobol"]), &[]).is_err(), "unknown tool accepted");
        assert!(resolve(&[], &v(&["rm -rf /"])).is_err(), "bad package name accepted");
    }

    #[test]
    fn sort_tools_follows_optional() {
        assert_eq!(sort_tools(&v(&["neovim", "docker", "go"])), v(&["docker", "go", "neovim"]));
    }

    #[test]
    fn package_names() {
        for ok in ["python", "lib32-glibc", "gtk+", "qt6-base", "r", "0ad", "@x"] {
            assert!(valid_pkg_name(ok), "{ok} rejected");
        }
        for bad in ["", "-x", ".x", "Python", "node;rm", "a b"] {
            assert!(!valid_pkg_name(bad), "{bad} accepted");
        }
    }
}
