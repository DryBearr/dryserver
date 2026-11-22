//! OS updates from a signed release: the Arch Linux snapshot every machine
//! is pinned to (B4) and the k3s binary (B6). `dryserver update apply`
//! calls these once the release passed `release::check` and its dryserver
//! binary is in place.
//!
//! Arch: pacman on every machine reads one dated snapshot of the Arch
//! archive, the day the admin signed (release.arch_date). Every machine
//! then runs exactly the same packages, a fix arrives when the admin signs
//! a newer day, and a bad day is undone by signing an older one with
//! `rollback`, which lets pacman downgrade. Before pacman runs, everything
//! that would make the run unsafe is checked, and the update is refused
//! with the reason: package signatures weakened in pacman.conf, /boot not
//! mounted, too little disk space, another pacman at work. pacman's own
//! checks stay on: no --overwrite, no skipped signatures, ever. A run that
//! fails part way leaves pacman's own state and the next run picks it up;
//! until one succeeds the machine must not reboot, since its boot image
//! may be half made.
//!
//! k3s: the binary the release names, checked against its sha256 and
//! swapped in with a rename, so a power cut leaves the old binary or the
//! new one, never half of one. The old one stays as k3s.prev; if k3s does
//! not come back healthy with the new one, the old one goes back. The k3s
//! data directories are never touched.
//!
//! Neither guards against a second update at the same time: the caller
//! holds the update lock for the whole release.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::ctx::Ctx;
use crate::err::{Error, Result};
use crate::release::{self, K3sVersion};
use crate::runner::{Cmd, LogFn, Runner};
use crate::sysconf::{self, Role};
use crate::{bail, errf, fsx};

/// pacman's list of servers; [core] and [extra] include it.
pub const MIRRORLIST: &str = "/etc/pacman.d/mirrorlist";
/// The list before the last change of the pinned day.
pub const MIRRORLIST_PREV: &str = "/etc/pacman.d/mirrorlist.prev";
pub const PACMAN_CONF: &str = "/etc/pacman.conf";
/// pacman holds this file while it changes the system, and leaves it
/// behind when it is killed.
pub const PACMAN_LOCK: &str = "/var/lib/pacman/db.lck";
const PACMAN_LOG: &str = "/var/log/pacman.log";
/// Where systemd-boot finds the kernel images it starts on UEFI machines
/// (the installer's UKI_PRESET): arch-KERNEL.efi for each kernel package
/// (arch-linux.efi, and the fallback arch-linux-lts.efi), each name also
/// with a systemd-boot boot counter (arch-linux+3.efi, arch-linux+2-1.efi).
/// BIOS machines boot /boot/vmlinuz-KERNEL with /boot/initramfs-KERNEL.img
/// through GRUB.
const UKI_DIR: &str = "/boot/EFI/Linux";
/// The kernels pacman installs: /usr/lib/modules/VERSION/vmlinuz, with the
/// name of its package in pkgbase next to it.
const MODULES: &str = "/usr/lib/modules";
/// The most entries looked at in MODULES and UKI_DIR.
const MAX_KERNELS: usize = 64;
/// FAT, the boot partition's file system, keeps times to two seconds.
const TIME_SLACK: Duration = Duration::from_secs(2);
/// What pacman prints when one of its hooks fails (mkinitcpio among
/// them). pacman still exits 0 after a failed hook that runs after the
/// transaction, so its output is the only sign.
const HOOK_FAILED: &str = "error: command failed to execute correctly";

pub const K3S_BIN: &str = crate::report::K3S_BIN;
/// The binary that ran before the last update, kept to go back to.
pub const K3S_PREV: &str = "/usr/local/bin/k3s.prev";
/// Temporary names next to the binary, so each rename stays on one file
/// system. None of them is ever the live binary, so leftovers from a
/// power cut are removed at the next start.
const K3S_NEW: &str = "/usr/local/bin/.k3s.dryserver-new";
const K3S_PREV_TMP: &str = "/usr/local/bin/.k3s.dryserver-prev";
const K3S_BACK: &str = "/usr/local/bin/.k3s.dryserver-back";
/// The largest k3s binary taken: about 70 MiB today, room to grow, and a
/// staged file of gigabytes is refused before it is read.
pub const MAX_K3S: u64 = 512 << 20;
const K3S_UNIT: &str = "k3s.service";
/// The kubelet inside k3s answers here, on loopback only.
const KUBELET_HEALTHZ: &str = "http://127.0.0.1:10248/healthz";

/// How much room and time an update gets. The default is what a machine
/// uses; tests shrink it.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Free bytes on / before pacman starts: downloads land in its cache
    /// there, and an upgrade unpacks each package next to the old files.
    pub min_free_root: u64,
    /// Free bytes on /boot: a new kernel image is written there.
    pub min_free_boot: u64,
    /// Refreshing the package lists and the signing keys.
    pub sync: Duration,
    /// Downloading the packages: may be stopped at any time without harm.
    pub download: Duration,
    /// Installing them from the cache: stopping it leaves a partly
    /// upgraded system, so it gets plenty.
    pub install: Duration,
    /// How long k3s may take to answer healthy after a restart. The
    /// control plane on a slow mini PC takes minutes, an agent less.
    pub k3s_ready_brain: Duration,
    pub k3s_ready_agent: Duration,
    /// How long k3s has to stay up once it answered: a binary that crashes
    /// a little later is restarted by systemd and would pass a single look.
    pub k3s_settle: Duration,
    pub k3s_poll: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            min_free_root: 2 << 30,
            min_free_boot: 200 << 20,
            sync: Duration::from_secs(10 * 60),
            download: Duration::from_secs(45 * 60),
            install: Duration::from_secs(30 * 60),
            k3s_ready_brain: Duration::from_secs(10 * 60),
            k3s_ready_agent: Duration::from_secs(5 * 60),
            k3s_settle: Duration::from_secs(30),
            k3s_poll: Duration::from_secs(5),
        }
    }
}

/// The machine being updated.
pub struct Host<'a> {
    /// "/" on a machine; a temporary directory in tests.
    pub root: PathBuf,
    pub run: &'a dyn Runner,
    /// The update's own log (the journal of update apply).
    pub log: LogFn,
    /// Who must own a staged binary and every directory above it: root.
    pub owner: u32,
    pub limits: Limits,
}

impl<'a> Host<'a> {
    /// This machine.
    pub fn new(run: &'a dyn Runner, log: LogFn) -> Host<'a> {
        Host { root: PathBuf::from("/"), run, log, owner: 0, limits: Limits::default() }
    }

    fn path(&self, p: &str) -> PathBuf {
        fsx::under(&self.root, p)
    }

    fn say(&self, msg: &str) {
        (self.log)(msg)
    }
}

// ---- the pinned snapshot ----

/// The mirrorlist that pins pacman to one snapshot day of the Arch
/// archive. The date is checked first: it becomes part of a URL pacman
/// fetches from, and nothing but a real YYYY/MM/DD may end up there.
pub fn mirrorlist(date: &str) -> Result<String> {
    release::arch_day(date)?;
    Ok(format!(
        "# dryserver: the Arch snapshot of {date}, from the release the admin signed.\n\
         # Every machine installs exactly these packages. Written by dryserver update.\n\
         Server = {}$repo/os/$arch\n",
        release::arch_url(date)
    ))
}

/// The snapshot day a mirrorlist pins pacman to: Some only for a list with
/// exactly one server, on the Arch archive, at a real date.
pub fn pinned_date(text: &str) -> Option<String> {
    let mut lines = text.lines().map(|l| l.split('#').next().unwrap_or("").trim()).filter(|l| !l.is_empty());
    let (one, more) = (lines.next()?, lines.next());
    if more.is_some() {
        return None;
    }
    let (key, value) = one.split_once('=')?;
    if key.trim() != "Server" {
        return None;
    }
    let date = value.trim().strip_prefix(release::ARCH_ARCHIVE)?.strip_suffix("/$repo/os/$arch")?;
    release::arch_day(date).ok()?;
    Some(date.to_string())
}

impl Host<'_> {
    /// Pins pacman to date. The list it replaces is kept as
    /// MIRRORLIST_PREV. Writing the list that is already there changes
    /// nothing, so a retry keeps the real previous one. Returns whether the
    /// list changed.
    pub fn pin_snapshot(&self, date: &str) -> Result<bool> {
        let new = mirrorlist(date)?;
        let path = self.path(MIRRORLIST);
        let cur = match fs::read(&path) {
            Ok(b) => Some(b),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(Error::from(e).wrap(format!("open {}", path.display()))),
        };
        if cur.as_deref() == Some(new.as_bytes()) {
            return Ok(false);
        }
        fsx::mkdir_all(fsx::dir(&path), 0o755)?;
        if let Some(cur) = cur {
            write_atomic(&self.path(MIRRORLIST_PREV), &cur, 0o644)?;
        }
        write_atomic(&path, new.as_bytes(), 0o644)?;
        Ok(true)
    }

    /// Puts the list from before the last pin back. That changes only
    /// where pacman looks next: the packages stay as they are (going back
    /// on packages is a signed rollback). Returns the day the restored list
    /// pins, when it pins one.
    pub fn unpin_snapshot(&self) -> Result<Option<String>> {
        let prev = fsx::read(self.path(MIRRORLIST_PREV)).map_err(|e| e.wrap("no previous mirrorlist to go back to"))?;
        write_atomic(&self.path(MIRRORLIST), &prev, 0o644)?;
        Ok(pinned_date(&String::from_utf8_lossy(&prev)))
    }
}

// ---- checks before pacman runs ----

/// The largest pacman.conf (or file it includes) read.
const MAX_CONF: u64 = 1 << 20;
const MAX_INCLUDE_DEPTH: u32 = 8;

/// What one SigLevel value does to package signatures.
#[derive(Debug, PartialEq, Eq)]
enum Sig {
    /// Lets an unsigned package, or one signed by a key nobody trusts,
    /// through.
    Weak,
    Required,
    /// About databases only, or the default trust.
    Neutral,
}

/// A SigLevel value as pacman reads it. Unprefixed values apply to
/// packages and databases alike. None for a value pacman does not know.
fn package_sig(value: &str) -> Option<Sig> {
    let (packages, rest) = match (value.strip_prefix("Package"), value.strip_prefix("Database")) {
        (Some(r), _) => (true, r),
        (None, Some(r)) => (false, r),
        (None, None) => (true, value),
    };
    if !matches!(rest, "Never" | "Optional" | "Required" | "TrustedOnly" | "TrustAll") {
        return None;
    }
    Some(match rest {
        _ if !packages => Sig::Neutral,
        "Never" | "Optional" | "TrustAll" => Sig::Weak,
        "Required" => Sig::Required,
        _ => Sig::Neutral,
    })
}

#[derive(Default)]
struct ConfScan {
    section: String,
    /// [options] has a SigLevel with Required for packages.
    required: bool,
    problems: Vec<String>,
    warnings: Vec<String>,
    /// Repositories with servers of their own, not from the mirrorlist.
    own_servers: BTreeMap<String, usize>,
}

impl Host<'_> {
    /// Reads pacman.conf the way pacman does (Include files in place) and
    /// refuses a configuration that weakens package signature checks: a
    /// SigLevel of Never, Optional or TrustAll for packages, globally or
    /// for one repository, or no global SigLevel with Required at all
    /// (pacman's built-in default is Optional; Arch ships "Required
    /// DatabaseOptional"). Database settings are left alone: Arch signs
    /// every package, not its databases. LocalFileSigLevel only concerns
    /// `pacman -U`, which an update never runs.
    ///
    /// Returns warnings about what does not weaken signatures but works
    /// against the update: packages pacman leaves out, and repositories
    /// with servers outside the pinned snapshot.
    pub fn check_pacman_conf(&self) -> Result<Vec<String>> {
        let mut s = ConfScan::default();
        self.scan_conf(PACMAN_CONF, &mut s, 0);
        if !s.required {
            s.problems
                .push(format!("{PACMAN_CONF} has no SigLevel with Required in [options]: pacman's own default lets unsigned packages in"));
        }
        if !s.problems.is_empty() {
            bail!("package signature checks are weakened, so nothing is installed: {}", s.problems.join("; "));
        }
        for (repo, n) in &s.own_servers {
            s.warnings.push(format!("repository [{repo}] has {n} server line(s) of its own: its packages are not pinned to the snapshot"));
        }
        Ok(s.warnings)
    }

    fn scan_conf(&self, file: &str, s: &mut ConfScan, depth: u32) {
        if depth > MAX_INCLUDE_DEPTH {
            s.problems.push(format!("{file}: Include nested more than {MAX_INCLUDE_DEPTH} deep"));
            return;
        }
        let text = match read_capped(&self.path(file), MAX_CONF) {
            Ok(t) => t,
            Err(e) => {
                s.problems.push(format!("cannot read {file}: {e}"));
                return;
            }
        };
        for (n, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                s.section = name.trim().to_string();
                continue;
            }
            let (key, value) = line.split_once('=').map(|(k, v)| (k.trim(), v.trim())).unwrap_or((line, ""));
            let at = format!("{file} line {}", n + 1);
            match key {
                "SigLevel" => {
                    for v in value.split_whitespace() {
                        match package_sig(v) {
                            Some(Sig::Weak) => s.problems.push(format!("{at}: SigLevel {} in [{}]", show(v), show(&s.section))),
                            Some(Sig::Required) if s.section == "options" => s.required = true,
                            Some(_) => {}
                            None => s.problems.push(format!("{at}: SigLevel {} is not a value pacman knows", show(v))),
                        }
                    }
                }
                "Include" if value.contains(['*', '?', '[']) || !value.starts_with('/') => {
                    s.problems.push(format!("{at}: Include {} cannot be checked (a pattern or a relative path)", show(value)));
                }
                "Include" => self.scan_conf(value, s, depth + 1),
                "Server" if s.section != "options" && file != MIRRORLIST => *s.own_servers.entry(s.section.clone()).or_default() += 1,
                "IgnorePkg" | "IgnoreGroup" if s.section == "options" && !value.is_empty() => {
                    s.warnings.push(format!("{at}: {key} = {}: pacman leaves these out of every update, security fixes too", show(value)));
                }
                _ => {}
            }
        }
    }

    /// /boot is its own partition. When it is not mounted, pacman puts the
    /// new kernel into the empty directory under it, the boot loader keeps
    /// starting the old kernel, and that kernel finds its modules gone: no
    /// network, no WireGuard.
    fn check_boot_mounted(&self) -> Result<()> {
        let listed = |p: &str| fsx::read_or_empty(self.path(p)).lines().any(|l| mount_point(l) == Some("/boot"));
        if listed("/etc/fstab") && !listed("/proc/self/mounts") {
            bail!("/boot is not mounted: a new kernel would land beside the boot partition, not on it. Mount it (mount /boot) first");
        }
        Ok(())
    }

    fn check_space(&self) -> Result<()> {
        for (dir, min) in [("/", self.limits.min_free_root), ("/boot", self.limits.min_free_boot)] {
            let free = free_bytes(&self.path(dir)).map_err(|e| e.wrap(format!("free space on {dir}")))?;
            if free < min {
                bail!(
                    "only {} MiB free on {dir}, an update needs {} MiB: make room first (old packages in /var/cache/pacman/pkg go with pacman -Sc)",
                    free >> 20,
                    min >> 20
                );
            }
        }
        Ok(())
    }

    /// pacman's lock. Held by a running pacman: refused, it is busy. Left
    /// by a pacman that was killed (a power cut, a timeout) when none runs:
    /// cleared, since pacman refuses to start while it exists, and said
    /// so. Returns that message.
    fn check_lock(&self) -> Result<Option<String>> {
        let lock = self.path(PACMAN_LOCK);
        if fs::symlink_metadata(&lock).is_err() {
            return Ok(None);
        }
        let pids = self.pacman_pids();
        if !pids.is_empty() {
            let pids: Vec<String> = pids.iter().map(u32::to_string).collect();
            bail!("pacman is already running (pid {}) and holds {PACMAN_LOCK}: the next run tries again", pids.join(", "));
        }
        let msg = format!("removed the stale pacman lock {PACMAN_LOCK}: no pacman runs (one was stopped part way?)");
        self.say(&msg);
        fsx::remove(&lock)?;
        Ok(Some(msg))
    }

    fn pacman_pids(&self) -> Vec<u32> {
        let Ok(dir) = fs::read_dir(self.path("/proc")) else {
            return Vec::new();
        };
        let mut pids: Vec<u32> = dir
            .flatten()
            .filter_map(|e| {
                let pid = e.file_name().to_str()?.parse().ok()?;
                (fsx::read_or_empty(e.path().join("comm")).trim() == "pacman").then_some(pid)
            })
            .collect();
        pids.sort_unstable();
        pids
    }
}

fn mount_point(line: &str) -> Option<&str> {
    let l = line.trim();
    if l.starts_with('#') { None } else { l.split_whitespace().nth(1) }
}

/// Bytes an ordinary writer may still use on the file system holding path.
fn free_bytes(path: &Path) -> Result<u64> {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| errf!("{} has a NUL byte", path.display()))?;
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: c is a NUL-terminated string and st points to room for one
    // statvfs, which the call fills when it returns 0.
    if unsafe { libc::statvfs(c.as_ptr(), st.as_mut_ptr()) } != 0 {
        return Err(Error::from(io::Error::last_os_error()).wrap(format!("statvfs {}", path.display())));
    }
    // SAFETY: statvfs returned 0, so it filled st.
    let st = unsafe { st.assume_init() };
    Ok(st.f_bavail.saturating_mul(st.f_frsize))
}

fn read_capped(path: &Path, max: u64) -> Result<String> {
    let f = File::open(path).map_err(|e| Error::from(e).wrap(format!("open {}", path.display())))?;
    let mut b = Vec::new();
    f.take(max + 1).read_to_end(&mut b).map_err(|e| Error::from(e).wrap(format!("read {}", path.display())))?;
    if b.len() as u64 > max {
        bail!("{} is larger than {max} bytes", path.display());
    }
    Ok(String::from_utf8_lossy(&b).into_owned())
}

// ---- the Arch update ----

/// How far an Arch update got before it failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Refused before anything changed.
    Refused,
    /// Refreshing the package lists and the signing keys: nothing else
    /// was installed.
    Sync,
    /// Downloading: nothing was installed.
    Download,
    /// Installing: pacman stopped part way, the system may be partly
    /// upgraded. The next run finishes it.
    Install,
}

#[derive(Debug, Clone)]
pub struct Failure {
    pub stage: Stage,
    pub reason: Error,
}

/// One line of pacman's log: "upgraded openssh 9.9p1-1 -> 9.9p1-2".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// installed, upgraded, downgraded, reinstalled or removed.
    pub action: String,
    pub name: String,
    pub version: String,
}

/// What an Arch update did.
#[derive(Debug, Clone, Default)]
pub struct ArchOutcome {
    /// The snapshot day asked for, and the one pinned before (None when
    /// the mirrorlist did not pin one, as after an install).
    pub date: String,
    pub previous: Option<String>,
    /// pacman ran with -uu: packages could go back to the older snapshot.
    pub downgrade: bool,
    /// How many packages changed, from pacman's log; `changes` lists at
    /// most MAX_CHANGES of them.
    pub count: usize,
    pub changes: Vec<Change>,
    /// The running kernel's modules are gone (a new kernel is installed):
    /// decided like the health report does.
    pub kernel_replaced: bool,
    /// Changed packages whose new code running programs only get through a
    /// restart (in practice a reboot): glibc, systemd, OpenSSH...
    pub restart: Vec<String>,
    /// Why a reboot now would not be safe, even after a successful run: a
    /// boot image that was not made again, a failed pacman hook.
    pub boot_problem: Option<String>,
    /// New .pacnew and .pacsave files: reported, never merged here.
    pub pacnew: Vec<String>,
    pub warnings: Vec<String>,
    pub failure: Option<Failure>,
    /// The end of the output of the pacman run that failed.
    pub tail: String,
}

/// The most changes listed one by one.
pub const MAX_CHANGES: usize = 2000;
/// The most of pacman's log read back after a run.
const MAX_LOG_READ: u64 = 8 << 20;
/// The most files looked at for .pacnew files.
const MAX_SCAN: usize = 50_000;
/// Packages whose new code reaches running programs only by a restart:
/// the kernel and what it loads at boot, the C library, systemd and D-Bus
/// that everything talks to, OpenSSL and OpenSSH's server.
const RESTART_PACKAGES: [&str; 10] =
    ["linux", "linux-firmware", "intel-ucode", "amd-ucode", "glibc", "systemd", "dbus", "dbus-broker", "openssl", "openssh"];

impl ArchOutcome {
    pub fn ok(&self) -> bool {
        self.failure.is_none()
    }

    /// Only a reboot starts the new code: a new kernel, or a package from
    /// RESTART_PACKAGES.
    pub fn reboot_needed(&self) -> bool {
        self.kernel_replaced || !self.restart.is_empty()
    }

    /// A reboot now leaves a machine that starts: pacman finished and the
    /// boot image was made again. After a failed run, never: the next run
    /// has to finish what pacman started.
    pub fn reboot_safe(&self) -> bool {
        self.failure.is_none() && self.boot_problem.is_none()
    }

    /// One line for the log and the report.
    pub fn summary(&self) -> String {
        let mut s = match &self.failure {
            Some(f) if f.stage == Stage::Refused => format!("Arch {}: refused: {}", show(&self.date), f.reason),
            Some(f) => format!("Arch {}: {} package(s) changed, then failed: {}", show(&self.date), self.count, f.reason),
            None => format!("Arch {}: {} package(s) changed", self.date, self.count),
        };
        if self.downgrade {
            s += ", rollback";
        }
        if self.reboot_needed() {
            s += if self.reboot_safe() { ", reboot needed" } else { ", reboot needed but NOT safe yet" };
        }
        if let Some(p) = &self.boot_problem {
            s += &format!(" ({p})");
        }
        if !self.pacnew.is_empty() {
            s += &format!(", new config files to merge by hand: {}", self.pacnew.join(" "));
        }
        s
    }
}

impl Host<'_> {
    /// Updates Arch Linux to the snapshot of date (YYYY/MM/DD), from a
    /// signed release; rollback is the release's flag.
    ///
    /// The steps:
    /// - refuse a malformed date, an older day than the pinned one without
    ///   rollback, weakened signatures, an unmounted /boot, too little
    ///   space, a running pacman; clear a stale lock;
    /// - pin the mirrorlist to the day (the old list kept);
    /// - `pacman -Syy`: the lists of exactly that day. Forced, since pacman
    ///   otherwise keeps lists that look newer than the snapshot's (after
    ///   the install, or going back), and would ask for packages the
    ///   snapshot does not have;
    /// - the signing keys first (`pacman -S --needed archlinux-keyring`),
    ///   so packages signed by new keys pass, but only when the snapshot's
    ///   keyring is newer (`pacman -Qu`): -S installs the snapshot's
    ///   version even when it is older, and an older keyring would trust
    ///   again keys revoked since. Never when going back, for that reason;
    /// - `pacman -Suw`: download only, safe to stop when the network is
    ///   slow;
    /// - `pacman -Su`: install from the cache. With rollback and an older
    ///   (or the same) day, -Suu lets packages downgrade, all but the
    ///   signing keys;
    /// - read back what changed, new .pacnew files, whether the kernel was
    ///   replaced and whether its boot image was made again.
    pub fn arch_update(&self, ctx: &Ctx, date: &str, rollback: bool) -> ArchOutcome {
        let mut out = ArchOutcome { date: date.to_string(), ..ArchOutcome::default() };
        if let Err(e) = self.arch_checks(date, rollback, &mut out) {
            out.failure = Some(Failure { stage: Stage::Refused, reason: e });
            self.say(&out.summary());
            return out;
        }
        let before = self.pacnew_files();
        let offset = fs::metadata(self.path(PACMAN_LOG)).map(|m| m.len()).unwrap_or(0);
        if let Err(e) = self.pin_snapshot(date) {
            out.failure = Some(Failure { stage: Stage::Refused, reason: e.wrap("pin the snapshot") });
            self.say(&out.summary());
            return out;
        }
        self.say(&format!("Arch: pacman now reads the snapshot of {date}{}", if out.downgrade { " (rollback)" } else { "" }));
        let mut hook_failed = false;
        let res = self.pacman_steps(ctx, &mut out, &mut hook_failed);
        out.failure = res.err();
        (out.count, out.changes) = self.changes_since(offset);
        out.restart = restart_packages(&out.changes);
        out.kernel_replaced = kernel_replaced(&self.root);
        let after = self.pacnew_files();
        out.pacnew = after.iter().filter(|(p, t)| before.get(*p) != Some(t)).map(|(p, _)| p.clone()).collect();
        let kernels = self.kernels();
        let kernel_changed = out.kernel_replaced
            || out
                .changes
                .iter()
                .any(|c| c.action != "removed" && (KERNEL_PACKAGES.contains(&c.name.as_str()) || kernels.contains_key(&c.name)));
        out.boot_problem = self.boot_problem(hook_failed, kernel_changed, &kernels);
        if out.failure.is_none() {
            // Old packages pile up in the cache with every update until the
            // disk is full; the archive keeps them for a rollback.
            let tctx = ctx.with_timeout(self.limits.sync);
            if let Err(e) = self.run.ok(&tctx, &pacman(&["-Sc", "--noconfirm"])) {
                out.warnings.push(format!("cleaning the package cache failed: {e}"));
            }
        }
        self.say(&out.summary());
        out
    }

    fn arch_checks(&self, date: &str, rollback: bool, out: &mut ArchOutcome) -> Result<()> {
        let day = release::arch_day(date)?;
        let current = fsx::read_or_empty(self.path(MIRRORLIST));
        out.previous = pinned_date(&current);
        match &out.previous {
            Some(prev) => {
                let prev_day = release::arch_day(prev)?;
                if day < prev_day && !rollback {
                    bail!("Arch snapshot {date} is older than the pinned {prev}, and the release is not a rollback");
                }
                // The same day with rollback: a rollback that failed part
                // way is tried again, downgrades included.
                out.downgrade = rollback && day <= prev_day;
            }
            None => {
                if !current.trim().is_empty() {
                    out.warnings.push(format!("{MIRRORLIST} did not pin a snapshot day: from now on it does"));
                }
                out.downgrade = rollback;
            }
        }
        out.warnings.extend(self.check_pacman_conf()?);
        self.check_boot_mounted()?;
        self.check_space()?;
        if let Some(w) = self.check_lock()? {
            out.warnings.push(w);
        }
        Ok(())
    }

    fn pacman_steps(&self, ctx: &Ctx, out: &mut ArchOutcome, hook_failed: &mut bool) -> Result<(), Failure> {
        let (u, rest): (&str, &[&str]) =
            if out.downgrade { ("uu", &["--noconfirm", "--ignore", "archlinux-keyring"]) } else { ("u", &["--noconfirm"]) };
        self.pacman_step(ctx, Stage::Sync, &["-Syy", "--noconfirm"], self.limits.sync, out, hook_failed)?;
        if !out.downgrade {
            // Prints the keyring only when the snapshot has a newer one.
            let newer = self.run.output(&ctx.with_timeout(self.limits.sync), &pacman(&["-Qu", "archlinux-keyring"]).quiet());
            if newer.is_ok_and(|o| o.contains("archlinux-keyring")) {
                self.pacman_step(
                    ctx,
                    Stage::Sync,
                    &["-S", "--needed", "--noconfirm", "archlinux-keyring"],
                    self.limits.sync,
                    out,
                    hook_failed,
                )?;
            }
        }
        let (download, install) = (format!("-S{u}w"), format!("-S{u}"));
        let mut args = vec![download.as_str()];
        args.extend(rest);
        self.pacman_step(ctx, Stage::Download, &args, self.limits.download, out, hook_failed)?;
        args[0] = install.as_str();
        self.pacman_step(ctx, Stage::Install, &args, self.limits.install, out, hook_failed)
    }

    fn pacman_step(
        &self,
        ctx: &Ctx,
        stage: Stage,
        args: &[&str],
        limit: Duration,
        out: &mut ArchOutcome,
        hook_failed: &mut bool,
    ) -> Result<(), Failure> {
        let tctx = ctx.with_timeout(limit);
        let (o, res) = self.run.run(&tctx, &pacman(args));
        *hook_failed |= o.contains(HOOK_FAILED);
        let Err(e) = res else {
            return Ok(());
        };
        out.tail = tail(&o);
        let e = if ctx.done() {
            e.wrap("the update was stopped")
        } else if tctx.done() {
            errf!("pacman ran longer than {} and was stopped ({e}); the lock it leaves is cleared at the next run", took(limit))
        } else {
            e
        };
        let problem = pacman_problem(&o);
        let reason = match stage {
            Stage::Install => errf!(
                "pacman stopped part way ({problem}): the system may be partly upgraded. Do not reboot; the next run tries again: {e}"
            ),
            Stage::Sync => errf!("refreshing the package lists of {} failed ({problem}); nothing was installed: {e}", out.date),
            _ => errf!("downloading the packages failed ({problem}); nothing was installed: {e}"),
        };
        Err(Failure { stage, reason })
    }

    /// What changed, from what pacman wrote to its log since offset. pacman
    /// logs in English whatever the locale.
    fn changes_since(&self, offset: u64) -> (usize, Vec<Change>) {
        let Ok(mut f) = File::open(self.path(PACMAN_LOG)) else {
            return (0, Vec::new());
        };
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        // A log that shrank was rotated: all of it is new.
        let from = if len < offset { 0 } else { offset }.max(len.saturating_sub(MAX_LOG_READ));
        let mut b = Vec::new();
        if f.seek(SeekFrom::Start(from)).is_err() || f.take(MAX_LOG_READ).read_to_end(&mut b).is_err() {
            return (0, Vec::new());
        }
        parse_changes(&String::from_utf8_lossy(&b))
    }

    /// .pacnew and .pacsave files under /etc with their change times: a new
    /// one, or one pacman wrote again, shows up in the difference.
    fn pacnew_files(&self) -> BTreeMap<String, SystemTime> {
        let mut found = BTreeMap::new();
        let mut seen = 0;
        let mut stack = vec![(self.path("/etc"), 0u32)];
        while let Some((dir, depth)) = stack.pop() {
            let Ok(rd) = fs::read_dir(&dir) else {
                continue;
            };
            for e in rd.flatten() {
                seen += 1;
                if seen > MAX_SCAN {
                    return found;
                }
                let Ok(t) = e.file_type() else {
                    continue;
                };
                if t.is_dir() && depth < 16 {
                    stack.push((e.path(), depth + 1));
                    continue;
                }
                let name = e.file_name().to_string_lossy().into_owned();
                if t.is_file() && (name.ends_with(".pacnew") || name.ends_with(".pacsave") || name.contains(".pacsave.")) {
                    let p = e.path();
                    let shown = format!("/{}", p.strip_prefix(&self.root).unwrap_or(&p).display());
                    let when = e.metadata().and_then(|m| m.modified()).unwrap_or(SystemTime::UNIX_EPOCH);
                    found.insert(printable(&shown), when);
                }
            }
        }
        found
    }

    /// Why rebooting now would not start this machine again, if anything
    /// says so: a failed pacman hook (mkinitcpio is one), or a kernel whose
    /// boot image was not made again after the kernel was put on disk.
    ///
    /// A boot image is current when it was written after its kernel: its
    /// modification time is at least the change time of the newest
    /// MODULES/*/vmlinuz of that kernel package (pacman sets the change
    /// time when it unpacks the file; the modification time it keeps is
    /// the package's build time). That stays true for every later run, so a
    /// machine that waits for its reboot is not called unsafe because a
    /// second run had no reason to build the image again. Every kernel
    /// package on disk is looked at, the fallback kernel too; of the images
    /// of one kernel (boot counter names) the newest counts.
    fn boot_problem(&self, hook_failed: bool, kernel_changed: bool, kernels: &BTreeMap<String, SystemTime>) -> Option<String> {
        if hook_failed {
            return Some(
                "a pacman hook failed, maybe the one that builds the boot image: reboot only after mkinitcpio -P ran cleanly".into(),
            );
        }
        if !kernel_changed {
            return None;
        }
        let written = |p: &Path| fs::metadata(p).and_then(|m| m.modified()).ok();
        let stale = |base: &str, p: &str| {
            format!("the kernel {base} changed but {p} was not made again: the machine would start a kernel without its modules")
        };
        let uefi = self.path(UKI_DIR).is_dir();
        for (base, put) in kernels {
            let current = |t: Option<SystemTime>| t.is_some_and(|t| t + TIME_SLACK >= *put);
            let bios = [format!("/boot/vmlinuz-{base}"), format!("/boot/initramfs-{base}.img")];
            if !uefi {
                if let Some(p) = bios.iter().find(|p| !current(written(&self.path(p)))) {
                    return Some(stale(base, p));
                }
                continue;
            }
            // mkinitcpio builds the image from /boot/vmlinuz-KERNEL when the
            // preset says so: that copy must be the new kernel too.
            let copy = &bios[0];
            if self.path(copy).exists() && !current(written(&self.path(copy))) {
                return Some(stale(base, copy));
            }
            match self.boot_images(base).into_iter().max_by_key(|(_, t)| *t) {
                None => return Some(format!("there is no boot image for the kernel {base} in {UKI_DIR}: the machine would not start it")),
                Some((name, t)) if !current(Some(t)) => return Some(stale(base, &format!("{UKI_DIR}/{name}"))),
                Some(_) => {}
            }
        }
        None
    }

    /// The kernel packages on disk, each with the time its newest vmlinuz
    /// was put there.
    fn kernels(&self) -> BTreeMap<String, SystemTime> {
        let mut found: BTreeMap<String, SystemTime> = BTreeMap::new();
        let Ok(rd) = fs::read_dir(self.path(MODULES)) else {
            return found;
        };
        for e in rd.flatten().take(MAX_KERNELS) {
            let Ok(md) = fs::symlink_metadata(e.path().join("vmlinuz")) else {
                continue;
            };
            if !md.is_file() {
                continue;
            }
            let base = read_capped(&e.path().join("pkgbase"), 256).unwrap_or_default().trim().to_string();
            let base = if kernel_name(&base) { base } else { "linux".to_string() };
            let at = changed_at(&md);
            let slot = found.entry(base).or_insert(at);
            *slot = (*slot).max(at);
        }
        found
    }

    /// The boot images of the kernel package base in UKI_DIR, by name, with
    /// the time each was written.
    fn boot_images(&self, base: &str) -> Vec<(String, SystemTime)> {
        let Ok(rd) = fs::read_dir(self.path(UKI_DIR)) else {
            return Vec::new();
        };
        rd.flatten()
            .take(MAX_KERNELS)
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                if uki_kernel(&name)? != base {
                    return None;
                }
                let md = fs::symlink_metadata(e.path()).ok().filter(|m| m.is_file())?;
                Some((name, md.modified().ok()?))
            })
            .collect()
    }

    /// Why this machine cannot reboot by itself, or None when it can. A
    /// disk that asks for its passphrase at boot waits for someone at the
    /// keyboard. A disk the TPM unlocks can, once the TPM is enrolled (the
    /// first boot takes the passphrase and removes its one-time key); so
    /// can one that is not encrypted.
    pub fn reboot_blocker(&self) -> Option<String> {
        let crypttab = fsx::read_or_empty(self.path("/etc/crypttab"));
        let line = crypttab.lines().find(|l| l.split_whitespace().next() == Some(crate::install::ROOT_MAPPER))?;
        if !line.contains("tpm2-device=") {
            return Some("the disk asks for its passphrase at every boot: reboot it by hand".into());
        }
        if fs::symlink_metadata(self.path(crate::install::FIRST_BOOT_KEY)).is_ok() {
            return Some("the TPM does not unlock the disk yet (its first boot is still to come): reboot it by hand".into());
        }
        None
    }
}

/// pacman in the C locale: its messages are matched (hook failures, the
/// reason a run failed).
fn pacman(args: &[&str]) -> Cmd {
    let mut c = Cmd::new("pacman", args);
    c.env.push("LC_ALL=C".into());
    c
}

/// The kernel packages a machine may boot: the kernel, and the fallback.
const KERNEL_PACKAGES: [&str; 2] = ["linux", "linux-lts"];

/// A kernel package name as pkgbase gives it.
fn kernel_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The kernel package a boot image in UKI_DIR belongs to, from its name:
/// arch-KERNEL.efi, arch-KERNEL+N.efi or arch-KERNEL+N-M.efi (the boot
/// counter systemd-boot keeps in the name: N tries left, M used).
fn uki_kernel(name: &str) -> Option<&str> {
    let s = name.strip_prefix("arch-")?.strip_suffix(".efi")?;
    let digits = |x: &str| !x.is_empty() && x.len() <= 6 && x.bytes().all(|b| b.is_ascii_digit());
    let base = match s.split_once('+') {
        None => s,
        Some((base, counter)) => {
            let ok = match counter.split_once('-') {
                Some((left, used)) => digits(left) && digits(used),
                None => digits(counter),
            };
            if !ok {
                return None;
            }
            base
        }
    };
    kernel_name(base).then_some(base)
}

/// When a file was put in place or last changed on this machine: its
/// change time, which only the kernel sets (unpacking a package keeps the
/// package's modification times).
fn changed_at(md: &fs::Metadata) -> SystemTime {
    match u64::try_from(md.ctime()) {
        Ok(secs) => SystemTime::UNIX_EPOCH + Duration::new(secs, md.ctime_nsec().clamp(0, 999_999_999) as u32),
        Err(_) => SystemTime::UNIX_EPOCH,
    }
}

/// Whether the running kernel was replaced, the way report.rs decides it:
/// the package that installed a newer kernel took the running one's
/// directory (/usr/lib/modules/VERSION/vmlinuz) with it. Without any
/// kernel there (a container) it was not.
fn kernel_replaced(root: &Path) -> bool {
    let running = fsx::read_or_empty(fsx::under(root, "/proc/sys/kernel/osrelease")).trim().to_string();
    if running.is_empty() || running.contains('/') {
        return false;
    }
    let modules = fsx::under(root, "/usr/lib/modules");
    if modules.join(&running).join("vmlinuz").is_file() {
        return false;
    }
    fs::read_dir(&modules).map(|d| d.flatten().take(64).any(|e| e.path().join("vmlinuz").is_file())).unwrap_or(false)
}

/// The changes in pacman log lines like
/// "[2026-11-20T09:14:02+0100] [ALPM] upgraded linux (6.12.1-1 -> 6.12.4-1)".
fn parse_changes(text: &str) -> (usize, Vec<Change>) {
    let word = |s: &str| !s.is_empty() && s.len() <= 128 && s.chars().all(|c| c.is_ascii_alphanumeric() || "@._+-".contains(c));
    let mut n = 0;
    let mut list = Vec::new();
    for line in text.lines() {
        let Some((_, rest)) = line.split_once("] [ALPM] ") else {
            continue;
        };
        let mut w = rest.splitn(3, ' ');
        let (Some(action), Some(name)) = (w.next(), w.next()) else {
            continue;
        };
        if !matches!(action, "installed" | "upgraded" | "downgraded" | "reinstalled" | "removed") || !word(name) {
            continue;
        }
        let version = w.next().unwrap_or("").trim().trim_start_matches('(').trim_end_matches(')');
        if version.len() > 128 || !version.chars().all(|c| c.is_ascii_alphanumeric() || " .:+-_>~".contains(c)) {
            continue;
        }
        n += 1;
        if list.len() < MAX_CHANGES {
            list.push(Change { action: action.into(), name: name.into(), version: version.into() });
        }
    }
    (n, list)
}

fn restart_packages(changes: &[Change]) -> Vec<String> {
    let mut v: Vec<String> = changes
        .iter()
        .filter(|c| matches!(c.action.as_str(), "upgraded" | "downgraded" | "installed"))
        .filter(|c| RESTART_PACKAGES.contains(&c.name.as_str()) || c.name.starts_with("linux-firmware-"))
        .map(|c| c.name.clone())
        .collect();
    v.sort();
    v.dedup();
    v
}

/// Why pacman failed, in a few words, from its output.
fn pacman_problem(out: &str) -> &'static str {
    let has = |s: &str| out.contains(s);
    if has("exists in filesystem") {
        "files on disk that belong to no package are in the way; dryserver never overwrites them: look at the files pacman names"
    } else if has("unable to lock database") {
        "another pacman holds the lock"
    } else if has("signature") || has("PGP") {
        "a package signature did not check out"
    } else if has("failed retrieving file") || has("failed to synchronize") || has("Could not resolve host") || has("too slow") {
        "downloads failed, the Arch archive may be slow or down"
    } else if has("not enough free disk space") || has("No space left on device") {
        "the disk is full"
    } else if has("could not satisfy dependencies") {
        "a dependency is missing from the snapshot"
    } else if has("conflict") {
        "packages conflict"
    } else {
        "see the log"
    }
}

/// The last lines of a command's output, at most about 4 KiB.
fn tail(out: &str) -> String {
    let lines: Vec<&str> = out.lines().filter(|l| !l.trim().is_empty()).collect();
    let mut t = lines[lines.len().saturating_sub(20)..].join("\n");
    if t.len() > 4096 {
        let mut cut = t.len() - 4096;
        while !t.is_char_boundary(cut) {
            cut += 1;
        }
        t = t[cut..].to_string();
    }
    printable(&t)
}

fn took(d: Duration) -> String {
    if d.as_secs() >= 60 { format!("{} minutes", d.as_secs() / 60) } else { format!("{} seconds", d.as_secs()) }
}

// ---- the k3s binary ----

/// How a k3s update ended, when it got as far as changing the binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum K3sOutcome {
    /// The new binary runs and k3s answers healthy.
    Running,
    /// The new binary is in place, k3s was not started: the kill switch
    /// holds it on this machine, or the machine has no cluster token. It
    /// runs once k3s may start again.
    Placed { why: String },
    /// The new binary did not come up healthy; the previous one is back
    /// and healthy.
    Reverted { why: String },
    /// Neither came up healthy, or the previous one could not be put back:
    /// the admin has to look. why is the new binary's failure, revert the
    /// previous one's.
    Broken { why: String, revert: String, left: Left },
}

/// Which binary a broken k3s update leaves in place.
///
/// When the previous binary does not come up healthy either, it stays:
/// it ran before, it is what the machine's installed release names (the
/// next update starts from a state that matches its record), and a
/// failure with both binaries points at something else (the brain down,
/// the network) that k3s rides out on its own, restarting every few
/// seconds. The new one stays only when there is nothing to go back to.
/// Either way the machine stays reachable: SSH and WireGuard do not
/// depend on k3s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Left {
    New,
    Previous,
}

impl Host<'_> {
    /// Installs the k3s binary the release names (sha256, version) from
    /// staged, a file in a staging directory only root can change, on a
    /// machine with this role, and restarts k3s with it.
    ///
    /// Err means it was refused and nothing changed: a staged file in the
    /// wrong place, too large or with another checksum, or a binary that
    /// says it is another version than the release does (the version skew
    /// rules go by the release's word). Otherwise the K3sOutcome says how
    /// it ended.
    ///
    /// The swap, each step safe to cut the power after:
    /// 1. copy to a temporary name next to the binary, flushed to disk,
    ///    and checked again there: what is renamed into place is exactly
    ///    what was checked;
    /// 2. hard link the current binary to k3s.prev (one rename replaces
    ///    the older k3s.prev);
    /// 3. rename the copy over the binary.
    ///
    /// A run that finds the new binary already in place (the power went
    /// after step 3) keeps k3s.prev as it is and goes on with the restart.
    pub fn k3s_install(&self, ctx: &Ctx, staged: &Path, sha256: &str, version: &str, role: Role) -> Result<K3sOutcome> {
        if !release::is_sha256(sha256) {
            bail!("{} is not a sha256 of 64 lowercase hex digits", show(sha256));
        }
        K3sVersion::parse(version)?;
        let size = self.check_staged(staged)?;
        release::verify_file(staged, sha256, size).map_err(|e| e.wrap("staged k3s"))?;
        let bin = self.path(K3S_BIN);
        self.clean_k3s_temps();
        if release::hash_file(&bin, MAX_K3S).is_ok_and(|(h, _)| h == sha256) {
            self.say(&format!("k3s {version} is in place already (an earlier run stopped before its health check)"));
            self.check_version(ctx, &bin, version)?;
        } else {
            self.stage_k3s(ctx, staged, sha256, size, version)?;
            self.keep_prev()?;
            fsx::rename(self.path(K3S_NEW), &bin)?;
            sync_dir(&bin)?;
            self.say(&format!("k3s {version} is in place, the previous binary kept as {K3S_PREV}"));
        }
        if let Some(why) = self.k3s_blocked(role) {
            self.say(&format!("k3s {version}: not started: {why}"));
            return Ok(K3sOutcome::Placed { why });
        }
        let outcome = match self.k3s_restart(ctx, role) {
            Ok(()) => K3sOutcome::Running,
            // Stopped (the update service was stopped): a revert could not
            // finish its own check either. The new binary stays; the next
            // run finds it in place and checks it, as after a power cut.
            Err(why) if ctx.done() => K3sOutcome::Broken {
                why: why.to_string(),
                revert: "the update was stopped before k3s was checked; the next run checks it again".into(),
                left: Left::New,
            },
            Err(why) => self.k3s_revert(ctx, role, sha256, why),
        };
        match &outcome {
            K3sOutcome::Running => self.say(&format!("k3s {version} runs and is healthy")),
            K3sOutcome::Reverted { why } => {
                self.say(&format!("k3s {version} was not healthy ({why}); the previous binary is back and healthy"))
            }
            K3sOutcome::Broken { why, revert, left } => self.say(&format!(
                "K3S BROKEN: k3s {version} was not healthy ({why}), and going back failed ({revert}); left in place: the {} binary",
                if *left == Left::New { "new" } else { "previous" }
            )),
            K3sOutcome::Placed { .. } => {}
        }
        Ok(outcome)
    }

    /// The staged file must be where only owner (root) can put or change
    /// it: the checksum proves what the file held while it was read, and
    /// nobody else may swap it before it is copied. So no directory from
    /// it up to the root may be a symbolic link, belong to someone else or
    /// be writable by others; the staging directory is closed to others
    /// altogether. Returns the file's size.
    fn check_staged(&self, staged: &Path) -> Result<u64> {
        if !staged.is_absolute() {
            bail!("the staged k3s {} is not an absolute path", staged.display());
        }
        let stat = |p: &Path| fs::symlink_metadata(p).map_err(|e| Error::from(e).wrap(format!("stat {}", p.display())));
        let dir = fsx::dir(staged);
        let mut d = dir.as_path();
        loop {
            let m = stat(d)?;
            if m.file_type().is_symlink() || !m.is_dir() {
                bail!("{} is not a directory but {}: k3s is only taken from a real directory", d.display(), kind(&m));
            }
            if m.uid() != self.owner {
                bail!(
                    "{} belongs to uid {}, not {}: k3s is only taken from where only root can change it",
                    d.display(),
                    m.uid(),
                    self.owner
                );
            }
            if m.mode() & 0o022 != 0 {
                bail!("{} may be changed by others than its owner (mode {:o})", d.display(), m.mode() & 0o7777);
            }
            if d == dir && m.mode() & 0o077 != 0 {
                bail!("the staging directory {} is open to others (mode {:o}, wants 0700)", d.display(), m.mode() & 0o7777);
            }
            match d.parent() {
                Some(p) if d != self.root && p.starts_with(&self.root) => d = p,
                _ => break,
            }
        }
        let m = stat(staged)?;
        if !m.file_type().is_file() {
            bail!("the staged k3s {} is {}, not a plain file", staged.display(), kind(&m));
        }
        if m.uid() != self.owner || m.mode() & 0o022 != 0 {
            bail!("the staged k3s {} may be changed by others than root (uid {}, mode {:o})", staged.display(), m.uid(), m.mode() & 0o7777);
        }
        if m.len() == 0 || m.len() > MAX_K3S {
            bail!("the staged k3s {} is {} bytes, not between 1 and {MAX_K3S}", staged.display(), m.len());
        }
        Ok(m.len())
    }

    fn clean_k3s_temps(&self) {
        for t in [K3S_NEW, K3S_PREV_TMP, K3S_BACK] {
            let p = self.path(t);
            if fs::symlink_metadata(&p).is_ok() {
                self.say(&format!("removing {t}, left by an update that was cut off"));
                let _ = fs::remove_file(&p);
            }
        }
    }

    /// Copies the staged binary to K3S_NEW, flushes it, checks the copy
    /// and asks it its version.
    fn stage_k3s(&self, ctx: &Ctx, staged: &Path, sha256: &str, size: u64, version: &str) -> Result<()> {
        let tmp = self.path(K3S_NEW);
        fsx::mkdir_all(fsx::dir(&tmp), 0o755)?;
        let res = (|| {
            copy_synced(staged, &tmp, size)?;
            release::verify_file(&tmp, sha256, size).map_err(|e| e.wrap("the copy of k3s"))?;
            fsx::chmod(&tmp, 0o755)?;
            self.check_version(ctx, &tmp, version)
        })();
        if res.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        res
    }

    /// The binary's own word on its version must be the release's: the
    /// skew rules between the brain and its agents go by the release.
    fn check_version(&self, ctx: &Ctx, bin: &Path, version: &str) -> Result<()> {
        let tctx = ctx.with_timeout(Duration::from_secs(30));
        let out = self
            .run
            .output(&tctx, &Cmd::new(&bin.display().to_string(), &["--version"]).quiet().stdout_only())
            .map_err(|e| e.wrap("the new k3s does not run"))?;
        let got = out.lines().next().and_then(|l| l.strip_prefix("k3s version ")).and_then(|v| v.split_whitespace().next()).unwrap_or("");
        if got != version {
            bail!("the new k3s says it is {}, the release says {version}", show(got));
        }
        Ok(())
    }

    /// Keeps the current binary as k3s.prev: a hard link, so nothing is
    /// copied and the live binary is never missing.
    fn keep_prev(&self) -> Result<()> {
        let bin = self.path(K3S_BIN);
        if fs::symlink_metadata(&bin).is_err() {
            self.say("there is no k3s binary yet, so no k3s.prev");
            return Ok(());
        }
        replace_with(&bin, &self.path(K3S_PREV_TMP), &self.path(K3S_PREV))
    }

    /// Why k3s must not be started here, if it must not: the same
    /// conditions as k3s.service's, checked before a start is asked for.
    /// A server that cut the coordinator off (kill switch) does not run
    /// what the coordinator's cluster would start; one without a token was
    /// not approved yet or was removed.
    fn k3s_blocked(&self, role: Role) -> Option<String> {
        match role {
            Role::Node => {
                if fs::symlink_metadata(self.path(sysconf::K3S_HOLD)).is_ok() {
                    return Some(format!(
                        "the kill switch holds k3s on this machine ({}): it stays stopped until the cut is lifted",
                        sysconf::K3S_HOLD
                    ));
                }
                if fsx::read_or_empty(self.path(sysconf::K3S_TOKEN)).trim().is_empty() {
                    return Some("this machine has no cluster token (not approved yet, or removed)".into());
                }
            }
            Role::Coordinator => {
                if !self.path(sysconf::K3S_CONFIG).is_file() {
                    return Some(format!("this coordinator has no {}", sysconf::K3S_CONFIG));
                }
            }
        }
        None
    }

    /// Restarts k3s and waits until it is healthy.
    fn k3s_restart(&self, ctx: &Ctx, role: Role) -> Result<()> {
        let before = self.k3s_unit(ctx).1;
        // --no-block: k3s.service waits for k3s to say it is ready, without
        // a time limit, so a blocking restart could hang for ever. Readiness
        // is waited for below, with one.
        self.run.ok(&ctx.with_timeout(Duration::from_secs(60)), &Cmd::new("systemctl", &["restart", "--no-block", K3S_UNIT]))?;
        self.wait_healthy(ctx, role, &before)
    }

    /// k3s.service's state and invocation ID. A new ID means a new start:
    /// the old k3s answering before it stopped does not count, nor a k3s
    /// that systemd restarted after a crash.
    fn k3s_unit(&self, ctx: &Ctx) -> (String, String) {
        let c = Cmd::new("systemctl", &["show", K3S_UNIT, "--property=ActiveState,InvocationID"]).quiet().stdout_only();
        let out = self.run.output(&ctx.with_timeout(Duration::from_secs(20)), &c).unwrap_or_default();
        let get = |k: &str| out.lines().find_map(|l| l.strip_prefix(k)?.strip_prefix('=')).unwrap_or("").trim().to_string();
        (get("ActiveState"), get("InvocationID"))
    }

    /// Waits until k3s runs under a new invocation, answers healthy, and
    /// still does after k3s_settle under the same invocation.
    ///
    /// Healthy is, on the brain, the API server's /readyz answering "ok"
    /// (asked with the admin kubeconfig k3s writes there), and on every
    /// machine the kubelet's /healthz on 127.0.0.1:10248. An agent's k3s
    /// starts its kubelet only after it fetched its configuration from the
    /// brain, so a healthy kubelet also shows that the agent reached the
    /// cluster; and it needs no credentials, nothing from k3s's data
    /// directory, and no answer from another machine. Whether the brain
    /// counts the node Ready is for the rollout on the brain to see.
    fn wait_healthy(&self, ctx: &Ctx, role: Role, before: &str) -> Result<()> {
        let limit = if role == Role::Coordinator { self.limits.k3s_ready_brain } else { self.limits.k3s_ready_agent };
        let wctx = ctx.with_timeout(limit);
        let mut last = String::from("it did not start");
        loop {
            let (state, id) = self.k3s_unit(&wctx);
            if state == "active" && !id.is_empty() && id != before {
                match self.k3s_probe(&wctx, role) {
                    Ok(()) => {
                        if wctx.sleep(self.limits.k3s_settle).is_ok() {
                            let (state2, id2) = self.k3s_unit(&wctx);
                            if state2 == "active" && id2 == id && self.k3s_probe(&wctx, role).is_ok() {
                                return Ok(());
                            }
                            last = "it came up, then stopped or was restarted (crashing?)".into();
                        }
                    }
                    Err(e) => last = e.to_string(),
                }
            } else if !state.is_empty() {
                last = format!("{K3S_UNIT} is {state}");
            }
            if wctx.sleep(self.limits.k3s_poll).is_err() {
                break;
            }
        }
        if let Some(e) = ctx.err() {
            return Err(e.wrap("waiting for k3s"));
        }
        Err(errf!("k3s was not healthy within {}: {last}", took(limit)))
    }

    fn k3s_probe(&self, ctx: &Ctx, role: Role) -> Result<()> {
        let p = ctx.with_timeout(Duration::from_secs(20));
        let answer = |c: Cmd, what: &str| -> Result<()> {
            let out = self.run.output(&p, &c.quiet().stdout_only()).map_err(|e| e.wrap(what))?;
            if out.trim() != "ok" {
                bail!("{what}: it answers {}", show(out.trim()));
            }
            Ok(())
        };
        if role == Role::Coordinator {
            let k3s = self.path(K3S_BIN).display().to_string();
            answer(Cmd::new(&k3s, &["kubectl", "get", "--raw", "/readyz"]), "the API server is not ready")?;
        }
        answer(Cmd::new("curl", &["-fsS", "--noproxy", "*", "--max-time", "5", KUBELET_HEALTHZ]), "the kubelet is not healthy")
    }

    /// Puts k3s.prev back and restarts k3s with it.
    fn k3s_revert(&self, ctx: &Ctx, role: Role, sha256: &str, why: Error) -> K3sOutcome {
        let why = why.to_string();
        let broken = |revert: String, left: Left| K3sOutcome::Broken { why: why.clone(), revert, left };
        let prev = self.path(K3S_PREV);
        match release::hash_file(&prev, MAX_K3S) {
            Err(e) => return broken(format!("there is no {K3S_PREV} to go back to ({e})"), Left::New),
            Ok((h, _)) if h == sha256 => return broken(format!("{K3S_PREV} is this same binary"), Left::New),
            Ok(_) => {}
        }
        self.say(&format!("k3s: {why}; putting {K3S_PREV} back"));
        if let Err(e) = replace_with(&prev, &self.path(K3S_BACK), &self.path(K3S_BIN)) {
            return broken(format!("putting {K3S_PREV} back failed: {e}"), Left::New);
        }
        match self.k3s_restart(ctx, role) {
            Ok(()) => K3sOutcome::Reverted { why },
            Err(e) => broken(format!("the previous k3s is back but not healthy either: {e}"), Left::Previous),
        }
    }
}

// ---- file helpers ----

/// Replaces path with data in one step: a temporary file next to it,
/// flushed to disk, renamed over it, and the directory flushed. A power
/// cut leaves the old file or the new one.
fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let tmp = sibling(path, ".dryserver-tmp");
    let _ = fs::remove_file(&tmp);
    let res = (|| {
        let mut f = create_new(&tmp, mode)?;
        f.write_all(data).and_then(|_| f.sync_all()).map_err(|e| Error::from(e).wrap(format!("write {}", tmp.display())))?;
        fsx::chmod(&tmp, mode)?; // the umask took bits off
        fsx::rename(&tmp, path)?;
        sync_dir(path)
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

fn create_new(path: &Path, mode: u32) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| Error::from(e).wrap(format!("create {}", path.display())))
}

/// Copies exactly size bytes from src (not followed if it is a symbolic
/// link) to a new file dst, flushed to disk.
fn copy_synced(src: &Path, dst: &Path, size: u64) -> Result<()> {
    let from = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(src)
        .map_err(|e| Error::from(e).wrap(format!("open {}", src.display())))?;
    let mut to = create_new(dst, 0o700)?;
    let n =
        io::copy(&mut from.take(size.saturating_add(1)), &mut to).map_err(|e| Error::from(e).wrap(format!("copy to {}", dst.display())))?;
    if n != size {
        bail!("{} changed size while it was copied", src.display());
    }
    to.sync_all().map_err(|e| Error::from(e).wrap(format!("sync {}", dst.display())))
}

/// Makes dst the same file as src in one rename: a hard link to src under
/// the temporary name tmp (a copy where the file system refuses links),
/// renamed over dst. Nothing to do when dst already is src: rename(2)
/// between two links to one file does nothing and would leave tmp behind.
fn replace_with(src: &Path, tmp: &Path, dst: &Path) -> Result<()> {
    let same = |a: &fs::Metadata, b: &fs::Metadata| a.dev() == b.dev() && a.ino() == b.ino();
    let s = fs::symlink_metadata(src).map_err(|e| Error::from(e).wrap(format!("stat {}", src.display())))?;
    if fs::symlink_metadata(dst).is_ok_and(|d| same(&s, &d)) {
        return Ok(());
    }
    let _ = fs::remove_file(tmp);
    let res = (|| {
        if fs::hard_link(src, tmp).is_err() {
            copy_synced(src, tmp, s.len())?;
            fsx::chmod(tmp, 0o755)?;
        }
        fsx::rename(tmp, dst)?;
        sync_dir(dst)
    })();
    if res.is_err() {
        let _ = fs::remove_file(tmp);
    }
    res
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// Flushes the directory holding path, so a rename in it survives a power
/// cut.
fn sync_dir(path: &Path) -> Result<()> {
    let d = fsx::dir(path);
    File::open(&d).and_then(|f| f.sync_all()).map_err(|e| Error::from(e).wrap(format!("sync {}", d.display())))
}

fn kind(m: &fs::Metadata) -> &'static str {
    let t = m.file_type();
    if t.is_symlink() {
        "a symbolic link"
    } else if t.is_dir() {
        "a directory"
    } else if t.is_file() {
        "a file"
    } else {
        "a special file"
    }
}

/// A value from outside for a message: quoted, escaped, cut short.
fn show(s: &str) -> String {
    let short: String = s.chars().take(60).collect();
    if short.len() < s.len() { format!("{short:?}...") } else { format!("{short:?}") }
}

/// Text with control characters replaced, for the log and the report.
fn printable(s: &str) -> String {
    s.chars().map(|c| if c.is_control() && c != '\n' { '?' } else { c }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::{Encryption, crypttab};
    use crate::testutil::{TempDir, get, put};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    type PacmanFn = Box<dyn Fn(&Ctx, &Path, &Cmd) -> (String, Result<()>) + Send + Sync>;

    /// Plays the machine: pacman as each test says, and a k3s.service that
    /// runs whatever binary is in place when it is restarted. The binary's
    /// text says how it behaves: "version=V" is what --version prints;
    /// "good" answers healthy, "sick" runs but never answers, "dead" never
    /// gets active, "flaky" is restarted by systemd all the time.
    struct Fake {
        root: PathBuf,
        ran: Mutex<Vec<Cmd>>,
        pacman: PacmanFn,
        /// The snapshot has a newer archlinux-keyring than the machine.
        keyring_newer: bool,
        running: Mutex<Option<String>>,
        invocation: Mutex<u32>,
    }

    impl Fake {
        fn new(root: &Path) -> Fake {
            Fake::with_pacman(root, |_, _, _| (String::new(), Ok(())))
        }

        fn with_pacman(root: &Path, f: impl Fn(&Ctx, &Path, &Cmd) -> (String, Result<()>) + Send + Sync + 'static) -> Fake {
            Fake {
                root: root.into(),
                ran: Mutex::default(),
                pacman: Box::new(f),
                keyring_newer: true,
                running: Mutex::default(),
                invocation: Mutex::new(0),
            }
        }

        fn lines(&self) -> Vec<String> {
            self.ran.lock().unwrap().iter().map(|c| c.to_string()).collect()
        }

        fn pacman_lines(&self) -> Vec<String> {
            self.lines().into_iter().filter(|l| l.starts_with("pacman")).collect()
        }

        fn count(&self, prefix: &str) -> usize {
            self.lines().iter().filter(|l| l.starts_with(prefix)).count()
        }

        fn behaves(&self, how: &str) -> bool {
            self.running.lock().unwrap().as_deref().is_some_and(|b| b.contains(how))
        }
    }

    impl Runner for Fake {
        fn run(&self, ctx: &Ctx, c: &Cmd) -> (String, Result<()>) {
            self.ran.lock().unwrap().push(c.clone());
            let ok = |s: &str| (s.to_string(), Ok(()));
            let args: Vec<&str> = c.args.iter().map(String::as_str).collect();
            match (c.name.as_str(), args.as_slice()) {
                ("pacman", ["-Qu", "archlinux-keyring"]) if self.keyring_newer => ok("archlinux-keyring 20261001-1 -> 20261115-1\n"),
                ("pacman", ["-Qu", _]) => (String::new(), Err("pacman failed: exit status 1".into())),
                ("pacman", _) => (self.pacman)(ctx, &self.root, c),
                ("systemctl", ["restart", "--no-block", "k3s.service"]) => {
                    *self.running.lock().unwrap() = Some(get(&self.root, K3S_BIN));
                    *self.invocation.lock().unwrap() += 1;
                    ok("")
                }
                ("systemctl", ["show", "k3s.service", _]) => {
                    let mut id = self.invocation.lock().unwrap();
                    let state = match self.running.lock().unwrap().as_deref() {
                        None => "inactive",
                        Some(b) if b.contains("dead") => "activating",
                        Some(b) => {
                            if b.contains("flaky") {
                                *id += 1;
                            }
                            "active"
                        }
                    };
                    let inv = if *id == 0 { String::new() } else { format!("{:032x}", *id) };
                    ok(&format!("ActiveState={state}\nInvocationID={inv}\n"))
                }
                ("curl", _) | (_, ["kubectl", "get", "--raw", "/readyz"]) => {
                    if self.behaves("good") || self.behaves("flaky") {
                        ok("ok")
                    } else {
                        (String::new(), Err(errf!("{} failed: exit status 7: connection refused", c.name)))
                    }
                }
                (bin, ["--version"]) => {
                    match fs::read_to_string(bin).unwrap_or_default().split_whitespace().find_map(|w| w.strip_prefix("version=")) {
                        Some(v) => ok(&format!("k3s version {v} (1d2e3f4a)\ngo version go1.25.4\n")),
                        None => (String::new(), Err(errf!("{bin} failed: exec format error"))),
                    }
                }
                _ => ok(""),
            }
        }
    }

    type Logs = Arc<Mutex<Vec<String>>>;

    fn host<'a>(root: &Path, run: &'a Fake) -> (Host<'a>, Logs) {
        let logs: Logs = Arc::default();
        let l = logs.clone();
        let limits = Limits {
            min_free_root: 0,
            min_free_boot: 0,
            k3s_ready_brain: Duration::from_millis(300),
            k3s_ready_agent: Duration::from_millis(300),
            k3s_settle: Duration::from_millis(1),
            k3s_poll: Duration::from_millis(1),
            ..Limits::default()
        };
        let log: LogFn = Arc::new(move |s: &str| l.lock().unwrap().push(s.to_string()));
        (Host { root: root.into(), run, log, owner: fsx::geteuid(), limits }, logs)
    }

    fn append(root: &Path, path: &str, text: &str) {
        let mut f = OpenOptions::new().append(true).create(true).open(fsx::under(root, path)).unwrap();
        f.write_all(text.as_bytes()).unwrap();
    }

    fn age(root: &Path, path: &str) {
        let f = OpenOptions::new().write(true).open(fsx::under(root, path)).unwrap();
        f.set_modified(SystemTime::now() - Duration::from_secs(86_400)).unwrap();
    }

    /// The boot images the installer makes.
    const UKI: &str = "/boot/EFI/Linux/arch-linux.efi";
    const VMLINUZ: &str = "/boot/vmlinuz-linux";
    const INITRAMFS: &str = "/boot/initramfs-linux.img";
    const RUNNING: &str = "6.12.1-arch1-1";
    const LIVE: &str = "Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch\nServer = https://mirror.example.org/$repo/os/$arch\n";
    const ARCH_CONF: &str = "#\n# /etc/pacman.conf\n#\n[options]\nHoldPkg     = pacman glibc\nArchitecture = auto\nCheckSpace\n\
        ParallelDownloads = 5\nSigLevel    = Required DatabaseOptional\nLocalFileSigLevel = Optional\n#RemoteFileSigLevel = Required\n\n\
        [core]\nInclude = /etc/pacman.d/mirrorlist\n\n[extra]\nInclude = /etc/pacman.d/mirrorlist\n\n\
        #[multilib]\n#Include = /etc/pacman.d/mirrorlist\n";

    /// An installed UEFI server as pacman finds it.
    fn machine() -> TempDir {
        let dir = TempDir::new();
        let r = dir.path();
        put(r, PACMAN_CONF, ARCH_CONF);
        put(r, MIRRORLIST, LIVE);
        put(r, "/etc/fstab", "UUID=1111 / ext4 rw 0 1\nUUID=2222 /boot vfat rw,umask=0077 0 2\n");
        put(r, "/proc/self/mounts", "/dev/mapper/root / ext4 rw 0 0\n/dev/vda1 /boot vfat rw 0 0\n");
        put(r, "/proc/sys/kernel/osrelease", format!("{RUNNING}\n"));
        put(r, &format!("/usr/lib/modules/{RUNNING}/vmlinuz"), "kernel");
        put(r, PACMAN_LOG, "[2026-11-01T08:00:00+0100] [ALPM] upgraded old (1-1 -> 1-2)\n");
        put(r, UKI, "old image");
        put(r, VMLINUZ, "old kernel");
        age(r, UKI);
        age(r, VMLINUZ);
        fs::create_dir_all(r.join("var/lib/pacman")).unwrap();
        dir
    }

    /// pacman -Su replaces the kernel the way the linux package does, and
    /// mkinitcpio makes these boot images again.
    fn new_kernel(root: &Path, images: &[&str]) {
        fs::remove_dir_all(fsx::under(root, format!("/usr/lib/modules/{RUNNING}"))).unwrap();
        put(root, "/usr/lib/modules/6.12.4-arch1-1/vmlinuz", "new kernel");
        append(root, PACMAN_LOG, "[2026-11-21T03:00:02+0000] [ALPM] upgraded linux (6.12.1.arch1-1 -> 6.12.4.arch1-1)\n");
        for p in images {
            put(root, p, "new image");
        }
    }

    const FORBIDDEN: [&str; 6] = ["--overwrite", "--nodeps", "-Sdd", "--dbonly", "--assume-installed", "SigLevel"];

    #[test]
    fn mirrorlist_pins_one_day() {
        let m = mirrorlist("2026/11/20").unwrap();
        assert!(m.ends_with("\nServer = https://archive.archlinux.org/repos/2026/11/20/$repo/os/$arch\n"), "{m}");
        assert_eq!(m.matches("Server").count(), 1);
        assert_eq!(pinned_date(&m).as_deref(), Some("2026/11/20"));
        let by_hand = "Server=https://archive.archlinux.org/repos/2026/11/20/$repo/os/$arch   # pinned\n";
        assert_eq!(pinned_date(by_hand).as_deref(), Some("2026/11/20"));
        for not_pinned in [
            LIVE,
            "",
            "Server = https://archive.archlinux.org/repos/2026/13/45/$repo/os/$arch\n",
            "Server = https://archive.archlinux.org/repos/2026/11/20/$repo/os/$arch\nServer = https://evil.example/$repo/os/$arch\n",
            "Server = https://archive.archlinux.org/repos/2026/11/20/../../$repo/os/$arch\n",
            "Server = http://archive.archlinux.org/repos/2026/11/20/$repo/os/$arch\n",
        ] {
            assert_eq!(pinned_date(not_pinned), None, "{not_pinned:?}");
        }
    }

    #[test]
    fn malformed_dates_never_reach_the_mirrorlist() {
        let dir = machine();
        let fake = Fake::new(dir.path());
        let (h, _) = host(dir.path(), &fake);
        for bad in [
            "2026-11-20",
            "2026/11/20\nServer = https://evil.example/$repo/os/$arch",
            "2026/02/30",
            "2026/11/2",
            " 2026/11/20",
            "../../../etc",
            "",
            "2026/11/20/",
            "\u{ff12}026/11/20",
        ] {
            assert!(mirrorlist(bad).is_err(), "{bad:?}");
            assert!(h.pin_snapshot(bad).is_err(), "{bad:?}");
            let out = h.arch_update(&Ctx::new(), bad, false);
            let f = out.failure.as_ref().unwrap();
            assert_eq!(f.stage, Stage::Refused, "{bad:?}");
            assert!(f.reason.to_string().contains("is not a date like"), "{}", f.reason);
            assert_eq!(get(dir.path(), MIRRORLIST), LIVE);
        }
        assert!(fake.lines().is_empty(), "{:?}", fake.lines());
        // A pinned list whose day is not a date (edited by hand) pins nothing.
        put(dir.path(), MIRRORLIST, "Server = https://archive.archlinux.org/repos/2026/13/45/$repo/os/$arch\n");
        let out = h.arch_update(&Ctx::new(), "2026/11/20", false);
        assert!(out.ok() && out.previous.is_none(), "{}", out.summary());
        assert!(out.warnings.iter().any(|w| w.contains("did not pin")), "{:?}", out.warnings);
    }

    #[test]
    fn pinning_keeps_the_previous_list_to_go_back_to() {
        let dir = machine();
        let r = dir.path();
        let fake = Fake::new(r);
        let (h, _) = host(r, &fake);
        assert!(h.pin_snapshot("2026/11/20").unwrap());
        assert_eq!(get(r, MIRRORLIST), mirrorlist("2026/11/20").unwrap());
        assert_eq!(get(r, MIRRORLIST_PREV), LIVE);
        assert_eq!(fs::metadata(h.path(MIRRORLIST)).unwrap().permissions().mode() & 0o777, 0o644);
        assert!(!h.path("/etc/pacman.d/mirrorlist.dryserver-tmp").exists());
        // Again with the same day (a retry): the real previous list stays.
        assert!(!h.pin_snapshot("2026/11/20").unwrap());
        assert_eq!(get(r, MIRRORLIST_PREV), LIVE);
        assert!(h.pin_snapshot("2026/11/21").unwrap());
        assert_eq!(pinned_date(&get(r, MIRRORLIST_PREV)).as_deref(), Some("2026/11/20"));
        assert_eq!(h.unpin_snapshot().unwrap().as_deref(), Some("2026/11/20"));
        assert_eq!(get(r, MIRRORLIST), mirrorlist("2026/11/20").unwrap());
        // A machine without any list yet.
        let empty = TempDir::new();
        let (h, _) = host(empty.path(), &fake);
        assert!(h.pin_snapshot("2026/11/20").unwrap());
        assert!(!h.path(MIRRORLIST_PREV).exists());
        assert!(h.unpin_snapshot().unwrap_err().to_string().contains("no previous mirrorlist"));
    }

    #[test]
    fn a_forward_update() {
        let dir = machine();
        let r = dir.path();
        put(r, "/etc/old.conf.pacnew", "from an earlier update");
        let fake = Fake::with_pacman(r, |_, root, c| {
            if c.args[0] == "-Su" {
                append(
                    root,
                    PACMAN_LOG,
                    "[2026-11-21T03:00:01+0000] [PACMAN] starting full system upgrade\n\
                     [2026-11-21T03:00:02+0000] [ALPM] upgraded openssh (9.9p1-1 -> 9.9p1-2)\n\
                     [2026-11-21T03:00:02+0000] [ALPM-SCRIPTLET] upgraded nothing really\n\
                     [2026-11-21T03:00:03+0000] [ALPM] upgraded htop (3.3.0-1 -> 3.3.0-2)\n\
                     [2026-11-21T03:00:03+0000] [ALPM] installed newdep (1.0-1)\n\
                     [2026-11-21T03:00:04+0000] [ALPM] warning: /etc/ssh/sshd_config installed as /etc/ssh/sshd_config.pacnew\n",
                );
                put(root, "/etc/ssh/sshd_config.pacnew", "new defaults");
            }
            (String::new(), Ok(()))
        });
        let (h, _) = host(r, &fake);
        let out = h.arch_update(&Ctx::new(), "2026/11/20", false);
        assert!(out.ok(), "{}", out.summary());
        assert_eq!(
            fake.pacman_lines(),
            [
                "pacman -Syy --noconfirm",
                "pacman -Qu archlinux-keyring",
                "pacman -S --needed --noconfirm archlinux-keyring",
                "pacman -Suw --noconfirm",
                "pacman -Su --noconfirm",
                "pacman -Sc --noconfirm",
            ]
        );
        for c in fake.ran.lock().unwrap().iter() {
            assert_eq!(c.env, ["LC_ALL=C"], "{c}");
            for f in FORBIDDEN {
                assert!(!c.args.iter().any(|a| a.contains(f)), "{c}");
            }
        }
        assert_eq!(pinned_date(&get(r, MIRRORLIST)).as_deref(), Some("2026/11/20"));
        assert_eq!((out.previous.as_deref(), out.downgrade), (None, false));
        assert!(out.warnings.iter().any(|w| w.contains("did not pin a snapshot day")), "{:?}", out.warnings);
        assert_eq!(out.count, 3);
        assert_eq!(out.changes[0], Change { action: "upgraded".into(), name: "openssh".into(), version: "9.9p1-1 -> 9.9p1-2".into() });
        assert_eq!(out.restart, ["openssh"]);
        assert!(!out.kernel_replaced && out.reboot_needed() && out.reboot_safe());
        assert_eq!(out.pacnew, ["/etc/ssh/sshd_config.pacnew"], "an older .pacnew is not new");
        let s = out.summary();
        assert!(s.contains("3 package(s) changed") && s.contains("reboot needed") && s.contains("sshd_config.pacnew"), "{s}");
    }

    #[test]
    fn an_older_keyring_in_the_snapshot_is_not_installed() {
        // Installed from the live mirrors after the signed day: the keyring
        // here is newer than the snapshot's, and -S would downgrade it.
        let dir = machine();
        let mut fake = Fake::new(dir.path());
        fake.keyring_newer = false;
        let (h, _) = host(dir.path(), &fake);
        assert!(h.arch_update(&Ctx::new(), "2026/11/20", false).ok());
        assert_eq!(
            fake.pacman_lines(),
            [
                "pacman -Syy --noconfirm",
                "pacman -Qu archlinux-keyring",
                "pacman -Suw --noconfirm",
                "pacman -Su --noconfirm",
                "pacman -Sc --noconfirm"
            ]
        );
    }

    #[test]
    fn a_new_kernel_needs_a_reboot_and_a_new_boot_image() {
        // UEFI, the image made again: a reboot is due and safe.
        let dir = machine();
        let fake = Fake::with_pacman(dir.path(), |_, root, c| {
            if c.args[0] == "-Su" {
                new_kernel(root, &[VMLINUZ, UKI]);
            }
            (String::new(), Ok(()))
        });
        let (h, _) = host(dir.path(), &fake);
        let out = h.arch_update(&Ctx::new(), "2026/11/20", false);
        assert!(out.ok() && out.kernel_replaced && out.reboot_needed() && out.reboot_safe(), "{}", out.summary());
        assert_eq!(out.restart, ["linux"]);

        // The image was not made again: a reboot would start a kernel
        // without its modules.
        let dir = machine();
        let fake = Fake::with_pacman(dir.path(), |_, root, c| {
            if c.args[0] == "-Su" {
                new_kernel(root, &[VMLINUZ]);
            }
            (String::new(), Ok(()))
        });
        let (h, _) = host(dir.path(), &fake);
        let out = h.arch_update(&Ctx::new(), "2026/11/20", false);
        assert!(out.ok() && out.reboot_needed() && !out.reboot_safe(), "{}", out.summary());
        assert!(out.boot_problem.as_deref().unwrap().contains(UKI), "{:?}", out.boot_problem);
        assert!(out.summary().contains("NOT safe"), "{}", out.summary());

        // A hook failed (pacman still exits 0).
        let dir = machine();
        let fake = Fake::with_pacman(dir.path(), |_, root, c| {
            if c.args[0] == "-Su" {
                new_kernel(root, &[VMLINUZ, UKI]);
                return (format!("(4/4) Updating linux initcpios...\n==> ERROR: no space\n{HOOK_FAILED}\n"), Ok(()));
            }
            (String::new(), Ok(()))
        });
        let (h, _) = host(dir.path(), &fake);
        let out = h.arch_update(&Ctx::new(), "2026/11/20", false);
        assert!(out.ok() && !out.reboot_safe() && out.boot_problem.as_deref().unwrap().contains("hook"), "{}", out.summary());

        // BIOS: GRUB starts /boot/vmlinuz-linux with its initramfs.
        let dir = machine();
        fs::remove_dir_all(dir.path().join("boot/EFI")).unwrap();
        put(dir.path(), INITRAMFS, "old initramfs");
        age(dir.path(), INITRAMFS);
        let fake = Fake::with_pacman(dir.path(), |_, root, c| {
            if c.args[0] == "-Su" {
                new_kernel(root, &[VMLINUZ]); // the kernel, not the initramfs
            }
            (String::new(), Ok(()))
        });
        let (h, _) = host(dir.path(), &fake);
        let out = h.arch_update(&Ctx::new(), "2026/11/20", false);
        assert!(out.boot_problem.as_deref().unwrap().contains(INITRAMFS), "{:?}", out.boot_problem);
    }

    #[test]
    fn pacman_failing_halfway_is_reported_and_finished_by_the_next_run() {
        let dir = machine();
        let r = dir.path();
        let calls = Arc::new(AtomicUsize::new(0));
        let n = calls.clone();
        let fake = Fake::with_pacman(r, move |_, root, c| {
            if c.args[0] == "-Su" && n.fetch_add(1, Ordering::SeqCst) == 0 {
                new_kernel(root, &[]);
                append(root, PACMAN_LOG, "[2026-11-21T03:00:03+0000] [ALPM] upgraded glibc (2.41-1 -> 2.41-2)\n");
                let o = "error: failed to commit transaction (conflicting files)\nfoo: /usr/bin/foo exists in filesystem\nErrors occurred, no packages were upgraded.\n";
                return (o.into(), Err("pacman failed: exit status 1: Errors occurred, no packages were upgraded.".into()));
            }
            (String::new(), Ok(()))
        });
        let (h, _) = host(r, &fake);
        let out = h.arch_update(&Ctx::new(), "2026/11/20", false);
        let f = out.failure.as_ref().unwrap();
        assert_eq!(f.stage, Stage::Install);
        let why = f.reason.to_string();
        assert!(why.contains("part way") && why.contains("Do not reboot") && why.contains("never overwrites"), "{why}");
        assert_eq!(out.count, 2, "what pacman did before it stopped");
        assert!(out.reboot_needed() && !out.reboot_safe(), "a half-done upgrade must not be rebooted into");
        assert!(out.tail.contains("exists in filesystem"), "{}", out.tail);
        assert!(!fake.lines().iter().any(|l| l.contains("-Sc")), "the cache is kept after a failure");
        assert_eq!(pinned_date(&get(r, MIRRORLIST)).as_deref(), Some("2026/11/20"), "the next run goes for the same day");
        // The next run finishes it.
        let out = h.arch_update(&Ctx::new(), "2026/11/20", false);
        assert!(out.ok() && out.previous.as_deref() == Some("2026/11/20") && !out.downgrade, "{}", out.summary());
        assert!(out.kernel_replaced, "still due: the running kernel is still gone");
    }

    #[test]
    fn a_pacman_that_runs_too_long_is_stopped_and_its_lock_cleared_next_time() {
        let dir = machine();
        let r = dir.path();
        let calls = Arc::new(AtomicUsize::new(0));
        let n = calls.clone();
        let fake = Fake::with_pacman(r, move |ctx, root, c| {
            if c.args[0] == "-Su" && n.fetch_add(1, Ordering::SeqCst) == 0 {
                while !ctx.done() {
                    std::thread::sleep(Duration::from_millis(1));
                }
                put(root, PACMAN_LOCK, ""); // as a killed pacman leaves it
                return (String::new(), Err("pacman failed: signal: killed".into()));
            }
            (String::new(), Ok(()))
        });
        let (mut h, logs) = host(r, &fake);
        h.limits.install = Duration::from_millis(50);
        let out = h.arch_update(&Ctx::new(), "2026/11/20", false);
        let f = out.failure.as_ref().unwrap();
        assert!(f.stage == Stage::Install && f.reason.to_string().contains("ran longer than"), "{}", f.reason);
        assert!(h.path(PACMAN_LOCK).exists());
        let out = h.arch_update(&Ctx::new(), "2026/11/20", false);
        assert!(out.ok(), "{}", out.summary());
        assert!(out.warnings.iter().any(|w| w.contains("stale pacman lock")), "{:?}", out.warnings);
        assert!(logs.lock().unwrap().iter().any(|l| l.contains("removed the stale pacman lock")), "it is logged");
        assert!(!h.path(PACMAN_LOCK).exists());
    }

    #[test]
    fn a_running_pacman_holds_the_update_off() {
        let dir = machine();
        let r = dir.path();
        put(r, PACMAN_LOCK, "");
        put(r, "/proc/4242/comm", "pacman\n");
        put(r, "/proc/77/comm", "bash\n");
        put(r, "/proc/self/comm", "dryserver\n");
        let fake = Fake::new(r);
        let (h, _) = host(r, &fake);
        let out = h.arch_update(&Ctx::new(), "2026/11/20", false);
        let f = out.failure.as_ref().unwrap();
        assert!(f.stage == Stage::Refused && f.reason.to_string().contains("pid 4242"), "{}", f.reason);
        assert!(h.path(PACMAN_LOCK).exists() && fake.lines().is_empty());
        assert_eq!(get(r, MIRRORLIST), LIVE, "nothing changed");
        // Once that pacman is gone, the lock it left is stale.
        fs::remove_dir_all(r.join("proc/4242")).unwrap();
        assert!(h.arch_update(&Ctx::new(), "2026/11/20", false).ok());
    }

    #[test]
    fn weakened_signature_checks_are_refused() {
        let options = "[options]\nArchitecture = auto\n";
        let repos = "[core]\nInclude = /etc/pacman.d/mirrorlist\n";
        let extra = "/etc/pacman.d/extra.conf";
        for (conf, included, want) in [
            (format!("{options}SigLevel = Never\n{repos}"), "", "SigLevel \"Never\""),
            (format!("{options}SigLevel = Optional TrustedOnly\n{repos}"), "", "\"Optional\""),
            (format!("{options}SigLevel = Required TrustAll\n{repos}"), "", "\"TrustAll\""),
            (format!("{options}SigLevel = PackageOptional DatabaseOptional\n{repos}"), "", "\"PackageOptional\""),
            (format!("{options}SigLevel = Required PackageTrustAll\n{repos}"), "", "\"PackageTrustAll\""),
            (format!("{options}{repos}"), "", "no SigLevel with Required"),
            (format!("{options}SigLevel = DatabaseRequired\n{repos}"), "", "no SigLevel with Required"),
            (format!("{options}SigLevel = Required\n[core]\nSigLevel = Never\nInclude = /etc/pacman.d/mirrorlist\n"), "", "in [\"core\"]"),
            (format!("{options}SigLevel = Required\nInclude = {extra}\n{repos}"), "SigLevel = Optional\n", "extra.conf line 1"),
            (format!("{options}SigLevel = Required\nInclude = /etc/pacman.d/*.conf\n{repos}"), "", "cannot be checked"),
            (format!("{options}SigLevel = Required\nInclude = {extra}\n{repos}"), "-", "cannot read /etc/pacman.d/extra.conf"),
            (format!("{options}SigLevel = Requried\n{repos}"), "", "not a value pacman knows"),
            (
                format!("{options}SigLevel = Required\n[core]\nInclude = {extra}\n"),
                "SigLevel = Never\nServer = https://x.example/$repo\n",
                "line 1",
            ),
        ] {
            let dir = machine();
            let r = dir.path();
            put(r, PACMAN_CONF, &conf);
            if included != "-" {
                put(r, extra, included);
            }
            let fake = Fake::new(r);
            let (h, _) = host(r, &fake);
            let out = h.arch_update(&Ctx::new(), "2026/11/20", false);
            let f = out.failure.as_ref().unwrap_or_else(|| panic!("accepted:\n{conf}"));
            let why = f.reason.to_string();
            assert!(f.stage == Stage::Refused && why.contains("weakened") && why.contains(want), "{why}\n{conf}");
            assert!(fake.lines().is_empty() && get(r, MIRRORLIST) == LIVE, "{conf}");
        }
        // The mirrorlist is read like any included file.
        let dir = machine();
        put(dir.path(), MIRRORLIST, format!("SigLevel = Never\n{LIVE}"));
        let fake = Fake::new(dir.path());
        let (h, _) = host(dir.path(), &fake);
        assert!(h.check_pacman_conf().unwrap_err().to_string().contains("mirrorlist line 1"));
    }

    #[test]
    fn sound_signature_settings_pass_with_warnings() {
        let dir = machine();
        let r = dir.path();
        let fake = Fake::new(r);
        let (h, _) = host(r, &fake);
        assert_eq!(h.check_pacman_conf().unwrap(), Vec::<String>::new(), "Arch's own pacman.conf");
        put(
            r,
            PACMAN_CONF,
            "[options]\nSigLevel = PackageRequired DatabaseNever\nLocalFileSigLevel = Optional\nIgnorePkg = openssh\n\
             [core]\nSigLevel = PackageRequired\nInclude = /etc/pacman.d/mirrorlist\n[custom]\nServer = https://repo.example/$arch\n",
        );
        let w = h.check_pacman_conf().unwrap();
        assert!(w.iter().any(|w| w.contains("IgnorePkg = \"openssh\"") && w.contains("security fixes")), "{w:?}");
        assert!(w.iter().any(|w| w.contains("[custom]") && w.contains("not pinned")), "{w:?}");
    }

    #[test]
    fn too_little_space_or_an_unmounted_boot_is_refused() {
        for (root, boot, want) in [(u64::MAX, 0, "free on /,"), (0, u64::MAX, "free on /boot")] {
            let dir = machine();
            let fake = Fake::new(dir.path());
            let (mut h, _) = host(dir.path(), &fake);
            h.limits.min_free_root = root;
            h.limits.min_free_boot = boot;
            let out = h.arch_update(&Ctx::new(), "2026/11/20", false);
            let why = out.failure.as_ref().unwrap().reason.to_string();
            assert!(why.contains(want) && why.contains("make room"), "{why}");
            assert!(fake.lines().is_empty() && get(dir.path(), MIRRORLIST) == LIVE);
        }
        let dir = machine();
        put(dir.path(), "/proc/self/mounts", "/dev/mapper/root / ext4 rw 0 0\n");
        let fake = Fake::new(dir.path());
        let (h, _) = host(dir.path(), &fake);
        let out = h.arch_update(&Ctx::new(), "2026/11/20", false);
        assert!(out.failure.unwrap().reason.to_string().contains("/boot is not mounted"));
        assert!(fake.lines().is_empty());
        // A machine without a /boot partition has nothing to mount.
        put(dir.path(), "/etc/fstab", "UUID=1111 / ext4 rw 0 1\n# UUID=2222 /boot vfat rw 0 2\n");
        assert!(h.arch_update(&Ctx::new(), "2026/11/20", false).ok());
    }

    #[test]
    fn going_back_needs_a_signed_rollback() {
        let dir = machine();
        let r = dir.path();
        let fake = Fake::new(r);
        let (h, _) = host(r, &fake);
        h.pin_snapshot("2026/11/20").unwrap();
        let out = h.arch_update(&Ctx::new(), "2026/11/01", false);
        let why = out.failure.as_ref().unwrap().reason.to_string();
        assert!(why.contains("older than the pinned 2026/11/20") && why.contains("not a rollback"), "{why}");
        assert!(fake.lines().is_empty() && pinned_date(&get(r, MIRRORLIST)).as_deref() == Some("2026/11/20"));

        let out = h.arch_update(&Ctx::new(), "2026/11/01", true);
        assert!(out.ok() && out.downgrade && out.previous.as_deref() == Some("2026/11/20"), "{}", out.summary());
        assert_eq!(
            fake.pacman_lines(),
            [
                "pacman -Syy --noconfirm",
                "pacman -Suuw --noconfirm --ignore archlinux-keyring",
                "pacman -Suu --noconfirm --ignore archlinux-keyring",
                "pacman -Sc --noconfirm",
            ],
            "older packages, but the newer signing keys stay"
        );
        assert_eq!(pinned_date(&get(r, MIRRORLIST_PREV)).as_deref(), Some("2026/11/20"));
        assert!(out.summary().contains("rollback"));
        // Again on the same day (a rollback that failed part way): still -uu.
        assert!(h.arch_update(&Ctx::new(), "2026/11/01", true).downgrade);
        // Forward again, rollback flag or not: no downgrades.
        assert!(!h.arch_update(&Ctx::new(), "2026/11/25", true).downgrade);
        assert!(!h.arch_update(&Ctx::new(), "2026/11/25", false).downgrade);
    }

    #[test]
    fn a_failed_download_installs_nothing() {
        let dir = machine();
        let fake = Fake::with_pacman(dir.path(), |_, _, c| {
            if c.args[0] == "-Suw" {
                let o = "error: failed retrieving file 'linux-6.12.4.pkg.tar.zst' from archive.archlinux.org : Operation too slow\n";
                return (o.into(), Err("pacman failed: exit status 1".into()));
            }
            (String::new(), Ok(()))
        });
        let (h, _) = host(dir.path(), &fake);
        let out = h.arch_update(&Ctx::new(), "2026/11/20", false);
        let f = out.failure.as_ref().unwrap();
        let why = f.reason.to_string();
        assert!(f.stage == Stage::Download && why.contains("nothing was installed") && why.contains("archive may be slow"), "{why}");
        assert!(!fake.lines().iter().any(|l| l == "pacman -Su --noconfirm"));
        assert_eq!(out.count, 0);
    }

    #[test]
    fn pacman_log_lines() {
        let log = "[2026-11-21T03:00:01+0000] [PACMAN] Running 'pacman -Su'\n\
                   [2026-11-21T03:00:02+0000] [ALPM] upgraded linux (6.12.1.arch1-1 -> 6.12.4.arch1-1)\n\
                   [2026-11-21T03:00:02+0000] [ALPM] removed oldthing (2:1.0-3)\n\
                   [2026-11-21T03:00:02+0000] [ALPM] downgraded glibc (2.41-2 -> 2.41-1)\n\
                   [2026-11-21T03:00:02+0000] [ALPM] upgraded \u{1b}[2Jevil (1 -> 2)\n\
                   [2026-11-21T03:00:02+0000] [ALPM] transaction completed\n\
                   [2026-11-21T03:00:02+0000] [ALPM-SCRIPTLET] upgraded x (1 -> 2)\n\
                   garbage \u{ff}\n";
        let (n, list) = parse_changes(log);
        assert_eq!(n, 3);
        let shown: Vec<String> = list.iter().map(|c| format!("{} {} {}", c.action, c.name, c.version)).collect();
        assert_eq!(
            shown,
            ["upgraded linux 6.12.1.arch1-1 -> 6.12.4.arch1-1", "removed oldthing 2:1.0-3", "downgraded glibc 2.41-2 -> 2.41-1"]
        );
        assert_eq!(restart_packages(&list), ["glibc", "linux"], "a removed package needs no restart");
    }

    #[test]
    fn who_may_reboot_alone() {
        let dir = TempDir::new();
        let r = dir.path();
        let fake = Fake::new(r);
        let (h, _) = host(r, &fake);
        assert_eq!(h.reboot_blocker(), None, "not encrypted");
        put(r, "/etc/crypttab", crypttab("abcd", Encryption::Passphrase, &["u0".into()]));
        assert!(h.reboot_blocker().unwrap().contains("passphrase at every boot"));
        put(r, "/etc/crypttab", crypttab("abcd", Encryption::Tpm, &[]));
        put(r, crate::install::FIRST_BOOT_KEY, "one-time key");
        assert!(h.reboot_blocker().unwrap().contains("TPM does not unlock"));
        fs::remove_file(h.path(crate::install::FIRST_BOOT_KEY)).unwrap();
        assert_eq!(h.reboot_blocker(), None, "the TPM unlocks it");
    }

    #[test]
    fn the_boot_image_is_where_the_installer_puts_it() {
        let preset = crate::install::UKI_PRESET;
        let value = |key: &str| preset.lines().find_map(|l| l.strip_prefix(key)).unwrap().trim_matches('"').to_string();
        let uki = value("default_uki=");
        let (dir, name) = uki.rsplit_once('/').unwrap();
        assert_eq!((dir, uki_kernel(name)), (UKI_DIR, Some("linux")), "{uki}");
        assert_eq!(value("ALL_kver="), VMLINUZ);
    }

    #[test]
    fn boot_image_names_with_counters_and_the_fallback() {
        for (name, kernel) in [
            ("arch-linux.efi", Some("linux")),
            ("arch-linux+3.efi", Some("linux")),
            ("arch-linux+2-1.efi", Some("linux")),
            ("arch-linux+0-3.efi", Some("linux")),
            ("arch-linux-lts.efi", Some("linux-lts")),
            ("arch-linux-lts+3.efi", Some("linux-lts")),
            ("arch-linux-lts+1-2.efi", Some("linux-lts")),
            ("arch-linux.efi.bak", None),
            ("arch-linux+.efi", None),
            ("arch-linux+a.efi", None),
            ("arch-linux+1-.efi", None),
            ("arch-linux+1-2-3.efi", None),
            ("arch-.efi", None),
            ("linux.efi", None),
            ("arch-Linux.efi", None),
            ("arch-linux+1234567.efi", None),
        ] {
            assert_eq!(uki_kernel(name), kernel, "{name}");
        }
    }

    /// Puts kernel version of package base on disk, as pacman unpacks it.
    fn put_kernel(root: &Path, version: &str, base: &str) {
        put(root, &format!("{MODULES}/{version}/vmlinuz"), "kernel");
        put(root, &format!("{MODULES}/{version}/pkgbase"), format!("{base}\n"));
    }

    #[test]
    fn a_second_run_while_the_reboot_is_due_is_still_safe() {
        // The first run brought a new kernel and its image; the machine has
        // not rebooted yet. A later run installs nothing and builds no image:
        // the image it has is still the right one.
        let dir = machine();
        let r = dir.path();
        let calls = Arc::new(AtomicUsize::new(0));
        let n = calls.clone();
        let fake = Fake::with_pacman(r, move |_, root, c| {
            if c.args[0] == "-Su" && n.fetch_add(1, Ordering::SeqCst) == 0 {
                new_kernel(root, &[VMLINUZ, UKI]);
            }
            (String::new(), Ok(()))
        });
        let (h, _) = host(r, &fake);
        let out = h.arch_update(&Ctx::new(), "2026/11/20", false);
        assert!(out.ok() && out.kernel_replaced && out.reboot_safe(), "{}", out.summary());
        // Longer than the slack for FAT's two-second times.
        std::thread::sleep(Duration::from_millis(2300));
        let out = h.arch_update(&Ctx::new(), "2026/11/21", false);
        assert!(out.ok() && out.count == 0 && out.kernel_replaced, "{}", out.summary());
        assert!(out.reboot_needed() && out.reboot_safe(), "a false alarm: {}", out.summary());
    }

    #[test]
    fn every_kernel_on_disk_needs_its_image() {
        // The fallback kernel and boot counters in the names (lane 2's
        // layout): each kernel needs a current image under one of its names.
        let lts = "/boot/EFI/Linux/arch-linux-lts+3.efi";
        let setup = |lts_image: Option<bool>| {
            let dir = machine();
            let r = dir.path();
            fs::remove_file(fsx::under(r, UKI)).unwrap();
            put(r, "/boot/EFI/Linux/arch-linux+2-1.efi", "old image");
            age(r, "/boot/EFI/Linux/arch-linux+2-1.efi");
            put_kernel(r, "6.6.60-1-lts", "linux-lts");
            match lts_image {
                Some(true) => put(r, lts, "lts image"),
                Some(false) => {
                    put(r, lts, "old lts image");
                    age(r, lts);
                }
                None => {}
            }
            let fake = Fake::with_pacman(r, |_, root, c| {
                if c.args[0] == "-Su" {
                    new_kernel(root, &[VMLINUZ, "/boot/EFI/Linux/arch-linux+3.efi"]);
                }
                (String::new(), Ok(()))
            });
            (dir, fake)
        };
        let (dir, fake) = setup(Some(true));
        let (h, _) = host(dir.path(), &fake);
        let out = h.arch_update(&Ctx::new(), "2026/11/20", false);
        assert!(out.ok() && out.reboot_safe(), "the newest image of each kernel is current: {}", out.summary());

        let (dir, fake) = setup(None);
        let (h, _) = host(dir.path(), &fake);
        let out = h.arch_update(&Ctx::new(), "2026/11/20", false);
        let p = out.boot_problem.clone().unwrap_or_default();
        assert!(!out.reboot_safe() && p.contains("no boot image for the kernel linux-lts"), "{p}");

        let (dir, fake) = setup(Some(false));
        let (h, _) = host(dir.path(), &fake);
        let out = h.arch_update(&Ctx::new(), "2026/11/20", false);
        let p = out.boot_problem.clone().unwrap_or_default();
        assert!(!out.reboot_safe() && p.contains(lts) && p.contains("linux-lts changed"), "{p}");
    }

    // ---- k3s ----

    const OLD: &str = "v1.36.5+k3s1";
    const NEW: &str = "v1.37.2+k3s1";
    const STAGED: &str = "/var/lib/dryserver/staging/k3s";

    fn binary(version: &str, how: &str) -> String {
        format!("#!k3s version={version} {how}\n{}\n", "x".repeat(4096))
    }

    /// A machine with k3s OLD running healthy, its token or config, and a
    /// staging directory only its owner can use (the temporary directories
    /// above it follow the user's umask, which may let the group write).
    fn k3s_machine(role: Role) -> TempDir {
        let dir = TempDir::new();
        let r = dir.path();
        put(r, K3S_BIN, binary(OLD, "good"));
        match role {
            Role::Node => put(r, sysconf::K3S_TOKEN, "K10abc::server:secret\n"),
            Role::Coordinator => put(r, sysconf::K3S_CONFIG, "node-ip: 10.66.0.1\n"),
        }
        fs::create_dir_all(r.join("var/lib/dryserver/staging")).unwrap();
        for (d, mode) in
            [("", 0o755), ("var", 0o755), ("var/lib", 0o755), ("var/lib/dryserver", 0o755), ("var/lib/dryserver/staging", 0o700)]
        {
            fs::set_permissions(r.join(d), fs::Permissions::from_mode(mode)).unwrap();
        }
        dir
    }

    /// Stages content and returns its path and sha256.
    fn stage(root: &Path, content: &str) -> (PathBuf, String) {
        let p = fsx::under(root, STAGED);
        fs::write(&p, content).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        let sha = release::hash_file(&p, MAX_K3S).unwrap().0;
        (p, sha)
    }

    /// What every k3s update must leave alone.
    fn untouched(root: &Path, fake: &Fake) {
        assert!(!root.join("var/lib/rancher").exists(), "k3s's data directory was touched");
        assert!(!fake.lines().iter().any(|l| l.contains("/var/lib/rancher")), "{:?}", fake.lines());
        for t in [K3S_NEW, K3S_PREV_TMP, K3S_BACK] {
            assert!(!fsx::under(root, t).exists(), "{t} left behind");
        }
    }

    #[test]
    fn k3s_update_on_an_agent() {
        let dir = k3s_machine(Role::Node);
        let r = dir.path();
        let fake = Fake::new(r);
        let (h, _) = host(r, &fake);
        let (staged, sha) = stage(r, &binary(NEW, "good"));
        assert_eq!(h.k3s_install(&Ctx::new(), &staged, &sha, NEW, Role::Node).unwrap(), K3sOutcome::Running);
        assert_eq!(get(r, K3S_BIN), binary(NEW, "good"));
        assert_eq!(get(r, K3S_PREV), binary(OLD, "good"));
        assert_eq!(fs::metadata(h.path(K3S_BIN)).unwrap().permissions().mode() & 0o777, 0o755);
        assert_eq!(fake.count("systemctl restart --no-block k3s.service"), 1);
        assert!(fake.count("curl -fsS --noproxy * --max-time 5 http://127.0.0.1:10248/healthz") >= 2, "asked, then again after settling");
        assert_eq!(fake.count(&format!("{} kubectl", h.path(K3S_BIN).display())), 0, "an agent has no API server to ask");
        untouched(r, &fake);
    }

    #[test]
    fn k3s_update_on_the_brain_asks_the_api_server() {
        let dir = k3s_machine(Role::Coordinator);
        let r = dir.path();
        let fake = Fake::new(r);
        let (h, _) = host(r, &fake);
        let (staged, sha) = stage(r, &binary(NEW, "good"));
        assert_eq!(h.k3s_install(&Ctx::new(), &staged, &sha, NEW, Role::Coordinator).unwrap(), K3sOutcome::Running);
        assert!(fake.count(&format!("{} kubectl get --raw /readyz", h.path(K3S_BIN).display())) >= 2);
        untouched(r, &fake);
    }

    #[test]
    fn a_wrong_checksum_or_version_changes_nothing() {
        let dir = k3s_machine(Role::Node);
        let r = dir.path();
        let fake = Fake::new(r);
        let (h, _) = host(r, &fake);
        let (staged, sha) = stage(r, &binary(NEW, "good"));
        for (sha, version, want) in [
            ("0".repeat(64), NEW, "the release says 0000"),
            (sha.to_uppercase(), NEW, "not a sha256"),
            (sha.clone(), "1.37.2", "not a k3s version"),
            (sha.clone(), "v1.37.3+k3s1", "says it is \"v1.37.2+k3s1\", the release says v1.37.3+k3s1"),
        ] {
            let err = h.k3s_install(&Ctx::new(), &staged, &sha, version, Role::Node).unwrap_err().to_string();
            assert!(err.contains(want), "{err}");
            assert_eq!(get(r, K3S_BIN), binary(OLD, "good"));
            assert!(!h.path(K3S_PREV).exists());
        }
        // A binary that does not run at all.
        let (staged, sha) = stage(r, "not a program");
        let err = h.k3s_install(&Ctx::new(), &staged, &sha, NEW, Role::Node).unwrap_err().to_string();
        assert!(err.contains("does not run"), "{err}");
        assert_eq!(fake.count("systemctl"), 0);
        untouched(r, &fake);
    }

    #[test]
    fn an_oversized_staged_file_is_refused_unread() {
        let dir = k3s_machine(Role::Node);
        let r = dir.path();
        let (staged, _) = stage(r, "");
        File::options().write(true).open(&staged).unwrap().set_len(MAX_K3S + 1).unwrap(); // sparse: costs no disk
        let fake = Fake::new(r);
        let (h, _) = host(r, &fake);
        let start = std::time::Instant::now();
        let err = h.k3s_install(&Ctx::new(), &staged, &"a".repeat(64), NEW, Role::Node).unwrap_err().to_string();
        assert!(err.contains("not between 1 and"), "{err}");
        assert!(start.elapsed() < Duration::from_secs(2), "it was read");
        let (staged, _) = stage(r, "");
        let err = h.k3s_install(&Ctx::new(), &staged, &"a".repeat(64), NEW, Role::Node).unwrap_err().to_string();
        assert!(err.contains("is 0 bytes"), "{err}");
        assert_eq!(get(r, K3S_BIN), binary(OLD, "good"));
    }

    #[test]
    fn k3s_is_taken_only_from_a_root_only_staging_directory() {
        type Spoil = fn(&Path, &Path);
        let content = binary(NEW, "good");
        let cases: [(&str, Spoil, &str); 7] = [
            (
                "symlink",
                |_, staged| {
                    let real = staged.with_file_name("real");
                    fs::rename(staged, &real).unwrap();
                    std::os::unix::fs::symlink(&real, staged).unwrap();
                },
                "a symbolic link, not a plain file",
            ),
            ("file mode", |_, staged| fs::set_permissions(staged, fs::Permissions::from_mode(0o666)).unwrap(), "may be changed by others"),
            (
                "dir mode",
                |r, _| fs::set_permissions(r.join("var/lib/dryserver/staging"), fs::Permissions::from_mode(0o755)).unwrap(),
                "open to others",
            ),
            (
                "parent mode",
                |r, _| fs::set_permissions(r.join("var/lib"), fs::Permissions::from_mode(0o777)).unwrap(),
                "var/lib may be changed",
            ),
            (
                "dir symlink",
                |r, _| {
                    let s = r.join("var/lib/dryserver/staging");
                    fs::rename(&s, r.join("var/lib/dryserver/elsewhere")).unwrap();
                    std::os::unix::fs::symlink("elsewhere", &s).unwrap();
                },
                "not a directory but a symbolic link",
            ),
            (
                "a directory",
                |_, staged| {
                    fs::remove_file(staged).unwrap();
                    fs::create_dir(staged).unwrap();
                },
                "is a directory, not a plain file",
            ),
            ("missing", |_, staged| fs::remove_file(staged).unwrap(), "no such file"),
        ];
        for (name, spoil, want) in cases {
            let dir = k3s_machine(Role::Node);
            let r = dir.path();
            let (staged, sha) = stage(r, &content);
            spoil(r, &staged);
            let fake = Fake::new(r);
            let (h, _) = host(r, &fake);
            let err = h.k3s_install(&Ctx::new(), &staged, &sha, NEW, Role::Node).unwrap_err().to_string();
            assert!(err.contains(want), "{name}: {err}");
            assert_eq!(get(r, K3S_BIN), binary(OLD, "good"), "{name}");
        }
        // Someone else's files, and a relative path.
        let dir = k3s_machine(Role::Node);
        let r = dir.path();
        let (staged, sha) = stage(r, &content);
        let fake = Fake::new(r);
        let (mut h, _) = host(r, &fake);
        h.owner = fsx::geteuid() + 1;
        assert!(h.k3s_install(&Ctx::new(), &staged, &sha, NEW, Role::Node).unwrap_err().to_string().contains("belongs to uid"));
        h.owner = fsx::geteuid();
        let err = h.k3s_install(&Ctx::new(), Path::new("staging/k3s"), &sha, NEW, Role::Node).unwrap_err().to_string();
        assert!(err.contains("not an absolute path"), "{err}");
    }

    #[test]
    fn held_or_tokenless_machines_get_the_binary_but_no_start() {
        for (role, spoil, want) in [
            (Role::Node, "hold", "kill switch"),
            (Role::Node, "token", "no cluster token"),
            (Role::Node, "empty token", "no cluster token"),
            (Role::Coordinator, "config", "has no /etc/rancher/k3s/config.yaml"),
        ] {
            let dir = k3s_machine(role);
            let r = dir.path();
            match spoil {
                "hold" => put(r, sysconf::K3S_HOLD, "the coordinator is cut off\n"),
                "token" => fs::remove_file(fsx::under(r, sysconf::K3S_TOKEN)).unwrap(),
                "empty token" => put(r, sysconf::K3S_TOKEN, "\n"),
                _ => fs::remove_file(fsx::under(r, sysconf::K3S_CONFIG)).unwrap(),
            }
            let fake = Fake::new(r);
            let (h, _) = host(r, &fake);
            let (staged, sha) = stage(r, &binary(NEW, "good"));
            match h.k3s_install(&Ctx::new(), &staged, &sha, NEW, role).unwrap() {
                K3sOutcome::Placed { why } => assert!(why.contains(want), "{why}"),
                other => panic!("{spoil}: {other:?}"),
            }
            assert_eq!(get(r, K3S_BIN), binary(NEW, "good"), "{spoil}");
            assert_eq!(get(r, K3S_PREV), binary(OLD, "good"));
            assert_eq!(fake.count("systemctl"), 0, "{spoil}: k3s must not be started: {:?}", fake.lines());
            assert_eq!(fake.count("curl"), 0);
            untouched(r, &fake);
        }
    }

    #[test]
    fn k3s_that_does_not_get_healthy_is_reverted() {
        for (how, want) in [("sick", "connection refused"), ("dead", "k3s.service is activating"), ("flaky", "restarted (crashing?)")] {
            let dir = k3s_machine(Role::Node);
            let r = dir.path();
            let fake = Fake::new(r);
            let (h, _) = host(r, &fake);
            let (staged, sha) = stage(r, &binary(NEW, how));
            match h.k3s_install(&Ctx::new(), &staged, &sha, NEW, Role::Node).unwrap() {
                K3sOutcome::Reverted { why } => assert!(why.contains(want) && why.contains("not healthy within"), "{how}: {why}"),
                other => panic!("{how}: {other:?}"),
            }
            assert_eq!(get(r, K3S_BIN), binary(OLD, "good"), "{how}: the previous binary is back");
            assert_eq!(get(r, K3S_PREV), binary(OLD, "good"), "{how}: and still kept");
            assert_eq!(fake.count("systemctl restart"), 2, "{how}");
            assert!(fake.behaves("good"), "{how}: k3s runs the previous binary");
            untouched(r, &fake);
        }
    }

    #[test]
    fn a_revert_that_fails_too_leaves_the_previous_binary() {
        let dir = k3s_machine(Role::Node);
        let r = dir.path();
        put(r, K3S_BIN, binary(OLD, "sick")); // the brain is down: neither binary gets healthy
        let fake = Fake::new(r);
        let (h, logs) = host(r, &fake);
        let (staged, sha) = stage(r, &binary(NEW, "sick"));
        match h.k3s_install(&Ctx::new(), &staged, &sha, NEW, Role::Node).unwrap() {
            K3sOutcome::Broken { why, revert, left } => {
                assert!(why.contains("not healthy") && revert.contains("not healthy either"), "{why} / {revert}");
                assert_eq!(left, Left::Previous);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(get(r, K3S_BIN), binary(OLD, "sick"));
        assert!(logs.lock().unwrap().iter().any(|l| l.starts_with("K3S BROKEN")), "it is said loudly");
        untouched(r, &fake);
    }

    #[test]
    fn a_stopped_update_leaves_the_check_to_the_next_run() {
        let dir = k3s_machine(Role::Node);
        let r = dir.path();
        let fake = Fake::new(r);
        let (h, _) = host(r, &fake);
        let (staged, sha) = stage(r, &binary(NEW, "sick"));
        let ctx = Ctx::new();
        let c = ctx.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            c.cancel();
        });
        match h.k3s_install(&ctx, &staged, &sha, NEW, Role::Node).unwrap() {
            K3sOutcome::Broken { revert, left, .. } => assert!(left == Left::New && revert.contains("stopped"), "{revert}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(get(r, K3S_BIN), binary(NEW, "sick"));
        assert_eq!(fake.count("systemctl restart"), 1, "no revert once stopped");
        // The next run finds it in place, checks it, and goes back.
        match h.k3s_install(&Ctx::new(), &staged, &sha, NEW, Role::Node).unwrap() {
            K3sOutcome::Reverted { .. } => {}
            other => panic!("{other:?}"),
        }
        assert_eq!(get(r, K3S_BIN), binary(OLD, "good"));
    }

    #[test]
    fn without_a_previous_binary_the_new_one_stays() {
        let dir = k3s_machine(Role::Node);
        let r = dir.path();
        fs::remove_file(fsx::under(r, K3S_BIN)).unwrap();
        let fake = Fake::new(r);
        let (h, _) = host(r, &fake);
        let (staged, sha) = stage(r, &binary(NEW, "sick"));
        match h.k3s_install(&Ctx::new(), &staged, &sha, NEW, Role::Node).unwrap() {
            K3sOutcome::Broken { revert, left, .. } => {
                assert!(revert.contains("no /usr/local/bin/k3s.prev"), "{revert}");
                assert_eq!(left, Left::New);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(get(r, K3S_BIN), binary(NEW, "sick"));
        assert_eq!(fake.count("systemctl restart"), 1, "nothing to go back to");
    }

    #[test]
    fn a_power_cut_at_any_step_of_the_swap_leaves_a_whole_binary() {
        let (old, new) = (binary(OLD, "good"), binary(NEW, "good"));
        for cut in 0..=5 {
            let dir = k3s_machine(Role::Node);
            let r = dir.path();
            let fake = Fake::new(r);
            let (h, _) = host(r, &fake);
            let (staged, sha) = stage(r, &new);
            let size = new.len() as u64;
            let ctx = Ctx::new();
            match cut {
                // Leftovers of a cut in an earlier revert or link.
                0 => {
                    put(r, K3S_BACK, &old[..10]);
                    put(r, K3S_PREV_TMP, "");
                }
                // During the copy: half a file under the temporary name.
                1 => put(r, K3S_NEW, &new[..new.len() / 2]),
                // After the copy, after k3s.prev, after the rename, after
                // the restart (the power went before the health check).
                _ => {
                    h.stage_k3s(&ctx, &staged, &sha, size, NEW).unwrap();
                    if cut >= 3 {
                        h.keep_prev().unwrap();
                    }
                    if cut >= 4 {
                        fsx::rename(h.path(K3S_NEW), h.path(K3S_BIN)).unwrap();
                    }
                    if cut >= 5 {
                        let _ = fake.run(&ctx, &Cmd::new("systemctl", &["restart", "--no-block", "k3s.service"]));
                    }
                }
            }
            let live = get(r, K3S_BIN);
            assert!(live == old || live == new, "cut {cut}: k3s is half a binary");
            assert!(cut < 3 || get(r, K3S_PREV) == old, "cut {cut}");
            // The machine boots, update apply runs again.
            assert_eq!(h.k3s_install(&ctx, &staged, &sha, NEW, Role::Node).unwrap(), K3sOutcome::Running, "cut {cut}");
            assert_eq!(get(r, K3S_BIN), new, "cut {cut}");
            assert_eq!(get(r, K3S_PREV), old, "cut {cut}: k3s.prev must stay the binary from before the update");
            untouched(r, &fake);
        }
    }
}
