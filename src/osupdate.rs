//! OS updates from a signed release: the Arch Linux snapshot every machine
//! is pinned to (B4). `dryserver update apply` calls it once the release
//! passed `release::check` and its dryserver binary is in place.
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
//! Nothing here guards against a second update at the same time: the
//! caller holds the update lock for the whole release.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::ctx::Ctx;
use crate::err::{Error, Result};
use crate::release;
use crate::runner::{Cmd, LogFn, Runner};
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
/// The one kernel image systemd-boot starts on UEFI machines (the
/// installer's UKI_PRESET), and the kernel and initramfs GRUB starts on
/// BIOS machines. There is no fallback image: a broken one does not boot.
const UKI: &str = "/boot/EFI/Linux/arch-linux.efi";
const VMLINUZ: &str = "/boot/vmlinuz-linux";
const INITRAMFS: &str = "/boot/initramfs-linux.img";
/// What pacman prints when one of its hooks fails (mkinitcpio among
/// them). pacman still exits 0 after a failed hook that runs after the
/// transaction, so its output is the only sign.
const HOOK_FAILED: &str = "error: command failed to execute correctly";

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
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            min_free_root: 2 << 30,
            min_free_boot: 200 << 20,
            sync: Duration::from_secs(10 * 60),
            download: Duration::from_secs(45 * 60),
            install: Duration::from_secs(30 * 60),
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
    pub limits: Limits,
}

impl<'a> Host<'a> {
    /// This machine.
    pub fn new(run: &'a dyn Runner, log: LogFn) -> Host<'a> {
        Host { root: PathBuf::from("/"), run, log, limits: Limits::default() }
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
        let started = SystemTime::now();
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
        let kernel_changed = out.kernel_replaced || out.changes.iter().any(|c| c.name == "linux" && c.action != "removed");
        out.boot_problem = self.boot_problem(hook_failed, kernel_changed, started);
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
    /// says so: a failed pacman hook (mkinitcpio is one), or a kernel that
    /// changed while the image the boot loader starts did not.
    fn boot_problem(&self, hook_failed: bool, kernel_changed: bool, started: SystemTime) -> Option<String> {
        if hook_failed {
            return Some(
                "a pacman hook failed, maybe the one that builds the boot image: reboot only after mkinitcpio -P ran cleanly".into(),
            );
        }
        if !kernel_changed {
            return None;
        }
        let made = |p: &str| fs::metadata(self.path(p)).and_then(|m| m.modified()).is_ok_and(|t| t + Duration::from_secs(2) >= started);
        let images: &[&str] = if self.path("/boot/EFI/Linux").is_dir() { &[UKI] } else { &[VMLINUZ, INITRAMFS] };
        images
            .iter()
            .find(|p| !made(p))
            .map(|p| format!("the kernel changed but {p} was not made again: the machine would start a kernel without its modules"))
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

    /// Plays the machine: pacman as each test says.
    struct Fake {
        root: PathBuf,
        ran: Mutex<Vec<Cmd>>,
        pacman: PacmanFn,
        /// The snapshot has a newer archlinux-keyring than the machine.
        keyring_newer: bool,
    }

    impl Fake {
        fn new(root: &Path) -> Fake {
            Fake::with_pacman(root, |_, _, _| (String::new(), Ok(())))
        }

        fn with_pacman(root: &Path, f: impl Fn(&Ctx, &Path, &Cmd) -> (String, Result<()>) + Send + Sync + 'static) -> Fake {
            Fake { root: root.into(), ran: Mutex::default(), pacman: Box::new(f), keyring_newer: true }
        }

        fn lines(&self) -> Vec<String> {
            self.ran.lock().unwrap().iter().map(|c| c.to_string()).collect()
        }

        fn pacman_lines(&self) -> Vec<String> {
            self.lines().into_iter().filter(|l| l.starts_with("pacman")).collect()
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
                _ => ok(""),
            }
        }
    }

    type Logs = Arc<Mutex<Vec<String>>>;

    fn host<'a>(root: &Path, run: &'a Fake) -> (Host<'a>, Logs) {
        let logs: Logs = Arc::default();
        let l = logs.clone();
        let limits = Limits { min_free_root: 0, min_free_boot: 0, ..Limits::default() };
        let log: LogFn = Arc::new(move |s: &str| l.lock().unwrap().push(s.to_string()));
        (Host { root: root.into(), run, log, limits }, logs)
    }

    fn append(root: &Path, path: &str, text: &str) {
        let mut f = OpenOptions::new().append(true).create(true).open(fsx::under(root, path)).unwrap();
        f.write_all(text.as_bytes()).unwrap();
    }

    fn age(root: &Path, path: &str) {
        let f = OpenOptions::new().write(true).open(fsx::under(root, path)).unwrap();
        f.set_modified(SystemTime::now() - Duration::from_secs(86_400)).unwrap();
    }

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
        assert!(crate::install::UKI_PRESET.contains(&format!("default_uki=\"{UKI}\"")));
        assert!(crate::install::UKI_PRESET.contains(VMLINUZ));
    }
}
