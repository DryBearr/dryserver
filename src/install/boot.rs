//! Two kernels and boot counting, so a kernel update that does not boot
//! does not leave a machine without screen or keyboard dead (UEFI).
//!
//! Every machine has the main kernel (`linux`) and a fallback kernel
//! (`linux-lts`), each with its own signed unified kernel image (UKI) in
//! ESP_LINUX and its own modules directory, so a main kernel upgrade
//! leaves the fallback untouched. systemd-boot finds both on its own and,
//! with no `default` in loader.conf, starts the first one in its order:
//! the newer kernel (main) first, and any image whose boot counter ran
//! out last.
//!
//! Boot counting (systemd's Automatic Boot Assessment): a new image is
//! put in place as `arch-linux+3.efi`. systemd-boot takes one try off its
//! name before each start (`+2-1`, `+1-2`, `+0-3`), systemd-bless-boot
//! drops the counter once boot-complete.target is reached, and an image
//! with no tries left is started only when nothing else is left. What
//! counts as a good boot is `dryserver boot check`, which systemd orders
//! before boot-complete.target: only signs from the machine itself, never
//! the brain, the mesh or the internet, so an outage there never makes a
//! good kernel bad. A panic or a hang restarts the machine by itself
//! (panic=10, a hardware watchdog), so the tries run down without a
//! person, and a failed check restarts it while another image waits.
//!
//! Where images come from, and why in two steps:
//! - mkinitcpio (from pacman's hook, or run by hand) writes each new
//!   image to a staging name (`arch-linux.efi.new`), which systemd-boot
//!   never starts: ukify writes in place, so a power cut while it writes
//!   leaves half a file, and a half file systemd-boot tries to start hangs
//!   the machine at its menu.
//! - mkinitcpio then runs its post hooks; ours (`dryserver boot place`)
//!   checks the image, flushes it to disk and renames it into place,
//!   counted, and only then removes the older image of that kernel.
//! - The fallback kernel's image is replaced only when the fallback
//!   kernel itself changed. New firmware or a new systemd makes mkinitcpio
//!   build every image again; the fallback keeps the one it was made with,
//!   so a broken initramfs cannot reach both kernels at once.
//! - Before pacman replaces a kernel, its modules go and the old image is
//!   then a kernel without modules. A pacman hook (`dryserver boot mark`,
//!   before mkinitcpio's own, which would remove the plain-named image)
//!   leaves that image one try only, so after a power cut in the middle
//!   the machine tries it once, fails the check (no modules) and starts
//!   the fallback kernel; and when the transaction fails before it changed
//!   anything, the old image passes its one try and is good again.
//!
//! Machines installed before this (no `linux-lts`) keep working as they
//! did: their presets write the image under its final name, which `place`
//! leaves alone, and nothing is counted or marked without a fallback.
//!
//! BIOS machines (GRUB) get `linux-lts` in GRUB's menu and the panic
//! restart, but no automatic fallback: someone has to pick it.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::ctx::Ctx;
use crate::err::{Error, Result};
use crate::runner::{Cmd, ExecRunner, Runner};
use crate::{bail, errf, fsx};

/// Where systemd-boot finds unified kernel images (the ESP is /boot).
pub const ESP_LINUX: &str = "/boot/EFI/Linux";
/// Appended to an image's name while it is being made. systemd-boot
/// starts only files that end in .efi.
pub const STAGED: &str = ".new";
/// How many times a new image is tried before the next one is started.
pub const TRIES: u32 = 3;
/// The mkinitcpio post hook: runs `dryserver boot place` for every image
/// mkinitcpio makes.
pub const POST_HOOK: &str = "/etc/initcpio/post/dryserver-boot";
/// The pacman hook that runs `dryserver boot mark` before a kernel goes.
pub const MARK_HOOK: &str = "/etc/pacman.d/hooks/55-dryserver-boot-mark.hook";
pub const CHECK_UNIT_PATH: &str = "/etc/systemd/system/dryserver-boot-check.service";
/// Makes boot-complete.target wait for the check.
pub const COMPLETE_DROPIN: &str = "/etc/systemd/system/boot-complete.target.d/10-dryserver.conf";
/// A hardware watchdog, when there is one.
pub const WATCHDOG_DROPIN: &str = "/etc/systemd/system.conf.d/10-dryserver-watchdog.conf";
/// Seconds after a kernel panic until the machine restarts itself; on
/// the kernel command line (a panic before the root file system is up)
/// and in sysctl (machines installed before).
pub const PANIC_SECS: u32 = 10;
/// Serializes mark, place and check.
const LOCK: &str = "/run/dryserver-boot.lock";
/// The vendor of systemd-boot's EFI variables.
const LOADER_GUID: &str = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";
/// Below this much free room on the ESP after an image was put in place,
/// the next kernel update may not fit: its new image is written before
/// the old one goes.
const ESP_LOW: u64 = 128 << 20;

pub const POST_HOOK_TEXT: &str = r#"#!/bin/sh
# dryserver: mkinitcpio runs this after it made a boot image. A unified
# kernel image made under its staging name is checked, flushed to disk and
# renamed into place, counted when a fallback kernel is installed. See
# `dryserver boot status`.
exec /usr/local/bin/dryserver boot place "$@"
"#;

pub const MARK_HOOK_TEXT: &str = "# dryserver: a kernel is about to be replaced or removed, and with it its
# modules. Its boot image gets one more try only, so a power cut before the
# new image is made does not leave a kernel without modules as the one that
# starts: it fails its boot check and the fallback kernel starts.
[Trigger]
Type = Path
Operation = Remove
Target = usr/lib/modules/*/vmlinuz

[Action]
Description = Giving the boot images of replaced kernels one more try...
When = PreTransaction
Exec = /usr/local/bin/dryserver boot mark
NeedsTargets
";

pub const CHECK_UNIT_TEXT: &str = "[Unit]
Description=Check that a newly installed kernel works
Documentation=man:systemd-bless-boot.service(8)
# Pulled in by boot-complete.target, which systemd-bless-boot pulls in only
# when the boot loader counts this boot (a new kernel image). Only signs
# from this machine itself count: a brain, mesh or internet that is down
# must never make a good kernel bad. So nothing here waits for them, nor
# for multi-user.target, which waits for k3s, which waits for the brain.
After=local-fs.target sshd.service systemd-networkd.service
Before=boot-complete.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/dryserver boot check
StandardOutput=journal+console
TimeoutStartSec=5min
";

pub const COMPLETE_DROPIN_TEXT: &str = "# dryserver: a counted boot is good once dryserver's boot check passed.
[Unit]
Requires=dryserver-boot-check.service
";

pub const WATCHDOG_TEXT: &str = "# dryserver: a hardware watchdog, when the machine has one, restarts it when
# the kernel or systemd hangs, and a crash of systemd restarts it too, so a
# new kernel that hangs uses up its tries without someone at the machine.
[Manager]
RuntimeWatchdogSec=1min
CrashAction=reboot
";

/// Emergency mode in the initramfs restarts the machine (mkinitcpio puts
/// emergency.service's drop-ins into the image).
pub const EMERGENCY_DROPIN: &str = "/etc/systemd/system/emergency.service.d/10-dryserver.conf";
pub const EMERGENCY_TEXT: &str = "# dryserver: nobody is at a server's console and root is locked, so emergency
# mode in the initramfs (a kernel that finds no disk, an unlock that failed)
# could only wait. It restarts the machine after 30 seconds instead: a new
# kernel that cannot boot uses up its tries and the other kernel starts.
# After the switch to the real root this does nothing.
[Service]
ExecStartPre=-/usr/bin/sh -c 'test -e /etc/initrd-release || exit 0; echo \"dryserver: restarting in 30 seconds\"; sleep 30; systemctl --no-block reboot'
";

/// The two kernels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kernel {
    Main,
    Fallback,
}

impl Kernel {
    pub const ALL: [Kernel; 2] = [Kernel::Main, Kernel::Fallback];

    /// The package, also the name of its mkinitcpio preset.
    pub fn pkgbase(self) -> &'static str {
        match self {
            Kernel::Main => "linux",
            Kernel::Fallback => "linux-lts",
        }
    }

    /// The image's name without counter and .efi.
    pub fn image(self) -> &'static str {
        match self {
            Kernel::Main => "arch-linux",
            Kernel::Fallback => "arch-linux-lts",
        }
    }

    pub fn from_pkgbase(s: &str) -> Option<Kernel> {
        Kernel::ALL.into_iter().find(|k| k.pkgbase() == s)
    }

    /// Where mkinitcpio makes this kernel's image.
    pub fn staged(self) -> String {
        format!("{ESP_LINUX}/{}.efi{STAGED}", self.image())
    }

    /// The image's name with tries left and done.
    pub fn counted(self, left: u32, done: u32) -> String {
        if done == 0 { format!("{}+{left}.efi", self.image()) } else { format!("{}+{left}-{done}.efi", self.image()) }
    }

    /// The mkinitcpio preset (UEFI): one unified kernel image, made under
    /// its staging name.
    pub fn preset(self) -> &'static str {
        match self {
            Kernel::Main => super::UKI_PRESET,
            Kernel::Fallback => super::LTS_PRESET,
        }
    }
}

/// A boot image in ESP_LINUX, read from its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    pub name: String,
    pub kernel: Kernel,
    /// Tries left; None when the image is not counted (it booted well).
    pub left: Option<u32>,
    pub done: u32,
}

impl Image {
    /// Names as systemd-boot reads them: arch-linux.efi, arch-linux+3.efi,
    /// arch-linux+2-1.efi, and the same for arch-linux-lts.
    pub fn parse(name: &str) -> Option<Image> {
        let stem = name.strip_suffix(".efi")?;
        let num =
            |s: &str| if !s.is_empty() && s.len() <= 9 && s.bytes().all(|b| b.is_ascii_digit()) { s.parse::<u32>().ok() } else { None };
        let (base, left, done) = match stem.rsplit_once('+') {
            None => (stem, None, 0),
            Some((base, counter)) => match counter.split_once('-') {
                None => (base, Some(num(counter)?), 0),
                Some((l, d)) => (base, Some(num(l)?), num(d)?),
            },
        };
        let kernel = Kernel::ALL.into_iter().find(|k| k.image() == base)?;
        Some(Image { name: name.into(), kernel, left, done })
    }

    /// Its tries ran out: started only when nothing else is left.
    pub fn bad(&self) -> bool {
        self.left == Some(0)
    }

    /// For people.
    pub fn describe(&self) -> String {
        match self.left {
            None => "good (it booted well)".into(),
            Some(0) => format!("bad: it failed {} tries", self.done),
            Some(n) if self.done == 0 => format!("new, not tried yet ({n} tries)"),
            Some(n) => format!("being tried: {} tries done, {n} left", self.done),
        }
    }
}

/// The boot images in dir, sorted by name; none when there is no such
/// directory (a BIOS machine).
pub fn images(dir: &Path) -> Result<Vec<Image>> {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::from(e).wrap(format!("read {}", dir.display()))),
    };
    let mut v: Vec<Image> = rd
        .flatten()
        .take(256)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter_map(|e| Image::parse(&e.file_name().to_string_lossy()))
        .collect();
    v.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(v)
}

/// Whether a kernel package is installed: a modules directory with its
/// name in pkgbase and its kernel.
pub fn installed(root: &Path, k: Kernel) -> bool {
    kernel_versions(root).iter().any(|(_, p)| p == k.pkgbase())
}

/// (version, pkgbase) of each kernel in /usr/lib/modules.
fn kernel_versions(root: &Path) -> Vec<(String, String)> {
    let Ok(rd) = fs::read_dir(fsx::under(root, "/usr/lib/modules")) else {
        return Vec::new();
    };
    rd.flatten()
        .take(64)
        .filter(|e| e.path().join("vmlinuz").is_file())
        .map(|e| (e.file_name().to_string_lossy().into_owned(), fsx::read_or_empty(e.path().join("pkgbase")).trim().to_string()))
        .collect()
}

fn osrelease(root: &Path) -> String {
    fsx::read_or_empty(fsx::under(root, "/proc/sys/kernel/osrelease")).trim().to_string()
}

/// The kernel that runs: from its pkgbase while its modules are there,
/// else from Arch's naming (linux-lts releases end in -lts).
fn running(root: &Path) -> Option<Kernel> {
    let rel = osrelease(root);
    if rel.is_empty() || rel.contains('/') {
        return None;
    }
    let pkgbase = fsx::read_or_empty(fsx::under(root, format!("/usr/lib/modules/{rel}/pkgbase"))).trim().to_string();
    match Kernel::from_pkgbase(&pkgbase) {
        Some(k) => Some(k),
        None if rel.ends_with("-lts") => Some(Kernel::Fallback),
        None => Some(Kernel::Main),
    }
}

/// A string variable of systemd-boot's (UTF-16 after four bytes of
/// attributes), None when it is not set.
fn efivar(root: &Path, name: &str) -> Option<String> {
    let path = fsx::under(root, format!("/sys/firmware/efi/efivars/{name}-{LOADER_GUID}"));
    let mut b = Vec::new();
    File::open(path).ok()?.take(4096).read_to_end(&mut b).ok()?;
    let units: Vec<u16> = b.get(4..)?.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
    let s = String::from_utf16_lossy(&units).trim_end_matches('\0').trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// The image systemd-boot counts this boot on: the name in
/// LoaderBootCountPath (already with this try taken off). None when this
/// boot is not counted.
fn counted_boot(root: &Path) -> Option<Image> {
    let path = efivar(root, "LoaderBootCountPath")?;
    let name = path.rsplit(['\\', '/']).next()?;
    Image::parse(name).filter(|i| i.left.is_some())
}

/// How a machine boots, for its health report: one of
/// crate::report::BOOT_STATES, "" when it cannot tell (not an installed
/// server, or not root: the ESP is root's alone).
pub fn state(root: &Path) -> &'static str {
    let Some(run) = running(root) else {
        return "";
    };
    if run == Kernel::Fallback {
        return "fallback";
    }
    if !installed(root, Kernel::Fallback) {
        return "no-fallback";
    }
    if !fsx::under(root, "/sys/firmware/efi").is_dir() {
        return "manual";
    }
    match images(&fsx::under(root, ESP_LINUX)) {
        Ok(imgs) if imgs.iter().any(|i| i.kernel == Kernel::Fallback && !i.bad()) => "ready",
        Ok(_) => "fallback-broken",
        Err(_) => "",
    }
}

// ---- the image itself ----

/// What a unified kernel image says about itself, from its PE headers.
#[derive(Debug, Default, PartialEq)]
struct Uki {
    /// The kernel release in its .uname section.
    uname: Option<String>,
}

fn le16(b: &[u8], at: usize) -> u64 {
    u64::from(u16::from_le_bytes([b[at], b[at + 1]]))
}

fn le32(b: &[u8], at: usize) -> u64 {
    u64::from(u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]))
}

/// Reads an image's headers and refuses one that cannot start: not a PE
/// file, cut short (a section ends past the end of the file), or without
/// a kernel or initramfs. Only the headers and .uname are read.
fn read_uki(path: &Path) -> Result<Uki> {
    let f = File::open(path).map_err(|e| Error::from(e).wrap(format!("open {}", path.display())))?;
    let len = f.metadata()?.len();
    let at = |buf: &mut [u8], off: u64| -> Result<()> {
        if off.saturating_add(buf.len() as u64) > len {
            bail!("{} is cut short ({len} bytes)", path.display());
        }
        f.read_exact_at(buf, off).map_err(|e| Error::from(e).wrap(format!("read {}", path.display())))
    };
    let mut dos = [0u8; 64];
    at(&mut dos, 0)?;
    if &dos[..2] != b"MZ" {
        bail!("{} is not an EFI program", path.display());
    }
    let pe = le32(&dos, 0x3c);
    let mut coff = [0u8; 24];
    at(&mut coff, pe)?;
    if &coff[..4] != b"PE\0\0" {
        bail!("{} is not an EFI program (no PE header)", path.display());
    }
    let (count, opt) = (le16(&coff, 6), le16(&coff, 20));
    if count == 0 || count > 96 {
        bail!("{} has {count} sections", path.display());
    }
    let mut table = vec![0u8; count as usize * 40];
    at(&mut table, pe + 24 + opt)?;
    let mut uki = Uki::default();
    let mut found = BTreeSet::new();
    for s in table.as_chunks::<40>().0 {
        let name = String::from_utf8_lossy(&s[..8]).trim_end_matches('\0').to_string();
        let (vsize, raw, ptr) = (le32(s, 8), le32(s, 16), le32(s, 20));
        if ptr + raw > len {
            bail!("{} is cut short: its {name} section ends after the end of the file", path.display());
        }
        if raw > 0 {
            found.insert(name.clone());
        }
        if name == ".uname" {
            let mut b = vec![0u8; vsize.min(raw).min(256) as usize];
            at(&mut b, ptr)?;
            uki.uname = Some(String::from_utf8_lossy(&b).trim_end_matches('\0').trim().to_string());
        }
    }
    for want in [".linux", ".initrd"] {
        if !found.contains(want) {
            bail!("{} has no {want} section: not a unified kernel image", path.display());
        }
    }
    Ok(uki)
}

fn sync_file(path: &Path) -> Result<()> {
    File::open(path).and_then(|f| f.sync_all()).map_err(|e| Error::from(e).wrap(format!("sync {}", path.display())))
}

/// Flushes a directory's entries (renames, removals). Some file systems
/// refuse fsync on a directory; then the next sync writes them.
fn sync_dir(dir: &Path) {
    let _ = File::open(dir).and_then(|f| f.sync_all());
}

fn remove_quietly(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(Error::from(e).wrap(format!("remove {}", path.display()))),
        _ => Ok(()),
    }
}

/// Why the ESP may be too full for the next kernel update, if it is.
fn space_warning(free: u64, image: u64) -> Option<String> {
    let need = image.saturating_add(ESP_LOW);
    (free < need).then(|| {
        format!(
            "warning: only {} free on /boot, and the next kernel update needs room for a new image of about {} beside the old one",
            crate::report::size(free),
            crate::report::size(image)
        )
    })
}

fn say(out: &mut dyn Write, line: &str) {
    let _ = writeln!(out, "dryserver boot: {line}");
}

// ---- place: the mkinitcpio post hook ----

/// Puts a unified kernel image mkinitcpio made under its staging name
/// (uki, as mkinitcpio names it) in place, for the kernel release kver.
/// Images under any other name (presets of machines installed before) are
/// left alone.
///
/// The steps, each safe to cut the power after:
/// 1. check the staged image, flush it to disk;
/// 2. the fallback kernel: when a good image of the same kernel release is
///    there, keep it and drop the staged one;
/// 3. rename it to its counted name (uncounted without a fallback kernel:
///    there is nothing to fall back to);
/// 4. remove the older images of that kernel.
pub fn place(root: &Path, uki: &str, kver: &str, out: &mut dyn Write) -> Result<()> {
    let kernel = Kernel::ALL.into_iter().find(|k| k.staged() == uki);
    let Some(kernel) = kernel else {
        if !uki.is_empty() {
            say(out, &format!("{uki} is not a dryserver staging image; left as it is"));
        }
        return Ok(());
    };
    let _lock = fsx::lock(fsx::under(root, LOCK))?;
    let dir = fsx::under(root, ESP_LINUX);
    let staged = fsx::under(root, uki);
    let checked = read_uki(&staged).and_then(|u| match &u.uname {
        Some(have) if !kver.is_empty() && *have != kver => bail!("{uki} is for kernel {have}, not {kver}"),
        _ => Ok(u),
    });
    if let Err(e) = checked {
        let _ = remove_quietly(&staged);
        sync_dir(&dir);
        return Err(e.wrap("the new boot image cannot start, so it is not used (the old one stays)"));
    }
    sync_file(&staged)?;
    let size = fs::metadata(&staged).map(|m| m.len()).unwrap_or(0);
    let old: Vec<Image> = images(&dir)?.into_iter().filter(|i| i.kernel == kernel).collect();
    if kernel == Kernel::Fallback {
        let same = |i: &&Image| i.left.is_none() && read_uki(&dir.join(&i.name)).is_ok_and(|u| u.uname.as_deref() == Some(kver));
        if let Some(keep) = old.iter().find(same) {
            remove_quietly(&staged)?;
            for i in old.iter().filter(|i| i.name != keep.name) {
                remove_quietly(&dir.join(&i.name))?;
            }
            sync_dir(&dir);
            say(out, &format!("kept {}: the fallback kernel {kver} did not change, so it keeps the image it was made with", keep.name));
            return Ok(());
        }
    }
    let counted = installed(root, Kernel::Fallback);
    let name = if counted { kernel.counted(TRIES, 0) } else { format!("{}.efi", kernel.image()) };
    fsx::rename(&staged, dir.join(&name))?;
    sync_dir(&dir);
    for i in old.iter().filter(|i| i.name != name) {
        remove_quietly(&dir.join(&i.name))?;
    }
    sync_dir(&dir);
    if counted {
        say(out, &format!("{name} is in place for kernel {kver}: {TRIES} tries to pass its boot check, then the other kernel starts"));
    } else {
        say(out, &format!("{name} is in place for kernel {kver} (no fallback kernel installed, so it is not counted)"));
    }
    if let Some(w) = fsx::space(&dir).ok().and_then(|(_, free)| space_warning(free, size)) {
        say(out, &w);
    }
    Ok(())
}

// ---- mark: the pacman hook before a kernel goes ----

/// Before pacman removes kernels (targets: their usr/lib/modules/V/vmlinuz
/// as pacman passes them, one per line), leaves each one's image one try
/// at most. Nothing without a fallback kernel to start instead.
pub fn mark(root: &Path, targets: &str, out: &mut dyn Write) -> Result<()> {
    if !installed(root, Kernel::Fallback) {
        return Ok(());
    }
    let mut kernels = BTreeSet::new();
    for line in targets.lines().take(1024) {
        let Some(ver) = line.trim().strip_prefix("usr/lib/modules/").and_then(|r| r.strip_suffix("/vmlinuz")) else {
            continue;
        };
        if ver.is_empty() || ver.contains('/') || ver == "." || ver == ".." {
            continue;
        }
        let pkgbase = fsx::read_or_empty(fsx::under(root, format!("/usr/lib/modules/{ver}/pkgbase")));
        if let Some(k) = Kernel::from_pkgbase(pkgbase.trim()) {
            kernels.insert(k);
        }
    }
    if kernels.is_empty() {
        return Ok(());
    }
    let _lock = fsx::lock(fsx::under(root, LOCK))?;
    let dir = fsx::under(root, ESP_LINUX);
    for i in images(&dir)?.into_iter().filter(|i| kernels.contains(&i.kernel)) {
        let new = match i.left {
            None => i.kernel.counted(1, 0),
            Some(n) if n > 1 => i.kernel.counted(1, i.done),
            Some(_) => continue,
        };
        fsx::rename(dir.join(&i.name), dir.join(&new))?;
        say(out, &format!("{} is now {new}: its kernel is being replaced, so it gets one more try until the new image is made", i.name));
    }
    sync_dir(&dir);
    Ok(())
}

// ---- check: is this boot good? ----

/// How long the check waits for what comes up late.
#[derive(Debug, Clone)]
pub struct CheckLimits {
    /// For sshd and for a network device each.
    pub wait: Duration,
    pub poll: Duration,
    /// Before a restart: time to read the reason on the console.
    pub reboot_delay: Duration,
}

impl Default for CheckLimits {
    fn default() -> Self {
        CheckLimits { wait: Duration::from_secs(60), poll: Duration::from_secs(2), reboot_delay: Duration::from_secs(30) }
    }
}

/// Whether / is mounted read-write, from the kernel's list of mounts.
fn root_writable(root: &Path) -> bool {
    let mounts = fsx::read_or_empty(fsx::under(root, "/proc/self/mounts"));
    // The last mount on / is the one in use.
    let mut opts = mounts.lines().filter_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        (f.len() >= 4 && f[1] == "/").then(|| f[3].to_string())
    });
    opts.next_back().is_some_and(|o| o.split(',').any(|x| x == "rw"))
}

/// Network devices the kernel found on real hardware (a driver bound to
/// a device): not lo, not WireGuard, bridges or other virtual ones. A
/// cable, a router or the brain do not matter here.
fn network_devices(root: &Path) -> Vec<String> {
    let Ok(rd) = fs::read_dir(fsx::under(root, "/sys/class/net")) else {
        return Vec::new();
    };
    let mut v: Vec<String> =
        rd.flatten().take(256).filter(|e| e.path().join("device").exists()).map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    v.sort();
    v
}

fn wait_for(ctx: &Ctx, lim: &CheckLimits, mut ok: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + lim.wait;
    loop {
        if ok() {
            return true;
        }
        if Instant::now() >= end || ctx.sleep(lim.poll).is_err() {
            return false;
        }
    }
}

/// Decides whether this boot is good, before boot-complete.target: / is
/// writable, the running kernel's modules are on disk, sshd runs, and the
/// kernel found a network device. Err when it is not; then, when the boot
/// is counted and another image is not marked bad, the machine restarts,
/// so the boot loader tries again or starts the other kernel. Otherwise it
/// stays up as it is: restarting would only start the same image again.
pub fn check(ctx: &Ctx, run: &dyn Runner, root: &Path, lim: &CheckLimits, out: &mut dyn Write) -> Result<()> {
    let mut problems = Vec::new();
    if !root_writable(root) {
        problems.push("/ is not mounted read-write".to_string());
    }
    let rel = osrelease(root);
    if rel.is_empty() || rel.contains('/') || !fsx::under(root, format!("/usr/lib/modules/{rel}/vmlinuz")).is_file() {
        problems.push(format!("the modules of the running kernel {rel} are not on disk"));
    }
    let sshd = Cmd::new("systemctl", &["is-active", "--quiet", "sshd.service"]);
    if !wait_for(ctx, lim, || run.ok(ctx, &sshd).is_ok()) {
        problems.push("sshd does not run".into());
    }
    if !wait_for(ctx, lim, || !network_devices(root).is_empty()) {
        problems.push("the kernel found no network device".into());
    }
    let image = counted_boot(root);
    let shown = image.as_ref().map(|i| i.name.clone()).unwrap_or_else(|| "this boot".into());
    if problems.is_empty() {
        say(out, &format!("{shown} passed the boot check (kernel {rel}, network {})", network_devices(root).join(" ")));
        return Ok(());
    }
    let why = problems.join("; ");
    say(out, &format!("{shown} failed the boot check: {why}"));
    let others: Vec<Image> = images(&fsx::under(root, ESP_LINUX))
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !i.bad() && image.as_ref().is_none_or(|c| c.name != i.name))
        .collect();
    match &image {
        Some(_) if !others.is_empty() => {
            say(
                out,
                &format!(
                    "restarting in {}s: the boot loader tries again or starts the next image ({})",
                    lim.reboot_delay.as_secs(),
                    others.iter().map(|i| i.name.as_str()).collect::<Vec<_>>().join(", ")
                ),
            );
            ctx.sleep(lim.reboot_delay)?;
            run.ok(ctx, &Cmd::new("systemctl", &["--no-block", "reboot"]))?;
        }
        Some(_) => say(out, "staying up: no other kernel image is left to try"),
        None => say(out, "staying up: this boot is not counted, so a restart would start the same image again"),
    }
    Err(errf!("boot check failed: {why}"))
}

// ---- status, for people ----

pub fn status(root: &Path, out: &mut dyn Write) -> Result<()> {
    let rel = osrelease(root);
    let kernel = running(root).map(|k| k.pkgbase()).unwrap_or("?");
    writeln!(out, "running kernel: {rel} ({kernel})")?;
    if let Some(e) = efivar(root, "LoaderEntrySelected") {
        writeln!(out, "started by systemd-boot from: {e}")?;
    }
    if let Some(d) = efivar(root, "LoaderEntryDefault") {
        writeln!(out, "warning: the default entry is pinned to {d} (bootctl set-default, or d in the boot menu):")?;
        writeln!(out, "  systemd-boot starts it even when it failed; undo with: bootctl set-default \"\"")?;
    }
    let installed: Vec<&str> = Kernel::ALL.into_iter().filter(|k| installed(root, *k)).map(|k| k.pkgbase()).collect();
    writeln!(out, "kernels installed: {}", if installed.is_empty() { "?".to_string() } else { installed.join(", ") })?;
    let dir = fsx::under(root, ESP_LINUX);
    if dir.is_dir() {
        let imgs = images(&dir)?;
        writeln!(out, "boot images in {ESP_LINUX}:")?;
        if imgs.is_empty() {
            writeln!(out, "  none")?;
        }
        for i in &imgs {
            writeln!(out, "  {:<24} {:<10} {}", i.name, i.kernel.pkgbase(), i.describe())?;
        }
        for k in Kernel::ALL {
            if fsx::under(root, k.staged()).exists() {
                writeln!(out, "  {} is left from an image that was not finished: run sudo mkinitcpio -P", k.staged())?;
            }
        }
    }
    let what = match state(root) {
        "ready" => "the fallback kernel waits: a main kernel that does not boot is tried 3 times, then linux-lts starts",
        "fallback" => "THE FALLBACK KERNEL RUNS: the main kernel did not boot (or was picked by hand)",
        "no-fallback" => "no fallback kernel: a kernel that does not boot leaves this machine down (installed before linux-lts)",
        "manual" => "BIOS: linux-lts is in GRUB's menu (Advanced options), picked by hand only",
        "fallback-broken" => "the fallback kernel's image is missing or failed: run sudo mkinitcpio -P",
        _ => "unknown (run as root)",
    };
    writeln!(out, "fallback: {what}")?;
    Ok(())
}

// ---- the command line ----

/// `dryserver boot place|mark|check|status`.
pub fn cli(args: &[String]) -> Result<()> {
    let root = Path::new("/");
    let verb = args.first().map(String::as_str).unwrap_or("status");
    if verb != "status" && !fsx::is_root() {
        bail!("run as root (sudo)");
    }
    let mut out = io::stdout();
    match verb {
        // mkinitcpio: kernel, initramfs and, for a UKI, its path.
        "place" => {
            let uki = args.get(3).map(String::as_str).unwrap_or("");
            let kver = std::env::var("KERNELVERSION").unwrap_or_default();
            place(root, uki, &kver, &mut out)
        }
        "mark" => {
            let mut targets = String::new();
            io::stdin().take(1 << 20).read_to_string(&mut targets)?;
            mark(root, &targets, &mut out)
        }
        "check" => check(&Ctx::on_signals(), &ExecRunner::silent(), root, &CheckLimits::default(), &mut out),
        "status" => status(root, &mut out),
        other => bail!("unknown boot command {other:?}: place, mark, check or status"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, put};
    use std::path::PathBuf;
    use std::sync::Mutex;

    const MAIN_V: &str = "6.17.8-arch1-1";
    const LTS_V: &str = "6.12.58-1-lts";

    /// A minimal unified kernel image: PE headers and the sections
    /// mkinitcpio's ukify writes, the kernel and initramfs filled with tag.
    fn uki(kver: &str, tag: &str) -> Vec<u8> {
        let sections: [(&str, Vec<u8>); 4] = [
            (".osrel", format!("ID=arch\nVERSION_ID={kver}\n").into_bytes()),
            (".uname", kver.as_bytes().to_vec()),
            (".linux", format!("kernel {tag}").into_bytes()),
            (".initrd", format!("initramfs {tag}").into_bytes()),
        ];
        let mut b = vec![0u8; 64];
        b[..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&64u32.to_le_bytes());
        b.extend_from_slice(b"PE\0\0");
        let mut coff = [0u8; 20];
        coff[..2].copy_from_slice(&0x8664u16.to_le_bytes());
        coff[2..4].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        b.extend_from_slice(&coff);
        let mut data_at = 64 + 24 + 40 * sections.len();
        let mut data = Vec::new();
        for (name, content) in &sections {
            let mut s = [0u8; 40];
            s[..name.len()].copy_from_slice(name.as_bytes());
            s[8..12].copy_from_slice(&(content.len() as u32).to_le_bytes());
            s[16..20].copy_from_slice(&(content.len() as u32).to_le_bytes());
            s[20..24].copy_from_slice(&(data_at as u32).to_le_bytes());
            b.extend_from_slice(&s);
            data.extend_from_slice(content);
            data_at += content.len();
        }
        b.extend_from_slice(&data);
        b
    }

    fn set_efivar(root: &Path, name: &str, value: &str) {
        let mut b = vec![7u8, 0, 0, 0];
        for u in value.encode_utf16().chain([0]) {
            b.extend_from_slice(&u.to_le_bytes());
        }
        put(root, &format!("/sys/firmware/efi/efivars/{name}-{LOADER_GUID}"), b);
    }

    /// A UEFI server running the main kernel, with or without linux-lts.
    fn machine(lts: bool) -> TempDir {
        let dir = TempDir::new();
        let root = dir.path();
        put(root, "/proc/sys/kernel/osrelease", format!("{MAIN_V}\n"));
        put(root, &format!("/usr/lib/modules/{MAIN_V}/vmlinuz"), "k");
        put(root, &format!("/usr/lib/modules/{MAIN_V}/pkgbase"), "linux\n");
        if lts {
            put(root, &format!("/usr/lib/modules/{LTS_V}/vmlinuz"), "k");
            put(root, &format!("/usr/lib/modules/{LTS_V}/pkgbase"), "linux-lts\n");
        }
        fs::create_dir_all(fsx::under(root, ESP_LINUX)).unwrap();
        fs::create_dir_all(fsx::under(root, "/sys/firmware/efi/efivars")).unwrap();
        put(root, "/proc/self/mounts", "proc /proc proc rw 0 0\n/dev/mapper/root / ext4 rw,relatime 0 0\n/dev/vda1 /boot vfat rw 0 0\n");
        put(root, "/sys/class/net/lo/operstate", "unknown\n");
        put(root, "/sys/class/net/enp1s0/device", "");
        dir
    }

    fn esp(root: &Path) -> PathBuf {
        fsx::under(root, ESP_LINUX)
    }

    fn names(root: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(esp(root)).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        v.sort();
        v
    }

    fn put_image(root: &Path, name: &str, kver: &str, tag: &str) {
        put(root, &format!("{ESP_LINUX}/{name}"), uki(kver, tag));
    }

    fn stage(root: &Path, k: Kernel, kver: &str, tag: &str) {
        put(root, &k.staged(), uki(kver, tag));
    }

    fn place_ok(root: &Path, k: Kernel, kver: &str) -> String {
        let mut out = Vec::new();
        place(root, &k.staged(), kver, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    fn image_tag(root: &Path, name: &str) -> String {
        String::from_utf8_lossy(&fs::read(esp(root).join(name)).unwrap()).to_string()
    }

    #[test]
    fn image_names() {
        let p = |s: &str| Image::parse(s).map(|i| (i.kernel, i.left, i.done));
        assert_eq!(p("arch-linux.efi"), Some((Kernel::Main, None, 0)));
        assert_eq!(p("arch-linux+3.efi"), Some((Kernel::Main, Some(3), 0)));
        assert_eq!(p("arch-linux+2-1.efi"), Some((Kernel::Main, Some(2), 1)));
        assert_eq!(p("arch-linux-lts.efi"), Some((Kernel::Fallback, None, 0)));
        assert_eq!(p("arch-linux-lts+0-3.efi"), Some((Kernel::Fallback, Some(0), 3)));
        assert!(Image::parse("arch-linux-lts+0-3.efi").unwrap().bad());
        for junk in [
            "arch-linux.efi.new",
            "arch-linux-lts.efi.new",
            "arch-linux+.efi",
            "arch-linux+3-.efi",
            "arch-linux+x.efi",
            "arch-linux+-1.efi",
            "arch-linux+1-2-3.efi",
            "arch-linuxx.efi",
            "ARCH-LINUX.efi",
            "arch-linux-fallback.efi",
            "arch-linux+99999999999.efi",
            "arch-linux",
        ] {
            assert_eq!(Image::parse(junk), None, "{junk}");
        }
        for k in Kernel::ALL {
            for (l, d) in [(3, 0), (1, 0), (0, 3), (2, 1)] {
                let i = Image::parse(&k.counted(l, d)).unwrap();
                assert_eq!((i.kernel, i.left, i.done), (k, Some(l), d));
            }
            // What mkinitcpio writes is never started by systemd-boot (it
            // starts *.efi only), and is no image here either.
            assert!(!k.staged().ends_with(".efi") && k.staged().starts_with(&format!("{ESP_LINUX}/")));
            // mkinitcpio: default_uki is the image's name (removed when its
            // kernel goes); the options after it make it in staging.
            let p = k.preset();
            assert!(p.contains(&format!("\ndefault_uki=\"{ESP_LINUX}/{}.efi\"\n", k.image())), "{p}");
            assert!(p.ends_with(&format!("\ndefault_options=\"--uki {}\"\n", k.staged())), "{p}");
            assert!(p.contains(&format!("\nALL_kver=\"/boot/vmlinuz-{}\"\n", k.pkgbase())));
            assert!(p.contains("\nPRESETS=('default')\n") && !p.contains("_image"), "one UKI per kernel, nothing else: {p}");
        }
    }

    #[test]
    fn a_new_main_image_is_counted_and_the_old_one_goes() {
        let dir = machine(true);
        let root = dir.path();
        put_image(root, "arch-linux.efi", "6.17.7-arch1-1", "old");
        put_image(root, "arch-linux-lts.efi", LTS_V, "lts");
        stage(root, Kernel::Main, MAIN_V, "new");
        let out = place_ok(root, Kernel::Main, MAIN_V);
        assert_eq!(names(root), ["arch-linux+3.efi", "arch-linux-lts.efi"]);
        assert!(image_tag(root, "arch-linux+3.efi").contains("kernel new"));
        assert!(out.contains("arch-linux+3.efi is in place") && out.contains("3 tries"), "{out}");
        // Made again before it was ever started (two updates without a
        // reboot): the newer one takes its place.
        stage(root, Kernel::Main, MAIN_V, "newer");
        place_ok(root, Kernel::Main, MAIN_V);
        assert_eq!(names(root), ["arch-linux+3.efi", "arch-linux-lts.efi"]);
        assert!(image_tag(root, "arch-linux+3.efi").contains("kernel newer"));
    }

    #[test]
    fn a_power_cut_between_rename_and_cleanup_is_finished_by_the_next_image() {
        let dir = machine(true);
        let root = dir.path();
        // The rename was done, the older images not removed yet.
        put_image(root, "arch-linux.efi", "6.17.6-arch1-1", "oldest");
        put_image(root, "arch-linux+1-2.efi", "6.17.7-arch1-1", "old");
        put_image(root, "arch-linux+3.efi", MAIN_V, "new");
        put_image(root, "arch-linux-lts.efi", LTS_V, "lts");
        stage(root, Kernel::Main, MAIN_V, "again");
        place_ok(root, Kernel::Main, MAIN_V);
        assert_eq!(names(root), ["arch-linux+3.efi", "arch-linux-lts.efi"]);
        assert!(image_tag(root, "arch-linux+3.efi").contains("kernel again"));
    }

    #[test]
    fn without_a_fallback_kernel_nothing_is_counted() {
        let dir = machine(false);
        let root = dir.path();
        put_image(root, "arch-linux+3.efi", "6.17.7-arch1-1", "old");
        stage(root, Kernel::Main, MAIN_V, "new");
        let out = place_ok(root, Kernel::Main, MAIN_V);
        assert_eq!(names(root), ["arch-linux.efi"]);
        assert!(out.contains("not counted"), "{out}");
        // Machines installed before: their preset writes the final name,
        // which is left alone, and so is every name that is not ours.
        for other in ["/boot/EFI/Linux/arch-linux.efi", "", "/tmp/arch-linux.efi.new", "/boot/EFI/Linux/arch-linux-fallback.efi.new"] {
            place(root, other, MAIN_V, &mut Vec::new()).unwrap();
            assert_eq!(names(root), ["arch-linux.efi"], "{other}");
        }
    }

    #[test]
    fn the_fallback_image_is_replaced_only_when_its_kernel_changed() {
        let dir = machine(true);
        let root = dir.path();
        put_image(root, "arch-linux.efi", MAIN_V, "main");
        put_image(root, "arch-linux-lts.efi", LTS_V, "proven");
        // New firmware or systemd: mkinitcpio -P makes every image again.
        // The fallback keeps the one it was made with.
        stage(root, Kernel::Fallback, LTS_V, "rebuilt");
        let out = place_ok(root, Kernel::Fallback, LTS_V);
        assert_eq!(names(root), ["arch-linux-lts.efi", "arch-linux.efi"]);
        assert!(image_tag(root, "arch-linux-lts.efi").contains("kernel proven"));
        assert!(out.contains("kept arch-linux-lts.efi"), "{out}");
        assert!(!fsx::under(root, Kernel::Fallback.staged()).exists());
        // One that failed its tries is not kept: a new one gets its chance.
        fs::rename(esp(root).join("arch-linux-lts.efi"), esp(root).join("arch-linux-lts+0-3.efi")).unwrap();
        stage(root, Kernel::Fallback, LTS_V, "rebuilt");
        place_ok(root, Kernel::Fallback, LTS_V);
        assert_eq!(names(root), ["arch-linux-lts+3.efi", "arch-linux.efi"]);
        assert!(image_tag(root, "arch-linux-lts+3.efi").contains("kernel rebuilt"));
        // A new fallback kernel: its new image, counted, in place of the
        // old one, whose modules are gone.
        fs::rename(esp(root).join("arch-linux-lts+3.efi"), esp(root).join("arch-linux-lts.efi")).unwrap();
        stage(root, Kernel::Fallback, "6.12.59-1-lts", "upgraded");
        place_ok(root, Kernel::Fallback, "6.12.59-1-lts");
        assert_eq!(names(root), ["arch-linux-lts+3.efi", "arch-linux.efi"]);
        assert!(image_tag(root, "arch-linux-lts+3.efi").contains("kernel upgraded"));
    }

    #[test]
    fn a_broken_image_is_never_put_in_place() {
        let dir = machine(true);
        let root = dir.path();
        put_image(root, "arch-linux.efi", "6.17.7-arch1-1", "old");
        let good = uki(MAIN_V, "new");
        let mut no_linux = good.clone();
        let at = no_linux.windows(6).position(|w| w == b".linux").unwrap();
        no_linux[at..at + 6].copy_from_slice(b".xinux");
        for (what, bytes, kver) in [
            ("cut short", good[..good.len() - 5].to_vec(), MAIN_V),
            ("empty", Vec::new(), MAIN_V),
            ("not PE", b"#!/bin/sh\necho no\n".repeat(10), MAIN_V),
            ("no kernel", no_linux, MAIN_V),
            ("another kernel", good.clone(), "6.17.9-arch1-1"),
        ] {
            put(root, &Kernel::Main.staged(), &bytes);
            let err = place(root, &Kernel::Main.staged(), kver, &mut Vec::new()).unwrap_err().to_string();
            assert!(err.contains("cannot start") && err.contains("the old one stays"), "{what}: {err}");
            assert_eq!(names(root), ["arch-linux.efi"], "{what}");
            assert!(image_tag(root, "arch-linux.efi").contains("kernel old"), "{what}");
        }
    }

    #[test]
    fn a_replaced_kernel_gets_one_more_try() {
        let dir = machine(true);
        let root = dir.path();
        put_image(root, "arch-linux.efi", MAIN_V, "main");
        put_image(root, "arch-linux-lts.efi", LTS_V, "lts");
        let main = format!("usr/lib/modules/{MAIN_V}/vmlinuz\n");
        let mut out = Vec::new();
        mark(root, &main, &mut out).unwrap();
        assert_eq!(names(root), ["arch-linux+1.efi", "arch-linux-lts.efi"]);
        assert!(String::from_utf8_lossy(&out).contains("arch-linux.efi is now arch-linux+1.efi"));
        // Counted ones keep at most one try; one with none left stays bad.
        for (have, want) in [
            ("arch-linux+3.efi", "arch-linux+1.efi"),
            ("arch-linux+2-1.efi", "arch-linux+1-1.efi"),
            ("arch-linux+1-2.efi", "arch-linux+1-2.efi"),
            ("arch-linux+0-3.efi", "arch-linux+0-3.efi"),
        ] {
            for n in names(root).iter().filter(|n| n.starts_with("arch-linux+")) {
                fs::remove_file(esp(root).join(n)).unwrap();
            }
            put_image(root, have, MAIN_V, "main");
            mark(root, &main, &mut Vec::new()).unwrap();
            assert_eq!(names(root), [want, "arch-linux-lts.efi"], "{have}");
        }
        // The fallback kernel too, and what pacman would never send: paths
        // out of /usr/lib/modules name no kernel, even with a pkgbase there.
        fs::remove_file(esp(root).join("arch-linux+0-3.efi")).unwrap();
        put_image(root, "arch-linux.efi", MAIN_V, "main");
        put(root, "/usr/lib/pkgbase", "linux\n");
        put(root, "/usr/lib/modules/a/b/pkgbase", "linux\n");
        let junk = format!(
            "usr/lib/modules/../vmlinuz\nusr/lib/modules/a/b/vmlinuz\nusr/lib/modules//vmlinuz\nlinux\nusr/lib/modules/{LTS_V}/vmlinuz\n"
        );
        mark(root, &junk, &mut Vec::new()).unwrap();
        assert_eq!(names(root), ["arch-linux-lts+1.efi", "arch-linux.efi"]);
        // Without a fallback kernel nothing is marked: there is nothing
        // else to start.
        let dir = machine(false);
        put_image(dir.path(), "arch-linux.efi", MAIN_V, "main");
        mark(dir.path(), &main, &mut Vec::new()).unwrap();
        assert_eq!(names(dir.path()), ["arch-linux.efi"]);
        // A BIOS machine has no ESP_LINUX.
        let dir = machine(true);
        fs::remove_dir_all(esp(dir.path())).unwrap();
        mark(dir.path(), &main, &mut Vec::new()).unwrap();
    }

    /// Answers systemctl for the boot check and records what ran.
    #[derive(Default)]
    struct Fake {
        ran: Mutex<Vec<String>>,
        /// sshd answers active after this many questions.
        sshd_after: usize,
        sshd_never: bool,
    }

    impl Runner for Fake {
        fn run(&self, _: &Ctx, c: &Cmd) -> (String, Result<()>) {
            let mut ran = self.ran.lock().unwrap();
            ran.push(c.to_string());
            let asked = ran.iter().filter(|l| l.contains("is-active")).count();
            if c.args.iter().any(|a| a == "is-active") && (self.sshd_never || asked <= self.sshd_after) {
                return (String::new(), Err("exit status 3".into()));
            }
            (String::new(), Ok(()))
        }
    }

    fn run_check(root: &Path, fake: &Fake) -> (Result<()>, String) {
        let lim = CheckLimits { wait: Duration::from_millis(200), poll: Duration::from_millis(5), reboot_delay: Duration::ZERO };
        let mut out = Vec::new();
        let res = check(&Ctx::new(), fake, root, &lim, &mut out);
        (res, String::from_utf8(out).unwrap())
    }

    fn rebooted(fake: &Fake) -> bool {
        fake.ran.lock().unwrap().iter().any(|l| l == "systemctl --no-block reboot")
    }

    #[test]
    fn a_good_boot_passes_without_the_brain_or_a_cable() {
        let dir = machine(true);
        let root = dir.path();
        put_image(root, "arch-linux+2-1.efi", MAIN_V, "new");
        put_image(root, "arch-linux-lts.efi", LTS_V, "lts");
        set_efivar(root, "LoaderBootCountPath", "\\EFI\\Linux\\arch-linux+2-1.efi");
        // The cable is out: the device is there, its link is not.
        put(root, "/sys/class/net/enp1s0/carrier", "0\n");
        put(root, "/sys/class/net/enp1s0/operstate", "down\n");
        // sshd comes up a little later.
        let fake = Fake { sshd_after: 2, ..Fake::default() };
        let (res, out) = run_check(root, &fake);
        res.unwrap();
        assert!(out.contains("arch-linux+2-1.efi passed the boot check") && out.contains("enp1s0"), "{out}");
        assert!(!rebooted(&fake));
        // Nothing but systemctl about sshd: no brain, mesh, k3s or internet.
        assert!(fake.ran.lock().unwrap().iter().all(|l| l == "systemctl is-active --quiet sshd.service"), "{:?}", fake.ran);
    }

    #[test]
    fn a_failed_boot_restarts_while_another_image_waits() {
        let dir = machine(true);
        let root = dir.path();
        // A power cut after pacman took the kernel's modules: the old image
        // (marked down to one try) started, its modules are gone.
        fs::remove_dir_all(fsx::under(root, format!("/usr/lib/modules/{MAIN_V}"))).unwrap();
        put_image(root, "arch-linux+0-1.efi", MAIN_V, "old");
        put_image(root, "arch-linux-lts.efi", LTS_V, "lts");
        set_efivar(root, "LoaderBootCountPath", "\\EFI\\Linux\\arch-linux+0-1.efi");
        let fake = Fake::default();
        let (res, out) = run_check(root, &fake);
        let err = res.unwrap_err().to_string();
        assert!(err.contains("modules of the running kernel") && err.contains("not on disk"), "{err}");
        assert!(rebooted(&fake), "{out}");
        assert!(out.contains("restarting") && out.contains("arch-linux-lts.efi"), "{out}");
    }

    #[test]
    fn a_failed_boot_stays_up_when_a_restart_cannot_help() {
        // Every other image failed its tries: a restart would start this
        // one again, and again.
        let dir = machine(true);
        let root = dir.path();
        put_image(root, "arch-linux+0-3.efi", MAIN_V, "main");
        put_image(root, "arch-linux-lts+0-3.efi", LTS_V, "lts");
        set_efivar(root, "LoaderBootCountPath", "\\EFI\\Linux\\arch-linux+0-3.efi");
        // Only lo and virtual devices: the driver for the real one is gone.
        fs::remove_file(fsx::under(root, "/sys/class/net/enp1s0/device")).unwrap();
        put(root, "/sys/class/net/wg0/operstate", "unknown\n");
        let fake = Fake::default();
        let (res, out) = run_check(root, &fake);
        assert!(res.unwrap_err().to_string().contains("no network device"));
        assert!(!rebooted(&fake) && out.contains("staying up: no other kernel image"), "{out}");
        // A boot the boot loader does not count (a good image) never
        // restarts: it would start the same one.
        let dir = machine(true);
        let root = dir.path();
        put_image(root, "arch-linux.efi", MAIN_V, "main");
        put_image(root, "arch-linux-lts.efi", LTS_V, "lts");
        let fake = Fake { sshd_never: true, ..Fake::default() };
        let (res, out) = run_check(root, &fake);
        assert!(res.unwrap_err().to_string().contains("sshd does not run"));
        assert!(!rebooted(&fake) && out.contains("not counted"), "{out}");
    }

    #[test]
    fn a_read_only_root_fails_the_check() {
        let dir = machine(true);
        let root = dir.path();
        put(root, "/proc/self/mounts", "/dev/mapper/root / ext4 rw 0 0\n/dev/mapper/root / ext4 ro,relatime 0 0\n");
        let (res, _) = run_check(root, &Fake::default());
        assert!(res.unwrap_err().to_string().contains("/ is not mounted read-write"));
    }

    #[test]
    fn what_the_report_says_about_booting() {
        let dir = machine(true);
        let root = dir.path();
        put_image(root, "arch-linux.efi", MAIN_V, "main");
        put_image(root, "arch-linux-lts+3.efi", LTS_V, "lts");
        assert_eq!(state(root), "ready");
        fs::rename(esp(root).join("arch-linux-lts+3.efi"), esp(root).join("arch-linux-lts+0-3.efi")).unwrap();
        assert_eq!(state(root), "fallback-broken");
        fs::remove_file(esp(root).join("arch-linux-lts+0-3.efi")).unwrap();
        assert_eq!(state(root), "fallback-broken", "no image for the fallback kernel");
        // The fallback kernel runs; also once a later upgrade took its
        // modules (then its release name says it).
        put(root, "/proc/sys/kernel/osrelease", format!("{LTS_V}\n"));
        assert_eq!(state(root), "fallback");
        fs::remove_dir_all(fsx::under(root, format!("/usr/lib/modules/{LTS_V}"))).unwrap();
        assert_eq!(state(root), "fallback");
        // Installed before linux-lts.
        let dir = machine(false);
        assert_eq!(state(dir.path()), "no-fallback");
        // BIOS: GRUB's menu only.
        let dir = machine(true);
        fs::remove_dir_all(fsx::under(dir.path(), "/sys/firmware/efi")).unwrap();
        assert_eq!(state(dir.path()), "manual");
        // Not a server at all.
        assert_eq!(state(TempDir::new().path()), "");
        for s in ["ready", "fallback", "no-fallback", "manual", "fallback-broken"] {
            assert!(crate::report::BOOT_STATES.contains(&s), "{s}");
        }
    }

    #[test]
    fn status_for_people() {
        let dir = machine(true);
        let root = dir.path();
        put_image(root, "arch-linux+1-2.efi", MAIN_V, "main");
        put_image(root, "arch-linux-lts.efi", LTS_V, "lts");
        stage(root, Kernel::Main, MAIN_V, "half");
        set_efivar(root, "LoaderEntrySelected", "arch-linux+1-2.efi");
        set_efivar(root, "LoaderEntryDefault", "arch-linux.efi");
        let mut out = Vec::new();
        status(root, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        for want in [
            &format!("running kernel: {MAIN_V} (linux)"),
            "started by systemd-boot from: arch-linux+1-2.efi",
            "the default entry is pinned to arch-linux.efi",
            "kernels installed: linux, linux-lts",
            "being tried: 2 tries done, 1 left",
            "good (it booted well)",
            "arch-linux.efi.new is left from an image that was not finished",
            "fallback: the fallback kernel waits",
        ] {
            assert!(out.contains(want), "missing {want:?}:\n{out}");
        }
    }

    #[test]
    fn the_files_that_wire_it_up() {
        // Only local signs count: nothing the brain, the mesh or k3s
        // decides may hold the check up or fail it.
        let unit = CHECK_UNIT_TEXT;
        let after = unit.lines().find(|l| l.starts_with("After=")).unwrap();
        for never in ["multi-user", "k3s", "wg-quick", "network-online", "dryserver-sync", "time-sync"] {
            assert!(!after.contains(never), "{after}");
        }
        assert!(unit.contains("\nBefore=boot-complete.target\n") && unit.contains("\nExecStart=/usr/local/bin/dryserver boot check\n"));
        assert!(unit.contains("\nType=oneshot\nRemainAfterExit=yes\n"), "{unit}");
        let name = CHECK_UNIT_PATH.rsplit('/').next().unwrap();
        assert!(COMPLETE_DROPIN_TEXT.contains(&format!("[Unit]\nRequires={name}\n")), "{COMPLETE_DROPIN_TEXT}");
        assert!(COMPLETE_DROPIN.starts_with("/etc/systemd/system/boot-complete.target.d/"));
        // mkinitcpio passes kernel, initramfs and UKI; all of them go on.
        assert!(POST_HOOK_TEXT.starts_with("#!/bin/sh\n") && POST_HOOK_TEXT.ends_with("exec /usr/local/bin/dryserver boot place \"$@\"\n"));
        // Before the transaction, on a kernel going; never stops pacman.
        for want in ["Type = Path", "Operation = Remove", "Target = usr/lib/modules/*/vmlinuz", "When = PreTransaction", "NeedsTargets"] {
            assert!(MARK_HOOK_TEXT.contains(&format!("{want}\n")), "{want}");
        }
        assert!(!MARK_HOOK_TEXT.contains("AbortOnFail") && !MARK_HOOK_TEXT.contains("Operation = Upgrade"));
        assert!(MARK_HOOK.ends_with(".hook") && MARK_HOOK.starts_with("/etc/pacman.d/hooks/"));
        assert!(WATCHDOG_TEXT.contains("[Manager]\nRuntimeWatchdogSec=") && WATCHDOG_TEXT.contains("\nCrashAction=reboot\n"));
        // Only in the initramfs; never fails emergency.service itself.
        assert!(EMERGENCY_DROPIN.starts_with("/etc/systemd/system/emergency.service.d/"));
        assert!(
            EMERGENCY_TEXT.contains("[Service]\nExecStartPre=-/usr/bin/sh -c 'test -e /etc/initrd-release || exit 0;"),
            "{EMERGENCY_TEXT}"
        );
        assert!(EMERGENCY_TEXT.contains("systemctl --no-block reboot'\n"));
    }

    /// test/validate-boot.sh runs the real mkinitcpio with copies of the
    /// installer's presets.
    #[test]
    fn the_container_check_uses_the_installers_presets() {
        let script = include_str!("../../test/validate-boot.sh");
        for k in Kernel::ALL {
            assert!(script.contains(&format!("<<'EOF'\n{}EOF\n", k.preset())), "test/validate-boot.sh has another {} preset", k.pkgbase());
        }
    }

    #[test]
    fn a_full_boot_partition_is_told() {
        assert!(space_warning(100 << 20, 60 << 20).unwrap().contains("only 100 MiB free on /boot"));
        assert_eq!(space_warning(800 << 20, 60 << 20), None);
    }

    #[test]
    fn efi_variables() {
        let dir = TempDir::new();
        let root = dir.path();
        assert_eq!(efivar(root, "LoaderBootCountPath"), None);
        set_efivar(root, "LoaderBootCountPath", "\\EFI\\Linux\\arch-linux-lts+2-1.efi");
        let i = counted_boot(root).unwrap();
        assert_eq!((i.kernel, i.left, i.done), (Kernel::Fallback, Some(2), 1));
        set_efivar(root, "LoaderBootCountPath", "\\EFI\\Linux\\arch-linux-lts.efi");
        assert_eq!(counted_boot(root), None, "a name without counter is no counted boot");
        put(root, &format!("/sys/firmware/efi/efivars/LoaderBootCountPath-{LOADER_GUID}"), [7u8, 0]);
        assert_eq!(efivar(root, "LoaderBootCountPath"), None);
    }
}
