//! What a machine says about itself: its versions, whether it waits for a
//! reboot, when it was last upgraded, load, memory, disk, temperature,
//! whether k3s and the firewall run, and how fresh its WireGuard links
//! are. Servers send it with every sync, the coordinator keeps the newest
//! one per member, and the admin's desktop shows it. `dryserver report`
//! prints it, for whoever asks a machine directly.
//!
//! Gathering never fails: what cannot be read stays empty, and a field
//! that takes too long is given up. A report is a machine's word about
//! itself, relayed by the coordinator: every reader checks it again
//! (sanitized), and a machine that lies changes only its own row.
//!
//! Fields are only ever added. A reader that meets one in a form it does
//! not know reads it as empty (lenient) instead of refusing the heartbeat
//! around it.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};

use crate::cidr::parse_ip4;
use crate::ctx::Ctx;
use crate::gotime::Time;
use crate::runner::{Cmd, Runner};
use crate::{fsx, mesh};

/// The form of the report this version writes.
pub const FORMAT: u32 = 1;
/// At most this many WireGuard peers are kept: a /24 mesh has 253 other
/// machines.
pub const MAX_PEERS: usize = 254;
/// The longest version string kept.
const MAX_TEXT: usize = 64;
/// Longer durations are nonsense (about 100 years).
const MAX_SECS: u64 = 100 * 365 * 86_400;
/// Later times are nonsense (the year 2200).
const MAX_TIME: i64 = 7_258_118_400;
/// More bytes than any of these machines has (1 PiB).
const MAX_BYTES: u64 = 1 << 50;
const MAX_LOAD: f64 = 100_000.0;
const MAX_CPUS: u32 = 4096;
/// Where k3s is installed.
pub const K3S_BIN: &str = "/usr/local/bin/k3s";
/// `k3s --version` with the binary's change time and size: asked again
/// only when the binary changes, not every minute.
const K3S_VERSION_CACHE: &str = "/run/dryserver-k3s-version";
const PACMAN_LOG: &str = "/var/log/pacman.log";
/// How much of the end of pacman's log is searched for the last upgrade.
/// One upgrade writes far less; more than this since the last one means
/// the machine has not been upgraded for a long time.
const PACMAN_TAIL: u64 = 512 << 10;
/// Everything gathered together; a tool that hangs costs its field only.
const GATHER_TIMEOUT: Duration = Duration::from_secs(10);

// What needs the admin's attention.
const DISK_FULL: u32 = 90;
const MEMORY_FULL: u32 = 90;
const HOT: i32 = 85;
/// Further off than this, TLS and the cluster start to fail.
const CLOCK_OFF: i64 = 120;
const UPGRADE_DUE: i64 = 30 * 86_400;
/// WireGuard shakes hands every two minutes on a link in use, and the
/// mesh's keepalive keeps every link in use.
pub const PEER_SILENT: u64 = 300;

/// A machine's report about itself.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Report {
    /// The form of the report (FORMAT when it was written).
    #[serde(deserialize_with = "lenient")]
    pub format: u32,
    /// The machine's own clock when it made the report, Unix seconds.
    #[serde(deserialize_with = "lenient")]
    pub time: i64,
    /// dryserver's version.
    #[serde(deserialize_with = "lenient")]
    pub dryserver: String,
    /// k3s's version, "" when k3s is not installed.
    #[serde(deserialize_with = "lenient")]
    pub k3s: String,
    /// The running kernel.
    #[serde(deserialize_with = "lenient")]
    pub kernel: String,
    /// The newest kernel on disk.
    #[serde(deserialize_with = "lenient")]
    pub kernel_installed: String,
    /// The running kernel is not on disk any more: an upgrade replaced it,
    /// and only a reboot starts the new one.
    #[serde(deserialize_with = "lenient")]
    pub reboot: bool,
    /// When pacman last started a full system upgrade, or else when the
    /// machine was installed; Unix seconds by the machine's clock, 0
    /// unknown.
    #[serde(deserialize_with = "lenient")]
    pub upgraded: i64,
    /// Seconds since boot.
    #[serde(deserialize_with = "lenient")]
    pub uptime: u64,
    /// Load average over 1, 5 and 15 minutes.
    #[serde(deserialize_with = "lenient")]
    pub load: [f64; 3],
    #[serde(deserialize_with = "lenient")]
    pub cpus: u32,
    /// Memory in use (not available to programs) and in all, bytes.
    #[serde(deserialize_with = "lenient")]
    pub mem_used: u64,
    #[serde(deserialize_with = "lenient")]
    pub mem_total: u64,
    /// The root file system, bytes.
    #[serde(deserialize_with = "lenient")]
    pub disk_used: u64,
    #[serde(deserialize_with = "lenient")]
    pub disk_total: u64,
    /// The hottest sensor, °C; none without sensors.
    #[serde(deserialize_with = "lenient", skip_serializing_if = "Option::is_none")]
    pub temp: Option<i32>,
    /// k3s.service runs; none when k3s is not installed.
    #[serde(deserialize_with = "lenient", skip_serializing_if = "Option::is_none")]
    pub k3s_active: Option<bool>,
    /// The `inet dryserver` firewall table is loaded; none when the
    /// machine could not tell (nft needs root).
    #[serde(deserialize_with = "lenient", skip_serializing_if = "Option::is_none")]
    pub firewall: Option<bool>,
    /// The WireGuard peers by mesh host number, with the age of their
    /// newest handshake.
    #[serde(deserialize_with = "lenient_list", skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<Peer>,
    /// The signed release this machine runs, by serial; 0 before its
    /// first update.
    #[serde(deserialize_with = "lenient", skip_serializing_if = "is_zero")]
    pub release: u64,
    /// Where its update stands: "" nothing going on, or one of
    /// UPDATE_STATES.
    #[serde(deserialize_with = "lenient", skip_serializing_if = "String::is_empty")]
    pub update: String,
    /// The release that update is about.
    #[serde(deserialize_with = "lenient", skip_serializing_if = "is_zero")]
    pub update_serial: u64,
    /// Why, in a few words: printable ASCII, at most MAX_NOTE characters.
    #[serde(deserialize_with = "lenient", skip_serializing_if = "String::is_empty")]
    pub update_note: String,
    /// Which kernel runs and whether the other one waits: one of
    /// BOOT_STATES, "" when the machine cannot tell.
    #[serde(deserialize_with = "lenient", skip_serializing_if = "String::is_empty")]
    pub boot: String,
    /// Its address on the home network, as it reaches the coordinator
    /// there: where the admin's `NAME.lan` and the kill switch go.
    #[serde(deserialize_with = "lenient", skip_serializing_if = "String::is_empty")]
    pub lan: String,
    /// The machine's SSH host key's signature over signed_text: the
    /// registry account relays the report and could change it. None from
    /// a machine of an older version.
    #[serde(deserialize_with = "lenient", skip_serializing_if = "String::is_empty")]
    pub sig: String,
}

/// How a machine boots (see install/boot.rs):
/// - ready: the main kernel runs, the fallback kernel (linux-lts) waits;
/// - fallback: the fallback kernel runs: the main one did not boot, or
///   someone picked it;
/// - no-fallback: there is no fallback kernel (installed before there was
///   one): a kernel that does not boot leaves the machine down;
/// - manual: a BIOS machine: the fallback kernel is in GRUB's menu, picked
///   by hand only;
/// - fallback-broken: the fallback kernel's image is missing or failed its
///   tries.
pub const BOOT_STATES: [&str; 5] = ["ready", "fallback", "no-fallback", "manual", "fallback-broken"];

/// What a machine says about its update:
/// - fetching: it has its turn and loads the release from the brain,
/// - pending: installed, not confirmed yet (it goes back by itself if it
///   is not confirmed in time),
/// - failed: installing it did not work,
/// - reverted: it went back to the release it ran before,
/// - refused: the release did not pass this machine's own checks,
/// - held: its kill switch is on; it updates nothing until it is lifted.
pub const UPDATE_STATES: [&str; 6] = ["fetching", "pending", "failed", "reverted", "refused", "held"];
/// The longest update note kept.
pub const MAX_NOTE: usize = 160;
/// The longest signature kept (one by an ed25519 key is about 300 bytes):
/// the heartbeat must stay well within what coordinators read.
const MAX_SIG: usize = 512;
const SIG_BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// A note from a machine made safe to show: printable ASCII only, so no
/// escape sequence reaches a terminal, and at most MAX_NOTE characters.
pub fn note(s: &str) -> String {
    shown(s, MAX_NOTE)
}

/// Text from another machine made safe to show: printable ASCII only, at
/// most max characters. Anything else becomes '?': a terminal obeys
/// control characters (an escape sequence can set the clipboard, the
/// title, or clear the screen), and other characters can pass for what
/// they are not.
pub fn shown(s: &str, max: usize) -> String {
    s.chars().map(|c| if (' '..='~').contains(&c) { c } else { '?' }).take(max).collect()
}

/// Text for the admin's terminal that may carry another machine's words,
/// such as an error: every control character but newline and tab becomes
/// '?', so no escape sequence (and no carriage return that writes over a
/// line) reaches the terminal. Everything else stays as it is.
pub fn printable(s: &str) -> String {
    s.chars().map(|c| if c.is_control() && !matches!(c, '\n' | '\t') { '?' } else { c }).collect()
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Peer {
    #[serde(deserialize_with = "lenient")]
    pub host: u32,
    /// Seconds since the newest handshake; none: never.
    #[serde(deserialize_with = "lenient", skip_serializing_if = "Option::is_none")]
    pub age: Option<u64>,
}

/// Serde helper: a value of the wrong type (or null) reads as the default.
/// One bad field costs that field, not the report or the heartbeat that
/// carries it.
pub fn lenient<'de, D: Deserializer<'de>, T: DeserializeOwned + Default>(d: D) -> Result<T, D::Error> {
    let v = serde_json::Value::deserialize(d)?;
    Ok(serde_json::from_value(v).unwrap_or_default())
}

/// lenient for a report carried in a heartbeat or a member: anything but
/// a JSON object (serde would read a list as the fields in order) is none.
pub fn lenient_report<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Report>, D::Error> {
    let v = serde_json::Value::deserialize(d)?;
    Ok(if v.is_object() { serde_json::from_value(v).ok() } else { None })
}

/// lenient for a list: the entries that read are kept.
fn lenient_list<'de, D: Deserializer<'de>, T: DeserializeOwned>(d: D) -> Result<Vec<T>, D::Error> {
    let v = serde_json::Value::deserialize(d)?;
    let serde_json::Value::Array(items) = v else {
        return Ok(Vec::new());
    };
    Ok(items.into_iter().filter_map(|i| serde_json::from_value(i).ok()).collect())
}

/// A version string, or "" when it has anything but the characters
/// versions are made of or is too long. Cut down it could mislead.
fn text(s: String) -> String {
    let ok = s.len() <= MAX_TEXT && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-' | '_' | ':' | '~'));
    if ok { s } else { String::new() }
}

/// used of total in percent, none when total is 0.
pub fn percent(used: u64, total: u64) -> Option<u32> {
    (total > 0).then(|| (u128::from(used.min(total)) * 100 / u128::from(total)) as u32)
}

impl Report {
    /// The report as a reader may use it: version strings of plain
    /// characters, numbers in their ranges (else 0 or none), at most
    /// MAX_PEERS peers, each once, sorted, and only host numbers for which
    /// fits says yes.
    pub fn sanitized(self, fits: impl Fn(u32) -> bool) -> Report {
        let secs = |s: u64| if s <= MAX_SECS { s } else { 0 };
        let time = |t: i64| if (0..=MAX_TIME).contains(&t) { t } else { 0 };
        let pair = |used: u64, total: u64| if used <= total && total <= MAX_BYTES { (used, total) } else { (0, 0) };
        let mut peers: BTreeMap<u32, Option<u64>> = BTreeMap::new();
        for p in self.peers {
            if peers.len() >= MAX_PEERS {
                break;
            }
            if fits(p.host) {
                peers.entry(p.host).or_insert(p.age.filter(|a| *a <= MAX_SECS));
            }
        }
        let (mem_used, mem_total) = pair(self.mem_used, self.mem_total);
        let (disk_used, disk_total) = pair(self.disk_used, self.disk_total);
        Report {
            format: self.format,
            time: time(self.time),
            dryserver: text(self.dryserver),
            k3s: text(self.k3s),
            kernel: text(self.kernel),
            kernel_installed: text(self.kernel_installed),
            reboot: self.reboot,
            upgraded: time(self.upgraded),
            uptime: secs(self.uptime),
            load: self.load.map(|l| if l.is_finite() && (0.0..=MAX_LOAD).contains(&l) { l } else { 0.0 }),
            cpus: if self.cpus <= MAX_CPUS { self.cpus } else { 0 },
            mem_used,
            mem_total,
            disk_used,
            disk_total,
            temp: self.temp.filter(|t| (-50..=200).contains(t)),
            k3s_active: self.k3s_active,
            firewall: self.firewall,
            peers: peers.into_iter().map(|(host, age)| Peer { host, age }).collect(),
            release: if self.release <= crate::release::MAX_SERIAL { self.release } else { 0 },
            update: if UPDATE_STATES.contains(&self.update.as_str()) { self.update } else { String::new() },
            update_serial: if self.update_serial <= crate::release::MAX_SERIAL { self.update_serial } else { 0 },
            update_note: note(&self.update_note),
            boot: if BOOT_STATES.contains(&self.boot.as_str()) { self.boot } else { String::new() },
            lan: if parse_ip4(&self.lan).is_some() { self.lan } else { String::new() },
            sig: if self.sig.len() <= MAX_SIG && self.sig.starts_with(SIG_BEGIN) { self.sig } else { String::new() },
        }
    }

    /// What the machine signs of its report (sig): who it is (its host
    /// number and WireGuard key, as the admin signed them), when, its
    /// update and its LAN address. Taken from the report as sanitized
    /// leaves it, on both sides.
    pub fn signed_text(&self, host: u32, wg_key: &str) -> String {
        format!(
            "dryserver-report-v1\nhost {host}\nkey {wg_key}\ntime {}\nrelease {}\nupdate {}\nupdate_serial {}\nlan {}\n",
            self.time, self.release, self.update, self.update_serial, self.lan
        )
    }

    /// Signs the report with this machine's SSH host key at key_file, as
    /// member host with WireGuard key wg_key.
    pub fn sign(&mut self, ctx: &Ctx, run: &dyn Runner, key_file: &Path, host: u32, wg_key: &str) -> crate::err::Result<()> {
        let text = self.clone().sanitized(|_| true).signed_text(host, wg_key);
        self.sig = crate::signed::host_sign(ctx, run, key_file, crate::signed::NS_REPORT, &text)?;
        Ok(())
    }

    /// Checks sig: made by the member host (WireGuard key wg_key) with its
    /// SSH host key host_key, both from the list the admin signed.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(&self, ctx: &Ctx, run: &dyn Runner, tmp_dir: &Path, host: u32, wg_key: &str, host_key: &str) -> crate::err::Result<()> {
        if self.sig.is_empty() {
            return Err("not signed".into());
        }
        crate::signed::host_verify(ctx, run, tmp_dir, host_key, crate::signed::NS_REPORT, &self.signed_text(host, wg_key), &self.sig)
    }

    /// Whether its last update did not work.
    pub fn update_failed(&self) -> bool {
        matches!(self.update.as_str(), "failed" | "reverted" | "refused")
    }

    /// How far the machine's clock was from the coordinator's when the
    /// coordinator got the report at seen (by its own clock); none when
    /// either is unknown.
    pub fn clock_offset(&self, seen: Time) -> Option<i64> {
        (self.time > 0 && !seen.is_zero()).then(|| self.time - seen.0.timestamp())
    }

    /// The peers whose newest handshake is older than PEER_SILENT, or that
    /// never shook hands.
    pub fn silent_peers(&self) -> Vec<u32> {
        self.peers.iter().filter(|p| p.age.is_none_or(|a| a > PEER_SILENT)).map(|p| p.host).collect()
    }

    /// What in the report needs the admin to look, each short enough for
    /// one line, worst first. seen is when the coordinator got it. Ages are
    /// taken on the machine's own clock, so a clock that is off shows up
    /// once, as itself, and does not make everything else look old or new.
    pub fn problems(&self, seen: Time) -> Vec<(Concern, String)> {
        let mut out = Vec::new();
        if self.reboot {
            out.push((Concern::Reboot, "reboot needed".to_string()));
        }
        match self.boot.as_str() {
            "fallback" => out.push((Concern::Boot, "running fallback kernel".into())),
            "no-fallback" => out.push((Concern::Boot, "no fallback kernel".into())),
            "fallback-broken" => out.push((Concern::Boot, "fallback kernel broken".into())),
            _ => {}
        }
        if let Some(p) = percent(self.disk_used, self.disk_total).filter(|p| *p >= DISK_FULL) {
            out.push((Concern::Disk, format!("disk {p}%")));
        }
        if let Some(p) = percent(self.mem_used, self.mem_total).filter(|p| *p >= MEMORY_FULL) {
            out.push((Concern::Memory, format!("memory {p}%")));
        }
        if let Some(t) = self.temp.filter(|t| *t >= HOT) {
            out.push((Concern::Heat, format!("{t}°C")));
        }
        if self.k3s_active == Some(false) {
            out.push((Concern::K3s, "k3s stopped".into()));
        }
        if self.firewall == Some(false) {
            out.push((Concern::Firewall, "firewall not loaded".into()));
        }
        if let Some(off) = self.clock_offset(seen).filter(|o| o.abs() > CLOCK_OFF) {
            out.push((Concern::Clock, format!("clock {} {}", short_age(off.unsigned_abs()), if off > 0 { "ahead" } else { "behind" })));
        }
        if self.upgraded > 0 && self.time > 0 && self.time - self.upgraded > UPGRADE_DUE {
            out.push((Concern::Upgrade, format!("not upgraded for {}", short_age((self.time - self.upgraded) as u64))));
        }
        if self.update_failed() {
            out.push((Concern::Update, format!("update {}", self.update)));
        }
        let silent = self.silent_peers().len();
        if silent > 0 {
            out.push((Concern::Peers, format!("{silent} silent peer{}", if silent == 1 { "" } else { "s" })));
        }
        out
    }
}

/// What a problem in a report is about, for a screen that shows some of
/// them in their own column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Concern {
    Reboot,
    /// Which kernel runs, and whether a fallback waits.
    Boot,
    Disk,
    Memory,
    Heat,
    K3s,
    Firewall,
    Clock,
    Upgrade,
    Update,
    Peers,
}

/// "45s", "12m", "3h", "5d": the largest unit only.
pub fn short_age(secs: u64) -> String {
    match secs {
        0..60 => format!("{secs}s"),
        60..3600 => format!("{}m", secs / 60),
        3600..86_400 => format!("{}h", secs / 3600),
        _ => format!("{}d", secs / 86_400),
    }
}

/// "512 MiB", "1.5 GiB".
pub fn size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    if unit < 3 { format!("{v:.0} {}", UNITS[unit]) } else { format!("{v:.1} {}", UNITS[unit]) }
}

// ---- gathering, on the machine itself ----

/// Gathers the report about the machine at root ("/" on a server). Never
/// fails; root is not needed, but without it the firewall and WireGuard
/// stay unknown. wg_subnet turns WireGuard peers into mesh host numbers.
pub fn gather(ctx: &Ctx, run: &dyn Runner, root: &Path, wg_subnet: &str) -> Report {
    let ctx = ctx.with_timeout(GATHER_TIMEOUT);
    let at = |p: &str| fsx::under(root, p);
    let now = Time::now().0.timestamp();
    let (kernel, kernel_installed, reboot) = kernel(root);
    let (mem_used, mem_total) = memory(&fsx::read_or_empty(at("/proc/meminfo")));
    let (disk_used, disk_total) = disk(root);
    let k3s_installed = at(K3S_BIN).is_file();
    let first = |p: &str| -> f64 { fsx::read_or_empty(at(p)).split_whitespace().next().and_then(|v| v.parse().ok()).unwrap_or(0.0) };
    let loadavg = fsx::read_or_empty(at("/proc/loadavg"));
    let mut load = [0.0; 3];
    for (slot, v) in load.iter_mut().zip(loadavg.split_whitespace()) {
        *slot = v.parse().unwrap_or(0.0);
    }
    let report = Report {
        format: FORMAT,
        time: now,
        dryserver: env!("CARGO_PKG_VERSION").into(),
        k3s: if k3s_installed { k3s_version(&ctx, run, root) } else { String::new() },
        kernel,
        kernel_installed,
        reboot,
        upgraded: last_upgrade(&at(PACMAN_LOG)),
        uptime: first("/proc/uptime") as u64,
        load,
        cpus: fsx::read_or_empty(at("/proc/cpuinfo")).lines().filter(|l| l.starts_with("processor")).count().min(u32::MAX as usize) as u32,
        mem_used,
        mem_total,
        disk_used,
        disk_total,
        temp: hottest(&at("/sys/class/thermal")),
        k3s_active: k3s_installed.then(|| run.ok(&ctx, &Cmd::new("systemctl", &["is-active", "--quiet", "k3s.service"])).is_ok()),
        firewall: firewall(&ctx, run),
        peers: handshakes(&ctx, run, wg_subnet, now),
        // Its update: added by the caller (rollout::Machine::describe),
        // which keeps that state.
        release: 0,
        update: String::new(),
        update_serial: 0,
        update_note: String::new(),
        boot: crate::install::boot::state(root).into(),
        // The caller's, with its signature (sync).
        lan: String::new(),
        sig: String::new(),
    };
    // What this machine sends is what every reader accepts, so nothing of
    // it is dropped on the way and it stays within the heartbeat's size.
    report.sanitized(|h| h > 0)
}

/// The running kernel, the newest one on disk, and whether a reboot is
/// due: the package that installed a newer kernel took the running one's
/// directory (/usr/lib/modules/VERSION/vmlinuz) with it. Without any kernel
/// there (a container, another layout) none is due.
fn kernel(root: &Path) -> (String, String, bool) {
    let running = fsx::read_or_empty(fsx::under(root, "/proc/sys/kernel/osrelease")).trim().to_string();
    let mut installed: Vec<(std::time::SystemTime, String)> = std::fs::read_dir(fsx::under(root, "/usr/lib/modules"))
        .map(|d| {
            d.flatten()
                .take(64)
                .filter_map(|e| {
                    let name = e.file_name().into_string().ok()?;
                    let built = std::fs::metadata(e.path().join("vmlinuz")).ok()?.modified().ok()?;
                    Some((built, name))
                })
                .collect()
        })
        .unwrap_or_default();
    if installed.iter().any(|(_, v)| *v == running) {
        return (running.clone(), running, false);
    }
    installed.sort();
    match installed.pop() {
        Some((_, newest)) => {
            let due = !running.is_empty();
            (running, newest, due)
        }
        None => (running, String::new(), false),
    }
}

/// Memory in use and in all from /proc/meminfo, bytes.
fn memory(meminfo: &str) -> (u64, u64) {
    let kib = |key: &str| meminfo.lines().find_map(|l| l.strip_prefix(key)?.trim().strip_suffix("kB")?.trim().parse::<u64>().ok());
    match (kib("MemTotal:"), kib("MemAvailable:")) {
        (Some(total), Some(avail)) => (total.saturating_sub(avail).saturating_mul(1024), total.saturating_mul(1024)),
        _ => (0, 0),
    }
}

/// Used and total bytes of the file system at root.
fn disk(root: &Path) -> (u64, u64) {
    let Ok(path) = std::ffi::CString::new(root.as_os_str().as_encoded_bytes()) else {
        return (0, 0);
    };
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: path is a NUL-terminated string and st points to room for
    // one statvfs, which the call fills when it returns 0.
    if unsafe { libc::statvfs(path.as_ptr(), st.as_mut_ptr()) } != 0 {
        return (0, 0);
    }
    // SAFETY: statvfs returned 0, so it filled st.
    let st = unsafe { st.assume_init() };
    let unit = st.f_frsize;
    let blocks = st.f_blocks;
    (blocks.saturating_sub(st.f_bfree).saturating_mul(unit), blocks.saturating_mul(unit))
}

/// The hottest thermal zone in °C. Sensors that read nonsense are left
/// out; none without sensors.
fn hottest(dir: &Path) -> Option<i32> {
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .take(64)
        .filter(|e| e.file_name().to_string_lossy().starts_with("thermal_zone"))
        .filter_map(|e| fsx::read_or_empty(e.path().join("temp")).trim().parse::<i64>().ok())
        .map(|milli| milli.div_euclid(1000))
        .filter(|c| (-40..=150).contains(c))
        .max()
        .map(|c| c as i32)
}

/// Whether the dryserver firewall table is loaded; none when nft cannot
/// tell.
fn firewall(ctx: &Ctx, run: &dyn Runner) -> Option<bool> {
    let out = run.output(ctx, &Cmd::new("nft", &["list", "tables"]).quiet().stdout_only()).ok()?;
    Some(out.lines().any(|l| l.trim() == "table inet dryserver"))
}

/// Each WireGuard peer's mesh host number (from the address WireGuard
/// routes to it) and how long ago its newest handshake was. The keys stay
/// here: the report names machines by number. `wg show wg0 dump` would do
/// it in one call, but its first line is the private key.
fn handshakes(ctx: &Ctx, run: &dyn Runner, wg_subnet: &str, now: i64) -> Vec<Peer> {
    let wg = |what: &str| run.output(ctx, &Cmd::new("wg", &["show", "wg0", what]).quiet().stdout_only()).unwrap_or_default();
    let routes = wg("allowed-ips");
    if routes.trim().is_empty() {
        return Vec::new();
    }
    let times: BTreeMap<String, i64> = wg("latest-handshakes")
        .lines()
        .take(4 * MAX_PEERS)
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            Some((f.next()?.to_string(), f.next()?.parse().ok()?))
        })
        .collect();
    let mut peers = Vec::new();
    for line in routes.lines().take(4 * MAX_PEERS) {
        let mut f = line.split_whitespace();
        let Some(key) = f.next() else { continue };
        let host = f.filter_map(|net| parse_ip4(net.split('/').next()?)).map(|ip| mesh::host_of(wg_subnet, ip)).find(|h| *h > 0);
        let Some(host) = host else { continue };
        let at = times.get(key).copied().unwrap_or(0);
        // A handshake "in the future" is the clock stepping back: now.
        peers.push(Peer { host, age: (at > 0).then(|| (now - at).max(0) as u64) });
    }
    peers
}

/// k3s's version, from `k3s --version` once per binary.
fn k3s_version(ctx: &Ctx, run: &dyn Runner, root: &Path) -> String {
    let bin = fsx::under(root, K3S_BIN);
    let Ok(meta) = std::fs::metadata(&bin) else {
        return String::new();
    };
    let stamp = format!("{}.{} {}", meta.mtime(), meta.mtime_nsec(), meta.size());
    let cache = fsx::under(root, K3S_VERSION_CACHE);
    if let Some((was, version)) = fsx::read_or_empty(&cache).split_once('\n')
        && was == stamp
    {
        return version.trim().to_string();
    }
    // "k3s version v1.31.4+k3s1 (a562d090)\ngo version go1.22.9"
    let out = run.output(ctx, &Cmd::new(&bin.display().to_string(), &["--version"]).quiet().stdout_only()).unwrap_or_default();
    let version = text(
        out.lines().next().and_then(|l| l.strip_prefix("k3s version ")).and_then(|v| v.split_whitespace().next()).unwrap_or("").to_string(),
    );
    if !version.is_empty() {
        // Not writable without root: then it is asked every time.
        let tmp = format!("{}.tmp", cache.display());
        let _ = fsx::mkdir_all(fsx::dir(&cache), 0o755);
        if fsx::write_file(&tmp, format!("{stamp}\n{version}\n"), 0o644).is_ok() {
            let _ = fsx::rename(&tmp, &cache);
        }
    }
    version
}

/// When pacman last started a full system upgrade, from the end of its
/// log; without one there, when the log begins (the install, which brought
/// the newest packages). 0 when there is no log.
fn last_upgrade(log: &Path) -> i64 {
    // A regular file only: a pipe would never end.
    if !std::fs::metadata(log).is_ok_and(|m| m.is_file()) {
        return 0;
    }
    let read = |from_end: bool, max: u64| -> String {
        let Ok(mut f) = std::fs::File::open(log) else {
            return String::new();
        };
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        if from_end && len > max && f.seek(SeekFrom::Start(len - max)).is_err() {
            return String::new();
        }
        let mut b = Vec::new();
        let _ = f.take(max).read_to_end(&mut b);
        String::from_utf8_lossy(&b).into_owned()
    };
    let tail = read(true, PACMAN_TAIL);
    tail.lines()
        .rev()
        .filter(|l| l.contains("[PACMAN] starting full system upgrade"))
        .find_map(log_time)
        .or_else(|| read(false, 4096).lines().find_map(log_time))
        .unwrap_or(0)
}

/// The time at the start of a pacman log line:
/// "[2026-11-20T09:14:02+0100] [PACMAN] ...".
fn log_time(line: &str) -> Option<i64> {
    let stamp = line.strip_prefix('[')?.split(']').next()?;
    chrono::DateTime::parse_from_str(stamp, "%Y-%m-%dT%H:%M:%S%z").ok().map(|t| t.timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::err::Result;
    use crate::testutil::{TempDir, put};
    use std::sync::Mutex;

    /// Answers the commands gather runs, and records them.
    #[derive(Default)]
    struct Fake {
        ran: Mutex<Vec<String>>,
        /// No nft, no wg: not root.
        unprivileged: bool,
        k3s_up: bool,
        routes: String,
        times: String,
    }

    impl Runner for Fake {
        fn run(&self, _: &Ctx, c: &Cmd) -> (String, Result<()>) {
            let line = format!("{} {}", c.name, c.args.join(" "));
            self.ran.lock().unwrap().push(line.clone());
            let denied = || (String::new(), Err("Operation not permitted".into()));
            match c.name.as_str() {
                "nft" if self.unprivileged => denied(),
                "nft" => ("table inet filter\ntable inet dryserver\n".into(), Ok(())),
                "wg" if self.unprivileged => denied(),
                "wg" if c.args[2] == "allowed-ips" => (self.routes.clone(), Ok(())),
                "wg" => (self.times.clone(), Ok(())),
                "systemctl" if self.k3s_up => (String::new(), Ok(())),
                "systemctl" => (String::new(), Err("exit status 3".into())),
                n if n.ends_with("/k3s") => ("k3s version v1.31.4+k3s1 (a562d090)\ngo version go1.22.9\n".into(), Ok(())),
                _ => (String::new(), Err("executable file not found".into())),
            }
        }
    }

    fn key(seed: u8) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode([seed; 32])
    }

    /// A machine's files as on an Arch server.
    fn machine() -> TempDir {
        let dir = TempDir::new();
        let root = dir.path();
        put(root, "/proc/sys/kernel/osrelease", "6.12.1-arch1-1\n");
        put(root, "/usr/lib/modules/6.12.1-arch1-1/vmlinuz", "k");
        put(root, "/usr/lib/modules/6.12.1-arch1-1/pkgbase", "linux\n");
        put(root, "/proc/meminfo", "MemTotal:        4000000 kB\nMemFree:          100000 kB\nMemAvailable:    3000000 kB\n");
        put(root, "/proc/uptime", "93784.52 300000.10\n");
        put(root, "/proc/loadavg", "0.52 0.58 0.59 1/1234 5678\n");
        put(root, "/proc/cpuinfo", "processor\t: 0\nmodel name\t: x\n\nprocessor\t: 1\nmodel name\t: x\n");
        put(root, "/sys/class/thermal/thermal_zone0/temp", "48000\n");
        put(root, "/sys/class/thermal/thermal_zone1/temp", "55500\n");
        // A broken sensor and something that is not a zone.
        put(root, "/sys/class/thermal/thermal_zone2/temp", "-273000\n");
        put(root, "/sys/class/thermal/cooling_device0/temp", "99000\n");
        put(
            root,
            PACMAN_LOG,
            "[2026-01-02T10:00:00+0000] [PACMAN] Running 'pacman -r /mnt -Sy base'\n\
             [2026-11-01T08:00:00+0100] [PACMAN] starting full system upgrade\n\
             [2026-11-01T08:01:00+0100] [ALPM] transaction completed\n\
             [2026-11-10T12:00:00+0100] [PACMAN] Running 'pacman -S htop'\n",
        );
        dir
    }

    /// The two filters for another machine's words: shown keeps printable
    /// ASCII alone (C0 and C1 controls, DEL, a direction override all
    /// become '?') and cuts; printable takes out the controls a terminal
    /// obeys and leaves the rest, newlines and tabs included.
    #[test]
    fn text_from_elsewhere_reaches_no_terminal_as_commands() {
        let evil = "a\x1b]52;c;Y3VybA==\x07b\x1b[2J\u{9b}2J\u{9d}0;t\x07\r\x7f\u{202e}°";
        assert_eq!(shown(evil, 100), "a?]52;c;Y3VybA==?b?[2J?2J?0;t?????");
        assert_eq!(shown("abcdef", 3), "abc");
        assert_eq!(note(&"x".repeat(500)).len(), MAX_NOTE);
        let p = printable(&format!("{evil}\nnext\tline"));
        assert!(!p.chars().any(|c| c.is_control() && c != '\n' && c != '\t'), "{p:?}");
        assert!(p.ends_with("\u{202e}°\nnext\tline") && p.starts_with("a?]52;"), "{p:?}");
        assert_eq!(printable("plain words: 3°C"), "plain words: 3°C");
    }

    #[test]
    fn what_a_server_reports() {
        let dir = machine();
        let root = dir.path();
        put(root, K3S_BIN, "#!k3s");
        let now = Time::now().0.timestamp();
        let fake = Fake {
            k3s_up: true,
            routes: format!(
                "{}\t10.66.0.1/32\n{}\t10.66.0.3/32 10.42.3.0/24\n{}\t(none)\n{}\t192.168.9.9/32\n",
                key(1),
                key(3),
                key(4),
                key(5)
            ),
            times: format!("{}\t{}\n{}\t0\n", key(1), now - 42, key(3)),
            ..Fake::default()
        };
        let r = gather(&Ctx::new(), &fake, root, "10.66.0.0/24");
        assert_eq!((r.format, r.dryserver.as_str()), (FORMAT, env!("CARGO_PKG_VERSION")));
        assert!((r.time - now).abs() < 5);
        assert_eq!((r.kernel.as_str(), r.kernel_installed.as_str(), r.reboot), ("6.12.1-arch1-1", "6.12.1-arch1-1", false));
        assert_eq!(r.k3s, "v1.31.4+k3s1");
        assert_eq!((r.k3s_active, r.firewall), (Some(true), Some(true)));
        assert_eq!(r.upgraded, 1_793_516_400, "the last full upgrade, not the later install of one package");
        assert_eq!((r.uptime, r.load, r.cpus), (93_784, [0.52, 0.58, 0.59], 2));
        assert_eq!((r.mem_used, r.mem_total), (1_000_000 * 1024, 4_000_000 * 1024));
        assert!(r.disk_total > 0 && r.disk_used <= r.disk_total);
        assert_eq!(r.temp, Some(55), "the hottest real sensor");
        assert_eq!(r.boot, "no-fallback", "installed before linux-lts");
        // Machines by number, never their keys; peers outside the mesh and
        // without an address are left out.
        assert_eq!(r.peers, vec![Peer { host: 1, age: Some(42) }, Peer { host: 3, age: None }]);
        assert!(!serde_json::to_string(&r).unwrap().contains(&key(1)));
        assert_eq!(r.silent_peers(), vec![3]);
    }

    #[test]
    fn k3s_version_is_asked_once_per_binary() {
        let dir = machine();
        let root = dir.path();
        put(root, K3S_BIN, "#!k3s");
        let fake = Fake::default();
        let asked = |f: &Fake| f.ran.lock().unwrap().iter().filter(|c| c.contains("/k3s --version")).count();
        for _ in 0..3 {
            assert_eq!(gather(&Ctx::new(), &fake, root, "10.66.0.0/24").k3s, "v1.31.4+k3s1");
        }
        assert_eq!(asked(&fake), 1, "{:?}", fake.ran.lock().unwrap());
        // A new binary (an update) is asked again.
        put(root, K3S_BIN, "#!k3s, newer");
        gather(&Ctx::new(), &fake, root, "10.66.0.0/24");
        assert_eq!(asked(&fake), 2);
    }

    #[test]
    fn what_cannot_be_read_stays_empty() {
        // Nothing there at all: no k3s, no sensors, no log, not root.
        let dir = TempDir::new();
        let fake = Fake { unprivileged: true, ..Fake::default() };
        let r = gather(&Ctx::new(), &fake, dir.path(), "");
        assert_eq!((r.k3s.as_str(), r.k3s_active, r.firewall, r.temp), ("", None, None, None));
        assert_eq!((r.kernel.as_str(), r.reboot, r.upgraded, r.uptime, r.mem_total), ("", false, 0, 0, 0));
        // The temporary directory's disk is real and may be full.
        let problems = r.problems(Time::now());
        assert!(r.peers.is_empty() && problems.iter().all(|(c, _)| *c == Concern::Disk), "{problems:?}");
        assert!(!fake.ran.lock().unwrap().iter().any(|c| c.starts_with("systemctl")), "no k3s, no question about it");
        // Junk in the files.
        let root = dir.path();
        put(root, "/proc/meminfo", "MemTotal: lots\n");
        put(root, "/proc/loadavg", "x \u{1b}[2J\n");
        put(root, "/proc/sys/kernel/osrelease", b"6.1\xff\xfe\x1b[31m\n");
        put(root, "/sys/class/thermal/thermal_zone0/temp", "hot\n");
        put(root, PACMAN_LOG, b"\xff\xfe garbage\n[not a time] [PACMAN] starting full system upgrade\n");
        let r = gather(&Ctx::new(), &fake, root, "");
        assert_eq!((r.mem_total, r.load, r.temp, r.upgraded), (0, [0.0; 3], None, 0));
        assert_eq!(r.kernel, "", "a kernel name with control characters is not shown at all");
    }

    #[test]
    fn a_replaced_kernel_needs_a_reboot() {
        let dir = machine();
        let root = dir.path();
        // pacman -Syu took the running kernel's directory with it.
        std::fs::remove_dir_all(fsx::under(root, "/usr/lib/modules/6.12.1-arch1-1")).unwrap();
        put(root, "/usr/lib/modules/6.12.4-arch1-1/vmlinuz", "k");
        // Left over by an out-of-tree module, without a kernel.
        put(root, "/usr/lib/modules/6.11.0-arch1-1/extramodules/x.ko", "m");
        let (running, installed, due) = kernel(root);
        assert_eq!((running.as_str(), installed.as_str(), due), ("6.12.1-arch1-1", "6.12.4-arch1-1", true));
        let r = Report { reboot: due, ..Report::default() };
        assert_eq!(r.problems(Time::now()), vec![(Concern::Reboot, "reboot needed".to_string())]);
    }

    #[test]
    fn which_kernel_boots() {
        for (state, want) in [
            ("fallback", Some("running fallback kernel")),
            ("no-fallback", Some("no fallback kernel")),
            ("fallback-broken", Some("fallback kernel broken")),
            ("ready", None),
            ("manual", None),
            ("", None),
        ] {
            let r = Report { boot: state.into(), ..Report::default() };
            let p: Vec<String> = r.problems(Time::now()).into_iter().filter(|(c, _)| *c == Concern::Boot).map(|(_, t)| t).collect();
            assert_eq!(p.first().map(String::as_str), want, "{state}");
            assert_eq!(r.clone().sanitized(|_| true).boot, state);
        }
        // A machine's word: only the known states, anything else is none.
        for junk in [serde_json::json!("fallback\u{1b}[2J"), serde_json::json!("FALLBACK"), serde_json::json!(5), serde_json::json!(null)] {
            let r: Report = serde_json::from_value(serde_json::json!({ "boot": junk })).unwrap();
            assert_eq!(r.sanitized(|_| true).boot, "", "{junk}");
        }
        // Not known: not sent.
        assert!(!serde_json::to_string(&Report::default()).unwrap().contains("\"boot\""));
    }

    #[test]
    fn the_last_upgrade_from_a_long_log() {
        let dir = TempDir::new();
        let log = dir.join("pacman.log");
        // An install, one upgrade, then more than the tail of other work.
        let mut text = String::from("[2026-01-02T10:00:00+0000] [PACMAN] Running 'pacman -Sy base'\n");
        text += "[2026-03-01T10:00:00+0000] [PACMAN] starting full system upgrade\n";
        while (text.len() as u64) < PACMAN_TAIL + 10_000 {
            text += "[2026-03-02T10:00:00+0000] [ALPM] installed something (1.0-1)\n";
        }
        std::fs::write(&log, &text).unwrap();
        assert_eq!(last_upgrade(&log), 1_767_348_000, "too long ago to find: the install");
        text += "[2026-11-20T09:14:02+0100] [PACMAN] starting full system upgrade\n";
        std::fs::write(&log, &text).unwrap();
        assert_eq!(last_upgrade(&log), 1_795_162_442);
        assert_eq!(last_upgrade(&dir.join("missing")), 0);
        assert_eq!(last_upgrade(dir.path()), 0, "a directory is no log");
    }

    #[test]
    fn a_hostile_report_is_cut_down() {
        let json = serde_json::json!({
            "format": "one",
            "time": -5,
            "dryserver": "0.1.0\u{1b}[2J",
            "k3s": "v".repeat(500),
            "kernel": "6.12.1-arch1-1",
            "reboot": "yes",
            "upgraded": i64::MAX,
            "uptime": u64::MAX,
            "load": [1e300, -1.0, 2.5],
            "cpus": 1_000_000,
            "mem_used": 9, "mem_total": 5,
            "disk_used": 1, "disk_total": u64::MAX,
            "temp": 5000,
            "firewall": "maybe",
            "peers": [{"host": 2, "age": 10}, {"host": 2, "age": 1}, {"host": 0}, {"host": 999, "age": 1}, "junk",
                      {"host": 3, "age": u64::MAX}, {"host": "x"}],
            "host": 3, "name": "node-c"
        });
        let r: Report = serde_json::from_value(json).unwrap();
        let r = r.sanitized(|h| (1..=254).contains(&h) && h != 7);
        assert_eq!(r.format, 0);
        assert_eq!((r.time, r.upgraded, r.uptime, r.cpus), (0, 0, 0, 0));
        assert_eq!((r.dryserver.as_str(), r.k3s.as_str(), r.kernel.as_str()), ("", "", "6.12.1-arch1-1"));
        assert!(!r.reboot);
        assert_eq!(r.load, [0.0, 0.0, 2.5]);
        assert_eq!((r.mem_used, r.mem_total, r.disk_used, r.disk_total), (0, 0, 0, 0));
        assert_eq!((r.temp, r.firewall), (None, None));
        assert_eq!(r.peers, vec![Peer { host: 2, age: Some(10) }, Peer { host: 3, age: None }], "each once, in the mesh");
        // Hundreds of peers: no more than MAX_PEERS.
        let many = Report { peers: (1..2000).map(|h| Peer { host: h, age: Some(1) }).collect(), ..Report::default() };
        assert_eq!(many.sanitized(|_| true).peers.len(), MAX_PEERS);
        // Not an object at all.
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Carrier {
            #[serde(deserialize_with = "lenient_report")]
            report: Option<Report>,
        }
        for junk in [r#"{"report":"x"}"#, r#"{"report":[1,2]}"#, r#"{"report":null}"#, "{}"] {
            assert_eq!(serde_json::from_str::<Carrier>(junk).unwrap().report, None, "{junk}");
        }
    }

    #[test]
    fn problems_and_clock_skew() {
        let seen = Time::ymd_hms(2026, 11, 20, 12, 0, 0);
        let at = seen.0.timestamp();
        let good = Report {
            time: at + 3,
            upgraded: at - 86_400,
            mem_used: 1,
            mem_total: 4,
            disk_used: 50,
            disk_total: 100,
            temp: Some(50),
            k3s_active: Some(true),
            firewall: Some(true),
            peers: vec![Peer { host: 1, age: Some(30) }],
            ..Report::default()
        };
        assert!(good.problems(seen).is_empty(), "{:?}", good.problems(seen));
        assert_eq!(good.clock_offset(seen), Some(3));
        let bad = Report {
            // Ten minutes behind; the upgrade age is on the machine's own
            // clock and is not made worse by that.
            time: at - 600,
            upgraded: at - 600 - 40 * 86_400,
            reboot: true,
            mem_used: 95,
            mem_total: 100,
            disk_used: 91,
            disk_total: 100,
            temp: Some(90),
            k3s_active: Some(false),
            firewall: Some(false),
            peers: vec![Peer { host: 1, age: Some(301) }, Peer { host: 2, age: None }, Peer { host: 3, age: Some(5) }],
            ..Report::default()
        };
        assert_eq!(
            bad.problems(seen).into_iter().map(|(_, text)| text).collect::<Vec<_>>(),
            vec![
                "reboot needed",
                "disk 91%",
                "memory 95%",
                "90°C",
                "k3s stopped",
                "firewall not loaded",
                "clock 10m behind",
                "not upgraded for 40d",
                "2 silent peers"
            ]
        );
        // Not known is no problem.
        assert_eq!(Report::default().clock_offset(seen), None);
        assert_eq!((percent(5, 0), percent(1, 3), percent(u64::MAX, u64::MAX)), (None, Some(33), Some(100)));
        assert_eq!(
            (short_age(59), short_age(60), short_age(7200), short_age(3 * 86_400)),
            ("59s".into(), "1m".into(), "2h".into(), "3d".into())
        );
        assert_eq!((size(512 << 20), size(3 << 29), size(0)), ("512 MiB".into(), "1.5 GiB".into(), "0 B".into()));
    }
}
