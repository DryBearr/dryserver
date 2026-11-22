//! Releases, from the admin's desktop to every machine: the brain first,
//! then one server at a time.
//!
//! 1. The desktop signs a release (release.rs) and uploads it with the
//!    dryserver and k3s binaries to the brain's registry (`release-put`).
//!    The registry account keeps it beside the registry file (Served),
//!    after it checked the signature, that it is newer than the one it
//!    has, the sizes and the checksums.
//! 2. The brain's sync (root) takes the newest one from there, checks it
//!    again, copies it into its own store, which only root can write, and
//!    starts the rollout with itself: `dryserver update apply`, then
//!    `update confirm` at a later sync, once the new binary is the one that
//!    runs and the brain is healthy. If that does not work, the rollout
//!    stops there and no server is touched.
//! 3. Then the servers, one at a time. The brain cordons and drains a
//!    server and gives it the turn. The server sees that in its sync reply,
//!    loads the release from the registry in pieces, checks it itself (a
//!    server never takes the brain's word that a release is good), installs
//!    it, and confirms it at a later sync once the new binary runs, the
//!    server is healthy and it reached the brain. Its report then carries
//!    the new serial; the brain uncordons it and moves on. The first server
//!    is the canary: the brain watches it for a while before the next one.
//!
//! A bad update must not take the swarm down. Each machine goes back by
//! itself when its update is not confirmed in time (lane 5's revert
//! guard), and the rollout stops at the first machine that fails, reverts,
//! refuses or does not finish in time; the admin looks, then publishes a
//! fixed release, resumes (`./dryserver release resume`: the machine tries
//! again) or passes the server over (`release resume -skip`). A new
//! release replaces a running rollout: machines go straight to the newest.
//!
//! Everything a machine gets from another one is checked here as if it
//! came from an attacker: sizes are capped before anything is read, the
//! signature and the checksums decide, and a server can only speak for
//! itself. A hacked server can fail or stall only its own turn, and a
//! stalled turn ends after TURN_TIMEOUT; but the rollout then stops there
//! until the admin passes it over.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use chrono::Timelike;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ctx::Ctx;
use crate::err::{Error, Kind, Result};
use crate::node::Node;
use crate::registry::{self, Member, Store};
use crate::release::{self, Place, Release};
use crate::report::{self, Report, shown};
use crate::runner::Cmd;
use crate::signed::{Envelope, Verifier};
use crate::{bail, errf, fsx, quarantine};

// ---- where things are ----

/// Each machine's own copy of releases: the one it runs, the one before,
/// and the one it is loading. Only root may read or write it.
///
/// Not under /var/lib/dryserver: on the brain that directory belongs to
/// the registry account, which could rename a directory in it and put its
/// own in its place while root reads it.
pub const STORE: &str = "/var/lib/dryserver-releases";
const STATE_FILE: &str = "state.json";
/// On the brain: the rollout as root keeps it. The registry gets a copy to
/// answer servers from, which root never reads back.
const ROLLOUT_FILE: &str = "rollout.json";
const INCOMING: &str = "incoming";
const INSTALLED: &str = "installed";
const PREVIOUS: &str = "previous";
const META_FILE: &str = "meta.json";
/// The signed release, as an Envelope in JSON.
pub const RELEASE_FILE: &str = "release.json";
pub const DRYSERVER_FILE: &str = "dryserver";
pub const K3S_FILE: &str = "k3s";
/// On the brain, beside the registry file: what the admin uploaded, kept
/// by the registry account to hand out.
pub const SERVED_DIR: &str = "release";
/// Where k3s is installed on every machine.
pub const K3S_BIN: &str = report::K3S_BIN;

// ---- limits ----

/// The most a server loads with one registry call. Each call is one SSH
/// connection, and the brain's firewall lets an address open only 10 a
/// minute: a 70 MiB k3s takes five.
pub const CHUNK: u64 = 16 << 20;
/// The most pieces one sync loads, for the same reason: the sync needs a
/// connection or two of its own (its heartbeat, the release's offer).
pub const MAX_PIECES: u32 = 6;
/// What must stay free on a disk after a release is stored on it: a full
/// disk on the brain would stop the registry, and with it the swarm.
pub const RESERVE: u64 = 256 << 20;
/// The largest k3s binary accepted. The release names its checksum, not
/// its size; this only keeps a machine from reading for ever.
pub const MAX_K3S: u64 = release::MAX_BINARY;
/// The first line of an upload: the signed release and the k3s size.
const MAX_HEADER: u64 = 32 << 10;
/// The signed release on disk or from the registry, with room to spare.
const MAX_ENVELOPE: u64 = 32 << 10;
/// This machine's update state.
const MAX_STATE: u64 = 16 << 10;
/// The brain's rollout state: a list or two of host numbers, a few lines.
const MAX_ROLLOUT: u64 = 256 << 10;

// ---- timing ----

/// Normal releases update machines only in this window, minutes after
/// midnight on the brain's clock: 03:00 to 05:00. It may cross midnight
/// (start after end). Urgent releases do not wait for it.
pub const WINDOW: (u32, u32) = (3 * 60, 5 * 60);
/// A server that has not finished its update this long after its turn
/// began stops the rollout (or, when it was never heard from since, is
/// passed over until it is back). An update with new packages and a new
/// k3s loads them, installs them, restarts k3s and may reboot: minutes
/// each on a mini PC and a slow archive. One that finishes later after
/// all lets the rollout go on by itself.
pub const TURN_TIMEOUT: i64 = 60 * 60;
/// A server never heard from since its turn began is passed over sooner:
/// it is off (an update that reboots is back within minutes, one that runs
/// keeps syncing).
pub const SILENT_TURN: i64 = 20 * 60;
/// How long the brain tries to drain a server before it gives up.
pub const DRAIN_LIMIT: i64 = 5 * 60;
/// One drain attempt; it goes on at the next sync. kubectl waits this long
/// for evictions that a PodDisruptionBudget holds back.
const DRAIN_TIMEOUT: &str = "--timeout=25s";
/// A member silent this long is offline: it syncs every minute.
pub const OFFLINE: i64 = 180;
/// How long the canary is watched after its update before the next server
/// gets its turn.
pub const SOAK: i64 = 5 * 60;
pub const SOAK_URGENT: i64 = 60;
/// A machine confirms its update at a sync after the one that installed
/// it, never in the same one: the new binary has to be the one that runs.
const CONFIRM_AFTER: i64 = 45;
/// How long one sync starts new pieces of a release; the rest follows at
/// the next sync. A piece started may take until the sync's own deadline.
const FETCH_BUDGET: Duration = Duration::from_secs(25);
/// One piece at most. What came of a piece cut off by it or by the sync's
/// deadline is kept: the next piece starts where it ended, so a slow link
/// gets on at every sync instead of loading the same piece again.
const CHUNK_TIMEOUT: Duration = Duration::from_secs(60);
/// Starting the apply: it runs in a service of its own (update apply
/// --detach), and the sync follows it with update status.
const START_TIMEOUT: Duration = Duration::from_secs(60);
/// Confirming and reverting are not cut off by the sync's deadline: a
/// half-run command is worse than a late sync.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// An apply that was started says how it went within this (in update
/// status); one that says nothing at all is tried again.
const START_GRACE: i64 = 5 * 60;
/// How many syncs in a row a problem that may pass (the update commands
/// do not answer, the disk is full for now, the brain's k3s is not known
/// yet) is tried again before the release counts as failed here: well
/// within TURN_TIMEOUT, a sync a minute.
pub const MAX_TRIES: u32 = 10;
/// How many turns one server gets in a rollout before the rollout stops at
/// it (the admin resumes or passes it over). A turn that ends without the
/// update (its kill switch went on, it went silent) gives it another one
/// later; a server, or a registry account that forges its reports, could
/// otherwise have it cordoned and drained again and again.
pub const MAX_TURNS: usize = 3;
/// The most warnings a rollout keeps (the newest).
const MAX_WARNINGS: usize = 8;
/// What the registry says when an upload needs the k3s binary too; the
/// desktop then sends it.
pub const SEND_K3S: &str = "send k3s";

/// The brain's clock: unix seconds, and minutes after midnight on its own
/// time zone (for the window).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Now {
    pub unix: i64,
    pub minute: u32,
}

impl Now {
    pub fn current() -> Now {
        let t = chrono::Local::now();
        Now { unix: t.timestamp(), minute: t.hour() * 60 + t.minute() }
    }
}

/// Whether minute (after midnight) is in the window [start, end). A window
/// with start after end crosses midnight; one with start == end is empty.
pub fn in_window(minute: u32, (start, end): (u32, u32)) -> bool {
    if start <= end { (start..end).contains(&minute) } else { minute >= start || minute < end }
}

/// "03:00-05:00".
pub fn window_text((start, end): (u32, u32)) -> String {
    format!("{:02}:{:02}-{:02}:{:02}", start / 60, start % 60, end / 60, end % 60)
}

// ---- lane 5: installing a release on this machine ----

/// What `dryserver update status --json` says, as far as the rollout
/// needs it. Fields it does not know are left out, and one of the wrong
/// kind reads as empty.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdateStatus {
    #[serde(deserialize_with = "report::lenient")]
    pub installed: Installed,
    /// Installed, not confirmed yet: it goes back by itself at its
    /// deadline. None: nothing pending.
    #[serde(deserialize_with = "report::lenient")]
    pub pending: Option<Pending>,
    /// What the last update action was and how it ended.
    #[serde(deserialize_with = "report::lenient")]
    pub last: Option<Last>,
    /// An apply (or a confirm, a revert) runs now: it decides.
    #[serde(deserialize_with = "report::lenient")]
    pub busy: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Installed {
    #[serde(deserialize_with = "report::lenient")]
    pub serial: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Pending {
    #[serde(deserialize_with = "report::lenient")]
    pub serial: u64,
    #[serde(deserialize_with = "report::lenient")]
    pub deadline: i64,
    /// The release that ran before this one, if any.
    #[serde(deserialize_with = "report::lenient")]
    pub previous: Option<u64>,
    /// "armed": applied, waits for its confirm; anything else: its apply
    /// did not finish (and, when nothing is busy, will not).
    #[serde(deserialize_with = "report::lenient")]
    pub stage: String,
    /// What its apply does now.
    #[serde(deserialize_with = "report::lenient")]
    pub step: String,
    /// The apply rebooted the machine, and the restarts seen since.
    #[serde(deserialize_with = "report::lenient")]
    pub reboot: bool,
    #[serde(deserialize_with = "report::lenient")]
    pub boots: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Last {
    /// Unix seconds.
    #[serde(deserialize_with = "report::lenient")]
    pub at: i64,
    #[serde(deserialize_with = "report::lenient")]
    pub serial: u64,
    /// "applied", "confirmed", "reverted"; "postponed" (nothing changed, a
    /// problem that may pass) or "refused" (nothing changed, it does not
    /// go on this machine).
    #[serde(deserialize_with = "report::lenient")]
    pub action: String,
    #[serde(deserialize_with = "report::lenient")]
    pub ok: bool,
    #[serde(deserialize_with = "report::lenient")]
    pub message: String,
}

impl UpdateStatus {
    pub fn pending_serial(&self) -> u64 {
        self.pending.as_ref().map_or(0, |p| p.serial)
    }

    /// The release this machine runs for good. `update apply` records the
    /// new release as installed at once; until it is confirmed it can still
    /// go back, so the one before it is what counts meanwhile. Taking the
    /// applied one let the brain count itself updated, stop settling its
    /// own update and go back at the deadline (seen after a reboot inside
    /// the window). And a release whose last record is its revert never
    /// counts, whatever is named installed: a revert that half failed may
    /// leave it named (the store's own record of what was confirmed
    /// decides then).
    pub fn confirmed_serial(&self) -> u64 {
        match &self.pending {
            Some(p) if p.serial == self.installed.serial => p.previous.unwrap_or(0),
            _ if self.last.as_ref().is_some_and(|l| l.serial == self.installed.serial && l.action == "reverted") => 0,
            _ => self.installed.serial,
        }
    }

    /// Whether the last update action confirmed release serial.
    pub fn confirmed(&self, serial: u64) -> bool {
        self.last.as_ref().is_some_and(|l| l.serial == serial && l.action == "confirmed")
    }

    /// Why release serial went back, when it did.
    pub fn reverted(&self, serial: u64) -> Option<String> {
        let l = self.last.as_ref().filter(|l| l.serial == serial && l.action == "reverted")?;
        Some(if l.message.is_empty() { "it went back to the release before".into() } else { l.message.clone() })
    }
}

/// The update commands on this machine (`dryserver update ...`, as root).
/// Every call to them is here, so a change in their interface is a change
/// in one place.
///
/// - apply --detach --reboot --release FILE --binary FILE [--k3s FILE]
///   --brain-k3s VERSION: starts the apply in a service of its own and
///   returns; the apply copies the files into its own staging, checks
///   them, loads the packages, installs the binary, k3s (the file is
///   given when this machine runs another k3s) and the packages, and may
///   reboot. Its outcome shows in status: busy while it runs, then a
///   pending release (armed: waits for confirm), or last (reverted,
///   postponed, refused).
/// - confirm --serial N: keeps it, after its own selfcheck.
/// - revert: puts back an update whose apply stopped part way.
/// - status --json: UpdateStatus.
pub struct Update<'a> {
    pub run: &'a dyn crate::runner::Runner,
    pub bin: &'a str,
}

impl Update<'_> {
    pub fn apply(&self, ctx: &Ctx, release: &Path, binary: &Path, k3s: Option<&Path>, brain_k3s: &str) -> Result<()> {
        let (r, b) = (release.display().to_string(), binary.display().to_string());
        let mut args = vec!["update", "apply", "--detach", "--reboot", "--release", &r, "--binary", &b];
        let k = k3s.map(|k| k.display().to_string());
        if let Some(k) = &k {
            args.extend(["--k3s", k.as_str()]);
        }
        args.extend(["--brain-k3s", brain_k3s]);
        self.run.ok(ctx, &Cmd::new(self.bin, &args))
    }

    pub fn confirm(&self, ctx: &Ctx, serial: u64) -> Result<()> {
        self.run.ok(ctx, &Cmd::new(self.bin, &["update", "confirm", "--serial", &serial.to_string()]))
    }

    pub fn revert(&self, ctx: &Ctx) -> Result<()> {
        self.run.ok(ctx, &Cmd::new(self.bin, &["update", "revert"]))
    }

    pub fn status(&self, ctx: &Ctx) -> Result<UpdateStatus> {
        let out = self.run.output(ctx, &Cmd::new(self.bin, &["update", "status", "--json"]).quiet().stdout_only())?;
        serde_json::from_str(out.trim()).map_err(|e| Error::from(e).wrap("dryserver update status"))
    }
}

// ---- small file helpers ----

/// Opens a regular file without following a symbolic link and without
/// blocking on a FIFO.
fn open_regular(path: &Path) -> Result<File> {
    let f = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path).map_err(|e| {
        if e.raw_os_error() == Some(libc::ELOOP) {
            errf!("{} is a symbolic link, not the file itself", path.display())
        } else {
            Error::from(e).wrap(format!("open {}", path.display()))
        }
    })?;
    let m = f.metadata().map_err(|e| Error::from(e).wrap(format!("stat {}", path.display())))?;
    if !m.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    Ok(f)
}

/// A small text file, refused when it is larger than max.
fn read_small(path: &Path, max: u64) -> Result<String> {
    read_capped(open_regular(path)?, max, path)
}

/// What an open file holds, refused when it is larger than max. path
/// names it in messages.
fn read_capped(f: File, max: u64, path: &Path) -> Result<String> {
    let mut s = String::new();
    f.take(max + 1).read_to_string(&mut s).map_err(|e| Error::from(e).wrap(format!("read {}", path.display())))?;
    if s.len() as u64 > max {
        bail!("{} is larger than {max} bytes", path.display());
    }
    Ok(s)
}

/// The sha256 of what r holds, at most max bytes of it; None when it
/// cannot be read.
fn sha_reader(r: impl Read, max: u64) -> Option<String> {
    let mut h = Sha256::new();
    let mut r = r.take(max);
    let mut buf = vec![0u8; 64 << 10];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(k) => h.update(&buf[..k]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    Some(fsx::hex(&h.finalize()))
}

fn file_len(path: &Path) -> u64 {
    std::fs::symlink_metadata(path).map(|m| if m.is_file() { m.len() } else { 0 }).unwrap_or(0)
}

/// Writes a file whole or not at all.
fn write_atomic(path: &Path, data: &str) -> Result<()> {
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    fsx::write_file(&tmp, data, 0o600)?;
    fsx::rename(&tmp, path)
}

fn remove_dir(path: &Path) -> Result<()> {
    match std::fs::remove_dir_all(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(Error::from(e).wrap(format!("remove {}", path.display()))),
        _ => Ok(()),
    }
}

/// Bytes free for an unprivileged user on the file system of path.
pub fn free_bytes(path: &Path) -> Option<u64> {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).ok()?;
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: c is a NUL-terminated path and st has room for one statvfs,
    // which the call fills when it returns 0.
    if unsafe { libc::statvfs(c.as_ptr(), st.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: statvfs returned 0, so st is filled.
    let st = unsafe { st.assume_init() };
    Some(st.f_bavail.saturating_mul(st.f_frsize))
}

/// Refuses when storing need more bytes would leave less than RESERVE
/// free.
fn room(free: fn(&Path) -> Option<u64>, dir: &Path, need: u64, who: &str) -> Result<()> {
    if let Some(have) = free(dir)
        && have < need.saturating_add(RESERVE)
    {
        bail!(
            "{who} has {} free; the release needs {} and {} must stay free",
            report::size(have),
            report::size(need),
            report::size(RESERVE)
        );
    }
    Ok(())
}

/// Copies exactly size bytes from r to a new file at dst, checking them
/// against sha256 as they pass. Too few is an interrupted transfer.
fn copy_exact(r: &mut dyn Read, dst: &Path, size: u64, sha256: &str, what: &str) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dst)
        .map_err(|e| Error::from(e).wrap(format!("open {}", dst.display())))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 << 10];
    let mut left = size;
    while left > 0 {
        let want = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        let k = match r.read(&mut buf[..want]) {
            Ok(0) => bail!("{what} ended after {} of {size} bytes", size - left),
            Ok(k) => k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::from(e).wrap(format!("read {what}"))),
        };
        h.update(&buf[..k]);
        f.write_all(&buf[..k]).map_err(|e| Error::from(e).wrap(format!("write {}", dst.display())))?;
        left -= k as u64;
    }
    let got = fsx::hex(&h.finalize());
    if got != sha256 {
        bail!("{what} has sha256 {got}, the release says {sha256}");
    }
    Ok(())
}

/// The sha256 of the binary this process runs. /proc/self/exe is the
/// running file even after an update put another one in its place.
fn running_sha(root: &Path) -> Option<String> {
    sha_reader(File::open(fsx::under(root, "/proc/self/exe")).ok()?, release::MAX_BINARY)
}

/// The sha256 of a file, None when it cannot be read.
fn sha_of(path: &Path, max: u64) -> Option<String> {
    release::hash_file(path, max).ok().map(|(sha, _)| sha)
}

// ---- the brain's copy for the swarm (registry account) ----

/// The first line of `release-put`: the signed release, and how many
/// bytes of k3s follow the dryserver binary (0: none, use the brain's
/// own k3s when it is the release's).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutHeader {
    pub release: Envelope,
    #[serde(default)]
    pub k3s_size: u64,
}

/// What `release-get SERIAL release` answers: the signed release, and how
/// large the brain's k3s file is (a hint for the piece sizes; the checksum
/// decides).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Offered {
    pub release: Envelope,
    pub k3s_size: u64,
}

/// The releases the admin uploaded, on the brain, as the registry account
/// keeps them: dir/SERIAL/{release.json, dryserver, k3s} for the newest and
/// the one before, and dir/current naming the newest.
#[derive(Debug, Clone)]
pub struct Served {
    pub dir: PathBuf,
    /// The brain's own k3s, used when an upload does not carry one.
    pub k3s: PathBuf,
    pub free: fn(&Path) -> Option<u64>,
    /// Gives an upload more time once its signature checked out
    /// (registry::extend_deadline).
    pub extend: fn(Duration),
}

impl Served {
    pub fn new(dir: impl Into<PathBuf>, k3s: impl Into<PathBuf>) -> Served {
        Served { dir: dir.into(), k3s: k3s.into(), free: free_bytes, extend: registry::extend_deadline }
    }

    /// Beside the registry file of store.
    pub fn beside(store: &Store, k3s: impl Into<PathBuf>) -> Served {
        Served::new(fsx::dir(&store.path).join(SERVED_DIR), k3s)
    }

    fn release_dir(&self, serial: u64) -> PathBuf {
        self.dir.join(serial.to_string())
    }

    /// A file of the uploads: dir/name, or dir/SERIAL/name. Reached
    /// through each directory opened by itself, never through a link:
    /// root reads these, and the registry account owns every directory
    /// on the way (O_NOFOLLOW alone covers only the last part of a path).
    pub fn open(&self, serial: Option<u64>, name: &str) -> Result<File> {
        let dir = registry::Dir::open(&self.dir)?;
        let dir = match serial {
            Some(n) => dir.sub(&n.to_string())?,
            None => dir,
        };
        dir.open_regular(name, libc::O_RDONLY)
    }

    /// The serial of the newest upload.
    pub fn current(&self) -> Option<u64> {
        let s = read_capped(self.open(None, "current").ok()?, 32, &self.dir.join("current")).ok()?;
        let s = s.trim();
        if s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        s.parse().ok().filter(|n| *n > 0)
    }

    pub fn envelope(&self, serial: u64) -> Result<Envelope> {
        let text = read_capped(self.open(Some(serial), RELEASE_FILE)?, MAX_ENVELOPE, &self.path(serial, RELEASE_FILE))?;
        serde_json::from_str(&text).map_err(|e| Error::from(e).wrap(format!("release {serial} on the coordinator")))
    }

    /// Where a file of an upload is. Root never opens it by this path
    /// (open).
    pub fn path(&self, serial: u64, name: &str) -> PathBuf {
        self.release_dir(serial).join(name)
    }

    /// The length of a file of an upload; 0 when it cannot be opened.
    fn len_of(&self, serial: u64, name: &str) -> u64 {
        self.open(Some(serial), name).and_then(|f| Ok(f.metadata()?.len())).unwrap_or(0)
    }

    /// The newest upload's release, as the registry account stored it.
    fn newest(&self) -> Option<Release> {
        let env = self.envelope(self.current()?).ok()?;
        serde_json::from_str(&env.doc).ok()
    }

    /// Refuses r unless it may follow the newest upload.
    fn after_newest(&self, r: &Release, now: i64) -> Result<()> {
        if let Some(old) = self.newest()
            && !release::decide(r, Some(&old), Place::Brain, now)?.install
        {
            bail!("release {} is on the coordinator already", r.serial);
        }
        Ok(())
    }

    /// Takes an upload (`release-put`): the header line, then exactly the
    /// dryserver binary, then the k3s binary when the header says so.
    /// Returns the serial. Nothing is kept unless all of it checks out: a
    /// cut-off, oversized or wrong upload, or one that does not fit on the
    /// disk, leaves the newest release as it was.
    ///
    /// The admin's signature on the release is the only authority: the
    /// key that reaches the registry is on every machine. And nothing large
    /// is read before the signature is checked and the release found newer
    /// than the one here.
    pub fn receive(&self, v: &dyn Verifier, input: &mut dyn Read, now: i64) -> Result<u64> {
        let mut input = BufReader::new(input);
        let mut line = Vec::new();
        (&mut input).take(MAX_HEADER).read_until(b'\n', &mut line).map_err(|e| Error::from(e).wrap("read the upload"))?;
        if line.last() != Some(&b'\n') {
            bail!("the upload does not start with a release header");
        }
        let head: PutHeader = serde_json::from_slice(&line).map_err(|e| Error::from(e).wrap("release header"))?;
        let r = release::open(v, &head.release, now)?;
        // Signed by the admin: moving the binaries may take as long as
        // the network needs.
        (self.extend)(registry::UPLOAD_DEADLINE);
        if head.k3s_size > MAX_K3S {
            bail!("the upload's k3s is {} bytes, more than {MAX_K3S}", head.k3s_size);
        }
        fsx::mkdir_all(&self.dir, 0o700)?;
        self.after_newest(&r, now)?;
        let k3s_len = if head.k3s_size > 0 { head.k3s_size } else { file_len(&self.k3s) };
        room(self.free, &self.dir, r.dryserver.size.saturating_add(k3s_len), "the coordinator")?;
        let stage = self.dir.join(format!("staging-{}", fsx::hex(&fsx::random_bytes(6))));
        fsx::mkdir_all(&stage, 0o700)?;
        let res = (|| -> Result<()> {
            copy_exact(&mut input, &stage.join(DRYSERVER_FILE), r.dryserver.size, &r.dryserver.sha256, "the dryserver binary")?;
            if head.k3s_size > 0 {
                copy_exact(&mut input, &stage.join(K3S_FILE), head.k3s_size, &r.k3s.sha256, "the k3s binary")?;
            } else {
                // Not sent: this coordinator's own k3s, if it is the
                // release's. Copied, so the servers get a file that stays.
                let missing = |e: Error| errf!("the coordinator has no k3s {} of its own ({e}): {SEND_K3S}", r.k3s.version);
                let mut f = open_regular(&self.k3s).map_err(missing)?;
                let len = f.metadata().map(|m| m.len()).unwrap_or(0);
                if len == 0 || len > MAX_K3S {
                    return Err(missing(errf!("{len} bytes")));
                }
                copy_exact(&mut f, &stage.join(K3S_FILE), len, &r.k3s.sha256, "its k3s").map_err(missing)?;
            }
            let mut more = [0u8; 1];
            if input.read(&mut more).map_err(|e| Error::from(e).wrap("read the upload"))? != 0 {
                bail!("the upload carries more than the release says");
            }
            fsx::write_file(stage.join(RELEASE_FILE), serde_json::to_string(&head.release)? + "\n", 0o600)?;
            self.commit(&r, &stage, now)
        })();
        if res.is_err() {
            let _ = remove_dir(&stage);
        }
        res.map(|_| r.serial)
    }

    /// Makes a checked upload the newest, under a lock: two uploads at the
    /// same time end with the newer one, never with a mix.
    fn commit(&self, r: &Release, stage: &Path, now: i64) -> Result<()> {
        let _lock = fsx::lock(self.dir.join(".lock"))?;
        self.after_newest(r, now)?;
        let prev = self.current();
        let dst = self.release_dir(r.serial);
        remove_dir(&dst)?;
        fsx::rename(stage, &dst)?;
        write_atomic(&self.dir.join("current"), &format!("{}\n", r.serial))?;
        // The newest and the one before stay; uploads cut off long ago go.
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                let stale = match name.parse::<u64>() {
                    Ok(n) => n != r.serial && Some(n) != prev,
                    Err(_) => {
                        name.starts_with("staging-")
                            && e.metadata()
                                .ok()
                                .and_then(|m| m.modified().ok())
                                .and_then(|t| t.elapsed().ok())
                                .is_some_and(|d| d.as_secs() > 3600)
                    }
                };
                if stale {
                    let _ = remove_dir(&e.path());
                }
            }
        }
        Ok(())
    }

    /// Answers `release-get SERIAL FILE OFFSET`: at most CHUNK bytes of
    /// the file from offset.
    pub fn send(&self, serial: u64, name: &str, offset: u64, out: &mut dyn Write) -> Result<()> {
        if name != DRYSERVER_FILE && name != K3S_FILE {
            bail!("no file {name:?} in a release");
        }
        let mut f = self.open(Some(serial), name).map_err(|e| e.wrap(format!("release {serial} is not on the coordinator")))?;
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        if offset > len {
            bail!("offset {offset} is past the end of {name} ({len} bytes)");
        }
        f.seek(SeekFrom::Start(offset))?;
        io::copy(&mut f.take(CHUNK), out)?;
        Ok(())
    }

    /// Answers `release-get SERIAL release`.
    pub fn offered(&self, serial: u64) -> Result<Offered> {
        Ok(Offered { release: self.envelope(serial)?, k3s_size: self.len_of(serial, K3S_FILE) })
    }
}

// ---- where a machine loads a release from ----

/// Where a machine loads a release from: a server from the brain's
/// registry over SSH, the brain from its registry's directory.
pub trait Source {
    fn offered(&self, ctx: &Ctx, serial: u64) -> Result<Offered>;
    /// Writes bytes [offset, offset+len) of the file to a new dst, or
    /// fails. What it wrote before it failed is the start of them: the
    /// caller keeps it and goes on from there.
    fn chunk(&self, ctx: &Ctx, serial: u64, name: &str, offset: u64, len: u64, dst: &Path) -> Result<()>;
}

/// The brain reading what its registry account keeps. Root reads it like
/// anything from outside: the files are checked against the signed
/// release after they are copied into root's own store.
pub struct LocalSource<'a>(pub &'a Served);

impl Source for LocalSource<'_> {
    fn offered(&self, _: &Ctx, serial: u64) -> Result<Offered> {
        self.0.offered(serial)
    }

    /// A file that is not there, or shorter than asked, is NotFound: it is
    /// no network that may come back by itself.
    fn chunk(&self, _: &Ctx, serial: u64, name: &str, offset: u64, len: u64, dst: &Path) -> Result<()> {
        let missing = |e: Error| Error::with_kind(Kind::NotFound, format!("{name} of release {serial} on the coordinator: {e}"));
        let mut f = self.0.open(Some(serial), name).map_err(missing)?;
        f.seek(SeekFrom::Start(offset))?;
        let mut out = File::create(dst).map_err(|e| Error::from(e).wrap(format!("open {}", dst.display())))?;
        let n = io::copy(&mut f.take(len), &mut out)?;
        if n != len {
            return Err(missing(errf!("it ends after {} bytes", offset + n)));
        }
        Ok(())
    }
}

/// A server asking the brain's registry over the mesh.
pub struct SshSource<'a>(pub &'a Node);

impl Source for SshSource<'_> {
    fn offered(&self, ctx: &Ctx, serial: u64) -> Result<Offered> {
        let n = self.0;
        let addr = crate::mesh::ip(&n.cfg.wg_subnet, 1);
        // Read capped, as it comes: whoever answers cannot make this
        // machine hold more than MAX_ENVELOPE of it.
        let dir = n.path(STORE);
        fsx::mkdir_all(&dir, 0o700)?;
        let tmp = dir.join("offered.part");
        let mut cmd = Command::new("ssh");
        cmd.args(n.ssh_args(&addr, &format!("release-get {serial} release")));
        let got = stream_to_file(ctx, &mut cmd, &tmp, MAX_ENVELOPE).and_then(|_| read_small(&tmp, MAX_ENVELOPE));
        let _ = std::fs::remove_file(&tmp);
        let out = got.map_err(|e| e.wrap("the coordinator's answer"))?;
        serde_json::from_str(&out).map_err(|e| Error::from(e).wrap("the coordinator's answer"))
    }

    fn chunk(&self, ctx: &Ctx, serial: u64, name: &str, offset: u64, len: u64, dst: &Path) -> Result<()> {
        let n = self.0;
        let addr = crate::mesh::ip(&n.cfg.wg_subnet, 1);
        let mut cmd = Command::new("ssh");
        cmd.args(n.ssh_args(&addr, &format!("release-get {serial} {name} {offset}")));
        let got = stream_to_file(ctx, &mut cmd, dst, len)?;
        if got != len {
            bail!("the coordinator sent {got} bytes of {name}, not {len}");
        }
        Ok(())
    }
}

/// Runs cmd and writes what it prints into a new file at dst: at most max
/// bytes. More is refused (and the command killed), so whoever answers
/// cannot fill the disk; the command is killed too when ctx is done.
/// Returns how many bytes came.
pub fn stream_to_file(ctx: &Ctx, cmd: &mut Command, dst: &Path, max: u64) -> Result<u64> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(dst)
        .map_err(|e| Error::from(e).wrap(format!("open {}", dst.display())))?;
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let name = cmd.get_program().to_string_lossy().into_owned();
    let mut child = cmd.spawn().map_err(|e| Error::from(e).wrap(&name))?;
    let mut out = child.stdout.take().ok_or_else(|| Error::new("no stdout"))?;
    let mut err = child.stderr.take().ok_or_else(|| Error::new("no stderr"))?;
    let copier = std::thread::spawn(move || -> Result<u64> {
        let mut buf = vec![0u8; 64 << 10];
        let mut n: u64 = 0;
        loop {
            let k = match out.read(&mut buf) {
                Ok(0) => return Ok(n),
                Ok(k) => k,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Error::from(e).wrap("read")),
            };
            n += k as u64;
            if n > max {
                // Dropping the pipe ends the sender.
                bail!("more than {max} bytes came");
            }
            file.write_all(&buf[..k]).map_err(|e| Error::from(e).wrap("write"))?;
        }
    });
    let errs = std::thread::spawn(move || {
        let mut kept = Vec::new();
        let _ = (&mut err).take(4096).read_to_end(&mut kept);
        let _ = io::copy(&mut err, &mut io::sink());
        String::from_utf8_lossy(&kept).into_owned()
    });
    let join = |c: std::thread::JoinHandle<Result<u64>>| c.join().unwrap_or_else(|_| Err(Error::new("the copy crashed")));
    let mut copier = Some(copier);
    let mut copied = None;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Ok(st),
            Ok(None) => {}
            Err(e) => break Err(Error::from(e)),
        }
        if ctx.done() {
            let _ = child.kill();
            break child.wait().map_err(Error::from);
        }
        if let Some(c) = copier.take_if(|c| c.is_finished()) {
            let res = join(c);
            if res.is_err() {
                // Too much, or the disk would not take it: the command has
                // nothing more to say.
                let _ = child.kill();
            }
            copied = Some(res);
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let copied = match (copied, copier) {
        (Some(res), _) => res,
        (None, Some(c)) => join(c),
        (None, None) => Err(Error::new("the copy crashed")),
    };
    let msg = errs.join().unwrap_or_default();
    let tail = msg.lines().map(str::trim).rfind(|l| !l.is_empty()).map(report::note).unwrap_or_default();
    if let Some(e) = ctx.err() {
        return Err(e);
    }
    let n = copied?;
    let st = status?;
    if !st.success() {
        let why = if tail.is_empty() { crate::runner::exit_text(st) } else { format!("{}: {tail}", crate::runner::exit_text(st)) };
        bail!("{name} failed: {why}");
    }
    Ok(n)
}

// ---- a machine updating itself ----

/// What the brain tells a member in its sync reply.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Offer {
    /// The release the swarm moves to; 0: none.
    pub serial: u64,
    /// This machine may update now.
    pub turn: bool,
    /// The k3s the brain runs, as the brain reports it: a server's k3s may
    /// not be newer (Kubernetes' version skew rule).
    pub brain_k3s: String,
    /// With the turn: the admin resumed the rollout at this machine, so it
    /// tries the release once more although it failed here before. Each
    /// resume has its own number; 0: none.
    #[serde(skip_serializing_if = "is_zero")]
    pub retry: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// What the registry tells member host in its sync reply. The turn holds
/// only while the rollout runs and the server is drained.
pub fn offer(s: &registry::State, host: u32) -> Offer {
    let r = &s.rollout;
    let mine = r.turn.as_ref().filter(|t| t.host == host && t.ready);
    let turn = host != 1 && r.paused.is_empty() && r.phase == Phase::Servers && mine.is_some();
    let brain_k3s = s.members.iter().find(|m| m.host == 1).and_then(|m| m.report.as_ref()).map(|r| r.k3s.clone()).unwrap_or_default();
    let retry = if turn { mine.map_or(0, |t| t.retry) } else { 0 };
    Offer { serial: r.serial, turn, brain_k3s, retry }
}

/// What a machine keeps about its update, in STORE/state.json.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Local {
    /// Installed and waiting for confirmation; 0: none.
    pub pending: u64,
    /// When it was installed, unix seconds.
    pub applied: i64,
    /// The last release that did not work here, how (failed, reverted,
    /// refused) and why. It is not tried again; the brain decides.
    pub failed: u64,
    pub outcome: String,
    pub why: String,
    /// What holds the update up for now (a piece that did not come, k3s
    /// not up yet): it is tried again at the next sync.
    pub note: String,
    /// The release installed, as `dryserver update status` said last.
    pub installed: u64,
    /// A release the admin said to try again although it failed or went
    /// back before, and (on a server) the number of that resume
    /// (Offer::retry): each resume is carried out once.
    pub retry: u64,
    pub retried: u64,
    /// The release a problem that may pass held up, and at how many syncs.
    pub tries_serial: u64,
    pub tries: u32,
}

/// What is known about the release being loaded, in STORE/incoming.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct Meta {
    serial: u64,
    k3s_size: u64,
    /// This machine's k3s is not the release's: load it too.
    need_k3s: bool,
}

/// Why an update step ended.
enum Stop {
    /// Not done yet, or a problem that may pass: again at the next sync.
    Again(Error),
    /// A problem that may pass but may also stay: again at the next sync,
    /// MAX_TRIES times, then the update failed.
    Later(String),
    /// The release did not pass this machine's checks. (Installing it
    /// runs on after the sync that started it: settle sees how it ended.)
    Refused(String),
    /// It was installed before and went back: not sent again unless the
    /// admin resumes.
    Reverted(String),
}

/// One machine (the brain or a server) updating itself.
pub struct Machine<'a> {
    pub n: &'a Node,
    /// The brain runs the k3s server, and is never held by a kill switch.
    pub brain: bool,
    pub free: fn(&Path) -> Option<u64>,
}

impl<'a> Machine<'a> {
    pub fn new(n: &'a Node, brain: bool) -> Machine<'a> {
        Machine { n, brain, free: free_bytes }
    }

    fn dir(&self) -> PathBuf {
        self.n.path(STORE)
    }

    fn ensure_dir(&self) -> Result<()> {
        let d = self.dir();
        fsx::mkdir_all(&d, 0o700)?;
        fsx::chmod(&d, 0o700)
    }

    pub fn load(&self) -> Local {
        read_small(&self.dir().join(STATE_FILE), MAX_STATE).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }

    fn save(&self, l: &Local) -> Result<()> {
        self.ensure_dir()?;
        write_atomic(&self.dir().join(STATE_FILE), &(serde_json::to_string_pretty(l)? + "\n"))
    }

    /// On the brain: the rollout as root keeps it; none before the first.
    fn own_rollout(&self) -> Rollout {
        read_small(&self.dir().join(ROLLOUT_FILE), MAX_ROLLOUT).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }

    fn save_rollout(&self, r: &Rollout) -> Result<()> {
        self.ensure_dir()?;
        write_atomic(&self.dir().join(ROLLOUT_FILE), &(serde_json::to_string_pretty(r)? + "\n"))
    }

    /// A release in one of the store's directories. It was checked before
    /// it was stored, and only root writes there.
    fn release_in(&self, sub: &str) -> Option<(Envelope, Release)> {
        let text = read_small(&self.dir().join(sub).join(RELEASE_FILE), MAX_ENVELOPE).ok()?;
        let env: Envelope = serde_json::from_str(&text).ok()?;
        let r = serde_json::from_str(&env.doc).ok()?;
        Some((env, r))
    }

    /// The release this machine runs (confirmed); None before its first
    /// update.
    pub fn installed(&self) -> Option<Release> {
        self.release_in(INSTALLED).map(|(_, r)| r)
    }

    /// The serial of the release this machine runs: its store's, or what
    /// `dryserver update status` said, whichever is higher.
    pub fn installed_serial(&self) -> u64 {
        self.installed().map_or(0, |r| r.serial).max(self.load().installed)
    }

    /// When this machine began to take releases (recorded now when it was
    /// not yet): what a rollback goes by while no release is installed
    /// here (update::note_start).
    fn start(&self, now: i64) -> i64 {
        crate::update::note_start(&crate::update::Machine::at_root(&self.n.root, self.n.run.clone(), self.n.verifier.clone()), now)
    }

    fn update(&self) -> Update<'_> {
        Update { run: self.n.run.as_ref(), bin: quarantine::SERVER_BIN }
    }

    /// Why a server does not update now: its kill switch is on. A machine
    /// in the middle of an incident changes nothing until the admin lifted
    /// it.
    fn hold(&self) -> Option<String> {
        if self.brain {
            return None;
        }
        match quarantine::load(self.n) {
            Ok(q) if q.is_empty() => None,
            Ok(q) => {
                let names: Vec<String> =
                    q.cuts.iter().map(|c| if registry::valid_name(&c.name) { c.name.clone() } else { "(unnamed)".into() }).collect();
                Some(format!("its kill switch is on ({} cut off): no update until it is lifted", names.join(", ")))
            }
            Err(e) => Some(format!("its kill switch state cannot be read ({e}): no update")),
        }
    }

    /// What this machine says about its update in its report.
    pub fn describe(&self, r: &mut Report) {
        let l = self.load();
        r.release = self.installed_serial();
        let incoming = self.release_in(INCOMING).map(|(_, i)| i.serial).unwrap_or(0);
        let (state, serial, note) = if l.pending != 0 {
            ("pending", l.pending, l.note.clone())
        } else if let Some(why) = self.hold() {
            ("held", 0, why)
        } else if incoming > r.release && incoming != l.failed {
            ("fetching", incoming, l.note.clone())
        } else if l.failed != 0 {
            (l.outcome.as_str(), l.failed, l.why.clone())
        } else {
            ("", 0, String::new())
        };
        r.update = if report::UPDATE_STATES.contains(&state) { state.to_string() } else { String::new() };
        r.update_serial = serial;
        r.update_note = report::note(&note);
    }

    /// One step towards the offered release, at a sync that reached the
    /// brain. rep is this machine's report of this sync, for its health.
    ///
    /// - Installed and pending: confirmed once the new binary runs and the
    ///   machine is healthy; a revert is noticed and recorded.
    /// - With the turn and an offer newer than what runs: loads the
    ///   release (going on where the last sync stopped), checks it, installs
    ///   it.
    ///
    /// Problems that may pass (a piece that did not come) are returned and
    /// tried again; a refused or failed update is recorded, shown in the
    /// report, and not tried again.
    pub fn step(&self, ctx: &Ctx, src: &dyn Source, offer: &Offer, rep: &Report, now: i64) -> Result<()> {
        // From the first sync on: when this machine began to take releases.
        self.start(now);
        let mut l = self.load();
        if l.pending != 0 {
            return self.settle(ctx, &mut l, rep, now);
        }
        if !offer.turn || offer.serial == 0 || self.installed_serial() >= offer.serial {
            return Ok(());
        }
        if offer.retry != 0 && (l.retry != offer.serial || l.retried != offer.retry) {
            // The admin resumed the rollout here: the release is tried once
            // more, even one that went back (ready).
            let failed_here = l.failed == offer.serial;
            l.retry = offer.serial;
            l.retried = offer.retry;
            if failed_here {
                (l.failed, l.tries) = (0, 0);
                l.outcome.clear();
                l.why.clear();
            }
            self.save(&l)?;
            if failed_here {
                // Its next report no longer shows the failure, before it
                // tries again: the brain waits for that report, so a report
                // from before the resume does not stop the rollout again.
                return Ok(());
            }
        }
        if l.failed == offer.serial {
            return Ok(());
        }
        if self.hold().is_some() {
            return Ok(());
        }
        let res = self.ready(ctx, offer, now, &mut l).and_then(|go| if go { self.advance(ctx, src, offer, now, &mut l) } else { Ok(()) });
        let (outcome, why) = match res {
            Ok(()) => return Ok(()),
            Err(Stop::Again(e)) => {
                let note = report::note(&e.to_string());
                if l.note != note {
                    l.note = note;
                    self.save(&l)?;
                }
                return Err(e);
            }
            Err(Stop::Later(why)) => return self.later(&mut l, offer.serial, &why),
            Err(Stop::Refused(why)) => ("refused", why),
            Err(Stop::Reverted(why)) => ("reverted", why),
        };
        self.fail(&mut l, offer.serial, outcome, &why)
    }

    /// A problem that may pass held release serial up: it is tried again
    /// at the next sync, MAX_TRIES syncs in a row, then it failed here.
    fn later(&self, l: &mut Local, serial: u64, why: &str) -> Result<()> {
        if l.tries_serial != serial {
            (l.tries_serial, l.tries) = (serial, 0);
        }
        l.tries += 1;
        if l.tries < MAX_TRIES {
            l.note = report::note(why);
            self.save(l)?;
            return Err(errf!("release {serial}: {why} (tried {} of {MAX_TRIES} times, again at the next sync)", l.tries));
        }
        self.fail(l, serial, "failed", &format!("{why} ({MAX_TRIES} syncs in a row)"))
    }

    /// Release serial did not work here (outcome: failed, refused or
    /// reverted): recorded, shown in the report, not tried again.
    fn fail(&self, l: &mut Local, serial: u64, outcome: &str, why: &str) -> Result<()> {
        l.failed = serial;
        l.outcome = outcome.into();
        l.why = report::note(why);
        l.note.clear();
        self.save(l)?;
        Err(errf!("release {serial} {outcome}: {why}"))
    }

    /// What holds the update up for now, for the report.
    fn wait(&self, l: &mut Local, why: &str) -> Result<()> {
        l.note = report::note(why);
        self.save(l)
    }

    /// What the update commands say before anything is loaded: true, go
    /// on. A release that went back before is not installed again (the
    /// commands do not refuse it themselves); one that is already
    /// installed or pending is taken over.
    fn ready(&self, ctx: &Ctx, offer: &Offer, now: i64, l: &mut Local) -> std::result::Result<bool, Stop> {
        // The sync's own time running out ends up here too.
        let st = self.update().status(ctx).map_err(|e| Stop::Later(format!("cannot ask how its updates stand: {e}")))?;
        if st.busy {
            return Err(Stop::Again(errf!("an update runs on this machine now")));
        }
        if st.confirmed_serial() >= offer.serial {
            l.installed = st.confirmed_serial();
            self.save(l).map_err(Stop::Again)?;
            return Ok(false);
        }
        match st.pending_serial() {
            0 => {}
            p if p == offer.serial && self.release_in(INCOMING).is_some_and(|(_, r)| r.serial == p) => {
                l.pending = p;
                l.applied = now;
                self.save(l).map_err(Stop::Again)?;
                return Ok(false);
            }
            p => return Err(Stop::Again(errf!("release {p} is installed and waits for its confirmation"))),
        }
        if let Some(why) = st.reverted(offer.serial)
            && l.retry != offer.serial
        {
            return Err(Stop::Reverted(why));
        }
        Ok(true)
    }

    /// Loads, checks and installs the offered release.
    fn advance(&self, ctx: &Ctx, src: &dyn Source, offer: &Offer, now: i64, l: &mut Local) -> std::result::Result<(), Stop> {
        let again = Stop::Again;
        let start = Instant::now();
        self.ensure_dir().map_err(again)?;
        let inc = self.dir().join(INCOMING);
        let place = if self.brain { Place::Brain } else { Place::Worker { brain_k3s: &offer.brain_k3s } };
        if !self.brain && offer.brain_k3s.trim().is_empty() {
            // Its report may not have come in yet (the brain just booted).
            return Err(Stop::Later("the coordinator does not say yet which k3s it runs".into()));
        }
        let installed = self.installed();

        // The signed release: loaded once, checked at every step.
        let (env, meta) = match self.release_in(INCOMING) {
            Some((env, r)) if r.serial == offer.serial => {
                let meta: Meta =
                    read_small(&inc.join(META_FILE), MAX_STATE).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
                (env, meta)
            }
            _ => {
                let o = src.offered(ctx, offer.serial).map_err(|e| Stop::Again(e.wrap("ask the coordinator for the release")))?;
                remove_dir(&inc).map_err(again)?;
                fsx::mkdir_all(&inc, 0o700).map_err(again)?;
                (o.release, Meta { serial: offer.serial, k3s_size: o.k3s_size, need_k3s: false })
            }
        };
        let since = self.start(now);
        let floor = release::Start { since };
        let (r, verdict) = release::check_from(self.n.verifier.as_ref(), &env, installed.as_ref(), floor, place, now)
            .map_err(|e| Stop::Refused(e.to_string()))?;
        if r.serial != offer.serial {
            return Err(Stop::Refused(format!("the coordinator offered release {} and sent release {}", offer.serial, r.serial)));
        }
        if !verdict.install {
            return Ok(());
        }
        let mut meta = meta;
        if meta.serial != r.serial {
            meta = Meta { serial: r.serial, ..meta };
        }
        if !inc.join(RELEASE_FILE).exists() {
            // Its k3s is loaded only when this machine's is another one.
            meta.need_k3s = sha_of(&self.n.path(K3S_BIN), MAX_K3S).as_deref() != Some(r.k3s.sha256.as_str());
            // The registry's word on its size: capped before it counts.
            if meta.need_k3s && meta.k3s_size > MAX_K3S {
                return Err(Stop::Refused(format!("the coordinator says its k3s is {} bytes", meta.k3s_size)));
            }
            let need = r.dryserver.size.saturating_add(if meta.need_k3s { meta.k3s_size } else { 0 });
            // Room may be made (logs rotate, an old image goes).
            room(self.free, &self.dir(), need, "this machine").map_err(|e| Stop::Later(e.to_string()))?;
            fsx::write_file(inc.join(META_FILE), serde_json::to_string(&meta).map_err(|e| again(e.into()))?, 0o600).map_err(again)?;
            write_atomic(&inc.join(RELEASE_FILE), &(serde_json::to_string(&env).map_err(|e| again(e.into()))? + "\n")).map_err(again)?;
        }
        let until = start + FETCH_BUDGET;
        let mut pieces = 0;
        self.fetch(ctx, src, r.serial, DRYSERVER_FILE, r.dryserver.size, &r.dryserver.sha256, until, &mut pieces)?;
        if meta.need_k3s {
            if meta.k3s_size == 0 {
                // The coordinator had no k3s file for it when it was asked
                // (it may be put back): asked again, a few times.
                let o = src.offered(ctx, r.serial).map_err(|e| Stop::Again(e.wrap("ask the coordinator for the release")))?;
                if o.k3s_size == 0 {
                    return Err(Stop::Later(format!("the coordinator has no k3s {} for release {}", r.k3s.version, r.serial)));
                }
                if o.k3s_size > MAX_K3S {
                    return Err(Stop::Refused(format!("the coordinator says its k3s is {} bytes", o.k3s_size)));
                }
                room(self.free, &self.dir(), o.k3s_size, "this machine").map_err(|e| Stop::Later(e.to_string()))?;
                meta.k3s_size = o.k3s_size;
                fsx::write_file(inc.join(META_FILE), serde_json::to_string(&meta).map_err(|e| again(e.into()))?, 0o600).map_err(again)?;
            }
            if meta.k3s_size > MAX_K3S {
                return Err(Stop::Refused(format!("the coordinator says its k3s is {} bytes", meta.k3s_size)));
            }
            self.fetch(ctx, src, r.serial, K3S_FILE, meta.k3s_size, &r.k3s.sha256, until, &mut pieces)?;
        }
        // Everything is here and checked: install it. The update commands
        // check the release once more themselves. It runs on in a service of
        // its own; the syncs that follow watch it (settle). A start that
        // does not happen may well work later.
        let k3s = meta.need_k3s.then(|| inc.join(K3S_FILE));
        self.update()
            .apply(
                &Ctx::new().with_timeout(START_TIMEOUT),
                &inc.join(RELEASE_FILE),
                &inc.join(DRYSERVER_FILE),
                k3s.as_deref(),
                &offer.brain_k3s,
            )
            .map_err(|e| Stop::Later(format!("cannot start the update: {e}")))?;
        // The resume it acted on stays: if this goes back too, the same
        // turn's offer must not clear that failure again. So do the tries
        // of a release that was postponed before.
        *l = Local {
            pending: r.serial,
            applied: now,
            installed: l.installed,
            retry: l.retry,
            retried: l.retried,
            note: "installing".into(),
            tries_serial: l.tries_serial,
            tries: l.tries,
            ..Local::default()
        };
        self.save(l).map_err(again)?;
        Ok(())
    }

    /// Loads one file of the release in pieces, going on from what earlier
    /// syncs loaded, and checks it once it is whole. pieces counts the
    /// pieces this sync asked for (MAX_PIECES).
    ///
    /// What came of a piece that was cut off (a slow link, the sync's own
    /// deadline) is kept, and the next piece starts where it ended: a slow
    /// server gets on at every sync instead of loading the same piece again
    /// and again. More than was asked for is thrown away. Nothing of it is
    /// used before the whole file matches the release's sha256.
    #[allow(clippy::too_many_arguments)]
    fn fetch(
        &self,
        ctx: &Ctx,
        src: &dyn Source,
        serial: u64,
        name: &str,
        size: u64,
        sha256: &str,
        until: Instant,
        pieces: &mut u32,
    ) -> std::result::Result<(), Stop> {
        let inc = self.dir().join(INCOMING);
        let done = inc.join(name);
        if done.exists() {
            return release::verify_file(&done, sha256, size).map_err(|e| {
                let _ = std::fs::remove_file(&done);
                Stop::Refused(format!("{name} from the coordinator does not match the release: {e}"))
            });
        }
        let part = inc.join(format!("{name}.part"));
        let mut have = file_len(&part);
        if have > size {
            let _ = std::fs::remove_file(&part);
            have = 0;
        }
        let so_far = |have: u64| format!("loading {name}: {} of {} so far", report::size(have), report::size(size));
        while have < size {
            if Instant::now() >= until || *pieces >= MAX_PIECES || ctx.done() {
                return Err(Stop::Again(errf!("{}, more at the next sync", so_far(have))));
            }
            *pieces += 1;
            let len = CHUNK.min(size - have);
            let piece = inc.join(format!("{name}.piece"));
            let _ = std::fs::remove_file(&piece);
            let res = src.chunk(&ctx.with_timeout(CHUNK_TIMEOUT), serial, name, have, len, &piece);
            let got = file_len(&piece);
            if got > len {
                let _ = std::fs::remove_file(&piece);
                return Err(Stop::Again(errf!("load {name}: the coordinator sent {got} bytes, not {len}")));
            }
            if got > 0 {
                let appended = (|| -> Result<()> {
                    let mut out = OpenOptions::new().create(true).append(true).mode(0o600).open(&part)?;
                    io::copy(&mut File::open(&piece)?, &mut out)?;
                    Ok(())
                })();
                if let Err(e) = appended {
                    let _ = std::fs::remove_file(&piece);
                    // A full disk may get room again (logs rotate, an old
                    // image goes): tried MAX_TRIES times.
                    return Err(match room(self.free, &self.dir(), size - have, "this machine") {
                        Err(full) => Stop::Later(full.to_string()),
                        Ok(()) => Stop::Again(e.wrap(format!("store {name}"))),
                    });
                }
            }
            let _ = std::fs::remove_file(&piece);
            have = file_len(&part);
            match res {
                // Short, and the coordinator says that is all: its copy
                // ends there.
                Ok(()) if got == 0 => {
                    return Err(Stop::Later(format!("the coordinator's copy of {name} ends after {have} of {size} bytes")));
                }
                Ok(()) => {}
                // Nothing came. A file the coordinator does not have will
                // not come by itself; a link that is down may.
                Err(e) if got == 0 && e.is_not_found() => return Err(Stop::Later(e.to_string())),
                Err(e) if got == 0 => return Err(Stop::Again(e.wrap(format!("load {name}")))),
                // Some came: on from where it ended.
                Err(e) => eprintln!("dryserver: update: {}, cut off: {e}", so_far(have)),
            }
        }
        if let Err(e) = release::verify_file(&part, sha256, size) {
            let _ = std::fs::remove_file(&part);
            return Err(Stop::Refused(format!("{name} from the coordinator does not match the release: {e}")));
        }
        fsx::rename(&part, &done).map_err(Stop::Again)
    }

    /// An update this machine started: its apply runs, or it waits for its
    /// confirmation, or it ended without installing the release.
    fn settle(&self, ctx: &Ctx, l: &mut Local, rep: &Report, now: i64) -> Result<()> {
        let up = self.update();
        let st = up.status(ctx)?;
        l.installed = st.confirmed_serial();
        let mine = st.pending.as_ref().filter(|p| p.serial == l.pending);
        if st.busy {
            // The apply runs (pacman may take its time): it decides.
            let step = mine.map(|p| p.step.as_str()).filter(|s| !s.is_empty()).unwrap_or("installing");
            return self.wait(l, step);
        }
        let pending = st.pending_serial();
        if pending != 0 && pending != l.pending {
            // Another release waits: its own deadline settles it.
            return self.save(l);
        }
        if let Some(p) = mine {
            if p.stage != "armed" {
                // Nothing runs, so its apply stopped part way (killed, or it
                // crashed): back now, not when its timer fires. The next sync
                // finds it reverted (or postponed, when it was loading).
                up.revert(&Ctx::new().with_timeout(CONFIRM_TIMEOUT))?;
                return self.wait(l, "its apply stopped part way; it went back");
            }
            if p.reboot && p.boots == 0 {
                return self.wait(l, "it reboots for its new packages and is confirmed after the restart");
            }
            if now.saturating_sub(l.applied) < CONFIRM_AFTER && now >= l.applied {
                return self.save(l);
            }
            let wait = match self.release_in(INCOMING) {
                None => Some("the installed release is not in this machine's store".to_string()),
                Some((_, r)) if running_sha(&self.n.root).as_deref() != Some(r.dryserver.sha256.as_str()) => {
                    Some("the new dryserver does not run yet".to_string())
                }
                Some(_) => healthy(rep, self.brain || self.n.path(crate::sysconf::K3S_TOKEN).exists()).err(),
            };
            if let Some(why) = wait {
                // Not confirmed: if it stays like this, the machine goes back
                // by itself at the deadline.
                if l.note != why {
                    l.note = why;
                    self.save(l)?;
                }
                return Ok(());
            }
            up.confirm(&Ctx::new().with_timeout(CONFIRM_TIMEOUT), l.pending)?;
            l.installed = l.installed.max(l.pending);
            return self.promote(l);
        }
        if st.confirmed(l.pending) {
            // Confirmed meanwhile (a sync killed after the confirm, or the
            // admin by hand). Only its record says so: a revert that half
            // failed may leave the release named installed.
            l.installed = l.installed.max(l.pending);
            return self.promote(l);
        }
        // Nothing waits and nothing runs: the apply ended without
        // installing it, and said why (results of this start only).
        let serial = l.pending;
        let said = st.last.as_ref().filter(|x| x.serial == serial && x.at >= l.applied);
        let message = said.map(|x| x.message.clone()).filter(|m| !m.is_empty());
        match said.map(|x| x.action.as_str()) {
            Some("postponed") => {
                l.pending = 0;
                return self.later(l, serial, message.as_deref().unwrap_or("it was postponed"));
            }
            Some("refused") => {
                l.pending = 0;
                return self.fail(l, serial, "refused", message.as_deref().unwrap_or("this machine refused it"));
            }
            None if st.reverted(serial).is_none() => {
                if now >= l.applied && now - l.applied < START_GRACE {
                    // Started a moment ago: not running yet.
                    return self.wait(l, "installing");
                }
                l.pending = 0;
                return self.later(l, serial, "the update ended without saying how");
            }
            _ => {}
        }
        let why = st.reverted(l.pending).or_else(|| st.last.as_ref().filter(|x| !x.ok && !x.message.is_empty()).map(|x| x.message.clone()));
        l.failed = l.pending;
        l.outcome = "reverted".into();
        l.why = report::note(why.as_deref().unwrap_or("it was not confirmed in time and went back"));
        l.pending = 0;
        l.note.clear();
        self.save(l)
    }

    /// The pending release runs: it becomes the installed one, and the one
    /// before is kept as the previous.
    fn promote(&self, l: &mut Local) -> Result<()> {
        let d = self.dir();
        let (inc, cur, prev) = (d.join(INCOMING), d.join(INSTALLED), d.join(PREVIOUS));
        if inc.join(RELEASE_FILE).exists() {
            remove_dir(&prev)?;
            if cur.exists() {
                fsx::rename(&cur, &prev)?;
            }
            fsx::rename(&inc, &cur)?;
        }
        *l = Local { installed: l.installed, ..Local::default() };
        self.save(l)
    }

    /// Lets the brain try its own update again (the admin resumed).
    fn forget_failure(&self, serial: u64) {
        let mut l = self.load();
        if l.failed == serial {
            (l.failed, l.tries) = (0, 0);
            l.outcome.clear();
            l.why.clear();
        }
        l.retry = serial;
        let _ = self.save(&l);
        let _ = remove_dir(&self.dir().join(INCOMING));
    }
}

/// Whether a machine's report says it is well enough to keep its update:
/// its firewall is loaded and k3s runs. expect_k3s: k3s must run (the
/// brain, a server in the cluster); otherwise it must only not be down.
pub fn healthy(r: &Report, expect_k3s: bool) -> std::result::Result<(), String> {
    if r.firewall != Some(true) {
        return Err("its firewall is not loaded".into());
    }
    if r.boot == "fallback" {
        // The kernel the update brought did not boot (or someone picked the
        // fallback): not the machine the update was to leave.
        return Err("it runs its fallback kernel: the main kernel did not boot well (dryserver boot status)".into());
    }
    match r.k3s_active {
        Some(false) => Err("k3s is not running".into()),
        None if expect_k3s => Err("k3s is not running".into()),
        _ => Ok(()),
    }
}

/// On a server, at a sync that reached the brain: one update step.
pub fn server_tick(ctx: &Ctx, n: &Node, offer: &Offer, rep: &Report, now: i64) -> Result<()> {
    Machine::new(n, false).step(ctx, &SshSource(n), offer, rep, now)
}

// ---- the rollout, on the brain ----

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    /// A normal release waits for the update window.
    Waiting,
    /// The brain updates itself.
    Brain,
    /// The servers update, one at a time.
    Servers,
    /// The brain's own update did not work: no server is touched.
    Failed,
    /// No release yet, or a phase this version does not know.
    #[default]
    #[serde(other)]
    None,
}

/// Why the rollout stopped, which decides what resuming does. A skip
/// (`release resume -skip`) passes the server over instead: it keeps its
/// release until the next one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Pause {
    /// The server could not be drained: resuming updates it without.
    Drain,
    /// Its update failed, reverted or was refused: resuming gives it the
    /// turn again (now, or when it is back), and it tries once more.
    Failed,
    /// It did not finish in TURN_TIMEOUT: resuming gives it the turn
    /// again; what it loaded so far stays.
    Timeout,
    /// The canary is not well after its update: resuming goes on.
    Canary,
    /// Not stopped (or stopped for a reason this version does not know).
    #[default]
    #[serde(other)]
    None,
}

/// The server whose turn it is.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Turn {
    pub host: u32,
    pub name: String,
    /// When the turn began, on the brain's clock.
    pub since: i64,
    /// Drained: the server may update now.
    pub ready: bool,
    /// The admin resumed the rollout at this server: the number of that
    /// resume (Offer::retry), 0: its first try. A report of a failure
    /// counts only once a report without it came in (cleared): the one
    /// sent before the server heard of the resume still shows it.
    #[serde(skip_serializing_if = "is_zero")]
    pub retry: u64,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub cleared: bool,
}

/// A server passed over, and why.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Skip {
    pub host: u32,
    pub name: String,
    pub why: String,
}

/// The rollout of the newest release. The brain's sync (root) keeps it in
/// its own store and moves it on; the registry gets a copy, which the
/// registry account reads to answer its callers. Of that copy root takes
/// back only resume_asked, the admin's resumes the registry counts: the
/// registry account could write anything else in it, and node names from
/// it would end up on kubectl's command line.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Rollout {
    /// The release being rolled out; 0: none.
    pub serial: u64,
    pub urgent: bool,
    /// When the release was made and when it expires (unix seconds).
    pub created: i64,
    pub expires: i64,
    pub phase: Phase,
    pub started: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn: Option<Turn>,
    /// Servers on the release, by host number.
    pub done: Vec<u32>,
    /// The first server that updated in this rollout, and when the brain
    /// stops watching it.
    pub canary: u32,
    pub canary_until: i64,
    pub skipped: Vec<Skip>,
    /// Servers whose turn ended while they were silent: they come last.
    pub deferred: Vec<u32>,
    /// Servers the admin let update without draining.
    pub force: Vec<u32>,
    /// Servers the admin resumed the rollout at: they try the release again
    /// at their next turn, before the others.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub again: Vec<u32>,
    /// How many tries again this rollout gave (Turn::retry numbers them).
    #[serde(skip_serializing_if = "is_zero")]
    pub retries: u64,
    /// One entry per turn a server was given in this rollout (MAX_TURNS).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub turns: Vec<u32>,
    /// Nodes this rollout cordoned and did not uncordon yet.
    pub cordoned: Vec<String>,
    /// Why the rollout stopped; empty while it runs.
    pub paused: String,
    pub pause: Pause,
    pub pause_host: u32,
    pub pause_name: String,
    /// The newest things the admin should know (a drain that timed out).
    pub warnings: Vec<String>,
    /// The newest upload, when the brain refused it, and why.
    pub refused_serial: u64,
    pub refused: String,
    /// Resumes the admin asked for (the registry counts them) and the ones
    /// the brain carried out. A resume tries the server the rollout stopped
    /// at again; a skip (`release resume -skip`) passes it over.
    pub resume_asked: u64,
    pub resume_done: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub skip_asked: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub skip_done: u64,
    /// A server in the middle of an update (the one a release this one
    /// replaced was updating, or one whose report says its update is
    /// pending): nothing starts beside it, neither the brain's own update
    /// nor a turn (one machine at a time). After TURN_TIMEOUT the rollout
    /// stops at it for the admin. 0: none.
    #[serde(skip_serializing_if = "is_zero32")]
    pub wait_for: u32,
    /// When the wait for it began, on the brain's clock (0 in a rollout
    /// from before: its start).
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub wait_since: i64,
    /// Root's last tick on the brain's clock (not handed to the registry),
    /// and when its ticks went on after a gap or a jump of its clock.
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub ticked: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub back: i64,
}

fn is_zero32(n: &u32) -> bool {
    *n == 0
}

fn is_zero_i64(n: &i64) -> bool {
    *n == 0
}

impl Rollout {
    pub fn is_none(&self) -> bool {
        *self == Rollout::default()
    }

    fn start(r: &Release, now: i64, stale: bool) -> Rollout {
        let mut out = Rollout {
            serial: r.serial,
            urgent: r.urgent,
            created: r.created,
            expires: r.expires,
            phase: if r.urgent { Phase::Brain } else { Phase::Waiting },
            started: now,
            ..Rollout::default()
        };
        if stale {
            out.warn(format!(
                "release {} expired by the coordinator's clock: check its clock, or sign a new release to show the updates are alive",
                r.serial
            ));
        }
        out
    }

    fn warn(&mut self, w: String) {
        self.warnings.retain(|o| *o != w);
        self.warnings.push(w);
        if self.warnings.len() > MAX_WARNINGS {
            self.warnings.remove(0);
        }
    }

    fn stop(&mut self, kind: Pause, host: u32, name: &str, why: String) {
        self.pause = kind;
        self.pause_host = host;
        self.pause_name = name.into();
        self.paused = why;
    }

    fn unpause(&mut self) {
        self.pause = Pause::None;
        self.pause_host = 0;
        self.pause_name.clear();
        self.paused.clear();
    }
}

/// What the brain's sync works with in one tick.
struct Brain<'a> {
    ctx: &'a Ctx,
    n: &'a Node,
    served: &'a Served,
    rep: &'a Report,
    now: Now,
    members: &'a [Member],
    r: Rollout,
    free: fn(&Path) -> Option<u64>,
    /// The cluster's node names, asked once per tick when needed.
    nodes: Option<Vec<String>>,
}

/// One step of the rollout, at every sync of the brain (as root): takes up
/// a new upload, carries out a resume, updates the brain, and gives the
/// servers their turns. Commands that take a while (draining) run without
/// the registry lock; what changed is written back at the end.
///
/// members is the swarm as this sync uses it for the mesh and the cluster:
/// exactly the list the admin signed (Node::signed_members), with what the
/// registry says of each member (its report, when it was last seen). Not
/// the registry's own list: the registry account writes that, and the
/// rollout names its servers to kubectl.
pub fn brain_tick(ctx: &Ctx, n: &Node, store: &Store, served: &Served, rep: &Report, now: Now, members: &[Member]) {
    brain_tick_with(ctx, n, store, served, rep, now, members, free_bytes);
}

#[allow(clippy::too_many_arguments)]
fn brain_tick_with(
    ctx: &Ctx,
    n: &Node,
    store: &Store,
    served: &Served,
    rep: &Report,
    now: Now,
    members: &[Member],
    free: fn(&Path) -> Option<u64>,
) {
    let Ok(s) = store.read() else { return };
    let m = Machine { n, brain: true, free };
    m.start(now.unix);
    let before = m.own_rollout();
    let mut b = Brain { ctx, n, served, rep, now, members, r: before.clone(), free, nodes: None };
    b.r.resume_asked = s.rollout.resume_asked;
    b.r.skip_asked = s.rollout.skip_asked;
    b.take_upload();
    if b.r.serial != 0 {
        b.mind_the_gap();
        b.resume();
        b.advance();
    }
    let r = b.r;
    if r != before
        && let Err(e) = m.save_rollout(&r)
    {
        // Not handed out either: the registry tells what root keeps.
        eprintln!("dryserver: rollout: cannot save its state: {e}");
        return;
    }
    // The registry's counts of the admin's asks are the registry's; root's
    // clock at each tick is root's alone (and would rewrite the registry
    // every minute).
    let copy = |s: &Rollout| Rollout { resume_asked: s.resume_asked, skip_asked: s.skip_asked, ticked: 0, ..r.clone() };
    if copy(&s.rollout) != s.rollout {
        let res = store.update(|s| {
            // A resume asked while this tick ran stays asked.
            s.rollout = copy(&s.rollout);
            Ok(())
        });
        if let Err(e) = res {
            eprintln!("dryserver: rollout: cannot hand its state to the registry: {e}");
        }
    }
}

impl Brain<'_> {
    fn machine(&self) -> Machine<'_> {
        Machine { n: self.n, brain: true, free: self.free }
    }

    /// kubectl on one node of the cluster. The name goes last, after `--`,
    /// so it is never read as an option (`-l...` would select every node),
    /// and only when it is a plain hostname, not the brain's own node, and
    /// a node the cluster lists; one it does not list is NotFound.
    fn kubectl(&mut self, args: &[&str], node: &str) -> Result<()> {
        if !registry::valid_name(node) {
            bail!("{:?} is not a node name", shown(node, 40));
        }
        if node == self.n.hostname || self.members.iter().any(|m| m.host == 1 && m.name == node) {
            bail!("{node} is the coordinator, which the rollout never cordons or drains");
        }
        if !self.nodes()?.iter().any(|n| n == node) {
            return Err(Error::with_kind(Kind::NotFound, format!("{node} is not a node of the cluster")));
        }
        let mut all = vec!["kubectl"];
        all.extend_from_slice(args);
        all.extend(["--", node]);
        self.n.run.ok(&self.ctx.with_timeout(Duration::from_secs(40)), &Cmd::new("k3s", &all))
    }

    /// The names of the cluster's nodes.
    fn nodes(&mut self) -> Result<&[String]> {
        if self.nodes.is_none() {
            let cmd = Cmd::new("k3s", &["kubectl", "get", "nodes", "-o", "name"]).quiet().stdout_only();
            let out = self.n.run.output(&self.ctx.with_timeout(Duration::from_secs(40)), &cmd)?;
            self.nodes = Some(out.lines().filter_map(|l| l.trim().strip_prefix("node/")).map(String::from).collect());
        }
        Ok(self.nodes.as_deref().unwrap_or_default())
    }

    fn member(&self, host: u32) -> Option<&Member> {
        self.members.iter().find(|m| m.host == host)
    }

    fn online(&self, m: &Member) -> bool {
        !m.last_seen.is_zero() && self.now.unix - m.last_seen.0.timestamp() <= OFFLINE
    }

    /// The brain's syncs come a minute apart. A longer gap (it was down, or
    /// its sync failed before it got here) or a jump of its clock is no
    /// time a server had for its turn or the canary was watched: the timers
    /// stand still across it, and for OFFLINE after it (settling), while
    /// the members report in again.
    fn mind_the_gap(&mut self) {
        let now = self.now.unix;
        let last = std::mem::replace(&mut self.r.ticked, now);
        if last == 0 {
            return;
        }
        let gap = now.saturating_sub(last);
        let jumped = !(0..=OFFLINE).contains(&gap);
        let timing = self.r.turn.is_some() || self.r.canary_until > last || self.r.wait_since != 0;
        if jumped {
            self.r.back = now;
            if timing {
                let what = if gap < 0 {
                    format!("the coordinator's clock went back {}", report::short_age(gap.unsigned_abs()))
                } else {
                    format!("the coordinator did not run the rollout for {}", report::short_age(gap as u64))
                };
                self.r.warn(format!("{what}: the turn and the canary's watch do not count that time"));
            }
        }
        if jumped || self.settling() {
            if let Some(t) = &mut self.r.turn {
                t.since = t.since.saturating_add(gap);
            }
            if self.r.canary_until > last {
                self.r.canary_until = self.r.canary_until.saturating_add(gap);
            }
            if self.r.wait_since != 0 {
                self.r.wait_since = self.r.wait_since.saturating_add(gap);
            }
        }
    }

    /// Just after a gap: members may not have reported since, so none is
    /// judged silent and no new turn begins.
    fn settling(&self) -> bool {
        self.r.back != 0 && (0..OFFLINE).contains(&(self.now.unix - self.r.back))
    }

    fn in_window(&self) -> bool {
        self.r.urgent || in_window(self.now.minute, WINDOW)
    }

    /// The newest upload, checked by root before it counts. A newer one
    /// replaces the rollout that runs: machines go straight to it.
    fn take_upload(&mut self) {
        let Some(serial) = self.served.current() else { return };
        if serial <= self.r.serial || serial == self.r.refused_serial {
            return;
        }
        let installed = self.machine().installed();
        let since = self.machine().start(self.now.unix);
        let start = release::Start { since };
        let checked = self
            .served
            .envelope(serial)
            .and_then(|env| release::check_from(self.n.verifier.as_ref(), &env, installed.as_ref(), start, Place::Brain, self.now.unix));
        match checked {
            Ok((rel, verdict)) if rel.serial == serial => {
                let old = std::mem::take(&mut self.r);
                let mut fresh = Rollout::start(&rel, self.now.unix, verdict.stale);
                // Asks for the old rollout do not carry over to the new one.
                (fresh.resume_asked, fresh.resume_done) = (old.resume_asked, old.resume_asked);
                (fresh.skip_asked, fresh.skip_done) = (old.skip_asked, old.skip_asked);
                if old.serial != 0 && (old.phase == Phase::Brain || old.turn.is_some()) {
                    fresh.warn(format!("release {} replaced release {} while it rolled out", rel.serial, old.serial));
                }
                // A server may be in the middle of the old release: the brain
                // does not start its own update before it is done.
                fresh.wait_for = match &old.turn {
                    Some(t) if t.ready => t.host,
                    _ if matches!(old.pause, Pause::Failed | Pause::Timeout) => old.pause_host,
                    _ => old.wait_for,
                };
                if fresh.wait_for != 0 {
                    fresh.wait_since = self.now.unix;
                }
                (fresh.ticked, fresh.back) = (old.ticked, old.back);
                self.r = fresh;
                // The old rollout's cordons go; the new one starts clean.
                // But for the node of the server in the middle: it may
                // still reboot for its update, its pods elsewhere. It is
                // uncordoned once it is done (hold_for_the_middle).
                let middle = self.member(self.r.wait_for).map(|m| m.name.clone());
                for name in old.cordoned {
                    if middle.as_ref() == Some(&name) {
                        self.r.cordoned.push(name);
                    } else {
                        self.uncordon(&name);
                    }
                }
            }
            Ok((rel, _)) => {
                self.r.refused_serial = serial;
                self.r.refused = format!("the newest upload is named {serial} but holds release {}", rel.serial);
            }
            Err(e) => {
                self.r.refused_serial = serial;
                self.r.refused = format!("release {serial} was refused by the coordinator: {e}");
            }
        }
    }

    fn uncordon(&mut self, name: &str) {
        match self.kubectl(&["uncordon"], name) {
            Ok(()) => self.r.cordoned.retain(|c| c != name),
            // Not a node (any more), or not one it may touch: nothing to undo.
            Err(e) if e.is_not_found() || !registry::valid_name(name) || name == self.n.hostname => {
                self.r.cordoned.retain(|c| c != name);
            }
            Err(e) => {
                if self.members.iter().any(|m| m.name == name) {
                    if !self.r.cordoned.iter().any(|c| c == name) {
                        self.r.cordoned.push(name.into());
                    }
                    self.r.warn(format!("cannot uncordon {name} yet ({e}); trying again"));
                } else {
                    // It left the swarm; the cluster forgets it.
                    self.r.cordoned.retain(|c| c != name);
                }
            }
        }
    }

    /// Carries out what the admin asked for at a stop. resume_asked and
    /// skip_asked are the registry's counts, which anyone who can write the
    /// registry can change: a count that grew is one ask (what the admin's
    /// ask does anyway), one that went back is none. And what is resumed or
    /// passed over is always the server root itself stopped at.
    ///
    /// - resume: the server the rollout stopped at tries again (a fresh
    ///   turn, at once or in the window, or when it is back if it is
    ///   offline); one that could not be drained updates without; after a
    ///   canary the rollout goes on; the brain tries its own update again.
    /// - skip: the server is passed over for this release. The brain never
    ///   is: without it no server updates.
    fn resume(&mut self) {
        let resume = self.r.resume_asked > self.r.resume_done;
        let skip = self.r.skip_asked > self.r.skip_done;
        self.r.resume_done = self.r.resume_asked;
        self.r.skip_done = self.r.skip_asked;
        if !resume && !skip {
            return;
        }
        let serial = self.r.serial;
        if self.r.phase == Phase::Failed {
            self.machine().forget_failure(serial);
            self.r.phase = Phase::Brain;
            self.r.unpause();
            let why = if skip { " (it is never passed over: without it no server updates)" } else { "" };
            self.r.warn(format!("resumed: the coordinator tries its own update again{why}"));
            return;
        }
        let (host, name) = (self.r.pause_host, self.r.pause_name.clone());
        if self.r.phase == Phase::Brain && self.r.pause != Pause::None {
            // Stopped at a server in the middle of an update, before the
            // brain's own: resume waits once more, -skip goes on without it.
            if skip {
                let why = self.r.paused.clone();
                self.r.skipped.retain(|s| s.host != host);
                self.r.skipped.push(Skip { host, name: name.clone(), why });
                self.uncordon(&name);
                (self.r.wait_for, self.r.wait_since) = (0, 0);
                self.r.warn(format!(
                    "resumed: {name} is passed over for release {serial}; the coordinator updates itself without waiting for it"
                ));
            } else {
                self.r.wait_since = self.now.unix;
                self.r.warn(format!("resumed: the coordinator waits once more for {name} to finish the update it is in"));
            }
            self.r.unpause();
            return;
        }
        match self.r.pause {
            Pause::None => {}
            Pause::Canary => {
                self.r.canary_until = 0;
                self.r.warn(format!("resumed: the rollout goes on after the canary {name}"));
                self.r.unpause();
            }
            Pause::Drain | Pause::Failed | Pause::Timeout if skip => {
                let why = self.r.paused.clone();
                self.r.skipped.retain(|s| s.host != host);
                self.r.skipped.push(Skip { host, name: name.clone(), why });
                self.r.again.retain(|h| *h != host);
                self.r.force.retain(|h| *h != host);
                self.uncordon(&name);
                if self.r.wait_for == host {
                    (self.r.wait_for, self.r.wait_since) = (0, 0);
                }
                self.r.warn(format!("resumed: {name} is passed over for release {serial}"));
                self.r.unpause();
            }
            Pause::Drain => {
                if !self.r.force.contains(&host) {
                    self.r.force.push(host);
                }
                self.r.warn(format!("resumed: {name} updates without being drained"));
                self.r.unpause();
            }
            Pause::Failed | Pause::Timeout => {
                if !self.r.again.contains(&host) {
                    self.r.again.push(host);
                }
                self.r.deferred.retain(|h| *h != host);
                // The admin looked: its turns count from here, and so does
                // the wait for it, while it is in the middle of an update.
                self.r.turns.retain(|h| *h != host);
                if self.r.wait_for == host {
                    self.r.wait_since = self.now.unix;
                }
                let when = match self.member(host) {
                    Some(m) if !self.online(m) => "when it is back",
                    _ if !self.in_window() => "in the update window",
                    _ => "now",
                };
                self.r.warn(format!("resumed: {name} tries release {serial} again, {when}"));
                self.r.unpause();
            }
        }
    }

    fn advance(&mut self) {
        // The brain's own update in the middle is settled at every tick,
        // whatever the phase: a newer release that waits for the window
        // replaced the rollout, not the update it installed, which would
        // otherwise go back by itself at its deadline. Nothing else moves
        // in that tick.
        if self.r.phase != Phase::Brain && self.machine().load().pending != 0 {
            return self.own_step(&Offer { serial: self.r.serial, ..Offer::default() });
        }
        // A few steps per tick: waiting -> brain -> servers.
        for _ in 0..3 {
            match self.r.phase {
                Phase::Waiting if self.in_window() => self.r.phase = Phase::Brain,
                Phase::Brain => {
                    self.brain_step();
                    if self.r.phase != Phase::Servers {
                        return;
                    }
                }
                Phase::Servers => return self.servers(),
                _ => return,
            }
        }
    }

    /// The brain updates itself, from its registry's copy.
    fn brain_step(&mut self) {
        let m = Machine { n: self.n, brain: true, free: self.free };
        if m.load().pending == 0 && m.installed_serial() < self.r.serial {
            // Its own update starts only while no server is in the middle
            // of one.
            if !self.r.paused.is_empty() {
                // Stopped at the one in the middle: on by itself once it is
                // done.
                if self.in_the_middle().is_some() {
                    return;
                }
                let name = self.r.pause_name.clone();
                self.r.warn(format!("{name} finished the update it was in; the coordinator updates itself"));
                self.r.unpause();
            }
            if self.hold_for_the_middle() {
                return;
            }
        }
        // The brain's own k3s is the control plane's.
        let offer = Offer { serial: self.r.serial, turn: true, brain_k3s: self.rep.k3s.clone(), ..Offer::default() };
        self.own_step(&offer);
        if m.installed_serial() >= self.r.serial {
            if let Some(why) = self.served_k3s_problem() {
                // Every server that runs another k3s would refuse it, one
                // after the other: better to know before the first.
                self.r.phase = Phase::Failed;
                self.r.paused = format!("release {} cannot go to the servers: {why}. No server was touched", self.r.serial);
                return;
            }
            self.r.phase = Phase::Servers;
            return;
        }
        let l = m.load();
        if l.failed == self.r.serial {
            self.r.phase = Phase::Failed;
            self.r.paused = format!(
                "the coordinator's own update to release {} {}: {}. No server was touched",
                self.r.serial,
                if l.outcome.is_empty() { "failed" } else { &l.outcome },
                l.why
            );
        }
    }

    /// The server in the middle of an update, if one is, which nothing may
    /// update beside: the one this rollout waits for (wait_for) until a
    /// report from a minute after the rollout began shows it done, or any
    /// server whose report says its update is pending. Not one the admin
    /// passed over, and not one that left.
    ///
    /// A server's report is made before its sync steps: one sent up to a
    /// minute after a switch to a newer release may come from a sync that
    /// still had the old turn and installs it right after. A later one
    /// shows whether it did. One switched off in the middle (the reboot of
    /// its update) still says pending, and is waited for too.
    fn in_the_middle(&self) -> Option<(u32, String)> {
        let skipped = |h: u32| self.r.skipped.iter().any(|s| s.host == h);
        let pending = |m: &Member| m.report.as_ref().is_some_and(|r| r.update == "pending");
        if self.r.wait_for != 0
            && !skipped(self.r.wait_for)
            && let Some(m) = self.member(self.r.wait_for)
            && (m.last_seen.0.timestamp() < self.r.started.saturating_add(60) || pending(m))
        {
            return Some((m.host, m.name.clone()));
        }
        self.members
            .iter()
            .filter(|m| m.host != 1 && m.name != self.n.hostname && !skipped(m.host))
            .find(|m| pending(m))
            .map(|m| (m.host, m.name.clone()))
    }

    /// Holds the next step back (the brain's own update, a server's turn)
    /// while a server is in the middle of an update: never two machines
    /// at once. One that stays in the middle for TURN_TIMEOUT (it hangs,
    /// or, hacked, says so for ever) stops the rollout there for the
    /// admin: resume waits once more, -skip goes on without it. true:
    /// wait. The node of one that is done is uncordoned, if this rollout
    /// kept it cordoned.
    fn hold_for_the_middle(&mut self) -> bool {
        let now = self.now.unix;
        let middle = self.in_the_middle();
        let was = self.r.wait_for;
        if was != 0 && middle.as_ref().is_none_or(|(h, _)| *h != was) {
            (self.r.wait_for, self.r.wait_since) = (0, 0);
            if let Some(name) = self.member(was).map(|m| m.name.clone())
                && self.r.cordoned.contains(&name)
            {
                self.uncordon(&name);
            }
        }
        let Some((host, name)) = middle else { return false };
        if self.r.wait_for != host {
            (self.r.wait_for, self.r.wait_since) = (host, now);
        }
        if self.r.wait_since == 0 {
            // A rollout from before wait_since: from its start.
            self.r.wait_since = self.r.started;
        }
        if now.saturating_sub(self.r.wait_since) >= TURN_TIMEOUT {
            let state = self.member(host).and_then(|m| m.report.as_ref()).map(|r| r.update.clone()).filter(|s| !s.is_empty());
            let late = report::short_age(TURN_TIMEOUT as u64);
            self.r.stop(
                Pause::Timeout,
                host,
                &name,
                format!(
                    "{name} did not finish the update it is in within {late} (its update says {}): nothing updates beside it",
                    state.as_deref().unwrap_or("nothing yet")
                ),
            );
        }
        true
    }

    /// One step of the brain's own update: settles one it installed, or
    /// loads and installs the offered release.
    fn own_step(&self, offer: &Offer) {
        let m = self.machine();
        if let Err(e) = m.step(self.ctx, &LocalSource(self.served), offer, self.rep, self.now.unix) {
            eprintln!("dryserver: rollout: the coordinator's own update: {e}");
        }
    }

    /// What is wrong with the k3s file the servers load with the release,
    /// if anything: it has to be the one the signed release names. Root
    /// checks the release's signature itself; the file is the registry
    /// account's.
    fn served_k3s_problem(&self) -> Option<String> {
        let serial = self.r.serial;
        let rel = match self.served.envelope(serial).and_then(|env| release::open(self.n.verifier.as_ref(), &env, self.now.unix)) {
            Ok(r) if r.serial == serial => r,
            Ok(r) => return Some(format!("the coordinator's copy of it holds release {}", r.serial)),
            Err(e) => return Some(format!("the coordinator's copy of it cannot be read ({e})")),
        };
        let sha = self.served.open(Some(serial), K3S_FILE).and_then(|f| {
            let len = f.metadata()?.len();
            if len > MAX_K3S {
                bail!("it is {len} bytes, more than {MAX_K3S}");
            }
            sha_reader(f, MAX_K3S).ok_or_else(|| errf!("it cannot be read"))
        });
        match sha {
            Ok(sha) if sha == rel.k3s.sha256 => None,
            Ok(_) => Some(format!("the coordinator's copy of k3s {} is not the release's", rel.k3s.version)),
            Err(e) => Some(format!("the coordinator has no copy of k3s {} for it ({e})", rel.k3s.version)),
        }
    }

    /// A server's update is done when it runs the release, confirmed, and
    /// is healthy.
    fn updated(r: &Report, target: u64) -> bool {
        r.release >= target && !matches!(r.update.as_str(), "pending" | "fetching") && healthy(r, false).is_ok()
    }

    fn servers(&mut self) {
        self.tidy_lists();
        self.tidy_cordons();
        if !self.r.paused.is_empty() {
            return self.watch_paused();
        }
        if self.r.turn.is_some() {
            return self.turn();
        }
        if self.now.unix < self.r.canary_until {
            if !self.settling() {
                self.watch_canary();
            }
            return;
        }
        if self.settling() || self.hold_for_the_middle() || !self.in_window() {
            return;
        }
        self.next();
    }

    /// Servers that left are dropped from the rollout's lists: a machine
    /// that joins later may get the same host number. One that was passed
    /// over but runs the release now counts as done.
    fn tidy_lists(&mut self) {
        let (members, target) = (self.members, self.r.serial);
        let here = |h: &u32| members.iter().any(|m| m.host == *h);
        self.r.done.retain(here);
        self.r.deferred.retain(here);
        self.r.force.retain(here);
        self.r.again.retain(here);
        self.r.turns.retain(here);
        self.r.skipped.retain(|s| members.iter().any(|m| m.host == s.host && m.name == s.name));
        let on: Vec<u32> = self
            .r
            .skipped
            .iter()
            .filter(|s| members.iter().any(|m| m.host == s.host && m.report.as_ref().is_some_and(|r| r.release >= target)))
            .map(|s| s.host)
            .collect();
        self.r.skipped.retain(|s| !on.contains(&s.host));
        self.r.done.extend(on);
    }

    /// Nodes cordoned earlier that nothing holds any more (an uncordon
    /// that failed, a server that left). The node of a server in the middle
    /// of an update stays cordoned: it may still reboot.
    fn tidy_cordons(&mut self) {
        let middle = self.in_the_middle().map(|(_, name)| name);
        let keep: Vec<String> = self.r.turn.iter().map(|t| t.name.clone()).chain(Some(self.r.pause_name.clone())).chain(middle).collect();
        for name in self.r.cordoned.clone() {
            if !keep.contains(&name) {
                self.uncordon(&name);
            }
        }
    }

    /// Gives the next server its turn: cordons it and starts draining.
    fn next(&mut self) {
        let target = self.r.serial;
        let mut servers: Vec<&Member> = self
            .members
            .iter()
            .filter(|m| m.host != 1 && m.name != self.n.hostname)
            .filter(|m| !self.r.done.contains(&m.host) && !self.r.skipped.iter().any(|s| s.host == m.host))
            .collect();
        // The ones the admin resumed at first, the silent ones last.
        let deferred = |h: u32| self.r.deferred.iter().position(|d| *d == h).map_or(0, |i| i + 1);
        servers.sort_by_key(|m| (!self.r.again.contains(&m.host), deferred(m.host), m.host));
        let mut already = Vec::new();
        let mut pick = None;
        for m in servers {
            let Some(rep) = &m.report else { continue };
            if rep.release >= target {
                already.push(m.host);
                continue;
            }
            if rep.update == "held" || !self.online(m) {
                continue;
            }
            pick = Some((m.host, m.name.clone()));
            break;
        }
        self.r.again.retain(|h| !already.contains(h));
        self.r.done.extend(already);
        let Some((host, name)) = pick else { return };
        let had = self.r.turns.iter().filter(|h| **h == host).count();
        if had >= MAX_TURNS {
            self.r.stop(
                Pause::Timeout,
                host,
                &name,
                format!("{name} had its turn {had} times, and each ended without its update (its kill switch went on, or it went silent)"),
            );
            return;
        }
        self.start_turn(host, name);
    }

    /// Gives host its turn: cordons it and starts draining.
    fn start_turn(&mut self, host: u32, name: String) {
        let before = self.r.clone();
        let retry = if self.r.again.contains(&host) {
            self.r.retries += 1;
            self.r.retries
        } else {
            0
        };
        // The turn and the cordon are written down before kubectl runs: a
        // sync killed (or a brain switched off) right after the cordon would
        // otherwise not know of it, and the node could stay cordoned for
        // good once another server got the turn. Draining cordons it too,
        // so it is uncordoned in any case.
        if !self.r.cordoned.contains(&name) {
            self.r.cordoned.push(name.clone());
        }
        self.r.deferred.retain(|d| *d != host);
        self.r.turns.push(host);
        self.r.turn = Some(Turn { host, name: name.clone(), since: self.now.unix, ready: false, retry, cleared: false });
        if let Err(e) = self.machine().save_rollout(&self.r) {
            eprintln!("dryserver: rollout: cannot save its state, so {name} gets no turn yet: {e}");
            self.r = before;
            return;
        }
        // The turn begins whatever the cordon does: a server that is no node
        // (its agent never joined, or the cluster dropped it) has nothing to
        // drain, and any other failure counts against DRAIN_LIMIT like a
        // drain that does not finish. Trying the same server again at every
        // sync without a turn would stall the rollout for ever.
        match self.kubectl(&["cordon"], &name) {
            Ok(()) => {}
            Err(e) if e.is_not_found() => {
                eprintln!("dryserver: rollout: {e}: {name} updates without being drained");
                self.r.warn(format!("{name} is not a node of the cluster: it updates without being drained"));
                self.r.cordoned.retain(|c| *c != name);
                if let Some(t) = &mut self.r.turn {
                    t.ready = true;
                }
            }
            Err(e) => self.r.warn(format!("cannot cordon {name} ({e}); trying again")),
        }
        self.turn();
    }

    fn turn(&mut self) {
        let Some(mut t) = self.r.turn.take() else { return };
        if t.host == 1 || t.name == self.n.hostname {
            self.r.warn("the coordinator held a server's turn; it was taken back".into());
            return;
        }
        let target = self.r.serial;
        let now = self.now.unix;
        let Some(m) = self.member(t.host).filter(|m| m.name == t.name).cloned() else {
            self.r.cordoned.retain(|c| *c != t.name);
            self.r.warn(format!("{} left the swarm during its turn", t.name));
            return;
        };
        if now < t.since {
            // The clock went back: the timeout counts from now.
            t.since = now;
        }
        if !t.ready {
            match self.kubectl(&["drain", "--ignore-daemonsets", "--delete-emptydir-data", DRAIN_TIMEOUT], &t.name.clone()) {
                Ok(()) => t.ready = true,
                Err(e) if e.is_not_found() => {
                    eprintln!("dryserver: rollout: {e}: {} updates without being drained", t.name);
                    self.r.warn(format!("{} is not a node of the cluster any more: it updates without being drained", t.name));
                    self.r.cordoned.retain(|c| *c != t.name);
                    t.ready = true;
                }
                Err(e) if self.r.force.contains(&t.host) => {
                    self.r.warn(format!("draining {} failed ({e}); it updates anyway, as you resumed", t.name));
                    t.ready = true;
                }
                Err(e) if now - t.since >= DRAIN_LIMIT => {
                    let why = format!(
                        "draining {} did not finish in {} ({e}): a PodDisruptionBudget may allow no eviction",
                        t.name,
                        report::short_age(DRAIN_LIMIT as u64)
                    );
                    if self.r.urgent {
                        self.r.warn(format!("{why}; it updates anyway, the release is urgent"));
                        t.ready = true;
                    } else {
                        self.uncordon(&t.name);
                        self.r.stop(Pause::Drain, t.host, &t.name, why);
                        return;
                    }
                }
                Err(_) => {}
            }
            self.r.turn = Some(t);
            return;
        }
        let seen = m.last_seen.0.timestamp() >= t.since;
        let canary = if self.r.canary == 0 { " (the canary)" } else { "" };
        if let Some(rep) = m.report.as_ref().filter(|_| seen) {
            let failed = rep.update_failed() && rep.update_serial == target;
            if t.retry != 0 && !t.cleared && !failed {
                // It heard of the resume: a failure from now on is new.
                t.cleared = true;
            }
            if rep.update == "held" {
                // Its kill switch went on: it changes nothing now. Its turn
                // goes to the next one; it updates once the switch is off.
                self.uncordon(&t.name);
                self.r.deferred.retain(|d| *d != t.host);
                self.r.deferred.push(t.host);
                self.r.warn(format!("{}'s kill switch went on during its turn; it updates once it is lifted", t.name));
                return;
            }
            if failed && (t.retry == 0 || t.cleared) {
                let note = if rep.update_note.is_empty() { String::new() } else { format!(": {}", rep.update_note) };
                let again = if t.retry != 0 { " again" } else { "" };
                self.r.stop(Pause::Failed, t.host, &t.name, format!("{}{canary}: update {}{again}{note}", t.name, rep.update));
                return;
            }
            if Self::updated(rep, target) {
                self.uncordon(&t.name);
                self.r.again.retain(|h| *h != t.host);
                self.r.done.push(t.host);
                if self.r.canary == 0 {
                    self.r.canary = t.host;
                    self.r.canary_until = now + if self.r.urgent { SOAK_URGENT } else { SOAK };
                }
                return;
            }
        }
        if now - t.since > TURN_TIMEOUT || (!seen && now - t.since > SILENT_TURN) {
            let late = report::short_age(TURN_TIMEOUT as u64);
            if !seen {
                // Never heard from since its turn began: offline. Its turn
                // goes to the next one; it updates when it is back.
                self.uncordon(&t.name);
                self.r.deferred.retain(|d| *d != t.host);
                self.r.deferred.push(t.host);
                self.r.warn(format!("{} went silent when its turn came; it updates when it is back", t.name));
            } else {
                let (rel, state) = m.report.as_ref().map(|r| (r.release, r.update.clone())).unwrap_or_default();
                let state = if state.is_empty() { "nothing".to_string() } else { state };
                self.r.stop(
                    Pause::Timeout,
                    t.host,
                    &t.name,
                    format!("{}{canary} did not finish its update in {late}: it runs release {rel}, its update says {state}", t.name),
                );
            }
            return;
        }
        self.r.turn = Some(t);
    }

    /// While stopped at a server: it stays cordoned while it is up and not
    /// well; it is uncordoned once it runs its old release well again. One
    /// that finishes after all lets the rollout go on by itself.
    fn watch_paused(&mut self) {
        let (host, name, target) = (self.r.pause_host, self.r.pause_name.clone(), self.r.serial);
        let Some(m) = self.member(host).filter(|m| m.name == name).cloned() else {
            if host != 0 {
                // It left the swarm: nothing to wait for any more.
                self.r.cordoned.retain(|c| *c != name);
                self.r.warn(format!("{name} left the swarm; the rollout goes on"));
                self.r.unpause();
            }
            return;
        };
        if self.r.pause == Pause::Timeout && self.r.wait_for == host && self.in_the_middle().is_none_or(|(h, _)| h != host) {
            // Stopped at one in the middle of an update outside a turn of
            // its own: done now, so the rollout goes on (its node is
            // uncordoned with the wait).
            self.r.warn(format!("{name} finished the update it was in; the rollout goes on"));
            self.r.unpause();
            self.hold_for_the_middle();
            return;
        }
        let Some(rep) = m.report.as_ref().filter(|_| self.online(&m)) else { return };
        let cordoned = self.r.cordoned.contains(&name);
        if matches!(self.r.pause, Pause::Timeout) && Self::updated(rep, target) {
            if cordoned {
                self.uncordon(&name);
            }
            self.r.again.retain(|h| *h != host);
            self.r.done.push(host);
            self.r.warn(format!("{name} finished its update after all; the rollout goes on"));
            self.r.unpause();
            return;
        }
        if cordoned && rep.release < target && rep.update != "pending" && healthy(rep, false).is_ok() {
            self.uncordon(&name);
        }
    }

    fn watch_canary(&mut self) {
        let host = self.r.canary;
        let Some(m) = self.member(host).cloned() else { return };
        let why = match &m.report {
            _ if !self.online(&m) => {
                Some(format!("it is silent for {}", report::short_age((self.now.unix - m.last_seen.0.timestamp()).max(0) as u64)))
            }
            None => Some("it sends no report".to_string()),
            Some(r) if r.update_failed() => Some(format!("update {}", r.update)),
            Some(r) if r.release < self.r.serial => Some(format!("it runs release {} again", r.release)),
            Some(r) => healthy(r, false).err(),
        };
        if let Some(why) = why {
            self.r.stop(Pause::Canary, host, &m.name, format!("the canary {} is not well after its update: {why}", m.name));
        }
    }
}

// ---- for people ----

/// "Release 1795171200 (urgent), made 2026-11-21 12:00 UTC: fixes X". The
/// notes are signed and printable ASCII (release::check_notes).
pub fn release_line(r: &Release) -> String {
    let made = chrono::DateTime::from_timestamp(r.created, 0).map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string()).unwrap_or_default();
    let mut s = format!("Release {}", r.serial);
    if r.urgent {
        s += " (urgent)";
    }
    if r.rollback {
        s += " (rollback)";
    }
    s += &format!(", made {made}");
    if !r.notes.is_empty() {
        s += &format!(": {}", shown(&r.notes, release::MAX_NOTES));
    }
    s
}

/// What the rollout does, one short sentence per item; true marks what
/// needs the admin. members are the coordinator's, checked by the desktop.
pub fn lines(r: &Rollout, members: &[Member], now: i64) -> Vec<(String, bool)> {
    let mut out: Vec<(String, bool)> = Vec::new();
    if !r.refused.is_empty() {
        out.push((shown(&r.refused, 300), true));
    }
    if r.serial == 0 {
        if out.is_empty() {
            out.push(("No release published yet: ./dryserver release publish".into(), false));
        }
        return out;
    }
    let name = |host: u32| members.iter().find(|m| m.host == host).map(|m| m.name.clone()).unwrap_or_else(|| format!("host {host}"));
    let servers: Vec<&Member> = members.iter().filter(|m| m.host != 1).collect();
    let on = servers.iter().filter(|m| r.done.contains(&m.host)).count();
    let window = window_text(WINDOW);
    match r.phase {
        Phase::None => {}
        Phase::Waiting => out.push((format!("Waiting for the update window {window} on the coordinator's clock."), false)),
        Phase::Brain if !r.paused.is_empty() => {
            let who = name(r.pause_host);
            out.push((format!("PAUSED: {}.", shown(&r.paused, 300)), true));
            out.push((format!("Look at it, then: ./dryserver release resume (the coordinator waits once more for {who})"), true));
            out.push((format!("Or let the coordinator update itself without waiting for {who}: ./dryserver release resume -skip"), true));
        }
        Phase::Brain if r.wait_for != 0 => {
            out.push((format!("The coordinator updates itself first, once {} finished the update it is in.", name(r.wait_for)), false))
        }
        Phase::Brain => out.push(("The coordinator updates itself first.".into(), false)),
        Phase::Failed => {
            out.push((format!("FAILED: {}.", shown(&r.paused, 300)), true));
            out.push(("Publish a fixed release, or try again: ./dryserver release resume".into(), true));
        }
        Phase::Servers => {
            if !r.paused.is_empty() {
                out.push((format!("PAUSED: {}.", shown(&r.paused, 300)), true));
                let who = name(r.pause_host);
                let what = match r.pause {
                    Pause::Drain => format!("updates {who} without draining"),
                    Pause::Canary => "goes on".into(),
                    _ => format!("{who} tries again"),
                };
                out.push((format!("Look at it, then: ./dryserver release resume ({what})"), true));
                if r.pause != Pause::Canary {
                    out.push((format!("Or pass {who} over for this release: ./dryserver release resume -skip"), true));
                }
            } else if let Some(t) = &r.turn {
                let age = report::short_age((now - t.since).max(0) as u64);
                let canary = if r.canary == 0 { ", the canary" } else { "" };
                let who = name(t.host);
                // Its report may say it is done before the brain read it.
                let confirmed = members
                    .iter()
                    .find(|m| m.host == t.host)
                    .and_then(|m| m.report.as_ref())
                    .is_some_and(|rep| rep.release >= r.serial && rep.update.is_empty());
                if t.ready && confirmed {
                    out.push((format!("{who} confirmed release {}; the coordinator takes note at its next sync.", r.serial), false));
                } else if t.ready {
                    out.push((format!("{who} updates (its turn for {age}{canary})."), false));
                } else {
                    out.push((format!("Draining {who} for its update ({age}{canary})."), false));
                }
            } else if now < r.canary_until {
                out.push((
                    format!("Watching the canary {} for {} more.", name(r.canary), report::short_age((r.canary_until - now) as u64)),
                    false,
                ));
            } else if on < servers.len() && !r.urgent {
                out.push((format!("Next server in the update window {window} on the coordinator's clock."), false));
            }
            out.push((format!("{on} of {} servers on this release.", servers.len()), false));
        }
    }
    if r.phase == Phase::Servers {
        let mut waiting = Vec::new();
        let mut held = Vec::new();
        let mut old = Vec::new();
        let mut again = Vec::new();
        for m in &servers {
            if r.done.contains(&m.host) || r.skipped.iter().any(|s| s.host == m.host) || r.turn.as_ref().is_some_and(|t| t.host == m.host) {
                continue;
            }
            if r.again.contains(&m.host) && r.pause_host != m.host {
                again.push(m.name.clone());
            }
            match &m.report {
                None => old.push(m.name.clone()),
                Some(rep) if rep.update == "held" => held.push(m.name.clone()),
                Some(_) if m.last_seen.is_zero() || now - m.last_seen.0.timestamp() > OFFLINE => waiting.push(m.name.clone()),
                Some(_) => {}
            }
        }
        if !again.is_empty() {
            out.push((format!("Tries again at its next turn, as you resumed: {}.", again.join(", ")), false));
        }
        if !waiting.is_empty() {
            out.push((
                format!("Silent, updates when back: {} (offline, or its kill switch cut the coordinator off).", waiting.join(", ")),
                false,
            ));
        }
        if !held.is_empty() {
            out.push((format!("Held, kill switch on: {}.", held.join(", ")), true));
        }
        if !old.is_empty() {
            out.push((format!("Cannot update, send no report (older dryserver): {}.", old.join(", ")), true));
        }
    }
    for s in &r.skipped {
        out.push((format!("Passed over: {}: {}", name(s.host), shown(&s.why, 200)), true));
    }
    for w in &r.warnings {
        out.push((format!("! {}", shown(w, 300)), true));
    }
    out
}

/// What a member's report says about its release, for its line on the
/// admin's screen; true: it needs a look.
pub fn member_release(r: &Report, target: u64) -> Option<(String, bool)> {
    match r.update.as_str() {
        "pending" => return Some(("updating".into(), false)),
        "fetching" => return Some(("loading update".into(), false)),
        "held" => return Some(("update held".into(), true)),
        s if r.update_failed() && (target == 0 || r.update_serial >= target) => return Some((format!("update {s}"), true)),
        _ => {}
    }
    if r.release == 0 && target == 0 {
        return None;
    }
    if r.release >= target {
        Some((format!("release {}", r.release), false))
    } else if r.release == 0 {
        Some(("no release yet".into(), false))
    } else {
        Some((format!("release {} (old)", r.release), false))
    }
}

// ---- the desktop's side ----

/// Refuses a binary that would not run on the servers: anything but a
/// static x86-64 Linux executable. A build for the desktop itself (`cargo
/// build`, linked against its C library) is caught here instead of on the
/// brain.
pub fn check_static(path: &Path) -> Result<()> {
    let mut head = Vec::new();
    open_regular(path)?.take(64 << 10).read_to_end(&mut head).map_err(|e| Error::from(e).wrap(format!("read {}", path.display())))?;
    // Offsets come from the file: no arithmetic on them may overflow.
    let at = |o: usize, n: usize| o.checked_add(n).and_then(|end| head.get(o..end));
    let u16_at = |o: usize| at(o, 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32_at = |o: usize| at(o, 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    let u64_at = |o: usize| at(o, 8).map(|b| u64::from_le_bytes(b.try_into().unwrap_or([0; 8])));
    let not = |why: &str| errf!("{} is not a dryserver for the servers: {why}", path.display());
    if head.get(0..4) != Some(b"\x7fELF") {
        return Err(not("not a Linux program"));
    }
    if head.get(4) != Some(&2) || head.get(5) != Some(&1) || u16_at(18) != Some(62) {
        return Err(not("not built for 64-bit x86"));
    }
    if !matches!(u16_at(16), Some(2 | 3)) {
        return Err(not("not a program"));
    }
    let (Some(phoff), Some(size), Some(count)) = (u64_at(32), u16_at(54), u16_at(56)) else {
        return Err(not("its header is cut short"));
    };
    for i in 0..u64::from(count) {
        let at = phoff.saturating_add(i.saturating_mul(u64::from(size)));
        let Some(kind) = usize::try_from(at).ok().and_then(u32_at) else {
            return Err(not("its program headers are not where it says"));
        };
        // PT_INTERP: it needs a dynamic loader and this desktop's libraries.
        if kind == 3 {
            return Err(not("it is linked against this computer's libraries; build the static one with make"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
