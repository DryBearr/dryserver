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
//! refuses or does not finish in time; the admin looks, then resumes
//! (`./dryserver release resume`) or publishes a fixed release. A new
//! release replaces a running rollout: machines go straight to the newest.
//!
//! Everything a machine gets from another one is checked here as if it
//! came from an attacker: sizes are capped before anything is read, the
//! signature and the checksums decide, and a server can only speak for
//! itself. A hacked server can fail or stall only its own turn, and a
//! stalled turn ends after TURN_TIMEOUT; but the rollout then stops there
//! until the admin resumes, once per release per hacked server.

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
use crate::mesh;
use crate::node::Node;
use crate::registry::{self, Member, Store};
use crate::release::{self, Place, Release};
use crate::report::{self, Report};
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
/// passed over until it is back).
pub const TURN_TIMEOUT: i64 = 20 * 60;
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
/// How long one sync spends loading a release; the rest follows at the
/// next sync.
const FETCH_BUDGET: Duration = Duration::from_secs(25);
/// One piece; a piece cut off by the sync's own deadline is loaded again.
const CHUNK_TIMEOUT: Duration = Duration::from_secs(60);
/// Installing and confirming are not cut off by the sync's deadline: a
/// half-run installer is worse than a late sync.
const APPLY_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// How many syncs in a row a problem that may pass (the update commands
/// do not answer, the disk is full for now, the brain's k3s is not known
/// yet) is tried again before the release counts as failed here: well
/// within TURN_TIMEOUT, a sync a minute.
pub const MAX_TRIES: u32 = 10;
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
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Last {
    #[serde(deserialize_with = "report::lenient")]
    pub serial: u64,
    /// "applied", "confirmed", "reverted", ...
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
/// - apply --release FILE --binary FILE --brain-k3s VERSION: copies the
///   binary into its own staging, checks the release, arms the revert
///   timer and installs it; exit 0: installed, pending confirmation.
/// - confirm --serial N: keeps it, after its own selfcheck.
/// - status --json: UpdateStatus.
///
/// The k3s binary of a release is loaded and kept with it (STORE), for
/// when apply installs k3s too; it takes no k3s file yet.
pub struct Update<'a> {
    pub run: &'a dyn crate::runner::Runner,
    pub bin: &'a str,
}

impl Update<'_> {
    pub fn apply(&self, ctx: &Ctx, release: &Path, binary: &Path, brain_k3s: &str) -> Result<()> {
        let (r, b) = (release.display().to_string(), binary.display().to_string());
        let args = ["update", "apply", "--release", &r, "--binary", &b, "--brain-k3s", brain_k3s];
        self.run.ok(ctx, &Cmd::new(self.bin, &args))
    }

    pub fn confirm(&self, ctx: &Ctx, serial: u64) -> Result<()> {
        self.run.ok(ctx, &Cmd::new(self.bin, &["update", "confirm", "--serial", &serial.to_string()]))
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
    let f = open_regular(path)?;
    let mut s = String::new();
    f.take(max + 1).read_to_string(&mut s).map_err(|e| Error::from(e).wrap(format!("read {}", path.display())))?;
    if s.len() as u64 > max {
        bail!("{} is larger than {max} bytes", path.display());
    }
    Ok(s)
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
    let f = File::open(fsx::under(root, "/proc/self/exe")).ok()?;
    let mut h = Sha256::new();
    let mut r = f.take(release::MAX_BINARY);
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
}

impl Served {
    pub fn new(dir: impl Into<PathBuf>, k3s: impl Into<PathBuf>) -> Served {
        Served { dir: dir.into(), k3s: k3s.into(), free: free_bytes }
    }

    /// Beside the registry file of store.
    pub fn beside(store: &Store, k3s: impl Into<PathBuf>) -> Served {
        Served::new(fsx::dir(&store.path).join(SERVED_DIR), k3s)
    }

    fn release_dir(&self, serial: u64) -> PathBuf {
        self.dir.join(serial.to_string())
    }

    /// The serial of the newest upload.
    pub fn current(&self) -> Option<u64> {
        let s = read_small(&self.dir.join("current"), 32).ok()?;
        let s = s.trim();
        if s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        s.parse().ok().filter(|n| *n > 0)
    }

    pub fn envelope(&self, serial: u64) -> Result<Envelope> {
        let text = read_small(&self.release_dir(serial).join(RELEASE_FILE), MAX_ENVELOPE)?;
        serde_json::from_str(&text).map_err(|e| Error::from(e).wrap(format!("release {serial} on the coordinator")))
    }

    pub fn path(&self, serial: u64, name: &str) -> PathBuf {
        self.release_dir(serial).join(name)
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
        registry::extend_deadline(registry::UPLOAD_DEADLINE);
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
        let path = self.path(serial, name);
        let mut f = open_regular(&path).map_err(|e| e.wrap(format!("release {serial} is not on the coordinator")))?;
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
        Ok(Offered { release: self.envelope(serial)?, k3s_size: file_len(&self.path(serial, K3S_FILE)) })
    }
}

// ---- where a machine loads a release from ----

/// Where a machine loads a release from: a server from the brain's
/// registry over SSH, the brain from its registry's directory.
pub trait Source {
    fn offered(&self, ctx: &Ctx, serial: u64) -> Result<Offered>;
    /// Writes exactly bytes [offset, offset+len) of the file to dst, or
    /// fails.
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

    fn chunk(&self, _: &Ctx, serial: u64, name: &str, offset: u64, len: u64, dst: &Path) -> Result<()> {
        let mut f = open_regular(&self.0.path(serial, name))?;
        f.seek(SeekFrom::Start(offset))?;
        let mut out = File::create(dst).map_err(|e| Error::from(e).wrap(format!("open {}", dst.display())))?;
        let n = io::copy(&mut f.take(len), &mut out)?;
        if n != len {
            bail!("{name} of release {serial} ended after {} bytes", offset + n);
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
}

/// What the registry tells member host in its sync reply. The turn holds
/// only while the rollout runs and the server is drained.
pub fn offer(s: &registry::State, host: u32) -> Offer {
    let r = &s.rollout;
    let turn = host != 1 && r.paused.is_empty() && r.phase == Phase::Servers && r.turn.as_ref().is_some_and(|t| t.host == host && t.ready);
    let brain_k3s = s.members.iter().find(|m| m.host == 1).and_then(|m| m.report.as_ref()).map(|r| r.k3s.clone()).unwrap_or_default();
    Offer { serial: r.serial, turn, brain_k3s }
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
    /// A release the admin said to try again although it went back before.
    pub retry: u64,
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
    /// The release did not pass this machine's checks.
    Refused(String),
    /// Installing it did not work.
    Failed(String),
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
        let mut l = self.load();
        if l.pending != 0 {
            return self.settle(ctx, &mut l, rep, now);
        }
        if !offer.turn || offer.serial == 0 || self.installed_serial() >= offer.serial || l.failed == offer.serial {
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
            Err(Stop::Later(why)) => {
                if l.tries_serial != offer.serial {
                    (l.tries_serial, l.tries) = (offer.serial, 0);
                }
                l.tries += 1;
                if l.tries < MAX_TRIES {
                    l.note = report::note(&why);
                    self.save(&l)?;
                    return Err(errf!("release {}: {why} (tried {} of {MAX_TRIES} times, again at the next sync)", offer.serial, l.tries));
                }
                ("failed", format!("{why} ({MAX_TRIES} syncs in a row)"))
            }
            Err(Stop::Refused(why)) => ("refused", why),
            Err(Stop::Failed(why)) => ("failed", why),
            Err(Stop::Reverted(why)) => ("reverted", why),
        };
        l.failed = offer.serial;
        l.outcome = outcome.into();
        l.why = report::note(&why);
        l.note.clear();
        self.save(&l)?;
        Err(errf!("release {} {outcome}: {why}", offer.serial))
    }

    /// What the update commands say before anything is loaded: true, go
    /// on. A release that went back before is not installed again (the
    /// commands do not refuse it themselves); one that is already
    /// installed or pending is taken over.
    fn ready(&self, ctx: &Ctx, offer: &Offer, now: i64, l: &mut Local) -> std::result::Result<bool, Stop> {
        // The sync's own time running out ends up here too.
        let st = self.update().status(ctx).map_err(|e| Stop::Later(format!("cannot ask how its updates stand: {e}")))?;
        if st.installed.serial >= offer.serial {
            l.installed = st.installed.serial;
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
        let (r, verdict) =
            release::check(self.n.verifier.as_ref(), &env, installed.as_ref(), place, now).map_err(|e| Stop::Refused(e.to_string()))?;
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
            let need = r.dryserver.size + if meta.need_k3s { meta.k3s_size } else { 0 };
            // Room may be made (logs rotate, an old image goes).
            room(self.free, &self.dir(), need, "this machine").map_err(|e| Stop::Later(e.to_string()))?;
            fsx::write_file(inc.join(META_FILE), serde_json::to_string(&meta).map_err(|e| again(e.into()))?, 0o600).map_err(again)?;
            write_atomic(&inc.join(RELEASE_FILE), &(serde_json::to_string(&env).map_err(|e| again(e.into()))? + "\n")).map_err(again)?;
        }
        let until = start + FETCH_BUDGET;
        self.fetch(ctx, src, r.serial, DRYSERVER_FILE, r.dryserver.size, &r.dryserver.sha256, until)?;
        if meta.need_k3s {
            if meta.k3s_size == 0 || meta.k3s_size > MAX_K3S {
                return Err(Stop::Refused(format!("the coordinator says its k3s is {} bytes", meta.k3s_size)));
            }
            self.fetch(ctx, src, r.serial, K3S_FILE, meta.k3s_size, &r.k3s.sha256, until)?;
        }
        // Everything is here and checked: install it. The update commands
        // check the release once more themselves.
        let actx = Ctx::new().with_timeout(APPLY_TIMEOUT);
        self.update()
            .apply(&actx, &inc.join(RELEASE_FILE), &inc.join(DRYSERVER_FILE), &offer.brain_k3s)
            .map_err(|e| Stop::Failed(e.to_string()))?;
        *l = Local { pending: r.serial, applied: now, installed: l.installed, ..Local::default() };
        self.save(l).map_err(again)?;
        Ok(())
    }

    /// Loads one file of the release in pieces, going on from what earlier
    /// syncs loaded, and checks it once it is whole.
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
        while have < size {
            if Instant::now() >= until {
                return Err(Stop::Again(errf!(
                    "loading {name}: {} of {} so far, more at the next sync",
                    report::size(have),
                    report::size(size)
                )));
            }
            let len = CHUNK.min(size - have);
            let piece = inc.join(format!("{name}.piece"));
            let got = src.chunk(&ctx.with_timeout(CHUNK_TIMEOUT), serial, name, have, len, &piece).and_then(|_| {
                let n = file_len(&piece);
                if n != len { Err(errf!("the coordinator sent {n} bytes of {name}, not {len}")) } else { Ok(()) }
            });
            if let Err(e) = got {
                let _ = std::fs::remove_file(&piece);
                return Err(Stop::Again(e.wrap(format!("load {name}"))));
            }
            // Only whole pieces join the part: a cut-off one is loaded again.
            let appended = (|| -> Result<()> {
                let mut out = OpenOptions::new().create(true).append(true).mode(0o600).open(&part)?;
                io::copy(&mut File::open(&piece)?, &mut out)?;
                Ok(())
            })();
            let _ = std::fs::remove_file(&piece);
            appended.map_err(|e| Stop::Again(e.wrap(format!("store {name}"))))?;
            have = file_len(&part);
        }
        if let Err(e) = release::verify_file(&part, sha256, size) {
            let _ = std::fs::remove_file(&part);
            return Err(Stop::Refused(format!("{name} from the coordinator does not match the release: {e}")));
        }
        fsx::rename(&part, &done).map_err(Stop::Again)
    }

    /// An installed release waiting for its confirmation.
    fn settle(&self, ctx: &Ctx, l: &mut Local, rep: &Report, now: i64) -> Result<()> {
        let up = self.update();
        let st = up.status(ctx)?;
        l.installed = st.installed.serial;
        let pending = st.pending_serial();
        if pending != 0 && pending != l.pending {
            // Another release waits: its own deadline settles it.
            return self.save(l);
        }
        if pending == l.pending {
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
            up.confirm(&Ctx::new().with_timeout(APPLY_TIMEOUT), l.pending)?;
            l.installed = l.installed.max(l.pending);
            return self.promote(l);
        }
        if st.installed.serial >= l.pending {
            // Confirmed meanwhile.
            return self.promote(l);
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
            l.failed = 0;
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

/// Why the rollout stopped, which decides what resuming does.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Pause {
    /// The server could not be drained: resuming updates it without.
    Drain,
    /// Its update failed, reverted or was refused: resuming passes it over.
    Failed,
    /// It did not finish in TURN_TIMEOUT: resuming passes it over.
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
    /// the brain carried out.
    pub resume_asked: u64,
    pub resume_done: u64,
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
pub fn brain_tick(ctx: &Ctx, n: &Node, store: &Store, served: &Served, rep: &Report, now: Now) {
    brain_tick_with(ctx, n, store, served, rep, now, free_bytes);
}

fn brain_tick_with(ctx: &Ctx, n: &Node, store: &Store, served: &Served, rep: &Report, now: Now, free: fn(&Path) -> Option<u64>) {
    let Ok(s) = store.read() else { return };
    let m = Machine { n, brain: true, free };
    let before = m.own_rollout();
    // The registry account writes the member list too: only members that
    // pass the checks a server makes take part (the sync logged the rest).
    let (members, _) = registry::check_members(s.members.clone(), |h| !mesh::ip(&n.cfg.wg_subnet, h).is_empty());
    let mut b = Brain { ctx, n, served, rep, now, members: &members, r: before.clone(), free, nodes: None };
    b.r.resume_asked = s.rollout.resume_asked;
    b.take_upload();
    if b.r.serial != 0 {
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
    if (Rollout { resume_asked: s.rollout.resume_asked, ..r.clone() }) != s.rollout {
        let res = store.update(|s| {
            // A resume asked while this tick ran stays asked.
            s.rollout = Rollout { resume_asked: s.rollout.resume_asked, ..r.clone() };
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
        let checked = self
            .served
            .envelope(serial)
            .and_then(|env| release::check(self.n.verifier.as_ref(), &env, installed.as_ref(), Place::Brain, self.now.unix));
        match checked {
            Ok((rel, verdict)) if rel.serial == serial => {
                let old = std::mem::take(&mut self.r);
                let mut fresh = Rollout::start(&rel, self.now.unix, verdict.stale);
                fresh.resume_asked = old.resume_asked;
                fresh.resume_done = old.resume_asked;
                if old.serial != 0 && (old.phase == Phase::Brain || old.turn.is_some()) {
                    fresh.warn(format!("release {} replaced release {} while it rolled out", rel.serial, old.serial));
                }
                self.r = fresh;
                // The old rollout's cordons go; the new one starts clean.
                for name in old.cordoned {
                    self.uncordon(&name);
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

    /// resume_asked is the registry's count, which anyone who can write
    /// the registry can change: a count that grew is one resume (what the
    /// admin's resume does anyway), one that went back is none.
    fn resume(&mut self) {
        if self.r.resume_asked <= self.r.resume_done {
            self.r.resume_done = self.r.resume_asked;
            return;
        }
        self.r.resume_done = self.r.resume_asked;
        if self.r.phase == Phase::Failed {
            self.machine().forget_failure(self.r.serial);
            self.r.phase = Phase::Brain;
            self.r.unpause();
            self.r.warn("resumed: the coordinator tries its own update again".into());
            return;
        }
        let (host, name) = (self.r.pause_host, self.r.pause_name.clone());
        match self.r.pause {
            Pause::None => {}
            Pause::Drain => {
                if !self.r.force.contains(&host) {
                    self.r.force.push(host);
                }
                self.r.warn(format!("resumed: {name} updates without being drained"));
                self.r.unpause();
            }
            Pause::Canary => {
                self.r.canary_until = 0;
                self.r.warn(format!("resumed: the rollout goes on after the canary {name}"));
                self.r.unpause();
            }
            Pause::Failed | Pause::Timeout => {
                let why = self.r.paused.clone();
                self.r.skipped.retain(|s| s.host != host);
                self.r.skipped.push(Skip { host, name: name.clone(), why });
                self.uncordon(&name);
                self.r.warn(format!("resumed: {name} is passed over"));
                self.r.unpause();
            }
        }
    }

    fn advance(&mut self) {
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
        let m = self.machine();
        // The brain's own k3s is the control plane's.
        let offer = Offer { serial: self.r.serial, turn: true, brain_k3s: self.rep.k3s.clone() };
        if let Err(e) = m.step(self.ctx, &LocalSource(self.served), &offer, self.rep, self.now.unix) {
            eprintln!("dryserver: rollout: the coordinator's own update: {e}");
        }
        if m.installed_serial() >= self.r.serial {
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

    /// A server's update is done when it runs the release, confirmed, and
    /// is healthy.
    fn updated(r: &Report, target: u64) -> bool {
        r.release >= target && !matches!(r.update.as_str(), "pending" | "fetching") && healthy(r, false).is_ok()
    }

    fn servers(&mut self) {
        self.tidy_cordons();
        if !self.r.paused.is_empty() {
            return self.watch_paused();
        }
        if self.r.turn.is_some() {
            return self.turn();
        }
        if self.now.unix < self.r.canary_until {
            return self.watch_canary();
        }
        if !self.in_window() {
            return;
        }
        self.next();
    }

    /// Nodes cordoned earlier that nothing holds any more (an uncordon
    /// that failed, a server that left).
    fn tidy_cordons(&mut self) {
        let keep: Vec<String> = self.r.turn.iter().map(|t| t.name.clone()).chain(Some(self.r.pause_name.clone())).collect();
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
        let deferred = |h: u32| self.r.deferred.iter().position(|d| *d == h).map_or(0, |i| i + 1);
        servers.sort_by_key(|m| (deferred(m.host), m.host));
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
        self.r.done.extend(already);
        let Some((host, name)) = pick else { return };
        // The turn begins whatever the cordon does: a server that is no node
        // (its agent never joined, or the cluster dropped it) has nothing to
        // drain, and any other failure counts against DRAIN_LIMIT like a
        // drain that does not finish. Trying the same server again at every
        // sync without a turn would stall the rollout for ever.
        let mut ready = false;
        match self.kubectl(&["cordon"], &name) {
            Ok(()) => {}
            Err(e) if e.is_not_found() => {
                eprintln!("dryserver: rollout: {e}: {name} updates without being drained");
                self.r.warn(format!("{name} is not a node of the cluster: it updates without being drained"));
                ready = true;
            }
            Err(e) => self.r.warn(format!("cannot cordon {name} ({e}); trying again")),
        }
        if !ready && !self.r.cordoned.contains(&name) {
            // Draining cordons it too, so it is uncordoned in any case.
            self.r.cordoned.push(name.clone());
        }
        self.r.deferred.retain(|d| *d != host);
        self.r.turn = Some(Turn { host, name, since: self.now.unix, ready });
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
            if rep.update == "held" {
                // Its kill switch went on: it changes nothing now. Its turn
                // goes to the next one; it updates once the switch is off.
                self.uncordon(&t.name);
                self.r.deferred.retain(|d| *d != t.host);
                self.r.deferred.push(t.host);
                self.r.warn(format!("{}'s kill switch went on during its turn; it updates once it is lifted", t.name));
                return;
            }
            if rep.update_failed() && rep.update_serial == target {
                let note = if rep.update_note.is_empty() { String::new() } else { format!(": {}", rep.update_note) };
                self.r.stop(Pause::Failed, t.host, &t.name, format!("{}{canary}: update {}{note}", t.name, rep.update));
                return;
            }
            if Self::updated(rep, target) {
                self.uncordon(&t.name);
                self.r.done.push(t.host);
                if self.r.canary == 0 {
                    self.r.canary = t.host;
                    self.r.canary_until = now + if self.r.urgent { SOAK_URGENT } else { SOAK };
                }
                return;
            }
        }
        if now - t.since > TURN_TIMEOUT {
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
                self.r.cordoned.retain(|c| *c != name);
            }
            return;
        };
        let Some(rep) = m.report.as_ref().filter(|_| self.online(&m)) else { return };
        let cordoned = self.r.cordoned.contains(&name);
        if matches!(self.r.pause, Pause::Timeout) && Self::updated(rep, target) {
            if cordoned {
                self.uncordon(&name);
            }
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

/// Text from the coordinator made safe to show: printable ASCII, cut short.
fn shown(s: &str, max: usize) -> String {
    s.chars().map(|c| if (' '..='~').contains(&c) { c } else { '?' }).take(max).collect()
}

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
        Phase::Brain => out.push(("The coordinator updates itself first.".into(), false)),
        Phase::Failed => {
            out.push((format!("FAILED: {}.", shown(&r.paused, 300)), true));
            out.push(("Publish a fixed release, or try again: ./dryserver release resume".into(), true));
        }
        Phase::Servers => {
            if !r.paused.is_empty() {
                out.push((format!("PAUSED: {}.", shown(&r.paused, 300)), true));
                let what = match r.pause {
                    Pause::Drain => "updates it without draining",
                    Pause::Canary => "goes on",
                    _ => "passes it over",
                };
                out.push((format!("Look at it, then: ./dryserver release resume ({what})"), true));
            } else if let Some(t) = &r.turn {
                let age = report::short_age((now - t.since).max(0) as u64);
                let canary = if r.canary == 0 { ", the canary" } else { "" };
                let who = name(t.host);
                if t.ready {
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
        for m in &servers {
            if r.done.contains(&m.host) || r.skipped.iter().any(|s| s.host == m.host) || r.turn.as_ref().is_some_and(|t| t.host == m.host) {
                continue;
            }
            match &m.report {
                None => old.push(m.name.clone()),
                Some(rep) if rep.update == "held" => held.push(m.name.clone()),
                Some(_) if m.last_seen.is_zero() || now - m.last_seen.0.timestamp() > OFFLINE => waiting.push(m.name.clone()),
                Some(_) => {}
            }
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
