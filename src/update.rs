//! A machine updates its own dryserver: the binary the admin signed in a
//! release, and the system files that binary renders. Whoever controls this
//! path controls every machine, so it installs only what passes
//! `release::check` and `release::verify_file`; and a bad update must never
//! leave a machine unreachable, so every update reverts by itself unless it
//! is confirmed in time.
//!
//! `update apply`, step by step:
//!
//! 1. Checks the release against the installed one and the binary against
//!    the release, from a directory only root can write.
//! 2. Writes a pending record and arms a revert timer before it changes
//!    anything. From then on, whatever happens (an error, Ctrl-C, a lost SSH
//!    session, a power cut), the machine goes back to what it ran before
//!    unless the update is confirmed in time.
//! 3. Copies the new binary next to the installed one under a temporary
//!    name and runs its self check there. Only then does it take the
//!    installed name, by a rename: a power cut leaves the old or the new
//!    binary, never half of one. The old one stays as dryserver.prev.
//! 4. Hands over to the new binary (`update activate`), which renders the
//!    system files from config.env with its own code, writes those that
//!    changed (each atomically, its old content kept), checks them with the
//!    real tools (nft -c, sshd -t, visudo -c, systemd-analyze verify), runs
//!    the state migrations it knows, and reloads only what changed. sshd is
//!    reloaded, never restarted: running sessions stay.
//!
//! `update confirm` makes it final once the self check passes. Without it,
//! the timer reverts: old binary, old files, reloads. The timer runs the
//! previous binary first, since the new one may be what is broken. A timer
//! does not survive a reboot, so a boot unit (GUARD_UNIT_TEXT) reverts an
//! update whose deadline passed, or that never finished applying, before
//! the firewall, the network and SSH start, and arms the timer again for one
//! whose window is still open. None of this needs the network or the
//! coordinator.
//!
//! The state lives in DIR, not under /var/lib/dryserver: on the coordinator
//! that directory belongs to the registry account, which every machine can
//! reach with the registry key. Nothing that account can write may steer
//! an update.

use std::collections::BTreeMap;
use std::fmt::Display;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::DateTime;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::ctx::Ctx;
use crate::err::{Error, Result};
use crate::node::{self, Node};
use crate::release::{self, Place, Release};
use crate::runner::{Cmd, Runner};
use crate::signed::{Envelope, SshVerifier, Verifier};
use crate::sysconf::{self, Params, Role};
use crate::{bail, errf, fsx, gotime, packages, quarantine, registry};

/// Root only (0700), every file in it too.
pub const DIR: &str = "/var/lib/dryserver-update";
/// Where the binary of a release waits to be checked and installed.
pub const STAGING: &str = "/var/lib/dryserver-update/staging";
/// The release this machine runs (the signed envelope as received).
pub const INSTALLED: &str = "/var/lib/dryserver-update/installed.json";
/// The update that waits for confirm, with everything needed to undo it.
pub const PENDING: &str = "/var/lib/dryserver-update/pending.json";
/// What the last apply, confirm or revert did, for status and the monitor.
pub const LAST: &str = "/var/lib/dryserver-update/last.json";
/// The old content of every file an update replaced, until it is final.
pub const BACKUPS: &str = "/var/lib/dryserver-update/backup";
/// The format version of dryserver's own state files (see MIGRATIONS).
pub const FORMAT_FILE: &str = "/var/lib/dryserver-update/state-format";
const LOCK: &str = "/var/lib/dryserver-update/lock";
pub const LOG: &str = "/var/log/dryserver-update.log";

pub const SERVER_BIN: &str = quarantine::SERVER_BIN;
/// The binary that ran before the last update. The revert timer and the
/// boot unit run it first.
pub const PREV_BIN: &str = "/usr/local/bin/dryserver.prev";
/// Temporary names in the same directory, so renames are atomic.
const NEW_BIN: &str = "/usr/local/bin/.dryserver.new";
const PREV_TMP: &str = "/usr/local/bin/.dryserver.prev.new";
const RESTORE_TMP: &str = "/usr/local/bin/.dryserver.restore";
const K3S_BIN: &str = "/usr/local/bin/k3s";
/// A file being replaced is first written here, next to it.
const TMP_SUFFIX: &str = ".dryserver-new";

pub const CONFIG: &str = "/etc/dryserver/config.env";
pub const ROLE_FILE: &str = "/etc/dryserver/role";
const HOSTNAME_FILE: &str = "/etc/hostname";
const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";
const FIREWALL: &str = "/etc/nftables.conf";

pub const GUARD_UNIT: &str = "dryserver-update-guard.service";
pub const GUARD_UNIT_PATH: &str = "/etc/systemd/system/dryserver-update-guard.service";
/// The transient revert timer of one update is this plus its id.
pub const TIMER_PREFIX: &str = "dryserver-update-revert-";

/// How long an update waits for confirm before it reverts by itself.
pub const WINDOW: i64 = 600;
pub const MIN_WINDOW: i64 = 60;
pub const MAX_WINDOW: i64 = 24 * 3600;
/// An update that sees this many restarts without being confirmed is
/// reverted at the next one. A machine whose clock is wrong at every boot
/// (no clock battery) would otherwise get a fresh window each time.
pub const MAX_BOOTS: u32 = 3;
const SELFCHECK_TIME: Duration = Duration::from_secs(60);
const ACTIVATE_TIME: Duration = Duration::from_secs(180);
const REVERT_TIME: Duration = Duration::from_secs(180);
/// The longest an update command waits for another one to finish.
const LOCK_WAIT: Duration = Duration::from_secs(60);
/// An apply does not queue behind another one, it refuses. It waits a
/// moment only: a child process that was forked while the lock was held
/// keeps it until it starts its own program.
const APPLY_LOCK_WAIT: Duration = Duration::from_secs(3);
/// The revert timer waits longer: an apply that is still running gets to
/// finish (or fail and revert) first.
const GUARD_LOCK_WAIT: Duration = Duration::from_secs(15 * 60);
/// A signed release envelope is a few KiB; refuse to read more.
const MAX_ENVELOPE: u64 = 64 << 10;
/// The format of the pending record. Its fields only grow: the previous
/// binary has to read what the new one wrote, to revert it.
const PENDING_FORMAT: u32 = 1;

pub const STAGE_INSTALLING: &str = "installing";
pub const STAGE_ARMED: &str = "armed";
pub const STAGE_REVERTING: &str = "reverting";

/// The boot half of the revert guard. It runs before the firewall, the
/// network and SSH, so they start with the files of the release that is
/// kept. The previous binary goes first: the new one may be what is broken.
pub const GUARD_UNIT_TEXT: &str = "# dryserver: after a restart, an update that was not confirmed in time
# (or never finished applying) is reverted before the firewall, the network
# and SSH start; one whose window is still open gets its revert timer back.
[Unit]
Description=Revert an unconfirmed dryserver update after a restart
DefaultDependencies=no
After=local-fs.target
Before=sysinit.target shutdown.target nftables.service systemd-networkd.service sshd.service wg-quick@wg0.service k3s.service dryserver-sync.timer
Conflicts=shutdown.target
ConditionPathExists=/var/lib/dryserver-update/pending.json

[Service]
Type=oneshot
ExecStart=/bin/sh -c '/usr/local/bin/dryserver.prev update guard --boot || /usr/local/bin/dryserver update guard --boot'
TimeoutStartSec=5min

[Install]
WantedBy=sysinit.target
";

/// Called at every point where a power cut could stop an update; tests
/// crash or fail there. A no-op on a real machine.
pub type Hook = Arc<dyn Fn(&str) -> io::Result<()> + Send + Sync>;

/// The machine being updated: "/" for real, a directory in tests.
pub struct Machine {
    pub root: PathBuf,
    pub run: Arc<dyn Runner>,
    /// Checks the admin's signature on releases.
    pub verifier: Arc<dyn Verifier>,
    /// Who must own the update directories and the staged binary: root.
    pub owner: u32,
    pub hook: Hook,
    pub migrations: &'static [Migration],
}

impl Machine {
    /// This machine, with the signing key the installer put on it.
    pub fn installed(run: Arc<dyn Runner>) -> Machine {
        Machine {
            root: PathBuf::from("/"),
            run,
            verifier: Arc::new(SshVerifier::installed(Path::new("/"), PathBuf::from("/run"))),
            owner: 0,
            hook: Arc::new(|_| Ok(())),
            migrations: MIGRATIONS,
        }
    }

    pub fn path(&self, p: &str) -> PathBuf {
        fsx::under(&self.root, p)
    }

    fn shown(&self, p: &str) -> String {
        self.path(p).display().to_string()
    }

    fn at(&self, point: &str) -> Result<()> {
        (self.hook)(point).map_err(|e| Error::from(e).wrap(point))
    }

    fn cmd(&self, ctx: &Ctx, name: &str, args: &[&str]) -> Result<String> {
        self.run.output(ctx, &Cmd::new(name, args))
    }
}

// ---- records ----

/// The update that waits for confirm. Written before anything changes and
/// after every file that changes, so a revert (by the timer, at boot, by
/// hand) knows exactly what to put back.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Pending {
    pub format: u32,
    /// Random; names the revert timer, so a stale timer of an earlier
    /// update never reverts this one.
    pub id: String,
    /// installing, armed (applied, waits for confirm) or reverting. Text,
    /// not an enum: a stage written by a newer binary still reads, and
    /// anything but armed reverts at boot.
    pub stage: String,
    pub serial: u64,
    pub version: String,
    /// The serial of the release that ran before, if any.
    #[serde(default)]
    pub previous: Option<u64>,
    pub release: Envelope,
    /// Unix seconds.
    pub applied: i64,
    pub deadline: i64,
    pub window: i64,
    /// Restarts seen while waiting for confirm.
    #[serde(default)]
    pub boots: u32,
    /// The binary that ran before, so a revert can tell the right one.
    pub prev_sha256: String,
    pub new_sha256: String,
    /// Every file this update wrote, in order.
    #[serde(default)]
    pub files: Vec<Replaced>,
    /// Fields a newer binary added: kept when an older one rewrites the
    /// record.
    #[serde(flatten)]
    pub rest: BTreeMap<String, serde_json::Value>,
}

/// One file an update wrote.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Replaced {
    pub path: String,
    /// Where its old content is; None when the file did not exist before
    /// (a revert removes it).
    pub backup: Option<String>,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

/// What the last apply, confirm or revert did.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Last {
    pub at: i64,
    pub serial: u64,
    /// applied, confirmed or reverted.
    pub action: String,
    /// False when it could not do all it had to.
    pub ok: bool,
    pub message: String,
}

fn read_json<T: DeserializeOwned>(m: &Machine, path: &str) -> Result<Option<T>> {
    match fs::read(m.path(path)) {
        Ok(b) => serde_json::from_slice(&b).map(Some).map_err(|e| Error::from(e).wrap(format!("{path} is damaged"))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::from(e).wrap(format!("open {path}"))),
    }
}

fn save_json<T: Serialize>(m: &Machine, path: &str, v: &T) -> Result<()> {
    write_atomic(m, &m.path(path), (serde_json::to_string_pretty(v)? + "\n").as_bytes(), 0o600, None)
}

pub fn load_pending(m: &Machine) -> Result<Option<Pending>> {
    read_json(m, PENDING)
}

fn save_pending(m: &Machine, p: &Pending) -> Result<()> {
    save_json(m, PENDING, p)
}

/// The end of an update, either way: the record goes, flushed to disk.
fn clear_pending(m: &Machine) -> Result<()> {
    remove_if_exists(&m.path(PENDING))?;
    let _ = remove_if_exists(&tmp_of(&m.path(PENDING)));
    sync_dir(&m.path(DIR))
}

/// The release this machine runs: the envelope and what it says.
pub fn load_installed(m: &Machine) -> Result<Option<(Envelope, Release)>> {
    let Some(env) = read_json::<Envelope>(m, INSTALLED)? else { return Ok(None) };
    let r: Release = serde_json::from_str(&env.doc)
        .map_err(|e| Error::from(e).wrap(format!("{INSTALLED} is damaged (removing it lets any signed release in, old ones included)")))?;
    Ok(Some((env, r)))
}

/// Unix seconds for people.
fn when(t: i64) -> String {
    DateTime::from_timestamp(t, 0).map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string()).unwrap_or_else(|| format!("{t} (unix time)"))
}

fn say(out: &mut dyn Write, msg: impl Display) {
    let _ = writeln!(out, "{msg}");
}

/// A line in LOG. Best effort: a full disk must not stop a revert.
fn note(m: &Machine, now: i64, msg: &str) {
    let p = m.path(LOG);
    let _ = fsx::mkdir_all(fsx::dir(&p), 0o755);
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).mode(0o600).open(&p) {
        let _ = writeln!(f, "{} {}", when(now), msg.replace('\n', "; "));
    }
}

fn tell(m: &Machine, out: &mut dyn Write, now: i64, msg: &str) {
    say(out, msg);
    note(m, now, msg);
}

/// Shows msg, logs it and keeps it as the last result.
fn record(m: &Machine, out: &mut dyn Write, now: i64, serial: u64, action: &str, ok: bool, msg: &str) {
    tell(m, out, now, msg);
    let _ = save_json(m, LAST, &Last { at: now, serial, action: action.into(), ok, message: msg.into() });
}

// ---- files ----

fn remove_if_exists(p: &Path) -> Result<()> {
    match fs::remove_file(p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::from(e).wrap(format!("remove {}", p.display()))),
    }
}

fn tmp_of(p: &Path) -> PathBuf {
    PathBuf::from(format!("{}{TMP_SUFFIX}", p.display()))
}

/// Flushes a directory, so a rename in it survives a power cut.
fn sync_dir(dir: &Path) -> Result<()> {
    File::open(dir).and_then(|f| f.sync_all()).map_err(|e| Error::from(e).wrap(format!("sync {}", dir.display())))
}

/// Writes path atomically: a temporary file next to it, flushed to disk,
/// renamed over it, the directory flushed. A power cut leaves the old or the
/// new content, never a mix.
fn write_atomic(m: &Machine, path: &Path, data: &[u8], mode: u32, owner: Option<(u32, u32)>) -> Result<()> {
    let dir = fsx::dir(path);
    fsx::mkdir_all(&dir, 0o755)?;
    let tmp = tmp_of(path);
    remove_if_exists(&tmp)?;
    let fail = |op: &str, e: io::Error| Error::from(e).wrap(format!("{op} {}", tmp.display()));
    let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp).map_err(|e| fail("open", e))?;
    let res = (|| -> Result<()> {
        f.write_all(data).map_err(|e| fail("write", e))?;
        m.at("write")?;
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::fchown(&f, Some(uid), Some(gid)).map_err(|e| fail("chown", e))?;
        }
        f.set_permissions(fs::Permissions::from_mode(mode)).map_err(|e| fail("chmod", e))?;
        f.sync_all().map_err(|e| fail("sync", e))
    })();
    drop(f);
    if let Err(e) = res {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    fsx::rename(&tmp, path)?;
    sync_dir(&dir)
}

/// Opens a regular file for reading without following a symbolic link and
/// without blocking on a FIFO.
fn open_regular(path: &Path) -> Result<File> {
    let f = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path).map_err(|e| {
        if e.raw_os_error() == Some(libc::ELOOP) {
            errf!("{} is a symbolic link, not the file itself", path.display())
        } else {
            Error::from(e).wrap(format!("open {}", path.display()))
        }
    })?;
    if !f.metadata().map_err(|e| Error::from(e).wrap(format!("stat {}", path.display())))?.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    Ok(f)
}

/// Copies exactly size bytes from src to a new file dst and flushes it.
/// Anything else (a link, another size, a full disk) leaves no dst behind.
fn copy_exact(m: &Machine, src: &Path, dst: &Path, size: u64, mode: u32, point: &str) -> Result<()> {
    let mut s = open_regular(src)?;
    let len = s.metadata().map_err(|e| Error::from(e).wrap(format!("stat {}", src.display())))?.len();
    if len != size {
        bail!("{} is {len} bytes, the release says {size}", src.display());
    }
    remove_if_exists(dst)?;
    let fail = |op: &str, e: io::Error| Error::from(e).wrap(format!("{op} {}", dst.display()));
    let mut d = OpenOptions::new().write(true).create_new(true).mode(mode).open(dst).map_err(|e| fail("open", e))?;
    let res = (|| -> Result<()> {
        let mut buf = vec![0u8; 64 << 10];
        let mut n: u64 = 0;
        loop {
            let k = match s.read(&mut buf) {
                Ok(0) => break,
                Ok(k) => k,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Error::from(e).wrap(format!("read {}", src.display()))),
            };
            n += k as u64;
            if n > size {
                bail!("{} grew while it was copied", src.display());
            }
            d.write_all(&buf[..k]).map_err(|e| fail("write", e))?;
            m.at(point)?;
        }
        if n != size {
            bail!("{} changed size while it was copied", src.display());
        }
        d.sync_all().map_err(|e| fail("sync", e))
    })();
    drop(d);
    if let Err(e) = res {
        let _ = fs::remove_file(dst);
        return Err(e);
    }
    Ok(())
}

/// A path from a record: absolute, without "..", so a damaged record cannot
/// point a revert anywhere else.
fn safe_path(p: &str) -> Result<()> {
    if !p.starts_with('/') || p.contains('\0') || p.split('/').any(|c| c == "..") {
        bail!("{p:?} is not a path dryserver manages");
    }
    Ok(())
}

/// Owned by root (m.owner), not writable by anyone else, not a link. A
/// file must also have one name only.
fn check_owned(m: &Machine, path: &Path, dir: bool) -> Result<()> {
    let md = fs::symlink_metadata(path).map_err(|e| Error::from(e).wrap(format!("stat {}", path.display())))?;
    let p = path.display();
    if md.file_type().is_symlink() {
        bail!("{p} is a symbolic link; an update takes nothing through a link");
    }
    if dir && !md.is_dir() {
        bail!("{p} is not a directory");
    }
    if !dir && !md.is_file() {
        bail!("{p} is not a regular file");
    }
    if md.uid() != m.owner {
        bail!("{p} belongs to user {}, not root", md.uid());
    }
    if md.mode() & 0o022 != 0 {
        bail!("{p} can be written by others than root (mode {:04o})", md.mode() & 0o7777);
    }
    if !dir && md.nlink() != 1 {
        bail!("{p} has {} names (hard links); an update takes only a file of its own", md.nlink());
    }
    Ok(())
}

/// The staging directory and every directory above it belong to root and
/// nobody else may write them: nobody else can swap the binary between its
/// check and its install.
fn check_dirs(m: &Machine) -> Result<()> {
    for d in ["/var", "/var/lib", DIR, STAGING] {
        check_owned(m, &m.path(d), true)?;
    }
    Ok(())
}

/// Creates DIR, STAGING and BACKUPS (0700) when they are missing. Existing
/// ones are left as they are: a wrong owner or mode is refused later, not
/// quietly repaired.
fn ensure_dirs(m: &Machine) -> Result<()> {
    fsx::mkdir_all(m.path("/var/lib"), 0o755)?;
    for d in [DIR, STAGING, BACKUPS] {
        let p = m.path(d);
        match fs::DirBuilder::new().mode(0o700).create(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(Error::from(e).wrap(format!("mkdir {}", p.display()))),
        }
    }
    Ok(())
}

// ---- the lock ----

/// The update lock, if nobody else holds it.
fn try_lock(m: &Machine) -> Result<Option<File>> {
    let p = m.path(LOCK);
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&p)
        .map_err(|e| Error::from(e).wrap(format!("open {}", p.display())))?;
    // SAFETY: flock on a valid open descriptor owned by f.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(Some(f));
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::EWOULDBLOCK) { Ok(None) } else { Err(Error::from(e).wrap(format!("lock {}", p.display()))) }
}

fn lock_wait(m: &Machine, ctx: &Ctx, max: Duration) -> Result<File> {
    let end = Instant::now() + max;
    loop {
        if let Some(f) = try_lock(m)? {
            return Ok(f);
        }
        if Instant::now() >= end {
            bail!("another update is running on this machine; try again when it is done");
        }
        ctx.sleep(Duration::from_millis(200))?;
    }
}

// ---- the machine ----

/// A machine that cut the coordinator off (the kill switch) takes nothing
/// from it, an update included. A cut that cannot be read counts as one.
fn refuse_if_cut(m: &Machine) -> Result<()> {
    let Some(st) = read_json::<quarantine::State>(m, quarantine::STATE_FILE)
        .map_err(|e| e.wrap("the kill switch state cannot be read, so no update is taken"))?
    else {
        return Ok(());
    };
    if st.coordinator_cut() {
        bail!("the coordinator is cut off on this machine (dryserver quarantine): no update until the cut is lifted");
    }
    Ok(())
}

fn role_of(m: &Machine) -> Result<Role> {
    let s = fsx::read_string(m.path(ROLE_FILE))?;
    Role::parse(s.trim()).ok_or_else(|| errf!("{ROLE_FILE} says {:?}, not node or coordinator", s.trim()))
}

/// What sysconf renders this machine from, read from the machine itself.
pub fn machine_params(m: &Machine) -> Result<Params> {
    let config = Config::load(m.path(CONFIG))?;
    let plan = packages::resolve(&config.tool_list(), &config.extra_list())?;
    let hostname = fsx::read_string(m.path(HOSTNAME_FILE))?.trim().to_string();
    if hostname.is_empty() {
        bail!("{HOSTNAME_FILE} is empty");
    }
    let role = role_of(m)?;
    let host_num = match role {
        Role::Coordinator => 1,
        Role::Node => read_json::<node::State>(m, node::JOIN_STATE)?.map(|s| s.host).unwrap_or(0),
    };
    let switch_mac = fsx::read_or_empty(m.path(node::SWITCH_MAC_FILE)).trim().to_string();
    Ok(Params { config, plan, hostname, role, host_num, switch_mac })
}

/// Rendered files an update leaves alone, and why.
pub const NOT_MANAGED: &[(&str, &str)] = &[
    ("/etc/hostname", "the machine's name, from its install"),
    ("/etc/hosts", "sync writes the mesh members into it"),
    ("/etc/dryserver/config.env", "what the files are rendered from"),
];

/// Whether an update keeps this rendered file in step with the binary.
pub fn managed(path: &str) -> bool {
    !NOT_MANAGED.iter().any(|(p, _)| *p == path)
        // The admin's login key belongs to the admin's account (and its
        // owner): rewriting it as root would lock the admin out.
        && !path.starts_with("/home/")
        // The WiFi password is not in a server's config.env; rendering
        // these again would lose it.
        && !path.starts_with("/var/lib/iwd/")
}

/// The system files this machine gets from this binary.
pub fn render_managed(m: &Machine) -> Result<Vec<sysconf::File>> {
    Ok(sysconf::render(&machine_params(m)?)?.into_iter().filter(|f| managed(&f.path)).collect())
}

// ---- writing files with a way back ----

/// Writes files for an update, recording each one in the pending record
/// (with its old content) before it changes.
pub struct Changes<'a> {
    m: &'a Machine,
    p: Pending,
    /// Paths written, in order, each once.
    changed: Vec<String>,
}

impl<'a> Changes<'a> {
    fn new(m: &'a Machine, p: Pending) -> Changes<'a> {
        Changes { m, p, changed: Vec::new() }
    }

    /// A file's content, None when it does not exist. For migrations; there
    /// is none yet outside the tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn read(&self, path: &str) -> Result<Option<Vec<u8>>> {
        safe_path(path)?;
        match fs::read(self.m.path(path)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::from(e).wrap(format!("open {path}"))),
        }
    }

    /// Makes path hold data with mode. Nothing happens when it does
    /// already; otherwise the old file is kept for a revert first. Returns
    /// whether it changed.
    pub fn put(&mut self, path: &str, mode: u32, data: &[u8]) -> Result<bool> {
        safe_path(path)?;
        let dst = self.m.path(path);
        let old = match fs::symlink_metadata(&dst) {
            Ok(md) if !md.is_file() => bail!("{path} is not a regular file; an update does not replace it"),
            Ok(md) => Some(md),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(Error::from(e).wrap(format!("stat {path}"))),
        };
        if let Some(md) = &old
            && md.mode() & 0o7777 == mode
            && fsx::read(&dst)? == data
        {
            return Ok(false);
        }
        // Written twice in one update (a migration after the render): the
        // first backup holds the content to go back to.
        if !self.p.files.iter().any(|f| f.path == path) {
            let entry = match &old {
                Some(md) => {
                    let backup = format!("{BACKUPS}/{}/{}", self.p.id, self.p.files.len());
                    let b = self.m.path(&backup);
                    fsx::mkdir_all(fsx::dir(&b), 0o700)?;
                    write_atomic(self.m, &b, &fsx::read(&dst)?, 0o600, None)?;
                    Replaced { path: path.into(), backup: Some(backup), mode: md.mode() & 0o7777, uid: md.uid(), gid: md.gid() }
                }
                None => Replaced { path: path.into(), backup: None, mode, uid: 0, gid: 0 },
            };
            self.p.files.push(entry);
            save_pending(self.m, &self.p)?;
        }
        write_atomic(self.m, &dst, data, mode, None)?;
        if !self.changed.iter().any(|c| c == path) {
            self.changed.push(path.into());
        }
        Ok(true)
    }
}

/// Puts back one file an update wrote.
fn restore(m: &Machine, f: &Replaced) -> Result<()> {
    safe_path(&f.path)?;
    let dst = m.path(&f.path);
    match &f.backup {
        Some(b) => {
            if safe_path(b).is_err() || !b.starts_with(&format!("{BACKUPS}/")) {
                bail!("{}: the record points its backup outside {BACKUPS}", f.path);
            }
            let data = fsx::read(m.path(b)).map_err(|e| e.wrap(format!("the old {} is lost", f.path)))?;
            write_atomic(m, &dst, &data, f.mode, Some((f.uid, f.gid)))?;
        }
        None => {
            remove_if_exists(&dst)?;
            sync_dir(&fsx::dir(&dst))?;
        }
    }
    remove_if_exists(&tmp_of(&dst))
}

// ---- state migrations ----

/// One change of format of dryserver's own state files. An update runs the
/// ones the machine has not had yet, in order, after the new binary is in
/// place; they write through Changes, so a revert puts the old files back.
pub struct Migration {
    /// The format the state is in after this step: 1, 2, 3...
    pub to: u32,
    pub what: &'static str,
    pub run: fn(&mut Changes) -> Result<()>,
}

/// Every migration, oldest first. None yet: the first one gets `to: 1`.
pub const MIGRATIONS: &[Migration] = &[];

/// The format of this machine's state files; 0 before any migration.
pub fn state_format(m: &Machine) -> Result<u32> {
    match fs::read_to_string(m.path(FORMAT_FILE)) {
        Ok(s) => s.trim().parse().map_err(|_| errf!("{FORMAT_FILE} is damaged ({:?})", s.trim())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(Error::from(e).wrap(format!("open {FORMAT_FILE}"))),
    }
}

/// The highest format migs know, after checking they are in order.
fn known_format(migs: &[Migration]) -> Result<u32> {
    for (i, mg) in migs.iter().enumerate() {
        if mg.to as usize != i + 1 {
            bail!("migration {:?} is numbered {}, not {}", mg.what, mg.to, i + 1);
        }
    }
    Ok(migs.len() as u32)
}

fn migrate(ch: &mut Changes, migs: &[Migration]) -> Result<Vec<&'static str>> {
    let known = known_format(migs)?;
    let cur = state_format(ch.m)?;
    if cur > known {
        // A release with an older dryserver (rollback) cannot go back past
        // a format change: that binary would misread the state.
        bail!("this machine's state files are in format {cur}, newer than this dryserver knows ({known})");
    }
    let mut done = Vec::new();
    for mg in &migs[cur as usize..] {
        (mg.run)(ch).map_err(|e| e.wrap(format!("state migration to format {} ({})", mg.to, mg.what)))?;
        ch.m.at("migrated")?;
        done.push(mg.what);
    }
    if cur < known {
        ch.put(FORMAT_FILE, 0o600, format!("{known}\n").as_bytes())?;
    }
    Ok(done)
}

// ---- checking and reloading what changed ----

/// What a changed file needs before it counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Effect {
    Units,
    Sysctl,
    Network,
    Firewall,
    Sshd,
    Sudoers,
    Resolved,
    Docker,
    WireGuard,
}

/// Files without an effect are read when they are next used (cron, the
/// login screen) or at the next boot (zram, logind); k3s's config at its
/// next restart, which an update does not force.
fn effect(p: &str) -> Option<Effect> {
    Some(if p == FIREWALL || p.starts_with(&format!("{}/", quarantine::NFT_DIR)) {
        Effect::Firewall
    } else if p.starts_with("/etc/ssh/sshd_config") {
        Effect::Sshd
    } else if p == "/etc/sudoers" || p.starts_with("/etc/sudoers.d/") {
        Effect::Sudoers
    } else if p.starts_with("/etc/systemd/system/") {
        Effect::Units
    } else if p.starts_with("/etc/systemd/network/") {
        Effect::Network
    } else if p.starts_with("/etc/sysctl.d/") {
        Effect::Sysctl
    } else if p.starts_with("/etc/systemd/resolved.conf") {
        Effect::Resolved
    } else if p == "/etc/docker/daemon.json" {
        Effect::Docker
    } else if p.starts_with("/etc/wireguard/") {
        Effect::WireGuard
    } else {
        return None;
    })
}

fn effects(paths: &[String]) -> Vec<Effect> {
    let mut v: Vec<Effect> = paths.iter().filter_map(|p| effect(p)).collect();
    v.sort();
    v.dedup();
    v
}

/// What systemd-analyze verify gets for changed unit files: the file, or
/// for a drop-in the unit it belongs to.
fn units_to_verify(m: &Machine, paths: &[String]) -> Vec<String> {
    let mut v = Vec::new();
    for p in paths {
        let Some(rel) = p.strip_prefix("/etc/systemd/system/") else { continue };
        let arg = match rel.split_once(".d/") {
            Some((unit, _)) => unit.to_string(),
            None if rel.contains('/') => continue,
            None => m.shown(p),
        };
        if !v.contains(&arg) {
            v.push(arg);
        }
    }
    v
}

/// Checks the changed files with the tools that read them, before anything
/// reloads them.
fn validate(m: &Machine, ctx: &Ctx, paths: &[String]) -> Result<()> {
    let mut errs = Vec::new();
    for e in effects(paths) {
        let res = match e {
            Effect::Firewall => m.cmd(ctx, "nft", &["-c", "-f", &m.shown(FIREWALL)]).map(drop).map_err(|e| e.wrap("the new firewall")),
            Effect::Sshd => m.cmd(ctx, "sshd", &["-t", "-f", &m.shown(SSHD_CONFIG)]).map(drop).map_err(|e| e.wrap("the new SSH settings")),
            Effect::Sudoers => paths
                .iter()
                .filter(|p| effect(p) == Some(Effect::Sudoers))
                .try_for_each(|p| m.cmd(ctx, "visudo", &["-c", "-q", "-f", &m.shown(p)]).map(drop).map_err(|e| e.wrap(p))),
            Effect::Units => {
                let units = units_to_verify(m, paths);
                if units.is_empty() {
                    Ok(())
                } else {
                    let mut args = vec!["verify", "--man=no"];
                    args.extend(units.iter().map(String::as_str));
                    m.cmd(ctx, "systemd-analyze", &args).map(drop).map_err(|e| e.wrap("the new systemd units"))
                }
            }
            Effect::WireGuard => wg_check(m, true).map(drop),
            _ => Ok(()),
        };
        if let Err(e) = res {
            errs.push(e);
        }
    }
    match Error::join(errs) {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Makes the running system use the changed files. Nothing is restarted
/// that would drop a session: sshd and Docker reload, the firewall loads in
/// one transaction (established connections stay accepted).
fn reload(m: &Machine, ctx: &Ctx, fx: &[Effect]) -> Result<()> {
    let mut errs = Vec::new();
    for e in fx {
        let res = match e {
            Effect::Units => m.cmd(ctx, "systemctl", &["daemon-reload"]).map(drop),
            Effect::Sysctl => m.cmd(ctx, "sysctl", &["-q", "--system"]).map(drop),
            Effect::Network => m.cmd(ctx, "networkctl", &["reload"]).map(drop),
            Effect::Firewall => m.cmd(ctx, "nft", &["-f", &m.shown(FIREWALL)]).map(drop),
            Effect::Sshd => reload_sshd(m, ctx),
            Effect::Resolved => m.cmd(ctx, "systemctl", &["try-reload-or-restart", "systemd-resolved.service"]).map(drop),
            Effect::Docker => {
                if m.cmd(ctx, "systemctl", &["is-active", "--quiet", "docker.service"]).is_ok() {
                    m.cmd(ctx, "systemctl", &["reload", "docker.service"]).map(drop)
                } else {
                    Ok(())
                }
            }
            Effect::WireGuard => reload_wg(m, ctx),
            Effect::Sudoers => Ok(()),
        };
        if let Err(e) = res {
            errs.push(e);
        }
    }
    match Error::join(errs) {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// sshd re-reads its settings on a reload and keeps running sessions. A
/// reload with settings it cannot read would stop it taking new ones, so
/// they are checked first, also on the way back.
fn reload_sshd(m: &Machine, ctx: &Ctx) -> Result<()> {
    m.cmd(ctx, "sshd", &["-t", "-f", &m.shown(SSHD_CONFIG)])
        .map_err(|e| e.wrap("the SSH settings fail sshd -t, sshd keeps the ones it has"))?;
    if m.cmd(ctx, "systemctl", &["is-active", "--quiet", "sshd.service"]).is_ok() {
        m.cmd(ctx, "systemctl", &["reload", "sshd.service"]).map(drop)
    } else {
        // Not running (perhaps the settings it had stopped it): start it,
        // without waiting, so a boot that is still going on is no trap.
        m.cmd(ctx, "systemctl", &["start", "--no-block", "sshd.service"]).map(drop)
    }
}

fn reload_wg(m: &Machine, ctx: &Ctx) -> Result<()> {
    let p = machine_params(m)?;
    Node::new(p.config, &p.hostname, &m.root, m.run.clone()).reload_wg(ctx)
}

// ---- the revert timer and the boot unit ----

fn timer_unit(id: &str) -> String {
    format!("{TIMER_PREFIX}{id}")
}

/// Arms the revert timer: after secs seconds (by the monotonic clock, so a
/// clock that jumps does not move it) the previous binary reverts the
/// update unless it was confirmed. The installed one is the fallback.
fn arm(m: &Machine, ctx: &Ctx, id: &str, serial: u64, secs: i64) -> Result<()> {
    let unit = timer_unit(id);
    let (prev, bin) = (m.shown(PREV_BIN), m.shown(SERVER_BIN));
    let script = format!("{prev} update guard --id {id} || {bin} update guard --id {id}");
    m.cmd(
        ctx,
        "systemd-run",
        &[
            &format!("--unit={unit}"),
            &format!("--on-active={secs}s"),
            "--timer-property=AccuracySec=1s",
            &format!("--description=Revert dryserver release {serial} unless it is confirmed"),
            "/bin/sh",
            "-c",
            &script,
        ],
    )
    .map(drop)
}

fn disarm(m: &Machine, ctx: &Ctx, id: &str) {
    let _ = m.run.run(ctx, &Cmd::new("systemctl", &["stop", &format!("{}.timer", timer_unit(id))]).quiet());
}

/// Installs and enables the boot unit, also on machines installed before it
/// existed: without it a reboot during the window would lose the revert.
fn ensure_boot_guard(m: &Machine, ctx: &Ctx) -> Result<()> {
    let p = m.path(GUARD_UNIT_PATH);
    if fsx::read(&p).ok().as_deref() != Some(GUARD_UNIT_TEXT.as_bytes()) {
        write_atomic(m, &p, GUARD_UNIT_TEXT.as_bytes(), 0o644, None)?;
        m.cmd(ctx, "systemctl", &["daemon-reload"])?;
    }
    m.cmd(ctx, "systemctl", &["enable", "--quiet", GUARD_UNIT]).map(drop)
}

// ---- apply ----

/// What `update apply` was given.
#[derive(Debug, Clone)]
pub struct Apply {
    /// The signed release envelope ({"doc": ..., "sig": ...}).
    pub release: PathBuf,
    /// The binary it names. Copied into STAGING first unless it is there.
    pub binary: PathBuf,
    /// The k3s the coordinator runs, for the version skew rule on a server;
    /// "" asks this machine's k3s.
    pub brain_k3s: String,
    /// Seconds until an unconfirmed update reverts.
    pub window: i64,
}

/// The signed release from path. Anyone may have written it (it is checked
/// by its signature), but it must be a regular file: a FIFO with nobody on
/// the other end would hang the update.
fn read_envelope(path: &Path) -> Result<Envelope> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| Error::from(e).wrap(format!("open {}", path.display())))?;
    if !f.metadata().map_err(|e| Error::from(e).wrap(format!("stat {}", path.display())))?.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    let mut s = String::new();
    f.take(MAX_ENVELOPE + 1).read_to_string(&mut s).map_err(|e| Error::from(e).wrap(format!("read {}", path.display())))?;
    if s.len() as u64 > MAX_ENVELOPE {
        bail!("{} is larger than a signed release can be", path.display());
    }
    serde_json::from_str(&s).map_err(|e| Error::from(e).wrap(format!("{} is not a signed release", path.display())))
}

/// The k3s version this server's agent runs. The coordinator runs at least
/// that one (an agent is never newer), so it is a safe stand-in for the
/// coordinator's when that is not given.
fn local_k3s(m: &Machine, ctx: &Ctx) -> Result<String> {
    let out = m.cmd(ctx, &m.shown(K3S_BIN), &["--version"])?;
    out.lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(2))
        .map(str::to_string)
        .ok_or_else(|| errf!("k3s --version said {:?}", out.lines().next().unwrap_or("")))
}

/// The binary in STAGING, copied there from elsewhere if needed, checked to
/// be root's alone.
fn stage(m: &Machine, binary: &Path, rel: &Release) -> Result<PathBuf> {
    check_dirs(m)?;
    let staging = m.path(STAGING);
    if binary.parent() == Some(staging.as_path()) {
        check_owned(m, binary, false)?;
        return Ok(binary.to_path_buf());
    }
    let dst = staging.join(format!("dryserver-{}", rel.serial));
    let tmp = tmp_of(&dst);
    copy_exact(m, binary, &tmp, rel.dryserver.size, 0o600, "stage")?;
    fsx::rename(&tmp, &dst)?;
    sync_dir(&staging)?;
    check_owned(m, &dst, false)?;
    Ok(dst)
}

/// Installs and checks the release in envelope `release` with the binary
/// `binary`. Refusals change nothing. Once it starts changing the machine,
/// any failure reverts it before returning.
pub fn apply(m: &Machine, ctx: &Ctx, a: &Apply, now: i64, out: &mut dyn Write) -> Result<()> {
    if !(MIN_WINDOW..=MAX_WINDOW).contains(&a.window) {
        bail!("the window must be between {MIN_WINDOW} and {MAX_WINDOW} seconds, not {}", a.window);
    }
    ensure_dirs(m)?;
    let _lock = lock_wait(m, ctx, APPLY_LOCK_WAIT)?;
    refuse_if_cut(m)?;
    let env = read_envelope(&a.release)?;
    if let Some(p) = load_pending(m)? {
        if p.release.doc == env.doc {
            say(out, format!("release {} is applied already and waits for confirm until {}", p.serial, when(p.deadline)));
            return Ok(());
        }
        bail!("release {} waits for confirm or revert; finish it first (dryserver update status)", p.serial);
    }
    let installed = load_installed(m)?;
    let brain = match role_of(m)? {
        Role::Coordinator => None,
        Role::Node if !a.brain_k3s.is_empty() => Some(a.brain_k3s.clone()),
        Role::Node => Some(local_k3s(m, ctx).map_err(|e| e.wrap("give the coordinator's k3s version with --brain-k3s"))?),
    };
    let place = match &brain {
        None => Place::Brain,
        Some(b) => Place::Worker { brain_k3s: b },
    };
    let (rel, verdict) = release::check(m.verifier.as_ref(), &env, installed.as_ref().map(|(_, r)| r), place, now)?;
    if verdict.stale {
        tell(
            m,
            out,
            now,
            &format!(
                "warning: release {} expired {}; whatever hands out releases may have stopped moving. Applying it anyway",
                rel.serial,
                when(rel.expires)
            ),
        );
    }
    if !verdict.install {
        say(out, format!("release {} is installed already, nothing to do", rel.serial));
        return Ok(());
    }
    let staged = stage(m, &a.binary, &rel)?;
    release::verify_file(&staged, &rel.dryserver.sha256, rel.dryserver.size)
        .map_err(|e| e.wrap("the binary is not the one the release names"))?;
    let bin = m.path(SERVER_BIN);
    let (prev_sha256, _) = release::hash_file(&bin, release::MAX_BINARY).map_err(|e| e.wrap("the installed dryserver"))?;
    ensure_boot_guard(m, ctx).map_err(|e| e.wrap("cannot install the boot half of the revert guard, nothing was changed"))?;

    let p = Pending {
        format: PENDING_FORMAT,
        id: fsx::hex(&fsx::random_bytes(8)),
        stage: STAGE_INSTALLING.into(),
        serial: rel.serial,
        version: rel.dryserver.version.clone(),
        previous: installed.as_ref().map(|(_, r)| r.serial),
        release: env.clone(),
        applied: now,
        deadline: now.saturating_add(a.window),
        window: a.window,
        boots: 0,
        prev_sha256,
        new_sha256: rel.dryserver.sha256.clone(),
        files: Vec::new(),
        rest: BTreeMap::new(),
    };
    save_pending(m, &p)?;
    if let Err(e) = arm(m, ctx, &p.id, p.serial, p.window) {
        let _ = clear_pending(m);
        return Err(e.wrap("cannot arm the timer that reverts an unconfirmed update, nothing was changed"));
    }
    let notes = if rel.notes.is_empty() { String::new() } else { format!(": {}", rel.notes) };
    tell(m, out, now, &format!("applying release {} (dryserver {}){notes}", rel.serial, rel.dryserver.version));
    match finish(m, ctx, &p.id, &staged, &rel, &env, out) {
        Ok(()) => {
            let _ = fs::remove_file(&staged);
            let msg = format!(
                "release {} is applied. Confirm it before {} (dryserver update confirm), or it reverts by itself",
                rel.serial,
                when(p.deadline)
            );
            record(m, out, now, rel.serial, "applied", true, &msg);
            Ok(())
        }
        Err(e) => {
            // The latest record: the new binary may have added files.
            let latest = load_pending(m).ok().flatten().filter(|q| q.id == p.id).unwrap_or(p);
            // A fresh context: when the apply was cancelled (Ctrl-C), the
            // way back must still run.
            let rctx = Ctx::new().with_timeout(REVERT_TIME);
            let why = format!("the apply failed: {e}");
            match revert(m, &rctx, latest, &why, false, now, out) {
                Ok(()) => Err(e.wrap(format!("release {} not applied, this machine runs what it ran before", rel.serial))),
                Err(r) => Err(errf!("release {} not applied: {e}\nand the way back did not finish: {r}", rel.serial)),
            }
        }
    }
}

/// The part of apply that changes the machine.
fn finish(m: &Machine, ctx: &Ctx, id: &str, staged: &Path, rel: &Release, env: &Envelope, out: &mut dyn Write) -> Result<()> {
    install_binary(m, ctx, staged, rel, out)?;
    // The new binary renders and reloads with its own code.
    let (o, res) = m.run.run(&ctx.with_timeout(ACTIVATE_TIME), &Cmd::new(&m.shown(SERVER_BIN), &["update", "activate", "--id", id]));
    let _ = out.write_all(o.as_bytes());
    res.map_err(|e| e.wrap("the new dryserver could not take over the system files"))?;
    let p = load_pending(m)?.ok_or_else(|| errf!("the pending record is gone"))?;
    if p.id != id {
        bail!("another update took over the pending record");
    }
    let mut ch = Changes::new(m, p);
    ch.put(INSTALLED, 0o600, (serde_json::to_string_pretty(env)? + "\n").as_bytes())?;
    let mut p = ch.p;
    p.stage = STAGE_ARMED.into();
    save_pending(m, &p)?;
    m.at("armed")
}

/// Puts the staged binary in place of the installed one, keeping that one
/// as dryserver.prev. The new one has to pass its self check before it
/// takes the installed name.
fn install_binary(m: &Machine, ctx: &Ctx, staged: &Path, rel: &Release, out: &mut dyn Write) -> Result<()> {
    let new = m.path(NEW_BIN);
    let bin_dir = fsx::dir(m.path(SERVER_BIN));
    let checked = (|| -> Result<()> {
        copy_exact(m, staged, &new, rel.dryserver.size, 0o700, "copy")?;
        fsx::chmod(&new, 0o755)?;
        sync_dir(&bin_dir)?;
        // The copy is what runs: check it, not only its source.
        release::verify_file(&new, &rel.dryserver.sha256, rel.dryserver.size).map_err(|e| e.wrap("the copy of the new binary"))?;
        m.at("binary copied")?;
        let (o, res) = m.run.run(&ctx.with_timeout(SELFCHECK_TIME), &Cmd::new(&new.display().to_string(), &["selfcheck"]));
        if let Err(e) = res {
            let _ = out.write_all(o.as_bytes());
            bail!("the new dryserver failed its self check, nothing was switched: {e}");
        }
        Ok(())
    })();
    if let Err(e) = checked {
        let _ = fs::remove_file(&new);
        return Err(e);
    }
    m.at("binary checked")?;
    let (bin, prev, prev_tmp) = (m.path(SERVER_BIN), m.path(PREV_BIN), m.path(PREV_TMP));
    remove_if_exists(&prev_tmp)?;
    fs::hard_link(&bin, &prev_tmp).map_err(|e| Error::from(e).wrap(format!("link {} {}", bin.display(), prev_tmp.display())))?;
    fsx::rename(&prev_tmp, &prev)?;
    // When dryserver.prev was this very file already (after a revert),
    // the rename does nothing and leaves the temporary name.
    remove_if_exists(&prev_tmp)?;
    sync_dir(&bin_dir)?;
    m.at("previous kept")?;
    fsx::rename(&new, &bin)?;
    sync_dir(&bin_dir)?;
    m.at("binary switched")?;
    say(out, format!("installed {SERVER_BIN} {} (the previous one stays as {PREV_BIN})", rel.dryserver.version));
    Ok(())
}

/// The new binary's half of apply: renders the system files, writes what
/// changed, runs the state migrations, checks and reloads. Runs only inside
/// `update apply`, which holds the lock and reverts when this fails.
pub fn activate(m: &Machine, ctx: &Ctx, id: &str, out: &mut dyn Write) -> Result<()> {
    if try_lock(m)?.is_some() {
        bail!("update activate is a step of update apply and runs only inside it");
    }
    let p = load_pending(m)?.ok_or_else(|| errf!("no update is being applied"))?;
    if p.id != id || p.stage != STAGE_INSTALLING {
        bail!("update {id:?} is not the one being applied");
    }
    // Sync, join and the kill switch change the mesh files under this lock;
    // a cut that landed since apply looked counts too.
    let _mesh = fsx::lock(m.path(quarantine::MESH_LOCK))?;
    refuse_if_cut(m)?;
    let files = render_managed(m)?;
    let mut ch = Changes::new(m, p);
    for f in &files {
        ch.put(&f.path, f.mode, f.content.as_bytes())?;
    }
    let migrated = migrate(&mut ch, m.migrations)?;
    let changed = ch.changed.clone();
    validate(m, ctx, &changed)?;
    reload(m, ctx, &effects(&changed))?;
    if changed.is_empty() {
        say(out, "no system file changed");
    }
    for c in &changed {
        say(out, format!("changed {c}"));
    }
    for w in migrated {
        say(out, format!("state migrated: {w}"));
    }
    Ok(())
}

// ---- revert ----

/// Puts the previous binary back, when it is not in place already.
fn restore_binary(m: &Machine, p: &Pending) -> Result<&'static str> {
    let bin = m.path(SERVER_BIN);
    if release::hash_file(&bin, release::MAX_BINARY).is_ok_and(|(s, _)| s == p.prev_sha256) {
        return Ok("the previous binary is in place");
    }
    match release::hash_file(&m.path(PREV_BIN), release::MAX_BINARY) {
        Ok((s, _)) if s == p.prev_sha256 => {}
        Ok(_) => bail!("{PREV_BIN} is not the binary that ran before the update, so {SERVER_BIN} stays the new one"),
        Err(e) => bail!("{PREV_BIN} cannot be used ({e}), so {SERVER_BIN} stays the new one"),
    }
    let tmp = m.path(RESTORE_TMP);
    remove_if_exists(&tmp)?;
    fs::hard_link(m.path(PREV_BIN), &tmp).map_err(|e| Error::from(e).wrap(format!("link {PREV_BIN}")))?;
    m.at("binary restoring")?;
    fsx::rename(&tmp, &bin)?;
    sync_dir(&fsx::dir(&bin))?;
    Ok("the previous binary is back")
}

/// Undoes an update: the binary, then every file in reverse order, then
/// reloads, then the record goes. Each step can run again after a power
/// cut; the record says "reverting" until the end, so the boot unit
/// finishes the job. At boot nothing has started yet, so only systemd
/// reloads its units.
fn revert(m: &Machine, ctx: &Ctx, mut p: Pending, why: &str, boot: bool, now: i64, out: &mut dyn Write) -> Result<()> {
    tell(m, out, now, &format!("reverting release {}: {why}", p.serial));
    p.stage = STAGE_REVERTING.into();
    let _ = save_pending(m, &p);
    let _mesh = fsx::lock(m.path(quarantine::MESH_LOCK)).ok();
    let mut problems = Vec::new();
    match restore_binary(m, &p) {
        Ok(s) => say(out, s),
        Err(e) => problems.push(e.to_string()),
    }
    for f in p.files.iter().rev() {
        if let Err(e) = restore(m, f) {
            problems.push(format!("{}: {e}", f.path));
        }
    }
    for t in [NEW_BIN, PREV_TMP, RESTORE_TMP] {
        let _ = remove_if_exists(&m.path(t));
    }
    let _ = m.at("files restored");
    let paths: Vec<String> = p.files.iter().map(|f| f.path.clone()).collect();
    let fx = effects(&paths);
    let reloaded = if boot {
        if fx.contains(&Effect::Units) { m.cmd(ctx, "systemctl", &["daemon-reload"]).map(drop) } else { Ok(()) }
    } else {
        disarm(m, ctx, &p.id);
        reload(m, ctx, &fx)
    };
    if let Err(e) = reloaded {
        problems.push(e.to_string());
    }
    if let Err(e) = clear_pending(m) {
        problems.push(e.to_string());
    }
    let _ = fs::remove_dir_all(m.path(&format!("{BACKUPS}/{}", p.id)));
    let before = p.previous.map(|s| format!("release {s}")).unwrap_or_else(|| "the dryserver it was installed with".into());
    if problems.is_empty() {
        record(
            m,
            out,
            now,
            p.serial,
            "reverted",
            true,
            &format!("release {} reverted ({why}); this machine runs {before} again", p.serial),
        );
        return Ok(());
    }
    let msg = format!("release {} reverted with problems ({why}):\n  {}", p.serial, problems.join("\n  "));
    record(m, out, now, p.serial, "reverted", false, &msg);
    Err(Error::new(msg))
}

/// `update revert`: undoes the update that waits for confirm.
pub fn revert_by_hand(m: &Machine, ctx: &Ctx, now: i64, out: &mut dyn Write) -> Result<()> {
    ensure_dirs(m)?;
    let _lock = lock_wait(m, ctx, LOCK_WAIT)?;
    let Some(p) = load_pending(m)? else {
        if let Some((_, r)) = load_installed(m)? {
            bail!("release {} is confirmed, there is nothing to revert. To go back, sign a release with rollback", r.serial);
        }
        bail!("no update waits for confirm, there is nothing to revert");
    };
    revert(m, &Ctx::new().with_timeout(REVERT_TIME), p, "reverted by hand", false, now, out)
}

// ---- confirm ----

/// `update confirm`: the update stays. Only when the installed binary is the
/// release's and passes its self check. serial, when given, must be the
/// waiting release; confirming one that is confirmed already is fine.
pub fn confirm(m: &Machine, ctx: &Ctx, serial: Option<u64>, now: i64, out: &mut dyn Write) -> Result<()> {
    ensure_dirs(m)?;
    let _lock = lock_wait(m, ctx, LOCK_WAIT)?;
    let Some(p) = load_pending(m)? else {
        if let (Some(s), Some((_, r))) = (serial, load_installed(m)?)
            && r.serial == s
        {
            say(out, format!("release {s} is confirmed already"));
            return Ok(());
        }
        bail!("no update waits for confirm");
    };
    if let Some(s) = serial
        && s != p.serial
    {
        bail!("release {} waits for confirm, not {s}", p.serial);
    }
    if p.stage != STAGE_ARMED {
        bail!(
            "release {} did not finish applying; it is reverted by its timer or at the next boot (or now: dryserver update revert)",
            p.serial
        );
    }
    let (sha, _) = release::hash_file(&m.path(SERVER_BIN), release::MAX_BINARY)?;
    if sha != p.new_sha256 {
        bail!("{SERVER_BIN} is not the binary of release {}; not confirmed", p.serial);
    }
    let (o, res) = m.run.run(&ctx.with_timeout(SELFCHECK_TIME), &Cmd::new(&m.shown(SERVER_BIN), &["selfcheck"]));
    let _ = out.write_all(o.as_bytes());
    res.map_err(|e| e.wrap(format!("the self check failed, not confirmed; release {} reverts at {}", p.serial, when(p.deadline))))?;
    // The record going is the moment the update is final.
    clear_pending(m)?;
    m.at("confirmed")?;
    disarm(m, ctx, &p.id);
    let _ = fs::remove_dir_all(m.path(&format!("{BACKUPS}/{}", p.id)));
    record(m, out, now, p.serial, "confirmed", true, &format!("release {} (dryserver {}) is confirmed", p.serial, p.version));
    Ok(())
}

// ---- the guard ----

/// The revert timer fired: the update with this id was not confirmed in
/// its window. The monotonic timer decides, not the wall clock, so a clock
/// that jumped back does not keep an update.
pub fn guard_timer(m: &Machine, ctx: &Ctx, id: &str, now: i64, out: &mut dyn Write) -> Result<()> {
    ensure_dirs(m)?;
    let _lock = lock_wait(m, ctx, GUARD_LOCK_WAIT)?;
    let Some(p) = load_pending(m)? else {
        say(out, "no update waits for confirm, nothing to revert");
        return Ok(());
    };
    if p.id != id {
        say(out, format!("this timer belongs to an earlier update; release {} has its own", p.serial));
        return Ok(());
    }
    let why = format!("it was not confirmed within {}", gotime::duration_string(p.window));
    revert(m, &Ctx::new().with_timeout(REVERT_TIME), p, &why, false, now, out)
}

/// At boot: reverts an update that did not finish applying, whose deadline
/// passed or that saw too many restarts; arms the timer again for the rest
/// of the window otherwise. A clock that went back never makes the wait
/// longer than one window.
pub fn guard_boot(m: &Machine, ctx: &Ctx, now: i64, out: &mut dyn Write) -> Result<()> {
    ensure_dirs(m)?;
    let _lock = lock_wait(m, ctx, LOCK_WAIT)?;
    let Some(mut p) = load_pending(m)? else { return Ok(()) };
    let why = if p.stage != STAGE_ARMED {
        Some("the machine went down before the update finished".to_string())
    } else if now >= p.deadline {
        Some(format!("it was not confirmed by {}", when(p.deadline)))
    } else if p.boots >= MAX_BOOTS {
        Some(format!("the machine restarted {} times without confirming it", p.boots + 1))
    } else {
        None
    };
    let rctx = Ctx::new().with_timeout(REVERT_TIME);
    if let Some(why) = why {
        return revert(m, &rctx, p, &why, true, now, out);
    }
    let window = p.window.clamp(MIN_WINDOW, MAX_WINDOW);
    let left = (p.deadline - now).clamp(1, window);
    p.boots += 1;
    save_pending(m, &p)?;
    disarm(m, ctx, &p.id);
    if let Err(e) = arm(m, ctx, &p.id, p.serial, left) {
        return revert(m, &rctx, p, &format!("its revert timer could not be armed again after the restart: {e}"), true, now, out);
    }
    tell(
        m,
        out,
        now,
        &format!("release {} still waits for confirm; it reverts in {} unless confirmed", p.serial, gotime::duration_string(left)),
    );
    Ok(())
}

// ---- selfcheck ----

/// One line of `dryserver selfcheck`.
#[derive(Debug, Clone, PartialEq)]
pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

fn check(name: &'static str, r: Result<String>) -> Check {
    match r {
        Ok(detail) => Check { name, ok: true, detail },
        Err(e) => Check { name, ok: false, detail: e.to_string().replace('\n', "; ") },
    }
}

/// Whether this binary and the machine around it are sound: the binary
/// runs, config.env loads, the firewall this binary renders passes nft -c,
/// sshd accepts its settings, wg0.conf parses, and so do the state files.
/// Takes a moment and needs no network, so it works with the coordinator
/// down.
pub fn selfcheck(m: &Machine, ctx: &Ctx) -> Vec<Check> {
    let mut v = vec![Check { name: "binary", ok: true, detail: format!("dryserver {} runs", env!("CARGO_PKG_VERSION")) }];
    v.push(check(
        "config",
        Config::load(m.path(CONFIG)).and_then(|c| {
            c.validate()?;
            Ok(format!("{CONFIG} loads"))
        }),
    ));
    let params = machine_params(m);
    v.push(check("firewall", params.clone().and_then(|p| firewall_check(m, ctx, &p))));
    v.push(check("ssh", m.cmd(ctx, "sshd", &["-t", "-f", &m.shown(SSHD_CONFIG)]).map(|_| "sshd -t accepts the settings".to_string())));
    let joined = params.as_ref().map(|p| p.role == Role::Coordinator || p.host_num > 0).unwrap_or(true);
    v.push(check("wireguard", wg_check(m, joined)));
    v.push(check("state", state_check(m, params.as_ref().map(|p| p.role).ok())));
    v
}

/// Prints the checks; an error when any failed.
pub fn print_checks(checks: &[Check], out: &mut dyn Write) -> Result<()> {
    for c in checks {
        say(out, format!("{} {}: {}", if c.ok { "ok  " } else { "FAIL" }, c.name, c.detail));
    }
    let bad = checks.iter().filter(|c| !c.ok).count();
    if bad > 0 {
        bail!("selfcheck: {bad} of {} checks failed", checks.len());
    }
    Ok(())
}

/// The firewall this binary would write, through nft -c, from a scratch
/// file: it loads the kill switch's rules too, as the real one does.
fn firewall_check(m: &Machine, ctx: &Ctx, p: &Params) -> Result<String> {
    let files = sysconf::render(p)?;
    let fw = files.iter().find(|f| f.path == FIREWALL).ok_or_else(|| errf!("this dryserver renders no {FIREWALL}"))?;
    let dir = m.path("/run");
    fsx::mkdir_all(&dir, 0o755)?;
    let tmp = dir.join(format!("dryserver-selfcheck-{}.nft", fsx::hex(&fsx::random_bytes(6))));
    fsx::write_file(&tmp, &fw.content, 0o600)?;
    let res = m.cmd(ctx, "nft", &["-c", "-f", &tmp.display().to_string()]);
    let _ = fs::remove_file(&tmp);
    res.map(|_| format!("the rendered {FIREWALL} passes nft -c"))
}

const WG_INTERFACE_KEYS: &[&str] =
    &["address", "listenport", "privatekey", "postup", "postdown", "preup", "predown", "dns", "mtu", "table", "saveconfig", "fwmark"];
const WG_PEER_KEYS: &[&str] = &["publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive"];

/// wg0.conf: one [Interface] first, known keys only, every peer with a key
/// and an address. Not there is fine before the machine joined.
fn wg_check(m: &Machine, joined: bool) -> Result<String> {
    let text = match fs::read_to_string(m.path(node::WG_CONF)) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound && !joined => return Ok(format!("no {} yet (not joined)", node::WG_CONF)),
        Err(e) => return Err(Error::from(e).wrap(format!("open {}", node::WG_CONF))),
    };
    let peers = parse_wg(&text).map_err(|e| e.wrap(node::WG_CONF))?;
    Ok(format!("{} parses, {peers} peers", node::WG_CONF))
}

fn parse_wg(text: &str) -> Result<usize> {
    let mut section = "";
    let (mut interfaces, mut address) = (0, false);
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if t.starts_with('[') {
            section = match t {
                "[Interface]" => {
                    interfaces += 1;
                    "interface"
                }
                "[Peer]" if interfaces > 0 => "peer",
                "[Peer]" => bail!("line {}: a peer before [Interface]", i + 1),
                _ => bail!("line {}: unknown section {t:?}", i + 1),
            };
            continue;
        }
        let Some((k, _)) = t.split_once('=') else { bail!("line {}: not key = value", i + 1) };
        let k = k.trim().to_ascii_lowercase();
        let known = match section {
            "interface" => WG_INTERFACE_KEYS,
            "peer" => WG_PEER_KEYS,
            _ => bail!("line {}: a setting before [Interface]", i + 1),
        };
        if !known.contains(&k.as_str()) {
            bail!("line {}: unknown setting {k:?}", i + 1);
        }
        address |= section == "interface" && k == "address";
    }
    if interfaces != 1 {
        bail!("{interfaces} [Interface] sections, not 1");
    }
    if !address {
        bail!("the interface has no Address");
    }
    let peers = quarantine::parse_peers(text);
    for p in &peers {
        use base64::Engine;
        let key = base64::engine::general_purpose::STANDARD.decode(&p.key).unwrap_or_default();
        if key.len() != 32 {
            bail!("peer {:?} has no valid PublicKey", p.name);
        }
        if p.allowed.is_empty() {
            bail!("peer {:?} has no AllowedIPs", p.name);
        }
    }
    Ok(peers.len())
}

/// dryserver's own state files parse as this binary reads them, and are in
/// a format it knows.
fn state_check(m: &Machine, role: Option<Role>) -> Result<String> {
    let mut n = 0;
    let mut seen = |found: bool| n += usize::from(found);
    seen(load_installed(m)?.is_some());
    seen(load_pending(m)?.is_some());
    seen(read_json::<Last>(m, LAST)?.is_some());
    seen(read_json::<node::State>(m, node::JOIN_STATE)?.is_some());
    seen(read_json::<quarantine::State>(m, quarantine::STATE_FILE)?.is_some());
    seen(read_json::<Envelope>(m, node::SIGNED_FILE)?.is_some());
    if role == Some(Role::Coordinator) {
        seen(read_json::<registry::State>(m, registry::DEFAULT_PATH)?.is_some());
    }
    let format = state_format(m)?;
    let known = known_format(m.migrations)?;
    if format > known {
        bail!("the state files are in format {format}, newer than this dryserver knows ({known})");
    }
    Ok(format!("{n} state files parse, format {format}"))
}

// ---- status ----

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Status {
    /// The version of the binary answering.
    pub running: String,
    pub installed: Option<ReleaseInfo>,
    pub pending: Option<PendingInfo>,
    pub last: Option<Last>,
    /// State files that could not be read.
    pub problems: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReleaseInfo {
    pub serial: u64,
    pub version: String,
    pub k3s: String,
    pub arch_date: String,
    pub urgent: bool,
    pub notes: String,
    pub expires: i64,
    pub stale: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PendingInfo {
    pub serial: u64,
    pub version: String,
    pub previous: Option<u64>,
    pub stage: String,
    pub applied: i64,
    pub deadline: i64,
    pub seconds_left: i64,
    pub boots: u32,
    pub files: Vec<String>,
}

/// What `update status` shows; reads only.
pub fn status(m: &Machine, now: i64) -> Status {
    let mut problems = Vec::new();
    let installed = match load_installed(m) {
        Ok(i) => i.map(|(_, r)| ReleaseInfo {
            serial: r.serial,
            version: r.dryserver.version.clone(),
            k3s: r.k3s.version.clone(),
            arch_date: r.arch_date.clone(),
            urgent: r.urgent,
            notes: r.notes.clone(),
            expires: r.expires,
            stale: now >= r.expires,
        }),
        Err(e) => {
            problems.push(e.to_string());
            None
        }
    };
    let pending = match load_pending(m) {
        Ok(p) => p.map(|p| PendingInfo {
            serial: p.serial,
            version: p.version.clone(),
            previous: p.previous,
            stage: p.stage.clone(),
            applied: p.applied,
            deadline: p.deadline,
            seconds_left: (p.deadline - now).max(0),
            boots: p.boots,
            files: p.files.iter().map(|f| f.path.clone()).collect(),
        }),
        Err(e) => {
            problems.push(e.to_string());
            None
        }
    };
    let last = read_json::<Last>(m, LAST).unwrap_or_else(|e| {
        problems.push(e.to_string());
        None
    });
    Status { running: env!("CARGO_PKG_VERSION").into(), installed, pending, last, problems }
}

pub fn print_status(s: &Status, out: &mut dyn Write) {
    say(out, format!("running: dryserver {}", s.running));
    match &s.installed {
        Some(r) => {
            let notes = if r.notes.is_empty() { String::new() } else { format!(": {}", r.notes) };
            let stale = if r.stale { format!(" (expired {}: no newer release arrived)", when(r.expires)) } else { String::new() };
            say(
                out,
                format!("installed: release {} (dryserver {}, k3s {}, Arch {}){notes}{stale}", r.serial, r.version, r.k3s, r.arch_date),
            );
        }
        None => say(out, "installed: no release yet (the dryserver this machine was installed with)"),
    }
    if let Some(p) = &s.pending {
        say(
            out,
            format!(
                "pending: release {} ({}), reverts by itself at {} (in {}) unless confirmed: dryserver update confirm",
                p.serial,
                p.stage,
                when(p.deadline),
                gotime::duration_string(p.seconds_left)
            ),
        );
    }
    if let Some(l) = &s.last {
        say(
            out,
            format!("last: {} {} release {}{}: {}", when(l.at), l.action, l.serial, if l.ok { "" } else { " (with problems)" }, l.message),
        );
    }
    for p in &s.problems {
        say(out, format!("problem: {p}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release::{Binary, K3s};
    use crate::signed::fake;
    use crate::testutil::{TempDir, put};
    use chrono::{TimeZone, Utc};
    use sha2::{Digest, Sha256};
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, Once, OnceLock, Weak};

    const OLD: &[u8] = b"\x7fELF dryserver 0.1.0";
    const NEW: &[u8] = b"\x7fELF dryserver 0.2.0, with the fix";
    const OLD_FIREWALL: &str = "#!/usr/bin/nft -f\n# the firewall of the older dryserver\n";
    const OLD_SSHD: &str = "# the SSH settings of the older dryserver\nPasswordAuthentication no\n";
    const SSHD_DROPIN: &str = "/etc/ssh/sshd_config.d/10-dryserver.conf";
    const SYNC_UNIT: &str = "/etc/systemd/system/dryserver-sync.service";
    const WG0: &str = "# dryserver mesh\n[Interface]\nAddress = 10.66.0.5/24\nListenPort = 51820\n\
        PostUp = wg set %i private-key /etc/wireguard/wg0.key\n\n# coord\n[Peer]\n\
        PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAllowedIPs = 10.66.0.1/32\n\
        Endpoint = 192.168.1.50:51820\nPersistentKeepalive = 25\n";

    fn now() -> i64 {
        Utc.with_ymd_and_hms(2026, 11, 21, 12, 0, 0).unwrap().timestamp()
    }

    fn sha(b: &[u8]) -> String {
        fsx::hex(&Sha256::digest(b))
    }

    fn rel(serial: u64, bin: &[u8]) -> Release {
        Release {
            serial,
            created: now() - 3600,
            expires: now() + 30 * release::DAY,
            dryserver: Binary { version: "0.2.0".into(), sha256: sha(bin), size: bin.len() as u64 },
            k3s: K3s { version: "v1.37.2+k3s1".into(), sha256: "b".repeat(64) },
            arch_date: "2026/11/19".into(),
            rollback: false,
            urgent: false,
            notes: "fixes the join timeout".into(),
        }
    }

    /// What the fake commands do.
    #[derive(Clone, Copy, Default)]
    struct Script {
        /// The new binary dies as soon as it starts.
        new_crashes: bool,
        /// update activate dies before doing anything, or after all of it.
        activate_dies: bool,
        activate_dies_late: bool,
        /// nft -c fails on /etc/nftables.conf when it holds this text.
        nft_fails: Option<&'static str>,
        /// nft -c fails on the self check's scratch firewall.
        candidate_nft_fails: bool,
        /// sshd -t fails when the drop-in holds this text.
        sshd_fails: Option<&'static str>,
        verify_fails: bool,
        systemd_run_fails: bool,
        selfcheck_fails: bool,
    }

    struct Fake {
        root: PathBuf,
        owner: Mutex<u32>,
        hook: Mutex<Hook>,
        migrations: Mutex<&'static [Migration]>,
        script: Mutex<Script>,
        ran: Mutex<Vec<String>>,
        /// The firewall each `nft -f` loaded, the SSH drop-in each sshd
        /// reload read.
        loaded: Mutex<Vec<String>>,
        reloaded_sshd: Mutex<Vec<String>>,
        me: OnceLock<Weak<Fake>>,
    }

    fn noop() -> Hook {
        Arc::new(|_| Ok(()))
    }

    impl Fake {
        fn machine(&self) -> Machine {
            Machine {
                root: self.root.clone(),
                run: self.me.get().unwrap().upgrade().unwrap(),
                verifier: Arc::new(fake::Key("admin")),
                owner: *self.owner.lock().unwrap(),
                hook: self.hook.lock().unwrap().clone(),
                migrations: *self.migrations.lock().unwrap(),
            }
        }

        fn ran(&self) -> Vec<String> {
            self.ran.lock().unwrap().clone()
        }

        fn index(&self, prefix: &str) -> Option<usize> {
            self.ran().iter().position(|c| c.starts_with(prefix))
        }

        fn has(&self, prefix: &str) -> bool {
            self.index(prefix).is_some()
        }
    }

    impl Runner for Fake {
        fn run(&self, ctx: &Ctx, c: &Cmd) -> (String, Result<()>) {
            let root = self.root.display().to_string();
            self.ran.lock().unwrap().push(c.to_string().replace(&root, ""));
            let s = *self.script.lock().unwrap();
            let name = c.name.replace(&root, "");
            let args: Vec<&str> = c.args.iter().map(String::as_str).collect();
            let fail = |msg: &str| (String::new(), Err(errf!("{} failed: {msg}", c.name)));
            let ok = || (String::new(), Ok(()));
            let read = |p: &str| fs::read_to_string(p).unwrap_or_default();
            let dropin = || read(&fsx::under(&self.root, SSHD_DROPIN).display().to_string());
            match (name.as_str(), args.as_slice()) {
                (NEW_BIN, ["selfcheck"]) if s.new_crashes => fail("signal 11 (core dumped)"),
                (_, ["selfcheck"]) if s.selfcheck_fails => fail("exit status 1"),
                (_, ["selfcheck"]) => {
                    let mut o = Vec::new();
                    let r = print_checks(&selfcheck(&self.machine(), ctx), &mut o);
                    (String::from_utf8_lossy(&o).into_owned(), r)
                }
                (SERVER_BIN, ["update", "activate", "--id", id]) => {
                    if s.activate_dies {
                        return fail("signal 6 (aborted)");
                    }
                    let mut o = Vec::new();
                    let r = activate(&self.machine(), ctx, id, &mut o);
                    if s.activate_dies_late {
                        return fail("signal 6 (aborted)");
                    }
                    (String::from_utf8_lossy(&o).into_owned(), r)
                }
                ("nft", ["-c", "-f", f]) => match s.nft_fails {
                    Some(t) if f.ends_with(FIREWALL) && read(f).contains(t) => fail("syntax error"),
                    _ if s.candidate_nft_fails && f.contains("dryserver-selfcheck-") => fail("syntax error"),
                    _ => ok(),
                },
                ("nft", ["-f", f]) => {
                    self.loaded.lock().unwrap().push(read(f));
                    ok()
                }
                ("sshd", ["-t", ..]) => match s.sshd_fails {
                    Some(t) if dropin().contains(t) => fail("Bad configuration option"),
                    _ => ok(),
                },
                ("systemctl", ["reload", "sshd.service"]) => {
                    self.reloaded_sshd.lock().unwrap().push(dropin());
                    ok()
                }
                ("systemd-analyze", _) if s.verify_fails => fail("Unknown key name"),
                ("systemd-run", _) if s.systemd_run_fails => fail("Failed to connect to bus"),
                (K3S_BIN, ["--version"]) => ("k3s version v1.37.2+k3s1 (12ab34cd)\ngo version go1.24.1\n".into(), Ok(())),
                _ => ok(),
            }
        }
    }

    /// A server (host 5) that runs the older dryserver: the files it wrote
    /// are this binary's render, except an older firewall and SSH setting.
    struct Lab {
        _dir: TempDir,
        fake: Arc<Fake>,
    }

    impl Lab {
        fn new() -> Lab {
            let dir = TempDir::new();
            let root = dir.path().to_path_buf();
            let fake = Arc::new(Fake {
                root: root.clone(),
                owner: Mutex::new(fsx::geteuid()),
                hook: Mutex::new(noop()),
                migrations: Mutex::new(&[]),
                script: Mutex::default(),
                ran: Mutex::default(),
                loaded: Mutex::default(),
                reloaded_sshd: Mutex::default(),
                me: OnceLock::new(),
            });
            fake.me.set(Arc::downgrade(&fake)).ok();
            let cfg = Config {
                coord_lan_ip: "192.168.1.50".into(),
                admin_ssh_pubkey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest admin@desktop".into(),
                ..Config::default()
            };
            put(&root, CONFIG, cfg.render());
            put(&root, HOSTNAME_FILE, "node-3a2f\n");
            put(&root, ROLE_FILE, "node\n");
            put(&root, node::JOIN_STATE, "{\"host\": 5}\n");
            put(&root, node::SWITCH_MAC_FILE, "52:54:66:aa:bb:cc\n");
            put(&root, node::WG_CONF, WG0);
            let lab = Lab { _dir: dir, fake };
            for f in render_managed(&lab.m()).unwrap() {
                lab.write(&f.path, f.content.as_bytes(), f.mode);
            }
            lab.write(FIREWALL, OLD_FIREWALL.as_bytes(), 0o600);
            lab.write(SSHD_DROPIN, OLD_SSHD.as_bytes(), 0o644);
            lab.write(SERVER_BIN, OLD, 0o755);
            ensure_dirs(&lab.m()).unwrap();
            // Whatever the umask of whoever runs the tests.
            for d in ["/var", "/var/lib"] {
                fsx::chmod(lab.p(d), 0o755).unwrap();
            }
            lab
        }

        fn m(&self) -> Machine {
            self.fake.machine()
        }

        fn p(&self, path: &str) -> PathBuf {
            fsx::under(&self.fake.root, path)
        }

        /// A new file (a read-only one cannot be opened for writing).
        fn write(&self, path: &str, data: &[u8], mode: u32) {
            let _ = fs::remove_file(self.p(path));
            put(&self.fake.root, path, data);
            fsx::chmod(self.p(path), mode).unwrap();
        }

        fn get(&self, path: &str) -> String {
            fs::read_to_string(self.p(path)).unwrap_or_default()
        }

        fn bytes(&self, path: &str) -> Vec<u8> {
            fs::read(self.p(path)).unwrap_or_default()
        }

        fn script(&self, f: impl FnOnce(&mut Script)) {
            f(&mut self.fake.script.lock().unwrap());
        }

        fn hook(&self, h: Hook) {
            *self.fake.hook.lock().unwrap() = h;
        }

        fn release_file(&self, r: &Release) -> PathBuf {
            self.envelope_file(r.serial, &release::seal(&fake::Key("admin"), r).unwrap())
        }

        fn envelope_file(&self, n: u64, env: &Envelope) -> PathBuf {
            let p = self.p(&format!("/tmp/release-{n}.json"));
            fsx::mkdir_all(fsx::dir(&p), 0o755).unwrap();
            fs::write(&p, serde_json::to_string(env).unwrap()).unwrap();
            p
        }

        /// The binary in the staging directory, as distribution leaves it.
        fn staged(&self, bin: &[u8]) -> PathBuf {
            let p = self.p(&format!("{STAGING}/dryserver"));
            fs::write(&p, bin).unwrap();
            fsx::chmod(&p, 0o600).unwrap();
            p
        }

        fn opts(&self, r: &Release, binary: PathBuf) -> Apply {
            Apply { release: self.release_file(r), binary, brain_k3s: String::new(), window: WINDOW }
        }

        fn apply_at(&self, r: &Release, at: i64) -> Result<()> {
            let a = self.opts(r, self.staged(NEW));
            apply(&self.m(), &Ctx::new(), &a, at, &mut Vec::new())
        }

        fn apply(&self, r: &Release) -> Result<()> {
            self.apply_at(r, now())
        }

        fn pending(&self) -> Option<Pending> {
            load_pending(&self.m()).unwrap()
        }

        fn last(&self) -> Last {
            read_json::<Last>(&self.m(), LAST).unwrap().unwrap_or_default()
        }

        fn rendered(&self, path: &str) -> String {
            render_managed(&self.m()).unwrap().into_iter().find(|f| f.path == path).unwrap().content
        }

        /// As before the update: the old binary and files, no record, no
        /// leftovers.
        fn assert_old(&self, why: &str) {
            assert_eq!(self.bytes(SERVER_BIN), OLD, "{why}: the binary");
            assert_eq!(self.get(FIREWALL), OLD_FIREWALL, "{why}: the firewall");
            assert_eq!(self.get(SSHD_DROPIN), OLD_SSHD, "{why}: the SSH settings");
            assert!(self.pending().is_none(), "{why}: a pending record is left");
            assert!(load_installed(&self.m()).unwrap().is_none(), "{why}: installed.json");
            self.assert_tidy(why);
        }

        /// The update in place, waiting for confirm.
        fn assert_new(&self, why: &str) {
            assert_eq!(self.bytes(SERVER_BIN), NEW, "{why}: the binary");
            assert_eq!(self.bytes(PREV_BIN), OLD, "{why}: dryserver.prev");
            assert_eq!(self.get(FIREWALL), self.rendered(FIREWALL), "{why}: the firewall");
            assert_eq!(self.get(SSHD_DROPIN), self.rendered(SSHD_DROPIN), "{why}: the SSH settings");
        }

        /// No temporary file outside the update's own directory. The boot
        /// unit is written before there is a record; a cut then leaves its
        /// temporary file, which systemd ignores (no unit suffix) and the
        /// next apply replaces.
        fn assert_tidy(&self, why: &str) {
            for t in [NEW_BIN, PREV_TMP, RESTORE_TMP] {
                assert!(!self.p(t).exists(), "{why}: {t} is left");
            }
            fn walk(d: &Path, skip: &[PathBuf], out: &mut Vec<PathBuf>) {
                for e in fs::read_dir(d).into_iter().flatten().flatten() {
                    let p = e.path();
                    if skip.contains(&p) {
                        continue;
                    }
                    if p.is_dir() && !p.is_symlink() {
                        walk(&p, skip, out);
                    } else if p.display().to_string().ends_with(TMP_SUFFIX) {
                        out.push(p);
                    }
                }
            }
            let mut left = Vec::new();
            walk(&self.fake.root, &[self.p(DIR), tmp_of(&self.p(GUARD_UNIT_PATH))], &mut left);
            assert!(left.is_empty(), "{why}: temporary files left: {left:?}");
        }
    }

    #[test]
    fn apply_then_confirm() {
        let lab = Lab::new();
        let mut out = Vec::new();
        let a = lab.opts(&rel(7, NEW), lab.staged(NEW));
        apply(&lab.m(), &Ctx::new(), &a, now(), &mut out).unwrap();
        let said = String::from_utf8_lossy(&out).into_owned();
        assert!(said.contains("release 7 is applied") && said.contains("dryserver update confirm"), "{said}");
        lab.assert_new("applied");
        assert_eq!(std::fs::metadata(lab.p(SERVER_BIN)).unwrap().permissions().mode() & 0o7777, 0o755);
        assert!(!lab.p(&format!("{STAGING}/dryserver")).exists(), "the staged binary is installed, not kept");

        // Only what changed was written, each with its old content kept.
        let p = lab.pending().unwrap();
        assert_eq!((p.stage.as_str(), p.serial, p.previous, p.deadline), (STAGE_ARMED, 7, None, now() + WINDOW));
        let paths: Vec<&str> = p.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, [FIREWALL, SSHD_DROPIN, INSTALLED]);
        assert_eq!(lab.get(p.files[0].backup.as_deref().unwrap()), OLD_FIREWALL);
        assert_eq!((p.files[0].mode, p.files[1].mode), (0o600, 0o644));
        assert_eq!(p.files[2].backup, None, "installed.json is new: a revert removes it");
        assert_eq!(load_installed(&lab.m()).unwrap().unwrap().1, rel(7, NEW));
        assert_eq!((p.prev_sha256.as_str(), p.new_sha256.as_str()), (sha(OLD).as_str(), sha(NEW).as_str()));

        // The order: timer first, then the new binary's check, then it
        // takes over; files are checked before anything reloads them.
        let f = &lab.fake;
        let order = [
            "systemctl enable --quiet dryserver-update-guard.service",
            "systemd-run --unit=dryserver-update-revert-",
            "/usr/local/bin/.dryserver.new selfcheck",
            "/usr/local/bin/dryserver update activate --id",
            "nft -c -f /etc/nftables.conf",
            "sshd -t -f /etc/ssh/sshd_config",
            "nft -f /etc/nftables.conf",
            "systemctl reload sshd.service",
        ];
        let ran = f.ran();
        let mut from = 0;
        for o in order {
            let i = ran[from..].iter().position(|c| c.starts_with(o)).unwrap_or_else(|| panic!("{o:?} missing or out of order: {ran:#?}"));
            from += i + 1;
        }
        let timer = f.ran().into_iter().find(|c| c.starts_with("systemd-run")).unwrap();
        let id = &p.id;
        assert!(timer.contains("--on-active=600s"), "{timer}");
        assert!(
            timer.ends_with(&format!(
                "/bin/sh -c /usr/local/bin/dryserver.prev update guard --id {id} || /usr/local/bin/dryserver update guard --id {id}"
            )),
            "the timer must run the previous binary first: {timer}"
        );
        assert!(!f.ran().iter().any(|c| c.contains("restart sshd") || c.contains("stop sshd")), "sshd must only reload");
        assert!(!f.has("systemd-analyze"), "no unit changed, nothing to verify");
        assert_eq!(lab.get(GUARD_UNIT_PATH), GUARD_UNIT_TEXT, "the boot half of the guard is installed");
        assert_eq!(*f.loaded.lock().unwrap(), [lab.rendered(FIREWALL)]);
        assert_eq!(lab.last().action, "applied");

        // Confirm: the record and the backups go, the timer stops.
        f.ran.lock().unwrap().clear();
        confirm(&lab.m(), &Ctx::new(), Some(7), now() + 60, &mut Vec::new()).unwrap();
        assert!(lab.pending().is_none());
        assert!(!lab.p(&format!("{BACKUPS}/{id}")).exists(), "the backups outlived the confirm");
        assert!(f.has("/usr/local/bin/dryserver selfcheck"), "{:?}", f.ran());
        assert!(f.has(&format!("systemctl stop dryserver-update-revert-{id}.timer")), "{:?}", f.ran());
        assert_eq!(load_installed(&lab.m()).unwrap().unwrap().1.serial, 7);
        assert_eq!((lab.last().action.as_str(), lab.last().ok), ("confirmed", true));
        lab.assert_tidy("confirmed");

        // The same release again does nothing; so does confirming it again.
        f.ran.lock().unwrap().clear();
        lab.apply_at(&rel(7, NEW), now() + 120).unwrap();
        assert_eq!(f.ran(), ["/usr/local/bin/k3s --version"], "anything but a read");
        assert!(lab.pending().is_none());
        confirm(&lab.m(), &Ctx::new(), Some(7), now(), &mut Vec::new()).unwrap();
        let e = confirm(&lab.m(), &Ctx::new(), None, now(), &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("no update waits for confirm"), "{e}");
    }

    struct PowerCut;

    /// The simulated power cuts are panics; only they are kept quiet.
    fn quiet_power_cuts() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let default = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                if !info.payload().is::<PowerCut>() {
                    default(info)
                }
            }));
        });
    }

    /// Cuts the power at the n-th step.
    fn cut_at(n: usize) -> (Hook, Arc<AtomicUsize>) {
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        let h: Hook = Arc::new(move |_| {
            if c.fetch_add(1, Ordering::SeqCst) == n {
                std::panic::panic_any(PowerCut);
            }
            Ok(())
        });
        (h, count)
    }

    #[test]
    fn power_cut_at_every_step_of_apply() {
        quiet_power_cuts();
        let (mut reverted, mut kept) = (0, 0);
        for n in 0.. {
            assert!(n < 500, "apply never finished");
            let lab = Lab::new();
            let (hook, count) = cut_at(n);
            lab.hook(hook);
            let res = catch_unwind(AssertUnwindSafe(|| lab.apply(&rel(7, NEW))));
            lab.hook(noop());
            let bin = lab.bytes(SERVER_BIN);
            assert!(bin == OLD || bin == NEW, "step {n}: the installed binary is neither the old nor the new one");
            let Err(_) = res else {
                res.unwrap().unwrap();
                assert!(count.load(Ordering::SeqCst) <= n, "step {n}");
                assert!(n >= 15, "too few steps were tried: {n}");
                assert!(reverted >= 10 && kept >= 2, "reverted {reverted}, kept {kept}");
                break;
            };
            // The machine starts again, without network.
            lab.fake.ran.lock().unwrap().clear();
            guard_boot(&lab.m(), &Ctx::new(), now() + 30, &mut Vec::new()).unwrap();
            match lab.pending() {
                None => {
                    reverted += 1;
                    lab.assert_old(&format!("cut at step {n}"));
                }
                Some(p) => {
                    kept += 1;
                    // Cut after the update was complete: it keeps waiting.
                    assert_eq!(p.stage, STAGE_ARMED, "step {n}");
                    lab.assert_new(&format!("cut at step {n}"));
                    assert!(lab.fake.has(&format!("systemd-run --unit=dryserver-update-revert-{} --on-active=570s", p.id)), "step {n}");
                }
            }
            // At boot nothing is running yet: nothing to reload.
            assert!(!lab.fake.has("nft -f") && !lab.fake.has("systemctl reload"), "step {n}: {:?}", lab.fake.ran());
        }
    }

    #[test]
    fn power_cut_at_every_step_of_revert() {
        quiet_power_cuts();
        for n in 0.. {
            assert!(n < 500, "revert never finished");
            let lab = Lab::new();
            lab.apply(&rel(7, NEW)).unwrap();
            let (hook, _) = cut_at(n);
            lab.hook(hook);
            let res = catch_unwind(AssertUnwindSafe(|| revert_by_hand(&lab.m(), &Ctx::new(), now() + 60, &mut Vec::new())));
            lab.hook(noop());
            let bin = lab.bytes(SERVER_BIN);
            assert!(bin == OLD || bin == NEW, "step {n}");
            if let Ok(done) = res {
                done.unwrap();
                lab.assert_old("reverted");
                assert!(n >= 5, "too few steps were tried: {n}");
                break;
            }
            guard_boot(&lab.m(), &Ctx::new(), now() + 90, &mut Vec::new()).unwrap();
            match lab.pending() {
                // The revert finished at boot.
                None => lab.assert_old(&format!("cut at step {n}")),
                // Cut before the revert had begun: the update still waits.
                Some(p) => {
                    assert_eq!(p.stage, STAGE_ARMED, "step {n}");
                    lab.assert_new(&format!("cut at step {n}"));
                }
            }
        }
    }

    #[test]
    fn power_cut_at_every_step_of_confirm() {
        quiet_power_cuts();
        for n in 0.. {
            assert!(n < 500, "confirm never finished");
            let lab = Lab::new();
            lab.apply(&rel(7, NEW)).unwrap();
            let (hook, _) = cut_at(n);
            lab.hook(hook);
            let res = catch_unwind(AssertUnwindSafe(|| confirm(&lab.m(), &Ctx::new(), None, now() + 60, &mut Vec::new())));
            lab.hook(noop());
            if let Ok(done) = res {
                done.unwrap();
                assert!(n >= 2, "too few steps were tried: {n}");
                break;
            }
            guard_boot(&lab.m(), &Ctx::new(), now() + 90, &mut Vec::new()).unwrap();
            lab.assert_new(&format!("cut at step {n}"));
            if let Some(p) = lab.pending() {
                assert_eq!(p.stage, STAGE_ARMED, "step {n}");
            }
            assert_eq!(load_installed(&lab.m()).unwrap().unwrap().1.serial, 7, "step {n}");
        }
    }

    #[test]
    fn the_new_binary_crashes_at_start() {
        let lab = Lab::new();
        lab.script(|s| s.new_crashes = true);
        let e = lab.apply(&rel(7, NEW)).unwrap_err().to_string();
        assert!(e.contains("failed its self check, nothing was switched") && e.contains("signal 11"), "{e}");
        lab.assert_old("a binary that crashes");
        assert!(!lab.p(PREV_BIN).exists(), "nothing was switched, nothing to keep");
        assert!(!lab.fake.has("/usr/local/bin/dryserver update activate"));
        let last = lab.last();
        assert!(last.action == "reverted" && last.ok && last.message.contains("signal 11"), "{last:?}");
        assert!(fs::read_to_string(lab.p(LOG)).unwrap().contains("failed its self check"));
    }

    #[test]
    fn the_new_binary_dies_taking_over() {
        for late in [false, true] {
            let lab = Lab::new();
            lab.script(|s| (s.activate_dies, s.activate_dies_late) = (!late, late));
            let e = lab.apply(&rel(7, NEW)).unwrap_err().to_string();
            assert!(e.contains("could not take over") && e.contains("signal 6"), "{e}");
            lab.assert_old(&format!("late {late}"));
            assert_eq!(lab.bytes(PREV_BIN), OLD);
            if late {
                // It had reloaded the new firewall; the old one is loaded again.
                assert_eq!(*lab.fake.loaded.lock().unwrap(), [lab.rendered(FIREWALL), OLD_FIREWALL.to_string()]);
                assert_eq!(*lab.fake.reloaded_sshd.lock().unwrap(), [lab.rendered(SSHD_DROPIN), OLD_SSHD.to_string()]);
            }
        }
    }

    #[test]
    fn a_firewall_that_fails_nft_is_never_loaded() {
        // Caught by the new binary's own check, before anything switched.
        let lab = Lab::new();
        lab.script(|s| s.candidate_nft_fails = true);
        let e = lab.apply(&rel(7, NEW)).unwrap_err().to_string();
        assert!(e.contains("failed its self check"), "{e}");
        lab.assert_old("candidate");
        // Caught after it was written.
        let lab = Lab::new();
        lab.script(|s| s.nft_fails = Some("dryserver-autocut"));
        let e = lab.apply(&rel(7, NEW)).unwrap_err().to_string();
        assert!(e.contains("the new firewall") && e.contains("syntax error"), "{e}");
        lab.assert_old("written");
        for fw in lab.fake.loaded.lock().unwrap().iter() {
            assert_eq!(fw, OLD_FIREWALL, "the failing firewall was loaded");
        }
        assert!(lab.fake.reloaded_sshd.lock().unwrap().iter().all(|s| s == OLD_SSHD));
    }

    #[test]
    fn ssh_settings_that_fail_sshd_t_are_never_loaded() {
        let lab = Lab::new();
        lab.script(|s| s.sshd_fails = Some("AllowAgentForwarding no"));
        let e = lab.apply(&rel(7, NEW)).unwrap_err().to_string();
        assert!(e.contains("the new SSH settings") && e.contains("Bad configuration option"), "{e}");
        lab.assert_old("sshd -t");
        assert!(lab.fake.reloaded_sshd.lock().unwrap().iter().all(|s| s == OLD_SSHD), "sshd reloaded the failing settings");
        assert!(!lab.fake.ran().iter().any(|c| c.contains("restart")), "{:?}", lab.fake.ran());
        // Settings sshd cannot read are never reloaded on the way back
        // either: sshd keeps what it runs with.
        let lab = Lab::new();
        lab.apply(&rel(7, NEW)).unwrap();
        lab.script(|s| s.sshd_fails = Some("older dryserver"));
        let e = revert_by_hand(&lab.m(), &Ctx::new(), now(), &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("sshd keeps the ones it has"), "{e}");
        assert_eq!(lab.get(SSHD_DROPIN), OLD_SSHD);
        assert!(lab.pending().is_none() && !lab.last().ok);
    }

    #[test]
    fn disk_full_while_copying() {
        let lab = Lab::new();
        lab.hook(Arc::new(|p| if p == "copy" { Err(io::Error::from_raw_os_error(libc::ENOSPC)) } else { Ok(()) }));
        let e = lab.apply(&rel(7, NEW)).unwrap_err().to_string();
        assert!(e.contains("no space left on device"), "{e}");
        lab.assert_old("disk full");
        assert!(!lab.p(NEW_BIN).exists(), "a half copy is left");
        // Full while writing a system file: the same way back.
        let lab = Lab::new();
        let writes = Arc::new(AtomicUsize::new(0));
        let w = writes.clone();
        lab.hook(Arc::new(move |p| {
            // The first writes are the record and the boot unit; fail a
            // later one, inside the new binary's half.
            if p == "write" && w.fetch_add(1, Ordering::SeqCst) == 4 { Err(io::Error::from_raw_os_error(libc::ENOSPC)) } else { Ok(()) }
        }));
        let e = lab.apply(&rel(7, NEW)).unwrap_err().to_string();
        assert!(e.contains("no space left on device"), "{e}");
        lab.hook(noop());
        lab.assert_old("disk full in the files");
    }

    #[test]
    fn the_staging_directory_must_be_roots_alone() {
        let refused = |lab: &Lab, a: Apply, want: &str| {
            let e = apply(&lab.m(), &Ctx::new(), &a, now(), &mut Vec::new()).unwrap_err().to_string();
            assert!(e.contains(want), "want {want:?} in {e}");
            lab.assert_old(want);
            assert!(!lab.fake.has("systemd-run") && !lab.p(PREV_BIN).exists(), "{want}: something changed");
        };
        for (dir, mode) in [(STAGING, 0o777), (STAGING, 0o770), (DIR, 0o722), ("/var/lib", 0o775)] {
            let lab = Lab::new();
            let a = lab.opts(&rel(7, NEW), lab.staged(NEW));
            fsx::chmod(lab.p(dir), mode).unwrap();
            refused(&lab, a, "can be written by others than root");
        }
        // Not root's.
        let lab = Lab::new();
        let a = lab.opts(&rel(7, NEW), lab.staged(NEW));
        *lab.fake.owner.lock().unwrap() = fsx::geteuid().wrapping_add(1);
        refused(&lab, a, "not root");
        // The staged file: writable by others, a second name, a link.
        let lab = Lab::new();
        let staged = lab.staged(NEW);
        fsx::chmod(&staged, 0o622).unwrap();
        refused(&lab, lab.opts(&rel(7, NEW), staged), "can be written by others");
        let lab = Lab::new();
        let staged = lab.staged(NEW);
        fs::hard_link(&staged, lab.p("/tmp-other-name")).unwrap();
        refused(&lab, lab.opts(&rel(7, NEW), staged), "hard links");
        let lab = Lab::new();
        let target = lab.p("/elsewhere");
        fs::write(&target, NEW).unwrap();
        let link = lab.p(&format!("{STAGING}/dryserver"));
        std::os::unix::fs::symlink(&target, &link).unwrap();
        refused(&lab, lab.opts(&rel(7, NEW), link), "symbolic link");
        // A link given from outside staging is not followed either.
        let lab = Lab::new();
        let link = lab.p("/tmp-link");
        std::os::unix::fs::symlink(lab.staged(NEW), &link).unwrap();
        refused(&lab, lab.opts(&rel(7, NEW), link), "symbolic link");
        // The staging directory itself a link.
        let lab = Lab::new();
        let a = lab.opts(&rel(7, NEW), lab.p("/somewhere/dryserver"));
        fs::remove_dir(lab.p(STAGING)).unwrap();
        fsx::mkdir_all(lab.p("/somewhere"), 0o700).unwrap();
        std::os::unix::fs::symlink(lab.p("/somewhere"), lab.p(STAGING)).unwrap();
        fs::write(lab.p("/somewhere/dryserver"), NEW).unwrap();
        refused(&lab, a, "symbolic link");
        // The wrong binary, or one of another size.
        let lab = Lab::new();
        refused(&lab, lab.opts(&rel(7, NEW), lab.staged(b"\x7fELF short")), "bytes, the release says");
        let lab = Lab::new();
        refused(&lab, lab.opts(&rel(7, NEW), lab.staged(b"\x7fELF dryserver 0.2.0, with the fiX")), "is not the one the release names");
    }

    #[test]
    fn a_binary_from_outside_staging_is_copied_in_first() {
        let lab = Lab::new();
        let outside = lab.p("/tmp/dryserver");
        fsx::mkdir_all(fsx::dir(&outside), 0o755).unwrap();
        fs::write(&outside, NEW).unwrap();
        fsx::chmod(&outside, 0o666).unwrap();
        apply(&lab.m(), &Ctx::new(), &lab.opts(&rel(7, NEW), outside.clone()), now(), &mut Vec::new()).unwrap();
        lab.assert_new("copied in");
        assert_eq!(fs::read(&outside).unwrap(), NEW, "the source is left alone");
    }

    #[test]
    fn releases_that_check_refuses() {
        let lab = Lab::new();
        lab.apply(&rel(7, NEW)).unwrap();
        confirm(&lab.m(), &Ctx::new(), None, now(), &mut Vec::new()).unwrap();
        let before = lab.fake.ran().len();
        let refused = |r: &Release, want: &str| {
            let e = lab.apply(r).unwrap_err().to_string();
            assert!(e.contains(want), "want {want:?} in {e}");
            assert!(lab.pending().is_none(), "{want}");
        };
        // Older than the installed one, even marked rollback.
        refused(&rel(6, NEW), "older than the installed release 7");
        refused(&Release { rollback: true, ..rel(6, NEW) }, "older than the installed release 7");
        // An older dryserver with a higher serial needs rollback.
        let mut older = rel(8, NEW);
        older.dryserver.version = "0.1.9".into();
        refused(&older, "sign it with rollback");
        // k3s newer than the coordinator's (this server's agent stands in).
        let mut ahead = rel(8, NEW);
        ahead.k3s.version = "v1.38.0+k3s1".into();
        refused(&ahead, "newer than the brain's");
        // Signed with another key, or not a release at all.
        let forged = release::seal(&fake::Key("intruder"), &rel(9, NEW)).unwrap();
        let a = Apply { release: lab.envelope_file(99, &forged), ..lab.opts(&rel(9, NEW), lab.staged(NEW)) };
        let e = apply(&lab.m(), &Ctx::new(), &a, now(), &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("bad signature"), "{e}");
        for junk in ["", "not json", &"x".repeat(MAX_ENVELOPE as usize + 1)] {
            let p = lab.p("/tmp/junk.json");
            fs::write(&p, junk).unwrap();
            let a = Apply { release: p, ..lab.opts(&rel(9, NEW), lab.staged(NEW)) };
            assert!(apply(&lab.m(), &Ctx::new(), &a, now(), &mut Vec::new()).is_err(), "{junk:.20}");
        }
        // A FIFO nobody writes to is refused at once, not waited on.
        let fifo = lab.p("/tmp/fifo.json");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: c is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let a = Apply { release: fifo, ..lab.opts(&rel(9, NEW), lab.staged(NEW)) };
        let e = apply(&lab.m(), &Ctx::new(), &a, now(), &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("not a regular file"), "{e}");
        assert_eq!(lab.bytes(SERVER_BIN), NEW);
        assert!(!lab.fake.ran()[before..].iter().any(|c| c.starts_with("systemd-run")), "a refused release armed a timer");
        // The window has limits.
        let a = Apply { window: 5, ..lab.opts(&rel(9, NEW), lab.staged(NEW)) };
        assert!(apply(&lab.m(), &Ctx::new(), &a, now(), &mut Vec::new()).unwrap_err().to_string().contains("window"));
    }

    #[test]
    fn one_update_at_a_time() {
        let lab = Lab::new();
        // Another apply holds the lock.
        let held = try_lock(&lab.m()).unwrap().unwrap();
        let e = lab.apply(&rel(7, NEW)).unwrap_err().to_string();
        assert!(e.contains("another update is running"), "{e}");
        lab.assert_old("locked");
        drop(held);
        // One waits for confirm: the same release again is fine, another
        // one waits its turn.
        lab.apply(&rel(7, NEW)).unwrap();
        lab.fake.ran.lock().unwrap().clear();
        lab.apply(&rel(7, NEW)).unwrap();
        assert!(lab.fake.ran().is_empty(), "{:?}", lab.fake.ran());
        let e = lab.apply(&rel(8, NEW)).unwrap_err().to_string();
        assert!(e.contains("release 7 waits for confirm or revert"), "{e}");
        assert_eq!(lab.pending().unwrap().serial, 7);
        // update activate only runs inside apply.
        let id = lab.pending().unwrap().id;
        let e = activate(&lab.m(), &Ctx::new(), &id, &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("runs only inside"), "{e}");
    }

    #[test]
    fn no_update_while_the_coordinator_is_cut_off() {
        let cut = |hosts: &[u32]| format!("{{\"cuts\": [{{\"name\": \"x\", \"hosts\": {hosts:?}}}]}}");
        for (state, want) in [(cut(&[1]), "cut off on this machine"), ("{".to_string(), "cannot be read")] {
            let lab = Lab::new();
            put(&lab.fake.root, quarantine::STATE_FILE, &state);
            let e = lab.apply(&rel(7, NEW)).unwrap_err().to_string();
            assert!(e.contains(want), "{e}");
            lab.assert_old(want);
            assert!(!lab.fake.has("systemd-run"));
        }
        // Another member cut off is no reason.
        let lab = Lab::new();
        put(&lab.fake.root, quarantine::STATE_FILE, cut(&[3]));
        lab.apply(&rel(7, NEW)).unwrap();
        // A cut that lands while the update runs stops it too.
        let lab = Lab::new();
        let root = lab.fake.root.clone();
        let state = cut(&[1]);
        lab.hook(Arc::new(move |p| {
            if p == "binary switched" {
                put(&root, quarantine::STATE_FILE, &state);
            }
            Ok(())
        }));
        let e = lab.apply(&rel(7, NEW)).unwrap_err().to_string();
        assert!(e.contains("cut off on this machine"), "{e}");
        lab.assert_old("cut while applying");
    }

    #[test]
    fn confirm_and_revert_need_an_update() {
        let lab = Lab::new();
        let e = confirm(&lab.m(), &Ctx::new(), None, now(), &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("no update waits for confirm"), "{e}");
        let e = revert_by_hand(&lab.m(), &Ctx::new(), now(), &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("nothing to revert"), "{e}");
        lab.apply(&rel(7, NEW)).unwrap();
        // Confirm the wrong serial, or with a failing self check, or with
        // another binary in place: not confirmed.
        let e = confirm(&lab.m(), &Ctx::new(), Some(8), now(), &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("release 7 waits for confirm, not 8"), "{e}");
        lab.script(|s| s.selfcheck_fails = true);
        let e = confirm(&lab.m(), &Ctx::new(), None, now(), &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("self check failed, not confirmed"), "{e}");
        lab.script(|s| s.selfcheck_fails = false);
        assert!(lab.pending().is_some());
        let swapped = Lab::new();
        swapped.apply(&rel(7, NEW)).unwrap();
        swapped.write(SERVER_BIN, b"something else", 0o755);
        let e = confirm(&swapped.m(), &Ctx::new(), None, now(), &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("is not the binary of release 7"), "{e}");
        // After confirm there is nothing to revert.
        confirm(&lab.m(), &Ctx::new(), None, now(), &mut Vec::new()).unwrap();
        let e = revert_by_hand(&lab.m(), &Ctx::new(), now(), &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("release 7 is confirmed") && e.contains("rollback"), "{e}");
        lab.assert_new("still confirmed");
        // An apply that did not finish is not confirmed either.
        let lab = Lab::new();
        lab.apply(&rel(7, NEW)).unwrap();
        let mut p = lab.pending().unwrap();
        p.stage = STAGE_INSTALLING.into();
        save_pending(&lab.m(), &p).unwrap();
        let e = confirm(&lab.m(), &Ctx::new(), None, now(), &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("did not finish applying"), "{e}");
    }

    #[test]
    fn revert_by_hand_puts_everything_back() {
        let lab = Lab::new();
        lab.apply(&rel(7, NEW)).unwrap();
        let id = lab.pending().unwrap().id;
        lab.fake.ran.lock().unwrap().clear();
        revert_by_hand(&lab.m(), &Ctx::new(), now() + 60, &mut Vec::new()).unwrap();
        lab.assert_old("by hand");
        assert!(!lab.p(&format!("{BACKUPS}/{id}")).exists());
        assert!(lab.fake.has(&format!("systemctl stop dryserver-update-revert-{id}.timer")));
        assert_eq!(*lab.fake.loaded.lock().unwrap().last().unwrap(), OLD_FIREWALL);
        assert_eq!(*lab.fake.reloaded_sshd.lock().unwrap().last().unwrap(), OLD_SSHD);
        let last = lab.last();
        assert!(last.action == "reverted" && last.ok && last.message.contains("reverted by hand"), "{last:?}");
        // The next update after a revert: dryserver.prev and dryserver are
        // one file then, and nothing is left over.
        lab.apply(&rel(8, NEW)).unwrap();
        lab.assert_new("after a revert");
        lab.assert_tidy("after a revert");
    }

    #[test]
    fn a_reboot_during_the_window() {
        let lab = Lab::new();
        lab.apply(&rel(7, NEW)).unwrap();
        let id = lab.pending().unwrap().id;
        // Up again after two minutes: the rest of the window, same id.
        lab.fake.ran.lock().unwrap().clear();
        guard_boot(&lab.m(), &Ctx::new(), now() + 120, &mut Vec::new()).unwrap();
        lab.assert_new("rebooted");
        assert!(lab.fake.has(&format!("systemd-run --unit=dryserver-update-revert-{id} --on-active=480s")), "{:?}", lab.fake.ran());
        assert_eq!(lab.pending().unwrap().boots, 1);
        // The timer then fires and reverts.
        guard_timer(&lab.m(), &Ctx::new(), &id, now() + 600, &mut Vec::new()).unwrap();
        lab.assert_old("timer after reboot");

        // Restarts without end (and a clock that is wrong each time) do not
        // keep an update for ever.
        let lab = Lab::new();
        lab.apply(&rel(7, NEW)).unwrap();
        for i in 0..MAX_BOOTS {
            guard_boot(&lab.m(), &Ctx::new(), now() - 3600, &mut Vec::new()).unwrap();
            assert_eq!(lab.pending().unwrap().boots, i + 1);
        }
        guard_boot(&lab.m(), &Ctx::new(), now() - 3600, &mut Vec::new()).unwrap();
        lab.assert_old("too many restarts");
        assert!(lab.last().message.contains("restarted 4 times"), "{:?}", lab.last());

        // A timer that cannot be armed again: revert at once.
        let lab = Lab::new();
        lab.apply(&rel(7, NEW)).unwrap();
        lab.script(|s| s.systemd_run_fails = true);
        guard_boot(&lab.m(), &Ctx::new(), now() + 60, &mut Vec::new()).unwrap();
        lab.assert_old("no timer after reboot");
    }

    #[test]
    fn the_deadline_passed_at_boot() {
        for late in [WINDOW, WINDOW + 1, 10 * release::DAY] {
            let lab = Lab::new();
            lab.apply(&rel(7, NEW)).unwrap();
            lab.fake.ran.lock().unwrap().clear();
            guard_boot(&lab.m(), &Ctx::new(), now() + late, &mut Vec::new()).unwrap();
            lab.assert_old(&format!("{late}s late"));
            // Before the services start: nothing reloads, no timer to stop.
            assert!(
                !lab.fake.has("nft -f") && !lab.fake.has("systemctl reload") && !lab.fake.has("systemctl stop"),
                "{:?}",
                lab.fake.ran()
            );
            assert!(lab.last().message.contains("not confirmed by"), "{:?}", lab.last());
        }
        // Changed units are reloaded at boot, before they start.
        let lab = Lab::new();
        lab.write(SYNC_UNIT, b"[Unit]\nDescription=older\n", 0o644);
        lab.apply(&rel(7, NEW)).unwrap();
        lab.fake.ran.lock().unwrap().clear();
        guard_boot(&lab.m(), &Ctx::new(), now() + WINDOW, &mut Vec::new()).unwrap();
        assert_eq!(lab.get(SYNC_UNIT), "[Unit]\nDescription=older\n");
        assert_eq!(lab.fake.ran(), ["systemctl daemon-reload"]);
        // Nothing pending: the boot unit does nothing.
        let lab = Lab::new();
        guard_boot(&lab.m(), &Ctx::new(), now(), &mut Vec::new()).unwrap();
        assert!(lab.fake.ran().is_empty());
    }

    #[test]
    fn the_clock_jumps_back_during_the_window() {
        // The timer runs on the monotonic clock: when it fires, the update
        // reverts, whatever the wall clock says.
        let lab = Lab::new();
        lab.apply(&rel(7, NEW)).unwrap();
        let id = lab.pending().unwrap().id;
        guard_timer(&lab.m(), &Ctx::new(), &id, now() - release::DAY, &mut Vec::new()).unwrap();
        lab.assert_old("clock back, timer fired");
        // At boot with the clock a day back: one window at most, not a day
        // and a window.
        let lab = Lab::new();
        lab.apply(&rel(7, NEW)).unwrap();
        let id = lab.pending().unwrap().id;
        guard_boot(&lab.m(), &Ctx::new(), now() - release::DAY, &mut Vec::new()).unwrap();
        assert!(lab.fake.has(&format!("systemd-run --unit=dryserver-update-revert-{id} --on-active=600s")), "{:?}", lab.fake.ran());
        // A timer from an earlier update never reverts this one.
        guard_timer(&lab.m(), &Ctx::new(), "0123456789abcdef", now(), &mut Vec::new()).unwrap();
        lab.assert_new("stale timer");
        assert!(lab.pending().is_some());
    }

    #[test]
    fn the_previous_binary_is_missing() {
        for (what, want) in [("missing", "dryserver.prev cannot be used"), ("changed", "is not the binary that ran before")] {
            let lab = Lab::new();
            lab.apply(&rel(7, NEW)).unwrap();
            if what == "missing" {
                fs::remove_file(lab.p(PREV_BIN)).unwrap();
            } else {
                fs::remove_file(lab.p(PREV_BIN)).unwrap();
                lab.write(PREV_BIN, b"something else", 0o755);
            }
            let e = revert_by_hand(&lab.m(), &Ctx::new(), now(), &mut Vec::new()).unwrap_err().to_string();
            assert!(e.contains(want), "{what}: {e}");
            // The files are back; the binary stays the new one, whole.
            assert_eq!(lab.bytes(SERVER_BIN), NEW, "{what}");
            assert_eq!(lab.get(FIREWALL), OLD_FIREWALL, "{what}");
            assert!(lab.pending().is_none() && load_installed(&lab.m()).unwrap().is_none(), "{what}");
            let last = lab.last();
            assert!(!last.ok && last.message.contains(want), "{what}: {last:?}");
        }
    }

    #[test]
    fn a_stale_release_is_applied_and_logged() {
        let lab = Lab::new();
        let r = Release { created: now() - 40 * release::DAY, expires: now() - 10 * release::DAY, ..rel(7, NEW) };
        lab.apply(&r).unwrap();
        lab.assert_new("stale");
        let log = fs::read_to_string(lab.p(LOG)).unwrap();
        assert!(log.contains("warning: release 7 expired"), "{log}");
        assert!(status(&lab.m(), now()).installed.unwrap().stale);
    }

    #[test]
    fn no_timer_no_update() {
        let lab = Lab::new();
        lab.script(|s| s.systemd_run_fails = true);
        let e = lab.apply(&rel(7, NEW)).unwrap_err().to_string();
        assert!(e.contains("cannot arm the timer") && e.contains("nothing was changed"), "{e}");
        lab.assert_old("no timer");
        assert!(!lab.fake.has("/usr/local/bin/.dryserver.new"), "{:?}", lab.fake.ran());
    }

    #[test]
    fn changed_units_are_verified_then_reloaded() {
        let lab = Lab::new();
        lab.write(SYNC_UNIT, b"[Unit]\nDescription=older\n", 0o644);
        lab.write("/etc/systemd/system/systemd-networkd-wait-online.service.d/any.conf", b"# older\n", 0o644);
        lab.write("/etc/sudoers.d/10-wheel", b"# older\n", 0o440);
        lab.apply(&rel(7, NEW)).unwrap();
        let f = &lab.fake;
        let verify = f.ran().into_iter().find(|c| c.starts_with("systemd-analyze")).unwrap();
        assert_eq!(
            verify,
            "systemd-analyze verify --man=no systemd-networkd-wait-online.service /etc/systemd/system/dryserver-sync.service"
        );
        assert!(f.has("visudo -c -q -f /etc/sudoers.d/10-wheel"));
        let reloads: Vec<usize> = f.ran().iter().enumerate().filter(|(_, c)| *c == "systemctl daemon-reload").map(|(i, _)| i).collect();
        assert_eq!(reloads.len(), 2, "one for the boot unit, one for the changed units: {:?}", f.ran());
        assert!(f.index("systemd-analyze").unwrap() < reloads[1], "verified after the reload: {:?}", f.ran());
        assert_eq!(std::fs::metadata(lab.p("/etc/sudoers.d/10-wheel")).unwrap().permissions().mode() & 0o777, 0o440);
        // A unit that fails verify reverts the update.
        let lab = Lab::new();
        lab.write(SYNC_UNIT, b"[Unit]\nDescription=older\n", 0o644);
        lab.script(|s| s.verify_fails = true);
        let e = lab.apply(&rel(7, NEW)).unwrap_err().to_string();
        assert!(e.contains("the new systemd units"), "{e}");
        lab.assert_old("verify");
        assert_eq!(lab.get(SYNC_UNIT), "[Unit]\nDescription=older\n");
    }

    #[test]
    fn files_that_are_not_the_updates_stay_untouched() {
        for p in ["/etc/hosts", "/etc/hostname", CONFIG, "/home/admin/.ssh/authorized_keys", "/var/lib/iwd/home.psk"] {
            assert!(!managed(p), "{p}");
        }
        for p in [FIREWALL, SSHD_DROPIN, SYNC_UNIT, "/etc/sudoers.d/10-wheel"] {
            assert!(managed(p), "{p}");
        }
        let lab = Lab::new();
        let mine =
            [("/etc/hosts", "127.0.0.1 localhost\n10.66.0.1 coord\n"), ("/home/admin/.ssh/authorized_keys", "ssh-ed25519 AAAAkey admin\n")];
        for (p, c) in mine {
            lab.write(p, c.as_bytes(), 0o644);
        }
        lab.apply(&rel(7, NEW)).unwrap();
        for (p, c) in mine {
            assert_eq!(lab.get(p), c, "{p}");
        }
        assert!(!lab.pending().unwrap().files.iter().any(|f| !managed(&f.path)));
    }

    #[test]
    fn a_coordinator_checks_as_the_brain() {
        let lab = Lab::new();
        lab.write(ROLE_FILE, b"coordinator\n", 0o644);
        // Rendered files of a coordinator differ; the server's render was
        // set up, so the coordinator's own files count as changed.
        let mut ahead = rel(7, NEW);
        ahead.k3s.version = "v1.38.0+k3s1".into();
        // The brain takes a k3s one minor version ahead; a server would not.
        lab.apply(&ahead).unwrap();
        assert!(!lab.fake.has("/usr/local/bin/k3s --version"), "the brain asks nobody for a k3s version");
        // A server told the coordinator's version uses it.
        let lab = Lab::new();
        let a = Apply { brain_k3s: "v1.38.1+k3s1".into(), ..lab.opts(&ahead, lab.staged(NEW)) };
        apply(&lab.m(), &Ctx::new(), &a, now(), &mut Vec::new()).unwrap();
        assert!(!lab.fake.has("/usr/local/bin/k3s --version"));
    }

    fn join_note(ch: &mut Changes) -> Result<()> {
        let old = ch.read(node::JOIN_STATE)?.unwrap_or_default();
        let mut v: serde_json::Value = serde_json::from_slice(&old)?;
        v["migrated"] = true.into();
        ch.put(node::JOIN_STATE, 0o600, (v.to_string() + "\n").as_bytes())?;
        Ok(())
    }

    static TEST_MIGRATIONS: &[Migration] = &[Migration { to: 1, what: "join.json notes the migration", run: join_note }];

    #[test]
    fn state_migrations_run_once_and_revert() {
        let lab = Lab::new();
        *lab.fake.migrations.lock().unwrap() = TEST_MIGRATIONS;
        let before = lab.get(node::JOIN_STATE);
        lab.apply(&rel(7, NEW)).unwrap();
        assert!(lab.get(node::JOIN_STATE).contains("\"migrated\":true"));
        assert_eq!(state_format(&lab.m()).unwrap(), 1);
        let files: Vec<String> = lab.pending().unwrap().files.iter().map(|f| f.path.clone()).collect();
        assert!(files.contains(&node::JOIN_STATE.to_string()) && files.contains(&FORMAT_FILE.to_string()), "{files:?}");
        // Revert: the state as it was, format 0.
        revert_by_hand(&lab.m(), &Ctx::new(), now(), &mut Vec::new()).unwrap();
        assert_eq!(lab.get(node::JOIN_STATE), before);
        assert_eq!(state_format(&lab.m()).unwrap(), 0);
        // Applied and confirmed, then the next update does not run it again.
        lab.apply(&rel(7, NEW)).unwrap();
        confirm(&lab.m(), &Ctx::new(), None, now(), &mut Vec::new()).unwrap();
        let migrated = lab.get(node::JOIN_STATE);
        lab.apply(&rel(8, NEW)).unwrap();
        assert_eq!(lab.get(node::JOIN_STATE), migrated);
        assert!(!lab.pending().unwrap().files.iter().any(|f| f.path == node::JOIN_STATE));

        // State newer than the binary knows: its self check fails, so it is
        // never switched to (a rollback cannot go back past a format).
        let lab = Lab::new();
        lab.write(FORMAT_FILE, b"5\n", 0o600);
        let e = lab.apply(&rel(7, NEW)).unwrap_err().to_string();
        assert!(e.contains("failed its self check"), "{e}");
        assert_eq!(lab.bytes(SERVER_BIN), OLD);
        let checks = selfcheck(&lab.m(), &Ctx::new());
        let state = checks.iter().find(|c| c.name == "state").unwrap();
        assert!(!state.ok && state.detail.contains("format 5, newer"), "{state:?}");
        // Migrations out of order are a bug, caught.
        fn nothing(_: &mut Changes) -> Result<()> {
            Ok(())
        }
        static GAP: &[Migration] = &[Migration { to: 2, what: "skips one", run: nothing }];
        assert!(known_format(GAP).unwrap_err().to_string().contains("numbered 2, not 1"));
        assert_eq!(known_format(MIGRATIONS).unwrap(), 0);
    }

    #[test]
    fn selfcheck_reports_each_check() {
        let lab = Lab::new();
        let checks = selfcheck(&lab.m(), &Ctx::new());
        let names: Vec<&str> = checks.iter().map(|c| c.name).collect();
        assert_eq!(names, ["binary", "config", "firewall", "ssh", "wireguard", "state"]);
        let mut out = Vec::new();
        print_checks(&checks, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("ok   firewall: the rendered /etc/nftables.conf passes nft -c"), "{text}");
        assert!(lab.fake.ran().iter().any(|c| c.starts_with("nft -c -f /run/dryserver-selfcheck-")));
        assert!(fs::read_dir(lab.p("/run")).unwrap().flatten().all(|e| !e.file_name().to_string_lossy().contains("selfcheck")));

        let failing = |lab: &Lab, name: &str, want: &str| {
            let checks = selfcheck(&lab.m(), &Ctx::new());
            let c = checks.iter().find(|c| c.name == name).unwrap();
            assert!(!c.ok && c.detail.contains(want), "{name}: {c:?}");
            let mut out = Vec::new();
            let e = print_checks(&checks, &mut out).unwrap_err().to_string();
            assert!(e.contains("checks failed") && String::from_utf8_lossy(&out).contains(&format!("FAIL {name}")), "{e}");
        };
        let lab = Lab::new();
        lab.write(CONFIG, b"USERNAME=root\n", 0o600);
        failing(&lab, "config", "username");
        failing(&lab, "firewall", "username");
        let lab = Lab::new();
        lab.script(|s| s.sshd_fails = Some("older dryserver"));
        failing(&lab, "ssh", "Bad configuration option");
        let lab = Lab::new();
        lab.write(node::WG_CONF, b"[Peer]\nPublicKey = x\n", 0o600);
        failing(&lab, "wireguard", "before [Interface]");
        let lab = Lab::new();
        fs::remove_file(lab.p(node::WG_CONF)).unwrap();
        failing(&lab, "wireguard", "no such file");
        lab.write(node::JOIN_STATE, b"{\"host\": 0}\n", 0o600);
        assert!(selfcheck(&lab.m(), &Ctx::new()).iter().all(|c| c.ok), "not joined yet: no wg0.conf is fine");
        for (p, junk) in
            [(node::JOIN_STATE, "{\"host\": \"five\"}"), (quarantine::STATE_FILE, "["), (PENDING, "{}"), (INSTALLED, "{\"doc\": \"x\"}")]
        {
            let lab = Lab::new();
            lab.write(p, junk.as_bytes(), 0o600);
            failing(&lab, "state", p);
        }
    }

    #[test]
    fn wireguard_configs() {
        assert_eq!(parse_wg(WG0).unwrap(), 1);
        let no_peers = "[Interface]\nAddress = 10.66.0.1/24\nListenPort = 51820\n";
        assert_eq!(parse_wg(no_peers).unwrap(), 0);
        for (conf, want) in [
            ("", "0 [Interface]"),
            ("[Interface]\nListenPort = 1\n", "no Address"),
            ("[Interface]\nAddress = a\n[Interface]\nAddress = b\n", "2 [Interface]"),
            ("[Interface]\nAddress = a\nBogus = 1\n", "unknown setting"),
            ("[Interface]\nAddress = a\n[Peers]\n", "unknown section"),
            ("[Interface]\nAddress = a\njunk\n", "not key = value"),
            ("Address = a\n[Interface]\n", "before [Interface]"),
            (&format!("{no_peers}[Peer]\nPublicKey = short\nAllowedIPs = 10.66.0.2/32\n"), "no valid PublicKey"),
            (&format!("{no_peers}[Peer]\nPublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n"), "no AllowedIPs"),
        ] {
            let e = parse_wg(conf).unwrap_err().to_string();
            assert!(e.contains(want), "{conf:?}: {e}");
        }
    }

    #[test]
    fn status_for_the_monitor() {
        let lab = Lab::new();
        let s = status(&lab.m(), now());
        assert!(s.installed.is_none() && s.pending.is_none() && s.last.is_none() && s.problems.is_empty(), "{s:?}");
        lab.apply(&rel(7, NEW)).unwrap();
        let s = status(&lab.m(), now() + 100);
        let p = s.pending.clone().unwrap();
        assert_eq!((p.serial, p.stage.as_str(), p.seconds_left, p.deadline), (7, STAGE_ARMED, WINDOW - 100, now() + WINDOW));
        assert_eq!(s.installed.as_ref().unwrap().serial, 7);
        assert_eq!(s.last.as_ref().unwrap().action, "applied");
        let json: serde_json::Value = serde_json::to_value(&s).unwrap();
        for k in ["running", "installed", "pending", "last", "problems"] {
            assert!(json.get(k).is_some(), "{k} missing: {json}");
        }
        let mut out = Vec::new();
        print_status(&s, &mut out);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("pending: release 7 (armed), reverts by itself at") && text.contains("in 8m20s"), "{text}");
        // A damaged record shows up as a problem, not a crash.
        lab.write(PENDING, b"{", 0o600);
        assert!(status(&lab.m(), now()).problems[0].contains("pending.json is damaged"));
    }

    #[test]
    fn the_boot_unit() {
        let u = GUARD_UNIT_TEXT;
        for want in [
            "DefaultDependencies=no\n",
            "After=local-fs.target\n",
            "Before=sysinit.target shutdown.target nftables.service systemd-networkd.service sshd.service wg-quick@wg0.service",
            &format!("ConditionPathExists={DIR}/pending.json\n"),
            &format!("ExecStart=/bin/sh -c '{PREV_BIN} update guard --boot || {SERVER_BIN} update guard --boot'\n"),
            "Type=oneshot\n",
            "WantedBy=sysinit.target\n",
        ] {
            assert!(u.contains(want), "missing {want:?}:\n{u}");
        }
        assert!(PENDING.starts_with(DIR) && STAGING.starts_with(DIR));
        // Not under the registry account's directory on the coordinator.
        assert!(!format!("{DIR}/").starts_with(&format!("{}/", fsx::dir(registry::DEFAULT_PATH).display())));
        assert_eq!(effect(GUARD_UNIT_PATH), Some(Effect::Units));
    }

    #[test]
    fn records_from_a_newer_binary_keep_their_fields() {
        let lab = Lab::new();
        lab.apply(&rel(7, NEW)).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&lab.get(PENDING)).unwrap();
        v["future"] = serde_json::json!({"k": 1});
        v["stage"] = "something-new".into();
        lab.write(PENDING, v.to_string().as_bytes(), 0o600);
        let mut p = lab.pending().unwrap();
        assert_eq!(p.rest["future"], serde_json::json!({"k": 1}));
        p.boots = 2;
        save_pending(&lab.m(), &p).unwrap();
        assert!(lab.get(PENDING).contains("\"future\""));
        // A stage this binary does not know reverts at boot.
        guard_boot(&lab.m(), &Ctx::new(), now(), &mut Vec::new()).unwrap();
        lab.assert_old("unknown stage");
        // A record that points outside what dryserver manages is refused
        // file by file.
        assert!(safe_path("/etc/../root/x").is_err() && safe_path("etc/x").is_err() && safe_path("/etc/x").is_ok());
        let lab = Lab::new();
        let f = Replaced { path: FIREWALL.into(), backup: Some("/etc/shadow".into()), ..Replaced::default() };
        assert!(restore(&lab.m(), &f).unwrap_err().to_string().contains("outside"));
    }
}
