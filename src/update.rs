//! A machine updates itself to a release the admin signed: its dryserver
//! binary and the system files that binary renders, its k3s binary, and
//! its Arch Linux packages (the snapshot day). Whoever controls this path
//! controls every machine, so it installs only what passes `release::check`
//! and `release::verify_file`; and a bad update must never leave a machine
//! unreachable, so every update reverts by itself unless it is confirmed in
//! time.
//!
//! `update apply`, step by step. The binary that runs it (the old one)
//! only checks and hands over; the new binary does everything else, so a
//! fix to the k3s, Arch or reboot code reaches a machine with the very
//! release that carries it:
//!
//! 1. The old binary checks the release against the installed one and
//!    what runs (signature, serial, the floor, the k3s skew), and the new
//!    binary against the release (copied into a directory only root can
//!    write). Refusals change nothing.
//! 2. It writes a pending record and arms a revert timer that covers the
//!    whole apply. From then on, whatever happens (an error, Ctrl-C, a lost
//!    SSH session, a power cut), the machine goes back to what it ran before
//!    unless the update finishes and is confirmed in time.
//! 3. It copies the new binary next to the installed one under a
//!    temporary name (NEW_BIN) and runs its self check there.
//! 4. The new binary, from that copy (`update prepare`), decides the k3s
//!    and Arch steps and checks what they need (pacman's settings, the room
//!    on disk, no other pacman at work: osupdate::arch_check; the k3s
//!    binary, staged), and loads the packages before anything else changes:
//!    the mirrorlist is pinned to the release's day (recorded like any file
//!    the update writes) and pacman refreshes its lists and the signing keys
//!    and downloads everything (osupdate::arch_download). A dead or slow
//!    mirror ends the update here with the mirrorlist put back: "postponed",
//!    tried again later, not a failed release. The signing keys may stay
//!    newer: they only ever move forward.
//! 5. The old binary puts the new one in place, by a rename: a power cut
//!    leaves the old or the new binary, never half of one. The old one
//!    stays as dryserver.prev.
//! 6. The new binary, now the installed one (`update activate`), renders
//!    the system files from config.env, writes those that changed (each
//!    atomically, its old content kept), checks them with the real tools
//!    (nft -c, sshd -t, visudo -c, systemd-analyze verify), runs the state
//!    migrations it knows, and reloads only what changed. sshd is reloaded,
//!    never restarted: running sessions stay.
//! 7. It installs the release's k3s when this machine runs another one (by
//!    its checksum, whatever the records say) and waits until k3s is
//!    healthy with it (osupdate::k3s_install); the k3s that ran before is
//!    kept to go back to.
//! 8. It installs the packages (osupdate::arch_install), the one step a
//!    revert cannot undo, last. pacman is never killed while it installs.
//! 9. It records the release as installed, and starts the confirm window:
//!    the timer is armed again with the window, which counts from now.
//! 10. It reboots, when the new packages need it (a new kernel, glibc,
//!     systemd...), the run finished, the boot images are current, the
//!     machine can come back by itself, and it was allowed (`--reboot`, the
//!     rollout's apply). Once: the record is armed, so the boot unit and a
//!     confirm after the reboot carry the update across it.
//!
//! When a step of the new binary fails, the old binary goes back (its
//! revert, as below). A release that keeps the k3s binary and the snapshot
//! day restarts no k3s and runs no pacman: a dryserver fix stays fast.
//!
//! The handover, the contract between any two dryserver binaries (one may
//! be years older than the other); every later version keeps it:
//! - `NEW update handover` prints the highest protocol NEW speaks (a
//!   number; HANDOVER). A binary from before the handover fails on it: it
//!   counts as 0. The old binary uses the lower of that and its own, and
//!   writes it into the record (Pending::handover). A binary keeps
//!   speaking every protocol from 1 up to its own.
//! - Protocol 1: the old binary passes the record's id and nothing else:
//!   `NEW update prepare --id ID` run from NEW_BIN at stage "preparing",
//!   then `NEW update activate --id ID` run as SERVER_BIN at stage
//!   "installing". The new binary reads all it needs from the record (the
//!   release envelope, k3s_file, brain_k3s, may_reboot, window) and keeps
//!   its own notes between its two steps in Pending::work. A failed
//!   prepare sets Pending::why and Pending::again (postponed when true),
//!   exits non-zero, and the old binary reverts. activate exits zero once
//!   the record is armed and the release recorded as applied; non-zero, and
//!   the old binary reverts.
//! - Protocol 0 (either binary from before the handover): the old binary
//!   runs steps 4 and 7 to 10 itself, and `update activate` writes the
//!   files only. A binary of this version does so when it hands over to an
//!   older one (a rollback), and does only the files when an older one
//!   hands over to it (the record says 0).
//! - The record's fields only grow (PENDING_FORMAT); a binary keeps the
//!   ones it does not know (Pending::rest), and the revert of any version
//!   puts back what the files list says.
//! - The update lock is kept open across the handover (Cmd::keep_fd) and
//!   by pacman's install: while any of them runs, the lock is held, also
//!   when the process that took it died, and no revert starts under them.
//!
//! The first release with the handover is applied by binaries without it,
//! which run its k3s and Arch steps with their own code: that release best
//! keeps k3s and the Arch day (dryserver only); the next ones get the new
//! code all the way.
//!
//! `update confirm` makes it final once the self check passes. Without it,
//! the timer reverts: old binary, old files (the mirrorlist among them),
//! the k3s that ran before when this update swapped it, reloads. The
//! packages stay as they are: going back on them is a signed release with
//! rollback (pacman -Suu to the older day). The timer runs the previous
//! binary first, since the new one may be what is broken. A timer does not
//! survive a reboot, so a boot unit (GUARD_UNIT_TEXT) reverts an update
//! whose deadline passed, or that never finished applying, before the
//! firewall, the network, SSH and k3s start, and arms the timer again for
//! one whose window is still open. None of this needs the network or the
//! coordinator.
//!
//! The rollout runs apply detached (`--detach`): in a transient service of
//! its own, so the minute sync that starts it stays responsive, and
//! stopping or killing the sync never stops pacman half way. The sync then
//! follows it with `update status --json`.
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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::DateTime;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::ctx::Ctx;
use crate::err::{Error, Result};
use crate::node::{self, Node};
use crate::osupdate::{self, ArchOutcome, K3sOutcome};
use crate::release::{self, Place, Release};
use crate::runner::{Cmd, LogFn, Runner};
use crate::signed::{Envelope, SshVerifier, Verifier};
use crate::sysconf::{self, Params, Role};
use crate::{bail, errf, fsx, gotime, packages, quarantine};

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
/// The Arch snapshot day the packages were last brought to, and how that
/// went (ArchState). Not part of what a revert puts back: the packages
/// stay.
pub const ARCH_STATE: &str = "/var/lib/dryserver-update/arch.json";
/// When this machine began to take releases (StartRecord): what a release
/// goes by while none is installed (release::Start).
pub const START: &str = "/var/lib/dryserver-update/start.json";
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
/// The transient revert timer of one update is this plus its id (the
/// confirm window), or plus its id and APPLY_SUFFIX (while it applies).
pub const TIMER_PREFIX: &str = "dryserver-update-revert-";
const APPLY_SUFFIX: &str = "-apply";
/// The transient service a detached apply runs in.
pub const APPLY_UNIT: &str = "dryserver-update-apply";

/// How long an update waits for confirm before it reverts by itself, from
/// the moment its apply is done.
pub const WINDOW: i64 = 600;
pub const MIN_WINDOW: i64 = 60;
pub const MAX_WINDOW: i64 = 24 * 3600;
/// When the apply's timer fires: an apply that did not finish by then and
/// does not run any more (killed, crashed) is reverted. One that still runs
/// (pacman taking its time) is waited for, and decides itself.
pub const APPLY_TIME: i64 = 30 * 60;
/// The confirm window grows by this when the apply reboots the machine:
/// the boot, k3s and a sync come first.
pub const REBOOT_WINDOW: i64 = 15 * 60;
/// How long a stopped detached apply gets (SIGINT to it, passed on to
/// pacman) before systemd kills what is left: pacman finishes the package
/// it is at and its hooks (a boot image) first.
const APPLY_STOP_TIME: &str = "30min";
/// An update that sees this many restarts without being confirmed is
/// reverted at the next one. A machine whose clock is wrong at every boot
/// (no clock battery) would otherwise get a fresh window each time.
pub const MAX_BOOTS: u32 = 3;
const SELFCHECK_TIME: Duration = Duration::from_secs(60);
/// `update activate` of a binary from before the handover: the files only.
const ACTIVATE_TIME: Duration = Duration::from_secs(180);
/// The handover this binary speaks (see the module): the highest protocol
/// it answers `update handover` with, and the one it uses with a new
/// binary that speaks it too.
pub const HANDOVER: u32 = 1;
/// How long the new binary's `update prepare` (the checks, the refresh and
/// the download, each with limits of its own) may take before it is asked
/// to stop (SIGINT), and how long it then gets before it is killed: it has
/// installed nothing.
const PREPARE_TIME: Duration = Duration::from_secs(3 * 3600);
const PREPARE_GRACE: Duration = Duration::from_secs(10 * 60);
/// How long the new binary's `update activate` (files, k3s, the packages)
/// may take before it is asked to stop. It is never killed: pacman may be
/// installing under it.
const HANDOVER_TIME: Duration = Duration::from_secs(8 * 3600);
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
/// The apply's own timer waits as long as the apply runs: pacman is never
/// cut off, and the apply decides at its end (the timer of a finished one
/// does nothing).
const APPLY_GUARD_LOCK_WAIT: Duration = Duration::from_secs(30 * 24 * 3600);
/// A signed release envelope is a few KiB; refuse to read more.
const MAX_ENVELOPE: u64 = 64 << 10;
/// The format of the pending record. Its fields only grow: the previous
/// binary has to read what the new one wrote, to revert it.
const PENDING_FORMAT: u32 = 1;

/// Loading the packages: nothing but the mirrorlist changed yet.
pub const STAGE_PREPARING: &str = "preparing";
pub const STAGE_INSTALLING: &str = "installing";
pub const STAGE_ARMED: &str = "armed";
pub const STAGE_REVERTING: &str = "reverting";

/// The boot half of the revert guard. It runs before the firewall, the
/// network and SSH, so they start with the files of the release that is
/// kept. The previous binary goes first: the new one may be what is broken.
///
/// It runs before systemd-sysctl.service too: that one applies
/// /etc/sysctl.d once at boot, and a revert at boot reloads nothing, so
/// kernel settings it puts back would otherwise wait for the next restart.
/// (systemd-sysctl then waits for the local file systems; nothing they need
/// waits for it.) Since everything up to sysinit.target waits for this unit,
/// it must never wait for systemd itself: see arm.
pub const GUARD_UNIT_TEXT: &str = "# dryserver: after a restart, an update that was not confirmed in time
# (or never finished applying) is reverted before the kernel settings, the
# firewall, the network and SSH start; one whose window is still open gets
# its revert timer back.
[Unit]
Description=Revert an unconfirmed dryserver update after a restart
DefaultDependencies=no
After=local-fs.target
Before=sysinit.target shutdown.target systemd-sysctl.service nftables.service systemd-networkd.service sshd.service wg-quick@wg0.service k3s.service dryserver-sync.timer
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
    /// pacman's and k3s's room and time; tests shrink them.
    pub limits: osupdate::Limits,
    /// Unix seconds now: an apply takes minutes, and its confirm window
    /// starts when it is done. Tests move it.
    pub clock: Arc<dyn Fn() -> i64 + Send + Sync>,
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
            limits: osupdate::Limits::default(),
            clock: Arc::new(|| chrono::Utc::now().timestamp()),
        }
    }

    /// The machine under root, for a caller that is not an update command
    /// (the sync, as root): it records when the machine began to take
    /// releases, and reads it.
    pub fn at_root(root: &Path, run: Arc<dyn Runner>, verifier: Arc<dyn Verifier>) -> Machine {
        Machine { root: root.to_path_buf(), verifier, owner: fsx::geteuid(), ..Machine::installed(run) }
    }

    pub fn path(&self, p: &str) -> PathBuf {
        fsx::under(&self.root, p)
    }

    fn now(&self) -> i64 {
        (self.clock)()
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
    /// preparing (loading the packages), installing, armed (applied,
    /// waits for confirm) or reverting. Text, not an enum: a stage written
    /// by a newer binary still reads, and anything but armed reverts at
    /// boot.
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
    /// What the apply does now, for status.
    #[serde(default)]
    pub step: String,
    /// The checksum of the k3s that ran before, once this update set out
    /// to swap k3s: a revert puts that one back. Empty: k3s is not this
    /// update's business (or there was none before).
    #[serde(default)]
    pub k3s_prev_sha256: String,
    /// The Arch snapshot day the packages go to; empty when they stay.
    #[serde(default)]
    pub arch_date: String,
    /// The apply rebooted the machine to start the new packages: confirm
    /// only after that reboot.
    #[serde(default)]
    pub reboot: bool,
    /// The update brought a new main kernel, or made its boot image again
    /// (osupdate::ArchOutcome::main_new): the next boot is that kernel's
    /// test, and a machine that runs its fallback kernel after it did not
    /// pass it. False: a fallback kernel that runs is not this update's
    /// doing.
    #[serde(default)]
    pub kernel: bool,
    /// The handover (see the module): the protocol the binary that started
    /// the update and the new one both speak; 0 when it was started by, or
    /// handed to, a binary from before it.
    #[serde(default)]
    pub handover: u32,
    /// What `update apply` was asked besides the release, for the new
    /// binary: the k3s binary given (--k3s, "" none), the coordinator's
    /// k3s the release was checked against, and whether it may reboot.
    #[serde(default)]
    pub k3s_file: String,
    #[serde(default)]
    pub brain_k3s: String,
    #[serde(default)]
    pub may_reboot: bool,
    /// Set by the new binary when its `update prepare` fails: why, and
    /// whether another try later may work (postponed, not refused).
    #[serde(default)]
    pub why: String,
    #[serde(default)]
    pub again: bool,
    /// What the new binary's `update prepare` decided and loaded, for its
    /// `update activate`. Its format is that binary's own; other binaries
    /// keep it as it is.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub work: serde_json::Value,
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
    /// applied, confirmed or reverted; or, for an apply that changed
    /// nothing in the end, postponed (a problem that may pass: try again
    /// later) or refused (this release does not go on this machine as it
    /// is).
    pub action: String,
    /// False when it could not do all it had to.
    pub ok: bool,
    pub message: String,
}

pub const POSTPONED: &str = "postponed";
pub const REFUSED: &str = "refused";

/// START: when this machine began to take releases, unix seconds.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct StartRecord {
    pub since: i64,
}

/// When this machine began to take releases. Recorded by the installer
/// (with a plausible clock), else the first time the updates look (the
/// sync does at every run, from the first boot on; or the first apply),
/// and kept from then on. A machine with no release
/// installed takes a rollback below what it was installed with only when
/// it was signed after this moment (release::Start). 0 when the record
/// cannot be read or written: no such rollback then.
pub fn note_start(m: &Machine, now: i64) -> i64 {
    match read_json::<StartRecord>(m, START) {
        Ok(Some(s)) => s.since,
        Ok(None) if now > 0 => match ensure_dirs(m).and_then(|_| save_json(m, START, &StartRecord { since: now })) {
            Ok(()) => now,
            Err(_) => 0,
        },
        _ => 0,
    }
}

/// What a release goes by while none is installed, besides what runs
/// (release::Start): when this machine began to take releases (recorded
/// now if it was not yet), and the Arch day its mirrorlist pins.
pub fn start_of(m: &Machine, now: i64) -> (i64, Option<String>) {
    (note_start(m, now), osupdate::pinned_date(&fsx::read_or_empty(m.path(osupdate::MIRRORLIST))))
}

/// The Arch packages after the last run that installed any (ARCH_STATE).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ArchState {
    /// The snapshot day the run brought the packages to.
    pub date: String,
    /// It finished. false: pacman stopped part way, the system may be
    /// partly upgraded: do not reboot; the next run on this day finishes it.
    pub done: bool,
    /// Unix seconds.
    pub at: i64,
    /// Packages whose new code only a reboot starts, and whether a new
    /// kernel came; for the reboot that is due.
    pub restart: Vec<String>,
    pub kernel: bool,
    /// Why a reboot would not start the machine; empty when it would.
    pub boot_problem: String,
    pub summary: String,
    /// The fallback kernel's update waits for the next run, once the main
    /// kernel booted well (osupdate: one kernel at a time).
    pub lts_waits: bool,
    /// The run failed, but pacman changed nothing (it refused before it
    /// began: files in the way, a damaged package): not done, and still
    /// safe to reboot.
    pub untouched: bool,
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

/// The update that waits, when there is one. Its id names a backup
/// directory a revert removes and goes into the timer's shell command: a
/// record whose id is not what apply makes (16 lowercase hex digits) is
/// damaged.
pub fn load_pending(m: &Machine) -> Result<Option<Pending>> {
    let p: Option<Pending> = read_json(m, PENDING)?;
    if let Some(p) = &p
        && !valid_id(&p.id)
    {
        bail!("{PENDING} is damaged: its id {:?} is not 16 hex digits", p.id.chars().take(40).collect::<String>());
    }
    Ok(p)
}

fn valid_id(id: &str) -> bool {
    id.len() == 16 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
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
    check_dir_chain(m, &dir)?;
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

/// dir and every directory above it, up to the machine's root, belong to
/// root and nobody else may write them: nobody else can rename one away
/// and put a link or a directory of their own in its place while an
/// update writes a file there as root.
fn check_dir_chain(m: &Machine, dir: &Path) -> Result<()> {
    let mut d = dir;
    loop {
        check_owned(m, d, true)?;
        match d.parent() {
            Some(up) if d != m.root && up.starts_with(&m.root) => d = up,
            _ => return Ok(()),
        }
    }
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
    let p = machine_params(m)?;
    let mut files: Vec<sysconf::File> = sysconf::render(&p)?.into_iter().filter(|f| managed(&f.path)).collect();
    // The registry account's limits: the installer writes them under its
    // uid, which only the machine knows; an update keeps them in step too.
    // A coordinator without that account has nothing to limit.
    if p.role == Role::Coordinator
        && let Some(uid) = uid_of(m, sysconf::REGISTRY_USER)
    {
        files.push(sysconf::File { path: registry_slice(uid), mode: 0o644, content: sysconf::REGISTRY_SLICE.into() });
    }
    Ok(files)
}

/// Where the registry account's slice settings go (systemd names a user's
/// slice by number).
pub fn registry_slice(uid: u32) -> String {
    format!("/etc/systemd/system/user-{uid}.slice.d/50-dryserver.conf")
}

/// The uid of an account of this machine, from its /etc/passwd.
fn uid_of(m: &Machine, user: &str) -> Option<u32> {
    let passwd = fsx::read_or_empty(m.path("/etc/passwd"));
    passwd.lines().map(|l| l.split(':').collect::<Vec<_>>()).find(|f| f.len() > 2 && f[0] == user).and_then(|f| f[2].parse().ok())
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
            check_dir_chain(m, &fsx::dir(&dst))?;
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
    /// systemd-tmpfiles makes what they say now (the registry account's
    /// home becomes root's at the update, not at the next boot).
    Tmpfiles,
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
    } else if p.starts_with("/etc/tmpfiles.d/") && p.ends_with(".conf") {
        Effect::Tmpfiles
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
fn reload(m: &Machine, ctx: &Ctx, paths: &[String]) -> Result<()> {
    let mut errs = Vec::new();
    for e in &effects(paths) {
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
            Effect::Tmpfiles => {
                // Each file that is there (a revert may have removed one).
                let files: Vec<String> =
                    paths.iter().filter(|p| effect(p) == Some(Effect::Tmpfiles) && m.path(p).is_file()).map(|p| m.shown(p)).collect();
                if files.is_empty() {
                    Ok(())
                } else {
                    let mut args = vec!["--create"];
                    args.extend(files.iter().map(String::as_str));
                    m.cmd(ctx, "systemd-tmpfiles", &args).map(drop)
                }
            }
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

/// Which revert timer of an update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Timer {
    /// Armed when the apply starts, for as long as it may take: it
    /// reverts an apply that stopped (was killed, the machine went down)
    /// before it finished, and leaves one alone that finished. Its guard
    /// waits for an apply that still runs.
    Apply,
    /// The confirm window, from the moment the apply is done (and again
    /// after a restart).
    Window,
}

fn timer_unit(id: &str, t: Timer) -> String {
    match t {
        Timer::Window => format!("{TIMER_PREFIX}{id}"),
        Timer::Apply => format!("{TIMER_PREFIX}{id}{APPLY_SUFFIX}"),
    }
}

/// Arms the revert timer: after secs seconds (by the monotonic clock, so a
/// clock that jumps does not move it) the previous binary reverts the
/// update unless it was confirmed. The installed one is the fallback.
///
/// At boot (the guard unit, which runs before sysinit.target) this must
/// not wait for systemd. systemd-run normally waits until the timer's start
/// job is done, and a timer by default needs sysinit.target first; but
/// sysinit.target waits for the guard, so the boot would stall until the
/// guard's start timeout killed it, five minutes with no network and no
/// SSH, and the update would lose its timer. So the timer goes without the
/// default dependencies (it needs nothing that is not there when the guard
/// runs: local file systems), keeping only its place at shutdown, and at
/// boot systemd-run only queues it (--no-block). The service the timer
/// starts keeps its defaults (after basic.target, so the revert can reload
/// what runs); nothing the guard waits for waits for it, so that cannot
/// stall the boot either. Outside the boot, systemd-run waits for the
/// timer to be active, so an apply learns that it is armed before it
/// changes anything.
fn arm(m: &Machine, ctx: &Ctx, t: Timer, id: &str, serial: u64, secs: i64, boot: bool) -> Result<()> {
    m.cmd(ctx, "systemd-run", &arm_args(m, t, id, serial, secs, boot).iter().map(String::as_str).collect::<Vec<_>>()).map(drop)
}

fn arm_args(m: &Machine, t: Timer, id: &str, serial: u64, secs: i64, boot: bool) -> Vec<String> {
    let (prev, bin) = (m.shown(PREV_BIN), m.shown(SERVER_BIN));
    let mut args = vec![format!("--unit={}", timer_unit(id, t)), format!("--on-active={secs}s")];
    if boot {
        args.push("--no-block".into());
    }
    for p in ["AccuracySec=1s", "DefaultDependencies=no", "Conflicts=shutdown.target", "Before=shutdown.target"] {
        args.push(format!("--timer-property={p}"));
    }
    let (what, flag) = match t {
        Timer::Window => ("it is confirmed", ""),
        Timer::Apply => ("its apply finishes", " --applying"),
    };
    args.push(format!("--description=Revert dryserver release {serial} unless {what}"));
    args.extend(["/bin/sh".into(), "-c".into(), format!("{prev} update guard --id {id}{flag} || {bin} update guard --id {id}{flag}")]);
    args
}

/// Whether the file systems of these paths have room for copies of these
/// sizes (the sizes on one file system add up), with limits.reserve left
/// on each. Err says where room is short.
fn room_for(m: &Machine, copies: &[(PathBuf, u64)]) -> Result<()> {
    let mut by_fs: BTreeMap<u64, (PathBuf, u64)> = BTreeMap::new();
    for (path, size) in copies {
        let dir = if path.is_dir() { path.clone() } else { fsx::dir(path) };
        let dev = fs::metadata(&dir).map_err(|e| Error::from(e).wrap(format!("stat {}", dir.display())))?.dev();
        by_fs.entry(dev).or_insert((dir, 0)).1 += size;
    }
    for (dir, need) in by_fs.into_values() {
        let (_, free) = fsx::space(&dir)?;
        let want = need.saturating_add(m.limits.reserve);
        if free < want {
            bail!(
                "only {} MiB free on the file system of {}, and the update needs {} MiB there for its copies of the new binaries: make room first",
                free >> 20,
                dir.display(),
                want.div_ceil(1 << 20)
            );
        }
    }
    Ok(())
}

/// Whether a step that failed this way may work on another try: the disk
/// is full or read-only for now, or the system is short of something.
fn passing(e: &Error) -> bool {
    let t = e.to_string();
    [
        "no space left on device",
        "disk quota exceeded",
        "read-only file system",
        "input/output error",
        "too many open files",
        "cannot allocate memory",
    ]
    .iter()
    .any(|p| t.contains(p))
}

/// How long until a revert that did not finish is tried again.
const REVERT_RETRY: i64 = 5 * 60;

/// Arms a timer that tries a revert that did not finish again, under a
/// name of its own: the timer whose revert failed may still be running.
fn arm_retry(m: &Machine, ctx: &Ctx, p: &Pending) -> Result<()> {
    let mut args = arm_args(m, Timer::Window, &p.id, p.serial, REVERT_RETRY, false);
    args[0] = format!("--unit={}{}-retry-{}", TIMER_PREFIX, p.id, fsx::hex(&fsx::random_bytes(3)));
    m.cmd(ctx, "systemd-run", &args.iter().map(String::as_str).collect::<Vec<_>>()).map(drop)
}

/// Stops an update's revert timers, both of them.
fn disarm(m: &Machine, ctx: &Ctx, id: &str) {
    for t in [Timer::Window, Timer::Apply] {
        stop_timer(m, ctx, id, t);
    }
}

fn stop_timer(m: &Machine, ctx: &Ctx, id: &str, t: Timer) {
    let _ = m.run.run(ctx, &Cmd::new("systemctl", &["stop", &format!("{}.timer", timer_unit(id, t))]).quiet());
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
    /// The k3s binary it names, copied into STAGING too. Needed only when
    /// this machine runs another k3s.
    pub k3s: Option<PathBuf>,
    /// The k3s the coordinator runs, for the version skew rule on a server;
    /// "" asks this machine's k3s.
    pub brain_k3s: String,
    /// Seconds until an unconfirmed update reverts, counted from the end
    /// of the apply.
    pub window: i64,
    /// The machine may reboot when the new packages need it (and it can
    /// come back by itself). Without it, the apply says that a reboot is
    /// due.
    pub reboot: bool,
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

fn staged_k3s(m: &Machine, serial: u64) -> PathBuf {
    m.path(STAGING).join(format!("k3s-{serial}"))
}

/// The k3s binary of the release in STAGING, copied from src (the
/// rollout's store, or wherever the admin put it) and checked against the
/// release's checksum there. The release names no size: the copy takes
/// the file's, at most osupdate::MAX_K3S.
fn stage_k3s(m: &Machine, src: &Path, rel: &Release) -> Result<PathBuf> {
    check_dirs(m)?;
    let size = open_regular(src)?.metadata().map_err(|e| Error::from(e).wrap(format!("stat {}", src.display())))?.len();
    if size == 0 || size > osupdate::MAX_K3S {
        bail!("{} is {size} bytes, not a k3s binary (at most {})", src.display(), osupdate::MAX_K3S);
    }
    let dst = staged_k3s(m, rel.serial);
    let tmp = tmp_of(&dst);
    copy_exact(m, src, &tmp, size, 0o600, "stage k3s")?;
    fsx::rename(&tmp, &dst)?;
    sync_dir(&m.path(STAGING))?;
    if let Err(e) = release::verify_file(&dst, &rel.k3s.sha256, size) {
        let _ = fs::remove_file(&dst);
        return Err(e.wrap("the k3s binary is not the one the release names"));
    }
    Ok(dst)
}

/// What osupdate says while it works: shown and logged after each step.
#[derive(Clone, Default)]
struct HostLog(Arc<Mutex<Vec<String>>>);

impl HostLog {
    fn func(&self) -> LogFn {
        let v = self.0.clone();
        Arc::new(move |s: &str| v.lock().unwrap_or_else(|e| e.into_inner()).push(s.to_string()))
    }

    fn flush(&self, m: &Machine, out: &mut dyn Write) {
        let lines = std::mem::take(&mut *self.0.lock().unwrap_or_else(|e| e.into_inner()));
        for l in lines {
            tell(m, out, m.now(), &l);
        }
    }
}

/// The k3s binary and the packages of this machine, for osupdate.
fn host<'a>(m: &'a Machine, log: &HostLog) -> osupdate::Host<'a> {
    osupdate::Host {
        root: m.root.clone(),
        run: m.run.as_ref(),
        log: log.func(),
        owner: m.owner,
        limits: m.limits.clone(),
        hook: m.hook.clone(),
        lock_fd: None,
    }
}

/// Whether the packages here are of a newer day (pinned) than the
/// release's, and stay so: no going back without a rollback (a machine
/// installed after the release, from a stick built later, runs newer
/// packages, and that is no reason to refuse the rest of the release). A
/// rollback takes them back; on a machine with no release installed, only
/// one signed after it began to take releases: an old rollback sent again
/// does not take its packages below what it was installed with.
fn newer_here(pinned: &str, rel: &Release, installed: bool, since: i64) -> bool {
    let (Ok(here), Ok(day)) = (release::arch_day(pinned), release::arch_day(&rel.arch_date)) else { return false };
    let may_go_back = rel.rollback && (installed || (since > 0 && rel.created > since));
    here > day && !may_go_back
}

/// Whether the packages have to be brought to date. The mirrorlist pins
/// another day (or none), or the last run on that day did not finish.
///
/// The fallback kernel waiting for its own run (one kernel at a time)
/// makes a run due only once the main kernel has booted well: until then
/// that run could not take it anyway, and a dryserver-only release must
/// not run pacman every time on a machine that cannot reboot by itself.
///
/// Pinned to the day without any record of a run: a fresh machine its
/// installer pinned to the day it installed from, nothing to do; unless
/// the release is a rollback to that day, since the installer took its
/// packages from mirrors of that day or newer, and a rollback asks for
/// exactly that day's.
fn arch_due(m: &Machine, date: &str, rollback: bool) -> bool {
    if osupdate::pinned_date(&fsx::read_or_empty(m.path(osupdate::MIRRORLIST))).as_deref() != Some(date) {
        return true;
    }
    match read_json::<ArchState>(m, ARCH_STATE) {
        Ok(Some(s)) if !(s.date == date && s.done) => true,
        Ok(Some(s)) => s.lts_waits && host(m, &HostLog::default()).main_booted_well(),
        Ok(None) => rollback,
        Err(_) => true,
    }
}

/// Why an apply did not get to change the machine. again: a problem that
/// may pass, worth another try later.
struct Refusal {
    serial: u64,
    again: bool,
    err: Error,
}

/// What the binary that runs `update apply` checked before it hands over:
/// the signed release, and the new binary staged and checked against it.
struct Intake {
    env: Envelope,
    rel: Release,
    previous: Option<u64>,
    staged: PathBuf,
    prev_sha256: String,
    /// The coordinator's k3s the release was checked against (a server).
    brain_k3s: String,
}

/// The k3s and Arch steps of an update, decided and loaded by the binary
/// that carries them out (the new one: see the handover) before anything
/// but the mirrorlist changed, and installed once it took over the files.
/// Between its two steps it waits in the record (Pending::work); its
/// format is that binary's own.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct Work {
    /// The k3s step: the staged binary (None: the release's is in place,
    /// its check still due), and the checksum of the k3s to go back to.
    k3s: Option<(Option<PathBuf>, String)>,
    /// The packages go to the release's snapshot day: checked and loaded,
    /// to be installed.
    arch: Option<ArchOutcome>,
}

/// Records why an apply changed nothing, for whoever started it (a
/// detached apply has nobody else to tell), and hands back the error.
fn refused(m: &Machine, out: &mut dyn Write, now: i64, r: Refusal) -> Error {
    if r.serial != 0 {
        let _ = fs::remove_file(staged_k3s(m, r.serial));
        let (action, how) = if r.again {
            (POSTPONED, "not applied for now, nothing was changed; it is tried again later")
        } else {
            (REFUSED, "refused, nothing was changed")
        };
        record(m, out, now, r.serial, action, false, &format!("release {} {how}: {}", r.serial, r.err));
    }
    r.err
}

/// The checks of the binary that runs `update apply`: the release (its
/// signature, against what is installed and what runs), and the new binary
/// staged and checked against it. Changes nothing but the staging
/// directory.
fn intake(m: &Machine, ctx: &Ctx, a: &Apply, now: i64, out: &mut dyn Write) -> std::result::Result<Option<Intake>, Refusal> {
    let early = |again: bool| move |err: Error| Refusal { serial: 0, again, err };
    refuse_if_cut(m).map_err(early(true))?;
    let env = read_envelope(&a.release).map_err(early(false))?;
    if let Some(p) = load_pending(m).map_err(early(false))? {
        if p.release.doc == env.doc && p.stage == STAGE_ARMED {
            say(out, format!("release {} is applied already and waits for confirm until {}", p.serial, when(p.deadline)));
            return Ok(None);
        }
        let err = if p.release.doc == env.doc {
            // No apply runs (this one holds the lock): it was stopped.
            errf!(
                "release {} did not finish applying (its apply was stopped): it goes back by its timer or at the next boot, or now with dryserver update revert",
                p.serial
            )
        } else {
            errf!("release {} waits for confirm or revert; finish it first (dryserver update status)", p.serial)
        };
        return Err(Refusal { serial: 0, again: true, err });
    }
    let installed = load_installed(m).map_err(early(false))?;
    let role = role_of(m).map_err(early(false))?;
    let brain = match role {
        Role::Coordinator => None,
        Role::Node if !a.brain_k3s.is_empty() => Some(a.brain_k3s.clone()),
        Role::Node => Some(local_k3s(m, ctx).map_err(|e| early(false)(e.wrap("give the coordinator's k3s version with --brain-k3s")))?),
    };
    let place = match &brain {
        None => Place::Brain,
        Some(b) => Place::Worker { brain_k3s: b },
    };
    let (since, _) = start_of(m, now);
    let start = release::Start { since };
    let (rel, verdict) =
        release::check_from(m.verifier.as_ref(), &env, installed.as_ref().map(|(_, r)| r), start, place, now).map_err(early(false))?;
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
        return Ok(None);
    }
    let serial = rel.serial;
    let no = move |err: Error| Refusal { serial, again: false, err };
    // A full disk passes once room is made: postponed, not refused.
    let full = move |err: Error| Refusal { serial, again: passing(&err), err };
    let staged_already = a.binary.parent() == Some(m.path(STAGING).as_path());
    let mut copies = vec![(m.path(SERVER_BIN), rel.dryserver.size)];
    if !staged_already {
        copies.push((m.path(STAGING), rel.dryserver.size));
    }
    room_for(m, &copies).map_err(|err| Refusal { serial, again: true, err })?;
    let staged = stage(m, &a.binary, &rel).map_err(full)?;
    release::verify_file(&staged, &rel.dryserver.sha256, rel.dryserver.size)
        .map_err(|e| no(e.wrap("the binary is not the one the release names")))?;
    let (prev_sha256, _) =
        release::hash_file(&m.path(SERVER_BIN), release::MAX_BINARY).map_err(|e| no(e.wrap("the installed dryserver")))?;
    let previous = installed.as_ref().map(|(_, r)| r.serial);
    Ok(Some(Intake { env, rel, previous, staged, prev_sha256, brain_k3s: brain.unwrap_or_default() }))
}

/// Decides the k3s and Arch steps of release rel and checks what they
/// need: pacman (osupdate::arch_check: its settings, the room on disk, no
/// other pacman at work) and the k3s binary, staged from k3s_file. Changes
/// nothing but the staging directory (and clears a stale pacman lock).
/// Err: whether another try later may work, and why.
fn plan_work(m: &Machine, rel: &Release, k3s_file: &str, log: &HostLog, out: &mut dyn Write) -> std::result::Result<Work, (bool, Error)> {
    let now = m.now();
    let installed = load_installed(m).map_err(|e| (false, e))?.is_some();
    let (since, pinned) = start_of(m, now);
    let host = host(m, log);
    let arch = if let Some(day) = pinned.as_deref().filter(|p| newer_here(p, rel, installed, since)) {
        tell(
            m,
            out,
            now,
            &format!(
                "the Arch packages here are of {day}, newer than the release's {} (installed later): they stay as they are, the next release moves them",
                rel.arch_date
            ),
        );
        None
    } else if arch_due(m, &rel.arch_date, rel.rollback) {
        let o = host.arch_check(&rel.arch_date, rel.rollback);
        log.flush(m, out);
        if let Some(f) = &o.failure {
            return Err((f.again, f.reason.clone()));
        }
        for w in &o.warnings {
            tell(m, out, now, &format!("warning: {w}"));
        }
        Some(o)
    } else {
        None
    };
    // k3s by what this machine runs, whatever its records say.
    let sha_of = |p: &str| release::hash_file(&m.path(p), osupdate::MAX_K3S).ok().map(|(h, _)| h);
    let running = sha_of(K3S_BIN);
    let k3s = if running.as_deref() == Some(rel.k3s.sha256.as_str()) {
        host.k3s_unchecked(&rel.k3s.sha256).then(|| (None, sha_of(osupdate::K3S_PREV).unwrap_or_default()))
    } else {
        if k3s_file.is_empty() {
            let e =
                errf!("release {} names k3s {} and this machine runs another one: give its binary with --k3s", rel.serial, rel.k3s.version);
            return Err((false, e));
        }
        // Staged, then copied next to the installed one (osupdate).
        let size = fs::metadata(k3s_file).map(|md| md.len()).unwrap_or(0);
        room_for(m, &[(m.path(STAGING), size), (m.path(K3S_BIN), size)]).map_err(|e| (true, e))?;
        let staged = stage_k3s(m, Path::new(k3s_file), rel).map_err(|e| (passing(&e), e))?;
        Some((Some(staged), running.unwrap_or_default()))
    };
    Ok(Work { k3s, arch })
}

/// The steps before the new binary takes over the files: plan_work, then
/// the packages are loaded (the mirrorlist pinned through the record
/// first). Err: whether another try later may work, and why.
fn prepare_work(
    m: &Machine,
    ctx: &Ctx,
    p: &mut Pending,
    rel: &Release,
    log: &HostLog,
    out: &mut dyn Write,
) -> std::result::Result<Work, (bool, Error)> {
    let mut w = plan_work(m, rel, &p.k3s_file, log, out)?;
    let mut what = Vec::new();
    if w.k3s.is_some() {
        what.push(format!("k3s {}", rel.k3s.version));
    }
    if let Some(o) = &w.arch {
        what.push(format!("the Arch packages of {}", o.date));
        p.arch_date = o.date.clone();
        save_pending(m, p).map_err(|e| (true, e))?;
    }
    if !what.is_empty() {
        tell(m, out, m.now(), &format!("release {} brings {} too", rel.serial, what.join(" and ")));
    }
    // The packages are loaded before anything else changes: a dead or slow
    // mirror ends the update here, with only the mirrorlist to put back.
    if let Some(o) = w.arch.as_mut() {
        prepare_arch(m, ctx, p, o, log, out)?;
    }
    Ok(w)
}

/// The handover protocol the binary at bin speaks (`update handover`; see
/// the module), 0 for one from before it: a rollback to an older
/// dryserver, which only writes the files and expects the rest of the
/// update of the binary that started it.
fn handover_of(m: &Machine, ctx: &Ctx, bin: &Path) -> u32 {
    let (o, res) = m.run.run(&ctx.with_timeout(SELFCHECK_TIME), &Cmd::new(&bin.display().to_string(), &["update", "handover"]));
    if res.is_err() {
        return 0;
    }
    o.split_whitespace().next().and_then(|w| w.parse().ok()).unwrap_or(0)
}

/// Installs and checks the release in envelope `release` with the binary
/// `binary`, and its k3s and packages when they are not this machine's
/// yet (see the module). Refusals change nothing; a dead mirror changes
/// nothing either. Once it starts changing the machine, any failure
/// reverts it before returning.
pub fn apply(m: &Machine, ctx: &Ctx, a: &Apply, now: i64, out: &mut dyn Write) -> Result<()> {
    if !(MIN_WINDOW..=MAX_WINDOW).contains(&a.window) {
        bail!("the window must be between {MIN_WINDOW} and {MAX_WINDOW} seconds, not {}", a.window);
    }
    ensure_dirs(m)?;
    let lock = lock_wait(m, ctx, APPLY_LOCK_WAIT)?;
    let i = match intake(m, ctx, a, now, out) {
        Ok(Some(i)) => i,
        Ok(None) => return Ok(()),
        Err(r) => return Err(refused(m, out, now, r)),
    };
    let rel = i.rel.clone();
    let serial = rel.serial;
    if let Err(e) = ensure_boot_guard(m, ctx) {
        let err = e.wrap("cannot install the boot half of the revert guard, nothing was changed");
        return Err(refused(m, out, now, Refusal { serial, again: true, err }));
    }
    let k3s_file = match &a.k3s {
        Some(k) => std::path::absolute(k).unwrap_or_else(|_| k.clone()).display().to_string(),
        None => String::new(),
    };
    let mut p = Pending {
        format: PENDING_FORMAT,
        id: fsx::hex(&fsx::random_bytes(8)),
        stage: STAGE_PREPARING.into(),
        serial,
        version: rel.dryserver.version.clone(),
        previous: i.previous,
        release: i.env.clone(),
        applied: now,
        deadline: now.saturating_add(APPLY_TIME),
        window: a.window,
        boots: 0,
        prev_sha256: i.prev_sha256.clone(),
        new_sha256: rel.dryserver.sha256.clone(),
        files: Vec::new(),
        step: "starting".into(),
        k3s_file,
        brain_k3s: i.brain_k3s.clone(),
        may_reboot: a.reboot,
        ..Pending::default()
    };
    let armed = save_pending(m, &p).and_then(|_| arm(m, ctx, Timer::Apply, &p.id, serial, APPLY_TIME, false));
    if let Err(e) = armed {
        let _ = clear_pending(m);
        let err = e.wrap("cannot arm the timer that reverts an unconfirmed update, nothing was changed");
        return Err(refused(m, out, now, Refusal { serial, again: true, err }));
    }
    let notes = if rel.notes.is_empty() { String::new() } else { format!(": {}", rel.notes) };
    tell(m, out, now, &format!("applying release {serial} (dryserver {}){notes}", rel.dryserver.version));
    let res = steps(m, ctx, &i, &mut p, Some(lock.as_raw_fd()), out);
    let _ = fs::remove_file(staged_k3s(m, serial));
    let Err((undo, e)) = res else {
        let _ = fs::remove_file(&i.staged);
        return Ok(());
    };
    // The latest record: the new binary may have added files. A fresh
    // context: when the apply was cancelled (Ctrl-C), the way back must
    // still run.
    let latest = load_pending(m).ok().flatten().filter(|q| q.id == p.id).unwrap_or(p);
    let rctx = Ctx::new().with_timeout(REVERT_TIME);
    if undo == Undo::Revert {
        let why = format!("the apply failed: {e}");
        return match revert(m, &rctx, latest, &why, false, m.now(), out, Undo::Revert) {
            Ok(()) => Err(e.wrap(format!("release {serial} not applied, this machine runs what it ran before"))),
            Err(r) => Err(errf!("release {serial} not applied: {e}\nand the way back did not finish: {r}")),
        };
    }
    match revert(m, &rctx, latest, &e.to_string(), false, m.now(), out, undo) {
        Ok(()) => Err(e.wrap(format!("release {serial} not applied, nothing was installed"))),
        Err(r) => Err(errf!("release {serial} not applied: {e}\nand putting the mirrorlist back did not finish: {r}")),
    }
}

/// The part of apply after the record and its timer are there: the new
/// binary checked next to the installed one, then handed over to (see the
/// module). Err: how the update goes back, and why.
fn steps(
    m: &Machine,
    ctx: &Ctx,
    i: &Intake,
    p: &mut Pending,
    lock_fd: Option<i32>,
    out: &mut dyn Write,
) -> std::result::Result<(), (Undo, Error)> {
    let back = |e: Error| (Undo::Revert, e);
    let rel = &i.rel;
    check_new_binary(m, ctx, &i.staged, rel, out).map_err(back)?;
    let new = m.path(NEW_BIN);
    let handover = handover_of(m, ctx, &new).min(HANDOVER);
    let log = HostLog::default();
    let mut work = None;
    if handover >= 1 {
        p.handover = handover;
        p.step = "the new dryserver checks what else the release brings, and loads it".into();
        save_pending(m, p).map_err(back)?;
        let cmd =
            Cmd::new(&new.display().to_string(), &["update", "prepare", "--id", &p.id]).interrupt(Some(PREPARE_GRACE)).keep_fd(lock_fd);
        let (o, res) = m.run.run(&ctx.with_timeout(PREPARE_TIME), &cmd);
        let _ = out.write_all(o.as_bytes());
        let q = current(m, &p.id).map_err(back)?;
        if let Err(e) = res {
            // The new binary says why, and whether another try may work.
            // One that died without saying is a release that does not work
            // here.
            let (undo, why) = match (q.why.is_empty(), q.again) {
                (true, _) => (Undo::Refuse, e.wrap("the new dryserver could not prepare the update")),
                (false, true) => (Undo::Postpone, Error::new(q.why.clone())),
                (false, false) => (Undo::Refuse, Error::new(q.why.clone())),
            };
            *p = q;
            return Err((undo, why));
        }
        *p = q;
    } else {
        // A dryserver from before the handover (a rollback to one) only
        // writes the files: the rest is this binary's, as it expects.
        let w = prepare_work(m, ctx, p, rel, &log, out).map_err(|(again, e)| (if again { Undo::Postpone } else { Undo::Refuse }, e))?;
        work = Some(w);
    }
    p.stage = STAGE_INSTALLING.into();
    p.step = format!("installing dryserver {}", rel.dryserver.version);
    save_pending(m, p).map_err(back)?;
    switch_binary(m, rel, out).map_err(back)?;
    // The new binary takes over: the files, and from a handover on all the
    // rest. pacman is never killed: a stopped apply passes SIGINT on.
    let cmd = Cmd::new(&m.shown(SERVER_BIN), &["update", "activate", "--id", &p.id]);
    let (o, res) = if handover >= 1 {
        m.run.run(&ctx.with_timeout(HANDOVER_TIME), &cmd.interrupt(None).keep_fd(lock_fd))
    } else {
        m.run.run(&ctx.with_timeout(ACTIVATE_TIME), &cmd)
    };
    let _ = out.write_all(o.as_bytes());
    let Some(mut w) = work else {
        return res.map_err(|e| back(e.wrap("the new dryserver could not finish the update")));
    };
    res.map_err(|e| back(e.wrap("the new dryserver could not take over the system files")))?;
    let role = role_of(m).map_err(back)?;
    let rebooting = install_work(m, ctx, &p.id, &i.env, rel, role, &mut w, lock_fd, &log, out).map_err(back)?;
    applied(m, ctx, rel.serial, w.arch.as_ref(), rebooting, &p.id, out);
    Ok(())
}

/// `update apply --detach`: starts the apply in a transient service of its
/// own (APPLY_UNIT) and returns once it runs. The sync that starts it stays
/// responsive while pacman works, and stopping or killing the sync never
/// stops pacman half way. The service's own stop (a shutdown, systemctl
/// stop) sends SIGINT to the apply alone (KillMode=mixed), which passes it
/// on to the new binary's step and that to pacman alone: pacman then stops
/// between two packages, and the hooks it runs (mkinitcpio, ukify making a
/// boot image) are never interrupted. With the default, every process of
/// the service got SIGINT, those hooks too. What is left after
/// APPLY_STOP_TIME is killed. `update status` says how it goes (busy, then
/// pending or last).
pub fn start_detached(m: &Machine, ctx: &Ctx, a: &Apply, out: &mut dyn Write) -> Result<()> {
    if !(MIN_WINDOW..=MAX_WINDOW).contains(&a.window) {
        bail!("the window must be between {MIN_WINDOW} and {MAX_WINDOW} seconds, not {}", a.window);
    }
    ensure_dirs(m)?;
    if try_lock(m)?.is_none() {
        bail!("another update is running on this machine; dryserver update status says how it goes");
    }
    // The service starts in /, with paths as given.
    let abs = |p: &Path| std::path::absolute(p).map(|p| p.display().to_string()).map_err(|e| Error::from(e).wrap(p.display()));
    let mut args = vec![
        format!("--unit={APPLY_UNIT}"),
        "--collect".into(),
        "--service-type=exec".into(),
        "--property=KillSignal=SIGINT".into(),
        "--property=KillMode=mixed".into(),
        format!("--property=TimeoutStopSec={APPLY_STOP_TIME}"),
        format!("--description=Apply dryserver release {}", a.release.display()),
        m.shown(SERVER_BIN),
        "update".into(),
        "apply".into(),
        "--release".into(),
        abs(&a.release)?,
        "--binary".into(),
        abs(&a.binary)?,
        "--window".into(),
        a.window.to_string(),
    ];
    if let Some(k) = &a.k3s {
        args.extend(["--k3s".into(), abs(k)?]);
    }
    if !a.brain_k3s.is_empty() {
        args.extend(["--brain-k3s".into(), a.brain_k3s.clone()]);
    }
    if a.reboot {
        args.push("--reboot".into());
    }
    m.cmd(ctx, "systemd-run", &args.iter().map(String::as_str).collect::<Vec<_>>())
        .map_err(|e| e.wrap("cannot start the update in a service of its own"))?;
    say(out, format!("the update runs in {APPLY_UNIT}.service: dryserver update status says how it goes"));
    Ok(())
}

/// Pins the mirrorlist to the release's day (through the record, so a
/// revert puts the list from before back) and loads everything
/// (osupdate::arch_download). Err: whether another try may work, and why.
fn prepare_arch(
    m: &Machine,
    ctx: &Ctx,
    p: &mut Pending,
    o: &mut ArchOutcome,
    log: &HostLog,
    out: &mut dyn Write,
) -> std::result::Result<(), (bool, Error)> {
    p.step = format!("loading the packages of Arch {}", o.date);
    let list = osupdate::mirrorlist(&o.date).map_err(|e| (false, e))?;
    let mut ch = Changes::new(m, p.clone());
    ch.put(osupdate::MIRRORLIST, 0o644, list.as_bytes()).map_err(|e| (true, e.wrap("pin the snapshot")))?;
    *p = ch.p;
    save_pending(m, p).map_err(|e| (true, e))?;
    m.at("pinned").map_err(|e| (true, e))?;
    host(m, log).arch_download(ctx, o);
    log.flush(m, out);
    match &o.failure {
        Some(f) => Err((f.again, f.reason.clone())),
        None => Ok(()),
    }
}

/// The record of the update with this id, as it is on disk now.
fn current(m: &Machine, id: &str) -> Result<Pending> {
    let p = load_pending(m)?.ok_or_else(|| errf!("the pending record is gone"))?;
    if p.id != id {
        bail!("another update took over the pending record");
    }
    Ok(p)
}

/// The update lock as this process got it from the apply that started it
/// (Cmd::keep_fd), marked close-on-exec again: only pacman's install keeps
/// it (osupdate::Host::lock_fd). None when there is none.
fn inherited_lock(m: &Machine) -> Option<i32> {
    let want = m.path(LOCK);
    for e in fs::read_dir("/proc/self/fd").ok()?.flatten().take(4096) {
        let Some(fd) = e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else { continue };
        if fs::read_link(e.path()).ok().as_deref() == Some(want.as_path()) {
            // SAFETY: fcntl on a descriptor of this process; it only sets
            // its close-on-exec flag.
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
            return Some(fd);
        }
    }
    None
}

/// The new binary's record of update id, for its steps: the one being
/// applied, at stage, handed over in a way this binary knows.
fn handed(m: &Machine, id: &str, stage: &str, what: &str) -> Result<Pending> {
    if try_lock(m)?.is_some() {
        bail!("update {what} is a step of update apply and runs only inside it");
    }
    let p = load_pending(m)?.ok_or_else(|| errf!("no update is being applied"))?;
    if p.id != id || p.stage != stage {
        bail!("update {id:?} is not the one being applied");
    }
    if p.handover > HANDOVER {
        bail!("update {id:?} hands over the way {} does, which this dryserver does not know (it knows {HANDOVER})", p.handover);
    }
    Ok(p)
}

/// The release in the record, its signature checked again by this binary.
fn release_of(m: &Machine, p: &Pending) -> Result<Release> {
    let rel = release::open(m.verifier.as_ref(), &p.release, m.now())?;
    if rel.serial != p.serial || rel.dryserver.sha256 != p.new_sha256 {
        bail!("the pending record does not match its release");
    }
    Ok(rel)
}

/// `update prepare`: the new binary's first step (handover), run from its
/// copy next to the installed one before it takes over: decides and checks
/// the k3s and Arch steps and loads the packages (prepare_work). On a
/// failure it says in the record why and whether another try may work;
/// the binary that started the update puts the mirrorlist back.
pub fn prepare(m: &Machine, ctx: &Ctx, id: &str, out: &mut dyn Write) -> Result<()> {
    let mut p = handed(m, id, STAGE_PREPARING, "prepare")?;
    if p.handover == 0 {
        bail!("update {id:?} was not handed over to this binary");
    }
    let _ = inherited_lock(m);
    let log = HostLog::default();
    let res = release_of(m, &p).map_err(|e| (false, e)).and_then(|rel| {
        refuse_if_cut(m).map_err(|e| (true, e))?;
        prepare_work(m, ctx, &mut p, &rel, &log, out)
    });
    match res {
        Ok(w) => {
            p.work = serde_json::to_value(&w)?;
            p.step = "loaded; the new dryserver takes over next".into();
            save_pending(m, &p)
        }
        Err((again, e)) => {
            let mut q = current(m, id).unwrap_or(p);
            q.why = e.to_string();
            q.again = again;
            let _ = save_pending(m, &q);
            Err(e)
        }
    }
}

/// The part of an update after the new binary took over the files: k3s
/// and the packages, in this order (what a revert puts back first, what it
/// cannot last). Then the release counts as installed and the confirm
/// window starts. Returns whether the machine reboots now.
#[allow(clippy::too_many_arguments)]
fn install_work(
    m: &Machine,
    ctx: &Ctx,
    id: &str,
    env: &Envelope,
    rel: &Release,
    role: Role,
    w: &mut Work,
    lock_fd: Option<i32>,
    log: &HostLog,
    out: &mut dyn Write,
) -> Result<bool> {
    let mut p = current(m, id)?;
    let host = osupdate::Host { lock_fd, ..host(m, log) };
    if let Some((staged, prev)) = &w.k3s {
        // Recorded first: a revert from here on puts that k3s back.
        p.k3s_prev_sha256 = prev.clone();
        p.step = format!("installing k3s {}", rel.k3s.version);
        save_pending(m, &p)?;
        let outcome = host.k3s_install(ctx, staged.as_deref(), &rel.k3s.sha256, &rel.k3s.version, role);
        log.flush(m, out);
        match outcome? {
            K3sOutcome::Unchanged | K3sOutcome::Running => {}
            K3sOutcome::Placed { why } => {
                tell(m, out, m.now(), &format!("k3s {} is in place and starts once it may: {why}", rel.k3s.version))
            }
            K3sOutcome::Reverted { why } => bail!("k3s {} was not healthy ({why}); the k3s from before runs again", rel.k3s.version),
            K3sOutcome::Broken { why, revert, .. } => {
                bail!(
                    "k3s {} was not healthy ({why}), and going back to the k3s from before did not work either ({revert})",
                    rel.k3s.version
                )
            }
        }
        m.at("k3s done")?;
    }
    let mut reboot = false;
    if let Some(o) = w.arch.as_mut() {
        // The last moment to stop before what a revert cannot undo.
        refuse_if_cut(m)?;
        p.step = format!("installing the packages of Arch {}", o.date);
        save_pending(m, &p)?;
        host.arch_install(ctx, o);
        log.flush(m, out);
        save_arch_state(m, o);
        for w in &o.warnings {
            tell(m, out, m.now(), &format!("warning: {w}"));
        }
        if !o.ok() {
            bail!("{}", o.summary());
        }
        reboot = p.may_reboot && o.reboot_needed() && o.reboot_safe() && host.reboot_blocker().is_none();
        p.kernel = o.main_new;
    }
    let mut ch = Changes::new(m, p);
    ch.put(INSTALLED, 0o600, (serde_json::to_string_pretty(env)? + "\n").as_bytes())?;
    let mut p = ch.p;
    // The confirm window starts now that the apply is done; a reboot gets
    // it the time to come back.
    let window = if reboot { (p.window + REBOOT_WINDOW).min(MAX_WINDOW) } else { p.window };
    arm(m, ctx, Timer::Window, id, rel.serial, window, false).map_err(|e| e.wrap("cannot arm the timer of the confirm window"))?;
    p.stage = STAGE_ARMED.into();
    p.deadline = m.now().saturating_add(window);
    p.window = window;
    p.step.clear();
    p.reboot = reboot;
    save_pending(m, &p)?;
    m.at("armed")?;
    // The apply's own timer has nothing left to do (and would do nothing).
    stop_timer(m, ctx, id, Timer::Apply);
    Ok(reboot)
}

/// The end of an apply that went well: said and recorded, then the reboot
/// its packages need.
fn applied(m: &Machine, ctx: &Ctx, serial: u64, arch: Option<&ArchOutcome>, rebooting: bool, id: &str, out: &mut dyn Write) {
    let deadline = load_pending(m).ok().flatten().map_or(0, |q| q.deadline);
    let msg =
        format!("release {serial} is applied. Confirm it before {} (dryserver update confirm), or it reverts by itself", when(deadline));
    record(m, out, m.now(), serial, "applied", true, &msg);
    reboot_after(m, ctx, arch, rebooting, id, out);
}

/// What the last run did to the packages, kept beside the update records:
/// the next apply and update status read it.
fn save_arch_state(m: &Machine, o: &ArchOutcome) {
    let s = ArchState {
        date: o.date.clone(),
        done: o.ok(),
        at: m.now(),
        restart: o.restart.clone(),
        kernel: o.kernel_replaced,
        boot_problem: o.boot_problem.clone().unwrap_or_default(),
        summary: o.summary(),
        lts_waits: o.lts_waits,
        untouched: !o.ok() && o.untouched,
    };
    if let Err(e) = save_json(m, ARCH_STATE, &s) {
        note(m, m.now(), &format!("cannot keep {ARCH_STATE}: {e}"));
    }
}

/// What a reboot would start, for people.
fn reboot_reason(kernel: bool, restart: &[String]) -> String {
    match (kernel, restart.is_empty()) {
        (true, _) => "the new kernel".into(),
        (false, false) => format!("the new {}", restart.join(", ")),
        (false, true) => "the new packages".into(),
    }
}

/// After an apply: the reboot its packages need, started now (rebooting:
/// the record says so, and the confirm waits for the restart) or left to
/// the admin, and said either way. Never after a failed run: that one
/// reverted instead.
fn reboot_after(m: &Machine, ctx: &Ctx, arch: Option<&ArchOutcome>, rebooting: bool, id: &str, out: &mut dyn Write) {
    let Some(o) = arch.filter(|o| o.reboot_needed()) else { return };
    let now = m.now();
    let what = reboot_reason(o.kernel_replaced, &o.restart);
    if !o.reboot_safe() {
        let why = o.boot_problem.as_deref().unwrap_or("the boot image may be broken");
        tell(m, out, now, &format!("warning: {what} needs a reboot, but rebooting is NOT safe now ({why}): fix that first"));
        return;
    }
    if !rebooting {
        let log = HostLog::default();
        let msg = match host(m, &log).reboot_blocker() {
            Some(why) => format!("{what} needs a reboot, and this machine cannot reboot by itself ({why})"),
            None => format!("{what} needs a reboot: sudo systemctl reboot, then confirm the update"),
        };
        tell(m, out, now, &msg);
        return;
    }
    tell(m, out, now, &format!("rebooting to start {what}; the update waits for its confirm after the restart"));
    if let Err(e) = m.cmd(ctx, "systemctl", &["--no-block", "reboot"]) {
        tell(m, out, now, &format!("warning: the reboot did not start ({e}): reboot by hand, then confirm the update"));
        if let Ok(mut q) = current(m, id) {
            q.reboot = false;
            let _ = save_pending(m, &q);
        }
    }
}

/// Copies the staged binary next to the installed one (NEW_BIN) and has it
/// pass its self check there: what runs is the copy, so the copy is what
/// is checked. Nothing is switched yet.
fn check_new_binary(m: &Machine, ctx: &Ctx, staged: &Path, rel: &Release, out: &mut dyn Write) -> Result<()> {
    let new = m.path(NEW_BIN);
    let bin_dir = fsx::dir(m.path(SERVER_BIN));
    let checked = (|| -> Result<()> {
        copy_exact(m, staged, &new, rel.dryserver.size, 0o700, "copy")?;
        fsx::chmod(&new, 0o755)?;
        sync_dir(&bin_dir)?;
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
    m.at("binary checked")
}

/// Puts the checked copy (NEW_BIN) in place of the installed binary,
/// keeping that one as dryserver.prev.
fn switch_binary(m: &Machine, rel: &Release, out: &mut dyn Write) -> Result<()> {
    let (bin, prev, prev_tmp, new) = (m.path(SERVER_BIN), m.path(PREV_BIN), m.path(PREV_TMP), m.path(NEW_BIN));
    let bin_dir = fsx::dir(&bin);
    // The copy that was checked and ran its first step, still the one the
    // release names.
    release::verify_file(&new, &rel.dryserver.sha256, rel.dryserver.size).map_err(|e| e.wrap("the copy of the new binary"))?;
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

/// `update activate`: the new binary's half of apply, run as the installed
/// binary once it took that name. It renders the system files, writes what
/// changed, runs the state migrations, checks and reloads; then, when the
/// update was handed over to it (from a binary with the handover on), the
/// rest: k3s, the packages, the release recorded as installed, the confirm
/// window, the reboot. Runs only inside `update apply`, which holds the
/// lock and reverts when this fails.
pub fn activate(m: &Machine, ctx: &Ctx, id: &str, out: &mut dyn Write) -> Result<()> {
    let p = {
        // Sync, join and the kill switch change the mesh files under this
        // lock; a cut that landed since apply looked counts too. The record
        // is read under it as well: a revert that ran while this waited for
        // the lock has cleared it or marked it reverting.
        if try_lock(m)?.is_some() {
            bail!("update activate is a step of update apply and runs only inside it");
        }
        let _mesh = fsx::lock(m.path(quarantine::MESH_LOCK))?;
        let p = handed(m, id, STAGE_INSTALLING, "activate")?;
        refuse_if_cut(m)?;
        let files = render_managed(m)?;
        let mut ch = Changes::new(m, p);
        for f in &files {
            ch.put(&f.path, f.mode, f.content.as_bytes())?;
        }
        let migrated = migrate(&mut ch, m.migrations)?;
        let changed = ch.changed.clone();
        validate(m, ctx, &changed)?;
        reload(m, ctx, &changed)?;
        if changed.is_empty() {
            say(out, "no system file changed");
        }
        for c in &changed {
            say(out, format!("changed {c}"));
        }
        for w in migrated {
            say(out, format!("state migrated: {w}"));
        }
        ch.p
    };
    if p.handover == 0 {
        // Started by a dryserver from before the handover: it installs k3s
        // and the packages itself.
        return Ok(());
    }
    let lock_fd = inherited_lock(m);
    let rel = release_of(m, &p)?;
    let role = role_of(m)?;
    let mut w: Work = if p.work.is_null() {
        Work::default()
    } else {
        serde_json::from_value(p.work.clone()).map_err(|e| Error::from(e).wrap("what update prepare loaded"))?
    };
    let log = HostLog::default();
    let rebooting = install_work(m, ctx, id, &p.release, &rel, role, &mut w, lock_fd, &log, out)?;
    applied(m, ctx, rel.serial, w.arch.as_ref(), rebooting, id, out);
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

/// What a revert stands for, which its record says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Undo {
    /// An update that changed the machine goes back.
    Revert,
    /// An apply that stopped while it loaded the packages: nothing but the
    /// mirrorlist changed, and another try later may work.
    Postpone,
    /// The same, for a problem another try does not fix.
    Refuse,
}

/// Undoes an update: the binary, then every file in reverse order (the
/// mirrorlist among them), then the k3s that ran before when this update
/// swapped it, then reloads, then the record goes. Each step can run again
/// after a power cut; the record says "reverting" until the end, so the
/// boot unit finishes the job. When the binary, a file or k3s cannot be
/// put back (a full disk), the record and the backups stay as well, so
/// nothing says the machine runs what it ran before while it does not: a
/// retry timer (REVERT_RETRY), the next boot, a sync's settle or `update
/// revert` tries again. A reload that fails does not keep them: the files
/// are back, and the next boot loads them. At boot nothing has started yet, so only
/// systemd reloads its units (k3s starts after the boot unit, with the
/// binary that is back). The packages are not put back: that is a signed
/// rollback release's work.
#[allow(clippy::too_many_arguments)]
fn revert(m: &Machine, ctx: &Ctx, mut p: Pending, why: &str, boot: bool, now: i64, out: &mut dyn Write, undo: Undo) -> Result<()> {
    if undo == Undo::Revert {
        tell(m, out, now, &format!("reverting release {}: {why}", p.serial));
    }
    // An activate that still runs (its apply was cancelled or died) holds
    // the mesh lock while it writes files and adds them to the record.
    // Once it is done, the record is read again, so the files it added are
    // put back too; marked reverting, it lets no activate start after.
    let _mesh = fsx::lock(m.path(quarantine::MESH_LOCK)).ok();
    let mut problems = Vec::new();
    // A record that cannot be read may list files the one in hand does
    // not: what is known is put back, but the record and the backups stay
    // for a look, and the revert says it did not finish.
    let damaged = match load_pending(m) {
        Ok(Some(q)) if q.id == p.id => {
            p = q;
            false
        }
        Ok(_) => false,
        Err(e) => {
            problems.push(format!("{e}: it stays, with the backups, until someone looks (dryserver update status)"));
            true
        }
    };
    if !damaged {
        p.stage = STAGE_REVERTING.into();
        p.step = "going back".into();
        let _ = save_pending(m, &p);
    }
    // The binary, a file or k3s that is not back for a reason that may
    // pass (a full disk): the record stays, and it is tried again. One
    // that will not pass (dryserver.prev gone, a backup lost) is said, and
    // the record goes: trying again would only hold every later update up.
    let mut unfinished = false;
    match restore_binary(m, &p) {
        Ok(s) => say(out, s),
        Err(e) => {
            unfinished |= passing(&e);
            problems.push(e.to_string());
        }
    }
    for f in p.files.iter().rev() {
        if let Err(e) = restore(m, f) {
            unfinished |= passing(&e);
            problems.push(format!("{}: {e}", f.path));
        }
    }
    for t in [NEW_BIN, PREV_TMP, RESTORE_TMP] {
        let _ = remove_if_exists(&m.path(t));
    }
    let _ = m.at("files restored");
    let mut k3s_back = false;
    if !p.k3s_prev_sha256.is_empty() {
        let log = HostLog::default();
        match host(m, &log).k3s_put_back(&p.k3s_prev_sha256) {
            Ok(back) => k3s_back = back,
            Err(e) => {
                unfinished |= passing(&e);
                problems.push(format!("k3s: {e}"));
            }
        }
        log.flush(m, out);
        if k3s_back {
            say(out, "the k3s from before is back");
        }
        let _ = m.at("k3s restored");
    }
    let paths: Vec<String> = p.files.iter().map(|f| f.path.clone()).collect();
    let fx = effects(&paths);
    let reloaded = if boot {
        if fx.contains(&Effect::Units) { m.cmd(ctx, "systemctl", &["daemon-reload"]).map(drop) } else { Ok(()) }
    } else {
        disarm(m, ctx, &p.id);
        let r = reload(m, ctx, &paths);
        // Not waited for: it takes minutes on the brain, and a revert must
        // not. k3s comes back by itself (Restart=always) if it fails.
        let k = if k3s_back { m.cmd(ctx, "systemctl", &["try-restart", "--no-block", "k3s.service"]).map(drop) } else { Ok(()) };
        r.and(k)
    };
    if let Err(e) = reloaded {
        problems.push(e.to_string());
    }
    if !damaged && !unfinished {
        if let Err(e) = clear_pending(m) {
            problems.push(e.to_string());
        }
        if valid_id(&p.id) {
            let _ = fs::remove_dir_all(m.path(&format!("{BACKUPS}/{}", p.id)));
        }
    }
    if !damaged && unfinished {
        p.step = format!(
            "going back did not finish: {} problem(s); tried again by a timer, at the next boot, or by dryserver update revert",
            problems.len()
        );
        let _ = save_pending(m, &p);
        if !boot && let Err(e) = arm_retry(m, ctx, &p) {
            problems.push(format!("the timer that tries again: {e}"));
        }
    }
    let before = p.previous.map(|s| format!("release {s}")).unwrap_or_else(|| "the dryserver it was installed with".into());
    let (action, done) = match undo {
        _ if unfinished && !damaged => (
            match undo {
                Undo::Revert => "reverted",
                Undo::Postpone => POSTPONED,
                Undo::Refuse => REFUSED,
            },
            format!(
                "release {} is going back ({why}), but that did not finish; its record and backups stay, and it is tried again",
                p.serial
            ),
        ),
        Undo::Revert => ("reverted", format!("release {} reverted ({why}); this machine runs {before} again", p.serial)),
        Undo::Postpone => {
            (POSTPONED, format!("release {} not applied for now, nothing was installed ({why}); it is tried again later", p.serial))
        }
        Undo::Refuse => (REFUSED, format!("release {} refused, nothing was installed ({why})", p.serial)),
    };
    if problems.is_empty() {
        record(m, out, now, p.serial, action, undo == Undo::Revert, &done);
        return Ok(());
    }
    let msg = format!("{done}, with problems on the way back:\n  {}", problems.join("\n  "));
    record(m, out, now, p.serial, action, false, &msg);
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
    // An apply stopped while it loaded the packages changed nothing but the
    // mirrorlist: postponed, worth another try.
    let undo = if p.stage == STAGE_PREPARING { Undo::Postpone } else { Undo::Revert };
    revert(m, &Ctx::new().with_timeout(REVERT_TIME), p, "reverted by hand", false, now, out, undo)
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
///
/// applying: the timer armed when the apply started (Timer::Apply). An
/// apply that still runs holds the lock: it is waited for, however long
/// pacman takes, and once it is done, one that finished (armed, with the
/// confirm window's own timer) is left alone. One that stopped part way
/// is reverted; one that stopped while it loaded the packages changed
/// nothing but the mirrorlist, and is postponed.
pub fn guard_timer(m: &Machine, ctx: &Ctx, id: &str, applying: bool, now: i64, out: &mut dyn Write) -> Result<()> {
    ensure_dirs(m)?;
    let wait = if applying { APPLY_GUARD_LOCK_WAIT } else { GUARD_LOCK_WAIT };
    let _lock = lock_wait(m, ctx, wait)?;
    let now = if applying { m.now() } else { now };
    let Some(p) = load_pending(m)? else {
        say(out, "no update waits for confirm, nothing to revert");
        return Ok(());
    };
    if p.id != id {
        say(out, format!("this timer belongs to an earlier update; release {} has its own", p.serial));
        return Ok(());
    }
    let rctx = Ctx::new().with_timeout(REVERT_TIME);
    if !applying {
        let why = format!("it was not confirmed within {}", gotime::duration_string(p.window));
        return revert(m, &rctx, p, &why, false, now, out, Undo::Revert);
    }
    match p.stage.as_str() {
        STAGE_ARMED => {
            say(out, format!("release {} finished applying; its confirm window has a timer of its own", p.serial));
            Ok(())
        }
        STAGE_PREPARING => revert(m, &rctx, p, "its apply stopped while it loaded the packages", false, now, out, Undo::Postpone),
        _ => revert(m, &rctx, p, "its apply stopped before it finished", false, now, out, Undo::Revert),
    }
}

/// At boot: reverts an update that did not finish applying, whose deadline
/// passed or that saw too many restarts; arms the timer again for the rest
/// of the window otherwise. A clock that went back never makes the wait
/// longer than one window.
pub fn guard_boot(m: &Machine, ctx: &Ctx, now: i64, out: &mut dyn Write) -> Result<()> {
    ensure_dirs(m)?;
    let _lock = lock_wait(m, ctx, LOCK_WAIT)?;
    let Some(mut p) = load_pending(m)? else { return Ok(()) };
    let rctx = Ctx::new().with_timeout(REVERT_TIME);
    if p.stage == STAGE_PREPARING {
        let why = "the machine went down while the update loaded the packages";
        return revert(m, &rctx, p, why, true, now, out, Undo::Postpone);
    }
    let why = if p.stage != STAGE_ARMED {
        Some("the machine went down before the update finished".to_string())
    } else if now >= p.deadline {
        Some(format!("it was not confirmed by {}", when(p.deadline)))
    } else if p.boots >= MAX_BOOTS {
        Some(format!("the machine restarted {} times without confirming it", p.boots + 1))
    } else {
        None
    };
    if let Some(why) = why {
        return revert(m, &rctx, p, &why, true, now, out, Undo::Revert);
    }
    let window = p.window.clamp(MIN_WINDOW, MAX_WINDOW);
    let left = (p.deadline - now).clamp(1, window);
    p.boots += 1;
    save_pending(m, &p)?;
    disarm(m, ctx, &p.id);
    if let Err(e) = arm(m, ctx, Timer::Window, &p.id, p.serial, left, true) {
        let why = format!("its revert timer could not be armed again after the restart: {e}");
        return revert(m, &rctx, p, &why, true, now, out, Undo::Revert);
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
    v.push(check("state", state_check(m)));
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
///
/// Root's files only. The registry's file on the coordinator is not read:
/// it lives in the registry account's directory (/var/lib/dryserver),
/// where that account can put a link to /dev/zero or a FIFO in its place
/// and make this check, run as root, read for ever or hang; and a file it
/// damaged on purpose would then hold back every update of the
/// coordinator, the fix for it included. The registry reads its own file.
fn state_check(m: &Machine) -> Result<String> {
    let mut n = 0;
    let mut seen = |found: bool| n += usize::from(found);
    seen(load_installed(m)?.is_some());
    seen(load_pending(m)?.is_some());
    seen(read_json::<Last>(m, LAST)?.is_some());
    seen(read_json::<node::State>(m, node::JOIN_STATE)?.is_some());
    seen(read_json::<quarantine::State>(m, quarantine::STATE_FILE)?.is_some());
    seen(read_json::<Envelope>(m, node::SIGNED_FILE)?.is_some());
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
    /// An apply, confirm or revert runs on this machine now (it holds the
    /// update lock).
    pub busy: bool,
    /// The Arch snapshot day the mirrorlist pins ("" when none), and the
    /// last run that installed packages.
    pub arch_pinned: String,
    pub arch: Option<ArchState>,
    /// Why a reboot is due, and whether this machine can do it alone
    /// ("reboot by hand: ..."), or why it must not reboot now; "" when no
    /// reboot is due.
    pub reboot: String,
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
    /// What the apply does now.
    pub step: String,
    /// The apply rebooted the machine: confirm after the restart.
    pub reboot: bool,
    /// The update brought a new main kernel (or its image): see
    /// Pending::kernel. With boots > 0 the machine started since, so a
    /// fallback kernel that runs now is that kernel failing.
    pub kernel: bool,
}

/// When this machine started, unix seconds (/proc/stat); 0 when unknown.
fn boot_time(m: &Machine) -> i64 {
    fsx::read_or_empty(m.path("/proc/stat")).lines().find_map(|l| l.strip_prefix("btime ")?.trim().parse().ok()).unwrap_or(0)
}

/// The reboot this machine is due, if any (see Status::reboot).
fn reboot_state(m: &Machine, arch: Option<&ArchState>) -> String {
    let since_boot = arch.filter(|a| a.at >= boot_time(m));
    if let Some(a) = arch.filter(|a| !a.done && !a.untouched) {
        return format!("do NOT reboot: the package update to {} stopped part way; the next one finishes it", a.date);
    }
    if let Some(a) = since_boot.filter(|a| !a.boot_problem.is_empty()) {
        return format!("do NOT reboot: {}", a.boot_problem);
    }
    let kernel = osupdate::kernel_replaced(&m.root);
    let restart = since_boot.map(|a| a.restart.clone()).unwrap_or_default();
    if !kernel && restart.is_empty() {
        return String::new();
    }
    let what = reboot_reason(kernel, &restart);
    match host(m, &HostLog::default()).reboot_blocker() {
        Some(why) => format!("reboot by hand to start {what}: {why}"),
        None => format!("reboot needed to start {what}"),
    }
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
            step: p.step.clone(),
            reboot: p.reboot,
            kernel: p.kernel,
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
    let arch = read_json::<ArchState>(m, ARCH_STATE).unwrap_or_else(|e| {
        problems.push(e.to_string());
        None
    });
    // Without the directory no update ever ran, nor runs.
    let busy = m.path(DIR).is_dir() && matches!(try_lock(m), Ok(None));
    Status {
        running: env!("CARGO_PKG_VERSION").into(),
        installed,
        pending,
        last,
        problems,
        busy,
        arch_pinned: osupdate::pinned_date(&fsx::read_or_empty(m.path(osupdate::MIRRORLIST))).unwrap_or_default(),
        reboot: reboot_state(m, arch.as_ref()),
        arch,
    }
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
    if s.busy {
        say(out, "busy: an update runs now");
    }
    if let Some(p) = &s.pending {
        let step = if p.step.is_empty() { String::new() } else { format!(", {}", p.step) };
        let when_back = if p.stage == STAGE_REVERTING {
            "it goes back; a timer, the next boot or dryserver update revert tries again".to_string()
        } else if p.stage == STAGE_ARMED {
            format!(
                "reverts by itself at {} (in {}) unless confirmed: dryserver update confirm",
                when(p.deadline),
                gotime::duration_string(p.seconds_left)
            )
        } else {
            format!("goes back by itself at {} unless its apply finishes", when(p.deadline))
        };
        say(out, format!("pending: release {} ({}{step}), {when_back}", p.serial, p.stage));
        if p.reboot && p.boots == 0 {
            say(out, "pending: the machine reboots for the new packages; confirm after the restart");
        }
    }
    let pinned = if s.arch_pinned.is_empty() { "no snapshot day pinned".to_string() } else { format!("pinned to {}", s.arch_pinned) };
    match &s.arch {
        Some(a) => say(out, format!("arch: {pinned}; last run {}: {}", when(a.at), a.summary)),
        None => say(out, format!("arch: {pinned}")),
    }
    if !s.reboot.is_empty() {
        say(out, format!("reboot: {}", s.reboot));
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
    use crate::registry;
    use crate::release::{Binary, K3s};
    use crate::signed::fake;
    use crate::testutil::{PowerCut, TempDir, put, quiet_power_cuts};
    use chrono::{TimeZone, Utc};
    use sha2::{Digest, Sha256};
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, OnceLock, Weak};

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

    /// The k3s binaries: what --version says, and how it runs (the fake
    /// k3s.service answers healthy for "good" only).
    const K3S_OLD: &[u8] = b"#!k3s version=v1.37.2+k3s1 good";
    const K3S_NEW: &[u8] = b"#!k3s version=v1.37.3+k3s1 good, newer";
    const K3S_SICK: &[u8] = b"#!k3s version=v1.37.3+k3s1 sick";
    /// The snapshot day the machine is pinned to, and a newer one.
    const DAY: &str = "2026/11/19";
    const NEXT_DAY: &str = "2026/11/20";

    /// A release of dryserver bin that keeps the machine's k3s and day.
    fn rel(serial: u64, bin: &[u8]) -> Release {
        Release {
            serial,
            created: now() - 3600,
            expires: now() + 30 * release::DAY,
            dryserver: Binary { version: "0.2.0".into(), sha256: sha(bin), size: bin.len() as u64 },
            k3s: K3s { version: "v1.37.2+k3s1".into(), sha256: sha(K3S_OLD) },
            arch_date: DAY.into(),
            rollback: false,
            urgent: false,
            notes: "fixes the join timeout".into(),
        }
    }

    /// The same with another k3s and another Arch day.
    fn os_rel(serial: u64, k3s: &[u8], day: &str) -> Release {
        let version = String::from_utf8_lossy(k3s).split_whitespace().find_map(|w| w.strip_prefix("version=")).unwrap().to_string();
        Release { k3s: K3s { version, sha256: sha(k3s) }, arch_date: day.into(), ..rel(serial, NEW) }
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
        /// pacman cannot load the packages (the archive is down).
        download_fails: bool,
        /// pacman stops part way through the install.
        install_fails: bool,
        /// pacman refuses the install before it changes anything (files of
        /// another package in the way), as it did on the coordinator.
        install_refused: bool,
        /// The install brings a new kernel (and its boot image).
        new_kernel: bool,
        /// systemctl reboot fails.
        reboot_fails: bool,
        /// The install takes this long by the machine's clock.
        install_takes: i64,
        /// The new binary is from before the handover: it knows no
        /// `update handover` or `update prepare`, and its activate writes
        /// the files only.
        new_is_legacy: bool,
        /// The k3s and Arch code of the binary that started the update is
        /// broken (as c4e6b2c's k3s version check was): its pacman and k3s
        /// commands fail. The new binary's work.
        old_os_code_broken: bool,
        /// update prepare dies without saying why.
        prepare_dies: bool,
    }

    struct Fake {
        root: PathBuf,
        owner: Mutex<u32>,
        hook: Mutex<Hook>,
        migrations: Mutex<&'static [Migration]>,
        script: Mutex<Script>,
        ran: Mutex<Vec<String>>,
        /// Which binary ran each command: "old" (the one that runs update
        /// apply) or "new" (its prepare and activate).
        by: Mutex<Vec<(&'static str, String)>>,
        /// The commands that kept a descriptor (the update lock).
        kept: Mutex<Vec<String>>,
        /// What must stay free beside the update's copies (Limits::reserve).
        reserve: Mutex<u64>,
        /// The firewall each `nft -f` loaded, the SSH drop-in each sshd
        /// reload read.
        loaded: Mutex<Vec<String>>,
        reloaded_sshd: Mutex<Vec<String>>,
        /// What k3s.service runs, and its invocation.
        k3s: Mutex<(Option<Vec<u8>>, u32)>,
        clock: Arc<std::sync::atomic::AtomicI64>,
        me: OnceLock<Weak<Fake>>,
    }

    fn noop() -> Hook {
        Arc::new(|_| Ok(()))
    }

    /// The fake as one binary sees it.
    struct As(Arc<Fake>, &'static str);

    impl Runner for As {
        fn run(&self, ctx: &Ctx, c: &Cmd) -> (String, Result<()>) {
            self.0.run_as(ctx, c, self.1)
        }
    }

    impl Fake {
        fn machine(&self) -> Machine {
            self.machine_as("old")
        }

        fn machine_as(&self, who: &'static str) -> Machine {
            let clock = self.clock.clone();
            Machine {
                root: self.root.clone(),
                run: Arc::new(As(self.me.get().unwrap().upgrade().unwrap(), who)),
                verifier: Arc::new(fake::Key("admin")),
                owner: *self.owner.lock().unwrap(),
                hook: self.hook.lock().unwrap().clone(),
                migrations: *self.migrations.lock().unwrap(),
                limits: osupdate::Limits {
                    min_free_root: 0,
                    min_free_boot: 0,
                    reserve: *self.reserve.lock().unwrap(),
                    k3s_ready_brain: Duration::from_millis(300),
                    k3s_ready_agent: Duration::from_millis(300),
                    k3s_settle: Duration::from_millis(1),
                    k3s_poll: Duration::from_millis(1),
                    inhibit_wait: Duration::from_millis(20),
                    ..osupdate::Limits::default()
                },
                clock: Arc::new(move || clock.load(Ordering::SeqCst)),
            }
        }

        fn pacman(&self, ctx: &Ctx, c: &Cmd, s: Script) -> (String, Result<()>) {
            let log = |line: &str| {
                let p = fsx::under(&self.root, "/var/log/pacman.log");
                let mut f = OpenOptions::new().append(true).create(true).open(p).unwrap();
                writeln!(f, "[2026-11-21T03:00:02+0000] [ALPM] {line}").unwrap();
            };
            match c.args[0].as_str() {
                "-Qu" => (String::new(), Err("pacman failed: exit status 1".into())),
                "-Suw" | "-Suuw" if s.download_fails => {
                    let o = "error: failed retrieving file 'glibc.pkg.tar.zst' from archive.archlinux.org : Could not resolve host\n";
                    (o.into(), Err(errf!("pacman failed: exit status 1: {}", o.trim())))
                }
                "-Su" | "-Suu" => {
                    assert_eq!(c.stop, crate::runner::Stop::Interrupt(None), "pacman is never killed while it installs");
                    self.clock.fetch_add(s.install_takes, Ordering::SeqCst);
                    if s.install_refused {
                        let o = "checking for file conflicts...\nerror: failed to commit transaction (conflicting files)\n\
                            openssl: /usr/lib/libcrypto.so.3 exists in filesystem (owned by openssl-3)\nErrors occurred, no packages were upgraded.\n";
                        return (o.into(), Err("pacman failed: exit status 1: Errors occurred, no packages were upgraded.".into()));
                    }
                    log("upgraded htop (3.3.0-1 -> 3.3.0-2)");
                    if s.install_fails {
                        let o = "error: failed to commit transaction (conflicting files)\nfoo: /usr/bin/foo exists in filesystem\n";
                        return (o.into(), Err("pacman failed: exit status 1: Errors occurred, no packages were upgraded.".into()));
                    }
                    if s.new_kernel {
                        let _ = fs::remove_dir_all(fsx::under(&self.root, "/usr/lib/modules/6.12.1-arch1-1"));
                        put(&self.root, "/usr/lib/modules/6.12.4-arch1-1/vmlinuz", "new kernel");
                        for p in ["/boot/vmlinuz-linux", "/boot/EFI/Linux/arch-linux.efi"] {
                            put(&self.root, p, "new image");
                        }
                        log("upgraded linux (6.12.1.arch1-1 -> 6.12.4.arch1-1)");
                    }
                    let _ = ctx;
                    (String::new(), Ok(()))
                }
                _ => (String::new(), Ok(())),
            }
        }

        fn k3s_runs(&self) -> Option<Vec<u8>> {
            self.k3s.lock().unwrap().0.clone()
        }
    }

    impl Fake {
        fn ran(&self) -> Vec<String> {
            self.ran.lock().unwrap().clone()
        }

        fn index(&self, prefix: &str) -> Option<usize> {
            self.ran().iter().position(|c| c.starts_with(prefix))
        }

        fn has(&self, prefix: &str) -> bool {
            self.index(prefix).is_some()
        }

        /// The binaries that ran commands starting with prefix.
        fn who_ran(&self, prefix: &str) -> Vec<&'static str> {
            let mut v: Vec<&'static str> = self.by.lock().unwrap().iter().filter(|(_, c)| c.starts_with(prefix)).map(|(w, _)| *w).collect();
            v.dedup();
            v
        }
    }

    impl Runner for Fake {
        fn run(&self, ctx: &Ctx, c: &Cmd) -> (String, Result<()>) {
            self.run_as(ctx, c, "old")
        }
    }

    impl Fake {
        fn run_as(&self, ctx: &Ctx, c: &Cmd, who: &'static str) -> (String, Result<()>) {
            let root = self.root.display().to_string();
            self.ran.lock().unwrap().push(c.to_string().replace(&root, ""));
            self.by.lock().unwrap().push((who, c.to_string().replace(&root, "")));
            if c.keep_fd.is_some() {
                self.kept.lock().unwrap().push(c.to_string().replace(&root, ""));
            }
            let s = *self.script.lock().unwrap();
            let name = c.name.replace(&root, "");
            let args: Vec<&str> = c.args.iter().map(String::as_str).collect();
            let fail = |msg: &str| (String::new(), Err(errf!("{} failed: {msg}", c.name)));
            let ok = || (String::new(), Ok(()));
            let read = |p: &str| fs::read_to_string(p).unwrap_or_default();
            let dropin = || read(&fsx::under(&self.root, SSHD_DROPIN).display().to_string());
            let os_cmd = name == "pacman" || name.contains("k3s") || args.contains(&"k3s.service");
            if who == "old" && s.old_os_code_broken && os_cmd && !matches!(args.as_slice(), ["--version"]) {
                return fail("the old binary's broken k3s and Arch code");
            }
            if who == "old" && s.old_os_code_broken && name.ends_with("k3s.dryserver-new") {
                return fail("the old binary's broken k3s and Arch code");
            }
            match (name.as_str(), args.as_slice()) {
                (NEW_BIN, ["update", "handover"]) if s.new_is_legacy => fail("exit status 1: unknown update command \"handover\""),
                (NEW_BIN, ["update", "handover"]) => (format!("{HANDOVER}\n"), Ok(())),
                (NEW_BIN, ["update", "prepare", "--id", _]) if s.prepare_dies => fail("signal 11 (core dumped)"),
                (NEW_BIN, ["update", "prepare", "--id", id]) => {
                    let mut o = Vec::new();
                    let r = prepare(&self.machine_as("new"), ctx, id, &mut o);
                    (String::from_utf8_lossy(&o).into_owned(), r)
                }
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
                    let m = self.machine_as("new");
                    // A binary from before the handover finds no handover in
                    // the record, and writes the files only: this one too.
                    let r = activate(&m, ctx, id, &mut o);
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
                ("pacman", _) => self.pacman(ctx, c, s),
                ("systemd-inhibit", _) => {
                    while !ctx.done() {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    fail("signal: killed")
                }
                ("systemctl", ["restart" | "try-restart", "--no-block", "k3s.service"]) => {
                    let mut k = self.k3s.lock().unwrap();
                    *k = (fs::read(fsx::under(&self.root, K3S_BIN)).ok(), k.1 + 1);
                    ok()
                }
                ("systemctl", ["show", "k3s.service", _]) => {
                    let k = self.k3s.lock().unwrap();
                    let state = if k.0.is_some() { "active" } else { "inactive" };
                    (format!("ActiveState={state}\nInvocationID={:032x}\n", k.1), Ok(()))
                }
                ("curl", _) | (_, ["kubectl", "get", "--raw", "/readyz"]) => {
                    if self.k3s_runs().is_some_and(|b| String::from_utf8_lossy(&b).contains("good")) {
                        ("ok".into(), Ok(()))
                    } else {
                        fail("exit status 7: connection refused")
                    }
                }
                ("systemctl", ["--no-block", "reboot"]) if s.reboot_fails => fail("Access denied"),
                (bin, ["--version"]) if bin.contains("k3s") => {
                    match read(&c.name).split_whitespace().find_map(|w| w.strip_prefix("version=")) {
                        Some(v) => (format!("k3s version {v} (12ab34cd)\ngo version go1.24.1\n"), Ok(())),
                        None => fail("exec format error"),
                    }
                }
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
            // Updates write only where root alone may: whatever the umask
            // of whoever runs the tests, the directories made here are so.
            static UMASK: std::sync::Once = std::sync::Once::new();
            // SAFETY: umask only sets the process's file mode mask.
            UMASK.call_once(|| unsafe {
                libc::umask(0o022);
            });
            let dir = TempDir::new();
            let root = dir.path().to_path_buf();
            let fake = Arc::new(Fake {
                root: root.clone(),
                owner: Mutex::new(fsx::geteuid()),
                hook: Mutex::new(noop()),
                migrations: Mutex::new(&[]),
                script: Mutex::default(),
                ran: Mutex::default(),
                by: Mutex::default(),
                kept: Mutex::default(),
                reserve: Mutex::new(0),
                loaded: Mutex::default(),
                reloaded_sshd: Mutex::default(),
                k3s: Mutex::new((Some(K3S_OLD.to_vec()), 1)),
                clock: Arc::new(std::sync::atomic::AtomicI64::new(now())),
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
            // k3s, and Arch pinned to DAY as the installer leaves it, with
            // the pacman.conf Arch ships and a kernel.
            lab.write(K3S_BIN, K3S_OLD, 0o755);
            lab.write(sysconf::K3S_TOKEN, b"K10abc::server:secret\n", 0o600);
            lab.write(osupdate::MIRRORLIST, osupdate::mirrorlist(DAY).unwrap().as_bytes(), 0o644);
            let conf = "[options]\nSigLevel = Required DatabaseOptional\n[core]\nInclude = /etc/pacman.d/mirrorlist\n";
            lab.write(osupdate::PACMAN_CONF, conf.as_bytes(), 0o644);
            lab.write("/proc/sys/kernel/osrelease", b"6.12.1-arch1-1\n", 0o644);
            lab.write("/usr/lib/modules/6.12.1-arch1-1/vmlinuz", b"kernel", 0o644);
            lab.write("/boot/EFI/Linux/arch-linux.efi", b"image", 0o644);
            lab.write("/var/log/pacman.log", b"", 0o644);
            fsx::mkdir_all(lab.p("/var/lib/pacman"), 0o755).unwrap();
            ensure_dirs(&lab.m()).unwrap();
            // Whatever the umask of whoever runs the tests.
            for d in ["/", "/var", "/var/lib"] {
                fsx::chmod(lab.p(d), 0o755).unwrap();
            }
            lab
        }

        /// A release with its k3s binary handed over (Some k3s) or not.
        fn os_opts(&self, r: &Release, k3s: Option<&[u8]>) -> Apply {
            let k3s = k3s.map(|b| {
                let p = self.p(&format!("/tmp/k3s-{}", r.serial));
                fsx::mkdir_all(fsx::dir(&p), 0o755).unwrap();
                fs::write(&p, b).unwrap();
                p
            });
            Apply { k3s, ..self.opts(r, self.staged(NEW)) }
        }

        fn apply_os(&self, r: &Release, k3s: Option<&[u8]>) -> Result<()> {
            apply(&self.m(), &Ctx::new(), &self.os_opts(r, k3s), now(), &mut Vec::new())
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
            Apply { release: self.release_file(r), binary, k3s: None, brain_k3s: String::new(), window: WINDOW, reboot: false }
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
        let id = &p.id;
        let timers: Vec<String> = f.ran().into_iter().filter(|c| c.starts_with("systemd-run")).collect();
        assert_eq!(timers.len(), 2, "{timers:?}");
        // The first covers the apply, however long it takes; the second is
        // the confirm window, armed once the apply is done.
        let (during, window) = (&timers[0], &timers[1]);
        assert!(
            during.starts_with(&format!("systemd-run --unit=dryserver-update-revert-{id}-apply --on-active={APPLY_TIME}s")),
            "{during}"
        );
        assert!(during.ends_with(&format!("guard --id {id} --applying")), "{during}");
        assert!(window.starts_with(&format!("systemd-run --unit=dryserver-update-revert-{id} --on-active=600s")), "{window}");
        let at = |c: &str| f.ran().iter().position(|r| r == c).unwrap();
        assert!(f.index("/usr/local/bin/dryserver update activate").unwrap() < at(window), "the window starts after the apply");
        assert!(
            f.has(&format!("systemctl stop dryserver-update-revert-{id}-apply.timer")),
            "the apply's timer goes once the window's runs"
        );
        for timer in [during, window] {
            // While the machine runs, systemd-run waits until the timer is
            // active: an apply that cannot arm it changes nothing.
            assert!(!timer.contains("--no-block"), "{timer}");
            assert!(timer.contains("--timer-property=DefaultDependencies=no"), "{timer}");
            assert!(
                timer.contains("/bin/sh -c /usr/local/bin/dryserver.prev update guard --id "),
                "the timer must run the previous binary first: {timer}"
            );
        }
        assert!(
            window.ends_with(&format!(
                "/bin/sh -c /usr/local/bin/dryserver.prev update guard --id {id} || /usr/local/bin/dryserver update guard --id {id}"
            )),
            "{window}"
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
            assert!(e.contains("could not finish the update") && e.contains("signal 6"), "{e}");
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
    fn review_a_full_disk_while_staging_postpones() {
        let lab = Lab::new();
        lab.hook(Arc::new(|p| if p == "stage" { Err(io::Error::from_raw_os_error(libc::ENOSPC)) } else { Ok(()) }));
        let src = lab.p("/var/lib/dryserver-releases/incoming/dryserver");
        fsx::mkdir_all(fsx::dir(&src), 0o700).unwrap();
        fs::write(&src, NEW).unwrap();
        let _ = apply(&lab.m(), &Ctx::new(), &lab.opts(&rel(7, NEW), src), now(), &mut Vec::new());
        assert_eq!(lab.last().action, POSTPONED);
        lab.assert_old("disk full while staging");
        // Too little room is seen before anything is copied: postponed too,
        // with where and how much; nothing armed, nothing staged.
        let lab = Lab::new();
        *lab.fake.reserve.lock().unwrap() = u64::MAX / 4;
        let src = lab.p("/tmp/dryserver");
        fsx::mkdir_all(fsx::dir(&src), 0o755).unwrap();
        fs::write(&src, NEW).unwrap();
        let e = apply(&lab.m(), &Ctx::new(), &lab.opts(&rel(7, NEW), src), now(), &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("MiB free on the file system of") && e.contains("make room first"), "{e}");
        assert_eq!((lab.last().action.as_str(), lab.last().serial), (POSTPONED, 7));
        assert!(!lab.fake.has("systemd-run") && !lab.p(&format!("{STAGING}/dryserver-7")).exists());
        // The k3s binary, in the new binary's step: postponed as well.
        let lab = Lab::new();
        let a = lab.os_opts(&os_rel(8, K3S_NEW, DAY), Some(K3S_NEW));
        lab.hook(Arc::new(|p| if p == "stage k3s" { Err(io::Error::from_raw_os_error(libc::EDQUOT)) } else { Ok(()) }));
        assert!(apply(&lab.m(), &Ctx::new(), &a, now(), &mut Vec::new()).is_err());
        assert_eq!((lab.last().action.as_str(), lab.last().serial), (POSTPONED, 8), "{:?}", lab.last());
        lab.assert_os_old("disk full while staging k3s");
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
    fn a_revert_puts_back_what_a_late_activate_added() {
        // The revert was handed the record as it was before activate wrote
        // the SSH settings and installed.json (apply cancelled while its
        // activate still ran): it reads it again under the mesh lock.
        let lab = Lab::new();
        lab.apply(&rel(7, NEW)).unwrap();
        let mut early = lab.pending().unwrap();
        assert!(early.files.len() > 1);
        early.files.truncate(1);
        revert(&lab.m(), &Ctx::new(), early, "test", false, now(), &mut Vec::new(), Undo::Revert).unwrap();
        lab.assert_old("files added after the record was read");
        // A record of another update on disk is not taken for this one.
        let lab = Lab::new();
        lab.apply(&rel(7, NEW)).unwrap();
        let mut other = lab.pending().unwrap();
        other.id = "0123456789abcdef".into();
        let mine = lab.pending().unwrap();
        save_pending(&lab.m(), &other).unwrap();
        revert(&lab.m(), &Ctx::new(), mine, "test", false, now(), &mut Vec::new(), Undo::Revert).unwrap();
        lab.assert_old("its own record");
    }

    #[test]
    fn an_activate_that_waited_for_a_revert_changes_nothing() {
        let lab = Lab::new();
        let id = "0123456789abcdef";
        let p = Pending { format: PENDING_FORMAT, id: id.into(), stage: STAGE_INSTALLING.into(), serial: 7, ..Pending::default() };
        save_pending(&lab.m(), &p).unwrap();
        // apply holds its lock, and a revert holds the mesh lock while the
        // new binary's activate starts and waits for it.
        let _apply = try_lock(&lab.m()).unwrap().expect("the update lock");
        let mesh = fsx::lock(lab.p(quarantine::MESH_LOCK)).unwrap();
        let fake = lab.fake.clone();
        let t = std::thread::spawn(move || activate(&fake.machine(), &Ctx::new(), id, &mut Vec::new()).map_err(|e| e.to_string()));
        std::thread::sleep(Duration::from_millis(300));
        // The revert finishes: the record goes, then the lock.
        clear_pending(&lab.m()).unwrap();
        drop(mesh);
        let e = t.join().unwrap().unwrap_err();
        assert!(e.contains("no update is being applied"), "{e}");
        assert_eq!(lab.get(FIREWALL), OLD_FIREWALL, "activate wrote files after the revert");
        assert!(lab.pending().is_none(), "activate brought the record back");
    }

    #[test]
    fn a_fresh_machine_refuses_an_older_release() {
        // Nothing wrote installed.json (every fresh install): the dryserver
        // that runs is the floor, so an old signed release sent again is
        // refused, and changes nothing.
        let lab = Lab::new();
        assert!(load_installed(&lab.m()).unwrap().is_none());
        let old = Release { dryserver: Binary { version: "0.0.0".into(), ..rel(7, NEW).dryserver }, ..rel(7, NEW) };
        let e = lab.apply(&old).unwrap_err().to_string();
        assert!(e.contains("older than the") && e.contains("this machine runs") && e.contains("rollback"), "{e}");
        lab.assert_old("an older release on a fresh machine");
        assert!(!lab.fake.has("systemd-run") && !lab.p(PREV_BIN).exists(), "something changed: {:?}", lab.fake.ran());
        // The first look was recorded, now: a rollback signed before it
        // (an hour ago) was not made for this machine. A hacked coordinator
        // sending an old one again does not move it below what it was
        // installed with.
        assert_eq!(read_json::<StartRecord>(&lab.m(), START).unwrap().unwrap().since, now());
        let back = Release { rollback: true, ..old.clone() };
        let e = lab.apply(&back).unwrap_err().to_string();
        assert!(e.contains("below what this machine was installed with") && e.contains("sent again"), "{e}");
        lab.assert_old("an old rollback sent again");
        // A release with an older Arch day than the installer pinned (the
        // stick was built after it): dryserver and k3s go in, the newer
        // packages stay; the same for an old rollback sent again.
        let mut out = Vec::new();
        let a = lab.opts(&Release { arch_date: "2026/11/01".into(), ..rel(7, NEW) }, lab.staged(NEW));
        apply(&lab.m(), &Ctx::new(), &a, now(), &mut out).unwrap();
        let said = String::from_utf8_lossy(&out).into_owned();
        assert!(said.contains("newer than the release's 2026/11/01 (installed later): they stay"), "{said}");
        lab.assert_new("an older day, newer packages here");
        assert!(!lab.fake.has("pacman") && lab.pinned().as_deref() == Some(DAY), "{:?}", lab.fake.ran());
        // A machine that took its first look a day ago takes a rollback
        // signed an hour ago: the release it runs may be the bad one, and
        // its packages go back too.
        let lab = Lab::new();
        save_json(&lab.m(), START, &StartRecord { since: now() - release::DAY }).unwrap();
        lab.apply(&back).unwrap();
        lab.assert_new("a rollback on a fresh machine");
        let lab = Lab::new();
        save_json(&lab.m(), START, &StartRecord { since: now() - release::DAY }).unwrap();
        lab.apply_os(&Release { arch_date: "2026/11/01".into(), ..back.clone() }, None).unwrap();
        assert!(lab.fake.has("pacman -Suu") && lab.pinned().as_deref() == Some("2026/11/01"), "{:?}", lab.fake.ran());
    }

    #[test]
    fn when_the_packages_are_due() {
        let lab = Lab::new();
        let m = lab.m();
        // Pinned by the installer to the day, no run yet: nothing to do,
        // unless the release is a rollback to exactly that day (the
        // installer's packages are of that day or newer).
        assert!(!arch_due(&m, DAY, false) && arch_due(&m, NEXT_DAY, false));
        assert!(arch_due(&m, DAY, true));
        let state = |done: bool, lts_waits: bool| ArchState { date: DAY.into(), done, lts_waits, ..ArchState::default() };
        for (s, due) in [(state(true, false), false), (state(false, false), true), (state(true, true), true)] {
            save_json(&m, ARCH_STATE, &s).unwrap();
            assert_eq!(arch_due(&m, DAY, false), due, "{s:?}");
        }
        // The fallback kernel waits, but the main kernel has not booted well
        // yet (still on its counter, or not started: a disk that asks for its
        // passphrase): a dryserver-only release runs no pacman for it.
        lab.write("/boot/EFI/Linux/arch-linux+2-1.efi", b"image", 0o644);
        assert!(!arch_due(&m, DAY, false));
        let _ = fs::remove_file(lab.p("/boot/EFI/Linux/arch-linux+2-1.efi"));
        lab.write("/proc/sys/kernel/osrelease", b"6.12.4-arch1-1\n", 0o644);
        assert!(!arch_due(&m, DAY, false), "the running kernel's modules are gone: not rebooted yet");
        lab.write("/proc/sys/kernel/osrelease", b"6.12.1-arch1-1\n", 0o644);
        // A record that cannot be read: run it.
        lab.write(ARCH_STATE, b"{", 0o600);
        assert!(arch_due(&m, DAY, false));
        // Not pinned at all (an install from before the pin): run it.
        lab.write(osupdate::MIRRORLIST, b"Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch\n", 0o644);
        let _ = fs::remove_file(lab.p(ARCH_STATE));
        assert!(arch_due(&m, DAY, false));
    }

    #[test]
    fn changed_tmpfiles_rules_take_effect_now() {
        // The registry account's home becomes root's at the update, not at
        // the next boot.
        let lab = Lab::new();
        let rule = sysconf::REGISTRY_TMPFILES;
        // Rendered on the coordinator only.
        lab.write(ROLE_FILE, b"coordinator\n", 0o644);
        let _ = fs::remove_file(lab.p(rule));
        lab.apply(&rel(7, NEW)).unwrap();
        let ran = lab.fake.ran();
        assert!(ran.iter().any(|c| c == &format!("systemd-tmpfiles --create {rule}")), "{ran:#?}");
        // On the way back the rule is gone again: nothing to create.
        lab.fake.ran.lock().unwrap().clear();
        revert_by_hand(&lab.m(), &Ctx::new(), now(), &mut Vec::new()).unwrap();
        assert!(!lab.fake.has("systemd-tmpfiles"), "{:?}", lab.fake.ran());
        assert_eq!(effect("/etc/tmpfiles.d/x.conf"), Some(Effect::Tmpfiles));
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
        assert!(
            lab.fake.has(&format!("systemd-run --unit=dryserver-update-revert-{id} --on-active=480s --no-block ")),
            "{:?}",
            lab.fake.ran()
        );
        assert_eq!(lab.pending().unwrap().boots, 1);
        // The timer then fires and reverts.
        guard_timer(&lab.m(), &Ctx::new(), &id, false, now() + 600, &mut Vec::new()).unwrap();
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
    fn the_boot_never_waits_for_systemd() {
        // The guard runs before sysinit.target, and a timer with the
        // default dependencies starts only after it: systemd-run must not
        // wait for that start, and the timer must not need sysinit.target.
        let m = Lab::new().m();
        let boot = arm_args(&m, Timer::Window, "0123456789abcdef", 7, 480, true);
        let running = arm_args(&m, Timer::Window, "0123456789abcdef", 7, 480, false);
        for (args, blocks) in [(&boot, false), (&running, true)] {
            assert_eq!(!args.contains(&"--no-block".to_string()), blocks, "{args:?}");
            for p in ["DefaultDependencies=no", "Conflicts=shutdown.target", "Before=shutdown.target", "AccuracySec=1s"] {
                assert!(args.contains(&format!("--timer-property={p}")), "{p} missing: {args:?}");
            }
            // The service the timer starts keeps its defaults (after
            // basic.target, which waits for nothing of the guard's).
            assert!(!args.iter().any(|a| a.starts_with("--property") || a == "-p"), "{args:?}");
            // Options come before the command, or sh would get them.
            let cmd = args.iter().position(|a| a == "/bin/sh").unwrap();
            assert!(args[..cmd].iter().all(|a| a.starts_with("--")) && cmd == args.len() - 3, "{args:?}");
        }
        // The guard itself waits for nothing that comes later in the boot.
        let u = GUARD_UNIT_TEXT;
        assert!(u.contains("DefaultDependencies=no\n") && u.contains("After=local-fs.target\n"), "{u}");
        assert!(!u.contains("After=sysinit") && !u.contains("After=basic") && !u.contains("Requires="), "{u}");
        // A reboot in the window: the timer comes back without the boot
        // waiting for it.
        let lab = Lab::new();
        lab.apply(&rel(7, NEW)).unwrap();
        lab.fake.ran.lock().unwrap().clear();
        guard_boot(&lab.m(), &Ctx::new(), now() + 120, &mut Vec::new()).unwrap();
        let ran = lab.fake.ran();
        let timer = ran.iter().find(|c| c.starts_with("systemd-run")).expect("the timer is armed again");
        assert!(timer.contains(" --no-block ") && timer.contains("--timer-property=DefaultDependencies=no"), "{timer}");
        // Nothing else at boot waits for a systemd job either.
        for c in &ran {
            assert!(!c.starts_with("systemctl start") && !c.starts_with("systemctl restart") && !c.starts_with("systemctl reload"), "{c}");
        }
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
        guard_timer(&lab.m(), &Ctx::new(), &id, false, now() - release::DAY, &mut Vec::new()).unwrap();
        lab.assert_old("clock back, timer fired");
        // At boot with the clock a day back: one window at most, not a day
        // and a window.
        let lab = Lab::new();
        lab.apply(&rel(7, NEW)).unwrap();
        let id = lab.pending().unwrap().id;
        guard_boot(&lab.m(), &Ctx::new(), now() - release::DAY, &mut Vec::new()).unwrap();
        assert!(lab.fake.has(&format!("systemd-run --unit=dryserver-update-revert-{id} --on-active=600s")), "{:?}", lab.fake.ran());
        // A timer from an earlier update never reverts this one.
        guard_timer(&lab.m(), &Ctx::new(), "0123456789abcdef", false, now(), &mut Vec::new()).unwrap();
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
        // The installer already put the boot unit in place (sysconf renders
        // it), so only the changed units need a reload.
        assert_eq!(reloads.len(), 1, "one for the changed units: {:?}", f.ran());
        assert!(f.index("systemd-analyze").unwrap() < reloads[0], "verified before the reload: {:?}", f.ran());
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
    fn the_registry_accounts_limits_follow_the_update_on_the_coordinator() {
        // Installed before IPAddressDeny was in them: the update brings it,
        // as any other file it manages, and a revert puts the old one back.
        let lab = Lab::new();
        lab.write(ROLE_FILE, b"coordinator\n", 0o644);
        lab.write("/etc/passwd", b"root:x:0:0::/root:/bin/bash\ndryreg:x:973:973::/var/lib/dryreg:/bin/sh\n", 0o644);
        let slice = registry_slice(973);
        let old = "[Slice]\nTasksMax=200\nMemoryMax=384M\nMemorySwapMax=0\n";
        lab.write(&slice, old.as_bytes(), 0o644);
        lab.apply(&rel(7, NEW)).unwrap();
        assert_eq!(lab.get(&slice), sysconf::REGISTRY_SLICE);
        assert!(lab.get(&slice).contains("IPAddressDeny=any"));
        assert!(lab.pending().unwrap().files.iter().any(|f| f.path == slice));
        let verified = lab.fake.ran().iter().any(|c| c.starts_with("systemd-analyze verify") && c.ends_with(" user-973.slice"));
        assert!(verified && lab.fake.has("systemctl daemon-reload"), "{:#?}", lab.fake.ran());
        revert_by_hand(&lab.m(), &Ctx::new(), now(), &mut Vec::new()).unwrap();
        assert_eq!(lab.get(&slice), old);
        // A server has no such account; a coordinator without it (or a
        // passwd that does not say) gets nothing, and no error.
        let lab = Lab::new();
        lab.write("/etc/passwd", b"dryreg:x:973:973::/var/lib/dryreg:/bin/sh\n", 0o644);
        assert!(!render_managed(&lab.m()).unwrap().iter().any(|f| f.path.contains(".slice.d/")));
        lab.write(ROLE_FILE, b"coordinator\n", 0o644);
        lab.write("/etc/passwd", b"root:x:0:0::/root:/bin/bash\ndryreg:x:nope:973::/:/bin/sh\n", 0o644);
        assert!(!render_managed(&lab.m()).unwrap().iter().any(|f| f.path.contains(".slice.d/")));
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
    fn the_self_check_reads_nothing_of_the_registry_account() {
        // On the coordinator the registry's file is the registry account's:
        // a FIFO, a link to an endless file or garbage there must neither
        // hang nor fail the self check every update runs as root.
        let lab = Lab::new();
        lab.write(ROLE_FILE, b"coordinator\n", 0o644);
        let reg = lab.p(registry::DEFAULT_PATH);
        fsx::mkdir_all(fsx::dir(&reg), 0o755).unwrap();
        let c = std::ffi::CString::new(reg.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: c is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        let m = lab.m();
        std::thread::spawn(move || tx.send(selfcheck(&m, &Ctx::new())).unwrap());
        let checks = rx.recv_timeout(Duration::from_secs(10)).expect("the self check hung on a FIFO");
        let state = checks.iter().find(|c| c.name == "state").unwrap();
        assert!(state.ok, "{state:?}");
        fs::remove_file(&reg).unwrap();
        std::os::unix::fs::symlink("/dev/zero", &reg).unwrap();
        assert!(selfcheck(&lab.m(), &Ctx::new()).iter().find(|c| c.name == "state").unwrap().ok);
        fs::remove_file(&reg).unwrap();
        fs::write(&reg, "{ damaged").unwrap();
        assert!(selfcheck(&lab.m(), &Ctx::new()).iter().find(|c| c.name == "state").unwrap().ok);
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
            "Before=sysinit.target shutdown.target systemd-sysctl.service nftables.service systemd-networkd.service sshd.service wg-quick@wg0.service",
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
    fn a_machine_installed_before_the_boot_unit_gets_it_first() {
        let lab = Lab::new();
        std::fs::remove_file(lab.p(GUARD_UNIT_PATH)).unwrap();
        lab.apply(&rel(7, NEW)).unwrap();
        assert_eq!(lab.get(GUARD_UNIT_PATH), GUARD_UNIT_TEXT);
        let ran = lab.fake.ran();
        let reload = ran.iter().position(|c| c == "systemctl daemon-reload").expect("a reload for the new unit");
        let enable = ran.iter().position(|c| c.starts_with("systemctl enable --quiet dryserver-update-guard.service")).expect("enabled");
        let timer = ran.iter().position(|c| c.starts_with("systemd-run")).expect("timer");
        assert!(reload < enable && enable < timer, "the boot unit is in place before anything is armed: {ran:?}");
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

    #[test]
    fn a_damaged_record_is_kept_for_a_look() {
        // Damaged while the apply ran: what is known goes back (the
        // binary), but the record and the backups stay, and the way back
        // says it did not finish.
        let lab = Lab::new();
        let pending = lab.p(PENDING);
        lab.hook(Arc::new(move |p| {
            if p == "binary switched" {
                fs::write(&pending, "{ damaged").unwrap();
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            Ok(())
        }));
        let e = lab.apply(&rel(7, NEW)).unwrap_err().to_string();
        lab.hook(noop());
        assert!(e.contains("way back did not finish") && e.contains("pending.json is damaged"), "{e}");
        assert_eq!(lab.bytes(SERVER_BIN), OLD, "the binary is back");
        assert_eq!(lab.get(PENDING), "{ damaged", "the record stays for a look");
        assert!(status(&lab.m(), now()).problems.iter().any(|p| p.contains("damaged")));
        // Damaged after activate wrote files: they are not lost.
        let lab = Lab::new();
        lab.apply(&rel(7, NEW)).unwrap();
        let p = lab.pending().unwrap();
        lab.write(PENDING, b"[]", 0o600);
        let e = revert(&lab.m(), &Ctx::new(), p.clone(), "test", false, now(), &mut Vec::new(), Undo::Revert).unwrap_err().to_string();
        assert!(e.contains("with the backups"), "{e}");
        assert!(lab.p(&format!("{BACKUPS}/{}", p.id)).is_dir(), "the backups stay");
        assert_eq!(lab.get(PENDING), "[]");
    }

    #[test]
    fn a_record_whose_id_is_not_apply_s_is_damaged() {
        // The id names a directory a revert removes and goes into the
        // timer's shell command.
        for id in ["x; rm -rf /", "../../etc", "0123456789ABCDEF", "0123456789abcde", ""] {
            let lab = Lab::new();
            lab.apply(&rel(7, NEW)).unwrap();
            let mut v: serde_json::Value = serde_json::from_str(&lab.get(PENDING)).unwrap();
            v["id"] = id.into();
            lab.write(PENDING, v.to_string().as_bytes(), 0o600);
            let e = load_pending(&lab.m()).unwrap_err().to_string();
            assert!(e.contains("not 16 hex digits"), "{id:?}: {e}");
            lab.fake.ran.lock().unwrap().clear();
            assert!(guard_boot(&lab.m(), &Ctx::new(), now(), &mut Vec::new()).is_err(), "{id:?}");
            assert!(revert_by_hand(&lab.m(), &Ctx::new(), now(), &mut Vec::new()).is_err(), "{id:?}");
            assert!(lab.fake.ran().is_empty(), "{id:?}: {:?}", lab.fake.ran());
            assert!(lab.p(BACKUPS).is_dir() && lab.p(DIR).is_dir());
        }
    }

    #[test]
    fn files_are_written_only_where_root_alone_writes() {
        // Someone else could swap a directory on the way while root writes.
        let lab = Lab::new();
        let dir = fsx::dir(lab.p(SSHD_DROPIN));
        fsx::chmod(&dir, 0o777).unwrap();
        let e = lab.apply(&rel(7, NEW)).unwrap_err().to_string();
        assert!(e.contains("can be written by others than root"), "{e}");
        fsx::chmod(&dir, 0o755).unwrap();
        assert_eq!(lab.get(SSHD_DROPIN), OLD_SSHD, "never written");
        assert_eq!(lab.bytes(SERVER_BIN), OLD);
        assert!(lab.pending().is_none());
        // A link on the way is refused as well.
        let lab = Lab::new();
        let etc_ssh = lab.p("/etc/ssh");
        fs::rename(&etc_ssh, lab.p("/etc/ssh-real")).unwrap();
        std::os::unix::fs::symlink(lab.p("/etc/ssh-real"), &etc_ssh).unwrap();
        let e = lab.apply(&rel(7, NEW)).unwrap_err().to_string();
        assert!(e.contains("symbolic link"), "{e}");
        assert_eq!(lab.bytes(SERVER_BIN), OLD);
    }

    // ---- k3s and the Arch packages ----

    impl Lab {
        fn pinned(&self) -> Option<String> {
            osupdate::pinned_date(&self.get(osupdate::MIRRORLIST))
        }

        fn arch(&self) -> Option<ArchState> {
            read_json(&self.m(), ARCH_STATE).unwrap()
        }

        fn first(&self, prefix: &str) -> usize {
            self.fake.index(prefix).unwrap_or_else(|| panic!("{prefix:?} did not run: {:#?}", self.fake.ran()))
        }

        /// The binary, the files, k3s and the pin as before; the packages
        /// are not undone.
        fn assert_os_old(&self, why: &str) {
            self.assert_old(why);
            assert!(self.bytes(K3S_BIN) == K3S_OLD, "{why}: the k3s binary");
            assert_eq!(self.pinned().as_deref(), Some(DAY), "{why}: the mirrorlist");
        }
    }

    #[test]
    fn a_release_with_a_new_k3s_and_new_packages() {
        let lab = Lab::new();
        let r = os_rel(8, K3S_NEW, NEXT_DAY);
        lab.apply_os(&r, Some(K3S_NEW)).unwrap();
        lab.assert_new("applied");
        assert!(lab.bytes(K3S_BIN) == K3S_NEW && lab.bytes(osupdate::K3S_PREV) == K3S_OLD);
        assert!(lab.fake.k3s_runs().as_deref() == Some(K3S_NEW), "k3s runs the new binary");
        assert_eq!(lab.pinned().as_deref(), Some(NEXT_DAY));
        let a = lab.arch().unwrap();
        assert!(a.date == NEXT_DAY && a.done, "{a:?}");
        // The order: the new binary is checked next to the old one, then
        // loads the packages before anything changes; then the binary, the
        // files, k3s, and the packages last.
        let order = [
            "systemd-run --unit=dryserver-update-revert-",
            "/usr/local/bin/.dryserver.new selfcheck",
            "/usr/local/bin/.dryserver.new update handover",
            "/usr/local/bin/.dryserver.new update prepare --id",
            "pacman -Syy",
            "pacman -Suw",
            "/usr/local/bin/dryserver update activate",
            "systemctl restart --no-block k3s.service",
            "pacman -Su --noconfirm",
        ];
        let at: Vec<usize> = order.iter().map(|o| lab.first(o)).collect();
        assert!(at.windows(2).all(|w| w[0] < w[1]), "out of order: {:#?}", lab.fake.ran());
        let p = lab.pending().unwrap();
        assert_eq!((p.stage.as_str(), p.k3s_prev_sha256.as_str(), p.arch_date.as_str()), (STAGE_ARMED, sha(K3S_OLD).as_str(), NEXT_DAY));
        assert!(p.files.iter().any(|f| f.path == osupdate::MIRRORLIST), "the pin is recorded to go back");
        assert!(!lab.p(&format!("{STAGING}/k3s-8")).exists(), "the staged k3s is not kept");
        // A revert puts k3s and the pin back, not the packages.
        lab.fake.ran.lock().unwrap().clear();
        revert_by_hand(&lab.m(), &Ctx::new(), now(), &mut Vec::new()).unwrap();
        lab.assert_os_old("reverted");
        assert!(lab.fake.has("systemctl try-restart --no-block k3s.service"), "{:?}", lab.fake.ran());
        assert!(!lab.fake.has("pacman"), "packages are not reverted: {:?}", lab.fake.ran());
        assert_eq!(lab.arch().unwrap().date, NEXT_DAY, "the packages stay where they are");
        // The same release again: the packages are there, the pin is not.
        lab.apply_os(&r, Some(K3S_NEW)).unwrap();
        confirm(&lab.m(), &Ctx::new(), Some(8), now(), &mut Vec::new()).unwrap();
        assert_eq!((lab.pinned().as_deref(), lab.bytes(K3S_BIN) == K3S_NEW), (Some(NEXT_DAY), true));
    }

    #[test]
    fn a_dryserver_only_release_restarts_nothing() {
        // The same k3s and the same day: no k3s restart, no pacman, fast.
        let lab = Lab::new();
        lab.apply(&rel(7, NEW)).unwrap();
        lab.assert_new("applied");
        assert!(!lab.fake.has("pacman") && !lab.fake.has("systemctl restart --no-block k3s"), "{:#?}", lab.fake.ran());
        assert!(lab.pending().unwrap().k3s_prev_sha256.is_empty());
        // Neither after the packages were brought to the day once.
        confirm(&lab.m(), &Ctx::new(), None, now(), &mut Vec::new()).unwrap();
        lab.apply_os(&os_rel(8, K3S_NEW, NEXT_DAY), Some(K3S_NEW)).unwrap();
        confirm(&lab.m(), &Ctx::new(), None, now(), &mut Vec::new()).unwrap();
        lab.fake.ran.lock().unwrap().clear();
        let mut r = os_rel(9, K3S_NEW, NEXT_DAY);
        r.notes = "only a fix".into();
        lab.apply_os(&r, None).unwrap();
        assert!(!lab.fake.has("pacman") && !lab.fake.has("systemctl restart --no-block k3s"), "{:#?}", lab.fake.ran());
    }

    #[test]
    fn a_dead_mirror_postpones_the_update_with_nothing_changed() {
        let lab = Lab::new();
        lab.script(|s| s.download_fails = true);
        let r = os_rel(8, K3S_NEW, NEXT_DAY);
        let e = lab.apply_os(&r, Some(K3S_NEW)).unwrap_err().to_string();
        assert!(e.contains("downloading the packages failed") && e.contains("nothing was installed"), "{e}");
        lab.assert_os_old("postponed");
        // The new binary was checked next to the old one, and loaded; it
        // never took over.
        assert!(
            !lab.fake.has("/usr/local/bin/dryserver update activate") && !lab.fake.has("systemctl restart --no-block k3s"),
            "{:#?}",
            lab.fake.ran()
        );
        let last = lab.last();
        assert_eq!((last.action.as_str(), last.serial, last.ok), (POSTPONED, 8, false), "{last:?}");
        assert!(lab.arch().is_none(), "no package was installed");
        // Once the archive is back, the same release goes in.
        lab.script(|s| s.download_fails = false);
        lab.apply_os(&r, Some(K3S_NEW)).unwrap();
        lab.assert_new("the next try");
    }

    #[test]
    fn k3s_that_does_not_get_healthy_reverts_the_release() {
        let lab = Lab::new();
        let e = lab.apply_os(&os_rel(8, K3S_SICK, NEXT_DAY), Some(K3S_SICK)).unwrap_err().to_string();
        assert!(e.contains("was not healthy") && e.contains("the k3s from before runs again"), "{e}");
        lab.assert_os_old("k3s reverted");
        assert!(lab.fake.k3s_runs().as_deref() == Some(K3S_OLD), "k3s runs the binary from before");
        assert!(!lab.fake.has("pacman -Su --noconfirm"), "no package was installed: {:#?}", lab.fake.ran());
        assert_eq!(lab.last().action, "reverted");
    }

    #[test]
    fn k3s_must_be_given_when_the_machine_runs_another() {
        let lab = Lab::new();
        let e = lab.apply_os(&os_rel(8, K3S_NEW, DAY), None).unwrap_err().to_string();
        assert!(e.contains("give its binary with --k3s"), "{e}");
        lab.assert_os_old("refused");
        assert!(!lab.fake.has("/usr/local/bin/dryserver update activate"), "it never took over");
        assert_eq!((lab.last().action.as_str(), lab.last().serial), (REFUSED, 8));
        // A binary that is not the release's is refused too.
        let e = lab.apply_os(&os_rel(8, K3S_NEW, DAY), Some(K3S_SICK)).unwrap_err().to_string();
        assert!(e.contains("not the one the release names"), "{e}");
        assert!(!lab.p(&format!("{STAGING}/k3s-8")).exists());
        lab.assert_os_old("wrong k3s");
    }

    #[test]
    fn a_package_install_that_stops_part_way_reverts_the_rest() {
        let lab = Lab::new();
        lab.script(|s| (s.install_fails, s.new_kernel) = (true, false));
        let a = Apply { reboot: true, ..lab.os_opts(&os_rel(8, K3S_NEW, NEXT_DAY), Some(K3S_NEW)) };
        let e = apply(&lab.m(), &Ctx::new(), &a, now(), &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("part way") && e.contains("Do not reboot"), "{e}");
        lab.assert_os_old("install failed");
        assert!(!lab.fake.has("systemctl --no-block reboot"), "never a reboot after a failed run");
        let a = lab.arch().unwrap();
        assert!(a.date == NEXT_DAY && !a.done, "{a:?}");
        let s = status(&lab.m(), now());
        assert!(s.reboot.contains("do NOT reboot"), "{}", s.reboot);
        // The next try finishes it.
        lab.script(|s| s.install_fails = false);
        lab.apply_os(&os_rel(9, K3S_NEW, NEXT_DAY), Some(K3S_NEW)).unwrap();
        assert!(lab.arch().unwrap().done);
        assert!(status(&lab.m(), now()).reboot.is_empty());
    }

    #[test]
    fn a_package_install_pacman_refused_says_its_words_and_leaves_reboots_safe() {
        // pacman refused before it changed anything: the update goes back
        // (k3s and the files), the packages are as they were, and a reboot
        // is as safe as before. What pacman said is kept, not guessed.
        let lab = Lab::new();
        lab.script(|s| s.install_refused = true);
        let e = lab.apply_os(&os_rel(8, K3S_NEW, NEXT_DAY), Some(K3S_NEW)).unwrap_err().to_string();
        assert!(e.contains("pacman changed nothing") && !e.contains("Do not reboot"), "{e}");
        let words = "openssl: /usr/lib/libcrypto.so.3 exists in filesystem (owned by openssl-3)";
        assert!(e.contains("error: failed to commit transaction (conflicting files)") && e.contains(words), "{e}");
        lab.assert_os_old("refused by pacman");
        let a = lab.arch().unwrap();
        assert!(!a.done && a.untouched && a.summary.contains(words), "{a:?}");
        assert!(!status(&lab.m(), now()).reboot.contains("do NOT reboot"), "{}", status(&lab.m(), now()).reboot);
        assert!(fs::read_to_string(lab.p(LOG)).unwrap().contains(words), "the update log has pacman's words");
        assert!(arch_due(&lab.m(), NEXT_DAY, false), "tried again by the next release");
    }

    #[test]
    fn the_confirm_window_starts_when_the_apply_is_done() {
        // A long install: the window counts from its end, and the apply's
        // own timer covered it until then.
        let lab = Lab::new();
        lab.script(|s| s.install_takes = 3 * 3600);
        lab.apply_os(&os_rel(8, K3S_OLD, NEXT_DAY), None).unwrap();
        let p = lab.pending().unwrap();
        assert_eq!((p.applied, p.deadline), (now(), now() + 3 * 3600 + WINDOW));
        assert!(lab.fake.has(&format!("systemd-run --unit=dryserver-update-revert-{} --on-active={WINDOW}s", p.id)));
    }

    #[test]
    fn a_new_kernel_reboots_once_with_the_update_armed() {
        let lab = Lab::new();
        lab.script(|s| s.new_kernel = true);
        let a = Apply { reboot: true, ..lab.os_opts(&os_rel(8, K3S_OLD, NEXT_DAY), None) };
        let mut out = Vec::new();
        apply(&lab.m(), &Ctx::new(), &a, now(), &mut out).unwrap();
        let said = String::from_utf8_lossy(&out).into_owned();
        assert!(said.contains("rebooting to start the new kernel"), "{said}");
        let p = lab.pending().unwrap();
        assert!(p.reboot && p.stage == STAGE_ARMED && p.window == WINDOW + REBOOT_WINDOW, "{p:?}");
        let reboot = lab.first("systemctl --no-block reboot");
        assert!(lab.first(&format!("systemd-run --unit=dryserver-update-revert-{} ", p.id)) < reboot, "armed before the reboot");
        assert_eq!(lab.fake.ran().iter().filter(|c| c.contains("reboot")).count(), 1);
        // The restart: the boot unit carries the update on.
        lab.write("/proc/sys/kernel/osrelease", b"6.12.4-arch1-1\n", 0o644);
        lab.write("/proc/stat", format!("cpu  1 2 3\nbtime {}\n", now() + 60).as_bytes(), 0o644);
        guard_boot(&lab.m(), &Ctx::new(), now() + 120, &mut Vec::new()).unwrap();
        assert_eq!(lab.pending().unwrap().boots, 1);
        assert!(status(&lab.m(), now()).reboot.is_empty(), "the new kernel runs");
        // The rollout's health check reads that this boot was the new
        // kernel's test.
        let json = serde_json::to_value(status(&lab.m(), now())).unwrap();
        assert_eq!((json["pending"]["kernel"].as_bool(), json["pending"]["boots"].as_u64()), (Some(true), Some(1)), "{json}");
        let lab = Lab::new();
        lab.apply_os(&os_rel(8, K3S_OLD, NEXT_DAY), None).unwrap();
        assert!(!lab.pending().unwrap().kernel, "no new kernel, no kernel test");

        // Without --reboot (by hand), or a disk that asks for its
        // passphrase: said, not done.
        for (allowed, crypt) in [(false, false), (true, true)] {
            let lab = Lab::new();
            lab.script(|s| s.new_kernel = true);
            if crypt {
                lab.write("/etc/crypttab", b"root UUID=abcd none luks\n", 0o600);
            }
            let a = Apply { reboot: allowed, ..lab.os_opts(&os_rel(8, K3S_OLD, NEXT_DAY), None) };
            let mut out = Vec::new();
            apply(&lab.m(), &Ctx::new(), &a, now(), &mut out).unwrap();
            let said = String::from_utf8_lossy(&out).into_owned();
            assert!(!lab.fake.has("systemctl --no-block reboot"), "{said}");
            let want = if crypt { "cannot reboot by itself" } else { "sudo systemctl reboot" };
            assert!(said.contains(want), "{said}");
            let p = lab.pending().unwrap();
            assert!(!p.reboot && p.window == WINDOW, "{p:?}");
            let s = status(&lab.m(), now());
            assert!(s.reboot.contains(if crypt { "reboot by hand" } else { "reboot needed" }), "{}", s.reboot);
        }

        // A reboot that does not start is said, and not waited for.
        let lab = Lab::new();
        lab.script(|s| (s.new_kernel, s.reboot_fails) = (true, true));
        let a = Apply { reboot: true, ..lab.os_opts(&os_rel(8, K3S_OLD, NEXT_DAY), None) };
        apply(&lab.m(), &Ctx::new(), &a, now(), &mut Vec::new()).unwrap();
        assert!(!lab.pending().unwrap().reboot);
    }

    #[test]
    fn power_cut_at_every_step_of_an_os_update() {
        quiet_power_cuts();
        let (mut reverted, mut kept) = (0, 0);
        let r = os_rel(8, K3S_NEW, NEXT_DAY);
        for n in 0.. {
            assert!(n < 800, "apply never finished");
            let lab = Lab::new();
            let a = lab.os_opts(&r, Some(K3S_NEW));
            let (hook, count) = cut_at(n);
            lab.hook(hook);
            let res = catch_unwind(AssertUnwindSafe(|| apply(&lab.m(), &Ctx::new(), &a, now(), &mut Vec::new())));
            lab.hook(noop());
            let k3s = lab.bytes(K3S_BIN);
            assert!(k3s == K3S_OLD || k3s == K3S_NEW, "step {n}: k3s is neither binary");
            let Err(_) = res else {
                res.unwrap().unwrap();
                assert!(count.load(Ordering::SeqCst) <= n, "step {n}");
                assert!(reverted >= 20 && kept >= 2, "reverted {reverted}, kept {kept}");
                break;
            };
            // The machine starts again: the boot unit runs before k3s.
            guard_boot(&lab.m(), &Ctx::new(), now() + 30, &mut Vec::new()).unwrap();
            match lab.pending() {
                None => {
                    reverted += 1;
                    lab.assert_os_old(&format!("cut at step {n}"));
                    assert!(!lab.p(osupdate::K3S_CHECK).exists(), "step {n}: a k3s check left for the k3s from before");
                }
                Some(p) => {
                    kept += 1;
                    assert_eq!(p.stage, STAGE_ARMED, "step {n}");
                    lab.assert_new(&format!("cut at step {n}"));
                    assert!(lab.bytes(K3S_BIN) == K3S_NEW && lab.pinned().as_deref() == Some(NEXT_DAY), "step {n}");
                }
            }
        }
    }

    #[test]
    fn the_apply_timer_leaves_a_finished_apply_alone() {
        let lab = Lab::new();
        lab.apply_os(&os_rel(8, K3S_NEW, NEXT_DAY), Some(K3S_NEW)).unwrap();
        let id = lab.pending().unwrap().id;
        guard_timer(&lab.m(), &Ctx::new(), &id, true, now(), &mut Vec::new()).unwrap();
        lab.assert_new("finished");
        assert!(lab.pending().is_some());
        // An apply that stopped part way (killed): reverted, k3s too.
        let mut p = lab.pending().unwrap();
        p.stage = STAGE_INSTALLING.into();
        save_pending(&lab.m(), &p).unwrap();
        guard_timer(&lab.m(), &Ctx::new(), &id, true, now(), &mut Vec::new()).unwrap();
        lab.assert_os_old("stopped part way");
        assert_eq!(lab.last().action, "reverted");
        // One that stopped while it loaded the packages: postponed.
        let lab = Lab::new();
        lab.apply_os(&os_rel(8, K3S_NEW, NEXT_DAY), Some(K3S_NEW)).unwrap();
        revert_by_hand(&lab.m(), &Ctx::new(), now(), &mut Vec::new()).unwrap();
        let id = "0123456789abcdef";
        let m = lab.m();
        let mut ch = Changes::new(
            &m,
            Pending {
                format: PENDING_FORMAT,
                id: id.into(),
                stage: STAGE_PREPARING.into(),
                serial: 9,
                prev_sha256: sha(OLD),
                ..Pending::default()
            },
        );
        ch.put(osupdate::MIRRORLIST, 0o644, osupdate::mirrorlist(NEXT_DAY).unwrap().as_bytes()).unwrap();
        guard_timer(&lab.m(), &Ctx::new(), id, true, now(), &mut Vec::new()).unwrap();
        assert_eq!(lab.pinned().as_deref(), Some(DAY));
        assert_eq!((lab.last().action.as_str(), lab.last().serial), (POSTPONED, 9));
        // At boot as well.
        let mut ch = Changes::new(
            &m,
            Pending {
                format: PENDING_FORMAT,
                id: id.into(),
                stage: STAGE_PREPARING.into(),
                serial: 9,
                prev_sha256: sha(OLD),
                ..Pending::default()
            },
        );
        ch.put(osupdate::MIRRORLIST, 0o644, osupdate::mirrorlist(NEXT_DAY).unwrap().as_bytes()).unwrap();
        guard_boot(&lab.m(), &Ctx::new(), now(), &mut Vec::new()).unwrap();
        assert_eq!((lab.pinned().as_deref(), lab.last().action.as_str()), (Some(DAY), POSTPONED));
    }

    #[test]
    fn the_kill_switch_stops_the_update_before_the_packages() {
        let lab = Lab::new();
        let root = lab.fake.root.clone();
        lab.hook(Arc::new(move |p| {
            if p == "k3s done" {
                put(&root, quarantine::STATE_FILE, "{\"cuts\": [{\"name\": \"x\", \"hosts\": [1]}]}");
            }
            Ok(())
        }));
        let e = lab.apply_os(&os_rel(8, K3S_NEW, NEXT_DAY), Some(K3S_NEW)).unwrap_err().to_string();
        assert!(e.contains("cut off on this machine"), "{e}");
        lab.assert_os_old("cut before the packages");
        assert!(!lab.fake.has("pacman -Su --noconfirm"), "{:#?}", lab.fake.ran());
    }

    #[test]
    fn the_release_files_may_go_once_they_are_staged() {
        // The rollout's store may move on (a newer release) while an apply
        // runs: it took copies of what it checked.
        let lab = Lab::new();
        let a = lab.os_opts(&os_rel(8, K3S_NEW, NEXT_DAY), Some(K3S_NEW));
        let (rel_file, k3s_file) = (a.release.clone(), a.k3s.clone().unwrap());
        lab.hook(Arc::new(move |p| {
            if p == "pinned" {
                let _ = fs::remove_file(&rel_file);
                let _ = fs::remove_file(&k3s_file);
            }
            Ok(())
        }));
        apply(&lab.m(), &Ctx::new(), &a, now(), &mut Vec::new()).unwrap();
        lab.assert_new("sources gone");
        assert!(lab.bytes(K3S_BIN) == K3S_NEW);
    }

    #[test]
    fn a_busy_pacman_postpones() {
        let lab = Lab::new();
        lab.write(osupdate::PACMAN_LOCK, b"", 0o644);
        lab.write("/proc/4242/comm", b"pacman\n", 0o644);
        let e = lab.apply_os(&os_rel(8, K3S_NEW, NEXT_DAY), Some(K3S_NEW)).unwrap_err().to_string();
        assert!(e.contains("pacman is already running"), "{e}");
        lab.assert_os_old("pacman busy");
        // The new binary looked, under the timer the old one armed, and
        // nothing but that timer was there to go.
        assert!(lab.fake.has("/usr/local/bin/.dryserver.new update prepare") && !lab.fake.has("pacman"), "{:#?}", lab.fake.ran());
        assert!(lab.fake.has("systemctl stop dryserver-update-revert-"), "{:#?}", lab.fake.ran());
        assert_eq!((lab.last().action.as_str(), lab.last().serial), (POSTPONED, 8));
    }

    #[test]
    fn status_says_what_runs_and_what_is_due() {
        let lab = Lab::new();
        let s = status(&lab.m(), now());
        assert!(!s.busy && s.arch_pinned == DAY && s.arch.is_none() && s.reboot.is_empty(), "{s:?}");
        let held = try_lock(&lab.m()).unwrap().unwrap();
        assert!(status(&lab.m(), now()).busy);
        drop(held);
        lab.script(|s| s.new_kernel = true);
        lab.apply_os(&os_rel(8, K3S_OLD, NEXT_DAY), None).unwrap();
        let s = status(&lab.m(), now());
        assert!(!s.busy && s.arch_pinned == NEXT_DAY && s.arch.as_ref().unwrap().done, "{s:?}");
        assert!(s.reboot.contains("reboot needed to start the new kernel"), "{}", s.reboot);
        let json = serde_json::to_value(&s).unwrap();
        for k in ["busy", "arch_pinned", "arch", "reboot"] {
            assert!(json.get(k).is_some(), "{k}: {json}");
        }
        assert!(json["pending"].get("step").is_some() && json["pending"].get("reboot").is_some(), "{json}");
        let mut out = Vec::new();
        print_status(&s, &mut out);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("arch: pinned to 2026/11/20") && text.contains("reboot: reboot needed"), "{text}");
    }

    #[test]
    fn a_detached_apply_runs_in_a_service_of_its_own() {
        let lab = Lab::new();
        let a = Apply { reboot: true, brain_k3s: "v1.37.2+k3s1".into(), ..lab.os_opts(&os_rel(8, K3S_NEW, NEXT_DAY), Some(K3S_NEW)) };
        start_detached(&lab.m(), &Ctx::new(), &a, &mut Vec::new()).unwrap();
        let run = lab.fake.ran().into_iter().find(|c| c.starts_with("systemd-run")).unwrap();
        for want in [
            "--unit=dryserver-update-apply",
            "--collect",
            "--property=KillSignal=SIGINT",
            "--property=KillMode=mixed",
            "--property=TimeoutStopSec=30min",
            "/usr/local/bin/dryserver update apply --release /tmp/release-8.json --binary",
            "--k3s /tmp/k3s-8",
            "--brain-k3s v1.37.2+k3s1",
            "--window 600 ",
        ] {
            assert!(run.contains(want), "{want:?} missing: {run}");
        }
        assert!(run.ends_with("--reboot"), "{run}");
        assert!(lab.pending().is_none(), "nothing applied in the caller");
        // Not while another update runs.
        let _held = try_lock(&lab.m()).unwrap().unwrap();
        let e = start_detached(&lab.m(), &Ctx::new(), &a, &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("another update is running"), "{e}");
    }

    #[test]
    fn review_a_revert_that_cannot_write_keeps_its_record() {
        const NEWER: &[u8] = b"\x7fELF dryserver 0.2.0, the next build";
        let lab = Lab::new();
        lab.apply(&rel(7, NEW)).unwrap();
        confirm(&lab.m(), &Ctx::new(), Some(7), now(), &mut Vec::new()).unwrap();
        apply(&lab.m(), &Ctx::new(), &lab.opts(&rel(8, NEWER), lab.staged(NEWER)), now(), &mut Vec::new()).unwrap();
        lab.hook(Arc::new(|p| if p == "write" { Err(io::Error::from_raw_os_error(libc::ENOSPC)) } else { Ok(()) }));
        let id = lab.pending().unwrap().id;
        assert!(guard_timer(&lab.m(), &Ctx::new(), &id, false, now() + WINDOW, &mut Vec::new()).is_err());
        assert_eq!(lab.bytes(SERVER_BIN), NEW);
        let installed = load_installed(&lab.m()).unwrap().map(|(_, r)| r.serial);
        assert!(lab.pending().is_some() || installed == Some(7), "record gone, says it runs {installed:?}");
        // The backups stay, and a timer of its own tries again.
        assert!(lab.p(&format!("{BACKUPS}/{id}")).is_dir());
        assert!(lab.fake.has(&format!("systemd-run --unit=dryserver-update-revert-{id}-retry-")), "{:#?}", lab.fake.ran());
        // Room again: the next try finishes it, and status says so.
        lab.hook(noop());
        let id2 = lab.pending().unwrap().id;
        guard_timer(&lab.m(), &Ctx::new(), &id2, false, now() + WINDOW + 300, &mut Vec::new()).unwrap();
        assert!(lab.pending().is_none() && load_installed(&lab.m()).unwrap().unwrap().1.serial == 7);
        assert!(!lab.p(&format!("{BACKUPS}/{id}")).exists());
        let s = status(&lab.m(), now());
        assert!(!s.busy && s.pending.is_none() && s.last.as_ref().unwrap().action == "reverted", "{s:?}");
    }

    #[test]
    fn a_revert_that_does_not_finish_says_so_in_status() {
        // A file that cannot be put back: the record says it goes back, not
        // what the apply was doing, and the rollout can rely on it.
        let lab = Lab::new();
        lab.apply_os(&os_rel(8, K3S_NEW, NEXT_DAY), Some(K3S_NEW)).unwrap();
        lab.hook(Arc::new(|p| if p == "write" { Err(io::Error::from_raw_os_error(libc::EDQUOT)) } else { Ok(()) }));
        assert!(revert_by_hand(&lab.m(), &Ctx::new(), now(), &mut Vec::new()).is_err());
        lab.hook(noop());
        // The record could not take the new stage either: it is written
        // once there is room, by the next try.
        let mut p = lab.pending().unwrap();
        p.stage = STAGE_REVERTING.into();
        p.step = "going back did not finish: 3 problem(s); tried again by a timer, at the next boot, or by dryserver update revert".into();
        save_pending(&lab.m(), &p).unwrap();
        let s = status(&lab.m(), now());
        let pend = s.pending.as_ref().unwrap();
        assert!(pend.stage == STAGE_REVERTING && pend.step.contains("going back did not finish"), "{pend:?}");
        assert!(!s.busy);
        // last.json could not be written on the full disk; the log line
        // could (it needs no new file).
        assert!(fs::read_to_string(lab.p(LOG)).unwrap().contains("but that did not finish"));
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["pending"]["stage"], STAGE_REVERTING);
        // The rest is back: the binary and k3s; the next try does the files.
        assert!(lab.bytes(SERVER_BIN) == OLD && lab.bytes(K3S_BIN) == K3S_OLD);
        revert_by_hand(&lab.m(), &Ctx::new(), now(), &mut Vec::new()).unwrap();
        lab.assert_os_old("the next try");
        // A backup that is gone will not come back: said, and the record
        // goes, so it does not hold every later update up.
        let lab = Lab::new();
        lab.apply(&rel(7, NEW)).unwrap();
        let p = lab.pending().unwrap();
        fs::remove_file(lab.p(p.files[0].backup.as_deref().unwrap())).unwrap();
        let e = revert_by_hand(&lab.m(), &Ctx::new(), now(), &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("is lost") && lab.pending().is_none(), "{e}");
        // A reload that fails does not keep the record: the files are back.
        let lab = Lab::new();
        lab.apply(&rel(7, NEW)).unwrap();
        lab.script(|s| s.sshd_fails = Some("older dryserver"));
        let e = revert_by_hand(&lab.m(), &Ctx::new(), now(), &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("problems on the way back") && e.contains("sshd -t"), "{e}");
        assert!(lab.pending().is_none() && lab.get(SSHD_DROPIN) == OLD_SSHD);
    }

    #[test]
    fn a_fix_to_the_k3s_and_arch_code_reaches_machines_with_its_own_release() {
        // The binary that runs `update apply` checks and hands over; the new
        // one runs everything else, so its fixes apply already. Here the
        // old one's k3s and Arch code fails every command it runs.
        let lab = Lab::new();
        lab.script(|s| s.old_os_code_broken = true);
        let a = Apply { reboot: true, ..lab.os_opts(&os_rel(8, K3S_NEW, NEXT_DAY), Some(K3S_NEW)) };
        apply(&lab.m(), &Ctx::new(), &a, now(), &mut Vec::new()).unwrap();
        lab.assert_new("handed over");
        assert!(lab.bytes(K3S_BIN) == K3S_NEW && lab.pinned().as_deref() == Some(NEXT_DAY) && lab.arch().unwrap().done);
        let f = &lab.fake;
        for (prefix, who) in [
            ("/usr/local/bin/.dryserver.new selfcheck", "old"),
            ("/usr/local/bin/.dryserver.new update prepare", "old"),
            ("/usr/local/bin/dryserver update activate", "old"),
            ("pacman -Syy", "new"),
            ("pacman -Suw", "new"),
            ("/usr/local/bin/.k3s.dryserver-new --version", "new"),
            ("systemctl restart --no-block k3s.service", "new"),
            ("pacman -Su --noconfirm", "new"),
            ("nft -f /etc/nftables.conf", "new"),
        ] {
            assert_eq!(f.who_ran(prefix), [who], "{prefix}: {:#?}", f.by.lock().unwrap());
        }
        // The old binary armed the apply's timer; the new one the window.
        let p = lab.pending().unwrap();
        assert_eq!((p.handover, p.stage.as_str(), p.may_reboot), (HANDOVER, STAGE_ARMED, true));
        assert_eq!(f.who_ran(&format!("systemd-run --unit=dryserver-update-revert-{}-apply ", p.id)), ["old"]);
        assert_eq!(f.who_ran(&format!("systemd-run --unit=dryserver-update-revert-{} ", p.id)), ["new"]);
        assert_eq!(lab.last().action, "applied");
        // Both steps of the new binary, and pacman's install under it, keep
        // the update lock: nothing reverts under them if apply dies.
        let kept = f.kept.lock().unwrap().clone();
        for want in ["/usr/local/bin/.dryserver.new update prepare --id", "/usr/local/bin/dryserver update activate --id", "pacman -Su "] {
            assert!(kept.iter().any(|k| k.starts_with(want)), "{want}: {kept:#?}");
        }
        assert!(!kept.iter().any(|k| k.starts_with("pacman -Syy") || k.contains("selfcheck")), "{kept:#?}");
        // Without the handover (the new binary from before it), the old
        // code runs those steps, and the update goes back.
        let lab = Lab::new();
        lab.script(|s| (s.old_os_code_broken, s.new_is_legacy) = (true, true));
        assert!(lab.apply_os(&os_rel(8, K3S_NEW, NEXT_DAY), Some(K3S_NEW)).is_err());
        lab.assert_os_old("the old code ran");
    }

    #[test]
    fn the_lock_stays_held_while_a_step_that_kept_it_runs() {
        // The apply dies (or is killed) while its new binary, or pacman
        // under it, still runs: those keep the update lock, so no settle
        // or timer reverts under them, and status says an update runs.
        let lab = Lab::new();
        let held = try_lock(&lab.m()).unwrap().unwrap();
        let fd = held.as_raw_fd();
        let step =
            std::thread::spawn(move || crate::runner::ExecRunner::silent().ok(&Ctx::new(), &Cmd::new("sleep", &["1"]).keep_fd(Some(fd))));
        std::thread::sleep(Duration::from_millis(300));
        drop(held);
        assert!(try_lock(&lab.m()).unwrap().is_none(), "the lock went with the process that took it");
        assert!(status(&lab.m(), now()).busy);
        let e = revert_by_hand(&lab.m(), &Ctx::new().with_timeout(Duration::from_millis(300)), now(), &mut Vec::new()).unwrap_err();
        assert!(e.to_string().contains("another update is running") || e.is_canceled() || e.is(crate::err::Kind::DeadlineExceeded), "{e}");
        step.join().unwrap().unwrap();
        assert!(try_lock(&lab.m()).unwrap().is_some(), "free once the step ended");
    }

    #[test]
    fn a_new_binary_from_before_the_handover_gets_the_old_way() {
        // A rollback to a dryserver from before the handover: it knows no
        // `update prepare`, its activate writes the files only, and the
        // binary that started the update does the rest itself.
        let lab = Lab::new();
        lab.script(|s| s.new_is_legacy = true);
        lab.apply_os(&os_rel(8, K3S_NEW, NEXT_DAY), Some(K3S_NEW)).unwrap();
        lab.assert_new("the old way");
        assert!(lab.bytes(K3S_BIN) == K3S_NEW && lab.arch().unwrap().done);
        let f = &lab.fake;
        assert!(!f.has("/usr/local/bin/.dryserver.new update prepare"));
        for prefix in ["pacman -Syy", "systemctl restart --no-block k3s.service", "pacman -Su --noconfirm"] {
            assert_eq!(f.who_ran(prefix), ["old"], "{prefix}");
        }
        assert_eq!(f.who_ran("nft -f /etc/nftables.conf"), ["new"], "the files are still the new binary's");
        assert_eq!((lab.pending().unwrap().handover, lab.last().action.as_str()), (0, "applied"));
        // A binary from before the handover starting the update: the record
        // has none, and this binary's activate writes the files only.
        let lab = Lab::new();
        let id = "0123456789abcdef";
        let p = Pending { format: PENDING_FORMAT, id: id.into(), stage: STAGE_INSTALLING.into(), serial: 7, ..Pending::default() };
        save_pending(&lab.m(), &p).unwrap();
        let apply_lock = try_lock(&lab.m()).unwrap().expect("the update lock");
        activate(&lab.fake.machine_as("new"), &Ctx::new(), id, &mut Vec::new()).unwrap();
        let mut p = lab.pending().unwrap();
        assert_eq!(p.stage, STAGE_INSTALLING, "the binary that started it arms the window");
        assert!(lab.get(FIREWALL) == lab.rendered(FIREWALL) && !lab.fake.has("pacman") && load_installed(&lab.m()).unwrap().is_none());
        // A handover newer than this binary knows is not guessed at.
        p.handover = HANDOVER + 1;
        save_pending(&lab.m(), &p).unwrap();
        let e = activate(&lab.fake.machine_as("new"), &Ctx::new(), id, &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("does not know"), "{e}");
        drop(apply_lock);
    }

    #[test]
    fn a_new_binary_that_dies_while_it_prepares_changes_nothing() {
        let lab = Lab::new();
        lab.script(|s| s.prepare_dies = true);
        let e = lab.apply_os(&os_rel(8, K3S_NEW, NEXT_DAY), Some(K3S_NEW)).unwrap_err().to_string();
        assert!(e.contains("could not prepare the update") && e.contains("signal 11"), "{e}");
        lab.assert_os_old("prepare died");
        assert_eq!((lab.last().action.as_str(), lab.last().serial), (REFUSED, 8), "a release whose binary crashes does not work here");
        assert!(!lab.p(NEW_BIN).exists() && !lab.fake.has("/usr/local/bin/dryserver update activate"));
        // Started by hand, or by anything but an apply: refused.
        let e = prepare(&lab.m(), &Ctx::new(), "0123456789abcdef", &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("runs only inside it"), "{e}");
    }
}
