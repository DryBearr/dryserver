//! Nightly backup of the coordinator, and the desktop's copy of it.
//!
//! If the coordinator's disk dies, the swarm would have to be installed
//! again. `dryserver backup` (a timer, every night) packs what a new
//! coordinator needs to take its place: the cluster's datastore and token,
//! the registry and the coordinator's keys. The archive is encrypted to a
//! key whose private half only the admin's desktop holds
//! (secrets/backup_ed25519): the coordinator can make a backup but never
//! read one, so neither a stolen backup nor a hacked coordinator gives
//! away an older state. `./dryserver backup-pull` on the desktop copies
//! the backups there.
//!
//! The archive, format 1 (restoring is a later step; this is all it needs):
//!
//! - `brain-<UTC time like 20261121T023012Z>.tar.age` in BACKUP_DIR, and
//!   next to it the same name plus `.sig`.
//! - `age -d -i secrets/backup_ed25519 FILE` gives a plain tar archive.
//! - Its first entry is MANIFEST: format, dryserver and k3s versions, host
//!   name, time, whether k3s was stopped for the copy, what was left out
//!   because it was missing, and every file with mode, size and SHA-256.
//! - Then every file under its path without the leading "/", with owner,
//!   group and mode, so `tar -xpf - -C /` puts them back. Only the paths
//!   in SOURCES are in it, never their parent directories: unpacking never
//!   changes /etc or /var/lib themselves.
//! - The .sig file is an SSH signature by the coordinator's host key
//!   (namespace NAMESPACE) over receipt(): the file's name, size and
//!   SHA-256. Anyone can encrypt to a public key, and the directory sits in
//!   the registry account's, so encryption alone does not say who made a
//!   file. The desktop takes only backups signed by the coordinator it
//!   pinned.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use chrono::{DateTime, Datelike, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ctx::Ctx;
use crate::err::{Error, Result};
use crate::gotime::Time;
use crate::runner::{Cmd, Runner};
use crate::signed::Verifier;
use crate::sysconf::Role;
use crate::{bail, errf, fsx, iso};

/// Where the coordinator keeps its backups.
pub const BACKUP_DIR: &str = "/var/lib/dryserver/backups";
/// The public half of secrets/backup_ed25519, from the USB stick.
pub const RECIPIENT: &str = "/usr/local/share/dryserver/backup_ed25519.pub";
/// The result of the last run, for the admin and a future monitor.
pub const STATUS_FILE: &str = "last.json";
/// What the coordinator's host key signs backups as.
pub const NAMESPACE: &str = "dryserver-backup";
/// Backups kept: the newest of each of the last KEEP_DAILY days that have
/// one, and of each of the last KEEP_WEEKLY weeks that have one.
pub const KEEP_DAILY: usize = 7;
pub const KEEP_WEEKLY: usize = 4;
/// What a backup must leave free on its disk, whichever is more.
pub const MIN_FREE_BYTES: u64 = 1 << 30;
pub const MIN_FREE_PERCENT: u64 = 10;
/// The archive format described above.
pub const FORMAT: u32 = 1;

const HOST_KEY: &str = "etc/ssh/ssh_host_ed25519_key";
const ROLE_FILE: &str = "etc/dryserver/role";
const LOCK_FILE: &str = ".lock";
const STAGING: &str = ".staging";
/// The registry's directory: the backups live inside it.
const PARENT: &str = "var/lib/dryserver";
/// There while the backup has k3s stopped. Whatever ends the backup
/// service (a crash, a kill, its timeout), the unit's ExecStopPost starts
/// k3s again when it finds this.
pub const K3S_MARK: &str = "/run/dryserver-backup.k3s-stopped";

/// One thing that goes into the backup, a path relative to "/".
struct Source {
    path: &'static str,
    /// The backup is refused without it.
    needed: bool,
    /// Copied while k3s is stopped: it changes while k3s runs.
    k3s: bool,
    /// Every entry of the directory path whose name starts with this,
    /// instead of path itself.
    prefix: Option<&'static str>,
}

const fn src(path: &'static str, needed: bool, k3s: bool) -> Source {
    Source { path, needed, k3s, prefix: None }
}

/// What a new coordinator needs. k3s's backup guide for a single server
/// with SQLite: the datastore directory and the server token, which
/// encrypts what the datastore keeps about the cluster itself. Its
/// certificates and the key of the encrypted secrets are in there too;
/// cred and tls hold the same as files and are kept for a simpler restore.
const SOURCES: &[Source] = &[
    src("var/lib/rancher/k3s/server/db", true, true),
    src("var/lib/rancher/k3s/server/token", true, true),
    src("var/lib/rancher/k3s/server/agent-token", false, true),
    src("var/lib/rancher/k3s/server/cred", false, true),
    src("var/lib/rancher/k3s/server/tls", false, true),
    Source { path: "var/lib/rancher/k3s/server/manifests", needed: false, k3s: true, prefix: Some("dryserver-") },
    src("etc/rancher/k3s/agent-token", true, false),
    src("etc/rancher/k3s/config.yaml", false, false),
    src("var/lib/dryserver/registry.json", true, false),
    src("etc/dryserver", true, false),
    src("etc/wireguard", true, false),
    Source { path: "etc/ssh", needed: true, k3s: false, prefix: Some("ssh_host_") },
];

/// The backup's file name for a time.
pub fn name_of(t: DateTime<Utc>) -> String {
    format!("brain-{}.tar.age", t.format("%Y%m%dT%H%M%SZ"))
}

/// The time in a backup's file name; None for any other name. Strict: the
/// name also comes from the coordinator and goes into a command line.
pub fn parse_name(name: &str) -> Option<DateTime<Utc>> {
    let t = name.strip_prefix("brain-")?.strip_suffix(".tar.age")?.as_bytes();
    if t.len() != 16 || t[8] != b'T' || t[15] != b'Z' {
        return None;
    }
    let digits = |r: std::ops::Range<usize>| -> Option<u32> {
        let s = &t[r];
        if !s.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(s).ok()?.parse().ok()
    };
    let (y, mo, d) = (digits(0..4)?, digits(4..6)?, digits(6..8)?);
    let (h, mi, s) = (digits(9..11)?, digits(11..13)?, digits(13..15)?);
    Utc.with_ymd_and_hms(y as i32, mo, d, h, mi, s).single()
}

/// The backups to keep of these. Counts days and weeks that have a backup,
/// not days on the calendar: after weeks with the coordinator switched
/// off the last good backups stay, and a clock that jumps does not empty
/// the directory. Never decides by "now", which may be wrong.
pub fn keep(stamps: &[DateTime<Utc>], daily: usize, weekly: usize) -> BTreeSet<DateTime<Utc>> {
    let mut all: Vec<DateTime<Utc>> = stamps.to_vec();
    all.sort_unstable_by(|a, b| b.cmp(a));
    all.dedup();
    let mut out = BTreeSet::new();
    let mut pick = |n: usize, bucket: &dyn Fn(&DateTime<Utc>) -> (i32, u32)| {
        let mut last = None;
        let mut count = 0;
        for t in &all {
            let b = bucket(t);
            if Some(b) == last {
                continue;
            }
            if count == n {
                break;
            }
            last = Some(b);
            count += 1;
            out.insert(*t);
        }
    };
    pick(daily, &|t| (t.year(), t.ordinal()));
    pick(weekly, &|t| (t.iso_week().year(), t.iso_week().week()));
    out
}

/// What the coordinator's host key signs for a backup.
pub fn receipt(name: &str, size: u64, sha256: &str) -> String {
    format!("dryserver backup\nfile {name}\nsize {size}\nsha256 {sha256}\n")
}

/// Whether a backup of need bytes leaves enough free on a disk of total
/// bytes with free bytes left.
pub fn room(total: u64, free: u64, need: u64) -> Result<()> {
    let floor = MIN_FREE_BYTES.max(total / 100 * MIN_FREE_PERCENT);
    let after = free.saturating_sub(need);
    if free < need || after < floor {
        bail!(
            "not enough disk space: the backup needs about {} MiB and must leave {} MiB free ({MIN_FREE_PERCENT}% of the disk, at least 1 GiB), \
             but only {} MiB are free. Free some space or remove old backups in {BACKUP_DIR}",
            need >> 20,
            floor >> 20,
            free >> 20
        );
    }
    Ok(())
}

/// The result of the last run, in BACKUP_DIR/STATUS_FILE.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Status {
    pub time: Time,
    /// "ok" or "failed".
    pub result: String,
    /// The backup written, "" when none was.
    pub file: String,
    pub size: u64,
    pub error: String,
    /// "restarted", "was not running" or "did not start again".
    pub k3s: String,
    pub warnings: Vec<String>,
}

/// What a run did.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Done {
    pub file: String,
    pub size: u64,
    pub k3s: String,
    pub removed: Vec<String>,
    pub warnings: Vec<String>,
    /// Went wrong after the backup was written (k3s did not start again).
    pub problem: Option<String>,
}

/// Starts k3s again if it is dropped while still armed: a panic during
/// the copy must not leave the cluster without its control plane.
struct StartAgain<'a> {
    run: &'a dyn Runner,
    armed: bool,
}

impl Drop for StartAgain<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.run.ok(&Ctx::new(), &Cmd::new("systemctl", &["start", "--no-block", "k3s.service"]));
        }
    }
}

/// Removes the staging copy (the plain datastore and keys) and a half
/// written archive, whatever happens.
struct Cleanup(Vec<PathBuf>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        for p in &self.0 {
            if p.is_dir() {
                let _ = std::fs::remove_dir_all(p);
            } else {
                let _ = std::fs::remove_file(p);
            }
        }
    }
}

/// One backup run on the coordinator.
pub struct Job<'a> {
    /// "/" on the coordinator; a test directory in tests.
    pub root: PathBuf,
    pub run: &'a dyn Runner,
    pub hostname: String,
    /// The age program.
    pub age: String,
    /// How often and how long to wait for k3s to be up again, and how
    /// many times to start it.
    pub poll: Duration,
    pub start_wait: Duration,
    pub start_tries: u32,
    /// (size, free) of the disk holding a path.
    pub space: fn(&Path) -> Result<(u64, u64)>,
}

impl<'a> Job<'a> {
    pub fn new(run: &'a dyn Runner, hostname: &str) -> Job<'a> {
        Job {
            root: PathBuf::from("/"),
            run,
            hostname: hostname.to_string(),
            age: "age".into(),
            poll: Duration::from_secs(2),
            start_wait: Duration::from_secs(120),
            start_tries: 3,
            space: |p| fsx::space(p),
        }
    }

    fn at(&self, rel: &str) -> PathBuf {
        fsx::under(&self.root, rel)
    }

    pub fn dir(&self) -> PathBuf {
        self.at(BACKUP_DIR)
    }

    /// Makes a backup and records how it went in the status file. Refuses,
    /// without touching the status, on a machine that is not the
    /// coordinator and while another backup runs.
    pub fn run(&self, ctx: &Ctx, now: Time, out: &mut dyn Write) -> Result<Done> {
        if Role::parse(fsx::read_or_empty(self.at(ROLE_FILE)).trim()) != Some(Role::Coordinator) {
            bail!("backups are made on the coordinator; this machine is not it");
        }
        self.prepare_dir()?;
        let Some(_lock) = fsx::try_lock(self.dir().join(LOCK_FILE))? else {
            bail!("another backup is running");
        };
        let res = self.make(ctx, now, out);
        let mut st = Status { time: now, ..Status::default() };
        match &res {
            Ok(d) => {
                st.result = if d.problem.is_some() { "failed" } else { "ok" }.into();
                st.file = d.file.clone();
                st.size = d.size;
                st.k3s = d.k3s.clone();
                st.warnings = d.warnings.clone();
                st.error = d.problem.clone().unwrap_or_default();
            }
            Err(e) => {
                st.result = "failed".into();
                st.error = e.to_string();
            }
        }
        let write = self.write_status(&st);
        let d = res?;
        write?;
        if let Some(p) = &d.problem {
            return Err(Error::new(p.clone()));
        }
        Ok(d)
    }

    fn write_status(&self, st: &Status) -> Result<()> {
        let path = self.dir().join(STATUS_FILE);
        let tmp = self.dir().join(format!("{STATUS_FILE}.tmp"));
        fsx::write_file(&tmp, serde_json::to_vec_pretty(st)?, 0o640)?;
        self.wheel(&tmp)?;
        fsx::rename(&tmp, &path)
    }

    /// Group wheel may read: the admin's login copies backups without
    /// sudo. They are encrypted; the status says nothing secret.
    fn wheel(&self, p: &Path) -> Result<()> {
        fsx::chmod(p, if p.is_dir() { 0o750 } else { 0o640 })?;
        self.run.ok(&Ctx::new(), &Cmd::new("chgrp", &["wheel", &p.display().to_string()]))
    }

    /// The backup directory: made by root, readable by wheel. It sits in
    /// the registry account's directory, which wheel may pass through but
    /// not list. Whatever stands there that root did not make is not used.
    fn prepare_dir(&self) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let dir = self.dir();
        match std::fs::symlink_metadata(&dir) {
            Ok(m) if !m.is_dir() || (fsx::is_root() && m.uid() != 0) => {
                bail!(
                    "{} is not a directory made by root; it was not touched. Look at it, remove it, and run the backup again",
                    dir.display()
                )
            }
            Ok(_) => {}
            Err(_) => fsx::mkdir_all(&dir, 0o750)?,
        }
        self.wheel(&dir)
    }

    fn make(&self, ctx: &Ctx, now: Time, out: &mut dyn Write) -> Result<Done> {
        let mut done = Done::default();
        // The admin's login (wheel) may pass through the registry's
        // directory to the backups, nothing more. Set every time: a chmod
        // of that directory takes it away.
        let parent = self.at(PARENT).display().to_string();
        if let Err(e) = self.run.ok(ctx, &Cmd::new("setfacl", &["-m", "g:wheel:x", &parent])) {
            done.warnings.push(format!("backup-pull will need sudo here: {e}"));
        }
        // Everything that can be checked before k3s is stopped.
        if let Err(e) = self.run.ok(ctx, &Cmd::new(&self.age, &["--version"]).quiet()) {
            bail!("the age tool is missing or broken ({e}); install it: pacman -S age");
        }
        let rcpt = self.at(RECIPIENT);
        let line = fsx::read_string(&rcpt).map_err(|e| e.wrap("no backup key on this machine (reinstall it from a new USB stick)"))?;
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 || fields[0] != "ssh-ed25519" || line.lines().filter(|l| !l.trim().is_empty()).count() != 1 {
            bail!("{} is not one ssh-ed25519 public key", rcpt.display());
        }
        let name = name_of(now.0);
        let final_path = self.dir().join(&name);
        let sig_path = self.dir().join(format!("{name}.sig"));
        if fsx::exists(&final_path) || fsx::exists(&sig_path) {
            bail!("a backup named {name} exists already; is the clock right?");
        }
        let mut newest: Vec<DateTime<Utc>> = self.backups()?.into_iter().filter(|t| *t > now.0).collect();
        newest.sort();
        if let Some(t) = newest.last() {
            done.warnings.push(format!("the clock is behind the newest backup ({}); this one is kept anyway", name_of(*t)));
        }
        let (live, k3s, missing) = self.pick()?;
        let need = live.iter().chain(&k3s).map(|p| tree_size(&self.at(p))).sum::<u64>();
        // The plain copy and the archive are on the disk at the same time.
        let (total, free) = (self.space)(&self.dir())?;
        room(total, free, need.saturating_mul(2) + (16 << 20))?;

        // Left by a run that was killed: the plain copy and half archives.
        let staging = self.dir().join(STAGING);
        if fsx::exists(&staging) {
            std::fs::remove_dir_all(&staging).map_err(|e| Error::from(e).wrap(format!("remove {}", staging.display())))?;
        }
        for e in std::fs::read_dir(self.dir()).map(|rd| rd.flatten().collect::<Vec<_>>()).unwrap_or_default() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with(".brain-") && n.ends_with(".tmp") {
                let _ = std::fs::remove_file(e.path());
            }
        }
        let tmp = self.dir().join(format!(".{name}.tmp"));
        let sig_tmp = self.dir().join(format!(".{name}.sig.tmp"));
        let _clean = Cleanup(vec![staging.clone(), tmp.clone(), sig_tmp.clone()]);
        fsx::mkdir_all(&staging, 0o700)?;
        fsx::chmod(&staging, 0o700)?;
        self.copy(ctx, &live, &staging)?;

        // The datastore: k3s stopped, so SQLite is not written during the
        // copy. KillMode=process: the containers keep running, only the
        // control plane pauses. Started again however the copy went.
        let state = self.run.run(ctx, &Cmd::new("systemctl", &["is-active", "k3s.service"]).stdout_only()).0;
        let running = matches!(state.trim(), "active" | "activating" | "reloading");
        let mut guard = StartAgain { run: self.run, armed: false };
        let mark = self.at(K3S_MARK);
        if running {
            guard.armed = true;
            if let Err(e) =
                fsx::mkdir_all(fsx::dir(&mark), 0o755).and_then(|_| fsx::write_file(&mark, "k3s was stopped for the backup\n", 0o600))
            {
                done.warnings.push(format!("no safety net if the backup dies with k3s stopped: {e}"));
            }
            let _ = writeln!(out, "backup: stopping k3s for the copy of its datastore");
            if let Err(e) = self.run.ok(&ctx.with_timeout(Duration::from_secs(180)), &Cmd::new("systemctl", &["stop", "k3s.service"])) {
                guard.armed = false;
                let started = self.start_k3s(out);
                if started {
                    let _ = std::fs::remove_file(&mark);
                }
                return Err(e.wrap(format!("stop k3s{}", if started { "" } else { "; and k3s did not start again" })));
            }
        }
        let copied = self.copy(ctx, &k3s, &staging);
        done.k3s = if running {
            guard.armed = false;
            if self.start_k3s(out) {
                let _ = std::fs::remove_file(&mark);
                "restarted".into()
            } else {
                let msg = format!(
                    "k3s did not start again after the backup (tried {} times). The cluster's control plane is down: \
                     sudo systemctl start k3s; journalctl -u k3s",
                    self.start_tries
                );
                done.problem = Some(msg);
                "did not start again".into()
            }
        } else {
            "was not running".into()
        };
        drop(guard);
        copied.map_err(|e| match &done.problem {
            Some(p) => errf!("{e}; and {p}"),
            None => e,
        })?;

        let manifest = manifest(&staging, &live, &k3s, &missing, &self.hostname, &done.k3s, &self.k3s_version(ctx), now)?;
        fsx::write_file(staging.join("MANIFEST"), manifest, 0o600)?;
        let mut entries = vec!["MANIFEST".to_string()];
        entries.extend(k3s.iter().chain(&live).cloned());
        fsx::write_file(&tmp, b"", 0o600)?;
        let (dir_s, tmp_s, rcpt_s) = (staging.display().to_string(), tmp.display().to_string(), rcpt.display().to_string());
        let mut args = vec![
            "-c".to_string(),
            r#"set -euo pipefail; age=$1; rcpt=$2; dir=$3; out=$4; shift 4
tar --create --file=- --directory="$dir" --sort=name -- "$@" | "$age" --encrypt --recipients-file "$rcpt" > "$out""#
                .into(),
            "bash".into(),
            self.age.clone(),
            rcpt_s,
            dir_s,
            tmp_s,
        ];
        args.extend(entries);
        self.run.ok(ctx, &Cmd::new("bash", &args)).map_err(|e| e.wrap("pack and encrypt the backup"))?;
        let (size, sum) = file_sum(&tmp)?;
        if size == 0 {
            bail!("the encrypted backup is empty");
        }
        let host_key = self.at(HOST_KEY).display().to_string();
        let sig = self
            .run
            .output(
                ctx,
                &Cmd::new("ssh-keygen", &["-Y", "sign", "-f", &host_key, "-n", NAMESPACE]).stdin(receipt(&name, size, &sum)).stdout_only(),
            )
            .map_err(|e| e.wrap("sign the backup with the host key"))?;
        if !sig.contains("BEGIN SSH SIGNATURE") {
            bail!("ssh-keygen gave no signature for the backup");
        }
        fsx::write_file(&sig_tmp, &sig, 0o600)?;
        for p in [&tmp, &sig_tmp] {
            std::fs::File::open(p).and_then(|f| f.sync_all()).map_err(|e| Error::from(e).wrap(format!("sync {}", p.display())))?;
            self.wheel(p)?;
        }
        // Never over an existing file (checked above; hard links fail
        // rather than replace).
        std::fs::hard_link(&sig_tmp, &sig_path).map_err(|e| Error::from(e).wrap(format!("keep {}", sig_path.display())))?;
        if let Err(e) = std::fs::hard_link(&tmp, &final_path) {
            let _ = std::fs::remove_file(&sig_path);
            return Err(Error::from(e).wrap(format!("keep {}", final_path.display())));
        }
        let _ = std::fs::File::open(self.dir()).and_then(|d| d.sync_all());
        done.file = name.clone();
        done.size = size;
        let _ = writeln!(out, "backup: wrote {} ({}, k3s {})", final_path.display(), human(size), done.k3s);
        for w in &done.warnings {
            let _ = writeln!(out, "backup: warning: {w}");
        }

        // Older backups beyond the plan, never the one just made.
        let all = self.backups()?;
        let mut kept = keep(&all, KEEP_DAILY, KEEP_WEEKLY);
        kept.insert(now.0);
        for t in all.iter().filter(|t| !kept.contains(t)) {
            let n = name_of(*t);
            for f in [n.clone(), format!("{n}.sig")] {
                let _ = std::fs::remove_file(self.dir().join(f));
            }
            done.removed.push(n);
        }
        if !done.removed.is_empty() {
            let _ = writeln!(out, "backup: removed {} older backup(s): {}", done.removed.len(), done.removed.join(", "));
        }
        Ok(done)
    }

    /// The times of the backups in the directory.
    fn backups(&self) -> Result<Vec<DateTime<Utc>>> {
        let rd = std::fs::read_dir(self.dir()).map_err(|e| Error::from(e).wrap(format!("read {}", self.dir().display())))?;
        Ok(rd.flatten().filter_map(|e| parse_name(&e.file_name().to_string_lossy())).collect())
    }

    /// The paths to copy (live ones, those of k3s) and the optional ones
    /// that are missing. A missing needed one refuses the backup before
    /// anything is stopped.
    fn pick(&self) -> Result<(Vec<String>, Vec<String>, Vec<String>)> {
        let (mut live, mut k3s, mut missing) = (Vec::new(), Vec::new(), Vec::new());
        for s in SOURCES {
            let found: Vec<String> = match s.prefix {
                None => {
                    if std::fs::symlink_metadata(self.at(s.path)).is_ok() {
                        vec![s.path.to_string()]
                    } else {
                        vec![]
                    }
                }
                Some(pre) => {
                    let mut v: Vec<String> = std::fs::read_dir(self.at(s.path))
                        .map(|rd| {
                            rd.flatten()
                                .map(|e| e.file_name().to_string_lossy().into_owned())
                                .filter(|n| n.starts_with(pre) && !n.contains('\n'))
                                .map(|n| format!("{}/{n}", s.path))
                                .collect()
                        })
                        .unwrap_or_default();
                    v.sort();
                    v
                }
            };
            let what = match s.prefix {
                Some(pre) => format!("{}/{pre}*", s.path),
                None => s.path.to_string(),
            };
            if found.is_empty() {
                if s.needed {
                    bail!("/{what} is missing; no backup without it");
                }
                missing.push(format!("/{what}"));
            }
            if s.k3s { k3s.extend(found) } else { live.extend(found) }
        }
        if !live.iter().any(|p| p == HOST_KEY) {
            bail!("/{HOST_KEY} is missing; no backup without it");
        }
        Ok((live, k3s, missing))
    }

    /// Copies paths (relative to root) into the staging directory with
    /// owners, modes and times.
    fn copy(&self, ctx: &Ctx, paths: &[String], staging: &Path) -> Result<()> {
        if paths.is_empty() {
            return Ok(());
        }
        let mut args = vec![
            "-c".to_string(),
            r#"set -euo pipefail; src=$1; dst=$2; shift 2
tar --create --file=- --directory="$src" --numeric-owner -- "$@" | tar --extract --file=- --directory="$dst" --numeric-owner --preserve-permissions"#
                .into(),
            "bash".into(),
            self.root.display().to_string(),
            staging.display().to_string(),
        ];
        args.extend(paths.iter().cloned());
        self.run.ok(ctx, &Cmd::new("bash", &args)).map_err(|e| e.wrap("copy for the backup"))
    }

    /// Starts k3s and waits until it is up, a few times. Says loudly when
    /// it does not come back.
    fn start_k3s(&self, out: &mut dyn Write) -> bool {
        // Not cancelled with the backup: k3s must come back.
        let bg = Ctx::new();
        for i in 0..self.start_tries.max(1) {
            let verb = if i == 0 { "start" } else { "restart" };
            let _ = self.run.ok(&bg, &Cmd::new("systemctl", &[verb, "--no-block", "k3s.service"]));
            let until = std::time::Instant::now() + self.start_wait;
            loop {
                if self.run.ok(&bg, &Cmd::new("systemctl", &["is-active", "--quiet", "k3s.service"])).is_ok() {
                    let _ = writeln!(out, "backup: k3s is running again");
                    return true;
                }
                if std::time::Instant::now() >= until {
                    break;
                }
                let _ = bg.sleep(self.poll);
            }
            let _ = writeln!(out, "backup: k3s is not up after {}s (try {} of {})", self.start_wait.as_secs(), i + 1, self.start_tries);
        }
        false
    }

    fn k3s_version(&self, ctx: &Ctx) -> String {
        let out =
            self.run.output(&ctx.with_timeout(Duration::from_secs(20)), &Cmd::new("k3s", &["--version"]).stdout_only()).unwrap_or_default();
        match out.lines().next().and_then(|l| l.split_whitespace().nth(2)) {
            Some(v) if v.starts_with('v') && v.len() < 64 => v.to_string(),
            _ => format!("{} (pinned; k3s --version did not answer)", iso::K3S_VERSION),
        }
    }
}

/// "512 KiB", "3 MiB".
fn human(n: u64) -> String {
    if n < 1 << 20 { format!("{} KiB", n.div_ceil(1 << 10)) } else { format!("{} MiB", n.div_ceil(1 << 20)) }
}

/// Bytes of regular files under p (p itself if it is one), without
/// following links.
fn tree_size(p: &Path) -> u64 {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => std::fs::read_dir(p).map(|rd| rd.flatten().map(|e| tree_size(&e.path())).sum()).unwrap_or(0),
        Ok(m) if m.is_file() => m.len(),
        _ => 0,
    }
}

/// Size and SHA-256 (hex) of a file, read in pieces.
fn file_sum(p: &Path) -> Result<(u64, String)> {
    let mut f = std::fs::File::open(p).map_err(|e| Error::from(e).wrap(format!("open {}", p.display())))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut n = 0u64;
    loop {
        let k = f.read(&mut buf).map_err(|e| Error::from(e).wrap(format!("read {}", p.display())))?;
        if k == 0 {
            break;
        }
        h.update(&buf[..k]);
        n += k as u64;
    }
    Ok((n, fsx::hex(&h.finalize())))
}

/// The MANIFEST: what is in the archive, for the restore and for a human.
#[allow(clippy::too_many_arguments)]
fn manifest(
    staging: &Path,
    live: &[String],
    k3s: &[String],
    missing: &[String],
    host: &str,
    k3s_state: &str,
    k3s_version: &str,
    now: Time,
) -> Result<String> {
    use std::os::unix::fs::PermissionsExt;
    let mut m = format!(
        "dryserver backup\nformat: {FORMAT}\ndryserver: {}\nk3s: {k3s_version}\nhost: {host}\ntime: {}\nk3s during the copy: {}\n",
        env!("CARGO_PKG_VERSION"),
        now.0.format("%Y-%m-%dT%H:%M:%SZ"),
        if k3s_state == "was not running" { "was not running" } else { "stopped" },
    );
    m += "restore: age -d -i secrets/backup_ed25519 FILE | tar -xpf - -C /\nmissing (left out, they were not there):\n";
    for x in missing {
        m += &format!("  {x}\n");
    }
    m += "files (mode, size, sha256, path):\n";
    fn walk(base: &Path, rel: &str, out: &mut Vec<String>) {
        let p = base.join(rel);
        match std::fs::symlink_metadata(&p) {
            Ok(md) if md.is_dir() => {
                let mut names: Vec<String> = std::fs::read_dir(&p)
                    .map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
                    .unwrap_or_default();
                names.sort();
                for n in names {
                    walk(base, &format!("{rel}/{n}"), out);
                }
            }
            Ok(_) => out.push(rel.to_string()),
            Err(_) => {}
        }
    }
    let mut files = Vec::new();
    for p in k3s.iter().chain(live) {
        walk(staging, p, &mut files);
    }
    for f in files {
        let p = staging.join(&f);
        let md = std::fs::symlink_metadata(&p).map_err(|e| Error::from(e).wrap(format!("stat {}", p.display())))?;
        let mode = md.permissions().mode() & 0o7777;
        if md.is_file() {
            let (size, sum) = file_sum(&p)?;
            m += &format!("  {mode:04o} {size} {sum} /{f}\n");
        } else {
            m += &format!("  {mode:04o} - - /{f}\n");
        }
    }
    Ok(m)
}

// ---- the desktop's side ----

/// The coordinator's backups, as the admin's login sees them.
pub trait Brain {
    /// One "name size" line per file in BACKUP_DIR.
    fn list(&self) -> Result<String>;
    /// Writes the file's bytes to w, at most limit of them; returns how
    /// many it wrote. More than limit is an error.
    fn fetch(&self, name: &str, limit: u64, w: &mut dyn Write) -> Result<u64>;
}

/// The most a listing may hold.
const MAX_LISTING: usize = 1 << 20;
const MAX_SIG: u64 = 16 << 10;

/// What backup-pull did.
#[derive(Debug, Default, PartialEq)]
pub struct Pulled {
    pub fetched: Vec<String>,
    pub removed: Vec<String>,
    pub problems: Vec<String>,
}

/// Parses the coordinator's listing: backups that have a signature, with
/// their sizes. Anything else in it is ignored.
pub fn parse_listing(text: &str) -> Vec<(String, u64)> {
    let mut files: Vec<(String, u64)> = Vec::new();
    let mut sigs: BTreeSet<String> = BTreeSet::new();
    for line in text.lines().take(10_000) {
        let mut f = line.split(' ');
        let (Some(name), Some(size), None) = (f.next(), f.next(), f.next()) else { continue };
        let Ok(size) = size.parse::<u64>() else { continue };
        if let Some(base) = name.strip_suffix(".sig") {
            if parse_name(base).is_some() {
                sigs.insert(base.to_string());
            }
        } else if parse_name(name).is_some() && size > 0 && !files.iter().any(|(n, _)| n == name) {
            files.push((name.to_string(), size));
        }
    }
    files.retain(|(n, _)| sigs.contains(n));
    files
}

/// Copies the coordinator's newest backups into dir, checks each one's
/// size and the coordinator's signature, and keeps the same plan there as
/// the coordinator does. A file already in dir is never replaced.
pub fn pull(brain: &dyn Brain, verifier: &dyn Verifier, dir: &Path, out: &mut dyn Write) -> Result<Pulled> {
    fsx::mkdir_all(dir, 0o700)?;
    let listing = brain.list()?;
    if listing.len() > MAX_LISTING {
        bail!("the coordinator's list of backups is too long");
    }
    let remote = parse_listing(&listing);
    let local: Vec<(DateTime<Utc>, String)> = std::fs::read_dir(dir)
        .map_err(|e| Error::from(e).wrap(format!("read {}", dir.display())))?
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            parse_name(&n).map(|t| (t, n))
        })
        .collect();
    let mut stamps: Vec<DateTime<Utc>> = local.iter().map(|(t, _)| *t).collect();
    stamps.extend(remote.iter().filter_map(|(n, _)| parse_name(n)));
    let kept = keep(&stamps, KEEP_DAILY, KEEP_WEEKLY);
    let mut res = Pulled::default();
    let mut wanted: Vec<&(String, u64)> = remote.iter().filter(|(n, _)| parse_name(n).is_some_and(|t| kept.contains(&t))).collect();
    wanted.sort_by(|a, b| b.0.cmp(&a.0));
    for (name, size) in wanted {
        let path = dir.join(name);
        if let Ok(m) = std::fs::metadata(&path) {
            if m.len() != *size {
                res.problems.push(format!("{name}: yours has {} bytes, the coordinator's {size}; yours is kept", m.len()));
            }
            continue;
        }
        match fetch_one(brain, verifier, dir, name, *size) {
            Ok(()) => {
                let _ = writeln!(out, "pulled {name} ({})", human(*size));
                res.fetched.push(name.clone());
            }
            Err(e) => res.problems.push(format!("{name}: {e}")),
        }
    }
    for (t, name) in &local {
        if !kept.contains(t) {
            for f in [name.clone(), format!("{name}.sig")] {
                let _ = std::fs::remove_file(dir.join(f));
            }
            res.removed.push(name.clone());
        }
    }
    Ok(res)
}

/// Fetches one backup and its signature into a part file, checks both,
/// and only then gives it its name.
fn fetch_one(brain: &dyn Brain, verifier: &dyn Verifier, dir: &Path, name: &str, size: u64) -> Result<()> {
    let mut sig = Vec::new();
    brain.fetch(&format!("{name}.sig"), MAX_SIG, &mut sig)?;
    let sig = String::from_utf8(sig).map_err(|_| errf!("the signature is not text"))?;
    let part = dir.join(format!(".{name}.part"));
    let _ = std::fs::remove_file(&part);
    let _clean = Cleanup(vec![part.clone()]);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode_600()
        .open(&part)
        .map_err(|e| Error::from(e).wrap(format!("open {}", part.display())))?;
    let mut hw = HashWriter { inner: &mut f, hash: Sha256::new(), n: 0 };
    let got = brain.fetch(name, size, &mut hw)?;
    let (n, sum) = (hw.n, fsx::hex(&hw.hash.finalize()));
    if got != size || n != size {
        bail!("got {n} bytes, the coordinator listed {size}");
    }
    f.sync_all().map_err(|e| Error::from(e).wrap(format!("sync {}", part.display())))?;
    verifier
        .verify(NAMESPACE, &receipt(name, size, &sum), &sig)
        .map_err(|e| e.wrap("not signed by the coordinator you pinned; not kept"))?;
    let sig_path = dir.join(format!("{name}.sig"));
    fsx::write_file(&sig_path, &sig, 0o600)?;
    std::fs::hard_link(&part, dir.join(name)).map_err(|e| Error::from(e).wrap(format!("keep {name}")))?;
    Ok(())
}

trait Mode600 {
    fn mode_600(&mut self) -> &mut Self;
}

impl Mode600 for std::fs::OpenOptions {
    fn mode_600(&mut self) -> &mut Self {
        std::os::unix::fs::OpenOptionsExt::mode(self, 0o600)
    }
}

/// Counts and hashes what passes through.
struct HashWriter<'a> {
    inner: &'a mut dyn Write,
    hash: Sha256,
    n: u64,
}

impl Write for HashWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let k = self.inner.write(buf)?;
        self.hash.update(&buf[..k]);
        self.n += k as u64;
        Ok(k)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// The coordinator over the admin's own SSH login, checked against the
/// host key this desktop pinned (secrets/coordinator_known_hosts, as for
/// approve and apps). One connection for the whole pull: the coordinator
/// lets one address open only a few SSH connections a minute.
pub struct SshBrain {
    pub host: String,
    pub port: String,
    pub user: String,
    pub known_hosts: PathBuf,
    ctl: Option<String>,
}

impl SshBrain {
    pub fn new(host: &str, port: &str, user: &str, known_hosts: PathBuf) -> SshBrain {
        let ctl = control_path(std::env::var_os("XDG_RUNTIME_DIR").as_deref().map(Path::new), std::process::id());
        let b = SshBrain { host: host.into(), port: port.into(), user: user.into(), known_hosts, ctl };
        if let Some(ctl) = &b.ctl {
            // Started with nothing attached, like approve's: a master that
            // holds our pipes would keep every call waiting.
            let _ = b
                .command(&["-o", ctl, "-M", "-N", "-f", "-o", "ControlPersist=60"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        b
    }

    fn command(&self, extra: &[&str]) -> Command {
        let port = if self.port.is_empty() { "22" } else { &self.port };
        let mut c = Command::new("ssh");
        c.args(["-p", port]);
        for o in [
            "BatchMode=yes",
            "ConnectTimeout=8",
            "ServerAliveInterval=15",
            "ServerAliveCountMax=3",
            "StrictHostKeyChecking=yes",
            "HostKeyAlgorithms=ssh-ed25519",
            "GlobalKnownHostsFile=/dev/null",
            "ForwardAgent=no",
            "ForwardX11=no",
            "ProxyJump=none",
            "LogLevel=ERROR",
        ] {
            c.args(["-o", o]);
        }
        c.arg("-o").arg(format!("UserKnownHostsFile={}", self.known_hosts.display()));
        c.args(extra);
        c.arg(format!("{}@{}", self.user, self.host));
        c
    }

    /// Runs a command on the coordinator, its output into w (at most
    /// limit bytes).
    fn call(&self, remote: &str, limit: u64, w: &mut dyn Write) -> Result<u64> {
        let mut extra = vec![];
        if let Some(ctl) = &self.ctl {
            extra = vec!["-o", "ControlMaster=no", "-o", ctl.as_str()];
        }
        let mut child = self
            .command(&extra)
            .arg(remote)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::from(e).wrap("ssh"))?;
        let mut err_pipe = child.stderr.take().ok_or_else(|| Error::new("ssh: no stderr"))?;
        let errs = std::thread::spawn(move || {
            let mut kept = Vec::new();
            let _ = (&mut err_pipe).take(8192).read_to_end(&mut kept);
            let _ = std::io::copy(&mut err_pipe, &mut std::io::sink());
            kept
        });
        let mut pipe = child.stdout.take().ok_or_else(|| Error::new("ssh: no stdout"))?;
        let mut buf = vec![0u8; 1 << 16];
        let mut n = 0u64;
        let copied: Result<()> = loop {
            match pipe.read(&mut buf) {
                Ok(0) => break Ok(()),
                Ok(k) if n + k as u64 > limit => break Err(errf!("the coordinator sent more than the {limit} bytes it listed")),
                Ok(k) => {
                    if let Err(e) = w.write_all(&buf[..k]) {
                        break Err(Error::from(e).wrap("write"));
                    }
                    n += k as u64;
                }
                Err(e) => break Err(Error::from(e).wrap("read from ssh")),
            }
        };
        if copied.is_err() {
            let _ = child.kill();
        }
        let st = child.wait().map_err(|e| Error::from(e).wrap("ssh"))?;
        let msg: String =
            String::from_utf8_lossy(&errs.join().unwrap_or_default()).chars().filter(|c| !c.is_control() || *c == '\n').take(300).collect();
        copied?;
        if !st.success() {
            if msg.contains("Host key verification failed") || msg.contains("HOST IDENTIFICATION HAS CHANGED") {
                bail!(
                    "the machine at {} does not have the SSH key this computer pinned for the coordinator; nothing was copied",
                    self.host
                );
            }
            bail!("ssh {}@{}: {}", self.user, self.host, msg.trim().lines().last().unwrap_or("failed"));
        }
        Ok(n)
    }
}

/// Where the shared connection's socket goes: the user's private runtime
/// directory. None without one, or when the path would be too long for a
/// socket (ssh adds %C, 40 characters, and a temporary suffix): then every
/// call connects by itself.
fn control_path(runtime_dir: Option<&Path>, pid: u32) -> Option<String> {
    let dir = runtime_dir.filter(|d| !d.as_os_str().is_empty())?;
    let path = dir.join(format!("dsp-{pid}-%C")).display().to_string();
    (path.len() - 2 + 40 + 20 < 108).then(|| format!("ControlPath={path}"))
}

impl Brain for SshBrain {
    fn list(&self) -> Result<String> {
        let mut out = Vec::new();
        self.call(&format!("find {BACKUP_DIR} -maxdepth 1 -type f -name 'brain-*' -printf '%f %s\\n'"), MAX_LISTING as u64, &mut out)?;
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    fn fetch(&self, name: &str, limit: u64, w: &mut dyn Write) -> Result<u64> {
        // Only our own names reach the remote shell.
        let base = name.strip_suffix(".sig").unwrap_or(name);
        if parse_name(base).is_none() {
            bail!("not a backup name: {name:?}");
        }
        self.call(&format!("cat -- {BACKUP_DIR}/{name}"), limit, w)
    }
}

impl Drop for SshBrain {
    fn drop(&mut self) {
        if let Some(ctl) = &self.ctl {
            let _ = self.command(&["-o", ctl, "-O", "exit"]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::ExecRunner;
    use crate::signed::{Signer, fake};
    use crate::testutil::{TempDir, get, put};
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    fn t(y: i32, mo: u32, d: u32, h: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, mo, d, h, 0, 0).unwrap()
    }

    #[test]
    fn names() {
        let at = Utc.with_ymd_and_hms(2026, 11, 21, 2, 30, 12).unwrap();
        assert_eq!(name_of(at), "brain-20261121T023012Z.tar.age");
        assert_eq!(parse_name(&name_of(at)), Some(at));
        for bad in [
            "brain-20261121T023012Z.tar.age.sig",
            "brain-20261121T023012.tar.age",
            "brain-2026112XT023012Z.tar.age",
            "brain-20261321T023012Z.tar.age",
            "brain-20260230T023012Z.tar.age",
            "brain-+0261121T023012Z.tar.age",
            "brain-20261121T023012Z.tar.age;rm",
            "../brain-20261121T023012Z.tar.age",
            "brain-20261121 023012Z.tar.age",
            "",
        ] {
            assert_eq!(parse_name(bad), None, "{bad}");
        }
    }

    #[test]
    fn retention_keeps_seven_days_and_four_weeks() {
        // One backup a night for 40 nights.
        let all: Vec<DateTime<Utc>> = (0..40).map(|i| t(2026, 10, 1, 2) + chrono::TimeDelta::days(i)).collect();
        let k = keep(&all, KEEP_DAILY, KEEP_WEEKLY);
        let newest = *all.last().unwrap();
        for i in 0..7 {
            assert!(k.contains(&(newest - chrono::TimeDelta::days(i))), "day {i}");
        }
        // 2026-11-09 is a Monday: the newest of each of the four newest
        // weeks are the 9th (this week), the 8th (also a daily one), the
        // 1st and October 25th.
        for d in [t(2026, 11, 8, 2), t(2026, 11, 1, 2), t(2026, 10, 25, 2)] {
            assert!(k.contains(&d), "{d}");
        }
        assert_eq!(k.len(), 7 + 2, "{k:?}");
        // Several a day: the newest of the day counts.
        let k = keep(&[t(2026, 11, 1, 1), t(2026, 11, 1, 5), t(2026, 11, 1, 3)], KEEP_DAILY, KEEP_WEEKLY);
        assert_eq!(k.into_iter().collect::<Vec<_>>(), vec![t(2026, 11, 1, 5)]);
        assert!(keep(&[], KEEP_DAILY, KEEP_WEEKLY).is_empty());
        // Duplicates count once.
        assert_eq!(keep(&[t(2026, 11, 1, 1), t(2026, 11, 1, 1)], 7, 4).len(), 1);
    }

    #[test]
    fn retention_survives_gaps_and_clock_jumps() {
        // Three nights, a month switched off, three nights: all six stay
        // (days that have a backup count, not calendar days).
        let mut all = vec![t(2026, 9, 1, 2), t(2026, 9, 2, 2), t(2026, 9, 3, 2)];
        all.extend([t(2026, 10, 10, 2), t(2026, 10, 11, 2), t(2026, 10, 12, 2)]);
        assert_eq!(keep(&all, KEEP_DAILY, KEEP_WEEKLY).len(), 6);
        // A clock that once jumped to 2031: that backup counts as the
        // newest, the good ones before it still fill the plan.
        let mut jumped: Vec<DateTime<Utc>> = (0..10).map(|i| t(2026, 11, 1, 2) + chrono::TimeDelta::days(i)).collect();
        jumped.push(t(2031, 1, 1, 2));
        let k = keep(&jumped, KEEP_DAILY, KEEP_WEEKLY);
        assert!(k.contains(&t(2031, 1, 1, 2)) && k.contains(&t(2026, 11, 10, 2)) && k.contains(&t(2026, 11, 5, 2)), "{k:?}");
        // Weeks across the new year (ISO weeks: 2026-12-31 and 2027-01-01
        // are in the same week 53 of 2026).
        let k = keep(&[t(2026, 12, 31, 2), t(2027, 1, 1, 2)], 0, KEEP_WEEKLY);
        assert_eq!(k.into_iter().collect::<Vec<_>>(), vec![t(2027, 1, 1, 2)]);
    }

    #[test]
    fn free_space_rule() {
        const G: u64 = 1 << 30;
        room(100 * G, 20 * G, 5 * G).unwrap();
        // 10% of 100 GiB must stay free.
        assert!(room(100 * G, 20 * G, 11 * G).unwrap_err().to_string().contains("not enough disk space"));
        // Small disk: at least 1 GiB.
        room(5 * G, 2 * G, G / 2).unwrap();
        assert!(room(5 * G, 2 * G, G + G / 5).is_err());
        assert!(room(100 * G, G, 2 * G).is_err(), "more than is free");
        assert!(room(0, 0, 1).is_err());
        // The real numbers come from statvfs.
        let (total, free) = fsx::space(std::env::temp_dir()).unwrap();
        assert!(total > 0 && free <= total, "{total} {free}");
        assert!(fsx::space("/no/such/dir").is_err());
    }

    /// systemctl, ssh-keygen, chgrp, setfacl and k3s are played; bash
    /// (the tar pipelines) and the age stand-in run for real.
    struct Fake {
        calls: Mutex<Vec<String>>,
        /// k3s's state, and what it was during each copy.
        k3s: Mutex<String>,
        during_copy: Mutex<Vec<(String, String)>>,
        starts: bool,
        stop_fails: bool,
        signed: Mutex<Vec<String>>,
        age: String,
        real: ExecRunner,
    }

    impl Fake {
        fn new(age: &Path, k3s: &str) -> Fake {
            Fake {
                calls: Mutex::default(),
                k3s: Mutex::new(k3s.into()),
                during_copy: Mutex::default(),
                starts: true,
                stop_fails: false,
                signed: Mutex::default(),
                age: age.display().to_string(),
                real: ExecRunner::silent(),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        fn pos(&self, prefix: &str) -> Option<usize> {
            self.calls().iter().position(|c| c.starts_with(prefix))
        }
    }

    impl Runner for Fake {
        fn run(&self, ctx: &Ctx, c: &Cmd) -> (String, Result<()>) {
            let a: Vec<&str> = c.args.iter().map(String::as_str).collect();
            let line = if c.name == "bash" { format!("bash {}", a[3..].join(" ")) } else { c.to_string() };
            self.calls.lock().unwrap().push(line.clone());
            let ok = |s: &str| (s.to_string(), Ok(()));
            let mut st = self.k3s.lock().unwrap();
            match (c.name.as_str(), a.as_slice()) {
                ("bash", _) => {
                    self.during_copy.lock().unwrap().push((line, st.clone()));
                    drop(st);
                    self.real.run(ctx, c)
                }
                (n, _) if n == self.age => self.real.run(ctx, c),
                ("systemctl", ["is-active", "k3s.service"]) => {
                    (format!("{st}\n"), if *st == "active" { Ok(()) } else { Err("exit status 3".into()) })
                }
                ("systemctl", ["is-active", "--quiet", "k3s.service"]) => {
                    if *st == "active" {
                        ok("")
                    } else {
                        (String::new(), Err("exit status 3".into()))
                    }
                }
                ("systemctl", ["stop", "k3s.service"]) => {
                    if self.stop_fails {
                        return (String::new(), Err("systemctl failed: timeout".into()));
                    }
                    *st = "inactive".into();
                    ok("")
                }
                ("systemctl", [_, "--no-block", "k3s.service"]) => {
                    if self.starts {
                        *st = "active".into();
                    } else {
                        *st = "activating".into();
                    }
                    ok("")
                }
                ("ssh-keygen", ["-Y", "sign", "-f", _, "-n", NAMESPACE]) => {
                    self.signed.lock().unwrap().push(c.stdin.clone());
                    ok(&fake::Key("coord").sign(NAMESPACE, &c.stdin).unwrap())
                }
                ("chgrp", ["wheel", _]) | ("setfacl", ["-m", "g:wheel:x", _]) => ok(""),
                ("k3s", ["--version"]) => ok("k3s version v1.37.2+k3s1 (abcdef12)\ngo version go1.25\n"),
                _ => (String::new(), Err(format!("unexpected command {line}").into())),
            }
        }
    }

    const AGE: &str = "#!/bin/sh\n[ \"$1\" = --version ] && { echo v1.2.1; exit 0; }\ncat\n";
    const AGE_FULL: &str = "#!/bin/sh\n[ \"$1\" = --version ] && exit 0\nhead -c 700 >/dev/null\nprintf partial\necho 'age: error: write: no space left on device' >&2\nexit 1\n";

    /// A coordinator's files under a test root.
    fn coordinator(dir: &TempDir, age: &str) -> PathBuf {
        let root = dir.join("root");
        for (p, c) in [
            ("etc/dryserver/role", "coordinator\n"),
            ("etc/dryserver/config.env", "USERNAME='admin'\n"),
            ("etc/dryserver/registry_ed25519", "private registry key\n"),
            ("usr/local/share/dryserver/backup_ed25519.pub", "ssh-ed25519 AAAAbackup dryserver-backup\n"),
            ("var/lib/rancher/k3s/server/db/state.db", "sqlite main file"),
            ("var/lib/rancher/k3s/server/db/state.db-wal", "sqlite wal"),
            ("var/lib/rancher/k3s/server/token", "K10token::server:secret\n"),
            ("var/lib/rancher/k3s/server/agent-token", "agenttoken\n"),
            ("var/lib/rancher/k3s/server/manifests/dryserver-traefik.yaml", "kind: HelmChartConfig\n"),
            ("var/lib/rancher/k3s/server/manifests/coredns.yaml", "k3s's own\n"),
            ("etc/rancher/k3s/agent-token", "agenttoken\n"),
            ("etc/rancher/k3s/config.yaml", "node-ip: 10.66.0.1\n"),
            ("var/lib/dryserver/registry.json", "{\"members\": []}\n"),
            ("etc/wireguard/wg0.key", "WGPRIVATE=\n"),
            ("etc/wireguard/wg0.conf", "[Interface]\n"),
            ("etc/ssh/ssh_host_ed25519_key", "host private\n"),
            ("etc/ssh/ssh_host_ed25519_key.pub", "ssh-ed25519 AAAAhost root@coord\n"),
            ("etc/ssh/sshd_config", "not backed up\n"),
        ] {
            put(&root, p, c);
        }
        std::fs::set_permissions(root.join("etc/ssh/ssh_host_ed25519_key"), std::fs::Permissions::from_mode(0o600)).unwrap();
        let a = dir.join("age");
        std::fs::write(&a, age).unwrap();
        std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o755)).unwrap();
        root
    }

    fn job<'a>(root: &Path, age: &Path, run: &'a Fake) -> Job<'a> {
        Job {
            root: root.to_path_buf(),
            run,
            hostname: "coord".into(),
            age: age.display().to_string(),
            poll: Duration::from_millis(1),
            start_wait: Duration::from_millis(20),
            start_tries: 2,
            space: |_| Ok((100 << 30, 50 << 30)),
        }
    }

    fn now() -> Time {
        Time(Utc.with_ymd_and_hms(2026, 11, 21, 2, 30, 12).unwrap())
    }

    fn tar_list(f: &Path) -> Vec<String> {
        let out = std::process::Command::new("tar").arg("-tf").arg(f).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).lines().map(str::to_string).collect()
    }

    fn tar_cat(f: &Path, member: &str) -> String {
        let out = std::process::Command::new("tar").arg("-xOf").arg(f).arg(member).output().unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn status(dir: &Path) -> Status {
        serde_json::from_str(&std::fs::read_to_string(dir.join(STATUS_FILE)).unwrap()).unwrap()
    }

    fn leftovers(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".brain-") || n == STAGING)
            .collect()
    }

    #[test]
    fn backup_of_a_running_coordinator() {
        let dir = TempDir::new();
        let root = coordinator(&dir, AGE);
        let f = Fake::new(&dir.join("age"), "active");
        let j = job(&root, &dir.join("age"), &f);
        let mut out = Vec::new();
        let d = j.run(&Ctx::new(), now(), &mut out).unwrap();
        let bdir = j.dir();
        let name = "brain-20261121T023012Z.tar.age";
        assert_eq!(d.file, name);
        assert_eq!(d.k3s, "restarted");
        let file = bdir.join(name);
        for p in [&file, &bdir.join(format!("{name}.sig"))] {
            assert_eq!(std::fs::metadata(p).unwrap().permissions().mode() & 0o777, 0o640, "{}", p.display());
        }
        assert_eq!(std::fs::metadata(&bdir).unwrap().permissions().mode() & 0o777, 0o750);
        // The datastore was copied with k3s stopped; k3s runs again.
        let copies = f.during_copy.lock().unwrap().clone();
        let db = copies.iter().find(|(l, _)| l.contains("var/lib/rancher/k3s/server/db ")).expect("datastore not copied");
        assert_eq!(db.1, "inactive", "{copies:?}");
        let live = copies.iter().find(|(l, _)| l.contains(" etc/dryserver ")).expect("dryserver's files not copied");
        assert_eq!(live.1, "active", "the rest is copied while k3s runs: {copies:?}");
        assert_eq!(*f.k3s.lock().unwrap(), "active");
        assert!(f.pos("systemctl stop k3s.service") < f.pos("systemctl start --no-block k3s.service"));
        assert!(!fsx::under(&root, K3S_MARK).exists(), "k3s runs: no mark left for the unit's ExecStopPost");
        assert!(f.calls().iter().any(|c| c.starts_with("setfacl -m g:wheel:x ") && c.ends_with("/var/lib/dryserver")), "{:?}", f.calls());

        // The layout: MANIFEST first, then only the chosen paths, never
        // their parent directories.
        let entries = tar_list(&file);
        assert_eq!(entries[0], "MANIFEST");
        for want in [
            "var/lib/rancher/k3s/server/db/state.db",
            "var/lib/rancher/k3s/server/db/state.db-wal",
            "var/lib/rancher/k3s/server/token",
            "var/lib/rancher/k3s/server/manifests/dryserver-traefik.yaml",
            "etc/rancher/k3s/agent-token",
            "var/lib/dryserver/registry.json",
            "etc/dryserver/role",
            "etc/dryserver/registry_ed25519",
            "etc/wireguard/wg0.key",
            "etc/ssh/ssh_host_ed25519_key",
            "etc/ssh/ssh_host_ed25519_key.pub",
        ] {
            assert!(entries.iter().any(|e| e == want), "{want} missing: {entries:?}");
        }
        for not in ["etc/", "var/", "etc/ssh/", "var/lib/dryserver/", "var/lib/rancher/k3s/server/"] {
            assert!(!entries.iter().any(|e| e == not), "{not} would change on restore: {entries:?}");
        }
        assert!(!entries.iter().any(|e| e.contains("coredns.yaml") || e.contains("sshd_config") || e.contains("backups")), "{entries:?}");
        let m = tar_cat(&file, "MANIFEST");
        for want in [
            "dryserver backup\nformat: 1\n",
            "k3s: v1.37.2+k3s1\n",
            "host: coord\n",
            "time: 2026-11-21T02:30:12Z\n",
            "k3s during the copy: stopped\n",
            "missing (left out, they were not there):\n  /var/lib/rancher/k3s/server/cred\n  /var/lib/rancher/k3s/server/tls\nfiles",
            &format!("16 {} /var/lib/rancher/k3s/server/db/state.db\n", fsx::hex(&Sha256::digest(b"sqlite main file"))),
            "0600 13 ",
        ] {
            assert!(m.contains(want), "MANIFEST missing {want:?}:\n{m}");
        }

        // Signed: name, size and checksum of exactly this file.
        let (size, sum) = file_sum(&file).unwrap();
        assert_eq!(*f.signed.lock().unwrap(), vec![receipt(name, size, &sum)]);
        let sig = std::fs::read_to_string(bdir.join(format!("{name}.sig"))).unwrap();
        fake::Key("coord").verify(NAMESPACE, &receipt(name, size, &sum), &sig).unwrap();

        let st = status(&bdir);
        assert_eq!((st.result.as_str(), st.file.as_str(), st.size, st.k3s.as_str()), ("ok", name, size, "restarted"));
        assert!(leftovers(&bdir).is_empty(), "{:?}", leftovers(&bdir));
        assert!(String::from_utf8_lossy(&out).contains("wrote"));
    }

    #[test]
    fn backup_when_k3s_is_not_running() {
        let dir = TempDir::new();
        let root = coordinator(&dir, AGE);
        let f = Fake::new(&dir.join("age"), "inactive");
        let j = job(&root, &dir.join("age"), &f);
        let d = j.run(&Ctx::new(), now(), &mut Vec::new()).unwrap();
        assert_eq!(d.k3s, "was not running");
        assert!(f.pos("systemctl stop").is_none() && f.pos("systemctl start").is_none(), "left as it was: {:?}", f.calls());
        assert!(!fsx::under(&root, K3S_MARK).exists(), "the unit must not start a k3s that was not running");
        assert!(tar_cat(&j.dir().join(&d.file), "MANIFEST").contains("k3s during the copy: was not running\n"));
    }

    #[test]
    fn k3s_that_does_not_come_back_is_loud() {
        let dir = TempDir::new();
        let root = coordinator(&dir, AGE);
        let mut f = Fake::new(&dir.join("age"), "active");
        f.starts = false;
        let j = job(&root, &dir.join("age"), &f);
        let mut out = Vec::new();
        let e = j.run(&Ctx::new(), now(), &mut out).unwrap_err().to_string();
        assert!(e.contains("k3s did not start again") && e.contains("tried 2 times"), "{e}");
        // Tried, then tried again.
        assert!(f.pos("systemctl start --no-block k3s.service").is_some() && f.pos("systemctl restart --no-block k3s.service").is_some());
        // The backup itself was still made, and the status says both.
        let st = status(&j.dir());
        assert_eq!(st.result, "failed");
        assert_eq!(st.k3s, "did not start again");
        assert!(!st.file.is_empty() && j.dir().join(&st.file).exists() && st.error.contains("did not start again"), "{st:?}");
        // The unit tries once more when the backup service ends.
        assert!(fsx::under(&root, K3S_MARK).exists());
        assert!(String::from_utf8_lossy(&out).contains("not up after"));
    }

    #[test]
    fn k3s_starts_again_when_the_copy_fails() {
        if fsx::is_root() {
            return; // root reads the file anyway
        }
        let dir = TempDir::new();
        let root = coordinator(&dir, AGE);
        let db = root.join("var/lib/rancher/k3s/server/db/state.db");
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o000)).unwrap();
        let f = Fake::new(&dir.join("age"), "active");
        let j = job(&root, &dir.join("age"), &f);
        let e = j.run(&Ctx::new(), now(), &mut Vec::new()).unwrap_err().to_string();
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(e.contains("copy for the backup"), "{e}");
        assert_eq!(*f.k3s.lock().unwrap(), "active", "k3s must run again: {:?}", f.calls());
        assert_eq!(status(&j.dir()).result, "failed");
        assert!(leftovers(&j.dir()).is_empty(), "the plain copy must go: {:?}", leftovers(&j.dir()));
    }

    #[test]
    fn k3s_that_does_not_stop_is_started_again() {
        let dir = TempDir::new();
        let root = coordinator(&dir, AGE);
        let mut f = Fake::new(&dir.join("age"), "active");
        f.stop_fails = true;
        let j = job(&root, &dir.join("age"), &f);
        let e = j.run(&Ctx::new(), now(), &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("stop k3s"), "{e}");
        assert!(f.pos("systemctl start --no-block k3s.service").is_some());
        assert!(!f.during_copy.lock().unwrap().iter().any(|(l, _)| l.contains("server/db")), "no datastore copy while k3s may write");
    }

    #[test]
    fn disk_full_while_writing() {
        let dir = TempDir::new();
        let root = coordinator(&dir, AGE_FULL);
        let f = Fake::new(&dir.join("age"), "active");
        let j = job(&root, &dir.join("age"), &f);
        let e = j.run(&Ctx::new(), now(), &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("pack and encrypt") && e.contains("no space left"), "{e}");
        assert!(!j.dir().join("brain-20261121T023012Z.tar.age").exists());
        assert!(leftovers(&j.dir()).is_empty(), "{:?}", leftovers(&j.dir()));
        assert_eq!(*f.k3s.lock().unwrap(), "active");
        let st = status(&j.dir());
        assert!(st.result == "failed" && st.file.is_empty() && st.error.contains("no space left"), "{st:?}");
    }

    #[test]
    fn refusals_before_anything_stops() {
        // Not enough room: nothing is stopped or written.
        let dir = TempDir::new();
        let root = coordinator(&dir, AGE);
        let f = Fake::new(&dir.join("age"), "active");
        let mut j = job(&root, &dir.join("age"), &f);
        j.space = |_| Ok((10 << 30, 1 << 30));
        let e = j.run(&Ctx::new(), now(), &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("not enough disk space"), "{e}");
        assert!(f.pos("systemctl stop").is_none());
        assert!(status(&j.dir()).error.contains("not enough disk space"));

        // Each case gets its own root: another test thread that forks a
        // command at the wrong moment keeps a copy of a just-dropped lock
        // open until its exec, so two runs on one root can collide.

        // No age.
        let dir = TempDir::new();
        let root = coordinator(&dir, AGE);
        let f = Fake::new(&dir.join("age"), "active");
        let mut j = job(&root, &dir.join("age"), &f);
        j.age = dir.join("no-such-age").display().to_string();
        let e = j.run(&Ctx::new(), now(), &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("the age tool is missing"), "{e}");
        assert!(f.pos("systemctl stop").is_none());

        // A needed file missing; optional ones missing are listed instead.
        let dir = TempDir::new();
        let root = coordinator(&dir, AGE);
        std::fs::remove_file(root.join("var/lib/rancher/k3s/server/token")).unwrap();
        let f = Fake::new(&dir.join("age"), "active");
        let j = job(&root, &dir.join("age"), &f);
        let e = j.run(&Ctx::new(), now(), &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("/var/lib/rancher/k3s/server/token is missing"), "{e}");
        assert!(f.pos("systemctl stop").is_none());

        // A bad backup key.
        let dir = TempDir::new();
        let root = coordinator(&dir, AGE);
        put(&root, "usr/local/share/dryserver/backup_ed25519.pub", "age1notansshkey\n");
        let f = Fake::new(&dir.join("age"), "active");
        let j = job(&root, &dir.join("age"), &f);
        assert!(j.run(&Ctx::new(), now(), &mut Vec::new()).unwrap_err().to_string().contains("not one ssh-ed25519 public key"));
        assert!(f.pos("systemctl stop").is_none());
    }

    #[test]
    fn only_the_coordinator_and_one_at_a_time() {
        let dir = TempDir::new();
        let root = coordinator(&dir, AGE);
        put(&root, "etc/dryserver/role", "node\n");
        let f = Fake::new(&dir.join("age"), "active");
        let j = job(&root, &dir.join("age"), &f);
        assert!(j.run(&Ctx::new(), now(), &mut Vec::new()).unwrap_err().to_string().contains("not it"));
        assert!(f.calls().is_empty() && !j.dir().exists(), "{:?}", f.calls());

        put(&root, "etc/dryserver/role", "coordinator\n");
        fsx::mkdir_all(j.dir(), 0o750).unwrap();
        let held = fsx::try_lock(j.dir().join(LOCK_FILE)).unwrap().expect("lock");
        let e = j.run(&Ctx::new(), now(), &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("another backup is running"), "{e}");
        assert!(f.pos("systemctl").is_none() && !j.dir().join(STATUS_FILE).exists(), "the running one writes the status");
        drop(held);
        j.run(&Ctx::new(), now(), &mut Vec::new()).unwrap();
    }

    #[test]
    fn a_planted_backup_directory_is_not_used() {
        let dir = TempDir::new();
        let root = coordinator(&dir, AGE);
        let elsewhere = dir.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, root.join("var/lib/dryserver/backups")).unwrap();
        let f = Fake::new(&dir.join("age"), "active");
        let j = job(&root, &dir.join("age"), &f);
        let e = j.run(&Ctx::new(), now(), &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("not a directory made by root"), "{e}");
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
    }

    #[test]
    fn retention_and_the_clock() {
        let dir = TempDir::new();
        let root = coordinator(&dir, AGE);
        let f = Fake::new(&dir.join("age"), "active");
        let j = job(&root, &dir.join("age"), &f);
        fsx::mkdir_all(j.dir(), 0o750).unwrap();
        // Twenty older nights, and one from a clock that ran ahead.
        let mut times = vec![now().0, t(2030, 1, 1, 2)];
        for i in 1..=20 {
            let at = now().0 - chrono::TimeDelta::days(i) - chrono::TimeDelta::hours(3);
            let n = name_of(at);
            put(&j.dir(), &n, "old");
            put(&j.dir(), &format!("{n}.sig"), "sig");
            times.push(at);
        }
        let ahead = name_of(t(2030, 1, 1, 2));
        put(&j.dir(), &ahead, "ahead");
        put(&j.dir(), &format!("{ahead}.sig"), "sig");
        put(&j.dir(), "notes.txt", "mine");
        let d = j.run(&Ctx::new(), now(), &mut Vec::new()).unwrap();
        assert!(d.warnings.iter().any(|w| w.contains("clock is behind")), "{:?}", d.warnings);
        assert!(j.dir().join(&d.file).exists(), "the backup just made is kept");
        assert!(j.dir().join(&ahead).exists());
        let left: BTreeSet<DateTime<Utc>> = j.backups().unwrap().into_iter().collect();
        let mut want = keep(&times, KEEP_DAILY, KEEP_WEEKLY);
        want.insert(now().0);
        assert_eq!(left, want, "only the plan, and always the one just made");
        assert!(!d.removed.is_empty());
        for n in &d.removed {
            assert!(!j.dir().join(n).exists() && !j.dir().join(format!("{n}.sig")).exists(), "{n}");
        }
        assert_eq!(get(&j.dir(), "notes.txt"), "mine", "files that are not backups stay");
        assert!(!status(&j.dir()).warnings.is_empty());

        // Same second again: never over an existing backup.
        let f = Fake::new(&dir.join("age"), "active");
        let j = job(&root, &dir.join("age"), &f);
        let e = j.run(&Ctx::new(), now(), &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("exists already"), "{e}");
        assert!(f.pos("systemctl stop").is_none());
    }

    // ---- backup-pull ----

    struct FakeBrain {
        files: BTreeMap<String, Vec<u8>>,
        /// Listed sizes that differ from what is sent.
        listed: BTreeMap<String, u64>,
        fetched: Mutex<Vec<String>>,
    }

    impl FakeBrain {
        /// Backups at these times, signed by the coordinator's key.
        fn new(times: &[DateTime<Utc>]) -> FakeBrain {
            let mut files = BTreeMap::new();
            for (i, t) in times.iter().enumerate() {
                let n = name_of(*t);
                let data = format!("encrypted backup {i}").into_bytes();
                let sum = fsx::hex(&Sha256::digest(&data));
                let sig = fake::Key("coord").sign(NAMESPACE, &receipt(&n, data.len() as u64, &sum)).unwrap();
                files.insert(format!("{n}.sig"), sig.into_bytes());
                files.insert(n, data);
            }
            FakeBrain { files, listed: BTreeMap::new(), fetched: Mutex::default() }
        }
    }

    impl Brain for FakeBrain {
        fn list(&self) -> Result<String> {
            Ok(self.files.iter().map(|(n, d)| format!("{n} {}\n", self.listed.get(n).copied().unwrap_or(d.len() as u64))).collect())
        }

        fn fetch(&self, name: &str, limit: u64, w: &mut dyn Write) -> Result<u64> {
            self.fetched.lock().unwrap().push(name.to_string());
            let d = self.files.get(name).ok_or_else(|| errf!("no such file"))?;
            if d.len() as u64 > limit {
                w.write_all(&d[..limit as usize]).unwrap();
                bail!("the coordinator sent more than the {limit} bytes it listed");
            }
            w.write_all(d).unwrap();
            Ok(d.len() as u64)
        }
    }

    fn nights(n: i64) -> Vec<DateTime<Utc>> {
        (0..n).map(|i| t(2026, 11, 20, 2) - chrono::TimeDelta::days(i)).collect()
    }

    #[test]
    fn pull_takes_the_newest_signed_backups() {
        let dir = TempDir::new();
        let local = dir.join("backups");
        let brain = FakeBrain::new(&nights(30));
        let r = pull(&brain, &fake::Key("coord"), &local, &mut Vec::new()).unwrap();
        let kept = keep(&nights(30), KEEP_DAILY, KEEP_WEEKLY);
        assert_eq!(r.fetched.len(), kept.len());
        assert!(r.problems.is_empty(), "{:?}", r.problems);
        for t in &kept {
            let n = name_of(*t);
            assert_eq!(std::fs::read(local.join(&n)).unwrap(), brain.files[&n]);
            assert_eq!(std::fs::metadata(local.join(&n)).unwrap().permissions().mode() & 0o777, 0o600);
            assert!(local.join(format!("{n}.sig")).exists());
        }
        assert_eq!(std::fs::metadata(&local).unwrap().permissions().mode() & 0o777, 0o700);
        // Again: nothing new to fetch.
        let r = pull(&brain, &fake::Key("coord"), &local, &mut Vec::new()).unwrap();
        assert!(r.fetched.is_empty() && r.removed.is_empty() && r.problems.is_empty(), "{r:?}");
        // A week later the brain has newer ones: the local copies follow
        // the same plan.
        let newer: Vec<DateTime<Utc>> = (0..7).map(|i| t(2026, 11, 27, 2) - chrono::TimeDelta::days(i)).collect();
        let r = pull(&FakeBrain::new(&newer), &fake::Key("coord"), &local, &mut Vec::new()).unwrap();
        assert_eq!(r.fetched.len(), 7);
        assert!(!r.removed.is_empty());
        for n in &r.removed {
            assert!(!local.join(n).exists() && !local.join(format!("{n}.sig")).exists());
        }
        assert!(no_parts(&local));
    }

    fn no_parts(d: &Path) -> bool {
        std::fs::read_dir(d).unwrap().flatten().all(|e| !e.file_name().to_string_lossy().ends_with(".part"))
    }

    #[test]
    fn pull_refuses_what_does_not_check_out() {
        let dir = TempDir::new();
        let local = dir.join("backups");
        let times = nights(3);
        let names: Vec<String> = times.iter().map(|t| name_of(*t)).collect();
        // [0]: signed by someone else. [1]: shorter than listed. [2]: longer.
        let mut brain = FakeBrain::new(&times);
        let forged = fake::Key("someone").sign(NAMESPACE, "whatever").unwrap();
        brain.files.insert(format!("{}.sig", names[0]), forged.into_bytes());
        let l1 = brain.files[&names[1]].len() as u64 + 10;
        brain.listed.insert(names[1].clone(), l1);
        let l2 = brain.files[&names[2]].len() as u64 - 3;
        brain.listed.insert(names[2].clone(), l2);
        let r = pull(&brain, &fake::Key("coord"), &local, &mut Vec::new()).unwrap();
        assert!(r.fetched.is_empty(), "{r:?}");
        assert_eq!(r.problems.len(), 3, "{:?}", r.problems);
        assert!(r.problems[0].contains("not signed by the coordinator"), "{:?}", r.problems);
        assert!(r.problems[1].contains("bytes, the coordinator listed"), "{:?}", r.problems);
        assert!(r.problems[2].contains("more than"), "{:?}", r.problems);
        for n in &names {
            assert!(!local.join(n).exists());
        }
        assert!(no_parts(&local));
    }

    #[test]
    fn pull_never_replaces_a_file() {
        let dir = TempDir::new();
        let local = dir.join("backups");
        let times = nights(2);
        let brain = FakeBrain::new(&times);
        let n = name_of(times[0]);
        put(&local, &n, "my own copy, different");
        let r = pull(&brain, &fake::Key("coord"), &local, &mut Vec::new()).unwrap();
        assert_eq!(get(&local, &n), "my own copy, different");
        assert!(r.problems.iter().any(|p| p.contains("yours is kept")), "{:?}", r.problems);
        assert_eq!(r.fetched, vec![name_of(times[1])]);
        assert!(!brain.fetched.lock().unwrap().contains(&n), "not even fetched");
    }

    /// The coordinator signs with ssh-keygen and its host key exactly as
    /// Job does; the desktop checks with the verifier backup-pull uses.
    #[test]
    fn host_key_signature_checks_out_on_the_desktop() {
        if !iso::in_path("ssh-keygen") {
            return;
        }
        let dir = TempDir::new();
        let key = dir.join("ssh_host_ed25519_key");
        let st = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "root@coord", "-f"])
            .arg(&key)
            .stdin(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(st.success());
        let doc = receipt("brain-20261121T023012Z.tar.age", 4096, &"ab".repeat(32));
        let k = key.display().to_string();
        let sig = ExecRunner::silent()
            .output(&Ctx::new(), &Cmd::new("ssh-keygen", &["-Y", "sign", "-f", &k, "-n", NAMESPACE]).stdin(doc.clone()).stdout_only())
            .unwrap();
        let v = crate::signed::SshVerifier { pubkey: dir.join("ssh_host_ed25519_key.pub"), tmp_dir: dir.path().to_path_buf() };
        v.verify(NAMESPACE, &doc, &sig).unwrap();
        // Another size, another name or another namespace: refused.
        assert!(v.verify(NAMESPACE, &receipt("brain-20261121T023012Z.tar.age", 4097, &"ab".repeat(32)), &sig).is_err());
        assert!(v.verify(NAMESPACE, &receipt("brain-20261120T023012Z.tar.age", 4096, &"ab".repeat(32)), &sig).is_err());
        assert!(v.verify("dryserver-members", &doc, &sig).is_err());
    }

    #[test]
    fn control_socket_fits() {
        assert_eq!(control_path(Some(Path::new("/run/user/1000")), 4242).as_deref(), Some("ControlPath=/run/user/1000/dsp-4242-%C"));
        assert_eq!(control_path(None, 1), None);
        assert_eq!(control_path(Some(Path::new("")), 1), None);
        // A socket path longer than the kernel takes: no shared connection
        // rather than no connection.
        assert_eq!(control_path(Some(&Path::new("/tmp").join("x".repeat(60))), 1), None);
    }

    #[test]
    fn listing_is_hostile() {
        let good = name_of(t(2026, 11, 20, 2));
        let text = format!(
            "{good} 100\n{good}.sig 400\n../../etc/passwd 100\nbrain-x.tar.age 5\nbrain-20261121T023012Z.tar.age abc\n\
             brain-20261122T023012Z.tar.age 10\n{good} 100 extra\n brain-20261123T023012Z.tar.age 10\nbrain-20261124T023012Z.tar.age 0\n\
             brain-20261124T023012Z.tar.age.sig 10\n{good} 200\n"
        );
        // Only the backup with a signature, once, at its first size.
        assert_eq!(parse_listing(&text), vec![(good, 100)]);
        assert!(parse_listing("").is_empty());
    }
}
