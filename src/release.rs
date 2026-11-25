//! The signed release: which dryserver binary, which k3s and which Arch
//! Linux snapshot the machines run. The admin's desktop signs it with
//! secrets/signing_ed25519 (`ssh-keygen -Y sign`, like the member list);
//! machines update only to a release that passes `check`. Whoever hands
//! it out (the brain, a mirror) cannot change it, and cannot make a
//! machine go back to an older one.
//!
//! What `check` refuses, in the order it looks:
//! - a document or signature larger than a few KiB, before anything else
//!   reads it;
//! - a bad signature, or one made for another use (another namespace):
//!   nothing unsigned is parsed;
//! - malformed JSON, unknown fields and malformed values;
//! - a serial that is not higher than the installed release's (an old
//!   release sent again), or the installed serial with other content;
//! - an older dryserver, k3s or Arch snapshot, unless the admin set
//!   `rollback` (the serial still has to go up). A machine that never took
//!   an update compares with what it runs: this binary's version and the
//!   k3s iso.rs pins;
//! - a k3s version that breaks Kubernetes' version skew rule.
//!
//! An expired release is not refused: it is reported as stale, so a feed
//! that stopped moving (a brain or mirror holding updates back) shows up
//! as a warning instead of silently keeping machines on old software.
//!
//! A fix has to reach every machine fast: `urgent` lets the rollout start
//! at once instead of in the nightly window (still one canary machine
//! first, still health checks). It is signed like everything else, so
//! only the admin can hurry an update along.
//!
//! Unknown fields are refused, not ignored. A field this binary does not
//! know may carry a rule the admin signed (say, "only these machines");
//! applying the rest of the release while dropping that rule would do
//! something the admin did not sign. A future format therefore ships
//! first as a release of the binary that understands it, signed in the
//! old format.

use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use chrono::{DateTime, NaiveDate};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::err::{Error, Result};
use crate::signed::{Envelope, Signer, Verifier};
use crate::{bail, errf, fsx, iso};

/// The SSH signature namespace of releases: a signed member list or admin
/// request never passes as a release, nor a release as one of them.
pub const NS_RELEASE: &str = "dryserver-release";
/// The largest release document and signature accepted. A release is a
/// few hundred bytes and an ed25519 signature about 300; anything much
/// larger is not worth handing to ssh-keygen or the JSON parser.
pub const MAX_DOC: usize = 8 << 10;
pub const MAX_SIG: usize = 4 << 10;
/// The highest serial. Past 2^53 many JSON tools (jq, JavaScript) round
/// numbers, and two serials that print the same would be a trap; it also
/// keeps a machine from being stuck at u64::MAX, where no serial is
/// higher.
pub const MAX_SERIAL: u64 = (1 << 53) - 1;
/// The largest dryserver binary a release may name. The static binary is
/// tens of MiB; this only stops a release from making machines read for
/// ever.
pub const MAX_BINARY: u64 = 256 << 20;
pub const DAY: i64 = 24 * 3600;
/// How long a release the desktop signs stays fresh, and the most it may
/// say. After that machines warn: the admin signs a new one (same content,
/// higher serial) to show the feed is alive.
pub const LIFETIME: i64 = 30 * DAY;
pub const MAX_LIFETIME: i64 = 366 * DAY;
/// Kubernetes' skew rule: a kubelet (a k3s agent) may be up to three minor
/// versions older than the API server (the brain), never newer.
pub const MAX_AGENT_SKEW: u32 = 3;
/// Dated snapshots of the Arch repositories.
pub const ARCH_ARCHIVE: &str = "https://archive.archlinux.org/repos/";
/// The longest release note, in bytes.
pub const MAX_NOTES: usize = 200;

/// What the admin signs. Every field is required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    /// Only ever goes up; machines refuse one not higher than theirs.
    pub serial: u64,
    /// Unix seconds.
    pub created: i64,
    pub expires: i64,
    pub dryserver: Binary,
    pub k3s: K3s,
    /// The Arch snapshot day, YYYY/MM/DD, as in ARCH_ARCHIVE + date.
    pub arch_date: String,
    /// Allows older versions than the installed ones (the serial still
    /// goes up): the way back from a bad release.
    pub rollback: bool,
    /// The rollout starts right away, not in the nightly window: for a
    /// security fix. The canary and health checks still come first.
    pub urgent: bool,
    /// What the release is for ("fixes X"), shown on the desktop and in
    /// the monitor. Printable ASCII, at most MAX_NOTES bytes, may be empty.
    pub notes: String,
    /// The swarm's settings the machines take with this release (their
    /// config.env), from the admin's config. Left out: they keep theirs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Settings>,
}

/// The first dryserver that knows Release::settings: an older one refuses
/// a release that has them (deny_unknown_fields), so they go only to a
/// coordinator that runs this one or newer.
pub const SETTINGS_SINCE: &str = "0.2.0";

/// Settings of the swarm a release carries. Only ones that change what
/// the machines' own files say (the firewall), so the update's checks and
/// its revert cover them; not the addresses, the mesh or the admin's
/// account, which every machine has to agree on at once.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// MESH_PORTS: open to the other members, like "8080/tcp 53/udp".
    pub mesh_ports: String,
    /// EGRESS_PORTS: what the machines may reach outside the mesh.
    pub egress_ports: String,
}

impl Settings {
    /// The settings of a config.
    pub fn of(c: &crate::config::Config) -> Settings {
        Settings { mesh_ports: c.mesh_ports.clone(), egress_ports: c.egress_ports.clone() }
    }

    /// Puts them into a machine's config; whether anything changed.
    pub fn apply(&self, c: &mut crate::config::Config) -> bool {
        let before = (c.mesh_ports.clone(), c.egress_ports.clone());
        c.mesh_ports = self.mesh_ports.clone();
        c.egress_ports = self.egress_ports.clone();
        before != (c.mesh_ports.clone(), c.egress_ports.clone())
    }

    pub fn validate(&self) -> Result<()> {
        for (name, v) in [("MESH_PORTS", &self.mesh_ports), ("EGRESS_PORTS", &self.egress_ports)] {
            if v.len() > 512 {
                bail!("{name} in the release is longer than 512 bytes");
            }
            crate::config::parse_ports(v).map_err(|e| errf!("{name} in the release: {e}"))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binary {
    /// MAJOR.MINOR.PATCH.
    pub version: String,
    /// Lowercase hex.
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct K3s {
    /// Like v1.37.2+k3s1.
    pub version: String,
    /// Of the amd64 binary, lowercase hex.
    pub sha256: String,
}

/// A dryserver version: MAJOR.MINOR.PATCH, digits only. Pre-releases
/// ("-rc1") are refused: their order is easy to get wrong, and a release
/// is what every machine runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(pub u32, pub u32, pub u32);

impl Version {
    pub fn parse(s: &str) -> Result<Version> {
        three(s).map(|(a, b, c)| Version(a, b, c)).ok_or_else(|| errf!("{} is not a version like 1.2.3", show(s)))
    }
}

/// A k3s version, vMAJOR.MINOR.PATCH+k3sBUILD. Release candidates are
/// refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct K3sVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub build: u32,
}

impl K3sVersion {
    pub fn parse(s: &str) -> Result<K3sVersion> {
        let parsed = s.strip_prefix('v').and_then(|r| r.split_once("+k3s")).and_then(|(v, build)| Some((three(v)?, number(build)?)));
        match parsed {
            Some(((major, minor, patch), build)) => Ok(K3sVersion { major, minor, patch, build }),
            None => Err(errf!("{} is not a k3s version like v1.37.2+k3s1", show(s))),
        }
    }
}

/// A decimal number of at most 6 digits, without leading zeros: one
/// spelling per number, so two versions that look different never compare
/// equal.
fn number(s: &str) -> Option<u32> {
    if s.is_empty() || s.len() > 6 || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
        return None;
    }
    s.parse().ok()
}

fn three(s: &str) -> Option<(u32, u32, u32)> {
    let mut it = s.split('.');
    let t = (number(it.next()?)?, number(it.next()?)?, number(it.next()?)?);
    if it.next().is_some() { None } else { Some(t) }
}

/// A value from the document for an error message: quoted, control
/// characters escaped, and cut short, since it comes from outside.
fn show(s: &str) -> String {
    let short: String = s.chars().take(40).collect();
    if short.len() < s.len() { format!("{short:?}...") } else { format!("{short:?}") }
}

pub fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// An Arch snapshot day: exactly YYYY/MM/DD, a real calendar date.
pub fn arch_day(s: &str) -> Result<NaiveDate> {
    let b = s.as_bytes();
    let shape = b.len() == 10 && b.iter().enumerate().all(|(i, c)| if i == 4 || i == 7 { *c == b'/' } else { c.is_ascii_digit() });
    let date = if shape {
        // Only ASCII digits and slashes here, so the slices are on
        // character boundaries.
        match (s[0..4].parse(), s[5..7].parse(), s[8..10].parse()) {
            (Ok(y), Ok(m), Ok(d)) => NaiveDate::from_ymd_opt(y, m, d),
            _ => None,
        }
    } else {
        None
    };
    date.ok_or_else(|| errf!("Arch snapshot date {} is not a date like 2026/11/20", show(s)))
}

/// Where the packages of an Arch snapshot day are.
pub fn arch_url(date: &str) -> String {
    format!("{ARCH_ARCHIVE}{date}/")
}

/// Unix seconds for people.
fn when(t: i64) -> String {
    DateTime::from_timestamp(t, 0).map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string()).unwrap_or_else(|| format!("{t} (unix time)"))
}

impl Release {
    /// Checks each field on its own. now is this machine's clock, in unix
    /// seconds; a release or snapshot more than a day ahead of it means
    /// one of the two clocks is wrong, and the message says so.
    pub fn validate(&self, now: i64) -> Result<()> {
        if self.serial == 0 {
            bail!("the release has no serial");
        }
        if self.serial > MAX_SERIAL {
            bail!("release serial {} is above the highest allowed ({MAX_SERIAL})", self.serial);
        }
        Version::parse(&self.dryserver.version).map_err(|e| e.wrap("dryserver version"))?;
        if !is_sha256(&self.dryserver.sha256) {
            bail!("the dryserver sha256 {} is not 64 lowercase hex digits", show(&self.dryserver.sha256));
        }
        if self.dryserver.size == 0 || self.dryserver.size > MAX_BINARY {
            bail!("the dryserver size {} is not between 1 and {MAX_BINARY} bytes", self.dryserver.size);
        }
        K3sVersion::parse(&self.k3s.version)?;
        if !is_sha256(&self.k3s.sha256) {
            bail!("the k3s sha256 {} is not 64 lowercase hex digits", show(&self.k3s.sha256));
        }
        let day = arch_day(&self.arch_date)?;
        check_notes(&self.notes)?;
        if let Some(s) = &self.settings {
            s.validate()?;
        }
        if self.created <= 0 {
            bail!("the release has no creation time");
        }
        if self.expires <= self.created {
            bail!("the release expires ({}) before it was made ({})", when(self.expires), when(self.created));
        }
        // Both positive and in order here, so this cannot overflow.
        if self.expires - self.created > MAX_LIFETIME {
            bail!("the release is valid for more than {} days", MAX_LIFETIME / DAY);
        }
        let ahead = now.saturating_add(DAY);
        if self.created > ahead {
            bail!(
                "the release was made {}, but this machine's clock says {}: check the clock here and on the desktop that signed it",
                when(self.created),
                when(now)
            );
        }
        let day_start = day.and_hms_opt(0, 0, 0).map(|t| t.and_utc().timestamp()).unwrap_or(i64::MAX);
        if day_start > ahead {
            bail!("Arch snapshot {} is in the future (this machine's clock says {}): check the clock", self.arch_date, when(now));
        }
        Ok(())
    }
}

/// Release notes reach the admin's terminal and the monitor: printable
/// ASCII only, so no escape sequence can redraw a screen and no invisible
/// or right-to-left character can make a note read other than it is.
pub fn check_notes(s: &str) -> Result<()> {
    if s.len() > MAX_NOTES {
        bail!("the release notes are {} bytes, more than {MAX_NOTES}", s.len());
    }
    if let Some(c) = s.chars().find(|c| !(' '..='~').contains(c)) {
        bail!("the release notes have a character that is not printable ASCII ({c:?})");
    }
    Ok(())
}

/// Where the release would run: k3s's version rules differ for the
/// server and its agents.
#[derive(Debug, Clone, Copy)]
pub enum Place<'a> {
    /// The brain, which runs the k3s server.
    Brain,
    /// A worker (k3s agent). brain_k3s is the version the brain's server
    /// runs now, as the brain reports it.
    Worker { brain_k3s: &'a str },
}

/// What to do with a release that passed `check`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    /// Newer than the installed release: install it. False when it is the
    /// installed release itself.
    pub install: bool,
    /// Past its expiry time. Still accepted (it is signed, and not older
    /// than what runs), but the feed stopped moving: warn.
    pub stale: bool,
}

/// Decides about a release from outside: Ok when it may be used, Err with
/// the reason when it is refused. installed is the release this machine
/// runs (None before its first update), now its clock in unix seconds.
/// Without a Start, a machine with no release installed takes no release
/// below what it runs, rollback or not.
pub fn check(v: &dyn Verifier, new: &Envelope, installed: Option<&Release>, place: Place, now: i64) -> Result<(Release, Verdict)> {
    check_from(v, new, installed, Start::default(), place, now)
}

/// check, for a machine whose Start is known (update::start).
pub fn check_from(
    v: &dyn Verifier,
    new: &Envelope,
    installed: Option<&Release>,
    start: Start,
    place: Place,
    now: i64,
) -> Result<(Release, Verdict)> {
    let r = open(v, new, now)?;
    let verdict = decide_from(&r, installed, RUNNING, start, place, now)?;
    Ok((r, verdict))
}

/// What a machine that has no release installed goes by, besides the
/// dryserver and k3s it runs: when it began to take releases (unix
/// seconds; 0 when not known). Its Arch day is not compared here: a
/// machine installed after the newest release runs newer packages than
/// that release names, which is no reason to refuse its dryserver and
/// k3s; the update keeps those packages instead (update.rs, arch_plan).
#[derive(Debug, Clone, Copy, Default)]
pub struct Start {
    pub since: i64,
}

/// The release inside an envelope, after its size, signature and fields
/// are checked.
pub fn open(v: &dyn Verifier, e: &Envelope, now: i64) -> Result<Release> {
    if e.doc.len() > MAX_DOC {
        bail!("the release is {} bytes, more than {MAX_DOC}", e.doc.len());
    }
    if e.sig.len() > MAX_SIG {
        bail!("the release signature is {} bytes, more than {MAX_SIG}", e.sig.len());
    }
    v.verify(NS_RELEASE, &e.doc, &e.sig).map_err(|e| e.wrap("release"))?;
    let r: Release = serde_json::from_str(&e.doc).map_err(|e| Error::from(e).wrap("signed release"))?;
    r.validate(now)?;
    Ok(r)
}

/// What a machine runs before its first update. Nothing wrote
/// installed.json yet (every fresh install), but the machine runs this
/// binary and the k3s its installer pinned, so a release is compared with
/// those instead, and with the Arch day the Start gives: otherwise a fresh
/// machine would take any signed release, an old one sent again included.
/// There is no serial to compare.
#[derive(Debug, Clone, Copy)]
struct Floor<'a> {
    dryserver: &'a str,
    k3s: &'a str,
}

const RUNNING: Floor<'static> = Floor { dryserver: env!("CARGO_PKG_VERSION"), k3s: iso::K3S_VERSION };

/// The rules between a valid release and the installed one (or, with
/// none installed, what runs).
pub fn decide(new: &Release, installed: Option<&Release>, place: Place, now: i64) -> Result<Verdict> {
    decide_from(new, installed, RUNNING, Start::default(), place, now)
}

/// A machine with no release installed may still have to go back: the
/// release it was installed with may be the bad one. So a rollback below
/// what it runs is taken, but only one signed after the machine began to
/// take releases (start.since). A rollback signed before that was not made
/// for this machine: a hacked coordinator would be sending an old one
/// again to move a fresh machine below what it was installed with. With
/// since unknown, none is taken.
fn decide_from(new: &Release, installed: Option<&Release>, floor: Floor, start: Start, place: Place, now: i64) -> Result<Verdict> {
    let stale = now >= new.expires;
    let base_k3s = match installed {
        Some(old) => {
            if new.serial == old.serial {
                if new == old {
                    return Ok(Verdict { install: false, stale });
                }
                bail!(
                    "release {} is not the installed release with the same serial: one serial was signed twice. \
                     Sign a new release, it gets a higher serial",
                    new.serial
                );
            }
            if new.serial < old.serial {
                bail!("release {} is older than the installed release {} (an old release sent again?)", new.serial, old.serial);
            }
            if !new.rollback {
                let than = |o: &str| format!("the installed {o}");
                no_older(new, &old.dryserver.version, &old.k3s.version, Some(&old.arch_date), &than)?;
            }
            old.k3s.version.as_str()
        }
        None => {
            let than = |o: &str| format!("the {o} this machine runs (it has no release installed yet)");
            if let Err(e) = no_older(new, floor.dryserver, floor.k3s, None, &than) {
                if !new.rollback {
                    return Err(e);
                }
                if start.since <= 0 || new.created <= start.since {
                    bail!(
                        "release {} is a rollback below what this machine was installed with, signed {}, before this machine took releases{}: \
                         an old release sent again? ({e})",
                        new.serial,
                        when(new.created),
                        if start.since > 0 { format!(" ({})", when(start.since)) } else { String::new() }
                    );
                }
            }
            floor.k3s
        }
    };
    skew(new, base_k3s, place)?;
    Ok(Verdict { install: true, stale })
}

/// Refuses a release with an older dryserver, k3s or Arch snapshot than
/// the ones given (no Arch snapshot: any). than says what they are, for
/// the message.
fn no_older(new: &Release, dryserver: &str, k3s: &str, arch_date: Option<&str>, than: &dyn Fn(&str) -> String) -> Result<()> {
    let back = |what: &str, n: &str, o: &str| {
        errf!("release {} has {what} {n}, older than {}; to go back, sign it with rollback", new.serial, than(o))
    };
    let base = |e: Error| e.wrap(than("version"));
    let n = &new.dryserver.version;
    if Version::parse(n)? < Version::parse(dryserver).map_err(base)? {
        return Err(back("dryserver", n, dryserver));
    }
    let n = &new.k3s.version;
    if K3sVersion::parse(n)? < K3sVersion::parse(k3s).map_err(base)? {
        return Err(back("k3s", n, k3s));
    }
    if let Some(o) = arch_date {
        let n = &new.arch_date;
        if arch_day(n)? < arch_day(o).map_err(base)? {
            return Err(back("Arch snapshot", n, o));
        }
    }
    Ok(())
}

/// Kubernetes' version skew rules for the k3s of a release. Minor
/// versions count, as in the upstream policy: patch releases of one minor
/// version mix freely. base_k3s is the k3s the brain runs before this
/// release: the installed release's, or the one its installer pinned.
fn skew(new: &Release, base_k3s: &str, place: Place) -> Result<()> {
    let k = K3sVersion::parse(&new.k3s.version)?;
    match place {
        Place::Worker { brain_k3s } => {
            let s = K3sVersion::parse(brain_k3s).map_err(|e| e.wrap("the brain's k3s"))?;
            if k.major != s.major {
                bail!("k3s {} has another major version than the brain's {}", new.k3s.version, show(brain_k3s));
            }
            if k.minor > s.minor {
                bail!("k3s {} would be newer than the brain's {}: the brain updates first", new.k3s.version, show(brain_k3s));
            }
            if s.minor - k.minor > MAX_AGENT_SKEW {
                bail!("k3s {} is more than {MAX_AGENT_SKEW} minor versions older than the brain's {}", new.k3s.version, show(brain_k3s));
            }
        }
        // The control plane moves one minor version at a time: skipping
        // one is unsupported upstream (stored objects are migrated one
        // step per version).
        Place::Brain => {
            let o = K3sVersion::parse(base_k3s).map_err(|e| e.wrap("the brain's k3s before this release"))?;
            if k.major != o.major || k.minor.abs_diff(o.minor) > 1 {
                bail!("the brain's k3s moves one minor version at a time, not from {base_k3s} to {}", new.k3s.version);
            }
        }
    }
    Ok(())
}

// ---- the desktop's side ----

/// The serial for the next release: one more than the last one signed,
/// and at least the time in seconds. A desktop that lost its record of the
/// last serial still counts up, as long as its clock is right.
pub fn next_serial(prev: Option<u64>, now: i64) -> Result<u64> {
    let after = match prev {
        Some(p) => p.checked_add(1).ok_or_else(|| errf!("serial {p} has no successor"))?,
        None => 1,
    };
    let s = after.max(u64::try_from(now).unwrap_or(0));
    if s > MAX_SERIAL {
        bail!("the next serial {s} is above the highest allowed ({MAX_SERIAL})");
    }
    Ok(s)
}

/// What the admin chooses for a new release; the rest comes from the
/// binary, iso.rs and the clock.
#[derive(Debug, Clone)]
pub struct Draft<'a> {
    pub binary: &'a Path,
    pub version: &'a str,
    pub arch_date: &'a str,
    pub rollback: bool,
    pub urgent: bool,
    pub notes: &'a str,
    pub settings: Option<Settings>,
}

impl Default for Draft<'_> {
    fn default() -> Self {
        Draft { binary: Path::new(""), version: "", arch_date: "", rollback: false, urgent: false, notes: "", settings: None }
    }
}

/// A release of the dryserver binary in d, with the k3s that iso.rs pins,
/// fresh for LIFETIME. prev is the last release this desktop signed, when
/// it knows it: the new one must pass a brain that runs prev, so the
/// desktop never signs what machines would refuse.
pub fn build(d: &Draft, prev: Option<&Release>, now: i64) -> Result<Release> {
    build_after(d, prev.map(|p| p.serial), prev, now)
}

/// Like build, with the serial after after (the last one signed) and the
/// versions checked against base: the release the machines run, older
/// than the last one signed when that one failed and went back.
pub fn build_after(d: &Draft, after: Option<u64>, base: Option<&Release>, now: i64) -> Result<Release> {
    let (sha256, size) = hash_file(d.binary, MAX_BINARY)?;
    let r = Release {
        serial: next_serial(after.max(base.map(|b| b.serial)), now)?,
        created: now,
        expires: now.saturating_add(LIFETIME),
        dryserver: Binary { version: d.version.into(), sha256, size },
        k3s: K3s { version: iso::K3S_VERSION.into(), sha256: iso::K3S_SHA256.into() },
        arch_date: d.arch_date.into(),
        rollback: d.rollback,
        urgent: d.urgent,
        notes: d.notes.into(),
        settings: d.settings.clone(),
    };
    r.validate(now)?;
    decide(&r, base, Place::Brain, now)?;
    Ok(r)
}

/// Signs a release.
pub fn seal(s: &dyn Signer, r: &Release) -> Result<Envelope> {
    let doc = serde_json::to_string(r)?;
    if doc.len() > MAX_DOC {
        bail!("the release is {} bytes, more than {MAX_DOC}", doc.len());
    }
    let sig = s.sign(NS_RELEASE, &doc)?;
    Ok(Envelope { doc, sig })
}

// ---- files ----

/// Checks that the file at path is exactly size bytes with this sha256.
/// It reads in small pieces, so memory use stays flat: a file of another
/// size is refused from its size alone, and one that grows while it is
/// read is refused as soon as it passes size.
///
/// The file is opened without following a symbolic link and without
/// blocking (a FIFO in its place cannot hang the check), and must be a
/// regular file. The check proves what the file held while it was read:
/// keep it in a directory only root can write, so nobody swaps it before
/// it is used.
pub fn verify_file(path: &Path, sha256: &str, size: u64) -> Result<()> {
    if !is_sha256(sha256) {
        bail!("{} is not a sha256 of 64 lowercase hex digits", show(sha256));
    }
    let f = open_regular(path)?;
    let len = f.metadata().map_err(|e| Error::from(e).wrap(format!("stat {}", path.display())))?.len();
    if len != size {
        bail!("{} is {len} bytes, the release says {size}", path.display());
    }
    let (got, n) = hash_reader(f, size).map_err(|e| e.wrap(path.display()))?;
    if n != size {
        bail!("{} changed size while it was read", path.display());
    }
    if got != sha256 {
        bail!("{} has sha256 {got}, the release says {sha256}", path.display());
    }
    Ok(())
}

/// The sha256 (lowercase hex) and size of a regular file of at most max
/// bytes, read in small pieces.
pub fn hash_file(path: &Path, max: u64) -> Result<(String, u64)> {
    let f = open_regular(path)?;
    let len = f.metadata().map_err(|e| Error::from(e).wrap(format!("stat {}", path.display())))?.len();
    if len > max {
        bail!("{} is {len} bytes, more than {max}", path.display());
    }
    hash_reader(f, max).map_err(|e| e.wrap(path.display()))
}

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

fn hash_reader(r: impl Read, max: u64) -> Result<(String, u64)> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 << 10];
    // One byte past max is enough to tell that there is more.
    let mut r = r.take(max.saturating_add(1));
    let mut n: u64 = 0;
    loop {
        let k = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(k) => k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::from(e).wrap("read")),
        };
        n += k as u64;
        if n > max {
            bail!("more than {max} bytes");
        }
        h.update(&buf[..k]);
    }
    Ok((fsx::hex(&h.finalize()), n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signed::{self, NS_ADMIN, NS_MEMBERS, fake};
    use crate::testutil::TempDir;
    use chrono::{TimeZone, Utc};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn t(y: i32, m: u32, d: u32) -> i64 {
        Utc.with_ymd_and_hms(y, m, d, 12, 0, 0).unwrap().timestamp()
    }

    fn now() -> i64 {
        t(2026, 11, 21)
    }

    /// The release that is installed.
    fn old() -> Release {
        Release {
            serial: 4,
            created: t(2026, 10, 1),
            expires: t(2026, 10, 31),
            dryserver: Binary { version: "0.1.0".into(), sha256: "c".repeat(64), size: 9 << 20 },
            k3s: K3s { version: "v1.36.5+k3s1".into(), sha256: "d".repeat(64) },
            arch_date: "2026/10/01".into(),
            rollback: false,
            urgent: false,
            notes: String::new(),
            settings: None,
        }
    }

    /// A newer one.
    fn rel() -> Release {
        Release {
            serial: 5,
            created: t(2026, 11, 20),
            expires: t(2026, 12, 20),
            dryserver: Binary { version: "0.2.0".into(), sha256: "a".repeat(64), size: 12 << 20 },
            k3s: K3s { version: "v1.37.2+k3s1".into(), sha256: "b".repeat(64) },
            arch_date: "2026/11/19".into(),
            rollback: false,
            urgent: false,
            notes: "fixes the join timeout".into(),
            settings: None,
        }
    }

    const BRAIN: Place = Place::Worker { brain_k3s: "v1.37.2+k3s1" };

    fn signed_doc(key: &fake::Key, doc: &str) -> Envelope {
        Envelope { doc: doc.into(), sig: key.sign(NS_RELEASE, doc).unwrap() }
    }

    fn refused(r: &Release, installed: Option<&Release>, place: Place, now: i64) -> String {
        let key = fake::Key("admin");
        let env = seal(&key, r).unwrap();
        check(&key, &env, installed, place, now).unwrap_err().to_string()
    }

    #[test]
    fn settings_travel_only_when_there_are_some() {
        let r = old();
        // A release without settings reads as before: an older machine
        // (deny_unknown_fields) takes it.
        assert!(!serde_json::to_string(&r).unwrap().contains("settings"));
        let s = Settings { mesh_ports: "8080/tcp".into(), egress_ports: "25/tcp".into() };
        let with = Release { settings: Some(s.clone()), ..r.clone() };
        let text = serde_json::to_string(&with).unwrap();
        assert_eq!(serde_json::from_str::<Release>(&text).unwrap(), with);
        with.validate(now()).unwrap();
        // Ports a config would refuse, or anything else in them, are refused.
        for bad in [
            Settings { mesh_ports: "99999/tcp".into(), ..s.clone() },
            Settings { egress_ports: "22/sctp".into(), ..s.clone() },
            Settings { egress_ports: "x".repeat(600), ..s.clone() },
        ] {
            assert!(Release { settings: Some(bad.clone()), ..r.clone() }.validate(now()).is_err(), "{bad:?}");
        }
        let unknown = text.replace("\"egress_ports\"", "\"wifi_pass\":\"x\",\"egress_ports\"");
        assert!(serde_json::from_str::<Release>(&unknown).is_err(), "nothing else rides along");
        // Into a machine's config.
        let mut c = crate::config::Config::default();
        assert!(s.apply(&mut c));
        assert!(!s.apply(&mut c), "the same again changes nothing");
        assert_eq!((c.mesh_ports.as_str(), c.egress_ports.as_str()), ("8080/tcp", "25/tcp"));
    }

    #[test]
    fn a_newer_release_is_accepted() {
        let key = fake::Key("admin");
        let env = seal(&key, &rel()).unwrap();
        let fresh = Verdict { install: true, stale: false };
        assert_eq!(check(&key, &env, Some(&old()), BRAIN, now()).unwrap(), (rel(), fresh));
        assert_eq!(check(&key, &env, Some(&old()), Place::Brain, now()).unwrap().1, fresh);
        // The first update of a machine: nothing installed yet.
        assert_eq!(check(&key, &env, None, BRAIN, now()).unwrap().1, fresh);
        assert_eq!(arch_url(&rel().arch_date), "https://archive.archlinux.org/repos/2026/11/19/");
    }

    #[test]
    fn signatures_are_checked() {
        let key = fake::Key("admin");
        let env = seal(&key, &rel()).unwrap();
        let mut changed = env.clone();
        changed.doc = changed.doc.replace("0.2.0", "0.2.1");
        assert!(check(&key, &changed, None, BRAIN, now()).unwrap_err().to_string().contains("bad signature"));
        // Signed with another key.
        let forged = seal(&fake::Key("intruder"), &rel()).unwrap();
        assert!(check(&key, &forged, None, BRAIN, now()).is_err());
        for sig in ["", "garbage"] {
            let e = Envelope { doc: env.doc.clone(), sig: sig.into() };
            assert!(check(&key, &e, None, BRAIN, now()).is_err(), "{sig:?}");
        }
        assert!(check(&key, &Envelope::default(), None, BRAIN, now()).is_err());
    }

    /// A signature made for one use never passes for another: not a member
    /// list or admin request as a release, not a release as a member list.
    #[test]
    fn namespaces_keep_documents_apart() {
        assert!(NS_RELEASE != NS_MEMBERS && NS_RELEASE != NS_ADMIN);
        let key = fake::Key("admin");
        let doc = serde_json::to_string(&rel()).unwrap();
        for ns in [NS_MEMBERS, NS_ADMIN] {
            let e = Envelope { doc: doc.clone(), sig: key.sign(ns, &doc).unwrap() };
            let err = check(&key, &e, None, BRAIN, now()).unwrap_err().to_string();
            assert!(err.contains("bad signature"), "{ns}: {err}");
        }
        // A release signature on a member list does not make it one.
        let list = signed::List { version: 9, members: vec![], rejected: vec![], keys: vec![], people: vec![] };
        let list_doc = serde_json::to_string(&list).unwrap();
        let as_release = Envelope { doc: list_doc.clone(), sig: key.sign(NS_RELEASE, &list_doc).unwrap() };
        let err = as_release.list(&key, |_| true).unwrap_err().to_string();
        assert!(err.contains("bad signature"), "{err}");
        // Nor does it pass as a release: the namespace is right but the
        // content is not a release.
        assert!(check(&key, &as_release, None, BRAIN, now()).is_err());
    }

    #[test]
    fn the_serial_only_goes_up() {
        let installed = rel();
        // Lower: an old release sent again, also one marked rollback.
        for rollback in [false, true] {
            let e = refused(&Release { rollback, ..old() }, Some(&installed), BRAIN, now());
            assert!(e.contains("older than the installed release 5"), "{e}");
        }
        // The same release again: nothing to do.
        let key = fake::Key("admin");
        let env = seal(&key, &installed).unwrap();
        assert_eq!(check(&key, &env, Some(&installed), BRAIN, now()).unwrap().1, Verdict { install: false, stale: false });
        // The same serial with other content.
        let twin = Release { arch_date: "2026/11/20".into(), ..rel() };
        let e = refused(&twin, Some(&installed), BRAIN, now());
        assert!(e.contains("signed twice"), "{e}");
        // No serial, or one too high to ever be followed.
        for (serial, want) in [(0, "no serial"), (MAX_SERIAL + 1, "highest allowed"), (u64::MAX, "highest allowed")] {
            let e = refused(&Release { serial, ..rel() }, None, BRAIN, now());
            assert!(e.contains(want), "{serial}: {e}");
        }
        let top = Release { serial: MAX_SERIAL, ..rel() };
        assert!(check(&key, &seal(&key, &top).unwrap(), Some(&installed), BRAIN, now()).unwrap().1.install);
    }

    #[test]
    fn next_serials() {
        assert_eq!(next_serial(None, 0).unwrap(), 1);
        assert_eq!(next_serial(Some(41), 0).unwrap(), 42);
        assert_eq!(next_serial(Some(41), 1_800_000_000).unwrap(), 1_800_000_000, "the clock moves it on");
        assert_eq!(next_serial(Some(1_900_000_000), 1_800_000_000).unwrap(), 1_900_000_001, "a clock behind still counts up");
        assert_eq!(next_serial(None, -5).unwrap(), 1, "a clock before 1970");
        assert!(next_serial(Some(MAX_SERIAL), 0).is_err());
        assert!(next_serial(Some(u64::MAX), 0).unwrap_err().to_string().contains("no successor"));
        assert!(next_serial(None, i64::MAX).is_err());
    }

    #[test]
    fn malformed_fields_are_refused() {
        type Change = fn(&mut Release);
        let cases: &[(Change, &str)] = &[
            (|r| r.dryserver.version = String::new(), "dryserver version"),
            (|r| r.dryserver.version = "0.2".into(), "dryserver version"),
            (|r| r.dryserver.version = "0.2.0.1".into(), "dryserver version"),
            (|r| r.dryserver.version = "v0.2.0".into(), "dryserver version"),
            (|r| r.dryserver.version = "0.02.0".into(), "dryserver version"),
            (|r| r.dryserver.version = "0.2.0-rc1".into(), "dryserver version"),
            (|r| r.dryserver.version = " 0.2.0".into(), "dryserver version"),
            (|r| r.dryserver.version = "0.2.99999999999".into(), "dryserver version"),
            (|r| r.dryserver.version = "0.2.\u{1b}[31m".into(), "\\u{1b}"),
            (|r| r.dryserver.version = "9".repeat(5000), "..."),
            (|r| r.dryserver.sha256 = "a".repeat(63), "dryserver sha256"),
            (|r| r.dryserver.sha256 = "a".repeat(65), "dryserver sha256"),
            (|r| r.dryserver.sha256 = "A".repeat(64), "dryserver sha256"),
            (|r| r.dryserver.sha256 = "g".repeat(64), "dryserver sha256"),
            (|r| r.dryserver.size = 0, "dryserver size"),
            (|r| r.dryserver.size = MAX_BINARY + 1, "dryserver size"),
            (|r| r.k3s.version = "1.37.2+k3s1".into(), "k3s version"),
            (|r| r.k3s.version = "v1.37.2".into(), "k3s version"),
            (|r| r.k3s.version = "v1.37.2-rc1+k3s1".into(), "k3s version"),
            (|r| r.k3s.version = "v1.37.2+k3s".into(), "k3s version"),
            (|r| r.k3s.version = "v1.37+k3s1".into(), "k3s version"),
            (|r| r.k3s.sha256 = String::new(), "k3s sha256"),
            (|r| r.arch_date = "2026-11-19".into(), "not a date"),
            (|r| r.arch_date = "2026/1/9".into(), "not a date"),
            (|r| r.arch_date = "2026/02/30".into(), "not a date"),
            (|r| r.arch_date = "2026/13/01".into(), "not a date"),
            (|r| r.arch_date = "+026/11/19".into(), "not a date"),
            (|r| r.arch_date = "2026/11/1é".into(), "not a date"),
            (|r| r.arch_date = String::new(), "not a date"),
            (|r| r.arch_date = "2026/11/23".into(), "in the future"),
            (|r| r.created = 0, "no creation time"),
            (|r| r.created = -7, "no creation time"),
            (|r| r.expires = r.created, "expires"),
            (|r| r.expires = i64::MIN, "expires"),
            (|r| r.expires = i64::MAX, "valid for more than"),
            (|r| r.created = t(2026, 11, 23), "check the clock"),
        ];
        for (change, want) in cases {
            let mut r = rel();
            change(&mut r);
            let e = refused(&r, None, BRAIN, now());
            assert!(e.contains(want), "{r:?}: want {want:?} in {e}");
        }
        // A day ahead is still a clock difference, not an error.
        let tomorrow = Release { created: now() + DAY, arch_date: "2026/11/22".into(), ..rel() };
        tomorrow.validate(now()).unwrap();
    }

    #[test]
    fn the_json_is_strict() {
        let key = fake::Key("admin");
        let good = serde_json::to_value(rel()).unwrap();
        let with = |f: &dyn Fn(&mut serde_json::Value)| {
            let mut v = good.clone();
            f(&mut v);
            v.to_string()
        };
        let docs = [
            (String::new(), "EOF"),
            ("{}".to_string(), "missing field"),
            ("null".to_string(), "invalid type"),
            (with(&|v| v["mirror"] = "evil".into()), "unknown field"),
            (with(&|v| v["dryserver"]["url"] = "http://evil".into()), "unknown field"),
            (with(&|v| v["serial"] = "5".into()), "invalid type"),
            (with(&|v| v["serial"] = (-1).into()), "invalid value"),
            (with(&|v| v["serial"] = 5.5.into()), "invalid type"),
            (with(&|v| v["rollback"] = serde_json::Value::Null), "invalid type"),
            (with(&|v| _ = v.as_object_mut().unwrap().remove("rollback")), "missing field"),
            (with(&|v| _ = v.as_object_mut().unwrap().remove("k3s")), "missing field"),
            (good.to_string().replacen("{", "{\"serial\":9,", 1), "duplicate field"),
            (good.to_string().replace("\"serial\":5", "\"serial\":18446744073709551616"), ""),
            (format!("{good} trailing"), "trailing"),
        ];
        for (doc, want) in docs {
            let e = check(&key, &signed_doc(&key, &doc), None, BRAIN, now()).unwrap_err().to_string();
            assert!(e.contains(want), "{doc}: want {want:?} in {e}");
        }
        // Spacing does not matter; the parsed content does.
        let pretty = serde_json::to_string_pretty(&rel()).unwrap();
        assert_eq!(check(&key, &signed_doc(&key, &pretty), None, BRAIN, now()).unwrap().0, rel());
    }

    /// Too large to bother: refused before the signature is checked.
    #[test]
    fn size_limits_come_first() {
        struct Counting(AtomicUsize);
        impl Verifier for Counting {
            fn verify(&self, _: &str, _: &str, _: &str) -> Result<()> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }
        let v = Counting(AtomicUsize::new(0));
        let mut big = serde_json::to_value(rel()).unwrap();
        big["arch_date"] = "x".repeat(MAX_DOC).into();
        let e = Envelope { doc: big.to_string(), sig: "BEGIN SSH SIGNATURE".into() };
        assert!(check(&v, &e, None, BRAIN, now()).unwrap_err().to_string().contains("more than 8192"));
        let e = Envelope { doc: serde_json::to_string(&rel()).unwrap(), sig: "s".repeat(MAX_SIG + 1) };
        assert!(check(&v, &e, None, BRAIN, now()).unwrap_err().to_string().contains("signature is"));
        assert_eq!(v.0.load(Ordering::SeqCst), 0, "the verifier ran on an oversized release");
        // Right at the limit is fine.
        let e = Envelope { doc: serde_json::to_string(&rel()).unwrap(), sig: "s".repeat(MAX_SIG) };
        check(&v, &e, None, BRAIN, now()).unwrap();
        // The desktop does not sign what machines would refuse.
        let r = Release { arch_date: "x".repeat(MAX_DOC), ..rel() };
        assert!(seal(&fake::Key("admin"), &r).is_err());
    }

    #[test]
    fn older_versions_need_rollback() {
        type Change = fn(&mut Release);
        let cases: &[(Change, &str)] = &[
            (|r| r.dryserver.version = "0.0.9".into(), "dryserver 0.0.9"),
            (|r| r.k3s.version = "v1.36.4+k3s1".into(), "k3s v1.36.4+k3s1"),
            (|r| r.arch_date = "2026/09/30".into(), "Arch snapshot 2026/09/30"),
        ];
        for (change, want) in cases {
            let mut r = rel();
            change(&mut r);
            let e = refused(&r, Some(&old()), BRAIN, now());
            assert!(e.contains(want) && e.contains("rollback"), "{e}");
            // With rollback it is the way back, with a higher serial.
            let key = fake::Key("admin");
            r.rollback = true;
            assert!(check(&key, &seal(&key, &r).unwrap(), Some(&old()), BRAIN, now()).unwrap().1.install);
        }
        // Versions compare as numbers, not as text.
        let mut r = rel();
        r.dryserver.version = "0.10.0".into();
        let installed = Release { dryserver: Binary { version: "0.9.0".into(), ..old().dryserver }, ..old() };
        assert!(check(&fake::Key("admin"), &seal(&fake::Key("admin"), &r).unwrap(), Some(&installed), BRAIN, now()).is_ok());
        let mut r = rel();
        r.k3s.version = "v1.36.5+k3s10".into();
        let installed = Release { k3s: K3s { version: "v1.36.5+k3s9".into(), ..old().k3s }, ..old() };
        assert!(check(&fake::Key("admin"), &seal(&fake::Key("admin"), &r).unwrap(), Some(&installed), BRAIN, now()).is_ok());
        // Equal versions are not older: only the snapshot moves on.
        let same = Release { serial: 6, arch_date: "2026/11/20".into(), ..rel() };
        assert!(check(&fake::Key("admin"), &seal(&fake::Key("admin"), &same).unwrap(), Some(&rel()), BRAIN, now()).is_ok());
    }

    #[test]
    fn kubernetes_version_skew() {
        let with_k3s = |v: &str| Release { k3s: K3s { version: v.into(), ..rel().k3s }, ..rel() };
        let ok = |r: &Release, installed: Option<&Release>, place: Place| {
            let key = fake::Key("admin");
            check(&key, &seal(&key, r).unwrap(), installed, place, now()).map(|(_, v)| v.install)
        };
        let worker = |b: &'static str| Place::Worker { brain_k3s: b };
        // A worker: the brain's minor version or up to three older.
        for brain in ["v1.37.0+k3s1", "v1.37.9+k3s2", "v1.38.1+k3s1", "v1.40.0+k3s1"] {
            assert!(ok(&with_k3s("v1.37.2+k3s1"), None, worker(brain)).unwrap(), "{brain}");
        }
        for (brain, want) in [
            ("v1.36.9+k3s1", "newer than the brain"),
            ("v1.41.0+k3s1", "more than 3 minor versions older"),
            ("v2.37.2+k3s1", "another major version"),
            ("", "the brain's k3s"),
            ("v1.37\n", "the brain's k3s"),
        ] {
            let e = ok(&with_k3s("v1.37.2+k3s1"), None, worker(brain)).unwrap_err().to_string();
            assert!(e.contains(want), "{brain:?}: {e}");
        }
        // The brain: one minor version at a time, up, or down with rollback.
        let installed = with_k3s("v1.36.5+k3s1");
        let installed = Release { serial: 4, ..installed };
        assert!(ok(&with_k3s("v1.37.0+k3s1"), Some(&installed), Place::Brain).unwrap());
        assert!(ok(&with_k3s("v1.36.9+k3s1"), Some(&installed), Place::Brain).unwrap());
        let e = ok(&with_k3s("v1.38.0+k3s1"), Some(&installed), Place::Brain).unwrap_err().to_string();
        assert!(e.contains("one minor version at a time"), "{e}");
        let back = Release { rollback: true, ..with_k3s("v1.35.0+k3s1") };
        assert!(ok(&back, Some(&installed), Place::Brain).unwrap());
        let far_back = Release { rollback: true, ..with_k3s("v1.34.0+k3s1") };
        assert!(ok(&far_back, Some(&installed), Place::Brain).is_err());
        // A new brain with nothing installed yet runs the k3s its installer
        // pinned: one minor version up from there is fine.
        assert_eq!(iso::K3S_VERSION, "v1.37.2+k3s1", "the cases below assume this pin");
        assert!(ok(&with_k3s("v1.38.0+k3s1"), None, Place::Brain).unwrap());
        let e = ok(&with_k3s("v1.39.0+k3s1"), None, Place::Brain).unwrap_err().to_string();
        assert!(e.contains("one minor version at a time, not from v1.37.2+k3s1"), "{e}");
    }

    #[test]
    fn nothing_installed_compares_with_what_runs() {
        let floor = Floor { dryserver: "0.3.0", k3s: "v1.37.2+k3s1" };
        let at = |dryserver: &str, k3s: &str, rollback: bool| Release {
            dryserver: Binary { version: dryserver.into(), ..rel().dryserver },
            k3s: K3s { version: k3s.into(), ..rel().k3s },
            rollback,
            ..rel()
        };
        // The machine took its first look at releases a day before rel()
        // was signed.
        let start = Start { since: rel().created - DAY };
        let fresh = |r: &Release, place: Place| decide_from(r, None, floor, start, place, now());
        for place in [Place::Brain, BRAIN] {
            // The same or newer versions: taken, whatever the serial.
            for r in [
                at("0.3.0", "v1.37.2+k3s1", false),
                at("0.3.1", "v1.37.3+k3s1", false),
                Release { serial: 1, ..at("1.0.0", "v1.37.2+k3s1", false) },
            ] {
                assert_eq!(fresh(&r, place).unwrap(), Verdict { install: true, stale: false }, "{r:?}");
            }
            // Older dryserver, k3s or Arch day than what runs: an old
            // release sent again, refused unless the admin signed it as a
            // rollback after this machine began to take releases.
            for (r, want) in [
                (at("0.2.9", "v1.37.2+k3s1", false), "dryserver 0.2.9, older than the 0.3.0 this machine runs"),
                (at("0.3.0", "v1.37.1+k3s1", false), "k3s v1.37.1+k3s1, older than the v1.37.2+k3s1 this machine runs"),
                (at("0.3.0", "v1.37.2+k3s0", false), "older than the v1.37.2+k3s1"),
            ] {
                let e = fresh(&r, place).unwrap_err().to_string();
                assert!(e.contains(want) && e.contains("sign it with rollback"), "{e}");
                let back = Release { rollback: true, ..r };
                assert!(fresh(&back, place).unwrap().install, "a rollback signed since");
                // The same rollback signed before the machine took releases,
                // or with that moment unknown: an old one sent again.
                for start in [Start { since: back.created }, Start { since: back.created + DAY }, Start { since: 0 }] {
                    let e = decide_from(&back, None, floor, start, place, now()).unwrap_err().to_string();
                    assert!(e.contains("below what this machine was installed with") && e.contains("sent again"), "{e}");
                }
            }
            // Any Arch day: the update keeps newer packages than the release names.
            let r = Release { arch_date: "2020/01/01".into(), ..at("0.3.0", "v1.37.2+k3s1", false) };
            assert!(fresh(&r, place).unwrap().install);
        }
        // The brain's k3s still moves one minor version at a time from
        // the pinned one, rollback or not.
        for (k3s, ok) in [("v1.38.0+k3s1", true), ("v1.39.0+k3s1", false), ("v1.36.0+k3s1", true), ("v1.35.9+k3s1", false)] {
            assert_eq!(fresh(&at("0.3.0", k3s, true), Place::Brain).is_ok(), ok, "{k3s}");
        }

        // The real floor is this binary and the pinned k3s; both must
        // parse, or a fresh machine would refuse every release.
        Version::parse(RUNNING.dryserver).unwrap();
        K3sVersion::parse(RUNNING.k3s).unwrap();
        assert_eq!((RUNNING.dryserver, RUNNING.k3s), (env!("CARGO_PKG_VERSION"), iso::K3S_VERSION));
        let key = fake::Key("admin");
        let ancient = Release { dryserver: Binary { version: "0.0.0".into(), ..rel().dryserver }, ..rel() };
        for place in [Place::Brain, BRAIN] {
            let e = refused(&ancient, None, place, now());
            assert!(e.contains("this machine runs (it has no release installed yet)"), "{e}");
            let back = Release { rollback: true, ..ancient.clone() };
            assert!(check(&key, &seal(&key, &back).unwrap(), None, place, now()).is_err(), "since unknown: no rollback below");
            let start = Start { since: back.created - 1 };
            assert!(check_from(&key, &seal(&key, &back).unwrap(), None, start, place, now()).unwrap().1.install);
        }
        // The release of this very binary is taken on a fresh machine.
        let this = Release { dryserver: Binary { version: env!("CARGO_PKG_VERSION").into(), ..rel().dryserver }, ..rel() };
        assert!(check(&key, &seal(&key, &this).unwrap(), None, Place::Brain, now()).unwrap().1.install);
    }

    #[test]
    fn expired_is_stale_not_refused() {
        let key = fake::Key("admin");
        let env = seal(&key, &rel()).unwrap();
        let expires = rel().expires;
        assert_eq!(check(&key, &env, Some(&old()), BRAIN, expires - 1).unwrap().1, Verdict { install: true, stale: false });
        assert_eq!(check(&key, &env, Some(&old()), BRAIN, expires).unwrap().1, Verdict { install: true, stale: true });
        // A feed that keeps handing out the installed release: nothing to
        // install, and the warning once it expires.
        assert_eq!(check(&key, &env, Some(&rel()), BRAIN, expires + DAY).unwrap().1, Verdict { install: false, stale: true });
        // A clock far in the future: stale, without overflowing.
        assert_eq!(check(&key, &env, Some(&old()), BRAIN, i64::MAX).unwrap().1, Verdict { install: true, stale: true });
        // A clock far in the past (a dead clock battery): refused, and
        // the message points at the clock.
        for clock in [0, -1, i64::MIN, t(2020, 1, 1)] {
            let e = check(&key, &env, Some(&old()), BRAIN, clock).unwrap_err().to_string();
            assert!(e.contains("check the clock"), "{clock}: {e}");
        }
    }

    #[test]
    fn notes_and_urgent() {
        let key = fake::Key("admin");
        // Notes: printable ASCII up to the limit, empty allowed.
        for notes in [String::new(), "fixes CVE-2026-1234 in the relay; urgent".into(), "~".repeat(MAX_NOTES)] {
            let r = Release { notes: notes.clone(), ..rel() };
            assert!(check(&key, &seal(&key, &r).unwrap(), Some(&old()), BRAIN, now()).is_ok(), "{notes:?}");
        }
        for (notes, want) in [
            ("x".repeat(MAX_NOTES + 1), "more than 200"),
            ("two\nlines".into(), "not printable"),
            ("tab\there".into(), "not printable"),
            ("\u{1b}[2Jclear".into(), "not printable"),
            ("nul\0".into(), "not printable"),
            ("del\u{7f}".into(), "not printable"),
            ("safe \u{202e}txt.exe".into(), "not printable"),
            ("zero\u{200b}width".into(), "not printable"),
            ("caf\u{e9}".into(), "not printable"),
        ] {
            let e = refused(&Release { notes, ..rel() }, None, BRAIN, now());
            assert!(e.contains(want), "{want}: {e}");
        }
        // Wrong types and missing fields.
        let good = serde_json::to_value(rel()).unwrap();
        for (field, value) in [
            ("urgent", serde_json::json!("yes")),
            ("urgent", serde_json::json!(1)),
            ("urgent", serde_json::Value::Null),
            ("notes", serde_json::json!(5)),
            ("notes", serde_json::json!(["a"])),
            ("notes", serde_json::Value::Null),
        ] {
            let mut v = good.clone();
            v[field] = value.clone();
            let e = check(&key, &signed_doc(&key, &v.to_string()), None, BRAIN, now()).unwrap_err().to_string();
            assert!(e.contains("invalid type"), "{field}={value}: {e}");
            v.as_object_mut().unwrap().remove(field);
            let e = check(&key, &signed_doc(&key, &v.to_string()), None, BRAIN, now()).unwrap_err().to_string();
            assert!(e.contains("missing field"), "{field}: {e}");
        }
        // Only the admin's signature makes a release urgent: flipping the
        // flag in a signed document, or signing it with another key, fails.
        let env = seal(&key, &rel()).unwrap();
        assert!(env.doc.contains("\"urgent\":false"));
        let hurried = Envelope { doc: env.doc.replace("\"urgent\":false", "\"urgent\":true"), sig: env.sig.clone() };
        assert!(check(&key, &hurried, Some(&old()), BRAIN, now()).unwrap_err().to_string().contains("bad signature"));
        let forged = seal(&fake::Key("intruder"), &Release { urgent: true, ..rel() }).unwrap();
        assert!(check(&key, &forged, Some(&old()), BRAIN, now()).unwrap_err().to_string().contains("bad signature"));
        let signed = seal(&key, &Release { urgent: true, ..rel() }).unwrap();
        assert!(check(&key, &signed, Some(&old()), BRAIN, now()).unwrap().0.urgent);
        // The same serial, now urgent, is a second document for one serial.
        let e = refused(&Release { urgent: true, ..rel() }, Some(&rel()), BRAIN, now());
        assert!(e.contains("signed twice"), "{e}");
    }

    fn sha(data: &[u8]) -> String {
        fsx::hex(&Sha256::digest(data))
    }

    #[test]
    fn verify_file_streams_with_a_cap() {
        let dir = TempDir::new();
        let data: Vec<u8> = (0..200_000u32).map(|i| (i * 7) as u8).collect();
        let path = dir.join("dryserver");
        std::fs::write(&path, &data).unwrap();
        let (sum, n) = (sha(&data), data.len() as u64);
        verify_file(&path, &sum, n).unwrap();
        assert_eq!(hash_file(&path, n).unwrap(), (sum.clone(), n));
        assert!(hash_file(&path, n - 1).unwrap_err().to_string().contains("more than"));

        let e = verify_file(&path, &sha(b"other"), n).unwrap_err().to_string();
        assert!(e.contains("the release says"), "{e}");
        for size in [n - 1, n + 1, 0] {
            assert!(verify_file(&path, &sum, size).unwrap_err().to_string().contains("bytes, the release says"), "{size}");
        }
        assert!(verify_file(&path, &sum.to_uppercase(), n).unwrap_err().to_string().contains("not a sha256"));

        // A huge file is refused from its size, without reading it.
        let huge = dir.join("huge");
        File::create(&huge).unwrap().set_len(8 << 30).unwrap();
        let start = std::time::Instant::now();
        assert!(verify_file(&huge, &sum, n).is_err());
        assert!(hash_file(&huge, MAX_BINARY).is_err());
        assert!(start.elapsed() < std::time::Duration::from_secs(2), "the huge file was read");

        // Not a regular file, not there, or a link to the right file.
        assert!(verify_file(dir.path(), &sum, n).unwrap_err().to_string().contains("not a regular file"));
        assert!(verify_file(&dir.join("missing"), &sum, n).unwrap_err().to_string().contains("no such file"));
        let link = dir.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(verify_file(&link, &sum, n).unwrap_err().to_string().contains("symbolic link"));
        // A FIFO nobody writes to: refused at once instead of hanging.
        let fifo = dir.join("fifo");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: c is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(verify_file(&fifo, &sum, n).unwrap_err().to_string().contains("not a regular file"));
    }

    /// A reader that keeps giving bytes: the cap stops it, memory stays flat.
    #[test]
    fn a_growing_file_is_cut_off() {
        let e = hash_reader(io::repeat(7), 1 << 20).unwrap_err().to_string();
        assert!(e.contains("more than 1048576"), "{e}");
        assert_eq!(hash_reader(&b"abc"[..], 3).unwrap(), (sha(b"abc"), 3));
        assert_eq!(hash_reader(&b""[..], u64::MAX).unwrap(), (sha(b""), 0));
    }

    #[test]
    fn the_desktop_builds_releases() {
        let dir = TempDir::new();
        let bin = dir.join("dryserver");
        std::fs::write(&bin, b"\x7fELF fake binary").unwrap();
        let d = Draft { binary: &bin, version: "0.2.0", arch_date: "2026/11/19", notes: "fixes X", ..Draft::default() };
        let r = build(&d, Some(&old()), now()).unwrap();
        assert_eq!(r.dryserver, Binary { version: "0.2.0".into(), sha256: sha(b"\x7fELF fake binary"), size: 16 });
        assert_eq!((r.rollback, r.urgent, r.notes.as_str()), (false, false, "fixes X"));
        assert_eq!(r.k3s, K3s { version: iso::K3S_VERSION.into(), sha256: iso::K3S_SHA256.into() });
        assert_eq!((r.serial, r.created, r.expires), (now() as u64, now(), now() + LIFETIME));
        verify_file(&bin, &r.dryserver.sha256, r.dryserver.size).unwrap();

        // What it builds, machines accept.
        let key = fake::Key("admin");
        let worker = Place::Worker { brain_k3s: iso::K3S_VERSION };
        assert!(check(&key, &seal(&key, &r).unwrap(), Some(&old()), worker, now()).unwrap().1.install);
        assert!(build(&Draft { urgent: true, ..d.clone() }, Some(&old()), now()).unwrap().urgent);
        // And it refuses what machines would refuse.
        assert!(build(&Draft { version: "0.2", ..d.clone() }, None, now()).is_err());
        assert!(build(&Draft { arch_date: "2026/11/31", ..d.clone() }, None, now()).is_err());
        assert!(build(&Draft { arch_date: "2099/01/01", ..d.clone() }, None, now()).unwrap_err().to_string().contains("future"));
        assert!(build(&Draft { notes: "line\nbreak", ..d.clone() }, None, now()).unwrap_err().to_string().contains("notes"));
        let newer = Release { dryserver: Binary { version: "9.0.0".into(), ..old().dryserver }, ..old() };
        assert!(build(&d, Some(&newer), now()).unwrap_err().to_string().contains("rollback"));
        assert!(build(&Draft { rollback: true, ..d.clone() }, Some(&newer), now()).unwrap().rollback);
        let missing = dir.join("missing");
        assert!(build(&Draft { binary: &missing, ..d.clone() }, None, now()).is_err());
        std::fs::write(&bin, b"").unwrap();
        assert!(build(&d, None, now()).unwrap_err().to_string().contains("dryserver size"));
    }

    /// The same with real OpenSSH keys.
    #[test]
    fn real_openssh() {
        if !iso::in_path("ssh-keygen") {
            return;
        }
        let dir = TempDir::new();
        let make = |name: &str| {
            let key = dir.join(name);
            let st = std::process::Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-f"]).arg(&key).status().unwrap();
            assert!(st.success());
            key
        };
        let (key, other) = (make("signing"), make("other"));
        let signer = signed::SshSigner { key };
        let v = signed::SshVerifier { pubkey: dir.join("signing.pub"), tmp_dir: dir.path().to_path_buf() };

        let env = seal(&signer, &rel()).unwrap();
        assert!(env.sig.len() < MAX_SIG);
        assert_eq!(check(&v, &env, Some(&old()), BRAIN, now()).unwrap().0, rel());
        let mut changed = env.clone();
        changed.doc = changed.doc.replace("\"serial\":5", "\"serial\":6");
        assert!(check(&v, &changed, Some(&old()), BRAIN, now()).unwrap_err().to_string().contains("bad signature"));
        let forged = seal(&signed::SshSigner { key: other }, &rel()).unwrap();
        assert!(check(&v, &forged, Some(&old()), BRAIN, now()).is_err(), "a release signed with another key passed");

        // A member list signed for real does not pass as a release, nor a
        // release as a member list.
        let list =
            signed::seal(&signer, &signed::List { version: 3, members: vec![], rejected: vec![], keys: vec![], people: vec![] }).unwrap();
        assert!(check(&v, &list, None, BRAIN, now()).unwrap_err().to_string().contains("bad signature"));
        let as_list = Envelope { doc: list.doc.clone(), sig: signer.sign(NS_RELEASE, &list.doc).unwrap() };
        assert!(as_list.list(&v, |_| true).unwrap_err().to_string().contains("bad signature"));
        let doc_as_list = Envelope { doc: env.doc.clone(), sig: signer.sign(NS_MEMBERS, &env.doc).unwrap() };
        assert!(check(&v, &doc_as_list, None, BRAIN, now()).unwrap_err().to_string().contains("bad signature"));
    }
}
