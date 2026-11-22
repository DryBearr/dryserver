//! The list of mesh members on the coordinator: pending join requests,
//! approved nodes and the scan report. The coordinator cannot let anyone
//! in: membership changes only through a list signed on the admin's
//! desktop (publish), after the admin compared the pairing code with the
//! one on the new machine's screen.

use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use base64::Engine;
use chrono::TimeDelta;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cidr::parse_ip4;
use crate::err::{Error, Result};
use crate::gotime::{Time, null_default};
use crate::k3stoken::Sealed;
use crate::report::{self, Report};
use crate::rollout::{self, Rollout, Served};
use crate::signed::{self, Envelope, List, Verifier};
use crate::{errf, fsx};

pub const MAX_PENDING: usize = 20;

pub fn request_ttl() -> TimeDelta {
    TimeDelta::hours(1)
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

fn is_zero64(n: &u64) -> bool {
    *n == 0
}

/// A member tells the coordinator which other members it has cut off, so
/// the admin sees it on the approval screen.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CutReport {
    pub name: String,
    /// Cut by the server itself (tries on closed ports), not on the
    /// admin's order.
    pub auto: bool,
}

/// At most this many cuts are kept per member.
pub const MAX_CUT_REPORTS: usize = 32;

/// An approved mesh node. The coordinator is member 1.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Member {
    /// Mesh host number: 10.66.0.<host>.
    pub host: u32,
    pub name: String,
    pub wg_key: String,
    pub ssh_host_key: String,
    pub lan_ip: String,
    /// Has a cable link to the switch.
    pub switch: bool,
    pub approved: Time,
    pub last_seen: Time,
    /// What this member has cut off, as it reported last.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cuts: Vec<CutReport>,
    /// What the member said about itself in its newest heartbeat, checked
    /// (Report::sanitized). For the admin only: other members never get
    /// it.
    #[serde(deserialize_with = "report::lenient_report", skip_serializing_if = "Option::is_none")]
    pub report: Option<Report>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pending,
    Approved,
    Rejected,
    /// Empty or unknown: a request with no decision recorded.
    #[default]
    #[serde(rename = "", other)]
    None,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Status::None => "",
            Status::Pending => "pending",
            Status::Approved => "approved",
            Status::Rejected => "rejected",
        })
    }
}

/// A machine asking to join.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Request {
    pub id: String,
    pub name: String,
    pub wg_key: String,
    pub ssh_host_key: String,
    pub lan_ip: String,
    pub switch: bool,
    /// As computed by the coordinator.
    pub code: String,
    pub created: Time,
    pub status: Status,
    #[serde(skip_serializing_if = "is_zero")]
    pub host: u32,
    /// Made by the installer with the join secret from the USB stick; see
    /// join_proof. The coordinator only carries it.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub proof: String,
}

/// A scan-report entry: something on the network that is not a member.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Device {
    pub ip: String,
    pub mac: String,
    pub vendor: String,
    pub ssh: bool,
    pub seen: Time,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    #[serde(deserialize_with = "null_default")]
    pub members: Vec<Member>,
    #[serde(deserialize_with = "null_default")]
    pub requests: Vec<Request>,
    #[serde(deserialize_with = "null_default")]
    pub unknown: Vec<Device>,
    pub scanned: Time,
    /// The member list the admin signed last, exactly as it arrived. The
    /// coordinator hands it to every node; it cannot make one itself.
    #[serde(skip_serializing_if = "Envelope::is_empty")]
    pub signed: Envelope,
    #[serde(skip_serializing_if = "is_zero64")]
    pub signed_version: u64,
    /// The installer's proof that this coordinator was installed from the
    /// admin's USB stick (see join_proof). The coordinator cannot make one.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub coordinator_proof: String,
    /// The token for joining the cluster as a k3s agent of each server the
    /// admin signed that is not in the cluster yet, one of its own, sealed
    /// by the coordinator's sync (k3stoken.rs, node.rs k3s_share): this
    /// file, which the registry account writes, never holds a token itself.
    /// Each member gets its own with the member list; nobody gets
    /// another's. Older versions kept the token here in plain text as
    /// "k3s_token", a field this version does not know: the first write
    /// after the update leaves it out. A form this version cannot read
    /// reads as none, and the coordinator's sync makes them again.
    #[serde(deserialize_with = "report::lenient", skip_serializing_if = "Vec::is_empty")]
    pub k3s_tokens: Vec<Sealed>,
    /// The rollout of the newest release (rollout.rs). The brain's sync
    /// moves it on; a form this version does not know reads as none
    /// instead of making the registry unreadable.
    #[serde(deserialize_with = "report::lenient", skip_serializing_if = "Rollout::is_none")]
    pub rollout: Rollout,
}

/// The 6-digit code both sides show. It covers the new node's keys and the
/// coordinator's SSH host key as the node saw it, so a fake coordinator or a
/// swapped request gives a different code.
pub fn pairing_code(wg_key: &str, node_host_key: &str, coord_host_key: &str) -> String {
    let input = ["dryserver-pairing-v1", wg_key.trim(), &key_body(node_host_key), &key_body(coord_host_key)].join("\n");
    let h = Sha256::digest(input.as_bytes());
    let n = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) % 1_000_000;
    format!("{:03} {:03}", n / 1000, n % 1000)
}

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    inner.update(msg);
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// Proof that a join request was made by a machine installed from the
/// admin's USB stick, for exactly this name and these keys.
///
/// The join secret is on the stick and on the admin's desktop. The
/// installer uses it once and stores only the proof; no installed machine
/// keeps the secret, the coordinator included. So a hacked coordinator
/// cannot show the admin a request with its own keys in place of the real
/// machine's: without the secret it has no proof for them, however many
/// keys it tries until the 6-digit pairing code matches.
pub fn join_proof(secret: &str, name: &str, wg_key: &str, ssh_host_key: &str) -> String {
    let msg = ["dryserver-join-v1", name, wg_key.trim(), &key_body(ssh_host_key)].join("\n");
    fsx::hex(&hmac_sha256(secret.trim().as_bytes(), msg.as_bytes()))
}

/// Whether r carries the proof for its own fields.
pub fn proof_ok(secret: &str, r: &Request) -> bool {
    proof_matches(secret, &r.name, &r.wg_key, &r.ssh_host_key, &r.proof)
}

/// Whether proof is the one for this name and these keys. Compared in
/// constant time.
pub fn proof_matches(secret: &str, name: &str, wg_key: &str, ssh_host_key: &str, proof: &str) -> bool {
    let want = join_proof(secret, name, wg_key, ssh_host_key);
    let (a, b) = (want.as_bytes(), proof.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The coordinator's own code: shown on its screen after its install and
/// on the admin's desktop before the coordinator is signed for the first
/// time. It covers the coordinator's WireGuard key and SSH host key, so
/// the admin knows the desktop talks to the machine that was installed and
/// not to something else at its address.
pub fn coordinator_code(wg_key: &str, host_key: &str) -> String {
    pairing_code(wg_key, host_key, host_key)
}

/// Drops the comment of an OpenSSH public key line.
fn key_body(k: &str) -> String {
    let f: Vec<&str> = k.split_whitespace().collect();
    if f.len() >= 2 { format!("{} {}", f[0], f[1]) } else { k.trim().to_string() }
}

/// A hostname label: lowercase letters, digits and -, 1 to 63 characters,
/// not starting or ending with -.
pub fn valid_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b[0] != b'-'
        && b[b.len() - 1] != b'-'
}

/// "ssh-ed25519 BASE64[ comment]" with one of the accepted key types and a
/// comment without whitespace.
fn valid_ssh_key(s: &str) -> bool {
    let Some((typ, rest)) = s.split_once(' ') else {
        return false;
    };
    if !matches!(typ, "ssh-ed25519" | "ecdsa-sha2-nistp256" | "ssh-rsa") {
        return false;
    }
    let (body, comment) = match rest.split_once(' ') {
        Some((b, c)) => (b, Some(c)),
        None => (rest, None),
    };
    let data = body.trim_end_matches('=');
    let pad = body.len() - data.len();
    let ws = |c: char| matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0c');
    !data.is_empty()
        && pad <= 3
        && data.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
        && comment.is_none_or(|c| !c.contains(ws))
}

/// A WireGuard public key: 32 bytes in standard base64.
pub fn valid_wg_key(s: &str) -> bool {
    matches!(base64::engine::general_purpose::STANDARD.decode(s), Ok(b) if b.len() == 32)
}

/// What is wrong with a member's fields, if anything. Nodes check every
/// member the coordinator sends with this before a name or key reaches
/// /etc/hosts, wg0.conf or the SSH trust files: a hacked coordinator could
/// otherwise write lines of its choosing into them.
pub fn member_problem(m: &Member) -> Option<&'static str> {
    if !valid_name(&m.name) {
        return Some("bad name");
    }
    if !valid_wg_key(&m.wg_key) {
        return Some("bad WireGuard key");
    }
    if !m.ssh_host_key.is_empty() && !valid_ssh_key(m.ssh_host_key.trim()) {
        return Some("bad SSH host key");
    }
    if !m.lan_ip.is_empty() && parse_ip4(&m.lan_ip).is_none() {
        return Some("bad LAN address");
    }
    None
}

/// Keeps the members that are safe to use and says why the others were
/// dropped. fits tells whether a host number has an address in the mesh.
/// A host number, name or key may appear once; the first one wins.
pub fn check_members(members: Vec<Member>, fits: impl Fn(u32) -> bool) -> (Vec<Member>, Vec<String>) {
    let mut ok: Vec<Member> = Vec::new();
    let mut problems = Vec::new();
    for m in members {
        // Debug form: control characters in a hostile name are escaped.
        let shown: String = m.name.chars().take(40).collect();
        let who = format!("member {shown:?} (host {})", m.host);
        let problem = if !fits(m.host) {
            Some("host number outside the mesh")
        } else if let Some(p) = member_problem(&m) {
            Some(p)
        } else if ok.iter().any(|o| o.host == m.host) {
            Some("host number used twice")
        } else if ok.iter().any(|o| o.name == m.name) {
            Some("name used twice")
        } else if ok.iter().any(|o| o.wg_key == m.wg_key) {
            Some("WireGuard key used twice")
        } else {
            None
        };
        match problem {
            Some(p) => problems.push(format!("{who}: {p}")),
            None => ok.push(m),
        }
    }
    (ok, problems)
}

/// Checks untrusted join-request fields strictly.
pub fn validate_request(r: &Request) -> Result<()> {
    if !valid_name(&r.name) {
        return Err("bad hostname".into());
    }
    if !valid_wg_key(&r.wg_key) {
        return Err("bad WireGuard key".into());
    }
    if !valid_ssh_key(r.ssh_host_key.trim()) {
        return Err("bad SSH host key".into());
    }
    if parse_ip4(&r.lan_ip).is_none() {
        return Err("bad LAN IP".into());
    }
    if !r.proof.is_empty() && !(r.proof.len() == 64 && r.proof.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))) {
        return Err("bad join proof".into());
    }
    Ok(())
}

impl State {
    /// Validates and stores a join request, returning its ID.
    pub fn add_request(&mut self, mut r: Request, coord_host_key: &str, now: Time) -> Result<String> {
        validate_request(&r)?;
        self.prune(now);
        for m in &self.members {
            if m.name == r.name {
                return Err(errf!("{} is already a member; remove it first to re-join", r.name));
            }
            if m.wg_key == r.wg_key {
                return Err("this WireGuard key already belongs to a member".into());
            }
        }
        let mut pending = 0;
        for q in &self.requests {
            if q.status != Status::Pending {
                continue;
            }
            // A retry from the same machine (same key) gets its existing request.
            if q.wg_key == r.wg_key && q.name == r.name && q.ssh_host_key == r.ssh_host_key {
                return Ok(q.id.clone());
            }
            if q.name == r.name {
                return Err(errf!("another machine is already asking to join as {}", r.name));
            }
            pending += 1;
        }
        if pending >= MAX_PENDING {
            return Err("too many pending requests; approve or reject some first".into());
        }
        r.id = fsx::hex(&fsx::random_bytes(8));
        r.code = pairing_code(&r.wg_key, &r.ssh_host_key, coord_host_key);
        r.created = now;
        r.status = Status::Pending;
        r.host = 0;
        let id = r.id.clone();
        self.requests.push(r);
        Ok(id)
    }

    /// Drops requests older than request_ttl.
    fn prune(&mut self, now: Time) {
        self.requests.retain(|r| now.since(r.created) <= request_ttl());
    }

    fn request(&mut self, id: &str) -> Result<&mut Request> {
        self.requests.iter_mut().find(|r| r.id == id).ok_or_else(|| Error::new("no such request (expired?)"))
    }

    /// What a waiting node may learn about its request. A pending request
    /// whose key already belongs to a member (the machine was approved
    /// through a duplicate request) reports that membership.
    pub fn request_status(&mut self, id: &str, now: Time) -> Result<Request> {
        self.prune(now);
        let members = self.members.clone();
        let r = self.request(id)?;
        if r.status == Status::Pending {
            for m in &members {
                if m.wg_key == r.wg_key {
                    r.status = Status::Approved;
                    r.host = m.host;
                }
            }
        }
        Ok(r.clone())
    }

    /// Makes a list signed by the admin the member list. The caller has
    /// checked the signature and the entries.
    ///
    /// - An older or equal version is refused: signed lists are not secret,
    ///   so anyone could send an old one back to undo a removal.
    /// - The coordinator's own name and keys must be the ones it has. A list
    ///   made for another coordinator would cut every node off from it.
    /// - Addresses and "last seen" of members that stay are kept; a new
    ///   member gets them from its join request.
    /// - Waiting requests are settled: signed in means approved; turned
    ///   down, or another machine under a signed member's name, rejected.
    pub fn publish(&mut self, list: &List, env: &Envelope, now: Time) -> Result<()> {
        if list.version <= self.signed_version {
            return Err(errf!("this list (version {}) is not newer than the current one (version {})", list.version, self.signed_version));
        }
        let Some(me) = self.members.iter().find(|m| m.host == 1) else {
            return Err("the coordinator has no entry for itself".into());
        };
        if !list.members.iter().any(|e| e.host == 1 && e.matches(me)) {
            return Err("the signed list does not carry this coordinator's own name and keys (was the coordinator reinstalled?)".into());
        }
        let mut members = Vec::new();
        for e in &list.members {
            let m = match self.members.iter().find(|m| m.host == e.host && m.wg_key == e.wg_key) {
                Some(old) => Member { name: e.name.clone(), ssh_host_key: e.ssh_host_key.clone(), ..old.clone() },
                None => {
                    let req = self.requests.iter().rev().find(|r| r.wg_key == e.wg_key);
                    Member {
                        host: e.host,
                        name: e.name.clone(),
                        wg_key: e.wg_key.clone(),
                        ssh_host_key: e.ssh_host_key.clone(),
                        lan_ip: req.map(|r| r.lan_ip.clone()).unwrap_or_default(),
                        switch: req.is_some_and(|r| r.switch),
                        approved: now,
                        last_seen: now,
                        cuts: Vec::new(),
                        report: None,
                    }
                }
            };
            members.push(m);
        }
        for q in &mut self.requests {
            if q.status != Status::Pending {
                continue;
            }
            if let Some(e) = list.members.iter().find(|e| e.wg_key == q.wg_key) {
                q.status = Status::Approved;
                q.host = e.host;
            } else if list.rejected.contains(&q.wg_key) || list.members.iter().any(|e| e.name == q.name) {
                q.status = Status::Rejected;
            }
        }
        self.members = members;
        self.signed = env.clone();
        self.signed_version = list.version;
        Ok(())
    }

    /// Records a member's current LAN IP, switch link, cuts and report.
    /// host identifies the member by its mesh address, which WireGuard ties
    /// to its key. Nothing in what it sends names another member, so a
    /// member that lies changes only its own entry.
    pub fn heartbeat(&mut self, host: u32, hb: Heartbeat, now: Time) -> Result<()> {
        let Heartbeat { lan_ip, switch: sw, cuts, report } = hb;
        let others: Vec<u32> = self.members.iter().map(|m| m.host).filter(|h| *h != host).collect();
        let Some(m) = self.members.iter_mut().find(|m| m.host == host) else {
            return Err("not a member".into());
        };
        if parse_ip4(&lan_ip).is_some() {
            m.lan_ip = lan_ip;
        }
        m.switch = sw;
        m.last_seen = now;
        // A member's word, shown to the admin: names only, and not many.
        m.cuts = cuts.into_iter().filter(|c| valid_name(&c.name)).take(MAX_CUT_REPORTS).collect();
        // The newest report replaces the last one, and none (an older
        // dryserver) leaves none rather than a stale one. Its peers can
        // only be other members.
        m.report = report.map(|r| r.sanitized(|h| others.contains(&h)));
        Ok(())
    }

    pub fn pending(&self) -> Vec<Request> {
        self.requests.iter().filter(|r| r.status == Status::Pending).cloned().collect()
    }
}

/// The registry file on the coordinator. Its directory is owned by the
/// registry user, which runs serve.
pub const DEFAULT_PATH: &str = "/var/lib/dryserver/registry.json";

/// The most the registry file may hold. Its largest honest content (254
/// members with their reports, the signed list, the waiting requests, the
/// scan report) is a few MiB; whoever writes more is not read.
pub const MAX_FILE: u64 = 16 << 20;
/// How long a caller waits for the registry file's lock. Each holder keeps
/// it for one read and one write. The registry account owns the lock file
/// and could hold it for ever: then the caller gives up and fails (root's
/// sync then applies the newest signed list it has seen to the mesh and
/// the cluster, raises an alarm on the console and leaves the rollout as
/// it is; the next sync tries again).
pub const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// The registry file, guarded by an exclusive lock.
#[derive(Debug, Clone)]
pub struct Store {
    pub path: PathBuf,
    pub lock_wait: std::time::Duration,
}

impl Store {
    pub fn new(path: impl Into<PathBuf>) -> Store {
        Store { path: path.into(), lock_wait: LOCK_WAIT }
    }

    pub fn default_path() -> Store {
        Store::new(DEFAULT_PATH)
    }

    /// The file's name inside its directory.
    fn name(&self) -> Result<String> {
        match self.path.file_name().and_then(|n| n.to_str()) {
            Some(n) if !n.is_empty() => Ok(n.to_string()),
            _ => Err(errf!("{} names no file", self.path.display())),
        }
    }

    /// Loads the state, calls f and saves the result atomically while
    /// holding the lock.
    ///
    /// Root (the coordinator's sync) runs this too, in a directory the
    /// registry account owns and may fill with anything, links included.
    /// So every file in it is reached through the directory opened once,
    /// and opened without following a link: a link planted under the lock
    /// or temp file name would otherwise have root write, or hand over,
    /// whatever file it points to.
    pub fn update<T>(&self, f: impl FnOnce(&mut State) -> Result<T>) -> Result<T> {
        let parent = fsx::dir(&self.path);
        fsx::mkdir_all(&parent, 0o700)?;
        let dir = Dir::open(&parent)?;
        let name = self.name()?;
        let lock_name = format!("{name}.lock");
        let lock = dir.open_regular(&lock_name, libc::O_RDONLY | libc::O_CREAT)?;
        dir.give(&lock);
        // Not waited for without end: see LOCK_WAIT.
        let end = std::time::Instant::now() + self.lock_wait;
        loop {
            // SAFETY: flock on a valid open descriptor; the lock is released
            // when `lock` is closed at the end of this function.
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EWOULDBLOCK) {
                return Err(Error::from(e).wrap(format!("lock {}", dir.path.join(&lock_name).display())));
            }
            if std::time::Instant::now() >= end {
                return Err(errf!(
                    "{} is held by another process for more than {}s: nothing read or written",
                    dir.path.join(&lock_name).display(),
                    self.lock_wait.as_secs_f32()
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let mut s = match dir.open_regular(&name, libc::O_RDONLY) {
            Ok(file) => {
                let len = file.metadata().map(|m| m.len()).unwrap_or(0);
                let mut b = Vec::new();
                if len <= MAX_FILE {
                    file.take(MAX_FILE + 1)
                        .read_to_end(&mut b)
                        .map_err(|e| Error::from(e).wrap(format!("read {}", self.path.display())))?;
                }
                if len > MAX_FILE || b.len() as u64 > MAX_FILE {
                    return Err(errf!("{} is larger than {MAX_FILE} bytes: not read", self.path.display()));
                }
                serde_json::from_slice(&b)?
            }
            Err(e) if e.is_not_found() => State::default(),
            Err(e) => return Err(e),
        };
        let out = f(&mut s)?;
        dir.replace(&name, &serde_json::to_vec_pretty(&s)?)?;
        drop(lock);
        Ok(out)
    }

    /// A snapshot of the state.
    pub fn read(&self) -> Result<State> {
        self.update(|s| Ok(s.clone()))
    }
}

/// A directory opened once, for files opened inside it by name. Its own
/// path is not looked up again, and a link in place of a file is refused.
/// Root reads the releases the registry account keeps through it too
/// (rollout::Served).
pub(crate) struct Dir {
    fd: OwnedFd,
    path: PathBuf,
    uid: u32,
    gid: u32,
}

/// The last OS error as an Error that names op and path.
fn os_err(op: &str, path: &Path) -> Error {
    Error::from(std::io::Error::last_os_error()).wrap(format!("{op} {}", path.display()))
}

fn c_string(s: &[u8], shown: &Path) -> Result<CString> {
    CString::new(s).map_err(|_| errf!("{} holds a NUL byte", shown.display()))
}

impl Dir {
    /// Opens path itself (not a link to it). Nobody but its owner may
    /// write in it when root uses it (a test or a desktop may run with a
    /// umask that lets its group write), never anyone at all; for anyone
    /// but root it has to be ours, as files written in it go to its owner.
    pub(crate) fn open(path: &Path) -> Result<Dir> {
        let c = c_string(path.as_os_str().as_bytes(), path)?;
        // SAFETY: c is a valid C string; the descriptor is owned below.
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        Dir::opened(fd, path)
    }

    /// The directory name inside this one, opened the same way: never
    /// through a link, whatever its path says.
    pub(crate) fn sub(&self, name: &str) -> Result<Dir> {
        let c = self.c_name(name)?;
        // SAFETY: valid directory descriptor and C string.
        let fd = unsafe {
            libc::openat(self.fd.as_raw_fd(), c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        };
        Dir::opened(fd, &self.path.join(name))
    }

    /// What open and sub opened, once it checks out.
    fn opened(fd: RawFd, path: &Path) -> Result<Dir> {
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            let link = std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink());
            if e.raw_os_error() == Some(libc::ELOOP) || link {
                return Err(errf!("{} is a symbolic link, not the directory itself", path.display()));
            }
            return Err(Error::from(e).wrap(format!("open {}", path.display())));
        }
        // SAFETY: fd was just opened and nothing else owns it.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let st = fstat(fd.as_raw_fd()).map_err(|e| Error::from(e).wrap(format!("stat {}", path.display())))?;
        let others = if fsx::is_root() { 0o022 } else { 0o002 };
        if st.st_mode & others != 0 {
            return Err(errf!("{} is writable by others", path.display()));
        }
        if !fsx::is_root() && st.st_uid != fsx::geteuid() {
            return Err(errf!("{} belongs to someone else", path.display()));
        }
        Ok(Dir { fd, path: path.to_path_buf(), uid: st.st_uid, gid: st.st_gid })
    }

    /// A plain name in this directory, as the C string openat takes.
    fn c_name(&self, name: &str) -> Result<CString> {
        if name.is_empty() || name.contains('/') || name == "." || name == ".." {
            return Err(errf!("{name:?} is not a file name"));
        }
        c_string(name.as_bytes(), &self.path.join(name))
    }

    /// Opens name in the directory: never a link, never something that is
    /// not a regular file, and without blocking on a FIFO. With O_CREAT it
    /// is made 0600 when missing.
    pub(crate) fn open_regular(&self, name: &str, flags: libc::c_int) -> Result<File> {
        let c = self.c_name(name)?;
        let path = self.path.join(name);
        let all = flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
        // SAFETY: valid directory descriptor and C string.
        let fd = unsafe { libc::openat(self.fd.as_raw_fd(), c.as_ptr(), all, 0o600 as libc::c_uint) };
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ELOOP) {
                return Err(errf!("{} is a symbolic link, not the file itself", path.display()));
            }
            return Err(Error::from(e).wrap(format!("open {}", path.display())));
        }
        // SAFETY: fd was just opened and nothing else owns it.
        let file = unsafe { File::from_raw_fd(fd) };
        let st = fstat(fd).map_err(|e| Error::from(e).wrap(format!("stat {}", path.display())))?;
        if st.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(errf!("{} is not a regular file", path.display()));
        }
        Ok(file)
    }

    /// Hands a file root opened here to the directory's owner, so the
    /// registry account can keep writing it. Only a file with no other name
    /// anywhere (a hard link could be someone else's file) that is root's
    /// or the owner's already.
    fn give(&self, file: &File) {
        if !fsx::is_root() {
            return;
        }
        let Ok(st) = fstat(file.as_raw_fd()) else { return };
        if st.st_nlink != 1 || (st.st_uid != 0 && st.st_uid != self.uid) {
            return;
        }
        // SAFETY: fchown on a valid open descriptor.
        let _ = unsafe { libc::fchown(file.as_raw_fd(), self.uid, self.gid) };
    }

    /// Replaces name with data whole or not at all: written to a temp file
    /// only this call made (O_EXCL, a name of its own), then renamed over
    /// name inside the same directory.
    fn replace(&self, name: &str, data: &[u8]) -> Result<()> {
        let tmp = format!("{name}.tmp.{}", fsx::hex(&fsx::random_bytes(8)));
        let (c_tmp, c_name) = (self.c_name(&tmp)?, self.c_name(name)?);
        let tmp_path = self.path.join(&tmp);
        let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: valid directory descriptor and C string.
        let fd = unsafe { libc::openat(self.fd.as_raw_fd(), c_tmp.as_ptr(), flags, 0o600 as libc::c_uint) };
        if fd < 0 {
            return Err(os_err("open", &tmp_path));
        }
        // SAFETY: fd was just opened and nothing else owns it.
        let mut file = unsafe { File::from_raw_fd(fd) };
        let done = file.write_all(data).map_err(|e| Error::from(e).wrap(format!("write {}", tmp_path.display()))).and_then(|()| {
            self.give(&file);
            // SAFETY: valid directory descriptor and C strings.
            if unsafe { libc::renameat(self.fd.as_raw_fd(), c_tmp.as_ptr(), self.fd.as_raw_fd(), c_name.as_ptr()) } != 0 {
                return Err(os_err("rename", &tmp_path));
            }
            Ok(())
        });
        if done.is_err() {
            // SAFETY: valid directory descriptor and C string.
            unsafe { libc::unlinkat(self.fd.as_raw_fd(), c_tmp.as_ptr(), 0) };
        }
        done
    }
}

fn fstat(fd: RawFd) -> std::io::Result<libc::stat> {
    // SAFETY: an all-zero stat is a valid value to be filled in.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fd is a valid descriptor and st a valid out pointer.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(st)
}

// ---- scan report ----

/// The most devices a scan report keeps. A device on the network may answer
/// for every address of a large network (ARP replies cost it nothing): the
/// report, and the registry file it is kept in, must not grow with it.
pub const MAX_UNKNOWN: usize = 256;
/// A MAC address and a vendor name as kept, at most.
const MAX_MAC: usize = 32;
const MAX_VENDOR: usize = 64;
/// The most devices read from one scan: every member's three addresses
/// and MAX_UNKNOWN others fit.
const MAX_FOUND: usize = 3 * 254 + MAX_UNKNOWN;

/// Reads `arp-scan --plain` output: "IP<tab>MAC<tab>vendor". MAX_FOUND
/// devices at most.
pub fn parse_arp_scan(out: &str) -> Vec<Device> {
    let mut devs: Vec<Device> = Vec::new();
    for line in out.lines() {
        if devs.len() >= MAX_FOUND {
            break;
        }
        let f: Vec<&str> = line.splitn(3, '\t').collect();
        if f.len() < 2 || f[0].parse::<std::net::IpAddr>().is_err() {
            continue;
        }
        let mut d = Device { ip: f[0].to_string(), mac: f[1].to_lowercase().chars().take(MAX_MAC).collect(), ..Device::default() };
        if f.len() == 3 {
            d.vendor = f[2].trim().chars().take(MAX_VENDOR).collect();
        }
        if !devs.iter().any(|x| x.ip == d.ip) {
            devs.push(d);
        }
    }
    devs
}

/// Keeps the devices whose address belongs to no member, MAX_UNKNOWN at
/// most. known holds every member address (LAN and switch).
pub fn unknown(found: &[Device], known: &[String], now: Time) -> Vec<Device> {
    found.iter().filter(|d| !known.contains(&d.ip)).take(MAX_UNKNOWN).map(|d| Device { seen: now, ..d.clone() }).collect()
}

/// The addresses a scan takes as members' (for unknown), and by address
/// why it does not take a member's claim to one.
///
/// A server's LAN address is its own word (its heartbeat): a hacked one
/// could name a rogue device's address as its own and so hide that device
/// from the report. A claim counts only when nothing speaks against it:
/// WireGuard on the coordinator sees that member's packets come from
/// another LAN address (seen, by WireGuard key; only the member's key opens
/// them), the address is the one WireGuard sees for another member, or
/// another member claims it too. fixed gives the addresses that follow from
/// a host number (switch, mesh) and the coordinator's own from its config;
/// the coordinator's claim is not asked.
pub fn member_addresses(
    members: &[Member],
    seen: &std::collections::BTreeMap<String, Ipv4Addr>,
    fixed: impl Fn(u32) -> Vec<String>,
) -> (Vec<String>, std::collections::BTreeMap<String, String>) {
    let mut known: Vec<String> = Vec::new();
    let mut notes = std::collections::BTreeMap::new();
    let verified: Vec<(String, &str)> = members.iter().filter_map(|m| Some((seen.get(&m.wg_key)?.to_string(), m.name.as_str()))).collect();
    for m in members {
        known.extend(fixed(m.host));
        let own = seen.get(&m.wg_key).map(|ip| ip.to_string());
        known.extend(own.clone());
        let claim = parse_ip4(&m.lan_ip).map(|ip| ip.to_string());
        let Some(claim) = claim.filter(|_| m.host != 1) else { continue };
        let others: Vec<&str> = members
            .iter()
            .filter(|o| o.host != m.host && o.host != 1 && parse_ip4(&o.lan_ip).is_some_and(|ip| ip.to_string() == claim))
            .map(|o| o.name.as_str())
            .collect();
        let held = verified.iter().find(|(ip, name)| *ip == claim && *name != m.name).map(|(_, name)| *name);
        let note = match (&own, held) {
            (Some(own), _) if *own != claim => Some(format!("{} says it is here, but talks from {own}", m.name)),
            // Where WireGuard sees it too.
            (Some(_), _) => None,
            (_, Some(other)) => Some(format!("{} says it is here, but this is {other}", m.name)),
            _ if !others.is_empty() => Some(format!("claimed by {} and {}", m.name, others.join(", "))),
            _ => None,
        };
        match note {
            Some(note) => {
                notes.entry(claim).or_insert(note);
            }
            None => known.push(claim),
        }
    }
    // An address some claim spoke against is a member's only where
    // WireGuard or the host number says so.
    known.retain(|ip| {
        !notes.contains_key(ip) || verified.iter().any(|(v, _)| v == ip) || members.iter().any(|m| fixed(m.host).contains(ip))
    });
    (known, notes)
}

// ---- the SSH forced command ----

const MAX_INPUT: u64 = 16 << 10;
/// A signed list of a full /24 mesh is about 100 KiB.
const MAX_SIGNED_INPUT: u64 = 1 << 20;

/// Describes the mesh subnet so serve can tell members by address.
pub trait Mesh {
    /// The member host number for a mesh IP, or 0.
    fn host_of(&self, ip: Ipv4Addr) -> u32;
    /// Whether a host number has an address in the mesh.
    fn fits(&self, host: u32) -> bool;
}

/// What the admin's desktop gets for its approval screen.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AdminState {
    #[serde(deserialize_with = "null_default")]
    pub members: Vec<Member>,
    /// Waiting requests only.
    #[serde(deserialize_with = "null_default")]
    pub requests: Vec<Request>,
    #[serde(deserialize_with = "null_default")]
    pub unknown: Vec<Device>,
    pub scanned: Time,
    pub signed: Envelope,
    /// See State::coordinator_proof.
    pub coordinator_proof: String,
    /// The newest release the admin uploaded, exactly as it arrived: the
    /// desktop checks its signature before it shows anything of it.
    #[serde(skip_serializing_if = "Envelope::is_empty")]
    pub release: Envelope,
    #[serde(deserialize_with = "report::lenient", skip_serializing_if = "Rollout::is_none")]
    pub rollout: Rollout,
    /// The coordinator's clock, unix seconds: the update window and the
    /// expiry of releases go by it.
    pub now: i64,
}

/// Answers "status". When approved it carries what the node needs to bring
/// up WireGuard towards the coordinator.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct StatusReply {
    pub status: Status,
    #[serde(skip_serializing_if = "is_zero")]
    pub host: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coordinator: Option<Member>,
    /// The signed member list that lets this machine in. The node trusts
    /// only this; host and coordinator above are addresses to reach it.
    #[serde(skip_serializing_if = "Envelope::is_empty")]
    pub signed: Envelope,
}

/// What a member sends with every sync ("peers"). One of an older version
/// sends no report; one of a newer version may send fields this one does
/// not know, which are left out.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Heartbeat {
    pub lan_ip: String,
    pub switch: bool,
    /// Members this one has cut off, for the admin's screen.
    #[serde(deserialize_with = "null_default")]
    pub cuts: Vec<CutReport>,
    #[serde(deserialize_with = "report::lenient_report", skip_serializing_if = "Option::is_none")]
    pub report: Option<Report>,
}

fn decode_first<T: serde::de::DeserializeOwned>(input: &mut dyn Read) -> Option<T> {
    decode_limited(input, MAX_INPUT)
}

fn decode_limited<T: serde::de::DeserializeOwned>(input: &mut dyn Read, max: u64) -> Option<T> {
    let mut buf = Vec::new();
    input.take(max).read_to_end(&mut buf).ok()?;
    serde_json::Deserializer::from_slice(&buf).into_iter::<T>().next()?.ok()
}

fn send<T: Serialize>(out: &mut dyn Write, v: &T) -> Result<()> {
    let mut b = serde_json::to_vec(v)?;
    b.push(b'\n');
    out.write_all(&b)?;
    Ok(())
}

/// A member as other machines get it. What a machine reports about itself
/// (versions, a reboot it waits for) is for the admin: it would tell a
/// member that was broken into where to go next.
fn without_report(m: &Member) -> Member {
    Member { report: None, ..m.clone() }
}

fn valid_id(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// How long one registry command may take at first. Most are a read or a
/// small write. An upload gets no more by its name, which anyone with the
/// USB stick's key can send: only once its header holds a release the
/// admin signed (extend_deadline).
pub fn deadline(cmdline: &str) -> std::time::Duration {
    let secs = match cmdline.split_whitespace().next() {
        Some("release-get") => 120,
        _ => 30,
    };
    std::time::Duration::from_secs(secs)
}

/// What an upload may take once its signature checked out: as long as the
/// network needs for the binaries.
pub const UPLOAD_DEADLINE: std::time::Duration = std::time::Duration::from_secs(600);

/// When this registry command must be done, unix seconds; 0: no limit.
/// main's watchdog ends the process after it.
static DEADLINE: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// Starts the limit for this command: d from now.
pub fn set_deadline(d: std::time::Duration) {
    DEADLINE.store(unix_now() + d.as_secs() as i64, std::sync::atomic::Ordering::SeqCst);
}

/// Gives the running command until d from now, if that is later.
pub fn extend_deadline(d: std::time::Duration) {
    DEADLINE.fetch_max(unix_now() + d.as_secs() as i64, std::sync::atomic::Ordering::SeqCst);
}

/// Whether the running command is past its limit.
pub fn past_deadline() -> bool {
    let d = DEADLINE.load(std::sync::atomic::Ordering::SeqCst);
    d != 0 && unix_now() > d
}

/// The mesh member calling from client, if it is one.
fn member_host(st: &Store, mesh: &dyn Mesh, client: &str) -> Result<u32> {
    let first = client.split_whitespace().next().unwrap_or("");
    let host = parse_ip4(first).map(|ip| mesh.host_of(ip)).unwrap_or(0);
    if host == 0 {
        return Err("only answered over the mesh".into());
    }
    if !st.read()?.members.iter().any(|m| m.host == host) {
        return Err("not a member".into());
    }
    Ok(host)
}

/// Refuses a resume or a skip made for another stop than the one the
/// rollout is at: root would not carry it out.
fn same_stop(r: &Rollout, ask: &signed::AdminRequest) -> Result<()> {
    if ask.serial == 0 {
        return Err(errf!(
            "the request names no rollout (none was there when you looked, or this dryserver is older than the coordinator's); \
             the rollout is at release {}: look again with ./dryserver release status",
            r.serial
        ));
    }
    if ask.serial != r.serial || ask.host != r.pause_host {
        return Err(errf!(
            "the rollout changed since you looked (it is at release {}{}): look again with ./dryserver release status",
            r.serial,
            if r.paused.is_empty() { ", not stopped".to_string() } else { format!(", stopped at host {}", r.pause_host) }
        ));
    }
    Ok(())
}

/// A release serial as a caller writes it.
fn parse_serial(s: &str) -> Result<u64> {
    if s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err("bad release serial".into());
    }
    s.parse().map_err(|_| Error::new("bad release serial"))
}

/// Handles one call from the SSH forced command. cmdline is
/// SSH_ORIGINAL_COMMAND, client is SSH_CLIENT ("ip port port").
///
///   request      stdin: Request JSON        -> {"id": ...}         (any source)
///   status ID                               -> StatusReply         (any source)
///   peers        stdin: Heartbeat           -> {"members": [...], "signed": ..., "k3s_sealed": Sealed, "release": Offer}  (mesh members only)
///   signed                                  -> {"signed": ...}     (any source; it proves itself)
///   admin        stdin: signed admin request -> AdminState          (holder of the signing key)
///   publish      stdin: signed member list   -> {"version": N}      (holder of the signing key)
///   release-put  stdin: PutHeader line, then the binaries -> {"serial": N}  (holder of the signing key)
///   release-get SERIAL release              -> Offered             (the server whose turn it is)
///   release-get SERIAL FILE OFFSET          -> up to CHUNK bytes   (the server whose turn it is)
///   release-resume stdin: signed admin request -> {"resume": N}    (holder of the signing key)
///   release-skip stdin: signed admin request -> {"skip": N}        (holder of the signing key)
///
/// The key that reaches this command is on every server and on the USB
/// stick, so it proves nothing. admin, publish, release-put,
/// release-resume and release-skip are allowed by the signature on their
/// input alone.
#[allow(clippy::too_many_arguments)]
pub fn serve(
    st: &Store,
    served: &Served,
    mesh: &dyn Mesh,
    verifier: &dyn Verifier,
    coord_host_key: &str,
    cmdline: &str,
    client: &str,
    input: &mut dyn Read,
    out: &mut dyn Write,
    now: Time,
) -> Result<()> {
    let f: Vec<&str> = cmdline.split_whitespace().collect();
    if f.is_empty() {
        return Err("no command".into());
    }
    match (f[0], f.len()) {
        ("request", 1) => {
            let r: Request = decode_first(input).ok_or_else(|| Error::new("bad request JSON"))?;
            let id = st.update(|s| s.add_request(r, coord_host_key, now))?;
            send(out, &serde_json::json!({ "id": id }))
        }
        ("status", 2) if valid_id(f[1]) => {
            let reply = st.update(|s| {
                let r = s.request_status(f[1], now)?;
                let mut reply = StatusReply { status: r.status, host: r.host, ..StatusReply::default() };
                if r.status == Status::Approved {
                    reply.coordinator = s.members.iter().find(|m| m.host == 1).map(without_report);
                    reply.signed = s.signed.clone();
                }
                Ok(reply)
            })?;
            send(out, &reply)
        }
        ("peers", 1) => {
            let first = client.split_whitespace().next().unwrap_or("");
            let host = parse_ip4(first).map(|ip| mesh.host_of(ip)).unwrap_or(0);
            if host == 0 {
                return Err("peers is only answered over the mesh".into());
            }
            // Longer than MAX_INPUT reads as cut off, and is refused.
            let hb: Heartbeat = decode_first(input).ok_or_else(|| Error::new("bad heartbeat JSON"))?;
            let (members, signed, sealed, offer) = st.update(|s| {
                s.heartbeat(host, hb, now)?;
                Ok((
                    s.members.iter().map(without_report).collect::<Vec<_>>(),
                    s.signed.clone(),
                    // Its own sealed token only: another member's is none
                    // of its business, encrypted or not.
                    s.k3s_tokens.iter().find(|t| t.host == host).cloned(),
                    rollout::offer(s, host),
                ))
            })?;
            send(out, &serde_json::json!({ "members": members, "signed": signed, "k3s_sealed": sealed, "release": offer }))
        }
        ("signed", 1) => {
            // Not secret, and nobody can change it without the admin's key.
            // A server that cut the coordinator off reads it here, over the
            // LAN, before it trusts the coordinator again.
            let signed = st.read()?.signed;
            send(out, &serde_json::json!({ "signed": signed }))
        }
        ("admin", 1) => {
            let req: Envelope = decode_first(input).ok_or_else(|| Error::new("bad admin request"))?;
            signed::open_admin(verifier, &req, "state", now.0.timestamp())?;
            let release = served.current().and_then(|n| served.envelope(n).ok()).unwrap_or_default();
            let reply = st.update(|s| {
                s.prune(now);
                Ok(AdminState {
                    members: s.members.clone(),
                    requests: s.pending(),
                    unknown: s.unknown.clone(),
                    scanned: s.scanned,
                    signed: s.signed.clone(),
                    coordinator_proof: s.coordinator_proof.clone(),
                    release,
                    rollout: s.rollout.clone(),
                    now: now.0.timestamp(),
                })
            })?;
            send(out, &reply)
        }
        ("publish", 1) => {
            let env: Envelope = decode_limited(input, MAX_SIGNED_INPUT).ok_or_else(|| Error::new("bad signed list"))?;
            let list = env.list(verifier, |h| mesh.fits(h))?;
            st.update(|s| s.publish(&list, &env, now))?;
            send(out, &serde_json::json!({ "version": list.version }))
        }
        ("release-put", 1) => {
            // After a newest that went back on the coordinator, a release
            // between what the machines run and it may follow it.
            let back = served.current().filter(|n| {
                st.read().is_ok_and(|s| {
                    let brain = s.members.iter().find(|m| m.host == 1).and_then(|m| m.report.as_ref());
                    rollout::went_back(&s.rollout, brain, *n).is_some()
                })
            });
            let serial = served.receive(verifier, input, now.0.timestamp(), back)?;
            send(out, &serde_json::json!({ "serial": serial }))
        }
        ("release-resume", 1) => {
            let req: Envelope = decode_first(input).ok_or_else(|| Error::new("bad admin request"))?;
            let ask = signed::open_request(verifier, &req, "release-resume", now.0.timestamp())?;
            let asked = st.update(|s| {
                if s.rollout.serial == 0 {
                    return Err("there is no rollout to resume".into());
                }
                same_stop(&s.rollout, &ask)?;
                // The ask itself, which root checks and carries out once;
                // the count is for the admin's screens.
                s.rollout.resume_ask = req.clone();
                s.rollout.resume_asked = s.rollout.resume_asked.wrapping_add(1);
                Ok(s.rollout.resume_asked)
            })?;
            send(out, &serde_json::json!({ "resume": asked }))
        }
        ("release-skip", 1) => {
            let req: Envelope = decode_first(input).ok_or_else(|| Error::new("bad admin request"))?;
            let ask = signed::open_request(verifier, &req, "release-skip", now.0.timestamp())?;
            let asked = st.update(|s| {
                let r = &s.rollout;
                if r.serial == 0 {
                    return Err("there is no rollout to resume".into());
                }
                if r.phase == rollout::Phase::Failed {
                    return Err("the coordinator's own update is never passed over: ./dryserver release resume tries it again".into());
                }
                if r.paused.is_empty() || r.pause_host == 0 {
                    return Err("the rollout is not stopped at a server: there is nothing to pass over".into());
                }
                same_stop(r, &ask)?;
                s.rollout.skip_ask = req.clone();
                s.rollout.skip_asked = s.rollout.skip_asked.wrapping_add(1);
                Ok(s.rollout.skip_asked)
            })?;
            send(out, &serde_json::json!({ "skip": asked }))
        }
        ("release-get", 3 | 4) => {
            // Only the server whose turn it is, and only the release of
            // the rollout: nobody else makes the coordinator send its
            // binaries over and over.
            let host = member_host(st, mesh, client).map_err(|e| e.wrap("release-get"))?;
            let serial = parse_serial(f[1])?;
            let s = st.read()?;
            if !rollout::offer(&s, host).turn || s.rollout.serial != serial {
                return Err(errf!("it is not this machine's turn to update to release {serial}"));
            }
            if f.len() == 3 && f[2] == "release" {
                return send(out, &served.offered(serial)?);
            }
            if f.len() != 4 {
                return Err("bad release-get".into());
            }
            let offset: u64 = parse_serial(f[3]).map_err(|_| Error::new("bad offset"))?;
            served.send(serial, f[2], offset, out)
        }
        _ => Err(errf!("unknown command {:?}", f[0])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::collections::HashMap;

    const COORD_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIcoordinatorkey root@coord";

    fn t0() -> Time {
        Time::ymd_hms(2026, 9, 19, 12, 0, 0)
    }

    pub fn wg_key() -> String {
        base64::engine::general_purpose::STANDARD.encode(fsx::random_bytes(32))
    }

    fn req(name: &str) -> Request {
        Request {
            name: name.into(),
            wg_key: wg_key(),
            ssh_host_key: format!("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInodekey root@{name}"),
            lan_ip: "192.168.1.23".into(),
            ..Request::default()
        }
    }

    fn member(host: u32, name: &str) -> Member {
        Member { host, name: name.into(), ..Member::default() }
    }

    #[test]
    fn pairing_code_covers_keys() {
        let k = wg_key();
        let a = pairing_code(&k, "ssh-ed25519 AAAAnode root@x", COORD_KEY);
        assert_eq!(a.len(), 7);
        assert_eq!(a.as_bytes()[3], b' ');
        let b = pairing_code(&k, "ssh-ed25519 AAAAnode other-comment", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIcoordinatorkey");
        assert_eq!(a, b, "key comments must not change the code");
        assert_ne!(pairing_code(&k, "ssh-ed25519 AAAAnode root@x", "ssh-ed25519 AAAAfakecoordinator"), a);
        assert_ne!(pairing_code(&wg_key(), "ssh-ed25519 AAAAnode root@x", COORD_KEY), a);
    }

    // Same digest as the Go version, so mixed-version installs agree.
    #[test]
    fn pairing_code_is_stable() {
        assert_eq!(pairing_code("KEY", "ssh-ed25519 AAAAnode x", "ssh-ed25519 AAAAcoord y"), pairing_code_reference());
    }

    fn pairing_code_reference() -> String {
        let h = Sha256::digest(b"dryserver-pairing-v1\nKEY\nssh-ed25519 AAAAnode\nssh-ed25519 AAAAcoord");
        let n = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) % 1_000_000;
        format!("{:03} {:03}", n / 1000, n % 1000)
    }

    #[test]
    fn validate_request_is_strict() {
        let good = req("node-1");
        validate_request(&good).unwrap();
        type Change = fn(&mut Request);
        let cases: [(&str, Change); 5] = [
            ("hostname injection", |r| r.name = "x; rm -rf /".into()),
            ("short wg key", |r| r.wg_key = "AAAA".into()),
            ("ssh key newline", |r| r.ssh_host_key += "\ncommand=\"sh\" ssh-ed25519 AAAA"),
            ("ssh key options", |r| r.ssh_host_key = format!("command=\"sh\" {}", r.ssh_host_key)),
            ("ipv6 lan", |r| r.lan_ip = "fe80::1".into()),
        ];
        for (name, change) in cases {
            let mut r = good.clone();
            change(&mut r);
            assert!(validate_request(&r).is_err(), "{name} accepted");
        }
    }

    #[test]
    fn members_from_the_coordinator_are_checked() {
        let good = |host: u32, name: &str, seed: u8| Member {
            host,
            name: name.into(),
            wg_key: base64::engine::general_purpose::STANDARD.encode([seed; 32]),
            ssh_host_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIhost root@x".into(),
            lan_ip: "192.168.1.20".into(),
            ..Member::default()
        };
        let fits = |h: u32| (1..=254).contains(&h);
        let all = vec![good(1, "coord", 1), good(2, "node-b", 2)];
        let (ok, problems) = check_members(all.clone(), fits);
        assert_eq!(ok, all);
        assert!(problems.is_empty(), "{problems:?}");
        // A self entry without a host key (as written at activation) is fine.
        assert!(member_problem(&Member { ssh_host_key: String::new(), lan_ip: String::new(), ..good(2, "node-b", 2) }).is_none());

        let bad = vec![
            (Member { name: "x archlinux.org".into(), ..good(3, "", 3) }, "bad name"),
            (Member { name: "a\n10.0.0.1 evil".into(), ..good(3, "", 3) }, "bad name"),
            (Member { name: String::new(), ..good(3, "", 3) }, "bad name"),
            (Member { wg_key: "C".into(), ..good(3, "n3", 3) }, "bad WireGuard key"),
            (Member { wg_key: "AAAA\n[Peer]".into(), ..good(3, "n3", 3) }, "bad WireGuard key"),
            (Member { ssh_host_key: "ssh-ed25519 AAAA x\nother,* ssh-ed25519 BBBB".into(), ..good(3, "n3", 3) }, "bad SSH host key"),
            (Member { lan_ip: "10.0.0.1 gateway".into(), ..good(3, "n3", 3) }, "bad LAN address"),
            (good(0, "n0", 4), "outside the mesh"),
            (good(255, "n255", 5), "outside the mesh"),
            (good(2, "other", 6), "host number used twice"),
            (good(4, "node-b", 7), "name used twice"),
            (good(5, "n5", 1), "WireGuard key used twice"),
        ];
        for (m, want) in bad {
            let mut list = all.clone();
            list.push(m.clone());
            let (ok, problems) = check_members(list, fits);
            assert_eq!(ok, all, "{m:?} was not dropped");
            assert!(problems.len() == 1 && problems[0].contains(want), "{m:?}: {problems:?}");
            assert!(!problems[0].contains('\n'), "a hostile name must not break the log line: {:?}", problems[0]);
        }
        // The first of two entries wins, also for the coordinator's address.
        let (ok, _) = check_members(vec![good(1, "coord", 1), good(1, "fake", 9)], fits);
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0].name, "coord");
    }

    #[test]
    fn hmac_matches_rfc_4231() {
        let hex = |b: [u8; 32]| fsx::hex(&b);
        assert_eq!(hex(hmac_sha256(&[0x0b; 20], b"Hi There")), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert_eq!(
            hex(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // A key longer than the block size is hashed first (test case 6).
        assert_eq!(
            hex(hmac_sha256(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First")),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn join_proof_covers_name_and_keys() {
        let r = req("node-a");
        let proof = join_proof("secret-1", &r.name, &r.wg_key, &r.ssh_host_key);
        assert_eq!(proof.len(), 64);
        let with = |f: &dyn Fn(&mut Request)| {
            let mut x = Request { proof: proof.clone(), ..r.clone() };
            f(&mut x);
            x
        };
        assert!(proof_ok("secret-1", &with(&|_| {})));
        assert!(proof_ok("secret-1\n", &with(&|_| {})), "a trailing newline in the secret file must not matter");
        // The key comment and addresses are not part of the identity.
        assert!(proof_ok("secret-1", &with(&|x| x.ssh_host_key += " root@other")));
        assert!(proof_ok("secret-1", &with(&|x| x.lan_ip = "10.0.0.9".into())));
        // Anything a hacked coordinator would swap breaks it.
        assert!(!proof_ok("secret-1", &with(&|x| x.wg_key = wg_key())));
        assert!(!proof_ok("secret-1", &with(&|x| x.name = "node-b".into())));
        assert!(!proof_ok("secret-1", &with(&|x| x.ssh_host_key = "ssh-ed25519 AAAAother".into())));
        assert!(!proof_ok("secret-2", &with(&|_| {})), "another stick's secret");
        assert!(!proof_ok("secret-1", &with(&|x| x.proof.clear())));
        assert!(!proof_ok("secret-1", &with(&|x| x.proof.push('0'))));
        // The registry carries a proof but refuses junk in its place.
        assert!(validate_request(&with(&|_| {})).is_ok());
        assert!(validate_request(&with(&|x| x.proof = "zz".into())).is_err());
        assert!(validate_request(&with(&|x| x.proof = "A".repeat(64))).is_err());
    }

    #[test]
    fn request_and_expiry() {
        let mut s = State { members: vec![Member { wg_key: wg_key(), ..member(1, "coord") }], ..State::default() };
        let r = req("node-a");
        let id = s.add_request(r.clone(), COORD_KEY, t0()).unwrap();
        let p = s.pending();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].code, pairing_code(&r.wg_key, &r.ssh_host_key, COORD_KEY));
        assert_eq!(s.request_status(&id, t0()).unwrap().status, Status::Pending);
        assert!(s.request_status(&id, t0().add(TimeDelta::hours(2))).is_err(), "request did not expire");
        // A member's name or key cannot ask again.
        s.members.push(Member { wg_key: r.wg_key.clone(), ..member(2, "node-a") });
        assert!(s.add_request(req("node-a"), COORD_KEY, t0()).is_err(), "duplicate member name accepted");
        assert!(s.add_request(Request { name: "other".into(), ..r }, COORD_KEY, t0()).is_err(), "a member's key accepted");
    }

    #[test]
    fn pending_limit() {
        let mut s = State::default();
        for i in 0..MAX_PENDING {
            s.add_request(req(&format!("n{}", "x".repeat(i + 1))), COORD_KEY, t0()).unwrap();
        }
        assert!(s.add_request(req("one-more"), COORD_KEY, t0()).is_err(), "pending limit not enforced");
    }

    #[test]
    fn heartbeat_updates_member() {
        let mut s =
            State { members: vec![member(1, "coord"), Member { lan_ip: "192.168.1.5".into(), ..member(2, "a") }], ..State::default() };
        let hb = |cuts: Vec<CutReport>| Heartbeat { lan_ip: "192.168.1.77".into(), switch: true, cuts, report: None };
        let cuts = vec![CutReport { name: "node-c".into(), auto: true }, CutReport { name: "x\u{1b}[2J evil".into(), auto: false }];
        s.heartbeat(2, hb(cuts), t0()).unwrap();
        let m = s.members.iter().find(|m| m.host == 2).unwrap();
        assert_eq!(m.cuts, vec![CutReport { name: "node-c".into(), auto: true }], "only real names are kept");
        let many: Vec<CutReport> = (0..100).map(|i| CutReport { name: format!("n{i}"), auto: false }).collect();
        s.heartbeat(2, hb(many), t0()).unwrap();
        assert_eq!(s.members.iter().find(|m| m.host == 2).unwrap().cuts.len(), MAX_CUT_REPORTS);
        s.heartbeat(2, hb(vec![]), t0()).unwrap();
        assert!(s.members.iter().find(|m| m.host == 2).unwrap().cuts.is_empty(), "a lifted cut must disappear");
        let m = &s.members[1];
        assert_eq!(m.lan_ip, "192.168.1.77");
        assert!(m.switch);
        assert_eq!(m.last_seen, t0());
        assert!(s.heartbeat(9, hb(vec![]), t0()).is_err(), "unknown host accepted");
    }

    /// A report as a server sends it, with peers.
    fn report(peers: &[u32]) -> Report {
        Report {
            format: report::FORMAT,
            time: t0().0.timestamp(),
            dryserver: "0.1.0".into(),
            kernel: "6.12.1-arch1-1".into(),
            disk_used: 10,
            disk_total: 100,
            peers: peers.iter().map(|h| report::Peer { host: *h, age: Some(12) }).collect(),
            ..Report::default()
        }
    }

    #[test]
    fn each_member_reports_for_itself_only() {
        let dir = TempDir::new();
        let st = coordinator(&dir);
        st.update(|s| {
            for (host, seed) in [(2, 2), (3, 3)] {
                s.members.push(Member { host, name: format!("n{host}"), wg_key: key32(seed), ..Member::default() });
            }
            Ok(())
        })
        .unwrap();
        let get = |host: u32| st.read().unwrap().members.into_iter().find(|m| m.host == host).unwrap();
        let send = |client: &str, body: &str| call(&st, "peers", client, body);

        // Its peers can only be other members; the rest of the report is
        // checked too, and fields it should not have are ignored.
        let body = serde_json::json!({
            "lan_ip": "192.168.1.23",
            "report": {"dryserver": "0.1.0", "kernel": "6.1\u{1b}[2J", "temp": 55,
                       "peers": [{"host": 1, "age": 3}, {"host": 2, "age": 3}, {"host": 3}, {"host": 77, "age": 1}],
                       "host": 3, "name": "n3", "members": []},
        });
        let out = send("10.66.0.2 5000 22", &body.to_string()).unwrap();
        let r = get(2).report.unwrap();
        assert_eq!((r.dryserver.as_str(), r.kernel.as_str(), r.temp), ("0.1.0", "", Some(55)));
        assert_eq!(r.peers.iter().map(|p| p.host).collect::<Vec<_>>(), vec![1, 3], "not itself, not a stranger");
        assert_eq!(get(3).report, None, "one member's report reached another's entry");
        assert!(!out.contains("report") && !out.contains("6.1"), "members get each other's reports: {out}");

        // A report that is not one, or a field of the wrong kind, costs
        // that much and not the heartbeat.
        for (lan, junk, want) in
            [("192.168.1.24", r#""report":"x""#, None), ("192.168.1.25", r#""report":{"uptime":"long","cpus":4}"#, Some(4))]
        {
            send("10.66.0.2 5000 22", &format!(r#"{{"lan_ip":"{lan}",{junk}}}"#)).unwrap();
            assert_eq!(get(2).lan_ip, lan, "{junk}");
            assert_eq!(get(2).report.map(|r| r.cpus), want, "{junk}");
        }

        // An older server sends none: no stale report stays behind.
        send("10.66.0.2 5000 22", &serde_json::to_string(&Heartbeat { report: Some(report(&[1])), ..Heartbeat::default() }).unwrap())
            .unwrap();
        assert!(get(2).report.is_some());
        send("10.66.0.2 5000 22", r#"{"lan_ip":"192.168.1.23","switch":false}"#).unwrap();
        assert_eq!(get(2).report, None);

        // Too big a heartbeat is refused, and changes nothing.
        let seen = get(2).last_seen;
        let huge = format!(r#"{{"lan_ip":"192.168.1.99","report":{{"k3s":"{}"}}}}"#, "v".repeat(MAX_INPUT as usize));
        assert!(send("10.66.0.2 5000 22", &huge).is_err());
        assert!(get(2).lan_ip != "192.168.1.99" && get(2).last_seen == seen);

        // The admin gets every report; a server waiting for approval gets
        // the coordinator without its report.
        st.update(|s| s.heartbeat(1, Heartbeat { report: Some(report(&[2, 3])), ..Heartbeat::default() }, t0())).unwrap();
        let ask = serde_json::to_string(&signed::seal_admin(&ADMIN, "state", t0().0.timestamp()).unwrap()).unwrap();
        let adm: AdminState = serde_json::from_str(&call(&st, "admin", "192.168.1.9 5000 22", &ask).unwrap()).unwrap();
        assert!(adm.members.iter().find(|m| m.host == 1).unwrap().report.as_ref().is_some_and(|r| r.peers.len() == 2));
        let id = st.read().unwrap().requests[0].id.clone();
        st.update(|s| {
            s.requests[0].status = Status::Approved;
            Ok(())
        })
        .unwrap();
        let out = call(&st, &format!("status {id}"), "192.168.1.23 5000 22", "").unwrap();
        assert!(out.contains("coord") && !out.contains("report"), "{out}");
    }

    #[test]
    fn the_largest_heartbeat_fits() {
        // What a server can send at most: every cut the coordinator keeps
        // with the longest names, and a report with every peer and the
        // longest versions. It must fit what this and older coordinators
        // read (MAX_INPUT), or the server could not sync.
        let long = |c: char| c.to_string().repeat(64);
        let r = Report {
            time: i64::from(u32::MAX),
            dryserver: long('d'),
            k3s: long('k'),
            kernel: long('r'),
            kernel_installed: long('i'),
            reboot: true,
            upgraded: i64::from(u32::MAX),
            uptime: u64::from(u32::MAX),
            load: [99999.99; 3],
            cpus: 4096,
            mem_used: 1 << 49,
            mem_total: 1 << 49,
            disk_used: 1 << 49,
            disk_total: 1 << 49,
            temp: Some(-49),
            k3s_active: Some(false),
            firewall: Some(false),
            peers: (1..=1000).map(|host| report::Peer { host, age: Some(3_000_000_000) }).collect(),
            release: crate::release::MAX_SERIAL,
            update: "reverted".into(),
            update_serial: crate::release::MAX_SERIAL,
            // Quotes take two bytes each in JSON.
            update_note: "\"".repeat(report::MAX_NOTE),
            ..report(&[])
        }
        .sanitized(|_| true);
        let cuts = (0..MAX_CUT_REPORTS).map(|i| CutReport { name: format!("{i:02}{}", "n".repeat(61)), auto: true }).collect();
        let hb = Heartbeat { lan_ip: "255.255.255.255".into(), switch: true, cuts, report: Some(r) };
        let len = serde_json::to_string(&hb).unwrap().len() as u64;
        assert!(len < MAX_INPUT * 3 / 4, "the largest heartbeat is {len} bytes");
    }

    #[test]
    fn a_registry_file_with_reports_of_any_age_loads() {
        let dir = TempDir::new();
        let path = dir.join("registry.json");
        // A report in a form this version does not know (a newer one wrote
        // it): the registry still loads, without it.
        std::fs::write(
            &path,
            r#"{"members":[{"host":1,"name":"coord","wg_key":"K","report":"from the future"},
                          {"host":2,"name":"a","wg_key":"L","report":{"format":9,"cpus":2,"gpu":{"x":1}}}]}"#,
        )
        .unwrap();
        let s = Store::new(path).read().unwrap();
        assert_eq!(s.members[0].report, None);
        assert_eq!(s.members[1].report.as_ref().map(|r| (r.format, r.cpus)), Some((9, 2)));
    }

    #[test]
    fn store_concurrent() {
        let dir = TempDir::new();
        let st = Store::new(dir.join("registry.json"));
        std::thread::scope(|sc| {
            for i in 0..10u8 {
                let st = &st;
                sc.spawn(move || {
                    let name = format!("node-{}", (b'a' + i) as char);
                    st.update(|s| s.add_request(req(&name), COORD_KEY, Time::now())).unwrap();
                });
            }
        });
        let s = st.read().unwrap();
        assert_eq!(s.requests.len(), 10, "lost updates");
    }

    /// The registry account owns the directory and may plant links under
    /// every name root uses there. Root (here: whoever runs the test, as
    /// links are followed alike) never writes, creates or reads through
    /// them; the store works again once they are gone.
    #[test]
    fn store_never_goes_through_planted_links() {
        let dir = TempDir::new();
        let path = dir.join("registry.json");
        let st = Store::new(&path);
        st.update(|s| s.add_request(req("node-a"), COORD_KEY, Time::now())).unwrap();
        // Stands in for /etc/ld.so.preload, and for a file that is not
        // there yet.
        let target = dir.join("victim");
        std::fs::write(&target, "untouched").unwrap();
        let missing = dir.join("missing");
        let link = |name: &str, to: &Path| {
            let _ = std::fs::remove_file(dir.join(name));
            std::os::unix::fs::symlink(to, dir.join(name)).unwrap();
        };
        let untouched = || {
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched");
            assert!(!missing.exists(), "a dangling link was followed");
        };

        // The old fixed temp name: not used any more, so not followed.
        link("registry.json.tmp", &target);
        st.update(|s| s.add_request(req("node-b"), COORD_KEY, Time::now())).unwrap();
        untouched();
        assert!(std::fs::symlink_metadata(dir.join("registry.json.tmp")).unwrap().file_type().is_symlink());
        assert_eq!(st.read().unwrap().requests.len(), 2);

        // The lock file, to a file that exists and to one that does not.
        for to in [&target, &missing] {
            link("registry.json.lock", to);
            let e = st.update(|s| s.add_request(req("node-c"), COORD_KEY, Time::now())).unwrap_err().to_string();
            assert!(e.contains("symbolic link"), "{e}");
            assert!(st.read().is_err());
            untouched();
        }
        // A FIFO in its place is refused, not waited on.
        std::fs::remove_file(dir.join("registry.json.lock")).unwrap();
        let fifo = std::ffi::CString::new(dir.join("registry.json.lock").as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid C string.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(st.read().unwrap_err().to_string().contains("not a regular file"));
        std::fs::remove_file(dir.join("registry.json.lock")).unwrap();

        // The registry file itself: neither read nor written through.
        std::fs::rename(&path, dir.join("saved.json")).unwrap();
        link("registry.json", &target);
        assert!(st.read().unwrap_err().to_string().contains("symbolic link"));
        untouched();
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(dir.join("saved.json"), &path).unwrap();

        // Gone again: it works, and no temp file was left behind.
        assert_eq!(st.read().unwrap().requests.len(), 2);
        let left: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("registry.json.tmp."))
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }

    /// The directory itself: a link to one, or one anybody may write in,
    /// is not used.
    #[test]
    fn store_refuses_a_linked_or_open_directory() {
        let dir = TempDir::new();
        std::fs::create_dir(dir.join("real")).unwrap();
        std::os::unix::fs::symlink(dir.join("real"), dir.join("linked")).unwrap();
        let e = Store::new(dir.join("linked/registry.json")).read().unwrap_err().to_string();
        assert!(e.contains("linked"), "{e}");
        assert!(!dir.join("real/registry.json").exists() && !dir.join("real/registry.json.lock").exists());

        std::fs::create_dir(dir.join("open")).unwrap();
        fsx::chmod(dir.join("open"), 0o777).unwrap();
        let e = Store::new(dir.join("open/registry.json")).read().unwrap_err().to_string();
        assert!(e.contains("writable by others"), "{e}");
        assert!(!dir.join("open/registry.json.lock").exists());
        assert!(Store::new(dir.join("real/registry.json")).read().is_ok());
    }

    /// Under the registry file's own name: a FIFO or a directory is
    /// refused at once, and a hard link to another file is never written
    /// through (the new state is a new file renamed over the name). That
    /// root hands only files with no other name to the registry account
    /// (fchown in give) needs root to test.
    #[test]
    fn store_never_writes_through_what_is_not_its_own_file() {
        use std::os::unix::fs::MetadataExt;
        let dir = TempDir::new();
        let path = dir.join("registry.json");
        let st = Store::new(&path);
        let c = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid C string.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(st.read().unwrap_err().to_string().contains("not a regular file"));
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(st.read().unwrap_err().to_string().contains("not a regular file"));
        std::fs::remove_dir(&path).unwrap();

        let victim = dir.join("victim");
        std::fs::write(&victim, "{}").unwrap();
        std::fs::hard_link(&victim, &path).unwrap();
        st.update(|s| s.add_request(req("node-a"), COORD_KEY, Time::now())).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "{}");
        assert_eq!(std::fs::metadata(&victim).unwrap().nlink(), 1, "the link was replaced, not written");
        assert_eq!(st.read().unwrap().requests.len(), 1);
        let left: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }

    #[test]
    fn reads_go_written_state() {
        let dir = TempDir::new();
        let path = dir.join("registry.json");
        std::fs::write(
            &path,
            r#"{"members":[{"host":1,"name":"coord","wg_key":"K","ssh_host_key":"","lan_ip":"192.168.1.50","switch":false,"approved":"2026-09-19T12:00:00.5+04:00","last_seen":"0001-01-01T00:00:00Z"}],"requests":null,"unknown":null,"scanned":"0001-01-01T00:00:00Z"}"#,
        )
        .unwrap();
        let s = Store::new(path).read().unwrap();
        assert_eq!(s.members[0].name, "coord");
        assert!(s.requests.is_empty());
        assert!(s.scanned.is_zero());
    }

    #[test]
    fn scan_report() {
        let out = "192.168.1.1\tAA:BB:CC:00:00:01\tTP-LINK\n\
                   192.168.1.23\t52:54:00:12:34:56\tQEMU\n\
                   192.168.1.23\t52:54:00:12:34:56\tQEMU (DUP: 2)\n\
                   junk line\n\
                   172.16.66.2\t52:54:00:aa:bb:cc\n";
        let found = parse_arp_scan(out);
        assert_eq!(found.len(), 3);
        assert_eq!(found[0].mac, "aa:bb:cc:00:00:01");
        assert_eq!(found[0].vendor, "TP-LINK");
        let unknown = unknown(&found, &["192.168.1.23".into(), "172.16.66.2".into()], t0());
        assert_eq!(unknown.len(), 1);
        assert_eq!(unknown[0].ip, "192.168.1.1");
        assert_eq!(unknown[0].seen, t0());
    }

    /// A hacked server names a rogue device's address as its own LAN
    /// address: the scan takes that only when nothing speaks against it.
    #[test]
    fn a_members_word_hides_no_device() {
        let m = |host: u32, name: &str, lan: &str| Member {
            host,
            name: name.into(),
            wg_key: format!("KEY{host}"),
            lan_ip: lan.into(),
            ..Member::default()
        };
        let fixed = |h: u32| {
            let mut v = vec![format!("172.16.66.{h}"), format!("10.66.0.{h}")];
            if h == 1 {
                v.push("192.168.1.50".into());
            }
            v
        };
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        let members = vec![
            // The registry account says anything for the coordinator: its
            // own address comes from its config.
            m(1, "coord", "192.168.1.66"),
            // WireGuard sees node-a where it says it is.
            m(2, "node-a", "192.168.1.20"),
            // node-b says it is at the rogue device; WireGuard sees it at
            // .21.
            m(3, "node-b", "192.168.1.99"),
            // node-c talks over the switch: its word is taken, unless
            // node-d says the same.
            m(4, "node-c", "192.168.1.30"),
            m(5, "node-d", "192.168.1.30"),
            // node-e claims node-a's address.
            m(6, "node-e", "192.168.1.20"),
            m(7, "node-f", "192.168.1.31"),
            m(8, "node-g", "not an address"),
        ];
        let seen = std::collections::BTreeMap::from([("KEY2".to_string(), ip("192.168.1.20")), ("KEY3".to_string(), ip("192.168.1.21"))]);
        let (known, notes) = member_addresses(&members, &seen, fixed);
        for want in ["192.168.1.50", "192.168.1.20", "192.168.1.21", "192.168.1.31", "172.16.66.3", "10.66.0.8"] {
            assert!(known.contains(&want.to_string()), "{want} not a member's: {known:?}");
        }
        for not in ["192.168.1.66", "192.168.1.99", "192.168.1.30", "not an address"] {
            assert!(!known.contains(&not.to_string()), "{not} taken: {known:?}");
        }
        assert_eq!(notes["192.168.1.99"], "node-b says it is here, but talks from 192.168.1.21");
        assert_eq!(notes["192.168.1.30"], "claimed by node-c and node-d");
        assert_eq!(notes["192.168.1.20"], "node-e says it is here, but this is node-a");
        assert_eq!(notes.len(), 3, "{notes:?}");
        // The rogue device shows up in the report.
        let found = parse_arp_scan("192.168.1.99\taa:bb:cc:00:00:99\tEvil\n192.168.1.20\taa:bb:cc:00:00:20\tnode-a\n");
        let report = unknown(&found, &known, t0());
        assert_eq!(report.iter().map(|d| d.ip.as_str()).collect::<Vec<_>>(), vec!["192.168.1.99"]);
        // Without WireGuard's word, only two claims for one address speak
        // against one.
        let (known, notes) = member_addresses(&members, &std::collections::BTreeMap::new(), fixed);
        assert!(known.contains(&"192.168.1.99".to_string()) && !known.contains(&"192.168.1.30".to_string()));
        assert_eq!(notes.keys().collect::<Vec<_>>(), vec!["192.168.1.20", "192.168.1.30"]);
    }

    /// One device answering for every address of a /16, with long names:
    /// the report keeps MAX_UNKNOWN of them, each short.
    #[test]
    fn a_flood_of_devices_is_cut_short() {
        let mut out = String::new();
        for i in 0..65_000u32 {
            out += &format!("10.1.{}.{}\t{}\t{}\n", i / 256, i % 256, "a".repeat(100), "V".repeat(1000));
        }
        let start = std::time::Instant::now();
        let found = parse_arp_scan(&out);
        assert!(start.elapsed() < std::time::Duration::from_secs(5), "{:?}", start.elapsed());
        assert_eq!(found.len(), MAX_FOUND);
        assert!(found.iter().all(|d| d.mac.len() == MAX_MAC && d.vendor.len() == MAX_VENDOR));
        assert_eq!(unknown(&found, &[], t0()).len(), MAX_UNKNOWN);
    }

    /// The registry account owns the lock file and may hold its lock for
    /// ever: root waits a while, then fails instead of hanging its sync.
    /// And a registry file larger than MAX_FILE is not read.
    #[test]
    fn store_neither_waits_for_ever_nor_reads_without_end() {
        let dir = TempDir::new();
        let path = dir.join("registry.json");
        let mut st = Store::new(&path);
        st.lock_wait = std::time::Duration::from_millis(300);
        st.update(|s| s.add_request(req("node-a"), COORD_KEY, Time::now())).unwrap();
        // Someone else holds it (another open file: flock is per open file).
        let held = std::fs::File::open(dir.join("registry.json.lock")).unwrap();
        // SAFETY: flock on a valid open descriptor.
        assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX) }, 0);
        let start = std::time::Instant::now();
        let e = st.read().unwrap_err().to_string();
        assert!(e.contains("held by another process") && e.contains("nothing read or written"), "{e}");
        assert!(start.elapsed() < std::time::Duration::from_secs(3));
        drop(held);
        assert_eq!(st.read().unwrap().requests.len(), 1);
        // Let go within the wait: taken.
        let held = std::fs::File::open(dir.join("registry.json.lock")).unwrap();
        // SAFETY: flock on a valid open descriptor.
        assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX) }, 0);
        std::thread::scope(|sc| {
            sc.spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(100));
                drop(held);
            });
            assert!(st.read().is_ok());
        });

        let big = format!("{{\"requests\":[],\"pad\":\"{}\"}}", "x".repeat(MAX_FILE as usize));
        std::fs::write(&path, big).unwrap();
        let e = st.read().unwrap_err().to_string();
        assert!(e.contains("larger than"), "{e}");
    }

    #[test]
    fn request_retry_is_idempotent() {
        let mut s = State::default();
        let r = req("node-a");
        let id1 = s.add_request(r.clone(), COORD_KEY, t0()).unwrap();
        let id2 = s.add_request(r, COORD_KEY, t0()).unwrap();
        assert_eq!(id1, id2);
        assert_eq!(s.requests.len(), 1, "retry made a new request");
        assert!(s.add_request(req("node-a"), COORD_KEY, t0()).is_err(), "same name from another machine accepted");
    }

    // ---- serve ----

    struct FakeMesh(HashMap<String, u32>);

    impl Mesh for FakeMesh {
        fn host_of(&self, ip: Ipv4Addr) -> u32 {
            self.0.get(&ip.to_string()).copied().unwrap_or(0)
        }
        fn fits(&self, host: u32) -> bool {
            (1..=254).contains(&host)
        }
    }

    const ADMIN: signed::fake::Key = signed::fake::Key("admin");

    fn call(st: &Store, cmd: &str, client: &str, stdin: &str) -> Result<String> {
        let mesh = FakeMesh(HashMap::from([("10.66.0.2".to_string(), 2)]));
        let served = Served::beside(st, fsx::dir(&st.path).join("k3s"));
        let mut out = Vec::new();
        serve(st, &served, &mesh, &ADMIN, COORD_KEY, cmd, client, &mut stdin.as_bytes(), &mut out, t0())?;
        Ok(String::from_utf8(out).unwrap())
    }

    fn key32(seed: u8) -> String {
        base64::engine::general_purpose::STANDARD.encode([seed; 32])
    }

    /// A coordinator with itself as member 1 and node-a waiting.
    fn coordinator(dir: &TempDir) -> Store {
        let st = Store::new(dir.join("registry.json"));
        st.update(|s| {
            s.members = vec![Member {
                host: 1,
                name: "coord".into(),
                wg_key: key32(1),
                ssh_host_key: format!("{COORD_KEY} root@coord"),
                lan_ip: "192.168.1.50".into(),
                switch: true,
                ..Member::default()
            }];
            let r = Request {
                name: "node-a".into(),
                wg_key: key32(2),
                ssh_host_key: "ssh-ed25519 AAAAnodea root@a".into(),
                lan_ip: "192.168.1.23".into(),
                switch: true,
                ..Request::default()
            };
            s.add_request(r, COORD_KEY, t0())?;
            Ok(())
        })
        .unwrap();
        st
    }

    fn entry(host: u32, name: &str, seed: u8, host_key: &str) -> signed::Entry {
        signed::Entry { host, name: name.into(), wg_key: key32(seed), ssh_host_key: host_key.into() }
    }

    fn publish(st: &Store, key: &signed::fake::Key, list: &List) -> Result<String> {
        call(st, "publish", "192.168.1.9 5000 22", &serde_json::to_string(&signed::seal(key, list).unwrap()).unwrap())
    }

    #[test]
    fn publish_signed_list() {
        let dir = TempDir::new();
        let st = coordinator(&dir);
        let coord = entry(1, "coord", 1, COORD_KEY);
        let node_a = entry(2, "node-a", 2, "ssh-ed25519 AAAAnodea");
        let v5 = List { version: 5, members: vec![coord.clone(), node_a.clone()], rejected: vec![] };

        // Not signed with the admin's key: refused, nothing changes.
        assert!(publish(&st, &signed::fake::Key("thief"), &v5).is_err());
        assert_eq!(st.read().unwrap().members.len(), 1);

        assert!(publish(&st, &ADMIN, &v5).unwrap().contains(r#""version":5"#));
        let s = st.read().unwrap();
        assert_eq!(s.signed_version, 5);
        let a = s.members.iter().find(|m| m.name == "node-a").unwrap();
        assert_eq!((a.host, a.lan_ip.as_str(), a.switch), (2, "192.168.1.23", true), "address must come from the join request");
        assert_eq!(s.members[0].lan_ip, "192.168.1.50", "a member that stays keeps its address");
        assert_eq!(s.requests[0].status, Status::Approved);
        assert_eq!(s.requests[0].host, 2);
        assert!(s.pending().is_empty());

        // The same or an older list is refused: no way back to an old list.
        for old in [5, 4] {
            let e = publish(&st, &ADMIN, &List { version: old, members: vec![coord.clone()], rejected: vec![] }).unwrap_err().to_string();
            assert!(e.contains("not newer"), "{e}");
        }
        assert_eq!(st.read().unwrap().members.len(), 2);

        // A newer list without node-a removes it.
        publish(&st, &ADMIN, &List { version: 6, members: vec![coord.clone()], rejected: vec![] }).unwrap();
        assert_eq!(st.read().unwrap().members.len(), 1);

        // A list for another coordinator (other keys or name) is refused.
        for other in [entry(1, "coord", 9, COORD_KEY), entry(1, "coord", 1, "ssh-ed25519 AAAAother"), entry(1, "brain", 1, COORD_KEY)] {
            let e = publish(&st, &ADMIN, &List { version: 7, members: vec![other], rejected: vec![] }).unwrap_err().to_string();
            assert!(e.contains("own name and keys"), "{e}");
        }
        // Bad entries are refused even with a good signature.
        let bad = List { version: 7, members: vec![coord.clone(), entry(300, "far", 3, "ssh-ed25519 AAAAx")], rejected: vec![] };
        assert!(publish(&st, &ADMIN, &bad).unwrap_err().to_string().contains("outside the mesh"));
        assert_eq!(st.read().unwrap().signed_version, 6);
    }

    #[test]
    fn publish_settles_requests() {
        let dir = TempDir::new();
        let st = coordinator(&dir);
        st.update(|s| {
            let r = Request {
                name: "node-z".into(),
                wg_key: key32(8),
                ssh_host_key: "ssh-ed25519 AAAAq".into(),
                lan_ip: "192.168.1.30".into(),
                ..Request::default()
            };
            s.add_request(r, COORD_KEY, t0())?;
            // A waiting request under node-a's name with another key (it
            // cannot arrive through add_request, which refuses it).
            let mut imp = s.requests[0].clone();
            imp.id = "00000000000000ff".into();
            imp.wg_key = key32(7);
            s.requests.push(imp);
            Ok(())
        })
        .unwrap();
        let list = List {
            version: 1,
            members: vec![entry(1, "coord", 1, COORD_KEY), entry(2, "node-a", 2, "ssh-ed25519 AAAAnodea")],
            rejected: vec![],
        };
        publish(&st, &ADMIN, &list).unwrap();
        let s = st.read().unwrap();
        let status = |seed: u8| s.requests.iter().find(|r| r.wg_key == key32(seed)).unwrap().status;
        assert_eq!(status(2), Status::Approved);
        assert_eq!(status(7), Status::Rejected, "an impostor under a signed name must be rejected");
        assert_eq!(status(8), Status::Pending);
        // Turning node-z down.
        let list = List { version: 2, rejected: vec![key32(8)], ..list };
        publish(&st, &ADMIN, &list).unwrap();
        assert!(st.read().unwrap().pending().is_empty());
    }

    #[test]
    fn admin_needs_the_signing_key() {
        let dir = TempDir::new();
        let st = coordinator(&dir);
        let now = t0().0.timestamp();
        let ask = |key: &signed::fake::Key, op: &str, time: i64| {
            call(&st, "admin", "192.168.1.9 5000 22", &serde_json::to_string(&signed::seal_admin(key, op, time).unwrap()).unwrap())
        };
        let reply: AdminState = serde_json::from_str(&ask(&ADMIN, "state", now).unwrap()).unwrap();
        assert_eq!(reply.members.len(), 1);
        assert_eq!(reply.requests.len(), 1);
        assert!(reply.signed.is_empty());
        assert!(ask(&signed::fake::Key("thief"), "state", now).is_err(), "the registry key alone must not open the registry");
        assert!(ask(&ADMIN, "state", now - 3600).unwrap_err().to_string().contains("old"), "a replayed request must expire");
        assert!(ask(&ADMIN, "other", now).is_err());
        assert!(call(&st, "admin", "192.168.1.9 5000 22", "{}").is_err());
        // A signed list is not an admin request and the other way round.
        let list = List { version: 1, members: vec![entry(1, "coord", 1, COORD_KEY)], rejected: vec![] };
        let env = serde_json::to_string(&signed::seal(&ADMIN, &list).unwrap()).unwrap();
        assert!(call(&st, "admin", "192.168.1.9 5000 22", &env).is_err());
        let adm = serde_json::to_string(&signed::seal_admin(&ADMIN, "state", now).unwrap()).unwrap();
        assert!(call(&st, "publish", "192.168.1.9 5000 22", &adm).is_err());
    }

    #[test]
    fn peers_carry_the_signed_list() {
        let dir = TempDir::new();
        let st = coordinator(&dir);
        let list = List {
            version: 3,
            members: vec![entry(1, "coord", 1, COORD_KEY), entry(2, "node-a", 2, "ssh-ed25519 AAAAnodea")],
            rejected: vec![],
        };
        // Before anything is signed the field is there but empty.
        st.update(|s| {
            s.members.push(Member { host: 2, name: "node-a".into(), wg_key: key32(2), ..Member::default() });
            Ok(())
        })
        .unwrap();
        let hb = r#"{"lan_ip":"192.168.1.23","switch":false}"#;
        let out: serde_json::Value = serde_json::from_str(&call(&st, "peers", "10.66.0.2 5000 22", hb).unwrap()).unwrap();
        assert_eq!(out["signed"]["doc"], "");
        publish(&st, &ADMIN, &list).unwrap();
        let out: serde_json::Value = serde_json::from_str(&call(&st, "peers", "10.66.0.2 5000 22", hb).unwrap()).unwrap();
        let env: Envelope = serde_json::from_value(out["signed"].clone()).unwrap();
        assert_eq!(env.list(&ADMIN, |h| h < 255).unwrap(), list, "nodes must get the list exactly as it was signed");
        // Before the coordinator sealed a cluster token: none, and never a
        // plain one.
        let out: serde_json::Value = serde_json::from_str(&call(&st, "peers", "10.66.0.2 5000 22", hb).unwrap()).unwrap();
        assert!(out["k3s_sealed"].is_null() && out.get("k3s_token").is_none(), "{out}");
        // Each member gets its own sealed token with it; nobody else gets
        // any, by any command.
        let sealed = |host: u32| crate::k3stoken::fake::sealed(COORD_KEY, host, &format!("ssh-ed25519 AAAAnode{host}"), "x");
        st.update(|s| {
            s.k3s_tokens = vec![sealed(3), sealed(2), sealed(4)];
            Ok(())
        })
        .unwrap();
        let out: serde_json::Value = serde_json::from_str(&call(&st, "peers", "10.66.0.2 5000 22", hb).unwrap()).unwrap();
        assert_eq!(serde_json::from_value::<Sealed>(out["k3s_sealed"].clone()).unwrap(), sealed(2));
        let text = out.to_string();
        assert!(!text.contains("AAAAnode3") && !text.contains("AAAAnode4") && out.get("k3s_token").is_none(), "{text}");
        for (cmd, stdin) in [
            ("signed", String::new()),
            ("admin", serde_json::to_string(&signed::seal_admin(&ADMIN, "state", t0().0.timestamp()).unwrap()).unwrap()),
        ] {
            let out = call(&st, cmd, "192.168.1.77 5000 22", &stdin).unwrap();
            assert!(!out.contains("AGE ENCRYPTED") && !out.contains("k3s"), "{cmd} hands out a cluster token: {out}");
        }
        // The same list for anyone who asks from the LAN, and nothing else.
        let out = call(&st, "signed", "192.168.1.77 5000 22", "").unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(serde_json::from_value::<Envelope>(v["signed"].clone()).unwrap(), env);
        assert!(v.as_object().unwrap().len() == 1 && !out.contains("lan_ip"), "signed must not leak addresses: {out}");
    }

    #[test]
    fn serve_join_flow() {
        let dir = TempDir::new();
        let st = Store::new(dir.join("registry.json"));
        st.update(|s| {
            s.members = vec![Member { wg_key: wg_key(), lan_ip: "192.168.1.50".into(), ..member(1, "coord") }];
            Ok(())
        })
        .unwrap();

        let r = req("node-a");
        let out = call(&st, "request", "192.168.1.23 5000 22", &serde_json::to_string(&r).unwrap()).unwrap();
        let id = serde_json::from_str::<serde_json::Value>(&out).unwrap()["id"].as_str().unwrap().to_string();
        assert_eq!(id.len(), 16);
        assert!(!out.contains("code"), "request reply {out:?} must not reveal the code");

        let out = call(&st, &format!("status {id}"), "192.168.1.23 5000 22", "").unwrap();
        assert!(out.contains(r#""status":"pending""#) && !out.contains("coordinator"), "pending status {out:?}");
        // Nothing on the coordinator can approve: only a signed list does.
        assert!(call(&st, &format!("approve {id}"), "192.168.1.23 5000 22", "").is_err());
        let me = st.read().unwrap().members[0].clone();
        let list = List {
            version: 1,
            members: vec![
                signed::Entry::of(&me),
                signed::Entry { host: 2, name: "node-a".into(), wg_key: r.wg_key.clone(), ssh_host_key: signed::key_body(&r.ssh_host_key) },
            ],
            rejected: vec![],
        };
        publish(&st, &ADMIN, &list).unwrap();
        let out = call(&st, &format!("status {id}"), "192.168.1.23 5000 22", "").unwrap();
        let sr: StatusReply = serde_json::from_str(&out).unwrap();
        assert_eq!(sr.status, Status::Approved);
        assert_eq!(sr.host, 2);
        assert_eq!(sr.coordinator.unwrap().lan_ip, "192.168.1.50");
        assert_eq!(sr.signed.list(&ADMIN, |h| h < 255).unwrap(), list, "the approved node must get the signed list");

        // peers: only from the member's mesh address.
        assert!(call(&st, "peers", "192.168.1.23 5000 22", r#"{"lan_ip":"192.168.1.23"}"#).is_err(), "peers answered over the LAN");
        assert!(call(&st, "peers", "10.66.0.9 5000 22", "{}").is_err(), "peers answered to a non-member");
        let out = call(&st, "peers", "10.66.0.2 5000 22", r#"{"lan_ip":"192.168.1.99","switch":true}"#).unwrap();
        assert!(out.contains("node-a") && out.contains("192.168.1.99"), "peers {out:?}");
    }

    #[test]
    fn members_get_their_turn_and_the_admin_the_rollout() {
        let dir = TempDir::new();
        let st = coordinator(&dir);
        let turn = |ready: bool| rollout::Turn { host: 2, name: "node-a".into(), since: 1, ready, ..rollout::Turn::default() };
        let set = |r: Rollout| {
            st.update(|s| {
                s.rollout = r;
                Ok(())
            })
            .unwrap()
        };
        st.update(|s| {
            s.members.push(Member { host: 2, name: "node-a".into(), wg_key: key32(2), ..Member::default() });
            s.members[0].report = Some(Report { k3s: "v1.37.2+k3s1".into(), ..Report::default() });
            Ok(())
        })
        .unwrap();
        let running = Rollout { serial: 9, phase: rollout::Phase::Servers, turn: Some(turn(true)), ..Rollout::default() };
        let hb = r#"{"lan_ip":"192.168.1.23"}"#;
        let offer = |st: &Store| {
            let out: serde_json::Value = serde_json::from_str(&call(st, "peers", "10.66.0.2 5000 22", hb).unwrap()).unwrap();
            out["release"].clone()
        };
        // Before any release: nothing offered.
        assert_eq!(offer(&st), serde_json::json!({"serial": 0, "turn": false, "brain_k3s": "v1.37.2+k3s1"}));
        set(running.clone());
        assert_eq!(offer(&st), serde_json::json!({"serial": 9, "turn": true, "brain_k3s": "v1.37.2+k3s1"}));
        // A try again the admin asked for goes with the turn, never without.
        set(Rollout { turn: Some(rollout::Turn { retry: 3, ..turn(true) }), ..running.clone() });
        assert_eq!(offer(&st), serde_json::json!({"serial": 9, "turn": true, "brain_k3s": "v1.37.2+k3s1", "retry": 3}));
        set(Rollout { turn: Some(rollout::Turn { retry: 3, ..turn(false) }), ..running.clone() });
        assert_eq!(offer(&st), serde_json::json!({"serial": 9, "turn": false, "brain_k3s": "v1.37.2+k3s1"}));
        set(running.clone());
        // Not drained yet, stopped, or the brain's own phase: no turn.
        for r in [
            Rollout { turn: Some(turn(false)), ..running.clone() },
            Rollout { paused: "node-x: update failed".into(), ..running.clone() },
            Rollout { phase: rollout::Phase::Brain, ..running.clone() },
            Rollout { turn: Some(rollout::Turn { host: 3, ..turn(true) }), ..running.clone() },
        ] {
            set(r.clone());
            assert_eq!(offer(&st)["turn"], false, "{r:?}");
        }
        set(running.clone());

        // The admin sees the rollout and the coordinator's clock.
        let ask =
            |key: &signed::fake::Key, op: &str| serde_json::to_string(&signed::seal_admin(key, op, t0().0.timestamp()).unwrap()).unwrap();
        let adm: AdminState = serde_json::from_str(&call(&st, "admin", "192.168.1.9 5000 22", &ask(&ADMIN, "state")).unwrap()).unwrap();
        assert_eq!((adm.rollout.serial, adm.now), (9, t0().0.timestamp()));
        // Only the admin resumes, with a request made for it, for the stop
        // the rollout is at.
        let resume = |key: &signed::fake::Key, op: &str, serial: u64, host: u32| {
            serde_json::to_string(&signed::seal_ask(key, op, t0().0.timestamp(), serial, host).unwrap()).unwrap()
        };
        let lan = "192.168.1.9 5000 22";
        assert!(call(&st, "release-resume", lan, &resume(&signed::fake::Key("thief"), "release-resume", 9, 0)).is_err());
        assert!(call(&st, "release-resume", lan, &resume(&ADMIN, "state", 9, 0)).is_err());
        let e = call(&st, "release-resume", lan, &ask(&ADMIN, "release-resume")).unwrap_err().to_string();
        assert!(e.contains("names no rollout"), "{e}");
        for (serial, host) in [(8, 0), (9, 2)] {
            let e = call(&st, "release-resume", lan, &resume(&ADMIN, "release-resume", serial, host)).unwrap_err().to_string();
            assert!(e.contains("the rollout changed since you looked (it is at release 9, not stopped)"), "{e}");
        }
        assert!(st.read().unwrap().rollout.resume_ask.is_empty());
        let out = call(&st, "release-resume", lan, &resume(&ADMIN, "release-resume", 9, 0)).unwrap();
        assert!(out.contains(r#""resume":1"#), "{out}");
        let r = st.read().unwrap().rollout;
        assert_eq!(r.resume_asked, 1);
        assert_eq!(signed::open_request(&ADMIN, &r.resume_ask, "release-resume", t0().0.timestamp()).unwrap().serial, 9);
        set(Rollout { paused: "node-a: update failed".into(), pause_host: 2, ..running.clone() });
        let e = call(&st, "release-skip", lan, &resume(&ADMIN, "release-skip", 9, 3)).unwrap_err().to_string();
        assert!(e.contains("stopped at host 2"), "{e}");
        assert!(call(&st, "release-skip", lan, &resume(&ADMIN, "release-skip", 9, 2)).unwrap().contains(r#""skip":1"#));
        set(Rollout::default());
        let e = call(&st, "release-resume", lan, &resume(&ADMIN, "release-resume", 9, 0)).unwrap_err().to_string();
        assert!(e.contains("no rollout to resume"), "{e}");
    }

    #[test]
    fn a_rollout_in_an_unknown_form_does_not_break_the_registry() {
        let dir = TempDir::new();
        let path = dir.join("registry.json");
        for rollout in [r#""from the future""#, r#"{"serial":5,"turn":"x"}"#, r#"{"serial":5,"phase":"teleport","pause":"why"}"#] {
            std::fs::write(&path, format!(r#"{{"members":[{{"host":1,"name":"coord","wg_key":"K"}}],"rollout":{rollout}}}"#)).unwrap();
            let s = Store::new(&path).read().unwrap();
            assert_eq!(s.members.len(), 1, "{rollout}");
            if rollout.contains("teleport") {
                assert_eq!((s.rollout.serial, s.rollout.phase, s.rollout.pause), (5, rollout::Phase::None, rollout::Pause::None));
            } else {
                assert!(s.rollout.is_none(), "{rollout}: {:?}", s.rollout);
            }
        }
    }

    /// An older version kept the cluster token in the file in plain text.
    #[test]
    fn the_plain_cluster_token_goes_with_the_first_write() {
        let dir = TempDir::new();
        let path = dir.join("registry.json");
        let plain = "K10abc::node:5ecre7plain";
        std::fs::write(&path, format!(r#"{{"members":[{{"host":1,"name":"coord","wg_key":"K"}}],"k3s_token":"{plain}"}}"#)).unwrap();
        let st = Store::new(&path);
        assert_eq!(st.read().unwrap().members.len(), 1);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains(plain) && !text.contains("k3s_token"), "{text}");
        // What the registry account may put there in place of sealed
        // tokens reads as none, and leaves the rest readable.
        for junk in [r#""K10abc::node:x""#, r#"[{"host":"two"}]"#, "7", r#"{"host":2}"#] {
            std::fs::write(&path, format!(r#"{{"members":[{{"host":1,"name":"coord","wg_key":"K"}}],"k3s_tokens":{junk}}}"#)).unwrap();
            let s = st.read().unwrap();
            assert!(s.k3s_tokens.is_empty() && s.members.len() == 1, "{junk}: {s:?}");
        }
    }

    #[test]
    fn moving_a_release_may_take_longer() {
        assert_eq!(deadline("peers").as_secs(), 30);
        assert_eq!(deadline("").as_secs(), 30);
        assert_eq!(deadline("release-get 5 dryserver 0").as_secs(), 120);
        // An upload gets more only once its signature checked out.
        assert_eq!(deadline("release-put").as_secs(), 30);
        set_deadline(std::time::Duration::from_secs(30));
        assert!(!past_deadline());
        extend_deadline(UPLOAD_DEADLINE);
        assert!(DEADLINE.load(std::sync::atomic::Ordering::SeqCst) >= unix_now() + 590);
        extend_deadline(std::time::Duration::from_secs(1));
        assert!(DEADLINE.load(std::sync::atomic::Ordering::SeqCst) >= unix_now() + 590, "an extension never shortens it");
    }

    #[test]
    fn serve_rejects_junk() {
        let dir = TempDir::new();
        let st = Store::new(dir.join("registry.json"));
        for cmd in ["", "sh", "status ../../etc/passwd", "status abc", "request extra", "approve 1234567890abcdef"] {
            assert!(call(&st, cmd, "192.168.1.23 1 22", "{}").is_err(), "{cmd:?} accepted");
        }
        assert!(call(&st, "request", "192.168.1.23 1 22", &"x".repeat(20000)).is_err(), "oversized input accepted");
    }
}
