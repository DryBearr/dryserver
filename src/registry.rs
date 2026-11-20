//! The list of mesh members on the coordinator: pending join requests,
//! approved nodes and the scan report. Nothing joins without an admin
//! approving a request whose pairing code matches the code shown on the new
//! machine.

use std::fmt;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use base64::Engine;
use chrono::TimeDelta;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cidr::parse_ip4;
use crate::err::{Error, Result};
use crate::gotime::{Time, null_default};
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

    /// Turns a pending request into a member with the next free host number
    /// (1 is the coordinator). max_host is the last usable host number.
    pub fn approve(&mut self, id: &str, max_host: u32, now: Time) -> Result<Member> {
        let r = self.request(id)?.clone();
        if r.status != Status::Pending {
            return Err(errf!("request is {}", r.status));
        }
        let host = (2..=max_host).find(|n| !self.members.iter().any(|m| m.host == *n));
        let Some(host) = host else {
            return Err("mesh subnet is full".into());
        };
        let m = Member {
            host,
            name: r.name.clone(),
            wg_key: r.wg_key.clone(),
            ssh_host_key: r.ssh_host_key.clone(),
            lan_ip: r.lan_ip.clone(),
            switch: r.switch,
            approved: now,
            last_seen: now,
        };
        self.members.push(m.clone());
        {
            let q = self.request(id)?;
            q.status = Status::Approved;
            q.host = host;
        }
        // Settle other pending requests: the same machine's duplicates are
        // approved with it; another machine asking under the same name is not.
        for q in &mut self.requests {
            if q.status != Status::Pending {
                continue;
            }
            if q.wg_key == m.wg_key {
                q.status = Status::Approved;
                q.host = host;
            } else if q.name == m.name {
                q.status = Status::Rejected;
            }
        }
        Ok(m)
    }

    pub fn reject(&mut self, id: &str) -> Result<()> {
        let r = self.request(id)?;
        if r.status != Status::Pending {
            return Err(errf!("request is {}", r.status));
        }
        r.status = Status::Rejected;
        Ok(())
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

    /// Revokes a member. Its peers drop it at their next sync.
    pub fn remove(&mut self, name: &str) -> Result<()> {
        match self.members.iter().position(|m| m.name == name) {
            None => Err(errf!("{name} is not a member")),
            Some(i) if self.members[i].host == 1 => Err("the coordinator cannot be removed".into()),
            Some(i) => {
                self.members.remove(i);
                Ok(())
            }
        }
    }

    /// Records a member's current LAN IP and switch link. host identifies
    /// the member by its mesh address, which WireGuard ties to its key.
    pub fn heartbeat(&mut self, host: u32, lan_ip: &str, sw: bool, now: Time) -> Result<()> {
        let Some(m) = self.members.iter_mut().find(|m| m.host == host) else {
            return Err("not a member".into());
        };
        if parse_ip4(lan_ip).is_some() {
            m.lan_ip = lan_ip.to_string();
        }
        m.switch = sw;
        m.last_seen = now;
        Ok(())
    }

    pub fn pending(&self) -> Vec<Request> {
        self.requests.iter().filter(|r| r.status == Status::Pending).cloned().collect()
    }
}

/// The registry file on the coordinator. Its directory is owned by the
/// registry user, which runs serve.
pub const DEFAULT_PATH: &str = "/var/lib/dryserver/registry.json";

/// The registry file, guarded by an exclusive lock.
#[derive(Debug, Clone)]
pub struct Store {
    pub path: PathBuf,
}

impl Store {
    pub fn new(path: impl Into<PathBuf>) -> Store {
        Store { path: path.into() }
    }

    pub fn default_path() -> Store {
        Store::new(DEFAULT_PATH)
    }

    fn sibling(&self, ext: &str) -> PathBuf {
        PathBuf::from(format!("{}{ext}", self.path.display()))
    }

    /// Loads the state, calls f and saves the result atomically while
    /// holding the lock.
    pub fn update<T>(&self, f: impl FnOnce(&mut State) -> Result<T>) -> Result<T> {
        fsx::mkdir_all(fsx::dir(&self.path), 0o700)?;
        let lock_path = self.sibling(".lock");
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|e| Error::from(e).wrap(format!("open {}", lock_path.display())))?;
        fix_owner(&lock_path);
        // SAFETY: flock on a valid open descriptor; the lock is released when
        // `lock` is closed at the end of this function.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut s = self.load()?;
        let out = f(&mut s)?;
        let b = serde_json::to_vec_pretty(&s)?;
        let tmp = self.sibling(".tmp");
        fsx::write_file(&tmp, b, 0o600)?;
        fix_owner(&tmp);
        fsx::rename(&tmp, &self.path)?;
        drop(lock);
        Ok(out)
    }

    /// A snapshot of the state.
    pub fn read(&self) -> Result<State> {
        self.update(|s| Ok(s.clone()))
    }

    fn load(&self) -> Result<State> {
        match std::fs::read(&self.path) {
            Ok(b) => Ok(serde_json::from_slice(&b)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(Error::from(e).wrap(format!("open {}", self.path.display()))),
        }
    }
}

/// Hands a file written by root back to the owner of its directory, so the
/// registry user can keep writing it.
fn fix_owner(path: &Path) {
    if !fsx::is_root() {
        return;
    }
    if let Ok(st) = std::fs::metadata(fsx::dir(path)) {
        let _ = std::os::unix::fs::chown(path, Some(st.uid()), Some(st.gid()));
    }
}

// ---- scan report ----

/// Reads `arp-scan --plain` output: "IP<tab>MAC<tab>vendor".
pub fn parse_arp_scan(out: &str) -> Vec<Device> {
    let mut devs: Vec<Device> = Vec::new();
    for line in out.lines() {
        let f: Vec<&str> = line.splitn(3, '\t').collect();
        if f.len() < 2 || f[0].parse::<std::net::IpAddr>().is_err() {
            continue;
        }
        let mut d = Device { ip: f[0].to_string(), mac: f[1].to_lowercase(), ..Device::default() };
        if f.len() == 3 {
            d.vendor = f[2].trim().to_string();
        }
        if !devs.iter().any(|x| x.ip == d.ip) {
            devs.push(d);
        }
    }
    devs
}

/// Keeps the devices whose address belongs to no member. known holds every
/// member address (LAN and switch).
pub fn unknown(found: &[Device], known: &[String], now: Time) -> Vec<Device> {
    found.iter().filter(|d| !known.contains(&d.ip)).map(|d| Device { seen: now, ..d.clone() }).collect()
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
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct HeartbeatIn {
    lan_ip: String,
    switch: bool,
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

fn valid_id(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Handles one call from the SSH forced command. cmdline is
/// SSH_ORIGINAL_COMMAND, client is SSH_CLIENT ("ip port port").
///
///   request      stdin: Request JSON        -> {"id": ...}         (any source)
///   status ID                               -> StatusReply         (any source)
///   peers        stdin: {"lan_ip","switch"} -> {"members": [...], "signed": ...}  (mesh members only)
///   admin        stdin: signed admin request -> AdminState          (holder of the signing key)
///   publish      stdin: signed member list   -> {"version": N}      (holder of the signing key)
///
/// The key that reaches this command is on every server and on the USB
/// stick, so it proves nothing. admin and publish are allowed by the
/// signature on their input alone.
#[allow(clippy::too_many_arguments)]
pub fn serve(
    st: &Store,
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
                let mut reply = StatusReply { status: r.status, host: r.host, coordinator: None };
                if r.status == Status::Approved {
                    reply.coordinator = s.members.iter().find(|m| m.host == 1).cloned();
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
            let hb: HeartbeatIn = decode_first(input).ok_or_else(|| Error::new("bad heartbeat JSON"))?;
            let (members, signed) = st.update(|s| {
                s.heartbeat(host, &hb.lan_ip, hb.switch, now)?;
                Ok((s.members.clone(), s.signed.clone()))
            })?;
            send(out, &serde_json::json!({ "members": members, "signed": signed }))
        }
        ("admin", 1) => {
            let req: Envelope = decode_first(input).ok_or_else(|| Error::new("bad admin request"))?;
            signed::open_admin(verifier, &req, "state", now.0.timestamp())?;
            let reply = st.update(|s| {
                s.prune(now);
                Ok(AdminState {
                    members: s.members.clone(),
                    requests: s.pending(),
                    unknown: s.unknown.clone(),
                    scanned: s.scanned,
                    signed: s.signed.clone(),
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
    fn approve_flow() {
        let mut s = State { members: vec![Member { wg_key: wg_key(), ..member(1, "coord") }], ..State::default() };
        let r = req("node-a");
        let id = s.add_request(r.clone(), COORD_KEY, t0()).unwrap();
        let p = s.pending();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].code, pairing_code(&r.wg_key, &r.ssh_host_key, COORD_KEY));
        let m = s.approve(&id, 254, t0()).unwrap();
        assert_eq!(m.host, 2);
        let st = s.request_status(&id, t0()).unwrap();
        assert_eq!((st.status, st.host), (Status::Approved, 2));
        assert!(s.approve(&id, 254, t0()).is_err(), "double approve");

        // Same name again is refused; after removal the host number is reused.
        assert!(s.add_request(req("node-a"), COORD_KEY, t0()).is_err(), "duplicate member name accepted");
        s.remove("node-a").unwrap();
        let id2 = s.add_request(req("node-b"), COORD_KEY, t0()).unwrap();
        assert_eq!(s.approve(&id2, 254, t0()).unwrap().host, 2, "freed host number not reused");
        assert!(s.remove("coord").is_err(), "coordinator removed");
    }

    #[test]
    fn reject_and_expiry() {
        let mut s = State::default();
        let id = s.add_request(req("node-x"), COORD_KEY, t0()).unwrap();
        s.reject(&id).unwrap();
        assert_eq!(s.request_status(&id, t0()).unwrap().status, Status::Rejected);
        assert!(s.request_status(&id, t0().add(TimeDelta::hours(2))).is_err(), "request did not expire");
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
    fn subnet_full() {
        let mut s = State { members: vec![member(1, "coord")], ..State::default() };
        // max_host 2: room for the coordinator and one node.
        let id = s.add_request(req("a"), COORD_KEY, t0()).unwrap();
        s.approve(&id, 2, t0()).unwrap();
        let id = s.add_request(req("b"), COORD_KEY, t0()).unwrap();
        assert!(s.approve(&id, 2, t0()).is_err(), "full subnet not detected");
    }

    #[test]
    fn heartbeat_updates_member() {
        let mut s =
            State { members: vec![member(1, "coord"), Member { lan_ip: "192.168.1.5".into(), ..member(2, "a") }], ..State::default() };
        s.heartbeat(2, "192.168.1.77", true, t0()).unwrap();
        let m = &s.members[1];
        assert_eq!(m.lan_ip, "192.168.1.77");
        assert!(m.switch);
        assert_eq!(m.last_seen, t0());
        assert!(s.heartbeat(9, "1.2.3.4", false, t0()).is_err(), "unknown host accepted");
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

    #[test]
    fn approve_settles_duplicates() {
        let r = req("node-a");
        let dup = |id: &str, wg: String| Request { id: id.into(), wg_key: wg, status: Status::Pending, created: t0(), ..r.clone() };
        let mut s =
            State { requests: vec![dup("a1", r.wg_key.clone()), dup("a2", r.wg_key.clone()), dup("x", wg_key())], ..State::default() };
        s.approve("a1", 254, t0()).unwrap();
        let st = s.request_status("a2", t0()).unwrap();
        assert_eq!((st.status, st.host), (Status::Approved, 2), "duplicate from the same machine");
        assert_eq!(s.request_status("x", t0()).unwrap().status, Status::Rejected, "impostor");
        assert!(s.pending().is_empty(), "requests left pending");
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
        let mut out = Vec::new();
        serve(st, &mesh, &ADMIN, COORD_KEY, cmd, client, &mut stdin.as_bytes(), &mut out, t0())?;
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
        st.update(|s| s.approve(&id, 254, t0())).unwrap();
        let out = call(&st, &format!("status {id}"), "192.168.1.23 5000 22", "").unwrap();
        let sr: StatusReply = serde_json::from_str(&out).unwrap();
        assert_eq!(sr.status, Status::Approved);
        assert_eq!(sr.host, 2);
        assert_eq!(sr.coordinator.unwrap().lan_ip, "192.168.1.50");

        // peers: only from the member's mesh address.
        assert!(call(&st, "peers", "192.168.1.23 5000 22", r#"{"lan_ip":"192.168.1.23"}"#).is_err(), "peers answered over the LAN");
        assert!(call(&st, "peers", "10.66.0.9 5000 22", "{}").is_err(), "peers answered to a non-member");
        let out = call(&st, "peers", "10.66.0.2 5000 22", r#"{"lan_ip":"192.168.1.99","switch":true}"#).unwrap();
        assert!(out.contains("node-a") && out.contains("192.168.1.99"), "peers {out:?}");
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
