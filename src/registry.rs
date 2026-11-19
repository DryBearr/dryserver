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
use crate::{errf, fsx};

pub const MAX_PENDING: usize = 20;

pub fn request_ttl() -> TimeDelta {
    TimeDelta::hours(1)
}

fn is_zero(n: &u32) -> bool {
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

/// Checks untrusted join-request fields strictly.
pub fn validate_request(r: &Request) -> Result<()> {
    if !valid_name(&r.name) {
        return Err("bad hostname".into());
    }
    match base64::engine::general_purpose::STANDARD.decode(&r.wg_key) {
        Ok(b) if b.len() == 32 => {}
        _ => return Err("bad WireGuard key".into()),
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

/// Describes the mesh subnet so serve can tell members by address.
pub trait Mesh {
    /// The member host number for a mesh IP, or 0.
    fn host_of(&self, ip: Ipv4Addr) -> u32;
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
    let mut buf = Vec::new();
    input.take(MAX_INPUT).read_to_end(&mut buf).ok()?;
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
///   peers        stdin: {"lan_ip","switch"} -> {"members": [...]}  (mesh members only)
#[allow(clippy::too_many_arguments)]
pub fn serve(
    st: &Store,
    mesh: &dyn Mesh,
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
            let members = st.update(|s| {
                s.heartbeat(host, &hb.lan_ip, hb.switch, now)?;
                Ok(s.members.clone())
            })?;
            send(out, &serde_json::json!({ "members": members }))
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
    }

    fn call(st: &Store, cmd: &str, client: &str, stdin: &str) -> Result<String> {
        let mesh = FakeMesh(HashMap::from([("10.66.0.2".to_string(), 2)]));
        let mut out = Vec::new();
        serve(st, &mesh, COORD_KEY, cmd, client, &mut stdin.as_bytes(), &mut out, t0())?;
        Ok(String::from_utf8(out).unwrap())
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
