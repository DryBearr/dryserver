//! The public entrance on a rented VPS: a relay that passes public TCP and
//! UDP ports to healthy machines at home. The machines dial out to the
//! VPS over WireGuard, so the backends here are mesh addresses. TLS ends
//! in the cluster: the relay never looks at what it carries, it copies
//! bytes. It faces the internet, so its limits matter more than its
//! features.
//!
//! Choices, and why:
//! - Backend choice: rendezvous hashing on the client's address with a
//!   key drawn at start. One client stays on one machine across its
//!   connections and UDP flows (a QUIC client whose NAT changes its port
//!   still reaches the machine that knows it); when a machine goes down
//!   only its clients move, and come back when it does. Outsiders cannot
//!   predict which machine they land on. The cost: one heavy client is
//!   not spread over machines, which a home cluster does not need.
//! - Per-address limits count an IPv6 client by its /64: one home or
//!   server gets a whole /64, and counting single addresses there would
//!   let it open 2^64 "clients". IPv4 addresses seen through a dual-stack
//!   socket (::ffff:a.b.c.d) count as the IPv4 address.
//! - Refusals (relay full, address over its share, no healthy machine)
//!   close the connection at once with a reset, before a thread or a
//!   backend connection is spent on it.
//! - Health: a TCP connect to each backend every few seconds; two failures
//!   in a row mark it down, two successes up. Before its first check a
//!   backend counts as down, and the first result decides. UDP has no
//!   handshake to check, so every UDP backend names a TCP check_port on
//!   the same machine (its ingress, say): the relay sees whether the
//!   machine is up, not whether the UDP service answers.
//! - UDP gets no PROXY header (there is no stream to put it in front of):
//!   the backend sees the relay's mesh address and one source port per
//!   client session.
//! - Threads: one per TCP listener (accepting), one per TCP connection
//!   (copying both ways with poll), one per UDP listener (an event loop
//!   over all its sessions), one per health target. Stacks are small and
//!   the count is bounded by tcp_total. Each TCP connection holds two
//!   buffers of BUF bytes. A side is read only when its buffer towards
//!   the other side is empty, so a peer that never reads stops the other
//!   side from being read and TCP flow control pushes back on it: memory
//!   does not grow with what a slow or hostile peer sends.
//! - Shutdown (the Ctx, or stop): listeners close at once, UDP sessions
//!   end, TCP connections end as soon as they are quiet for a moment and
//!   at the latest after drain_ms, and every thread is joined.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::hash::{BuildHasher, RandomState};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::bail;
use crate::ctx::Ctx;
use crate::err::{Error, Result};
use crate::runner::LogFn;

/// Stack of every relay thread: the copy loops keep their buffers on the
/// heap and need little.
const STACK: usize = 128 << 10;
/// Bytes buffered per direction of a TCP connection.
const BUF: usize = 16 << 10;
/// How often waiting loops look at the stop flag.
const TICK: Duration = Duration::from_millis(200);
/// While shutting down, a TCP connection this long without traffic counts
/// as idle and ends.
const DRAIN_QUIET: Duration = Duration::from_millis(250);
/// The most datagrams or connections taken from one socket in a row, so
/// one busy client cannot starve the others.
const BURST: usize = 64;
pub const MAX_CONFIG: u64 = 64 << 10;
pub const MAX_LISTENERS: usize = 64;
pub const MAX_BACKENDS: usize = 32;
const MAX_CONNS: usize = 65536;
/// The largest UDP payload over IPv4.
pub const MAX_DATAGRAM: usize = 65507;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn name(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

/// What the relay passes where. Unknown fields are refused: a typo in a
/// limit must not silently leave the default in place.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listeners: Vec<Listener>,
    #[serde(default)]
    pub limits: Limits,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    pub protocol: Protocol,
    /// The public port.
    pub port: u16,
    /// The address to listen on. Default: every address, IPv6 and IPv4
    /// ([::], which takes IPv4 too on Linux), or IPv4 only on a machine
    /// without IPv6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind: Option<IpAddr>,
    pub backends: Vec<Backend>,
    /// TCP only: tell the backend who the client is with a PROXY protocol
    /// v2 header before the client's bytes.
    #[serde(default)]
    pub proxy_protocol: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backend {
    pub addr: SocketAddr,
    /// The TCP port on the same machine that the health check connects
    /// to. Required for UDP; for TCP it defaults to the backend's own
    /// port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_port: Option<u16>,
}

impl Backend {
    fn check_addr(&self) -> SocketAddr {
        SocketAddr::new(self.addr.ip(), self.check_port.unwrap_or(self.addr.port()))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Open TCP connections from one client address (IPv6: one /64).
    pub tcp_per_ip: usize,
    /// Open TCP connections in all.
    pub tcp_total: usize,
    pub udp_per_ip: usize,
    pub udp_sessions: usize,
    pub connect_timeout_ms: u64,
    /// A TCP connection with no bytes moving either way this long ends.
    pub tcp_idle_ms: u64,
    pub udp_idle_ms: u64,
    /// Larger datagrams are dropped, both ways.
    pub datagram_max: usize,
    pub check_every_ms: u64,
    /// At shutdown, how long busy TCP connections may go on.
    pub drain_ms: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            tcp_per_ip: 64,
            tcp_total: 4096,
            udp_per_ip: 32,
            udp_sessions: 4096,
            connect_timeout_ms: 3000,
            tcp_idle_ms: 5 * 60 * 1000,
            udp_idle_ms: 60 * 1000,
            datagram_max: 1500,
            check_every_ms: 2000,
            drain_ms: 3000,
        }
    }
}

fn in_range<T: PartialOrd + std::fmt::Display>(name: &str, v: T, lo: T, hi: T) -> Result<()> {
    if v < lo || v > hi {
        bail!("relay limit {name} is {v}, not between {lo} and {hi}");
    }
    Ok(())
}

/// A backend address the relay can connect to.
fn usable(ip: IpAddr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast() && ip != IpAddr::V4(Ipv4Addr::BROADCAST)
}

impl Config {
    /// Reads and checks a config file of at most MAX_CONFIG bytes.
    pub fn load(path: &Path) -> Result<Config> {
        let f = File::open(path).map_err(|e| Error::from(e).wrap(format!("open {}", path.display())))?;
        let mut text = String::new();
        f.take(MAX_CONFIG + 1).read_to_string(&mut text).map_err(|e| Error::from(e).wrap(format!("read {}", path.display())))?;
        Config::parse(&text).map_err(|e| e.wrap(path.display()))
    }

    pub fn parse(text: &str) -> Result<Config> {
        if text.len() as u64 > MAX_CONFIG {
            bail!("the relay config is more than {MAX_CONFIG} bytes");
        }
        let c: Config = serde_json::from_str(text).map_err(|e| Error::from(e).wrap("relay config"))?;
        c.validate()?;
        Ok(c)
    }

    pub fn validate(&self) -> Result<()> {
        self.check(false)
    }

    /// any_port lets tests listen on port 0 (a port the OS picks).
    fn check(&self, any_port: bool) -> Result<()> {
        let l = &self.limits;
        in_range("tcp_total", l.tcp_total, 1, MAX_CONNS)?;
        in_range("tcp_per_ip", l.tcp_per_ip, 1, l.tcp_total)?;
        in_range("udp_sessions", l.udp_sessions, 1, MAX_CONNS)?;
        in_range("udp_per_ip", l.udp_per_ip, 1, l.udp_sessions)?;
        in_range("connect_timeout_ms", l.connect_timeout_ms, 1, 60_000)?;
        in_range("tcp_idle_ms", l.tcp_idle_ms, 1, 24 * 3600 * 1000)?;
        in_range("udp_idle_ms", l.udp_idle_ms, 1, 3600 * 1000)?;
        in_range("datagram_max", l.datagram_max, 1, MAX_DATAGRAM)?;
        in_range("check_every_ms", l.check_every_ms, 10, 600_000)?;
        in_range("drain_ms", l.drain_ms, 0, 600_000)?;
        if self.listeners.is_empty() || self.listeners.len() > MAX_LISTENERS {
            bail!("the relay needs 1 to {MAX_LISTENERS} listeners, not {}", self.listeners.len());
        }
        let mut ports = HashSet::new();
        for (i, li) in self.listeners.iter().enumerate() {
            let at = format!("relay listener {} ({} port {})", i + 1, li.protocol.name(), li.port);
            if li.port == 0 && !any_port {
                bail!("{at}: no port");
            }
            if li.port != 0 && !ports.insert((li.protocol, li.port)) {
                bail!("{at}: the port is used twice");
            }
            if let Some(b) = li.bind
                && b.is_multicast()
            {
                bail!("{at}: cannot listen on {b}");
            }
            if li.proxy_protocol && li.protocol == Protocol::Udp {
                bail!("{at}: the PROXY protocol is for TCP only");
            }
            if li.backends.is_empty() || li.backends.len() > MAX_BACKENDS {
                bail!("{at}: needs 1 to {MAX_BACKENDS} backends, not {}", li.backends.len());
            }
            let mut seen = HashSet::new();
            for b in &li.backends {
                let a = b.addr;
                if !usable(a.ip()) || a.port() == 0 {
                    bail!("{at}: cannot pass traffic to {a}");
                }
                if let SocketAddr::V6(v6) = a
                    && (v6.scope_id() != 0 || v6.flowinfo() != 0)
                {
                    bail!("{at}: backend {a} has a scope or flow label");
                }
                if !seen.insert(a) {
                    bail!("{at}: backend {a} is listed twice");
                }
                match (li.protocol, b.check_port) {
                    (_, Some(0)) => bail!("{at}: backend {a} has check port 0"),
                    (Protocol::Udp, None) => {
                        bail!("{at}: UDP backend {a} needs a check_port: the relay can only see a machine's health over TCP")
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
}

/// Who counts as one client for the per-address limits and for picking a
/// backend: an IPv4 address, or an IPv6 /64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientKey {
    V4(Ipv4Addr),
    V6([u8; 8]),
}

pub fn client_key(ip: IpAddr) -> ClientKey {
    match v4(ip) {
        Some(a) => ClientKey::V4(a),
        None => {
            let o = v6(ip).octets();
            ClientKey::V6([o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]])
        }
    }
}

fn v4(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(a) => Some(a),
        IpAddr::V6(a) => a.to_ipv4_mapped(),
    }
}

fn v6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(a) => a.to_ipv6_mapped(),
        IpAddr::V6(a) => a,
    }
}

/// The PROXY protocol v2 header (haproxy.org, proxy-protocol.txt section
/// 2.2) for a TCP connection from src to dst, where dst is the address the
/// client connected to. Both IPv4 (also as ::ffff:a.b.c.d): TCP over
/// IPv4; otherwise TCP over IPv6, with an IPv4 side written as mapped.
pub fn proxy_v2(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    // The fixed signature, then version 2 with the PROXY command.
    let mut h = vec![0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21];
    match (v4(src.ip()), v4(dst.ip())) {
        (Some(s), Some(d)) => {
            h.push(0x11); // AF_INET, STREAM
            h.extend(12u16.to_be_bytes());
            h.extend(s.octets());
            h.extend(d.octets());
        }
        _ => {
            h.push(0x21); // AF_INET6, STREAM
            h.extend(36u16.to_be_bytes());
            h.extend(v6(src.ip()).octets());
            h.extend(v6(dst.ip()).octets());
        }
    }
    h.extend(src.port().to_be_bytes());
    h.extend(dst.port().to_be_bytes());
    h
}

/// What the relay refused or dropped, for the monitor.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    /// TCP connections refused because the relay was full.
    pub tcp_full: u64,
    /// Refused because the client's address had its share.
    pub tcp_ip_full: u64,
    /// Refused because no backend was healthy or none took the connection.
    pub tcp_no_backend: u64,
    /// Backend connections that failed (another one was tried next).
    pub tcp_connect_failed: u64,
    pub accept_errors: u64,
    pub udp_full: u64,
    pub udp_ip_full: u64,
    pub udp_no_backend: u64,
    pub udp_too_big: u64,
}

/// Open connections or sessions, in all and per client.
struct Gate {
    per_ip: usize,
    total: usize,
    open: Mutex<(usize, HashMap<ClientKey, usize>)>,
}

enum Full {
    Total,
    Ip,
}

/// One admitted connection or session; dropping it frees its place.
struct Ticket {
    gate: Arc<Gate>,
    key: ClientKey,
}

impl Gate {
    fn new(per_ip: usize, total: usize) -> Arc<Gate> {
        Arc::new(Gate { per_ip, total, open: Mutex::new((0, HashMap::new())) })
    }

    fn admit(self: &Arc<Self>, key: ClientKey) -> std::result::Result<Ticket, Full> {
        let mut g = self.open.lock().unwrap();
        if g.0 >= self.total {
            return Err(Full::Total);
        }
        let n = g.1.entry(key).or_insert(0);
        if *n >= self.per_ip {
            return Err(Full::Ip);
        }
        *n += 1;
        g.0 += 1;
        Ok(Ticket { gate: self.clone(), key })
    }

    fn count(&self) -> usize {
        self.open.lock().unwrap().0
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        let mut g = self.gate.open.lock().unwrap();
        g.0 -= 1;
        // Entries go when they reach zero, so the map never holds more
        // clients than there are open connections.
        if let Entry::Occupied(mut e) = g.1.entry(self.key) {
            *e.get_mut() -= 1;
            if *e.get() == 0 {
                e.remove();
            }
        }
    }
}

/// A backend and its health, shared by every listener that uses the same
/// check address.
struct Target {
    addr: SocketAddr,
    up: Arc<AtomicBool>,
}

impl Target {
    fn up(&self) -> bool {
        self.up.load(Ordering::SeqCst)
    }
}

struct Route {
    backends: Vec<Target>,
    proxy: bool,
}

struct Shared {
    limits: Limits,
    seed: RandomState,
    tcp: Arc<Gate>,
    udp: Arc<Gate>,
    counts: Mutex<Counts>,
    live: Arc<AtomicUsize>,
    log: LogFn,
}

impl Shared {
    fn count(&self, f: impl FnOnce(&mut Counts)) {
        f(&mut self.counts.lock().unwrap());
    }

    fn ms(&self, ms: u64) -> Duration {
        Duration::from_millis(ms)
    }
}

/// Backends in the order this client tries them: highest weight first
/// (rendezvous hashing).
fn rank(seed: &RandomState, key: ClientKey, backends: &[Target]) -> Vec<usize> {
    let mut w: Vec<(u64, usize)> = backends.iter().enumerate().map(|(i, b)| (seed.hash_one((key, b.addr)), i)).collect();
    w.sort_unstable_by(|a, b| b.cmp(a));
    w.into_iter().map(|(_, i)| i).collect()
}

/// The caller's context, or the relay's own stop.
#[derive(Clone)]
struct Stop {
    outer: Ctx,
    own: Ctx,
}

impl Stop {
    fn done(&self) -> bool {
        self.outer.done() || self.own.done()
    }

    /// Sleeps d; false when stopped meanwhile.
    fn sleep(&self, d: Duration) -> bool {
        let end = Instant::now() + d;
        loop {
            if self.done() {
                return false;
            }
            let now = Instant::now();
            if now >= end {
                return true;
            }
            thread::sleep((end - now).min(Duration::from_millis(50)));
        }
    }
}

/// Starts a thread with a small stack, counted in live while it runs.
fn spawn(live: &Arc<AtomicUsize>, name: &str, f: impl FnOnce() + Send + 'static) -> io::Result<JoinHandle<()>> {
    struct Live(Arc<AtomicUsize>);
    impl Drop for Live {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    live.fetch_add(1, Ordering::SeqCst);
    // Moved into the thread: if the thread cannot start, the closure is
    // dropped and the count goes back down with it.
    let guard = Live(live.clone());
    thread::Builder::new().name(name.into()).stack_size(STACK).spawn(move || {
        let _guard = guard;
        f()
    })
}

fn pfd(fd: RawFd, events: libc::c_short) -> libc::pollfd {
    // A negative descriptor is skipped by poll: nothing to wait for there.
    libc::pollfd { fd: if events == 0 { -1 } else { fd }, events, revents: 0 }
}

fn poll(fds: &mut [libc::pollfd], wait: Duration) -> io::Result<usize> {
    // Rounded up, so a wait shorter than a millisecond does not spin.
    let ms = (wait.as_millis() + 1).min(i32::MAX as u128) as libc::c_int;
    // SAFETY: fds is a valid, exclusively borrowed slice of pollfd for the
    // whole call, and its length is passed with it.
    let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
    if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
}

/// Closes a connection with a reset: no lingering state on the relay for
/// a connection it refuses.
fn reset(s: TcpStream) {
    let l = libc::linger { l_onoff: 1, l_linger: 0 };
    // SAFETY: a valid socket descriptor and a pointer to a linger value of
    // the size passed.
    unsafe {
        libc::setsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&l as *const libc::linger).cast(),
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        );
    }
}

/// The descriptors the limits can need, with room for the rest.
fn fd_need(cfg: &Config) -> u64 {
    let l = &cfg.limits;
    let has = |p| cfg.listeners.iter().any(|li| li.protocol == p);
    let tcp = if has(Protocol::Tcp) { 2 * l.tcp_total } else { 0 };
    let udp = if has(Protocol::Udp) { l.udp_sessions } else { 0 };
    let checks: usize = cfg.listeners.iter().map(|li| li.backends.len()).sum();
    (tcp + udp + cfg.listeners.len() + checks + 64) as u64
}

/// Raises the open-file limit to what the relay's limits need, so it
/// refuses clients by its own rules and not by running out of
/// descriptors half way through an accept.
fn raise_fd_limit(need: u64) -> Result<()> {
    let mut r = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: r is a valid rlimit to fill.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut r) } != 0 {
        return Err(Error::from(io::Error::last_os_error()).wrap("getrlimit"));
    }
    if r.rlim_cur >= need as libc::rlim_t {
        return Ok(());
    }
    if r.rlim_max < need as libc::rlim_t {
        bail!("the relay's limits need {need} open files, but this system allows {}: raise LimitNOFILE or lower the limits", r.rlim_max);
    }
    r.rlim_cur = need as libc::rlim_t;
    // SAFETY: r is a valid rlimit, below the hard limit.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &r) } != 0 {
        return Err(Error::from(io::Error::last_os_error()).wrap("setrlimit"));
    }
    Ok(())
}

enum Sock {
    Tcp(TcpListener),
    Udp(UdpSocket),
}

/// Opens a listener. std sets SO_REUSEADDR on TCP listeners (a restarted
/// relay gets its port back while old connections are in TIME_WAIT) and
/// never SO_REUSEPORT (no other process can share the port).
fn bind(l: &Listener) -> Result<(Sock, SocketAddr)> {
    let tries = match l.bind {
        Some(ip) => vec![SocketAddr::new(ip, l.port)],
        None => vec![SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), l.port), SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), l.port)],
    };
    let mut last = None;
    for a in tries {
        let r = match l.protocol {
            Protocol::Tcp => TcpListener::bind(a).and_then(|s| Ok((s.local_addr()?, Sock::Tcp(s)))),
            Protocol::Udp => UdpSocket::bind(a).and_then(|s| Ok((s.local_addr()?, Sock::Udp(s)))),
        };
        match r {
            Ok((addr, s)) => return Ok((s, addr)),
            // Only a machine without IPv6 falls back to IPv4; a port in use
            // does not.
            Err(e) if l.bind.is_none() && matches!(e.raw_os_error(), Some(libc::EAFNOSUPPORT | libc::EADDRNOTAVAIL)) => last = Some(e),
            Err(e) => return Err(Error::from(e).wrap(format!("listen on {} {a}", l.protocol.name()))),
        }
    }
    Err(last.map(Error::from).unwrap_or_else(|| Error::new("no address")).wrap(format!("listen on {} port {}", l.protocol.name(), l.port)))
}

/// A running relay. Dropping it stops it.
pub struct Relay {
    stop: Stop,
    shared: Arc<Shared>,
    routes: Vec<Arc<Route>>,
    addrs: Vec<(Protocol, SocketAddr)>,
    threads: Vec<JoinHandle<()>>,
}

impl Relay {
    /// Checks cfg, opens every listener and starts. A port that cannot be
    /// opened fails the start before any thread runs. The relay runs until
    /// ctx is done or it is stopped.
    pub fn start(ctx: &Ctx, cfg: &Config, log: LogFn) -> Result<Relay> {
        cfg.validate()?;
        Relay::launch(ctx, cfg, log)
    }

    fn launch(ctx: &Ctx, cfg: &Config, log: LogFn) -> Result<Relay> {
        cfg.check(true)?;
        raise_fd_limit(fd_need(cfg))?;
        let mut bound = Vec::new();
        for l in &cfg.listeners {
            bound.push(bind(l)?);
        }
        let mut health: HashMap<SocketAddr, Arc<AtomicBool>> = HashMap::new();
        let routes: Vec<Arc<Route>> = cfg
            .listeners
            .iter()
            .map(|l| {
                let backends =
                    l.backends.iter().map(|b| Target { addr: b.addr, up: health.entry(b.check_addr()).or_default().clone() }).collect();
                Arc::new(Route { backends, proxy: l.proxy_protocol })
            })
            .collect();
        let lim = cfg.limits.clone();
        let shared = Arc::new(Shared {
            tcp: Gate::new(lim.tcp_per_ip, lim.tcp_total),
            udp: Gate::new(lim.udp_per_ip, lim.udp_sessions),
            limits: lim,
            seed: RandomState::new(),
            counts: Mutex::new(Counts::default()),
            live: Arc::new(AtomicUsize::new(0)),
            log,
        });
        let mut relay = Relay {
            stop: Stop { outer: ctx.clone(), own: Ctx::new() },
            shared: shared.clone(),
            routes: routes.clone(),
            addrs: cfg.listeners.iter().zip(&bound).map(|(l, (_, a))| (l.protocol, *a)).collect(),
            threads: Vec::new(),
        };
        for (target, up) in health {
            let (stop, sh) = (relay.stop.clone(), shared.clone());
            relay.started(spawn(&shared.live, "relay-check", move || check_loop(&stop, &sh, target, &up)))?;
        }
        for (route, (sock, _)) in routes.into_iter().zip(bound) {
            let (stop, sh) = (relay.stop.clone(), shared.clone());
            let h = match sock {
                Sock::Tcp(l) => spawn(&shared.live, "relay-accept", move || accept_loop(&stop, &sh, &route, l)),
                Sock::Udp(u) => spawn(&shared.live, "relay-udp", move || udp_loop(&stop, &sh, &route, u)),
            };
            relay.started(h)?;
        }
        (shared.log)(&format!(
            "relay: listening on {}",
            relay.addrs.iter().map(|(p, a)| format!("{} {a}", p.name())).collect::<Vec<_>>().join(", ")
        ));
        Ok(relay)
    }

    /// Keeps a started thread; when one cannot start, stops the others
    /// (dropping the relay does) and fails.
    fn started(&mut self, h: io::Result<JoinHandle<()>>) -> Result<()> {
        match h {
            Ok(h) => {
                self.threads.push(h);
                Ok(())
            }
            Err(e) => Err(Error::from(e).wrap("start a relay thread")),
        }
    }

    /// The addresses listened on, in config order (with the ports the OS
    /// chose for port 0).
    pub fn addrs(&self) -> &[(Protocol, SocketAddr)] {
        &self.addrs
    }

    pub fn counts(&self) -> Counts {
        *self.shared.counts.lock().unwrap()
    }

    /// Open TCP connections and UDP sessions.
    pub fn open(&self) -> (usize, usize) {
        (self.shared.tcp.count(), self.shared.udp.count())
    }

    /// Whether a backend counts as healthy; None for an unknown address.
    pub fn up(&self, backend: SocketAddr) -> Option<bool> {
        self.routes.iter().flat_map(|r| &r.backends).find(|t| t.addr == backend).map(Target::up)
    }

    /// Relay threads running now.
    pub fn threads(&self) -> usize {
        self.shared.live.load(Ordering::SeqCst)
    }

    /// Stops: listeners close, sessions and connections end (busy ones
    /// after at most drain_ms), and every thread is joined.
    pub fn stop(mut self) {
        self.stop.own.cancel();
        self.join();
    }

    /// Waits until the context given to start is done and everything has
    /// ended.
    pub fn wait(mut self) {
        self.join();
    }

    fn join(&mut self) {
        for h in std::mem::take(&mut self.threads) {
            let _ = h.join();
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.own.cancel();
        self.join();
    }
}

fn check_loop(stop: &Stop, sh: &Shared, target: SocketAddr, up: &AtomicBool) {
    let (every, timeout) = (sh.ms(sh.limits.check_every_ms), sh.ms(sh.limits.connect_timeout_ms));
    let mut known = false;
    // Results in a row that disagree with the current state.
    let mut streak = 0;
    loop {
        let ok = TcpStream::connect_timeout(&target, timeout).is_ok();
        let flip = if !known {
            known = true;
            true
        } else if ok != up.load(Ordering::SeqCst) {
            streak += 1;
            streak >= 2
        } else {
            streak = 0;
            false
        };
        if flip {
            streak = 0;
            up.store(ok, Ordering::SeqCst);
            (sh.log)(&format!("relay: backend {target} is {}", if ok { "up" } else { "down" }));
        }
        if !stop.sleep(every) {
            return;
        }
    }
}

fn accept_loop(stop: &Stop, sh: &Arc<Shared>, route: &Arc<Route>, l: TcpListener) {
    let mut conns: Vec<JoinHandle<()>> = Vec::new();
    if l.set_nonblocking(true).is_ok() {
        while !stop.done() {
            let mut fds = [pfd(l.as_raw_fd(), libc::POLLIN)];
            if poll(&mut fds, TICK).unwrap_or(0) > 0 {
                for _ in 0..BURST {
                    match l.accept() {
                        Ok((s, peer)) => conns.extend(admit(stop, sh, route, s, peer)),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            sh.count(|c| c.accept_errors += 1);
                            // Out of descriptors or memory: the listener
                            // stays readable, so wait instead of spinning.
                            if matches!(e.raw_os_error(), Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)) {
                                thread::sleep(Duration::from_millis(50));
                                break;
                            }
                        }
                    }
                }
            }
            conns.retain(|h| !h.is_finished());
        }
    }
    // No new connections from here on; the open ones drain.
    drop(l);
    for h in conns {
        let _ = h.join();
    }
}

/// Lets a new connection in, or refuses it at once.
fn admit(stop: &Stop, sh: &Arc<Shared>, route: &Arc<Route>, s: TcpStream, peer: SocketAddr) -> Option<JoinHandle<()>> {
    if !route.backends.iter().any(Target::up) {
        sh.count(|c| c.tcp_no_backend += 1);
        reset(s);
        return None;
    }
    let ticket = match sh.tcp.admit(client_key(peer.ip())) {
        Ok(t) => t,
        Err(full) => {
            sh.count(|c| match full {
                Full::Total => c.tcp_full += 1,
                Full::Ip => c.tcp_ip_full += 1,
            });
            reset(s);
            return None;
        }
    };
    let (stop, sh2, route) = (stop.clone(), sh.clone(), route.clone());
    // If the thread cannot start, the closure drops the connection and the
    // ticket with it.
    spawn(&sh.live, "relay-tcp", move || {
        let _ticket = ticket;
        serve(&stop, &sh2, &route, s, peer);
    })
    .ok()
}

/// One TCP connection: a backend, the PROXY header, then bytes both ways.
fn serve(stop: &Stop, sh: &Shared, route: &Route, client: TcpStream, peer: SocketAddr) {
    let lim = &sh.limits;
    let timeout = sh.ms(lim.connect_timeout_ms);
    let mut backend = None;
    for i in rank(&sh.seed, client_key(peer.ip()), &route.backends) {
        let t = &route.backends[i];
        if stop.done() {
            break;
        }
        if !t.up() {
            continue;
        }
        match TcpStream::connect_timeout(&t.addr, timeout) {
            Ok(b) => {
                backend = Some(b);
                break;
            }
            Err(_) => sh.count(|c| c.tcp_connect_failed += 1),
        }
    }
    let Some(b) = backend else {
        sh.count(|c| c.tcp_no_backend += 1);
        return reset(client);
    };
    if route.proxy {
        let Ok(dst) = client.local_addr() else { return reset(client) };
        // A few dozen bytes into an empty send buffer: this does not wait
        // on the backend, and the timeout covers the case where it would.
        if b.set_write_timeout(Some(timeout)).is_err() || (&b).write_all(&proxy_v2(peer, dst)).is_err() {
            return reset(client);
        }
    }
    let _ = client.set_nodelay(true);
    let _ = b.set_nodelay(true);
    pump(stop, &client, &b, sh.ms(lim.tcp_idle_ms), sh.ms(lim.drain_ms));
}

/// One direction of a connection: bytes read from one side, not yet
/// written to the other.
struct Half {
    buf: Vec<u8>,
    start: usize,
    end: usize,
    /// The source ended (it sent FIN).
    eof: bool,
    /// The end was passed on: the destination's writing side is shut.
    shut: bool,
}

impl Half {
    fn new() -> Half {
        Half { buf: vec![0; BUF], start: 0, end: 0, eof: false, shut: false }
    }

    fn empty(&self) -> bool {
        self.start == self.end
    }

    /// Reads into the empty buffer. False when the connection broke.
    fn fill(&mut self, mut src: &TcpStream, last: &mut Instant) -> bool {
        match src.read(&mut self.buf) {
            Ok(0) => {
                self.eof = true;
                true
            }
            Ok(n) => {
                (self.start, self.end) = (0, n);
                *last = Instant::now();
                true
            }
            Err(e) => matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted),
        }
    }

    /// Writes what the buffer holds, as much as the destination takes now.
    /// std writes sockets with MSG_NOSIGNAL: a closed peer is an error
    /// here, never a SIGPIPE.
    fn flush(&mut self, mut dst: &TcpStream, last: &mut Instant) -> bool {
        while !self.empty() {
            match dst.write(&self.buf[self.start..self.end]) {
                Ok(0) => return false,
                Ok(n) => {
                    self.start += n;
                    *last = Instant::now();
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return true,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return false,
            }
        }
        true
    }
}

/// Copies a ↔ b until both sides ended, one broke, nothing moved for idle,
/// or the relay stops.
fn pump(stop: &Stop, a: &TcpStream, b: &TcpStream, idle: Duration, drain: Duration) {
    if a.set_nonblocking(true).is_err() || b.set_nonblocking(true).is_err() {
        return;
    }
    let (mut up, mut down) = (Half::new(), Half::new()); // a → b, b → a
    let mut last = Instant::now();
    let mut drain_end: Option<Instant> = None;
    loop {
        // A side that ended and whose bytes are all through: pass the end
        // on (half-close), the other direction goes on.
        for (h, dst) in [(&mut up, b), (&mut down, a)] {
            if h.eof && h.empty() && !h.shut {
                let _ = dst.shutdown(Shutdown::Write);
                h.shut = true;
            }
        }
        if up.shut && down.shut {
            return;
        }
        let now = Instant::now();
        let quiet = now.duration_since(last);
        if quiet >= idle {
            return;
        }
        if stop.done() {
            let end = *drain_end.get_or_insert(now + drain);
            if now >= end || quiet >= DRAIN_QUIET {
                return;
            }
        }
        let want = |from: &Half, to: &Half| {
            (if !from.eof && from.empty() { libc::POLLIN } else { 0 }) | (if to.empty() { 0 } else { libc::POLLOUT })
        };
        let (ea, eb) = (want(&up, &down), want(&down, &up));
        let mut fds = [pfd(a.as_raw_fd(), ea), pfd(b.as_raw_fd(), eb)];
        match poll(&mut fds, (idle - quiet).min(TICK)) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        }
        if ea & libc::POLLIN != 0 && fds[0].revents != 0 && !up.fill(a, &mut last) {
            return;
        }
        if eb & libc::POLLIN != 0 && fds[1].revents != 0 && !down.fill(b, &mut last) {
            return;
        }
        // Written right away: a socket that cannot take it says so.
        if !up.flush(b, &mut last) || !down.flush(a, &mut last) {
            return;
        }
    }
}

/// One UDP client: its own socket, connected to one backend.
struct Session {
    sock: UdpSocket,
    backend: usize,
    last: Instant,
    _ticket: Ticket,
}

/// A source address a UDP client can have. Anything else is forged, and
/// one naming the listener itself would make the relay answer itself.
fn plausible(client: SocketAddr, own: SocketAddr) -> bool {
    let ip = client.ip();
    client.port() != 0 && usable(ip) && v4(ip) != Some(Ipv4Addr::BROADCAST) && client != own
}

fn udp_loop(stop: &Stop, sh: &Shared, route: &Route, sock: UdpSocket) {
    let Ok(own) = sock.local_addr() else { return };
    if sock.set_nonblocking(true).is_err() {
        return;
    }
    let idle = sh.ms(sh.limits.udp_idle_ms);
    let max = sh.limits.datagram_max;
    // One byte more than allowed: a datagram that fills it was too big.
    let mut buf = vec![0u8; max + 1];
    let mut sessions: HashMap<SocketAddr, Session> = HashMap::new();
    let mut fds = Vec::new();
    let mut order = Vec::new();
    let mut swept = Instant::now();
    while !stop.done() {
        fds.clear();
        order.clear();
        fds.push(pfd(sock.as_raw_fd(), libc::POLLIN));
        for (client, s) in &sessions {
            fds.push(pfd(s.sock.as_raw_fd(), libc::POLLIN));
            order.push(*client);
        }
        if poll(&mut fds, TICK).unwrap_or(0) > 0 {
            let now = Instant::now();
            if fds[0].revents != 0 {
                for _ in 0..BURST {
                    let (n, client) = match sock.recv_from(&mut buf) {
                        Ok(r) => r,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    };
                    if n > max {
                        sh.count(|c| c.udp_too_big += 1);
                        continue;
                    }
                    if !plausible(client, own) {
                        continue;
                    }
                    let s = match sessions.entry(client) {
                        Entry::Occupied(e) => e.into_mut(),
                        Entry::Vacant(e) => match open_session(sh, route, client) {
                            Some(s) => e.insert(s),
                            None => continue,
                        },
                    };
                    // Full socket buffers drop the datagram, as the
                    // network would.
                    let _ = s.sock.send(&buf[..n]);
                    s.last = now;
                }
            }
            for (i, client) in order.iter().enumerate() {
                let Some(s) = sessions.get_mut(client).filter(|_| fds[i + 1].revents != 0) else { continue };
                for _ in 0..BURST {
                    match s.sock.recv(&mut buf) {
                        Ok(n) if n > max => sh.count(|c| c.udp_too_big += 1),
                        Ok(n) => {
                            let _ = sock.send_to(&buf[..n], client);
                            s.last = now;
                        }
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        // Nothing more, or an ICMP error from the backend
                        // (the session stays until it is idle).
                        Err(_) => break,
                    }
                }
            }
        }
        let now = Instant::now();
        if now.duration_since(swept) >= Duration::from_millis(50) {
            swept = now;
            // Idle sessions end; so do those on a backend that went down,
            // and the client's next datagram opens one on a healthy one.
            sessions.retain(|_, s| now.duration_since(s.last) < idle && route.backends[s.backend].up());
        }
    }
}

fn open_session(sh: &Shared, route: &Route, client: SocketAddr) -> Option<Session> {
    let key = client_key(client.ip());
    let ticket = match sh.udp.admit(key) {
        Ok(t) => t,
        Err(full) => {
            sh.count(|c| match full {
                Full::Total => c.udp_full += 1,
                Full::Ip => c.udp_ip_full += 1,
            });
            return None;
        }
    };
    let Some(i) = rank(&sh.seed, key, &route.backends).into_iter().find(|&i| route.backends[i].up()) else {
        sh.count(|c| c.udp_no_backend += 1);
        return None;
    };
    let to = route.backends[i].addr;
    let any: IpAddr = if to.is_ipv4() { Ipv4Addr::UNSPECIFIED.into() } else { Ipv6Addr::UNSPECIFIED.into() };
    let sock = UdpSocket::bind(SocketAddr::new(any, 0)).ok()?;
    sock.connect(to).ok()?;
    sock.set_nonblocking(true).ok()?;
    Some(Session { sock, backend: i, last: Instant::now(), _ticket: ticket })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    fn quiet_log() -> LogFn {
        Arc::new(|_| {})
    }

    fn quick() -> Limits {
        // Small totals: the tests never need more open files than a default
        // 1024 soft limit.
        Limits {
            tcp_total: 256,
            udp_sessions: 256,
            connect_timeout_ms: 500,
            check_every_ms: 50,
            drain_ms: 200,
            tcp_idle_ms: 10_000,
            udp_idle_ms: 10_000,
            ..Limits::default()
        }
    }

    fn local() -> Option<IpAddr> {
        Some(Ipv4Addr::LOCALHOST.into())
    }

    fn listener(protocol: Protocol, backends: &[Backend]) -> Listener {
        Listener { protocol, port: 0, bind: local(), backends: backends.to_vec(), proxy_protocol: false }
    }

    fn be(addr: SocketAddr) -> Backend {
        Backend { addr, check_port: None }
    }

    fn start(listeners: Vec<Listener>, limits: Limits) -> Relay {
        Relay::launch(&Ctx::new(), &Config { listeners, limits }, quiet_log()).unwrap()
    }

    fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
        let end = Instant::now() + Duration::from_secs(10);
        while !cond() {
            assert!(Instant::now() < end, "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn healthy(r: &Relay, addrs: &[SocketAddr]) {
        for a in addrs {
            wait_until(&format!("{a} up"), || r.up(*a) == Some(true));
        }
    }

    /// A TCP server on loopback that runs handler for each connection.
    struct Server {
        addr: SocketAddr,
        stop: Arc<AtomicBool>,
    }

    impl Server {
        fn on(bind: &str, handler: impl Fn(TcpStream, &AtomicBool) + Send + Sync + 'static) -> Server {
            let l = TcpListener::bind(bind).unwrap();
            Server::with(l, handler)
        }

        fn with(l: TcpListener, handler: impl Fn(TcpStream, &AtomicBool) + Send + Sync + 'static) -> Server {
            l.set_nonblocking(true).unwrap();
            let addr = l.local_addr().unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let (s, handler) = (stop.clone(), Arc::new(handler));
            thread::spawn(move || {
                while !s.load(Ordering::SeqCst) {
                    match l.accept() {
                        Ok((c, _)) => {
                            c.set_nonblocking(false).unwrap();
                            let (h, s) = (handler.clone(), s.clone());
                            thread::spawn(move || h(c, &s));
                        }
                        Err(_) => thread::sleep(Duration::from_millis(5)),
                    }
                }
            });
            Server { addr, stop }
        }

        /// Echoes, passes the end back, and keeps what it got.
        fn echo(bind: &str) -> (Server, Arc<Mutex<Vec<u8>>>) {
            let got = Arc::new(Mutex::new(Vec::new()));
            let g = got.clone();
            let s = Server::on(bind, move |mut c, _| {
                let mut buf = [0u8; 8192];
                loop {
                    match c.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            g.lock().unwrap().extend_from_slice(&buf[..n]);
                            if c.write_all(&buf[..n]).is_err() {
                                return;
                            }
                        }
                    }
                }
                let _ = c.shutdown(Shutdown::Write);
            });
            (s, got)
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
        }
    }

    /// A port nothing listens on.
    /// A port where connects are refused and that stays so: a socket bound
    /// to it but never listening. The port of a dropped listener could be
    /// handed to a test running in parallel, which would bring the "dead"
    /// backend to life. The socket is left open on purpose until the test
    /// process ends (a few per run).
    fn dead_port() -> SocketAddr {
        // SAFETY: plain socket calls on a descriptor owned here; the
        // address structs are zeroed and sized for AF_INET.
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
            assert!(fd >= 0, "socket");
            let mut a: libc::sockaddr_in = std::mem::zeroed();
            a.sin_family = libc::AF_INET as libc::sa_family_t;
            a.sin_addr.s_addr = u32::from(Ipv4Addr::LOCALHOST).to_be();
            let len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            assert_eq!(libc::bind(fd, &a as *const libc::sockaddr_in as *const libc::sockaddr, len), 0, "bind");
            let mut got = len;
            assert_eq!(libc::getsockname(fd, &mut a as *mut libc::sockaddr_in as *mut libc::sockaddr, &mut got), 0, "getsockname");
            SocketAddr::from((Ipv4Addr::LOCALHOST, u16::from_be(a.sin_port)))
        }
    }

    fn tcp_addr(r: &Relay, i: usize) -> SocketAddr {
        r.addrs()[i].1
    }

    /// Sends and reads back the same bytes.
    fn echoes(c: &mut TcpStream, msg: &[u8]) -> bool {
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut got = vec![0u8; msg.len()];
        c.write_all(msg).is_ok() && c.read_exact(&mut got).is_ok() && got == msg
    }

    /// The relay ended the connection (FIN or reset) within the time.
    fn closed_within(c: &mut TcpStream, d: Duration) -> bool {
        c.set_read_timeout(Some(d)).unwrap();
        let mut b = [0u8; 64];
        loop {
            match c.read(&mut b) {
                Ok(0) => return true,
                Ok(_) => continue,
                Err(e) => return matches!(e.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted),
            }
        }
    }

    fn ipv6_loopback() -> bool {
        TcpListener::bind("[::1]:0").is_ok()
    }

    // ---- config ----

    fn good_config() -> Config {
        Config::parse(
            r#"{"listeners": [
                {"protocol": "tcp", "port": 443, "proxy_protocol": true,
                 "backends": [{"addr": "10.66.0.2:443"}, {"addr": "10.66.0.3:443", "check_port": 8443}]},
                {"protocol": "udp", "port": 443, "backends": [{"addr": "10.66.0.2:443", "check_port": 443}]}
            ], "limits": {"tcp_per_ip": 16}}"#,
        )
        .unwrap()
    }

    #[test]
    fn config_parses_with_defaults() {
        let c = good_config();
        assert_eq!(c.limits, Limits { tcp_per_ip: 16, ..Limits::default() });
        assert_eq!(c.listeners[0].backends[1].check_addr(), "10.66.0.3:8443".parse().unwrap());
        assert_eq!(c.listeners[0].backends[0].check_addr(), "10.66.0.2:443".parse().unwrap());
        assert_eq!(c.listeners[1].protocol, Protocol::Udp);
        // What it writes, it reads back.
        assert_eq!(Config::parse(&serde_json::to_string(&c).unwrap()).unwrap(), c);
    }

    #[test]
    fn config_is_strict() {
        type Change = fn(&mut Config);
        let cases: &[(Change, &str)] = &[
            (|c| c.listeners.clear(), "1 to 64 listeners"),
            (|c| c.listeners = vec![c.listeners[1].clone(); MAX_LISTENERS + 1], "1 to 64 listeners"),
            (|c| c.listeners[0].port = 0, "no port"),
            (|c| c.listeners[1].protocol = Protocol::Tcp, "used twice"),
            (|c| c.listeners[1].proxy_protocol = true, "TCP only"),
            (|c| c.listeners[1].backends[0].check_port = None, "needs a check_port"),
            (|c| c.listeners[0].backends[0].check_port = Some(0), "check port 0"),
            (|c| c.listeners[0].backends.clear(), "1 to 32 backends"),
            (|c| c.listeners[0].backends = vec![be("10.66.0.9:1".parse().unwrap()); 2], "listed twice"),
            (|c| c.listeners[0].backends[0].addr = "0.0.0.0:443".parse().unwrap(), "cannot pass"),
            (|c| c.listeners[0].backends[0].addr = "[::]:443".parse().unwrap(), "cannot pass"),
            (|c| c.listeners[0].backends[0].addr = "224.0.0.1:443".parse().unwrap(), "cannot pass"),
            (|c| c.listeners[0].backends[0].addr = "255.255.255.255:443".parse().unwrap(), "cannot pass"),
            (|c| c.listeners[0].backends[0].addr = "10.66.0.2:0".parse().unwrap(), "cannot pass"),
            (|c| c.listeners[0].backends[0].addr = "[fe80::1%2]:443".parse().unwrap(), "scope"),
            (|c| c.listeners[0].bind = Some("ff02::1".parse().unwrap()), "cannot listen"),
            (|c| c.limits.tcp_total = 0, "tcp_total"),
            (|c| c.limits.tcp_total = MAX_CONNS + 1, "tcp_total"),
            (|c| c.limits.tcp_per_ip = c.limits.tcp_total + 1, "tcp_per_ip"),
            (|c| c.limits.udp_per_ip = 0, "udp_per_ip"),
            (|c| c.limits.udp_sessions = 0, "udp_sessions"),
            (|c| c.limits.connect_timeout_ms = 0, "connect_timeout_ms"),
            (|c| c.limits.tcp_idle_ms = 0, "tcp_idle_ms"),
            (|c| c.limits.udp_idle_ms = 0, "udp_idle_ms"),
            (|c| c.limits.datagram_max = 0, "datagram_max"),
            (|c| c.limits.datagram_max = MAX_DATAGRAM + 1, "datagram_max"),
            (|c| c.limits.check_every_ms = 1, "check_every_ms"),
            (|c| c.limits.drain_ms = 600_001, "drain_ms"),
        ];
        for (change, want) in cases {
            let mut c = good_config();
            change(&mut c);
            let e = c.validate().unwrap_err().to_string();
            assert!(e.contains(want), "want {want:?} in {e}");
        }
        // The JSON itself.
        for (text, want) in [
            ("", "EOF"),
            ("{}", "missing field"),
            (r#"{"listeners": [], "extra": 1}"#, "unknown field"),
            (r#"{"listeners": [], "limits": {"tcp_per_iip": 5}}"#, "unknown field"),
            (r#"{"listeners": [{"protocol": "sctp", "port": 1, "backends": []}]}"#, "unknown variant"),
            (r#"{"listeners": [{"protocol": "tcp", "port": 70000, "backends": []}]}"#, "invalid value"),
            (r#"{"listeners": [{"protocol": "tcp", "port": 1, "backends": [{"addr": "10.0.0.1"}]}]}"#, "invalid socket address"),
            (r#"{"listeners": [{"protocol": "tcp", "port": 1, "backends": [{"addr": "host:1"}]}]}"#, "invalid socket address"),
            (r#"{"listeners": [{"protocol": "tcp", "port": 1, "backends": ["10.0.0.1:1"]}]}"#, "invalid type"),
        ] {
            let e = Config::parse(text).unwrap_err().to_string();
            assert!(e.contains(want), "{text}: want {want:?} in {e}");
        }
        let huge = format!("{{\"listeners\": [], \"pad\": \"{}\"}}", "x".repeat(MAX_CONFIG as usize));
        assert!(Config::parse(&huge).unwrap_err().to_string().contains("more than"));
        let dir = crate::testutil::TempDir::new();
        std::fs::write(dir.join("relay.json"), &huge).unwrap();
        assert!(Config::load(&dir.join("relay.json")).unwrap_err().to_string().contains("more than"));
        std::fs::write(dir.join("relay.json"), serde_json::to_string(&good_config()).unwrap()).unwrap();
        assert_eq!(Config::load(&dir.join("relay.json")).unwrap(), good_config());
    }

    // ---- pure parts ----

    #[test]
    fn proxy_v2_header_bytes() {
        let h = proxy_v2("192.0.2.10:51234".parse().unwrap(), "203.0.113.7:443".parse().unwrap());
        #[rustfmt::skip]
        let want: &[u8] = &[
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, // signature
            0x21,                   // version 2, PROXY
            0x11,                   // TCP over IPv4
            0x00, 0x0C,             // 12 address bytes
            192, 0, 2, 10,          // source address
            203, 0, 113, 7,         // destination address
            0xC8, 0x22,             // source port 51234
            0x01, 0xBB,             // destination port 443
        ];
        assert_eq!(h, want);

        let h = proxy_v2("[2001:db8::1]:40000".parse().unwrap(), "[2001:db8::2]:443".parse().unwrap());
        let mut want = vec![0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x21, 0x00, 0x24];
        want.extend([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        want.extend([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        want.extend([0x9C, 0x40, 0x01, 0xBB]);
        assert_eq!(h, want);
        assert_eq!(h.len(), 16 + 36);

        // IPv4 clients on a dual-stack socket appear mapped: written as IPv4.
        let mapped = proxy_v2("[::ffff:192.0.2.10]:51234".parse().unwrap(), "[::ffff:203.0.113.7]:443".parse().unwrap());
        assert_eq!(mapped, proxy_v2("192.0.2.10:51234".parse().unwrap(), "203.0.113.7:443".parse().unwrap()));
        // One side IPv4, one IPv6: both as IPv6, the IPv4 one mapped.
        let mixed = proxy_v2("192.0.2.10:1".parse().unwrap(), "[2001:db8::2]:2".parse().unwrap());
        assert_eq!(&mixed[13..16], &[0x21, 0x00, 0x24]);
        assert_eq!(&mixed[16..32], &"::ffff:192.0.2.10".parse::<Ipv6Addr>().unwrap().octets());
    }

    #[test]
    fn clients_by_address_and_ipv6_prefix() {
        let k = |s: &str| client_key(s.parse().unwrap());
        assert_eq!(k("192.0.2.1"), ClientKey::V4("192.0.2.1".parse().unwrap()));
        assert_ne!(k("192.0.2.1"), k("192.0.2.2"));
        assert_eq!(k("::ffff:192.0.2.1"), k("192.0.2.1"), "an IPv4 client seen through a dual-stack socket");
        assert_eq!(k("2001:db8:1:2::1"), k("2001:db8:1:2:ffff:ffff:ffff:ffff"), "one /64 is one client");
        assert_ne!(k("2001:db8:1:2::1"), k("2001:db8:1:3::1"));
    }

    #[test]
    fn forged_udp_sources_are_dropped() {
        let own: SocketAddr = "203.0.113.7:443".parse().unwrap();
        for bad in [
            "0.0.0.0:1",
            "198.51.100.1:0",
            "224.0.0.1:5",
            "255.255.255.255:5",
            "[::ffff:255.255.255.255]:5",
            "[ff02::1]:5",
            "203.0.113.7:443",
        ] {
            assert!(!plausible(bad.parse().unwrap(), own), "{bad}");
        }
        for good in ["198.51.100.1:5353", "[2001:db8::1]:443", "203.0.113.7:444"] {
            assert!(plausible(good.parse().unwrap(), own), "{good}");
        }
    }

    #[test]
    fn gates_count_per_client_and_in_all() {
        let g = Gate::new(2, 3);
        let (a, b) = (client_key("192.0.2.1".parse().unwrap()), client_key("192.0.2.2".parse().unwrap()));
        let t1 = g.admit(a).ok().unwrap();
        let _t2 = g.admit(a).ok().unwrap();
        assert!(matches!(g.admit(a), Err(Full::Ip)));
        let _t3 = g.admit(b).ok().unwrap();
        assert!(matches!(g.admit(b), Err(Full::Total)));
        assert_eq!(g.count(), 3);
        drop(t1);
        assert!(g.admit(a).is_ok(), "a closed connection frees its place");
        drop(_t2);
        drop(_t3);
        assert_eq!(g.count(), 0);
        assert!(g.open.lock().unwrap().1.is_empty(), "no entries kept for clients that left");
    }

    #[test]
    fn rendezvous_keeps_clients_in_place() {
        let seed = RandomState::new();
        let targets =
            |n: u16| (0..n).map(|i| Target { addr: SocketAddr::from(([10, 66, 0, 2], 400 + i)), up: Arc::default() }).collect::<Vec<_>>();
        let four = targets(4);
        let mut per = [0; 4];
        let keys: Vec<ClientKey> = (0..2000u32).map(|i| client_key(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i)))).collect();
        for k in &keys {
            let r = rank(&seed, *k, &four);
            assert_eq!(r, rank(&seed, *k, &four), "the same client gets the same order");
            let mut sorted = r.clone();
            sorted.sort();
            assert_eq!(sorted, vec![0, 1, 2, 3]);
            per[r[0]] += 1;
        }
        assert!(per.iter().all(|&n| n > 300), "clients spread over backends: {per:?}");
        // Without backend 3, only its clients move.
        let three = targets(3);
        for k in &keys {
            let before = rank(&seed, *k, &four)[0];
            if before != 3 {
                assert_eq!(rank(&seed, *k, &three)[0], before);
            }
        }
    }

    // ---- TCP ----

    #[test]
    fn tcp_bytes_arrive_unchanged_both_ways() {
        let (echo, _) = Server::echo("127.0.0.1:0");
        let r = start(vec![listener(Protocol::Tcp, &[be(echo.addr)])], quick());
        healthy(&r, &[echo.addr]);
        let mut c = TcpStream::connect(tcp_addr(&r, 0)).unwrap();
        // Every byte value, a megabyte, written while it comes back.
        let data: Vec<u8> = (0..(1u32 << 20)).map(|i| (i ^ (i >> 8) ^ (i >> 16)) as u8).collect();
        let mut w = c.try_clone().unwrap();
        let send = data.clone();
        let writer = thread::spawn(move || {
            w.write_all(&send).unwrap();
            // Half-close: the echo server sees the end, sends the rest and
            // ends too.
            w.shutdown(Shutdown::Write).unwrap();
        });
        let mut got = Vec::new();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        c.read_to_end(&mut got).unwrap();
        writer.join().unwrap();
        assert!(got == data, "{} bytes back of {}", got.len(), data.len());
        wait_until("the connection to end", || r.open().0 == 0);
    }

    /// The backend gets the PROXY header and then the client's bytes.
    fn proxy_case(bind: &str) {
        let (rec, got) = Server::echo("127.0.0.1:0");
        let mut l = listener(Protocol::Tcp, &[be(rec.addr)]);
        l.proxy_protocol = true;
        l.bind = Some(bind.parse().unwrap());
        let r = start(vec![l], quick());
        healthy(&r, &[rec.addr]);
        let relay = tcp_addr(&r, 0);
        let mut c = TcpStream::connect(relay).unwrap();
        let header = proxy_v2(c.local_addr().unwrap(), relay);
        // The echo comes back with the header in front: the client sees
        // what the backend got.
        c.write_all(b"ping").unwrap();
        c.shutdown(Shutdown::Write).unwrap();
        let mut back = Vec::new();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.read_to_end(&mut back).unwrap();
        let want = [header.as_slice(), b"ping"].concat();
        assert_eq!(back, want);
        // Health checks connect too, but send nothing.
        assert_eq!(*got.lock().unwrap(), want);
    }

    #[test]
    fn proxy_header_ipv4() {
        proxy_case("127.0.0.1");
    }

    #[test]
    fn proxy_header_and_echo_ipv6() {
        if !ipv6_loopback() {
            return;
        }
        proxy_case("::1");
        // An IPv6 client to an IPv6 backend, without the header.
        let (echo, _) = Server::echo("[::1]:0");
        let mut l = listener(Protocol::Tcp, &[be(echo.addr)]);
        l.bind = Some("::1".parse().unwrap());
        let r = start(vec![l], quick());
        healthy(&r, &[echo.addr]);
        assert!(echoes(&mut TcpStream::connect(tcp_addr(&r, 0)).unwrap(), b"over IPv6"));
    }

    #[test]
    fn a_dead_backend_is_skipped() {
        let (echo, _) = Server::echo("127.0.0.1:0");
        let dead = dead_port();
        let r = start(vec![listener(Protocol::Tcp, &[be(dead), be(echo.addr)])], quick());
        healthy(&r, &[echo.addr]);
        wait_until("the dead backend marked down", || r.up(dead) == Some(false));
        for _ in 0..5 {
            assert!(echoes(&mut TcpStream::connect(tcp_addr(&r, 0)).unwrap(), b"hello"));
        }
        assert_eq!(r.counts().tcp_connect_failed, 0, "a backend marked down is not even tried");
    }

    /// A backend that looks healthy but refuses the connection: the next
    /// one is tried.
    #[test]
    fn a_failed_connect_tries_the_next_backend() {
        let (checks, _) = Server::echo("127.0.0.1:0");
        let a = TcpListener::bind("127.0.0.1:0").unwrap();
        let b = TcpListener::bind("127.0.0.1:0").unwrap();
        let (aa, ba) = (a.local_addr().unwrap(), b.local_addr().unwrap());
        // Both checked on the healthy server's port, so both count as up.
        let check = Some(checks.addr.port());
        let l = listener(Protocol::Tcp, &[Backend { addr: aa, check_port: check }, Backend { addr: ba, check_port: check }]);
        let r = start(vec![l], quick());
        healthy(&r, &[aa, ba]);
        // Kill whichever this client tries first; serve on the other.
        let first = rank(&r.shared.seed, client_key(Ipv4Addr::LOCALHOST.into()), &r.routes[0].backends)[0];
        let (dead, alive) = if first == 0 { (a, b) } else { (b, a) };
        drop(dead);
        let _srv = Server::with(alive, |mut c, _| {
            let mut buf = [0u8; 5];
            if c.read_exact(&mut buf).is_ok() {
                let _ = c.write_all(&buf);
            }
        });
        assert!(echoes(&mut TcpStream::connect(tcp_addr(&r, 0)).unwrap(), b"again"));
        assert_eq!(r.counts().tcp_connect_failed, 1);
    }

    #[test]
    fn no_healthy_backend_closes_at_once() {
        let dead = dead_port();
        let r = start(vec![listener(Protocol::Tcp, &[be(dead)])], quick());
        wait_until("the backend marked down", || r.up(dead) == Some(false));
        let begin = Instant::now();
        let mut c = TcpStream::connect(tcp_addr(&r, 0)).unwrap();
        assert!(closed_within(&mut c, Duration::from_secs(2)));
        assert!(begin.elapsed() < Duration::from_secs(1));
        assert_eq!(r.counts().tcp_no_backend, 1);
        assert_eq!(r.open().0, 0, "a refused connection takes no place");
    }

    #[test]
    fn per_ip_limit() {
        let (echo, _) = Server::echo("127.0.0.1:0");
        let r = start(vec![listener(Protocol::Tcp, &[be(echo.addr)])], Limits { tcp_per_ip: 2, tcp_total: 10, ..quick() });
        healthy(&r, &[echo.addr]);
        let relay = tcp_addr(&r, 0);
        let mut c1 = TcpStream::connect(relay).unwrap();
        let mut c2 = TcpStream::connect(relay).unwrap();
        assert!(echoes(&mut c1, b"1") && echoes(&mut c2, b"2"));
        let mut c3 = TcpStream::connect(relay).unwrap();
        assert!(closed_within(&mut c3, Duration::from_secs(2)));
        assert_eq!((r.counts().tcp_ip_full, r.counts().tcp_full), (1, 0));
        drop(c1);
        wait_until("the closed connection to free its place", || r.open().0 == 1);
        assert!(echoes(&mut TcpStream::connect(relay).unwrap(), b"4"));
        assert!(echoes(&mut c2, b"still there"));
    }

    #[test]
    fn global_limit() {
        let (echo, _) = Server::echo("127.0.0.1:0");
        let r = start(vec![listener(Protocol::Tcp, &[be(echo.addr)])], Limits { tcp_per_ip: 2, tcp_total: 2, ..quick() });
        healthy(&r, &[echo.addr]);
        let relay = tcp_addr(&r, 0);
        let mut c1 = TcpStream::connect(relay).unwrap();
        let mut c2 = TcpStream::connect(relay).unwrap();
        assert!(echoes(&mut c1, b"1") && echoes(&mut c2, b"2"));
        let mut c3 = TcpStream::connect(relay).unwrap();
        assert!(closed_within(&mut c3, Duration::from_secs(2)));
        assert_eq!(r.counts().tcp_full, 1, "the relay as a whole was full");
    }

    /// Many connections at once from one address: the rest are refused
    /// without a thread each, and the relay keeps working.
    #[test]
    fn a_flood_from_one_address() {
        let (echo, _) = Server::echo("127.0.0.1:0");
        let r = start(vec![listener(Protocol::Tcp, &[be(echo.addr)])], Limits { tcp_per_ip: 8, tcp_total: 64, ..quick() });
        healthy(&r, &[echo.addr]);
        let base = r.threads();
        let relay = tcp_addr(&r, 0);
        // Under load the relay's reset of a refused connection can reach the
        // client before its connect() returns: that one is closed too.
        let tries: Vec<std::io::Result<TcpStream>> = (0..100).map(|_| TcpStream::connect(relay)).collect();
        let reset_early = tries.iter().filter(|t| t.is_err()).count();
        let mut flood: Vec<TcpStream> = tries.into_iter().flatten().collect();
        wait_until("every connection decided", || {
            let c = r.counts();
            c.tcp_ip_full + r.open().0 as u64 == 100
        });
        assert_eq!(r.open().0, 8);
        assert!(r.threads() <= base + 8, "{} threads for 8 connections", r.threads());
        let closed = reset_early + flood.iter_mut().map(|c| closed_within(c, Duration::from_millis(200))).filter(|&x| x).count();
        assert_eq!(closed, 92, "refused connections are closed at once, the 8 let in stay open");
        drop(flood);
        wait_until("the flood to end", || r.open().0 == 0);
        assert!(echoes(&mut TcpStream::connect(relay).unwrap(), b"still serving"));
    }

    #[test]
    fn a_silent_client_times_out() {
        let (echo, _) = Server::echo("127.0.0.1:0");
        let r = start(vec![listener(Protocol::Tcp, &[be(echo.addr)])], Limits { tcp_idle_ms: 300, ..quick() });
        healthy(&r, &[echo.addr]);
        let begin = Instant::now();
        let mut c = TcpStream::connect(tcp_addr(&r, 0)).unwrap();
        wait_until("the connection to open", || r.open().0 == 1);
        assert!(closed_within(&mut c, Duration::from_secs(5)));
        assert!(begin.elapsed() >= Duration::from_millis(250), "closed before the idle time");
        wait_until("its place to be free", || r.open().0 == 0);
    }

    #[test]
    fn a_hanging_backend_times_out() {
        let hang = Server::on("127.0.0.1:0", |c, stop| {
            // Accepts and never reads or writes.
            while !stop.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(20));
            }
            drop(c);
        });
        let r = start(vec![listener(Protocol::Tcp, &[be(hang.addr)])], Limits { tcp_idle_ms: 300, ..quick() });
        healthy(&r, &[hang.addr]);
        let mut c = TcpStream::connect(tcp_addr(&r, 0)).unwrap();
        c.write_all(b"anyone there?").unwrap();
        assert!(closed_within(&mut c, Duration::from_secs(5)));
        wait_until("its place to be free", || r.open().0 == 0);
    }

    /// A client that never reads while the backend sends without end: the
    /// backend is held back, the relay's memory does not grow.
    #[test]
    fn a_client_that_never_reads_holds_the_backend_back() {
        // The most any one connection took: health checks connect too,
        // and each takes a little before it is gone.
        let sent = Arc::new(AtomicU64::new(0));
        let s2 = sent.clone();
        let flood = Server::on("127.0.0.1:0", move |mut c, _| {
            let chunk = [7u8; 16384];
            let mut mine = 0;
            while let Ok(n) = c.write(&chunk) {
                mine += n as u64;
                s2.fetch_max(mine, Ordering::SeqCst);
            }
        });
        let r = start(vec![listener(Protocol::Tcp, &[be(flood.addr)])], Limits { tcp_idle_ms: 3000, ..quick() });
        healthy(&r, &[flood.addr]);
        let c = TcpStream::connect(tcp_addr(&r, 0)).unwrap();
        // Fill every buffer on the way, then nothing more moves.
        let mut before = 0;
        wait_until("the backend to stall", || {
            thread::sleep(Duration::from_millis(200));
            let now = sent.load(Ordering::SeqCst);
            let stalled = now > 0 && now == before;
            before = now;
            stalled
        });
        assert!(before < 64 << 20, "{before} bytes went into a client that reads nothing");
        thread::sleep(Duration::from_millis(300));
        assert_eq!(sent.load(Ordering::SeqCst), before);
        // With nothing moving, the idle time ends it.
        wait_until("the stalled connection to end", || r.open().0 == 0);
        drop(c);
    }

    // ---- UDP ----

    /// A UDP echo server, with a TCP port for its health check. Keeps the
    /// source address of each datagram.
    struct UdpEcho {
        addr: SocketAddr,
        check: Server,
        seen: Arc<Mutex<Vec<SocketAddr>>>,
        stop: Arc<AtomicBool>,
    }

    impl UdpEcho {
        fn new() -> UdpEcho {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
            let addr = s.local_addr().unwrap();
            let (seen, stop) = (Arc::new(Mutex::new(Vec::new())), Arc::new(AtomicBool::new(false)));
            let (sn, st) = (seen.clone(), stop.clone());
            thread::spawn(move || {
                let mut buf = [0u8; 70000];
                while !st.load(Ordering::SeqCst) {
                    if let Ok((n, from)) = s.recv_from(&mut buf) {
                        sn.lock().unwrap().push(from);
                        let _ = s.send_to(&buf[..n], from);
                    }
                }
            });
            UdpEcho { addr, check: Server::on("127.0.0.1:0", |_, _| {}), seen, stop }
        }

        fn backend(&self) -> Backend {
            Backend { addr: self.addr, check_port: Some(self.check.addr.port()) }
        }
    }

    impl Drop for UdpEcho {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
        }
    }

    fn udp_client() -> UdpSocket {
        let c = UdpSocket::bind("127.0.0.1:0").unwrap();
        c.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        c
    }

    fn udp_echoes(c: &UdpSocket, to: SocketAddr, msg: &[u8]) -> bool {
        c.send_to(msg, to).unwrap();
        let mut buf = [0u8; 70000];
        matches!(c.recv_from(&mut buf), Ok((n, from)) if from == to && &buf[..n] == msg)
    }

    #[test]
    fn udp_round_trip_for_two_clients_at_once() {
        let echo = UdpEcho::new();
        let r = start(vec![listener(Protocol::Udp, &[echo.backend()])], quick());
        healthy(&r, &[echo.addr]);
        let relay = r.addrs()[0].1;
        let workers: Vec<_> = (0..2u8)
            .map(|id| {
                thread::spawn(move || {
                    let c = udp_client();
                    for i in 0..50u8 {
                        let msg = [id, i, id ^ i, 0xAA];
                        assert!(udp_echoes(&c, relay, &msg), "client {id} datagram {i}");
                    }
                })
            })
            .collect();
        for w in workers {
            w.join().unwrap();
        }
        assert_eq!(r.open().1, 2);
        let seen: HashSet<SocketAddr> = echo.seen.lock().unwrap().iter().copied().collect();
        assert_eq!(seen.len(), 2, "one relay socket per client session");
    }

    #[test]
    fn udp_sessions_expire() {
        let echo = UdpEcho::new();
        let r = start(vec![listener(Protocol::Udp, &[echo.backend()])], Limits { udp_idle_ms: 300, ..quick() });
        healthy(&r, &[echo.addr]);
        let relay = r.addrs()[0].1;
        let c = udp_client();
        assert!(udp_echoes(&c, relay, b"one"));
        assert_eq!(r.open().1, 1);
        wait_until("the session to expire", || r.open().1 == 0);
        assert!(udp_echoes(&c, relay, b"two"));
        let seen = echo.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 2);
        assert_ne!(seen[0], seen[1], "an expired session's socket is not reused");
    }

    #[test]
    fn udp_limits_and_sizes() {
        let echo = UdpEcho::new();
        let limits = Limits { udp_per_ip: 2, udp_sessions: 10, datagram_max: 100, ..quick() };
        let r = start(vec![listener(Protocol::Udp, &[echo.backend()])], limits);
        healthy(&r, &[echo.addr]);
        let relay = r.addrs()[0].1;
        let (c1, c2, c3) = (udp_client(), udp_client(), udp_client());
        assert!(udp_echoes(&c1, relay, b"a") && udp_echoes(&c2, relay, b"b"));
        assert!(!udp_echoes(&c3, relay, b"c"), "a third session from one address");
        assert_eq!(r.counts().udp_ip_full, 1);
        // The size limit.
        assert!(udp_echoes(&c1, relay, &[1u8; 100]));
        assert!(!udp_echoes(&c1, relay, &[1u8; 101]));
        assert_eq!(r.counts().udp_too_big, 1);
        assert!(udp_echoes(&c1, relay, b"after"));
    }

    #[test]
    fn udp_global_session_limit() {
        let echo = UdpEcho::new();
        let r = start(vec![listener(Protocol::Udp, &[echo.backend()])], Limits { udp_per_ip: 1, udp_sessions: 1, ..quick() });
        healthy(&r, &[echo.addr]);
        let relay = r.addrs()[0].1;
        let (c1, c2) = (udp_client(), udp_client());
        assert!(udp_echoes(&c1, relay, b"a"));
        assert!(!udp_echoes(&c2, relay, b"b"));
        assert_eq!(r.counts().udp_full, 1);
    }

    #[test]
    fn udp_follows_health() {
        let echo = UdpEcho::new();
        let r = start(vec![listener(Protocol::Udp, &[echo.backend()])], quick());
        healthy(&r, &[echo.addr]);
        let relay = r.addrs()[0].1;
        let c = udp_client();
        assert!(udp_echoes(&c, relay, b"up"));
        // The check port goes away: the machine counts as down, its
        // sessions end and new datagrams are dropped.
        echo.check.stop.store(true, Ordering::SeqCst);
        wait_until("the backend marked down", || r.up(echo.addr) == Some(false));
        wait_until("its session to end", || r.open().1 == 0);
        assert!(!udp_echoes(&c, relay, b"down"));
        assert!(r.counts().udp_no_backend >= 1);
    }

    // ---- health ----

    #[test]
    fn health_needs_two_results_in_a_row() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let srv = Server::with(l, |_, _| {});
        let logs = Arc::new(Mutex::new(Vec::<String>::new()));
        let lg = logs.clone();
        let log: LogFn = Arc::new(move |s: &str| lg.lock().unwrap().push(s.to_string()));
        let cfg = Config { listeners: vec![listener(Protocol::Tcp, &[be(addr)])], limits: Limits { check_every_ms: 100, ..quick() } };
        let r = Relay::launch(&Ctx::new(), &cfg, log).unwrap();
        healthy(&r, &[addr]);
        drop(srv);
        let gone = Instant::now();
        wait_until("down", || r.up(addr) == Some(false));
        assert!(gone.elapsed() >= Duration::from_millis(100), "one failed check is not enough");
        // Back on the same port.
        let l = loop {
            if let Ok(l) = TcpListener::bind(addr) {
                break l;
            }
            thread::sleep(Duration::from_millis(10));
        };
        let back = Instant::now();
        let _srv = Server::with(l, |_, _| {});
        wait_until("up again", || r.up(addr) == Some(true));
        assert!(back.elapsed() >= Duration::from_millis(100), "one good check is not enough");
        let logs = logs.lock().unwrap().join("\n");
        assert!(logs.contains(&format!("backend {addr} is down")) && logs.contains(&format!("backend {addr} is up")), "{logs}");
    }

    // ---- start and stop ----

    #[test]
    fn shutdown_leaves_no_threads_and_frees_the_ports() {
        let (echo, _) = Server::echo("127.0.0.1:0");
        let udp = UdpEcho::new();
        let limits = Limits { drain_ms: 2000, ..quick() };
        let ctx = Ctx::new();
        let cfg = Config { listeners: vec![listener(Protocol::Tcp, &[be(echo.addr)]), listener(Protocol::Udp, &[udp.backend()])], limits };
        let r = Relay::launch(&ctx, &cfg, quiet_log()).unwrap();
        healthy(&r, &[echo.addr, udp.addr]);
        let (tcp_at, udp_at) = (r.addrs()[0].1, r.addrs()[1].1);
        // An idle connection and a UDP session stay open.
        let mut idle = TcpStream::connect(tcp_at).unwrap();
        assert!(echoes(&mut idle, b"hi"));
        assert!(udp_echoes(&udp_client(), udp_at, b"hi"));
        let live = r.shared.live.clone();
        assert!(live.load(Ordering::SeqCst) >= 5, "checks, accept, udp and one connection");
        let begin = Instant::now();
        ctx.cancel();
        r.wait();
        assert!(begin.elapsed() < Duration::from_millis(1500), "an idle connection held the shutdown for {:?}", begin.elapsed());
        assert_eq!(live.load(Ordering::SeqCst), 0, "threads left after shutdown");
        assert!(closed_within(&mut idle, Duration::from_secs(1)));

        // Port reuse: a new relay gets the same ports at once, although
        // the old connection is in TIME_WAIT.
        let mut again = cfg.clone();
        again.listeners[0].port = tcp_at.port();
        again.listeners[1].port = udp_at.port();
        let r2 = Relay::launch(&Ctx::new(), &again, quiet_log()).unwrap();
        // While it runs, nobody else gets them.
        let e = Relay::launch(&Ctx::new(), &again, quiet_log()).err().unwrap().to_string();
        assert!(e.contains("address already in use") || e.contains("in use"), "{e}");
        let live2 = r2.shared.live.clone();
        r2.stop();
        assert_eq!(live2.load(Ordering::SeqCst), 0);
    }

    /// A busy connection may finish within drain_ms, then it is cut.
    #[test]
    fn shutdown_cuts_busy_connections_after_the_drain_time() {
        let sent = Arc::new(AtomicU64::new(0));
        let s2 = sent.clone();
        let trickle = Server::on("127.0.0.1:0", move |mut c, stop| {
            while !stop.load(Ordering::SeqCst) && c.write_all(b".").is_ok() {
                s2.fetch_add(1, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(20));
            }
        });
        let r = start(vec![listener(Protocol::Tcp, &[be(trickle.addr)])], Limits { drain_ms: 500, ..quick() });
        healthy(&r, &[trickle.addr]);
        let mut c = TcpStream::connect(tcp_addr(&r, 0)).unwrap();
        let mut b = [0u8; 1];
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.read_exact(&mut b).unwrap();
        let live = r.shared.live.clone();
        let begin = Instant::now();
        r.stop();
        let took = begin.elapsed();
        assert!(took >= Duration::from_millis(400) && took < Duration::from_secs(3), "{took:?}");
        assert_eq!(live.load(Ordering::SeqCst), 0);
        assert!(closed_within(&mut c, Duration::from_secs(2)));
    }

    #[test]
    fn start_fails_cleanly_on_a_port_in_use() {
        let taken = TcpListener::bind("127.0.0.1:0").unwrap();
        let (echo, _) = Server::echo("127.0.0.1:0");
        let mut busy = listener(Protocol::Tcp, &[be(echo.addr)]);
        busy.port = taken.local_addr().unwrap().port();
        let cfg = Config { listeners: vec![listener(Protocol::Tcp, &[be(echo.addr)]), busy], limits: quick() };
        let e = Relay::launch(&Ctx::new(), &cfg, quiet_log()).err().unwrap().to_string();
        assert!(e.contains(&format!("listen on tcp 127.0.0.1:{}", taken.local_addr().unwrap().port())), "{e}");
        // The public start refuses port 0.
        assert!(
            Relay::start(&Ctx::new(), &Config { listeners: vec![listener(Protocol::Tcp, &[be(echo.addr)])], limits: quick() }, quiet_log())
                .err()
                .unwrap()
                .to_string()
                .contains("no port")
        );
    }

    #[test]
    fn the_open_file_limit_covers_the_limits() {
        let need = fd_need(&good_config());
        assert_eq!(need, (2 * 4096 + 4096 + 2 + 3 + 64) as u64);
        raise_fd_limit(64).unwrap();
        let mut r = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: r is a valid rlimit to fill.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut r) }, 0);
        if r.rlim_max != libc::RLIM_INFINITY {
            assert!(raise_fd_limit(r.rlim_max + 1).unwrap_err().to_string().contains("LimitNOFILE"));
        }
    }
}
