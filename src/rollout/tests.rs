//! The rollout end to end in one process: a brain with the real registry
//! and its copy of the releases, servers with their own stores, lane 5's
//! update commands and kubectl as fakes, and a clock the tests move.

use super::*;
use crate::config::Config;
use crate::gotime::Time;
use crate::registry::{Heartbeat, Mesh};
use crate::runner::Runner;
use crate::signed::fake::Key;
use crate::testutil::{TempDir, put};
use chrono::TimeZone;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, MutexGuard};

const ADMIN: Key = Key("admin");
/// The k3s every machine runs.
const K3S: &[u8] = b"k3s v1.37.2+k3s1, the binary";
const OLD_BIN: &[u8] = b"\x7fELF dryserver 0.1.0, as installed";
const K3S_VERSION: &str = "v1.37.2+k3s1";
/// Minutes after midnight on the brain's clock.
const IN_WINDOW: u32 = 4 * 60;
const DAYTIME: u32 = 14 * 60;

fn t0() -> i64 {
    chrono::Utc.with_ymd_and_hms(2026, 11, 21, 4, 0, 0).unwrap().timestamp()
}

fn sha(b: &[u8]) -> String {
    fsx::hex(&Sha256::digest(b))
}

fn time(t: i64) -> Time {
    Time(chrono::DateTime::from_timestamp(t, 0).unwrap())
}

fn exe(root: &Path) -> PathBuf {
    fsx::under(root, "/proc/self/exe")
}

/// lane 5's `dryserver update` on one machine, and kubectl on the brain.
#[derive(Default)]
struct Sim {
    root: PathBuf,
    installed: u64,
    pending: u64,
    /// The last action: serial, what, how it ended, why.
    last: (u64, String, bool, String),
    apply_fails: Option<String>,
    /// The new binary does not come up: the old one keeps running.
    broken: bool,
    kubectl: Vec<String>,
    drain_fails: Vec<String>,
    cordon_fails: Vec<String>,
    /// The cluster's nodes; None: coord and node-a to node-h.
    nodes: Option<Vec<String>>,
    applied: Vec<Vec<String>>,
    confirmed: Vec<Vec<String>>,
    /// What ran before the pending release, for a revert.
    before: Vec<u8>,
    /// kubectl calls that kill the sync right after they ran.
    die_on: Vec<String>,
    /// The API server does not answer: every kubectl call fails.
    api_down: bool,
    /// `update status` does not answer this many more times.
    status_fails: u32,
    /// The machine's clock (the swarm's), for when last happened.
    clock: i64,
    last_at: i64,
    /// The detached apply still runs at this many more status calls; and
    /// how many each apply takes.
    busy: u32,
    slow: u32,
    /// The apply loads nothing (the archive is down) this many more times:
    /// postponed, nothing changed.
    postpone: u32,
    /// The apply refuses the release, nothing changed.
    refuse: Option<String>,
    /// The apply stopped part way (killed): its record stays installing.
    dies: bool,
    /// `update revert` cannot finish this many more times: the record
    /// stays, its stage reverting.
    revert_fails: u32,
    reverting: bool,
    /// The release brought a new main kernel (pending.kernel).
    kernel: bool,
    /// The apply rebooted the machine for new packages; restarts since.
    reboot: bool,
    boots: u32,
    /// `dryserver registry` through sshd does not answer (the brain).
    registry_down: bool,
    /// What `sshd -T` says of a login as the admin, instead of what it
    /// should.
    sshd_admin: Option<String>,
    /// sshd calls: ssh to the registry, sshd -T.
    sshd: Vec<String>,
    /// ssh-keygen calls (signing a turn, checking one).
    keygen: Vec<String>,
    /// A server: the coordinator's SSH does not answer at its LAN address
    /// (its firewall drops SSH from the home network).
    lan_down: bool,
    /// The brain: nft -c refuses its firewall.
    nft_fails: bool,
    /// A server: it has no way of its own to the coordinator's LAN
    /// address (its WiFi is down, WireGuard runs over the switch).
    no_route: bool,
}

/// What `sshd -T -C user=...` says on a machine set up as dryserver does.
fn sshd_t(user: &str) -> String {
    let force =
        if user == "dryreg" { crate::sysconf::registry_command(&crate::cidr::Cidr::parse("10.66.0.0/24").unwrap()) } else { "none".into() };
    format!(
        "PubkeyAuthentication yes\nPasswordAuthentication no\nAuthenticationMethods publickey\nForceCommand {force}\n\
         AuthorizedKeysFile .ssh/authorized_keys\nAllowUsers admin\nAllowUsers dryreg\n"
    )
}

struct Fake(Mutex<Sim>);

impl Fake {
    fn sim(&self) -> MutexGuard<'_, Sim> {
        self.0.lock().unwrap()
    }

    /// The revert timer fires: back to what ran before.
    fn revert(&self) {
        self.sim().revert("not confirmed before its deadline");
    }
}

impl Sim {
    fn revert(&mut self, why: &str) {
        if self.pending != 0 {
            self.done(self.pending, "reverted", true, why);
            self.pending = 0;
            self.dies = false;
            let b = self.before.clone();
            std::fs::write(exe(&self.root), b).unwrap();
        }
    }

    fn done(&mut self, serial: u64, action: &str, ok: bool, msg: &str) {
        self.last = (serial, action.into(), ok, msg.into());
        self.last_at = self.clock;
    }
}

impl Runner for Fake {
    fn run(&self, _: &Ctx, c: &Cmd) -> (String, Result<()>) {
        if let Some(out) = crate::signed::fake::host_run(c) {
            self.sim().keygen.push(c.args.join(" "));
            return out;
        }
        let mut s = self.sim();
        let a: Vec<&str> = c.args.iter().map(String::as_str).collect();
        match (c.name.as_str(), a.as_slice()) {
            ("k3s", ["kubectl", ..]) if s.api_down => {
                (String::new(), Err("k3s failed: exit status 1: The connection to the server 127.0.0.1:6443 was refused".into()))
            }
            (quarantine::SERVER_BIN, ["update", "status", "--json"]) if s.status_fails > 0 => {
                s.status_fails -= 1;
                (String::new(), Err(errf!("dryserver failed: killed after 30s")))
            }
            ("k3s", ["kubectl", "get", "nodes", "-o", "name"]) => {
                let names = s.nodes.clone().unwrap_or_else(|| {
                    std::iter::once("coord".to_string()).chain((b'a'..=b'h').map(|c| format!("node-{}", c as char))).collect()
                });
                (names.iter().map(|n| format!("node/{n}\n")).collect(), Ok(()))
            }
            ("k3s", ["kubectl", rest @ ..]) => {
                s.kubectl.push(rest.join(" "));
                if let Some(i) = s.die_on.iter().position(|d| *d == rest.join(" ")) {
                    s.die_on.remove(i);
                    drop(s);
                    panic!("the sync was killed");
                }
                if rest[0] == "cordon" && s.cordon_fails.iter().any(|n| Some(n.as_str()) == rest.last().copied()) {
                    return (String::new(), Err("k3s failed: exit status 1: the server is currently unable to handle the request".into()));
                }
                if rest[0] == "drain" && s.drain_fails.iter().any(|n| Some(n.as_str()) == rest.last().copied()) {
                    let e = "k3s failed: exit status 1: Cannot evict pod as it would violate the pod's disruption budget.";
                    return (String::new(), Err(e.into()));
                }
                (String::new(), Ok(()))
            }
            // Started in a service of its own: here it runs at once, and
            // its outcome shows in status (busy for a while, if told).
            (quarantine::SERVER_BIN, ["update", "apply", "--detach", "--reboot", "--release", rel, "--binary", bin, rest @ ..]) => {
                assert!(matches!(rest, ["--brain-k3s", _] | ["--k3s", _, "--brain-k3s", _]), "{c}");
                if let ["--k3s", k, ..] = rest {
                    assert!(std::fs::metadata(k).is_ok(), "{c}: the k3s file is not there");
                }
                s.applied.push(c.args.clone());
                let env: Envelope = serde_json::from_str(&std::fs::read_to_string(rel).unwrap()).unwrap();
                let r: Release = serde_json::from_str(&env.doc).unwrap();
                if s.postpone > 0 {
                    s.postpone -= 1;
                    let msg = format!("release {} not applied for now, nothing was installed (downloading the packages failed)", r.serial);
                    s.done(r.serial, "postponed", false, &msg);
                    return (String::new(), Ok(()));
                }
                if let Some(e) = s.refuse.clone() {
                    s.done(r.serial, "refused", false, &format!("release {} refused, nothing was changed: {e}", r.serial));
                    return (String::new(), Ok(()));
                }
                s.before = std::fs::read(exe(&s.root)).unwrap();
                if let Some(e) = s.apply_fails.clone() {
                    let msg = format!("release {} reverted (the apply failed: {e}); this machine runs what it ran before", r.serial);
                    s.done(r.serial, "reverted", true, &msg);
                    return (String::new(), Ok(()));
                }
                s.pending = r.serial;
                s.busy = s.slow;
                s.done(r.serial, "applied", true, "");
                if !s.broken {
                    std::fs::copy(bin, exe(&s.root)).unwrap();
                }
                (String::new(), Ok(()))
            }
            (quarantine::SERVER_BIN, ["update", "revert"]) => {
                if s.pending != 0 && s.revert_fails > 0 {
                    s.revert_fails -= 1;
                    s.reverting = true;
                    let e = "dryserver failed: exit status 1: putting back /usr/local/bin/dryserver failed: No space left on device";
                    return (String::new(), Err(e.into()));
                }
                s.reverting = false;
                s.revert("reverted by hand");
                (String::new(), Ok(()))
            }
            (quarantine::SERVER_BIN, ["update", "confirm", "--serial", n]) => {
                s.confirmed.push(c.args.clone());
                if s.pending == 0 || n.parse::<u64>().unwrap() != s.pending {
                    return (String::new(), Err("nothing to confirm".into()));
                }
                s.installed = s.pending;
                s.last = (s.pending, "confirmed".into(), true, String::new());
                s.pending = 0;
                (String::new(), Ok(()))
            }
            (quarantine::SERVER_BIN, ["update", "status", "--json"]) => {
                let pending = if s.pending == 0 {
                    serde_json::Value::Null
                } else {
                    let stage = if s.reverting {
                        "reverting"
                    } else if s.dies {
                        "installing"
                    } else {
                        "armed"
                    };
                    serde_json::json!({"serial": s.pending, "previous": if s.installed == 0 { serde_json::Value::Null } else { s.installed.into() },
                        "stage": stage, "step": "", "reboot": s.reboot, "deadline": 0, "seconds_left": 300, "boots": s.boots, "files": [],
                        "kernel": s.kernel})
                };
                let busy = s.busy > 0;
                if busy {
                    s.busy -= 1;
                }
                // Like the real `update status`: an applied release counts as
                // installed at once, pending until it is confirmed.
                let shown = if s.pending == 0 { s.installed } else { s.pending };
                let st = serde_json::json!({
                    "running": "0.1.0",
                    "installed": {"serial": shown, "version": "0.1.0", "k3s": K3S_VERSION},
                    "pending": pending,
                    "last": {"at": s.last_at, "serial": s.last.0, "action": s.last.1, "ok": s.last.2, "message": s.last.3},
                    "problems": [],
                    "busy": busy,
                });
                (st.to_string(), Ok(()))
            }
            // A server tries the coordinator's way in from the home network,
            // with the host key it pinned.
            ("ip", ["-4", "-o", "route", "get", "192.168.1.50"]) => {
                if s.no_route {
                    return (String::new(), Err("ip failed: exit status 2: RTNETLINK answers: Network is unreachable".into()));
                }
                ("192.168.1.50 dev eth0 src 192.168.1.21 uid 0 \\    cache \n".into(), Ok(()))
            }
            ("ssh", [.., "dryreg@192.168.1.50", "signed"]) => {
                s.sshd.push("ssh dryreg@192.168.1.50 signed".into());
                assert!(c.args.iter().any(|a| a.starts_with("UserKnownHostsFile=") && a.ends_with("known_hosts")), "{c}");
                if s.lan_down {
                    return (
                        String::new(),
                        Err("ssh failed: exit status 255: connect to host 192.168.1.50 port 22: Connection timed out".into()),
                    );
                }
                (r#"{"signed":{"doc":"","sig":""}}"#.into(), Ok(()))
            }
            ("nft", ["-c", "-f", f]) => {
                assert!(f.ends_with("/etc/nftables.conf"), "{c}");
                if s.nft_fails {
                    return (String::new(), Err("nft failed: exit status 1: syntax error".into()));
                }
                (String::new(), Ok(()))
            }
            ("ssh", [.., target, "signed"]) => {
                s.sshd.push(format!("ssh {target} signed"));
                assert!(c.args.iter().any(|a| a == "StrictHostKeyChecking=yes"), "{c}");
                if s.registry_down {
                    return (String::new(), Err("ssh failed: exit status 1: dryserver: registry: unknown command".into()));
                }
                (r#"{"signed":{"doc":"","sig":""}}"#.into(), Ok(()))
            }
            ("sshd", ["-T", "-C", spec]) => {
                s.sshd.push(format!("sshd -T -C {spec}"));
                let user = spec.strip_prefix("user=").and_then(|u| u.split(',').next()).unwrap_or_default();
                match (&s.sshd_admin, user) {
                    (Some(out), "admin") => (out.clone(), Ok(())),
                    _ => (sshd_t(user), Ok(())),
                }
            }
            _ => (String::new(), Err(errf!("unexpected command {c}"))),
        }
    }
}

/// The input chain of the firewall sysconf renders, as far as SSH goes.
const FIREWALL_TEXT: &str = "table inet dryserver {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\
    \t\tiifname \"wg0\" jump mesh\n\t\t# SSH from the WiFi/router network\n\
    \t\ttcp dport 22 ct state new add @ssh_meter4 { ip saddr limit rate over 10/minute burst 20 packets } drop\n\
    \t\ttcp dport 22 accept\n\t}\n\tchain mesh {\n\t\ttcp dport 22 accept\n\t}\n}\n";

/// A machine's SSH host key, "ssh-ed25519 BASE64".
fn host_key(name: &str) -> String {
    format!("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{}", name.replace('-', ""))
}

/// One machine: its own root, its fake commands.
struct Box_ {
    _dir: TempDir,
    node: Node,
    fake: Arc<Fake>,
    host: u32,
    name: String,
}

fn machine(host: u32, name: &str) -> Box_ {
    let dir = TempDir::new();
    put(dir.path(), "/proc/self/exe", OLD_BIN);
    put(dir.path(), K3S_BIN, K3S);
    put(dir.path(), crate::node::HOST_KEY, format!("{name} private\n"));
    put(dir.path(), crate::node::HOST_KEY_PUB, format!("{} root@{name}\n", host_key(name)));
    // What node.rs keeps: this machine's host number and the newest list
    // the admin signed, which names the coordinator's host key.
    put(dir.path(), crate::node::JOIN_STATE, format!("{{\"host\":{host}}}"));
    let coord =
        crate::signed::Entry { host: 1, name: "coord".into(), wg_key: crate::admin::tests::key32(1), ssh_host_key: host_key("coord") };
    let list =
        crate::signed::List { version: 1, members: vec![coord], rejected: vec![], keys: vec![], people: vec![], ..Default::default() };
    put(dir.path(), crate::node::SIGNED_FILE, serde_json::to_string(&crate::signed::seal(&ADMIN, &list).unwrap()).unwrap());
    put(dir.path(), "/tmp/.keep", "");
    put(dir.path(), FIREWALL, FIREWALL_TEXT);
    let fake = Arc::new(Fake(Mutex::new(Sim { root: dir.path().to_path_buf(), ..Sim::default() })));
    let node = Node {
        cfg: Config {
            wg_subnet: "10.66.0.0/24".into(),
            username: "admin".into(),
            coord_lan_ip: "192.168.1.50".into(),
            ..Config::default()
        },
        hostname: name.into(),
        root: dir.path().to_path_buf(),
        run: fake.clone(),
        tmp_dir: Some(dir.path().join("tmp")),
        verifier: Arc::new(ADMIN),
    };
    Box_ { _dir: dir, node, fake, host, name: name.into() }
}

struct MeshNet;

impl Mesh for MeshNet {
    fn host_of(&self, ip: Ipv4Addr) -> u32 {
        let o = ip.octets();
        if o[..3] == [10, 66, 0] { u32::from(o[3]) } else { 0 }
    }
    fn fits(&self, host: u32) -> bool {
        (1..=254).contains(&host)
    }
}

/// What a server's link to the brain does wrong, once.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Fault {
    /// Nothing goes wrong with this piece.
    Fine,
    /// The brain does not answer.
    Down,
    /// The piece is cut off half way.
    Cut,
    /// More comes than was asked for.
    More,
    /// The right length, one byte changed.
    Flip,
}

fn plenty(_: &Path) -> Option<u64> {
    None
}

fn full(_: &Path) -> Option<u64> {
    Some(100 << 20)
}

struct Swarm {
    now: i64,
    minute: u32,
    brain: Box_,
    servers: Vec<Box_>,
    store: Store,
    served: Served,
    /// Servers that do not sync.
    offline: Vec<u32>,
    /// Servers that send their heartbeat but never act on their turn.
    ignore_turn: Vec<u32>,
    /// Servers that run their fallback kernel.
    fallback: Vec<u32>,
    /// Servers whose k3s does not run.
    sick: Vec<u32>,
    /// The k3s version the brain reports.
    brain_k3s: String,
    faults: Mutex<Vec<(u32, Fault)>>,
    /// Pieces asked for: (host, name, offset).
    pieces: Mutex<Vec<(u32, String, u64)>>,
    /// Slow links: at most this many bytes of a piece come before its
    /// connection is cut off.
    slow: Vec<(u32, u64)>,
    /// Machines whose disk is full.
    full_disk: Vec<u32>,
    /// The members the admin signed, by host and name: the brain's sync
    /// hands the rollout only these (node::sync, signed_members).
    signed: Vec<(u32, String)>,
    /// The size of k3s the registry tells the servers, instead of its own.
    k3s_size_lie: Option<u64>,
    /// A hacked registry account's offer to each server, instead of what
    /// the registry would offer it.
    forge: Option<fn(&registry::State, u32) -> Offer>,
}

impl Swarm {
    fn new(servers: usize) -> Swarm {
        let brain = machine(1, "coord");
        let store = Store::new(brain.node.path(registry::DEFAULT_PATH));
        let served = Served::beside(&store, brain.node.path(K3S_BIN));
        let servers: Vec<Box_> = (0..servers).map(|i| machine(i as u32 + 2, &format!("node-{}", (b'a' + i as u8) as char))).collect();
        let now = t0();
        store
            .update(|s| {
                s.members = std::iter::once((1, "coord".to_string()))
                    .chain(servers.iter().map(|m| (m.host, m.name.clone())))
                    .map(|(host, name)| Member {
                        host,
                        name,
                        wg_key: crate::admin::tests::key32(host as u8),
                        last_seen: time(now),
                        ..Member::default()
                    })
                    .collect();
                Ok(())
            })
            .unwrap();
        let signed = std::iter::once((1, "coord".to_string())).chain(servers.iter().map(|m| (m.host, m.name.clone()))).collect();
        let sw = Swarm {
            now,
            minute: IN_WINDOW,
            brain,
            servers,
            store,
            served,
            offline: vec![],
            ignore_turn: vec![],
            sick: vec![],
            fallback: vec![],
            brain_k3s: K3S_VERSION.into(),
            faults: Mutex::new(vec![]),
            pieces: Mutex::new(vec![]),
            slow: vec![],
            full_disk: vec![],
            signed,
            k3s_size_lie: None,
            forge: None,
        };
        sw.brain_sync();
        for i in 0..sw.servers.len() {
            sw.server_sync(i).unwrap();
        }
        sw
    }

    fn server(&self, host: u32) -> &Box_ {
        self.servers.iter().find(|m| m.host == host).unwrap()
    }

    fn healthy(&self, host: u32) -> Report {
        Report {
            format: report::FORMAT,
            time: self.now,
            dryserver: "0.1.0".into(),
            k3s: if host == 1 { self.brain_k3s.clone() } else { K3S_VERSION.into() },
            k3s_active: Some(!self.sick.contains(&host)),
            boot: if self.fallback.contains(&host) { "fallback".into() } else { String::new() },
            firewall: Some(true),
            ..Report::default()
        }
    }

    /// One registry command, as from host (0: the admin on the home
    /// network).
    fn call(&self, cmd: &str, host: u32, input: &[u8]) -> Result<Vec<u8>> {
        let client = if host == 0 { "192.168.1.9 5000 22".to_string() } else { format!("10.66.0.{host} 5000 22") };
        let mut out = Vec::new();
        registry::serve(
            &self.store,
            &self.served,
            &MeshNet,
            &ADMIN,
            "ssh-ed25519 AAAA",
            cmd,
            &client,
            &mut &input[..],
            &mut out,
            time(self.now),
        )?;
        Ok(out)
    }

    fn free(&self, host: u32) -> fn(&Path) -> Option<u64> {
        if self.full_disk.contains(&host) { full } else { plenty }
    }

    fn brain_sync(&self) {
        self.brain.fake.sim().clock = self.now;
        let m = Machine { n: &self.brain.node, brain: true, free: self.free(1) };
        let mut rep = self.healthy(1);
        m.describe(&mut rep);
        let all = self
            .store
            .update(|s| {
                s.heartbeat(1, Heartbeat { report: Some(rep.clone()), ..Heartbeat::default() }, time(self.now))?;
                Ok(s.members.clone())
            })
            .unwrap();
        // What node::sync hands over (signed_members): the signed members,
        // with what the registry says of them; one it does not list is
        // still a member, of which nothing is known.
        let members: Vec<Member> = self
            .signed
            .iter()
            .map(|(h, n)| {
                all.iter().find(|m| m.host == *h && m.name == *n).cloned().unwrap_or(Member {
                    host: *h,
                    name: n.clone(),
                    ..Member::default()
                })
            })
            .collect();
        brain_tick_with(
            &Ctx::new(),
            &self.brain.node,
            &self.store,
            &self.served,
            &rep,
            Now { unix: self.now, minute: self.minute },
            &members,
            self.free(1),
        );
    }

    fn server_sync(&self, i: usize) -> Result<()> {
        let m = &self.servers[i];
        if self.offline.contains(&m.host) {
            return Ok(());
        }
        m.fake.sim().clock = self.now;
        let mach = Machine { n: &m.node, brain: false, free: self.free(m.host) };
        let mut rep = self.healthy(m.host);
        mach.describe(&mut rep);
        let hb = Heartbeat { lan_ip: format!("192.168.1.{}", 20 + m.host), report: Some(rep.clone()), ..Heartbeat::default() };
        self.store.update(|s| s.heartbeat(m.host, hb, time(self.now)))?;
        if self.ignore_turn.contains(&m.host) {
            return Ok(());
        }
        let o = self.forge.unwrap_or(offer)(&self.store.read()?, m.host);
        mach.step(&Ctx::new(), &Reg { sw: self, host: m.host }, &o, &rep, self.now)
    }

    /// A minute passes: the brain syncs, then every server.
    fn tick(&mut self) {
        self.now += 60;
        self.brain_sync();
        for i in 0..self.servers.len() {
            let _ = self.server_sync(i);
        }
        self.one_at_a_time();
    }

    fn ticks(&mut self, n: usize) {
        for _ in 0..n {
            self.tick();
        }
    }

    /// Ticks until f says yes, at most limit minutes.
    fn until(&mut self, limit: usize, f: impl Fn(&Swarm) -> bool) {
        for _ in 0..limit {
            if f(self) {
                return;
            }
            self.tick();
        }
        assert!(f(self), "not reached in {limit} minutes: {:#?}", self.rollout());
    }

    /// Minutes pass until f says yes right after the brain's sync, before
    /// the servers sync in that minute.
    fn brain_until(&mut self, limit: usize, f: impl Fn(&Swarm) -> bool) {
        for _ in 0..limit {
            self.now += 60;
            self.brain_sync();
            if f(self) {
                return;
            }
            for i in 0..self.servers.len() {
                let _ = self.server_sync(i);
            }
        }
        panic!("not reached in {limit} minutes: {:#?}", self.rollout());
    }

    /// Never two members updating at once, and never more than one node
    /// cordoned by the rollout.
    fn one_at_a_time(&self) {
        let members: Vec<u32> = self.store.read().unwrap().members.iter().map(|m| m.host).collect();
        let pending: Vec<u32> = std::iter::once(&self.brain)
            .chain(&self.servers)
            .filter(|m| members.contains(&m.host) && m.fake.sim().pending != 0)
            .map(|m| m.host)
            .collect();
        assert!(pending.len() <= 1, "updating at once: {pending:?}");
        let mut cordoned: Vec<String> = Vec::new();
        for line in &self.brain.fake.sim().kubectl {
            let f: Vec<&str> = line.split(' ').collect();
            let node = f[f.len() - 1];
            match f[0] {
                "cordon" if !cordoned.iter().any(|c| c == node) => cordoned.push(node.into()),
                "uncordon" => cordoned.retain(|c| c != node),
                _ => {}
            }
        }
        // A machine that left is deleted from the cluster with its cordon.
        let names: Vec<String> = self.store.read().unwrap().members.iter().map(|m| m.name.clone()).collect();
        cordoned.retain(|c| names.contains(c));
        // So is one the cluster dropped.
        if let Some(nodes) = &self.brain.fake.sim().nodes {
            cordoned.retain(|c| nodes.contains(c));
        }
        assert!(cordoned.len() <= 1, "cordoned at once: {cordoned:?}");
    }

    fn rollout(&self) -> Rollout {
        self.store.read().unwrap().rollout
    }

    fn installed(&self, host: u32) -> u64 {
        let b = if host == 1 { &self.brain } else { self.server(host) };
        Machine::new(&b.node, host == 1).installed_serial()
    }

    fn everyone_on(&self, serial: u64) -> bool {
        self.installed(1) == serial && self.servers.iter().all(|m| self.installed(m.host) == serial)
    }

    fn kubectl(&self) -> Vec<String> {
        self.brain.fake.sim().kubectl.clone()
    }

    fn release(&self, serial: u64, version: &str, urgent: bool) -> (Envelope, Vec<u8>) {
        let bin = format!("\x7fELF dryserver {version}, release {serial}").into_bytes();
        let r = Release {
            serial,
            created: self.now - 60,
            expires: self.now + release::LIFETIME,
            dryserver: release::Binary { version: version.into(), sha256: sha(&bin), size: bin.len() as u64 },
            k3s: release::K3s { version: K3S_VERSION.into(), sha256: sha(K3S) },
            arch_date: "2026/11/19".into(),
            rollback: false,
            urgent,
            notes: format!("release {serial}"),
            settings: None,
        };
        (release::seal(&ADMIN, &r).unwrap(), bin)
    }

    fn upload(&self, env: &Envelope, bin: &[u8], k3s: Option<&[u8]>) -> Result<u64> {
        let head = PutHeader { release: env.clone(), k3s_size: k3s.map_or(0, |k| k.len() as u64) };
        let mut input = (serde_json::to_string(&head).unwrap() + "\n").into_bytes();
        input.extend_from_slice(bin);
        if let Some(k) = k3s {
            input.extend_from_slice(k);
        }
        let out = self.call("release-put", 0, &input)?;
        Ok(serde_json::from_slice::<serde_json::Value>(&out).unwrap()["serial"].as_u64().unwrap())
    }

    fn publish(&self, serial: u64, urgent: bool) {
        let (env, bin) = self.release(serial, "0.2.0", urgent);
        assert_eq!(self.upload(&env, &bin, None).unwrap(), serial);
    }

    fn lines(&self) -> String {
        let s = self.store.read().unwrap();
        lines(&s.rollout, &s.members, self.now).into_iter().map(|(l, _)| l).collect::<Vec<_>>().join("\n")
    }

    fn fault(&self, host: u32, f: Fault) {
        self.faults.lock().unwrap().push((host, f));
    }

    /// The admin's `release resume`, or with skip `release resume -skip`,
    /// for the stop the registry shows.
    fn ask(&self, skip: bool) -> Result<Vec<u8>> {
        let op = if skip { "release-skip" } else { "release-resume" };
        self.call(op, 0, serde_json::to_string(&self.signed_ask(op, self.now)).unwrap().as_bytes())
    }

    /// An offer of the turn for host as root on the brain signs it, made
    /// now (g changes the grant before it is signed).
    fn granted(&self, host: u32, serial: u64, g: impl FnOnce(&mut Grant)) -> Offer {
        let mut grant =
            Grant { host, serial, brain_k3s: K3S_VERSION.into(), issued: self.now, expires: self.now + GRANT_LIFE, ..Grant::default() };
        g(&mut grant);
        let doc = serde_json::to_string(&grant).unwrap();
        let sig = crate::signed::fake::host_sig(&host_key("coord"), crate::signed::NS_TURN, &doc);
        Offer { serial, turn: true, brain_k3s: K3S_VERSION.into(), retry: grant.retry, grant: Envelope { doc, sig }, probe_lan: false }
    }

    /// The admin's ask for op at time, for the stop the registry shows.
    fn signed_ask(&self, op: &str, time: i64) -> Envelope {
        let r = self.rollout();
        crate::signed::seal_ask(&ADMIN, op, time, r.serial, r.pause_host).unwrap()
    }

    fn resume(&self) {
        self.ask(false).unwrap();
    }

    fn skip(&self) {
        self.ask(true).unwrap();
    }

    /// Ticks until f says yes, at most limit minutes, and never stops on
    /// the way.
    fn until_unpaused(&mut self, limit: usize, f: impl Fn(&Swarm) -> bool) {
        for _ in 0..limit {
            if f(self) {
                return;
            }
            self.tick();
            assert!(self.rollout().paused.is_empty(), "it stopped: {:#?}", self.rollout());
        }
        assert!(f(self), "not reached in {limit} minutes: {:#?}", self.rollout());
    }
}

/// A server asking the brain's registry, in process, from its mesh address.
struct Reg<'a> {
    sw: &'a Swarm,
    host: u32,
}

impl Source for Reg<'_> {
    fn offered(&self, ctx: &Ctx, serial: u64) -> Result<Offered> {
        if self.sw.forge.is_some() {
            // A hacked registry account hands the release to anyone.
            return LocalSource(&self.sw.served).offered(ctx, serial);
        }
        let out = self.sw.call(&format!("release-get {serial} release"), self.host, b"")?;
        let mut o: Offered = serde_json::from_slice(&out)?;
        if let Some(n) = self.sw.k3s_size_lie {
            o.k3s_size = n;
        }
        Ok(o)
    }

    fn chunk(&self, ctx: &Ctx, serial: u64, name: &str, offset: u64, len: u64, dst: &Path) -> Result<()> {
        self.sw.pieces.lock().unwrap().push((self.host, name.into(), offset));
        if self.sw.forge.is_some() {
            let len = len.min(file_len(&self.sw.served.path(serial, name)).saturating_sub(offset));
            return LocalSource(&self.sw.served).chunk(ctx, serial, name, offset, len, dst);
        }
        let fault = {
            let mut f = self.sw.faults.lock().unwrap();
            f.iter().position(|(h, _)| *h == self.host).map(|i| f.remove(i).1)
        };
        if fault == Some(Fault::Down) {
            bail!("ssh: connect to host 10.66.0.1 port 22: Connection timed out");
        }
        let mut out = self.sw.call(&format!("release-get {serial} {name} {offset}"), self.host, b"")?;
        match fault {
            Some(Fault::Cut) => out.truncate(out.len() / 2),
            Some(Fault::More) => out.extend_from_slice(b"and more"),
            Some(Fault::Flip) => out[0] ^= 1,
            _ => {}
        }
        if let Some(&(_, most)) = self.sw.slow.iter().find(|(h, _)| *h == self.host)
            && out.len() as u64 > most
        {
            // Like stream_to_file when its time runs out: what came is in
            // the file, and the piece failed.
            out.truncate(most as usize);
            std::fs::write(dst, &out)?;
            return Err(Error::deadline());
        }
        std::fs::write(dst, &out)?;
        Ok(())
    }
}

// ---- the window ----

#[test]
fn the_window_may_cross_midnight() {
    let normal = (3 * 60, 5 * 60);
    for (m, want) in [(179, false), (180, true), (299, true), (300, false), (0, false), (1439, false)] {
        assert_eq!(in_window(m, normal), want, "{m}");
    }
    let night = (23 * 60, 60);
    for (m, want) in [(22 * 60 + 59, false), (23 * 60, true), (23 * 60 + 59, true), (0, true), (59, true), (60, false), (12 * 60, false)] {
        assert_eq!(in_window(m, night), want, "{m}");
    }
    assert!(!(0..1440).any(|m| in_window(m, (100, 100))), "an empty window is never open");
    assert_eq!(window_text(WINDOW), "03:00-05:00");
    assert_eq!(window_text(night), "23:00-01:00");
}

// ---- the whole way ----

#[test]
fn a_release_reaches_every_machine_brain_first_then_one_at_a_time() {
    let mut sw = Swarm::new(3);
    sw.publish(10, false);
    // The brain first: no server is touched before it runs the release.
    for _ in 0..60 {
        let brain_before = sw.installed(1);
        sw.tick();
        let touched = sw.servers.iter().any(|m| !m.fake.sim().applied.is_empty()) || sw.kubectl().iter().any(|l| l.starts_with("cordon"));
        assert!(!touched || sw.installed(1) == 10, "a server was touched before the brain ran the release");
        if brain_before != 10 && touched {
            // In the minute the brain confirmed, at most the canary began.
            assert!(sw.servers[1..].iter().all(|m| m.fake.sim().applied.is_empty()));
        }
        if sw.everyone_on(10) {
            break;
        }
    }
    sw.ticks(2);
    let r = sw.rollout();
    assert_eq!((r.done.clone(), r.canary), (vec![2, 3, 4], 2));
    assert!(r.cordoned.is_empty() && r.turn.is_none() && r.paused.is_empty(), "{r:#?}");
    // Each server: cordoned, drained, updated, uncordoned, in host order.
    let k = sw.kubectl();
    let order: Vec<&String> = k.iter().filter(|l| !l.starts_with("drain") || l.contains("--ignore-daemonsets")).collect();
    let want = [
        "cordon -- node-a",
        "drain --ignore-daemonsets --delete-emptydir-data --timeout=25s -- node-a",
        "uncordon -- node-a",
        "cordon -- node-b",
        "drain --ignore-daemonsets --delete-emptydir-data --timeout=25s -- node-b",
        "uncordon -- node-b",
        "cordon -- node-c",
        "drain --ignore-daemonsets --delete-emptydir-data --timeout=25s -- node-c",
        "uncordon -- node-c",
    ];
    assert_eq!(order, want.iter().map(|s| s.to_string()).collect::<Vec<_>>().iter().collect::<Vec<_>>());
    // Each machine: installed from its own store, with the brain's k3s
    // version, and confirmed by serial. Nobody loaded k3s: every machine
    // has the release's.
    for m in std::iter::once(&sw.brain).chain(&sw.servers) {
        let inc = m.node.path(STORE).join(INCOMING);
        let path = |f: &str| inc.join(f).display().to_string();
        let want = [
            "update",
            "apply",
            "--detach",
            "--reboot",
            "--release",
            &path(RELEASE_FILE),
            "--binary",
            &path(DRYSERVER_FILE),
            "--brain-k3s",
            K3S_VERSION,
        ];
        assert_eq!(m.fake.sim().applied, vec![want.map(String::from).to_vec()], "{}", m.name);
        assert_eq!(m.fake.sim().confirmed, vec![vec!["update".to_string(), "confirm".into(), "--serial".into(), "10".into()]]);
    }
    assert!(!sw.pieces.lock().unwrap().iter().any(|p| p.1 == "k3s"));
    assert!(sw.lines().contains("3 of 3 servers on this release."), "{}", sw.lines());
    // The canary was watched before the next server got its turn.
    let a_done = sw.servers[0].fake.sim().installed;
    assert_eq!(a_done, 10);
    // Reports say so.
    let s = sw.store.read().unwrap();
    for m in &s.members {
        let rep = m.report.as_ref().unwrap();
        assert_eq!((rep.release, rep.update.as_str()), (10, ""), "{}", m.name);
    }
}

#[test]
fn the_canary_is_watched_before_the_next_turn() {
    let mut sw = Swarm::new(2);
    sw.publish(10, false);
    sw.until(30, |s| s.installed(2) == 10 && s.rollout().done == vec![2]);
    let until = sw.rollout().canary_until;
    assert!(until > sw.now, "the canary is watched");
    assert!(sw.lines().contains("Watching the canary node-a"), "{}", sw.lines());
    // Its k3s goes down while it is watched: the rollout stops.
    sw.sick.push(2);
    sw.ticks(2);
    let r = sw.rollout();
    assert_eq!(r.pause, Pause::Canary, "{r:#?}");
    assert!(r.paused.contains("the canary node-a is not well") && r.paused.contains("k3s is not running"), "{}", r.paused);
    assert!(!sw.kubectl().iter().any(|l| l == "cordon -- node-b"), "the next server got a turn");
    // The admin looks and goes on.
    sw.sick.clear();
    sw.resume();
    sw.until(30, |s| s.everyone_on(10));
}

#[test]
fn normal_releases_wait_for_the_window_urgent_ones_do_not() {
    let mut sw = Swarm::new(2);
    sw.minute = DAYTIME;
    sw.publish(10, false);
    sw.ticks(5);
    assert_eq!(sw.rollout().phase, Phase::Waiting);
    assert!(sw.brain.fake.sim().applied.is_empty(), "the brain updated outside the window");
    assert!(sw.lines().contains("Waiting for the update window 03:00-05:00 on the coordinator's clock."), "{}", sw.lines());
    // In the window it goes; when the window closes between two servers,
    // the next one waits for the next night.
    sw.minute = IN_WINDOW;
    sw.until(30, |s| s.rollout().done == vec![2]);
    sw.minute = DAYTIME;
    sw.ticks(10);
    assert!(sw.now > sw.rollout().canary_until);
    assert_eq!(sw.installed(3), 0, "a server updated outside the window");
    assert!(sw.lines().contains("Next server in the update window"), "{}", sw.lines());
    sw.minute = IN_WINDOW;
    sw.until(30, |s| s.everyone_on(10));

    // Urgent: at once, in the middle of the day; still one at a time.
    let mut sw = Swarm::new(2);
    sw.minute = DAYTIME;
    sw.publish(10, true);
    sw.until(30, |s| s.everyone_on(10));
    sw.ticks(2);
    let r = sw.rollout();
    assert!(r.urgent && r.done == vec![2, 3], "{r:#?}");
}

#[test]
fn a_swarm_of_one_brain() {
    let mut sw = Swarm::new(0);
    sw.publish(10, true);
    sw.until(5, |s| s.installed(1) == 10);
    sw.tick();
    let r = sw.rollout();
    assert_eq!(r.phase, Phase::Servers);
    assert!(sw.kubectl().is_empty(), "{:?}", sw.kubectl());
    assert!(sw.lines().contains("0 of 0 servers on this release."), "{}", sw.lines());
}

// ---- the brain ----

/// The brain's own update had no time limit: a hung apply showed "The
/// coordinator updates itself first." for ever. Now status says how long
/// it runs and what it says, and past TURN_TIMEOUT that it needs a look.
#[test]
fn review_a_brain_update_that_hangs_is_shown_to_need_a_look() {
    let mut sw = Swarm::new(1);
    sw.brain.fake.sim().slow = 100_000;
    sw.publish(10, true);
    sw.until(3, |s| s.brain.fake.sim().pending == 10);
    sw.tick();
    let flagged = |sw: &Swarm| {
        let s = sw.store.read().unwrap();
        lines(&s.rollout, &s.members, sw.now).into_iter().find(|(l, _)| l.contains("coordinator")).unwrap()
    };
    let (line, admin) = flagged(&sw);
    assert!(line.starts_with("The coordinator updates itself first (") && line.contains("its update says pending") && !admin, "{line}");
    sw.ticks(TURN_TIMEOUT as usize / 60 + 1);
    let (line, admin) = flagged(&sw);
    assert!(line.contains("own update runs for 1h") && line.contains("sudo dryserver update status") && admin, "{line}");
    assert!(sw.servers.iter().all(|m| m.fake.sim().applied.is_empty()), "nothing else moves");
    // Done after all: on it goes.
    sw.brain.fake.sim().busy = 0;
    sw.until(5, |s| s.installed(1) == 10);
    sw.tick();
    assert_eq!(sw.rollout().brain_since, 0);
}

#[test]
fn a_brain_whose_update_fails_touches_no_server() {
    let mut sw = Swarm::new(2);
    sw.brain.fake.sim().apply_fails = Some("dryserver failed: exit status 1: cannot install".into());
    sw.publish(10, true);
    sw.ticks(5);
    let r = sw.rollout();
    assert_eq!(r.phase, Phase::Failed, "{r:#?}");
    assert!(
        r.paused.contains(
            "own update to release 10 reverted: release 10 reverted (the apply failed: dryserver failed: exit status 1: cannot install)"
        ) && r.paused.contains("No server was touched"),
        "{}",
        r.paused
    );
    assert!(sw.lines().contains("FAILED:"), "{}", sw.lines());
    assert!(sw.kubectl().is_empty() && sw.servers.iter().all(|m| m.fake.sim().applied.is_empty()));
    assert_eq!(sw.brain.fake.sim().applied.len(), 1, "a failed update is not tried again by itself");
    // The admin fixed what was wrong and resumes: it tries again.
    sw.brain.fake.sim().apply_fails = None;
    sw.resume();
    sw.until(30, |s| s.everyone_on(10));
}

#[test]
fn a_brain_that_reverts_touches_no_server() {
    let mut sw = Swarm::new(2);
    // The new binary does not come up: it is never confirmed.
    sw.brain.fake.sim().broken = true;
    sw.publish(10, true);
    sw.ticks(5);
    assert_eq!(sw.brain.fake.sim().pending, 10);
    assert_eq!(sw.rollout().phase, Phase::Brain);
    let st = Machine::new(&sw.brain.node, true).load();
    assert!(st.note.contains("the new dryserver does not run yet"), "{st:?}");
    // The revert guard fires after its deadline.
    sw.brain.fake.revert();
    sw.tick();
    let r = sw.rollout();
    assert_eq!(r.phase, Phase::Failed);
    assert!(r.paused.contains("release 10 reverted") && r.paused.contains("not confirmed"), "{}", r.paused);
    sw.ticks(30);
    assert!(sw.kubectl().is_empty() && sw.servers.iter().all(|m| m.fake.sim().applied.is_empty()));
    assert_eq!(sw.installed(1), 0);
    assert_eq!(sw.brain.fake.sim().applied.len(), 1, "a release that went back is not sent again by itself");
    // The admin found the problem and resumes: only then it is tried again.
    sw.brain.fake.sim().broken = false;
    sw.resume();
    sw.until(30, |s| s.everyone_on(10));
    assert_eq!(sw.brain.fake.sim().applied.len(), 2);
}

#[test]
fn a_brain_that_is_not_healthy_does_not_confirm() {
    let mut sw = Swarm::new(1);
    sw.sick.push(1);
    sw.publish(10, true);
    sw.ticks(5);
    assert_eq!((sw.brain.fake.sim().pending, sw.installed(1)), (10, 0));
    assert!(Machine::new(&sw.brain.node, true).load().note.contains("k3s is not running"));
    sw.sick.clear();
    sw.until(10, |s| s.everyone_on(10));
}

// ---- servers ----

#[test]
fn a_server_offline_at_its_turn_updates_when_it_is_back() {
    let mut sw = Swarm::new(3);
    sw.offline.push(2);
    sw.store
        .update(|s| {
            s.members.iter_mut().find(|m| m.host == 2).unwrap().last_seen = time(t0() - 3600);
            Ok(())
        })
        .unwrap();
    sw.publish(10, true);
    sw.until(60, |s| s.installed(3) == 10 && s.installed(4) == 10);
    assert_eq!(sw.installed(2), 0);
    assert!(!sw.kubectl().iter().any(|l| l == "cordon -- node-a"), "an offline server got a turn");
    assert_eq!(sw.rollout().canary, 3, "the first server that updated is the canary");
    assert!(sw.lines().contains("Silent, updates when back: node-a"), "{}", sw.lines());
    // It comes back, and gets its turn.
    sw.offline.clear();
    sw.until(30, |s| s.everyone_on(10));
}

#[test]
fn a_server_that_goes_silent_in_its_turn_is_passed_over_until_it_is_back() {
    let mut sw = Swarm::new(2);
    sw.publish(10, true);
    sw.brain_until(10, |s| s.rollout().turn.is_some());
    assert_eq!(sw.rollout().turn.unwrap().host, 2);
    // node-a is switched off the moment its turn came.
    sw.offline.push(2);
    sw.ticks(TURN_TIMEOUT as usize / 60 + 2);
    let r = sw.rollout();
    assert!(r.paused.is_empty(), "silence is not a failure: {r:#?}");
    assert!(r.deferred.contains(&2) && r.warnings.iter().any(|w| w.contains("node-a went silent when its turn came")), "{r:#?}");
    assert!(sw.kubectl().contains(&"uncordon -- node-a".to_string()));
    sw.until(20, |s| s.installed(3) == 10);
    sw.offline.clear();
    sw.until(30, |s| s.everyone_on(10));
}

#[test]
fn a_server_with_its_kill_switch_on_is_held() {
    let mut sw = Swarm::new(3);
    // node-b cut node-c off: an incident, it changes nothing now.
    put(&sw.server(3).node.root, quarantine::STATE_FILE, r#"{"cuts":[{"name":"node-c","hosts":[4]}]}"#);
    sw.publish(10, true);
    sw.until(60, |s| s.installed(2) == 10 && s.installed(4) == 10);
    assert_eq!(sw.installed(3), 0);
    assert!(!sw.kubectl().iter().any(|l| l == "cordon -- node-b"));
    let rep = sw.store.read().unwrap().members.iter().find(|m| m.host == 3).unwrap().report.clone().unwrap();
    assert_eq!(rep.update, "held");
    assert!(rep.update_note.contains("kill switch is on (node-c cut off)"), "{}", rep.update_note);
    assert!(sw.lines().contains("Held, kill switch on: node-b."), "{}", sw.lines());
    // Even handed a turn, it does nothing.
    let m = Machine { n: &sw.server(3).node, brain: false, free: plenty };
    let o = sw.granted(3, 10, |_| {});
    m.step(&Ctx::new(), &Reg { sw: &sw, host: 3 }, &o, &sw.healthy(3), sw.now).unwrap();
    assert!(sw.server(3).fake.sim().applied.is_empty());
    // Lifted: it updates.
    std::fs::remove_file(sw.server(3).node.path(quarantine::STATE_FILE)).unwrap();
    sw.until(30, |s| s.everyone_on(10));
}

#[test]
fn a_server_removed_in_its_turn() {
    let mut sw = Swarm::new(2);
    sw.publish(10, true);
    sw.until(10, |s| s.rollout().turn.is_some_and(|t| t.ready));
    sw.ignore_turn.push(2);
    sw.signed.retain(|(h, _)| *h != 2);
    sw.store
        .update(|s| {
            s.members.retain(|m| m.host != 2);
            Ok(())
        })
        .unwrap();
    // It can no longer load anything.
    assert!(sw.call("release-get 10 release", 2, b"").unwrap_err().to_string().contains("not a member"));
    sw.offline.push(2);
    sw.tick();
    let r = sw.rollout();
    assert!(r.warnings.iter().any(|w| w.contains("node-a left the swarm during its turn")), "{r:#?}");
    assert!(!r.cordoned.contains(&"node-a".to_string()));
    sw.until(30, |s| s.installed(3) == 10);
    assert!(sw.rollout().paused.is_empty());
}

#[test]
fn a_claim_of_success_without_the_new_release_is_not_success() {
    let mut sw = Swarm::new(2);
    // node-a says it is fine, and never updates.
    sw.ignore_turn.push(2);
    sw.publish(10, true);
    sw.until(10, |s| s.rollout().turn.is_some_and(|t| t.ready));
    sw.ticks(TURN_TIMEOUT as usize / 60 + 2);
    let r = sw.rollout();
    assert_eq!(r.pause, Pause::Timeout, "{r:#?}");
    assert!(r.paused.contains("node-a (the canary) did not finish its update in 1h: it runs release 0"), "{}", r.paused);
    // It runs its old release well: uncordoned, and nobody else is touched.
    sw.ticks(5);
    assert!(!sw.rollout().cordoned.contains(&"node-a".to_string()), "{:#?}", sw.rollout());
    assert!(!sw.kubectl().iter().any(|l| l == "cordon -- node-b"));
    assert_eq!(sw.rollout().pause, Pause::Timeout, "it waits for the admin");
    assert!(sw.lines().contains("PAUSED:") && sw.lines().contains("(node-a tries again)"), "{}", sw.lines());
    // The admin resumes: node-a has its turn again, and stalls again.
    sw.resume();
    sw.until(5, |s| s.rollout().turn.is_some_and(|t| t.host == 2 && t.retry != 0));
    sw.until(TURN_TIMEOUT as usize / 60 + 5, |s| s.rollout().pause == Pause::Timeout);
    assert!(!sw.kubectl().iter().any(|l| l == "cordon -- node-b"));
    // Passed over on the admin's word: uncordoned, and the others go on.
    sw.skip();
    sw.until(30, |s| s.installed(3) == 10);
    let r = sw.rollout();
    assert!(r.skipped.iter().any(|s| s.host == 2) && !r.cordoned.contains(&"node-a".to_string()), "{r:#?}");
    assert!(sw.lines().contains("Passed over: node-a:"), "{}", sw.lines());
    assert_eq!(sw.installed(2), 0);
}

/// What a hacked registry account wrote into the registry's rollout made
/// root run `kubectl uncordon -lkubernetes.io/hostname`, `drain coord` and
/// `drain -lkubernetes.io/hostname` (every node). Root keeps its own
/// rollout, takes only the resume count from the registry, and names a
/// node to kubectl only after `--`, when the cluster lists it and it is
/// not the brain.
#[test]
fn the_registry_account_cannot_steer_kubectl() {
    let mut sw = Swarm::new(2);
    let evil = "-lkubernetes.io/hostname";
    let plant = |sw: &Swarm| {
        let now = sw.now;
        sw.store
            .update(|s| {
                if !s.members.iter().any(|m| m.host == 9) {
                    let report = Some(Report { format: report::FORMAT, time: now, ..Report::default() });
                    let wg_key = crate::admin::tests::key32(9);
                    s.members.push(Member { host: 9, name: evil.into(), wg_key, last_seen: time(now), report, ..Member::default() });
                }
                s.rollout.cordoned = vec![evil.into(), "coord".into()];
                s.rollout.turn = Some(Turn { host: 1, name: "coord".into(), since: now, ..Turn::default() });
                s.rollout.phase = Phase::Servers;
                s.rollout.done.clear();
                Ok(())
            })
            .unwrap();
    };
    plant(&sw);
    sw.tick();
    sw.publish(10, true);
    for _ in 0..60 {
        plant(&sw);
        sw.tick();
        if sw.everyone_on(10) {
            break;
        }
    }
    assert!(sw.everyone_on(10), "{:#?}", sw.rollout());
    let k = sw.kubectl();
    assert!(!k.is_empty());
    for line in &k {
        assert!(!line.contains("-l") && !line.contains("coord"), "{k:?}");
        assert!(line.ends_with(" -- node-a") || line.ends_with(" -- node-b"), "{k:?}");
    }

    // Even root's own state cannot name such a node, the brain, or one
    // the cluster does not have.
    let n = &sw.brain.node;
    let members = sw.store.read().unwrap().members;
    let served = Served::beside(&sw.store, n.path(K3S_BIN));
    let rep = sw.healthy(1);
    let mut b = Brain {
        ctx: &Ctx::new(),
        n,
        served: &served,
        rep: &rep,
        now: Now { unix: sw.now, minute: IN_WINDOW },
        members: &members,
        r: Rollout::default(),
        free: plenty,
        nodes: None,
    };
    let long = "a".repeat(64);
    for name in [evil, "coord", "node-z", "a\nb", "", " node-a", "node-a ", "Node-a", &long, "node-a\0", "--all", "-", "node-a/x"] {
        let e = b.kubectl(&["drain"], name).unwrap_err();
        assert!(name != "node-z" || e.is_not_found(), "{e}");
        b.r.cordoned = vec![name.into()];
        b.uncordon(name);
        assert!(b.r.cordoned.is_empty(), "{name}: {:?}", b.r.cordoned);
    }
    b.r.turn = Some(Turn { host: 1, name: "coord".into(), since: sw.now, ..Turn::default() });
    b.turn();
    assert!(b.r.turn.is_none());
    assert_eq!(sw.kubectl(), k, "kubectl ran for a refused name");
}

#[test]
fn a_hacked_server_speaks_for_itself_only() {
    let mut sw = Swarm::new(3);
    sw.publish(10, true);
    sw.until(10, |s| s.rollout().turn.is_some_and(|t| t.ready && t.host == 2));
    // node-c, hacked, wants the release out of turn, from the home network,
    // for another serial, or files that are none.
    for (host, cmd) in [
        (4, "release-get 10 release"),
        (4, "release-get 10 dryserver 0"),
        (0, "release-get 10 release"),
        (77, "release-get 10 release"),
        (2, "release-get 9 release"),
        (2, "release-get 10 ../../etc/shadow 0"),
        (2, "release-get 10 dryserver -1"),
        (2, "release-get x release"),
    ] {
        assert!(sw.call(cmd, host, b"").is_err(), "{host}: {cmd}");
    }
    // It claims to run the release: only its own entry says so, and only
    // it is counted done without an update.
    let lie = Report { release: 10, ..sw.healthy(4) };
    sw.store.update(|s| s.heartbeat(4, Heartbeat { report: Some(lie), ..Heartbeat::default() }, time(sw.now))).unwrap();
    sw.ignore_turn.push(4);
    sw.until(60, |s| s.installed(2) == 10 && s.installed(3) == 10);
    sw.ticks(2);
    assert_eq!(sw.installed(4), 0);
    assert!(!sw.kubectl().iter().any(|l| l == "cordon -- node-c"), "its word was taken for itself only");
    // Its report cannot reach another member's entry either: the registry
    // knows callers by their mesh address.
    let s = sw.store.read().unwrap();
    assert_eq!(s.members.iter().find(|m| m.host == 3).unwrap().report.as_ref().unwrap().release, 10);
}

/// A hacked server that reports failures and updates in the middle while
/// it is not its turn changes nothing for the others; at its own turn its
/// lie stops the rollout there, at it.
#[test]
fn a_hacked_server_lying_out_of_turn_stops_only_its_own_turn() {
    let mut sw = Swarm::new(3);
    sw.offline.push(4);
    sw.publish(10, true);
    let lies = ["failed", "pending", "refused", "reverted", "fetching"];
    for i in 0..60 {
        let lie = Report { update: lies[i % lies.len()].into(), update_serial: 10, update_note: "lies".into(), ..sw.healthy(4) };
        sw.store.update(|s| s.heartbeat(4, Heartbeat { report: Some(lie), ..Heartbeat::default() }, time(sw.now))).unwrap();
        sw.tick();
        if !sw.rollout().paused.is_empty() {
            break;
        }
    }
    let r = sw.rollout();
    assert_eq!((sw.installed(2), sw.installed(3)), (10, 10), "{r:#?}");
    assert_eq!((r.pause, r.pause_host), (Pause::Failed, 4), "{r:#?}");
    assert!(sw.server(4).fake.sim().applied.is_empty());
}

/// A server whose report says its kill switch is on whenever its turn
/// comes, and off between (a hacked server, or a registry account that
/// forges its reports), was cordoned and drained again and again. Now it
/// gets MAX_TURNS turns, then the rollout stops at it for the admin.
#[test]
fn a_server_held_at_every_turn_gets_max_turns() {
    let mut sw = Swarm::new(2);
    sw.ignore_turn.push(2);
    sw.publish(10, true);
    let cut = sw.server(2).node.path(quarantine::STATE_FILE);
    for _ in 0..120 {
        if sw.rollout().turn.is_some_and(|t| t.host == 2 && t.ready) {
            put(&sw.server(2).node.root, quarantine::STATE_FILE, r#"{"cuts":[{"name":"node-b","hosts":[3]}]}"#);
        } else {
            let _ = std::fs::remove_file(&cut);
        }
        sw.tick();
        if !sw.rollout().paused.is_empty() {
            break;
        }
    }
    let r = sw.rollout();
    assert_eq!((r.pause, r.pause_host), (Pause::Timeout, 2), "{r:#?}");
    assert!(r.paused.contains("node-a had its turn 3 times, and each ended without its update"), "{}", r.paused);
    assert_eq!(sw.installed(3), 10, "the others went on meanwhile");
    let cordons = sw.kubectl().iter().filter(|l| *l == "cordon -- node-a").count();
    assert_eq!(cordons, MAX_TURNS);
    // The admin looks and resumes: its turns count again, and it updates.
    let _ = std::fs::remove_file(&cut);
    sw.ignore_turn.clear();
    sw.resume();
    sw.until_unpaused(30, |s| s.everyone_on(10));
}

#[test]
fn a_server_that_holds_its_turn_does_not_stall_the_rollout_for_ever() {
    let mut sw = Swarm::new(2);
    sw.publish(10, true);
    // node-a takes its turn, installs, and then never confirms (it reports
    // pending for ever).
    sw.server(2).fake.sim().broken = true;
    sw.until(10, |s| s.server(2).fake.sim().pending == 10);
    sw.ticks(TURN_TIMEOUT as usize / 60 + 2);
    let r = sw.rollout();
    assert_eq!(r.pause, Pause::Timeout);
    assert!(r.paused.contains("its update says pending"), "{}", r.paused);
    // It is up and not well: cordoned. When it goes back to its old release
    // and runs well, it is uncordoned, the rollout still waits for the admin.
    assert!(r.cordoned.contains(&"node-a".to_string()));
    sw.server(2).fake.revert();
    sw.ticks(3);
    let r = sw.rollout();
    assert!(!r.cordoned.contains(&"node-a".to_string()) && r.pause == Pause::Timeout, "{r:#?}");
    let rep = sw.store.read().unwrap().members.iter().find(|m| m.host == 2).unwrap().report.clone().unwrap();
    assert_eq!((rep.update.as_str(), rep.update_serial), ("reverted", 10));
    assert!(sw.lines().contains("node-a") && sw.lines().contains("PAUSED"), "{}", sw.lines());
}

#[test]
fn a_canary_that_fails_stops_the_rollout() {
    let mut sw = Swarm::new(3);
    sw.server(2).fake.sim().apply_fails = Some("dryserver failed: exit status 1: no space left on device".into());
    sw.publish(10, true);
    sw.until(20, |s| !s.rollout().paused.is_empty());
    let r = sw.rollout();
    assert_eq!(r.pause, Pause::Failed);
    assert!(
        r.paused.contains(
            "node-a (the canary): update reverted: release 10 reverted (the apply failed: dryserver failed: exit status 1: no space left"
        ),
        "{}",
        r.paused
    );
    sw.ticks(10);
    assert!(sw.servers[1..].iter().all(|m| m.fake.sim().applied.is_empty()), "a server after a failed canary updated");
    // It runs its old release well: not held cordoned.
    assert!(!sw.rollout().cordoned.contains(&"node-a".to_string()), "{:#?}", sw.rollout());
    assert_eq!(sw.server(2).fake.sim().applied.len(), 1, "a failed update is not tried again by itself");
}

#[test]
fn a_server_that_refuses_the_release_stops_the_rollout() {
    let mut sw = Swarm::new(2);
    // The brain reports an older k3s than the release's: a server never
    // runs a newer k3s than the control plane, whatever the brain says.
    sw.brain_k3s = "v1.36.1+k3s1".into();
    sw.publish(10, true);
    sw.until(20, |s| !s.rollout().paused.is_empty());
    let l = Machine::new(&sw.server(2).node, false).load();
    assert_eq!((l.failed, l.outcome.as_str()), (10, "refused"));
    assert!(l.why.contains("would be newer than the brain's"), "{l:?}");
    let r = sw.rollout();
    assert_eq!(r.pause, Pause::Failed, "{r:#?}");
    assert!(r.paused.contains("node-a (the canary): update refused: k3s v1.37.2+k3s1 would be newer"), "{}", r.paused);
    assert!(sw.server(2).fake.sim().applied.is_empty());
    sw.ticks(3);
    assert!(sw.server(3).fake.sim().applied.is_empty() && !sw.rollout().cordoned.contains(&"node-a".to_string()));
}

#[test]
fn a_kill_switch_that_goes_on_in_its_turn_passes_the_turn_on() {
    let mut sw = Swarm::new(2);
    sw.ignore_turn.push(2);
    sw.publish(10, true);
    sw.until(10, |s| s.rollout().turn.is_some_and(|t| t.ready && t.host == 2));
    put(&sw.server(2).node.root, quarantine::STATE_FILE, r#"{"cuts":[{"name":"node-b","hosts":[3]}]}"#);
    sw.ignore_turn.clear();
    sw.ticks(2);
    let r = sw.rollout();
    assert!(r.paused.is_empty() && r.deferred.contains(&2), "{r:#?}");
    assert!(r.warnings.iter().any(|w| w.contains("node-a's kill switch went on during its turn")), "{r:#?}");
    assert!(sw.server(2).fake.sim().applied.is_empty());
    sw.until(30, |s| s.installed(3) == 10);
}

// ---- gaps in the rollout ----

impl Swarm {
    /// A server the admin approved: in the member list, and syncing.
    fn join(&mut self, host: u32, name: &str) {
        let m = machine(host, name);
        let now = self.now;
        self.store
            .update(|s| {
                s.members.push(Member {
                    host,
                    name: name.into(),
                    wg_key: crate::admin::tests::key32(host as u8),
                    last_seen: time(now),
                    ..Member::default()
                });
                Ok(())
            })
            .unwrap();
        self.servers.push(m);
        self.signed.push((host, name.into()));
    }

    /// A server the admin removed from the member list.
    fn remove(&mut self, host: u32) {
        self.store
            .update(|s| {
                s.members.retain(|m| m.host != host);
                Ok(())
            })
            .unwrap();
        self.servers.retain(|m| m.host != host);
        self.signed.retain(|(h, _)| *h != host);
    }
}

/// Off for days (past the release's expiry, too): passed over while it is,
/// and it catches up once it is back; in the window for a normal release.
#[test]
fn a_server_off_for_days_catches_up() {
    for urgent in [true, false] {
        let mut sw = Swarm::new(2);
        sw.offline.push(2);
        sw.publish(10, urgent);
        sw.until(60, |s| s.installed(3) == 10);
        sw.now += 40 * release::DAY;
        sw.minute = DAYTIME;
        sw.offline.clear();
        sw.ticks(10);
        if !urgent {
            assert_eq!(sw.installed(2), 0, "it updated outside the window");
            sw.minute = IN_WINDOW;
        }
        sw.until_unpaused(30, |s| s.everyone_on(10));
    }
}

/// A server approved while a rollout runs, or after it finished, gets the
/// release too: one at a time, after the others.
#[test]
fn a_server_that_joins_during_or_after_a_rollout_updates() {
    let mut sw = Swarm::new(2);
    sw.publish(10, true);
    sw.until(10, |s| s.rollout().turn.is_some_and(|t| t.host == 2));
    sw.join(4, "node-c");
    sw.until_unpaused(40, |s| s.everyone_on(10));
    sw.ticks(2);
    assert_eq!(sw.rollout().done, vec![2, 3, 4]);
    // Joined after it was done.
    sw.join(5, "node-d");
    sw.until_unpaused(20, |s| s.everyone_on(10));
    sw.ticks(2);
    assert_eq!(sw.rollout().done, vec![2, 3, 4, 5]);
    assert!(sw.lines().contains("4 of 4 servers on this release."), "{}", sw.lines());
}

/// Removed while the rollout is stopped at it: there is nothing left to
/// wait for, and the rollout goes on by itself.
#[test]
fn a_server_removed_while_the_rollout_is_stopped_at_it() {
    let mut sw = Swarm::new(2);
    sw.server(2).fake.sim().apply_fails = Some("dryserver failed: exit status 1: broken disk".into());
    sw.publish(10, true);
    sw.until(20, |s| !s.rollout().paused.is_empty());
    sw.remove(2);
    sw.until_unpaused(30, |s| s.installed(3) == 10);
    let r = sw.rollout();
    assert!(r.warnings.iter().any(|w| w == "node-a left the swarm; the rollout goes on"), "{r:#?}");
    assert!(!r.cordoned.contains(&"node-a".to_string()));
}

/// The lists name host numbers, and a machine that joins later may get the
/// number of one that left: it must not count as done, nor as passed over.
#[test]
fn a_new_machine_with_the_host_number_of_one_that_left_updates() {
    let mut sw = Swarm::new(2);
    sw.publish(10, true);
    sw.until(30, |s| s.everyone_on(10));
    sw.ticks(2);
    assert_eq!(sw.rollout().done, vec![2, 3]);
    sw.remove(2);
    sw.tick();
    sw.join(2, "node-x");
    sw.until_unpaused(20, |s| s.everyone_on(10));
    sw.ticks(2);
    assert_eq!(sw.rollout().done, vec![3, 2]);
}

/// One passed over that runs the release after all (the admin updated it
/// by hand, or its update came through late) counts as done.
#[test]
fn a_server_passed_over_that_updates_after_all_counts_as_done() {
    let mut sw = Swarm::new(2);
    sw.server(2).fake.sim().apply_fails = Some("dryserver failed: exit status 1: broken disk".into());
    sw.publish(10, true);
    sw.until(20, |s| !s.rollout().paused.is_empty());
    sw.skip();
    sw.until(30, |s| s.installed(3) == 10);
    assert!(sw.lines().contains("Passed over: node-a"), "{}", sw.lines());
    // The admin updated it by hand: it runs the release after all.
    let m = Machine::new(&sw.server(2).node, false);
    m.save(&Local { installed: 10, ..Local::default() }).unwrap();
    sw.until(10, |s| s.rollout().done.contains(&2));
    assert!(sw.rollout().skipped.is_empty() && sw.lines().contains("2 of 2 servers on this release."), "{}", sw.lines());
}

/// A turn that timed out, and the server then confirms (its update took
/// long): the rollout goes on by itself.
#[test]
fn a_server_that_confirms_after_its_turn_timed_out() {
    let mut sw = Swarm::new(2);
    sw.server(2).fake.sim().broken = true;
    sw.publish(10, true);
    sw.until(10, |s| s.server(2).fake.sim().pending == 10);
    sw.until(TURN_TIMEOUT as usize / 60 + 5, |s| s.rollout().pause == Pause::Timeout);
    std::fs::copy(sw.server(2).node.path(STORE).join(INCOMING).join(DRYSERVER_FILE), exe(&sw.server(2).node.root)).unwrap();
    sw.until(10, |s| s.rollout().paused.is_empty());
    assert!(sw.rollout().warnings.iter().any(|w| w.contains("node-a finished its update after all")), "{:#?}", sw.rollout());
    sw.until_unpaused(30, |s| s.everyone_on(10));
}

/// A new release while a server is in the middle of the old one (installed,
/// not confirmed yet): the brain waits for it before it updates itself, so
/// never two machines update at once (one_at_a_time checks every minute).
/// A server that says it is in the middle for ever holds it up for
/// TURN_TIMEOUT, then the rollout stops there for the admin (it went on by
/// itself before, beside a server that may still have been updating).
#[test]
fn a_new_release_waits_for_the_server_in_the_middle_of_the_old_one() {
    let mut sw = Swarm::new(2);
    sw.server(2).fake.sim().broken = true;
    sw.publish(10, true);
    sw.until(10, |s| s.server(2).fake.sim().pending == 10);
    sw.publish(11, true);
    sw.ticks(5);
    let r = sw.rollout();
    assert!(r.serial == 11 && r.phase == Phase::Brain && r.wait_for == 2, "{r:#?}");
    assert_eq!(sw.brain.fake.sim().applied.len(), 1, "the brain updated while node-a did");
    assert!(sw.lines().contains("The coordinator updates itself first, once node-a finished the update it is in."), "{}", sw.lines());
    // node-a's revert guard: back to its old release. Then the brain.
    sw.server(2).fake.revert();
    sw.server(2).fake.sim().broken = false;
    sw.until(60, |s| s.everyone_on(11));

    // A lie: pending for ever, nothing installed.
    let mut sw = Swarm::new(2);
    sw.ignore_turn.push(2);
    sw.publish(10, true);
    sw.until(10, |s| s.rollout().turn.is_some_and(|t| t.ready && t.host == 2));
    Machine::new(&sw.server(2).node, false).save(&Local { pending: 10, applied: sw.now, ..Local::default() }).unwrap();
    sw.publish(11, true);
    let start = sw.now;
    sw.until(TURN_TIMEOUT as usize / 60 + 5, |s| s.rollout().pause == Pause::Timeout);
    assert!(sw.now - start >= TURN_TIMEOUT, "it waited {}s", sw.now - start);
    sw.ticks(10);
    assert_eq!(sw.brain.fake.sim().applied.len(), 1, "the brain went on by itself");
    // Passed over on the admin's word: the brain goes on.
    sw.skip();
    sw.until(5, |s| s.brain.fake.sim().applied.len() == 2);
    let r = sw.rollout();
    assert!(r.warnings.iter().any(|w| w.contains("node-a is passed over for release 11; the coordinator updates itself")), "{r:#?}");
    assert!(!r.cordoned.contains(&"node-a".to_string()), "{r:#?}");
}

/// A normal release published while a server is in the middle of the
/// urgent one: the server finishes, and its node is uncordoned then, not at
/// 03:00 when the new release's window opens. The same while the brain's
/// own update failed (Phase::Failed).
#[test]
fn review_a_server_done_with_the_old_release_is_uncordoned_before_the_window() {
    for brain_fails in [false, true] {
        let mut sw = Swarm::new(3);
        sw.server(3).fake.sim().slow = 100_000;
        sw.publish(10, true);
        sw.until(120, |s| s.server(3).fake.sim().pending == 10);
        sw.minute = DAYTIME;
        sw.publish(11, false);
        sw.ticks(2);
        assert!(sw.rollout().phase == Phase::Waiting && sw.rollout().wait_for == 3, "{:#?}", sw.rollout());
        if brain_fails {
            let m = Machine::new(&sw.brain.node, true);
            let r = Rollout { phase: Phase::Failed, paused: "the coordinator's own update to release 11 failed".into(), ..m.own_rollout() };
            m.save_rollout(&r).unwrap();
            sw.ticks(2);
        }
        assert!(sw.rollout().cordoned.contains(&"node-b".to_string()), "{:#?}", sw.rollout());
        (sw.server(3).fake.sim().busy, sw.server(3).fake.sim().slow) = (0, 0);
        sw.until(10, |s| s.installed(3) == 10);
        sw.ticks(30);
        let k = sw.kubectl();
        let un = k.iter().rposition(|x| x == "uncordon -- node-b");
        let co = k.iter().rposition(|x| x == "cordon -- node-b" || x.starts_with("drain") && x.ends_with("-- node-b"));
        assert!(un > co, "node-b stays cordoned until the window: {k:?}");
        let r = sw.rollout();
        assert!(!r.cordoned.contains(&"node-b".to_string()) && r.wait_for == 0, "{r:#?}");
        if brain_fails {
            assert_eq!(r.phase, Phase::Failed, "{r:#?}");
        } else {
            assert_eq!((r.phase, sw.installed(1)), (Phase::Waiting, 10), "nothing else moved before the window: {r:#?}");
        }
    }
}

/// The brain's sync killed (or the brain switched off) right after it
/// cordoned a server: the cordon was not written down, and once another
/// server got the turn the first stayed cordoned for good.
#[test]
fn a_sync_killed_after_the_cordon_still_uncordons() {
    let mut sw = Swarm::new(2);
    // The brain's sync dies in the cordon.
    sw.brain.fake.sim().die_on.push("cordon -- node-a".into());
    sw.publish(10, true);
    let mut died = false;
    for _ in 0..10 {
        sw.now += 60;
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sw.brain_sync())).is_err() {
            died = true;
            break;
        }
        for i in 0..sw.servers.len() {
            let _ = sw.server_sync(i);
        }
    }
    assert!(died && sw.kubectl().contains(&"cordon -- node-a".to_string()));
    // Off before it ever got the turn: another one does.
    sw.offline.push(2);
    sw.store
        .update(|s| {
            s.members.iter_mut().find(|m| m.host == 2).unwrap().last_seen = time(0);
            Ok(())
        })
        .unwrap();
    sw.until(30, |s| s.installed(3) == 10);
    sw.ticks(3);
    let k = sw.kubectl();
    let last = |verb: &str| k.iter().rposition(|l| l == &format!("{verb} -- node-a"));
    assert!(last("uncordon") > last("cordon"), "node-a stays cordoned: {k:?}");
    assert!(!sw.rollout().cordoned.contains(&"node-a".to_string()));
}

/// The sync killed after `update apply` and before it wrote down that it
/// did: the next sync takes the installed release over and confirms it.
#[test]
fn a_sync_killed_after_apply_takes_its_update_over() {
    for host in [1, 2] {
        let mut sw = Swarm::new(1);
        sw.publish(10, true);
        let b = if host == 1 { &sw.brain } else { sw.server(2) };
        let (fake, dir) = (b.fake.clone(), b.node.path(STORE));
        sw.until(10, |_| fake.sim().pending == 10);
        // What step wrote after apply is lost.
        std::fs::remove_file(dir.join(STATE_FILE)).unwrap();
        sw.until(10, |s| s.everyone_on(10));
        assert_eq!(fake.sim().applied.len(), 1, "{host}: installed twice");
        assert_eq!(fake.sim().confirmed.len(), 1);
    }
}

/// Disk full: the release waits for room, a few syncs, then the update
/// failed there; room made in time and it goes on.
#[test]
fn a_full_disk_waits_for_room_then_fails() {
    let mut sw = Swarm::new(1);
    sw.full_disk.push(2);
    sw.publish(10, true);
    sw.until(10, |s| s.rollout().turn.is_some_and(|t| t.ready));
    sw.ticks(3);
    let l = Machine::new(&sw.server(2).node, false).load();
    assert!(l.failed == 0 && l.note.contains("must stay free"), "{l:?}");
    sw.full_disk.clear();
    sw.until_unpaused(20, |s| s.everyone_on(10));

    let mut sw = Swarm::new(1);
    sw.full_disk.push(2);
    sw.publish(10, true);
    sw.until(MAX_TRIES as usize + 10, |s| !s.rollout().paused.is_empty());
    assert!(sw.rollout().paused.contains("update failed: this machine has 100 MiB free"), "{}", sw.rollout().paused);

    // The brain's own disk: its update fails, no server is touched.
    let mut sw = Swarm::new(1);
    sw.full_disk.push(1);
    sw.publish(10, true);
    sw.until(MAX_TRIES as usize + 5, |s| s.rollout().phase == Phase::Failed);
    assert!(sw.rollout().paused.contains("must stay free"), "{}", sw.rollout().paused);
    assert!(sw.kubectl().is_empty());
}

/// The release's k3s file on the coordinator is gone or another one: every
/// server with another k3s would refuse it in turn. The brain finds out
/// before the first server.
#[test]
fn a_release_whose_k3s_is_gone_on_the_brain_touches_no_server() {
    for damage in [None, Some(&b"another k3s"[..])] {
        let mut sw = Swarm::new(1);
        sw.publish(10, true);
        let at = sw.served.path(10, K3S_FILE);
        match damage {
            None => std::fs::remove_file(&at).unwrap(),
            Some(b) => std::fs::write(&at, b).unwrap(),
        }
        sw.until(10, |s| s.rollout().phase == Phase::Failed);
        let r = sw.rollout();
        assert!(r.paused.contains("release 10 cannot go to the servers") && r.paused.contains("k3s v1.37.2+k3s1"), "{}", r.paused);
        assert!(sw.lines().contains("FAILED:"), "{}", sw.lines());
        assert!(sw.kubectl().is_empty() && sw.servers.iter().all(|m| m.fake.sim().applied.is_empty()));
        // Put back and resumed.
        std::fs::write(&at, K3S).unwrap();
        sw.resume();
        sw.until(30, |s| s.everyone_on(10));
    }

    // Gone after the check, while a server that needs it loads: it asks
    // again, a few times, and goes on once it is back.
    let mut sw = Swarm::new(1);
    put(&sw.server(2).node.root, K3S_BIN, b"k3s v1.36.0+k3s1, older");
    sw.publish(10, true);
    sw.brain_until(10, |s| s.rollout().phase == Phase::Servers);
    let at = sw.served.path(10, K3S_FILE);
    std::fs::remove_file(&at).unwrap();
    sw.ticks(4);
    let l = Machine::new(&sw.server(2).node, false).load();
    assert!(l.failed == 0 && l.note.contains("the coordinator has no k3s v1.37.2+k3s1 for release 10"), "{l:?}");
    std::fs::write(&at, K3S).unwrap();
    sw.until_unpaused(20, |s| s.everyone_on(10));
}

/// The rollout took its servers from the registry's member list, which the
/// registry account writes. Now it takes the list the admin signed, as the
/// mesh and the cluster do: a machine the registry account adds never gets
/// a turn (nor its name to kubectl), and one it drops is still a server.
#[test]
fn the_rollout_follows_only_the_signed_members() {
    let mut sw = Swarm::new(2);
    let now = sw.now;
    sw.store
        .update(|s| {
            let report = Some(Report { format: report::FORMAT, time: now, firewall: Some(true), ..Report::default() });
            s.members.push(Member {
                host: 9,
                name: "rogue".into(),
                wg_key: crate::admin::tests::key32(9),
                last_seen: time(now),
                report,
                ..Member::default()
            });
            Ok(())
        })
        .unwrap();
    let plant = |sw: &Swarm| {
        let now = sw.now;
        sw.store
            .update(|s| {
                if let Some(m) = s.members.iter_mut().find(|m| m.host == 9) {
                    m.last_seen = time(now);
                }
                // node-b is gone from its list, or under another name.
                s.members.retain(|m| m.host != 3);
                Ok(())
            })
            .unwrap();
    };
    sw.publish(10, true);
    for _ in 0..30 {
        plant(&sw);
        sw.tick();
    }
    assert_eq!((sw.installed(2), sw.installed(3)), (10, 0));
    assert!(!sw.kubectl().iter().any(|l| l.contains("rogue")), "{:?}", sw.kubectl());
    let r = sw.rollout();
    assert!(!r.done.contains(&9) && r.turn.is_none() && r.paused.is_empty(), "{r:#?}");
    // Listed again: node-b updates too.
    let b = sw.server(3).name.clone();
    sw.store
        .update(|s| {
            s.members.push(Member { host: 3, name: b, wg_key: crate::admin::tests::key32(3), last_seen: time(now), ..Member::default() });
            Ok(())
        })
        .unwrap();
    sw.until_unpaused(30, |s| s.everyone_on(10));
}

/// What the registry account may write in its copy of the rollout: root
/// reads back only the admin's counts, and passes over or tries again only
/// the server it stopped at itself.
#[test]
fn the_registry_account_cannot_choose_what_is_passed_over() {
    let mut sw = Swarm::new(3);
    sw.server(2).fake.sim().apply_fails = Some("dryserver failed: exit status 1: broken disk".into());
    sw.publish(10, true);
    sw.until(20, |s| !s.rollout().paused.is_empty());
    // It names another server and gives it a retry, and the admin, shown
    // that, passes node-b over: root stopped at node-a, so that ask does
    // nothing.
    let skip_b = crate::signed::seal_ask(&ADMIN, "release-skip", sw.now, 10, 3).unwrap();
    sw.store
        .update(|s| {
            s.rollout.pause_host = 3;
            s.rollout.pause_name = "node-b".into();
            s.rollout.skipped.push(Skip { host: 4, name: "node-c".into(), why: "x".into() });
            s.rollout.again.push(4);
            s.rollout.skip_ask = skip_b;
            s.rollout.skip_asked += 3;
            Ok(())
        })
        .unwrap();
    sw.tick();
    let r = sw.rollout();
    assert!(r.skipped.is_empty() && r.again.is_empty() && (r.pause, r.pause_host) == (Pause::Failed, 2), "{r:#?}");
    // The admin's skip of node-a passes node-a over, and only it.
    sw.skip();
    sw.tick();
    let r = sw.rollout();
    assert_eq!(r.skipped.iter().map(|s| s.host).collect::<Vec<_>>(), vec![2], "{r:#?}");
    sw.until_unpaused(30, |s| s.installed(3) == 10 && s.installed(4) == 10);
}

// ---- resuming ----

/// `release resume` used to pass a failed server over and never try it
/// again. Now it tries the server first; its report from before it heard
/// of the resume, which still shows the failure, does not stop the rollout
/// again.
#[test]
fn resume_tries_the_failed_server_again() {
    let mut sw = Swarm::new(2);
    sw.server(2).fake.sim().apply_fails = Some("dryserver failed: exit status 1: no space left on device".into());
    sw.publish(10, true);
    sw.until(20, |s| !s.rollout().paused.is_empty());
    let l = sw.lines();
    assert!(l.contains("Look at it, then: dryserver release resume (node-a tries again)"), "{l}");
    assert!(l.contains("Or pass node-a over for this release: dryserver release resume -skip"), "{l}");
    // The admin made room on node-a and resumes.
    sw.server(2).fake.sim().apply_fails = None;
    sw.resume();
    sw.until_unpaused(30, |s| s.everyone_on(10));
    sw.ticks(2);
    let r = sw.rollout();
    assert!(r.paused.is_empty() && r.done == vec![2, 3] && r.again.is_empty() && r.skipped.is_empty(), "{r:#?}");
    assert!(r.warnings.iter().any(|w| w == "resumed: node-a tries release 10 again, now"), "{r:#?}");
    assert_eq!(sw.server(2).fake.sim().applied.len(), 2, "tried once more, no more");
    let l = Machine::new(&sw.server(2).node, false).load();
    assert_eq!((l.failed, l.retry), (0, 0), "{l:?}");
}

/// A release that went back is installed again only because the admin
/// resumed.
#[test]
fn resume_installs_a_release_that_went_back_again() {
    let mut sw = Swarm::new(1);
    sw.server(2).fake.sim().broken = true;
    sw.publish(10, true);
    sw.until(10, |s| s.server(2).fake.sim().pending == 10);
    sw.server(2).fake.revert();
    sw.until(5, |s| !s.rollout().paused.is_empty());
    sw.ticks(5);
    assert_eq!(sw.server(2).fake.sim().applied.len(), 1, "not again by itself");
    sw.server(2).fake.sim().broken = false;
    sw.resume();
    sw.until_unpaused(30, |s| s.everyone_on(10));
    assert_eq!(sw.server(2).fake.sim().applied.len(), 2);
}

/// Resumed, installed again, and it goes back again: the rollout stops
/// there again, and the same resume does not make it install a third time
/// (installing cleared what it knew of the resume it acted on).
#[test]
fn a_release_that_goes_back_again_after_a_resume_is_not_tried_a_third_time() {
    let mut sw = Swarm::new(2);
    sw.server(2).fake.sim().broken = true;
    sw.publish(10, true);
    sw.until(10, |s| s.server(2).fake.sim().pending == 10);
    sw.server(2).fake.revert();
    sw.until(5, |s| !s.rollout().paused.is_empty());
    sw.resume();
    sw.until(10, |s| s.server(2).fake.sim().pending == 10);
    assert_eq!(sw.server(2).fake.sim().applied.len(), 2);
    // It goes back while its turn still stands.
    sw.server(2).fake.revert();
    sw.until(5, |s| !s.rollout().paused.is_empty());
    sw.ticks(10);
    let r = sw.rollout();
    assert!(r.paused.contains("node-a (the canary): update reverted again"), "{}", r.paused);
    assert_eq!(sw.server(2).fake.sim().applied.len(), 2, "installed again without a resume");
    let l = Machine::new(&sw.server(2).node, false).load();
    assert_eq!((l.failed, l.outcome.as_str()), (10, "reverted"), "{l:?}");
    assert!(sw.server(3).fake.sim().applied.is_empty());
}

/// One that fails again stops the rollout again; -skip passes it over and
/// the others go on. It keeps its release.
#[test]
fn a_server_that_fails_again_is_stopped_at_again_until_skipped() {
    let mut sw = Swarm::new(2);
    sw.server(2).fake.sim().apply_fails = Some("dryserver failed: exit status 1: broken disk".into());
    sw.publish(10, true);
    sw.until(20, |s| !s.rollout().paused.is_empty());
    sw.resume();
    sw.tick();
    assert!(sw.rollout().paused.is_empty(), "{:#?}", sw.rollout());
    sw.until(10, |s| !s.rollout().paused.is_empty());
    let r = sw.rollout();
    assert_eq!((r.pause, r.pause_host), (Pause::Failed, 2), "{r:#?}");
    assert!(r.paused.contains("node-a (the canary): update reverted again: release 10 reverted (the apply failed: dryserver failed: exit status 1: broken disk"), "{}", r.paused);
    assert_eq!(sw.server(2).fake.sim().applied.len(), 2);
    assert!(sw.server(3).fake.sim().applied.is_empty());
    // Resumed twice: tried twice more.
    sw.resume();
    sw.until(10, |s| s.server(2).fake.sim().applied.len() == 3 && !s.rollout().paused.is_empty());
    sw.skip();
    sw.until(30, |s| s.installed(3) == 10);
    sw.ticks(2);
    let r = sw.rollout();
    assert!(r.skipped.iter().any(|s| s.host == 2 && s.why.contains("broken disk")) && r.again.is_empty(), "{r:#?}");
    assert!(r.warnings.iter().any(|w| w == "resumed: node-a is passed over for release 10"), "{r:#?}");
    assert!(!r.cordoned.contains(&"node-a".to_string()));
    assert_eq!((sw.installed(2), sw.server(2).fake.sim().applied.len()), (0, 3));
    assert!(sw.lines().contains("Passed over: node-a: node-a (the canary): update reverted again"), "{}", sw.lines());
}

/// Resumed while it is switched off: the others go on, and it tries again
/// once it is back.
#[test]
fn resume_at_a_server_that_is_off_tries_it_when_it_is_back() {
    let mut sw = Swarm::new(2);
    sw.server(2).fake.sim().apply_fails = Some("dryserver failed: exit status 1: no space left on device".into());
    sw.publish(10, true);
    sw.until(20, |s| !s.rollout().paused.is_empty());
    sw.offline.push(2);
    sw.ticks(OFFLINE as usize / 60 + 1);
    sw.server(2).fake.sim().apply_fails = None;
    sw.resume();
    sw.until_unpaused(30, |s| s.installed(3) == 10);
    let r = sw.rollout();
    assert!(r.warnings.iter().any(|w| w == "resumed: node-a tries release 10 again, when it is back"), "{r:#?}");
    assert!(r.again == vec![2] && r.skipped.is_empty(), "{r:#?}");
    assert!(sw.lines().contains("Tries again at its next turn, as you resumed: node-a."), "{}", sw.lines());
    sw.offline.clear();
    sw.until_unpaused(30, |s| s.everyone_on(10));
    sw.ticks(2);
    assert!(sw.rollout().again.is_empty() && sw.rollout().done.contains(&2), "{:#?}", sw.rollout());
}

/// A resume outside the window of a normal release waits for the window.
#[test]
fn resume_of_a_normal_release_waits_for_the_window() {
    let mut sw = Swarm::new(1);
    sw.server(2).fake.sim().apply_fails = Some("dryserver failed: exit status 1: no space left on device".into());
    sw.publish(10, false);
    sw.until(20, |s| !s.rollout().paused.is_empty());
    sw.server(2).fake.sim().apply_fails = None;
    sw.minute = DAYTIME;
    sw.resume();
    sw.ticks(10);
    assert!(sw.rollout().warnings.iter().any(|w| w.ends_with("again, in the update window")), "{:#?}", sw.rollout());
    assert_eq!(sw.server(2).fake.sim().applied.len(), 1);
    sw.minute = IN_WINDOW;
    sw.until_unpaused(30, |s| s.everyone_on(10));
}

/// What resume and -skip do at each kind of stop, and that the brain is
/// never passed over: the registry refuses it, and root treats a skip the
/// registry account counted anyway as a resume.
#[test]
fn skip_passes_over_a_server_but_never_the_brain() {
    // A drain that does not finish: -skip passes it over, undrained and
    // not updated.
    let mut sw = Swarm::new(2);
    sw.brain.fake.sim().drain_fails.push("node-a".into());
    sw.publish(10, false);
    sw.until(30, |s| !s.rollout().paused.is_empty());
    let l = sw.lines();
    assert!(l.contains("dryserver release resume (updates node-a without draining)") && l.contains("-skip"), "{l}");
    sw.skip();
    sw.until(30, |s| s.installed(3) == 10);
    assert!(sw.server(2).fake.sim().applied.is_empty() && sw.rollout().skipped.iter().any(|s| s.host == 2));

    // The canary: resume goes on, there is nothing to pass over.
    let mut sw = Swarm::new(2);
    sw.publish(10, false);
    sw.until(30, |s| s.installed(2) == 10 && s.rollout().done == vec![2]);
    sw.sick.push(2);
    sw.ticks(2);
    let l = sw.lines();
    assert!(l.contains("dryserver release resume (goes on)") && !l.contains("-skip"), "{l}");
    sw.sick.clear();
    sw.skip();
    sw.until_unpaused(30, |s| s.everyone_on(10));

    // The brain.
    let mut sw = Swarm::new(1);
    sw.brain.fake.sim().apply_fails = Some("dryserver failed: exit status 1: cannot install".into());
    sw.publish(10, true);
    sw.ticks(3);
    assert_eq!(sw.rollout().phase, Phase::Failed);
    let e = sw.ask(true).unwrap_err().to_string();
    assert!(e.contains("never passed over") && e.contains("dryserver release resume"), "{e}");
    sw.brain.fake.sim().apply_fails = None;
    // The registry account keeps the admin's skip anyway: a resume.
    let skip = sw.signed_ask("release-skip", sw.now);
    sw.store
        .update(|s| {
            s.rollout.skip_ask = skip;
            Ok(())
        })
        .unwrap();
    sw.until(30, |s| s.everyone_on(10));
    assert!(sw.rollout().warnings.iter().any(|w| w.contains("tries its own update again (it is never passed over")), "{:#?}", sw.rollout());

    // Nothing stopped: there is nothing to pass over.
    let mut sw = Swarm::new(1);
    sw.publish(10, true);
    sw.tick();
    assert!(sw.ask(true).unwrap_err().to_string().contains("not stopped at a server"));
}

// ---- transfers ----

#[test]
fn a_cut_off_or_oversized_piece_is_loaded_again() {
    let size = sw_bin_len();
    for (fault, then) in [(Fault::Cut, size / 2), (Fault::More, 0), (Fault::Down, 0)] {
        let mut sw = Swarm::new(1);
        sw.fault(2, fault);
        sw.publish(10, true);
        sw.until(30, |s| s.everyone_on(10));
        let pieces = sw.pieces.lock().unwrap().clone();
        // What came of a cut piece stays; more than asked for does not.
        assert_eq!(pieces, vec![(2, "dryserver".to_string(), 0), (2, "dryserver".to_string(), then)], "{fault:?}");
    }
}

/// The size of the dryserver binary of Swarm::release.
fn sw_bin_len() -> u64 {
    Swarm::new(0).release(10, "0.2.0", true).1.len() as u64
}

/// A release of size bytes of dryserver.
fn big_release(sw: &Swarm, serial: u64, size: u64) -> (Envelope, Vec<u8>) {
    let big: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
    let (env, _) = sw.release(serial, "0.2.0", true);
    let mut r: Release = serde_json::from_str(&env.doc).unwrap();
    r.dryserver.sha256 = sha(&big);
    r.dryserver.size = big.len() as u64;
    (release::seal(&ADMIN, &r).unwrap(), big)
}

/// A 16 MiB piece took longer than its time on a slow link, and every try
/// started it over: a slow server never finished. Now what came stays and
/// the next piece starts where it ended, a few connections per sync at
/// most, and the whole file is checked before it is used.
#[test]
fn a_slow_link_gets_on_at_every_sync() {
    let mut sw = Swarm::new(1);
    let mib = 1 << 20;
    sw.slow.push((2, mib));
    let (env, big) = big_release(&sw, 10, 10 * mib);
    sw.upload(&env, &big, None).unwrap();
    sw.until(10, |s| s.rollout().turn.is_some_and(|t| t.ready));
    let mut syncs = Vec::new();
    while !sw.everyone_on(10) && syncs.len() < 10 {
        let before = sw.pieces.lock().unwrap().len();
        sw.tick();
        syncs.push(sw.pieces.lock().unwrap().len() - before);
    }
    assert!(sw.everyone_on(10), "{:#?}", sw.rollout());
    assert!(syncs.iter().all(|n| *n <= MAX_PIECES as usize), "pieces per sync: {syncs:?}");
    let offsets: Vec<u64> = sw.pieces.lock().unwrap().iter().filter(|p| p.0 == 2).map(|p| p.2).collect();
    assert_eq!(offsets, (0..10).map(|i| i * mib).collect::<Vec<_>>(), "each byte once");
    assert_eq!(std::fs::read(exe(&sw.server(2).node.root)).unwrap(), big);
    let note = Machine::new(&sw.server(2).node, false).load().note;
    assert!(note.is_empty(), "{note}");

    // One byte changed on the way, in a piece that was cut: refused, and
    // nothing of it is kept.
    let mut sw = Swarm::new(1);
    sw.slow.push((2, mib));
    for _ in 0..3 {
        sw.fault(2, Fault::Fine);
    }
    sw.fault(2, Fault::Flip);
    let (env, big) = big_release(&sw, 10, 10 * mib);
    sw.upload(&env, &big, None).unwrap();
    sw.until(20, |s| !s.rollout().paused.is_empty());
    let l = Machine::new(&sw.server(2).node, false).load();
    assert_eq!((l.failed, l.outcome.as_str()), (10, "refused"), "{l:?}");
    assert!(l.why.contains("does not match the release"), "{}", l.why);
    assert!(sw.server(2).fake.sim().applied.is_empty());
    assert!(!sw.server(2).node.path(STORE).join(INCOMING).join("dryserver.part").exists());
    // Resumed with the link fixed, it loads it again whole.
    sw.resume();
    sw.until_unpaused(30, |s| s.everyone_on(10));
}

/// The registry's copy of the binary went missing (the registry account,
/// a damaged disk): the brain tried to load it at every sync for ever, and
/// the rollout said only that the brain updates itself. Now it is a problem
/// that may pass, and after MAX_TRIES syncs its own update failed.
#[test]
fn a_brain_whose_copy_of_the_release_is_gone_stops() {
    let mut sw = Swarm::new(1);
    let (env, bin) = sw.release(10, "0.2.0", true);
    sw.upload(&env, &bin, None).unwrap();
    std::fs::remove_file(sw.served.path(10, DRYSERVER_FILE)).unwrap();
    sw.until(MAX_TRIES as usize + 3, |s| s.rollout().phase == Phase::Failed);
    let r = sw.rollout();
    assert!(r.paused.contains("update to release 10 failed: dryserver of release 10 on the coordinator"), "{}", r.paused);
    assert_eq!(Machine::new(&sw.brain.node, true).load().tries, MAX_TRIES);
    assert!(sw.kubectl().is_empty());
    // Resumed, it has its MAX_TRIES syncs again, not one.
    sw.resume();
    sw.ticks(3);
    assert_eq!(sw.rollout().phase, Phase::Brain, "{:#?}", sw.rollout());
    // Put back: it goes on.
    std::fs::write(sw.served.path(10, DRYSERVER_FILE), &bin).unwrap();
    sw.until(30, |s| s.everyone_on(10));
}

/// A slow server whose turn timed out keeps what it loaded: resumed, it
/// goes on from there.
#[test]
fn a_slow_server_that_timed_out_goes_on_where_it_was() {
    let mut sw = Swarm::new(1);
    let mib = 1 << 20;
    sw.slow.push((2, mib));
    let (env, big) = big_release(&sw, 10, 10 * mib);
    sw.upload(&env, &big, None).unwrap();
    // One sync's pieces, then it stops answering its turn.
    sw.until(10, |s| !s.pieces.lock().unwrap().is_empty());
    sw.ignore_turn.push(2);
    sw.until(TURN_TIMEOUT as usize / 60 + 5, |s| s.rollout().pause == Pause::Timeout);
    let had = sw.pieces.lock().unwrap().len();
    assert_eq!(had, MAX_PIECES as usize);
    assert!(sw.rollout().paused.contains("its update says fetching"), "{}", sw.rollout().paused);
    sw.ignore_turn.clear();
    sw.resume();
    sw.until_unpaused(30, |s| s.everyone_on(10));
    let offsets: Vec<u64> = sw.pieces.lock().unwrap().iter().map(|p| p.2).collect();
    assert_eq!(offsets, (0..10).map(|i| i * mib).collect::<Vec<_>>(), "nothing loaded twice");
    assert_eq!(std::fs::read(exe(&sw.server(2).node.root)).unwrap(), big);
}

#[test]
fn a_changed_file_is_refused() {
    let mut sw = Swarm::new(2);
    sw.fault(2, Fault::Flip);
    sw.publish(10, true);
    sw.until(20, |s| !s.rollout().paused.is_empty());
    let l = Machine::new(&sw.server(2).node, false).load();
    assert_eq!((l.failed, l.outcome.as_str()), (10, "refused"));
    assert!(l.why.contains("dryserver from the coordinator does not match the release"), "{}", l.why);
    assert!(sw.server(2).fake.sim().applied.is_empty(), "a wrong binary was installed");
    assert!(sw.rollout().paused.contains("update refused"), "{}", sw.rollout().paused);
}

#[test]
fn a_large_release_comes_in_pieces_across_syncs() {
    let mut sw = Swarm::new(1);
    let (env, big) = big_release(&sw, 10, CHUNK + 1000);
    // The second piece is cut off: the first one stays, and so does what
    // came of the second; the next piece starts where it ended.
    sw.fault(2, Fault::Fine);
    sw.fault(2, Fault::Cut);
    sw.upload(&env, &big, None).unwrap();
    sw.until(20, |s| s.everyone_on(10));
    let mine: Vec<u64> = sw.pieces.lock().unwrap().iter().filter(|p| p.0 == 2).map(|p| p.2).collect();
    assert_eq!(mine, vec![0, CHUNK, CHUNK + 500], "each byte once");
    assert_eq!(std::fs::read(exe(&sw.server(2).node.root)).unwrap(), big);
}

#[test]
fn a_server_with_another_k3s_loads_the_releases() {
    let mut sw = Swarm::new(1);
    put(&sw.server(2).node.root, K3S_BIN, b"k3s v1.36.0+k3s1, older");
    sw.publish(10, true);
    sw.until(30, |s| s.everyone_on(10));
    // Loaded, checked and kept with the installed release, for when the
    // update commands install k3s too.
    assert!(sw.pieces.lock().unwrap().iter().any(|p| p == &(2, "k3s".to_string(), 0)));
    let kept = sw.server(2).node.path(STORE).join(INSTALLED).join(K3S_FILE);
    assert_eq!(std::fs::read(kept).unwrap(), K3S);
    // The others did not need it.
    assert!(!sw.brain.node.path(STORE).join(INSTALLED).join(K3S_FILE).exists());
}

#[test]
fn a_release_that_went_back_is_not_sent_again_by_itself() {
    let mut sw = Swarm::new(2);
    sw.server(2).fake.sim().broken = true;
    sw.publish(10, true);
    sw.until(10, |s| s.server(2).fake.sim().pending == 10);
    sw.server(2).fake.revert();
    sw.until(5, |s| !s.rollout().paused.is_empty());
    let r = sw.rollout();
    assert_eq!(r.pause, Pause::Failed, "{r:#?}");
    assert!(r.paused.contains("node-a (the canary): update reverted: not confirmed before its deadline"), "{}", r.paused);
    // Even with its own record lost and handed the turn again, it does not
    // install the release that went back: the update commands would.
    std::fs::remove_file(sw.server(2).node.path(STORE).join(STATE_FILE)).unwrap();
    let m = Machine { n: &sw.server(2).node, brain: false, free: plenty };
    let o = sw.granted(2, 10, |_| {});
    let e = m.step(&Ctx::new(), &Reg { sw: &sw, host: 2 }, &o, &sw.healthy(2), sw.now).unwrap_err().to_string();
    assert!(e.contains("release 10 reverted"), "{e}");
    assert_eq!(sw.server(2).fake.sim().applied.len(), 1);
    assert_eq!((m.load().failed, m.load().outcome.as_str()), (10, "reverted"));
}

#[test]
fn stream_to_file_caps_and_times_out() {
    let dir = TempDir::new();
    let dst = dir.join("out");
    let sh = |script: &str| {
        let mut c = Command::new("sh");
        c.args(["-c", script]);
        c
    };
    assert_eq!(stream_to_file(&Ctx::new(), &mut sh("printf abcdef"), &dst, 6).unwrap(), 6);
    assert_eq!(std::fs::read(&dst).unwrap(), b"abcdef");
    let e = stream_to_file(&Ctx::new(), &mut sh("head -c 1000000 /dev/zero"), &dst, 10).unwrap_err().to_string();
    assert!(e.contains("more than 10 bytes"), "{e}");
    let e = stream_to_file(&Ctx::new(), &mut sh("echo nope >&2; exit 3"), &dst, 10).unwrap_err().to_string();
    assert!(e.contains("exit status 3") && e.contains("nope"), "{e}");
    let start = Instant::now();
    let ctx = Ctx::new().with_timeout(Duration::from_millis(200));
    assert!(stream_to_file(&ctx, &mut sh("sleep 10"), &dst, 10).is_err());
    assert!(start.elapsed() < Duration::from_secs(5), "a silent sender was not cut off");
    // What came before the time ran out is in the file: fetch keeps it.
    let ctx = Ctx::new().with_timeout(Duration::from_millis(500));
    assert!(stream_to_file(&ctx, &mut sh("printf abc; sleep 10"), &dst, 10).is_err());
    assert_eq!(std::fs::read(&dst).unwrap(), b"abc");
    // An endless sender stops at the cap without filling the disk.
    let e = stream_to_file(&Ctx::new(), &mut sh("yes"), &dst, 1 << 20).unwrap_err().to_string();
    assert!(e.contains("more than"), "{e}");
    assert!(file_len(&dst) <= 1 << 20);
}

// ---- uploads ----

#[test]
fn uploads_that_do_not_check_out_leave_nothing_behind() {
    let sw = Swarm::new(0);
    let (env, bin) = sw.release(10, "0.2.0", false);
    let head = |k3s_size: u64| serde_json::to_string(&PutHeader { release: env.clone(), k3s_size }).unwrap() + "\n";
    let put = |input: Vec<u8>| sw.call("release-put", 0, &input).map(|_| ()).unwrap_err().to_string();
    let cat = |parts: &[&[u8]]| parts.concat();
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (cat(&[head(0).as_bytes(), &bin[..bin.len() / 2]]), "ended after"),
        (cat(&[head(0).as_bytes(), &bin, b"x"]), "more than the release says"),
        (cat(&[head(0).as_bytes(), &bin[1..], b"\0"]), "sha256"),
        (cat(&[head(MAX_K3S + 1).as_bytes(), &bin]), "more than"),
        (cat(&[head(5).as_bytes(), &bin, b"abc"]), "ended after"),
        (cat(&[head(K3S.len() as u64).as_bytes(), &bin, b"not the k3s of the release.."]), "sha256"),
        (head(0).trim_end().as_bytes().to_vec(), "header"),
        (vec![b'{'; (MAX_HEADER + 10) as usize], "header"),
        (b"{}\n".to_vec(), "header"),
        (
            cat(&[
                (serde_json::to_string(&PutHeader {
                    release: release::seal(&Key("thief"), &serde_json::from_str(&env.doc).unwrap()).unwrap(),
                    k3s_size: 0,
                })
                .unwrap()
                    + "\n")
                    .as_bytes(),
                &bin,
            ]),
            "bad signature",
        ),
    ];
    for (input, want) in cases {
        let e = put(input);
        assert!(e.contains(want), "want {want:?}: {e}");
    }
    let left: Vec<String> = std::fs::read_dir(&sw.served.dir)
        .map(|d| d.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| n != ".lock").collect())
        .unwrap_or_default();
    assert!(left.is_empty(), "left behind: {left:?}");
    assert_eq!(sw.served.current(), None);
    // What checks out is taken.
    assert_eq!(sw.upload(&env, &bin, None).unwrap(), 10);
    assert_eq!(sw.served.current(), Some(10));
    assert_eq!(std::fs::read(sw.served.path(10, K3S_FILE)).unwrap(), K3S, "the brain's own k3s, copied");
}

#[test]
fn a_full_disk_on_the_brain_refuses_the_upload() {
    let mut sw = Swarm::new(0);
    sw.served.free = full;
    let (env, bin) = sw.release(10, "0.2.0", false);
    let e = sw.upload(&env, &bin, None).unwrap_err().to_string();
    assert!(e.contains("the coordinator has 100 MiB free") && e.contains("must stay free"), "{e}");
    assert_eq!(sw.served.current(), None);
    assert!(std::fs::read_dir(&sw.served.dir).unwrap().flatten().all(|e| !e.file_name().to_string_lossy().starts_with("staging")));
}

#[test]
fn the_brain_without_the_releases_k3s_asks_for_it() {
    let sw = Swarm::new(0);
    put(&sw.brain.node.root, K3S_BIN, b"another k3s");
    let (env, bin) = sw.release(10, "0.2.0", false);
    let e = sw.upload(&env, &bin, None).unwrap_err().to_string();
    assert!(e.contains(SEND_K3S), "{e}");
    assert_eq!(sw.upload(&env, &bin, Some(K3S)).unwrap(), 10);
    assert_eq!(std::fs::read(sw.served.path(10, K3S_FILE)).unwrap(), K3S);
}

#[test]
fn two_publishes_in_quick_succession() {
    let mut sw = Swarm::new(1);
    sw.publish(10, true);
    sw.publish(11, true);
    // An older one after them, or the same again, is refused.
    let (env, bin) = sw.release(10, "0.2.0", true);
    assert!(sw.upload(&env, &bin, None).unwrap_err().to_string().contains("older than"));
    let (env, bin) = sw.release(11, "0.2.0", true);
    assert!(sw.upload(&env, &bin, None).unwrap_err().to_string().contains("on the coordinator already"));
    let mut twin: Release = serde_json::from_str(&env.doc).unwrap();
    twin.notes = "another release under the same serial".into();
    let e = sw.upload(&release::seal(&ADMIN, &twin).unwrap(), &bin, None).unwrap_err().to_string();
    assert!(e.contains("signed twice"), "{e}");
    sw.until(30, |s| s.everyone_on(11));
    // Machines went straight to the newest.
    assert!(std::iter::once(&sw.brain).chain(&sw.servers).all(|m| m.fake.sim().applied.len() == 1));
    // The newest and the one before are kept, no more.
    sw.publish(12, true);
    let mut dirs: Vec<String> = std::fs::read_dir(&sw.served.dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.parse::<u64>().is_ok())
        .collect();
    dirs.sort();
    assert_eq!(dirs, vec!["11", "12"]);
}

#[test]
fn a_new_release_replaces_a_running_rollout() {
    let mut sw = Swarm::new(3);
    sw.publish(10, true);
    sw.until(30, |s| s.installed(2) == 10 && s.rollout().turn.as_ref().is_some_and(|t| t.host == 3 && t.ready));
    sw.publish(11, true);
    sw.tick();
    let r = sw.rollout();
    assert_eq!(r.serial, 11);
    assert!(r.warnings.iter().any(|w| w.contains("release 11 replaced release 10")), "{r:#?}");
    // node-b had its turn for release 10 and may be in the middle of it: it
    // stays cordoned (it may still reboot for it) until a report shows it
    // done, and only then the brain goes on.
    assert!(!sw.kubectl().contains(&"uncordon -- node-b".to_string()) && r.cordoned == vec!["node-b".to_string()], "{r:#?}");
    let uncordoned = |s: &Swarm| s.kubectl().contains(&"uncordon -- node-b".to_string());
    sw.until(10, |s| uncordoned(s) || s.brain.fake.sim().applied.len() > 1);
    assert!(uncordoned(&sw), "the brain updated before node-b was done");
    sw.until(60, |s| s.everyone_on(11));
    sw.ticks(2);
    assert_eq!(sw.rollout().done, vec![2, 3, 4]);
}

// ---- clocks ----

#[test]
fn the_brains_clock_is_checked() {
    let mut sw = Swarm::new(1);
    // The desktop's clock is right, the brain's two days behind: refused,
    // and the message says to check the clock.
    let (env, bin) = sw.release(10, "0.2.0", true);
    sw.now -= 2 * release::DAY;
    let e = sw.upload(&env, &bin, None).unwrap_err().to_string();
    assert!(e.contains("check the clock"), "{e}");
    // Far ahead: the release is past its expiry, still taken, with a
    // warning.
    sw.now += 2 * release::DAY + release::LIFETIME + release::DAY;
    sw.upload(&env, &bin, None).unwrap();
    sw.tick();
    let r = sw.rollout();
    assert!(r.warnings.iter().any(|w| w.contains("expired by the coordinator's clock")), "{r:#?}");
    sw.until(30, |s| s.everyone_on(10));
}

#[test]
fn a_clock_that_goes_back_does_not_freeze_a_turn() {
    let mut sw = Swarm::new(1);
    sw.ignore_turn.push(2);
    sw.publish(10, true);
    sw.until(10, |s| s.rollout().turn.is_some_and(|t| t.ready));
    sw.now -= 30 * 24 * 3600;
    // The minutes the members need to report in again do not count.
    sw.ticks((TURN_TIMEOUT + OFFLINE) as usize / 60 + 2);
    assert_eq!(sw.rollout().pause, Pause::Timeout, "{:#?}", sw.rollout());
    assert!(sw.rollout().warnings.iter().any(|w| w.contains("clock went back 29d")), "{:#?}", sw.rollout());
}

/// A brain that was down for half an hour (or whose clock jumped ahead)
/// stopped the rollout at the server whose turn it was: the turn's time
/// ran out while nobody could reach the brain. And the canary was "silent"
/// at the first tick after, before it could report in. The timers now
/// stand still across the gap and while the members report in again.
#[test]
fn a_brain_that_was_down_does_not_count_the_time_against_a_turn() {
    for jump in [30 * 60, 2 * 3600] {
        let mut sw = Swarm::new(2);
        sw.server(2).fake.sim().broken = true;
        sw.publish(10, true);
        sw.until(10, |s| s.server(2).fake.sim().pending == 10);
        sw.ticks(TURN_TIMEOUT as usize / 60 - 5);
        // Down: no sync anywhere reaches it.
        sw.now += jump;
        sw.ticks(2);
        let r = sw.rollout();
        assert!(r.paused.is_empty(), "{jump}: {r:#?}");
        assert!(r.warnings.iter().any(|w| w.contains("did not run the rollout for")), "{r:#?}");
        // It comes up: the turn goes on with the minutes it had left.
        sw.server(2).fake.sim().broken = false;
        std::fs::copy(sw.server(2).node.path(STORE).join(INCOMING).join(DRYSERVER_FILE), exe(&sw.server(2).node.root)).unwrap();
        sw.until_unpaused(30, |s| s.everyone_on(10));
    }

    // The canary under watch: not judged silent before it could report.
    let mut sw = Swarm::new(2);
    sw.publish(10, false);
    sw.until(30, |s| s.rollout().done == vec![2]);
    assert!(sw.rollout().canary_until > sw.now);
    let left = sw.rollout().canary_until - sw.now;
    sw.now += 3600;
    sw.brain_sync();
    // Still watched for the time it had left.
    assert_eq!(sw.rollout().canary_until - sw.now, left);
    sw.until_unpaused(30, |s| s.everyone_on(10));
}

// ---- drains ----

#[test]
fn a_drain_that_a_pdb_holds_back() {
    let mut sw = Swarm::new(2);
    sw.brain.fake.sim().drain_fails.push("node-a".into());
    sw.publish(10, false);
    sw.until(30, |s| !s.rollout().paused.is_empty());
    let r = sw.rollout();
    assert_eq!(r.pause, Pause::Drain);
    assert!(r.paused.contains("draining node-a did not finish in 5m") && r.paused.contains("PodDisruptionBudget"), "{}", r.paused);
    assert!(!r.cordoned.contains(&"node-a".to_string()), "a node that was not drained stays cordoned");
    assert!(sw.server(2).fake.sim().applied.is_empty(), "updated without its turn");
    assert!(sw.lines().contains("updates node-a without draining"), "{}", sw.lines());
    // The admin resumes: it updates without the drain.
    sw.resume();
    sw.until(40, |s| s.everyone_on(10));
    assert!(sw.rollout().warnings.iter().any(|w| w.contains("it updates anyway, as you resumed")));

    // Urgent: it warns and goes on.
    let mut sw = Swarm::new(2);
    sw.brain.fake.sim().drain_fails.push("node-a".into());
    sw.publish(10, true);
    sw.until(40, |s| s.everyone_on(10));
    let r = sw.rollout();
    assert!(r.paused.is_empty() && r.warnings.iter().any(|w| w.contains("PodDisruptionBudget") && w.contains("urgent")), "{r:#?}");
}

/// A server that is not a node of the cluster (its agent never joined, or
/// k3s_share removed it) blocked the rollout for ever: its cordon failed
/// at every sync and it never got its turn, so no timeout began.
#[test]
fn a_server_that_is_no_node_does_not_block_the_rollout() {
    let mut sw = Swarm::new(2);
    sw.brain.fake.sim().nodes = Some(vec!["coord".into(), "node-b".into()]);
    sw.publish(10, false);
    sw.until(40, |s| s.everyone_on(10));
    sw.ticks(3);
    let r = sw.rollout();
    assert!(r.paused.is_empty() && r.cordoned.is_empty() && r.done == vec![2, 3], "{r:#?}");
    assert!(r.warnings.iter().any(|w| w.contains("node-a is not a node of the cluster")), "{r:#?}");
    assert!(!sw.kubectl().iter().any(|l| l.ends_with("node-a")), "{:?}", sw.kubectl());
    assert!(sw.kubectl().contains(&"drain --ignore-daemonsets --delete-emptydir-data --timeout=25s -- node-b".to_string()));

    // One that leaves the cluster while it is drained.
    let mut sw = Swarm::new(2);
    sw.brain.fake.sim().drain_fails.push("node-a".into());
    sw.publish(10, false);
    sw.until(10, |s| s.kubectl().iter().any(|l| l.starts_with("drain") && l.ends_with("node-a")));
    sw.brain.fake.sim().nodes = Some(vec!["coord".into(), "node-b".into()]);
    sw.until(40, |s| s.everyone_on(10));
    assert!(sw.rollout().paused.is_empty(), "{:#?}", sw.rollout());
}

/// Problems that pass (the brain's k3s not known yet) are tried again at
/// the next sync, not recorded as a failure of the release; after
/// MAX_TRIES syncs in a row they are.
#[test]
fn a_problem_that_passes_is_tried_again() {
    let mut sw = Swarm::new(1);
    sw.brain_k3s = String::new();
    sw.publish(10, true);
    sw.until(20, |s| s.rollout().turn.as_ref().is_some_and(|t| t.ready));
    sw.ticks(3);
    let l = Machine::new(&sw.server(2).node, false).load();
    assert!(l.failed == 0 && l.note.contains("does not say yet which k3s"), "{l:?}");
    sw.brain_k3s = K3S_VERSION.into();
    sw.until(20, |s| s.everyone_on(10));

    let mut sw = Swarm::new(1);
    sw.brain_k3s = String::new();
    sw.publish(10, true);
    sw.until(40, |s| !s.rollout().paused.is_empty());
    let r = sw.rollout();
    assert_eq!(r.pause, Pause::Failed, "{r:#?}");
    assert!(r.paused.contains(&format!("{MAX_TRIES} syncs in a row")), "{}", r.paused);
}

/// A cordon that fails for another reason counts against the drain limit,
/// and the rollout then stops as for a drain that does not finish.
#[test]
fn a_cordon_that_keeps_failing_stops_the_rollout() {
    let mut sw = Swarm::new(2);
    sw.brain.fake.sim().cordon_fails.push("node-a".into());
    sw.brain.fake.sim().drain_fails.push("node-a".into());
    sw.publish(10, false);
    sw.until(30, |s| !s.rollout().paused.is_empty());
    let r = sw.rollout();
    assert_eq!((r.pause, r.pause_name.as_str()), (Pause::Drain, "node-a"), "{r:#?}");
    assert!(r.paused.contains("did not finish in 5m"), "{}", r.paused);
    assert!(sw.server(2).fake.sim().applied.is_empty() && sw.server(3).fake.sim().applied.is_empty());
    let cordons = sw.kubectl().iter().filter(|l| l.starts_with("cordon")).count();
    assert_eq!(cordons, 1, "the turn began at the first try: {:?}", sw.kubectl());
}

// ---- edges of the fixes before ----

/// A server that is no node updates without a drain; an API server that
/// does not answer is not the same thing: then nothing is drained, so
/// nothing updates undrained (urgent releases aside), and a node cordoned
/// before is uncordoned once the API answers again.
#[test]
fn an_api_that_does_not_answer_is_not_a_missing_node() {
    let mut sw = Swarm::new(2);
    sw.brain.fake.sim().api_down = true;
    sw.publish(10, false);
    sw.until(30, |s| !s.rollout().paused.is_empty());
    let r = sw.rollout();
    assert_eq!((r.pause, r.pause_host), (Pause::Drain, 2), "{r:#?}");
    assert!(!r.warnings.iter().any(|w| w.contains("is not a node")), "{r:#?}");
    assert!(sw.servers.iter().all(|m| m.fake.sim().applied.is_empty()), "updated undrained");
    // The API answers again: node-a, cordoned at its turn, is uncordoned.
    sw.brain.fake.sim().api_down = false;
    sw.ticks(2);
    assert!(sw.rollout().cordoned.is_empty(), "{:#?}", sw.rollout());
    assert_eq!(sw.kubectl().last().map(String::as_str), Some("uncordon -- node-a"));
}

/// Update commands that do not answer for a while are asked again, and the
/// release is not recorded as failed; for MAX_TRIES syncs in a row it is.
#[test]
fn update_commands_that_do_not_answer_are_asked_again() {
    let mut sw = Swarm::new(1);
    sw.server(2).fake.sim().status_fails = MAX_TRIES - 2;
    sw.publish(10, true);
    sw.until_unpaused(30, |s| s.everyone_on(10));
    assert_eq!(sw.server(2).fake.sim().applied.len(), 1);

    let mut sw = Swarm::new(1);
    sw.server(2).fake.sim().status_fails = 1000;
    sw.publish(10, true);
    sw.until(MAX_TRIES as usize + 10, |s| !s.rollout().paused.is_empty());
    let r = sw.rollout();
    assert!(r.paused.contains("cannot ask how its updates stand") && r.paused.contains("update failed"), "{}", r.paused);
    // Counted for this release.
    let l = Machine::new(&sw.server(2).node, false).load();
    assert_eq!((l.tries_serial, l.tries), (10, MAX_TRIES));
}

thread_local! {
    static EXTENDED: std::cell::RefCell<Vec<Duration>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn record_extension(d: Duration) {
    EXTENDED.with(|e| e.borrow_mut().push(d));
}

/// Anyone with the key on the USB stick can start an upload: it gets the
/// long deadline only once its header holds a release the admin signed.
#[test]
fn an_upload_gets_its_long_deadline_only_once_signed() {
    let mut sw = Swarm::new(0);
    sw.served.extend = record_extension;
    let (env, bin) = sw.release(10, "0.2.0", false);
    let thief = release::seal(&Key("thief"), &serde_json::from_str(&env.doc).unwrap()).unwrap();
    let line = |e: &Envelope| serde_json::to_string(&PutHeader { release: e.clone(), k3s_size: 0 }).unwrap() + "\n";
    for input in [
        [line(&thief).as_bytes(), &bin].concat(),
        b"{\"release\":{\"doc\":\"x\",\"sig\":\"y\"}}\n".to_vec(),
        vec![b'{'; (MAX_HEADER + 10) as usize],
        line(&Envelope { doc: env.doc.clone(), sig: String::new() }).into_bytes(),
    ] {
        assert!(sw.call("release-put", 0, &input).is_err());
    }
    assert!(EXTENDED.with(|e| e.borrow().is_empty()), "extended for an unsigned upload");
    sw.upload(&env, &bin, None).unwrap();
    assert_eq!(EXTENDED.with(|e| e.borrow().clone()), vec![registry::UPLOAD_DEADLINE]);
}

/// Root's own rollout file damaged or lost (a bad disk): the rollout
/// starts over from the newest upload, and nobody updates twice.
#[test]
fn a_damaged_rollout_file_on_the_brain_starts_over() {
    let mut sw = Swarm::new(3);
    sw.publish(10, true);
    sw.until(30, |s| s.installed(2) == 10 && s.rollout().turn.as_ref().is_some_and(|t| t.host == 3));
    std::fs::write(sw.brain.node.path(STORE).join(ROLLOUT_FILE), "{\"serial\": \"garbage").unwrap();
    sw.until_unpaused(40, |s| s.everyone_on(10));
    sw.ticks(2);
    for m in std::iter::once(&sw.brain).chain(&sw.servers) {
        assert_eq!(m.fake.sim().applied.len(), 1, "{} updated twice", m.name);
    }
    let r = sw.rollout();
    assert!(r.cordoned.is_empty() && r.done.len() == 3, "{r:#?}");
}

// ---- reports and words ----

#[test]
fn reports_say_where_the_update_stands() {
    let sw = Swarm::new(1);
    let m = Machine::new(&sw.server(2).node, false);
    let mut r = Report::default();
    m.describe(&mut r);
    assert_eq!((r.release, r.update.as_str()), (0, ""));
    let save = |l: Local| m.save(&l).unwrap();
    save(Local { pending: 7, note: "the new dryserver does not run yet".into(), ..Local::default() });
    m.describe(&mut r);
    assert_eq!((r.update.as_str(), r.update_serial, r.update_note.as_str()), ("pending", 7, "the new dryserver does not run yet"));
    save(Local { failed: 7, outcome: "reverted".into(), why: "x\u{1b}[2J".into(), ..Local::default() });
    m.describe(&mut r);
    assert_eq!((r.update.as_str(), r.update_note.as_str()), ("reverted", "x?[2J"));
    assert_eq!(member_release(&r, 7), Some(("update reverted".into(), true)));
    // A hostile state word is dropped by the readers.
    let bad =
        Report { update: "rm -rf".into(), update_note: "\u{7}".repeat(500), release: u64::MAX, ..Report::default() }.sanitized(|_| true);
    assert_eq!((bad.update.as_str(), bad.update_note.len(), bad.release), ("", report::MAX_NOTE, 0));
    assert_eq!(member_release(&Report { release: 9, ..Report::default() }, 10), Some(("release 9 (old)".into(), false)));
    assert_eq!(member_release(&Report { release: 10, ..Report::default() }, 10), Some(("release 10".into(), false)));
    assert_eq!(member_release(&Report::default(), 0), None);
}

#[test]
fn rollout_lines_are_plain_text() {
    let members =
        vec![Member { host: 1, name: "coord".into(), ..Member::default() }, Member { host: 2, name: "node-a".into(), ..Member::default() }];
    let r = Rollout {
        serial: 10,
        phase: Phase::Servers,
        paused: "node-a: update failed: \u{1b}]52;c;ZXZpbA==\u{7}".into(),
        pause: Pause::Failed,
        warnings: vec!["w\nx".into()],
        ..Rollout::default()
    };
    for (l, _) in lines(&r, &members, 0) {
        assert!(l.chars().all(|c| (' '..='~').contains(&c)), "{l:?}");
    }
    assert!(lines(&Rollout::default(), &members, 0)[0].0.contains("No release published yet"));
}

#[test]
fn only_static_linux_programs_are_published() {
    let dir = TempDir::new();
    // An ELF header with one program header of the given type.
    let elf = |kind: u32| {
        let mut b = vec![0u8; 64 + 56];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[16..18].copy_from_slice(&3u16.to_le_bytes());
        b[18..20].copy_from_slice(&62u16.to_le_bytes());
        b[32..40].copy_from_slice(&64u64.to_le_bytes());
        b[54..56].copy_from_slice(&56u16.to_le_bytes());
        b[56..58].copy_from_slice(&1u16.to_le_bytes());
        b[64..68].copy_from_slice(&kind.to_le_bytes());
        b
    };
    let at = |name: &str, data: &[u8]| {
        let p = dir.join(name);
        std::fs::write(&p, data).unwrap();
        p
    };
    check_static(&at("static", &elf(1))).unwrap();
    for (name, data, want) in [
        ("dynamic", elf(3), "linked against this computer's libraries"),
        ("script", b"#!/bin/sh\necho hi\n".to_vec(), "not a Linux program"),
        (
            "arm",
            {
                let mut b = elf(1);
                b[18] = 183;
                b
            },
            "64-bit x86",
        ),
        ("short", b"\x7fELF\x02\x01".to_vec(), "64-bit x86"),
        ("cut", elf(1)[..50].to_vec(), "cut short"),
        ("no headers", elf(1)[..60].to_vec(), "not where it says"),
    ] {
        let e = check_static(&at(name, &data)).unwrap_err().to_string();
        assert!(e.contains(want), "{name}: {e}");
    }
    // Far-away program headers do not crash it.
    let mut far = elf(1);
    far[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(check_static(&at("far", &far)).is_err());
}

#[test]
fn update_status_is_read_leniently() {
    let s: UpdateStatus = serde_json::from_str(
        r#"{"running":"0.2.0","installed":{"serial":9,"version":"0.2.0","stale":false},
            "pending":{"serial":10,"stage":"booted","deadline":77,"seconds_left":5,"boots":1,"files":["x"],"kernel":true},
            "last":{"at":1,"serial":8,"action":"reverted","ok":true,"message":"selfcheck failed"},"problems":["x"]}"#,
    )
    .unwrap();
    assert_eq!((s.installed.serial, s.pending_serial(), s.pending.as_ref().unwrap().deadline), (9, 10, 77));
    assert!(s.pending.as_ref().unwrap().kernel);
    assert_eq!(s.reverted(8).as_deref(), Some("selfcheck failed"));
    assert_eq!(s.reverted(9), None);
    // Nothing pending; fields of the wrong kind read as empty.
    let s: UpdateStatus = serde_json::from_str(r#"{"installed":{"serial":"x"},"pending":null,"last":5}"#).unwrap();
    assert_eq!((s.installed.serial, s.pending_serial(), s.last), (0, 0, None));
}

// ---- the detached apply ----

#[test]
fn an_apply_that_takes_its_time_is_waited_for() {
    // Loading and installing the packages take many minutes; the apply runs
    // in a service of its own, and the server keeps syncing meanwhile.
    let mut sw = Swarm::new(2);
    sw.server(2).fake.sim().slow = 15;
    sw.publish(10, true);
    sw.until(10, |s| s.server(2).fake.sim().pending == 10);
    for _ in 0..8 {
        sw.tick();
        assert!(sw.server(2).fake.sim().confirmed.is_empty(), "confirmed while its apply still ran");
        let r = sw.store.read().unwrap().members.iter().find(|m| m.host == 2).unwrap().report.clone().unwrap();
        assert_eq!((r.update.as_str(), r.update_serial), ("pending", 10), "{r:?}");
    }
    sw.until_unpaused(40, |s| s.everyone_on(10));
    assert_eq!(sw.server(2).fake.sim().applied.len(), 1, "started once");
}

#[test]
fn a_dead_mirror_postpones_and_is_tried_again() {
    // Nothing changed when the packages could not be loaded: tried again,
    // not a failed release.
    let mut sw = Swarm::new(2);
    sw.brain.fake.sim().postpone = 2;
    sw.server(2).fake.sim().postpone = 3;
    sw.publish(10, true);
    sw.until_unpaused(60, |s| s.everyone_on(10));
    assert_eq!(sw.brain.fake.sim().applied.len(), 3);
    assert_eq!(sw.server(2).fake.sim().applied.len(), 4);
    // One that never works fails after MAX_TRIES, and stops the rollout.
    let mut sw = Swarm::new(2);
    sw.server(2).fake.sim().postpone = 1000;
    sw.publish(10, true);
    sw.until(60, |s| !s.rollout().paused.is_empty());
    let r = sw.rollout();
    assert!(r.pause == Pause::Failed && r.paused.contains("update failed") && r.paused.contains("syncs in a row"), "{}", r.paused);
    assert_eq!(sw.server(2).fake.sim().applied.len(), MAX_TRIES as usize);
}

#[test]
fn a_release_the_apply_refuses_stops_the_rollout() {
    let mut sw = Swarm::new(2);
    sw.server(2).fake.sim().refuse = Some("pacman would not take every package from the pinned snapshot".into());
    sw.publish(10, true);
    sw.until(30, |s| !s.rollout().paused.is_empty());
    let r = sw.rollout();
    assert!(r.pause == Pause::Failed && r.paused.contains("update refused") && r.paused.contains("pinned snapshot"), "{}", r.paused);
    assert_eq!(sw.server(2).fake.sim().applied.len(), 1, "not tried again by itself");
}

#[test]
fn an_apply_that_stopped_part_way_goes_back_at_once() {
    // Killed in the middle (its record says installing, nothing runs): the
    // next sync reverts it instead of waiting for its timer.
    let mut sw = Swarm::new(2);
    sw.server(2).fake.sim().dies = true;
    sw.publish(10, true);
    sw.until(30, |s| !s.rollout().paused.is_empty());
    let r = sw.rollout();
    assert!(r.pause == Pause::Failed && r.paused.contains("update reverted") && r.paused.contains("reverted by hand"), "{}", r.paused);
    let s = sw.server(2).fake.sim();
    assert!(s.pending == 0 && s.confirmed.is_empty(), "never confirmed");
}

#[test]
fn an_update_that_reboots_is_confirmed_after_the_restart() {
    let mut sw = Swarm::new(1);
    sw.server(2).fake.sim().reboot = true;
    sw.publish(10, true);
    sw.until(10, |s| s.server(2).fake.sim().pending == 10);
    sw.ticks(5);
    assert!(sw.server(2).fake.sim().confirmed.is_empty(), "confirmed before the reboot it waits for");
    sw.server(2).fake.sim().boots = 1;
    sw.until_unpaused(10, |s| s.everyone_on(10));
}

#[test]
fn an_old_rollback_sent_again_does_not_move_a_fresh_machine_below_its_install() {
    // The swarm took its first look now; a rollback signed two days ago, of
    // a dryserver older than the one the machines run, is an old one sent
    // again: refused, by the coordinator already.
    let mut sw = Swarm::new(1);
    sw.tick();
    let bin = b"\x7fELF dryserver 0.0.1, old".to_vec();
    let r = Release {
        serial: 9,
        created: sw.now - 2 * release::DAY,
        expires: sw.now + release::DAY,
        dryserver: release::Binary { version: "0.0.1".into(), sha256: sha(&bin), size: bin.len() as u64 },
        k3s: release::K3s { version: K3S_VERSION.into(), sha256: sha(K3S) },
        arch_date: "2026/11/19".into(),
        rollback: true,
        urgent: true,
        notes: "old".into(),
        settings: None,
    };
    sw.upload(&release::seal(&ADMIN, &r).unwrap(), &bin, None).unwrap();
    sw.ticks(3);
    let ro = sw.rollout();
    assert!(ro.refused.contains("below what this machine was installed with"), "{ro:#?}");
    assert!(sw.brain.fake.sim().applied.is_empty() && sw.server(2).fake.sim().applied.is_empty());
    // A rollback signed now (after the first look) goes through.
    let r = Release { serial: 10, created: sw.now - 60, ..r };
    sw.upload(&release::seal(&ADMIN, &r).unwrap(), &bin, None).unwrap();
    sw.until_unpaused(30, |s| s.everyone_on(10));
}

#[test]
fn a_machine_on_its_fallback_kernel_is_not_well() {
    // Its update brought a new main kernel, and after the restart it runs
    // the fallback one: that kernel did not work. Not confirmed, and the
    // rollout stops there.
    let mut sw = Swarm::new(2);
    sw.fallback.push(2);
    (sw.server(2).fake.sim().kernel, sw.server(2).fake.sim().boots) = (true, 1);
    sw.publish(10, true);
    sw.until(30, |s| s.server(2).fake.sim().pending == 10);
    sw.ticks(5);
    assert!(sw.server(2).fake.sim().confirmed.is_empty(), "confirmed on its fallback kernel");
    let r = sw.store.read().unwrap().members.iter().find(|m| m.host == 2).unwrap().report.clone().unwrap();
    assert!(r.update_note.contains("fallback kernel"), "{r:?}");
    // On its fallback kernel already, by an update that brought no kernel,
    // or with no restart since one that did: no reason to go back. It is
    // kept; as the canary, the brain stops for the admin to look.
    for (kernel, boots) in [(false, 1), (true, 0), (false, 0)] {
        let mut sw = Swarm::new(2);
        sw.fallback.push(2);
        (sw.server(2).fake.sim().kernel, sw.server(2).fake.sim().boots) = (kernel, boots);
        sw.publish(10, false);
        sw.until(10, |s| s.installed(2) == 10);
        sw.until(5, |s| s.rollout().pause == Pause::Canary);
        sw.fallback.clear();
        sw.resume();
        sw.until_unpaused(30, |s| s.everyone_on(10));
    }
    // The canary that falls back after its update stops the rollout.
    let mut sw = Swarm::new(2);
    sw.publish(10, false);
    sw.until(30, |s| s.rollout().canary != 0);
    let canary = sw.rollout().canary;
    sw.fallback.push(canary);
    sw.until(5, |s| !s.rollout().paused.is_empty());
    let ro = sw.rollout();
    assert!(ro.pause == Pause::Canary && ro.paused.contains("fallback kernel"), "{}", ro.paused);
}

// ---- found in review ----

/// A newer normal release that came while the brain's own urgent update
/// waited for its confirm, outside the window: the brain stopped settling
/// its own update (only the brain's phase did), and its timer took the
/// urgent fix back after 10 minutes. Now the brain settles its own update
/// at every tick, whatever the phase.
#[test]
fn review_the_brains_own_update_is_confirmed_while_a_newer_release_waits_for_the_window() {
    let mut sw = Swarm::new(1);
    sw.minute = DAYTIME;
    sw.publish(10, true);
    sw.until(5, |s| s.brain.fake.sim().pending == 10);
    sw.publish(11, false);
    sw.ticks(9);
    let confirmed = sw.brain.fake.sim().confirmed.clone();
    assert!(confirmed.iter().any(|c| c.last().map(String::as_str) == Some("10")), "brain never confirmed 10");
    assert_eq!((sw.installed(1), sw.rollout().phase), (10, Phase::Waiting), "{:#?}", sw.rollout());
    // Its update went back meanwhile: recorded, and the newer release is
    // tried in the window all the same.
    let mut sw = Swarm::new(1);
    sw.minute = DAYTIME;
    sw.brain.fake.sim().broken = true;
    sw.publish(10, true);
    sw.until(5, |s| s.brain.fake.sim().pending == 10);
    sw.publish(11, false);
    sw.tick();
    sw.brain.fake.revert();
    sw.ticks(3);
    let l = Machine::new(&sw.brain.node, true).load();
    assert!(l.pending == 0 && l.failed == 10 && sw.brain.fake.sim().confirmed.is_empty(), "{l:?}");
    assert_eq!(sw.rollout().phase, Phase::Waiting);
    sw.brain.fake.sim().broken = false;
    sw.minute = IN_WINDOW;
    sw.until_unpaused(30, |s| s.everyone_on(11));
    assert_eq!(sw.brain.fake.sim().applied.len(), 2);
}

/// A revert that half failed (the old binary could not be put back) left
/// nothing pending and the new release named as installed: settle took
/// that for a confirm made meanwhile, and the server counted as updated.
/// Only a confirm record for the release counts.
#[test]
fn review_a_revert_that_half_failed_is_no_update() {
    let mut sw = Swarm::new(2);
    sw.server(2).fake.sim().broken = true;
    sw.publish(10, true);
    sw.until(10, |s| s.server(2).fake.sim().pending == 10);
    {
        let mut s = sw.server(2).fake.sim();
        (s.installed, s.pending) = (10, 0);
        s.done(10, "reverted", false, "release 10 went back part way: putting back the old dryserver failed");
    }
    sw.until(5, |s| !s.rollout().paused.is_empty());
    let r = sw.rollout();
    assert_eq!((r.pause, r.pause_host), (Pause::Failed, 2), "{r:#?}");
    assert!(r.paused.contains("update reverted") && r.paused.contains("putting back the old dryserver failed"), "{}", r.paused);
    let l = Machine::new(&sw.server(2).node, false).load();
    assert_eq!((l.pending, l.failed, l.installed, sw.installed(2)), (0, 10, 0, 0), "{l:?}");
    assert!(!sw.server(2).node.path(STORE).join(INSTALLED).exists(), "kept as installed");
    // Passed over, it does not count as done: it never ran release 10 well.
    sw.skip();
    sw.until(30, |s| s.installed(3) == 10);
    sw.ticks(2);
    assert!(!sw.rollout().done.contains(&2) && sw.rollout().skipped.iter().any(|s| s.host == 2), "{:#?}", sw.rollout());
    // The update commands say so of a release with no record of its own.
    let st = UpdateStatus {
        installed: Installed { serial: 10 },
        last: Some(Last { serial: 10, action: "reverted".into(), ..Last::default() }),
        ..UpdateStatus::default()
    };
    assert_eq!(st.confirmed_serial(), 0);
    let st = UpdateStatus { last: Some(Last { serial: 11, action: "reverted".into(), ..Last::default() }), ..st };
    assert_eq!(st.confirmed_serial(), 10);

    // Confirmed by hand meanwhile: that counts.
    let mut sw = Swarm::new(1);
    sw.server(2).fake.sim().broken = true;
    sw.publish(10, true);
    sw.until(10, |s| s.server(2).fake.sim().pending == 10);
    {
        let mut s = sw.server(2).fake.sim();
        (s.installed, s.pending) = (10, 0);
        s.done(10, "confirmed", true, "release 10 (dryserver 0.2.0) is confirmed");
    }
    sw.until_unpaused(5, |s| s.everyone_on(10));
    assert!(sw.server(2).node.path(STORE).join(INSTALLED).join(RELEASE_FILE).exists());
}

/// The registry's word on the size of its k3s was added to the release's
/// dryserver size before it was checked against MAX_K3S: a size near
/// u64::MAX panicked in a debug build and wrapped to a small room check in
/// a release build. Now it is capped first.
#[test]
fn review_a_k3s_size_from_the_registry_is_capped_before_it_is_added() {
    for lie in [u64::MAX, u64::MAX - sw_bin_len() + 1, MAX_K3S + 1] {
        let mut sw = Swarm::new(1);
        put(&sw.server(2).node.root, K3S_BIN, b"k3s v1.36.0+k3s1, older");
        sw.k3s_size_lie = Some(lie);
        sw.publish(10, true);
        sw.until(20, |s| !s.rollout().paused.is_empty());
        let l = Machine::new(&sw.server(2).node, false).load();
        assert_eq!((l.failed, l.outcome.as_str()), (10, "refused"), "{lie}: {l:?}");
        assert!(l.why.contains(&format!("the coordinator says its k3s is {lie} bytes")), "{lie}: {}", l.why);
        assert!(sw.server(2).fake.sim().applied.is_empty() && !sw.pieces.lock().unwrap().iter().any(|p| p.1 == "k3s"));
    }
}

/// O_NOFOLLOW covers only the last part of a path: a link the registry
/// account put at release/ or release/SERIAL in its own directory was
/// followed when root read the releases. Now root goes through each
/// directory opened by itself, never through a link, so the links below
/// lead nowhere even to the genuine release they point at.
#[test]
fn review_root_never_reads_releases_through_a_planted_link() {
    let mut sw = Swarm::new(1);
    sw.publish(10, true);
    let real = sw.served.dir.with_file_name("elsewhere");
    std::fs::rename(&sw.served.dir, &real).unwrap();
    std::fs::write(real.join("current"), "123\n").unwrap();
    std::fs::rename(real.join("10"), real.join("123")).unwrap();
    std::os::unix::fs::symlink(&real, &sw.served.dir).unwrap();
    assert_eq!(sw.served.current(), None);
    assert!(sw.served.envelope(123).is_err() && sw.served.offered(123).is_err());
    let dst = sw.brain.node.path("/tmp-piece");
    assert!(LocalSource(&sw.served).chunk(&Ctx::new(), 123, DRYSERVER_FILE, 0, 4, &dst).is_err());
    sw.ticks(3);
    assert!(sw.rollout().serial == 0 && sw.brain.fake.sim().applied.is_empty(), "{:#?}", sw.rollout());

    // A link at release/SERIAL, to the genuine release moved aside.
    let mut sw = Swarm::new(1);
    sw.publish(10, true);
    let moved = sw.served.dir.join("moved");
    std::fs::rename(sw.served.dir.join("10"), &moved).unwrap();
    std::os::unix::fs::symlink(&moved, sw.served.dir.join("10")).unwrap();
    assert_eq!(sw.served.current(), Some(10));
    let e = sw.served.envelope(10).unwrap_err().to_string();
    assert!(e.contains("symbolic link"), "{e}");
    assert!(sw.served.offered(10).is_err());
    assert!(LocalSource(&sw.served).chunk(&Ctx::new(), 10, DRYSERVER_FILE, 0, 4, &dst).is_err());
    let mut out = Vec::new();
    assert!(sw.served.send(10, DRYSERVER_FILE, 0, &mut out).is_err() && out.is_empty());
    sw.ticks(3);
    let r = sw.rollout();
    assert!(r.serial == 0 && r.refused_serial == 10 && r.refused.contains("symbolic link"), "{r:#?}");
    assert!(sw.brain.fake.sim().applied.is_empty());

    // Taken up first, then the files swapped for a link: the brain's copy
    // stops, and so does the check of the servers' k3s.
    let sw = Swarm::new(1);
    sw.publish(10, true);
    sw.brain_sync();
    let other = sw.served.dir.join("other");
    std::fs::rename(sw.served.dir.join("10"), &other).unwrap();
    std::os::unix::fs::symlink(&other, sw.served.dir.join("10")).unwrap();
    let n = &sw.brain.node;
    let rep = sw.healthy(1);
    let members = sw.store.read().unwrap().members;
    let b = Brain {
        ctx: &Ctx::new(),
        n,
        served: &sw.served,
        rep: &rep,
        now: Now { unix: sw.now, minute: IN_WINDOW },
        members: &members,
        r: Rollout { serial: 10, ..Rollout::default() },
        free: plenty,
        nodes: None,
    };
    let why = b.served_k3s_problem().unwrap_or_default();
    assert!(why.contains("cannot be read") && why.contains("symbolic link"), "{why}");
}

/// A slow server whose turn timed out, then a fixed release: the brain
/// waited TURN_TIMEOUT for it at most and then updated itself, and the
/// next server, while the slow one still applied. Now nothing starts while
/// a server says its update is pending; after TURN_TIMEOUT the rollout
/// stops there for the admin instead of going on. And the node stays
/// cordoned while it is in the middle.
#[test]
fn review_a_slow_server_from_the_old_rollout_is_not_updating_beside_the_next() {
    let mut sw = Swarm::new(3);
    sw.server(3).fake.sim().slow = 100_000;
    sw.publish(10, true);
    sw.until(120, |s| s.server(3).fake.sim().pending == 10);
    sw.until(90, |s| s.rollout().pause == Pause::Timeout);
    sw.publish(11, true);
    sw.ticks(130); // tick() asserts one_at_a_time
    let r = sw.rollout();
    assert!(r.serial == 11 && r.phase == Phase::Brain && (r.pause, r.pause_host) == (Pause::Timeout, 3), "{r:#?}");
    assert!(r.paused.contains("node-b did not finish the update it is in"), "{}", r.paused);
    assert!(r.cordoned == vec!["node-b".to_string()], "uncordoned in the middle of its update: {r:#?}");
    assert_eq!(sw.brain.fake.sim().applied.len(), 1);
    let l = sw.lines();
    assert!(l.contains("PAUSED: node-b did not finish") && l.contains("dryserver release resume -skip"), "{l}");
    // The admin resumes: it waits once more, and stops again.
    sw.resume();
    sw.ticks(5);
    assert!(sw.rollout().paused.is_empty() && sw.brain.fake.sim().applied.len() == 1, "{:#?}", sw.rollout());
    assert!(sw.rollout().warnings.iter().any(|w| w.contains("waits once more for node-b")), "{:#?}", sw.rollout());
    sw.until(TURN_TIMEOUT as usize / 60 + 2, |s| s.rollout().pause == Pause::Timeout);
    // It finishes after all: uncordoned, and the brain goes on by itself.
    (sw.server(3).fake.sim().busy, sw.server(3).fake.sim().slow) = (0, 0);
    sw.until(60, |s| s.everyone_on(11));
    assert!(sw.rollout().paused.is_empty(), "{:#?}", sw.rollout());
    let k = sw.kubectl();
    let at = |l: &str| k.iter().rposition(|x| x == l).unwrap();
    assert!(at("uncordon -- node-b") < k.iter().rposition(|x| x.starts_with("cordon")).unwrap(), "{k:?}");
    assert!(sw.rollout().warnings.iter().any(|w| w == "node-b finished the update it was in; the coordinator updates itself"));
}

/// A hacked server that says its update is pending, out of any turn and
/// for ever, holds the rollout up only until the admin passes it over: it
/// stops there after TURN_TIMEOUT.
#[test]
fn a_server_that_says_it_is_in_the_middle_for_ever_holds_up_until_passed_over() {
    for brain_first in [true, false] {
        let mut sw = Swarm::new(3);
        sw.offline.push(4);
        sw.publish(10, true);
        if !brain_first {
            sw.until(10, |s| s.installed(1) == 10);
        }
        let lie = |sw: &Swarm| {
            let rep = Report { update: "pending".into(), update_serial: 10, ..sw.healthy(4) };
            sw.store.update(|s| s.heartbeat(4, Heartbeat { report: Some(rep), ..Heartbeat::default() }, time(sw.now))).unwrap();
        };
        let applies = |sw: &Swarm| std::iter::once(&sw.brain).chain(&sw.servers).map(|m| m.fake.sim().applied.len()).sum::<usize>();
        // What started before the lie finishes; nothing starts after it.
        lie(&sw);
        let before = applies(&sw);
        for _ in 0..TURN_TIMEOUT / 60 + 5 {
            lie(&sw);
            sw.tick();
        }
        let r = sw.rollout();
        assert_eq!((r.pause, r.pause_host), (Pause::Timeout, 4), "{brain_first}: {r:#?}");
        assert!(r.paused.contains("node-c did not finish the update it is in within 1h (its update says pending)"), "{}", r.paused);
        assert_eq!(applies(&sw), before, "{brain_first}: updated beside it");
        sw.skip();
        for _ in 0..40 {
            lie(&sw);
            sw.tick();
        }
        assert!(sw.everyone_on(10) || sw.servers[..2].iter().all(|m| sw.installed(m.host) == 10), "{:#?}", sw.rollout());
        assert!(sw.installed(1) == 10 && sw.rollout().paused.is_empty(), "{:#?}", sw.rollout());
        assert!(sw.rollout().skipped.iter().any(|s| s.host == 4));
    }
}

/// Seen on a VM rollout: a server confirmed, and `release status` said
/// "its turn: updating" again until the brain read its new report. Now it
/// says the server confirmed and the coordinator takes note of it next.
#[test]
fn review_a_confirmed_server_is_not_shown_updating_again() {
    let mut sw = Swarm::new(2);
    sw.publish(10, true);
    let report = |s: &Swarm| s.store.read().unwrap().members.iter().find(|m| m.host == 2).unwrap().report.clone().unwrap();
    sw.until(20, |s| report(s).release == 10);
    assert!(sw.rollout().turn.is_some_and(|t| t.host == 2 && t.ready), "{:#?}", sw.rollout());
    let l = sw.lines();
    assert!(l.contains("node-a confirmed release 10; the coordinator takes note at its next sync"), "{l}");
    assert!(!l.contains("node-a updates"), "{l}");
    let s = sw.store.read().unwrap();
    let v = crate::admin::View {
        members: s.members.iter().map(|m| (m.clone(), true)).collect(),
        rollout: s.rollout.clone(),
        ..Default::default()
    };
    let status = crate::publish::status_lines(&v, sw.now).join("\n");
    assert!(status.contains("confirmed release 10, the coordinator takes note at its next sync"), "{status}");
    assert!(!status.contains("its turn: updating"), "{status}");
    drop(s);
    sw.tick();
    assert!(sw.lines().contains("Watching the canary node-a"), "{}", sw.lines());
}

/// Release 11 failed on the coordinator and went back: the swarm runs 10.
/// The registry refused a release between them without rollback, as it
/// compared with 11. Now only the serial rule holds after a newest that
/// went back; the brain and the servers check the versions themselves.
#[test]
fn after_a_newest_that_went_back_a_release_between_is_taken() {
    let mut sw = Swarm::new(1);
    sw.publish(10, true);
    sw.until(30, |s| s.everyone_on(10));
    let (env, bin) = sw.release(11, "0.4.0", true);
    sw.upload(&env, &bin, None).unwrap();
    let (between, between_bin) = sw.release(12, "0.3.0", true);
    let e = sw.upload(&between, &between_bin, None).unwrap_err().to_string();
    assert!(e.contains("older than"), "{e}");
    sw.brain.fake.sim().apply_fails = Some("dryserver failed: exit status 1: cannot install".into());
    sw.until(5, |s| s.rollout().phase == Phase::Failed);
    // Still refused: the same serial again. One below what the machines
    // run gets past the registry, and the brain refuses it itself.
    let (twin, twin_bin) = sw.release(11, "0.3.0", true);
    assert!(sw.upload(&twin, &twin_bin, None).unwrap_err().to_string().contains("signed twice"));
    let (below, below_bin) = sw.release(12, "0.1.0", true);
    sw.upload(&below, &below_bin, None).unwrap();
    sw.tick();
    let r = sw.rollout();
    assert!(r.serial == 11 && r.refused_serial == 12 && r.refused.contains("older than the installed"), "{r:#?}");
    let (between, between_bin) = sw.release(13, "0.3.0", true);
    sw.upload(&between, &between_bin, None).unwrap();
    sw.brain.fake.sim().apply_fails = None;
    sw.until_unpaused(30, |s| s.everyone_on(13));
    let (below, below_bin) = sw.release(14, "0.1.0", true);
    let e = sw.upload(&below, &below_bin, None).unwrap_err().to_string();
    assert!(e.contains("older than"), "{e}");
}

/// The brain confirmed a release on its own health and self check, which
/// say nothing of the ways in: one that broke `dryserver registry` or
/// sshd's settings for the admin (sshd -t accepts those) was kept, and
/// then no server could sync and no fix could be uploaded. Now the brain
/// keeps a release only once a call through sshd reached the registry as
/// a member's does, sshd -T lets the admin and the registry account in,
/// and (with servers up) a server synced through the new release.
#[test]
fn review_the_brain_keeps_a_release_only_once_the_ways_in_work() {
    let brain_note = |sw: &Swarm| Machine::new(&sw.brain.node, true).load().note;
    // The registry does not answer through sshd.
    let mut sw = Swarm::new(1);
    sw.brain.fake.sim().registry_down = true;
    sw.publish(10, true);
    sw.ticks(5);
    assert!(sw.brain.fake.sim().confirmed.is_empty(), "kept a release that broke the registry");
    assert!(brain_note(&sw).contains("the registry does not answer through sshd"), "{}", brain_note(&sw));
    sw.brain.fake.revert();
    sw.tick();
    assert_eq!(sw.rollout().phase, Phase::Failed);
    assert!(sw.servers.iter().all(|m| m.fake.sim().applied.is_empty()));

    // sshd would lock the admin out: a command forced on the account, or
    // the account not let in.
    for (bad, want) in [
        (sshd_t("admin").replace("ForceCommand none", "ForceCommand /bin/false"), "would force a command on the admin admin"),
        (sshd_t("admin").replace("AllowUsers admin\n", ""), "would not let the admin admin in"),
        (sshd_t("admin").replace("PubkeyAuthentication yes", "PubkeyAuthentication no"), "no public key"),
        (sshd_t("admin").replace("AuthorizedKeysFile .ssh/authorized_keys", "AuthorizedKeysFile none"), "no authorized keys"),
    ] {
        let mut sw = Swarm::new(1);
        sw.brain.fake.sim().sshd_admin = Some(bad);
        sw.publish(10, true);
        sw.ticks(5);
        assert!(sw.brain.fake.sim().confirmed.is_empty() && brain_note(&sw).contains(want), "{want}: {}", brain_note(&sw));
        // Settings in lower case, as older OpenSSH writes them, that let
        // the admin in: kept.
        sw.brain.fake.sim().sshd_admin = Some(sshd_t("admin").to_lowercase());
        sw.until(3, |s| s.installed(1) == 10);
    }

    // No server synced through the new release: not kept, and kept once
    // one did.
    let mut sw = Swarm::new(2);
    sw.publish(10, true);
    sw.until(5, |s| s.brain.fake.sim().pending == 10);
    sw.offline = vec![2, 3];
    sw.ticks(2);
    assert!(sw.brain.fake.sim().confirmed.is_empty() && brain_note(&sw).contains("no server has synced"), "{}", brain_note(&sw));
    sw.offline = vec![2];
    sw.until(3, |s| s.installed(1) == 10);
    let calls = sw.brain.fake.sim().sshd.clone();
    for want in ["ssh dryreg@10.66.0.1 signed", "sshd -T -C user=admin,host=", "sshd -T -C user=dryreg,host="] {
        assert!(
            calls.iter().any(|c| c.starts_with(want) && (want.starts_with("ssh ") || c.contains("addr=192.168.1.50"))),
            "{want}: {calls:?}"
        );
    }
    // With every server off since long before, the registry call alone
    // does.
    let mut sw = Swarm::new(1);
    sw.offline.push(2);
    sw.store
        .update(|s| {
            s.members.iter_mut().find(|m| m.host == 2).unwrap().last_seen = time(t0() - 3600);
            Ok(())
        })
        .unwrap();
    sw.publish(10, true);
    sw.until(5, |s| s.installed(1) == 10);
}

/// A release whose firewall drops SSH from the home network passed every
/// check before the brain kept it (they go through loopback and the mesh),
/// and then `release publish` could not reach the brain again. A server on
/// the home network tries that way in while the brain updates itself.
#[test]
fn review_the_brain_keeps_a_release_only_once_its_ssh_answers_from_the_lan() {
    let brain_note = |sw: &Swarm| Machine::new(&sw.brain.node, true).load().note;
    let mut sw = Swarm::new(2);
    for h in [2, 3] {
        sw.server(h).fake.sim().lan_down = true;
    }
    sw.publish(10, true);
    sw.ticks(8);
    assert!(sw.brain.fake.sim().confirmed.is_empty(), "kept a release the admin's desktop cannot reach");
    let want = "node-a, node-b cannot reach its SSH at 192.168.1.50 from the home network";
    assert!(brain_note(&sw).contains(want), "{}", brain_note(&sw));
    // It goes back at its deadline: the rollout stops with the reason, no
    // server touched, and it does not try again by itself.
    sw.brain.fake.revert();
    sw.ticks(5);
    let r = sw.rollout();
    assert!(r.phase == Phase::Failed && r.paused.contains(want), "{r:#?}");
    assert!(sw.servers.iter().all(|m| m.fake.sim().applied.is_empty()));
    assert_eq!(sw.brain.fake.sim().applied.len(), 1);

    // One server that gets through is enough; they try only while the
    // brain updates itself.
    let mut sw = Swarm::new(2);
    sw.server(3).fake.sim().lan_down = true;
    sw.publish(10, true);
    sw.until(5, |s| s.installed(1) == 10);
    assert!(sw.rollout().warnings.iter().all(|w| !w.contains("without a server proving")), "{:#?}", sw.rollout());
    let tries = |sw: &Swarm| sw.server(2).fake.sim().sshd.iter().filter(|c| c.contains("@192.168.1.50")).count();
    sw.ticks(2);
    let n = tries(&sw);
    assert!(n > 0);
    sw.ticks(5);
    assert_eq!(tries(&sw), n, "the servers go on trying after the brain is done");

    // A server with no way of its own to that address (its WiFi down,
    // WireGuard over the switch) says nothing of the coordinator: it does
    // not hold the update; one that gets through still decides.
    let mut sw = Swarm::new(2);
    sw.server(2).fake.sim().no_route = true;
    sw.publish(10, true);
    sw.until(5, |s| s.installed(1) == 10);
    assert!(sw.rollout().warnings.iter().all(|w| !w.contains("without a server proving")), "{:#?}", sw.rollout());
    let mut sw = Swarm::new(1);
    sw.server(2).fake.sim().no_route = true;
    sw.publish(10, true);
    sw.until(5, |s| s.installed(1) == 10);
    let r = sw.rollout();
    assert!(r.warnings.iter().any(|w| w.contains("no server has a way of its own to that address")), "{r:#?}");
    assert!(sw.server(2).fake.sim().sshd.is_empty(), "it does not try without a route");

    // A server that was not asked (the registry account kept the ask from
    // it): the brain waits a while, then goes by its firewall's rules, and
    // says so.
    let mut sw = Swarm::new(1);
    sw.forge = Some(|s, h| Offer { probe_lan: false, ..offer(s, h) });
    sw.publish(10, true);
    sw.ticks(3);
    assert!(sw.brain.fake.sim().confirmed.is_empty() && brain_note(&sw).contains("no server has tried its SSH"), "{}", brain_note(&sw));
    sw.until(6, |s| s.installed(1) == 10);
    let r = sw.rollout();
    assert!(r.warnings.iter().any(|w| w.contains("without a server proving") && w.contains("were not asked")), "{r:#?}");

    // No server that can try (none at all, or from a dryserver before):
    // the firewall's own rules decide.
    let mut sw = Swarm::new(0);
    sw.publish(10, true);
    sw.until(5, |s| s.installed(1) == 10);
    assert!(sw.rollout().warnings.iter().any(|w| w.contains("no server can try it")), "{:#?}", sw.rollout());
    for (fw, why) in [
        (
            FIREWALL_TEXT.replace("\t\ttcp dport 22 accept\n\t}\n\tchain mesh", "\t}\n\tchain mesh"),
            "has no rule that takes SSH from the home network",
        ),
        (FIREWALL_TEXT.into(), "does not pass nft -c"),
    ] {
        let mut sw = Swarm::new(0);
        put(&sw.brain.node.root, FIREWALL, fw);
        sw.brain.fake.sim().nft_fails = why.contains("nft");
        sw.publish(10, true);
        sw.ticks(5);
        assert!(sw.brain.fake.sim().confirmed.is_empty() && brain_note(&sw).contains(why), "{why}: {}", brain_note(&sw));
    }
}

#[test]
fn the_rules_of_one_nft_chain() {
    let lines = chain_lines(FIREWALL_TEXT, "input");
    assert_eq!(lines.last().map(String::as_str), Some("tcp dport 22 accept"), "{lines:?}");
    assert!(!lines.iter().any(|l| l.contains("mesh {") || l.starts_with('#')), "{lines:?}");
    assert!(chain_lines(FIREWALL_TEXT, "inp").is_empty() && chain_lines("chain input {\n}\n", "input").is_empty());
    // The firewall sysconf renders for the coordinator has the rule.
    let config = Config {
        coord_lan_ip: "192.168.1.50".into(),
        admin_ssh_pubkey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest admin@desktop".into(),
        ..Config::default()
    };
    let plan = crate::packages::resolve(&config.tool_list(), &[]).unwrap();
    let p = crate::sysconf::Params {
        config,
        plan,
        hostname: "coord".into(),
        role: crate::sysconf::Role::Coordinator,
        host_num: 1,
        switch_mac: String::new(),
    };
    let fw = crate::sysconf::render(&p).unwrap().into_iter().find(|f| f.path == FIREWALL).unwrap().content;
    let lines = chain_lines(&fw, "input");
    assert!(lines.iter().any(|l| l == "tcp dport 22 accept") && lines.iter().any(|l| l.contains("jump mesh")), "{lines:?}");
}

/// The admin's signature on a resume or a skip was checked only in the
/// forced command, the registry account's own code; root took the counts
/// from registry.json. So the registry account alone could pass a failed
/// canary over, or resume as often as it liked. Now root checks the signed
/// ask itself, for the stop it is at, and carries each out once.
#[test]
fn review_the_registry_alone_cannot_pass_a_failed_canary_over() {
    let mut sw = Swarm::new(3);
    sw.server(2).fake.sim().apply_fails = Some("dryserver failed: exit status 1: no space left on device".into());
    sw.publish(10, true);
    sw.until(20, |s| !s.rollout().paused.is_empty());
    sw.store
        .update(|s| {
            s.rollout.skip_asked += 1;
            Ok(())
        })
        .unwrap();
    sw.ticks(15);
    let updated: Vec<u32> = sw.servers[1..].iter().filter(|m| !m.fake.sim().applied.is_empty()).map(|m| m.host).collect();
    assert!(updated.is_empty(), "servers {updated:?} updated without the admin's signed skip");

    // Asks it may hold that do nothing: signed by another key, for
    // another op than its slot, another release or stop, or too old.
    let plant = |sw: &Swarm, resume: Envelope, skip: Envelope| {
        sw.store
            .update(|s| {
                (s.rollout.resume_ask, s.rollout.skip_ask) = (resume.clone(), skip.clone());
                Ok(())
            })
            .unwrap();
    };
    // Each newer than the one before, so each fails for its own reason.
    let now = sw.now;
    let ask = |op: &str, t: i64, serial: u64, host: u32| crate::signed::seal_ask(&ADMIN, op, t, serial, host).unwrap();
    let resume = sw.signed_ask("release-resume", now + 5);
    let none = Envelope::default;
    for (resume, skip) in [
        (none(), crate::signed::seal_ask(&Key("thief"), "release-skip", now, 10, 2).unwrap()),
        (Envelope { doc: resume.doc.replace("\"host\":2", "\"host\":2,\"x\":1"), sig: resume.sig.clone() }, none()),
        (ask("release-resume", now - 16 * 60, 10, 2), none()),
        (none(), ask("release-resume", now + 1, 10, 2)),
        (ask("release-resume", now + 2, 9, 2), none()),
        (ask("release-resume", now + 3, 10, 3), none()),
    ] {
        plant(&sw, resume, skip);
        sw.tick();
        let r = sw.rollout();
        assert!((r.pause, r.pause_host) == (Pause::Failed, 2) && r.again.is_empty() && r.skipped.is_empty(), "{r:#?}");
    }
    assert_eq!(sw.server(2).fake.sim().applied.len(), 1);

    // The admin's own resume: node-a tries once more, once. Sent again (the
    // same ask, within its 15 minutes) it does nothing.
    sw.resume();
    let ask = sw.store.read().unwrap().rollout.resume_ask;
    sw.until(10, |s| s.server(2).fake.sim().applied.len() == 2 && !s.rollout().paused.is_empty());
    for _ in 0..5 {
        plant(&sw, ask.clone(), Envelope::default());
        sw.tick();
    }
    assert_eq!(sw.server(2).fake.sim().applied.len(), 2, "one resume carried out twice");
    assert!(sw.rollout().ask_done > 0 && sw.rollout().paused.contains("again"), "{:#?}", sw.rollout());
    // The admin's skip: node-a is passed over, and the others go on.
    sw.skip();
    sw.until_unpaused(30, |s| s.installed(3) == 10 && s.installed(4) == 10);
    assert!(sw.rollout().skipped.iter().any(|s| s.host == 2));
}

/// The offer is made by the registry account, and servers took its turn,
/// retry and brain_k3s as they came: it could give every server the turn
/// at once (no drain, no canary), make up a resume, or lie about the
/// brain's k3s. Now root on the brain signs each turn with the brain's
/// host key, and a server takes only one signed for itself, for this
/// release, while it is fresh, with the retry and the k3s it names.
#[test]
fn review_the_registry_alone_cannot_hand_out_turns() {
    let mut sw = Swarm::new(3);
    // Every server gets the turn, with the one turn root signed, a made-up
    // resume and an older k3s for the brain's.
    sw.forge = Some(|s, host| {
        let mut o = offer(s, host);
        o.grant = s.rollout.turn.as_ref().map(|t| t.grant.clone()).unwrap_or_default();
        (o.turn, o.retry, o.brain_k3s) = (s.rollout.phase == Phase::Servers, 7, "v1.36.1+k3s1".into());
        o
    });
    sw.publish(10, true);
    sw.until(10, |s| s.installed(2) == 10); // tick() asserts one_at_a_time
    assert!(sw.servers[1..].iter().all(|m| m.fake.sim().applied.is_empty()), "updated out of turn");
    let l = Machine::new(&sw.server(3).node, false).load();
    assert!(l.note.contains("does not check out: it is host 2's, and this machine is host 3"), "{l:?}");
    // node-a's own update went by what root signed: its k3s, no retry.
    assert!(sw.server(2).fake.sim().applied[0].ends_with(&["--brain-k3s".to_string(), K3S_VERSION.to_string()]));
    assert_eq!(Machine::new(&sw.server(2).node, false).load().retried, 0);
    sw.forge = None;
    sw.until_unpaused(30, |s| s.everyone_on(10));

    // Turns that do not check out, handed to node-a: nothing happens.
    let mut sw = Swarm::new(2);
    sw.server(2).fake.sim().apply_fails = Some("dryserver failed: exit status 1: broken disk".into());
    sw.publish(10, true);
    sw.until(20, |s| !s.rollout().paused.is_empty());
    let n = sw.now;
    let m = Machine { n: &sw.server(2).node, brain: false, free: plenty };
    let other = |g: &mut Grant| g.host = 3;
    let mut tampered = sw.granted(2, 10, |g| g.retry = 1);
    tampered.grant.doc = tampered.grant.doc.replace("\"retry\":1", "\"retry\":2");
    let mut foreign = sw.granted(2, 10, |g| g.retry = 1);
    foreign.grant.sig = crate::signed::fake::host_sig(&host_key("node-b"), crate::signed::NS_TURN, &foreign.grant.doc);
    let mut wrong_ns = sw.granted(2, 10, |g| g.retry = 1);
    wrong_ns.grant.sig = crate::signed::fake::host_sig(&host_key("coord"), crate::k3stoken::NAMESPACE, &wrong_ns.grant.doc);
    for (o, want) in [
        (Offer { grant: Envelope::default(), ..sw.granted(2, 10, |g| g.retry = 1) }, "it is not signed"),
        (sw.granted(2, 10, |g| (g.retry, g.host) = (1, 3)), "it is host 3's"),
        // Without a resume a server it failed on does nothing at all.
        (sw.granted(2, 10, other), ""),
        (Offer { serial: 10, ..sw.granted(2, 9, |g| g.retry = 1) }, "it is for release 9"),
        (sw.granted(2, 10, |g| (g.retry, g.issued, g.expires) = (1, n - 3600, n - 1800)), "it expired"),
        (sw.granted(2, 10, |g| (g.retry, g.issued, g.expires) = (1, n + 3600, n + 4200)), "ahead of this machine's clock"),
        (tampered, "not signed by the coordinator the admin signed"),
        (foreign, "not signed by the coordinator the admin signed"),
        (wrong_ns, "not signed by the coordinator the admin signed"),
        // A retry the registry account made up beside a turn root signed
        // without one.
        (Offer { retry: 5, ..sw.granted(2, 10, |_| {}) }, ""),
    ] {
        let e = m.step(&Ctx::new(), &Reg { sw: &sw, host: 2 }, &o, &sw.healthy(2), n).err().map(|e| e.to_string()).unwrap_or_default();
        assert!(e.contains(want), "{want}: {e}");
        let l = m.load();
        assert!(l.failed == 10 && l.retried == 0, "{want}: {l:?}");
    }
    assert_eq!(sw.server(2).fake.sim().applied.len(), 1, "installed again on a turn root did not sign");
    // Signed for it, with the admin's resume: it tries once more.
    sw.server(2).fake.sim().apply_fails = None;
    let o = sw.granted(2, 10, |g| g.retry = 1);
    m.step(&Ctx::new(), &Reg { sw: &sw, host: 2 }, &o, &sw.healthy(2), n).unwrap();
    assert_eq!((m.load().failed, m.load().retried), (0, 1));

    // A server of the version before reads the offer as it always did.
    #[derive(Deserialize)]
    struct Before {
        serial: u64,
        turn: bool,
        brain_k3s: String,
        retry: u64,
    }
    let old: Before = serde_json::from_str(&serde_json::to_string(&o).unwrap()).unwrap();
    assert!(old.serial == 10 && old.turn && old.brain_k3s == K3S_VERSION && old.retry == 1);
}

/// What root signs: the turn of a drained server, anew before it expires
/// and when it changes, never the brain's own; one that cannot be signed
/// gives no turn.
#[test]
fn root_signs_each_turn_and_signs_it_anew() {
    let mut sw = Swarm::new(2);
    sw.ignore_turn.push(2);
    sw.publish(10, true);
    sw.until(10, |s| s.rollout().turn.is_some_and(|t| t.ready));
    let grant = |sw: &Swarm| serde_json::from_str::<Grant>(&sw.rollout().turn.unwrap().grant.doc).unwrap();
    let g = grant(&sw);
    assert_eq!((g.host, g.serial, g.retry, g.brain_k3s.as_str(), g.expires - g.issued), (2, 10, 0, K3S_VERSION, GRANT_LIFE));
    assert!(offer(&sw.store.read().unwrap(), 2).grant == sw.rollout().turn.unwrap().grant);
    assert!(offer(&sw.store.read().unwrap(), 3).grant.is_empty(), "another server's turn handed to node-b");
    sw.ticks(2);
    assert_eq!(grant(&sw), g, "signed anew while it was fresh");
    sw.ticks(((GRANT_LIFE - GRANT_RENEW) / 60) as usize);
    assert!(grant(&sw).issued > g.issued && grant(&sw).expires > g.expires, "not signed anew before it expired");
    // The brain's k3s changed: signed anew at once.
    sw.brain_k3s = "v1.37.3+k3s1".into();
    sw.tick();
    assert_eq!(grant(&sw).brain_k3s, "v1.37.3+k3s1");
    // Its host key cannot sign: no turn, and the admin is told.
    std::fs::remove_file(sw.brain.node.path(crate::node::HOST_KEY)).unwrap();
    sw.ticks(GRANT_RENEW as usize / 60 + 1);
    let r = sw.rollout();
    assert!(r.turn.as_ref().is_some_and(|t| t.grant.is_empty()) && !offer(&sw.store.read().unwrap(), 2).turn, "{r:#?}");
    assert!(r.warnings.iter().any(|w| w.starts_with("cannot sign node-a's turn")), "{r:#?}");
    assert!(sw.brain.fake.sim().keygen.iter().all(|k| k.contains(crate::signed::NS_TURN)));
}

/// What the brain reads of `sshd -T`, with the real sshd where it is
/// installed (OpenSSH 10 writes the keywords mixed case, older ones in
/// lower case), on settings like the ones dryserver writes.
#[test]
fn the_brain_reads_what_the_real_sshd_says() {
    if !crate::iso::in_path("sshd") || !crate::iso::in_path("ssh-keygen") {
        eprintln!("the_brain_reads_what_the_real_sshd_says: no sshd here, skipped");
        return;
    }
    struct Sshd(crate::runner::ExecRunner, PathBuf);
    impl Runner for Sshd {
        fn run(&self, ctx: &Ctx, c: &Cmd) -> (String, Result<()>) {
            let f = self.1.display().to_string();
            let mut args = vec!["-T".to_string(), "-f".into(), f];
            args.extend(c.args.iter().skip(1).cloned());
            let a: Vec<&str> = args.iter().map(String::as_str).collect();
            self.0.run(ctx, &Cmd::new(&c.name, &a).quiet().stdout_only())
        }
    }
    let dir = TempDir::new();
    let key = dir.join("hostkey");
    assert!(Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", ""]).arg("-f").arg(&key).status().unwrap().success());
    let force = crate::sysconf::registry_command(&crate::cidr::Cidr::parse("10.66.0.0/24").unwrap());
    let conf = |admin: &str| {
        let path = dir.join("sshd_config");
        let text = format!(
            "HostKey {}\nPasswordAuthentication no\nAuthenticationMethods publickey\nPermitRootLogin no\nAllowUsers admin dryreg\n{admin}\
             Match User dryreg\n\tForceCommand {force}\n\tDisableForwarding yes\n\tPermitTTY no\n",
            key.display()
        );
        std::fs::write(&path, text).unwrap();
        path
    };
    let b = machine(1, "coord");
    let node = |path: PathBuf| Node { run: Arc::new(Sshd(crate::runner::ExecRunner::silent(), path)), ..b.node.clone() };
    let n = node(conf(""));
    sshd_lets_in(&Ctx::new(), &n, "admin", "192.168.1.50", None).unwrap();
    sshd_lets_in(&Ctx::new(), &n, "dryreg", "192.168.1.50", Some(&force)).unwrap();
    assert!(sshd_lets_in(&Ctx::new(), &n, "admin", "192.168.1.50", Some(&force)).is_err());
    for (bad, want) in [
        ("Match User admin\n\tForceCommand /bin/false\n", "would force a command"),
        ("Match User admin\n\tPubkeyAuthentication no\n", "no public key"),
        ("Match User admin\n\tAuthorizedKeysFile none\n", "no authorized keys"),
        ("DenyUsers admin\n", "would not let"),
    ] {
        let e = sshd_lets_in(&Ctx::new(), &node(conf(bad)), "admin", "192.168.1.50", None).unwrap_err();
        assert!(e.contains(want), "{bad}: {e}");
    }
}

/// Seen on a VM: after the coordinator's apply stopped part way and its
/// revert did not finish, its report said "updating (release N):
/// installing" for good: settle returned on the revert's error before it
/// said why, and the note the apply's start left stayed. Now the note says
/// the way back did not finish, and it is tried again at each sync (update
/// revert is safe to repeat while the record says reverting).
#[test]
fn a_revert_that_does_not_finish_says_so_and_is_tried_again() {
    for host in [1, 2] {
        let mut sw = Swarm::new(1);
        let fake = if host == 1 { sw.brain.fake.clone() } else { sw.server(2).fake.clone() };
        (fake.sim().dies, fake.sim().revert_fails) = (true, 2);
        sw.publish(10, true);
        sw.until(10, |_| fake.sim().pending == 10 && fake.sim().reverting);
        sw.tick();
        let local = |sw: &Swarm| Machine::new(if host == 1 { &sw.brain.node } else { &sw.server(2).node }, host == 1).load();
        let l = local(&sw);
        assert!(l.note.contains("going back did not finish yet") && l.note.contains("No space left"), "{host}: {l:?}");
        let rep = sw.store.read().unwrap().members.iter().find(|m| m.host == host).unwrap().report.clone().unwrap();
        assert!(rep.update == "pending" && !rep.update_note.contains("installing"), "{host}: {rep:?}");
        assert!(rep.update_note.contains("going back did not finish yet"), "{host}: {rep:?}");
        // It finishes: recorded as gone back, and the rollout stops.
        sw.until(5, |s| !s.rollout().paused.is_empty() || s.rollout().phase == Phase::Failed);
        assert_eq!(fake.sim().pending, 0);
        let l = local(&sw);
        assert!(l.pending == 0 && l.failed == 10 && l.outcome == "reverted", "{host}: {l:?}");
        assert!(fake.sim().confirmed.is_empty());
    }
}
