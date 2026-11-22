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
    /// The apply rebooted the machine for new packages; restarts since.
    reboot: bool,
    boots: u32,
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
                    let stage = if s.dies { "installing" } else { "armed" };
                    serde_json::json!({"serial": s.pending, "previous": if s.installed == 0 { serde_json::Value::Null } else { s.installed.into() },
                        "stage": stage, "step": "", "reboot": s.reboot, "deadline": 0, "seconds_left": 300, "boots": s.boots, "files": []})
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
            _ => (String::new(), Err(errf!("unexpected command {c}"))),
        }
    }
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
    let fake = Arc::new(Fake(Mutex::new(Sim { root: dir.path().to_path_buf(), ..Sim::default() })));
    let node = Node {
        cfg: Config { wg_subnet: "10.66.0.0/24".into(), ..Config::default() },
        hostname: name.into(),
        root: dir.path().to_path_buf(),
        run: fake.clone(),
        tmp_dir: None,
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
        let o = offer(&self.store.read()?, m.host);
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

    /// The admin's `release resume`, or with skip `release resume -skip`.
    fn ask(&self, skip: bool) -> Result<Vec<u8>> {
        let op = if skip { "release-skip" } else { "release-resume" };
        self.call(op, 0, serde_json::to_string(&crate::signed::seal_admin(&ADMIN, op, self.now).unwrap()).unwrap().as_bytes())
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
    fn offered(&self, _: &Ctx, serial: u64) -> Result<Offered> {
        let out = self.sw.call(&format!("release-get {serial} release"), self.host, b"")?;
        Ok(serde_json::from_slice(&out)?)
    }

    fn chunk(&self, _: &Ctx, serial: u64, name: &str, offset: u64, _len: u64, dst: &Path) -> Result<()> {
        self.sw.pieces.lock().unwrap().push((self.host, name.into(), offset));
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
    sw.call(
        "release-resume",
        0,
        serde_json::to_string(&crate::signed::seal_admin(&ADMIN, "release-resume", sw.now).unwrap()).unwrap().as_bytes(),
    )
    .unwrap();
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
    let ask = serde_json::to_string(&crate::signed::seal_admin(&ADMIN, "release-resume", sw.now).unwrap()).unwrap();
    sw.call("release-resume", 0, ask.as_bytes()).unwrap();
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
    let ask = serde_json::to_string(&crate::signed::seal_admin(&ADMIN, "release-resume", sw.now).unwrap()).unwrap();
    sw.call("release-resume", 0, ask.as_bytes()).unwrap();
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
    let o = Offer { serial: 10, turn: true, brain_k3s: K3S_VERSION.into(), retry: 0 };
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
/// TURN_TIMEOUT at most.
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
    sw.until(TURN_TIMEOUT as usize / 60 + 5, |s| s.brain.fake.sim().applied.len() == 2);
    assert!(sw.now - start >= TURN_TIMEOUT, "it waited {}s", sw.now - start);
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
    // It names another server, gives it a retry, and counts a skip.
    sw.store
        .update(|s| {
            s.rollout.pause_host = 3;
            s.rollout.pause_name = "node-b".into();
            s.rollout.skipped.push(Skip { host: 4, name: "node-c".into(), why: "x".into() });
            s.rollout.again.push(4);
            s.rollout.skip_asked += 3;
            Ok(())
        })
        .unwrap();
    sw.tick();
    let r = sw.rollout();
    assert_eq!(r.skipped.iter().map(|s| s.host).collect::<Vec<_>>(), vec![2], "{r:#?}");
    assert!(r.again.is_empty(), "{r:#?}");
    sw.until_unpaused(30, |s| s.installed(3) == 10 && s.installed(4) == 10);
    // A count that goes back is no ask; the next one counts again.
    sw.store
        .update(|s| {
            s.rollout.resume_asked = 0;
            s.rollout.skip_asked = 0;
            Ok(())
        })
        .unwrap();
    sw.tick();
    let r = sw.rollout();
    assert!(r.paused.is_empty() && (r.resume_done, r.skip_done) == (0, 0), "{r:#?}");
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
    assert!(l.contains("Look at it, then: ./dryserver release resume (node-a tries again)"), "{l}");
    assert!(l.contains("Or pass node-a over for this release: ./dryserver release resume -skip"), "{l}");
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
    assert!(l.contains("./dryserver release resume (updates node-a without draining)") && l.contains("-skip"), "{l}");
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
    assert!(l.contains("./dryserver release resume (goes on)") && !l.contains("-skip"), "{l}");
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
    assert!(e.contains("never passed over") && e.contains("./dryserver release resume"), "{e}");
    sw.brain.fake.sim().apply_fails = None;
    sw.store
        .update(|s| {
            s.rollout.skip_asked += 5;
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
    let o = Offer { serial: 10, turn: true, brain_k3s: K3S_VERSION.into(), retry: 0 };
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
    assert!(sw.kubectl().contains(&"uncordon -- node-b".to_string()), "the old turn's node stays cordoned");
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
    let ask = serde_json::to_string(&crate::signed::seal_admin(&ADMIN, "release-resume", sw.now).unwrap()).unwrap();
    sw.call("release-resume", 0, ask.as_bytes()).unwrap();
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
            "pending":{"serial":10,"stage":"booted","deadline":77,"seconds_left":5,"boots":1,"files":["x"]},
            "last":{"at":1,"serial":8,"action":"reverted","ok":true,"message":"selfcheck failed"},"problems":["x"]}"#,
    )
    .unwrap();
    assert_eq!((s.installed.serial, s.pending_serial(), s.pending.as_ref().unwrap().deadline), (9, 10, 77));
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
    // After its update it booted the fallback kernel: the new main kernel
    // did not work. Not confirmed, and the rollout stops there.
    let mut sw = Swarm::new(2);
    sw.fallback.push(2);
    sw.publish(10, true);
    sw.until(30, |s| s.server(2).fake.sim().pending == 10);
    sw.ticks(5);
    assert!(sw.server(2).fake.sim().confirmed.is_empty(), "confirmed on its fallback kernel");
    let r = sw.store.read().unwrap().members.iter().find(|m| m.host == 2).unwrap().report.clone().unwrap();
    assert!(r.update_note.contains("fallback kernel"), "{r:?}");
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
