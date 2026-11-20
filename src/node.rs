//! Runs on a server (or on the installer for a server being installed): asks
//! the coordinator to join, waits for approval, brings up the mesh and keeps
//! it in sync.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::{self, Config};
use crate::ctx::Ctx;
use crate::err::{Error, Kind, Result};
use crate::gotime::Time;
use crate::mesh::{self, SelfInfo};
use crate::registry::{self, Member, Status, StatusReply, Store};
use crate::runner::{Cmd, Runner};
use crate::signed::{self, Envelope, Verifier};
use crate::sysconf::{self, Params};
use crate::{errf, fsx, quarantine};

// Files inside the server's root.
pub const REGISTRY_KEY: &str = "/etc/dryserver/registry_ed25519";
/// The pinned coordinator host key.
pub const KNOWN_HOSTS: &str = "/etc/dryserver/known_hosts";
pub const JOIN_STATE: &str = "/etc/dryserver/join.json";
pub const WG_KEY: &str = "/etc/wireguard/wg0.key";
pub const WG_PUB: &str = "/etc/wireguard/wg0.pub";
pub const WG_CONF: &str = "/etc/wireguard/wg0.conf";
pub const HOST_KEY_PUB: &str = "/etc/ssh/ssh_host_ed25519_key.pub";
/// Records which Ethernet port is the switch port.
pub const SWITCH_MAC_FILE: &str = "/etc/dryserver/switch.mac";
/// The public half of the admin's signing key, from the installer. Outside
/// /etc/dryserver (root only) because the coordinator's registry user reads
/// it too; root owns it, everyone may read it.
pub const SIGNING_PUB: &str = "/usr/local/share/dryserver/signing_ed25519.pub";
/// The newest signed member list this server has verified. A lower version
/// from the coordinator later is a rollback.
pub const SIGNED_FILE: &str = "/etc/dryserver/members.signed.json";
/// What the last sync thought of the coordinator's list; a change is logged.
pub const SIGNED_STATUS: &str = "/run/dryserver-signed.status";
/// Shows join status on the console login screen.
pub const ISSUE_FILE: &str = "/etc/issue.d/50-dryserver.issue";

fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// Kept in JOIN_STATE between steps and reboots.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub request_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub code: String,
    /// Mesh host number once approved.
    #[serde(skip_serializing_if = "is_zero")]
    pub host: u32,
}

#[derive(Clone)]
pub struct Node {
    pub cfg: Config,
    pub hostname: String,
    /// "/" on the server, "/mnt" from the installer.
    pub root: PathBuf,
    pub run: Arc<dyn Runner>,
    /// RAM-backed dir for temporary key material; None = /run.
    pub tmp_dir: Option<PathBuf>,
}

/// What a node reports on each sync.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Heartbeat {
    pub lan_ip: String,
    pub switch: bool,
}

impl Node {
    pub fn path(&self, p: &str) -> PathBuf {
        fsx::under(&self.root, p)
    }

    fn read(&self, p: &str) -> Result<String> {
        Ok(fsx::read_string(self.path(p))?.trim().to_string())
    }

    pub fn write(&self, p: &str, mode: u32, content: &str) -> Result<()> {
        let dst = self.path(p);
        fsx::mkdir_all(fsx::dir(&dst), 0o755)?;
        let tmp = PathBuf::from(format!("{}.tmp", dst.display()));
        fsx::write_file(&tmp, content, mode)?;
        fsx::rename(&tmp, &dst)
    }

    fn cmd(&self, ctx: &Ctx, name: &str, args: &[&str]) -> Result<()> {
        self.run.ok(ctx, &Cmd::new(name, args))
    }

    /// The recorded switch port, "" if none.
    pub fn switch_mac(&self) -> String {
        self.read(SWITCH_MAC_FILE).unwrap_or_default()
    }

    pub fn load_state(&self) -> State {
        std::fs::read(self.path(JOIN_STATE)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    pub fn save_state(&self, s: &State) -> Result<()> {
        let b = serde_json::to_string_pretty(s)?;
        self.write(JOIN_STATE, 0o600, &format!("{b}\n"))
    }

    /// Runs one registry command on the coordinator as the registry user.
    /// The coordinator's host key is pinned in KNOWN_HOSTS on first contact;
    /// the pairing code shows the admin which key the node saw.
    fn ssh(&self, ctx: &Ctx, addr: &str, command: &str, stdin: &str) -> (String, Result<()>) {
        let key = self.path(REGISTRY_KEY).display().to_string();
        let kh = format!("UserKnownHostsFile={}", self.path(KNOWN_HOSTS).display());
        let target = format!("{}@{addr}", sysconf::REGISTRY_USER);
        let args = [
            "-i",
            &key,
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "HostKeyAlgorithms=ssh-ed25519",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "HashKnownHosts=no",
            "-o",
            &kh,
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            &target,
            command,
        ];
        self.run.run(ctx, &Cmd::new("ssh", &args).stdin(stdin).stdout_only())
    }

    /// The host key pinned for the coordinator.
    fn coordinator_key(&self) -> Result<String> {
        let text = fsx::read_string(self.path(KNOWN_HOSTS))?;
        for line in text.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() >= 3 && f[1] == "ssh-ed25519" && f[0].split(',').any(|h| h == self.cfg.coord_lan_ip) {
                return Ok(format!("{} {}", f[1], f[2]));
            }
        }
        Err("coordinator host key not recorded".into())
    }

    /// Sends a join request and returns the pairing code to show.
    pub fn request(&self, ctx: &Ctx, lan_ip: &str, sw: bool) -> Result<String> {
        let wg = self.read(WG_PUB)?;
        let host_key = self.read(HOST_KEY_PUB)?;
        let req = registry::Request {
            name: self.hostname.clone(),
            wg_key: wg.clone(),
            ssh_host_key: host_key.clone(),
            lan_ip: lan_ip.into(),
            switch: sw,
            ..registry::Request::default()
        };
        let body = serde_json::to_string(&req)?;
        let (out, res) = self.ssh(ctx, &self.cfg.coord_lan_ip, "request", &body);
        if let Err(e) = res {
            return Err(e.wrap(format!("cannot reach the coordinator at {} (is it installed and switched on?)", self.cfg.coord_lan_ip)));
        }
        #[derive(Deserialize)]
        struct Reply {
            #[serde(default)]
            id: String,
        }
        let id = serde_json::from_str::<Reply>(&out).map(|r| r.id).unwrap_or_default();
        if id.is_empty() {
            return Err(errf!("coordinator said: {}", out.trim()));
        }
        let coord_key = self.coordinator_key()?;
        let code = registry::pairing_code(&wg, &host_key, &coord_key);
        self.save_state(&State { request_id: id, code: code.clone(), host: 0 })?;
        Ok(code)
    }

    /// Polls until the request is decided. Approved returns the reply with
    /// the host number and the coordinator's details.
    pub fn wait(&self, ctx: &Ctx, every: Duration) -> Result<StatusReply> {
        let st = self.load_state();
        if st.request_id.is_empty() {
            return Err("no join request sent".into());
        }
        loop {
            let (out, res) = self.ssh(ctx, &self.cfg.coord_lan_ip, &format!("status {}", st.request_id), "");
            match res {
                Ok(()) => {
                    if let Ok(r) = serde_json::from_str::<StatusReply>(&out) {
                        match r.status {
                            Status::Approved => {
                                // What it sends ends up in wg0.conf, /etc/hosts
                                // and the SSH trust files: check all of it.
                                let coord_ok = r.coordinator.as_ref().is_some_and(|c| c.host == 1 && registry::member_problem(c).is_none());
                                if !coord_ok || r.host < 2 || mesh::ip(&self.cfg.wg_subnet, r.host).is_empty() {
                                    return Err("coordinator sent an incomplete or invalid approval".into());
                                }
                                return Ok(r);
                            }
                            Status::Rejected => return Err(Error::with_kind(Kind::Rejected, "the coordinator rejected this machine")),
                            _ => {}
                        }
                    }
                }
                // The registry's error reaches us on stderr, which ends up
                // in the error message.
                Err(e) if out.contains("no such request") || e.to_string().contains("no such request") => {
                    return Err(Error::with_kind(Kind::Expired, "the join request expired; a new one is needed"));
                }
                Err(_) => {}
            }
            ctx.sleep(every)?;
        }
    }

    /// Writes the mesh config for an approved node: its switch address,
    /// WireGuard with the coordinator as first peer (the rest arrive with the
    /// first sync), names and host keys.
    pub fn activate(&self, r: &StatusReply, me: SelfInfo, plan: &Params) -> Result<()> {
        let mut st = self.load_state();
        st.host = r.host;
        self.save_state(&st)?;
        let mut plan = plan.clone();
        plan.host_num = r.host;
        for f in sysconf::render(&plan)? {
            // Only the switch port file depends on the host number.
            if f.path == "/etc/systemd/network/10-switch.network" {
                self.write(&f.path, f.mode, &f.content)?;
            }
        }
        // Pin the coordinator's key under its mesh address too, for sync.
        let key = self.coordinator_key()?;
        let pin = format!("{},{} {key}\n", self.cfg.coord_lan_ip, mesh::ip(&self.cfg.wg_subnet, 1));
        self.write(KNOWN_HOSTS, 0o600, &pin)?;
        let me = SelfInfo { host: r.host, ..me };
        let coord = r.coordinator.clone().ok_or_else(|| Error::new("coordinator sent an incomplete approval"))?;
        self.apply(me, &[coord, Member { host: r.host, name: self.hostname.clone(), ..Member::default() }])
    }

    /// Writes WireGuard, hosts and SSH files for the given members.
    pub fn apply(&self, me: SelfInfo, members: &[Member]) -> Result<()> {
        self.write(WG_CONF, 0o600, &mesh::wg_config(&self.cfg, me, members))?;
        let cur = fsx::read_or_empty(self.path("/etc/hosts"));
        self.write("/etc/hosts", 0o644, &mesh::hosts(&cur, &self.cfg, members))?;
        self.write("/etc/ssh/ssh_known_hosts", 0o644, &mesh::known_hosts(&self.cfg, members))?;
        self.write("/etc/ssh/ssh_config.d/20-dryserver.conf", 0o644, &mesh::ssh_config(&self.cfg, members))
    }

    /// Asks the coordinator for the member list over the mesh, reporting
    /// this node's current LAN IP and cable link. Also returns the signed
    /// list as the coordinator sent it (empty when it has none).
    pub fn fetch_members(&self, ctx: &Ctx, hb: &Heartbeat) -> Result<(Vec<Member>, Envelope)> {
        let body = serde_json::to_string(hb)?;
        let out = {
            let (out, res) = self.ssh(ctx, &mesh::ip(&self.cfg.wg_subnet, 1), "peers", &body);
            res?;
            out
        };
        #[derive(Deserialize)]
        struct Reply {
            #[serde(default, deserialize_with = "crate::gotime::null_default")]
            members: Vec<Member>,
            #[serde(default, deserialize_with = "crate::gotime::null_default")]
            signed: Envelope,
        }
        let (members, signed) = match serde_json::from_str::<Reply>(&out) {
            Ok(r) if !r.members.is_empty() => (r.members, r.signed),
            _ => return Err("bad member list from coordinator".into()),
        };
        // Nothing from the coordinator is used unchecked.
        let (members, problems) = registry::check_members(members, |h| !mesh::ip(&self.cfg.wg_subnet, h).is_empty());
        for p in &problems {
            eprintln!("dryserver: sync: ignoring {p}");
        }
        // Without the coordinator's own entry this server would drop its
        // peer and never reach it again: keep the current mesh instead.
        if !members.iter().any(|m| m.host == 1) {
            return Err("the coordinator's member list has no usable entry for the coordinator itself; keeping the current mesh".into());
        }
        Ok((members, signed))
    }

    /// Compares what the coordinator sent with the list the admin signed
    /// and says the result in one line. Remembers the newest valid signed
    /// list, so an older one later is noticed.
    ///
    /// For now this only reports: the mesh still follows the coordinator.
    pub fn check_signed(&self, members: &[Member], env: &Envelope, v: Option<&dyn Verifier>) -> String {
        let Some(v) = v else {
            return "not checked: this server has no signing key (installed by an older dryserver)".into();
        };
        if env.is_empty() {
            return "NOT SIGNED: the coordinator sent no signed member list (sign it from your desktop: ./dryserver approve)".into();
        }
        let fits = |h: u32| !mesh::ip(&self.cfg.wg_subnet, h).is_empty();
        let list = match env.list(v, fits) {
            Ok(l) => l,
            Err(e) => return format!("NOT VALID: the coordinator's signed member list was refused: {e}"),
        };
        // The stored list was verified when it was saved; root owns it.
        let seen: Option<(u64, Envelope)> = std::fs::read(self.path(SIGNED_FILE)).ok().and_then(|b| {
            let e: Envelope = serde_json::from_slice(&b).ok()?;
            let l: signed::List = serde_json::from_str(&e.doc).ok()?;
            Some((l.version, e))
        });
        match &seen {
            Some((ver, _)) if list.version < *ver => {
                return format!(
                    "ROLLBACK: the coordinator sent signed list version {}, this server has already seen version {ver}",
                    list.version
                );
            }
            Some((ver, old)) if list.version == *ver && old.doc != env.doc => {
                return format!("CONFLICT: the coordinator sent a different signed list with the same version {ver}");
            }
            Some((ver, _)) if list.version == *ver => {}
            _ => {
                let saved = serde_json::to_string(env).map_err(Error::from).and_then(|t| self.write(SIGNED_FILE, 0o600, &(t + "\n")));
                if let Err(e) = saved {
                    return format!("NOT SAVED: cannot remember signed list version {}: {e}", list.version);
                }
            }
        }
        let extra: Vec<&str> = members.iter().filter(|m| !list.has(m)).map(|m| m.name.as_str()).collect();
        let missing: Vec<&str> = list.members.iter().filter(|e| !members.iter().any(|m| e.matches(m))).map(|e| e.name.as_str()).collect();
        if extra.is_empty() && missing.is_empty() {
            return format!("ok: member list matches signed version {} ({} members)", list.version, list.members.len());
        }
        let mut parts = Vec::new();
        if !extra.is_empty() {
            parts.push(format!("not signed by you: {}", extra.join(", ")));
        }
        if !missing.is_empty() {
            parts.push(format!("signed but not sent: {}", missing.join(", ")));
        }
        format!("MISMATCH with signed version {}: {}", list.version, parts.join("; "))
    }

    /// Logs the status when it changed since the last sync, so the journal
    /// gets one line per change and not one per minute.
    fn note_signed(&self, status: &str) {
        let path = self.path(SIGNED_STATUS);
        if fsx::read_or_empty(&path).trim() == status {
            return;
        }
        eprintln!("dryserver: member list: {status}");
        let _ = fsx::mkdir_all(fsx::dir(&path), 0o755);
        let _ = fsx::write_file(&path, format!("{status}\n"), 0o644);
    }

    // ---- commands run at boot and by the timer ----

    /// Activates on the running system and starts the mesh.
    fn activate_live(&self, ctx: &Ctx, r: &StatusReply, params: &Params) -> Result<()> {
        let mut params = params.clone();
        params.switch_mac = self.switch_mac();
        self.activate(r, SelfInfo { host: 0, switch: port_link(&params.switch_mac) }, &params)?;
        let _ = self.cmd(ctx, "networkctl", &["reload"]); // switch address
        self.cmd(ctx, "systemctl", &["enable", "--now", "wg-quick@wg0.service", "dryserver-sync.timer"])?;
        // First full sync; if the tunnel is not up yet the timer retries.
        let _ = self.cmd(ctx, "systemctl", &["start", "--no-block", "dryserver-sync.service"]);
        Ok(())
    }

    /// Pings each peer's switch address when both sides report a cable link,
    /// and uses the WiFi/router path for peers that do not answer (e.g. a
    /// cable into the router instead of the switch).
    fn check_switch(&self, ctx: &Ctx, me: SelfInfo, members: &[Member]) -> Vec<Member> {
        if !me.switch || self.cfg.wg_transport != config::TRANSPORT_AUTO {
            return members.to_vec();
        }
        let mut out = members.to_vec();
        for m in out.iter_mut() {
            if m.host == me.host || !m.switch {
                continue;
            }
            if self.cmd(ctx, "ping", &["-c", "1", "-W", "1", &mesh::ip(&self.cfg.switch_subnet, m.host)]).is_err() {
                m.switch = false;
            }
        }
        out
    }

    /// Applies wg0.conf to the running interface without dropping
    /// connections, or starts it.
    pub fn reload_wg(&self, ctx: &Ctx) -> Result<()> {
        if self.cmd(ctx, "systemctl", &["is-active", "--quiet", "wg-quick@wg0.service"]).is_err() {
            return self.cmd(ctx, "systemctl", &["start", "wg-quick@wg0.service"]);
        }
        let stripped = self.run.output(ctx, &Cmd::new("wg-quick", &["strip", "wg0"]).quiet().stdout_only())?;
        let key = self.read(WG_KEY)?;
        let dir = self.tmp_dir.clone().unwrap_or_else(|| PathBuf::from("/run"));
        let tmp = dir.join(format!("dryserver-wg0-{}.conf", fsx::hex(&fsx::random_bytes(6))));
        struct Remove<'a>(&'a Path);
        impl Drop for Remove<'_> {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(self.0);
            }
        }
        let _rm = Remove(&tmp);
        // 0600 in a RAM-backed directory.
        let mut f = std::fs::OpenOptions::new();
        std::os::unix::fs::OpenOptionsExt::mode(f.write(true).create_new(true), 0o600);
        f.open(&tmp)?.write_all(with_private_key(&stripped, &key).as_bytes())?;
        self.cmd(ctx, "wg", &["syncconf", "wg0", &tmp.display().to_string()])
    }
}

/// Adds the private key to a stripped config: syncconf applies the file as
/// the whole interface config and would otherwise clear the key. wg0.conf
/// itself never holds the key.
pub fn with_private_key(conf: &str, key: &str) -> String {
    conf.replacen("[Interface]\n", &format!("[Interface]\nPrivateKey = {}\n", key.trim()), 1)
}

/// Runs at boot on a server that is not approved yet: sends (or resumes) a
/// join request, shows the pairing code on the console and waits. On
/// approval it brings up the mesh and disables itself.
pub fn join_loop(ctx: &Ctx, n: &Node, params: &Params, log: &mut dyn Write) -> Result<()> {
    if n.load_state().host > 0 {
        return n.cmd(ctx, "systemctl", &["disable", "dryserver-join.service"]);
    }
    let mut show = |msg: &str| {
        let _ = writeln!(log, "{msg}");
        let _ = n.write(ISSUE_FILE, 0o644, &format!("\n{msg}\n\n"));
        let _ = n.cmd(ctx, "agetty", &["--reload"]);
    };
    loop {
        if quarantine::blocks_join(n) {
            show("dryserver: quarantined, the coordinator is cut off: not joining.\nUndo with: sudo dryserver quarantine -lift");
            return Ok(());
        }
        let mut st = n.load_state();
        if st.request_id.is_empty() {
            let sent = local_ip(ctx, n.run.as_ref(), &n.cfg.coord_lan_ip).and_then(|lan| n.request(ctx, &lan, port_link(&n.switch_mac())));
            match sent {
                Ok(code) => st.code = code,
                Err(e) => {
                    show(&format!("dryserver: cannot reach the coordinator at {} yet, retrying: {e}", n.cfg.coord_lan_ip));
                    ctx.sleep(Duration::from_secs(30))?;
                    continue;
                }
            }
        }
        show(&format!(
            "dryserver: waiting for approval. On the coordinator run: sudo dryserver approve\n\
             Approve only if it shows this code:  {}",
            st.code
        ));
        match n.wait(ctx, Duration::from_secs(5)) {
            Ok(r) => {
                // A cut may have landed while waiting: check again under
                // the mesh lock, so the coordinator's peer is never added
                // after it.
                let lock = fsx::lock(n.path(quarantine::MESH_LOCK))?;
                if quarantine::blocks_join(n) {
                    show("dryserver: quarantined, the coordinator is cut off: not joining.\nUndo with: sudo dryserver quarantine -lift");
                    return Ok(());
                }
                n.activate_live(ctx, &r, params)?;
                drop(lock);
                show(&format!("dryserver: joined the mesh as {}", mesh::ip(&n.cfg.wg_subnet, r.host)));
                let _ = std::fs::remove_file(n.path(ISSUE_FILE));
                let _ = n.cmd(ctx, "agetty", &["--reload"]);
                return n.cmd(ctx, "systemctl", &["disable", "dryserver-join.service"]);
            }
            Err(e) if e.is(Kind::Rejected) => {
                show("dryserver: the coordinator rejected this machine.");
                let _ = n.cmd(ctx, "systemctl", &["disable", "dryserver-join.service"]);
                return Err(e);
            }
            Err(e) if e.is(Kind::Expired) => {
                let _ = n.save_state(&State::default());
            }
            Err(_) if ctx.done() => return Err(ctx.err().unwrap()),
            Err(_) => ctx.sleep(Duration::from_secs(10))?,
        }
    }
}

/// Refreshes the mesh from the member list. Nodes ask the coordinator over
/// the mesh; the coordinator reads its own registry. Members cut off by
/// `dryserver quarantine` are left out, and with the coordinator cut a node
/// does not sync at all: false means paused.
pub fn sync(ctx: &Ctx, n: &Node, coordinator: bool, store: &Store) -> Result<bool> {
    let tmp = n.tmp_dir.clone().unwrap_or_else(|| PathBuf::from("/run"));
    let v = signed::SshVerifier::installed(&n.root, tmp);
    sync_with(ctx, n, coordinator, store, v.has_key().then_some(&v as &dyn Verifier))
}

/// sync with the signature checker given (None: this server has no signing
/// key).
pub fn sync_with(ctx: &Ctx, n: &Node, coordinator: bool, store: &Store, v: Option<&dyn Verifier>) -> Result<bool> {
    if !coordinator && quarantine::load(n)?.coordinator_cut() {
        return Ok(false);
    }
    let sw = port_link(&n.switch_mac());
    let mut me = SelfInfo { host: 0, switch: sw };
    let members = if coordinator {
        me.host = 1;
        store.update(|s| {
            s.heartbeat(1, &n.cfg.coord_lan_ip, sw, Time::now())?;
            Ok(s.members.clone())
        })?
    } else {
        me.host = n.load_state().host;
        if me.host == 0 {
            return Err("not joined yet".into());
        }
        let lan = local_ip(ctx, n.run.as_ref(), &n.cfg.coord_lan_ip).unwrap_or_default();
        let (members, env) = n.fetch_members(ctx, &Heartbeat { lan_ip: lan, switch: sw })?;
        n.note_signed(&n.check_signed(&members, &env, v));
        members
    };
    // The switch pings take up to a second each: before the lock, so a cut
    // never waits for them.
    let members = n.check_switch(ctx, me, &members);
    // Check again under the lock: a cut may have landed while fetching.
    let _lock = fsx::lock(n.path(quarantine::MESH_LOCK))?;
    let q = quarantine::load(n)?;
    if !coordinator && q.coordinator_cut() {
        return Ok(false);
    }
    let members: Vec<Member> = members.into_iter().filter(|m| m.host == me.host || !q.blocks(m)).collect();
    n.apply(me, &members)?;
    n.reload_wg(ctx)?;
    Ok(true)
}

// ---- network info ----

struct Port {
    name: String,
    mac: String,
}

/// Physical Ethernet ports. Virtual links (Docker, WireGuard, bridges) and
/// WiFi are left out.
fn wired_ports() -> Vec<Port> {
    let mut out = Vec::new();
    let Ok(ents) = std::fs::read_dir("/sys/class/net") else {
        return out;
    };
    let mut names: Vec<String> = ents.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    for name in names {
        let dir = Path::new("/sys/class/net").join(&name);
        if !dir.join("device").exists() || dir.join("wireless").exists() {
            continue;
        }
        let mac = fsx::read_or_empty(dir.join("address")).trim().to_string();
        out.push(Port { name, mac });
    }
    out
}

/// Picks the Ethernet port for the switch and returns its MAC: with several
/// ports, one that does not carry the default route (that one leads to the
/// router). Empty when there is no Ethernet port.
pub fn switch_port(ctx: &Ctx, run: &dyn Runner) -> String {
    let ports = wired_ports();
    if ports.is_empty() {
        return String::new();
    }
    #[derive(Deserialize)]
    struct Route {
        #[serde(default)]
        dev: String,
    }
    let (out, _) = run.run(ctx, &Cmd::new("ip", &["-j", "route", "show", "default"]).quiet());
    let routes: Vec<Route> = serde_json::from_str(&out).unwrap_or_default();
    for p in &ports {
        if !routes.iter().any(|r| r.dev == p.name) {
            return p.mac.clone();
        }
    }
    ports[0].mac.clone()
}

/// Whether the port with this MAC has a cable link.
pub fn port_link(mac: &str) -> bool {
    if mac.is_empty() {
        return false;
    }
    for p in wired_ports() {
        if p.mac == mac {
            return fsx::read_or_empty(Path::new("/sys/class/net").join(&p.name).join("carrier")).trim() == "1";
        }
    }
    false
}

/// This machine's address on the route towards dst, e.g. its LAN IP when
/// dst is the coordinator.
pub fn local_ip(ctx: &Ctx, run: &dyn Runner, dst: &str) -> Result<String> {
    let out = run.output(ctx, &Cmd::new("ip", &["-j", "route", "get", dst]).quiet())?;
    #[derive(Deserialize)]
    struct Route {
        #[serde(default)]
        prefsrc: String,
    }
    match serde_json::from_str::<Vec<Route>>(&out) {
        Ok(r) if !r.is_empty() && !r[0].prefsrc.is_empty() => Ok(r[0].prefsrc.clone()),
        _ => Err(errf!("no route to {dst}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packages;
    use crate::testutil::{TempDir, get, put};
    use std::sync::Mutex;

    const COORD_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIcoord";
    const NODE_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInode root@node-a";
    const WG_PUBKEY: &str = "bm9kZS1hLXB1YmxpYy1rZXktMzItYnl0ZXMtbG9uZyE=";
    const COORD_WG: &str = "Y29vcmQtcHVibGljLWtleS0zMi1ieXRlcy1sb25nISE=";

    /// Answers registry commands like the coordinator would, and records the
    /// host key the way ssh accept-new does.
    struct FakeCoord {
        root: PathBuf,
        statuses: Mutex<Vec<StatusReply>>,
        calls: Mutex<Vec<String>>,
        last: Mutex<Option<Cmd>>,
        applied: Mutex<String>,
        /// The "peers" reply to send instead of the normal two members.
        peers: Mutex<Option<String>>,
    }

    impl FakeCoord {
        fn new(root: &Path, statuses: Vec<StatusReply>) -> Arc<FakeCoord> {
            Arc::new(FakeCoord {
                root: root.to_path_buf(),
                statuses: Mutex::new(statuses),
                calls: Mutex::new(Vec::new()),
                last: Mutex::new(None),
                applied: Mutex::new(String::new()),
                peers: Mutex::new(None),
            })
        }
    }

    impl Runner for FakeCoord {
        fn run(&self, _ctx: &Ctx, c: &Cmd) -> (String, Result<()>) {
            *self.last.lock().unwrap() = Some(c.clone());
            // Sync helpers: systemctl, ping, ip, wg-quick and wg.
            match c.name.as_str() {
                "systemctl" | "ping" | "ip" | "agetty" | "networkctl" => return (String::new(), Ok(())),
                "wg-quick" => return ("[Interface]\nListenPort = 51820\n".into(), Ok(())),
                "wg" => {
                    *self.applied.lock().unwrap() = std::fs::read_to_string(&c.args[2]).unwrap_or_default();
                    return (String::new(), Ok(()));
                }
                _ => {}
            }
            let cmd = c.args[c.args.len() - 1].clone();
            let host = c.args[c.args.len() - 2].clone();
            self.calls.lock().unwrap().push(format!("{host} {cmd}"));
            let kh = fsx::under(&self.root, KNOWN_HOSTS);
            if !kh.exists() {
                std::fs::write(&kh, format!("{} {COORD_KEY}\n", host.trim_start_matches("dryreg@"))).unwrap();
            }
            if cmd == "request" {
                return match serde_json::from_str::<registry::Request>(&c.stdin) {
                    Ok(r) if r.name == "node-a" => (r#"{"id":"0123456789abcdef"}"#.into(), Ok(())),
                    _ => (String::new(), Err("bad request".into())),
                };
            }
            if cmd.starts_with("status ") {
                let mut st = self.statuses.lock().unwrap();
                let r = st[0].clone();
                if st.len() > 1 {
                    st.remove(0);
                }
                return (serde_json::to_string(&r).unwrap(), Ok(()));
            }
            if cmd == "peers" {
                let fixed = self.peers.lock().unwrap().clone();
                let list = fixed.unwrap_or_else(|| {
                    format!(
                        r#"{{"members":[{{"host":1,"name":"coord","wg_key":"{COORD_WG}","lan_ip":"192.168.1.50"}},{{"host":2,"name":"node-a","wg_key":"{WG_PUBKEY}"}}]}}"#
                    )
                });
                return (list, Ok(()));
            }
            (String::new(), Err("unknown".into()))
        }
    }

    fn setup(statuses: Vec<StatusReply>) -> (TempDir, Node, Arc<FakeCoord>) {
        let dir = TempDir::new();
        let root = dir.path();
        put(root, WG_PUB, format!("{WG_PUBKEY}\n"));
        put(root, HOST_KEY_PUB, format!("{NODE_KEY}\n"));
        put(root, "/etc/hosts", "127.0.0.1 localhost\n");
        std::fs::create_dir_all(fsx::under(root, "/etc/dryserver")).unwrap();
        let cfg =
            Config { coord_lan_ip: "192.168.1.50".into(), admin_ssh_pubkey: "ssh-ed25519 AAAA me@desktop".into(), ..Config::default() };
        let fc = FakeCoord::new(root, statuses);
        let n = Node { cfg, hostname: "node-a".into(), root: root.to_path_buf(), run: fc.clone(), tmp_dir: None };
        (dir, n, fc)
    }

    #[test]
    fn join_flow() {
        let coord = Member {
            host: 1,
            name: "coord".into(),
            wg_key: COORD_WG.into(),
            lan_ip: "192.168.1.50".into(),
            switch: true,
            ssh_host_key: COORD_KEY.into(),
            ..Member::default()
        };
        let (_dir, n, fc) = setup(vec![
            StatusReply { status: Status::Pending, ..StatusReply::default() },
            StatusReply { status: Status::Approved, host: 4, coordinator: Some(coord) },
        ]);
        let ctx = Ctx::new();
        let code = n.request(&ctx, "192.168.1.23", true).unwrap();
        assert_eq!(code, registry::pairing_code(WG_PUBKEY, NODE_KEY, COORD_KEY), "code must match the coordinator's");
        assert_eq!(n.load_state().request_id, "0123456789abcdef");

        let r = n.wait(&ctx, Duration::from_millis(1)).unwrap();
        assert_eq!(r.host, 4);
        let plan = packages::resolve(&[], &[]).unwrap();
        let params = Params {
            config: n.cfg.clone(),
            plan,
            hostname: "node-a".into(),
            role: sysconf::Role::Node,
            switch_mac: "52:54:66:00:00:04".into(),
            ..Params::default()
        };
        n.activate(&r, SelfInfo { host: 0, switch: true }, &params).unwrap();
        let wg = get(&n.root, WG_CONF);
        assert!(wg.contains("Address = 10.66.0.4/24") && wg.contains("Endpoint = 172.16.66.1:51820"), "wg0.conf:\n{wg}");
        assert!(get(&n.root, "/etc/systemd/network/10-switch.network").contains("Address=172.16.66.4/24"));
        assert!(get(&n.root, KNOWN_HOSTS).contains("192.168.1.50,10.66.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIcoord"));
        assert!(get(&n.root, "/etc/hosts").contains("10.66.0.1 coord") && n.load_state().host == 4, "hosts/state not updated");

        let (members, signed) = n.fetch_members(&ctx, &Heartbeat { lan_ip: "192.168.1.23".into(), switch: false }).unwrap();
        assert_eq!(members.len(), 2);
        assert!(signed.is_empty(), "an older coordinator sends no signed list");
        assert_eq!(fc.calls.lock().unwrap().last().unwrap(), "dryreg@10.66.0.1 peers", "sync must go over the mesh");
    }

    #[test]
    fn rejected() {
        let (_dir, n, _) = setup(vec![StatusReply { status: Status::Rejected, ..StatusReply::default() }]);
        let ctx = Ctx::new();
        n.request(&ctx, "192.168.1.23", false).unwrap();
        assert!(n.wait(&ctx, Duration::from_millis(1)).unwrap_err().is(Kind::Rejected));
    }

    #[test]
    fn expired_request_detected_from_error() {
        struct Gone;
        impl Runner for Gone {
            fn run(&self, _: &Ctx, _: &Cmd) -> (String, Result<()>) {
                (String::new(), Err("ssh failed: exit status 1: dryserver: no such request (expired?)".into()))
            }
        }
        let (_dir, mut n, _) = setup(vec![]);
        n.save_state(&State { request_id: "0123456789abcdef".into(), ..State::default() }).unwrap();
        n.run = Arc::new(Gone);
        assert!(n.wait(&Ctx::new(), Duration::from_millis(1)).unwrap_err().is(Kind::Expired));
    }

    #[test]
    fn ssh_args() {
        let (_dir, n, fc) = setup(vec![StatusReply { status: Status::Pending, ..StatusReply::default() }]);
        n.request(&Ctx::new(), "192.168.1.23", false).unwrap();
        let args = fc.last.lock().unwrap().clone().unwrap().args.join(" ");
        for want in [
            "BatchMode=yes",
            "StrictHostKeyChecking=accept-new",
            "HostKeyAlgorithms=ssh-ed25519",
            "GlobalKnownHostsFile=/dev/null",
            "LogLevel=ERROR",
            "dryreg@192.168.1.50 request",
        ] {
            assert!(args.contains(want), "ssh args missing {want:?}: {args}");
        }
    }

    #[test]
    fn private_key_added_once() {
        let got = with_private_key("[Interface]\nListenPort = 51820\n\n[Peer]\nPublicKey = X\n", "SECRET=\n");
        assert!(got.starts_with("[Interface]\nPrivateKey = SECRET=\nListenPort = 51820\n"), "{got:?}");
        assert_eq!(got.matches("PrivateKey").count(), 1);
    }

    #[test]
    fn sync_respects_quarantine() {
        let (_dir, mut n, _) = setup(vec![]);
        n.save_state(&State { host: 2, ..State::default() }).unwrap();
        put(&n.root, WG_KEY, "PRIVKEY=\n");
        put(&n.root, KNOWN_HOSTS, format!("192.168.1.50,10.66.0.1 {COORD_KEY}\n"));
        let tmp = TempDir::new();
        n.tmp_dir = Some(tmp.path().to_path_buf());
        let fc = FakeCoord::new(&n.root, vec![]);
        n.run = fc.clone();
        let store = Store::new("/nonexistent");

        // Coordinator cut: no contact at all, nothing rewritten.
        put(&n.root, quarantine::STATE_FILE, format!(r#"{{"cuts":[{{"name":"coord","hosts":[1],"wg_keys":["{COORD_WG}"]}}]}}"#));
        put(&n.root, WG_CONF, "untouched\n");
        assert!(!sync(&Ctx::new(), &n, false, &store).unwrap(), "sync must report paused");
        assert!(fc.calls.lock().unwrap().is_empty(), "sync talked to a cut coordinator");
        assert_eq!(get(&n.root, WG_CONF), "untouched\n");

        // A damaged quarantine file stops sync instead of guessing.
        put(&n.root, quarantine::STATE_FILE, "{oops");
        assert!(sync(&Ctx::new(), &n, false, &store).is_err());
        assert_eq!(get(&n.root, WG_CONF), "untouched\n");

        // Only a worker cut: sync runs and leaves it out, by key.
        put(&n.root, quarantine::STATE_FILE, format!(r#"{{"cuts":[{{"name":"node-x","hosts":[9],"wg_keys":["{COORD_WG}"]}}]}}"#));
        assert!(sync(&Ctx::new(), &n, false, &store).unwrap());
        let wg = get(&n.root, WG_CONF);
        assert!(wg.contains("[Interface]") && !wg.contains(COORD_WG), "a cut key came back:\n{wg}");
        // This server itself is never left out of its own files.
        assert!(get(&n.root, "/etc/hosts").contains("node-a"));
    }

    #[test]
    fn sync_checks_what_the_coordinator_sends() {
        let (_dir, mut n, _) = setup(vec![]);
        n.save_state(&State { host: 2, ..State::default() }).unwrap();
        put(&n.root, WG_KEY, "PRIVKEY=\n");
        put(&n.root, KNOWN_HOSTS, format!("192.168.1.50,10.66.0.1 {COORD_KEY}\n"));
        let tmp = TempDir::new();
        n.tmp_dir = Some(tmp.path().to_path_buf());
        let fc = FakeCoord::new(&n.root, vec![]);
        n.run = fc.clone();
        let store = Store::new("/nonexistent");
        let coord = format!(r#"{{"host":1,"name":"coord","wg_key":"{COORD_WG}","lan_ip":"192.168.1.50"}}"#);
        let me = format!(r#"{{"host":2,"name":"node-a","wg_key":"{WG_PUBKEY}"}}"#);
        let evil_key = "ZXZpbC0tcHVibGljLWtleS0zMi1ieXRlcy1sb25nISE=";

        // Hostile entries are left out; the good ones still apply.
        let hostile = [
            format!(r#"{{"host":5,"name":"x archlinux.org","wg_key":"{evil_key}"}}"#),
            format!(r#"{{"host":6,"name":"a\n10.66.0.6 pkg.example.org","wg_key":"{evil_key}"}}"#),
            r#"{"host":7,"name":"n7","wg_key":"AAAA\nEndpoint = 1.2.3.4:51820"}"#.to_string(),
            format!(r#"{{"host":8,"name":"n8","wg_key":"{evil_key}","lan_ip":"1.2.3.4 archlinux.org"}}"#),
            format!(r#"{{"host":9,"name":"n9","wg_key":"{evil_key}","ssh_host_key":"ssh-ed25519 AAAA x\n* ssh-ed25519 BBBB"}}"#),
            format!(r#"{{"host":1,"name":"coord2","wg_key":"{evil_key}"}}"#),
            format!(r#"{{"host":999,"name":"far","wg_key":"{evil_key}"}}"#),
        ];
        *fc.peers.lock().unwrap() = Some(format!(r#"{{"members":[{coord},{me},{}]}}"#, hostile.join(",")));
        assert!(sync(&Ctx::new(), &n, false, &store).unwrap());
        let (hosts, wg) = (get(&n.root, "/etc/hosts"), get(&n.root, WG_CONF));
        let kh = get(&n.root, "/etc/ssh/ssh_known_hosts");
        for bad in ["archlinux.org", "pkg.example.org", "1.2.3.4", evil_key, "coord2", "BBBB", "10.66.0.6"] {
            assert!(!hosts.contains(bad) && !wg.contains(bad) && !kh.contains(bad), "{bad:?} reached a system file:\n{hosts}\n{wg}\n{kh}");
        }
        assert!(hosts.contains("10.66.0.1 coord\n") && wg.contains(COORD_WG));

        // A list without a usable coordinator changes nothing: applying it
        // would remove the peer this server needs to ever sync again.
        *fc.peers.lock().unwrap() = Some(format!(r#"{{"members":[{{"host":1,"name":"bad name","wg_key":"{COORD_WG}"}},{me}]}}"#));
        let e = sync(&Ctx::new(), &n, false, &store).unwrap_err().to_string();
        assert!(e.contains("keeping the current mesh"), "{e}");
        assert_eq!(get(&n.root, WG_CONF), wg, "wg0.conf changed although the list was refused");
    }

    #[test]
    fn signed_list_is_checked_and_reported() {
        use crate::signed::{Entry, List, fake::Key, seal};
        let (_dir, mut n, _) = setup(vec![]);
        n.save_state(&State { host: 2, ..State::default() }).unwrap();
        put(&n.root, WG_KEY, "PRIVKEY=\n");
        put(&n.root, KNOWN_HOSTS, format!("192.168.1.50,10.66.0.1 {COORD_KEY}\n"));
        let tmp = TempDir::new();
        n.tmp_dir = Some(tmp.path().to_path_buf());
        let fc = FakeCoord::new(&n.root, vec![]);
        n.run = fc.clone();
        let store = Store::new("/nonexistent");
        let admin = Key("admin");
        let coord = Entry { host: 1, name: "coord".into(), wg_key: COORD_WG.into(), ssh_host_key: String::new() };
        let me = Entry { host: 2, name: "node-a".into(), wg_key: WG_PUBKEY.into(), ssh_host_key: String::new() };
        let members = format!(
            r#"{{"host":1,"name":"coord","wg_key":"{COORD_WG}","lan_ip":"192.168.1.50"}},{{"host":2,"name":"node-a","wg_key":"{WG_PUBKEY}"}}"#
        );
        let reply =
            |extra: &str, env: &Envelope| format!(r#"{{"members":[{members}{extra}],"signed":{}}}"#, serde_json::to_string(env).unwrap());
        let status = |n: &Node| get(&n.root, SIGNED_STATUS);
        let run = |n: &Node, text: String, v: Option<&dyn Verifier>| {
            *fc.peers.lock().unwrap() = Some(text);
            // Warn only: sync always succeeds and applies the list.
            assert!(sync_with(&Ctx::new(), n, false, &store, v).unwrap());
            status(n)
        };

        // No signing key on this server, then nothing signed yet.
        assert!(run(&n, reply("", &Envelope::default()), None).starts_with("not checked"));
        assert!(run(&n, reply("", &Envelope::default()), Some(&admin)).starts_with("NOT SIGNED"));

        // A valid list that matches.
        let v5 = seal(&admin, &List { version: 5, members: vec![coord.clone(), me.clone()], rejected: vec![] }).unwrap();
        assert_eq!(run(&n, reply("", &v5), Some(&admin)), "ok: member list matches signed version 5 (2 members)\n");
        assert!(get(&n.root, SIGNED_FILE).contains("version"), "the verified list must be remembered");

        // The coordinator adds a machine the admin never signed.
        let evil = "ZXZpbC0tcHVibGljLWtleS0zMi1ieXRlcy1sb25nISE=";
        let s = run(&n, reply(&format!(r#",{{"host":3,"name":"rogue","wg_key":"{evil}"}}"#), &v5), Some(&admin));
        assert!(s.starts_with("MISMATCH") && s.contains("not signed by you: rogue"), "{s}");
        assert!(get(&n.root, WG_CONF).contains(evil), "this slice only warns; the mesh still follows the coordinator");

        // A signed member whose key the coordinator swapped.
        *fc.peers.lock().unwrap() = None;
        let swapped = format!(
            r#"{{"members":[{{"host":1,"name":"coord","wg_key":"{evil}"}},{{"host":2,"name":"node-a","wg_key":"{WG_PUBKEY}"}}],"signed":{}}}"#,
            serde_json::to_string(&v5).unwrap()
        );
        let s = run(&n, swapped, Some(&admin));
        assert!(s.contains("not signed by you: coord") && s.contains("signed but not sent: coord"), "{s}");

        // Forged, or signed by another key.
        let forged = Envelope { doc: v5.doc.replace("node-a", "node-x"), sig: v5.sig.clone() };
        assert!(run(&n, reply("", &forged), Some(&admin)).starts_with("NOT VALID"));
        let other = seal(&Key("thief"), &List { version: 9, members: vec![coord.clone(), me.clone()], rejected: vec![] }).unwrap();
        assert!(run(&n, reply("", &other), Some(&admin)).starts_with("NOT VALID"));
        assert!(get(&n.root, SIGNED_FILE).contains(&v5.sig), "an invalid list must not replace the remembered one");

        // An older list (rollback), and a different list under the same version.
        let v4 = seal(&admin, &List { version: 4, members: vec![coord.clone(), me.clone()], rejected: vec![] }).unwrap();
        let s = run(&n, reply("", &v4), Some(&admin));
        assert!(s.starts_with("ROLLBACK") && s.contains("version 4") && s.contains("seen version 5"), "{s}");
        let v5b = seal(&admin, &List { version: 5, members: vec![coord.clone(), me.clone()], rejected: vec!["x".into()] }).unwrap();
        assert!(run(&n, reply("", &v5b), Some(&admin)).starts_with("CONFLICT"));

        // A newer list replaces the remembered one.
        let v6 = seal(&admin, &List { version: 6, members: vec![coord, me], rejected: vec![] }).unwrap();
        assert!(run(&n, reply("", &v6), Some(&admin)).starts_with("ok: member list matches signed version 6"));
        assert!(get(&n.root, SIGNED_FILE).contains(&v6.sig));
    }

    #[test]
    fn invalid_approval_is_refused() {
        let coord = |wg: &str, name: &str| Member {
            host: 1,
            name: name.into(),
            wg_key: wg.into(),
            ssh_host_key: COORD_KEY.into(),
            lan_ip: "192.168.1.50".into(),
            ..Member::default()
        };
        for (reply, why) in [
            (StatusReply { status: Status::Approved, host: 4, coordinator: Some(coord("short", "coord")) }, "bad key"),
            (StatusReply { status: Status::Approved, host: 4, coordinator: Some(coord(COORD_WG, "c d")) }, "bad name"),
            (
                StatusReply { status: Status::Approved, host: 4, coordinator: Some(Member { host: 3, ..coord(COORD_WG, "coord") }) },
                "not host 1",
            ),
            (StatusReply { status: Status::Approved, host: 9999, coordinator: Some(coord(COORD_WG, "coord")) }, "host outside the mesh"),
            (StatusReply { status: Status::Approved, host: 4, coordinator: None }, "no coordinator"),
        ] {
            let (_dir, n, _) = setup(vec![reply]);
            n.request(&Ctx::new(), "192.168.1.23", false).unwrap();
            let e = n.wait(&Ctx::new(), Duration::from_millis(1)).unwrap_err().to_string();
            assert!(e.contains("invalid approval"), "{why}: {e}");
        }
    }

    #[test]
    fn join_stops_when_quarantined() {
        let (_dir, n, fc) = setup(vec![StatusReply { status: Status::Pending, ..StatusReply::default() }]);
        put(&n.root, quarantine::STATE_FILE, r#"{"cuts":[{"hosts":[1]}]}"#);
        let plan = packages::resolve(&[], &[]).unwrap();
        let params = Params { config: n.cfg.clone(), plan, hostname: "node-a".into(), ..Params::default() };
        join_loop(&Ctx::new(), &n, &params, &mut Vec::new()).unwrap();
        assert!(fc.calls.lock().unwrap().is_empty(), "join asked a cut coordinator");
        assert!(get(&n.root, ISSUE_FILE).contains("quarantined"));
    }

    #[test]
    fn sync_keeps_private_key() {
        let (_dir, mut n, _) = setup(vec![]);
        n.save_state(&State { host: 2, ..State::default() }).unwrap();
        put(&n.root, WG_KEY, "PRIVKEY=\n");
        put(&n.root, KNOWN_HOSTS, format!("192.168.1.50,10.66.0.1 {COORD_KEY}\n"));
        let tmp = TempDir::new();
        n.tmp_dir = Some(tmp.path().to_path_buf());
        let fc = FakeCoord::new(&n.root, vec![]);
        n.run = fc.clone();
        assert!(sync(&Ctx::new(), &n, false, &Store::new("/nonexistent")).unwrap());
        let applied = fc.applied.lock().unwrap().clone();
        assert!(applied.contains("PrivateKey = PRIVKEY="), "syncconf input lost the private key:\n{applied}");
        assert!(!get(&n.root, WG_CONF).contains("PRIVKEY"), "wg0.conf must not hold the private key");
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0, "temporary key file left behind");
    }
}
