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
/// Proof from the installer that this machine was installed from the
/// admin's USB stick; sent with every join request.
pub const JOIN_PROOF: &str = "/etc/dryserver/join.proof";
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

/// What a coordinator shows on its console until the admin signed it.
pub fn coordinator_issue(code: &str) -> String {
    format!(
        "\ndryserver: this coordinator is not signed yet, no machine can join.\n\
         On your own computer run: ./dryserver approve   and press S.\n\
         Sign only if it shows this code:  {code}\n\n"
    )
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
    /// Checks the admin's signature on member lists.
    pub verifier: Arc<dyn Verifier>,
}

/// What a node reports on each sync.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Heartbeat {
    pub lan_ip: String,
    pub switch: bool,
    /// Members this node has cut off, for the admin's screen.
    pub cuts: Vec<registry::CutReport>,
}

impl Node {
    /// A node rooted at root that checks signatures with the signing key
    /// the installer put there.
    pub fn new(cfg: Config, hostname: &str, root: &Path, run: Arc<dyn Runner>) -> Node {
        let tmp = if root == Path::new("/") { PathBuf::from("/run") } else { std::env::temp_dir() };
        Node {
            cfg,
            hostname: hostname.into(),
            root: root.to_path_buf(),
            run,
            tmp_dir: None,
            verifier: Arc::new(signed::SshVerifier::installed(root, tmp)),
        }
    }

    pub fn path(&self, p: &str) -> PathBuf {
        fsx::under(&self.root, p)
    }

    fn fits(&self, host: u32) -> bool {
        !mesh::ip(&self.cfg.wg_subnet, host).is_empty()
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

    /// Asks the coordinator at its LAN address for the signed member list
    /// without checking its SSH host key. Safe only because the caller
    /// verifies the admin's signature on what comes back: whoever answers
    /// can send an old list or none, but not a forged one.
    pub fn fetch_signed_unpinned(&self, ctx: &Ctx) -> Result<Envelope> {
        let key = self.path(REGISTRY_KEY).display().to_string();
        let target = format!("{}@{}", sysconf::REGISTRY_USER, self.cfg.coord_lan_ip);
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
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            &target,
            "signed",
        ];
        let out = self.run.output(ctx, &Cmd::new("ssh", &args).stdout_only())?;
        #[derive(Deserialize)]
        struct Reply {
            #[serde(default)]
            signed: Envelope,
        }
        Ok(serde_json::from_str::<Reply>(&out).map_err(|e| Error::from(e).wrap("the coordinator's answer"))?.signed)
    }

    /// The host key pinned for the coordinator.
    pub fn coordinator_key(&self) -> Result<String> {
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
            proof: self.read(JOIN_PROOF).unwrap_or_default(),
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
                                if !coord_ok || r.host < 2 || !self.fits(r.host) {
                                    return Err("coordinator sent an incomplete or invalid approval".into());
                                }
                                self.check_approval(&r)?;
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

    /// An approval counts only with a member list signed by the admin
    /// that holds this machine under its own name and keys, and the
    /// coordinator this machine has been talking to. The coordinator's word
    /// alone lets nobody in.
    fn check_approval(&self, r: &StatusReply) -> Result<()> {
        let list = r
            .signed
            .list(self.verifier.as_ref(), |h| self.fits(h))
            .map_err(|e| e.wrap("the approval has no valid member list signed by the admin"))?;
        let me = Member {
            host: r.host,
            name: self.hostname.clone(),
            wg_key: self.read(WG_PUB)?,
            ssh_host_key: self.read(HOST_KEY_PUB)?,
            ..Member::default()
        };
        if !list.has(&me) {
            return Err("the signed member list does not hold this machine with its name and keys".into());
        }
        let coord = r.coordinator.as_ref().ok_or_else(|| Error::new("coordinator sent an incomplete or invalid approval"))?;
        let Some(signed_coord) = list.members.iter().find(|e| e.host == 1) else {
            return Err("the signed member list has no coordinator".into());
        };
        if !signed_coord.matches(coord) {
            return Err("the coordinator's keys in the approval are not the ones the admin signed".into());
        }
        if signed::key_body(&signed_coord.ssh_host_key) != self.coordinator_key()? {
            return Err("the coordinator this machine talks to is not the one the admin signed".into());
        }
        Ok(())
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
        // The list that let this machine in is the first one it has seen.
        self.write(SIGNED_FILE, 0o600, &(serde_json::to_string(&r.signed)? + "\n"))?;
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
        Ok((members, signed))
    }

    /// Version of the newest signed list this server has verified, 0 if
    /// none.
    pub fn seen_version(&self) -> u64 {
        std::fs::read(self.path(SIGNED_FILE))
            .ok()
            .and_then(|b| serde_json::from_slice::<Envelope>(&b).ok())
            .and_then(|e| serde_json::from_str::<signed::List>(&e.doc).ok())
            .map(|l| l.version)
            .unwrap_or(0)
    }

    /// The members this server uses: exactly the list the admin signed.
    /// What the coordinator says about them is taken only for addresses
    /// (LAN address, switch link); machines it lists without a signature
    /// are left out and named in the returned status line.
    ///
    /// Refused, leaving the mesh as it is: no list, a bad signature, a
    /// version older than one this server has seen (an old list would
    /// bring a removed machine back), another list under the same version,
    /// or a list without this server.
    pub fn signed_members(&self, me: u32, sent: &[Member], env: &Envelope) -> Result<(Vec<Member>, String)> {
        if env.is_empty() {
            return Err("the coordinator sent no signed member list".into());
        }
        let list = env.list(self.verifier.as_ref(), |h| self.fits(h))?;
        // The stored list was verified when it was saved; root owns it.
        let seen: Option<(u64, Envelope)> = std::fs::read(self.path(SIGNED_FILE)).ok().and_then(|b| {
            let e: Envelope = serde_json::from_slice(&b).ok()?;
            let l: signed::List = serde_json::from_str(&e.doc).ok()?;
            Some((l.version, e))
        });
        match &seen {
            Some((ver, _)) if list.version < *ver => {
                return Err(errf!(
                    "the coordinator sent signed list version {}, older than version {ver} this server has seen",
                    list.version
                ));
            }
            Some((ver, old)) if list.version == *ver && old.doc != env.doc => {
                return Err(errf!("the coordinator sent a different signed list under the same version {ver}"));
            }
            _ => {}
        }
        if !list.members.iter().any(|e| e.host == me) {
            return Err("this server is not in the signed member list (was it removed?)".into());
        }
        if !seen.as_ref().is_some_and(|(ver, _)| *ver == list.version) {
            self.write(SIGNED_FILE, 0o600, &(serde_json::to_string(env)? + "\n"))?;
        }
        let members: Vec<Member> = list
            .members
            .iter()
            .map(|e| match sent.iter().find(|m| e.matches(m)) {
                Some(m) => m.clone(),
                // Signed but not sent (or sent with other keys): still a
                // member, reached when it calls in.
                None => Member {
                    host: e.host,
                    name: e.name.clone(),
                    wg_key: e.wg_key.clone(),
                    ssh_host_key: e.ssh_host_key.clone(),
                    ..Member::default()
                },
            })
            .collect();
        let extra: Vec<&str> = sent.iter().filter(|m| !list.has(m)).map(|m| m.name.as_str()).collect();
        let status = if extra.is_empty() {
            format!("ok: signed version {}, {} members", list.version, members.len())
        } else {
            format!(
                "ok: signed version {}, {} members; IGNORED, not signed by the admin: {}",
                list.version,
                members.len(),
                extra.join(", ")
            )
        };
        Ok((members, status))
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
            "dryserver: waiting for approval. On your own computer run: ./dryserver approve\n\
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
/// the mesh and use only what the admin signed; the coordinator reads its
/// own registry, which changes only through signed lists. Members cut off
/// by `dryserver quarantine` are left out, and with the coordinator cut a
/// node does not sync at all: false means paused.
pub fn sync(ctx: &Ctx, n: &Node, coordinator: bool, store: &Store) -> Result<bool> {
    // First: a member the firewall blocked for trying closed ports is cut
    // off for good, until the admin lifts it.
    if let Err(e) = quarantine::auto_cut(ctx, n, coordinator) {
        eprintln!("dryserver: automatic cut: {e}");
    }
    let q = quarantine::load(n)?;
    if !coordinator && q.coordinator_cut() {
        return Ok(false);
    }
    let cuts = q.reports();
    let sw = port_link(&n.switch_mac());
    let mut me = SelfInfo { host: 0, switch: sw };
    let members = if coordinator {
        me.host = 1;
        let (members, signed) = store.update(|s| {
            s.heartbeat(1, &n.cfg.coord_lan_ip, sw, &cuts, Time::now())?;
            Ok((s.members.clone(), s.signed_version > 0))
        })?;
        // Signed by the admin: the code on the console has done its job.
        if signed && n.path(ISSUE_FILE).exists() {
            let _ = std::fs::remove_file(n.path(ISSUE_FILE));
            let _ = n.cmd(ctx, "agetty", &["--reload"]);
        }
        members
    } else {
        me.host = n.load_state().host;
        if me.host == 0 {
            return Err("not joined yet".into());
        }
        let lan = local_ip(ctx, n.run.as_ref(), &n.cfg.coord_lan_ip).unwrap_or_default();
        let (sent, env) = n.fetch_members(ctx, &Heartbeat { lan_ip: lan, switch: sw, cuts })?;
        match n.signed_members(me.host, &sent, &env) {
            Ok((members, status)) => {
                n.note_signed(&status);
                members
            }
            Err(e) => {
                n.note_signed(&format!("REFUSED, mesh left as it is: {e}"));
                return Err(e.wrap("member list refused, mesh left as it is"));
            }
        }
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
    use crate::signed::fake::Key;
    use crate::signed::{Entry, List, seal};
    use crate::testutil::{TempDir, get, put};
    use std::sync::Mutex;

    const COORD_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIcoord";
    const NODE_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInode root@node-a";
    const WG_PUBKEY: &str = "bm9kZS1hLXB1YmxpYy1rZXktMzItYnl0ZXMtbG9uZyE=";
    const COORD_WG: &str = "Y29vcmQtcHVibGljLWtleS0zMi1ieXRlcy1sb25nISE=";
    const OTHER_WG: &str = "bm9kZS1jLXB1YmxpYy1rZXktMzItYnl0ZXMtbG9uZyE=";
    const EVIL_WG: &str = "ZXZpbC0tcHVibGljLWtleS0zMi1ieXRlcy1sb25nISE=";
    const ADMIN: Key = Key("admin");

    fn coord_entry() -> Entry {
        Entry { host: 1, name: "coord".into(), wg_key: COORD_WG.into(), ssh_host_key: COORD_KEY.into() }
    }

    /// This machine (node-a) as the admin signs it.
    fn node_entry(host: u32) -> Entry {
        Entry { host, name: "node-a".into(), wg_key: WG_PUBKEY.into(), ssh_host_key: signed::key_body(NODE_KEY) }
    }

    fn other_entry() -> Entry {
        Entry { host: 3, name: "node-c".into(), wg_key: OTHER_WG.into(), ssh_host_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInodec".into() }
    }

    fn sign(key: &Key, version: u64, members: Vec<Entry>) -> Envelope {
        seal(key, &List { version, members, rejected: vec![] }).unwrap()
    }

    fn coord_member() -> Member {
        Member {
            host: 1,
            name: "coord".into(),
            wg_key: COORD_WG.into(),
            lan_ip: "192.168.1.50".into(),
            switch: true,
            ssh_host_key: COORD_KEY.into(),
            ..Member::default()
        }
    }

    fn node_member(host: u32) -> Member {
        Member { host, name: "node-a".into(), wg_key: WG_PUBKEY.into(), ssh_host_key: NODE_KEY.into(), ..Member::default() }
    }

    /// A "peers" reply.
    fn peers(members: &[Member], env: &Envelope) -> String {
        serde_json::json!({ "members": members, "signed": env }).to_string()
    }

    /// Answers registry commands like the coordinator would, and records the
    /// host key the way ssh accept-new does.
    struct FakeCoord {
        root: PathBuf,
        statuses: Mutex<Vec<StatusReply>>,
        calls: Mutex<Vec<String>>,
        last: Mutex<Option<Cmd>>,
        applied: Mutex<String>,
        /// The "peers" reply; by default the coordinator and this node as
        /// host 2, signed as version 5.
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
                // No blocked members in the firewall's set.
                "nft" => return (String::new(), Err("no such set".into())),
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
                let reply =
                    fixed.unwrap_or_else(|| peers(&[coord_member(), node_member(2)], &sign(&ADMIN, 5, vec![coord_entry(), node_entry(2)])));
                return (reply, Ok(()));
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
        let n =
            Node { cfg, hostname: "node-a".into(), root: root.to_path_buf(), run: fc.clone(), tmp_dir: None, verifier: Arc::new(ADMIN) };
        (dir, n, fc)
    }

    /// A joined node (host 2) ready to sync, with the fake coordinator.
    fn joined() -> (TempDir, TempDir, Node, Arc<FakeCoord>) {
        let (dir, mut n, fc) = setup(vec![]);
        n.save_state(&State { host: 2, ..State::default() }).unwrap();
        put(&n.root, WG_KEY, "PRIVKEY=\n");
        put(&n.root, KNOWN_HOSTS, format!("192.168.1.50,10.66.0.1 {COORD_KEY}\n"));
        let tmp = TempDir::new();
        n.tmp_dir = Some(tmp.path().to_path_buf());
        (dir, tmp, n, fc)
    }

    fn approved(host: u32, signed: Envelope) -> StatusReply {
        StatusReply { status: Status::Approved, host, coordinator: Some(coord_member()), signed }
    }

    #[test]
    fn join_flow() {
        let env = sign(&ADMIN, 3, vec![coord_entry(), node_entry(4)]);
        let (_dir, n, fc) = setup(vec![StatusReply { status: Status::Pending, ..StatusReply::default() }, approved(4, env.clone())]);
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
        assert!(get(&n.root, SIGNED_FILE).contains(&env.sig), "the list that let this machine in must be remembered");

        let (members, signed) = n.fetch_members(&ctx, &Heartbeat { lan_ip: "192.168.1.23".into(), switch: false, cuts: vec![] }).unwrap();
        assert_eq!(members.len(), 2);
        assert!(!signed.is_empty());
        assert_eq!(fc.calls.lock().unwrap().last().unwrap(), "dryreg@10.66.0.1 peers", "sync must go over the mesh");
    }

    #[test]
    fn approval_needs_the_admins_signature() {
        let good = vec![coord_entry(), node_entry(4)];
        let cases: Vec<(StatusReply, &str)> = vec![
            // The coordinator alone says "approved".
            (approved(4, Envelope::default()), "no valid member list signed by the admin"),
            (approved(4, sign(&Key("thief"), 3, good.clone())), "no valid member list signed by the admin"),
            // Signed, but not for this machine as it is.
            (approved(4, sign(&ADMIN, 3, vec![coord_entry()])), "does not hold this machine"),
            (approved(5, sign(&ADMIN, 3, good.clone())), "does not hold this machine"),
            (
                approved(4, sign(&ADMIN, 3, vec![coord_entry(), Entry { wg_key: EVIL_WG.into(), ..node_entry(4) }])),
                "does not hold this machine",
            ),
            (
                approved(4, sign(&ADMIN, 3, vec![coord_entry(), Entry { name: "node-b".into(), ..node_entry(4) }])),
                "does not hold this machine",
            ),
            (
                approved(4, sign(&ADMIN, 3, vec![coord_entry(), Entry { ssh_host_key: "ssh-ed25519 AAAAother".into(), ..node_entry(4) }])),
                "does not hold this machine",
            ),
            // The coordinator in the reply is not the signed one.
            (
                StatusReply {
                    coordinator: Some(Member { wg_key: EVIL_WG.into(), ..coord_member() }),
                    ..approved(4, sign(&ADMIN, 3, good.clone()))
                },
                "not the ones the admin signed",
            ),
            // The signed coordinator is another machine than the one this
            // node has been talking to.
            (
                StatusReply {
                    coordinator: Some(Member { ssh_host_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIelse".into(), ..coord_member() }),
                    ..approved(
                        4,
                        sign(
                            &ADMIN,
                            3,
                            vec![
                                Entry { ssh_host_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIelse".into(), ..coord_entry() },
                                node_entry(4),
                            ],
                        ),
                    )
                },
                "is not the one the admin signed",
            ),
            // Malformed replies.
            (
                StatusReply {
                    coordinator: Some(Member { wg_key: "short".into(), ..coord_member() }),
                    ..approved(4, sign(&ADMIN, 3, good.clone()))
                },
                "invalid approval",
            ),
            (
                StatusReply {
                    coordinator: Some(Member { name: "c d".into(), ..coord_member() }),
                    ..approved(4, sign(&ADMIN, 3, good.clone()))
                },
                "invalid approval",
            ),
            (
                StatusReply { coordinator: Some(Member { host: 3, ..coord_member() }), ..approved(4, sign(&ADMIN, 3, good.clone())) },
                "invalid approval",
            ),
            (approved(9999, sign(&ADMIN, 3, good.clone())), "invalid approval"),
            (StatusReply { coordinator: None, ..approved(4, sign(&ADMIN, 3, good.clone())) }, "invalid approval"),
        ];
        for (reply, want) in cases {
            let (_dir, n, _) = setup(vec![reply.clone()]);
            n.request(&Ctx::new(), "192.168.1.23", false).unwrap();
            let e = n.wait(&Ctx::new(), Duration::from_millis(1)).unwrap_err().to_string();
            assert!(e.contains(want), "want {want:?}, got {e:?} for {reply:?}");
            assert!(get(&n.root, WG_CONF).is_empty(), "a refused approval must not write the mesh config");
        }
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
    fn sync_uses_only_the_signed_list() {
        let (_dir, _tmp, n, fc) = joined();
        let store = Store::new("/nonexistent");
        let ctx = Ctx::new();
        let v5 = sign(&ADMIN, 5, vec![coord_entry(), node_entry(2)]);
        let set = |text: String| *fc.peers.lock().unwrap() = Some(text);
        let status = |n: &Node| get(&n.root, SIGNED_STATUS);

        assert!(sync(&ctx, &n, false, &store).unwrap());
        assert_eq!(status(&n), "ok: signed version 5, 2 members\n");
        assert!(get(&n.root, SIGNED_FILE).contains(&v5.sig), "the verified list must be remembered");
        let good = get(&n.root, WG_CONF);
        assert!(good.contains(COORD_WG));

        // The coordinator adds a machine the admin never signed: left out.
        let rogue = Member { host: 9, name: "rogue".into(), wg_key: EVIL_WG.into(), lan_ip: "192.168.1.66".into(), ..Member::default() };
        set(peers(&[coord_member(), node_member(2), rogue], &v5));
        assert!(sync(&ctx, &n, false, &store).unwrap());
        assert!(status(&n).contains("IGNORED, not signed by the admin: rogue"), "{}", status(&n));
        for f in [WG_CONF, "/etc/hosts", "/etc/ssh/ssh_known_hosts"] {
            let text = get(&n.root, f);
            assert!(!text.contains(EVIL_WG) && !text.contains("rogue") && !text.contains("192.168.1.66"), "{f}:\n{text}");
        }

        // It swaps a signed member's key: the signed key stays in use.
        set(peers(&[Member { wg_key: EVIL_WG.into(), ..coord_member() }, node_member(2)], &v5));
        assert!(sync(&ctx, &n, false, &store).unwrap());
        let wg = get(&n.root, WG_CONF);
        assert!(wg.contains(COORD_WG) && !wg.contains(EVIL_WG), "{wg}");

        // It leaves a signed member out: still a peer, reached when it calls.
        let v6 = sign(&ADMIN, 6, vec![coord_entry(), node_entry(2), other_entry()]);
        set(peers(&[coord_member(), node_member(2)], &v6));
        assert!(sync(&ctx, &n, false, &store).unwrap());
        let wg = get(&n.root, WG_CONF);
        assert!(wg.contains(OTHER_WG) && get(&n.root, "/etc/hosts").contains("10.66.0.3 node-c"), "{wg}");
        assert!(get(&n.root, SIGNED_FILE).contains(&v6.sig), "a newer list replaces the remembered one");
        let kept = get(&n.root, WG_CONF);

        // Everything below is refused and leaves the mesh as it is.
        let refused: Vec<(String, &str)> = vec![
            (peers(&[coord_member(), node_member(2)], &Envelope::default()), "no signed member list"),
            (
                r#"{"members":[{"host":1,"name":"coord","wg_key":"Y29vcmQtcHVibGljLWtleS0zMi1ieXRlcy1sb25nISE="}]}"#.into(),
                "no signed member list",
            ),
            (peers(&[coord_member()], &Envelope { doc: v6.doc.replace("node-c", "node-x"), sig: v6.sig.clone() }), "bad signature"),
            (peers(&[coord_member()], &sign(&Key("thief"), 9, vec![coord_entry(), node_entry(2)])), "bad signature"),
            // An older list would bring a removed machine back.
            (peers(&[coord_member()], &v5), "older than version 6"),
            (
                peers(&[coord_member()], &sign(&ADMIN, 6, vec![coord_entry(), node_entry(2)])),
                "different signed list under the same version",
            ),
            // This server was removed.
            (peers(&[coord_member()], &sign(&ADMIN, 7, vec![coord_entry(), other_entry()])), "not in the signed member list"),
            (peers(&[coord_member()], &sign(&ADMIN, 7, vec![node_entry(2)])), "no coordinator"),
        ];
        for (reply, want) in refused {
            set(reply);
            let e = sync(&ctx, &n, false, &store).unwrap_err().to_string();
            assert!(e.contains(want) && e.contains("mesh left as it is"), "want {want:?}: {e}");
            assert_eq!(get(&n.root, WG_CONF), kept, "the mesh changed although the list was refused ({want})");
            assert!(status(&n).starts_with("REFUSED"), "{}", status(&n));
            assert!(get(&n.root, SIGNED_FILE).contains(&v6.sig), "a refused list replaced the remembered one ({want})");
        }

        // A server without the signing key trusts nothing.
        let mut blind = n.clone();
        blind.verifier = Arc::new(signed::SshVerifier::installed(&n.root, n.root.clone()));
        set(peers(&[coord_member(), node_member(2)], &sign(&ADMIN, 8, vec![coord_entry(), node_entry(2)])));
        assert!(sync(&ctx, &blind, false, &store).unwrap_err().to_string().contains("no signing key"));
    }

    #[test]
    fn hostile_addresses_never_reach_files() {
        let (_dir, _tmp, n, fc) = joined();
        let env = sign(&ADMIN, 5, vec![coord_entry(), node_entry(2), other_entry()]);
        // node-c is signed, but the coordinator sends junk for its address
        // and key comment, and a second entry for the coordinator.
        let reply = format!(
            r#"{{"members":[{},{},{{"host":3,"name":"node-c","wg_key":"{OTHER_WG}","ssh_host_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInodec","lan_ip":"1.2.3.4 archlinux.org"}},{{"host":1,"name":"coord2","wg_key":"{EVIL_WG}"}},{{"host":7,"name":"a\n10.66.0.7 pkg.example.org","wg_key":"{EVIL_WG}"}}],"signed":{}}}"#,
            serde_json::to_string(&coord_member()).unwrap(),
            serde_json::to_string(&node_member(2)).unwrap(),
            serde_json::to_string(&env).unwrap()
        );
        *fc.peers.lock().unwrap() = Some(reply);
        assert!(sync(&Ctx::new(), &n, false, &Store::new("/nonexistent")).unwrap());
        let (hosts, wg, kh) = (get(&n.root, "/etc/hosts"), get(&n.root, WG_CONF), get(&n.root, "/etc/ssh/ssh_known_hosts"));
        for bad in ["archlinux.org", "pkg.example.org", "1.2.3.4", EVIL_WG, "coord2", "10.66.0.7"] {
            assert!(!hosts.contains(bad) && !wg.contains(bad) && !kh.contains(bad), "{bad:?} reached a system file:\n{hosts}\n{wg}\n{kh}");
        }
        // node-c stays a member (it is signed), without the bad address.
        assert!(hosts.contains("10.66.0.3 node-c\n") && wg.contains(OTHER_WG) && kh.contains("node-c,10.66.0.3 ssh-ed25519"));
    }

    #[test]
    fn sync_respects_quarantine() {
        let (_dir, _tmp, n, fc) = joined();
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

        // Only another member cut: sync runs and leaves it out, also when
        // the admin's signed list still has it.
        put(&n.root, quarantine::STATE_FILE, format!(r#"{{"cuts":[{{"name":"node-c","hosts":[3],"wg_keys":["{OTHER_WG}"]}}]}}"#));
        let env = sign(&ADMIN, 5, vec![coord_entry(), node_entry(2), other_entry()]);
        *fc.peers.lock().unwrap() = Some(peers(&[coord_member(), node_member(2)], &env));
        assert!(sync(&Ctx::new(), &n, false, &store).unwrap());
        let wg = get(&n.root, WG_CONF);
        assert!(wg.contains(COORD_WG) && !wg.contains(OTHER_WG), "a cut member came back:\n{wg}");
        // This server itself is never left out of its own files.
        assert!(get(&n.root, "/etc/hosts").contains("node-a"));
    }

    #[test]
    fn coordinator_code_leaves_the_console_once_signed() {
        let (_dir, tmp, mut n, _) = joined();
        n.tmp_dir = Some(tmp.path().to_path_buf());
        let store_dir = TempDir::new();
        let store = Store::new(store_dir.join("registry.json"));
        store
            .update(|s| {
                s.members = vec![coord_member()];
                Ok(())
            })
            .unwrap();
        put(&n.root, ISSUE_FILE, coordinator_issue("123 456"));
        assert!(get(&n.root, ISSUE_FILE).contains("Sign only if it shows this code:  123 456"));
        sync(&Ctx::new(), &n, true, &store).unwrap();
        assert!(!get(&n.root, ISSUE_FILE).is_empty(), "the code must stay until a list is signed");
        store
            .update(|s| {
                s.signed_version = 9;
                Ok(())
            })
            .unwrap();
        sync(&Ctx::new(), &n, true, &store).unwrap();
        assert!(get(&n.root, ISSUE_FILE).is_empty(), "the code must go once the admin signed");
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
        let (_dir, tmp, n, fc) = joined();
        assert!(sync(&Ctx::new(), &n, false, &Store::new("/nonexistent")).unwrap());
        let applied = fc.applied.lock().unwrap().clone();
        assert!(applied.contains("PrivateKey = PRIVKEY="), "syncconf input lost the private key:\n{applied}");
        assert!(!get(&n.root, WG_CONF).contains("PRIVKEY"), "wg0.conf must not hold the private key");
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0, "temporary key file left behind");
    }
}
