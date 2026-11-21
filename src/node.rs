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
use crate::registry::{self, Heartbeat, Member, Status, StatusReply, Store};
use crate::report::{self, Report};
use crate::runner::{Cmd, Runner};
use crate::signed::{self, Envelope, Verifier};
use crate::sysconf::{self, Params};
use crate::{errf, fsx, quarantine, rollout};

// Files inside the server's root.
pub const REGISTRY_KEY: &str = "/etc/dryserver/registry_ed25519";
/// The pinned coordinator host key.
pub const KNOWN_HOSTS: &str = "/etc/dryserver/known_hosts";
pub const JOIN_STATE: &str = "/etc/dryserver/join.json";
/// Written by leave before anything else (when and why), removed by the
/// next approval. Only while it is there does a sync stop k3s again: a
/// join.json that is lost or damaged says nothing about the admin's
/// decision, and must never take a live server out of the cluster.
pub const LEFT: &str = "/etc/dryserver/left";
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
/// What a machine that is no member found left of k3s at the last sync;
/// a change is logged.
pub const K3S_LEFT_STATUS: &str = "/run/dryserver-k3s-left.status";
/// What held up this server's update at the last sync; a change is logged.
pub const UPDATE_STATUS: &str = "/run/dryserver-update.status";
/// How often a machine waiting for approval asks the coordinator. The
/// coordinator's firewall lets one address open 10 SSH connections a
/// minute; asking every 3 or 5 seconds ran into that after a few minutes.
pub const JOIN_POLL: Duration = Duration::from_secs(8);
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

/// What k3s keeps for the control plane; only the coordinator has it.
const K3S_SERVER_DIR: &str = "/var/lib/rancher/k3s/server";
/// Where k3s on the coordinator keeps the token agents join with.
pub const K3S_AGENT_TOKEN: &str = "/var/lib/rancher/k3s/server/agent-token";
/// The cgroups of what k3s runs: its own helpers (containerd and the
/// container shims) and every pod.
pub const K3S_CGROUPS: [&str; 2] = ["/sys/fs/cgroup/system.slice/k3s.service", "/sys/fs/cgroup/kubepods.slice"];
/// On the coordinator: which machine (by WireGuard key) holds each name in
/// the cluster. A machine installed again under an old name is another
/// machine; the cluster has to forget the old one first.
pub const K3S_NODES: &str = "/etc/dryserver/k3s-nodes.json";
/// Where pods have things mounted, their secrets among them.
const POD_MOUNTS: [&str; 3] = ["/var/lib/kubelet/pods/", "/run/k3s/", "/run/netns/cni-"];

/// What the coordinator answers to "peers".
#[derive(Debug, Clone, Default)]
pub struct Fetched {
    /// Checked entries; what the coordinator says, not what is signed.
    pub members: Vec<Member>,
    /// The signed list as sent (empty when the coordinator has none).
    pub signed: Envelope,
    /// The token for joining the k3s cluster; "" before k3s is up.
    pub k3s_token: String,
    /// The release the swarm moves to, and whether this machine may
    /// update now.
    pub release: rollout::Offer,
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

    /// The join state, for decisions that undo something: None when there
    /// is no file (not asked to join yet, or it was lost), an error when it
    /// cannot be read or parsed. load_state takes both for host 0, which is
    /// right for "may it sync", not for "did it leave".
    pub fn read_state(&self) -> Result<Option<State>> {
        match std::fs::read(self.path(JOIN_STATE)) {
            Ok(b) => serde_json::from_slice(&b).map(Some).map_err(|e| Error::from(e).wrap(format!("{JOIN_STATE} is damaged"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::from(e).wrap(format!("read {JOIN_STATE}"))),
        }
    }

    /// Whether leave's marker is there.
    fn has_left(&self) -> bool {
        std::fs::symlink_metadata(self.path(LEFT)).is_ok()
    }

    /// This machine is a member (approved, or in the admin's signed list):
    /// an earlier leave is over. A marker that stays stops nothing while
    /// join.json names a host, so a failure is only reported.
    fn clear_left(&self) {
        match std::fs::remove_file(self.path(LEFT)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => eprintln!("dryserver: cannot remove {LEFT}: {e}"),
            _ => {}
        }
    }

    pub fn save_state(&self, s: &State) -> Result<()> {
        let b = serde_json::to_string_pretty(s)?;
        self.write(JOIN_STATE, 0o600, &format!("{b}\n"))
    }

    /// Runs one registry command on the coordinator as the registry user.
    /// The coordinator's host key is pinned in KNOWN_HOSTS on first contact;
    /// the pairing code shows the admin which key the node saw.
    fn ssh(&self, ctx: &Ctx, addr: &str, command: &str, stdin: &str) -> (String, Result<()>) {
        self.run.run(ctx, &Cmd::new("ssh", &self.ssh_args(addr, command)).stdin(stdin).stdout_only())
    }

    /// The ssh arguments for one registry command at addr, with the pinned
    /// host key.
    pub fn ssh_args(&self, addr: &str, command: &str) -> Vec<String> {
        let key = self.path(REGISTRY_KEY).display().to_string();
        let kh = format!("UserKnownHostsFile={}", self.path(KNOWN_HOSTS).display());
        let target = format!("{}@{addr}", sysconf::REGISTRY_USER);
        [
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
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
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
        // A member again: an earlier leave is over. After the host number,
        // so that between the two finish_leave sees a member and stops
        // nothing.
        self.clear_left();
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

    /// What this machine reports about itself with the heartbeat.
    pub fn report(&self, ctx: &Ctx) -> Report {
        report::gather(ctx, self.run.as_ref(), &self.root, &self.cfg.wg_subnet)
    }

    /// The report with where this machine's update stands.
    pub fn full_report(&self, ctx: &Ctx, coordinator: bool) -> Report {
        let mut r = self.report(ctx);
        rollout::Machine::new(self, coordinator).describe(&mut r);
        r
    }

    /// Asks the coordinator for the member list over the mesh, reporting
    /// this node's current LAN IP, cable link and health. Also returns the
    /// signed list as the coordinator sent it (empty when it has none).
    pub fn fetch_members(&self, ctx: &Ctx, hb: &Heartbeat) -> Result<Fetched> {
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
            #[serde(default, deserialize_with = "crate::gotime::null_default")]
            k3s_token: String,
            // An older coordinator sends none; one this version cannot
            // read offers nothing.
            #[serde(default, deserialize_with = "report::lenient")]
            release: rollout::Offer,
        }
        let (members, signed, k3s_token, release) = match serde_json::from_str::<Reply>(&out) {
            Ok(r) if !r.members.is_empty() => (r.members, r.signed, r.k3s_token, r.release),
            _ => return Err("bad member list from coordinator".into()),
        };
        // Nothing from the coordinator is used unchecked.
        let (members, problems) = registry::check_members(members, |h| !mesh::ip(&self.cfg.wg_subnet, h).is_empty());
        for p in &problems {
            eprintln!("dryserver: sync: ignoring {p}");
        }
        Ok(Fetched { members, signed, k3s_token, release })
    }

    /// On a server: joins the k3s cluster once the coordinator handed out
    /// the token. Writes the token and the config for this machine's mesh
    /// address, and starts k3s (again, if either changed).
    ///
    /// The token comes from the coordinator unsigned. It can only make
    /// this machine's k3s agent talk to the coordinator's address over the
    /// mesh, which is where it talks anyway.
    pub fn k3s_join(&self, ctx: &Ctx, me: u32, token: &str) -> Result<()> {
        let token = token.trim();
        if token.is_empty() || me < 2 {
            return Ok(());
        }
        if token.len() > 512 || !token.starts_with("K10") || !token.chars().all(|c| c.is_ascii_alphanumeric() || c == ':') {
            return Err("the coordinator sent a cluster token that is not one; k3s left as it is".into());
        }
        if !token.contains("::node:") {
            // The control plane's own token opens more than a server needs.
            return Err("the coordinator sent a token that is not for agents; k3s left as it is".into());
        }
        // Sync runs, so the coordinator is not cut off (any more).
        let _ = std::fs::remove_file(self.path(sysconf::K3S_HOLD));
        let config = sysconf::k3s_agent_config(&mesh::ip(&self.cfg.wg_subnet, 1), &mesh::ip(&self.cfg.wg_subnet, me));
        let mut changed = false;
        // The token is the secret; the config only says where things are.
        for (path, mode, want) in [(sysconf::K3S_TOKEN, 0o600, format!("{token}\n")), (sysconf::K3S_CONFIG, 0o644, config)] {
            if fsx::read_or_empty(self.path(path)) != want {
                self.write(path, mode, &want)?;
                let _ = fsx::chmod(self.path(path), mode);
                changed = true;
            }
        }
        let running = self.cmd(ctx, "systemctl", &["is-active", "--quiet", "k3s.service"]).is_ok();
        if changed && running {
            self.cmd(ctx, "systemctl", &["restart", "--no-block", "k3s.service"])
        } else if !running {
            self.cmd(ctx, "systemctl", &["start", "--no-block", "k3s.service"])
        } else {
            Ok(())
        }
    }

    /// On the coordinator: puts the cluster's agent token where members
    /// get it, and takes out of the cluster what is no longer there: a
    /// machine that left the swarm, and the old machine behind a name that
    /// was installed again (the cluster would turn the new one away).
    pub fn k3s_share(&self, ctx: &Ctx, store: &Store, members: &[Member]) {
        let token = fsx::read_or_empty(self.path(K3S_AGENT_TOKEN)).trim().to_string();
        if token.is_empty() {
            // k3s is not up yet; the next sync tries again.
            return;
        }
        if token.contains("::node:") {
            let _ = store.update(|s| {
                if s.k3s_token != token {
                    s.k3s_token = token.clone();
                }
                Ok(())
            });
        } else {
            // Without a secret of its own for agents, k3s gives them the
            // server's token. That one is never handed out.
            eprintln!("dryserver: k3s has no token of its own for agents ({} missing?); servers get none", sysconf::K3S_AGENT_SECRET);
        }
        let Ok(out) = self.run.output(ctx, &Cmd::new("k3s", &["kubectl", "get", "nodes", "-o", "name"]).quiet().stdout_only()) else {
            return;
        };
        let names: Vec<&str> =
            out.lines().filter_map(|l| l.trim().strip_prefix("node/")).filter(|n| *n != self.hostname && registry::valid_name(n)).collect();
        let was: std::collections::BTreeMap<String, String> =
            serde_json::from_str(&fsx::read_or_empty(self.path(K3S_NODES))).unwrap_or_default();
        let mut known = was.clone();
        known.retain(|name, _| names.contains(&name.as_str()));
        for name in names {
            let why = match (members.iter().find(|m| m.name == name), known.get(name)) {
                (None, _) => "is no longer a member",
                (Some(m), Some(key)) if *key != m.wg_key => "was installed again",
                (Some(m), None) => {
                    known.insert(name.to_string(), m.wg_key.clone());
                    continue;
                }
                _ => continue,
            };
            eprintln!("dryserver: {name} {why}: removing the old machine from the cluster");
            if self.cmd(ctx, "k3s", &["kubectl", "delete", "node", name, "--timeout=20s"]).is_ok() {
                known.remove(name);
            }
        }
        if known != was
            && let Ok(text) = serde_json::to_string(&known)
        {
            let _ = self.write(K3S_NODES, 0o600, &(text + "\n"));
        }
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
        if !list.members.iter().any(|e| self.is_me(me, e)) {
            // Newer than a list this server was in: the admin took it out.
            if seen.as_ref().is_some_and(|(ver, _)| list.version > *ver) {
                return Err(Error::with_kind(
                    Kind::Removed,
                    format!("the admin removed this server from the swarm (signed list version {})", list.version),
                ));
            }
            return Err("this server is not in the signed member list".into());
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

    /// Whether a signed entry is this machine: its number and its
    /// WireGuard key. The number alone is not enough; after a removal the
    /// admin's next approval hands it to another machine.
    pub(crate) fn is_me(&self, me: u32, e: &signed::Entry) -> bool {
        e.host == me && self.read(WG_PUB).map_or(true, |k| k == e.wg_key)
    }

    /// The admin took this machine out of the swarm. It stops running the
    /// swarm's apps, forgets its way into the cluster and no longer counts
    /// itself a member. To come back it asks again (sudo dryserver join)
    /// and waits for approval like a new machine.
    ///
    /// The decision is recorded first and the work done after it: from then
    /// on every sync finishes what is left (finish_leave), so a stop that
    /// did not take, or a reboot half way, is caught there. The record is
    /// the LEFT marker, written before join.json says host 0: a reboot
    /// between the two leaves a member with a marker, which stops nothing,
    /// and its next sync hears of the removal again.
    pub(crate) fn leave(&self, ctx: &Ctx, env: &Envelope, why: &Error) {
        self.record_leave(why);
        let _ = self.save_state(&State::default());
        if let Ok(text) = serde_json::to_string(env) {
            let _ = self.write(SIGNED_FILE, 0o600, &(text + "\n"));
        }
        self.k3s_leave(ctx);
        self.note_signed(&format!(
            "REMOVED: {why}. k3s and its containers are stopped, and every sync checks they stay stopped. \
             To bring this machine back: sudo dryserver join"
        ));
    }

    /// Writes the LEFT marker: when, and why. The first one stays, so it
    /// tells when the admin's decision arrived.
    fn record_leave(&self, why: &Error) {
        if self.has_left() {
            return;
        }
        let text = format!("left {:?}\n{}\n", Time::now(), why.to_string().replace('\n', " "));
        if let Err(e) = self.write(LEFT, 0o600, &text) {
            // The stop below still runs; only its repeats need the marker.
            eprintln!("dryserver: cannot record the leave in {LEFT} ({e}): later syncs will not stop k3s again");
        }
    }

    /// Finishes what leave started, on every sync of a server that is no
    /// member: whatever of k3s is still there is stopped again, until
    /// nothing is. A stop can fail (systemctl timed out, a process escaped
    /// the kill), and k3s can be started again by hand; leave runs once
    /// and would not notice.
    ///
    /// Only after a leave (its marker is there), and not once join.json
    /// names a host. A join.json that is gone or damaged does not mean the
    /// admin removed this server: without the marker nothing happens, and a
    /// damaged one stops nothing even with it, which is said loudly.
    ///
    /// A machine waiting for its first approval has nothing there, and
    /// pays one file look for this: no command.
    pub(crate) fn finish_leave(&self, ctx: &Ctx) {
        if !self.has_left() {
            return;
        }
        // The control plane is never stopped here, also on a coordinator
        // whose role file was lost: only the coordinator has its directory.
        if self.path(K3S_SERVER_DIR).exists() {
            return;
        }
        let left = self.k3s_remains(ctx);
        if left.is_empty() {
            self.note(K3S_LEFT_STATUS, "k3s: nothing of k3s is left on this machine", "");
            return;
        }
        // Under the mesh lock, and only while this machine still is no
        // member. An approval sets the host number and removes the marker
        // under the same lock, and the token comes after it: a machine that
        // joins again is never stopped here.
        let _lock = match fsx::lock(self.path(quarantine::MESH_LOCK)) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("dryserver: k3s is still there although this machine is no member, not stopped: {e}");
                return;
            }
        };
        if !self.has_left() {
            return;
        }
        match self.read_state() {
            Ok(Some(s)) if s.host != 0 => return,
            // Host 0, or no file: an approval always writes one (and takes
            // the marker away), and lifting a quarantine forgets the join
            // request of a machine that is no member. The marker decides.
            Ok(_) => {}
            Err(e) => {
                let status = format!(
                    "NOT stopped: this machine left the swarm ({LEFT}), but {e}, so it cannot tell whether it joined again ({}). \
                     Look at {JOIN_STATE}",
                    left.join(", ")
                );
                self.note(K3S_LEFT_STATUS, &format!("k3s: {status}"), &status);
                return;
            }
        }
        let status = format!("still there although this machine is no member ({}): stopping it again", left.join(", "));
        self.note(K3S_LEFT_STATUS, &format!("k3s: {status}"), &status);
        self.k3s_leave(ctx);
    }

    /// What of k3s is on this machine: its token, processes in its cgroups,
    /// an active k3s.service, pods' mounts. Empty when none of it is.
    ///
    /// systemctl is asked only while k3s.service has a cgroup. systemd
    /// removes that cgroup once the unit has stopped and its last process
    /// is gone, so where k3s never ran no command runs.
    pub fn k3s_remains(&self, ctx: &Ctx) -> Vec<String> {
        let mut left = Vec::new();
        if fsx::exists(self.path(sysconf::K3S_TOKEN)) {
            left.push("its token".to_string());
        }
        for cgroup in K3S_CGROUPS {
            if populated(&self.path(cgroup)) {
                left.push(format!("processes in {}", cgroup.rsplit('/').next().unwrap_or(cgroup)));
            }
        }
        if self.path(K3S_CGROUPS[0]).is_dir() && self.cmd(ctx, "systemctl", &["is-active", "--quiet", "k3s.service"]).is_ok() {
            left.push("k3s.service is active".into());
        }
        let mounts = self.pod_mounts().len();
        if mounts > 0 {
            left.push(format!("{mounts} pod mounts"));
        }
        left
    }

    /// Where pods have something mounted, from /proc/self/mounts.
    fn pod_mounts(&self) -> Vec<String> {
        let mounts = fsx::read_or_empty(self.path("/proc/self/mounts"));
        mounts
            .lines()
            .filter_map(|l| l.split(' ').nth(1))
            .filter(|p| POD_MOUNTS.iter().any(|pre| p.starts_with(pre)))
            .map(str::to_string)
            .collect()
    }

    /// Deletes this machine's way into the cluster and stops k3s with
    /// every container it started.
    pub fn k3s_leave(&self, ctx: &Ctx) {
        for f in [sysconf::K3S_TOKEN, sysconf::K3S_CONFIG] {
            let _ = std::fs::remove_file(self.path(f));
        }
        self.k3s_stop(ctx);
    }

    /// On a server that cuts the coordinator off: k3s stops, with every
    /// container, and stays down until the cut is lifted. The coordinator
    /// runs the cluster's control plane; if it is not trusted, neither is
    /// anything it started here. The way into the cluster is kept for the
    /// day the cut is lifted.
    pub fn k3s_hold(&self, ctx: &Ctx) {
        if self.write(sysconf::K3S_HOLD, 0o600, "the coordinator is cut off (dryserver quarantine)\n").is_err() {
            eprintln!("dryserver: cannot write {}; k3s may start again at boot", sysconf::K3S_HOLD);
        }
        self.k3s_stop(ctx);
    }

    /// Stops k3s and every container it started.
    ///
    /// systemd stops only the k3s process (KillMode=process keeps apps up
    /// while k3s restarts), so the rest goes through the kernel: one write
    /// to cgroup.kill ends everything in a cgroup. What the pods had
    /// mounted goes last, their secrets (kept in memory) with it.
    fn k3s_stop(&self, ctx: &Ctx) {
        let _ = self.cmd(ctx, "systemctl", &["stop", "k3s.service"]);
        for cgroup in K3S_CGROUPS {
            let kill = self.path(&format!("{cgroup}/cgroup.kill"));
            if kill.exists() {
                let _ = std::fs::OpenOptions::new().write(true).open(&kill).and_then(|mut f| f.write_all(b"1"));
            }
        }
        let mut points = self.pod_mounts();
        // A mount inside another sorts after it: backwards is inside first.
        points.sort_unstable();
        for point in points.into_iter().rev() {
            // Lazy: the killed processes may need a moment to let go.
            let _ = self.run.output(ctx, &Cmd::new("umount", &["-l", &point]).quiet());
        }
    }

    /// Logs the status of the member list when it changed since the last
    /// sync.
    fn note_signed(&self, status: &str) {
        self.note(SIGNED_STATUS, &format!("member list: {status}"), status);
    }

    /// Keeps status in the file at path and logs line when the status
    /// changed since the last sync, so the journal gets one line per change
    /// and not one per minute. Returns whether it changed.
    fn note(&self, path: &str, line: &str, status: &str) -> bool {
        let path = self.path(path);
        if fsx::read_or_empty(&path).trim() == status {
            return false;
        }
        eprintln!("dryserver: {line}");
        let _ = fsx::mkdir_all(fsx::dir(&path), 0o755);
        let _ = fsx::write_file(&path, format!("{status}\n"), 0o644);
        true
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

/// Whether a cgroup, or one below it, holds a process. cgroup.procs alone
/// does not tell: kubepods.slice keeps every pod in cgroups below itself,
/// and its own list stays empty. A missing cgroup holds nothing.
fn populated(dir: &Path) -> bool {
    let events = fsx::read_or_empty(dir.join("cgroup.events"));
    if !events.is_empty() {
        return events.lines().any(|l| l.trim() == "populated 1");
    }
    !fsx::read_or_empty(dir.join("cgroup.procs")).trim().is_empty()
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
        match n.wait(ctx, JOIN_POLL) {
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
    // A server that is no member runs nothing of the cluster: what its
    // leave did not stop is stopped now. Also while it is quarantined, and
    // whatever the quarantine file says.
    let state = if coordinator { Ok(None) } else { n.read_state() };
    let host = if coordinator { 1 } else { state.as_ref().ok().and_then(|s| s.as_ref()).map_or(0, |s| s.host) };
    if host == 0 {
        n.finish_leave(ctx);
    }
    let q = quarantine::load(n)?;
    if !coordinator && q.coordinator_cut() {
        return Ok(false);
    }
    let mut cuts = q.reports();
    // No more than the coordinator keeps: the heartbeat stays small.
    cuts.truncate(registry::MAX_CUT_REPORTS);
    let sw = port_link(&n.switch_mac());
    let mut me = SelfInfo { host: 0, switch: sw };
    let mut token = String::new();
    let mut offer = rollout::Offer::default();
    // What this machine says about itself, its update included. Kept for
    // the update step after the mesh: it is this sync's health.
    let rep;
    let members = if coordinator {
        me.host = 1;
        rep = n.full_report(ctx, true);
        let hb = Heartbeat { lan_ip: n.cfg.coord_lan_ip.clone(), switch: sw, cuts, report: Some(rep.clone()) };
        let (members, signed) = store.update(|s| {
            s.heartbeat(1, hb, Time::now())?;
            Ok((s.members.clone(), s.signed_version > 0))
        })?;
        // Signed by the admin: the code on the console has done its job.
        if signed && n.path(ISSUE_FILE).exists() {
            let _ = std::fs::remove_file(n.path(ISSUE_FILE));
            let _ = n.cmd(ctx, "agetty", &["--reload"]);
        }
        // The registry account writes that file: what it holds reaches the
        // mesh files and the cluster only checked, like a server checks
        // what the coordinator sends.
        let (members, problems) = registry::check_members(members, |h| !mesh::ip(&n.cfg.wg_subnet, h).is_empty());
        for p in &problems {
            eprintln!("dryserver: sync: ignoring {p}");
        }
        members
    } else {
        me.host = host;
        if me.host == 0 {
            return Err(match state {
                // Not "no member": this machine does not know. It changes
                // nothing, and says so at every sync.
                Err(e) => errf!(
                    "not a member of the swarm as far as this server can tell: {e}. \
                     The mesh and k3s are left as they are; put back {JOIN_STATE} (it holds {{\"host\": N}}) or ask to join again"
                ),
                Ok(None) if !n.has_left() => errf!(
                    "not a member of the swarm: there is no {JOIN_STATE}. Not joined yet (sudo dryserver join asks to join), \
                     or the file was lost: then the mesh and k3s are left as they are; put it back (it holds {{\"host\": N}})"
                ),
                _ => "not a member of the swarm: not joined yet, or removed by the admin (sudo dryserver join asks to join)".into(),
            });
        }
        let lan = local_ip(ctx, n.run.as_ref(), &n.cfg.coord_lan_ip).unwrap_or_default();
        rep = n.full_report(ctx, false);
        let hb = Heartbeat { lan_ip: lan, switch: sw, cuts, report: Some(rep.clone()) };
        let fetched = match n.fetch_members(ctx, &hb) {
            Ok(f) => f,
            Err(e) => {
                // A removed machine is cut from the mesh before it hears
                // why. The coordinator hands the signed list to anyone on
                // the home network; only the admin's signature on it
                // counts, so it does not matter who answers.
                if let Ok(env) = n.fetch_signed_unpinned(ctx)
                    && let Err(gone) = n.signed_members(me.host, &[], &env)
                    && gone.is(Kind::Removed)
                {
                    n.leave(ctx, &env, &gone);
                    return Err(gone);
                }
                return Err(e);
            }
        };
        let Fetched { members: sent, signed: env, k3s_token, release } = fetched;
        token = k3s_token;
        offer = release;
        match n.signed_members(me.host, &sent, &env) {
            Ok((members, status)) => {
                n.note_signed(&status);
                // In the admin's list: a marker left by a leave that went
                // down before it wrote host 0 goes.
                n.clear_left();
                members
            }
            Err(e) if e.is(Kind::Removed) => {
                n.leave(ctx, &env, &e);
                return Err(e);
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
    let all = members;
    let members: Vec<Member> = all.iter().filter(|m| m.host == me.host || !q.blocks(m)).cloned().collect();
    n.apply(me, &members)?;
    n.reload_wg(ctx)?;
    drop(_lock);
    // The cluster follows the mesh: the coordinator shares the token and
    // drops machines that left; a server joins once it has the token.
    if coordinator {
        n.k3s_share(ctx, store, &all);
        // The rollout of the newest release: the coordinator first, then
        // one server at a time.
        let served = rollout::Served::beside(store, n.path(rollout::K3S_BIN));
        rollout::brain_tick(ctx, n, store, &served, &rep, rollout::Now::current());
    } else {
        if let Err(e) = n.k3s_join(ctx, me.host, &token) {
            eprintln!("dryserver: k3s: {e}");
        }
        // This sync reached the coordinator: confirm an installed update,
        // or load and install the offered one when it is this machine's
        // turn.
        match rollout::server_tick(ctx, n, &offer, &rep, Time::now().0.timestamp()) {
            Ok(()) => {
                let _ = std::fs::remove_file(n.path(UPDATE_STATUS));
            }
            Err(e) => {
                n.note(UPDATE_STATUS, &format!("update: {e}"), &e.to_string());
            }
        }
    }
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
        /// k3s command lines.
        k3s: Mutex<Vec<String>>,
        /// systemctl and umount command lines.
        ran: Mutex<Vec<String>>,
        /// The coordinator does not answer over the mesh.
        mesh_down: Mutex<bool>,
        /// The "signed" reply on the home network; None: nobody answers.
        signed: Mutex<Option<Envelope>>,
        /// k3s.service runs: systemctl start and stop change it.
        k3s_up: Mutex<bool>,
        /// systemctl stop k3s.service fails, like one that timed out.
        stop_fails: Mutex<bool>,
        /// The last heartbeat a "peers" call sent.
        heartbeat: Mutex<String>,
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
                k3s: Mutex::new(Vec::new()),
                ran: Mutex::new(Vec::new()),
                mesh_down: Mutex::new(false),
                signed: Mutex::new(None),
                k3s_up: Mutex::new(false),
                stop_fails: Mutex::new(false),
                heartbeat: Mutex::new(String::new()),
            })
        }
    }

    impl Runner for FakeCoord {
        fn run(&self, _ctx: &Ctx, c: &Cmd) -> (String, Result<()>) {
            *self.last.lock().unwrap() = Some(c.clone());
            // Sync helpers: systemctl, ping, ip, wg-quick and wg.
            match c.name.as_str() {
                "systemctl" | "umount" => {
                    self.ran.lock().unwrap().push(format!("{} {}", c.name, c.args.join(" ")));
                    if c.name == "umount" {
                        // Gone from the mount table, like a lazy umount.
                        let mounts = fsx::under(&self.root, "/proc/self/mounts");
                        let left: String = fsx::read_or_empty(&mounts)
                            .lines()
                            .filter(|l| l.split(' ').nth(1) != c.args.last().map(String::as_str))
                            .map(|l| format!("{l}\n"))
                            .collect();
                        if mounts.exists() {
                            std::fs::write(&mounts, left).unwrap();
                        }
                    } else if c.args.last().is_some_and(|a| a == "k3s.service") {
                        let mut up = self.k3s_up.lock().unwrap();
                        match c.args[0].as_str() {
                            "is-active" if !*up => return (String::new(), Err("inactive".into())),
                            "stop" if *self.stop_fails.lock().unwrap() => {
                                return (String::new(), Err("systemctl failed: Job for k3s.service canceled".into()));
                            }
                            "stop" => *up = false,
                            "start" | "restart" => *up = true,
                            _ => {}
                        }
                    }
                    return (String::new(), Ok(()));
                }
                "ping" | "ip" | "agetty" | "networkctl" => return (String::new(), Ok(())),
                // No blocked members in the firewall's set.
                "nft" => return (String::new(), Err("no such set".into())),
                // The cluster knows the coordinator, this node and one
                // machine that is no longer a member.
                "k3s" => {
                    self.k3s.lock().unwrap().push(c.args.join(" "));
                    let out = if c.args.contains(&"get".to_string()) { "node/coord\nnode/node-a\nnode/ghost\nnode/bad name\n" } else { "" };
                    return (out.into(), Ok(()));
                }
                "wg-quick" => return ("[Interface]\nListenPort = 51820\n".into(), Ok(())),
                "wg" if c.args[0] == "syncconf" => {
                    *self.applied.lock().unwrap() = std::fs::read_to_string(&c.args[2]).unwrap_or_default();
                    return (String::new(), Ok(()));
                }
                // The report's look at the links: the coordinator only.
                "wg" if c.args[2] == "allowed-ips" => return (format!("{COORD_WG}\t10.66.0.1/32\n"), Ok(())),
                "wg" => return (format!("{COORD_WG}\t{}\n", Time::now().0.timestamp() - 7), Ok(())),
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
            if cmd == "signed" {
                return match self.signed.lock().unwrap().clone() {
                    Some(env) => (serde_json::json!({ "signed": env }).to_string(), Ok(())),
                    None => (String::new(), Err("ssh: connect to host 192.168.1.50 port 22: Connection timed out".into())),
                };
            }
            if cmd == "peers" && *self.mesh_down.lock().unwrap() {
                return (String::new(), Err("ssh: connect to host 10.66.0.1 port 22: Connection timed out".into()));
            }
            if cmd == "peers" {
                *self.heartbeat.lock().unwrap() = c.stdin.clone();
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

        let f = n.fetch_members(&ctx, &Heartbeat { lan_ip: "192.168.1.23".into(), ..Heartbeat::default() }).unwrap();
        assert_eq!(f.members.len(), 2);
        assert!(!f.signed.is_empty() && f.k3s_token.is_empty());
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
    fn a_server_takes_its_turn_after_the_mesh() {
        let (_dir, _tmp, n, fc) = joined();
        let store = Store::new("/nonexistent");
        let ctx = Ctx::new();
        let env = sign(&ADMIN, 5, vec![coord_entry(), node_entry(2)]);
        let with = |release: serde_json::Value| {
            let mut reply: serde_json::Value = serde_json::from_str(&peers(&[coord_member(), node_member(2)], &env)).unwrap();
            reply["release"] = release;
            *fc.peers.lock().unwrap() = Some(reply.to_string());
        };
        // An offer this version cannot read is no offer.
        with(serde_json::json!("junk"));
        assert!(sync(&ctx, &n, false, &store).unwrap());
        assert!(!fc.calls.lock().unwrap().iter().any(|c| c.contains("status")), "{:?}", fc.calls.lock().unwrap());
        // Its turn: the update commands are asked (and here they are not
        // there). The mesh is synced all the same.
        with(serde_json::json!({"serial": 9, "turn": true, "brain_k3s": "v1.37.2+k3s1"}));
        assert!(sync(&ctx, &n, false, &store).unwrap(), "an update problem must not fail the sync");
        assert!(get(&n.root, WG_CONF).contains(COORD_WG));
        let status = get(&n.root, UPDATE_STATUS);
        assert!(status.contains("release 9 failed: cannot ask how its updates stand"), "{status}");
        // The next heartbeat says so, and it is not tried again by itself.
        let asked = fc.calls.lock().unwrap().len();
        assert!(sync(&ctx, &n, false, &store).unwrap());
        let hb = fc.heartbeat.lock().unwrap().clone();
        assert!(hb.contains(r#""update":"failed""#) && hb.contains(r#""update_serial":9"#), "{hb}");
        assert_eq!(fc.calls.lock().unwrap().len(), asked + 1, "only the sync itself: {:?}", fc.calls.lock().unwrap());
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

    /// A joined server that runs apps: token, config, cgroups, pod mounts.
    fn running_apps() -> (TempDir, TempDir, Node, Arc<FakeCoord>, String) {
        let (dir, tmp, n, fc) = joined();
        assert!(sync(&Ctx::new(), &n, false, &Store::new("/nonexistent")).unwrap());
        put(&n.root, sysconf::K3S_TOKEN, "K10abc::node:secret\n");
        put(&n.root, sysconf::K3S_CONFIG, "server: https://10.66.0.1:6443\n");
        for cgroup in K3S_CGROUPS {
            put(&n.root, &format!("{cgroup}/cgroup.kill"), "");
        }
        put(
            &n.root,
            "/proc/self/mounts",
            "proc /proc proc rw 0 0\n\
             tmpfs /var/lib/kubelet/pods/a/volumes/kubernetes.io~secret/s tmpfs rw 0 0\n\
             overlay /run/k3s/containerd/x/rootfs overlay rw 0 0\n\
             shm /run/k3s/containerd/x/rootfs/dev/shm tmpfs rw 0 0\n\
             nsfs /run/netns/cni-1 nsfs rw 0 0\n\
             /dev/vda2 /var/lib/rancher ext4 rw 0 0\n",
        );
        fc.ran.lock().unwrap().clear();
        *fc.k3s_up.lock().unwrap() = true;
        let wg = get(&n.root, WG_CONF);
        (dir, tmp, n, fc, wg)
    }

    /// Everything a removed server must have done.
    fn assert_left(n: &Node, fc: &FakeCoord, list: &Envelope, wg: &str) {
        assert!(
            get(&n.root, sysconf::K3S_TOKEN).is_empty() && get(&n.root, sysconf::K3S_CONFIG).is_empty(),
            "the way into the cluster stays"
        );
        for cgroup in K3S_CGROUPS {
            assert_eq!(get(&n.root, &format!("{cgroup}/cgroup.kill")), "1", "{cgroup} not killed");
        }
        assert_eq!(
            *fc.ran.lock().unwrap(),
            vec![
                "systemctl stop k3s.service",
                "umount -l /var/lib/kubelet/pods/a/volumes/kubernetes.io~secret/s",
                "umount -l /run/netns/cni-1",
                "umount -l /run/k3s/containerd/x/rootfs/dev/shm",
                "umount -l /run/k3s/containerd/x/rootfs",
            ],
            "k3s first, then the pods' mounts from the inside out, and nothing else"
        );
        assert_eq!(n.load_state().host, 0, "it still counts itself a member");
        let status = get(&n.root, SIGNED_STATUS);
        assert!(status.starts_with("REMOVED") && status.contains("sudo dryserver join"), "{status}");
        assert!(get(&n.root, SIGNED_FILE).contains(&list.sig), "the list that removed it is the newest it has seen");
        assert_eq!(get(&n.root, WG_CONF), wg);
        // From here on it is like a machine that never joined, and with
        // nothing of k3s left there is nothing to stop again.
        fc.ran.lock().unwrap().clear();
        let e = sync(&Ctx::new(), n, false, &Store::new("/nonexistent")).unwrap_err().to_string();
        assert!(e.contains("not a member of the swarm"), "{e}");
        assert_eq!(*fc.ran.lock().unwrap(), vec!["systemctl is-active --quiet k3s.service"], "stopped again with nothing left");
        assert!(get(&n.root, K3S_LEFT_STATUS).trim().is_empty());
    }

    /// The kernel's word on k3s's cgroups.
    fn cgroups(n: &Node, populated: bool) {
        for cgroup in K3S_CGROUPS {
            put(&n.root, &format!("{cgroup}/cgroup.events"), format!("populated {}\nfrozen 0\n", u8::from(populated)));
            put(&n.root, &format!("{cgroup}/cgroup.kill"), "");
        }
    }

    fn stopped(fc: &FakeCoord) -> bool {
        fc.ran.lock().unwrap().iter().any(|c| c == "systemctl stop k3s.service")
    }

    #[test]
    fn a_removed_server_stops_k3s_until_it_is_gone() {
        let (_dir, _tmp, n, fc, _) = running_apps();
        let (store, ctx) = (Store::new("/nonexistent"), Ctx::new());
        // systemctl gives up on the stop, and the kill misses something.
        cgroups(&n, true);
        *fc.stop_fails.lock().unwrap() = true;
        *fc.peers.lock().unwrap() = Some(peers(&[coord_member()], &sign(&ADMIN, 7, vec![coord_entry(), other_entry()])));
        assert!(sync(&ctx, &n, false, &store).unwrap_err().is(Kind::Removed));
        assert!(n.load_state().host == 0 && get(&n.root, sysconf::K3S_TOKEN).is_empty());

        // Every later sync stops it again, and says so in one line: the
        // status stays the same from one sync to the next.
        for round in 0..3 {
            fc.ran.lock().unwrap().clear();
            cgroups(&n, true);
            let e = sync(&ctx, &n, false, &store).unwrap_err().to_string();
            assert!(e.contains("not a member of the swarm"), "{e}");
            assert!(stopped(&fc), "round {round}: {:?}", fc.ran.lock().unwrap());
            for cgroup in K3S_CGROUPS {
                assert_eq!(get(&n.root, &format!("{cgroup}/cgroup.kill")), "1", "round {round}: {cgroup} not killed again");
            }
            let status = get(&n.root, K3S_LEFT_STATUS);
            for want in ["processes in k3s.service", "processes in kubepods.slice", "k3s.service is active"] {
                assert!(status.contains(want), "round {round}: {status}");
            }
            assert!(!n.note(K3S_LEFT_STATUS, "", status.trim()), "the same status is not logged again");
        }

        // The stop works at last, and the kernel lets go of the last
        // process: systemd removes the unit's cgroup.
        *fc.stop_fails.lock().unwrap() = false;
        sync(&ctx, &n, false, &store).unwrap_err();
        assert!(!*fc.k3s_up.lock().unwrap());
        cgroups(&n, false);
        std::fs::remove_dir_all(n.path(K3S_CGROUPS[0])).unwrap();
        fc.ran.lock().unwrap().clear();
        sync(&ctx, &n, false, &store).unwrap_err();
        assert!(fc.ran.lock().unwrap().is_empty(), "nothing left, nothing to run: {:?}", fc.ran.lock().unwrap());
        assert!(get(&n.root, K3S_LEFT_STATUS).trim().is_empty(), "the end is logged once too");
    }

    #[test]
    fn a_machine_waiting_to_join_pays_nothing() {
        let (_dir, n, fc) = setup(vec![]);
        let ctx = Ctx::new();
        for round in 0..2 {
            let e = sync(&ctx, &n, false, &Store::new("/nonexistent")).unwrap_err().to_string();
            assert!(e.contains("not a member of the swarm"), "{e}");
            assert!(fc.ran.lock().unwrap().is_empty(), "round {round}: {:?}", fc.ran.lock().unwrap());
            assert!(!n.path(K3S_LEFT_STATUS).exists());
            // An empty slice from long ago changes nothing.
            put(&n.root, &format!("{}/cgroup.events", K3S_CGROUPS[1]), "populated 0\nfrozen 0\n");
        }
    }

    #[test]
    fn a_machine_that_joins_again_is_never_stopped() {
        let (_dir, _tmp, n, fc, _) = running_apps();
        let (store, ctx) = (Store::new("/nonexistent"), Ctx::new());
        *fc.peers.lock().unwrap() = Some(peers(&[coord_member()], &sign(&ADMIN, 7, vec![coord_entry(), other_entry()])));
        assert!(sync(&ctx, &n, false, &store).unwrap_err().is(Kind::Removed));

        // sudo dryserver join, approved again as host 4: the approval sets
        // the host number, then sync writes the token and starts k3s.
        n.save_state(&State { host: 4, ..State::default() }).unwrap();
        let env = sign(&ADMIN, 8, vec![coord_entry(), node_entry(4)]);
        *fc.peers.lock().unwrap() = Some(
            serde_json::json!({ "members": [coord_member(), node_member(4)], "signed": env, "k3s_token": "K10abc::node:again" })
                .to_string(),
        );
        cgroups(&n, true);
        for _ in 0..2 {
            fc.ran.lock().unwrap().clear();
            assert!(sync(&ctx, &n, false, &store).unwrap());
            assert!(!stopped(&fc), "{:?}", fc.ran.lock().unwrap());
            assert_eq!(get(&n.root, sysconf::K3S_TOKEN), "K10abc::node:again\n");
        }
        assert!(*fc.k3s_up.lock().unwrap());
        // The approval lands between the look and the stop: the second look,
        // under the mesh lock, sees the member.
        n.finish_leave(&ctx);
        assert!(!stopped(&fc) && n.path(sysconf::K3S_TOKEN).exists());
    }

    #[test]
    fn a_reboot_half_way_through_leave_is_caught() {
        let (_dir, _tmp, n, fc, _) = running_apps();
        // leave recorded the decision, then the machine went down. At boot
        // k3s found its token and started again.
        n.record_leave(&Error::new("the admin removed this server from the swarm (signed list version 7)"));
        n.save_state(&State::default()).unwrap();
        cgroups(&n, true);
        fc.calls.lock().unwrap().clear();
        let e = sync(&Ctx::new(), &n, false, &Store::new("/nonexistent")).unwrap_err().to_string();
        assert!(e.contains("not a member of the swarm"), "{e}");
        assert!(stopped(&fc) && get(&n.root, sysconf::K3S_TOKEN).is_empty() && get(&n.root, sysconf::K3S_CONFIG).is_empty());
        assert!(get(&n.root, K3S_LEFT_STATUS).contains("its token"));
        assert!(fc.calls.lock().unwrap().is_empty(), "no need to ask the coordinator again");
    }

    /// k3s still runs as it did: token, config, nothing killed or stopped.
    fn untouched(n: &Node, fc: &FakeCoord, why: &str) {
        assert!(!stopped(fc), "{why}: {:?}", fc.ran.lock().unwrap());
        assert!(!get(&n.root, sysconf::K3S_TOKEN).is_empty() && !get(&n.root, sysconf::K3S_CONFIG).is_empty(), "{why}");
        for cgroup in K3S_CGROUPS {
            assert_eq!(get(&n.root, &format!("{cgroup}/cgroup.kill")), "", "{why}: {cgroup} killed");
        }
    }

    #[test]
    fn a_lost_or_damaged_join_state_never_stops_a_live_server() {
        for (text, want) in [
            (None, "there is no /etc/dryserver/join.json"),
            (Some(""), "join.json is damaged"),
            (Some("{\"host\": 2"), "join.json is damaged"),
            (Some("{\"host\": \"two\"}"), "join.json is damaged"),
            (Some("\0\0\0\0"), "join.json is damaged"),
        ] {
            let (_dir, _tmp, n, fc, _) = running_apps();
            match text {
                None => std::fs::remove_file(n.path(JOIN_STATE)).unwrap(),
                Some(t) => put(&n.root, JOIN_STATE, t),
            }
            cgroups(&n, true);
            for round in 0..2 {
                let e = sync(&Ctx::new(), &n, false, &Store::new("/nonexistent")).unwrap_err().to_string();
                // Said at every sync, with what to do.
                assert!(e.contains(want) && e.contains("left as they are") && e.contains("{\"host\": N}"), "{text:?} round {round}: {e}");
                untouched(&n, &fc, &format!("{text:?} round {round}"));
                assert!(fc.ran.lock().unwrap().is_empty(), "{text:?}: {:?}", fc.ran.lock().unwrap());
            }
            n.finish_leave(&Ctx::new());
            untouched(&n, &fc, &format!("{text:?}, finish_leave by itself"));
            // It is not taken for host 0 anywhere it would undo something.
            if let Some(t) = text {
                assert!(n.read_state().is_err(), "{t:?}");
            }
        }
    }

    #[test]
    fn a_damaged_join_state_after_a_leave_stops_nothing_and_says_so() {
        let (_dir, _tmp, n, fc, _) = running_apps();
        n.record_leave(&Error::new("removed"));
        put(&n.root, JOIN_STATE, "{\"host\": 2");
        cgroups(&n, true);
        for round in 0..2 {
            fc.ran.lock().unwrap().clear();
            n.finish_leave(&Ctx::new());
            untouched(&n, &fc, &format!("round {round}"));
            let status = get(&n.root, K3S_LEFT_STATUS);
            assert!(status.starts_with("NOT stopped") && status.contains("join.json is damaged"), "{status}");
            assert!(!n.note(K3S_LEFT_STATUS, "", status.trim()), "logged once, not at every sync");
        }
    }

    #[test]
    fn the_leave_marker() {
        let (_dir, _tmp, n, fc, _) = running_apps();
        let (store, ctx) = (Store::new("/nonexistent"), Ctx::new());
        *fc.peers.lock().unwrap() = Some(peers(&[coord_member()], &sign(&ADMIN, 7, vec![coord_entry(), other_entry()])));
        assert!(sync(&ctx, &n, false, &store).unwrap_err().is(Kind::Removed));
        // When and why, root's alone; a later leave keeps the first time.
        let marker = get(&n.root, LEFT);
        assert!(marker.starts_with("left 20") && marker.contains("signed list version 7"), "{marker}");
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(n.path(LEFT)).unwrap().permissions()) & 0o777, 0o600);
        n.leave(&ctx, &sign(&ADMIN, 8, vec![coord_entry()]), &Error::new("again"));
        assert_eq!(get(&n.root, LEFT), marker);

        // Lifting a quarantine forgets a non-member's join.json: the
        // marker still has k3s stopped.
        std::fs::remove_file(n.path(JOIN_STATE)).unwrap();
        put(&n.root, sysconf::K3S_TOKEN, "K10abc::node:secret\n");
        cgroups(&n, true);
        fc.ran.lock().unwrap().clear();
        let e = sync(&ctx, &n, false, &store).unwrap_err().to_string();
        assert!(e.contains("removed by the admin"), "{e}");
        assert!(stopped(&fc) && n.path(LEFT).exists() && !n.path(sysconf::K3S_TOKEN).exists());

        // Approved again (sudo dryserver join): the marker goes with the
        // approval, so a later host 0 that is no leave (a join request
        // that expired, say) stops nothing.
        let env = sign(&ADMIN, 9, vec![coord_entry(), node_entry(4)]);
        let params = Params {
            config: n.cfg.clone(),
            plan: packages::resolve(&[], &[]).unwrap(),
            hostname: "node-a".into(),
            role: sysconf::Role::Node,
            switch_mac: "52:54:66:00:00:04".into(),
            ..Params::default()
        };
        n.activate(&approved(4, env), SelfInfo { host: 0, switch: true }, &params).unwrap();
        assert!(!n.path(LEFT).exists() && n.load_state().host == 4);
        put(&n.root, sysconf::K3S_TOKEN, "K10abc::node:again\n");
        put(&n.root, sysconf::K3S_CONFIG, "server: https://10.66.0.1:6443\n");
        for cgroup in K3S_CGROUPS {
            put(&n.root, &format!("{cgroup}/cgroup.kill"), "");
        }
        n.save_state(&State::default()).unwrap();
        fc.ran.lock().unwrap().clear();
        sync(&ctx, &n, false, &store).unwrap_err();
        n.finish_leave(&ctx);
        untouched(&n, &fc, "rejoined, then host 0 without a leave");
    }

    #[test]
    fn a_member_drops_a_marker_its_leave_left_half_way() {
        // leave wrote its marker and went down before join.json said host
        // 0; meanwhile the admin signed this server in again.
        let (_dir, _tmp, n, fc, _) = running_apps();
        n.record_leave(&Error::new("removed"));
        cgroups(&n, true);
        assert!(sync(&Ctx::new(), &n, false, &Store::new("/nonexistent")).unwrap());
        untouched(&n, &fc, "a member with a marker");
        assert!(!n.path(LEFT).exists(), "the signed list says member: the marker goes");
    }

    #[test]
    fn leave_under_the_kill_switch_and_again_and_again() {
        let (_dir, _tmp, n, fc, _) = running_apps();
        let ctx = Ctx::new();
        // The coordinator is cut off and k3s is held. Lifting finds that
        // the admin removed this server meanwhile; the cut stays.
        put(&n.root, quarantine::STATE_FILE, format!(r#"{{"cuts":[{{"name":"coord","hosts":[1],"wg_keys":["{COORD_WG}"]}}]}}"#));
        put(&n.root, sysconf::K3S_HOLD, "x\n");
        cgroups(&n, true);
        *fc.stop_fails.lock().unwrap() = true;
        let gone = sign(&ADMIN, 7, vec![coord_entry(), other_entry()]);
        let why = Error::with_kind(Kind::Removed, "the admin removed this server from the swarm (signed list version 7)");
        for _ in 0..3 {
            n.leave(&ctx, &gone, &why);
        }
        let status = get(&n.root, SIGNED_STATUS);
        assert!(status.starts_with("REMOVED") && !n.note(SIGNED_STATUS, "", status.trim()), "{status}");
        assert!(n.load_state().host == 0 && get(&n.root, SIGNED_FILE).contains(&gone.sig));

        // Sync stays away from the cut coordinator but still stops k3s,
        // also when the quarantine file is damaged.
        fc.calls.lock().unwrap().clear();
        for (state, want_paused) in [(None, true), (Some("{oops"), false)] {
            if let Some(text) = state {
                put(&n.root, quarantine::STATE_FILE, text);
            }
            fc.ran.lock().unwrap().clear();
            let res = sync(&ctx, &n, false, &Store::new("/nonexistent"));
            assert_eq!(res.as_ref().is_ok_and(|ok| !ok), want_paused, "{res:?}");
            assert!(stopped(&fc), "{:?}", fc.ran.lock().unwrap());
            assert!(fc.calls.lock().unwrap().is_empty(), "sync talked to a cut coordinator");
            assert!(n.path(sysconf::K3S_HOLD).exists(), "the hold belongs to the cut and goes with it");
        }
    }

    #[test]
    fn only_what_is_there_is_stopped() {
        let (_dir, n, fc) = setup(vec![]);
        // A server that left: a token, no cgroups (k3s never started), no
        // pod mounts.
        n.record_leave(&Error::new("removed"));
        n.save_state(&State::default()).unwrap();
        put(&n.root, sysconf::K3S_TOKEN, "K10abc::node:secret\n");
        n.finish_leave(&Ctx::new());
        assert!(!n.path(sysconf::K3S_TOKEN).exists());
        assert_eq!(*fc.ran.lock().unwrap(), vec!["systemctl stop k3s.service"], "no is-active without a cgroup, no umount");
        for cgroup in K3S_CGROUPS {
            assert!(!n.path(cgroup).exists(), "{cgroup} was made up");
        }
        // The coordinator's control plane is never stopped here, even if
        // it looks like a server that is no member (its role file lost).
        put(&n.root, K3S_AGENT_TOKEN, "K10abc::node:secret\n");
        put(&n.root, sysconf::K3S_TOKEN, "K10abc::node:secret\n");
        cgroups(&n, true);
        *fc.k3s_up.lock().unwrap() = true;
        fc.ran.lock().unwrap().clear();
        n.finish_leave(&Ctx::new());
        assert!(fc.ran.lock().unwrap().is_empty() && n.path(sysconf::K3S_TOKEN).exists());
    }

    #[test]
    fn removed_server_hears_it_over_the_mesh() {
        let (_dir, _tmp, n, fc, wg) = running_apps();
        // The coordinator has not dropped this server's peer yet.
        let gone = sign(&ADMIN, 7, vec![coord_entry(), other_entry()]);
        *fc.peers.lock().unwrap() = Some(peers(&[coord_member()], &gone));
        let e = sync(&Ctx::new(), &n, false, &Store::new("/nonexistent")).unwrap_err();
        assert!(e.is(Kind::Removed) && e.to_string().contains("signed list version 7"), "{e}");
        assert_left(&n, &fc, &gone, &wg);
    }

    #[test]
    fn removed_server_hears_it_on_the_home_network() {
        let (_dir, _tmp, n, fc, wg) = running_apps();
        let store = Store::new("/nonexistent");
        let ctx = Ctx::new();
        let untouched = |why: &str| {
            let e = sync(&ctx, &n, false, &store).unwrap_err();
            assert!(!e.is(Kind::Removed), "{why}: {e}");
            assert!(!get(&n.root, sysconf::K3S_TOKEN).is_empty() && n.load_state().host == 2, "{why}: left the cluster");
            assert!(fc.ran.lock().unwrap().is_empty(), "{why}: {:?}", fc.ran.lock().unwrap());
        };
        // The coordinator is silent everywhere: maybe it is only switched
        // off. The apps keep running.
        *fc.mesh_down.lock().unwrap() = true;
        untouched("coordinator off");
        // Whoever answers on the home network needs the admin's signature
        // on a newer list.
        for (env, why) in [
            (sign(&ADMIN, 4, vec![coord_entry()]), "an older list without this server"),
            (sign(&Key("thief"), 9, vec![coord_entry()]), "a list signed by someone else"),
            (sign(&ADMIN, 5, vec![coord_entry()]), "another list under the version it has"),
            (Envelope::default(), "no list"),
            (sign(&ADMIN, 9, vec![node_entry(2)]), "a list without a coordinator"),
        ] {
            *fc.signed.lock().unwrap() = Some(env);
            untouched(why);
        }
        // A newer list with this server in it: nothing to do but remember it.
        let newer = sign(&ADMIN, 8, vec![coord_entry(), node_entry(2), other_entry()]);
        *fc.signed.lock().unwrap() = Some(newer.clone());
        untouched("still a member");
        assert!(get(&n.root, SIGNED_FILE).contains(&newer.sig));
        // Removed, and its number already went to another machine.
        let gone = sign(&ADMIN, 9, vec![coord_entry(), Entry { host: 2, ..other_entry() }]);
        *fc.signed.lock().unwrap() = Some(gone.clone());
        let e = sync(&ctx, &n, false, &store).unwrap_err();
        assert!(e.is(Kind::Removed), "{e}");
        assert_left(&n, &fc, &gone, &wg);
    }

    #[test]
    fn server_joins_the_cluster_with_the_coordinators_token() {
        let (_dir, _tmp, n, fc) = joined();
        let store = Store::new("/nonexistent");
        let ctx = Ctx::new();
        // No token yet (k3s on the coordinator is still starting).
        put(&n.root, sysconf::K3S_HOLD, "x\n");
        assert!(sync(&ctx, &n, false, &store).unwrap());
        assert!(n.path(sysconf::K3S_HOLD).exists(), "nothing to start yet");
        assert!(get(&n.root, sysconf::K3S_TOKEN).is_empty() && get(&n.root, sysconf::K3S_CONFIG).is_empty());

        let token = "K10abcdef0123::node:5ecre7";
        let reply = |t: &str| {
            let env = sign(&ADMIN, 5, vec![coord_entry(), node_entry(2)]);
            serde_json::json!({ "members": [coord_member(), node_member(2)], "signed": env, "k3s_token": t }).to_string()
        };
        *fc.peers.lock().unwrap() = Some(reply(token));
        assert!(sync(&ctx, &n, false, &store).unwrap());
        assert_eq!(get(&n.root, sysconf::K3S_TOKEN), format!("{token}\n"));
        assert!(!n.path(sysconf::K3S_HOLD).exists(), "sync runs again: a hold left from a cut is over");
        let conf = get(&n.root, sysconf::K3S_CONFIG);
        assert!(
            conf.contains("server: https://10.66.0.1:6443") && conf.contains("node-ip: 10.66.0.2") && conf.contains("flannel-iface: wg0"),
            "{conf}"
        );
        use std::os::unix::fs::PermissionsExt;
        for (f, mode) in [(sysconf::K3S_TOKEN, 0o600), (sysconf::K3S_CONFIG, 0o644)] {
            assert_eq!(std::fs::metadata(n.path(f)).unwrap().permissions().mode() & 0o777, mode, "{f}");
        }
        // Junk in place of a token changes nothing, and neither does the
        // control plane's own token.
        for bad in [
            "not a token",
            "K10abc\nserver: https://evil",
            "K10;rm -rf",
            &"K10".repeat(400),
            "K10abcdef0123::server:5ecre7",
            "K10abcdef0123",
        ] {
            assert!(n.k3s_join(&ctx, 2, bad).is_err(), "{bad:?}");
            assert_eq!(get(&n.root, sysconf::K3S_TOKEN), format!("{token}\n"));
        }
        // The coordinator itself and a machine without an address never join as agents.
        n.k3s_join(&ctx, 1, "K10other::node:x").unwrap();
        n.k3s_join(&ctx, 0, "K10other::node:x").unwrap();
        assert_eq!(get(&n.root, sysconf::K3S_TOKEN), format!("{token}\n"));
    }

    #[test]
    fn coordinator_shares_the_token_and_drops_left_machines() {
        let (_dir, _tmp, n, fc) = joined();
        let dir = TempDir::new();
        let store = Store::new(dir.join("registry.json"));
        let members = vec![coord_member(), node_member(2)];
        let coord = Node { hostname: "coord".into(), ..n.clone() };
        // k3s not up yet: nothing to share, nobody dropped.
        coord.k3s_share(&Ctx::new(), &store, &members);
        assert!(fc.k3s.lock().unwrap().is_empty());
        put(&coord.root, K3S_AGENT_TOKEN, "K10abc::node:secret\n");
        coord.k3s_share(&Ctx::new(), &store, &members);
        assert_eq!(store.read().unwrap().k3s_token, "K10abc::node:secret");
        let calls = fc.k3s.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec!["kubectl get nodes -o name".to_string(), "kubectl delete node ghost --timeout=20s".into()],
            "only the machine that left goes"
        );
        assert_eq!(get(&coord.root, K3S_NODES).trim(), format!(r#"{{"node-a":"{WG_PUBKEY}"}}"#), "which machine holds the name node-a");
        // node-a was installed again: same name, another machine. The
        // cluster forgets the old one, or it would turn the new one away.
        fc.k3s.lock().unwrap().clear();
        let again = vec![coord_member(), Member { wg_key: OTHER_WG.into(), ..node_member(2) }];
        coord.k3s_share(&Ctx::new(), &store, &again);
        assert!(fc.k3s.lock().unwrap().contains(&"kubectl delete node node-a --timeout=20s".to_string()), "{:?}", fc.k3s.lock().unwrap());
        assert_eq!(get(&coord.root, K3S_NODES).trim(), "{}", "the name is free for the new machine");
        // k3s without a token of its own for agents: the server's token
        // is never handed out.
        let dir2 = TempDir::new();
        let store2 = Store::new(dir2.join("registry.json"));
        put(&coord.root, K3S_AGENT_TOKEN, "K10abc::server:topsecret\n");
        coord.k3s_share(&Ctx::new(), &store2, &members);
        assert_eq!(store2.read().map(|s| s.k3s_token).unwrap_or_default(), "");
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

    /// On the coordinator the members come from the registry file, which
    /// the registry account can write: a name with a newline there must
    /// not add an SSH `Match exec` or anything else to root's files.
    #[test]
    fn coordinator_checks_the_registry_members() {
        let (_dir, _tmp, n, _) = joined();
        let store_dir = TempDir::new();
        let store = Store::new(store_dir.join("registry.json"));
        let evil = Member { name: "node-b\nMatch exec \"touch /tmp/pwned\"".into(), ..node_member(2) };
        let key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [7u8; 32]);
        let good = Member { name: "node-c".into(), wg_key: key, ..node_member(3) };
        store
            .update(|s| {
                s.members = vec![coord_member(), evil, good];
                Ok(())
            })
            .unwrap();
        sync(&Ctx::new(), &Node { hostname: "coord".into(), ..n.clone() }, true, &store).unwrap();
        for f in ["/etc/ssh/ssh_config.d/20-dryserver.conf", "/etc/ssh/ssh_known_hosts", "/etc/hosts", WG_CONF] {
            let out = get(&n.root, f);
            assert!(!out.contains("Match") && !out.contains("pwned"), "{f}:\n{out}");
        }
        let cfg = get(&n.root, "/etc/ssh/ssh_config.d/20-dryserver.conf");
        assert!(cfg.contains("Host coord node-c\n") && !cfg.contains("node-b"), "{cfg}");
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

    #[test]
    fn every_heartbeat_carries_the_report() {
        // A server: with the member list request.
        let (_dir, _tmp, n, fc) = joined();
        put(&n.root, "/proc/sys/kernel/osrelease", "6.12.1-arch1-1\n");
        let many: Vec<String> = (0..100).map(|i| format!(r#"{{"name":"n{i}","hosts":[{}]}}"#, i + 10)).collect();
        put(&n.root, quarantine::STATE_FILE, format!(r#"{{"cuts":[{}]}}"#, many.join(",")));
        assert!(sync(&Ctx::new(), &n, false, &Store::new("/nonexistent")).unwrap());
        let hb: Heartbeat = serde_json::from_str(&fc.heartbeat.lock().unwrap()).unwrap();
        let r = hb.report.expect("no report in the heartbeat");
        assert_eq!((r.dryserver.as_str(), r.kernel.as_str()), (env!("CARGO_PKG_VERSION"), "6.12.1-arch1-1"));
        assert_eq!(r.peers, vec![report::Peer { host: 1, age: Some(7) }], "the coordinator's link, by number");
        assert_eq!(hb.cuts.len(), registry::MAX_CUT_REPORTS, "no more cuts than the coordinator keeps");

        // The coordinator: its own entry, in its own registry.
        let (_dir, _tmp, n, _) = joined();
        let dir = TempDir::new();
        let store = Store::new(dir.join("registry.json"));
        store
            .update(|s| {
                s.members = vec![coord_member(), node_member(2)];
                Ok(())
            })
            .unwrap();
        sync(&Ctx::new(), &Node { hostname: "coord".into(), ..n }, true, &store).unwrap();
        let st = store.read().unwrap();
        assert!(st.members[0].report.as_ref().is_some_and(|r| r.dryserver == env!("CARGO_PKG_VERSION")));
        assert_eq!(st.members[1].report, None, "the coordinator wrote a report for another machine");
    }
}
