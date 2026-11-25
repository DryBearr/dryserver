//! Runs on a server (or on the installer for a server being installed): asks
//! the coordinator to join, waits for approval, brings up the mesh and keeps
//! it in sync.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::config::{self, Config};
use crate::ctx::Ctx;
use crate::err::{Error, Kind, Result};
use crate::gotime::Time;
use crate::k3stoken::{self, Sealed};
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
/// Its private half, root's: the coordinator signs the cluster token
/// with it, and a server opens its sealed token with it.
pub const HOST_KEY: &str = "/etc/ssh/ssh_host_ed25519_key";
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
/// How many times in a row the machine at the coordinator's address may
/// answer a waiting machine with another SSH host key before it forgets
/// the pinned one and asks again (about a minute of polls). A machine on
/// the home network that answered in the coordinator's place when the
/// request went out would otherwise leave it stuck for good: every poll
/// of the real coordinator fails on the key.
pub const HOST_KEY_TRIES: u32 = 5;

/// How a join request the coordinator turned down starts (refusal).
const REFUSED: &str = "the coordinator turned this machine's request down";

/// What the registry's no to a join request (in e) means, with what the
/// admin does about it; none for anything else. The registry's words,
/// which a hacked registry account chooses: they only ever reach this
/// machine's console.
fn refusal(name: &str, e: &Error) -> Option<String> {
    let msg = e.to_string();
    Some(if msg.contains("is already a member; remove it first") {
        format!(
            "the name {name} is a member already. If this machine takes its place, remove {name} on your computer in \
             dryserver approve (d); this machine then asks again by itself"
        )
    } else if msg.contains("WireGuard key already belongs to a member") {
        format!(
            "this machine is a member already, by its WireGuard key, but has no record of it ({JOIN_STATE}). Put that back, \
             or remove it on your computer in dryserver approve (d): it then asks again by itself"
        )
    } else if msg.contains("another machine is already asking to join as") {
        format!(
            "another machine is asking to join as {name} already. If that one is not this machine (its code is not the one \
             below), reject it on your computer in dryserver approve (r): this machine then asks again by itself"
        )
    } else if msg.contains("too many pending requests") || msg.contains("wait already; approve or reject") {
        "too many machines are waiting to join. Approve or reject them on your computer in dryserver approve; this \
         machine asks again by itself"
            .into()
    } else {
        return None;
    })
}

/// Whether ssh failed because the host has another key than the pinned
/// one.
fn host_key_failed(e: &Error) -> bool {
    let msg = e.to_string();
    msg.contains("Host key verification failed") || msg.contains("HOST IDENTIFICATION HAS CHANGED")
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// What a coordinator shows on its console until the admin signed it.
pub fn coordinator_issue(code: &str) -> String {
    format!(
        "\ndryserver: this coordinator is not signed yet, no machine can join.\n\
         On your own computer run: dryserver approve   and press S.\n\
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
/// Where the coordinator of an older version remembered the one token it
/// sealed for every server: there, that token reached servers.
pub const K3S_SEALED: &str = "/etc/dryserver/k3s-sealed.json";
/// On the coordinator: the join token root made for each server that has
/// not joined the cluster yet (Joins). Root's alone. Lost, each such
/// server gets a new one.
pub const K3S_JOIN: &str = "/etc/dryserver/k3s-join.json";
/// On the coordinator: the SHA-256 of the cluster's shared agent token
/// (K3S_AGENT_TOKEN) while servers hold it, because an older version
/// handed it out or a server joined without a token of its own. Any of
/// them could register a node under another server's name with it, until
/// the admin makes a new one (README, A new cluster token).
pub const K3S_SHARED: &str = "/etc/dryserver/k3s-shared-token";
/// On the coordinator's console while its registry cannot be used and the
/// mesh and the cluster follow its own newest list (Node::own_list).
pub const REGISTRY_ISSUE: &str = "/etc/issue.d/40-dryserver-registry.issue";
/// On the coordinator's console while K3S_SHARED holds the current token.
pub const SHARED_ISSUE: &str = "/etc/issue.d/41-dryserver-k3s-token.issue";
/// How long a join token lasts (k3s deletes it then), and how long before
/// that the next sync makes a new one.
pub const JOIN_TOKEN_TTL: i64 = 24 * 3600;
pub const JOIN_TOKEN_RENEW: i64 = 3600;
/// On the coordinator: node names a machine took in the cluster without
/// the node password root made for that name (k3s_share), with when and
/// how. k3s gave that machine a certificate for the name, good for a
/// year: no server gets a token for the name meanwhile.
pub const K3S_TAKEN: &str = "/etc/dryserver/k3s-taken.json";
/// How long a taken name stays taken: k3s's certificates last a year.
pub const TAKEN_FOR: i64 = 400 * 86_400;
/// On the coordinator's console while a name is taken or the node of a
/// server that was in the cluster is gone.
pub const NAMES_ISSUE: &str = "/etc/issue.d/42-dryserver-k3s-names.issue";
/// Root's mark on the node-password secrets it makes: an annotation (the
/// password's stamp) and a finalizer, so that k3s, which removes one
/// without a node after ten minutes, keeps it until its server joined.
const PASSWORD_MARK: &str = "dryserver.io/node-password";

/// A node name taken in the cluster (K3S_TAKEN).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct Taken {
    /// Unix seconds by this machine's clock.
    since: i64,
    why: String,
}

/// The node-password secrets in the cluster by node name: Some(stamp) on
/// root's own, None on one k3s made from an agent's password.
type Passwords = BTreeMap<String, Option<String>>;

/// Unix seconds for the console.
fn day(t: i64) -> String {
    chrono::DateTime::from_timestamp(t, 0).map_or_else(|| format!("{t} (unix time)"), |d| d.format("%Y-%m-%d %H:%M UTC").to_string())
}

/// What root marks its node-password secret with: a digest of the
/// password, which tells nothing of it.
fn stamp(password: &str) -> String {
    fsx::hex(&sha2::Sha256::digest(format!("dryserver-node-password\n{password}").as_bytes()))[..32].to_string()
}

/// What root on the coordinator keeps of the join tokens it made
/// (K3S_JOIN).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct Joins {
    /// By host number: the token of each server that has not joined yet.
    tokens: BTreeMap<u32, Join>,
    /// Tokens no longer handed out that k3s did not delete when asked:
    /// asked again at every sync until they expire.
    stale: Vec<Join>,
}

/// One join token root made.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct Join {
    /// The server it is for, as the admin signed it.
    name: String,
    wg_key: String,
    /// The coordinator's host key it was signed with.
    coord: String,
    /// Its id, which `k3s token delete` takes.
    id: String,
    /// When k3s deletes it, Unix seconds by this machine's clock.
    expires: i64,
    /// The server's node password, sealed with the token; its hash is in
    /// the cluster under the server's name. Empty on a token an older
    /// version made, which bound no name.
    password: String,
    /// What root leaves in the registry for the server.
    sealed: Sealed,
}

impl Join {
    /// Whether it is the token of this member as the admin signed it now,
    /// sealed by this coordinator.
    fn of(&self, m: &Member, coord: &str) -> bool {
        self.sealed.host == m.host
            && self.name == m.name
            && self.wg_key == m.wg_key
            && self.sealed.key == signed::key_body(&m.ssh_host_key)
            && self.coord == coord
    }
}
/// What the coordinator's last sync could not seal; a change is logged.
pub const K3S_SHARE_STATUS: &str = "/run/dryserver-k3s-share.status";
/// Whether this server could sign its report at the last sync; a change
/// is logged.
pub const REPORT_STATUS: &str = "/run/dryserver-report.status";
/// Which servers' reports the coordinator's last sync did not take; a
/// change is logged.
pub const REPORTS_STATUS: &str = "/run/dryserver-reports.status";
/// On the coordinator: from which release on servers sign their reports,
/// and the newest signed report taken from each (ReportCheck).
pub const SIGNED_REPORTS: &str = "/etc/dryserver/signed-reports.json";
/// A receipt (registry::Receipt) is made again this often while the list
/// stays the same: its time says the coordinator's sync runs.
pub const RECEIPT_EVERY: i64 = 300;
/// A signed report older than this is not taken.
pub const REPORT_MAX_AGE: i64 = 86_400;

/// What root on the coordinator keeps of the reports it took
/// (SIGNED_REPORTS).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct ReportCheck {
    /// The release this coordinator ran when it first checked reports (at
    /// least 1): from it on every server's release signs its reports, so
    /// an unsigned report that says it runs one of them is not taken. One
    /// of an older release is, as before: that server cannot sign yet.
    since: u64,
    /// By host number: the WireGuard key and the time of the newest
    /// signed report taken. An older one is not taken again.
    seen: BTreeMap<u32, (String, i64)>,
}
/// What a server made of the token the coordinator sent at the last sync;
/// a change is logged.
pub const K3S_TOKEN_STATUS: &str = "/run/dryserver-k3s-token.status";

/// What the coordinator answers to "peers".
#[derive(Debug, Clone, Default)]
pub struct Fetched {
    /// Checked entries; what the coordinator says, not what is signed.
    pub members: Vec<Member>,
    /// The signed list as sent (empty when the coordinator has none).
    pub signed: Envelope,
    /// This machine's token for joining the k3s cluster, sealed by root on
    /// the coordinator (k3stoken.rs); none before k3s is up there.
    pub k3s_sealed: Option<Sealed>,
    /// The coordinator sent the token itself, as versions before sealed
    /// tokens did. Never taken: the registry account could have put any
    /// token there.
    pub k3s_plain: bool,
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
        // Made new at exactly mode: a file left at that name by a killed
        // run, with another mode, never carries a secret.
        fsx::write_new(&tmp, content, mode)?;
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
    pub(crate) fn has_left(&self) -> bool {
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
            // The coordinator answered and said no: the reason first, and
            // what to do. Its key is pinned by now, so the code is known.
            if let Some(why) = refusal(&self.hostname, &e) {
                let code = self.coordinator_key().map(|k| registry::pairing_code(&wg, &host_key, &k)).unwrap_or_default();
                let code = if code.is_empty() {
                    String::new()
                } else {
                    format!("\nThis machine's code is {code}: the approval screen shows it with the request.")
                };
                return Err(errf!("{REFUSED}: {why}.{code}"));
            }
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
    /// the host number and the coordinator's details. Kind::HostKey when
    /// the machine at the coordinator's address answered HOST_KEY_TRIES
    /// times in a row with another SSH host key than the one pinned when
    /// the request went out.
    pub fn wait(&self, ctx: &Ctx, every: Duration) -> Result<StatusReply> {
        let st = self.load_state();
        if st.request_id.is_empty() {
            return Err("no join request sent".into());
        }
        let mut other_key = 0;
        loop {
            let (out, res) = self.ssh(ctx, &self.cfg.coord_lan_ip, &format!("status {}", st.request_id), "");
            other_key = if res.as_ref().is_err_and(host_key_failed) { other_key + 1 } else { 0 };
            if other_key >= HOST_KEY_TRIES {
                return Err(self.other_key());
            }
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

    /// What the machine at the coordinator's address answering with
    /// another SSH host key than the pinned one means before approval.
    fn other_key(&self) -> Error {
        Error::with_kind(
            Kind::HostKey,
            format!(
                "the coordinator at {} answers with another SSH host key than the one this machine saw when it asked to join. \
                 Someone else on the network may have answered then (that request can never be approved), or the coordinator \
                 was installed again",
                self.cfg.coord_lan_ip
            ),
        )
    }

    /// Before approval only: forgets the pinned coordinator key and the
    /// join request, so the next request pins whoever answers then and
    /// shows a new code. Safe because a pin lets nobody in: the code the
    /// admin compares covers the key this machine pinned, and an approval
    /// counts only with a list the admin signed for that same key
    /// (check_approval).
    fn forget_coordinator(&self) -> Result<()> {
        match std::fs::remove_file(self.path(KNOWN_HOSTS)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(Error::from(e).wrap(format!("remove {KNOWN_HOSTS}"))),
            _ => {}
        }
        self.save_state(&State::default())
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
        self.apply_live(me, members, &BTreeMap::new(), 0)
    }

    /// apply, with what WireGuard knows of each peer now (mesh::wg_config_live).
    pub fn apply_live(&self, me: SelfInfo, members: &[Member], live: &BTreeMap<String, mesh::Live>, now: i64) -> Result<()> {
        self.write(WG_CONF, 0o600, &mesh::wg_config_live(&self.cfg, me, members, live, now))?;
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
            // One this version cannot read is none.
            #[serde(default, deserialize_with = "report::lenient")]
            k3s_sealed: Option<Sealed>,
            // What an older coordinator sends instead.
            #[serde(default, deserialize_with = "report::lenient")]
            k3s_token: String,
            // An older coordinator sends none; one this version cannot
            // read offers nothing.
            #[serde(default, deserialize_with = "report::lenient")]
            release: rollout::Offer,
        }
        let (members, signed, k3s_sealed, k3s_plain, release) = match serde_json::from_str::<Reply>(&out) {
            Ok(r) if !r.members.is_empty() => (r.members, r.signed, r.k3s_sealed, !r.k3s_token.is_empty(), r.release),
            _ => return Err("bad member list from coordinator".into()),
        };
        // Nothing from the coordinator is used unchecked.
        let (members, problems) = registry::check_members(members, |h| !mesh::ip(&self.cfg.wg_subnet, h).is_empty());
        for p in &problems {
            eprintln!("dryserver: sync: ignoring {p}");
        }
        Ok(Fetched { members, signed, k3s_sealed, k3s_plain, release })
    }

    /// On a server: the cluster token in what the coordinator sent for this
    /// machine, with its node password, once it checks out
    /// (k3stoken::open): sealed for this machine's host key by the
    /// coordinator the admin signed (coord_key, from the signed list). None
    /// while there is none.
    pub fn k3s_open(&self, ctx: &Ctx, me: u32, coord_key: &str, sealed: Option<&Sealed>, plain: bool) -> Result<Option<k3stoken::Opened>> {
        if me < 2 {
            return Ok(None);
        }
        let Some(s) = sealed else {
            if plain {
                return Err(
                    "the coordinator sent the cluster token unencrypted, as dryserver did before, which this version never takes: \
                     update the coordinator (dryserver release publish)"
                        .into(),
                );
            }
            return Ok(None);
        };
        let my_key = signed::key_body(&self.read(HOST_KEY_PUB)?);
        let tmp = self.tmp_dir.clone().unwrap_or_else(|| PathBuf::from("/run"));
        let coord_key = signed::key_body(coord_key);
        k3stoken::open(ctx, self.run.as_ref(), s, me, &my_key, &coord_key, &self.path(HOST_KEY), &tmp).map(Some)
    }

    /// On a server, at every sync: joins the cluster with the token the
    /// coordinator sealed for this machine. One that does not check out,
    /// or none, leaves the token and k3s as they are: nothing is written
    /// and nothing restarted. What is wrong is logged once.
    pub fn k3s_take(&self, ctx: &Ctx, me: u32, coord_key: &str, sealed: Option<&Sealed>, plain: bool) {
        match self.k3s_open(ctx, me, coord_key, sealed, plain) {
            Ok(Some(o)) => {
                self.note(K3S_TOKEN_STATUS, "k3s: the coordinator's cluster token for this machine checks out", "ok");
                if let Err(e) = self.k3s_join(ctx, me, &o.token, o.password.as_deref()) {
                    eprintln!("dryserver: k3s: {e}");
                }
            }
            Ok(None) => {}
            Err(e) => {
                let status = format!("{e}; the token and k3s are left as they are");
                self.note(K3S_TOKEN_STATUS, &format!("k3s: {status}"), &status);
            }
        }
    }

    /// On a server: joins the k3s cluster with token, checked (k3s_open).
    /// Writes the token, the node password root on the coordinator made for
    /// this machine's name (none from an older coordinator: k3s makes its
    /// own then) and the config for this machine's mesh address, and
    /// starts k3s (again, if any of them changed).
    pub fn k3s_join(&self, ctx: &Ctx, me: u32, token: &str, password: Option<&str>) -> Result<()> {
        let token = token.trim();
        if token.is_empty() || me < 2 {
            return Ok(());
        }
        // Never one without the hash of the cluster's certificate
        // authority (the agent would trust whoever answers), nor the
        // control plane's own token, which opens more than a server needs.
        if let Some(p) = k3stoken::problem(token) {
            return Err(errf!("the coordinator sent a cluster token that is {p}; k3s left as it is"));
        }
        if let Some(p) = password.and_then(k3stoken::password_problem) {
            return Err(errf!("the coordinator sent a node password that is {p}; k3s left as it is"));
        }
        // Sync runs, so the coordinator is not cut off (any more).
        let _ = std::fs::remove_file(self.path(sysconf::K3S_HOLD));
        let config = sysconf::k3s_agent_config(&mesh::ip(&self.cfg.wg_subnet, 1), &mesh::ip(&self.cfg.wg_subnet, me));
        let mut changed = false;
        // The token and the password are secrets; the config only says
        // where things are.
        let mut files = vec![(sysconf::K3S_TOKEN, 0o600, format!("{token}\n")), (sysconf::K3S_CONFIG, 0o644, config)];
        if let Some(p) = password {
            files.push((sysconf::K3S_NODE_PASSWORD, 0o600, format!("{p}\n")));
        }
        for (path, mode, want) in files {
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

    /// On the coordinator, at every sync with a list the admin signed
    /// (members): the cluster follows it.
    ///
    /// - Out of the cluster goes what is no longer there: a machine that
    ///   left the swarm, and the old machine behind a name that was
    ///   installed again (the cluster would turn the new one away).
    /// - Each server that is not in the cluster yet gets a join token of its
    ///   own (`k3s token create`, for a day, made again before it ends) and
    ///   a node password, sealed together for it (k3stoken.rs). The
    ///   registry holds exactly those. The password's hash goes into the
    ///   cluster first (k3s's secret `<name>.node-password.k3s`, made by
    ///   root and marked as root's): from then on k3s gives a certificate
    ///   for that name only to the agent with the password. Without it any
    ///   token registers any name, also the token of a server that has not
    ///   joined yet.
    /// - A node under a member's name is that member's (K3S_NODES) only
    ///   when the password k3s keeps for the name is root's for that
    ///   member. Any other, or a password k3s took from an agent for a name
    ///   root made none for, means that a machine with a join token took
    ///   the name, and k3s gave it a certificate for it that lasts a year.
    ///   The name is taken (K3S_TAKEN): a node under it is deleted at every
    ///   sync, no server gets a token for it, and the console says so.
    /// - Once its node is there the token is deleted: the server goes on
    ///   with its kubelet certificate, which k3s takes for its own name
    ///   only. A member that was in the cluster never gets a token again,
    ///   also when its node is gone: a hacked server could delete its own
    ///   node to get one. It comes back with its certificate, or the admin
    ///   removes it and approves it again.
    /// - Servers that joined before (older versions, the shared token)
    ///   stay as they are: the first node under a member's name was that
    ///   member's then, and still is.
    ///
    /// store None: the registry cannot be used (see sync); what it holds
    /// stays as it is, and no token is made, as none would arrive.
    pub fn k3s_share(&self, ctx: &Ctx, store: Option<&Store>, members: &[Member], now: i64) {
        let Ok(out) = self.run.output(ctx, &Cmd::new("k3s", &["kubectl", "get", "nodes", "-o", "name"]).quiet().stdout_only()) else {
            // k3s is not up (yet): the next sync tries again.
            return;
        };
        let coord_name = members.iter().find(|m| m.host == 1).map(|m| m.name.clone()).unwrap_or_default();
        let own = |n: &str| n == self.hostname || n == coord_name;
        let names: Vec<&str> =
            out.lines().filter_map(|l| l.trim().strip_prefix("node/")).filter(|n| !own(n) && registry::valid_name(n)).collect();
        // None when k3s does not list them: then no node is taken for a
        // member, and no token made.
        let mut passwords = match self.k3s_passwords(ctx) {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("dryserver: k3s: cannot list the node passwords: {e}");
                None
            }
        };
        let coord = members.iter().find(|m| m.host == 1).map(|m| signed::key_body(&m.ssh_host_key)).unwrap_or_default();
        let first = std::fs::symlink_metadata(self.path(K3S_JOIN)).is_err();
        let was_joins: Joins = serde_json::from_str(&fsx::read_or_empty(self.path(K3S_JOIN))).unwrap_or_default();
        let mut joins = was_joins.clone();
        // Which machine holds each name; none when the file is not there
        // or damaged.
        let nodes_file: Option<BTreeMap<String, String>> =
            std::fs::read(self.path(K3S_NODES)).ok().and_then(|b| serde_json::from_slice(&b).ok());
        // Servers hold the shared token (an older version handed it out),
        // or root kept no tokens or names yet (or lost them): names go as
        // they did before. A server in the cluster would be taken for one
        // that took its name.
        let legacy = first || nodes_file.is_none() || self.k3s_shared_in_use();
        // Servers that joined with a token root did not make for them hold
        // the shared one: an older version handed it out.
        let mut shared = std::fs::symlink_metadata(self.path(K3S_SEALED)).is_ok()
            || (first && names.iter().any(|n| members.iter().any(|m| m.host >= 2 && m.name == *n)));
        let was = nodes_file.clone().unwrap_or_default();
        let mut known = was.clone();
        let was_taken: BTreeMap<String, Taken> = serde_json::from_str(&fsx::read_or_empty(self.path(K3S_TAKEN))).unwrap_or_default();
        let mut taken = was_taken.clone();
        taken.retain(|_, t| now - t.since < TAKEN_FOR);
        let take = |taken: &mut BTreeMap<String, Taken>, name: &str, why: &str| {
            if !taken.contains_key(name) {
                eprintln!("dryserver: k3s: ALARM: the name {name} is taken in the cluster: {why}");
                taken.insert(name.to_string(), Taken { since: now, why: why.into() });
            }
        };
        let member = |name: &str| members.iter().find(|m| m.host >= 2 && m.name == name);

        // The nodes in the cluster.
        for name in &names {
            let why = match (member(name), known.get(*name)) {
                (None, k) => {
                    if k.is_none() && !first {
                        take(&mut taken, name, "a machine registered it although no server of that name is signed");
                    }
                    "is no longer a member"
                }
                (Some(m), Some(key)) if *key != m.wg_key => "was installed again",
                (Some(_), Some(_)) => continue,
                (Some(m), None) => {
                    let join = joins.tokens.get(&m.host).filter(|j| j.of(m, &coord));
                    // The token root sealed the password of that name with.
                    let holder =
                        |s: &str| joins.tokens.values().chain(&joins.stale).find(|j| !j.password.is_empty() && stamp(&j.password) == s);
                    // A token an older version made, the shared one, or no
                    // tokens kept yet: the first node under its name is the
                    // member's, as before.
                    let old = legacy || join.is_some_and(|j| j.password.is_empty());
                    match passwords.as_ref().map(|p| p.get(*name)) {
                        _ if taken.contains_key(*name) => "holds a name that is taken",
                        // Root's password: k3s let in only the agent that
                        // has it, and root sealed it for that server alone.
                        Some(Some(Some(s))) if holder(s).is_none_or(|j| j.of(m, &coord)) => {
                            known.insert(name.to_string(), m.wg_key.clone());
                            continue;
                        }
                        // Root's for the machine that had the name before
                        // (removed, or installed again) and came while it
                        // was still in the mesh: not this server.
                        Some(Some(Some(_))) => "came with the password of the machine that had the name before",
                        _ if old => {
                            shared |= join.is_none();
                            known.insert(name.to_string(), m.wg_key.clone());
                            continue;
                        }
                        // k3s does not say: the next sync decides.
                        None => continue,
                        Some(Some(None)) => {
                            take(&mut taken, name, "a machine registered it without the node password root made for that server");
                            "is not that server's"
                        }
                        Some(None) => {
                            take(&mut taken, name, "a machine registered it with a certificate for it, without its node password");
                            "is not that server's"
                        }
                    }
                }
            };
            eprintln!("dryserver: {name} {why}: removing that node from the cluster");
            if self.cmd(ctx, "k3s", &["kubectl", "delete", "node", name, "--timeout=20s"]).is_ok()
                && self.k3s_password_drop(ctx, name, &mut passwords)
            {
                known.remove(*name);
            }
        }
        // Gone from the cluster: a machine that left the swarm or was
        // installed again takes its name's password along. One that is
        // still the member stays known: it gets no token.
        for (name, key) in &was {
            if names.contains(&name.as_str()) || !known.contains_key(name) || member(name).is_some_and(|m| m.wg_key == *key) {
                continue;
            }
            if self.k3s_password_drop(ctx, name, &mut passwords) {
                known.remove(name);
            }
        }
        // Passwords without a node. Root's for a name no server has any
        // more go; one k3s took from an agent means that agent has a
        // certificate for the name.
        for (name, mark) in passwords.clone().unwrap_or_default() {
            if names.contains(&name.as_str()) || own(&name) || known.contains_key(&name) || !registry::valid_name(&name) {
                continue;
            }
            match (mark, member(&name)) {
                (Some(_), None) => {
                    self.k3s_password_drop(ctx, &name, &mut passwords);
                }
                (Some(_), Some(_)) => {}
                (None, None) if !first => {
                    take(&mut taken, &name, "a machine got a certificate for it although no server of that name is signed");
                }
                (None, None) => {}
                (None, Some(m)) => {
                    let join = joins.tokens.get(&m.host).filter(|j| j.of(m, &coord));
                    // Joining with a token an older version made, or with
                    // the shared one: k3s drops it in ten minutes if no
                    // node comes.
                    let old = first || join.is_some_and(|j| j.password.is_empty()) || (legacy && join.is_none());
                    if !old {
                        take(&mut taken, &name, "a machine got a certificate for it without the node password root made for that server");
                    }
                }
            }
        }
        if (known != was || nodes_file.is_none())
            && let Ok(text) = serde_json::to_string(&known)
        {
            let _ = self.write(K3S_NODES, 0o600, &(text + "\n"));
        }
        // A token for another machine than the member under its number now
        // (removed, installed again, another key) is never handed out again.
        let stale: Vec<u32> =
            joins.tokens.iter().filter(|(h, j)| !members.iter().any(|m| m.host == **h && j.of(m, &coord))).map(|(h, _)| *h).collect();
        for h in stale {
            joins.stale.extend(joins.tokens.remove(&h));
        }
        let mut problems = Vec::new();
        // Servers that were in the cluster and whose node is gone.
        let mut gone = Vec::new();
        for m in members.iter().filter(|m| m.host >= 2) {
            if known.get(&m.name) == Some(&m.wg_key) {
                // In the cluster: its token has done its job. Out of it
                // again: it gets none.
                joins.stale.extend(joins.tokens.remove(&m.host));
                if !names.contains(&m.name.as_str()) {
                    gone.push(m.name.clone());
                }
                continue;
            }
            if taken.contains_key(&m.name) {
                joins.stale.extend(joins.tokens.remove(&m.host));
                continue;
            }
            let key = signed::key_body(&m.ssh_host_key);
            if !k3stoken::is_ed25519(&key) {
                let why = if key.is_empty() { "it has no SSH host key in the signed list" } else { "its SSH host key is not ssh-ed25519" };
                problems.push(format!("no join token for {}: {why}", m.name));
                continue;
            }
            if store.is_none() {
                continue;
            }
            let Some(mark) = passwords.as_ref().map(|p| p.get(&m.name).cloned()) else {
                problems.push(format!("no join token for {}: k3s does not list the node passwords", m.name));
                continue;
            };
            // The token it has, if root made it with a password.
            let current = joins.tokens.get(&m.host).filter(|j| j.of(m, &coord) && !j.password.is_empty()).cloned();
            let password = current.as_ref().map_or_else(k3stoken::new_password, |j| j.password.clone());
            let want = stamp(&password);
            // Its password goes into the cluster before any token for it.
            match mark {
                Some(Some(s)) if s == want => {}
                // k3s took one from its agent, which joins with a token an
                // older version made (else the name would be taken above).
                Some(None) => continue,
                found => {
                    // Root's, from a password root no longer has.
                    if found.is_some() && !self.k3s_password_drop(ctx, &m.name, &mut passwords) {
                        problems.push(format!("no join token for {}: cannot remove its old node password from the cluster", m.name));
                        continue;
                    }
                    if let Err(e) = self.k3s_password_make(ctx, &m.name, &password) {
                        problems.push(format!("no join token for {}: cannot put its node password into the cluster ({e})", m.name));
                        continue;
                    }
                    if let Some(p) = passwords.as_mut() {
                        p.insert(m.name.clone(), Some(want));
                    }
                }
            }
            if current.is_some_and(|j| j.expires - now > JOIN_TOKEN_RENEW) {
                continue;
            }
            match self.k3s_mint(ctx, m, &key, &coord, &password, now) {
                Ok(j) => joins.stale.extend(joins.tokens.insert(m.host, j)),
                // One it has keeps working while it lasts.
                Err(e) => problems.push(format!("no new join token for {}: {e}", m.name)),
            }
        }
        // k3s deletes a token when it ends; one asked to go earlier that did
        // not is asked again until then.
        let mut left = Vec::new();
        for j in std::mem::take(&mut joins.stale) {
            if j.expires > now && !self.k3s_unmint(ctx, &j.id) {
                left.push(j);
            }
        }
        joins.stale = left;
        if (first || joins != was_joins)
            && let Ok(text) = serde_json::to_string(&joins)
            && let Err(e) = self.write(K3S_JOIN, 0o600, &(text + "\n"))
        {
            problems.push(format!("cannot keep the join tokens in {K3S_JOIN} ({e})"));
        }
        if taken != was_taken
            && let Ok(text) = serde_json::to_string(&taken)
            && let Err(e) = self.write(K3S_TAKEN, 0o600, &(text + "\n"))
        {
            problems.push(format!("cannot keep the taken names in {K3S_TAKEN} ({e})"));
        }
        if let Some(store) = store {
            let sealed: Vec<Sealed> = joins.tokens.values().map(|j| j.sealed.clone()).collect();
            let res = store.update(|s| {
                s.k3s_tokens = sealed;
                Ok(())
            });
            if let Err(e) = res {
                problems.push(format!("cannot leave the join tokens in the registry: {e}"));
            }
        }
        let mut alarms: Vec<String> = taken
            .iter()
            .map(|(name, t)| {
                format!(
                    "ALARM: the name {name} is taken in the cluster since {}: {}. That machine had a join token (most likely a \
                     server that had not joined yet: find out which; or one of an older dryserver with the shared agent token, \
                     README: A new cluster token), and k3s gave it a certificate for {name}, good for a year. \
                     No server gets a join token for {name}, and a node under it is deleted at every sync. To have a server under \
                     that name in the cluster, remove it in dryserver approve and install it again under another name",
                    day(t.since),
                    t.why
                )
            })
            .collect();
        alarms.extend(gone.iter().map(|name| {
            format!(
                "{name} was in the cluster and its node is gone. It gets no new join token: with one, a hacked server could leave \
                 the cluster and take another server's name. It comes back by itself when k3s starts again on it (its \
                 certificate is good for its own name); if it does not, remove it in dryserver approve, run sudo dryserver join \
                 on it and approve it again"
            )
        }));
        self.alarm(ctx, NAMES_ISSUE, (!alarms.is_empty()).then(|| alarms.join("\n\n")).as_deref());
        if let Some(warning) = self.k3s_shared(ctx, shared) {
            problems.insert(0, warning);
        }
        problems.splice(0..0, alarms);
        let status = if problems.is_empty() {
            format!("{} servers wait to join the cluster, each with a token of its own", joins.tokens.len())
        } else {
            problems.join("; ")
        };
        self.note(K3S_SHARE_STATUS, &format!("k3s: {status}"), &status);
    }

    /// Signs this machine's report, as member host, with its host key:
    /// the registry account relays it, to root on the coordinator and to
    /// the admin. Unsigned when that fails, which is logged once.
    fn sign_report(&self, ctx: &Ctx, host: u32, r: &mut Report) {
        match self.read(WG_PUB).and_then(|wg| r.sign(ctx, self.run.as_ref(), &self.path(HOST_KEY), host, &wg)) {
            Ok(()) => self.note(REPORT_STATUS, "report: signed", ""),
            Err(e) => self.note(REPORT_STATUS, &format!("report: sent unsigned: {e}"), &e.to_string()),
        };
    }

    /// On the coordinator, once its mesh follows the list in SIGNED_FILE:
    /// a receipt for that list in the registry, signed with its host key
    /// (registry::Receipt). Made again when the list changed or the last
    /// one is RECEIPT_EVERY old.
    fn receipt(&self, ctx: &Ctx, store: &Store, now: i64) {
        let Ok(Some((version, env))) = self.seen_list() else { return };
        let sha = fsx::hex(&sha2::Sha256::digest(env.doc.as_bytes()));
        let had = store.read().map(|s| s.receipt).unwrap_or_default();
        if had.version == version && had.sha256 == sha && (0..RECEIPT_EVERY).contains(&(now - had.time)) {
            return;
        }
        let text = registry::Receipt::text(version, &sha, now);
        let sig = match signed::host_sign(ctx, self.run.as_ref(), &self.path(HOST_KEY), signed::NS_RECEIPT, &text) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("dryserver: cannot sign the receipt for list version {version}: {e}");
                return;
            }
        };
        let r = registry::Receipt { version, sha256: sha, time: now, sig };
        if let Err(e) = store.update(|s| {
            s.receipt = r;
            Ok(())
        }) {
            eprintln!("dryserver: cannot leave the receipt for list version {version} in the registry: {e}");
        }
    }

    /// On the coordinator, for the rollout: members with only the reports
    /// they signed themselves (report::Report::verify, with their keys in
    /// the list the admin signed). The registry account relays them and
    /// could have a server pass for updated. A report that is not signed by
    /// its server, older than one taken before or than REPORT_MAX_AGE, or
    /// unsigned from a release that signs (ReportCheck::since) is none: the
    /// rollout waits for that server. own: this coordinator's report.
    fn trusted_reports(&self, ctx: &Ctx, members: Vec<Member>, own: &Report, now: i64) -> Vec<Member> {
        let was: Option<ReportCheck> = serde_json::from_str(&fsx::read_or_empty(self.path(SIGNED_REPORTS))).ok();
        let mut check = was.clone().unwrap_or(ReportCheck { since: own.release.max(1), ..ReportCheck::default() });
        let tmp = self.tmp_dir.clone().unwrap_or_else(|| PathBuf::from("/run"));
        let mut refused = Vec::new();
        let mut out = Vec::new();
        for mut m in members {
            let Some(r) = m.report.take().filter(|_| m.host >= 2) else {
                out.push(m);
                continue;
            };
            let why = if r.sig.is_empty() {
                (r.release >= check.since)
                    .then(|| format!("unsigned, though it says it runs release {} (from {} on reports are signed)", r.release, check.since))
            } else if let Err(e) = r.verify(ctx, self.run.as_ref(), &tmp, m.host, &m.wg_key, &m.ssh_host_key) {
                Some(format!("not signed by it ({e})"))
            } else if check.seen.get(&m.host).is_some_and(|(k, t)| *k == m.wg_key && r.time < *t) {
                Some("older than one it sent before".to_string())
            } else if now - r.time > REPORT_MAX_AGE {
                Some("more than a day old".to_string())
            } else {
                check.seen.insert(m.host, (m.wg_key.clone(), r.time));
                None
            };
            match why {
                Some(why) => refused.push(format!("{}: {why}", m.name)),
                None => m.report = Some(r),
            }
            out.push(m);
        }
        check.seen.retain(|h, (k, _)| out.iter().any(|m| m.host == *h && m.wg_key == *k));
        if was.as_ref() != Some(&check)
            && let Ok(text) = serde_json::to_string(&check)
        {
            let _ = self.write(SIGNED_REPORTS, 0o600, &(text + "\n"));
        }
        let status = refused.join("; ");
        let line = if status.is_empty() {
            "reports: every server's report checks out".to_string()
        } else {
            format!("reports not taken (the rollout waits for those servers): {status}")
        };
        self.note(REPORTS_STATUS, &line, &status);
        out
    }

    /// The node-password secrets in the cluster (k3s's, in kube-system).
    fn k3s_passwords(&self, ctx: &Ctx) -> Result<Passwords> {
        let selector = format!("type={}", k3stoken::PASSWORD_TYPE);
        let cmd = Cmd::new("k3s", &["kubectl", "get", "secrets", "-n", "kube-system", "--field-selector", &selector, "-o", "json"])
            .quiet()
            .stdout_only();
        let out = self.run.output(ctx, &cmd)?;
        let v: serde_json::Value = serde_json::from_str(&out).map_err(|e| Error::from(e).wrap("k3s's list of node passwords"))?;
        let items = v["items"].as_array().ok_or_else(|| Error::new("k3s's list of node passwords has no items"))?;
        let mut found = Passwords::new();
        for item in items {
            let meta = &item["metadata"];
            let Some(name) = meta["name"].as_str().and_then(|n| n.strip_suffix(k3stoken::PASSWORD_SECRET)) else {
                continue;
            };
            found.insert(name.to_string(), meta["annotations"][PASSWORD_MARK].as_str().map(str::to_string));
        }
        Ok(found)
    }

    /// Puts the hash of password into the cluster as the node password of
    /// name, marked as root's, with a finalizer that keeps it there until
    /// root removes it (k3s removes one without a node after ten minutes).
    /// Fails when the name has one already.
    fn k3s_password_make(&self, ctx: &Ctx, name: &str, password: &str) -> Result<()> {
        let hash = base64::engine::general_purpose::STANDARD.encode(k3stoken::password_hash(password));
        let secret = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": k3stoken::password_secret(name),
                "namespace": "kube-system",
                "annotations": { PASSWORD_MARK: stamp(password) },
                "finalizers": [PASSWORD_MARK],
            },
            "type": k3stoken::PASSWORD_TYPE,
            "data": { "hash": hash },
        });
        self.run.output(ctx, &Cmd::new("k3s", &["kubectl", "create", "-f", "-"]).stdin(secret.to_string()).quiet()).map(drop)
    }

    /// Removes the node password the cluster keeps for name, root's or
    /// k3s's; whether it is gone. passwords: what k3s listed (nothing to
    /// do for a name it did not list), kept up to date.
    fn k3s_password_drop(&self, ctx: &Ctx, name: &str, passwords: &mut Option<Passwords>) -> bool {
        if passwords.as_ref().is_some_and(|p| !p.contains_key(name)) {
            return true;
        }
        let secret = k3stoken::password_secret(name);
        let gone = |(out, res): (String, Result<()>)| match res {
            Ok(()) => true,
            Err(e) => [out, e.to_string()].iter().any(|t| t.contains("NotFound") || t.contains("not found")),
        };
        let free = Cmd::new(
            "k3s",
            &["kubectl", "patch", "secret", &secret, "-n", "kube-system", "--type=merge", "-p", r#"{"metadata":{"finalizers":null}}"#],
        );
        let delete = Cmd::new("k3s", &["kubectl", "delete", "secret", &secret, "-n", "kube-system", "--ignore-not-found", "--wait=false"]);
        let done = gone(self.run.run(ctx, &free.quiet())) && self.run.run(ctx, &delete.quiet()).1.is_ok();
        if done && let Some(p) = passwords.as_mut() {
            p.remove(name);
        }
        done
    }

    /// Whether servers hold the shared agent token (K3S_SHARED, or the
    /// record of an older version that sealed it for them).
    fn k3s_shared_in_use(&self) -> bool {
        let token = fsx::read_or_empty(self.path(K3S_AGENT_TOKEN)).trim().to_string();
        let digest = fsx::hex(&sha2::Sha256::digest(token.as_bytes()));
        std::fs::symlink_metadata(self.path(K3S_SEALED)).is_ok()
            || (!token.is_empty() && fsx::read_or_empty(self.path(K3S_SHARED)).trim() == digest)
    }

    /// Makes a join token for member m (SSH host key key) and seals it
    /// with its node password.
    fn k3s_mint(&self, ctx: &Ctx, m: &Member, key: &str, coord: &str, password: &str, now: i64) -> Result<Join> {
        let ttl = format!("{JOIN_TOKEN_TTL}s");
        let what = format!("dryserver: {} joins the cluster", m.name);
        // Its output is the token: never logged.
        let cmd = Cmd::new("k3s", &["token", "create", "--ttl", &ttl, "--description", &what]).quiet().stdout_only();
        let out = self.run.output(ctx, &cmd).map_err(|e| e.wrap("k3s token create"))?;
        let token = out.trim();
        let Some(id) = k3stoken::bootstrap_id(token).filter(|_| k3stoken::problem(token).is_none()).map(str::to_string) else {
            return Err("k3s token create made no bootstrap token this version takes".into());
        };
        match k3stoken::seal(ctx, self.run.as_ref(), token, password, m.host, key, &self.path(HOST_KEY)) {
            Ok(sealed) => Ok(Join {
                name: m.name.clone(),
                wg_key: m.wg_key.clone(),
                coord: coord.into(),
                id,
                expires: now + JOIN_TOKEN_TTL,
                password: password.into(),
                sealed,
            }),
            Err(e) => {
                self.k3s_unmint(ctx, &id);
                Err(e)
            }
        }
    }

    /// Deletes the join token id; whether it is gone.
    fn k3s_unmint(&self, ctx: &Ctx, id: &str) -> bool {
        match self.run.run(ctx, &Cmd::new("k3s", &["token", "delete", id]).quiet()) {
            (_, Ok(())) => true,
            (out, Err(e)) => out.contains("not found") || e.to_string().contains("not found"),
        }
    }

    /// Whether servers hold the cluster's shared agent token (K3S_SHARED),
    /// as a warning for the status line and the console, none when they do
    /// not. shared: this sync found that some do. Making a new token
    /// (README) ends it.
    fn k3s_shared(&self, ctx: &Ctx, shared: bool) -> Option<String> {
        let token = fsx::read_or_empty(self.path(K3S_AGENT_TOKEN)).trim().to_string();
        let digest = (!token.is_empty()).then(|| fsx::hex(&sha2::Sha256::digest(token.as_bytes())));
        let mut recorded = fsx::read_or_empty(self.path(K3S_SHARED)).trim().to_string();
        if shared
            && let Some(d) = &digest
            && *d != recorded
            && self.write(K3S_SHARED, 0o600, &format!("{d}\n")).is_ok()
        {
            recorded = d.clone();
        }
        if !recorded.is_empty() {
            // What the older version left is in K3S_SHARED now.
            let _ = std::fs::remove_file(self.path(K3S_SEALED));
        }
        let warning = match &digest {
            Some(d) if *d == recorded => Some(
                "WARNING: servers that joined the cluster before hold its shared agent token (an older dryserver handed it out): \
                 any of them could register a node under the name of a server you approve next. Make a new one \
                 (README: A new cluster token)"
                    .to_string(),
            ),
            _ => {
                if !recorded.is_empty() {
                    let _ = std::fs::remove_file(self.path(K3S_SHARED));
                }
                None
            }
        };
        self.alarm(ctx, SHARED_ISSUE, warning.as_deref());
        warning
    }

    /// Shows text on this machine's console login screen in its own file,
    /// or takes it away (None). On the coordinator, for what the admin must
    /// see even when the registry account hides it from the approval
    /// screen.
    fn alarm(&self, ctx: &Ctx, file: &str, text: Option<&str>) {
        let want = text.map(|t| format!("\ndryserver: {t}\n\n")).unwrap_or_default();
        if fsx::read_or_empty(self.path(file)) == want {
            return;
        }
        let _ = match text {
            Some(_) => self.write(file, 0o644, &want),
            None => std::fs::remove_file(self.path(file)).map_err(Error::from),
        };
        let _ = self.cmd(ctx, "agetty", &["--reload"]);
    }

    /// The newest signed list this machine has verified, with its version;
    /// None when it has none. A file that cannot be read is an error, not
    /// none: taken for none, any older list would pass as new and bring
    /// back a machine the admin removed.
    pub fn seen_list(&self) -> Result<Option<(u64, Envelope)>> {
        let damaged = |e: String| {
            errf!(
                "{SIGNED_FILE} is damaged ({e}). It holds the newest member list this machine has seen, so no list is \
                 taken until it is put right; remove it to take the coordinator's list as it comes"
            )
        };
        match std::fs::read(self.path(SIGNED_FILE)) {
            Ok(b) => {
                let env: Envelope = serde_json::from_slice(&b).map_err(|e| damaged(e.to_string()))?;
                let list: signed::List = serde_json::from_str(&env.doc).map_err(|e| damaged(e.to_string()))?;
                Ok(Some((list.version, env)))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::from(e).wrap(format!("read {SIGNED_FILE}"))),
        }
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
        let seen = self.seen_list()?;
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

    /// On the coordinator, when the registry cannot be used (why): the
    /// members of the newest list it has seen (SIGNED_FILE), with an alarm
    /// on its console.
    ///
    /// The registry account owns the registry file and its lock: it can
    /// hold the lock, write more than is ever read, drop the signed list or
    /// put back an older one. That stalls what goes through the registry
    /// (servers get no newer list, no new join token, the rollout waits),
    /// not the admin's decisions root already has: a server the admin
    /// removed stays out of this coordinator's mesh and out of the cluster.
    /// Its own file only ever holds a list checked when it was saved, and is
    /// checked again here.
    ///
    /// The error returned with the members says what happened, for the
    /// sync's exit. With no list of its own that holds this coordinator,
    /// or one it cannot read, nothing is applied: Err.
    fn own_list(&self, ctx: &Ctx, why: Error) -> Result<(Vec<Member>, Error)> {
        let own = self.seen_list().and_then(|seen| {
            let (ver, env) = seen.ok_or_else(|| Error::new("this coordinator has seen no signed list"))?;
            let list = env.list(self.verifier.as_ref(), |h| self.fits(h))?;
            if !list.members.iter().any(|e| self.is_me(1, e)) {
                return Err(errf!("its list (version {ver}) does not hold this coordinator"));
            }
            Ok((ver, list))
        });
        let (ver, list) = match own {
            Ok(own) => own,
            Err(e) => {
                self.note_signed(&format!("REFUSED, mesh and cluster left as they are: {why} ({e})"));
                self.alarm(ctx, REGISTRY_ISSUE, Some(&format!("ALARM: {why}. The mesh and the cluster are left as they are ({e}).")));
                return Err(why.wrap("the registry's member list refused, mesh and cluster left as they are"));
            }
        };
        self.note_signed(&format!(
            "REFUSED, the mesh and the cluster follow the newest list this coordinator has seen (version {ver}) instead: {why}"
        ));
        self.alarm(
            ctx,
            REGISTRY_ISSUE,
            Some(&format!(
                "ALARM: {why}.\nThe mesh and the cluster follow the newest member list this coordinator has seen (version \
                 {ver}). Servers get no newer list and no new join tokens, and updates wait. The registry account ({}) may be \
                 broken into; if you removed a server and it still runs: dryserver quarantine-all -name NAME",
                sysconf::REGISTRY_USER
            )),
        );
        let members = list
            .members
            .iter()
            .map(|e| Member {
                host: e.host,
                name: e.name.clone(),
                wg_key: e.wg_key.clone(),
                ssh_host_key: e.ssh_host_key.clone(),
                ..Member::default()
            })
            .collect();
        Ok((
            members,
            why.wrap(format!("the registry's member list refused; the mesh and the cluster follow version {ver} from {SIGNED_FILE}")),
        ))
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
        for f in [sysconf::K3S_TOKEN, sysconf::K3S_CONFIG, sysconf::K3S_NODE_PASSWORD] {
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

    /// On a server with a cable link (auto mode): which peers it reaches on
    /// the switch. Each peer's switch address gets one ping, all at once,
    /// and the answer decides, not the peer's word in the list: the
    /// registry account keeps that list, and saying "no cable" for every
    /// machine would move every link to a LAN address of its choosing. A
    /// peer that does not answer is reached over the WiFi/router path (a
    /// cable into the router instead of the switch, a pulled cable).
    ///
    /// The coordinator dials nobody (mesh::endpoint) and pings nothing.
    fn check_switch(&self, ctx: &Ctx, me: SelfInfo, members: &[Member]) -> Vec<Member> {
        let mut out = members.to_vec();
        if me.host == 1 || !me.switch || self.cfg.wg_transport != config::TRANSPORT_AUTO {
            return out;
        }
        let run = self.run.as_ref();
        let answers: Vec<bool> = std::thread::scope(|s| {
            let pings: Vec<_> = out
                .iter()
                .map(|m| {
                    let addr = mesh::ip(&self.cfg.switch_subnet, m.host);
                    let mine = m.host == me.host;
                    s.spawn(move || !mine && !addr.is_empty() && run.ok(ctx, &Cmd::new("ping", &["-c", "1", "-W", "1", &addr])).is_ok())
                })
                .collect();
            pings.into_iter().map(|p| p.join().unwrap_or(false)).collect()
        });
        for (m, up) in out.iter_mut().zip(answers) {
            m.switch = up;
        }
        out
    }

    /// On a server whose sync did not reach the coordinator over the mesh:
    /// points WireGuard at the coordinator where this server's own config
    /// says it is (mesh::endpoint, after a ping of its switch address), if
    /// it sends anywhere else. That needs nothing from the coordinator, so
    /// a link that went wrong (a pulled cable, an approval that named the
    /// wrong path) comes back without a member list, which only that link
    /// brings. Only a peer that is there: one a cut took out stays out.
    fn mend_coordinator(&self, ctx: &Ctx, me: SelfInfo) {
        let Ok(Some((_, env))) = self.seen_list() else { return };
        let Ok(list) = env.list(self.verifier.as_ref(), |h| self.fits(h)) else { return };
        let Some(coord) = list.members.iter().find(|e| e.host == 1) else { return };
        let peer = Member { host: 1, name: coord.name.clone(), wg_key: coord.wg_key.clone(), switch: true, ..Member::default() };
        let Some(peer) = self.check_switch(ctx, me, &[peer]).pop() else { return };
        let want = mesh::endpoint(&self.cfg, me, &peer);
        let Ok(_lock) = fsx::lock(self.path(quarantine::MESH_LOCK)) else { return };
        if want.is_empty() || !quarantine::load(self).is_ok_and(|q| !q.coordinator_cut()) {
            return;
        }
        let endpoints = self.run.output(ctx, &Cmd::new("wg", &["show", "wg0", "endpoints"]).quiet().stdout_only()).unwrap_or_default();
        let Some(now) = endpoints.lines().find_map(|l| l.split_once(char::is_whitespace).filter(|(k, _)| *k == peer.wg_key)) else {
            return;
        };
        let now = now.1.trim();
        if now != want && self.cmd(ctx, "wg", &["set", "wg0", "peer", &peer.wg_key, "endpoint", &want]).is_ok() {
            eprintln!("dryserver: sync: the coordinator does not answer over the mesh; WireGuard sends to it at {want} now (was {now})");
        }
    }

    /// On a server: what WireGuard knows of each peer now (mesh::live_peers);
    /// nothing when wg0 is down or wg cannot tell.
    fn live_links(&self, ctx: &Ctx) -> BTreeMap<String, mesh::Live> {
        let wg = |what: &str| self.run.output(ctx, &Cmd::new("wg", &["show", "wg0", what]).quiet().stdout_only()).unwrap_or_default();
        let endpoints = wg("endpoints");
        if endpoints.trim().is_empty() {
            return BTreeMap::new();
        }
        mesh::live_peers(&endpoints, &wg("latest-handshakes"))
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

/// How often join_loop asks: a waiting request, a request that did not go
/// out, and after any other failure.
struct Pace {
    poll: Duration,
    retry: Duration,
    pause: Duration,
}

/// Runs at boot on a server that is not approved yet: sends (or resumes) a
/// join request, shows the pairing code on the console and waits. On
/// approval it brings up the mesh and disables itself.
pub fn join_loop(ctx: &Ctx, n: &Node, params: &Params, log: &mut dyn Write) -> Result<()> {
    let pace = Pace { poll: JOIN_POLL, retry: Duration::from_secs(30), pause: Duration::from_secs(10) };
    joining(ctx, n, params, log, &pace)
}

fn joining(ctx: &Ctx, n: &Node, params: &Params, log: &mut dyn Write, pace: &Pace) -> Result<()> {
    match n.read_state() {
        Ok(Some(s)) if s.host > 0 => return n.cmd(ctx, "systemctl", &["disable", "dryserver-join.service"]),
        Ok(_) => {}
        // A damaged join.json may belong to a member: a new request would
        // write over the one record of its mesh number.
        Err(e) => {
            return Err(errf!(
                "{e}: not asking to join, it may hold this server's mesh number. Put it back ({{\"host\": N}}), \
                 or remove it to ask to join as a new machine"
            ));
        }
    }
    let mut show = |msg: &str| {
        let _ = writeln!(log, "{msg}");
        let _ = n.write(ISSUE_FILE, 0o644, &format!("\n{msg}\n\n"));
        let _ = n.cmd(ctx, "agetty", &["--reload"]);
    };
    // Why the code changed, shown with the next one.
    let mut forgot = String::new();
    // Requests in a row that failed on the coordinator's host key.
    let mut other_key = 0;
    loop {
        if quarantine::blocks_join(n) {
            show("dryserver: quarantined, the coordinator is cut off: not joining.\nUndo with: sudo dryserver quarantine -lift");
            return Ok(());
        }
        let mut st = n.load_state();
        if st.request_id.is_empty() {
            let sent = local_ip(ctx, n.run.as_ref(), &n.cfg.coord_lan_ip).and_then(|lan| n.request(ctx, &lan, port_link(&n.switch_mac())));
            match sent {
                Ok(code) => {
                    other_key = 0;
                    st.code = code;
                }
                Err(e) => {
                    other_key = if host_key_failed(&e) { other_key + 1 } else { 0 };
                    if other_key >= HOST_KEY_TRIES {
                        // The key was pinned by an earlier request (or an
                        // approval before a removal) and the machine there
                        // now has another: ask again from the start.
                        other_key = 0;
                        forgot = forget(n, &n.other_key())?;
                        continue;
                    }
                    if e.to_string().starts_with(REFUSED) {
                        show(&format!("dryserver: {e}"));
                    } else {
                        show(&format!("dryserver: cannot reach the coordinator at {} yet, retrying: {e}", n.cfg.coord_lan_ip));
                    }
                    ctx.sleep(pace.retry)?;
                    continue;
                }
            }
        }
        show(&format!(
            "{forgot}dryserver: waiting for approval. On your own computer run: dryserver approve\n\
             Approve only if it shows this code:  {}",
            st.code
        ));
        match n.wait(ctx, pace.poll) {
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
            Err(e) if e.is(Kind::HostKey) => forgot = forget(n, &e)?,
            Err(_) if ctx.done() => return Err(ctx.err().unwrap()),
            Err(_) => ctx.sleep(pace.pause)?,
        }
    }
}

/// Forgets the coordinator's pinned key and the join request after why
/// (Node::forget_coordinator); returns what the console says about it,
/// above the new code.
fn forget(n: &Node, why: &Error) -> Result<String> {
    n.forget_coordinator().map_err(|e| e.wrap(format!("{why}; cannot ask again")))?;
    eprintln!("dryserver: {why}: forgot that key and asked again with a new code");
    Ok(format!("dryserver: {why}.\nThis machine forgot that key and asked again: only the code below counts.\n\n"))
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
    let (mut sealed, mut plain) = (None, false);
    let mut offer = rollout::Offer::default();
    // On the coordinator: its members are the admin's signed list.
    let mut signed = false;
    // What this machine says about itself, its update included. Kept for
    // the update step after the mesh: it is this sync's health.
    let rep;
    // On the coordinator: why the registry could not be used this time;
    // then the mesh and the cluster follow its own newest list.
    let mut alone: Option<Error> = None;
    let members = if coordinator {
        me.host = 1;
        let mut r = n.full_report(ctx, true);
        r.lan = n.cfg.coord_lan_ip.clone();
        n.sign_report(ctx, 1, &mut r);
        rep = r;
        let hb = Heartbeat { lan_ip: n.cfg.coord_lan_ip.clone(), switch: sw, cuts, report: Some(rep.clone()) };
        let read = store.update(|s| {
            s.heartbeat(1, hb, Time::now())?;
            Ok((s.members.clone(), s.signed.clone()))
        });
        // The registry account writes that file: what it holds reaches the
        // mesh files and the cluster only checked, like a server checks
        // what the coordinator sends. Its fields first, then who is in:
        // exactly the list the admin signed, no older than one this
        // coordinator has seen. Its other entries are only taken for
        // addresses. A registry account that lists a machine of its own,
        // or drops members, changes neither the mesh nor the cluster.
        let checked = match read {
            Err(e) => Err(e.wrap(format!("cannot use the registry {}", store.path.display()))),
            Ok((members, env)) => {
                let (members, problems) = registry::check_members(members, |h| !mesh::ip(&n.cfg.wg_subnet, h).is_empty());
                for p in &problems {
                    eprintln!("dryserver: sync: ignoring {p}");
                }
                if env.is_empty() && std::fs::symlink_metadata(n.path(SIGNED_FILE)).is_err() {
                    // Nothing signed yet: nobody joins without the admin, so
                    // the coordinator is alone in its mesh, and in its
                    // cluster.
                    Ok((members.into_iter().filter(|m| m.host == 1).collect(), None))
                } else if env.is_empty() {
                    Err(errf!("the registry holds no signed member list, although this coordinator has seen one ({SIGNED_FILE})"))
                } else {
                    n.signed_members(1, &members, &env).map(|(m, status)| (m, Some(status)))
                }
            }
        };
        match checked {
            Ok((members, None)) => members,
            Ok((members, Some(status))) => {
                n.note_signed(&status);
                signed = true;
                n.alarm(ctx, REGISTRY_ISSUE, None);
                // Signed by the admin: the code on the console has done
                // its job.
                if n.path(ISSUE_FILE).exists() {
                    let _ = std::fs::remove_file(n.path(ISSUE_FILE));
                    let _ = n.cmd(ctx, "agetty", &["--reload"]);
                }
                members
            }
            Err(e) => {
                let (members, why) = n.own_list(ctx, e)?;
                signed = true;
                alone = Some(why);
                members
            }
        }
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
        let mut r = n.full_report(ctx, false);
        r.lan = lan.clone();
        n.sign_report(ctx, host, &mut r);
        rep = r;
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
                n.mend_coordinator(ctx, me);
                return Err(e);
            }
        };
        let Fetched { members: sent, signed: env, k3s_sealed, k3s_plain, release } = fetched;
        (sealed, plain) = (k3s_sealed, k3s_plain);
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
    // The switch pings take up to a second: before the lock, so a cut
    // never waits for them.
    let members = n.check_switch(ctx, me, &members);
    let live = if coordinator { BTreeMap::new() } else { n.live_links(ctx) };
    // Check again under the lock: a cut may have landed while fetching.
    let _lock = fsx::lock(n.path(quarantine::MESH_LOCK))?;
    let q = quarantine::load(n)?;
    if !coordinator && q.coordinator_cut() {
        return Ok(false);
    }
    let all = members;
    let members: Vec<Member> = all.iter().filter(|m| m.host == me.host || !q.blocks(m)).cloned().collect();
    n.apply_live(me, &members, &live, Time::now().0.timestamp())?;
    n.reload_wg(ctx)?;
    drop(_lock);
    // The cluster follows the mesh: the coordinator seals the token for
    // each server and drops machines that left; a server joins once it
    // has a token sealed for it by the coordinator the admin signed.
    if coordinator {
        // Only from a list the admin signed does a machine leave the
        // cluster. Before the first one there is nobody but the
        // coordinator, and nobody to share the token with.
        if signed && alone.is_none() {
            n.receipt(ctx, store, Time::now().0.timestamp());
        }
        if signed {
            n.k3s_share(ctx, alone.is_none().then_some(store), &all, Time::now().0.timestamp());
        }
        if let Some(why) = alone {
            // The rollout lives in the registry: it waits.
            return Err(why);
        }
        // The rollout of the newest release: the coordinator first, then
        // one server at a time, among the members the admin signed. What
        // each says about its update counts only signed by it.
        let all = n.trusted_reports(ctx, all, &rep, Time::now().0.timestamp());
        let served = rollout::Served::beside(store, n.path(rollout::K3S_BIN));
        rollout::brain_tick(ctx, n, store, &served, &rep, rollout::Now::current(), &all);
    } else {
        let coord_key = all.iter().find(|m| m.host == 1).map(|m| m.ssh_host_key.clone()).unwrap_or_default();
        n.k3s_take(ctx, me.host, &coord_key, sealed.as_ref(), plain);
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

    /// A token for agents, and another one (after a rotation).
    const TOKEN: &str = k3stoken::fake::TOKEN;
    const TOKEN2: &str = "K10f3a1c0d9e8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1::node:fedcba9876543210fedcba9876543210";

    /// The token the coordinator sealed for node-a as host.
    fn sealed_for(host: u32, token: &str) -> Sealed {
        k3stoken::fake::sealed(COORD_KEY, host, &signed::key_body(NODE_KEY), token)
    }

    /// A "peers" reply to node-a as host: the coordinator and node-a,
    /// signed as version, and the sealed token sent with it.
    fn peers_sealed(host: u32, version: u64, sealed: Option<&Sealed>) -> String {
        let env = sign(&ADMIN, version, vec![coord_entry(), node_entry(host)]);
        serde_json::json!({ "members": [coord_member(), node_member(host)], "signed": env, "k3s_sealed": sealed }).to_string()
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
        /// age and ssh-keygen calls (k3stoken::fake answers them).
        crypto: Mutex<Vec<Cmd>>,
        /// age is not installed.
        no_age: Mutex<bool>,
        /// `wg show wg0 endpoints` and `latest-handshakes`.
        live: Mutex<(String, String)>,
        /// Switch addresses that answer a ping; None: every one.
        answers: Mutex<Option<Vec<String>>>,
        /// How the next registry calls fail: "down" times out, "key" meets
        /// another host key.
        script: Mutex<Vec<&'static str>>,
        /// The coordinator's k3s.
        cluster: Mutex<Cluster>,
    }

    /// A node password k3s keeps (k3stoken::password_secret).
    #[derive(Debug, Clone, PartialEq)]
    struct Pass {
        /// Root's mark; none on one k3s made from an agent's password.
        mark: Option<String>,
        hash: String,
        finalizer: bool,
    }

    /// What k3s on the coordinator answers.
    struct Cluster {
        /// `kubectl get nodes -o name`; by default the coordinator, one
        /// machine that is no longer a member, and junk.
        nodes: String,
        /// The node passwords, by node name.
        passwords: BTreeMap<String, Pass>,
        /// k3s does not list them.
        list_fails: bool,
        /// k3s does not answer.
        down: bool,
        create_fails: bool,
        delete_fails: bool,
        /// Join tokens made so far; the deleted and the not deleted ids.
        made: u32,
        deleted: Vec<String>,
        failed: Vec<String>,
    }

    impl Default for Cluster {
        fn default() -> Cluster {
            Cluster {
                nodes: "node/coord\nnode/ghost\nnode/bad name\n".into(),
                passwords: BTreeMap::new(),
                list_fails: false,
                down: false,
                create_fails: false,
                delete_fails: false,
                made: 0,
                deleted: Vec::new(),
                failed: Vec::new(),
            }
        }
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
                crypto: Mutex::new(Vec::new()),
                no_age: Mutex::new(false),
                live: Mutex::new((String::new(), String::new())),
                answers: Mutex::new(None),
                script: Mutex::new(Vec::new()),
                cluster: Mutex::new(Cluster::default()),
            })
        }

        /// The age calls since the last look.
        fn ages(&self) -> usize {
            self.crypto.lock().unwrap().drain(..).filter(|c| c.name == "age").count()
        }

        /// An agent asks the coordinator's k3s for a certificate as name
        /// with password, then registers its node: k3s's node-password
        /// check (nodepassword.ensure). Whether it got in.
        fn agent(&self, name: &str, password: &str) -> bool {
            let mut k = self.cluster.lock().unwrap();
            match k.passwords.get(name) {
                Some(p) if !k3stoken::hash_matches(&p.hash, password) => return false,
                Some(_) => {}
                None => {
                    let hash = k3stoken::password_hash(password);
                    k.passwords.insert(name.into(), Pass { mark: None, hash, finalizer: false });
                }
            }
            if !k.nodes.lines().any(|l| l == format!("node/{name}")) {
                k.nodes += &format!("node/{name}\n");
            }
            true
        }

        /// The node password root sealed for host (from the coordinator's
        /// K3S_JOIN).
        fn sealed_password(root: &Path, host: u32) -> String {
            let joins: serde_json::Value = serde_json::from_str(&get(root, K3S_JOIN)).unwrap();
            joins["tokens"][host.to_string()]["password"].as_str().unwrap().to_string()
        }

        /// systemctl calls for k3s.service other than is-active.
        fn k3s_moves(&self) -> Vec<String> {
            self.ran.lock().unwrap().iter().filter(|c| c.ends_with("k3s.service") && !c.contains("is-active")).cloned().collect()
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
                "ping" => {
                    let up = self.answers.lock().unwrap().as_ref().is_none_or(|a| a.contains(c.args.last().unwrap()));
                    self.ran.lock().unwrap().push(format!("ping {}", c.args.last().unwrap()));
                    return (String::new(), if up { Ok(()) } else { Err("ping failed: exit status 1".into()) });
                }
                "ip" if c.args.iter().any(|a| a == "get") => return (r#"[{"prefsrc":"192.168.1.23"}]"#.into(), Ok(())),
                "ip" | "agetty" | "networkctl" => return (String::new(), Ok(())),
                // No blocked members in the firewall's set.
                "nft" => return (String::new(), Err("no such set".into())),
                "k3s" => {
                    self.k3s.lock().unwrap().push(c.args.join(" "));
                    let k = self.cluster.lock().unwrap();
                    if k.down {
                        return (String::new(), Err("k3s failed: exit status 1: The connection to the server was refused".into()));
                    }
                    drop(k);
                    let args: Vec<&str> = c.args.iter().map(String::as_str).collect();
                    let mut k = self.cluster.lock().unwrap();
                    let fail = |m: &str| (String::new(), Err(Error::new(format!("k3s failed: exit status 1: {m}"))));
                    return match args.as_slice() {
                        [
                            "kubectl",
                            "get",
                            "secrets",
                            "-n",
                            "kube-system",
                            "--field-selector",
                            "type=k3s.cattle.io/node-password",
                            "-o",
                            "json",
                        ] => {
                            if k.list_fails {
                                return fail("Unable to connect to the server");
                            }
                            let items: Vec<serde_json::Value> = k
                                .passwords
                                .iter()
                                .map(|(name, p)| {
                                    let mut meta =
                                        serde_json::json!({ "name": k3stoken::password_secret(name), "namespace": "kube-system" });
                                    if let Some(m) = &p.mark {
                                        meta["annotations"] = serde_json::json!({ PASSWORD_MARK: m });
                                    }
                                    if p.finalizer {
                                        meta["finalizers"] = serde_json::json!([PASSWORD_MARK]);
                                    }
                                    serde_json::json!({ "metadata": meta, "type": k3stoken::PASSWORD_TYPE, "data": { "hash": "x" } })
                                })
                                .collect();
                            (serde_json::json!({ "kind": "List", "items": items }).to_string(), Ok(()))
                        }
                        ["kubectl", "get", "nodes", ..] => (k.nodes.clone(), Ok(())),
                        ["kubectl", "create", "-f", "-"] => {
                            let s: serde_json::Value = serde_json::from_str(&c.stdin).unwrap();
                            let secret = s["metadata"]["name"].as_str().unwrap();
                            let name = secret.strip_suffix(k3stoken::PASSWORD_SECRET).unwrap().to_string();
                            assert_eq!(
                                (s["type"].as_str(), s["metadata"]["namespace"].as_str()),
                                (Some(k3stoken::PASSWORD_TYPE), Some("kube-system"))
                            );
                            if k.passwords.contains_key(&name) {
                                return fail(&format!("Error from server (AlreadyExists): secrets \"{secret}\" already exists"));
                            }
                            let hash =
                                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s["data"]["hash"].as_str().unwrap())
                                    .unwrap();
                            let mark = s["metadata"]["annotations"][PASSWORD_MARK].as_str().map(str::to_string);
                            let finalizer = s["metadata"]["finalizers"][0].as_str() == Some(PASSWORD_MARK);
                            k.passwords.insert(name, Pass { mark, hash: String::from_utf8(hash).unwrap(), finalizer });
                            (format!("secret/{secret} created\n"), Ok(()))
                        }
                        [
                            "kubectl",
                            "patch",
                            "secret",
                            secret,
                            "-n",
                            "kube-system",
                            "--type=merge",
                            "-p",
                            r#"{"metadata":{"finalizers":null}}"#,
                        ] => match k.passwords.get_mut(secret.strip_suffix(k3stoken::PASSWORD_SECRET).unwrap_or(secret)) {
                            Some(p) => {
                                p.finalizer = false;
                                (String::new(), Ok(()))
                            }
                            None => fail(&format!("Error from server (NotFound): secrets \"{secret}\" not found")),
                        },
                        ["kubectl", "delete", "secret", secret, "-n", "kube-system", "--ignore-not-found", "--wait=false"] => {
                            let name = secret.strip_suffix(k3stoken::PASSWORD_SECRET).unwrap_or(secret).to_string();
                            if k.passwords.get(&name).is_some_and(|p| p.finalizer) {
                                // Held by the finalizer: stays.
                                return (String::new(), Ok(()));
                            }
                            k.passwords.remove(&name);
                            (String::new(), Ok(()))
                        }
                        ["kubectl", "delete", "node", name, "--timeout=20s"] => {
                            k.nodes = k.nodes.lines().filter(|l| *l != format!("node/{name}")).map(|l| format!("{l}\n")).collect();
                            (String::new(), Ok(()))
                        }
                        ["token", "create", ..] if k.create_fails => (String::new(), Err("k3s failed: exit status 1".into())),
                        ["token", "create", ..] => {
                            k.made += 1;
                            (format!("{}::tok{:03}.0123456789abcdef\n", &TOKEN[..67], k.made), Ok(()))
                        }
                        ["token", "delete", id] if k.delete_fails => {
                            k.failed.push(id.to_string());
                            (String::new(), Err("k3s failed: exit status 1: etcdserver: request timed out".into()))
                        }
                        ["token", "delete", id] => {
                            k.deleted.push(id.to_string());
                            (format!("bootstrap token {id:?} deleted\n"), Ok(()))
                        }
                        _ => (String::new(), Ok(())),
                    };
                }
                "age" | "ssh-keygen" => {
                    self.crypto.lock().unwrap().push(c.clone());
                    if c.name == "age" && *self.no_age.lock().unwrap() {
                        return (String::new(), Err("exec: \"age\": executable file not found in $PATH".into()));
                    }
                    // A turn root on the coordinator signed (rollout::Grant).
                    if c.args
                        .iter()
                        .any(|a| [crate::signed::NS_TURN, crate::signed::NS_REPORT, crate::signed::NS_RECEIPT].contains(&a.as_str()))
                    {
                        return crate::signed::fake::host_run(c).unwrap_or_else(|| (String::new(), Err("unknown".into())));
                    }
                    return k3stoken::fake::run(c).unwrap_or_else(|| (String::new(), Err("unknown".into())));
                }
                "wg-quick" => return ("[Interface]\nListenPort = 51820\n".into(), Ok(())),
                "wg" if c.args[0] == "syncconf" => {
                    *self.applied.lock().unwrap() = std::fs::read_to_string(&c.args[2]).unwrap_or_default();
                    return (String::new(), Ok(()));
                }
                // The report's look at the links: the coordinator only.
                "wg" if c.args[2] == "allowed-ips" => return (format!("{COORD_WG}\t10.66.0.1/32\n"), Ok(())),
                "wg" if c.args[0] == "set" => {
                    self.ran.lock().unwrap().push(format!("wg {}", c.args.join(" ")));
                    return (String::new(), Ok(()));
                }
                "wg" if c.args[2] == "endpoints" => return (self.live.lock().unwrap().0.clone(), Ok(())),
                "wg" if !self.live.lock().unwrap().1.is_empty() => return (self.live.lock().unwrap().1.clone(), Ok(())),
                "wg" => return (format!("{COORD_WG}\t{}\n", Time::now().0.timestamp() - 7), Ok(())),
                _ => {}
            }
            let cmd = c.args[c.args.len() - 1].clone();
            let host = c.args[c.args.len() - 2].clone();
            self.calls.lock().unwrap().push(format!("{host} {cmd}"));
            let kh = fsx::under(&self.root, KNOWN_HOSTS);
            let pinned = c.args.iter().any(|a| a == "StrictHostKeyChecking=accept-new");
            let next = {
                let mut script = self.script.lock().unwrap();
                if script.is_empty() { "" } else { script.remove(0) }
            };
            match next {
                "down" => {
                    return (
                        String::new(),
                        Err("ssh failed: exit status 255: ssh: connect to host 192.168.1.50 port 22: Connection timed out".into()),
                    );
                }
                "key" => return (String::new(), Err("ssh failed: exit status 255: Host key verification failed.".into())),
                _ => {}
            }
            // A pin of another key than the coordinator's: ssh refuses.
            if pinned && kh.exists() && !fsx::read_or_empty(&kh).contains(COORD_KEY) {
                return (String::new(), Err("ssh failed: exit status 255: Host key verification failed.".into()));
            }
            if !kh.exists() {
                std::fs::write(&kh, format!("{} {COORD_KEY}\n", host.trim_start_matches("dryreg@"))).unwrap();
            }
            // The registry says no: a member has the name, or another
            // machine asks under it.
            let no = |m: &str| (String::new(), Err(Error::new(format!("ssh failed: exit status 1: dryserver: {m}"))));
            match next {
                "member" if cmd == "request" => return no("node-a is already a member; remove it first to re-join"),
                "squat" if cmd == "request" => return no("another machine is already asking to join as node-a"),
                _ => {}
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
        put(root, HOST_KEY, "node-a private\n");
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
        assert!(!f.signed.is_empty() && f.k3s_sealed.is_none() && !f.k3s_plain);
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

    /// The registry account keeps the addresses in the member list. Were
    /// they taken for both ends, it would point the coordinator at a wrong
    /// address for every server and every server at a wrong one for the
    /// coordinator, and wg syncconf would put that back every minute: no
    /// handshake, and with the mesh down no server ever fetches a list
    /// that sets it right.
    #[test]
    fn the_registry_cannot_move_mesh_endpoints() {
        let (_dir, _tmp, n, _fc, _sd, store) = brain();
        let env = sign(&ADMIN, 5, vec![coord_entry(), node_entry(2)]);
        registry(&store, vec![coord_member(), Member { lan_ip: "203.0.113.20".into(), ..node_member(2) }], env.clone());
        sync(&Ctx::new(), &n, true, &store).unwrap();
        let brain_wg = get(&n.root, WG_CONF);
        let (_dir, _tmp, n, fc) = joined();
        *fc.peers.lock().unwrap() =
            Some(peers(&[Member { lan_ip: "203.0.113.50".into(), switch: false, ..coord_member() }, node_member(2)], &env));
        assert!(sync(&Ctx::new(), &n, false, &Store::new("/nonexistent")).unwrap());
        let server_wg = get(&n.root, WG_CONF);
        assert!(
            !brain_wg.contains("203.0.113.20") && !brain_wg.contains("Endpoint") && brain_wg.contains(WG_PUBKEY),
            "--- coordinator\n{brain_wg}"
        );
        assert!(server_wg.contains("Endpoint = 192.168.1.50:51820") && !server_wg.contains("203.0.113.50"), "--- server\n{server_wg}");
    }

    /// A server that does not reach the coordinator over the mesh gets no
    /// list that could set the link right: it sets it from its own config.
    #[test]
    fn a_server_mends_its_link_to_the_coordinator_by_itself() {
        let (_dir, _tmp, n, fc) = joined();
        let store = Store::new("/nonexistent");
        assert!(sync(&Ctx::new(), &n, false, &store).unwrap());
        *fc.mesh_down.lock().unwrap() = true;
        let sets = |fc: &FakeCoord| fc.ran.lock().unwrap().drain(..).filter(|c| c.starts_with("wg set")).collect::<Vec<_>>();
        sets(&fc);
        // Sent to the wrong place (an approval or a list that lied, a cable
        // pulled): the coordinator's address from the config.
        *fc.live.lock().unwrap() = (format!("{COORD_WG}\t203.0.113.50:51820\n"), String::new());
        assert!(sync(&Ctx::new(), &n, false, &store).is_err());
        assert_eq!(sets(&fc), vec![format!("wg set wg0 peer {COORD_WG} endpoint 192.168.1.50:51820")]);
        // Already there, or no such peer running: nothing to do.
        for live in [format!("{COORD_WG}\t192.168.1.50:51820\n"), format!("{OTHER_WG}\t203.0.113.50:51820\n"), String::new()] {
            *fc.live.lock().unwrap() = (live.clone(), String::new());
            assert!(sync(&Ctx::new(), &n, false, &store).is_err());
            assert!(sets(&fc).is_empty(), "{live}");
        }
        // With a switch link the switch address is tried first.
        *fc.live.lock().unwrap() = (format!("{COORD_WG}\t203.0.113.50:51820\n"), String::new());
        n.mend_coordinator(&Ctx::new(), SelfInfo { host: 2, switch: true });
        assert_eq!(sets(&fc), vec![format!("wg set wg0 peer {COORD_WG} endpoint 172.16.66.1:51820")]);
        *fc.answers.lock().unwrap() = Some(vec![]);
        n.mend_coordinator(&Ctx::new(), SelfInfo { host: 2, switch: true });
        assert_eq!(sets(&fc), vec![format!("wg set wg0 peer {COORD_WG} endpoint 192.168.1.50:51820")]);
        // A coordinator this server cut off is never brought back.
        put(&n.root, quarantine::STATE_FILE, r#"{"cuts":[{"hosts":[1]}]}"#);
        n.mend_coordinator(&Ctx::new(), SelfInfo { host: 2, switch: false });
        assert!(sets(&fc).is_empty());
    }

    /// Between two servers the list's address is a hint: a link WireGuard
    /// has a fresh handshake on keeps its endpoint, which only the peer's
    /// own packets set.
    #[test]
    fn a_live_link_between_servers_stays() {
        let (_dir, _tmp, n, fc) = joined();
        let env = sign(&ADMIN, 5, vec![coord_entry(), node_entry(2), other_entry()]);
        let c = other_entry();
        let node_c = Member {
            host: 3,
            name: c.name,
            wg_key: c.wg_key,
            ssh_host_key: c.ssh_host_key,
            lan_ip: "203.0.113.30".into(),
            ..Member::default()
        };
        *fc.peers.lock().unwrap() = Some(peers(&[coord_member(), node_member(2), node_c.clone()], &env));
        let now = Time::now().0.timestamp();
        let block = |n: &Node| get(&n.root, WG_CONF).split("# node-c\n").nth(1).unwrap_or_default().to_string();
        *fc.live.lock().unwrap() = (format!("{OTHER_WG}\t192.168.1.33:51820\n"), format!("{OTHER_WG}\t{}\n", now - 30));
        assert!(sync(&Ctx::new(), &n, false, &Store::new("/nonexistent")).unwrap());
        assert!(block(&n).contains("Endpoint = 192.168.1.33:51820"), "{}", block(&n));
        // The link went silent: the list's address is tried again.
        *fc.live.lock().unwrap() = (format!("{OTHER_WG}\t192.168.1.33:51820\n"), format!("{OTHER_WG}\t{}\n", now - 600));
        assert!(sync(&Ctx::new(), &n, false, &Store::new("/nonexistent")).unwrap());
        assert!(block(&n).contains("Endpoint = 203.0.113.30:51820"), "{}", block(&n));
        // wg cannot tell (wg0 down): the list's address.
        *fc.live.lock().unwrap() = (String::new(), String::new());
        assert!(sync(&Ctx::new(), &n, false, &Store::new("/nonexistent")).unwrap());
        assert!(block(&n).contains("Endpoint = 203.0.113.30:51820"), "{}", block(&n));
    }

    /// Whether a link goes over the switch is up to a ping of the peer's
    /// switch address, not up to what the list says about its cable.
    #[test]
    fn the_switch_is_found_by_ping() {
        let (_dir, _tmp, mut n, fc) = joined();
        let c = other_entry();
        let node_c = Member { host: 3, name: c.name, wg_key: c.wg_key, lan_ip: "192.168.1.30".into(), ..Member::default() };
        // The list says nobody has a cable.
        let members = vec![Member { switch: false, ..coord_member() }, node_member(2), node_c];
        let me = SelfInfo { host: 2, switch: true };
        let ctx = Ctx::new();
        let cases: Vec<(Option<Vec<String>>, [bool; 2])> =
            vec![(None, [true, true]), (Some(vec!["172.16.66.1".into()]), [true, false]), (Some(vec![]), [false, false])];
        for (answers, want) in cases {
            *fc.answers.lock().unwrap() = answers.clone();
            let got = n.check_switch(&ctx, me, &members);
            assert_eq!([got[0].switch, got[2].switch], want, "{answers:?}");
            let wg = mesh::wg_config(&n.cfg, me, &got);
            let coord = if want[0] { "172.16.66.1:51820" } else { "192.168.1.50:51820" };
            assert!(wg.contains(&format!("AllowedIPs = 10.66.0.1/32\nEndpoint = {coord}")), "{wg}");
        }
        let pings = |fc: &FakeCoord| fc.ran.lock().unwrap().drain(..).filter(|c| c.starts_with("ping")).count();
        assert_eq!(pings(&fc), 6, "two peers, three times; never itself");
        // Without a cable, in LAN mode, and on the coordinator: no ping,
        // and the list's word about cables changes nothing.
        let lan = Config { wg_transport: config::TRANSPORT_LAN.into(), ..n.cfg.clone() };
        for (cfg, me) in
            [(n.cfg.clone(), SelfInfo { host: 2, switch: false }), (lan, me), (n.cfg.clone(), SelfInfo { host: 1, switch: true })]
        {
            n.cfg = cfg;
            let wg = mesh::wg_config(&n.cfg, me, &n.check_switch(&ctx, me, &members));
            assert!(!wg.contains("172.16.66."), "{wg}");
        }
        assert_eq!(pings(&fc), 0);
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
        // Its turn, as root on the coordinator signed it: the update
        // commands are asked (and here they are not there). The mesh is
        // synced all the same.
        let now = Time::now().0.timestamp();
        let grant =
            rollout::Grant { host: 2, serial: 9, brain_k3s: "v1.37.2+k3s1".into(), issued: now, expires: now + 600, ..Default::default() };
        let doc = serde_json::to_string(&grant).unwrap();
        let sig = crate::signed::fake::host_sig(COORD_KEY, crate::signed::NS_TURN, &doc);
        with(serde_json::json!({"serial": 9, "turn": true, "brain_k3s": "v1.37.2+k3s1", "grant": {"doc": doc, "sig": sig}}));
        assert!(sync(&ctx, &n, false, &store).unwrap(), "an update problem must not fail the sync");
        assert!(get(&n.root, WG_CONF).contains(COORD_WG));
        let status = get(&n.root, UPDATE_STATUS);
        assert!(status.contains("release 9: cannot ask how its updates stand") && status.contains("tried 1 of"), "{status}");
        // That may pass: it is tried again at the next syncs, then it
        // counts as failed.
        for _ in 1..rollout::MAX_TRIES {
            let asked = fc.calls.lock().unwrap().len();
            assert!(sync(&ctx, &n, false, &store).unwrap());
            assert!(fc.calls.lock().unwrap()[asked..].iter().any(|c| c.contains("status")), "not tried again");
        }
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
        *fc.peers.lock().unwrap() = Some(peers_sealed(4, 8, Some(&sealed_for(4, TOKEN))));
        cgroups(&n, true);
        for _ in 0..2 {
            fc.ran.lock().unwrap().clear();
            assert!(sync(&ctx, &n, false, &store).unwrap());
            assert!(!stopped(&fc), "{:?}", fc.ran.lock().unwrap());
            assert_eq!(get(&n.root, sysconf::K3S_TOKEN), format!("{TOKEN}\n"));
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

        let token = TOKEN;
        *fc.peers.lock().unwrap() = Some(peers_sealed(2, 5, Some(&sealed_for(2, token))));
        assert!(sync(&ctx, &n, false, &store).unwrap());
        assert_eq!(get(&n.root, sysconf::K3S_TOKEN), format!("{token}\n"));
        assert_eq!(get(&n.root, K3S_TOKEN_STATUS), "ok\n");
        // Opened on stdin, and nothing of it on a command line.
        for c in fc.crypto.lock().unwrap().iter() {
            assert!(c.quiet && !c.args.join(" ").contains("0123456789abcdef"), "{c}");
        }
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
            &TOKEN.replace("::node:", "::server:"),
            &TOKEN[..67],
            "K10::node:5ecre7",
        ] {
            assert!(n.k3s_join(&ctx, 2, bad, None).is_err(), "{bad:?}");
            assert_eq!(get(&n.root, sysconf::K3S_TOKEN), format!("{token}\n"));
        }
        // The coordinator itself and a machine without an address never join as agents.
        n.k3s_join(&ctx, 1, TOKEN2, None).unwrap();
        n.k3s_join(&ctx, 0, TOKEN2, None).unwrap();
        assert_eq!(get(&n.root, sysconf::K3S_TOKEN), format!("{token}\n"));
        // A token rotated on the coordinator reaches it the same way, and
        // k3s starts again with it.
        fc.ran.lock().unwrap().clear();
        *fc.peers.lock().unwrap() = Some(peers_sealed(2, 5, Some(&sealed_for(2, TOKEN2))));
        assert!(sync(&ctx, &n, false, &store).unwrap());
        assert_eq!(get(&n.root, sysconf::K3S_TOKEN), format!("{TOKEN2}\n"));
        assert_eq!(fc.k3s_moves(), vec!["systemctl restart --no-block k3s.service"]);
    }

    /// The registry account can send anything in place of this machine's
    /// sealed token. Nothing it can make or move is taken, and nothing of
    /// it reaches the token file or restarts k3s, however often it comes.
    #[test]
    fn a_token_the_coordinator_did_not_seal_for_this_machine_changes_nothing() {
        let (_dir, tmp, n, fc) = joined();
        let (store, ctx) = (Store::new("/nonexistent"), Ctx::new());
        *fc.peers.lock().unwrap() = Some(peers_sealed(2, 5, Some(&sealed_for(2, TOKEN))));
        assert!(sync(&ctx, &n, false, &store).unwrap());
        assert_eq!(get(&n.root, sysconf::K3S_TOKEN), format!("{TOKEN}\n"));
        let mine = sealed_for(2, TOKEN);
        let me = signed::key_body(NODE_KEY);
        let evil = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIevil";
        let other = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInodec";
        let attacker = "K10aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa::node:attacker";
        let cases: Vec<(String, &str)> = vec![
            // Encrypted to this machine's key with a token of its choosing
            // (the hash of a certificate authority of its own): anyone can
            // encrypt to a public key, but only the coordinator signs.
            (peers_sealed(2, 5, Some(&k3stoken::fake::sealed(evil, 2, &me, attacker))), "not signed by the coordinator"),
            (peers_sealed(2, 5, Some(&Sealed { sig: String::new(), ..k3stoken::fake::sealed(evil, 2, &me, attacker) })), "not signed"),
            // Another member's, as it is or with this machine's number.
            (peers_sealed(2, 5, Some(&k3stoken::fake::sealed(COORD_KEY, 3, other, TOKEN))), "made for another machine"),
            (peers_sealed(2, 5, Some(&Sealed { host: 2, ..k3stoken::fake::sealed(COORD_KEY, 3, &me, TOKEN) })), "not signed"),
            (peers_sealed(2, 5, Some(&Sealed { key: other.into(), ..mine.clone() })), "another SSH host key"),
            // Signed for this machine, encrypted to another.
            (
                peers_sealed(2, 5, Some(&{
                    let age = k3stoken::fake::encrypt(other, TOKEN);
                    let sig = k3stoken::fake::sign(COORD_KEY, &k3stoken::signed_text(2, &me, &age));
                    Sealed { host: 2, key: me.clone(), age, sig }
                })),
                "cannot decrypt",
            ),
            // Too large, or not one at all.
            (peers_sealed(2, 5, Some(&Sealed { age: format!("{}{}", mine.age, "A".repeat(k3stoken::MAX_PART)), ..mine.clone() })), "larger"),
            (peers_sealed(2, 5, None).replace(r#""k3s_sealed":null"#, r#""k3s_sealed":"K10abc::node:x""#), ""),
            // An older coordinator, or the registry account posing as one:
            // the token itself is never taken.
            (
                serde_json::json!({ "members": [coord_member(), node_member(2)], "signed": sign(&ADMIN, 5, vec![coord_entry(), node_entry(2)]), "k3s_token": attacker })
                    .to_string(),
                "unencrypted",
            ),
        ];
        for (reply, want) in cases {
            fc.ran.lock().unwrap().clear();
            *fc.peers.lock().unwrap() = Some(reply);
            for round in 0..3 {
                assert!(sync(&ctx, &n, false, &store).unwrap(), "{want}");
                assert_eq!(get(&n.root, sysconf::K3S_TOKEN), format!("{TOKEN}\n"), "{want} round {round}");
                assert!(fc.k3s_moves().is_empty(), "{want} round {round}: {:?}", fc.ran.lock().unwrap());
                let status = get(&n.root, K3S_TOKEN_STATUS);
                assert!(status.contains(want) && (want.is_empty() || status.contains("left as they are")), "{want}: {status}");
                // Logged once: the status stays the same at the next sync.
                assert!(!n.note(K3S_TOKEN_STATUS, "", status.trim()), "{want}");
            }
        }
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0, "the checks left files behind");
        // Its own again: taken, and nothing changes.
        *fc.peers.lock().unwrap() = Some(peers_sealed(2, 5, Some(&mine)));
        fc.ran.lock().unwrap().clear();
        assert!(sync(&ctx, &n, false, &store).unwrap());
        assert!(fc.k3s_moves().is_empty() && get(&n.root, K3S_TOKEN_STATUS) == "ok\n", "{:?}", fc.ran.lock().unwrap());
        // Sealed anew with the same token (age output differs every time;
        // a coordinator restored from its backup makes new ones): nothing
        // written, k3s not restarted.
        let age = mine.age.replacen('\n', "\n\n", 1);
        let again = Sealed { sig: k3stoken::fake::sign(COORD_KEY, &k3stoken::signed_text(2, &me, &age)), age, ..mine.clone() };
        assert_ne!(again, mine);
        *fc.peers.lock().unwrap() = Some(peers_sealed(2, 5, Some(&again)));
        assert!(sync(&ctx, &n, false, &store).unwrap());
        assert!(fc.k3s_moves().is_empty() && get(&n.root, sysconf::K3S_TOKEN) == format!("{TOKEN}\n"), "{:?}", fc.ran.lock().unwrap());
    }

    /// age or ssh-keygen missing or failing on a server leaves the token
    /// and k3s as they are.
    #[test]
    fn a_server_without_its_tools_changes_nothing() {
        let (_dir, _tmp, n, fc) = joined();
        let (store, ctx) = (Store::new("/nonexistent"), Ctx::new());
        *fc.no_age.lock().unwrap() = true;
        *fc.peers.lock().unwrap() = Some(peers_sealed(2, 5, Some(&sealed_for(2, TOKEN))));
        assert!(sync(&ctx, &n, false, &store).unwrap());
        assert!(get(&n.root, sysconf::K3S_TOKEN).is_empty() && fc.k3s_moves().is_empty());
        assert!(get(&n.root, K3S_TOKEN_STATUS).contains("cannot decrypt"), "{}", get(&n.root, K3S_TOKEN_STATUS));
        // The private host key is gone, or the public one: nothing opens.
        *fc.no_age.lock().unwrap() = false;
        for key in [HOST_KEY, HOST_KEY_PUB] {
            std::fs::remove_file(n.path(key)).unwrap();
            assert!(sync(&ctx, &n, false, &store).unwrap());
            assert!(get(&n.root, sysconf::K3S_TOKEN).is_empty() && fc.k3s_moves().is_empty(), "{key}");
            assert!(get(&n.root, K3S_TOKEN_STATUS).contains("left as they are"), "{key}");
        }
    }

    /// How root asks k3s for the node passwords.
    const LIST_PASSWORDS: &str = "kubectl get secrets -n kube-system --field-selector type=k3s.cattle.io/node-password -o json";

    /// The node password inside a sealed token.
    fn password_inside(s: &Sealed) -> String {
        let body: String = s.age.lines().filter(|l| !l.starts_with("-----")).collect();
        let plain = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body).unwrap();
        String::from_utf8(plain).unwrap().lines().nth(2).unwrap().strip_prefix("node-password ").unwrap().to_string()
    }

    /// The token inside a sealed one (k3stoken::fake's age).
    fn inside(s: &Sealed) -> String {
        let body: String = s.age.lines().filter(|l| !l.starts_with("-----")).collect();
        let plain = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body).unwrap();
        String::from_utf8(plain).unwrap().lines().nth(1).unwrap().to_string()
    }

    /// The n-th join token the fake k3s made.
    fn join_token(n: u32) -> String {
        format!("{}::tok{n:03}.0123456789abcdef", &TOKEN[..67])
    }

    fn node_c() -> Member {
        let c = other_entry();
        Member { host: 3, name: c.name, wg_key: c.wg_key, ssh_host_key: c.ssh_host_key, ..Member::default() }
    }

    const NOW: i64 = 1_800_000_000;

    /// Each server joins with a token of its own, made for it alone, and
    /// deleted once it is in the cluster.
    #[test]
    fn each_server_joins_with_a_token_of_its_own() {
        let (_dir, _tmp, coord, fc, _sd, store) = brain();
        let members = vec![coord_member(), node_member(2)];
        let ctx = Ctx::new();
        put(&coord.root, K3S_AGENT_TOKEN, format!("{TOKEN}\n"));
        let calls = |fc: &FakeCoord| fc.k3s.lock().unwrap().drain(..).collect::<Vec<_>>();
        // k3s is not up: nothing made, nobody dropped.
        fc.cluster.lock().unwrap().down = true;
        coord.k3s_share(&ctx, Some(&store), &members, NOW);
        assert!(store.read().unwrap().k3s_tokens.is_empty() && fc.ages() == 0 && !coord.path(K3S_JOIN).exists());
        fc.cluster.lock().unwrap().down = false;
        calls(&fc);
        coord.k3s_share(&ctx, Some(&store), &members, NOW);
        assert_eq!(
            calls(&fc),
            vec![
                "kubectl get nodes -o name".to_string(),
                LIST_PASSWORDS.into(),
                "kubectl delete node ghost --timeout=20s".into(),
                "kubectl create -f -".into(),
                "token create --ttl 86400s --description dryserver: node-a joins the cluster".into(),
            ],
            "only the machine that left goes; node-a's password goes into the cluster before its token is made"
        );
        // Root's node password for node-a, kept by its finalizer, and
        // sealed with the token for node-a alone.
        let pass = fc.cluster.lock().unwrap().passwords["node-a"].clone();
        let password = FakeCoord::sealed_password(&coord.root, 2);
        assert!(pass.mark.is_some() && pass.finalizer && k3stoken::hash_matches(&pass.hash, &password), "{pass:?}");
        assert!(!fc.k3s.lock().unwrap().iter().any(|c| c.contains(&password)), "the password on a command line");
        let sealed = store.read().unwrap().k3s_tokens;
        assert_eq!(sealed.len(), 1);
        assert_eq!((sealed[0].host, sealed[0].key.as_str(), inside(&sealed[0])), (2, signed::key_body(NODE_KEY).as_str(), join_token(1)));
        assert_eq!(password_inside(&sealed[0]), password);
        // The registry's file holds nothing of a token itself, and the one
        // token all agents shared is never handed out.
        let file = std::fs::read_to_string(&store.path).unwrap();
        assert!(!file.contains("tok001") && !file.contains(&TOKEN[67..]) && !file.contains(&password), "{file}");
        for c in fc.crypto.lock().unwrap().iter() {
            assert!(c.quiet && !c.args.join(" ").contains("tok001"), "the token on a command line: {c}");
        }
        assert!(get(&coord.root, K3S_JOIN).contains("\"tok001\""));
        let mode = |p: &str| std::fs::metadata(coord.path(p)).map(|m| std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o777);
        assert_eq!(mode(K3S_JOIN).unwrap(), 0o600);
        // Nothing changed: nothing made again.
        fc.ages();
        coord.k3s_share(&ctx, Some(&store), &members, NOW + 60);
        assert!(!calls(&fc).iter().any(|c| c.starts_with("token")) && fc.ages() == 0);
        assert_eq!(store.read().unwrap().k3s_tokens, sealed);
        // node-a is in the cluster: its token goes, and the registry holds
        // none for it any more. Another password does not get in.
        assert!(!fc.agent("node-a", &k3stoken::new_password()));
        assert!(fc.agent("node-a", &password));
        coord.k3s_share(&ctx, Some(&store), &members, NOW + 120);
        assert_eq!(fc.cluster.lock().unwrap().deleted, vec!["tok001".to_string()]);
        assert!(store.read().unwrap().k3s_tokens.is_empty());
        assert_eq!(get(&coord.root, K3S_NODES).trim(), format!(r#"{{"node-a":"{WG_PUBKEY}"}}"#), "which machine holds the name node-a");
        assert!(get(&coord.root, K3S_SHARE_STATUS).starts_with("0 servers wait"), "{}", get(&coord.root, K3S_SHARE_STATUS));
        assert!(!coord.path(SHARED_ISSUE).exists() && !coord.path(K3S_SHARED).exists());
        calls(&fc);
        coord.k3s_share(&ctx, Some(&store), &members, NOW + 180);
        assert_eq!(calls(&fc), vec!["kubectl get nodes -o name".to_string(), LIST_PASSWORDS.into()]);
        // node-a was installed again: same name, another machine. The
        // cluster forgets the old one, or it would turn the new one away,
        // and the new one gets a token of its own.
        let again = vec![coord_member(), Member { wg_key: OTHER_WG.into(), ..node_member(2) }];
        coord.k3s_share(&ctx, Some(&store), &again, NOW + 240);
        let made = calls(&fc);
        assert!(
            made.contains(&"kubectl delete node node-a --timeout=20s".to_string()) && made.iter().any(|c| c.starts_with("token create"))
        );
        assert_eq!(get(&coord.root, K3S_NODES).trim(), "{}", "the name is free for the new machine");
        assert_eq!(store.read().unwrap().k3s_tokens.iter().map(inside).collect::<Vec<_>>(), vec![join_token(2)]);
        // With a password of its own: the old machine's is gone.
        let new = FakeCoord::sealed_password(&coord.root, 2);
        assert_ne!(new, password);
        assert!(!fc.agent("node-a", &password) && fc.agent("node-a", &new));
        coord.k3s_share(&ctx, Some(&store), &again, NOW + 300);
        assert_eq!(get(&coord.root, K3S_NODES).trim(), format!(r#"{{"node-a":"{OTHER_WG}"}}"#));
    }

    /// The review's case: node-a, hacked, holds no token that registers a
    /// node under the name of node-c, which the admin just approved. Its
    /// own was deleted when it joined, and node-c's is sealed for node-c.
    #[test]
    fn a_server_in_the_cluster_holds_no_token_for_another_name() {
        let (_dir, _tmp, coord, fc, _sd, store) = brain();
        put(&coord.root, K3S_AGENT_TOKEN, format!("{TOKEN}\n"));
        let ctx = Ctx::new();
        coord.k3s_share(&ctx, Some(&store), &[coord_member(), node_member(2)], NOW);
        fc.cluster.lock().unwrap().nodes = "node/coord\nnode/node-a\n".into();
        coord.k3s_share(&ctx, Some(&store), &[coord_member(), node_member(2)], NOW + 60);
        coord.k3s_share(&ctx, Some(&store), &[coord_member(), node_member(2), node_c()], NOW + 120);
        let sealed = store.read().unwrap().k3s_tokens;
        assert_eq!(sealed.len(), 1, "{sealed:?}");
        assert_eq!((sealed[0].host, sealed[0].key.as_str(), inside(&sealed[0])), (3, node_c().ssh_host_key.as_str(), join_token(2)));
        assert_eq!(fc.cluster.lock().unwrap().deleted, vec!["tok001".to_string()], "node-a's own token is gone");
        // What a server takes is only what was sealed for its own key.
        let (_d2, _t2, n, sfc) = joined();
        *sfc.peers.lock().unwrap() = Some(peers_sealed(2, 5, Some(&sealed[0])));
        assert!(sync(&ctx, &n, false, &Store::new("/nonexistent")).unwrap());
        assert!(get(&n.root, sysconf::K3S_TOKEN).is_empty() && sfc.k3s_moves().is_empty());
    }

    /// The token from the coordinator to a server, sealed all the way: the
    /// registry holds nothing it could join with.
    #[test]
    fn the_token_reaches_a_server_sealed() {
        let (_dir, _tmp, b, bfc, _sd, store) = brain();
        registry(&store, vec![coord_member(), node_member(2)], sign(&ADMIN, 5, vec![coord_entry(), node_entry(2)]));
        sync(&Ctx::new(), &b, true, &store).unwrap();
        let mine = store.read().unwrap().k3s_tokens.into_iter().find(|t| t.host == 2).expect("nothing sealed for node-a");
        // Nothing changed: nothing is made again, the registry stays as it is.
        bfc.ages();
        for _ in 0..2 {
            sync(&Ctx::new(), &b, true, &store).unwrap();
            assert_eq!(bfc.ages(), 0);
            assert_eq!(store.read().unwrap().k3s_tokens, vec![mine.clone()]);
        }
        let (_d2, _t2, n, fc) = joined();
        *fc.peers.lock().unwrap() = Some(peers_sealed(2, 5, Some(&mine)));
        assert!(sync(&Ctx::new(), &n, false, &Store::new("/nonexistent")).unwrap());
        assert_eq!(get(&n.root, sysconf::K3S_TOKEN), format!("{}\n", join_token(1)));
        assert_eq!(fc.k3s_moves(), vec!["systemctl start --no-block k3s.service"]);
        // With the node password root put into the cluster for node-a,
        // which its agent shows k3s: it gets in under its name.
        let password = FakeCoord::sealed_password(&b.root, 2);
        assert_eq!(get(&n.root, sysconf::K3S_NODE_PASSWORD), format!("{password}\n"));
        let mode = std::fs::metadata(n.path(sysconf::K3S_NODE_PASSWORD)).unwrap();
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&mode.permissions()) & 0o777, 0o600);
        assert!(bfc.agent("node-a", get(&n.root, sysconf::K3S_NODE_PASSWORD).trim()));
        sync(&Ctx::new(), &b, true, &store).unwrap();
        assert_eq!(get(&b.root, K3S_NODES).trim(), format!(r#"{{"node-a":"{WG_PUBKEY}"}}"#));
        assert!(store.read().unwrap().k3s_tokens.is_empty());
        // Nothing changes on node-a while it gets nothing new.
        fc.ran.lock().unwrap().clear();
        assert!(sync(&Ctx::new(), &n, false, &Store::new("/nonexistent")).unwrap());
        assert!(fc.k3s_moves().is_empty());
        // A token from a coordinator of an older version (the token
        // alone): the agent keeps the password k3s made for it.
        let (_d3, _t3, n3, fc3) = joined();
        put(&n3.root, sysconf::K3S_NODE_PASSWORD, "k3s made this\n");
        *fc3.peers.lock().unwrap() = Some(peers_sealed(2, 5, Some(&sealed_for(2, TOKEN))));
        assert!(sync(&Ctx::new(), &n3, false, &Store::new("/nonexistent")).unwrap());
        assert_eq!(
            (get(&n3.root, sysconf::K3S_TOKEN), get(&n3.root, sysconf::K3S_NODE_PASSWORD)),
            (format!("{TOKEN}\n"), "k3s made this\n".into())
        );
        // The admin removes node-a: its password goes with its token.
        n.k3s_leave(&Ctx::new());
        assert!(!n.path(sysconf::K3S_NODE_PASSWORD).exists() && !n.path(sysconf::K3S_TOKEN).exists());
    }

    /// The review's case: node-a, hacked, deletes its own node (its
    /// kubelet may) to get a new join token, and with it registers the
    /// name of a server that has not joined yet. A server that was in the
    /// cluster gets no token again. It comes back with its certificate.
    #[test]
    fn review_a_joined_server_gets_a_new_token_by_leaving_the_cluster() {
        let (_dir, _tmp, coord, fc, _sd, store) = brain();
        put(&coord.root, K3S_AGENT_TOKEN, format!("{TOKEN}\n"));
        let ctx = Ctx::new();
        let members = [coord_member(), node_member(2)];
        coord.k3s_share(&ctx, Some(&store), &members, NOW);
        assert!(fc.agent("node-a", &FakeCoord::sealed_password(&coord.root, 2)));
        coord.k3s_share(&ctx, Some(&store), &members, NOW + 60);
        assert!(store.read().unwrap().k3s_tokens.is_empty(), "node-a joined: no token is left for it");
        fc.cluster.lock().unwrap().nodes = "node/coord\n".into(); // node-a deletes its own Node
        for t in [NOW + 120, NOW + 180, NOW + JOIN_TOKEN_TTL] {
            coord.k3s_share(&ctx, Some(&store), &members, t);
            let again: Vec<String> = store.read().unwrap().k3s_tokens.iter().filter(|t| t.host == 2).map(inside).collect();
            assert!(again.is_empty(), "node-a was in the cluster and got a new bootstrap token: {again:?}");
        }
        assert_eq!(fc.cluster.lock().unwrap().made, 1, "no token made for it in k3s either");
        let status = get(&coord.root, K3S_SHARE_STATUS);
        assert!(status.contains("node-a was in the cluster and its node is gone") && status.contains("approve it again"), "{status}");
        assert!(get(&coord.root, NAMES_ISSUE).contains("node-a was in the cluster"));
        // Its password stays in the cluster: its kubelet registers its node
        // again with its certificate, and it is node-a again.
        assert!(fc.cluster.lock().unwrap().passwords.contains_key("node-a"));
        fc.cluster.lock().unwrap().nodes = "node/coord\nnode/node-a\n".into();
        coord.k3s_share(&ctx, Some(&store), &members, NOW + JOIN_TOKEN_TTL + 60);
        assert!(get(&coord.root, K3S_SHARE_STATUS).starts_with("0 servers wait") && !coord.path(NAMES_ISSUE).exists());
        // The admin removes it: name and password go, and approved again it
        // is a new machine to the cluster, with a token and a password of
        // its own.
        fc.cluster.lock().unwrap().nodes = "node/coord\n".into();
        coord.k3s_share(&ctx, Some(&store), &[coord_member()], NOW + JOIN_TOKEN_TTL + 120);
        assert!(!fc.cluster.lock().unwrap().passwords.contains_key("node-a") && get(&coord.root, K3S_NODES).trim() == "{}");
        coord.k3s_share(&ctx, Some(&store), &members, NOW + JOIN_TOKEN_TTL + 180);
        assert_eq!(store.read().unwrap().k3s_tokens.iter().map(|t| t.host).collect::<Vec<_>>(), vec![2]);
    }

    /// The review's case: a server holding a token (node-a, before it
    /// joined) registers a node under the name of another server that has
    /// not joined yet. k3s turns it away: node-c's password is root's.
    /// Should a node under node-c come all the same with a password root
    /// did not make (an older version, or a password someone removed), it
    /// is never taken for node-c's: the name is taken, its node deleted,
    /// and no server gets a token for it.
    #[test]
    fn review_the_first_node_under_a_name_is_taken_for_that_member() {
        let (_dir, _tmp, coord, fc, _sd, store) = brain();
        put(&coord.root, K3S_AGENT_TOKEN, format!("{TOKEN}\n"));
        let ctx = Ctx::new();
        let members = [coord_member(), node_member(2), node_c()];
        fc.cluster.lock().unwrap().nodes = "node/coord\n".into();
        coord.k3s_share(&ctx, Some(&store), &members, NOW);
        let c_token = store.read().unwrap().k3s_tokens.iter().find(|t| t.host == 3).map(inside).expect("node-c has a token");
        let c_id = k3stoken::bootstrap_id(&c_token).unwrap().to_string();
        let a_password = FakeCoord::sealed_password(&coord.root, 2);
        assert!(!fc.agent("node-c", &a_password), "k3s gave node-a a certificate for node-c");
        coord.k3s_share(&ctx, Some(&store), &members, NOW + 60);
        assert!(!get(&coord.root, K3S_NODES).contains("node-c") && !fc.cluster.lock().unwrap().deleted.contains(&c_id));
        // A node under node-c with a password k3s took from some agent.
        fc.cluster.lock().unwrap().passwords.remove("node-c");
        assert!(fc.agent("node-c", &a_password));
        coord.k3s_share(&ctx, Some(&store), &members, NOW + 120);
        let deleted = fc.cluster.lock().unwrap().deleted.clone();
        assert!(
            !get(&coord.root, K3S_NODES).contains("node-c"),
            "a node node-c never made is recorded as node-c's ({}) and node-c's own token is deleted ({deleted:?})",
            get(&coord.root, K3S_NODES).trim()
        );
        assert!(!fc.cluster.lock().unwrap().nodes.contains("node-c"), "the node that took the name is deleted");
        // node-c's token is withdrawn, not handed to anyone: a server
        // joining under that name would share it with whoever holds the
        // certificate.
        assert!(deleted.contains(&c_id) && !store.read().unwrap().k3s_tokens.iter().any(|t| t.host == 3));
        let alarm = get(&coord.root, NAMES_ISSUE);
        assert!(alarm.contains("ALARM: the name node-c is taken") && alarm.contains("install it again under another name"), "{alarm}");
        // It stays so: the node is deleted whenever it comes back, nobody
        // gets a token for node-c, and the name is kept for a year.
        fc.k3s.lock().unwrap().clear();
        for t in [NOW + 180, NOW + JOIN_TOKEN_TTL, NOW + TAKEN_FOR - 1] {
            fc.agent("node-c", &a_password);
            coord.k3s_share(&ctx, Some(&store), &members, t);
            assert!(!fc.cluster.lock().unwrap().nodes.contains("node-c") && !get(&coord.root, K3S_NODES).contains("node-c"));
        }
        assert!(!store.read().unwrap().k3s_tokens.iter().any(|t| t.host == 3));
        assert!(!fc.k3s.lock().unwrap().iter().any(|c| c.contains("node-c joins")), "a token made for node-c");
        assert!(get(&coord.root, K3S_TAKEN).contains("node-c"));
        // node-a itself is not held up.
        assert!(store.read().unwrap().k3s_tokens.iter().any(|t| t.host == 2));
    }

    /// node-a, holding a token before it joined, registers the name of a
    /// server the admin has not approved yet. k3s gives it a certificate
    /// for that name; root sees it and keeps the name from every server.
    #[test]
    fn a_name_registered_before_its_server_is_approved_stays_taken() {
        let (_dir, _tmp, coord, fc, _sd, store) = brain();
        put(&coord.root, K3S_AGENT_TOKEN, format!("{TOKEN}\n"));
        let ctx = Ctx::new();
        let members = [coord_member(), node_member(2)];
        coord.k3s_share(&ctx, Some(&store), &members, NOW);
        let a_password = FakeCoord::sealed_password(&coord.root, 2);
        // A certificate without a node, then a node.
        let ghost = |fc: &FakeCoord| fc.cluster.lock().unwrap().nodes = "node/coord\n".into();
        assert!(fc.agent("node-c", &a_password));
        ghost(&fc);
        coord.k3s_share(&ctx, Some(&store), &members, NOW + 60);
        assert!(get(&coord.root, K3S_TAKEN).contains("node-c"), "{}", get(&coord.root, K3S_TAKEN));
        assert!(fc.agent("node-c", &a_password));
        coord.k3s_share(&ctx, Some(&store), &members, NOW + 120);
        assert!(!fc.cluster.lock().unwrap().nodes.contains("node-c"));
        // The admin approves node-c later: it gets no token, and the
        // console says why.
        let both = [coord_member(), node_member(2), node_c()];
        coord.k3s_share(&ctx, Some(&store), &both, NOW + 3600);
        assert!(!store.read().unwrap().k3s_tokens.iter().any(|t| t.host == 3));
        assert!(get(&coord.root, NAMES_ISSUE).contains("the name node-c is taken"));
        // After a year and a bit the certificate is gone, and so is the mark.
        coord.k3s_share(&ctx, Some(&store), &both, NOW + 60 + TAKEN_FOR);
        assert!(store.read().unwrap().k3s_tokens.iter().any(|t| t.host == 3) && !get(&coord.root, K3S_TAKEN).contains("node-c"));
    }

    /// Servers that joined before this version keep their names and
    /// their passwords (k3s made those), a server joining with a token an
    /// older version made gets in, and nothing is taken for them.
    #[test]
    fn servers_that_joined_before_keep_their_names() {
        let (_dir, _tmp, coord, fc, _sd, store) = brain();
        put(&coord.root, K3S_AGENT_TOKEN, format!("{TOKEN}\n"));
        let ctx = Ctx::new();
        let members = [coord_member(), node_member(2), node_c()];
        // node-a joined under an older version; node-c holds a token that
        // version made (no password in it) and is joining with it.
        put(&coord.root, K3S_NODES, format!(r#"{{"node-a":"{WG_PUBKEY}"}}"#));
        let old = serde_json::json!({ "tokens": { "3": {
            "name": "node-c", "wg_key": OTHER_WG, "coord": signed::key_body(COORD_KEY), "id": "old001",
            "expires": NOW + 3600 * 20, "sealed": k3stoken::fake::sealed(COORD_KEY, 3, &node_c().ssh_host_key, &join_token(9)) } } });
        put(&coord.root, K3S_JOIN, old.to_string());
        fc.cluster.lock().unwrap().nodes = "node/coord\nnode/node-a\n".into();
        assert!(fc.agent("node-a", "k3s made this one on node-a"));
        assert!(fc.agent("node-c", "and this one on node-c"));
        fc.cluster.lock().unwrap().nodes = "node/coord\nnode/node-a\n".into();
        coord.k3s_share(&ctx, Some(&store), &members, NOW);
        assert!(get(&coord.root, K3S_TAKEN).is_empty() && !coord.path(NAMES_ISSUE).exists(), "{}", get(&coord.root, K3S_TAKEN));
        assert!(fc.cluster.lock().unwrap().deleted.is_empty(), "node-c's token was taken away half way");
        fc.agent("node-c", "and this one on node-c");
        coord.k3s_share(&ctx, Some(&store), &members, NOW + 60);
        assert_eq!(get(&coord.root, K3S_NODES).trim(), format!(r#"{{"node-a":"{WG_PUBKEY}","node-c":"{OTHER_WG}"}}"#));
        assert_eq!(fc.cluster.lock().unwrap().deleted, vec!["old001".to_string()]);
        assert!(fc.cluster.lock().unwrap().passwords.values().all(|p| p.mark.is_none()), "their passwords are left as k3s made them");
        assert!(get(&coord.root, K3S_TAKEN).is_empty() && get(&coord.root, K3S_SHARE_STATUS).starts_with("0 servers wait"));
    }

    /// Root's record of the names lost or damaged: the servers in the
    /// cluster stay, and are recorded again.
    #[test]
    fn a_lost_record_of_the_names_keeps_the_servers_in_the_cluster() {
        let (_dir, _tmp, coord, fc, _sd, store) = brain();
        put(&coord.root, K3S_AGENT_TOKEN, format!("{TOKEN}\n"));
        let ctx = Ctx::new();
        let members = [coord_member(), node_member(2)];
        // node-a joined under an older version, which left k3s its password.
        coord.k3s_share(&ctx, Some(&store), &[coord_member()], NOW);
        put(&coord.root, K3S_NODES, format!(r#"{{"node-a":"{WG_PUBKEY}"}}"#));
        assert!(fc.agent("node-a", "k3s made it, as an older version let it"));
        coord.k3s_share(&ctx, Some(&store), &members, NOW);
        for (i, lost) in ["", "{\"node-a\": "].into_iter().enumerate() {
            if lost.is_empty() {
                std::fs::remove_file(coord.path(K3S_NODES)).unwrap();
            } else {
                put(&coord.root, K3S_NODES, lost);
            }
            coord.k3s_share(&ctx, Some(&store), &members, NOW + 60 * (i as i64 + 1));
            assert_eq!(get(&coord.root, K3S_NODES).trim(), format!(r#"{{"node-a":"{WG_PUBKEY}"}}"#), "{lost:?}");
            assert!(fc.cluster.lock().unwrap().nodes.contains("node-a") && get(&coord.root, K3S_TAKEN).is_empty(), "{lost:?}");
        }
    }

    /// A machine that had a name before (removed, or installed again) and
    /// registered under it with its old password while it was still in
    /// the mesh is not the new server under that name.
    #[test]
    fn the_machine_that_had_a_name_before_is_not_the_new_one() {
        let (_dir, _tmp, coord, fc, _sd, store) = brain();
        put(&coord.root, K3S_AGENT_TOKEN, format!("{TOKEN}\n"));
        let ctx = Ctx::new();
        coord.k3s_share(&ctx, Some(&store), &[coord_member(), node_c()], NOW);
        let before = FakeCoord::sealed_password(&coord.root, 3);
        // node-c installed again (another key) before the old one joined;
        // the old one joins with what it had, then root's sync comes.
        let again = [coord_member(), Member { wg_key: EVIL_WG.into(), ..node_c() }];
        assert!(fc.agent("node-c", &before));
        coord.k3s_share(&ctx, Some(&store), &again, NOW + 60);
        assert!(!get(&coord.root, K3S_NODES).contains("node-c") && !fc.cluster.lock().unwrap().nodes.contains("node-c"));
        let new = FakeCoord::sealed_password(&coord.root, 3);
        assert!(new != before && !fc.agent("node-c", &before) && fc.agent("node-c", &new));
        coord.k3s_share(&ctx, Some(&store), &again, NOW + 120);
        assert_eq!(get(&coord.root, K3S_NODES).trim(), format!(r#"{{"node-c":"{EVIL_WG}"}}"#));
        assert!(get(&coord.root, K3S_TAKEN).is_empty());
    }

    /// k3s that does not list the node passwords gets no name taken and
    /// hands out no new token; one a server has keeps working.
    #[test]
    fn without_the_node_passwords_no_token_is_made() {
        let (_dir, _tmp, coord, fc, _sd, store) = brain();
        put(&coord.root, K3S_AGENT_TOKEN, format!("{TOKEN}\n"));
        let ctx = Ctx::new();
        let members = [coord_member(), node_member(2)];
        coord.k3s_share(&ctx, Some(&store), &[coord_member()], NOW);
        fc.cluster.lock().unwrap().list_fails = true;
        coord.k3s_share(&ctx, Some(&store), &members, NOW + 60);
        assert!(store.read().unwrap().k3s_tokens.is_empty() && fc.cluster.lock().unwrap().made == 0);
        assert!(get(&coord.root, K3S_SHARE_STATUS).contains("no join token for node-a: k3s does not list the node passwords"));
        fc.cluster.lock().unwrap().list_fails = false;
        coord.k3s_share(&ctx, Some(&store), &members, NOW + 120);
        let password = FakeCoord::sealed_password(&coord.root, 2);
        fc.cluster.lock().unwrap().list_fails = true;
        assert!(fc.agent("node-a", &password));
        coord.k3s_share(&ctx, Some(&store), &members, NOW + 180);
        assert!(!get(&coord.root, K3S_NODES).contains("node-a") && fc.cluster.lock().unwrap().nodes.contains("node-a"), "decided blind");
        assert_eq!(store.read().unwrap().k3s_tokens.len(), 1, "the token node-a has stays");
        fc.cluster.lock().unwrap().list_fails = false;
        coord.k3s_share(&ctx, Some(&store), &members, NOW + 240);
        assert!(get(&coord.root, K3S_NODES).contains("node-a") && store.read().unwrap().k3s_tokens.is_empty());
    }

    /// Who gets a join token, and when one is made again or deleted.
    #[test]
    fn who_gets_a_join_token_and_when() {
        let (_dir, _tmp, n, fc, _sd, store) = brain();
        let ctx = Ctx::new();
        let tokens = || store.read().unwrap().k3s_tokens;
        let hosts = || tokens().iter().map(|t| (t.host, t.key.clone(), inside(t))).collect::<Vec<_>>();
        let node_a = signed::key_body(NODE_KEY);
        let c_key = node_c().ssh_host_key;
        let both = vec![coord_member(), node_member(2), node_c()];
        let share = |members: &[Member], now: i64| n.k3s_share(&ctx, Some(&store), members, now);
        let deleted = || std::mem::take(&mut fc.cluster.lock().unwrap().deleted);
        share(&both, NOW);
        assert_eq!(hosts(), vec![(2, node_a.clone(), join_token(1)), (3, c_key.clone(), join_token(2))], "none for the coordinator");
        assert_eq!(fc.ages(), 2);
        let first = tokens();

        // The registry account changes one, drops one and adds one for a
        // machine of its own: root's next sync puts back exactly its own.
        store
            .update(|s| {
                s.k3s_tokens[0].age = k3stoken::fake::encrypt(&node_a, TOKEN2);
                s.k3s_tokens.remove(1);
                s.k3s_tokens.push(k3stoken::fake::sealed(COORD_KEY, 9, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIevil", TOKEN));
                Ok(())
            })
            .unwrap();
        share(&both, NOW + 60);
        assert_eq!((tokens(), fc.ages(), fc.cluster.lock().unwrap().made), (first.clone(), 0, 2));
        // What root keeps is lost (a restore without it): each server gets
        // a new one. The old ones end by themselves within a day.
        std::fs::remove_file(n.path(K3S_JOIN)).unwrap();
        share(&both, NOW + 120);
        assert_eq!((hosts().iter().map(|h| h.2.clone()).collect::<Vec<_>>(), fc.ages()), (vec![join_token(3), join_token(4)], 2));
        assert!(!get(&n.root, K3S_SHARE_STATUS).contains("WARNING"), "{}", get(&n.root, K3S_SHARE_STATUS));
        // A token about to end is made again, and the old one deleted.
        share(&both, NOW + 120 + JOIN_TOKEN_TTL - JOIN_TOKEN_RENEW + 1);
        assert_eq!(hosts().iter().map(|h| h.2.clone()).collect::<Vec<_>>(), vec![join_token(5), join_token(6)]);
        assert_eq!(deleted(), vec!["tok003".to_string(), "tok004".into()]);
        let later = NOW + 200 + JOIN_TOKEN_TTL - JOIN_TOKEN_RENEW;

        // A newer list: node-c removed, node-a installed again with a new
        // host key, two servers with keys nothing can be sealed for.
        let new_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInewnode";
        let members = vec![
            coord_member(),
            Member { ssh_host_key: new_key.into(), ..node_member(2) },
            Member {
                host: 4,
                name: "node-d".into(),
                wg_key: EVIL_WG.into(),
                ssh_host_key: "ecdsa-sha2-nistp256 AAAAE2Vj".into(),
                ..Member::default()
            },
            Member { host: 5, name: "node-e".into(), wg_key: OTHER_WG.into(), ..Member::default() },
        ];
        share(&members, later);
        assert_eq!(hosts(), vec![(2, new_key.to_string(), join_token(7))]);
        assert_eq!(deleted(), vec!["tok005".to_string(), "tok006".into()], "node-a's old key and node-c lose theirs");
        let status = get(&n.root, K3S_SHARE_STATUS);
        assert!(
            status.contains("no join token for node-d: its SSH host key is not ssh-ed25519")
                && status.contains("no join token for node-e: it has no SSH host key"),
            "{status}"
        );

        // k3s cannot make one, then age is missing, then the coordinator's
        // own key: node-a keeps the one it has while it lasts, a token made
        // but not sealed is deleted again, and the line says why.
        let end = later + JOIN_TOKEN_TTL;
        fc.cluster.lock().unwrap().create_fails = true;
        share(&members, end - 10);
        assert!(get(&n.root, K3S_SHARE_STATUS).contains("no new join token for node-a: k3s token create"));
        assert_eq!(hosts()[0].2, join_token(7));
        fc.cluster.lock().unwrap().create_fails = false;
        *fc.no_age.lock().unwrap() = true;
        share(&members, end - 10);
        assert!(get(&n.root, K3S_SHARE_STATUS).contains("no new join token for node-a: encrypt the cluster token (is age installed?)"));
        assert_eq!((hosts()[0].2.clone(), deleted()), (join_token(7), vec!["tok008".to_string()]));
        *fc.no_age.lock().unwrap() = false;
        std::fs::remove_file(n.path(HOST_KEY)).unwrap();
        share(&members, end - 10);
        assert!(get(&n.root, K3S_SHARE_STATUS).contains("sign the cluster token with the host key"));
        put(&n.root, HOST_KEY, "coord private\n");
        // A token k3s does not delete when asked is asked again until it
        // would have ended anyway.
        fc.cluster.lock().unwrap().delete_fails = true;
        share(&members, end - 10);
        assert_eq!(hosts()[0].2, join_token(10));
        share(&members, end - 5);
        assert_eq!(std::mem::take(&mut fc.cluster.lock().unwrap().failed), vec!["tok007".to_string(), "tok007".into()]);
        share(&members, end + 1);
        assert!(fc.cluster.lock().unwrap().failed.is_empty(), "asked again after it ended");
        assert!(!get(&n.root, K3S_JOIN).contains("tok007"));
    }

    /// Servers that joined before this version hold the one token an older
    /// version handed every agent: any of them could register a node under
    /// a new server's name. The coordinator says so until a new one is
    /// made.
    #[test]
    fn the_shared_token_is_named_until_a_new_one_is_made() {
        let warned =
            |n: &Node| get(&n.root, K3S_SHARE_STATUS).starts_with("WARNING") && get(&n.root, SHARED_ISSUE).contains("A new cluster token");
        let members = vec![coord_member(), node_member(2)];
        let ctx = Ctx::new();
        // Updated from a version that sealed the shared token for servers,
        // or one that served it plainly: node-a is in the cluster already.
        for sealed_before in [true, false] {
            let (_dir, _tmp, n, fc, _sd, store) = brain();
            put(&n.root, K3S_AGENT_TOKEN, format!("{TOKEN}\n"));
            put(&n.root, K3S_NODES, format!(r#"{{"node-a":"{WG_PUBKEY}"}}"#));
            if sealed_before {
                put(&n.root, K3S_SEALED, r#"{"2":"abc"}"#);
            }
            fc.cluster.lock().unwrap().nodes = "node/coord\nnode/node-a\n".into();
            n.k3s_share(&ctx, Some(&store), &members, NOW);
            assert!(warned(&n), "{}", get(&n.root, K3S_SHARE_STATUS));
            assert!(!n.path(K3S_SEALED).exists() && get(&n.root, K3S_SHARED).trim() == fsx::hex(&sha2::Sha256::digest(TOKEN)));
            n.k3s_share(&ctx, Some(&store), &members, NOW + 60);
            assert!(warned(&n));
            // The admin made a new one.
            put(&n.root, K3S_AGENT_TOKEN, format!("{TOKEN2}\n"));
            n.k3s_share(&ctx, Some(&store), &members, NOW + 120);
            assert!(!warned(&n) && !n.path(SHARED_ISSUE).exists() && !n.path(K3S_SHARED).exists(), "{}", get(&n.root, K3S_SHARE_STATUS));
            n.k3s_share(&ctx, Some(&store), &members, NOW + 180);
            assert!(!n.path(SHARED_ISSUE).exists());
        }
        // A new cluster: node-a joins with its own token, nothing to say.
        let (_dir, _tmp, n, fc, _sd, store) = brain();
        put(&n.root, K3S_AGENT_TOKEN, format!("{TOKEN}\n"));
        n.k3s_share(&ctx, Some(&store), &members, NOW);
        fc.cluster.lock().unwrap().nodes = "node/coord\nnode/node-a\n".into();
        n.k3s_share(&ctx, Some(&store), &members, NOW + 60);
        assert!(!warned(&n) && !n.path(K3S_SHARED).exists(), "{}", get(&n.root, K3S_SHARE_STATUS));
        // A node under a member's name that came without the password root
        // made for it: someone held a token (maybe the shared one). The
        // name is taken, and the alarm says where to look.
        n.k3s_share(&ctx, Some(&store), &[coord_member(), node_member(2), node_c()], NOW + 120);
        fc.cluster.lock().unwrap().passwords.remove("node-c");
        assert!(fc.agent("node-c", &k3stoken::new_password()));
        n.k3s_share(&ctx, Some(&store), &[coord_member(), node_member(2), node_c()], NOW + 180);
        let status = get(&n.root, K3S_SHARE_STATUS);
        assert!(status.starts_with("ALARM: the name node-c is taken") && status.contains("A new cluster token"), "{status}");
        assert!(!warned(&n) && get(&n.root, NAMES_ISSUE).contains("node-c is taken"));
    }

    /// A coordinator (its own WireGuard key is the one the admin signs as
    /// host 1) with a registry in a directory of its own.
    fn brain() -> (TempDir, TempDir, Node, Arc<FakeCoord>, TempDir, Store) {
        let (dir, tmp, n, fc) = joined();
        put(&n.root, WG_PUB, format!("{COORD_WG}\n"));
        put(&n.root, HOST_KEY_PUB, format!("{COORD_KEY} root@coord\n"));
        put(&n.root, HOST_KEY, "coord private\n");
        let n = Node { hostname: "coord".into(), ..n };
        let store_dir = TempDir::new();
        let store = Store::new(store_dir.join("registry.json"));
        (dir, tmp, n, fc, store_dir, store)
    }

    fn registry(store: &Store, members: Vec<Member>, env: Envelope) {
        store
            .update(|s| {
                s.members = members;
                s.signed_version = env.list(&ADMIN, |_| true).map(|l| l.version).unwrap_or(0);
                s.signed = env;
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn coordinator_code_leaves_the_console_once_signed() {
        let (_dir, _tmp, n, _, _sd, store) = brain();
        registry(&store, vec![coord_member()], Envelope::default());
        put(&n.root, ISSUE_FILE, coordinator_issue("123 456"));
        assert!(get(&n.root, ISSUE_FILE).contains("Sign only if it shows this code:  123 456"));
        sync(&Ctx::new(), &n, true, &store).unwrap();
        assert!(!get(&n.root, ISSUE_FILE).is_empty(), "the code must stay until a list is signed");
        // A version number alone (the registry account can write one) is
        // no signature.
        store
            .update(|s| {
                s.signed_version = 9;
                Ok(())
            })
            .unwrap();
        sync(&Ctx::new(), &n, true, &store).unwrap();
        assert!(!get(&n.root, ISSUE_FILE).is_empty(), "the code went without a signed list");
        registry(&store, vec![coord_member()], sign(&ADMIN, 9, vec![coord_entry()]));
        sync(&Ctx::new(), &n, true, &store).unwrap();
        assert!(get(&n.root, ISSUE_FILE).is_empty(), "the code must go once the admin signed");
    }

    /// On the coordinator the members come from the registry file, which
    /// the registry account can write: a name with a newline there must
    /// not add an SSH `Match exec` or anything else to root's files.
    #[test]
    fn coordinator_checks_the_registry_members() {
        let (_dir, _tmp, n, _, _sd, store) = brain();
        let evil = Member { name: "node-b\nMatch exec \"touch /tmp/pwned\"".into(), ..node_member(2) };
        let key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [7u8; 32]);
        let good = Member { name: "node-c".into(), wg_key: key.clone(), ..node_member(3) };
        let signed = Entry { host: 3, name: "node-c".into(), wg_key: key, ssh_host_key: signed::key_body(NODE_KEY) };
        registry(&store, vec![coord_member(), evil, good], sign(&ADMIN, 4, vec![coord_entry(), signed]));
        sync(&Ctx::new(), &n, true, &store).unwrap();
        for f in ["/etc/ssh/ssh_config.d/20-dryserver.conf", "/etc/ssh/ssh_known_hosts", "/etc/hosts", WG_CONF] {
            let out = get(&n.root, f);
            assert!(!out.contains("Match") && !out.contains("pwned"), "{f}:\n{out}");
        }
        let cfg = get(&n.root, "/etc/ssh/ssh_config.d/20-dryserver.conf");
        assert!(cfg.contains("Host coord node-c\n") && !cfg.contains("node-b"), "{cfg}");
    }

    /// The registry account (every server reaches it) writes the
    /// registry file. What root on the coordinator puts into the mesh and
    /// the cluster from it is exactly what the admin signed.
    #[test]
    fn the_coordinator_uses_only_the_list_the_admin_signed() {
        let (_dir, _tmp, n, fc, _sd, store) = brain();
        put(&n.root, K3S_AGENT_TOKEN, format!("{TOKEN}\n"));
        fc.cluster.lock().unwrap().nodes = "node/coord\nnode/node-a\nnode/ghost\n".into();
        let c = other_entry();
        let node_c = Member {
            host: 3,
            name: c.name,
            wg_key: c.wg_key,
            ssh_host_key: c.ssh_host_key,
            lan_ip: "192.168.1.30".into(),
            ..Member::default()
        };
        let list = sign(&ADMIN, 5, vec![coord_entry(), node_entry(2), other_entry()]);
        registry(&store, vec![coord_member(), Member { lan_ip: "192.168.1.20".into(), ..node_member(2) }, node_c.clone()], list.clone());
        sync(&Ctx::new(), &n, true, &store).unwrap();
        let wg = get(&n.root, WG_CONF);
        assert!(wg.contains(WG_PUBKEY) && wg.contains(OTHER_WG) && !wg.contains("Endpoint"), "{wg}");
        assert!(get(&n.root, SIGNED_FILE).contains(&list.sig), "the version this coordinator has seen");

        // A machine of its own beside them, and node-a gone: neither
        // reaches the mesh files, and the cluster keeps node-a.
        let rogue = Member {
            host: 9,
            name: "rogue".into(),
            wg_key: EVIL_WG.into(),
            ssh_host_key: "ssh-ed25519 AAAAevil".into(),
            ..Member::default()
        };
        registry(&store, vec![coord_member(), node_c.clone(), rogue], list.clone());
        fc.k3s.lock().unwrap().clear();
        sync(&Ctx::new(), &n, true, &store).unwrap();
        let wg = get(&n.root, WG_CONF);
        assert!(!wg.contains(EVIL_WG) && wg.contains(WG_PUBKEY), "{wg}");
        for f in ["/etc/hosts", "/etc/ssh/ssh_known_hosts"] {
            assert!(!get(&n.root, f).contains("rogue") && get(&n.root, f).contains("node-a"), "{f}");
        }
        assert!(!fc.k3s.lock().unwrap().iter().any(|c| c.contains("delete node node-a")), "{:?}", fc.k3s.lock().unwrap());

        // Unsigned lists change nothing: an older one (it would bring back
        // a machine the admin removed), a forged one, one without this
        // coordinator, none at all (the registry account dropped it). The
        // mesh and the cluster follow the newest list this coordinator has
        // seen, and nothing new goes through the registry.
        let before = get(&n.root, WG_CONF);
        let refused = [
            (sign(&ADMIN, 4, vec![coord_entry(), other_entry()]), "older than version 5"),
            (sign(&Key("thief"), 7, vec![coord_entry()]), "bad signature"),
            // Another machine signed in this coordinator's place: it leaves
            // nothing and stops nobody, it only refuses.
            (sign(&ADMIN, 7, vec![Entry { wg_key: EVIL_WG.into(), ..coord_entry() }, node_entry(2)]), "removed this server"),
            (Envelope::default(), "no signed member list"),
        ];
        for (env, want) in refused {
            registry(&store, vec![coord_member()], env);
            fc.k3s.lock().unwrap().clear();
            let e = sync(&Ctx::new(), &n, true, &store).unwrap_err().to_string();
            assert!(e.contains(want) && e.contains("follow version 5"), "{want}: {e}");
            assert_eq!(get(&n.root, WG_CONF), before, "{want}");
            let calls = fc.k3s.lock().unwrap().clone();
            assert!(!calls.iter().any(|c| c.contains("node-a") || c.starts_with("token")), "{want}: {calls:?}");
            assert!(get(&n.root, SIGNED_STATUS).contains("REFUSED") && get(&n.root, REGISTRY_ISSUE).contains("ALARM"), "{want}");
            assert!(get(&n.root, SIGNED_FILE).contains(&list.sig), "{want}");
        }
        // The registry is right again: the alarm goes.
        registry(&store, vec![coord_member(), node_member(2), node_c.clone()], list.clone());
        sync(&Ctx::new(), &n, true, &store).unwrap();
        assert!(!n.path(REGISTRY_ISSUE).exists() && get(&n.root, SIGNED_STATUS).starts_with("ok"));
        // Before the first signature the coordinator is alone, and nobody
        // leaves its cluster.
        let (_dir, _tmp, n, fc, _sd, store) = brain();
        put(&n.root, K3S_AGENT_TOKEN, format!("{TOKEN}\n"));
        registry(&store, vec![coord_member(), node_member(2)], Envelope::default());
        sync(&Ctx::new(), &n, true, &store).unwrap();
        assert!(!get(&n.root, WG_CONF).contains("[Peer]"), "{}", get(&n.root, WG_CONF));
        assert!(fc.k3s.lock().unwrap().is_empty(), "{:?}", fc.k3s.lock().unwrap());
    }

    /// The registry account can stall the registry: hold its lock, write
    /// more than is read, junk, or an older list. Root's sync then follows
    /// the newest list it has seen: a server the admin removed stays out of
    /// the mesh and the cluster, and the console says what happened.
    #[test]
    fn a_stalled_registry_stalls_no_removal() {
        let (_dir, _tmp, n, fc, sd, store) = brain();
        let c = other_entry();
        let node_c = Member { lan_ip: "192.168.1.30".into(), ..node_c() };
        let v5 = sign(&ADMIN, 5, vec![coord_entry(), node_entry(2), c.clone()]);
        fc.cluster.lock().unwrap().nodes = "node/coord\nnode/node-a\nnode/node-c\n".into();
        registry(&store, vec![coord_member(), node_member(2), node_c.clone()], v5.clone());
        sync(&Ctx::new(), &n, true, &store).unwrap();
        assert!(get(&n.root, WG_CONF).contains(OTHER_WG));
        // The admin removes node-c.
        let v6 = sign(&ADMIN, 6, vec![coord_entry(), node_entry(2)]);
        registry(&store, vec![coord_member(), node_member(2)], v6.clone());
        sync(&Ctx::new(), &n, true, &store).unwrap();
        let kept = get(&n.root, WG_CONF);
        assert!(!kept.contains(OTHER_WG) && kept.contains(WG_PUBKEY), "{kept}");
        let lock = std::fs::File::open(sd.join("registry.json.lock")).unwrap();
        let quick = Store { lock_wait: Duration::from_millis(50), ..store.clone() };
        type Stall<'a> = Box<dyn Fn() + 'a>;
        let stalls: Vec<(&str, Stall)> = vec![
            ("older than version 6", Box::new(|| registry(&store, vec![coord_member(), node_member(2), node_c.clone()], v5.clone()))),
            (
                "held by another process",
                Box::new(|| {
                    // SAFETY: flock on a file this test holds open.
                    assert_eq!(unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX) }, 0);
                }),
            ),
            (
                "larger than",
                Box::new(|| {
                    // SAFETY: as above; the lock goes, the file grows.
                    unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_UN) };
                    std::fs::File::create(&store.path).unwrap().set_len(registry::MAX_FILE + 1).unwrap();
                }),
            ),
            ("cannot use the registry", Box::new(|| std::fs::write(&store.path, "{\"members\": [").unwrap())),
        ];
        for (want, stall) in stalls {
            stall();
            // node-c's kubelet registers its node again: it goes again.
            fc.cluster.lock().unwrap().nodes = "node/coord\nnode/node-a\nnode/node-c\n".into();
            fc.k3s.lock().unwrap().clear();
            let e = sync(&Ctx::new(), &n, true, &quick).unwrap_err().to_string();
            assert!(e.contains(want) && e.contains("follow version 6"), "{want}: {e}");
            assert_eq!(get(&n.root, WG_CONF), kept, "{want}");
            let calls = fc.k3s.lock().unwrap().clone();
            assert!(calls.contains(&"kubectl delete node node-c --timeout=20s".to_string()), "{want}: {calls:?}");
            assert!(!calls.iter().any(|c| c.starts_with("token")), "{want}: {calls:?}");
            let alarm = get(&n.root, REGISTRY_ISSUE);
            assert!(alarm.contains("ALARM") && alarm.contains("version 6") && alarm.contains("quarantine-all"), "{want}: {alarm}");
        }
        // Its own list damaged too: nothing is applied.
        put(&n.root, SIGNED_FILE, "{\"doc\": ");
        let e = sync(&Ctx::new(), &n, true, &quick).unwrap_err().to_string();
        assert!(e.contains("left as they are"), "{e}");
        assert_eq!(get(&n.root, WG_CONF), kept);
        // Before the first signed list, an unreadable registry applies
        // nothing either.
        let (_dir, _tmp, n, fc, _sd, store) = brain();
        std::fs::write(&store.path, "{\"members\": [").unwrap();
        assert!(sync(&Ctx::new(), &n, true, &store).is_err());
        assert!(get(&n.root, WG_CONF).is_empty() && fc.k3s.lock().unwrap().is_empty());
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

    const EVIL_PIN: &str = "192.168.1.50 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIevil\n";

    fn fast() -> Pace {
        Pace { poll: Duration::from_millis(1), retry: Duration::from_millis(1), pause: Duration::from_millis(1) }
    }

    fn join_params(n: &Node) -> Params {
        let plan = packages::resolve(&[], &[]).unwrap();
        Params { config: n.cfg.clone(), plan, hostname: "node-a".into(), role: sysconf::Role::Node, ..Params::default() }
    }

    /// Something on the home network answered in the coordinator's place
    /// when the request went out: this machine pinned its key, and every
    /// poll of the real coordinator fails on it. Its code can never be
    /// approved; without a way out the machine waits for good.
    #[test]
    fn a_coordinator_key_pinned_from_someone_else_is_forgotten() {
        let env = sign(&ADMIN, 3, vec![coord_entry(), node_entry(4)]);
        let (_dir, n, fc) = setup(vec![approved(4, env)]);
        put(&n.root, KNOWN_HOSTS, EVIL_PIN);
        n.save_state(&State { request_id: "fedcba9876543210".into(), code: "111 111".into(), host: 0 }).unwrap();
        let mut log = Vec::new();
        joining(&Ctx::new().with_timeout(Duration::from_secs(20)), &n, &join_params(&n), &mut log, &fast()).unwrap();
        let log = String::from_utf8_lossy(&log).to_string();
        let calls = fc.calls.lock().unwrap().clone();
        let polls = calls.iter().take_while(|c| c.ends_with("status fedcba9876543210")).count();
        assert_eq!(polls as u32, HOST_KEY_TRIES, "{calls:?}");
        assert_eq!(calls[HOST_KEY_TRIES as usize], "dryreg@192.168.1.50 request", "a new request after forgetting: {calls:?}");
        let code = registry::pairing_code(WG_PUBKEY, NODE_KEY, COORD_KEY);
        assert!(log.contains("answers with another SSH host key") && log.contains("only the code below counts"), "{log}");
        assert!(log.contains(&format!("Approve only if it shows this code:  {code}")), "{log}");
        assert!(get(&n.root, KNOWN_HOSTS).contains(COORD_KEY) && !get(&n.root, KNOWN_HOSTS).contains("evil"));
        assert_eq!(n.load_state().host, 4, "joined with the real coordinator");
    }

    /// The same when the pinned key fails the request itself (it expired
    /// while someone else answered, or the machine left and the
    /// coordinator was installed again).
    #[test]
    fn a_request_that_keeps_failing_on_the_key_starts_over() {
        let env = sign(&ADMIN, 3, vec![coord_entry(), node_entry(4)]);
        let (_dir, n, fc) = setup(vec![approved(4, env)]);
        put(&n.root, KNOWN_HOSTS, EVIL_PIN);
        let mut log = Vec::new();
        joining(&Ctx::new().with_timeout(Duration::from_secs(20)), &n, &join_params(&n), &mut log, &fast()).unwrap();
        let calls = fc.calls.lock().unwrap().clone();
        assert_eq!(calls.iter().filter(|c| c.ends_with(" request")).count() as u32, HOST_KEY_TRIES + 1, "{calls:?}");
        assert!(String::from_utf8_lossy(&log).contains("only the code below counts"));
        assert_eq!(n.load_state().host, 4);
    }

    /// A coordinator that does not answer for a while is no reason to
    /// forget its key, and neither are key failures with anything else
    /// between them.
    /// The UX bug seen on the VM: a request the coordinator turned down
    /// showed as "cannot reach the coordinator". The reason comes first,
    /// with what to do and the code the approval screen shows.
    #[test]
    fn a_refused_request_says_why_first() {
        for (script, want) in [("member", "the name node-a is a member already"), ("squat", "another machine is asking to join as node-a")]
        {
            let env = sign(&ADMIN, 3, vec![coord_entry(), node_entry(4)]);
            let (_dir, n, fc) = setup(vec![approved(4, env)]);
            *fc.script.lock().unwrap() = vec![script, script];
            let mut log = Vec::new();
            joining(&Ctx::new().with_timeout(Duration::from_secs(20)), &n, &join_params(&n), &mut log, &fast()).unwrap();
            let log = String::from_utf8(log).unwrap();
            let first = log.lines().next().unwrap();
            assert!(first.starts_with("dryserver: the coordinator turned this machine's request down: ") && first.contains(want), "{log}");
            let code = registry::pairing_code(WG_PUBKEY, NODE_KEY, COORD_KEY);
            assert!(log.contains("dryserver approve") && log.contains(&format!("This machine's code is {code}")), "{log}");
            assert!(!log.contains("cannot reach"), "{log}");
            // It asks again by itself, and joins once the name is free.
            assert_eq!(n.load_state().host, 4, "{script}");
        }
    }

    #[test]
    fn a_coordinator_that_is_away_keeps_its_pin() {
        let tries = HOST_KEY_TRIES as usize;
        let scripts: Vec<Vec<&str>> =
            vec![vec!["down"; 3 * tries], vec!["key"; tries - 1], [vec!["key"; tries - 1], vec!["down"], vec!["key"; tries - 1]].concat()];
        for script in scripts {
            let env = sign(&ADMIN, 3, vec![coord_entry(), node_entry(4)]);
            let (_dir, n, fc) = setup(vec![StatusReply { status: Status::Pending, ..StatusReply::default() }, approved(4, env)]);
            n.request(&Ctx::new(), "192.168.1.23", false).unwrap();
            *fc.script.lock().unwrap() = script.clone();
            joining(&Ctx::new().with_timeout(Duration::from_secs(20)), &n, &join_params(&n), &mut Vec::new(), &fast()).unwrap();
            let calls = fc.calls.lock().unwrap().clone();
            assert_eq!(calls.iter().filter(|c| c.ends_with(" request")).count(), 1, "asked again after {script:?}: {calls:?}");
            assert!(get(&n.root, KNOWN_HOSTS).contains(COORD_KEY) && n.load_state().host == 4, "{script:?}");
        }
    }

    #[test]
    fn a_damaged_record_of_the_newest_list_takes_no_list() {
        let (_dir, _tmp, n, fc) = joined();
        let store = Store::new("/nonexistent");
        let ctx = Ctx::new();
        let v5 = sign(&ADMIN, 5, vec![coord_entry(), node_entry(2), other_entry()]);
        *fc.peers.lock().unwrap() = Some(peers(&[coord_member(), node_member(2)], &v5));
        assert!(sync(&ctx, &n, false, &store).unwrap());
        let kept = get(&n.root, WG_CONF);
        // The record is damaged; the coordinator then serves an older list
        // without node-c. Taken for "none seen", it would pass as new.
        put(&n.root, SIGNED_FILE, "{\"doc\": \"{\\\"version\\\":");
        let v3 = sign(&ADMIN, 3, vec![coord_entry(), node_entry(2)]);
        *fc.peers.lock().unwrap() = Some(peers(&[coord_member(), node_member(2)], &v3));
        let e = sync(&ctx, &n, false, &store).unwrap_err().to_string();
        assert!(e.contains("is damaged") && e.contains("mesh left as it is"), "{e}");
        assert_eq!(get(&n.root, WG_CONF), kept);
        assert_eq!(get(&n.root, SIGNED_FILE), "{\"doc\": \"{\\\"version\\\":", "the record was written over");
        assert!(get(&n.root, SIGNED_STATUS).contains("REFUSED"));
        // Removed by the admin's hand: the coordinator's list is taken.
        std::fs::remove_file(n.path(SIGNED_FILE)).unwrap();
        assert!(sync(&ctx, &n, false, &store).unwrap());
        assert!(get(&n.root, SIGNED_FILE).contains(&v3.sig));
    }

    #[test]
    fn join_never_writes_over_a_damaged_join_state() {
        let (_dir, n, fc) = setup(vec![StatusReply { status: Status::Pending, ..StatusReply::default() }]);
        put(&n.root, JOIN_STATE, "{\"host\": 4,");
        let plan = packages::resolve(&[], &[]).unwrap();
        let params = Params { config: n.cfg.clone(), plan, hostname: "node-a".into(), ..Params::default() };
        let e = join_loop(&Ctx::new(), &n, &params, &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("damaged") && e.contains("not asking to join"), "{e}");
        assert!(fc.calls.lock().unwrap().is_empty(), "a request was sent");
        assert_eq!(get(&n.root, JOIN_STATE), "{\"host\": 4,", "the one record of its mesh number was written over");
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

    /// A server signs its report, with its LAN address, with its own host
    /// key: the registry account relays it to root and to the admin.
    #[test]
    fn a_server_signs_its_report() {
        let (_dir, tmp, n, fc) = joined();
        assert!(sync(&Ctx::new(), &n, false, &Store::new("/nonexistent")).unwrap());
        let hb: Heartbeat = serde_json::from_str(&fc.heartbeat.lock().unwrap()).unwrap();
        let r = hb.report.unwrap();
        assert_eq!((r.lan.as_str(), hb.lan_ip.as_str()), ("192.168.1.23", "192.168.1.23"));
        let check = |r: &Report, host: u32, wg: &str, key: &str| r.verify(&Ctx::new(), fc.as_ref(), tmp.path(), host, wg, key).is_ok();
        assert!(check(&r, 2, WG_PUBKEY, NODE_KEY), "{:?}", r.sig);
        // As the registry keeps it (sanitized), still.
        let kept = r.clone().sanitized(|h| h == 1);
        assert!(check(&kept, 2, WG_PUBKEY, NODE_KEY));
        // Not for another machine, and not changed.
        assert!(!check(&r, 3, WG_PUBKEY, NODE_KEY) && !check(&r, 2, OTHER_WG, NODE_KEY) && !check(&r, 2, WG_PUBKEY, COORD_KEY));
        for changed in [
            Report { release: 99, ..r.clone() },
            Report { lan: "192.168.1.66".into(), ..r.clone() },
            Report { update: "pending".into(), ..r.clone() },
        ] {
            assert!(!check(&changed, 2, WG_PUBKEY, NODE_KEY), "{changed:?}");
        }
        assert!(get(&n.root, REPORT_STATUS).trim().is_empty());
        // Without its host key it sends the report unsigned, and says so.
        std::fs::remove_file(n.path(HOST_KEY)).unwrap();
        assert!(sync(&Ctx::new(), &n, false, &Store::new("/nonexistent")).unwrap());
        let hb: Heartbeat = serde_json::from_str(&fc.heartbeat.lock().unwrap()).unwrap();
        assert!(hb.report.unwrap().sig.is_empty() && get(&n.root, REPORT_STATUS).contains("host key"));
    }

    /// The review's case: the registry account could have a server pass
    /// for updated (release, update state) for the rollout. Root takes a
    /// server's report only signed by that server; an older server's
    /// unsigned one only while it says it runs a release from before
    /// reports were signed.
    #[test]
    fn review_the_rollout_takes_only_reports_servers_signed() {
        let (_dir, tmp, coord, fc, _sd, _store) = brain();
        let ctx = Ctx::new();
        let now = Time::now().0.timestamp();
        // node-a's real report, and the registry account's.
        let (_d2, t2, server, sfc) = joined();
        let mut real = Report { time: now, release: 4, ..Report::default() };
        real.sign(&ctx, sfc.as_ref(), &server.path(HOST_KEY), 2, WG_PUBKEY).unwrap();
        drop(t2);
        let with = |r: Option<Report>| vec![coord_member(), Member { report: r, ..node_member(2) }];
        let taken =
            |r: Option<Report>| coord.trusted_reports(&ctx, with(r), &Report { release: 5, ..Report::default() }, now)[1].report.clone();
        assert_eq!(taken(Some(real.clone())), Some(real.clone()), "its own signed report");
        let forged = [
            Report { release: 6, ..real.clone() },
            Report { update: String::new(), update_serial: 0, release: 9, sig: String::new(), ..real.clone() },
            Report {
                sig: signed::fake::host_sig(COORD_KEY, signed::NS_REPORT, &Report { release: 6, ..real.clone() }.signed_text(2, WG_PUBKEY)),
                release: 6,
                ..real.clone()
            },
            Report { sig: signed::fake::host_sig(NODE_KEY, signed::NS_TURN, &real.signed_text(2, WG_PUBKEY)), ..real.clone() },
        ];
        for f in forged {
            assert_eq!(taken(Some(f.clone())), None, "{f:?}");
        }
        assert!(get(&coord.root, REPORTS_STATUS).contains("node-a: "), "{}", get(&coord.root, REPORTS_STATUS));
        // Since: the release this coordinator ran when it first checked
        // (5). An older server says it runs 4, unsigned: taken as before.
        assert!(get(&coord.root, SIGNED_REPORTS).contains(r#""since":5"#), "{}", get(&coord.root, SIGNED_REPORTS));
        let old = Report { sig: String::new(), ..real.clone() };
        assert_eq!(taken(Some(old.clone())), Some(old));
        // An older signed report than one taken: not taken again.
        let mut older = Report { time: now - 600, ..real.clone() };
        older.sig.clear();
        older.sign(&ctx, sfc.as_ref(), &server.path(HOST_KEY), 2, WG_PUBKEY).unwrap();
        assert_eq!(taken(Some(older)), None, "a replayed older report");
        let mut stale = Report { time: now - REPORT_MAX_AGE - 1, ..real.clone() };
        stale.sig.clear();
        stale.sign(&ctx, sfc.as_ref(), &server.path(HOST_KEY), 2, WG_PUBKEY).unwrap();
        std::fs::remove_file(coord.path(SIGNED_REPORTS)).unwrap();
        assert_eq!(taken(Some(stale)), None, "a day old");
        // The coordinator's own report and members without one pass.
        let out = coord.trusted_reports(&ctx, with(None), &Report::default(), now);
        assert_eq!(out.len(), 2);
        let _ = (tmp, fc);
    }

    /// Root leaves a receipt for the list its mesh follows, signed with its
    /// host key, made again when the list changes or every five minutes.
    #[test]
    fn the_coordinator_leaves_a_receipt_for_the_list_it_follows() {
        let (_dir, tmp, b, fc, _sd, store) = brain();
        let env = sign(&ADMIN, 5, vec![coord_entry(), node_entry(2)]);
        registry(&store, vec![coord_member(), node_member(2)], env.clone());
        sync(&Ctx::new(), &b, true, &store).unwrap();
        let r = store.read().unwrap().receipt;
        let sha = fsx::hex(&sha2::Sha256::digest(env.doc.as_bytes()));
        assert_eq!((r.version, r.sha256.as_str()), (5, sha.as_str()));
        let text = registry::Receipt::text(r.version, &r.sha256, r.time);
        assert!(signed::host_verify(&Ctx::new(), fc.as_ref(), tmp.path(), COORD_KEY, signed::NS_RECEIPT, &text, &r.sig).is_ok());
        // Nothing new: the same receipt.
        sync(&Ctx::new(), &b, true, &store).unwrap();
        assert_eq!(store.read().unwrap().receipt, r);
        // The registry account puts another one there: root makes its own
        // again. A newer list: a receipt for it.
        store
            .update(|s| {
                s.receipt.version = 7;
                Ok(())
            })
            .unwrap();
        sync(&Ctx::new(), &b, true, &store).unwrap();
        assert_eq!(store.read().unwrap().receipt.version, 5);
        let env6 = sign(&ADMIN, 6, vec![coord_entry()]);
        registry(&store, vec![coord_member()], env6);
        sync(&Ctx::new(), &b, true, &store).unwrap();
        assert_eq!(store.read().unwrap().receipt.version, 6);
        // A registry that holds an older list back: root follows its own
        // newest, and leaves no receipt for the old one (it cannot write).
        registry(&store, vec![coord_member(), node_member(2)], env);
        assert!(sync(&Ctx::new(), &b, true, &store).is_err());
        assert_eq!(store.read().unwrap().receipt.version, 6);
    }
}
