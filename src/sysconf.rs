//! The system files written to every installed server: firewall, SSH,
//! kernel hardening, network, Docker and login settings. Rendering is pure
//! so the output can be golden-tested and validated with the real tools
//! (nft -c, sshd -t).

use std::fmt;
use std::net::Ipv4Addr;

use crate::cidr::Cidr;
use crate::config::{self, Config, Port};
use crate::err::{Context, Result};
use crate::install::boot;
use crate::{backup, coredns, errf, fsx, packages, quarantine};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Role {
    #[default]
    Node,
    Coordinator,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Node => "node",
            Role::Coordinator => "coordinator",
        }
    }

    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "node" => Some(Role::Node),
            "coordinator" => Some(Role::Coordinator),
            _ => None,
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The locked account on the coordinator that runs the registry as an SSH
/// forced command.
pub const REGISTRY_USER: &str = "dryreg";
/// Its home. It belongs to root: the account runs code that anyone with
/// the USB stick's key reaches, and it must not be able to change what
/// sshd reads for it.
pub const REGISTRY_HOME: &str = "/var/lib/dryreg";
/// Its SSH key, where only root may change it.
pub const REGISTRY_KEYS: &str = "/etc/ssh/authorized_keys.d/dryreg";
/// Makes the home root's on machines installed before (at boot).
pub const REGISTRY_TMPFILES: &str = "/etc/tmpfiles.d/dryserver-registry.conf";
const REGISTRY_TMPFILES_TEXT: &str = "# dryserver: the registry account's home and the SSH files in it belong to
# root, so code running as the account cannot swap its key for one without
# the forced command.
d /var/lib/dryreg 0755 root root -
z /var/lib/dryreg/.ssh 0755 root root -
z /var/lib/dryreg/.ssh/authorized_keys 0644 root root -
";

/// What the registry account runs, for the subnet of the mesh: the forced
/// command of its key and of sshd.
pub fn registry_command(mesh: &Cidr) -> String {
    format!("/usr/local/bin/dryserver registry --subnet {}", mesh.network_string())
}

#[derive(Debug, Clone, Default)]
pub struct Params {
    pub config: Config,
    pub plan: packages::Plan,
    pub hostname: String,
    pub role: Role,
    /// This machine's mesh host number (10.66.0.N). 0 means not approved
    /// yet: files that need it are rendered without it.
    pub host_num: u32,
    /// The Ethernet port that gets the switch address (auto mode). Empty
    /// when the machine has no Ethernet port.
    pub switch_mac: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct File {
    pub path: String,
    pub mode: u32,
    pub content: String,
}

fn file(path: impl Into<String>, mode: u32, content: impl Into<String>) -> File {
    File { path: path.into(), mode, content: content.into() }
}

/// Every system file for the machine described by p.
pub fn render(p: &Params) -> Result<Vec<File>> {
    let c = &p.config;
    c.validate()?;
    let mesh_ports = config::parse_ports(&c.mesh_ports).unwrap_or_default();
    let egress_ports = config::parse_ports(&c.egress_ports).unwrap_or_default();

    let mut switch_addr = String::new();
    if c.wg_transport == config::TRANSPORT_AUTO && p.host_num > 0 {
        switch_addr = host_addr(&c.switch_subnet, p.host_num).wrap("switch address")?;
    }
    // The firewall, SSH and the registry's command take the values as
    // parsed, in their one plain form, never the config's text: a spelling
    // nft does not take would leave the machine without a firewall.
    let plain = |what: &str| errf!("{what} is not in its plain form; fix it in config.env");
    let wg_port = config::port_number(&c.wg_port).ok_or_else(|| plain("WG_PORT"))?;
    let coord_lan = config::ipv4(&c.coord_lan_ip).ok_or_else(|| plain("COORD_LAN_IP"))?;
    let mesh = Cidr::parse(&c.wg_subnet).ok_or_else(|| plain("WG_SUBNET"))?;
    let switch = match c.wg_transport == config::TRANSPORT_AUTO {
        true => Some(Cidr::parse(&c.switch_subnet).ok_or_else(|| plain("SWITCH_SUBNET"))?),
        false => None,
    };
    let coord_mesh = Ipv4Addr::from(mesh.network().wrapping_add(1));

    // The node keeps the settings it needs for sync, but not the WiFi
    // password: iwd has its own copy.
    let node_cfg = Config { wifi_pass: String::new(), ..c.clone() };

    let mut files = vec![
        file("/etc/hostname", 0o644, format!("{}\n", p.hostname)),
        file("/etc/hosts", 0o644, hosts(&p.hostname)),
        file(
            "/etc/nftables.conf",
            0o600,
            nftables(&Firewall {
                role: p.role,
                wg_port,
                switch,
                mesh,
                coord_mesh,
                coord_lan,
                mesh_tcp: ports_of(&mesh_ports, "tcp"),
                mesh_udp: ports_of(&mesh_ports, "udp"),
                out_tcp: ports_of(&egress_ports, "tcp"),
                out_udp: ports_of(&egress_ports, "udp"),
            }),
        ),
        file("/etc/ssh/sshd_config.d/10-dryserver.conf", 0o644, sshd(&c.username, p.role, &mesh)),
        file(
            format!("/home/{}/.ssh/authorized_keys", c.username),
            0o600,
            format!("{}\n", format!("{} {}", config::normalize_pubkey(&c.admin_ssh_pubkey), c.admin_key_label).trim()),
        ),
        file("/etc/sudoers.d/10-wheel", 0o440, "# Members of wheel may use sudo after typing their password.\n%wheel ALL=(ALL:ALL) ALL\n"),
        file("/etc/sysctl.d/90-dryserver.conf", 0o644, SYSCTL),
        file("/etc/systemd/network/20-wired.network", 0o644, WIRED),
        file("/etc/systemd/network/25-wireless.network", 0o644, WIRELESS),
        file("/etc/systemd/system/systemd-networkd-wait-online.service.d/any.conf", 0o644, WAIT_ONLINE),
        file("/etc/systemd/logind.conf.d/10-lid.conf", 0o644, LID),
        file("/etc/systemd/resolved.conf.d/10-dryserver.conf", 0o644, RESOLVED),
        file("/etc/systemd/zram-generator.conf", 0o644, ZRAM),
        file("/etc/dryserver/config.env", 0o600, node_cfg.render()),
        file("/etc/dryserver/role", 0o644, format!("{}\n", p.role)),
        file("/etc/systemd/system/dryserver-join.service", 0o644, JOIN_UNIT),
        file("/etc/systemd/system/dryserver-sync.service", 0o644, SYNC_UNIT),
        file("/etc/systemd/system/k3s.service", 0o644, k3s_unit(p.role)),
        file("/etc/systemd/system/dryserver-sync.timer", 0o644, SYNC_TIMER),
        file("/etc/systemd/system/dryserver-tpm-enroll.service", 0o644, TPM_ENROLL_UNIT),
        // Reverts an update that was not confirmed in time, also after a
        // reboot in the middle of one (see src/update.rs).
        file(crate::update::GUARD_UNIT_PATH, 0o644, crate::update::GUARD_UNIT_TEXT),
        // A kernel update that does not boot falls back to the other
        // kernel (see src/install/boot.rs). Harmless where nothing is
        // counted: BIOS machines, and ones installed without linux-lts.
        file(boot::POST_HOOK, 0o755, boot::POST_HOOK_TEXT),
        file(boot::MARK_HOOK, 0o644, boot::MARK_HOOK_TEXT),
        file(boot::CHECK_UNIT_PATH, 0o644, boot::CHECK_UNIT_TEXT),
        file(boot::COMPLETE_DROPIN, 0o644, boot::COMPLETE_DROPIN_TEXT),
        file(boot::WATCHDOG_DROPIN, 0o644, boot::WATCHDOG_TEXT),
        file(boot::EMERGENCY_DROPIN, 0o644, boot::EMERGENCY_TEXT),
    ];
    if p.role == Role::Coordinator {
        files.push(file("/etc/cron.d/dryserver-scan", 0o644, SCAN_CRON));
        files.push(file(REGISTRY_TMPFILES, 0o644, REGISTRY_TMPFILES_TEXT));
        let mesh1 = coord_mesh.to_string();
        // No secret in it, and kubectl (run by the admin) reads it too.
        files.push(file(K3S_CONFIG, 0o644, k3s_server_config(&mesh1)));
        files.push(file(K3S_INGRESS_CONFIG, 0o600, K3S_INGRESS));
        files.push(file(coredns::PDB_PATH, 0o600, coredns::PDB));
        files.push(file(format!("/etc/systemd/system/{DNS_NAME}.service"), 0o644, DNS_UNIT));
        files.push(file(format!("/etc/systemd/system/{DNS_TIMER}"), 0o644, DNS_TIMER_UNIT));
        files.push(file("/etc/systemd/system/dryserver-backup.service", 0o644, BACKUP_UNIT_TEMPLATE.replace("{mark}", backup::K3S_MARK)));
        files.push(file(format!("/etc/systemd/system/{BACKUP_TIMER}"), 0o644, BACKUP_TIMER_UNIT));
    }
    if !switch_addr.is_empty() && !p.switch_mac.is_empty() {
        files.push(file("/etc/systemd/network/10-switch.network", 0o644, switch_network(&p.switch_mac, &switch_addr)));
    }
    if !c.wifi_ssid.is_empty() {
        files.push(iwd_file(&c.wifi_ssid, &c.wifi_pass));
    }
    if p.plan.packages.iter().any(|x| x == "docker") {
        files.push(file("/etc/docker/daemon.json", 0o644, DOCKER_DAEMON));
    }
    Ok(files)
}

/// Host n of cidr with the prefix, e.g. ("10.66.0.0/24", 5) -> "10.66.0.5/24".
pub fn host_addr(cidr: &str, n: u32) -> Result<String> {
    let Some(c) = Cidr::parse(cidr) else {
        return Err(errf!("invalid CIDR address: {cidr}"));
    };
    if n < 1 || n as u64 >= c.size() - 1 {
        return Err(errf!("host {n} does not fit in {cidr}"));
    }
    Ok(format!("{}/{}", Ipv4Addr::from(c.network().wrapping_add(n)), c.prefix))
}

fn ports_of(ports: &[Port], proto: &str) -> Vec<u16> {
    let mut out: Vec<u16> = Vec::new();
    for p in ports {
        if p.proto == proto && !out.contains(&p.num) {
            out.push(p.num);
        }
    }
    out
}

fn hosts(hostname: &str) -> String {
    format!("127.0.0.1 localhost\n::1       localhost\n127.0.1.1 {hostname}\n")
}

pub const K3S_CONFIG: &str = "/etc/rancher/k3s/config.yaml";
/// A server's token for joining the cluster, handed out by the coordinator
/// to members over the mesh.
pub const K3S_TOKEN: &str = "/etc/rancher/k3s/token";
/// A server's node password, which k3s takes as proof that the server is
/// the one its node name belongs to; root on the coordinator makes it and
/// seals it with the token (k3stoken.rs).
pub const K3S_NODE_PASSWORD: &str = "/etc/rancher/node/password";
/// On the coordinator: the secret agents join with, made at install. With
/// none of its own, k3s hands agents the server's token, and that one
/// opens the control plane's own doors (its certificate authority).
pub const K3S_AGENT_SECRET: &str = "/etc/rancher/k3s/agent-token";
/// k3s applies what it finds in this directory on the coordinator.
pub const K3S_INGRESS_CONFIG: &str = "/var/lib/rancher/k3s/server/manifests/dryserver-traefik.yaml";
/// The ingress (Traefik, part of k3s) runs on every machine instead of as
/// one pod on one server. With one pod, everything from outside stops for
/// five minutes when the server that happens to hold it dies.
const K3S_INGRESS: &str = "# dryserver: the ingress runs on every machine, so it does not go down
# with the one server that happened to hold it.
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: traefik
  namespace: kube-system
spec:
  valuesContent: |-
    deployment:
      kind: DaemonSet
";
/// On the coordinator: keeps the cluster's DNS on two machines, and off
/// the coordinator where it can (see coredns.rs). Every two minutes, so
/// copies move apart soon after a server joins or comes back; a run is
/// two short kubectl calls and changes nothing when all is well.
const DNS_NAME: &str = "dryserver-dns";
pub const DNS_TIMER: &str = "dryserver-dns.timer";
const DNS_UNIT: &str = "[Unit]
Description=Keep the cluster's DNS on two machines
After=k3s.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/dryserver cluster-dns
";
const DNS_TIMER_UNIT: &str = "[Unit]
Description=Check where the cluster's DNS runs, every two minutes

[Timer]
OnBootSec=3min
OnUnitActiveSec=2min

[Install]
WantedBy=timers.target
";

/// On the coordinator: the nightly backup (see backup.rs). Missed nights
/// run at the next boot (Persistent); the random delay keeps it off the
/// hour other jobs like.
pub const BACKUP_TIMER: &str = "dryserver-backup.timer";
const BACKUP_UNIT_TEMPLATE: &str = "[Unit]
Description=Back up the coordinator, encrypted for the admin's desktop
After=k3s.service time-sync.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/dryserver backup
# What the backup and its tools make is root's alone unless the backup
# says otherwise (the backups themselves: 0640, group wheel).
UMask=0077
# However the backup ends (a crash, a kill, the timeout) while it has k3s
# stopped for the copy, k3s starts again.
ExecStopPost=/usr/bin/sh -c 'if [ -e {mark} ]; then rm -f {mark}; systemctl start --no-block k3s.service; fi'
TimeoutStartSec=3h
";
const BACKUP_TIMER_UNIT: &str = "[Unit]
Description=Back up the coordinator every night

[Timer]
OnCalendar=*-*-* 02:30:00
RandomizedDelaySec=20min
Persistent=true

[Install]
WantedBy=timers.target
";

/// While this file exists a server does not run k3s. It cut the
/// coordinator off: what the coordinator's cluster started here is not
/// trusted until the admin lifts the cut.
pub const K3S_HOLD: &str = "/etc/dryserver/k3s.hold";

/// k3s runs your apps as one cluster over the mesh: the server (control
/// plane) on the coordinator, an agent on every other machine. It starts
/// when its condition holds: the coordinator has its config from the
/// install, a server gets config and token once it is approved.
fn k3s_unit(role: Role) -> String {
    let (what, mode, needs) = match role {
        Role::Coordinator => ("control plane of your cluster", "server", K3S_CONFIG.to_string()),
        Role::Node => ("runs your apps as part of the cluster", "agent", format!("{K3S_TOKEN}\nConditionPathExists=!{K3S_HOLD}")),
    };
    format!(
        "[Unit]
Description=k3s {mode}: {what}
Wants=network-online.target
After=network-online.target nftables.service wg-quick@wg0.service
ConditionPathExists={needs}

[Service]
Type=notify
ExecStart=/usr/local/bin/k3s {mode}
KillMode=process
Delegate=yes
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
TimeoutStartSec=0
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
"
    )
}

/// The coordinator's k3s config.
///
/// - Everything on the mesh address: the API server is not reachable from
///   the home network.
/// - Secrets are encrypted in the cluster's database.
/// - Agents join with their own token, which opens nothing else.
/// - No ServiceLB: it would open ports 80 and 443 on every machine. The
///   way in from outside is the tunnel, which runs as a pod.
/// - Apps never run on the coordinator (taint); k3s's own parts may.
/// - The admin user (wheel) may use kubectl without sudo.
pub fn k3s_server_config(coord_mesh: &str) -> String {
    format!(
        "# dryserver: k3s control plane on the mesh.
node-ip: {coord_mesh}
advertise-address: {coord_mesh}
flannel-iface: wg0
cluster-cidr: {K3S_POD_CIDR}
service-cidr: {K3S_SERVICE_CIDR}
secrets-encryption: true
agent-token-file: {K3S_AGENT_SECRET}
write-kubeconfig-mode: \"0640\"
write-kubeconfig-group: wheel
disable:
  - servicelb
node-taint:
  - \"CriticalAddonsOnly=true:NoExecute\"
"
    )
}

/// A server's k3s config, written once it knows its mesh address.
pub fn k3s_agent_config(coord_mesh: &str, node_mesh: &str) -> String {
    format!(
        "# dryserver: k3s agent, joins the coordinator over the mesh.
server: https://{coord_mesh}:6443
token-file: {K3S_TOKEN}
node-ip: {node_mesh}
flannel-iface: wg0
"
    )
}

/// What the firewall is rendered from.
pub struct Firewall {
    pub role: Role,
    pub wg_port: u16,
    /// The switch subnet in auto mode.
    pub switch: Option<Cidr>,
    /// The mesh subnet.
    pub mesh: Cidr,
    /// The coordinator's mesh and LAN addresses.
    pub coord_mesh: Ipv4Addr,
    pub coord_lan: Ipv4Addr,
    /// MESH_PORTS: open to every member over the mesh.
    pub mesh_tcp: Vec<u16>,
    pub mesh_udp: Vec<u16>,
    /// EGRESS_PORTS: extra ports this machine and its containers may
    /// connect to on the internet.
    pub out_tcp: Vec<u16>,
    pub out_udp: Vec<u16>,
}

/// "{ 22, 8080 }" from a fixed list and a configured one, without repeats.
fn port_set(fixed: &[u16], extra: &[u16]) -> String {
    let mut all: Vec<u16> = Vec::new();
    for p in fixed.iter().chain(extra) {
        if !all.contains(p) {
            all.push(*p);
        }
    }
    format!("{{ {} }}", all.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "))
}

/// k3s's own address ranges for pods and services (its defaults).
pub const K3S_POD_CIDR: &str = "10.42.0.0/16";
pub const K3S_SERVICE_CIDR: &str = "10.43.0.0/16";

/// The mesh address counted as a knock on a closed port this often in a
/// minute is blocked for an hour (see the mesh chain).
pub const KNOCKS_PER_MINUTE: u32 = 30;
/// The set of members blocked for knocking; sync reads it.
pub const OFFENDERS_SET: &str = "offenders4";
/// On a server, the coordinator is counted on its own and against a
/// higher bar: cut off, it takes every app on the server down with it. On
/// the coordinator no account but root may try a closed port of a server
/// (its output chain), and a scan sends far more than this.
pub const COORD_KNOCKS_PER_MINUTE: u32 = 100;
/// The set the coordinator lands in for that; sync reads it. A server cuts
/// the coordinator off for knocks counted here, never for ones counted
/// with the members in OFFENDERS_SET.
pub const COORD_OFFENDER_SET: &str = "coord_offender4";

fn nftables(f: &Firewall) -> String {
    let wg_port = f.wg_port;
    let switch_rule = match &f.switch {
        None => String::new(),
        Some(s) => format!("\n\n\t\t# Switch network: WireGuard only.\n\t\tip saddr {} drop", s.network_string()),
    };
    // SSH inside the mesh: on a server only from the coordinator (the path
    // of "ssh <server>" from the admin's desktop); on the coordinator from
    // every member (they fetch the member list over it).
    let mesh_ssh = match f.role {
        Role::Coordinator => "tcp dport 22 accept".to_string(),
        Role::Node => format!("ip saddr {} tcp dport 22 accept", f.coord_mesh),
    };
    let mesh_tcp = if f.mesh_tcp.is_empty() { String::new() } else { format!("\n\t\ttcp dport {} accept", port_set(&[], &f.mesh_tcp)) };
    let mesh_udp = if f.mesh_udp.is_empty() { String::new() } else { format!("\n\t\tudp dport {} accept", port_set(&[], &f.mesh_udp)) };
    // A server reaches the coordinator's registry over the LAN to join and
    // to check it again after a quarantine.
    let registry = match f.role {
        Role::Node => format!("\n\t\tip daddr {} tcp dport 22 accept", f.coord_lan),
        _ => String::new(),
    };
    let out_tcp = port_set(&[53, 80, 443], &f.out_tcp);
    let out_udp = port_set(&[53, 123], &f.out_udp);
    let to_mesh_tcp = if f.mesh_tcp.is_empty() {
        String::new()
    } else {
        format!("\n\t\toifname \"wg0\" tcp dport {} accept", port_set(&[], &f.mesh_tcp))
    };
    let to_mesh_udp = if f.mesh_udp.is_empty() {
        String::new()
    } else {
        format!("\n\t\toifname \"wg0\" udp dport {} accept", port_set(&[], &f.mesh_udp))
    };
    // k3s. The API server is on the coordinator; every machine has a
    // kubelet and its part of the pod network.
    let k3s_mesh = match f.role {
        Role::Coordinator => "tcp dport { 6443, 10250 } accept",
        Role::Node => "tcp dport 10250 accept",
    };
    let k3s_local = match f.role {
        Role::Coordinator => "{ 6443, 10250 }",
        Role::Node => "10250",
    };
    let web_tcp = port_set(&[80, 443], &f.out_tcp);
    let extra_udp = if f.out_udp.is_empty() { String::new() } else { format!("\n\t\tudp dport {} accept", port_set(&[], &f.out_udp)) };
    // What this machine may start over the mesh. A server: anything, the
    // firewall on the other side decides. The coordinator: what the
    // to_mesh chain lets through.
    let (to_mesh, to_mesh_chain) = match f.role {
        Role::Node => ("\t\t# The mesh: the firewall on the other side decides.\n\t\toifname \"wg0\" accept".to_string(), String::new()),
        Role::Coordinator => (
            format!(
                "\t\t# The mesh, also by address: a service address rewritten to a
		# server's still goes \"to the router\" here (see below).
		oifname \"wg0\" jump to_mesh
		ip daddr {m} ip daddr != {c} jump to_mesh",
                m = f.mesh.network_string(),
                c = f.coord_mesh
            ),
            r#"

	# What this machine may start over the mesh. A server cuts it off
	# when it tries closed ports there, and that stops every app: only
	# root (k3s, sync) may try them. Regular accounts reach the servers
	# with SSH (the admin's "ssh <server>" jumps through here) and ping;
	# system accounts, the registry's among them, not at all. Numbers,
	# not names: the firewall loads where the accounts do not exist
	# (the installer checks it there). What the kernel sends with no
	# program behind it passes: the pod network's VXLAN for the pods
	# here, and its answers.
	chain to_mesh {
		meta skuid 0 accept
		meta skuid >= 1000 tcp dport 22 accept
		meta skuid >= 1000 icmp type echo-request accept
		meta skuid != 0 limit rate 10/minute log prefix "dryserver-out-drop: "
		meta skuid != 0 reject with icmpx admin-prohibited
		accept
	}"#
            .to_string(),
        ),
    };
    // A server counts the coordinator's tries on its own (see
    // COORD_KNOCKS_PER_MINUTE); the coordinator has no such rule for
    // itself.
    let (coord_set, coord_block, coord_knocks) = match f.role {
        Role::Coordinator => (String::new(), String::new(), String::new()),
        Role::Node => (
            format!(
                "

	# The coordinator, blocked for an hour when it tried more than
	# {ck} closed ports in a minute. \"dryserver sync\" makes that a
	# quarantine that lasts.
	set {COORD_OFFENDER_SET} {{
		type ipv4_addr
		flags dynamic, timeout
		timeout 1h
	}}",
                ck = COORD_KNOCKS_PER_MINUTE
            ),
            format!("\n\t\tiifname \"wg0\" ip saddr @{COORD_OFFENDER_SET} drop"),
            format!(
                "
		# The coordinator is counted on its own, against a higher bar:
		# its cut stops every app here. On it only root may try a
		# closed port of this machine, and a scan sends far more.
		ip saddr {c} limit rate over {ck}/minute burst {ck} packets add @{COORD_OFFENDER_SET} {{ ip saddr }} log prefix \"dryserver-autocut: \"
		ip saddr {c} limit rate 10/minute log prefix \"dryserver-mesh-drop: \"
		ip saddr {c} drop",
                c = f.coord_mesh,
                ck = COORD_KNOCKS_PER_MINUTE
            ),
        ),
    };
    format!(
        r#"#!/usr/bin/nft -f
# dryserver firewall, generated from config.env. To open more ports to the
# mesh, change MESH_PORTS there; for more outgoing ports, EGRESS_PORTS.
# Only this table is touched, so Docker's own rules survive reloads.

destroy table inet dryserver

table inet dryserver {{
	# Addresses that opened too many SSH connections in the last minute.
	set ssh_meter4 {{
		type ipv4_addr
		flags dynamic
		timeout 1m
	}}
	set ssh_meter6 {{
		type ipv6_addr
		flags dynamic
		timeout 1m
	}}
	# Addresses that pinged this machine in the last minute.
	set ping_meter4 {{
		type ipv4_addr
		flags dynamic
		timeout 1m
	}}
	set ping_meter6 {{
		type ipv6_addr
		flags dynamic
		timeout 1m
	}}

	# Members that tried closed ports: counted in knock4, and with more
	# than {knocks} tries in a minute blocked in {offenders} for an hour.
	# "dryserver sync" makes that a quarantine that lasts.
	set knock4 {{
		type ipv4_addr
		flags dynamic
		timeout 1m
	}}
	set {offenders} {{
		type ipv4_addr
		flags dynamic, timeout
		timeout 1h
	}}{coord_set}

	chain input {{
		type filter hook input priority filter; policy drop;
		iifname "wg0" ip saddr @{offenders} drop{coord_block}
		ct state vmap {{ established : accept, related : accept, invalid : drop }}
		iif lo accept

		# Pings, at most 10 a second from each address: a flood from one
		# machine on the home network takes no other's (the pings over
		# the switch that keep the links there).
		icmp type echo-request add @ping_meter4 {{ ip saddr limit rate 10/second burst 20 packets }} accept
		icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert }} accept
		icmpv6 type echo-request add @ping_meter6 {{ ip6 saddr limit rate 10/second burst 20 packets }} accept

		# Pods on this machine reach its kubelet (and on the coordinator
		# the API server). Nothing else on this machine is for pods or
		# containers: without the drop they would fall through to the
		# rules for the home network below and reach SSH.
		iifname "cni0" tcp dport {k3s_local} accept
		iifname {{ "cni0", "flannel.1", "docker0", "br-*" }} drop

		# Everything from the mesh is decided there, and ends there.
		iifname "wg0" jump mesh

		# WireGuard from the WiFi/router network and the switch.
		udp dport {wg_port} accept{switch_rule}

		# SSH from the WiFi/router network, at most 10 new connections a
		# minute per address. Logins need the admin SSH key.
		tcp dport 22 ct state new add @ssh_meter4 {{ ip saddr limit rate over 10/minute burst 20 packets }} drop
		tcp dport 22 ct state new add @ssh_meter6 {{ ip6 saddr limit rate over 10/minute burst 20 packets }} drop
		tcp dport 22 accept
	}}

	# Traffic from other servers over WireGuard.
	chain mesh {{
		{mesh_ssh}{mesh_tcp}{mesh_udp}
		icmp type echo-request accept
		icmpv6 type echo-request accept
		# k3s between members: API server and kubelets (both ask for
		# certificates), and the pod network (VXLAN).
		{k3s_mesh}
		udp dport 8472 accept

		# Anything else from a member is a try on a closed port, but only
		# a try to open something counts: a TCP packet in the middle of a
		# connection this machine no longer knows (it restarted) is late.
		tcp flags & (syn | ack) != syn drop{coord_knocks}

		# Too many tries and a member is cut off here; every refusal is
		# logged (at a limit).
		add @knock4 {{ ip saddr limit rate over {knocks}/minute burst {knocks} packets }} add @{offenders} {{ ip saddr }} log prefix "dryserver-autocut: "
		limit rate 10/minute log prefix "dryserver-mesh-drop: "
		drop
	}}

	# What this machine itself may start. Replies to what came in are
	# always allowed.
	chain output {{
		type filter hook output priority filter; policy drop;
		ct state vmap {{ established : accept, related : accept, invalid : drop }}
		oif lo accept
{to_mesh}
		# This machine's own pods (health checks), the pod network and
		# the cluster's service addresses. By address: a service address
		# is rewritten to a pod's only after the route was chosen, so
		# the interface still says "router" here.
		oifname {{ "cni0", "flannel.1" }} accept
		ip daddr {{ {pod_cidr}, {svc_cidr} }} accept
		meta l4proto {{ icmp, ipv6-icmp, igmp }} accept
		# DNS, time, web (updates, images), plus EGRESS_PORTS.
		tcp dport {out_tcp} accept
		udp dport {out_udp} accept
		# DHCP renewals, WireGuard to the other servers.
		udp sport 68 udp dport 67 accept
		udp sport 546 udp dport 547 accept
		udp dport {wg_port} accept{registry}

		limit rate 10/minute log prefix "dryserver-out-drop: "
		reject with icmpx admin-prohibited
	}}{to_mesh_chain}

	# Mesh addresses only through WireGuard, from this machine, its pods
	# and its containers, also on connections already open: with wg0
	# down its route is gone, and the default route would carry k3s and
	# the pod network there in the clear. Here, after every rewrite of an
	# address, the interface is the one the packet leaves by.
	chain postrouting {{
		type filter hook postrouting priority filter; policy accept;
		ip daddr {mesh} oifname != {{ "wg0", "lo" }} limit rate 10/minute log prefix "dryserver-out-drop: "
		ip daddr {mesh} oifname != {{ "wg0", "lo" }} drop
	}}

	# Containers. Before Docker's own chains; a drop here is final.
	chain forward {{
		type filter hook forward priority filter - 5; policy accept;
		ct state established,related accept
		iifname {{ "docker0", "br-*" }} jump containers
		iifname "cni0" jump pods
		# Nothing from outside the cluster starts a connection to a pod:
		# a NodePort or hostPort is not a door from the home network.
		# Pods are reached by other pods, by this machine, and through
		# the ingress.
		oifname "cni0" iifname != {{ "cni0", "flannel.1" }} drop
		# Routing is for this machine's own containers and pods. What
		# arrives from the home network, the switch, the mesh or another
		# machine's pods is never passed on to another network: no
		# machine here is a router into the cluster.
		iifname "flannel.1" oifname != "cni0" drop
		iifname != {{ "cni0", "flannel.1", "docker0", "br-*" }} oifname != {{ "docker0", "br-*" }} drop
	}}

	# What a k3s pod may start. Which pod may talk to which is for
	# NetworkPolicy; this is the wall around all of them.
	chain pods {{
		oifname {{ "cni0", "flannel.1" }} accept
		# The API server and the kubelets, over the mesh.
		oifname "wg0" ip daddr {coord_mesh} tcp dport 6443 accept
		oifname "wg0" tcp dport 10250 accept{to_mesh_tcp}{to_mesh_udp}
		oifname "wg0" limit rate 10/minute log prefix "dryserver-pod-drop: "
		oifname "wg0" drop
		udp dport {{ 53, 123 }} accept
		tcp dport 53 accept
		ip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 }} drop
		ip6 daddr {{ fc00::/7, fe80::/10 }} drop
		tcp dport {web_tcp} accept{extra_udp}
		# Cloudflare Tunnel (cloudflared runs as a pod).
		meta l4proto {{ tcp, udp }} th dport 7844 accept
		meta l4proto {{ icmp, ipv6-icmp }} accept
		limit rate 10/minute log prefix "dryserver-pod-drop: "
		drop
	}}

	# What a container may start: the internet on the same ports as this
	# machine, the mesh on MESH_PORTS, never the home network.
	chain containers {{
		# Between containers Docker's own isolation decides.
		oifname {{ "docker0", "br-*" }} accept{to_mesh_tcp}{to_mesh_udp}
		oifname "wg0" limit rate 10/minute log prefix "dryserver-container-drop: "
		oifname "wg0" drop
		# DNS and time first: the resolver is often the home router.
		udp dport {{ 53, 123 }} accept
		tcp dport 53 accept
		ip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 }} drop
		ip6 daddr {{ fc00::/7, fe80::/10 }} drop
		tcp dport {web_tcp} accept{extra_udp}
		meta l4proto {{ icmp, ipv6-icmp }} accept
		limit rate 10/minute log prefix "dryserver-container-drop: "
		drop
	}}
}}

# Kill switch rules from "dryserver quarantine", when there are any.
{include}
"#,
        include = quarantine::NFT_INCLUDE,
        coord_mesh = f.coord_mesh,
        mesh = f.mesh.network_string(),
        pod_cidr = K3S_POD_CIDR,
        svc_cidr = K3S_SERVICE_CIDR,
        knocks = KNOCKS_PER_MINUTE,
        offenders = OFFENDERS_SET,
    )
}

/// Ceiling for everything the registry account runs. Its key is on every
/// USB stick and server, so anyone holding it can log in (to the forced
/// command only) as often as the firewall lets them. Without a ceiling,
/// sessions that never end use up the coordinator's memory.
///
/// No network either: the registry only reads and writes files, and code
/// running as the account must not reach the servers (tries on their
/// closed ports cut the coordinator off), the home network or the
/// internet. The SSH connections it serves are not affected: a socket
/// stays with the unit that made it, and sshd.service accepted them.
pub const REGISTRY_SLICE: &str = "# dryserver: the registry account cannot starve the coordinator, and
# what it runs has no network (its SSH connections belong to sshd).
[Slice]
TasksMax=200
MemoryMax=384M
MemorySwapMax=0
IPAddressDeny=any
";

fn sshd(user: &str, role: Role, mesh: &Cidr) -> String {
    let users = if role == Role::Coordinator { format!("{user} {REGISTRY_USER}") } else { user.to_string() };
    // Last in the file: a Match block lasts to its end.
    let registry = if role == Role::Coordinator {
        format!(
            "
# The registry account runs one short command per connection, whatever its
# key says: nothing it can change gives it a shell, a terminal or a
# forwarded port. Its key is in a file only root may change (machines
# installed before keep it in the account's home, which belongs to root).
# A connection with nothing running, or a command that says nothing for a
# minute, is closed.
Match User {REGISTRY_USER}
	AuthorizedKeysFile {REGISTRY_KEYS} {REGISTRY_HOME}/.ssh/authorized_keys
	ForceCommand {}
	DisableForwarding yes
	PermitTTY no
	UnusedConnectionTimeout 30
	ChannelTimeout session=60
",
            registry_command(mesh)
        )
    } else {
        String::new()
    };
    format!(
        "# dryserver SSH hardening. Login with the admin SSH key only.
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
PermitRootLogin no
PermitEmptyPasswords no
AllowUsers {users}
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
PermitTunnel no
# No agent forwarding: your desktop key never reaches a server, so a hacked
# server cannot use it. TCP forwarding is needed for ProxyJump through the
# coordinator.
AllowAgentForwarding no
AllowTcpForwarding yes
# A client that stopped answering (switched off, cable pulled) is dropped
# after a minute and a half.
ClientAliveInterval 30
ClientAliveCountMax 3
{registry}"
    )
}

const SYSCTL: &str = "# dryserver kernel hardening
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.yama.ptrace_scope = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# Restart 10 seconds after a kernel panic instead of hanging: a machine
# without screen or keyboard comes back by itself, and a new kernel that
# panics uses up its boot tries (the kernel command line says the same for
# panics before this file is read).
kernel.panic = 10

# Loose reverse-path filter: strict mode breaks machines with WiFi and a
# cable in the same network.
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
";

const WIRED: &str = "# Ethernet ports: DHCP when the cable reaches a router (then the cable
# also carries internet). The switch port has its own file, 10-switch.network.
[Match]
Type=ether
Kind=!*

[Network]
DHCP=yes

[DHCPv4]
RouteMetric=100

[IPv6AcceptRA]
RouteMetric=100
";

/// Gives the chosen port its fixed switch address next to DHCP, so an
/// isolated switch and a router-connected one both work.
fn switch_network(mac: &str, addr: &str) -> String {
    format!(
        "# The Ethernet port used for the switch: fixed address {addr} (no gateway)
# plus DHCP in case the switch is connected to the router.
[Match]
MACAddress={mac}

[Network]
DHCP=yes
Address={addr}

[DHCPv4]
RouteMetric=100

[IPv6AcceptRA]
RouteMetric=100
"
    )
}

const WIRELESS: &str = "# WiFi (iwd connects, networkd does DHCP). Higher metric than Ethernet,
# so a cable to the router wins for internet when present.
[Match]
Type=wlan

[Network]
DHCP=yes

[DHCPv4]
RouteMetric=600

[IPv6AcceptRA]
RouteMetric=600
";

const WAIT_ONLINE: &str = "# Boot does not wait for every link: an isolated switch or missing WiFi
# must not hold up startup.
[Service]
ExecStart=
ExecStart=/usr/lib/systemd/systemd-networkd-wait-online --any --timeout=30
";

const LID: &str = "# Laptop as server: keep running with the lid closed.
[Login]
HandleLidSwitch=ignore
HandleLidSwitchExternalPower=ignore
HandleLidSwitchDocked=ignore
";

const RESOLVED: &str = "# No LLMNR or mDNS: both answer name lookups from anyone on the network
# and are a common way to poison names on a LAN.
[Resolve]
LLMNR=no
MulticastDNS=no
";

const JOIN_UNIT: &str = "[Unit]
Description=Ask the coordinator to let this server join the mesh
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dryserver join
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
";

/// Runs once, at the first boot of a TPM-mode install: the disk was
/// unlocked with the passphrase, now the TPM learns this boot.
const TPM_ENROLL_UNIT: &str = "[Unit]
Description=Let the TPM unlock the disk from now on
ConditionPathExists=/etc/cryptsetup-keys.d/tpm-enroll.key
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/dryserver tpm-enroll --first-boot

[Install]
WantedBy=multi-user.target
";

const SYNC_UNIT: &str = "[Unit]
Description=Update the WireGuard mesh from the coordinator's member list
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/dryserver sync
";

const SYNC_TIMER: &str = "[Unit]
Description=Update the WireGuard mesh every minute

[Timer]
OnBootSec=20s
OnUnitActiveSec=60s

[Install]
WantedBy=timers.target
";

/// Lists unknown devices on the coordinator's networks every 15 minutes,
/// for the approval screen. Report only: nothing is ever added.
const SCAN_CRON: &str = "# dryserver: look for unknown devices on the network (report only).
*/15 * * * * root /usr/local/bin/dryserver scan >/dev/null 2>&1
";

const ZRAM: &str = "# Compressed swap in RAM. No swap partition, so nothing from memory is
# written unencrypted to disk.
[zram0]
zram-size = min(ram / 2, 8192)
compression-algorithm = zstd
";

const DOCKER_DAEMON: &str = r#"{
  "ip": "127.0.0.1",
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" }
}
"#;

/// Names the network file the way iwd expects: plain SSIDs as-is, anything
/// else hex-encoded after "=".
pub fn iwd_file(ssid: &str, pass: &str) -> File {
    let plain = ssid.chars().all(|r| r.is_ascii_alphanumeric() || r == '-' || r == '_');
    let name = if plain { ssid.to_string() } else { format!("={}", fsx::hex(ssid.as_bytes())) };
    if pass.is_empty() {
        return file(format!("/var/lib/iwd/{name}.open"), 0o600, "[Settings]\nAutoConnect=true\n");
    }
    file(format!("/var/lib/iwd/{name}.psk"), 0o600, format!("[Security]\nPassphrase={pass}\n\n[Settings]\nAutoConnect=true\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> Config {
        Config {
            coord_lan_ip: "192.168.1.50".into(),
            admin_ssh_pubkey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest admin@desktop".into(),
            ..Config::default()
        }
    }

    fn cases() -> Vec<(&'static str, Params)> {
        let mut node = base_config();
        node.wifi_ssid = "Home Net!".into();
        node.wifi_pass = "correct horse".into();
        node.mesh_ports = "8080/tcp 53/udp 9000/tcp".into();
        let node_plan = packages::resolve(&node.tool_list(), &[]).unwrap();

        let mut coord = base_config();
        coord.wg_transport = config::TRANSPORT_LAN.into();
        coord.tools = "go".into();
        let coord_plan = packages::resolve(&coord.tool_list(), &[]).unwrap();

        let p = |c: &Config, plan: &packages::Plan, host: &str, role, n, mac: &str| Params {
            config: c.clone(),
            plan: plan.clone(),
            hostname: host.into(),
            role,
            host_num: n,
            switch_mac: mac.into(),
        };
        vec![
            ("node", p(&node, &node_plan, "node-3a2f", Role::Node, 5, "52:54:66:aa:bb:cc")),
            ("node-new", p(&node, &node_plan, "node-9c1d", Role::Node, 0, "52:54:66:aa:bb:dd")),
            ("coordinator", p(&coord, &coord_plan, "coord", Role::Coordinator, 1, "52:54:66:aa:bb:ee")),
        ]
    }

    fn dump(files: &[File]) -> String {
        files.iter().map(|f| format!("===== {} ({:04o})\n{}", f.path, f.mode, f.content)).collect()
    }

    #[test]
    fn golden() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/sysconf");
        let update = std::env::var("UPDATE_GOLDEN").is_ok();
        for (name, p) in cases() {
            let got = dump(&render(&p).unwrap());
            let path = format!("{dir}/{name}.golden");
            if update {
                std::fs::create_dir_all(dir).unwrap();
                std::fs::write(&path, &got).unwrap();
                continue;
            }
            let want = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e} (run with UPDATE_GOLDEN=1)"));
            assert!(got == want, "{name} differs from {path}; run with UPDATE_GOLDEN=1 and review the diff");
        }
    }

    fn find<'a>(files: &'a [File], path: &str) -> &'a File {
        files.iter().find(|f| f.path == path).unwrap_or_else(|| panic!("{path} not rendered"))
    }

    fn has(files: &[File], path: &str) -> bool {
        files.iter().any(|f| f.path == path)
    }

    #[test]
    fn security_properties() {
        let cs = cases();
        let node = render(&cs[0].1).unwrap();
        let fresh = render(&cs[1].1).unwrap();
        let coord = render(&cs[2].1).unwrap();

        let nft = &find(&node, "/etc/nftables.conf").content;
        for want in [
            "policy drop",
            "destroy table inet dryserver",
            "ip saddr 172.16.66.0/24 drop",
            // SSH inside the mesh only from the coordinator.
            "ip saddr 10.66.0.1 tcp dport 22 accept",
            "tcp dport { 8080, 9000 } accept",
            "udp dport { 53 } accept",
            // The mesh chain ends in a drop, so nothing from the mesh
            // reaches the LAN rules below it.
            "limit rate 10/minute log prefix \"dryserver-mesh-drop: \"\n\t\tdrop\n\t}",
            "iifname \"wg0\" ip saddr @offenders4 drop\n\t\tiifname \"wg0\" ip saddr @coord_offender4 drop\n\t\tct state vmap",
            // Outgoing: default drop, the registry on the coordinator's LAN
            // address, containers kept off the home network.
            "type filter hook output priority filter; policy drop;",
            "ip daddr 192.168.1.50 tcp dport 22 accept",
            "reject with icmpx admin-prohibited",
            "ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 } drop",
        ] {
            assert!(nft.contains(want), "node nftables missing {want:?}:\n{nft}");
        }
        assert!(!nft.contains("\n\t\ttcp dport 22 accept\n\t\ttcp dport {"), "a server must not take SSH from every member");
        // k3s: kubelet from members and from this machine's pods; the API
        // port only on the coordinator; pods and containers end before
        // the home network's rules; NodePorts are no door.
        for want in [
            "iifname \"cni0\" tcp dport 10250 accept\n\t\tiifname { \"cni0\", \"flannel.1\", \"docker0\", \"br-*\" } drop",
            "tcp dport 10250 accept\n\t\tudp dport 8472 accept",
            "ip daddr { 10.42.0.0/16, 10.43.0.0/16 } accept",
            "oifname \"cni0\" iifname != { \"cni0\", \"flannel.1\" } drop",
            "oifname \"wg0\" ip daddr 10.66.0.1 tcp dport 6443 accept",
        ] {
            assert!(nft.contains(want), "node nftables missing {want:?}:\n{nft}");
        }
        assert!(!nft.contains("6443, 10250"), "a server has no API server port");
        // k3s units: the server on the coordinator, an agent elsewhere,
        // each waiting for what it needs.
        let unit = &find(&node, "/etc/systemd/system/k3s.service").content;
        assert!(
            unit.contains("ExecStart=/usr/local/bin/k3s agent\n") && unit.contains("ConditionPathExists=/etc/rancher/k3s/token\n"),
            "{unit}"
        );
        assert!(!has(&node, K3S_CONFIG), "a server's k3s config needs its mesh address first");
        let unit = &find(&coord, "/etc/systemd/system/k3s.service").content;
        assert!(
            unit.contains("ExecStart=/usr/local/bin/k3s server\n") && unit.contains("ConditionPathExists=/etc/rancher/k3s/config.yaml\n"),
            "{unit}"
        );
        let conf = find(&coord, K3S_CONFIG);
        assert_eq!(conf.mode, 0o644, "kubectl run by the admin reads it; it holds no secret");
        for want in [
            "node-ip: 10.66.0.1",
            "advertise-address: 10.66.0.1",
            "flannel-iface: wg0",
            "secrets-encryption: true",
            "- servicelb",
            "CriticalAddonsOnly=true:NoExecute",
            "cluster-cidr: 10.42.0.0/16",
            "service-cidr: 10.43.0.0/16",
        ] {
            assert!(conf.content.contains(want), "coordinator k3s config missing {want:?}:\n{}", conf.content);
        }
        assert!(k3s_agent_config("10.66.0.1", "10.66.0.7").contains("node-ip: 10.66.0.7"));
        assert!(conf.content.contains("agent-token-file: /etc/rancher/k3s/agent-token\n"), "servers would get the control plane's token");
        // The ingress on every machine, set where k3s picks it up.
        let ingress = find(&coord, K3S_INGRESS_CONFIG);
        assert!(
            ingress.content.contains("kind: HelmChartConfig") && ingress.content.contains("deployment:\n      kind: DaemonSet\n"),
            "{}",
            ingress.content
        );
        assert!(!has(&node, K3S_INGRESS_CONFIG));
        // The cluster's DNS: its disruption budget where k3s picks it up,
        // next to (never in place of) k3s's own coredns.yaml, and the
        // timer that keeps two copies apart. Coordinator only.
        let pdb = find(&coord, coredns::PDB_PATH);
        assert!(pdb.mode == 0o600 && pdb.content == coredns::PDB, "{pdb:?}");
        assert!(!coord.iter().any(|f| f.path.ends_with("/manifests/coredns.yaml") || f.path.ends_with(".skip")));
        let timer = &find(&coord, "/etc/systemd/system/dryserver-dns.timer").content;
        assert!(timer.contains("OnUnitActiveSec=2min") && timer.contains("WantedBy=timers.target"), "{timer}");
        let svc = &find(&coord, "/etc/systemd/system/dryserver-dns.service").content;
        assert!(svc.contains("Type=oneshot\nExecStart=/usr/local/bin/dryserver cluster-dns\n"), "{svc}");
        for f in [coredns::PDB_PATH, "/etc/systemd/system/dryserver-dns.timer", "/etc/systemd/system/dryserver-dns.service"] {
            assert!(!has(&node, f), "{f} on a server");
        }
        // The nightly backup, on the coordinator only.
        let timer = &find(&coord, "/etc/systemd/system/dryserver-backup.timer").content;
        for want in ["OnCalendar=*-*-* 02:30:00", "RandomizedDelaySec=", "Persistent=true", "WantedBy=timers.target"] {
            assert!(timer.contains(want), "{want}: {timer}");
        }
        let svc = &find(&coord, "/etc/systemd/system/dryserver-backup.service").content;
        assert!(svc.contains("Type=oneshot\nExecStart=/usr/local/bin/dryserver backup\n"), "{svc}");
        assert!(svc.contains("\nUMask=0077\n"), "{svc}");
        assert!(
            svc.contains("ExecStopPost=/usr/bin/sh -c 'if [ -e /run/dryserver-backup.k3s-stopped ]; then rm -f /run/dryserver-backup.k3s-stopped; systemctl start --no-block k3s.service; fi'\n"),
            "k3s must start again when the backup dies: {svc}"
        );
        assert!(!has(&node, "/etc/systemd/system/dryserver-backup.timer") && !has(&node, "/etc/systemd/system/dryserver-backup.service"));
        // A server that cut the coordinator off does not start k3s.
        let unit = &find(&node, "/etc/systemd/system/k3s.service").content;
        assert!(unit.contains("ConditionPathExists=!/etc/dryserver/k3s.hold\n"), "{unit}");
        assert!(!find(&coord, "/etc/systemd/system/k3s.service").content.contains("k3s.hold"));
        // No machine routes anyone into the cluster.
        for nft in [nft, &find(&coord, "/etc/nftables.conf").content] {
            assert!(nft.contains("iifname \"flannel.1\" oifname != \"cni0\" drop"), "{nft}");
            assert!(
                nft.contains("iifname != { \"cni0\", \"flannel.1\", \"docker0\", \"br-*\" } oifname != { \"docker0\", \"br-*\" } drop"),
                "{nft}"
            );
        }
        let coord_nft = &find(&coord, "/etc/nftables.conf").content;
        assert!(
            coord_nft.contains("chain mesh {\n\t\ttcp dport 22 accept"),
            "the coordinator serves the member list to every member:\n{coord_nft}"
        );
        assert!(!coord_nft.contains("ip daddr 192.168.1.50 tcp dport 22"), "the coordinator does not call its own registry");
        assert!(
            coord_nft.contains("tcp dport { 6443, 10250 } accept")
                && coord_nft.contains("iifname \"cni0\" tcp dport { 6443, 10250 } accept")
        );
        // EGRESS_PORTS open for the machine and its containers.
        let mut open = cs[0].1.clone();
        open.config.egress_ports = "25565/tcp 27015/udp".into();
        let nft2 = find(&render(&open).unwrap(), "/etc/nftables.conf").content.clone();
        for want in [
            "tcp dport { 53, 80, 443, 25565 } accept",
            "udp dport { 53, 123, 27015 } accept",
            "tcp dport { 80, 443, 25565 } accept",
            "udp dport { 27015 } accept",
        ] {
            assert!(nft2.contains(want), "EGRESS_PORTS missing {want:?}:\n{nft2}");
        }
        assert!(!nft.contains("flush ruleset"), "nftables must not flush Docker's rules");
        assert!(nft.trim_end().ends_with(quarantine::NFT_INCLUDE), "quarantine rules must load after the main table:\n{nft}");
        assert!(!find(&coord, "/etc/nftables.conf").content.contains("ip saddr 172.16"), "lan transport must not add a switch rule");

        let sshd = &find(&node, "/etc/ssh/sshd_config.d/10-dryserver.conf").content;
        for want in ["PasswordAuthentication no", "PermitRootLogin no", "AllowUsers admin\n", "AllowAgentForwarding no"] {
            assert!(sshd.contains(want), "sshd missing {want:?}");
        }
        let sshd_coord = &find(&coord, "/etc/ssh/sshd_config.d/10-dryserver.conf").content;
        assert!(sshd_coord.contains("AllowUsers admin dryreg"));
        // Connections do not pile up: dead clients go, and the registry
        // account's idle ones too.
        assert!(sshd_coord.ends_with("\tUnusedConnectionTimeout 30\n\tChannelTimeout session=60\n"), "{sshd_coord}");
        // The registry account: whatever key it has, only the registry runs,
        // with no terminal and nothing forwarded; its key is read from where
        // only root writes (and, on machines installed before, from its
        // home, which tmpfiles makes root's).
        let block = &sshd_coord[sshd_coord.find("\nMatch User dryreg\n").expect("no Match block for dryreg")..];
        for want in [
            "\tAuthorizedKeysFile /etc/ssh/authorized_keys.d/dryreg /var/lib/dryreg/.ssh/authorized_keys\n",
            "\tForceCommand /usr/local/bin/dryserver registry --subnet 10.66.0.0/24\n",
            "\tDisableForwarding yes\n",
            "\tPermitTTY no\n",
        ] {
            assert!(block.contains(want), "missing {want:?}:\n{block}");
        }
        let tmp = find(&coord, REGISTRY_TMPFILES);
        for want in [
            "d /var/lib/dryreg 0755 root root -\n",
            "z /var/lib/dryreg/.ssh 0755 root root -\n",
            "z /var/lib/dryreg/.ssh/authorized_keys 0644 root root -\n",
        ] {
            assert!(tmp.content.contains(want) && tmp.content.contains(REGISTRY_HOME), "{}", tmp.content);
        }
        assert!(crate::update::managed(REGISTRY_TMPFILES) && !has(&node, REGISTRY_TMPFILES));
        assert_eq!(REGISTRY_KEYS, format!("/etc/ssh/authorized_keys.d/{REGISTRY_USER}"));
        let sshd_node = &find(&node, "/etc/ssh/sshd_config.d/10-dryserver.conf").content;
        assert!(sshd_node.contains("ClientAliveInterval 30\nClientAliveCountMax 3\n") && !sshd_node.contains("Match"), "{sshd_node}");

        let sw = &find(&node, "/etc/systemd/network/10-switch.network").content;
        assert!(sw.contains("Address=172.16.66.5/24") && sw.contains("MACAddress=52:54:66:aa:bb:cc"), "{sw}");
        assert!(!find(&node, "/etc/systemd/network/20-wired.network").content.contains("Address="));
        assert!(!has(&fresh, "/etc/systemd/network/10-switch.network"), "unapproved node must not guess a switch address");
        assert!(!has(&coord, "/etc/systemd/network/10-switch.network"), "lan transport must not configure a switch port");

        let cfg = find(&node, "/etc/dryserver/config.env");
        assert!(cfg.mode == 0o600 && !cfg.content.contains("correct horse"), "node config must be private, without the WiFi password");
        let iwd = find(&node, "/var/lib/iwd/=486f6d65204e657421.psk");
        assert!(iwd.mode == 0o600 && iwd.content.contains("Passphrase=correct horse"), "{iwd:?}");
        assert_eq!(find(&node, "/etc/sudoers.d/10-wheel").mode, 0o440);

        assert!(find(&node, "/etc/docker/daemon.json").content.contains(r#""ip": "127.0.0.1""#));
        assert!(!has(&coord, "/etc/docker/daemon.json"), "no docker bundle, no daemon.json");
    }

    /// A pod's DNS question may go to a CoreDNS copy on another machine,
    /// and CoreDNS there asks the home router and the API server. Every
    /// hop of that path is open on every machine, before the drops that
    /// end each chain.
    #[test]
    fn pod_dns_crosses_machines() {
        for (name, p) in cases() {
            let nft = find(&render(&p).unwrap(), "/etc/nftables.conf").content.clone();
            let chain = |c: &str| {
                let start = nft.find(&format!("chain {c} {{")).unwrap_or_else(|| panic!("{name}: no chain {c}"));
                nft[start..start + nft[start..].find("\n\t}").unwrap()].to_string()
            };
            let before = |c: &str, a: &str, b: &str| {
                let text = chain(c);
                let (i, j) = (text.find(a), text.find(b));
                assert!(i.is_some() && j.is_some() && i < j, "{name}: in {c}, {a:?} must come before {b:?}:\n{text}");
            };
            // The asking pod: out through the pod network (VXLAN over the
            // mesh, which the kernel sends with no program behind it).
            before("pods", "oifname { \"cni0\", \"flannel.1\" } accept", "oifname \"wg0\" drop");
            match p.role {
                Role::Node => before("output", "oifname \"wg0\" accept", "reject with icmpx admin-prohibited"),
                Role::Coordinator => {
                    before("output", "oifname \"wg0\" jump to_mesh", "reject with icmpx admin-prohibited");
                    assert!(chain("to_mesh").ends_with("reject with icmpx admin-prohibited\n\t\taccept"), "{name}: {}", chain("to_mesh"));
                }
            }
            // The machine with the copy: VXLAN in from the mesh, on to its pod.
            before("mesh", "udp dport 8472 accept", "\t\tdrop");
            let fwd = chain("forward");
            assert!(fwd.contains("iifname \"flannel.1\" oifname != \"cni0\" drop"), "{name}: {fwd}");
            assert!(fwd.contains("oifname \"cni0\" iifname != { \"cni0\", \"flannel.1\" } drop"), "{name}: {fwd}");
            // CoreDNS there: the home router, and the API server it watches.
            before("pods", "udp dport { 53, 123 } accept", "ip daddr { 10.0.0.0/8");
            before("pods", "tcp dport 53 accept", "ip daddr { 10.0.0.0/8");
            before("pods", "oifname \"wg0\" ip daddr 10.66.0.1 tcp dport 6443 accept", "oifname \"wg0\" drop");
        }
    }

    #[test]
    fn review_registry_account_cannot_reach_the_mesh() {
        let cs = cases();
        let coord = render(&cs[2].1).unwrap();
        let nft = &find(&coord, "/etc/nftables.conf").content;
        let fenced = nft.contains("skuid") || REGISTRY_SLICE.contains("IPAddressDeny");
        assert!(fenced, "any local account on the coordinator may open connections into wg0:\n{nft}");
    }

    /// A server cuts the coordinator off for tries on its closed ports,
    /// and with it every app. On the coordinator only root may make them:
    /// other accounts reach the mesh with SSH and ping, system accounts
    /// (the registry's) not at all, pods only on ports servers keep open.
    #[test]
    fn only_root_on_the_coordinator_tries_ports_of_the_servers() {
        let cs = cases();
        let coord = find(&render(&cs[2].1).unwrap(), "/etc/nftables.conf").content.clone();
        let chain = |c: &str| {
            let start = coord.find(&format!("chain {c} {{")).unwrap_or_else(|| panic!("no chain {c}:\n{coord}"));
            coord[start..start + coord[start..].find("\n\t}").unwrap()].to_string()
        };
        let output = chain("output");
        // Into the mesh by interface, and by address: a service address
        // rewritten to a server's mesh address still names the router.
        let lo = output.find("oif lo accept").unwrap();
        let est = output.find("ct state vmap").unwrap();
        for want in ["oifname \"wg0\" jump to_mesh", "ip daddr 10.66.0.0/24 ip daddr != 10.66.0.1 jump to_mesh"] {
            let at = output.find(want).unwrap_or_else(|| panic!("missing {want:?}:\n{output}"));
            assert!(est < at && lo < at, "open connections and loopback go first:\n{output}");
            assert!(at < output.find("tcp dport { 53, 80, 443 } accept").unwrap(), "{want} after the web ports:\n{output}");
        }
        assert!(!output.contains("oifname \"wg0\" accept"), "{output}");
        assert_eq!(
            chain("to_mesh").lines().filter(|l| !l.trim_start().starts_with('#')).skip(1).map(str::trim).collect::<Vec<_>>(),
            vec![
                "meta skuid 0 accept",
                "meta skuid >= 1000 tcp dport 22 accept",
                "meta skuid >= 1000 icmp type echo-request accept",
                "meta skuid != 0 limit rate 10/minute log prefix \"dryserver-out-drop: \"",
                "meta skuid != 0 reject with icmpx admin-prohibited",
                "accept",
            ]
        );
        // Numbers only: a name nft cannot look up (the installer, a
        // container) would leave the machine without a firewall.
        assert!(!coord.contains("skuid \"") && !coord.contains("skgid"), "{coord}");
        // Pods there: over the mesh only to the API server, kubelets and
        // MESH_PORTS (all open on servers), never a closed port.
        let pods = chain("pods");
        let wg: Vec<&str> = pods.lines().map(str::trim).filter(|l| l.contains("oifname \"wg0\"")).collect();
        assert_eq!(
            wg,
            vec![
                "oifname \"wg0\" ip daddr 10.66.0.1 tcp dport 6443 accept",
                "oifname \"wg0\" tcp dport 10250 accept",
                "oifname \"wg0\" limit rate 10/minute log prefix \"dryserver-pod-drop: \"",
                "oifname \"wg0\" drop",
            ],
            "{pods}"
        );
        // The registry account's slice has no network.
        assert!(REGISTRY_SLICE.contains("\nIPAddressDeny=any\n") && !REGISTRY_SLICE.contains("IPAddressAllow"), "{REGISTRY_SLICE}");

        // A server keeps its own way out: hostNetwork apps run as any
        // account there.
        let node = find(&render(&cs[0].1).unwrap(), "/etc/nftables.conf").content.clone();
        assert!(node.contains("\t\t# The mesh: the firewall on the other side decides.\n\t\toifname \"wg0\" accept\n"), "{node}");
        assert!(!node.contains("skuid") && !node.contains("chain to_mesh"), "{node}");
    }

    /// Servers count tries to open something, never late packets of a
    /// connection they forgot; the coordinator on its own, against a
    /// higher bar and into its own set.
    #[test]
    fn knock_counting() {
        let cs = cases();
        let node = find(&render(&cs[0].1).unwrap(), "/etc/nftables.conf").content.clone();
        let mesh = &node[node.find("chain mesh {").unwrap()..];
        let mesh = &mesh[..mesh.find("\n\t}").unwrap()];
        let order = [
            "udp dport 8472 accept",
            "tcp flags & (syn | ack) != syn drop",
            "ip saddr 10.66.0.1 limit rate over 100/minute burst 100 packets add @coord_offender4 { ip saddr } log prefix \"dryserver-autocut: \"",
            "ip saddr 10.66.0.1 limit rate 10/minute log prefix \"dryserver-mesh-drop: \"",
            "ip saddr 10.66.0.1 drop",
            "add @knock4 { ip saddr limit rate over 30/minute burst 30 packets } add @offenders4 { ip saddr }",
        ];
        let at: Vec<usize> = order.iter().map(|w| mesh.find(w).unwrap_or_else(|| panic!("missing {w:?}:\n{mesh}"))).collect();
        assert!(at.windows(2).all(|w| w[0] < w[1]), "out of order:\n{mesh}");
        assert_eq!(mesh.matches("@offenders4").count(), 1, "the coordinator never lands with the members:\n{mesh}");
        assert!(node.contains("iifname \"wg0\" ip saddr @offenders4 drop\n\t\tiifname \"wg0\" ip saddr @coord_offender4 drop\n"), "{node}");
        assert!(node.contains("\tset coord_offender4 {\n\t\ttype ipv4_addr\n\t\tflags dynamic, timeout\n\t\ttimeout 1h\n\t}"), "{node}");
        assert_eq!((COORD_KNOCKS_PER_MINUTE, KNOCKS_PER_MINUTE), (100, 30));

        // The coordinator counts members only, and has no set for itself.
        let coord = find(&render(&cs[2].1).unwrap(), "/etc/nftables.conf").content.clone();
        assert!(coord.contains("tcp flags & (syn | ack) != syn drop") && !coord.contains("coord_offender4"), "{coord}");
    }

    /// What makes a kernel update fall back reaches every machine, also
    /// ones installed before: updates write these files again.
    #[test]
    fn every_machine_gets_the_boot_fallback() {
        for (name, p) in cases() {
            let files = render(&p).unwrap();
            for (path, mode) in [
                (boot::POST_HOOK, 0o755),
                (boot::MARK_HOOK, 0o644),
                (boot::CHECK_UNIT_PATH, 0o644),
                (boot::COMPLETE_DROPIN, 0o644),
                (boot::WATCHDOG_DROPIN, 0o644),
                (boot::EMERGENCY_DROPIN, 0o644),
            ] {
                assert_eq!(find(&files, path).mode, mode, "{name}: {path}");
                assert!(crate::update::managed(path), "{path} would not reach machines installed before");
            }
            let sysctl = &find(&files, "/etc/sysctl.d/90-dryserver.conf").content;
            assert!(sysctl.contains(&format!("\nkernel.panic = {}\n", boot::PANIC_SECS)), "{name}: {sysctl}");
        }
    }

    #[test]
    fn host_addresses() {
        for (cidr, n, want) in
            [("10.66.0.0/24", 1, "10.66.0.1/24"), ("172.16.66.0/24", 254, "172.16.66.254/24"), ("10.66.0.0/23", 300, "10.66.1.44/23")]
        {
            assert_eq!(host_addr(cidr, n).unwrap(), want);
        }
        for n in [0, 255] {
            assert!(host_addr("10.66.0.0/24", n).is_err(), "host {n} accepted in /24");
        }
    }
}
