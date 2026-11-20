//! The system files written to every installed server: firewall, SSH,
//! kernel hardening, network, Docker and login settings. Rendering is pure
//! so the output can be golden-tested and validated with the real tools
//! (nft -c, sshd -t).

use std::fmt;
use std::net::Ipv4Addr;

use crate::cidr::Cidr;
use crate::config::{self, Config, Port};
use crate::err::{Context, Result};
use crate::{errf, fsx, packages, quarantine};

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
                wg_port: c.wg_port.clone(),
                switch: switch_subnet(c),
                coord_mesh: host_addr(&c.wg_subnet, 1).map(|a| a.split('/').next().unwrap_or("").to_string()).unwrap_or_default(),
                coord_lan: c.coord_lan_ip.clone(),
                mesh_tcp: ports_of(&mesh_ports, "tcp"),
                mesh_udp: ports_of(&mesh_ports, "udp"),
                out_tcp: ports_of(&egress_ports, "tcp"),
                out_udp: ports_of(&egress_ports, "udp"),
            }),
        ),
        file("/etc/ssh/sshd_config.d/10-dryserver.conf", 0o644, sshd(&c.username, p.role)),
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
        file("/etc/systemd/system/dryserver-sync.timer", 0o644, SYNC_TIMER),
        file("/etc/systemd/system/dryserver-tpm-enroll.service", 0o644, TPM_ENROLL_UNIT),
    ];
    if p.role == Role::Coordinator {
        files.push(file("/etc/cron.d/dryserver-scan", 0o644, SCAN_CRON));
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

fn switch_subnet(c: &Config) -> String {
    if c.wg_transport == config::TRANSPORT_AUTO { c.switch_subnet.clone() } else { String::new() }
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

/// What the firewall is rendered from.
pub struct Firewall {
    pub role: Role,
    pub wg_port: String,
    /// The switch subnet in auto mode, else "".
    pub switch: String,
    /// The coordinator's mesh and LAN addresses.
    pub coord_mesh: String,
    pub coord_lan: String,
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

fn nftables(f: &Firewall) -> String {
    let wg_port = &f.wg_port;
    let switch_rule = if f.switch.is_empty() {
        String::new()
    } else {
        format!("\n\n\t\t# Switch network: WireGuard only.\n\t\tip saddr {} drop", f.switch)
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
        Role::Node if !f.coord_lan.is_empty() => format!("\n\t\tip daddr {} tcp dport 22 accept", f.coord_lan),
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
	}}

	chain input {{
		type filter hook input priority filter; policy drop;
		iifname "wg0" ip saddr @{offenders} drop
		ct state vmap {{ established : accept, related : accept, invalid : drop }}
		iif lo accept

		icmp type echo-request limit rate 10/second accept
		icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert }} accept
		icmpv6 type echo-request limit rate 10/second accept

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

		# Anything else from a member is a try on a closed port. Too many
		# and it is cut off here; every refusal is logged (at a limit).
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
		# The mesh: the firewall on the other side decides.
		oifname "wg0" accept
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
		ip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 }} drop
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
		ip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 }} drop
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
        pod_cidr = K3S_POD_CIDR,
        svc_cidr = K3S_SERVICE_CIDR,
        knocks = KNOCKS_PER_MINUTE,
        offenders = OFFENDERS_SET,
    )
}

fn sshd(user: &str, role: Role) -> String {
    let users = if role == Role::Coordinator { format!("{user} {REGISTRY_USER}") } else { user.to_string() };
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
ClientAliveInterval 300
ClientAliveCountMax 2
"
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
            "iifname \"wg0\" ip saddr @offenders4 drop\n\t\tct state vmap",
            // Outgoing: default drop, the registry on the coordinator's LAN
            // address, containers kept off the home network.
            "type filter hook output priority filter; policy drop;",
            "ip daddr 192.168.1.50 tcp dport 22 accept",
            "reject with icmpx admin-prohibited",
            "ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } drop",
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
        assert!(find(&coord, "/etc/ssh/sshd_config.d/10-dryserver.conf").content.contains("AllowUsers admin dryreg"));

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
