//! The system files written to every installed server: firewall, SSH,
//! kernel hardening, network, Docker and login settings. Rendering is pure
//! so the output can be golden-tested and validated with the real tools
//! (nft -c, sshd -t).

use std::fmt;
use std::net::Ipv4Addr;

use crate::cidr::Cidr;
use crate::config::{self, Config, Port};
use crate::err::{Context, Result};
use crate::{errf, fsx, packages};

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
            nftables(&c.wg_port, &switch_subnet(c), &ports_of(&mesh_ports, "tcp"), &ports_of(&mesh_ports, "udp")),
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

fn nftables(wg_port: &str, switch: &str, mesh_tcp: &[u16], mesh_udp: &[u16]) -> String {
    let switch_rule =
        if switch.is_empty() { String::new() } else { format!("\n\n\t\t# Switch network: WireGuard only.\n\t\tip saddr {switch} drop") };
    let tcp: String = mesh_tcp.iter().map(|p| format!(", {p}")).collect();
    let udp_rule = if mesh_udp.is_empty() {
        String::new()
    } else {
        let list = mesh_udp.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ");
        format!("\n\t\tudp dport {{ {list} }} accept")
    };
    format!(
        r#"#!/usr/bin/nft -f
# dryserver firewall, generated from config.env. To open more ports to the
# mesh, change MESH_PORTS there. Only this table is touched, so Docker's own
# rules survive reloads.

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

	chain input {{
		type filter hook input priority filter; policy drop;
		ct state vmap {{ established : accept, related : accept, invalid : drop }}
		iif lo accept

		icmp type echo-request limit rate 10/second accept
		icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert }} accept
		icmpv6 type echo-request limit rate 10/second accept

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
		tcp dport {{ 22{tcp} }} accept{udp_rule}
		icmp type echo-request accept
		icmpv6 type echo-request accept
	}}
}}
"#
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
# Agent forwarding lets you hop between servers with your desktop key;
# TCP forwarding is needed for ProxyJump through a server.
AllowAgentForwarding yes
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
            "tcp dport { 22, 8080, 9000 } accept",
            "udp dport { 53 } accept",
        ] {
            assert!(nft.contains(want), "node nftables missing {want:?}");
        }
        assert!(!nft.contains("flush ruleset"), "nftables must not flush Docker's rules");
        assert!(!find(&coord, "/etc/nftables.conf").content.contains("ip saddr 172.16"), "lan transport must not add a switch rule");

        let sshd = &find(&node, "/etc/ssh/sshd_config.d/10-dryserver.conf").content;
        for want in ["PasswordAuthentication no", "PermitRootLogin no", "AllowUsers admin\n"] {
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
