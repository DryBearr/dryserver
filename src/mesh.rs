//! Turns the registry's member list into this machine's WireGuard config,
//! /etc/hosts names and SSH trust files, and the desktop's SSH config.

use std::net::Ipv4Addr;

use crate::cidr::Cidr;
use crate::config::{self, Config};
use crate::registry::{self, Member};
use crate::sysconf;

/// What this machine knows about itself.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct SelfInfo {
    /// Mesh host number.
    pub host: u32,
    /// Has a cable link on its Ethernet port.
    pub switch: bool,
}

/// The mesh or switch address of host n, without prefix; "" when it does
/// not fit.
pub fn ip(cidr: &str, n: u32) -> String {
    match sysconf::host_addr(cidr, n) {
        Ok(addr) => addr.split('/').next().unwrap_or("").to_string(),
        Err(_) => String::new(),
    }
}

/// The host number of ip inside cidr, or 0.
pub fn host_of(cidr: &str, ip: Ipv4Addr) -> u32 {
    let Some(n) = Cidr::parse(cidr) else {
        return 0;
    };
    if !n.contains(ip) {
        return 0;
    }
    let v = u32::from(ip).wrapping_sub(n.network()) as u64;
    if v == 0 || v >= n.size() - 1 {
        return 0;
    }
    v as u32
}

/// registry::Mesh for the configured mesh subnet.
pub struct Subnet(pub String);

impl registry::Mesh for Subnet {
    fn host_of(&self, ip: Ipv4Addr) -> u32 {
        host_of(&self.0, ip)
    }
}

/// Where to send WireGuard packets for peer: its switch address when both
/// machines have a cable link (auto mode), otherwise its LAN address.
pub fn endpoint(cfg: &Config, me: SelfInfo, peer: &Member) -> String {
    let mut addr = peer.lan_ip.clone();
    if cfg.wg_transport == config::TRANSPORT_AUTO && me.switch && peer.switch {
        addr = ip(&cfg.switch_subnet, peer.host);
    }
    if addr.is_empty() {
        return String::new();
    }
    format!("{addr}:{}", cfg.wg_port)
}

/// /etc/wireguard/wg0.conf. The private key stays in its own file and is
/// loaded by PostUp, so this file holds nothing secret.
pub fn wg_config(cfg: &Config, me: SelfInfo, members: &[Member]) -> String {
    let addr = sysconf::host_addr(&cfg.wg_subnet, me.host).unwrap_or_default();
    let mut b = format!(
        "# dryserver mesh, rewritten by \"dryserver sync\" from the coordinator's list.\n\
         [Interface]\n\
         Address = {addr}\n\
         ListenPort = {}\n\
         PostUp = wg set %i private-key /etc/wireguard/wg0.key\n",
        cfg.wg_port
    );
    for m in sorted(members) {
        if m.host == me.host {
            continue;
        }
        b += &format!("\n# {}\n[Peer]\nPublicKey = {}\nAllowedIPs = {}/32\n", m.name, m.wg_key, ip(&cfg.wg_subnet, m.host));
        let ep = endpoint(cfg, me, &m);
        if !ep.is_empty() {
            b += &format!("Endpoint = {ep}\n");
        }
        b += "PersistentKeepalive = 25\n";
    }
    b
}

pub const HOSTS_BEGIN: &str = "# dryserver mesh begin";
pub const HOSTS_END: &str = "# dryserver mesh end";

/// /etc/hosts with the mesh block replaced by current names.
pub fn hosts(current: &str, cfg: &Config, members: &[Member]) -> String {
    let mut keep: Vec<String> = Vec::new();
    let mut skip = false;
    for l in current.trim_end_matches('\n').split('\n') {
        if l == HOSTS_BEGIN {
            skip = true;
        } else if l == HOSTS_END {
            skip = false;
        } else if !skip {
            keep.push(l.to_string());
        }
    }
    keep.push(HOSTS_BEGIN.into());
    for m in sorted(members) {
        keep.push(format!("{} {}", ip(&cfg.wg_subnet, m.host), m.name));
    }
    keep.push(HOSTS_END.into());
    keep.join("\n") + "\n"
}

/// Every member's SSH host key under its name and mesh IP, so SSH between
/// servers never asks to trust a key.
pub fn known_hosts(cfg: &Config, members: &[Member]) -> String {
    let mut b = String::from("# dryserver mesh host keys, from the coordinator.\n");
    for m in sorted(members) {
        let f: Vec<&str> = m.ssh_host_key.split_whitespace().collect();
        if f.len() < 2 {
            continue;
        }
        b += &format!("{},{} {} {}\n", m.name, ip(&cfg.wg_subnet, m.host), f[0], f[1]);
    }
    b
}

/// Lets `ssh <name>` reach any member over the mesh and forwards the agent
/// (the desktop key) for the next hop. No private keys live on servers.
pub fn ssh_config(cfg: &Config, members: &[Member]) -> String {
    let names: Vec<String> = sorted(members).into_iter().map(|m| m.name).collect();
    format!(
        "# dryserver mesh hosts: ssh <name> works between servers using the key\n\
         # forwarded from your desktop (connect with ssh -A).\n\
         Host {}\n    User {}\n    ForwardAgent yes\n    StrictHostKeyChecking yes\n",
        names.join(" "),
        cfg.username
    )
}

fn sorted(members: &[Member]) -> Vec<Member> {
    let mut out = members.to_vec();
    out.sort_by_key(|m| m.host);
    out
}

// ---- desktop export ----

/// One mesh member as seen from the desktop.
#[derive(Debug, Clone, PartialEq)]
pub struct Server {
    pub name: String,
    pub mesh_ip: String,
}

/// Reads the dryserver block of a server's /etc/hosts.
pub fn parse_hosts_block(hosts: &str) -> Vec<Server> {
    let mut out = Vec::new();
    let mut inside = false;
    for l in hosts.split('\n') {
        match l.trim() {
            HOSTS_BEGIN => {
                inside = true;
                continue;
            }
            HOSTS_END => {
                inside = false;
                continue;
            }
            _ => {}
        }
        let f: Vec<&str> = l.split_whitespace().collect();
        if inside && f.len() == 2 {
            out.push(Server { name: f[1].into(), mesh_ip: f[0].into() });
        }
    }
    out
}

/// ~/.ssh/config.d/dryserver: the coordinator by its LAN IP, every other
/// server through it (ProxyJump) by mesh IP. The agent (your desktop key) is
/// forwarded so you can hop between servers.
pub fn desktop_ssh_config(user: &str, coord_name: &str, coord_lan_ip: &str, port: &str, known_hosts: &str, servers: &[Server]) -> String {
    let port_line = if !port.is_empty() && port != "22" { format!("    Port {port}\n") } else { String::new() };
    let mut b = format!(
        "# dryserver servers, written by \"dryserver ssh-config\". Regenerate after\n\
         # adding machines. Your key stays on this desktop; it is forwarded (-A).\n\
         \n\
         Host {coord_name}\n    HostName {coord_lan_ip}\n{port_line}    User {user}\n    ForwardAgent yes\n    UserKnownHostsFile ~/.ssh/known_hosts {known_hosts}\n"
    );
    for s in servers {
        if s.name == coord_name {
            continue;
        }
        b += &format!(
            "\nHost {}\n    HostName {}\n    User {user}\n    ProxyJump {coord_name}\n    ForwardAgent yes\n    UserKnownHostsFile ~/.ssh/known_hosts {known_hosts}\n",
            s.name, s.mesh_ip
        );
    }
    b
}

/// Adds the coordinator's LAN address to the key lines from a server's
/// /etc/ssh/ssh_known_hosts (name,meshIP keytype key). SSH writes addresses
/// on other ports than 22 as [host]:port.
pub fn desktop_known_hosts(server_known_hosts: &str, coord_name: &str, coord_lan_ip: &str, port: &str) -> String {
    let coord = if !port.is_empty() && port != "22" { format!("[{coord_lan_ip}]:{port}") } else { coord_lan_ip.to_string() };
    let mut b = String::from("# dryserver server host keys, from the coordinator.\n");
    for l in server_known_hosts.split('\n') {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() != 3 || f[0].starts_with('#') {
            continue;
        }
        let mut hosts = f[0].to_string();
        if f[0].split(',').next() == Some(coord_name) {
            hosts += &format!(",{coord}");
        }
        b += &format!("{hosts} {} {}\n", f[1], f[2]);
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(transport: &str) -> Config {
        Config { coord_lan_ip: "192.168.1.50".into(), wg_transport: transport.into(), ..Config::default() }
    }

    fn members() -> Vec<Member> {
        let m = |host, name: &str, key: &str, lan: &str, switch, hk: &str| Member {
            host,
            name: name.into(),
            wg_key: key.into(),
            lan_ip: lan.into(),
            switch,
            ssh_host_key: hk.into(),
            ..Member::default()
        };
        vec![
            m(3, "node-c", "KEYC", "192.168.1.30", false, "ssh-ed25519 AAAAc root@node-c"),
            m(1, "coord", "KEYA", "192.168.1.50", true, "ssh-ed25519 AAAAa root@coord"),
            m(2, "node-b", "KEYB", "192.168.1.20", true, "ssh-ed25519 AAAAb root@node-b"),
        ]
    }

    #[test]
    fn endpoint_choice() {
        let ms = members();
        let auto = cfg(config::TRANSPORT_AUTO);
        let me = SelfInfo { host: 2, switch: true };
        assert_eq!(endpoint(&auto, me, &ms[1]), "172.16.66.1:51820", "both on switch");
        assert_eq!(endpoint(&auto, me, &ms[0]), "192.168.1.30:51820", "peer without cable must use LAN");
        assert_eq!(endpoint(&auto, SelfInfo { host: 2, switch: false }, &ms[1]), "192.168.1.50:51820", "self without cable");
        assert_eq!(endpoint(&cfg(config::TRANSPORT_LAN), me, &ms[1]), "192.168.1.50:51820", "lan mode");
    }

    #[test]
    fn wg0_conf() {
        let out = wg_config(&cfg(config::TRANSPORT_AUTO), SelfInfo { host: 2, switch: true }, &members());
        for want in [
            "Address = 10.66.0.2/24",
            "ListenPort = 51820",
            "private-key /etc/wireguard/wg0.key",
            "# coord\n[Peer]\nPublicKey = KEYA\nAllowedIPs = 10.66.0.1/32\nEndpoint = 172.16.66.1:51820",
            "AllowedIPs = 10.66.0.3/32\nEndpoint = 192.168.1.30:51820",
        ] {
            assert!(out.contains(want), "wg0.conf missing {want:?}:\n{out}");
        }
        assert!(!out.contains("KEYB") && !out.contains("PrivateKey"), "must not list itself or hold the private key");
        assert!(out.find("# coord") < out.find("# node-c"), "peers not sorted by host");
    }

    #[test]
    fn hosts_block() {
        let cur = "127.0.0.1 localhost\n# dryserver mesh begin\n10.66.0.9 old-node\n# dryserver mesh end\n192.168.1.5 printer\n";
        let c = cfg(config::TRANSPORT_LAN);
        let out = hosts(cur, &c, &members());
        assert!(!out.contains("old-node") && out.contains("printer") && out.contains("10.66.0.3 node-c"), "hosts:\n{out}");
        assert_eq!(hosts(&out, &c, &members()), out, "hosts rewrite must be stable");
    }

    #[test]
    fn known_hosts_and_ssh_config() {
        let c = cfg(config::TRANSPORT_LAN);
        let kh = known_hosts(&c, &members());
        assert!(kh.contains("coord,10.66.0.1 ssh-ed25519 AAAAa\n") && !kh.contains("root@"), "known_hosts:\n{kh}");
        let sc = ssh_config(&c, &members());
        assert!(sc.contains("Host coord node-b node-c") && sc.contains("ForwardAgent yes"), "ssh_config:\n{sc}");
    }

    #[test]
    fn host_numbers() {
        for (addr, want) in [("10.66.0.7", 7), ("10.66.0.0", 0), ("10.66.0.255", 0), ("10.66.1.7", 0), ("192.168.1.7", 0)] {
            assert_eq!(host_of("10.66.0.0/24", addr.parse().unwrap()), want, "{addr}");
        }
        assert_eq!(ip("172.16.66.0/24", 5), "172.16.66.5");
    }

    #[test]
    fn desktop_export() {
        let c = cfg(config::TRANSPORT_LAN);
        let h = hosts("127.0.0.1 localhost\n", &c, &members());
        let servers = parse_hosts_block(&h);
        assert_eq!(servers.len(), 3);
        assert_eq!(servers[0].name, "coord");
        assert_eq!(servers[2].mesh_ip, "10.66.0.3");
        let conf = desktop_ssh_config("admin", "coord", "192.168.1.50", "22", "~/.ssh/known_hosts.d/dryserver", &servers);
        for want in [
            "Host coord\n    HostName 192.168.1.50\n",
            "Host node-b\n    HostName 10.66.0.2\n    User admin\n    ProxyJump coord\n    ForwardAgent yes",
        ] {
            assert!(conf.contains(want), "config missing {want:?}:\n{conf}");
        }
        let kh = desktop_known_hosts(&known_hosts(&c, &members()), "coord", "192.168.1.50", "22");
        assert!(kh.contains("coord,10.66.0.1,192.168.1.50 ssh-ed25519 AAAAa\n"), "{kh}");
        assert!(kh.contains("node-c,10.66.0.3 ssh-ed25519 AAAAc\n"), "{kh}");
        let kh = desktop_known_hosts(&known_hosts(&c, &members()), "coord", "127.0.0.1", "2201");
        assert!(kh.contains("coord,10.66.0.1,[127.0.0.1]:2201 "), "non-22 port:\n{kh}");
    }
}
