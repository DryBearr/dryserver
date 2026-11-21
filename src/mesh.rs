//! Turns the registry's member list into this machine's WireGuard config,
//! /etc/hosts names and SSH trust files, and the desktop's SSH config.

use std::net::Ipv4Addr;

use crate::cidr::{Cidr, parse_ip4};
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

    fn fits(&self, host: u32) -> bool {
        !ip(&self.0, host).is_empty()
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
        if m.host == me.host || m.wg_key.contains(|c: char| c.is_whitespace() || c.is_control()) {
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
/// Suffix of a server's LAN name: node-b.lan.
pub const LAN_SUFFIX: &str = ".lan";
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

/// Lets `ssh <name>` reach any member over the mesh by name, with pinned host
/// keys. The desktop key is never forwarded, so no key reaches servers.
pub fn ssh_config(cfg: &Config, members: &[Member]) -> String {
    let names: Vec<String> = sorted(members).into_iter().map(|m| m.name).collect();
    format!(
        "# dryserver mesh hosts: names and pinned host keys. Your desktop key is\n\
         # never forwarded to servers; connect to each server from the desktop.\n\
         Host {}\n    User {}\n    ForwardAgent no\n    StrictHostKeyChecking yes\n",
        names.join(" "),
        cfg.username
    )
}

/// The members by host number, the ones with a name that is not a plain
/// hostname left out. Names reach the files written from this only after
/// registry::check_members; checked again here because a name with a
/// newline would add lines of its own choosing to them (an SSH
/// `Match exec`, a WireGuard peer).
fn sorted(members: &[Member]) -> Vec<Member> {
    let mut out: Vec<Member> = members.iter().filter(|m| registry::valid_name(&m.name)).cloned().collect();
    out.sort_by_key(|m| m.host);
    out
}

// ---- desktop export ----

/// One mesh member as seen from the desktop: its identity from the list
/// the admin signed, its LAN address as the coordinator reports it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Server {
    pub name: String,
    pub mesh_ip: String,
    /// "" when not known. Not signed: SSH checks the host key anyway.
    pub lan_ip: String,
    /// "type base64", from the signed list.
    pub host_key: String,
}

/// ~/.ssh/config.d/dryserver: the coordinator by its LAN IP, every other
/// server through it (ProxyJump) by mesh IP. ProxyJump only tunnels the
/// connection through the coordinator; the key never leaves the desktop.
/// ForwardAgent no is explicit so a "Host *" default in ~/.ssh/config cannot
/// turn forwarding back on.
///
/// Each server with a known LAN address also gets "<name>.lan": straight to
/// that address, never through the coordinator, checked against the same
/// pinned host key (HostKeyAlias). The kill switch uses these when the
/// coordinator cannot be trusted.
pub fn desktop_ssh_config(user: &str, coord_name: &str, coord_lan_ip: &str, port: &str, known_hosts: &str, servers: &[Server]) -> String {
    let port_line = if !port.is_empty() && port != "22" { format!("    Port {port}\n") } else { String::new() };
    let mut b = format!(
        "# dryserver servers, written by \"dryserver ssh-config\". Regenerate after\n\
         # adding machines. Your key stays on this desktop and is never forwarded.\n\
         \n\
         Host {coord_name}\n    HostName {coord_lan_ip}\n{port_line}    User {user}\n    ForwardAgent no\n    UserKnownHostsFile ~/.ssh/known_hosts {known_hosts}\n"
    );
    for s in servers {
        if s.name == coord_name {
            continue;
        }
        b += &format!(
            "\nHost {}\n    HostName {}\n    User {user}\n    ProxyJump {coord_name}\n    ForwardAgent no\n    UserKnownHostsFile ~/.ssh/known_hosts {known_hosts}\n",
            s.name, s.mesh_ip
        );
    }
    for s in servers {
        if s.name == coord_name || parse_ip4(&s.lan_ip).is_none() {
            continue;
        }
        b += &format!(
            "\nHost {}{LAN_SUFFIX}\n    HostName {}\n    HostKeyAlias {}\n    User {user}\n    ProxyJump none\n    ForwardAgent no\n    UserKnownHostsFile ~/.ssh/known_hosts {known_hosts}\n",
            s.name, s.lan_ip, s.name
        );
    }
    b
}

/// The desktop's known_hosts: every server's SSH host key from the signed
/// list, under its name and mesh IP. The coordinator is also listed under
/// its LAN address; SSH writes addresses on other ports than 22 as
/// [host]:port.
pub fn desktop_known_hosts(servers: &[Server], coord_name: &str, coord_lan_ip: &str, port: &str) -> String {
    let coord = if !port.is_empty() && port != "22" { format!("[{coord_lan_ip}]:{port}") } else { coord_lan_ip.to_string() };
    let mut b = String::from("# dryserver server host keys, from the member list you signed.\n");
    for s in servers {
        let f: Vec<&str> = s.host_key.split_whitespace().collect();
        if f.len() < 2 {
            continue;
        }
        let mut hosts = format!("{},{}", s.name, s.mesh_ip);
        if s.name == coord_name {
            hosts += &format!(",{coord}");
        }
        b += &format!("{hosts} {} {}\n", f[0], f[1]);
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
        assert!(!out.contains(".lan"), "LAN addresses do not belong in /etc/hosts:\n{out}");
        // A name that slipped through must still not become a line.
        let mut odd = members();
        odd[0].name = "x archlinux.org".into();
        odd[2].name = "a\n10.0.0.1 evil".into();
        let out = hosts("", &c, &odd);
        assert!(!out.contains("archlinux.org") && !out.contains("evil") && out.contains("10.66.0.1 coord"), "hosts:\n{out}");
    }

    /// On the brain the members come straight from the registry file,
    /// which the registry account writes. A name with a newline must not
    /// add lines to any file root writes from it.
    #[test]
    fn a_bad_name_adds_no_lines() {
        let c = cfg(config::TRANSPORT_LAN);
        let mut odd = members();
        odd[0].name = "x\nMatch exec \"touch /tmp/pwned\"".into();
        odd[2].name = "y\n[Peer]\nPublicKey = EVIL".into();
        odd[1].wg_key = "KEYA\nAllowedIPs = 0.0.0.0/0".into();
        let me = SelfInfo { host: 9, switch: false };
        for out in [ssh_config(&c, &odd), known_hosts(&c, &odd), wg_config(&c, me, &odd), hosts("", &c, &odd)] {
            assert!(!out.contains("Match") && !out.contains("EVIL") && !out.contains("0.0.0.0/0") && !out.contains("pwned"), "{out}");
            assert!(!out.contains("node-c") && !out.contains("node-b"), "{out}");
        }
        assert!(ssh_config(&c, &odd).contains("Host coord\n"), "{}", ssh_config(&c, &odd));
        assert!(!wg_config(&c, me, &odd).contains("KEYA"));
    }

    #[test]
    fn known_hosts_and_ssh_config() {
        let c = cfg(config::TRANSPORT_LAN);
        let kh = known_hosts(&c, &members());
        assert!(kh.contains("coord,10.66.0.1 ssh-ed25519 AAAAa\n") && !kh.contains("root@"), "known_hosts:\n{kh}");
        let sc = ssh_config(&c, &members());
        assert!(sc.contains("Host coord node-b node-c") && sc.contains("ForwardAgent no"), "ssh_config:\n{sc}");
        assert!(!sc.contains("ForwardAgent yes"), "servers must not forward the agent:\n{sc}");
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
        let server = |name: &str, n: u32, lan: &str| Server {
            name: name.into(),
            mesh_ip: format!("10.66.0.{n}"),
            lan_ip: lan.into(),
            host_key: format!("ssh-ed25519 AAAA{name}"),
        };
        let servers = vec![server("coord", 1, "192.168.1.50"), server("node-b", 2, ""), server("node-c", 3, "192.168.1.30")];
        let conf = desktop_ssh_config("admin", "coord", "192.168.1.50", "22", "~/.ssh/known_hosts.d/dryserver", &servers);
        for want in [
            "Host coord\n    HostName 192.168.1.50\n",
            "Host node-b\n    HostName 10.66.0.2\n    User admin\n    ProxyJump coord\n    ForwardAgent no",
        ] {
            assert!(conf.contains(want), "config missing {want:?}:\n{conf}");
        }
        assert!(!conf.contains("ForwardAgent yes"), "the desktop key must never be forwarded:\n{conf}");
        assert!(
            conf.contains("Host node-c.lan\n    HostName 192.168.1.30\n    HostKeyAlias node-c\n    User admin\n    ProxyJump none\n    ForwardAgent no\n"),
            "LAN entry:\n{conf}"
        );
        assert!(!conf.contains("Host coord.lan"), "the coordinator is reached by LAN address already:\n{conf}");
        assert!(!conf.contains("Host node-b.lan"), "no LAN entry without a LAN address:\n{conf}");
        // A LAN address that is not an address never becomes an entry.
        let conf = desktop_ssh_config(
            "admin",
            "coord",
            "192.168.1.50",
            "22",
            "kh",
            &[server("coord", 1, ""), server("node-x", 4, "evil.example.org")],
        );
        assert!(!conf.contains("evil.example.org"), "{conf}");

        let kh = desktop_known_hosts(&servers, "coord", "192.168.1.50", "22");
        assert!(kh.contains("coord,10.66.0.1,192.168.1.50 ssh-ed25519 AAAAcoord\n"), "{kh}");
        assert!(kh.contains("node-c,10.66.0.3 ssh-ed25519 AAAAnode-c\n"), "{kh}");
        let kh = desktop_known_hosts(&servers, "coord", "127.0.0.1", "2201");
        assert!(kh.contains("coord,10.66.0.1,[127.0.0.1]:2201 "), "non-22 port:\n{kh}");
        // A member without a host key gets no line (SSH then refuses it).
        let kh = desktop_known_hosts(&[Server { host_key: String::new(), ..server("node-z", 9, "") }], "coord", "192.168.1.50", "22");
        assert!(!kh.contains("node-z"), "{kh}");
    }
}
