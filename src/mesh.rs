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

/// Where to send WireGuard packets for peer, "" for nowhere.
///
/// The addresses in the member list are each member's own word, kept by
/// the registry account, which may be hacked: taken for both ends of a
/// link, they would let it point every machine at a wrong address for
/// good. So:
///
/// - The coordinator names no address: every server dials it and keeps the
///   link up (PersistentKeepalive), and WireGuard answers where the
///   server's packets came from, as it learns from each packet it can
///   open.
/// - A server reaches the coordinator at the address in its own config
///   (COORD_LAN_IP), or at the coordinator's switch address when both
///   have a cable link (auto mode; node.rs tries it with a ping first).
/// - Another server at its switch address when both have a cable link
///   (auto mode), else at its LAN address as the list says, a hint that a
///   live link overrides (wg_config_live).
pub fn endpoint(cfg: &Config, me: SelfInfo, peer: &Member) -> String {
    if me.host == 1 {
        return String::new();
    }
    let mut addr = if peer.host == 1 { cfg.coord_lan_ip.clone() } else { peer.lan_ip.clone() };
    if on_switch(cfg, me, peer) {
        addr = ip(&cfg.switch_subnet, peer.host);
    }
    if addr.is_empty() {
        return String::new();
    }
    format!("{addr}:{}", cfg.wg_port)
}

/// Whether the link to peer goes over the switch: auto mode, and both
/// machines have a cable link.
fn on_switch(cfg: &Config, me: SelfInfo, peer: &Member) -> bool {
    cfg.wg_transport == config::TRANSPORT_AUTO && me.switch && peer.switch
}

/// How long after its newest handshake a link counts as live. WireGuard
/// shakes hands every two minutes on a link in use (the keepalive keeps
/// every link in use) and drops a session older than three.
pub const LIVE_SECS: i64 = 180;

/// What WireGuard on this machine knows of a peer: where its packets come
/// from ("a.b.c.d:port") and its newest handshake (Unix seconds, 0 never).
/// Only the peer's own key opens a packet that moves it, so the registry
/// account cannot.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Live {
    pub endpoint: String,
    pub handshake: i64,
}

/// Reads `wg show wg0 endpoints` and `wg show wg0 latest-handshakes`: by
/// WireGuard key, the IPv4 endpoint and the newest handshake of each peer.
/// Lines that are not that ("(none)", IPv6) are left out.
pub fn live_peers(endpoints: &str, handshakes: &str) -> std::collections::BTreeMap<String, Live> {
    let mut out = std::collections::BTreeMap::new();
    for line in endpoints.lines().take(4 * 254) {
        let mut f = line.split_whitespace();
        let (Some(key), Some(ep)) = (f.next(), f.next()) else { continue };
        let valid =
            ep.rsplit_once(':').is_some_and(|(addr, port)| addr.parse::<Ipv4Addr>().is_ok() && port.parse::<u16>().is_ok_and(|p| p > 0));
        if valid && registry::valid_wg_key(key) {
            out.insert(key.to_string(), Live { endpoint: ep.to_string(), handshake: 0 });
        }
    }
    for line in handshakes.lines().take(4 * 254) {
        let mut f = line.split_whitespace();
        if let (Some(key), Some(at)) = (f.next(), f.next().and_then(|t| t.parse::<i64>().ok()))
            && let Some(l) = out.get_mut(key)
        {
            l.handshake = at;
        }
    }
    out
}

/// /etc/wireguard/wg0.conf, from the list alone (wg_config_live writes it).
#[cfg(test)]
pub fn wg_config(cfg: &Config, me: SelfInfo, members: &[Member]) -> String {
    wg_config_live(cfg, me, members, &std::collections::BTreeMap::new(), 0)
}

/// /etc/wireguard/wg0.conf. The private key stays in its own file and is
/// loaded by PostUp, so this file holds nothing secret.
///
/// live is what WireGuard knows of each peer now (live_peers, at Unix
/// time now). Between two servers, the list's LAN address is only a
/// hint: a link with a handshake in the last LIVE_SECS keeps the endpoint
/// WireGuard has, which the peer's own packets set. Without it, `wg
/// syncconf` would put the hint back every minute. A switch address is
/// never kept that way: a switch link holds only while this sync's ping
/// says so (endpoint), so a pulled cable moves the link to the LAN at the
/// next sync, and a cable plugged in moves it to the switch.
pub fn wg_config_live(cfg: &Config, me: SelfInfo, members: &[Member], live: &std::collections::BTreeMap<String, Live>, now: i64) -> String {
    let switch = Cidr::parse(&cfg.switch_subnet).filter(|_| cfg.wg_transport == config::TRANSPORT_AUTO);
    let kept = |m: &Member| -> Option<String> {
        if me.host == 1 || m.host == 1 || on_switch(cfg, me, m) {
            return None;
        }
        let l = live.get(&m.wg_key)?;
        let fresh = l.handshake > 0 && (now - l.handshake).abs() <= LIVE_SECS;
        let addr = l.endpoint.rsplit_once(':').and_then(|(a, _)| a.parse::<Ipv4Addr>().ok())?;
        (fresh && !switch.is_some_and(|s| s.contains(addr))).then(|| l.endpoint.clone())
    };
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
        let ep = kept(&m).unwrap_or_else(|| endpoint(cfg, me, &m));
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
/// Host keys are checked against known_hosts (from the signed list) alone,
/// and an unknown or changed key is refused: an old key the user once
/// accepted in ~/.ssh/known_hosts, say of a coordinator that was cut off
/// and reinstalled at the same address, never passes for the server where
/// the admin types the sudo password.
///
/// Each server with a known LAN address also gets "<name>.lan": straight to
/// that address, never through the coordinator, checked against the same
/// pinned host key (HostKeyAlias). The kill switch uses these when the
/// coordinator cannot be trusted.
pub fn desktop_ssh_config(user: &str, coord_name: &str, coord_lan_ip: &str, port: &str, known_hosts: &str, servers: &[Server]) -> String {
    let port_line = if !port.is_empty() && port != "22" { format!("    Port {port}\n") } else { String::new() };
    let keys = format!("    StrictHostKeyChecking yes\n    UserKnownHostsFile {known_hosts}\n    GlobalKnownHostsFile /dev/null\n");
    let mut b = format!(
        "# dryserver servers, written by \"dryserver ssh-config\". Regenerate after\n\
         # adding machines. Your key stays on this desktop and is never forwarded.\n\
         # Host keys come from the list you signed: a server with another key is\n\
         # refused (after a reinstall, run ssh-config again).\n\
         \n\
         Host {coord_name}\n    HostName {coord_lan_ip}\n{port_line}    User {user}\n    ForwardAgent no\n{keys}"
    );
    for s in servers {
        if s.name == coord_name {
            continue;
        }
        b += &format!(
            "\nHost {}\n    HostName {}\n    User {user}\n    ProxyJump {coord_name}\n    ForwardAgent no\n{keys}",
            s.name, s.mesh_ip
        );
    }
    for s in servers {
        if s.name == coord_name || parse_ip4(&s.lan_ip).is_none() {
            continue;
        }
        b += &format!(
            "\nHost {}{LAN_SUFFIX}\n    HostName {}\n    HostKeyAlias {}\n    User {user}\n    ProxyJump none\n    ForwardAgent no\n{keys}",
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

    /// The registry account keeps the member list, addresses included. It
    /// never picks where a server finds the coordinator, nor where the
    /// coordinator finds a server.
    #[test]
    fn the_list_never_moves_the_coordinators_links() {
        let mut ms = members();
        ms[1].lan_ip = "203.0.113.50".into();
        ms[1].switch = false;
        for transport in [config::TRANSPORT_AUTO, config::TRANSPORT_LAN] {
            let c = cfg(transport);
            for sw in [false, true] {
                let me = SelfInfo { host: 2, switch: sw };
                // The coordinator says it has no cable: on a switch link
                // node.rs found by ping, it is used anyway.
                let want = if sw && transport == config::TRANSPORT_AUTO { "172.16.66.1:51820" } else { "192.168.1.50:51820" };
                assert_eq!(endpoint(&c, me, &Member { switch: sw, ..ms[1].clone() }), want, "{transport} {sw}");
                assert!(!wg_config(&c, me, &ms).contains("203.0.113.50"), "{transport} {sw}");
            }
            // The coordinator: no address for anyone, so it answers where
            // each server's packets come from.
            let out = wg_config(&c, SelfInfo { host: 1, switch: true }, &ms);
            assert!(!out.contains("Endpoint") && out.matches("PersistentKeepalive = 25").count() == 2, "{transport}:\n{out}");
            assert!(out.contains("PublicKey = KEYB\nAllowedIPs = 10.66.0.2/32\n"), "{out}");
        }
    }

    #[test]
    fn a_live_link_beats_the_lists_address() {
        let ms = members();
        let now = 1_800_000_000;
        let live = |ep: &str, ago: i64| {
            std::collections::BTreeMap::from([("KEYC".to_string(), Live { endpoint: ep.into(), handshake: now - ago })])
        };
        let node_c = |c: &Config, me: SelfInfo, l: &std::collections::BTreeMap<String, Live>| {
            let out = wg_config_live(c, me, &ms, l, now);
            let block = out.split("# node-c\n").nth(1).unwrap_or_default().to_string();
            block.lines().find(|l| l.starts_with("Endpoint = ")).unwrap_or("").to_string()
        };
        let (auto, lan) = (cfg(config::TRANSPORT_AUTO), cfg(config::TRANSPORT_LAN));
        let me = SelfInfo { host: 2, switch: false };
        // Roamed to another address (DHCP), or the list is wrong: the link
        // that works stays.
        for c in [&auto, &lan] {
            assert_eq!(node_c(c, me, &live("192.168.1.77:51820", 20)), "Endpoint = 192.168.1.77:51820");
            assert_eq!(node_c(c, me, &live("192.168.1.77:51820", LIVE_SECS)), "Endpoint = 192.168.1.77:51820");
            // Silent too long, never shaken, or nothing known: the hint.
            for l in [live("192.168.1.77:51820", LIVE_SECS + 1), live("192.168.1.77:51820", now), std::collections::BTreeMap::new()] {
                assert_eq!(node_c(c, me, &l), "Endpoint = 192.168.1.30:51820");
            }
        }
        // A switch address WireGuard still has, while this sync's ping
        // found no switch link: the cable was pulled, the LAN takes over.
        assert_eq!(node_c(&auto, me, &live("172.16.66.3:51820", 20)), "Endpoint = 192.168.1.30:51820");
        // A switch link this sync found beats a live LAN link: the cable
        // was plugged in.
        let mut both = ms.clone();
        both[0].switch = true;
        let out = wg_config_live(&auto, SelfInfo { host: 2, switch: true }, &both, &live("192.168.1.77:51820", 20), now);
        assert!(out.contains("AllowedIPs = 10.66.0.3/32\nEndpoint = 172.16.66.3:51820"), "{out}");
        // The coordinator's address is never taken from a live link.
        let coord = std::collections::BTreeMap::from([("KEYA".to_string(), Live { endpoint: "10.9.9.9:51820".into(), handshake: now })]);
        assert!(wg_config_live(&lan, me, &ms, &coord, now).contains("AllowedIPs = 10.66.0.1/32\nEndpoint = 192.168.1.50:51820"));
    }

    #[test]
    fn live_links_from_wg_show() {
        let key = |n: u8| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [n; 32]);
        let (a, b, c, d, e) = (key(1), key(2), key(3), key(4), key(5));
        let endpoints = format!(
            "{a}\t192.168.1.50:51820\n{b}\t(none)\n{c}\t[fd00::1]:51820\n{d}\t10.0.0.9:0\nbad\t1.2.3.4:5\n{e}\t192.168.1.31:51820\n"
        );
        let times = format!("{a}\t1800000000\n{e}\t0\n{b}\t1800000001\n{e}\tsoon\n");
        let got = live_peers(&endpoints, &times);
        assert_eq!(got.len(), 2, "{got:?}");
        assert_eq!(got[&a], Live { endpoint: "192.168.1.50:51820".into(), handshake: 1_800_000_000 });
        assert_eq!(got[&e], Live { endpoint: "192.168.1.31:51820".into(), handshake: 0 });
        assert!(live_peers("", &times).is_empty());
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
        // Each entry checks host keys against the signed ones alone, and
        // refuses any other: an old key in ~/.ssh/known_hosts (the old
        // coordinator's, at the same address) never passes.
        let keys =
            "    StrictHostKeyChecking yes\n    UserKnownHostsFile ~/.ssh/known_hosts.d/dryserver\n    GlobalKnownHostsFile /dev/null\n";
        let entries: Vec<&str> = conf.split("\nHost ").skip(1).collect();
        assert_eq!(entries.len(), 4, "{conf}");
        for e in &entries {
            assert!(e.ends_with(keys), "entry {e:?}");
        }
        assert!(!conf.contains("~/.ssh/known_hosts ") && !conf.contains("StrictHostKeyChecking ask"), "{conf}");
        // The kill switch still finds every server that does not go
        // through the coordinator.
        let names: Vec<String> = crate::quarantine::remotes(&conf).into_iter().map(|r| r.name).collect();
        assert_eq!(names, ["coord", "node-c"]);
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
