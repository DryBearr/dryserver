//! The VPN for your own devices (phones, laptops): a WireGuard network of
//! its own, on one server, the gateway. A device on it reaches the apps
//! whose entrance is `vpn`, and nothing else: not SSH, not the mesh, not
//! the home network, not the other devices.
//!
//! - Which server is the gateway, its port and its subnet, and every
//!   device with its key and address, are in the member list the admin
//!   signs. The coordinator cannot add a device, and one taken out of the
//!   list is cut off within a minute.
//! - The gateway's interface (wgp) is kept by its sync: made, given its
//!   address and its peers, and taken down when the server is no longer
//!   the gateway. It uses the server's own mesh key: its public half is
//!   in the signed list already, so a device's config needs nothing that
//!   only the coordinator says.
//! - The firewall (sysconf) has the rules on every machine, inert without
//!   wgp: a device reaches only the VPN's ingress on the gateway. The port
//!   the gateway listens on is a set its sync fills.
//! - The VPN's ingress is a Traefik of its own (namespace vpn, on the
//!   gateway), with certificates from Let's Encrypt, proven through
//!   Cloudflare DNS: no port has to be open for them. It serves only the
//!   Ingresses labelled dryserver/vpn, and the cluster's own Traefik
//!   none of them.
//! - A device's config has no DNS server: with the gateway down, only the
//!   VPN's apps stop, not the device's internet. Their names point at the
//!   gateway's VPN address in public DNS (DNS only, never proxied).

use std::collections::BTreeSet;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::cidr::Cidr;
use crate::ctx::Ctx;
use crate::err::{Error, Result};
use crate::runner::{Cmd, Runner};
use crate::{bail, errf, fsx, registry};

/// The gateway's interface.
pub const IFACE: &str = "wgp";
pub const DEFAULT_PORT: u16 = 51821;
pub const DEFAULT_SUBNET: &str = "10.99.0.0/24";
/// More devices than this are not a home's.
pub const MAX_DEVICES: usize = 100;
/// Below what most mobile networks and PPPoE lines carry, WireGuard's
/// own bytes included.
pub const MTU: u16 = 1380;
/// A device sends something this often (seconds), so the NAT it sits
/// behind keeps its way back open.
pub const KEEPALIVE: u16 = 25;
/// The nft sets (inet dryserver) of the ports the gateway listens on and
/// of its VPN address.
pub const PORTS_SET: &str = "vpn_ports";
pub const ADDRS_SET: &str = "vpn_addrs";
/// The VPN's ingress, in the cluster.
pub const NAMESPACE: &str = "vpn";
/// On an Ingress: the VPN's Traefik serves it, the cluster's never.
pub const LABEL: &str = "dryserver/vpn";
/// The pods of the VPN's Traefik.
pub const POD_LABEL: &str = "dryserver-vpn";
/// The ports the VPN's Traefik listens on inside its pod; the gateway's
/// VPN address 80 and 443 lead there.
pub const HTTP_PORT: u16 = 18000;
pub const HTTPS_PORT: u16 = 18443;
const PING_PORT: u16 = 19000;
/// The Cloudflare token for the certificates: a file on the gateway, root
/// put it there (`sudo dryserver vpn token` on it), only the VPN's Traefik
/// reads it. Never in the cluster: there, the cluster's own Traefik on
/// every machine may read every secret.
pub const TOKEN_DIR: &str = "/var/lib/dryserver-vpn/secrets";
pub const TOKEN_FILE: &str = "/var/lib/dryserver-vpn/secrets/cloudflare-token";
/// The VPN's own files: on the coordinator what it applied, on the
/// gateway its Traefik's certificates (ACME_DIR).
pub const STATE_DIR: &str = "/var/lib/dryserver-vpn";
/// Where the VPN's Traefik keeps its certificates, on the gateway.
pub const ACME_DIR: &str = "/var/lib/dryserver-vpn/acme";
/// The account the VPN's Traefik runs as.
pub const TRAEFIK_UID: u32 = 65532;
/// Traefik, by digest: v3.7.20 (security fixes of 2026-11-23).
pub const TRAEFIK_IMAGE: &str = "docker.io/library/traefik:v3.7.20@sha256:8301d6f60957a422f98918aacf2b01482abde3e74ead3719aabdb7c64045fe28";
/// What the gateway's sync found, for its report (RAM: gone at boot).
pub const STATUS_FILE: &str = "/run/dryserver/vpn-status.json";
/// What Let's Encrypt calls the resolver.
pub const RESOLVER: &str = "dryserver";

/// Address ranges a VPN subnet may not touch: k3s's pods and services,
/// and what is never a network (this machine, link-local, multicast).
const RESERVED: [&str; 3] = [crate::sysconf::K3S_POD_CIDR, crate::sysconf::K3S_SERVICE_CIDR, "172.17.0.0/16"];
/// A VPN subnet is a private one: a public range would take real
/// addresses away from the gateway (Let's Encrypt's, Cloudflare's).
const PRIVATE: [&str; 3] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];

/// The VPN as the admin set it up.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Plan {
    /// The server (its name in the signed list) devices connect to.
    pub gateway: String,
    /// The UDP port the gateway listens on.
    pub port: u16,
    pub subnet: String,
    /// Where devices find it from the internet: a DNS name or an IPv4
    /// address (your line's public one).
    pub endpoint: String,
    /// The port on that address: the router forwards it to port on the
    /// gateway. 0: the same as port.
    pub public_port: u16,
}

/// A device on the VPN.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Device {
    pub name: String,
    /// Its WireGuard public key.
    pub key: String,
    /// Its address in the subnet.
    pub addr: String,
}

/// A device name: like a machine's ("phone", "ana-laptop").
pub fn valid_device_name(s: &str) -> bool {
    registry::valid_name(s) && s.len() <= 32
}

/// A DNS name devices can dial, lowercase, or an IPv4 address.
pub fn valid_endpoint(s: &str) -> bool {
    if s.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    let labels: Vec<&str> = s.split('.').collect();
    s.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| registry::valid_name(l))
        && !labels.last().is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
}

fn overlap(a: &Cidr, b: &Cidr) -> bool {
    let p = a.prefix.min(b.prefix);
    let m = if p == 0 { 0 } else { u32::MAX << (32 - p) };
    a.network() & m == b.network() & m
}

impl Plan {
    #[cfg(test)]
    pub fn new(gateway: &str, endpoint: &str) -> Plan {
        Plan { gateway: gateway.into(), port: DEFAULT_PORT, subnet: DEFAULT_SUBNET.into(), endpoint: endpoint.into(), public_port: 0 }
    }

    pub fn cidr(&self) -> Option<Cidr> {
        Cidr::parse(&self.subnet).filter(|c| c.addr == c.network())
    }

    /// The gateway's address: the first in the subnet.
    pub fn gateway_addr(&self) -> Option<Ipv4Addr> {
        self.cidr().map(|c| Ipv4Addr::from(c.network() + 1))
    }

    /// The port devices dial.
    pub fn dial_port(&self) -> u16 {
        if self.public_port == 0 { self.port } else { self.public_port }
    }

    /// What the plan says, checked on its own.
    pub fn check(&self) -> Result<()> {
        if !registry::valid_name(&self.gateway) {
            bail!("the VPN's gateway is not a machine name: {:?}", self.gateway);
        }
        if self.port < 1024 {
            bail!("the VPN's port: 1024 to 65535");
        }
        let Some(c) = self.cidr() else {
            bail!("the VPN's subnet is not a network like {DEFAULT_SUBNET}: {:?}", self.subnet);
        };
        if !(16..=28).contains(&c.prefix) {
            bail!("the VPN's subnet: from /16 to /28 (like {DEFAULT_SUBNET})");
        }
        let inside = |outer: &Cidr| outer.prefix <= c.prefix && overlap(outer, &c);
        if !PRIVATE.iter().any(|r| inside(&Cidr::parse(r).expect("a fixed range"))) {
            bail!("the VPN's subnet {} is not a private one (inside 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16)", self.subnet);
        }
        for r in RESERVED {
            if overlap(&c, &Cidr::parse(r).expect("a fixed range")) {
                bail!("the VPN's subnet {} overlaps {r}, which is not free (the cluster's or Docker's)", self.subnet);
            }
        }
        if !valid_endpoint(&self.endpoint) {
            bail!("the VPN's address for devices is not a DNS name or an IPv4 address: {:?}", self.endpoint);
        }
        Ok(())
    }

    /// Whether the plan's subnet overlaps another network the swarm uses
    /// (the mesh, the home network), named for the error.
    pub fn clashes(&self, what: &str, net: &str) -> Result<()> {
        if let (Some(a), Some(b)) = (self.cidr(), Cidr::parse(net))
            && overlap(&a, &b)
        {
            bail!("the VPN's subnet {} overlaps {what} ({net}): choose another one (--subnet)", self.subnet);
        }
        Ok(())
    }
}

/// Checks the plan and the devices together, as the signed list carries
/// them. members: (name, host number, WireGuard key) of every machine.
pub fn check(plan: Option<&Plan>, devices: &[Device], members: &[(&str, u32, &str)]) -> Result<()> {
    if devices.len() > MAX_DEVICES {
        bail!("the signed list has {} devices, more than {MAX_DEVICES}", devices.len());
    }
    if let Some(p) = plan {
        p.check()?;
        match members.iter().find(|(n, _, _)| *n == p.gateway) {
            None => bail!("the VPN's gateway {} is not a machine of the swarm", p.gateway),
            Some((_, 1, _)) => bail!("the VPN's gateway cannot be the coordinator: choose a server"),
            Some(_) => {}
        }
    }
    let mut names = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut addrs = BTreeSet::new();
    for d in devices {
        if !valid_device_name(&d.name) || !names.insert(d.name.as_str()) {
            bail!("the signed list has a device with a bad or repeated name: {:?}", d.name);
        }
        if !registry::valid_wg_key(&d.key) || !keys.insert(d.key.as_str()) || members.iter().any(|(_, _, k)| *k == d.key) {
            bail!("the device {} has a bad key, or one another device or a machine has", d.name);
        }
        let Ok(ip) = d.addr.parse::<Ipv4Addr>() else { bail!("the device {} has no address", d.name) };
        if !addrs.insert(ip) {
            bail!("the device {} has an address another device has", d.name);
        }
        if let Some(c) = plan.and_then(Plan::cidr)
            && !usable(&c, ip)
        {
            bail!("the device {} has an address outside the VPN's subnet, or one no device can have: {ip}", d.name);
        }
    }
    Ok(())
}

/// An address a device may have: inside, not the network, the gateway or
/// the broadcast address.
fn usable(c: &Cidr, ip: Ipv4Addr) -> bool {
    let n = u32::from(ip);
    c.contains(ip) && n > c.network() + 1 && n < c.network() + (c.size() as u32) - 1
}

/// The first free address for a new device.
pub fn next_addr(plan: &Plan, devices: &[Device]) -> Option<Ipv4Addr> {
    let c = plan.cidr()?;
    let taken: BTreeSet<Ipv4Addr> = devices.iter().filter_map(|d| d.addr.parse().ok()).collect();
    (c.network() + 2..c.network() + (c.size() as u32) - 1).map(Ipv4Addr::from).find(|ip| !taken.contains(ip))
}

/// What a device imports into the WireGuard app. private: its private
/// key when dryserver made it; without, a line says where it goes.
/// gateway_key: the gateway's public key (its mesh key).
pub fn client_config(plan: &Plan, d: &Device, private: Option<&str>, gateway_key: &str) -> String {
    let gw = plan.gateway_addr().map(|a| a.to_string()).unwrap_or_default();
    let key = match private {
        Some(k) => format!("PrivateKey = {}", k.trim()),
        None => "# PrivateKey: the one this device made (its public key is the one you gave dryserver)".into(),
    };
    format!(
        "# dryserver VPN: {name} ({addr}), through {gateway}.\n\
         # Only the VPN's apps go through it; everything else as before.\n\
         [Interface]\n{key}\nAddress = {addr}/32\nMTU = {MTU}\n\n\
         [Peer]\nPublicKey = {gateway_key}\nAllowedIPs = {gw}/32\nEndpoint = {endpoint}:{port}\nPersistentKeepalive = {KEEPALIVE}\n",
        name = d.name,
        addr = d.addr,
        gateway = plan.gateway,
        endpoint = plan.endpoint,
        port = plan.dial_port(),
    )
}

// ---- on the gateway ----

/// A device as the gateway sees it. Its key's start only: the report
/// has a size limit, and that is enough to tell the devices apart.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Seen {
    pub key: String,
    /// When it last made a handshake (seconds since 1970); 0: never.
    pub handshake: i64,
}

/// How much of a device's key the report carries.
pub const KEY_PREFIX: usize = 12;

/// What the gateway's sync found, for its report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Status {
    /// This machine is the gateway and its interface is up.
    pub gateway: bool,
    pub port: u16,
    pub devices: Vec<Seen>,
    /// The Cloudflare token for the certificates is on the gateway.
    pub token: bool,
    /// What is not right yet, in words.
    pub problem: String,
}

/// What a machine knows to be the gateway, or stop being it.
pub struct Here<'a> {
    pub root: &'a Path,
    pub run: &'a dyn Runner,
    /// This machine's name in the signed list.
    pub name: &'a str,
    pub coordinator: bool,
    /// The mesh's port: the VPN's must be another.
    pub mesh_port: u16,
    /// The mesh's private key (its file).
    pub key_file: PathBuf,
    /// For the interface's config, RAM-backed.
    pub tmp: PathBuf,
}

impl Here<'_> {
    fn ip(&self, ctx: &Ctx, args: &[&str]) -> Result<String> {
        self.run.output(ctx, &Cmd::new("ip", args).quiet())
    }

    fn has_iface(&self, ctx: &Ctx) -> bool {
        self.run.ok(ctx, &Cmd::new("ip", &["-o", "link", "show", "dev", IFACE]).quiet()).is_ok()
    }

    /// The firewall's sets: exactly this port and address (or none), in
    /// one step.
    fn set_firewall(&self, ctx: &Ctx, open: Option<(u16, Ipv4Addr)>) -> Result<()> {
        let mut t = format!("flush set inet dryserver {PORTS_SET}\nflush set inet dryserver {ADDRS_SET}\n");
        if let Some((port, addr)) = open {
            t += &format!("add element inet dryserver {PORTS_SET} {{ {port} }}\nadd element inet dryserver {ADDRS_SET} {{ {addr} }}\n");
        }
        self.run.ok(ctx, &Cmd::new("nft", &["-f", "-"]).stdin(t).quiet()).map_err(|e| {
            e.wrap("the firewall has no VPN rules yet (this machine's firewall is from before the VPN: it comes with the next update)")
        })
    }

    /// Makes this machine the gateway the plan says, or no gateway, and
    /// keeps what it found for the report. Each sync: a step cut off half
    /// way is done by the next one.
    pub fn reconcile(&self, ctx: &Ctx, plan: Option<&Plan>, devices: &[Device]) -> Status {
        let st = self.make(ctx, plan, devices);
        let file = fsx::under(self.root, STATUS_FILE);
        if st == Status::default() {
            let _ = std::fs::remove_file(&file);
        } else if let Ok(json) = serde_json::to_string(&st) {
            let _ = fsx::mkdir_all(fsx::dir(&file), 0o755).and_then(|_| fsx::write_file(&file, json + "\n", 0o644));
        }
        st
    }

    fn make(&self, ctx: &Ctx, plan: Option<&Plan>, devices: &[Device]) -> Status {
        let mine = plan.filter(|p| p.gateway == self.name && !self.coordinator);
        let Some(p) = mine else {
            down(ctx, self.root, self.run);
            return Status::default();
        };
        let token = std::fs::metadata(fsx::under(self.root, TOKEN_FILE)).is_ok_and(|m| m.len() > 0);
        let mut st = Status { port: p.port, token, ..Status::default() };
        if let Err(e) = self.up(ctx, p, devices) {
            st.problem = e.to_string();
            return st;
        }
        st.gateway = true;
        st.devices = self.seen(ctx);
        st
    }

    fn up(&self, ctx: &Ctx, p: &Plan, devices: &[Device]) -> Result<()> {
        if p.port == self.mesh_port {
            bail!("the VPN's port {} is the mesh's: choose another one (dryserver vpn on ... --vpn-port)", p.port);
        }
        let (Some(c), Some(gw)) = (p.cidr(), p.gateway_addr()) else { bail!("the VPN's subnet is not one") };
        let key = fsx::read_or_empty(fsx::under(self.root, &self.key_file));
        if !registry::valid_wg_key(key.trim()) {
            bail!("this machine has no mesh key to be the VPN's gateway with");
        }
        // Its certificates' and its token's folders, for the VPN's Traefik
        // (its account): the certificates its own, the token only to read.
        fsx::mkdir_all(fsx::under(self.root, STATE_DIR), 0o755)?;
        for (dir, mode) in [(ACME_DIR, 0o700), (TOKEN_DIR, 0o500)] {
            let d = fsx::under(self.root, dir);
            fsx::mkdir_all(&d, mode)?;
            if self.root == Path::new("/") {
                std::os::unix::fs::chown(&d, Some(TRAEFIK_UID), Some(TRAEFIK_UID))
                    .map_err(|e| Error::from(e).wrap(format!("own {dir}")))?;
            }
        }
        // The firewall first: without its VPN rules, no interface.
        self.set_firewall(ctx, Some((p.port, gw)))?;
        if !self.has_iface(ctx) {
            self.ip(ctx, &["link", "add", "dev", IFACE, "type", "wireguard"])?;
        }
        self.ip(ctx, &["link", "set", "dev", IFACE, "mtu", &MTU.to_string()])?;
        let want = format!("{gw}/{}", c.prefix);
        let have = self.ip(ctx, &["-4", "-o", "address", "show", "dev", IFACE]).unwrap_or_default();
        let addrs: Vec<&str> = have.lines().filter_map(|l| l.split_whitespace().skip_while(|w| *w != "inet").nth(1)).collect();
        if addrs != [want.as_str()] {
            self.ip(ctx, &["-4", "address", "flush", "dev", IFACE])?;
            self.ip(ctx, &["-4", "address", "add", &want, "dev", IFACE])?;
        }
        let conf = wg_config(key.trim(), p.port, devices);
        self.syncconf(ctx, &conf)?;
        self.ip(ctx, &["link", "set", "dev", IFACE, "up"]).map(|_| ())
    }

    /// wg syncconf from a 0600 file in RAM, removed after.
    fn syncconf(&self, ctx: &Ctx, conf: &str) -> Result<()> {
        fsx::mkdir_all(&self.tmp, 0o700)?;
        let tmp = self.tmp.join(format!("dryserver-{IFACE}-{}.conf", fsx::hex(&fsx::random_bytes(6))));
        struct Remove<'a>(&'a Path);
        impl Drop for Remove<'_> {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(self.0);
            }
        }
        let _rm = Remove(&tmp);
        let mut f = std::fs::OpenOptions::new();
        std::os::unix::fs::OpenOptionsExt::mode(f.write(true).create_new(true), 0o600);
        f.open(&tmp)?.write_all(conf.as_bytes())?;
        self.run.ok(ctx, &Cmd::new("wg", &["syncconf", IFACE, &tmp.display().to_string()]))
    }

    fn seen(&self, ctx: &Ctx) -> Vec<Seen> {
        let out = self.run.output(ctx, &Cmd::new("wg", &["show", IFACE, "dump"]).quiet().stdout_only()).unwrap_or_default();
        dump(&out)
    }
}

/// No gateway here: the interface goes, the firewall's sets are emptied,
/// and the certificates and the token go too (they are the gateway's
/// alone). Quiet: also where none of it ever was.
pub fn down(ctx: &Ctx, root: &Path, run: &dyn Runner) {
    if run.ok(ctx, &Cmd::new("ip", &["-o", "link", "show", "dev", IFACE]).quiet()).is_ok() {
        let _ = run.ok(ctx, &Cmd::new("ip", &["link", "del", "dev", IFACE]));
    }
    // Only where the firewall has the sets: from before the VPN, there is
    // nothing to empty.
    let t = format!("flush set inet dryserver {PORTS_SET}\nflush set inet dryserver {ADDRS_SET}\n");
    let _ = run.ok(ctx, &Cmd::new("nft", &["-f", "-"]).stdin(t).quiet());
    for dir in [ACME_DIR, TOKEN_DIR] {
        let d = fsx::under(root, dir);
        if d.exists() {
            let _ = std::fs::remove_dir_all(&d);
        }
    }
}

/// Puts the Cloudflare token for the certificates on the gateway (as
/// root): its account's to read, nobody else's, and its Traefik started
/// again so that it takes it.
pub fn put_token(ctx: &Ctx, root: &Path, run: &dyn Runner, token: &str) -> Result<()> {
    let dir = fsx::under(root, TOKEN_DIR);
    if !dir.is_dir() {
        bail!(
            "this machine is not the VPN's gateway (yet): {TOKEN_DIR} is not there. Run it on the gateway, a minute after dryserver vpn on"
        );
    }
    let file = fsx::under(root, TOKEN_FILE);
    let tmp = file.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    fsx::write_new(&tmp, format!("{}\n", token.trim()), 0o400)?;
    if root == Path::new("/") {
        std::os::unix::fs::chown(&tmp, Some(TRAEFIK_UID), Some(TRAEFIK_UID)).map_err(|e| Error::from(e).wrap("own the token"))?;
    }
    fsx::rename(&tmp, &file)?;
    // Its Traefik reads the token when it starts: its container is stopped,
    // and the cluster starts it again at once.
    let label = format!("io.kubernetes.pod.namespace={NAMESPACE}");
    let ids =
        run.output(ctx, &Cmd::new("k3s", &["crictl", "ps", "-q", "--label", &label, "--name", "traefik"]).quiet()).unwrap_or_default();
    for id in ids.split_whitespace().filter(|i| i.bytes().all(|b| b.is_ascii_hexdigit())).take(4) {
        let _ = run.ok(ctx, &Cmd::new("k3s", &["crictl", "stop", id]).quiet());
    }
    Ok(())
}

/// The interface's whole config: syncconf takes it as it is, so a device
/// taken out of the list is gone from the interface too.
pub fn wg_config(private: &str, port: u16, devices: &[Device]) -> String {
    let mut s = format!("[Interface]\nPrivateKey = {private}\nListenPort = {port}\n");
    for d in devices {
        s += &format!("\n[Peer]\n# {}\nPublicKey = {}\nAllowedIPs = {}/32\n", d.name, d.key, d.addr);
    }
    s
}

/// The devices in `wg show IFACE dump`: after the interface's own line,
/// key, preshared key, endpoint, allowed IPs, handshake, rx, tx,
/// keepalive, tab separated.
pub fn dump(out: &str) -> Vec<Seen> {
    out.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            if f.len() < 7 || !registry::valid_wg_key(f[0]) {
                return None;
            }
            Some(Seen { key: f[0].chars().take(KEY_PREFIX).collect(), handshake: f[4].parse().unwrap_or(0) })
        })
        .take(MAX_DEVICES)
        .collect()
}

// ---- in the cluster ----

/// The VPN's ingress: a Traefik of its own on the gateway, its account
/// and what it may read (the apps' Ingresses, services and endpoints).
/// Applied by the coordinator; labelled so that its removal finds every
/// part.
pub fn cluster_manifest(p: &Plan) -> Result<String> {
    p.check()?;
    let gw = p.gateway_addr().ok_or_else(|| errf!("the VPN's subnet is not one"))?;
    let apps = crate::apps::NAMESPACE;
    let part = "app.kubernetes.io/part-of: dryserver-vpn";
    // The apps' namespace too: what the VPN's Traefik may read is there,
    // and on a new cluster it is not there before the first app.
    let apps_ns = crate::apps::namespace_yaml();
    Ok(format!(
        r#"{apps_ns}---
apiVersion: v1
kind: Namespace
metadata:
  name: {NAMESPACE}
  labels:
    {part}
    # Its Traefik listens on the gateway's VPN address (hostPort) and
    # keeps its certificates there (hostPath); the pod itself is locked
    # down below.
    pod-security.kubernetes.io/enforce: privileged
    pod-security.kubernetes.io/warn: baseline
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: traefik
  namespace: {NAMESPACE}
  labels:
    {part}
---
# What it reads of the apps: their Ingresses, services and endpoints, and
# their TLS secrets (Traefik watches them; none of the apps' is named).
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: dryserver-vpn-traefik
  namespace: {apps}
  labels:
    {part}
rules:
  - apiGroups: [""]
    resources: [services, endpoints, secrets]
    verbs: [get, list, watch]
  - apiGroups: [discovery.k8s.io]
    resources: [endpointslices]
    verbs: [get, list, watch]
  - apiGroups: [networking.k8s.io]
    resources: [ingresses]
    verbs: [get, list, watch]
  - apiGroups: [networking.k8s.io]
    resources: [ingresses/status]
    verbs: [update]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: dryserver-vpn-traefik
  namespace: {apps}
  labels:
    {part}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: dryserver-vpn-traefik
subjects:
  - kind: ServiceAccount
    name: traefik
    namespace: {NAMESPACE}
---
# The cluster's ingress classes: an Ingress the cluster gave its default
# class is still the VPN's when it carries the label.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: dryserver-vpn-traefik
  labels:
    {part}
rules:
  - apiGroups: [networking.k8s.io]
    resources: [ingressclasses]
    verbs: [get, list, watch]
  - apiGroups: [""]
    resources: [nodes]
    verbs: [get, list, watch]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: dryserver-vpn-traefik
  labels:
    {part}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: dryserver-vpn-traefik
subjects:
  - kind: ServiceAccount
    name: traefik
    namespace: {NAMESPACE}
---
# Only the devices reach it: their subnet, the gateway's own address left
# out (its accounts, or what the gateway sends itself, are not devices),
# and nothing else, no pod, no machine.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: devices-only
  namespace: {NAMESPACE}
  labels:
    {part}
spec:
  podSelector: {{}}
  policyTypes: [Ingress]
  ingress:
    - from:
        - ipBlock:
            cidr: "{subnet}"
            except: ["{gw}/32"]
      ports:
        - port: {HTTP_PORT}
        - port: {HTTPS_PORT}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: traefik
  namespace: {NAMESPACE}
  labels:
    {part}
spec:
  replicas: 1
  # Its ports are the gateway's: the new copy starts once the old is gone.
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app.kubernetes.io/name: {POD_LABEL}
  template:
    metadata:
      labels:
        app.kubernetes.io/name: {POD_LABEL}
        {part}
    spec:
      serviceAccountName: traefik
      enableServiceLinks: false
      # Bound to the gateway by name: a node's own labels (which its
      # kubelet may set) do not move it.
      nodeName: "{gateway}"
      securityContext:
        runAsNonRoot: true
        runAsUser: {TRAEFIK_UID}
        runAsGroup: {TRAEFIK_UID}
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: traefik
          image: "{TRAEFIK_IMAGE}"
          args:
            - --global.checknewversion=false
            - --global.sendanonymoususage=false
            - --entrypoints.web.address=:{HTTP_PORT}
            - --entrypoints.web.http.redirections.entrypoint.to=:443
            - --entrypoints.web.http.redirections.entrypoint.scheme=https
            - --entrypoints.websecure.address=:{HTTPS_PORT}
            - --entrypoints.websecure.http.tls.certresolver={RESOLVER}
            - --entrypoints.traefik.address=:{PING_PORT}
            - --ping=true
            - --providers.kubernetesingress=true
            - --providers.kubernetesingress.namespaces={apps}
            - --providers.kubernetesingress.labelselector={LABEL}=true
            - --certificatesresolvers.{RESOLVER}.acme.storage=/data/acme.json
            - --certificatesresolvers.{RESOLVER}.acme.dnschallenge.provider=cloudflare
            - --certificatesresolvers.{RESOLVER}.acme.dnschallenge.resolvers=1.1.1.1:53,8.8.8.8:53
            - --log.level=INFO
          env:
            # A file on the gateway, never a secret in the cluster.
            - name: CF_DNS_API_TOKEN_FILE
              value: /secrets/cloudflare-token
          ports:
            - name: web
              containerPort: {HTTP_PORT}
              hostPort: 80
              hostIP: "{gw}"
            - name: websecure
              containerPort: {HTTPS_PORT}
              hostPort: 443
              hostIP: "{gw}"
          readinessProbe:
            httpGet:
              path: /ping
              port: {PING_PORT}
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /ping
              port: {PING_PORT}
            periodSeconds: 30
            failureThreshold: 4
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
            limits:
              cpu: 500m
              memory: 256Mi
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - name: certificates
              mountPath: /data
            - name: token
              mountPath: /secrets
              readOnly: true
            - name: tmp
              mountPath: /tmp
      volumes:
        # Made by the gateway's sync, its account's alone.
        - name: certificates
          hostPath:
            path: {ACME_DIR}
            type: Directory
        - name: token
          hostPath:
            path: {TOKEN_DIR}
            type: Directory
        - name: tmp
          emptyDir: {{}}
"#,
        gateway = p.gateway,
        subnet = p.subnet,
    ))
}

/// What the coordinator keeps of what it applied.
const APPLIED: &str = "vpn-applied";
/// Applied again this often all the same, so a part deleted by hand comes
/// back.
const REAPPLY_SECS: i64 = 10 * 60;

/// On the coordinator, each sync: the VPN's ingress as the plan says, or
/// none. state: a directory of the coordinator's own. Returns lines for
/// the log, the problems only.
pub fn cluster_on_coordinator(ctx: &Ctx, c: &dyn crate::apps::Cluster, plan: Option<&Plan>, state: &Path, now: i64) -> Vec<String> {
    let mut log = Vec::new();
    let file = state.join(APPLIED);
    let was = fsx::read_or_empty(&file);
    let (digest, at) = was.trim().split_once(' ').map(|(d, t)| (d.to_string(), t.parse::<i64>().unwrap_or(0))).unwrap_or_default();
    match plan {
        Some(p) => {
            let manifest = match cluster_manifest(p) {
                Ok(m) => m,
                Err(e) => return vec![format!("vpn: {e}")],
            };
            use sha2::Digest;
            let d = fsx::hex(&sha2::Sha256::digest(manifest.as_bytes()));
            if d == digest && now - at < REAPPLY_SECS {
                return log;
            }
            match c.kubectl(ctx, &["apply", "-f", "-"], &manifest) {
                Ok(_) => {
                    let _ = fsx::mkdir_all(state, 0o700).and_then(|_| fsx::write_file(&file, format!("{d} {now}\n"), 0o600));
                }
                Err(e) => log.push(format!("vpn: the VPN's ingress was not applied: {e}")),
            }
        }
        None if !was.is_empty() => {
            let sel = "app.kubernetes.io/part-of=dryserver-vpn";
            let steps: [&[&str]; 3] = [
                &["-n", NAMESPACE, "delete", "deployment,serviceaccount,networkpolicy", "-l", sel, "--ignore-not-found"],
                &["-n", crate::apps::NAMESPACE, "delete", "role,rolebinding", "-l", sel, "--ignore-not-found"],
                &["delete", "clusterrole,clusterrolebinding", "-l", sel, "--ignore-not-found"],
            ];
            let mut ok = true;
            for s in steps {
                if let Err(e) = c.kubectl(ctx, s, "") {
                    log.push(format!("vpn: the VPN's ingress is not taken down yet: {e}"));
                    ok = false;
                    break;
                }
            }
            if ok {
                let _ = std::fs::remove_file(&file);
            }
        }
        None => {}
    }
    log
}

#[cfg(test)]
mod tests;
