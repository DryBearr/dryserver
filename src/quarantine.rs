//! The kill switch. `dryserver quarantine` cuts mesh members off from this
//! server without asking the coordinator, for when the coordinator (or
//! another member) may be hacked:
//!
//! - their WireGuard peers leave wg0.conf and the running interface,
//! - the firewall drops their addresses, also on connections already open,
//! - with the coordinator cut, sync and join stop talking to it.
//!
//! The cut is saved in STATE_FILE and survives reboots until `-lift`. The
//! removed wg0.conf blocks are saved too, so lifting brings the coordinator
//! back without its help. `dryserver quarantine-all` on the desktop runs it
//! on every server over the WiFi/router network, never through the
//! coordinator.

use std::io::Write;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::cidr::{Cidr, parse_ip4};
use crate::config::Config;
use crate::ctx::Ctx;
use crate::err::{Error, Result};
use crate::gotime::Time;
use crate::mesh;
use crate::node::{self, Node};
use crate::registry::{self, Member};
use crate::runner::Cmd;
use crate::{bail, fsx};

pub const STATE_FILE: &str = "/etc/dryserver/quarantine.json";
pub const NFT_DIR: &str = "/etc/dryserver/nft.d";
pub const NFT_FILE: &str = "/etc/dryserver/nft.d/quarantine.nft";
/// How /etc/nftables.conf loads NFT_DIR. A glob, so a missing directory or
/// file is not an error and never stops the main firewall from loading.
pub const NFT_INCLUDE: &str = "include \"/etc/dryserver/nft.d/*.nft\"";
pub const TABLE: &str = "dryserver_quarantine";
pub const ISSUE_FILE: &str = "/etc/issue.d/40-dryserver-quarantine.issue";
/// Held by sync, join and quarantine while they change the mesh files.
pub const MESH_LOCK: &str = "/run/dryserver-mesh.lock";
/// Where dryserver lives on servers; sudo's PATH may not have it.
pub const SERVER_BIN: &str = "/usr/local/bin/dryserver";

/// One member cut off from this server.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Cut {
    /// The member's name on this server, "" when unknown.
    pub name: String,
    /// Mesh host numbers; 1 is the coordinator.
    pub hosts: Vec<u32>,
    pub wg_keys: Vec<String>,
    /// IPv4 addresses the firewall drops.
    pub ips: Vec<String>,
    /// The wg0.conf blocks that were removed; -lift puts them back.
    pub peers: Vec<String>,
    pub since: Time,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub cuts: Vec<Cut>,
}

impl State {
    pub fn is_empty(&self) -> bool {
        self.cuts.is_empty()
    }

    /// Sync and join must not talk to the coordinator.
    pub fn coordinator_cut(&self) -> bool {
        self.cuts.iter().any(|c| c.hosts.contains(&1))
    }

    /// Whether m is cut, by WireGuard key or by mesh address.
    pub fn blocks(&self, m: &Member) -> bool {
        self.cuts.iter().any(|c| c.hosts.contains(&m.host) || (!m.wg_key.is_empty() && c.wg_keys.contains(&m.wg_key)))
    }

    fn ips(&self) -> Vec<Ipv4Addr> {
        let mut v: Vec<Ipv4Addr> = self.cuts.iter().flat_map(|c| c.ips.iter()).filter_map(|s| parse_ip4(s)).collect();
        v.sort();
        v.dedup();
        v
    }

    fn names(&self) -> String {
        self.cuts.iter().map(|c| shown(&c.name)).collect::<Vec<_>>().join(", ")
    }

    /// Adds c, folded into an earlier cut of the same member.
    fn add(&mut self, c: Cut) {
        let same = |o: &Cut| (!c.name.is_empty() && o.name == c.name) || o.hosts.iter().any(|h| c.hosts.contains(h));
        match self.cuts.iter_mut().find(|o| same(o)) {
            Some(o) => {
                union(&mut o.hosts, &c.hosts);
                union(&mut o.wg_keys, &c.wg_keys);
                union(&mut o.ips, &c.ips);
                union(&mut o.peers, &c.peers);
                if o.name.is_empty() {
                    o.name = c.name;
                }
            }
            None => self.cuts.push(c),
        }
    }
}

fn union<T: PartialEq + Clone>(into: &mut Vec<T>, from: &[T]) {
    for x in from {
        if !into.contains(x) {
            into.push(x.clone());
        }
    }
}

/// A name from wg0.conf (it came from the coordinator, so it may be
/// anything) made safe to print or write into a file.
fn shown(name: &str) -> String {
    if registry::valid_name(name) { name.to_string() } else { "(unnamed)".into() }
}

/// The start of a WireGuard key, for showing.
fn short_key(k: &str) -> String {
    k.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=')).take(8).collect()
}

/// The saved cut. A damaged file is an error, so sync stays away from the
/// coordinator rather than guessing.
pub fn load(n: &Node) -> Result<State> {
    match std::fs::read(n.path(STATE_FILE)) {
        Ok(b) => serde_json::from_slice(&b)
            .map_err(|e| Error::from(e).wrap(format!("{STATE_FILE} is damaged; `sudo dryserver quarantine -lift` clears it"))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
        Err(e) => Err(Error::from(e).wrap(format!("open {STATE_FILE}"))),
    }
}

/// Whether join must stop: the coordinator is cut, or the saved cut cannot
/// be read.
pub fn blocks_join(n: &Node) -> bool {
    load(n).map(|q| q.coordinator_cut()).unwrap_or(true)
}

// ---- wg0.conf ----

/// One [Peer] section of wg0.conf.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Peer {
    /// From the comment line above the section.
    pub name: String,
    pub key: String,
    pub allowed: Vec<String>,
    /// The section's lines with the comment and blank lines above it.
    pub block: String,
}

impl Peer {
    fn covers(&self, ip: Ipv4Addr) -> bool {
        self.allowed.iter().any(|a| {
            let c = if a.contains('/') { Cidr::parse(a) } else { parse_ip4(a).map(|i| Cidr { addr: u32::from(i), prefix: 32 }) };
            c.is_some_and(|c| c.contains(ip))
        })
    }

    /// Host numbers of the peer's single addresses inside the mesh.
    fn hosts(&self, subnet: &str) -> Vec<u32> {
        let mut v: Vec<u32> = self
            .allowed
            .iter()
            .filter_map(|a| parse_ip4(a.strip_suffix("/32").unwrap_or(a)))
            .map(|ip| mesh::host_of(subnet, ip))
            .filter(|h| *h > 0)
            .collect();
        v.dedup();
        v
    }
}

/// Splits wg0.conf into blocks: everything before the first peer, then one
/// block per [Peer] that starts at the comment and blank lines above it.
fn blocks(conf: &str) -> Vec<String> {
    let lines: Vec<&str> = conf.lines().collect();
    let mut starts = vec![0];
    for (i, l) in lines.iter().enumerate() {
        if l.trim() != "[Peer]" {
            continue;
        }
        let floor = *starts.last().unwrap_or(&0);
        let mut s = i;
        while s > floor && lines[s - 1].trim_start().starts_with('#') {
            s -= 1;
        }
        while s > floor && lines[s - 1].trim().is_empty() {
            s -= 1;
        }
        if s > floor {
            starts.push(s);
        }
    }
    starts.push(lines.len());
    starts.windows(2).map(|w| lines[w[0]..w[1]].iter().map(|l| format!("{l}\n")).collect()).collect()
}

pub fn parse_peers(conf: &str) -> Vec<Peer> {
    let mut out = Vec::new();
    for b in blocks(conf) {
        let mut p = Peer { block: b.clone(), ..Peer::default() };
        let mut in_peer = false;
        for l in b.lines() {
            let t = l.trim();
            if t.starts_with('[') {
                in_peer = t == "[Peer]";
                continue;
            }
            if !in_peer {
                if let Some(c) = t.strip_prefix('#')
                    && p.name.is_empty()
                {
                    p.name = c.trim().to_string();
                }
                continue;
            }
            let Some((k, v)) = t.split_once('=') else { continue };
            match k.trim().to_ascii_lowercase().as_str() {
                "publickey" => p.key = v.trim().to_string(),
                "allowedips" => p.allowed.extend(v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty())),
                _ => {}
            }
        }
        if b.lines().any(|l| l.trim() == "[Peer]") {
            out.push(p);
        }
    }
    out
}

/// wg0.conf without the peers that have one of keys.
pub fn without(conf: &str, keys: &[String]) -> String {
    blocks(conf).into_iter().filter(|b| !parse_peers(b).first().is_some_and(|p| keys.contains(&p.key))).collect()
}

/// wg0.conf with the saved peer blocks added back, skipping keys it has.
pub fn with_peers(conf: &str, saved: &[String]) -> String {
    let mut have: Vec<String> = parse_peers(conf).into_iter().map(|p| p.key).collect();
    let mut out = conf.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    for b in saved {
        let Some(p) = parse_peers(b).into_iter().next() else { continue };
        if p.key.is_empty() || have.contains(&p.key) {
            continue;
        }
        have.push(p.key);
        out += b;
    }
    out
}

// ---- what to cut ----

/// What a cut does on this server, worked out from its wg0.conf.
#[derive(Debug, Default)]
pub struct Plan {
    pub cuts: Vec<Cut>,
    /// Things the admin should know.
    pub notes: Vec<String>,
}

/// Default gateways from `ip -4 route show default`.
pub fn gateways(routes: &str) -> Vec<Ipv4Addr> {
    routes
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let i = f.iter().position(|w| *w == "via")?;
            parse_ip4(f.get(i + 1)?)
        })
        .collect()
}

/// Works out the cuts. names empty means the coordinator. me is this
/// server's host number (0 before joining) and name.
pub fn plan(cfg: &Config, me: u32, me_name: &str, peers: &[Peer], names: &[String], gateways: &[Ipv4Addr], now: Time) -> Result<Plan> {
    let Some(coord_ip) = parse_ip4(&mesh::ip(&cfg.wg_subnet, 1)) else {
        bail!("bad mesh subnet {:?}", cfg.wg_subnet);
    };
    let mut p = Plan::default();
    // The addresses of a host: mesh, switch and, for the coordinator, its
    // fixed LAN address. Never this server's own.
    let addresses = |hosts: &[u32], notes: &mut Vec<String>| -> Vec<String> {
        let mut ips = Vec::new();
        for &h in hosts {
            if h == me {
                continue;
            }
            ips.push(mesh::ip(&cfg.wg_subnet, h));
            if !cfg.switch_subnet.is_empty() {
                ips.push(mesh::ip(&cfg.switch_subnet, h));
            }
        }
        if hosts.contains(&1)
            && let Some(lan) = parse_ip4(&cfg.coord_lan_ip)
        {
            if gateways.contains(&lan) {
                notes.push(format!(
                    "{lan} (the coordinator's LAN address) is also this server's internet gateway, so it stays reachable; \
                     the WireGuard cut and the mesh address block still apply"
                ));
            } else {
                ips.push(lan.to_string());
            }
        }
        ips.retain(|ip| !ip.is_empty());
        ips.dedup();
        ips
    };

    if names.is_empty() {
        if me == 1 {
            bail!("this machine is the coordinator; name the members to cut with -name");
        }
        let found: Vec<&Peer> = peers.iter().filter(|x| x.covers(coord_ip)).collect();
        if found.is_empty() {
            p.notes
                .push("no WireGuard peer for the coordinator in wg0.conf (not joined yet, or cut already); blocking its addresses".into());
        }
        let mut hosts = vec![1];
        for x in &found {
            union(&mut hosts, &x.hosts(&cfg.wg_subnet));
        }
        hosts.retain(|h| *h != me);
        let name = found.iter().map(|x| x.name.clone()).find(|n| registry::valid_name(n)).unwrap_or_default();
        p.cuts.push(Cut {
            name,
            ips: addresses(&hosts, &mut p.notes),
            hosts,
            wg_keys: found.iter().map(|x| x.key.clone()).filter(|k| !k.is_empty()).collect(),
            peers: found.iter().map(|x| x.block.clone()).collect(),
            since: now,
        });
        return Ok(p);
    }

    let mut known: Vec<String> = peers.iter().map(|x| shown(&x.name)).collect();
    known.sort();
    known.dedup();
    for name in names {
        if !registry::valid_name(name) {
            bail!("{name:?} is not a server name");
        }
        if name == me_name {
            bail!("{name} is this server; run the cut on the other servers");
        }
        let found: Vec<&Peer> = peers.iter().filter(|x| x.name == *name).collect();
        if found.is_empty() {
            bail!("no mesh member named {name} on this server (members here: {})", known.join(", "));
        }
        if found.len() > 1 {
            p.notes.push(format!("{} WireGuard peers are named {name}; cutting all of them", found.len()));
        }
        let mut hosts = Vec::new();
        for x in &found {
            union(&mut hosts, &x.hosts(&cfg.wg_subnet));
        }
        if hosts.contains(&me) {
            p.notes.push(format!("a peer named {name} claims this server's own mesh address; it is cut by key only"));
            hosts.retain(|h| *h != me);
        }
        p.cuts.push(Cut {
            name: name.clone(),
            ips: addresses(&hosts, &mut p.notes),
            hosts,
            wg_keys: found.iter().map(|x| x.key.clone()).filter(|k| !k.is_empty()).collect(),
            peers: found.iter().map(|x| x.block.clone()).collect(),
            since: now,
        });
    }
    Ok(p)
}

/// The firewall table for the saved cuts.
pub fn nft_rules(st: &State) -> String {
    let ips = st.ips();
    let elements = if ips.is_empty() {
        String::new()
    } else {
        format!("\n\t\telements = {{ {} }}", ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", "))
    };
    format!(
        r#"#!/usr/bin/nft -f
# dryserver quarantine, written by "dryserver quarantine" and loaded with
# /etc/nftables.conf. Cut off: {names}.
# Undo with: sudo dryserver quarantine -lift

destroy table inet {TABLE}

table inet {TABLE} {{
	set cut4 {{
		type ipv4_addr{elements}
	}}

	# Before the dryserver and Docker tables. A drop here is final, also
	# for connections that were already open.
	chain input {{
		type filter hook input priority filter - 10; policy accept;
		ip saddr @cut4 limit rate 6/minute log prefix "dryserver-quarantine: "
		ip saddr @cut4 drop
	}}

	chain forward {{
		type filter hook forward priority filter - 10; policy accept;
		ip saddr @cut4 drop
		ip daddr @cut4 drop
	}}

	chain output {{
		type filter hook output priority filter - 10; policy accept;
		ip daddr @cut4 drop
	}}
}}
"#,
        names = st.names()
    )
}

fn issue(st: &State) -> String {
    format!(
        "\ndryserver: QUARANTINE: cut off from {}. Sync with the coordinator is {}.\n\
         Undo with: sudo dryserver quarantine -lift\n\n",
        st.names(),
        if st.coordinator_cut() { "paused" } else { "running" }
    )
}

// ---- running it on a server ----

/// Checks the rules with nft -c, then moves them where nftables.conf loads
/// them. A file that fails the check never reaches that place, so it can
/// never stop the firewall from loading at boot.
fn write_rules(ctx: &Ctx, n: &Node, st: &State) -> Result<()> {
    fsx::mkdir_all(n.path(NFT_DIR), 0o700)?;
    let check = n.path(&format!("{NFT_FILE}.check"));
    fsx::write_file(&check, nft_rules(st), 0o600)?;
    if let Err(e) = n.run.ok(ctx, &Cmd::new("nft", &["-c", "-f", &check.display().to_string()])) {
        let _ = std::fs::remove_file(&check);
        return Err(e.wrap("the firewall rules failed nft -c, nothing loaded"));
    }
    fsx::rename(&check, n.path(NFT_FILE))
}

fn save(n: &Node, st: &State) -> Result<()> {
    n.write(STATE_FILE, 0o600, &(serde_json::to_string_pretty(st)? + "\n"))
}

fn joined(n: &Node, coordinator: bool) -> bool {
    coordinator || n.load_state().host > 0
}

/// Cuts names (the coordinator when empty) off this server.
pub fn cut(ctx: &Ctx, n: &Node, coordinator: bool, names: &[String], out: &mut dyn Write) -> Result<()> {
    let me = if coordinator { 1 } else { n.load_state().host };
    let _lock = fsx::lock(n.path(MESH_LOCK))?;
    let mut st = match load(n) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(out, "warning: {e}\n  keeping it as {STATE_FILE}.damaged and starting over");
            let _ = fsx::rename(n.path(STATE_FILE), n.path(&format!("{STATE_FILE}.damaged")));
            State::default()
        }
    };
    let conf = fsx::read_or_empty(n.path(node::WG_CONF));
    let peers = parse_peers(&conf);
    let routes = n.run.output(ctx, &Cmd::new("ip", &["-4", "route", "show", "default"]).quiet()).unwrap_or_default();
    let plan = plan(&n.cfg, me, &n.hostname, &peers, names, &gateways(&routes), Time::now())?;

    // Report first: if this session runs through a machine being cut, it
    // freezes as soon as the firewall rules load.
    let _ = writeln!(out, "Cutting off from {}:", n.hostname);
    for c in &plan.cuts {
        let who = if c.hosts.contains(&1) { format!("{} (coordinator)", shown(&c.name)) } else { shown(&c.name) };
        let _ = writeln!(out, "  {who}: blocks {}; {} WireGuard peer(s)", c.ips.join(", "), c.wg_keys.len());
    }
    for note in &plan.notes {
        let _ = writeln!(out, "note: {note}");
    }
    for c in plan.cuts {
        st.add(c);
    }
    let keys: Vec<String> = st.cuts.iter().flat_map(|c| c.wg_keys.clone()).collect();
    let kept: Vec<&Peer> = peers.iter().filter(|p| !keys.contains(&p.key)).collect();
    if !kept.is_empty() {
        let _ = writeln!(out, "Peers this server keeps (check that you know each one; cut others with -name):");
        for p in kept {
            let addrs: String =
                p.allowed.join(",").chars().filter(|c| c.is_ascii_hexdigit() || matches!(c, '.' | '/' | ':' | ',')).collect();
            let _ = writeln!(out, "  {:<20} {:<18} key {}", shown(&p.name), addrs, short_key(&p.key));
        }
    }
    let _ = writeln!(out, "If this session goes through a machine being cut, it freezes now; the cut still finishes.");
    let _ = out.flush();

    // Saved first: if a later step fails or the machine reboots, sync and
    // join already stay away, and running the command again finishes it.
    save(n, &st)?;
    let mut errs = Vec::new();
    if !conf.is_empty() {
        let stripped = without(&conf, &keys);
        if stripped != conf
            && let Err(e) = n.write(node::WG_CONF, 0o600, &stripped)
        {
            errs.push(e.wrap("remove the peers from wg0.conf"));
        }
    }
    if let Err(e) = write_rules(ctx, n, &st) {
        errs.push(e);
    }
    if n.write(ISSUE_FILE, 0o644, &issue(&st)).is_ok() {
        let _ = n.run.ok(ctx, &Cmd::new("agetty", &["--reload"]));
    }
    if fsx::exists(n.path(NFT_FILE))
        && let Err(e) = n.run.ok(ctx, &Cmd::new("nft", &["-f", &n.path(NFT_FILE).display().to_string()]))
    {
        errs.push(e.wrap("load the firewall rules"));
    }
    if !conf.is_empty()
        && let Err(e) = n.reload_wg(ctx)
    {
        errs.push(e.wrap("apply wg0.conf"));
    }
    if !fsx::read_or_empty(n.path("/etc/nftables.conf")).contains(NFT_INCLUDE) {
        let _ = writeln!(
            out,
            "note: this server's /etc/nftables.conf is from an older dryserver and does not load the quarantine \
             rules at boot. After a reboot the WireGuard cut and the paused sync stay, but run this command again \
             to block the addresses."
        );
    }
    if let Some(e) = Error::join(errs) {
        return Err(e.wrap("the quarantine is saved but not complete; run the command again"));
    }
    let _ = writeln!(out, "Done. {} cut off. Undo with: sudo dryserver quarantine -lift", st.names());
    Ok(())
}

/// Undoes every cut: puts the saved peers back, removes the firewall
/// table, and lets sync and join run again.
pub fn lift(ctx: &Ctx, n: &Node, coordinator: bool, out: &mut dyn Write) -> Result<()> {
    let lock = fsx::lock(n.path(MESH_LOCK))?;
    let st = match load(n) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(out, "warning: {e}; the removed peers cannot be put back from it");
            State::default()
        }
    };
    let any = !st.is_empty() || fsx::exists(n.path(STATE_FILE)) || fsx::exists(n.path(NFT_FILE));
    if !any {
        let _ = writeln!(out, "{} is not quarantined.", n.hostname);
        return Ok(());
    }
    let mut errs = Vec::new();
    // Peers first, so sync can reach the coordinator again over the mesh.
    let conf = fsx::read_or_empty(n.path(node::WG_CONF));
    if !conf.is_empty() {
        let saved: Vec<String> = st.cuts.iter().flat_map(|c| c.peers.clone()).collect();
        let back = with_peers(&conf, &saved);
        if back != conf
            && let Err(e) = n.write(node::WG_CONF, 0o600, &back)
        {
            errs.push(e.wrap("put the peers back into wg0.conf"));
        }
    }
    match std::fs::remove_file(n.path(NFT_FILE)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => errs.push(Error::from(e).wrap(format!("remove {NFT_FILE}"))),
        _ => {}
    }
    if let Err(e) = n.run.ok(ctx, &Cmd::new("nft", &["destroy", "table", "inet", TABLE])) {
        errs.push(e.wrap("remove the firewall table"));
    }
    if !conf.is_empty()
        && let Err(e) = n.reload_wg(ctx)
    {
        errs.push(e.wrap("apply wg0.conf"));
    }
    if let Some(e) = Error::join(errs) {
        // The saved cut stays, so sync keeps away until a re-run finishes.
        return Err(e.wrap("the quarantine is only partly lifted; run the command again"));
    }
    let _ = std::fs::remove_file(n.path(ISSUE_FILE));
    let _ = n.run.ok(ctx, &Cmd::new("agetty", &["--reload"]));
    let _ = std::fs::remove_file(n.path(STATE_FILE));
    drop(lock);
    if joined(n, coordinator) {
        let _ = n.run.ok(ctx, &Cmd::new("systemctl", &["start", "--no-block", "dryserver-sync.service"]));
    } else {
        let _ = n.run.ok(ctx, &Cmd::new("systemctl", &["restart", "--no-block", "dryserver-join.service"]));
    }
    let _ = writeln!(out, "Lifted on {}. Sync runs again.", n.hostname);
    if st.coordinator_cut() {
        let _ = writeln!(
            out,
            "If the coordinator was reinstalled, its keys changed and sync will fail on the old pinned key: \
             this server has to be paired with the new coordinator again (not automated yet)."
        );
    }
    Ok(())
}

pub fn status(ctx: &Ctx, n: &Node, out: &mut dyn Write) -> Result<()> {
    let st = load(n)?;
    if st.is_empty() {
        let _ = writeln!(out, "{} is not quarantined.", n.hostname);
        return Ok(());
    }
    let loaded = n.run.ok(ctx, &Cmd::new("nft", &["list", "table", "inet", TABLE]).quiet()).is_ok();
    let _ = writeln!(out, "{} is quarantined (firewall rules {}):", n.hostname, if loaded { "loaded" } else { "NOT loaded" });
    for c in &st.cuts {
        let who = if c.hosts.contains(&1) { format!("{} (coordinator)", shown(&c.name)) } else { shown(&c.name) };
        let _ = writeln!(
            out,
            "  {who} since {}: blocks {}; {} WireGuard key(s)",
            c.since.0.format("%Y-%m-%d %H:%M UTC"),
            c.ips.join(", "),
            c.wg_keys.len()
        );
    }
    let _ = writeln!(out, "Sync with the coordinator is {}.", if st.coordinator_cut() { "paused" } else { "running" });
    Ok(())
}

// ---- the desktop side ----

/// A server the desktop reaches directly over the WiFi/router network.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Remote {
    pub name: String,
    pub addr: String,
    pub port: String,
    pub user: String,
    pub coordinator: bool,
}

/// The servers in the desktop's ~/.ssh/config.d/dryserver that do not go
/// through the coordinator: every "<name>.lan" entry, and the coordinator's
/// own entry.
pub fn remotes(conf: &str) -> Vec<Remote> {
    let mut out = Vec::new();
    let mut cur: Option<(String, Vec<(String, String)>)> = None;
    let mut finish = |b: Option<(String, Vec<(String, String)>)>| {
        let Some((host, kv)) = b else { return };
        let get = |k: &str| kv.iter().find(|(x, _)| x == k).map(|(_, v)| v.clone()).unwrap_or_default();
        let (addr, jump) = (get("hostname"), get("proxyjump"));
        if parse_ip4(&addr).is_none() {
            return;
        }
        let port = if get("port").is_empty() { "22".to_string() } else { get("port") };
        let r = |name: String, coordinator| Remote { name, addr: addr.clone(), port: port.clone(), user: get("user"), coordinator };
        if let Some(name) = host.strip_suffix(".lan") {
            if registry::valid_name(name) {
                out.push(r(name.to_string(), false));
            }
        } else if (jump.is_empty() || jump == "none") && registry::valid_name(&host) {
            out.push(r(host, true));
        }
    };
    for l in conf.lines() {
        let t = l.trim();
        let Some((k, v)) = t.split_once(char::is_whitespace) else { continue };
        let (k, v) = (k.to_ascii_lowercase(), v.trim().to_string());
        if k == "host" {
            finish(cur.take());
            cur = Some((v, Vec::new()));
        } else if let Some((_, kv)) = cur.as_mut() {
            kv.push((k, v));
        }
    }
    finish(cur.take());
    out
}

/// Which servers a desktop run reaches: for a cut of the coordinator every
/// other server; for named members every server except those.
pub fn targets(all: &[Remote], names: &[String]) -> Vec<Remote> {
    all.iter().filter(|r| if names.is_empty() { !r.coordinator } else { !names.contains(&r.name) }).cloned().collect()
}

/// The ssh command line for one server: straight to its LAN address, never
/// through the coordinator, with its pinned host key and no agent.
pub fn remote_args(r: &Remote, known_hosts: &str, action: &[String]) -> Vec<String> {
    let mut a: Vec<String> = [
        "-t",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "ProxyJump=none",
        "-o",
        "ForwardAgent=no",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    a.extend(["-o".into(), format!("UserKnownHostsFile={known_hosts}"), "-o".into(), format!("HostKeyAlias={}", r.name)]);
    a.extend(["-p".into(), r.port.clone()]);
    if !r.user.is_empty() {
        a.extend(["-l".into(), r.user.clone()]);
    }
    a.push(r.addr.clone());
    a.extend(["sudo".into(), SERVER_BIN.into(), "quarantine".into()]);
    a.extend(action.iter().cloned());
    a
}

/// "a,b" from -name, checked and without repeats.
pub fn parse_names(s: &str) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for n in s.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        if !registry::valid_name(n) {
            bail!("{n:?} is not a server name");
        }
        if !out.iter().any(|o| o == n) {
            out.push(n.to_string());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::runner::Runner;
    use crate::testutil::{TempDir, get, put};
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    /// What mesh::wg_config writes for a node (host 2) with the coordinator
    /// and node-c as peers.
    const WG0: &str = "# dryserver mesh, rewritten by \"dryserver sync\" from the coordinator's list.
[Interface]
Address = 10.66.0.2/24
ListenPort = 51820
PostUp = wg set %i private-key /etc/wireguard/wg0.key

# coord
[Peer]
PublicKey = COORDKEY=
AllowedIPs = 10.66.0.1/32
Endpoint = 192.168.1.50:51820
PersistentKeepalive = 25

# node-c
[Peer]
PublicKey = NODECKEY=
AllowedIPs = 10.66.0.3/32
Endpoint = 192.168.1.30:51820
PersistentKeepalive = 25
";

    fn cfg() -> Config {
        Config {
            coord_lan_ip: "192.168.1.50".into(),
            wg_subnet: "10.66.0.0/24".into(),
            switch_subnet: "172.16.66.0/24".into(),
            wg_transport: config::TRANSPORT_AUTO.into(),
            ..Config::default()
        }
    }

    fn t0() -> Time {
        Time::ymd_hms(2026, 11, 20, 12, 0, 0)
    }

    #[test]
    fn peers_parsed_from_generated_config() {
        let c = cfg();
        let me = crate::mesh::SelfInfo { host: 2, switch: false };
        let members = vec![
            Member { host: 1, name: "coord".into(), wg_key: "K1".into(), lan_ip: "192.168.1.50".into(), ..Member::default() },
            Member { host: 2, name: "node-b".into(), wg_key: "K2".into(), ..Member::default() },
            Member { host: 3, name: "node-c".into(), wg_key: "K3".into(), lan_ip: "192.168.1.30".into(), ..Member::default() },
        ];
        let conf = mesh::wg_config(&c, me, &members);
        let peers = parse_peers(&conf);
        assert_eq!(peers.len(), 2, "{peers:?}");
        assert_eq!((peers[0].name.as_str(), peers[0].key.as_str()), ("coord", "K1"));
        assert_eq!(peers[1].allowed, vec!["10.66.0.3/32".to_string()]);
        assert_eq!(peers[1].hosts(&c.wg_subnet), vec![3]);
        // Keys end in '=': split on the first one only.
        assert_eq!(parse_peers(WG0)[0].key, "COORDKEY=");
    }

    #[test]
    fn without_and_back() {
        let cut = without(WG0, &["COORDKEY=".into()]);
        assert!(!cut.contains("COORDKEY") && !cut.contains("# coord"), "{cut}");
        assert!(cut.contains("[Interface]") && cut.contains("# node-c\n[Peer]\nPublicKey = NODECKEY="), "{cut}");
        assert_eq!(without(WG0, &["nope".into()]), WG0, "no match must leave the file as it was");
        let saved: Vec<String> = parse_peers(WG0).into_iter().filter(|p| p.key == "COORDKEY=").map(|p| p.block).collect();
        let back = with_peers(&cut, &saved);
        assert_eq!(parse_peers(&back).len(), 2);
        assert_eq!(with_peers(&back, &saved), back, "putting back twice must not duplicate the peer");
        assert_eq!(with_peers(WG0, &saved), WG0);
    }

    #[test]
    fn odd_configs() {
        // No comments, no blank lines, a peer first, CRLF-free odd spacing.
        let conf = "[Peer]\npublickey=A=\nallowedips = 10.66.0.1/32, 10.66.0.9/32\n[Peer]\nPublicKey = B=\nAllowedIPs = 10.66.0.4/32\n";
        let p = parse_peers(conf);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].key, "A=");
        assert_eq!(p[0].hosts("10.66.0.0/24"), vec![1, 9]);
        assert_eq!(without(conf, &["A=".into()]), "[Peer]\nPublicKey = B=\nAllowedIPs = 10.66.0.4/32\n");
        assert!(parse_peers("").is_empty() && parse_peers("[Interface]\nAddress = 10.66.0.2/24\n").is_empty());
        // A wide AllowedIPs still counts as covering the coordinator.
        let wide = parse_peers("[Peer]\nPublicKey = W=\nAllowedIPs = 10.66.0.0/24\n");
        assert!(wide[0].covers("10.66.0.1".parse().unwrap()));
    }

    #[test]
    fn plan_coordinator() {
        let p = plan(&cfg(), 2, "node-b", &parse_peers(WG0), &[], &[], t0()).unwrap();
        assert_eq!(p.cuts.len(), 1);
        let c = &p.cuts[0];
        assert_eq!(c.name, "coord");
        assert_eq!(c.hosts, vec![1]);
        assert_eq!(c.wg_keys, vec!["COORDKEY=".to_string()]);
        assert_eq!(c.ips, vec!["10.66.0.1".to_string(), "172.16.66.1".into(), "192.168.1.50".into()]);
        assert!(c.peers[0].contains("# coord") && !c.peers[0].contains("node-c"));
        assert!(p.notes.is_empty(), "{:?}", p.notes);
    }

    #[test]
    fn plan_edge_cases() {
        let c = cfg();
        let peers = parse_peers(WG0);
        // On the coordinator itself there is nothing to cut by default.
        assert!(plan(&c, 1, "coord", &peers, &[], &[], t0()).unwrap_err().to_string().contains("is the coordinator"));
        // The coordinator's LAN address is the gateway: keep it reachable.
        let p = plan(&c, 2, "node-b", &peers, &[], &["192.168.1.50".parse().unwrap()], t0()).unwrap();
        assert!(!p.cuts[0].ips.contains(&"192.168.1.50".to_string()) && p.notes[0].contains("gateway"), "{p:?}");
        // Not joined yet: no peers, still blocks the addresses.
        let p = plan(&c, 0, "node-b", &[], &[], &[], t0()).unwrap();
        assert!(p.cuts[0].wg_keys.is_empty() && p.cuts[0].ips.contains(&"10.66.0.1".to_string()) && !p.notes.is_empty());
        // No switch subnet: no switch address.
        let lan_only = Config { switch_subnet: String::new(), ..cfg() };
        let p = plan(&lan_only, 2, "node-b", &peers, &[], &[], t0()).unwrap();
        assert_eq!(p.cuts[0].ips, vec!["10.66.0.1".to_string(), "192.168.1.50".into()]);
        // Two peers claim the coordinator's address (a hacked coordinator can
        // send that): both are cut.
        let two = format!("{WG0}\n# evil\n[Peer]\nPublicKey = EVIL=\nAllowedIPs = 10.66.0.1/32\n");
        let p = plan(&c, 2, "node-b", &parse_peers(&two), &[], &[], t0()).unwrap();
        assert_eq!(p.cuts[0].wg_keys, vec!["COORDKEY=".to_string(), "EVIL=".into()]);
    }

    #[test]
    fn plan_named() {
        let c = cfg();
        let peers = parse_peers(WG0);
        let p = plan(&c, 2, "node-b", &peers, &["node-c".into()], &[], t0()).unwrap();
        let cut = &p.cuts[0];
        assert_eq!((cut.name.as_str(), cut.hosts.clone()), ("node-c", vec![3]));
        assert_eq!(cut.ips, vec!["10.66.0.3".to_string(), "172.16.66.3".into()], "a worker's DHCP address must never be blocked");
        // Naming the coordinator also blocks its LAN address.
        let p = plan(&c, 2, "node-b", &peers, &["coord".into()], &[], t0()).unwrap();
        assert!(p.cuts[0].ips.contains(&"192.168.1.50".to_string()));
        for (names, want) in [
            (vec!["node-b".to_string()], "is this server"),
            (vec!["ghost".to_string()], "no mesh member named ghost"),
            (vec!["Bad Name".to_string()], "not a server name"),
        ] {
            let e = plan(&c, 2, "node-b", &peers, &names, &[], t0()).unwrap_err().to_string();
            assert!(e.contains(want), "{names:?}: {e}");
        }
        // The coordinator can cut a worker by name.
        let p = plan(&c, 1, "coord", &peers, &["node-c".into()], &[], t0()).unwrap();
        assert_eq!(p.cuts[0].hosts, vec![3]);
        // A peer claiming this server's own address is cut by key only.
        let own = "# node-c\n[Peer]\nPublicKey = X=\nAllowedIPs = 10.66.0.2/32\n";
        let p = plan(&c, 2, "node-b", &parse_peers(own), &["node-c".into()], &[], t0()).unwrap();
        assert!(p.cuts[0].hosts.is_empty() && p.cuts[0].ips.is_empty() && p.cuts[0].wg_keys == vec!["X=".to_string()]);
    }

    #[test]
    fn state_rules() {
        let mut st = State::default();
        let p = plan(&cfg(), 2, "node-b", &parse_peers(WG0), &[], &[], t0()).unwrap();
        st.add(p.cuts[0].clone());
        // A second cut of the same member merges, it does not duplicate.
        let again = plan(&cfg(), 2, "node-b", &[], &[], &[], t0()).unwrap();
        st.add(again.cuts[0].clone());
        assert_eq!(st.cuts.len(), 1);
        assert_eq!(st.cuts[0].peers.len(), 1, "the saved peer block must survive a re-run");
        assert!(st.coordinator_cut());
        assert!(st.blocks(&Member { host: 1, ..Member::default() }));
        assert!(st.blocks(&Member { host: 9, wg_key: "COORDKEY=".into(), ..Member::default() }), "same key under a new address");
        assert!(!st.blocks(&Member { host: 3, wg_key: "NODECKEY=".into(), ..Member::default() }));
        assert!(!st.blocks(&Member { host: 3, ..Member::default() }), "empty keys never match");
    }

    #[test]
    fn rules_text() {
        let mut st = State::default();
        st.add(Cut { name: "coord".into(), hosts: vec![1], ips: vec!["10.66.0.1".into(), "192.168.1.50".into()], ..Cut::default() });
        st.add(Cut { name: "x\n}; evil".into(), hosts: vec![7], ips: vec!["not-an-ip".into(), "10.66.0.7".into()], ..Cut::default() });
        let r = nft_rules(&st);
        assert!(r.contains("elements = { 10.66.0.1, 10.66.0.7, 192.168.1.50 }"), "{r}");
        assert!(r.contains("destroy table inet dryserver_quarantine") && r.contains("priority filter - 10"));
        assert!(!r.contains("evil") && !r.contains("not-an-ip"), "names and addresses from the coordinator must not reach the file:\n{r}");
        assert!(!nft_rules(&State::default()).contains("elements"), "an empty set has no elements line");
    }

    #[test]
    fn gateway_parse() {
        let out = "default via 192.168.1.1 dev wlan0 proto dhcp src 192.168.1.20 metric 600\ndefault dev wg9 scope link\n";
        assert_eq!(gateways(out), vec!["192.168.1.1".parse::<Ipv4Addr>().unwrap()]);
        assert!(gateways("").is_empty());
    }

    #[test]
    fn names_flag() {
        assert_eq!(parse_names(" node-b, node-c,node-b ,").unwrap(), vec!["node-b".to_string(), "node-c".into()]);
        assert!(parse_names("").unwrap().is_empty());
        assert!(parse_names("ok,../etc").is_err());
    }

    #[test]
    fn desktop_remotes() {
        let conf = mesh::desktop_ssh_config(
            "admin",
            "coord",
            "192.168.1.50",
            "2201",
            "~/.ssh/known_hosts.d/dryserver",
            &[
                mesh::Server {
                    name: "coord".into(),
                    mesh_ip: "10.66.0.1".into(),
                    lan_ip: "192.168.1.50".into(),
                    ..mesh::Server::default()
                },
                mesh::Server {
                    name: "node-b".into(),
                    mesh_ip: "10.66.0.2".into(),
                    lan_ip: "192.168.1.20".into(),
                    ..mesh::Server::default()
                },
                mesh::Server { name: "node-c".into(), mesh_ip: "10.66.0.3".into(), ..mesh::Server::default() },
            ],
        );
        let all = remotes(&conf);
        assert_eq!(
            all,
            vec![
                Remote { name: "coord".into(), addr: "192.168.1.50".into(), port: "2201".into(), user: "admin".into(), coordinator: true },
                Remote { name: "node-b".into(), addr: "192.168.1.20".into(), port: "22".into(), user: "admin".into(), coordinator: false },
            ],
            "{conf}"
        );
        assert_eq!(targets(&all, &[]).iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), vec!["node-b"]);
        assert_eq!(targets(&all, &["node-b".into()]).iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), vec!["coord"]);
        let a = remote_args(&all[1], "/home/me/.ssh/known_hosts.d/dryserver", &["-name".into(), "node-c".into()]).join(" ");
        for want in [
            "-t ",
            "ProxyJump=none",
            "ForwardAgent=no",
            "StrictHostKeyChecking=yes",
            "HostKeyAlias=node-b",
            "-p 22 -l admin 192.168.1.20 sudo /usr/local/bin/dryserver quarantine -name node-c",
        ] {
            assert!(a.contains(want), "missing {want:?}: {a}");
        }
        // Hand-edited or foreign entries are skipped, not trusted.
        assert!(remotes("Host evil.lan\n    HostName example.com\nHost x\n    HostName 10.0.0.1\n    ProxyJump coord\n").is_empty());
    }

    // ---- running against a fake server root ----

    /// Records commands; nft -c fails when told to.
    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<String>>,
        nft_check_fails: bool,
        gateway: String,
    }

    impl Runner for Fake {
        fn run(&self, _: &Ctx, c: &Cmd) -> (String, Result<()>) {
            let line = c.to_string();
            self.calls.lock().unwrap().push(line.clone());
            match c.name.as_str() {
                "nft" if self.nft_check_fails && c.args.first().map(String::as_str) == Some("-c") => (String::new(), Err("syntax".into())),
                "ip" => (format!("default via {} dev wlan0\n", self.gateway), Ok(())),
                "wg-quick" => ("[Interface]\nListenPort = 51820\n".into(), Ok(())),
                _ => (String::new(), Ok(())),
            }
        }
    }

    fn server(root: &Path, fake: Arc<Fake>) -> Node {
        put(root, node::WG_CONF, WG0);
        put(root, node::WG_KEY, "PRIV=\n");
        put(root, node::JOIN_STATE, r#"{"host":2}"#);
        put(root, "/etc/nftables.conf", format!("table inet dryserver {{}}\n{NFT_INCLUDE}\n"));
        Node {
            cfg: cfg(),
            hostname: "node-b".into(),
            root: root.to_path_buf(),
            run: fake,
            tmp_dir: Some(root.join("run")),
            verifier: Arc::new(crate::signed::fake::Key("admin")),
        }
    }

    #[test]
    fn cut_and_lift() {
        let dir = TempDir::new();
        let fake = Arc::new(Fake { gateway: "192.168.1.1".into(), ..Fake::default() });
        let n = server(dir.path(), fake.clone());
        std::fs::create_dir_all(dir.path().join("run")).unwrap();
        let ctx = Ctx::new();
        let mut out = Vec::new();
        cut(&ctx, &n, false, &[], &mut out).unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("coord (coordinator): blocks 10.66.0.1, 172.16.66.1, 192.168.1.50") && text.contains("node-c"), "{text}");

        let st = load(&n).unwrap();
        assert!(st.coordinator_cut());
        let wg = get(dir.path(), node::WG_CONF);
        assert!(!wg.contains("COORDKEY") && wg.contains("NODECKEY"), "{wg}");
        assert!(get(dir.path(), NFT_FILE).contains("10.66.0.1"));
        assert!(!dir.path().join("etc/dryserver/nft.d/quarantine.nft.check").exists(), "check file left behind");
        assert!(get(dir.path(), ISSUE_FILE).contains("QUARANTINE"));
        let calls = fake.calls.lock().unwrap().join("\n");
        assert!(calls.contains("nft -c -f") && calls.contains("nft -f") && calls.contains("wg syncconf wg0"), "{calls}");

        // Running it again changes nothing and keeps the saved peer.
        cut(&ctx, &n, false, &[], &mut Vec::new()).unwrap();
        assert_eq!(load(&n).unwrap(), st);

        let mut out = Vec::new();
        lift(&ctx, &n, false, &mut out).unwrap();
        assert!(load(&n).unwrap().is_empty() && !dir.path().join(STATE_FILE.trim_start_matches('/')).exists());
        assert!(get(dir.path(), node::WG_CONF).contains("COORDKEY="), "lift must put the coordinator's peer back");
        assert!(get(dir.path(), NFT_FILE).is_empty() && get(dir.path(), ISSUE_FILE).is_empty());
        let calls = fake.calls.lock().unwrap().join("\n");
        assert!(
            calls.contains("nft destroy table inet dryserver_quarantine") && calls.contains("systemctl start --no-block dryserver-sync")
        );
        assert!(String::from_utf8_lossy(&out).contains("paired with the new coordinator"));
        // Lifting when nothing is cut is fine.
        let mut out = Vec::new();
        lift(&ctx, &n, false, &mut out).unwrap();
        assert!(String::from_utf8_lossy(&out).contains("not quarantined"));
    }

    #[test]
    fn failed_check_never_installs_rules() {
        let dir = TempDir::new();
        let fake = Arc::new(Fake { nft_check_fails: true, ..Fake::default() });
        let n = server(dir.path(), fake.clone());
        let e = cut(&Ctx::new(), &n, false, &[], &mut Vec::new()).unwrap_err().to_string();
        assert!(e.contains("not complete") && e.contains("nft -c"), "{e}");
        assert!(!dir.path().join(NFT_FILE.trim_start_matches('/')).exists(), "a file that failed the check reached nft.d");
        // The cut is still saved and the peer still removed.
        assert!(load(&n).unwrap().coordinator_cut());
        assert!(!get(dir.path(), node::WG_CONF).contains("COORDKEY"));
    }

    #[test]
    fn damaged_state() {
        let dir = TempDir::new();
        let n = server(dir.path(), Arc::new(Fake::default()));
        put(dir.path(), STATE_FILE, "{not json");
        assert!(load(&n).is_err() && blocks_join(&n), "a damaged file must keep join away");
        // A new cut starts over and keeps the damaged file aside.
        let mut out = Vec::new();
        cut(&Ctx::new(), &n, false, &[], &mut out).unwrap();
        assert!(String::from_utf8_lossy(&out).contains("damaged"));
        assert!(load(&n).unwrap().coordinator_cut());
        assert!(get(dir.path(), &format!("{STATE_FILE}.damaged")).contains("not json"));
    }

    #[test]
    fn old_firewall_file_warns() {
        let dir = TempDir::new();
        let n = server(dir.path(), Arc::new(Fake::default()));
        put(dir.path(), "/etc/nftables.conf", "table inet dryserver {}\n");
        let mut out = Vec::new();
        cut(&Ctx::new(), &n, false, &[], &mut out).unwrap();
        assert!(String::from_utf8_lossy(&out).contains("older dryserver"));
    }

    #[test]
    fn status_text() {
        let dir = TempDir::new();
        let n = server(dir.path(), Arc::new(Fake::default()));
        let mut out = Vec::new();
        status(&Ctx::new(), &n, &mut out).unwrap();
        assert!(String::from_utf8_lossy(&out).contains("not quarantined"));
        cut(&Ctx::new(), &n, false, &["node-c".into()], &mut Vec::new()).unwrap();
        let mut out = Vec::new();
        status(&Ctx::new(), &n, &mut out).unwrap();
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("node-c since") && s.contains("Sync with the coordinator is running"), "{s}");
    }
}
