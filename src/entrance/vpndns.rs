//! The VPN as an entrance: apps with `ENTRANCE=vpn` are reached by the
//! admin's devices only, through the VPN's own Traefik on its gateway
//! (vpn.rs). What the desktop does for them: their names in Cloudflare
//! DNS, each an A record to the gateway's VPN address, DNS only (never
//! proxied: Cloudflare answers the name and sees none of the traffic).
//!
//! - Only records that carry the VPN's mark are ever changed or deleted.
//!   A name that moves from the tunnel to the VPN takes the tunnel's
//!   record of dryserver's with it (the other way round, cfsync takes the
//!   VPN's). Anything else under the name is someone else's: a conflict,
//!   left alone, unless the admin confirmed a takeover.
//! - The address comes from the cluster: the port of the VPN's Traefik.
//!   Without it (the VPN is not set up), nothing is added.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::json;

use super::cfapi::{Api, Curl, NEED_DNS};
use super::cfsync::{self, Record, Seen};
use super::cloudflare::{API_TOKEN_FILE, MakeHttp};
use super::{Conflict, Entrance, Health, Report, State, Traffic, Want};
use crate::apps::{Cluster, Overview};
use crate::bail;
use crate::ctx::Ctx;
use crate::err::Result;
use crate::runner::ExecRunner;

/// The comment on every DNS record the VPN made.
pub const MARK: &str = "managed by dryserver vpn";

/// One change to Cloudflare DNS.
#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    Create { zone: String, name: String },
    Repoint { zone: String, id: String, name: String },
    Delete { zone: String, id: String, name: String, why: String },
}

impl Step {
    pub fn line(&self, ip: Ipv4Addr) -> String {
        match self {
            Step::Create { name, .. } => format!("add {name} -> {ip} (DNS only)"),
            Step::Repoint { name, .. } => format!("point {name} at {ip} (DNS only)"),
            Step::Delete { name, why, .. } => format!("delete the record of {name} ({why})"),
        }
    }
}

/// What a sync would do.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Plan {
    pub steps: Vec<Step>,
    pub conflicts: Vec<Conflict>,
    pub unrouted: Vec<String>,
    pub notes: Vec<String>,
}

/// Whether the VPN made this record.
pub fn ours(r: &Record) -> bool {
    r.kind == "A" && r.comment == MARK
}

/// Whether the tunnel's side of dryserver made it: marked, a CNAME to a
/// Cloudflare tunnel.
fn tunnels(r: &Record) -> bool {
    r.kind == "CNAME" && r.comment == cfsync::MARK && r.content.ends_with(".cfargotunnel.com")
}

fn holder(r: &Record) -> String {
    format!("{} record {}{}", r.kind, r.content, if r.proxied { ", proxied" } else { "" })
}

/// The changes that make DNS have want's names at ip and no other record
/// of the VPN's. Pure: from what Cloudflare has (seen).
pub fn plan(seen: &Seen, want: &Want, ip: Ipv4Addr) -> Plan {
    let mut p = Plan::default();
    let content = ip.to_string();
    let mut fixes = Vec::new();
    let hosts: Vec<&str> = want.names.iter().map(|n| n.host.as_str()).collect();
    for n in &want.names {
        let Some(zone) = seen.zone_of(&n.host) else {
            p.unrouted.push(n.host.clone());
            continue;
        };
        if !zone.active() {
            p.notes.push(format!(
                "{} is in {}, which Cloudflare does not serve yet (its nameservers): it resolves once it does",
                n.host, zone.name
            ));
        }
        let at: Vec<&Record> = seen
            .records
            .iter()
            .filter(|r| r.zone == zone.id && r.name == n.host && matches!(r.kind.as_str(), "A" | "AAAA" | "CNAME"))
            .collect();
        let mine: Vec<&Record> = at.iter().copied().filter(|r| ours(r)).collect();
        // The tunnel's record of dryserver's: the name moved to the VPN.
        let tunnel: Vec<&Record> = at.iter().copied().filter(|r| tunnels(r)).collect();
        let theirs: Vec<&Record> = at.iter().copied().filter(|r| !ours(r) && !tunnels(r)).collect();
        if !theirs.is_empty() {
            if want.takeover.contains(&n.host) {
                for r in &theirs {
                    fixes.push(Step::Delete {
                        zone: r.zone.clone(),
                        id: r.id.clone(),
                        name: r.name.clone(),
                        why: format!("{}, taken over", holder(r)),
                    });
                }
            } else {
                let holder = theirs.iter().map(|r| holder(r)).collect::<Vec<_>>().join(" and ");
                p.conflicts.push(Conflict { host: n.host.clone(), app: n.app.clone(), holder });
                continue;
            }
        }
        for r in &tunnel {
            fixes.push(Step::Delete {
                zone: r.zone.clone(),
                id: r.id.clone(),
                name: r.name.clone(),
                why: "the tunnel's; the app is the VPN's now".into(),
            });
        }
        let good = |r: &Record| r.content == content && !r.proxied;
        let keep = mine.iter().find(|r| good(r)).or(mine.first());
        match keep {
            None => fixes.push(Step::Create { zone: zone.id.clone(), name: n.host.clone() }),
            Some(r) if !good(r) => fixes.push(Step::Repoint { zone: r.zone.clone(), id: r.id.clone(), name: r.name.clone() }),
            Some(_) => {}
        }
        for r in mine.iter().filter(|r| Some(r.id.as_str()) != keep.map(|k| k.id.as_str())) {
            fixes.push(Step::Delete {
                zone: r.zone.clone(),
                id: r.id.clone(),
                name: r.name.clone(),
                why: "a second record of the VPN's".into(),
            });
        }
    }
    for r in seen.records.iter().filter(|r| ours(r)) {
        if !hosts.contains(&r.name.as_str()) && !want.disputed.contains(&r.name) {
            p.steps.push(Step::Delete {
                zone: r.zone.clone(),
                id: r.id.clone(),
                name: r.name.clone(),
                why: "no app of the VPN uses it".into(),
            });
        }
    }
    fixes.extend(std::mem::take(&mut p.steps));
    p.steps = fixes;
    p
}

/// The record the VPN makes for name.
pub fn record(name: &str, ip: Ipv4Addr) -> serde_json::Value {
    json!({"type": "A", "name": name, "content": ip.to_string(), "proxied": false, "ttl": 300, "comment": MARK})
}

/// The address the cluster's VPN Traefik listens on (its port 443's);
/// None without one.
pub fn cluster_addr(ctx: &Ctx, c: &dyn Cluster) -> Result<Option<Ipv4Addr>> {
    let out = c.kubectl(ctx, &["-n", crate::vpn::NAMESPACE, "get", "deployment", "traefik", "-o", "json", "--ignore-not-found"], "")?;
    if out.trim().is_empty() {
        return Ok(None);
    }
    let d: serde_json::Value = serde_json::from_str(&out).map_err(|_| crate::errf!("the cluster's answer about the VPN is not one"))?;
    let ports = d["spec"]["template"]["spec"]["containers"][0]["ports"].as_array().cloned().unwrap_or_default();
    Ok(ports.iter().filter(|p| p["hostPort"] == 443).find_map(|p| p["hostIP"].as_str().and_then(|ip| ip.parse::<Ipv4Addr>().ok())))
}

/// The VPN's entrance on this desktop.
pub struct Vpn {
    pub api_token_file: PathBuf,
    /// This desktop's copy of the list it signed: where the gateway's
    /// address comes from (never from the cluster, which could name any).
    pub signed_copy: PathBuf,
    pub http: MakeHttp,
}

impl Vpn {
    pub fn new(secrets: &Path) -> Vpn {
        Vpn {
            api_token_file: secrets.join(API_TOKEN_FILE),
            signed_copy: secrets.join(crate::admin::SIGNED_COPY),
            http: Arc::new(|token| Box::new(Curl { token, run: Arc::new(ExecRunner::silent()) })),
        }
    }

    /// The gateway's VPN address, as the list this desktop signed has it.
    fn signed_addr(&self) -> Option<Ipv4Addr> {
        let env: crate::signed::Envelope = serde_json::from_slice(&std::fs::read(&self.signed_copy).ok()?).ok()?;
        let list: crate::signed::List = serde_json::from_str(&env.doc).ok()?;
        list.vpn.as_ref().and_then(crate::vpn::Plan::gateway_addr)
    }

    fn api_token(&self) -> Result<Option<String>> {
        super::cloudflare::Cloudflare { token_file: PathBuf::new(), api_token_file: self.api_token_file.clone(), http: self.http.clone() }
            .api_token()
    }
}

impl Entrance for Vpn {
    fn id(&self) -> &'static str {
        super::VPN
    }
    fn title(&self) -> &'static str {
        "VPN (your devices)"
    }
    fn carries(&self) -> &'static [Traffic] {
        &[Traffic::Web]
    }
    /// An app may pick it before the VPN is set up; until then its names
    /// are not in DNS, and the sync says so.
    fn ready(&self) -> bool {
        true
    }
    fn automatic(&self) -> bool {
        self.api_token_file.exists()
    }
    fn state(&self, _: &Ctx, seen: &Overview) -> State {
        let users = super::users(super::VPN, &seen.apps);
        let mut s = if users.is_empty() {
            State::not_set_up("no app comes in through it")
        } else {
            State { health: Health::Up, summary: format!("{} app(s): {}", users.len(), users.join(", ")), notes: Vec::new() }
        };
        s.notes.push("Its gateway and devices: dryserver vpn. Set up with dryserver vpn on SERVER --endpoint ADDRESS".into());
        s
    }
    fn open_question(&self, _: &Overview) -> Result<String> {
        bail!("the VPN is set up with dryserver vpn on SERVER --endpoint ADDRESS (it signs the member list)")
    }
    fn open(&self, _: &Ctx, _: &dyn Cluster) -> Result<String> {
        bail!("the VPN is set up with dryserver vpn on SERVER --endpoint ADDRESS")
    }
    fn sync(&self, ctx: &Ctx, c: &dyn Cluster, seen: &Overview, want: &Want, dry: bool) -> Result<Report> {
        if let Some(a) = seen.apps.iter().find(|a| a.newer) {
            bail!(
                "{} was set up by a newer dryserver; update dryserver on this computer first (git pull && make install). Nothing was changed in DNS",
                a.name
            );
        }
        let mut r = Report::default();
        let Some(ip) = self.signed_addr() else {
            if !want.names.is_empty() {
                r.notes.push(format!(
                    "the VPN is not set up yet (dryserver vpn on SERVER --endpoint ADDRESS): {} reach(es) no device until it is",
                    want.names.iter().map(|n| n.host.as_str()).collect::<Vec<_>>().join(", ")
                ));
            }
            return Ok(r);
        };
        // The cluster runs what the coordinator applied from the signed
        // list; another address there is said, and not followed.
        if !want.names.is_empty() {
            match cluster_addr(ctx, c)? {
                Some(a) if a != ip => r.notes.push(format!(
                    "the cluster's VPN ingress listens on {a}, not on {ip} as your signed list says: the coordinator has not followed \
                     the list (dryserver approve), or something changed it"
                )),
                None => {
                    r.notes.push("the VPN's ingress does not run in the cluster yet (the coordinator starts it within a minute)".into())
                }
                Some(_) => {}
            }
        }
        let Some(token) = self.api_token()? else {
            for n in &want.names {
                r.notes.push(format!("In Cloudflare DNS add an A record {} -> {ip}, DNS only (grey cloud)", n.host));
            }
            return Ok(r);
        };
        let http = (self.http)(token);
        let api = Api { http: http.as_ref(), ctx };
        let (_, zones) = cfsync::zones(&api)?;
        let found = Seen { records: cfsync::records(&api, &zones)?, zones, ..Seen::default() };
        let p = plan(&found, want, ip);
        r.conflicts = p.conflicts;
        r.unrouted = p.unrouted;
        r.notes = [r.notes, p.notes].concat();
        for s in &p.steps {
            r.changes.push(s.line(ip));
        }
        if dry {
            return Ok(r);
        }
        // Fewer changes than shown is fine: the tunnel's sync, which runs
        // first, took a record of a name that moved over already.
        if let Some(confirmed) = &want.confirmed
            && !r.changes.iter().all(|c| confirmed.contains(c))
        {
            bail!("Cloudflare DNS changed since the preview; nothing was changed. Look again");
        }
        for s in &p.steps {
            match s {
                Step::Create { zone, name } => {
                    let _: serde_json::Value = api.send("POST", &format!("/zones/{zone}/dns_records"), &record(name, ip), NEED_DNS)?;
                }
                Step::Repoint { zone, id, name } => {
                    let _: serde_json::Value = api.send("PUT", &format!("/zones/{zone}/dns_records/{id}"), &record(name, ip), NEED_DNS)?;
                }
                Step::Delete { zone, id, .. } => {
                    let _: serde_json::Value = api.delete(&format!("/zones/{zone}/dns_records/{id}"), NEED_DNS)?;
                }
            }
        }
        Ok(r)
    }
    fn close(&self, _: &Ctx, _: &dyn Cluster) -> Result<()> {
        bail!("the VPN is taken down with dryserver vpn off; its apps' names go with ENTRANCE changes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entrance::Name;
    use crate::entrance::cfsync::{MARK as TUNNEL_MARK, Tunnel, Zone};

    const TUNNEL: &str = "11111111-2222-3333-4444-555555555555";

    fn seen(records: Vec<Record>) -> Seen {
        Seen {
            zones: vec![Zone { id: "z1".into(), name: "example.com".into(), status: "active".into() }],
            tunnels: vec![Tunnel { id: TUNNEL.into(), deleted: false, created: "2026".into() }],
            records,
            ..Seen::default()
        }
    }

    fn rec(id: &str, name: &str, kind: &str, content: &str, comment: &str) -> Record {
        Record {
            zone: "z1".into(),
            id: id.into(),
            name: name.into(),
            kind: kind.into(),
            content: content.into(),
            proxied: kind == "CNAME",
            comment: comment.into(),
        }
    }

    fn want(hosts: &[&str]) -> Want {
        Want { names: hosts.iter().map(|h| Name { host: h.to_string(), app: "matrix".into() }).collect(), ..Want::default() }
    }

    const IP: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 1);

    #[test]
    fn names_point_at_the_gateway_dns_only() {
        let p = plan(&seen(vec![]), &want(&["matrix.example.com", "chat.other.org"]), IP);
        assert_eq!(p.steps, vec![Step::Create { zone: "z1".into(), name: "matrix.example.com".into() }]);
        assert_eq!(p.unrouted, vec!["chat.other.org".to_string()]);
        assert_eq!(p.steps[0].line(IP), "add matrix.example.com -> 10.99.0.1 (DNS only)");
        let r = record("matrix.example.com", IP);
        assert_eq!((r["proxied"].as_bool(), r["comment"].as_str(), r["type"].as_str()), (Some(false), Some(MARK), Some("A")));
        // Right already: nothing to do. Wrong address or proxied: fixed.
        let ok = seen(vec![rec("r1", "matrix.example.com", "A", "10.99.0.1", MARK)]);
        assert!(plan(&ok, &want(&["matrix.example.com"]), IP).steps.is_empty());
        let old = seen(vec![rec("r1", "matrix.example.com", "A", "10.98.0.1", MARK)]);
        assert_eq!(
            plan(&old, &want(&["matrix.example.com"]), IP).steps,
            vec![Step::Repoint { zone: "z1".into(), id: "r1".into(), name: "matrix.example.com".into() }]
        );
        let mut proxied = rec("r1", "matrix.example.com", "A", "10.99.0.1", MARK);
        proxied.proxied = true;
        assert!(matches!(plan(&seen(vec![proxied]), &want(&["matrix.example.com"]), IP).steps[..], [Step::Repoint { .. }]));
    }

    #[test]
    fn only_the_vpns_records_and_the_tunnels_of_a_moved_app_change() {
        // Someone else's record: a conflict, left alone.
        let theirs = seen(vec![rec("r9", "matrix.example.com", "A", "203.0.113.7", "")]);
        let p = plan(&theirs, &want(&["matrix.example.com"]), IP);
        assert!(p.steps.is_empty() && p.conflicts.len() == 1 && p.conflicts[0].holder.contains("203.0.113.7"), "{p:?}");
        // Unless taken over.
        let mut w = want(&["matrix.example.com"]);
        w.takeover = vec!["matrix.example.com".into()];
        let p = plan(&theirs, &w, IP);
        assert!(matches!(&p.steps[..], [Step::Delete { id, .. }, Step::Create { .. }] if id == "r9"), "{p:?}");
        // A CNAME with the mark that is no tunnel's: someone else's.
        let odd = seen(vec![rec("x1", "matrix.example.com", "CNAME", "elsewhere.example.net", TUNNEL_MARK)]);
        assert_eq!(plan(&odd, &want(&["matrix.example.com"]), IP).conflicts.len(), 1);
        // The app moved from the tunnel: its CNAME of dryserver's goes first.
        let moved = seen(vec![rec("t1", "matrix.example.com", "CNAME", &format!("{TUNNEL}.cfargotunnel.com"), TUNNEL_MARK)]);
        let p = plan(&moved, &want(&["matrix.example.com"]), IP);
        assert!(matches!(&p.steps[..], [Step::Delete { id, .. }, Step::Create { .. }] if id == "t1"), "{p:?}");
        // The VPN's records of names no app has any more go; the tunnel's,
        // a disputed name's and others' stay.
        let left = seen(vec![
            rec("v1", "old.example.com", "A", "10.99.0.1", MARK),
            rec("v2", "fight.example.com", "A", "10.99.0.1", MARK),
            rec("t1", "shop.example.com", "CNAME", &format!("{TUNNEL}.cfargotunnel.com"), TUNNEL_MARK),
            rec("x1", "mail.example.com", "A", "203.0.113.7", ""),
        ]);
        let mut w = want(&[]);
        w.disputed = vec!["fight.example.com".into()];
        let p = plan(&left, &w, IP);
        assert_eq!(
            p.steps,
            vec![Step::Delete {
                zone: "z1".into(),
                id: "v1".into(),
                name: "old.example.com".into(),
                why: "no app of the VPN uses it".into()
            }]
        );
        // A second record of ours goes.
        let two =
            seen(vec![rec("v1", "matrix.example.com", "A", "10.99.0.1", MARK), rec("v2", "matrix.example.com", "A", "10.99.0.1", MARK)]);
        assert!(matches!(&plan(&two, &want(&["matrix.example.com"]), IP).steps[..], [Step::Delete { id, .. }] if id == "v2"));
    }

    #[test]
    fn a_name_moving_to_the_tunnel_takes_the_vpns_record_away() {
        let s = seen(vec![rec("v1", "matrix.example.com", "A", "10.99.0.1", MARK)]);
        let p = cfsync::plan(&s, &want(&["matrix.example.com"]), true);
        let names: Vec<String> = p
            .steps
            .iter()
            .filter_map(|st| match st {
                cfsync::Step::Delete { id, why, .. } => Some(format!("delete {id}: {why}")),
                cfsync::Step::Create { name, .. } => Some(format!("create {name}")),
                _ => None,
            })
            .collect();
        assert_eq!(
            names,
            vec!["delete v1: the VPN's; the app comes in through the tunnel now".to_string(), "create matrix.example.com".to_string()],
            "{p:?}"
        );
        assert!(p.conflicts.is_empty());
        // The tunnel never deletes a VPN record of a name it does not want.
        let p = cfsync::plan(&s, &want(&[]), true);
        assert!(!p.steps.iter().any(|st| matches!(st, cfsync::Step::Delete { id, .. } if id == "v1")), "{p:?}");
    }

    #[test]
    fn the_address_the_cluster_listens_on() {
        let c = crate::apps::tests::Fake::default();
        c.answers.lock().unwrap().push(("-n vpn get deployment traefik".into(), String::new()));
        assert_eq!(cluster_addr(&Ctx::new(), &c).unwrap(), None);
        let c = crate::apps::tests::Fake::default();
        let d = json!({"spec": {"template": {"spec": {"containers": [{"ports": [{"hostPort": 80, "hostIP": "10.99.0.9"}, {"hostPort": 443, "hostIP": "10.99.0.1"}]}]}}}});
        c.answers.lock().unwrap().push(("-n vpn get deployment traefik".into(), d.to_string()));
        assert_eq!(cluster_addr(&Ctx::new(), &c).unwrap(), Some(IP));
    }
}
