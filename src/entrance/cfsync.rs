//! Cloudflare set up from the desktop: the tunnel, its routes and the DNS
//! names, made to match what the apps want.
//!
//! A sync looks at what Cloudflare has (look), works out what to change
//! (plan: a pure function) and makes those changes in order (apply).
//! Running it again finds nothing to change; a run cut off half way is
//! finished by the next one, because the plan starts from what is there.
//!
//! - The tunnel is named "dryserver", configured in Cloudflare
//!   (config_src cloudflare). Deleted in the dashboard, it is made again.
//! - Its configuration routes each Cloudflare host name to the ingress,
//!   sorted, then answers 404 for anything else.
//! - Each host name gets a proxied CNAME to <tunnel-id>.cfargotunnel.com,
//!   marked in its comment. Only records that carry the mark and point at
//!   a dryserver tunnel of this account are ever changed or deleted. A
//!   record of the name that points elsewhere is someone else's: it is
//!   reported as a conflict and left alone, unless the admin confirmed a
//!   takeover of that name.
//! - Only host names inside a zone the token can see are routed.

use std::path::Path;

use serde::Deserialize;
use serde_json::json;

use super::cfapi::{self, Api, Http, NEED_DNS, NEED_TUNNEL, NEED_ZONE_READ};
use super::cloudflare::{self, TARGET};
use super::{Conflict, Want};
use crate::apps::Cluster;
use crate::ctx::Ctx;
use crate::err::{Error, Result};
use crate::{bail, errf, fsx};

pub const TUNNEL_NAME: &str = "dryserver";
/// The comment on every DNS record dryserver made.
pub const MARK: &str = "managed by dryserver";
/// Zones one sync looks at, at most.
const MAX_ZONES: usize = 50;

/// A zone the token can see.
#[derive(Debug, Clone, PartialEq)]
pub struct Zone {
    pub id: String,
    pub name: String,
}

/// A tunnel named dryserver in the account, live or deleted.
#[derive(Debug, Clone, PartialEq)]
pub struct Tunnel {
    pub id: String,
    pub deleted: bool,
    pub created: String,
}

/// An A, AAAA or CNAME record in one of the zones.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub zone: String,
    pub id: String,
    pub name: String,
    pub kind: String,
    pub content: String,
    pub proxied: bool,
    pub comment: String,
}

/// What Cloudflare (and this desktop, and the cluster) have now.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Seen {
    pub account: String,
    pub zones: Vec<Zone>,
    pub tunnels: Vec<Tunnel>,
    /// The ingress rules of the live tunnel: (host name, service), the
    /// catch-all with an empty host. None without a live tunnel.
    pub ingress: Option<Vec<(String, String)>>,
    pub records: Vec<Record>,
    /// The live tunnel's token.
    pub run_token: Option<String>,
    /// What secrets/cloudflare_tunnel_token holds.
    pub saved_token: Option<String>,
    /// The mark of the token the cluster's cloudflared runs with; None
    /// when the cluster runs no tunnel.
    pub cluster_mark: Option<String>,
}

impl Seen {
    /// The tunnel in use: the oldest live one of that name.
    pub fn live(&self) -> Option<&Tunnel> {
        self.tunnels.iter().filter(|t| !t.deleted).min_by(|a, b| a.created.cmp(&b.created))
    }

    /// The zone a host name is in: the longest zone name it ends with.
    pub fn zone_of(&self, host: &str) -> Option<&Zone> {
        self.zones.iter().filter(|z| host == z.name || host.ends_with(&format!(".{}", z.name))).max_by_key(|z| z.name.len())
    }

    /// Whether dryserver made this record: the mark, a CNAME, and a
    /// dryserver tunnel of this account as its target.
    pub fn ours(&self, r: &Record) -> bool {
        r.kind == "CNAME" && r.comment == MARK && target_id(&r.content).is_some_and(|id| self.tunnels.iter().any(|t| t.id == id))
    }
}

/// The tunnel a CNAME points at, if it points at one.
pub fn target_id(content: &str) -> Option<String> {
    let c = content.trim_end_matches('.').to_ascii_lowercase();
    c.strip_suffix(".cfargotunnel.com").filter(|id| cfapi::valid_uuid(id)).map(str::to_string)
}

/// What a CNAME to the tunnel says.
pub fn target(tunnel: &str) -> String {
    format!("{tunnel}.cfargotunnel.com")
}

/// One change to make.
#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    CreateTunnel,
    /// Route these host names (sorted) through the tunnel, 404 for the rest.
    PutConfig(Vec<String>),
    /// Save the tunnel's token in secrets/.
    SaveToken,
    /// Run cloudflared in the cluster with the tunnel's token.
    Connect,
    Delete {
        zone: String,
        id: String,
        name: String,
        why: String,
    },
    Create {
        zone: String,
        name: String,
    },
    /// Point a record of ours at the tunnel, proxied.
    Repoint {
        zone: String,
        id: String,
        name: String,
    },
}

impl Step {
    pub fn describe(&self) -> String {
        match self {
            Step::CreateTunnel => format!("create the tunnel {TUNNEL_NAME} in Cloudflare"),
            Step::PutConfig(hosts) if hosts.is_empty() => "route no name through the tunnel (every request gets 404)".into(),
            Step::PutConfig(hosts) => format!("route {} through the tunnel", hosts.join(", ")),
            Step::SaveToken => format!("save the tunnel's token in secrets/{}", cloudflare::TOKEN_FILE),
            Step::Connect => "start the tunnel in the cluster with its token".into(),
            Step::Delete { name, why, .. } => format!("delete the DNS record of {name} ({why})"),
            Step::Create { name, .. } => format!("add {name} to DNS, pointing at the tunnel"),
            Step::Repoint { name, .. } => format!("point {name} at the tunnel"),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Plan {
    pub steps: Vec<Step>,
    pub conflicts: Vec<Conflict>,
    pub notes: Vec<String>,
}

fn holder(r: &Record) -> String {
    let what = if r.comment == MARK { " (marked by dryserver, but not for a tunnel of this account)" } else { "" };
    format!("{} record {}{what}", r.kind, cfapi::clean(&r.content))
}

/// What to change so Cloudflare serves exactly want. want.open: start the
/// tunnel in the cluster when it does not run there (an explicit set up);
/// without it a tunnel the admin closed stays closed.
pub fn plan(seen: &Seen, want: &Want, open: bool) -> Plan {
    let mut p = Plan::default();
    let live = seen.live().map(|t| t.id.clone());
    if live.is_none() {
        p.steps.push(Step::CreateTunnel);
    }
    if seen.tunnels.iter().filter(|t| !t.deleted).count() > 1 {
        p.notes.push(format!("Cloudflare has more than one tunnel named {TUNNEL_NAME}; the oldest is used"));
    }
    // The names to route: in a zone of this account, claimed once.
    let mut routed: Vec<(&str, &str, &Zone)> = Vec::new();
    for n in &want.names {
        if want.disputed.contains(&n.host) {
            continue;
        }
        match seen.zone_of(&n.host) {
            Some(z) => routed.push((&n.host, &n.app, z)),
            None => p.notes.push(format!("{} ({}) is not in a zone this API token can see; not routed", n.host, n.app)),
        }
    }
    routed.sort_by(|a, b| a.0.cmp(b.0));
    routed.dedup_by(|a, b| a.0 == b.0);
    let hosts: Vec<String> = routed.iter().map(|r| r.0.to_string()).collect();
    let mut rules: Vec<(String, String)> = hosts.iter().map(|h| (h.clone(), TARGET.to_string())).collect();
    rules.push((String::new(), "http_status:404".into()));
    if live.is_none() || seen.ingress.as_ref() != Some(&rules) {
        p.steps.push(Step::PutConfig(hosts.clone()));
    }
    // The token: on this desktop, and in the cluster. A sync after an app
    // changed (not open) replaces only tokens of a dryserver tunnel: one
    // the admin made in the dashboard keeps working until the admin says
    // otherwise on the Outside screen.
    let token = if live.is_some() { seen.run_token.clone() } else { None };
    let dryserver = |t: &str| cloudflare::tunnel_of(t).is_some_and(|id| seen.tunnels.iter().any(|x| x.id == id));
    if token.is_none() || seen.saved_token != token {
        if open || seen.saved_token.as_deref().is_none_or(dryserver) {
            p.steps.push(Step::SaveToken);
        } else {
            p.notes
                .push(format!("secrets/{} holds the token of another tunnel; s on the Outside screen replaces it", cloudflare::TOKEN_FILE));
        }
    }
    let mark = token.as_deref().map(cloudflare::token_mark);
    match &seen.cluster_mark {
        Some(m) if mark.as_ref() == Some(m) => {}
        Some(m) => {
            let runs_ours = seen.saved_token.as_deref().is_some_and(|s| cloudflare::token_mark(s) == *m && dryserver(s));
            if open || runs_ours {
                p.steps.push(Step::Connect);
            } else {
                p.notes.push(format!("the cluster runs another tunnel; s on the Outside screen switches it to the tunnel {TUNNEL_NAME}"));
            }
        }
        None if open => p.steps.push(Step::Connect),
        None => p.notes.push("the tunnel is closed in the cluster; s on the Outside screen opens it".into()),
    }
    // DNS, name by name.
    let mut takeovers = Vec::new();
    let mut fixes = Vec::new();
    for (host, app, zone) in &routed {
        let at: Vec<&Record> = seen
            .records
            .iter()
            .filter(|r| r.zone == zone.id && r.name == *host && matches!(r.kind.as_str(), "A" | "AAAA" | "CNAME"))
            .collect();
        let (mine, theirs): (Vec<&Record>, Vec<&Record>) = at.into_iter().partition(|r| seen.ours(r));
        if !theirs.is_empty() {
            if want.takeover.iter().any(|t| t == host) {
                for r in &theirs {
                    takeovers.push(Step::Delete { zone: r.zone.clone(), id: r.id.clone(), name: r.name.clone(), why: "taken over".into() });
                }
            } else if mine.is_empty()
                && theirs.len() == 1
                && theirs[0].kind == "CNAME"
                && target_id(&theirs[0].content).is_some_and(|id| live.as_deref() == Some(&id))
            {
                p.notes.push(format!("{host} already points at the tunnel (a record made in the dashboard); left as it is"));
                continue;
            } else {
                p.conflicts.push(Conflict { host: host.to_string(), app: app.to_string(), holder: holder(theirs[0]) });
                continue;
            }
        }
        let good = |r: &Record| r.proxied && live.is_some() && target_id(&r.content) == live;
        let keep = mine.iter().find(|r| good(r)).or(mine.first());
        match keep {
            None => fixes.push(Step::Create { zone: zone.id.clone(), name: host.to_string() }),
            Some(r) if !good(r) => fixes.push(Step::Repoint { zone: r.zone.clone(), id: r.id.clone(), name: r.name.clone() }),
            Some(_) => {}
        }
        for r in mine.iter().filter(|r| Some(r.id.as_str()) != keep.map(|k| k.id.as_str())) {
            fixes.push(Step::Delete {
                zone: r.zone.clone(),
                id: r.id.clone(),
                name: r.name.clone(),
                why: "a second record of ours".into(),
            });
        }
    }
    // Ours, for names no app routes through Cloudflare any more.
    let mut stale = Vec::new();
    for r in seen.records.iter().filter(|r| seen.ours(r)) {
        if !hosts.contains(&r.name) && !want.disputed.contains(&r.name) {
            stale.push(Step::Delete { zone: r.zone.clone(), id: r.id.clone(), name: r.name.clone(), why: "no app uses it".into() });
        }
    }
    p.steps.extend(takeovers);
    p.steps.extend(fixes);
    p.steps.extend(stale);
    p
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ApiAccount {
    id: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ApiZone {
    id: String,
    name: String,
    account: ApiAccount,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ApiTunnel {
    id: String,
    name: String,
    deleted_at: Option<String>,
    created_at: String,
    config_src: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ApiRecord {
    id: String,
    name: String,
    #[serde(rename = "type")]
    kind: String,
    content: String,
    proxied: bool,
    comment: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ApiRule {
    hostname: Option<String>,
    service: String,
    path: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ApiIngress {
    ingress: Vec<ApiRule>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ApiConfig {
    config: Option<ApiIngress>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ApiVerify {
    status: String,
}

/// Checks the token first, so a revoked one is named as such.
fn verify(api: &Api) -> Result<()> {
    // A refusal is about the token; an outage or no connection is not.
    let v: ApiVerify = api.get("/user/tokens/verify", "to be valid").map_err(|e| {
        if e.is(crate::err::Kind::Rejected) || e.to_string().starts_with("Cloudflare said no") {
            errf!("the API token does not work: {e}. Make a new one (see the README: Reaching apps from outside) and save it again")
        } else {
            e
        }
    })?;
    if v.status != "active" {
        bail!("the API token is {}; make a new one and save it again", cfapi::clean(&v.status));
    }
    Ok(())
}

/// What Cloudflare has now. saved_token and cluster_mark come from this
/// desktop and the cluster.
pub fn look(api: &Api, saved_token: Option<String>, cluster_mark: Option<String>) -> Result<Seen> {
    verify(api)?;
    let zones: Vec<ApiZone> = api.list("/zones?per_page=50", NEED_ZONE_READ)?;
    let mut accounts: Vec<&str> = zones.iter().map(|z| z.account.id.as_str()).collect();
    accounts.sort();
    accounts.dedup();
    let account = match accounts.as_slice() {
        [] => bail!("the API token sees no zone. Give it {NEED_ZONE_READ} and {NEED_DNS} for your domain"),
        [a] if cfapi::valid_id(a) => a.to_string(),
        [_] => bail!("Cloudflare sent an account id that is not one"),
        _ => bail!("the API token sees zones of more than one Cloudflare account; limit it to the zones of one account"),
    };
    if zones.len() > MAX_ZONES {
        bail!("the API token sees more than {MAX_ZONES} zones; limit it to the zones you use with dryserver");
    }
    let mut seen = Seen { account: account.clone(), saved_token, cluster_mark, ..Seen::default() };
    for z in &zones {
        match cfapi::host(&z.name) {
            Some(name) if cfapi::valid_id(&z.id) => seen.zones.push(Zone { id: z.id.clone(), name }),
            _ => bail!("Cloudflare sent a zone that is not one"),
        }
    }
    let tunnels: Vec<ApiTunnel> = api.list(&format!("/accounts/{account}/cfd_tunnel?name={TUNNEL_NAME}&per_page=100"), NEED_TUNNEL)?;
    for t in tunnels.iter().filter(|t| t.name == TUNNEL_NAME) {
        if !cfapi::valid_uuid(&t.id) {
            bail!("Cloudflare sent a tunnel id that is not one");
        }
        let deleted = t.deleted_at.as_deref().is_some_and(|d| !d.is_empty());
        if !deleted && t.config_src == "local" {
            bail!(
                "the tunnel {TUNNEL_NAME} in Cloudflare is configured by cloudflared's own file, not in Cloudflare; \
                 delete or rename it in the dashboard, then sync again"
            );
        }
        seen.tunnels.push(Tunnel { id: t.id.to_ascii_lowercase(), deleted, created: cfapi::clean(&t.created_at) });
    }
    if let Some(live) = seen.live().map(|t| t.id.clone()) {
        let path = format!("/accounts/{account}/cfd_tunnel/{live}");
        let c: ApiConfig = api.get(&format!("{path}/configurations"), NEED_TUNNEL)?;
        seen.ingress = Some(
            c.config
                .unwrap_or_default()
                .ingress
                .iter()
                .map(|r| {
                    let host = r.hostname.as_deref().and_then(cfapi::host).unwrap_or_default();
                    // A rule with a path is not one of ours: it never compares equal.
                    let service = if r.path.as_deref().is_some_and(|p| !p.is_empty()) { "(with a path)".into() } else { r.service.clone() };
                    (host, service)
                })
                .collect(),
        );
        let token: String = api.get(&format!("{path}/token"), NEED_TUNNEL)?;
        cloudflare::valid_tunnel_token(&token).map_err(|_| errf!("Cloudflare sent a tunnel token that is not one"))?;
        seen.run_token = Some(token);
    }
    for z in seen.zones.clone() {
        let records: Vec<ApiRecord> = api.list(&format!("/zones/{}/dns_records?per_page=1000", z.id), NEED_DNS)?;
        for r in records.into_iter().filter(|r| matches!(r.kind.as_str(), "A" | "AAAA" | "CNAME")) {
            let (Some(name), true) = (cfapi::host(&r.name), cfapi::valid_id(&r.id)) else { continue };
            seen.records.push(Record {
                zone: z.id.clone(),
                id: r.id,
                name,
                kind: r.kind,
                content: r.content.chars().take(300).collect(),
                proxied: r.proxied,
                comment: r.comment.unwrap_or_default(),
            });
        }
    }
    Ok(seen)
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Created {
    id: String,
}

/// Writes the tunnel's token to secrets/, for this user only, in one
/// step: a reader never sees half a token.
pub fn save_token(path: &Path, token: &str) -> Result<()> {
    cloudflare::valid_tunnel_token(token)?;
    let tmp = path.with_extension("tmp");
    fsx::mkdir_all(fsx::dir(path), 0o700)?;
    let _ = std::fs::remove_file(&tmp);
    fsx::write_file(&tmp, format!("{token}\n"), 0o600)?;
    fsx::chmod(&tmp, 0o600)?;
    fsx::rename(&tmp, path)
}

/// Makes the changes in order. Returns what was done; an error says how
/// far it got. The next run starts from what is there, so it finishes
/// the rest.
pub fn apply(api: &Api, ctx: &Ctx, c: &dyn Cluster, seen: &Seen, steps: &[Step], token_file: &Path) -> (Vec<String>, Option<Error>) {
    let mut done = Vec::new();
    let mut live = seen.live().map(|t| t.id.clone());
    let mut token = seen.run_token.clone();
    let account = &seen.account;
    for step in steps {
        let res: Result<()> = (|| {
            let tunnel = || live.clone().ok_or_else(|| errf!("no tunnel"));
            match step {
                Step::CreateTunnel => {
                    let t: Created = api.send(
                        "POST",
                        &format!("/accounts/{account}/cfd_tunnel"),
                        &json!({"name": TUNNEL_NAME, "config_src": "cloudflare"}),
                        NEED_TUNNEL,
                    )?;
                    if !cfapi::valid_uuid(&t.id) {
                        bail!("Cloudflare sent a tunnel id that is not one");
                    }
                    let id = t.id.to_ascii_lowercase();
                    let tk: String = api.get(&format!("/accounts/{account}/cfd_tunnel/{id}/token"), NEED_TUNNEL)?;
                    cloudflare::valid_tunnel_token(&tk).map_err(|_| errf!("Cloudflare sent a tunnel token that is not one"))?;
                    live = Some(id);
                    token = Some(tk);
                }
                Step::PutConfig(hosts) => {
                    let mut ingress: Vec<serde_json::Value> = hosts.iter().map(|h| json!({"hostname": h, "service": TARGET})).collect();
                    ingress.push(json!({"service": "http_status:404"}));
                    let _: serde_json::Value = api.send(
                        "PUT",
                        &format!("/accounts/{account}/cfd_tunnel/{}/configurations", tunnel()?),
                        &json!({"config": {"ingress": ingress}}),
                        NEED_TUNNEL,
                    )?;
                }
                Step::SaveToken => save_token(token_file, token.as_deref().ok_or_else(|| errf!("no tunnel token"))?)?,
                Step::Connect => cloudflare::connect_tunnel(ctx, c, token.as_deref().ok_or_else(|| errf!("no tunnel token"))?)?,
                Step::Delete { zone, id, .. } => {
                    let _: serde_json::Value = api.delete(&format!("/zones/{zone}/dns_records/{id}"), NEED_DNS)?;
                }
                Step::Create { zone, name } => {
                    let _: serde_json::Value =
                        api.send("POST", &format!("/zones/{zone}/dns_records"), &record(name, &tunnel()?), NEED_DNS)?;
                }
                Step::Repoint { zone, id, name } => {
                    let _: serde_json::Value =
                        api.send("PUT", &format!("/zones/{zone}/dns_records/{id}"), &record(name, &tunnel()?), NEED_DNS)?;
                }
            }
            Ok(())
        })();
        match res {
            Ok(()) => done.push(step.describe()),
            Err(e) => {
                let e = e.wrap(format!("{} of {} changes made, then \"{}\" failed", done.len(), steps.len(), step.describe()));
                return (done, Some(e));
            }
        }
    }
    (done, None)
}

/// A record of ours for name: a proxied CNAME to the tunnel, marked.
fn record(name: &str, tunnel: &str) -> serde_json::Value {
    json!({"type": "CNAME", "name": name, "content": target(tunnel), "proxied": true, "ttl": 1, "comment": MARK})
}

/// Checks an API client and a token file are usable, then looks, plans
/// and (unless dry) applies.
pub struct Sync<'a> {
    pub http: &'a dyn Http,
    pub token_file: &'a Path,
    pub cluster_mark: Option<String>,
}

impl Sync<'_> {
    pub fn run(&self, ctx: &Ctx, c: &dyn Cluster, want: &Want, open: bool, dry: bool) -> Result<super::Report> {
        let api = Api { http: self.http, ctx };
        let saved = std::fs::read_to_string(self.token_file).ok().and_then(|t| cloudflare::tunnel_token(&t).ok());
        let seen = look(&api, saved, self.cluster_mark.clone())?;
        let p = plan(&seen, want, open);
        let mut r = super::Report { conflicts: p.conflicts, notes: p.notes, changes: Vec::new() };
        if dry {
            r.changes = p.steps.iter().map(Step::describe).collect();
            return Ok(r);
        }
        let (done, err) = apply(&api, ctx, c, &seen, &p.steps, self.token_file);
        r.changes = done;
        match err {
            Some(e) => Err(e),
            None => Ok(r),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::apps::tests::Fake as FakeCluster;
    use crate::entrance::{Name, Report};
    use crate::testutil::TempDir;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};

    pub const ACCOUNT: &str = "0123456789abcdef0123456789abcdef";
    pub const ZONE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// What the fake Cloudflare holds.
    #[derive(Clone, Default)]
    pub struct Cf {
        /// id, name, account
        pub zones: Vec<(String, String, String)>,
        /// id, name, deleted, created, config_src
        pub tunnels: Vec<(String, String, bool, String, String)>,
        pub configs: BTreeMap<String, Vec<(String, String)>>,
        pub records: Vec<Record>,
        /// What token verify says; "" answers 401.
        pub verify: String,
        n: u32,
    }

    /// A fake Cloudflare: the API's paths over state in memory.
    #[derive(Default)]
    pub struct FakeCf {
        pub cf: Mutex<Cf>,
        pub calls: Mutex<Vec<String>>,
        /// Changes asked for so far (POST, PUT, DELETE).
        pub changes: AtomicUsize,
        /// This change fails with 500, before it is made...
        pub fail_at: Mutex<Option<usize>>,
        /// ...or after it was made (an answer lost on the way).
        pub fail_after: AtomicBool,
        /// Paths with one of these in them answer 403.
        pub forbid: Mutex<Vec<String>>,
        /// Everything answers 503.
        pub down: AtomicBool,
    }

    pub fn fresh() -> FakeCf {
        let f = FakeCf::default();
        {
            let mut c = f.cf.lock().unwrap();
            c.zones.push((ZONE.into(), "example.com".into(), ACCOUNT.into()));
            c.verify = "active".into();
        }
        f
    }

    fn ok(result: serde_json::Value) -> (u16, String) {
        (200, json!({"success": true, "errors": [], "result": result, "result_info": {"total_pages": 1}}).to_string())
    }

    fn no(status: u16, code: i64, msg: &str) -> (u16, String) {
        (status, json!({"success": false, "errors": [{"code": code, "message": msg}]}).to_string())
    }

    /// A tunnel token as Cloudflare makes them: base64 of account, tunnel
    /// and secret.
    pub fn token_of(id: &str) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(json!({"a": ACCOUNT, "t": id, "s": "c2VjcmV0LXNlY3JldA=="}).to_string())
    }

    fn rec_from(zone: &str, id: &str, b: &serde_json::Value) -> Record {
        Record {
            zone: zone.into(),
            id: id.into(),
            name: b["name"].as_str().unwrap_or("").into(),
            kind: b["type"].as_str().unwrap_or("").into(),
            content: b["content"].as_str().unwrap_or("").into(),
            proxied: b["proxied"].as_bool().unwrap_or(false),
            comment: b["comment"].as_str().unwrap_or("").into(),
        }
    }

    impl Http for FakeCf {
        fn call(&self, _: &Ctx, method: &str, path: &str, body: Option<&str>) -> Result<(u16, String)> {
            self.calls.lock().unwrap().push(format!("{method} {path}"));
            if self.down.load(SeqCst) {
                return Ok((503, "<html>down</html>".into()));
            }
            let (p, q) = path.split_once('?').unwrap_or((path, ""));
            if self.forbid.lock().unwrap().iter().any(|f| p.contains(f.as_str())) {
                return Ok(no(403, 10000, "Authentication error"));
            }
            let mut fail_now = false;
            if method != "GET" {
                let n = self.changes.fetch_add(1, SeqCst) + 1;
                if *self.fail_at.lock().unwrap() == Some(n) {
                    if !self.fail_after.load(SeqCst) {
                        return Ok(no(500, 1000, "internal error"));
                    }
                    fail_now = true;
                }
            }
            let body: serde_json::Value = body.map(|b| serde_json::from_str(b).unwrap()).unwrap_or_default();
            let query = |k: &str| q.split('&').find_map(|kv| kv.strip_prefix(&format!("{k}="))).map(str::to_string);
            let parts: Vec<&str> = p.trim_start_matches('/').split('/').collect();
            let mut cf = self.cf.lock().unwrap();
            let answer = match (method, parts.as_slice()) {
                ("GET", ["user", "tokens", "verify"]) if cf.verify.is_empty() => no(401, 1000, "Invalid API Token"),
                ("GET", ["user", "tokens", "verify"]) => ok(json!({"id": "t", "status": cf.verify})),
                ("GET", ["zones"]) => ok(json!(
                    cf.zones.iter().map(|(id, name, a)| json!({"id": id, "name": name, "account": {"id": a}})).collect::<Vec<_>>()
                )),
                ("GET", ["accounts", _, "cfd_tunnel"]) => {
                    let name = query("name");
                    let list: Vec<_> = cf
                        .tunnels
                        .iter()
                        .filter(|t| name.as_deref().is_none_or(|n| n == t.1))
                        .map(|t| {
                            let deleted = if t.2 { json!("2026-11-01T00:00:00Z") } else { json!(null) };
                            json!({"id": t.0, "name": t.1, "deleted_at": deleted, "created_at": t.3, "config_src": t.4})
                        })
                        .collect();
                    ok(json!(list))
                }
                ("POST", ["accounts", _, "cfd_tunnel"]) => {
                    cf.n += 1;
                    let id = format!("{:08x}-0000-4000-8000-{:012x}", cf.n, cf.n);
                    let created = format!("2026-11-21T00:00:{:02}Z", cf.n);
                    cf.tunnels.push((
                        id.clone(),
                        body["name"].as_str().unwrap().into(),
                        false,
                        created,
                        body["config_src"].as_str().unwrap().into(),
                    ));
                    ok(json!({"id": id, "name": body["name"]}))
                }
                ("GET", ["accounts", _, "cfd_tunnel", id, "configurations"]) => {
                    let rules = cf.configs.get(*id).map(|rules| {
                        let ingress: Vec<_> = rules
                            .iter()
                            .map(|(h, s)| if h.is_empty() { json!({"service": s}) } else { json!({"hostname": h, "service": s}) })
                            .collect();
                        json!({"ingress": ingress, "warp-routing": {"enabled": false}})
                    });
                    ok(json!({"tunnel_id": id, "config": rules}))
                }
                ("PUT", ["accounts", _, "cfd_tunnel", id, "configurations"]) => {
                    let rules = body["config"]["ingress"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|r| (r["hostname"].as_str().unwrap_or("").to_string(), r["service"].as_str().unwrap().to_string()))
                        .collect();
                    cf.configs.insert(id.to_string(), rules);
                    ok(json!({}))
                }
                ("GET", ["accounts", _, "cfd_tunnel", id, "token"]) => ok(json!(token_of(id))),
                ("GET", ["zones", z, "dns_records"]) => {
                    let list: Vec<_> = cf
                        .records
                        .iter()
                        .filter(|r| r.zone == *z)
                        .map(|r| {
                            let comment = if r.comment.is_empty() { json!(null) } else { json!(r.comment) };
                            json!({"id": r.id, "name": r.name, "type": r.kind, "content": r.content, "proxied": r.proxied, "comment": comment})
                        })
                        .collect();
                    ok(json!(list))
                }
                ("POST", ["zones", z, "dns_records"]) => {
                    let name = body["name"].as_str().unwrap_or("").to_string();
                    // Like Cloudflare: a CNAME shares its name with nothing.
                    if cf.records.iter().any(|r| r.zone == *z && r.name == name && matches!(r.kind.as_str(), "A" | "AAAA" | "CNAME")) {
                        no(400, 81053, "An A, AAAA, or CNAME record with that host already exists.")
                    } else {
                        cf.n += 1;
                        let id = format!("{:032x}", cf.n);
                        cf.records.push(rec_from(z, &id, &body));
                        ok(json!({"id": id}))
                    }
                }
                ("PUT", ["zones", z, "dns_records", id]) => {
                    cf.records.retain(|r| r.id != *id);
                    cf.records.push(rec_from(z, id, &body));
                    ok(json!({"id": id}))
                }
                ("DELETE", ["zones", _, "dns_records", id]) => {
                    cf.records.retain(|r| r.id != *id);
                    ok(json!({"id": id}))
                }
                _ => no(404, 7003, "no route"),
            };
            Ok(if fail_now { no(500, 1000, "internal error") } else { answer })
        }
    }

    /// One fake Cloudflare for every client the entrance makes.
    impl Http for std::sync::Arc<FakeCf> {
        fn call(&self, ctx: &Ctx, method: &str, path: &str, body: Option<&str>) -> Result<(u16, String)> {
            self.as_ref().call(ctx, method, path, body)
        }
    }

    /// The Cloudflare entrance in dir, talking to cf, with an API token
    /// saved when token is.
    pub fn entrance(dir: &Path, cf: &std::sync::Arc<FakeCf>, token: bool) -> cloudflare::Cloudflare {
        use std::os::unix::fs::PermissionsExt;
        let mut e = cloudflare::Cloudflare::new(dir);
        if token {
            std::fs::write(&e.api_token_file, format!("{}\n", cfapi::tests::API_TOKEN)).unwrap();
            std::fs::set_permissions(&e.api_token_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let cf = cf.clone();
        e.http = std::sync::Arc::new(move |t| {
            assert_eq!(t, cfapi::tests::API_TOKEN);
            Box::new(cf.clone())
        });
        e
    }

    pub fn want(hosts: &[&str]) -> Want {
        let names = hosts.iter().map(|h| Name { host: h.to_string(), app: h.split('.').next().unwrap().into() }).collect();
        Want { names, ..Want::default() }
    }

    /// The mark of the token the fake cluster was last given.
    pub fn mark_of(c: &FakeCluster) -> Option<String> {
        let calls = c.calls.lock().unwrap();
        let (_, manifest) = calls.iter().rev().find(|(a, _)| a == "apply -f -")?;
        let line = manifest.lines().find(|l| l.contains("dryserver/token-mark"))?;
        Some(line.split('"').nth(1)?.to_string())
    }

    struct World {
        cf: FakeCf,
        cluster: FakeCluster,
        dir: TempDir,
    }

    impl World {
        fn new() -> World {
            World { cf: fresh(), cluster: FakeCluster::default(), dir: TempDir::new() }
        }

        fn token_file(&self) -> std::path::PathBuf {
            self.dir.join(cloudflare::TOKEN_FILE)
        }

        /// A sync as the Outside screen runs it (the cluster runs what it
        /// was last given).
        fn sync(&self, want: &Want, dry: bool) -> Result<Report> {
            self.sync_with(want, true, mark_of(&self.cluster), dry)
        }

        fn sync_with(&self, want: &Want, open: bool, mark: Option<String>, dry: bool) -> Result<Report> {
            Sync { http: &self.cf, token_file: &self.token_file(), cluster_mark: mark }.run(&Ctx::new(), &self.cluster, want, open, dry)
        }

        fn live(&self) -> String {
            self.cf.cf.lock().unwrap().tunnels.iter().find(|t| !t.2).map(|t| t.0.clone()).unwrap()
        }

        fn records(&self) -> Vec<String> {
            let mut r: Vec<String> = self
                .cf
                .cf
                .lock()
                .unwrap()
                .records
                .iter()
                .map(|r| format!("{} {} {} {} {}", r.name, r.kind, r.content, if r.proxied { "proxied" } else { "dns-only" }, r.comment))
                .collect();
            r.sort();
            r
        }

        fn config(&self) -> Vec<(String, String)> {
            let live = self.live();
            self.cf.cf.lock().unwrap().configs.get(&live).cloned().unwrap_or_default()
        }

        fn add(&self, name: &str, kind: &str, content: &str, comment: &str) {
            let mut cf = self.cf.cf.lock().unwrap();
            cf.n += 1;
            let id = format!("{:032x}", 1000 + cf.n);
            cf.records.push(Record {
                zone: ZONE.into(),
                id,
                name: name.into(),
                kind: kind.into(),
                content: content.into(),
                proxied: true,
                comment: comment.into(),
            });
        }
    }

    fn ours(name: &str, tunnel: &str) -> String {
        format!("{name} CNAME {tunnel}.cfargotunnel.com proxied {MARK}")
    }

    #[test]
    fn from_nothing_to_serving() {
        let w = World::new();
        let names = want(&["shop.example.com", "blog.example.com"]);
        // A dry run says what it would do and does none of it.
        let plan = w.sync(&names, true).unwrap();
        assert_eq!(
            plan.changes,
            vec![
                "create the tunnel dryserver in Cloudflare",
                "route blog.example.com, shop.example.com through the tunnel",
                "save the tunnel's token in secrets/cloudflare_tunnel_token",
                "start the tunnel in the cluster with its token",
                "add blog.example.com to DNS, pointing at the tunnel",
                "add shop.example.com to DNS, pointing at the tunnel",
            ]
        );
        assert_eq!(w.cf.changes.load(SeqCst), 0);
        assert!(w.cluster.calls.lock().unwrap().is_empty() && !w.token_file().exists());

        let done = w.sync(&names, false).unwrap();
        assert_eq!(done.changes.len(), 6, "{done:?}");
        let id = w.live();
        let cf = w.cf.cf.lock().unwrap().clone();
        assert_eq!(cf.tunnels.len(), 1);
        assert_eq!((cf.tunnels[0].1.as_str(), cf.tunnels[0].4.as_str()), ("dryserver", "cloudflare"));
        assert_eq!(
            w.config(),
            vec![
                ("blog.example.com".to_string(), TARGET.to_string()),
                ("shop.example.com".into(), TARGET.into()),
                (String::new(), "http_status:404".into())
            ]
        );
        assert_eq!(w.records(), vec![ours("blog.example.com", &id), ours("shop.example.com", &id)]);
        // The token: saved for this user only, and given to the cluster.
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::read_to_string(w.token_file()).unwrap().trim(), token_of(&id));
        assert_eq!(std::fs::metadata(w.token_file()).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(mark_of(&w.cluster), Some(cloudflare::token_mark(&token_of(&id))));
        assert!(w.cluster.calls.lock().unwrap().iter().all(|(a, _)| !a.contains(&token_of(&id))));

        // Again: nothing to change, nothing changed.
        let before = w.cf.changes.load(SeqCst);
        let again = w.sync(&names, false).unwrap();
        assert!(again.changes.is_empty() && again.conflicts.is_empty(), "{again:?}");
        assert_eq!(w.cf.changes.load(SeqCst), before);
        assert_eq!(w.cluster.calls.lock().unwrap().iter().filter(|(a, _)| a == "apply -f -").count(), 1);
    }

    #[test]
    fn a_run_cut_off_half_way_is_finished_by_the_next() {
        let names = want(&["blog.example.com", "shop.example.com"]);
        // The clean run makes 4 changes in Cloudflare: the tunnel, its
        // configuration, two records.
        for after in [false, true] {
            for k in 1..=4 {
                let w = World::new();
                *w.cf.fail_at.lock().unwrap() = Some(k);
                w.cf.fail_after.store(after, SeqCst);
                let e = w.sync(&names, false).unwrap_err().to_string();
                assert!(e.contains("changes made, then") && e.contains("internal error"), "{e}");
                *w.cf.fail_at.lock().unwrap() = None;
                w.sync(&names, false).unwrap_or_else(|e| panic!("change {k} (after: {after}): {e}"));
                let third = w.sync(&names, false).unwrap();
                assert!(third.changes.is_empty(), "change {k} (after: {after}): {third:?}");
                let id = w.live();
                assert_eq!(w.cf.cf.lock().unwrap().tunnels.len(), 1, "one tunnel, also when its answer was lost");
                assert_eq!(w.records(), vec![ours("blog.example.com", &id), ours("shop.example.com", &id)]);
                assert_eq!(w.config().len(), 3);
                assert_eq!(mark_of(&w.cluster), Some(cloudflare::token_mark(&token_of(&id))));
            }
        }
    }

    #[test]
    fn someone_elses_record_is_left_alone_until_taken_over() {
        let w = World::new();
        w.add("blog.example.com", "A", "203.0.113.7", "");
        w.add("blog.example.com", "AAAA", "2001:db8::7", "");
        let names = want(&["blog.example.com", "shop.example.com"]);
        let r = w.sync(&names, false).unwrap();
        assert_eq!(r.conflicts.len(), 1, "{r:?}");
        assert_eq!((r.conflicts[0].host.as_str(), r.conflicts[0].app.as_str()), ("blog.example.com", "blog"));
        assert!(r.conflicts[0].holder.starts_with("A record 203.0.113.7") || r.conflicts[0].holder.starts_with("AAAA record"), "{r:?}");
        let id = w.live();
        let recs = w.records();
        assert!(
            recs.contains(&"blog.example.com A 203.0.113.7 proxied ".to_string()) && recs.contains(&ours("shop.example.com", &id)),
            "{recs:?}"
        );
        assert_eq!(recs.len(), 3);
        // Running again does not touch it either.
        assert!(w.sync(&names, false).unwrap().changes.is_empty());
        // The admin confirms the takeover: theirs go first, then ours.
        let mut take = names.clone();
        take.takeover = vec!["blog.example.com".into()];
        let r = w.sync(&take, false).unwrap();
        assert!(r.conflicts.is_empty() && r.changes.len() == 3, "{r:?}");
        assert_eq!(w.records(), vec![ours("blog.example.com", &id), ours("shop.example.com", &id)]);
        assert!(w.sync(&names, false).unwrap().changes.is_empty());
    }

    #[test]
    fn records_that_look_like_ours() {
        let w = World::new();
        w.sync(&want(&[]), false).unwrap();
        let id = w.live();
        // Made in the dashboard for this very tunnel: it works, it stays.
        w.add("blog.example.com", "CNAME", &target(&id), "");
        // Marked, but for a tunnel that is not one of ours.
        w.add("shop.example.com", "CNAME", "11111111-2222-4333-8444-555555555555.cfargotunnel.com", MARK);
        let r = w.sync(&want(&["blog.example.com", "shop.example.com"]), false).unwrap();
        assert!(r.notes.iter().any(|n| n.contains("blog.example.com already points at the tunnel")), "{r:?}");
        assert_eq!(r.conflicts.len(), 1, "{r:?}");
        assert!(r.conflicts[0].host == "shop.example.com" && r.conflicts[0].holder.contains("not for a tunnel of this account"), "{r:?}");
        assert!(r.changes.iter().all(|c| !c.contains("DNS record")), "{r:?}");
        // With no app wanting them, neither is deleted: not ours.
        let r = w.sync(&want(&[]), false).unwrap();
        assert!(r.changes.iter().all(|c| !c.contains("delete")), "{r:?}");
        assert_eq!(w.records().len(), 2);
    }

    #[test]
    fn the_tunnel_deleted_in_the_dashboard() {
        let w = World::new();
        let names = want(&["blog.example.com"]);
        w.sync(&names, false).unwrap();
        let old = w.live();
        w.cf.cf.lock().unwrap().tunnels[0].2 = true;
        let r = w.sync(&names, false).unwrap();
        let new = w.live();
        assert_ne!(old, new);
        assert!(r.changes.contains(&"create the tunnel dryserver in Cloudflare".to_string()), "{r:?}");
        assert!(r.changes.contains(&"point blog.example.com at the tunnel".to_string()), "our record follows the new tunnel: {r:?}");
        assert!(r.changes.contains(&"start the tunnel in the cluster with its token".to_string()), "{r:?}");
        assert_eq!(w.records(), vec![ours("blog.example.com", &new)]);
        assert_eq!(std::fs::read_to_string(w.token_file()).unwrap().trim(), token_of(&new));
        assert!(w.sync(&names, false).unwrap().changes.is_empty());
    }

    #[test]
    fn names_no_app_uses_any_more_go() {
        let w = World::new();
        w.add("www.example.com", "A", "203.0.113.9", "");
        w.sync(&want(&["blog.example.com", "shop.example.com"]), false).unwrap();
        let id = w.live();
        let r = w.sync(&want(&["blog.example.com"]), false).unwrap();
        assert_eq!(
            r.changes,
            vec!["route blog.example.com through the tunnel", "delete the DNS record of shop.example.com (no app uses it)"]
        );
        // No app at all: only the 404 rule, and none of our records.
        let r = w.sync(&want(&[]), false).unwrap();
        assert_eq!(r.changes[0], "route no name through the tunnel (every request gets 404)");
        assert_eq!(w.config(), vec![(String::new(), "http_status:404".to_string())]);
        assert_eq!(w.records(), vec!["www.example.com A 203.0.113.9 proxied ".to_string()], "someone else's record stays");
        assert!(!w.records().iter().any(|r| r.contains(&id)));
        assert!(w.sync(&want(&[]), false).unwrap().changes.is_empty());
    }

    #[test]
    fn only_names_inside_a_zone() {
        let w = World::new();
        w.cf.cf.lock().unwrap().zones.push(("b".repeat(32), "sub.example.com".into(), ACCOUNT.into()));
        let r = w.sync(&want(&["blog.other.org", "a.sub.example.com", "example.com"]), false).unwrap();
        assert!(r.notes.iter().any(|n| n.contains("blog.other.org (blog) is not in a zone this API token can see")), "{r:?}");
        let cf = w.cf.cf.lock().unwrap().clone();
        let zone_of = |name: &str| cf.records.iter().find(|r| r.name == name).map(|r| r.zone.clone());
        assert_eq!(zone_of("a.sub.example.com"), Some("b".repeat(32)), "the longest zone");
        assert_eq!(zone_of("example.com"), Some(ZONE.into()), "the zone's own name");
        assert_eq!(zone_of("blog.other.org"), None);
        assert!(!w.config().iter().any(|(h, _)| h == "blog.other.org"));
    }

    #[test]
    fn a_disputed_name_is_left_as_it_is() {
        let w = World::new();
        w.sync(&want(&["blog.example.com"]), false).unwrap();
        let id = w.live();
        let disputed = Want { disputed: vec!["blog.example.com".into()], ..Want::default() };
        let r = w.sync(&disputed, false).unwrap();
        assert!(r.changes.iter().all(|c| !c.contains("DNS record")), "{r:?}");
        assert_eq!(w.records(), vec![ours("blog.example.com", &id)]);
    }

    #[test]
    fn the_tunnel_in_the_cluster() {
        let w = World::new();
        let names = want(&["blog.example.com"]);
        // After a deploy (not an explicit set up), a closed tunnel stays
        // closed; the rest is done.
        let r = w.sync_with(&names, false, None, false).unwrap();
        assert!(!r.changes.iter().any(|c| c.contains("start the tunnel")), "{r:?}");
        assert!(r.notes.iter().any(|n| n.contains("closed in the cluster")), "{r:?}");
        assert!(w.cluster.calls.lock().unwrap().is_empty());
        assert_eq!(w.records().len(), 1);
        // The cluster runs another tunnel (one made in the dashboard): a
        // sync after a deploy leaves it running; the admin switches it.
        let other = Some("0123456789abcdef".to_string());
        let r = w.sync_with(&names, false, other.clone(), false).unwrap();
        assert!(r.changes.is_empty() && r.notes.iter().any(|n| n.contains("the cluster runs another tunnel")), "{r:?}");
        let r = w.sync_with(&names, true, other, false).unwrap();
        assert_eq!(r.changes, vec!["start the tunnel in the cluster with its token"]);
        // The cluster runs an older dryserver tunnel (deleted in the
        // dashboard): that one is replaced without asking.
        w.cf.cf.lock().unwrap().tunnels[0].2 = true;
        let r = w.sync_with(&names, false, mark_of(&w.cluster), false).unwrap();
        assert!(
            r.changes.iter().any(|c| c.contains("start the tunnel")) && r.changes.iter().any(|c| c.contains("save the tunnel")),
            "{r:?}"
        );
        assert_eq!(mark_of(&w.cluster), Some(cloudflare::token_mark(&token_of(&w.live()))));
        // An explicit set up opens a closed one.
        let w = World::new();
        assert!(w.sync_with(&names, true, None, false).unwrap().changes.iter().any(|c| c.contains("start the tunnel")));
    }

    #[test]
    fn the_token_the_admin_saved_by_hand() {
        // The manual path: a tunnel made in the dashboard, its token saved
        // and running. Saving an API token and deploying must not take it
        // away; s on the Outside screen does, after showing it.
        let w = World::new();
        let manual = token_of("99999999-9999-4999-8999-999999999999");
        std::fs::write(w.token_file(), format!("{manual}\n")).unwrap();
        let mark = Some(cloudflare::token_mark(&manual));
        let r = w.sync_with(&want(&["blog.example.com"]), false, mark.clone(), false).unwrap();
        assert!(!r.changes.iter().any(|c| c.contains("save the tunnel") || c.contains("start the tunnel")), "{r:?}");
        assert!(r.notes.iter().any(|n| n.contains("holds the token of another tunnel")), "{r:?}");
        assert_eq!(std::fs::read_to_string(w.token_file()).unwrap().trim(), manual);
        assert!(w.cluster.calls.lock().unwrap().is_empty());
        let plan = w.sync_with(&want(&["blog.example.com"]), true, mark, true).unwrap();
        assert!(plan.changes.iter().any(|c| c.contains("save the tunnel")) && plan.changes.iter().any(|c| c.contains("start the tunnel")));
        assert_eq!(cloudflare::tunnel_of(&manual).as_deref(), Some("99999999-9999-4999-8999-999999999999"));
        assert_eq!(cloudflare::tunnel_of("not base64 at all"), None);
    }

    #[test]
    fn plan_details() {
        let id = "f70ff985-a4ef-4643-bbbc-4a0ed4fc8415".to_string();
        let rec = |rid: &str, content: &str, proxied: bool| Record {
            zone: ZONE.into(),
            id: rid.repeat(32 / rid.len()),
            name: "blog.example.com".into(),
            kind: "CNAME".into(),
            content: content.into(),
            proxied,
            comment: MARK.into(),
        };
        let token = token_of(&id);
        let seen = Seen {
            account: ACCOUNT.into(),
            zones: vec![Zone { id: ZONE.into(), name: "example.com".into() }],
            tunnels: vec![
                Tunnel { id: id.clone(), deleted: false, created: "2026-01-01".into() },
                Tunnel { id: "a0000000-0000-4000-8000-000000000000".into(), deleted: false, created: "2026-02-01".into() },
            ],
            ingress: Some(vec![("blog.example.com".into(), TARGET.into()), (String::new(), "http_status:404".into())]),
            // Two of ours: one not proxied, one right.
            records: vec![rec("1", &target(&id), false), rec("2", &format!("{}.", target(&id).to_uppercase()), true)],
            run_token: Some(token.clone()),
            saved_token: Some(token.clone()),
            cluster_mark: Some(cloudflare::token_mark(&token)),
        };
        let p = plan(&seen, &want(&["blog.example.com"]), true);
        assert_eq!(p.steps.len(), 1, "{p:?}");
        assert!(matches!(&p.steps[0], Step::Delete { id, why, .. } if id.starts_with('1') && why == "a second record of ours"), "{p:?}");
        assert!(p.notes.iter().any(|n| n.contains("more than one tunnel named dryserver")), "the oldest is used: {p:?}");
        // Only the one that is not proxied: it is pointed again.
        let one = Seen { records: vec![rec("1", &target(&id), false)], ..seen.clone() };
        assert!(matches!(&plan(&one, &want(&["blog.example.com"]), true).steps[..], [Step::Repoint { .. }]));
        // A rule with a path is not one of ours: the configuration is put again.
        let path = Seen {
            ingress: Some(vec![("blog.example.com".into(), "(with a path)".into()), (String::new(), "http_status:404".into())]),
            ..one
        };
        assert!(plan(&path, &want(&["blog.example.com"]), true).steps.iter().any(|s| matches!(s, Step::PutConfig(_))));
        assert_eq!(target_id("bad.cfargotunnel.com"), None);
        assert_eq!(target_id(&format!("{}.", target(&id).to_uppercase())), Some(id));
    }

    #[test]
    fn when_cloudflare_says_no() {
        let names = want(&["blog.example.com"]);
        let nothing_changed = |w: &World| {
            assert_eq!(w.cf.changes.load(SeqCst), 0);
            assert!(w.cluster.calls.lock().unwrap().is_empty(), "the running tunnel is not touched");
            assert!(!w.token_file().exists());
        };
        // A revoked token: said at once, nothing else asked.
        let w = World::new();
        w.cf.cf.lock().unwrap().verify.clear();
        let e = w.sync(&names, false).unwrap_err().to_string();
        assert!(e.contains("the API token does not work") && e.contains("Invalid API Token"), "{e}");
        assert_eq!(w.cf.calls.lock().unwrap().len(), 1);
        nothing_changed(&w);
        let w = World::new();
        w.cf.cf.lock().unwrap().verify = "expired".into();
        assert!(w.sync(&names, false).unwrap_err().to_string().contains("the API token is expired"));
        // A permission missing: named.
        for (path, need) in [("dns_records", NEED_DNS), ("cfd_tunnel", NEED_TUNNEL), ("zones", NEED_ZONE_READ)] {
            let w = World::new();
            w.cf.forbid.lock().unwrap().push(path.into());
            let e = w.sync(&names, false).unwrap_err().to_string();
            assert!(e.contains(need) && e.contains("Authentication error"), "{path}: {e}");
            nothing_changed(&w);
        }
        // Cloudflare is down: the tunnel keeps running.
        let w = World::new();
        w.cf.down.store(true, SeqCst);
        assert!(w.sync(&names, false).unwrap_err().to_string().contains("having trouble"));
        nothing_changed(&w);
        // What the token sees must be one account with zones.
        let w = World::new();
        w.cf.cf.lock().unwrap().zones.clear();
        assert!(w.sync(&names, false).unwrap_err().to_string().contains("sees no zone"));
        let w = World::new();
        w.cf.cf.lock().unwrap().zones.push(("c".repeat(32), "other.org".into(), "f".repeat(32)));
        assert!(w.sync(&names, false).unwrap_err().to_string().contains("more than one Cloudflare account"));
        // Ids that are not ids never reach a path.
        let w = World::new();
        w.cf.cf.lock().unwrap().zones[0].0 = "../../accounts".into();
        assert!(w.sync(&names, false).unwrap_err().to_string().contains("not one"));
        assert!(!w.cf.calls.lock().unwrap().iter().any(|c| c.contains("..")));
        // A tunnel of that name that cloudflared configures by file.
        let w = World::new();
        w.cf.cf.lock().unwrap().tunnels.push((
            "f70ff985-a4ef-4643-bbbc-4a0ed4fc8415".into(),
            "dryserver".into(),
            false,
            "x".into(),
            "local".into(),
        ));
        assert!(w.sync(&names, false).unwrap_err().to_string().contains("configured by cloudflared's own file"));
        nothing_changed(&w);
    }

    #[test]
    fn names_from_cloudflare_are_compared_in_lower_case() {
        let w = World::new();
        w.sync(&want(&["blog.example.com"]), false).unwrap();
        for r in w.cf.cf.lock().unwrap().records.iter_mut() {
            r.name = "Blog.Example.COM".into();
        }
        assert!(w.sync(&want(&["blog.example.com"]), false).unwrap().changes.is_empty());
    }
}
