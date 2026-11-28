//! Entrances: the ways from the internet into the cluster. Nothing on the
//! machines listens to the internet; an entrance carries what arrives for
//! the apps' public names to the ingress (and later raw TCP and UDP ports
//! to the apps that want them).
//!
//! - Cloudflare Tunnel: cloudflared pods dial out to Cloudflare, which
//!   sends what arrives for your host names through them.
//! - Your VPS (later): a rented server with a public address relays web
//!   and game ports over WireGuard.
//!
//! Every app with a public host name picks one. The choice is an
//! annotation on its Ingress (dryserver/entrance); an Ingress without one
//! belongs to Cloudflare, which is how every app was reached before there
//! was a choice. One host name belongs to one app and one entrance: a name
//! claimed twice goes to neither until the admin settles it.
//!
//! What each entrance must serve is computed from the apps the cluster
//! runs. Its sync makes it serve exactly that; running it again changes
//! nothing, and a run cut off half way is finished by the next one.

pub mod cfapi;
pub mod cfsync;
pub mod cloudflare;
pub mod vpndns;

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::apps::{App, Cluster, Overview, Running};
use crate::ctx::Ctx;
use crate::err::Result;
use crate::{bail, errf};

/// The annotation on an app's Ingress that names its entrance.
pub const ANNOTATION: &str = "dryserver/entrance";
pub const CLOUDFLARE: &str = "cloudflare";
pub const VPS: &str = "vps";
/// The VPN for the admin's devices (vpn.rs): only they reach these apps.
pub const VPN: &str = "vpn";
/// The entrance of an Ingress without the annotation.
pub const DEFAULT: &str = CLOUDFLARE;
/// Every entrance this dryserver knows, in the order the screens show them.
pub const IDS: [&str; 3] = [CLOUDFLARE, VPN, VPS];
/// Where the entrances' pods live, apart from the apps.
pub const NAMESPACE: &str = "edge";

pub fn valid_id(s: &str) -> Result<()> {
    if IDS.contains(&s) { Ok(()) } else { Err(errf!("an entrance: one of {}", IDS.join(", "))) }
}

/// What an entrance can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Traffic {
    /// HTTP and HTTPS by host name, to the ingress.
    Web,
    /// A raw TCP port, to one app (game servers).
    Tcp,
    /// A raw UDP port, to one app.
    Udp,
}

/// One public host name and the app behind it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Name {
    pub host: String,
    pub app: String,
}

/// A raw port an app wants reachable from outside. No entrance carries
/// these yet; the VPS will.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Port {
    pub traffic: Traffic,
    /// The port on the entrance's public address.
    pub public: u16,
    pub app: String,
    /// The app's own port.
    pub port: u16,
}

/// What an entrance must serve.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Want {
    /// Sorted by host name, each name once.
    pub names: Vec<Name>,
    pub ports: Vec<Port>,
    /// Names claimed twice (two apps, or two entrances): no entrance adds
    /// or removes anything for them until the admin settles it.
    pub disputed: Vec<String>,
    /// Names the admin confirmed this entrance may take over from
    /// whatever holds them now.
    pub takeover: Vec<String>,
    /// Start the entrance where it does not run: the admin asked for a
    /// set up. A sync after an app changed leaves a closed one closed.
    pub open: bool,
    /// The changes the admin was shown and said y to, in order. A sync
    /// that would now make other changes makes none.
    pub confirmed: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    NotSetUp,
    Down,
    /// Some of it works.
    Partly,
    Up,
}

/// How an entrance is doing, for the screens.
#[derive(Debug, Clone, PartialEq)]
pub struct State {
    pub health: Health,
    /// One line: "connected, 2 of 2 copies".
    pub summary: String,
    /// More to know, one line each.
    pub notes: Vec<String>,
}

impl State {
    pub fn not_set_up(summary: impl Into<String>) -> State {
        State { health: Health::NotSetUp, summary: summary.into(), notes: Vec::new() }
    }
}

/// A name the entrance cannot take: something else holds it there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    pub host: String,
    /// The app that wants it.
    pub app: String,
    /// What holds it now, in words ("A record 203.0.113.7").
    pub holder: String,
}

/// What a sync did, or with a dry run would do.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Report {
    /// One line per change.
    pub changes: Vec<String>,
    pub conflicts: Vec<Conflict>,
    pub notes: Vec<String>,
    /// Why a sync after an app changed left everything as it is on
    /// purpose (Cloudflare: the cluster runs a tunnel set up by hand).
    pub held: Option<String>,
    /// Names the entrance cannot route (Cloudflare: in no zone the API
    /// token can see).
    pub unrouted: Vec<String>,
}

impl Report {
    /// One line for the screen.
    pub fn summary(&self, dry: bool) -> String {
        if let Some(why) = &self.held {
            return format!("left as it is: {why}");
        }
        let n = self.changes.len();
        let mut s = match (n, dry) {
            (0, _) => "nothing to change".to_string(),
            (1, true) => "1 change to make".to_string(),
            (n, true) => format!("{n} changes to make"),
            (1, false) => "1 change made".to_string(),
            (n, false) => format!("{n} changes made"),
        };
        if !self.conflicts.is_empty() {
            s += &format!(", {} name(s) held by something else", self.conflicts.len());
        }
        s
    }
}

/// A way in from outside.
pub trait Entrance: Send + Sync {
    /// What apps put in their annotation: "cloudflare".
    fn id(&self) -> &'static str;
    /// For people: "Cloudflare Tunnel".
    fn title(&self) -> &'static str;
    fn carries(&self) -> &'static [Traffic];
    /// Set up enough that apps may choose it. Asks nobody.
    fn ready(&self) -> bool;
    /// Its sync changes things by itself (Cloudflare: with an API
    /// token), so it runs after an app that uses it changed.
    fn automatic(&self) -> bool;
    /// How it is doing, from what the cluster said (seen) and whatever
    /// else it needs to ask within ctx.
    fn state(&self, ctx: &Ctx, seen: &Overview) -> State;
    /// What opening it from what the admin saved on this desktop would
    /// do, as a question to confirm; an error says what is missing.
    fn open_question(&self, seen: &Overview) -> Result<String>;
    /// Opens it from what the admin saved (or gives it what changed
    /// there). Returns what to tell the admin.
    fn open(&self, ctx: &Ctx, c: &dyn Cluster) -> Result<String>;
    /// Makes it serve exactly want; with dry, only says what that would
    /// change. Names someone else holds are left alone and reported,
    /// unless want.takeover lists them.
    fn sync(&self, ctx: &Ctx, c: &dyn Cluster, seen: &Overview, want: &Want, dry: bool) -> Result<Report>;
    /// Takes it down: nothing from outside arrives through it any more.
    /// The apps keep running inside.
    fn close(&self, ctx: &Ctx, c: &dyn Cluster) -> Result<()>;
}

/// The entrances a desktop has, shared by the screens and their workers.
pub type Entrances = Arc<Vec<Box<dyn Entrance>>>;

/// What an entrance carries, for people: "web, TCP, UDP".
pub fn carries(e: &dyn Entrance) -> String {
    e.carries()
        .iter()
        .map(|t| match t {
            Traffic::Web => "web",
            Traffic::Tcp => "TCP",
            Traffic::Udp => "UDP",
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// What each entrance must serve, from the apps the cluster runs, and
/// what is wrong with their claims. A name claimed by two apps goes to
/// neither; an app that names an entrance this dryserver does not know
/// gets nothing.
pub fn wants(apps: &[Running]) -> (BTreeMap<&'static str, Want>, Vec<String>) {
    let mut by_host: BTreeMap<&str, Vec<&Running>> = BTreeMap::new();
    for a in apps {
        for h in &a.hosts {
            by_host.entry(&h.name).or_default().push(a);
        }
    }
    let mut out: BTreeMap<&'static str, Want> = IDS.iter().map(|id| (*id, Want::default())).collect();
    let mut problems = Vec::new();
    for (host, claims) in by_host {
        if claims.len() > 1 {
            let who: Vec<&str> = claims.iter().map(|a| a.name.as_str()).collect();
            problems.push(format!("{host} is the public name of {}: none of them gets it from outside", who.join(" and ")));
            for w in out.values_mut() {
                w.disputed.push(host.to_string());
            }
            continue;
        }
        let a = claims[0];
        match IDS.iter().find(|id| **id == a.entrance) {
            Some(id) => out.get_mut(id).into_iter().for_each(|w| w.names.push(Name { host: host.into(), app: a.name.clone() })),
            None => problems.push(format!("{} asks for an entrance this dryserver does not know; {host} is not served", a.name)),
        }
    }
    (out, problems)
}

/// The apps that come in through an entrance, by name.
pub fn users(id: &str, apps: &[Running]) -> Vec<String> {
    apps.iter().filter(|a| a.public() && a.entrance == id).map(|a| a.name.clone()).collect()
}

/// Whether app may take its public names: a name belongs to one app (and
/// so to one entrance). The same app may move them to another entrance.
/// Every name another app has is named at once.
pub fn check_host(app: &App, apps: &[Running]) -> Result<()> {
    let taken: Vec<(&str, &str)> = app
        .hosts
        .iter()
        .filter_map(|h| apps.iter().find(|a| a.has(&h.name) && a.name != app.name).map(|a| (h.name.as_str(), a.name.as_str())))
        .collect();
    match taken.as_slice() {
        [] => Ok(()),
        [(host, other)] => bail!("{host} is already a public name of {other}; remove it there first"),
        many => {
            let list: Vec<String> = many.iter().map(|(h, a)| format!("{h} ({a})")).collect();
            bail!("these names belong to other apps: {}; remove them there first", list.join(", "))
        }
    }
}

/// Your own VPS. It will relay web and game ports to the cluster over
/// WireGuard; until it exists, it is shown as not set up and no app can
/// choose it.
pub struct Vps;

impl Entrance for Vps {
    fn id(&self) -> &'static str {
        VPS
    }
    fn title(&self) -> &'static str {
        "Your VPS"
    }
    fn carries(&self) -> &'static [Traffic] {
        &[Traffic::Web, Traffic::Tcp, Traffic::Udp]
    }
    fn ready(&self) -> bool {
        false
    }
    fn automatic(&self) -> bool {
        false
    }
    fn state(&self, _: &Ctx, _: &Overview) -> State {
        State::not_set_up("not set up")
    }
    fn open_question(&self, _: &Overview) -> Result<String> {
        bail!("a VPS cannot be set up yet; it comes in a later version")
    }
    fn open(&self, _: &Ctx, _: &dyn Cluster) -> Result<String> {
        bail!("a VPS cannot be set up yet")
    }
    fn sync(&self, _: &Ctx, _: &dyn Cluster, _: &Overview, _: &Want, _: bool) -> Result<Report> {
        bail!("a VPS is not set up yet")
    }
    fn close(&self, _: &Ctx, _: &dyn Cluster) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn running(name: &str, host: &str, entrance: &str) -> Running {
        let hosts = if host.is_empty() { vec![] } else { vec![crate::apps::Host { name: host.into(), port: 80 }] };
        Running { name: name.into(), port: 80, hosts, entrance: entrance.into(), ..Running::default() }
    }

    #[test]
    fn each_name_to_one_entrance() {
        let apps = vec![
            running("blog", "blog.example.com", CLOUDFLARE),
            running("shop", "shop.example.com", CLOUDFLARE),
            running("game", "play.example.com", VPS),
            running("inside", "", CLOUDFLARE),
            // Two apps claim one name: neither gets it, both entrances
            // leave it alone.
            running("a", "same.example.com", CLOUDFLARE),
            running("b", "same.example.com", VPS),
            running("odd", "odd.example.com", "?"),
        ];
        let (w, problems) = wants(&apps);
        let names = |id: &str| w[id].names.iter().map(|n| format!("{}={}", n.host, n.app)).collect::<Vec<_>>();
        assert_eq!(names(CLOUDFLARE), vec!["blog.example.com=blog", "shop.example.com=shop"]);
        assert_eq!(names(VPS), vec!["play.example.com=game"]);
        assert_eq!(w[CLOUDFLARE].disputed, vec!["same.example.com"]);
        assert_eq!(w[VPS].disputed, vec!["same.example.com"]);
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(problems[1].contains("same.example.com is the public name of a and b"), "{problems:?}");
        assert!(problems[0].contains("odd asks for an entrance this dryserver does not know"), "{problems:?}");
        assert_eq!(users(CLOUDFLARE, &apps), vec!["blog", "shop", "a"]);
        // No apps: every entrance serves nothing.
        let (w, problems) = wants(&[]);
        assert!(problems.is_empty() && w.values().all(|w| *w == Want::default()) && w.len() == IDS.len());
    }

    #[test]
    fn a_name_belongs_to_one_app() {
        let apps = vec![running("blog", "blog.example.com", CLOUDFLARE)];
        let app = |name: &str, host: &str, entrance: &str| App {
            name: name.into(),
            hosts: if host.is_empty() { vec![] } else { vec![crate::apps::tests::host(host, 8080)] },
            entrance: entrance.into(),
            ..crate::apps::tests::app()
        };
        let e = check_host(&app("shop", "blog.example.com", VPS), &apps).unwrap_err();
        assert!(e.to_string().contains("blog.example.com is already a public name of blog"), "{e}");
        assert!(check_host(&app("shop", "blog.example.com", CLOUDFLARE), &apps).is_err());
        // The same app may keep it, or move it to another entrance.
        check_host(&app("blog", "blog.example.com", VPS), &apps).unwrap();
        check_host(&app("shop", "shop.example.com", CLOUDFLARE), &apps).unwrap();
        check_host(&app("shop", "", CLOUDFLARE), &apps).unwrap();
        for id in IDS {
            valid_id(id).unwrap();
        }
        assert!(valid_id("").is_err() && valid_id("Cloudflare").is_err() && valid_id("vps\n").is_err());
    }

    #[test]
    fn many_names_per_app() {
        let mut shop = running("shop", "shop.example.com", CLOUDFLARE);
        shop.hosts.push(crate::apps::Host { name: "example.com".into(), port: 80 });
        shop.hosts.push(crate::apps::Host { name: "shop.example.net".into(), port: 9000 });
        shop.hosts.sort();
        let mut other = running("other", "other.example.com", CLOUDFLARE);
        other.hosts.push(crate::apps::Host { name: "shop.example.net".into(), port: 80 });
        let apps = vec![shop.clone(), other, running("blog", "blog.example.com", CLOUDFLARE)];
        let (w, problems) = wants(&apps);
        let names: Vec<String> = w[CLOUDFLARE].names.iter().map(|n| format!("{}={}", n.host, n.app)).collect();
        assert_eq!(
            names,
            vec!["blog.example.com=blog", "example.com=shop", "other.example.com=other", "shop.example.com=shop"],
            "every name of every app, sorted; the one two apps claim goes to neither"
        );
        assert_eq!(w[CLOUDFLARE].disputed, vec!["shop.example.net"]);
        assert!(problems[0].contains("shop.example.net is the public name of shop and other"), "{problems:?}");
        // Every name another app has is named, not only the first.
        let a = App {
            name: "new".into(),
            hosts: vec![
                crate::apps::tests::host("blog.example.com", 8080),
                crate::apps::tests::host("free.example.com", 8080),
                crate::apps::tests::host("shop.example.com", 8080),
            ],
            ..crate::apps::tests::app()
        };
        let e = check_host(&a, &apps).unwrap_err().to_string();
        assert!(e.contains("blog.example.com (blog), shop.example.com (shop)") && !e.contains("free"), "{e}");
        // An app keeps its own names, adds new ones and drops others.
        let again = App { name: "shop".into(), hosts: vec![crate::apps::tests::host("www.example.com", 8080)], ..a };
        check_host(&again, &apps).unwrap();
        check_host(&App { hosts: vec![], ..again }, &apps).unwrap();
    }

    #[test]
    fn the_vps_is_not_there_yet() {
        let v = Vps;
        assert!(!v.ready() && v.state(&Ctx::new(), &Overview::default()).health == Health::NotSetUp);
        assert!(v.sync(&Ctx::new(), &crate::apps::tests::Fake::default(), &Overview::default(), &Want::default(), true).is_err());
        assert_eq!(carries(&v), "web, TCP, UDP");
    }
}
