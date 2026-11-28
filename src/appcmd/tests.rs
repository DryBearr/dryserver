use std::sync::Arc;

use super::*;
use crate::apps::Host;
use crate::apps::tests::Fake;
use crate::entrance::cfsync::tests::{FakeCf, ZONE, entrance, fresh, mark_of};
use crate::entrance::cfsync::{MARK, Record};
use crate::entrance::{Vps, Want};
use crate::testutil::TempDir;

const NET: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// An app as the cluster lists it: (name, port, names with their ports).
type Listed<'a> = (&'a str, u16, &'a [(&'a str, u16)]);

/// What kubectl lists for these apps, with the tunnel running with mark.
fn listing(apps: &[Listed], mark: &str) -> String {
    let mut items = vec![
        r#"{"kind":"Node","metadata":{"name":"coord","labels":{"node-role.kubernetes.io/control-plane":"true"}}}"#.to_string(),
        r#"{"kind":"Node","metadata":{"name":"node-a","labels":{}}}"#.to_string(),
        format!(
            r#"{{"kind":"Deployment","metadata":{{"name":"cloudflared","namespace":"edge","labels":{{"app":"cloudflared"}}}},"spec":{{"replicas":2,"template":{{"metadata":{{"annotations":{{"dryserver/token-mark":"{mark}"}}}}}}}},"status":{{"readyReplicas":2}}}}"#
        ),
    ];
    for (name, port, hosts) in apps {
        items.push(format!(
            r#"{{"kind":"Deployment","metadata":{{"name":"{name}","namespace":"apps","labels":{{"app":"{name}"}},"annotations":{{"dryserver/format":"2"}}}},"spec":{{"replicas":1,"template":{{"spec":{{"containers":[{{"image":"{name}:v1","ports":[{{"containerPort":{port}}}],"resources":{{"limits":{{"memory":"512Mi","cpu":"1"}}}}}}]}}}}}},"status":{{"readyReplicas":1}}}}"#
        ));
        items.push(format!(
            r#"{{"kind":"Pod","metadata":{{"name":"{name}-1","namespace":"apps","labels":{{"app":"{name}"}}}},"spec":{{"nodeName":"node-a"}}}}"#
        ));
        if !hosts.is_empty() {
            let rules: Vec<String> = hosts
                .iter()
                .map(|(h, p)| {
                    let to = if p == port { 80 } else { *p };
                    format!(
                        r#"{{"host":"{h}","http":{{"paths":[{{"backend":{{"service":{{"name":"{name}","port":{{"number":{to}}}}}}}}}]}}}}"#
                    )
                })
                .collect();
            items.push(format!(
                r#"{{"kind":"Ingress","metadata":{{"name":"{name}","namespace":"apps","labels":{{"app":"{name}"}},"annotations":{{"dryserver/entrance":"cloudflare","dryserver/format":"2"}}}},"spec":{{"rules":[{}]}}}}"#,
                rules.join(",")
            ));
        }
    }
    format!(r#"{{"items":[{}]}}"#, items.join(","))
}

/// A cluster, Cloudflare with example.com and example.net, and the
/// tunnel set up and running.
struct World {
    cluster: Arc<Fake>,
    cf: Arc<FakeCf>,
    doors: Entrances,
    mark: String,
    _dir: TempDir,
}

impl World {
    fn new() -> World {
        World::with_token(true)
    }

    fn with_token(token: bool) -> World {
        let dir = TempDir::new();
        let cf = Arc::new(fresh());
        cf.cf.lock().unwrap().zones.push((NET.into(), "example.net".into(), crate::entrance::cfsync::tests::ACCOUNT.into()));
        let cluster = Arc::new(Fake::default());
        let doors: Entrances = Arc::new(vec![Box::new(entrance(dir.path(), &cf, token)), Box::new(Vps)]);
        let mut mark = String::new();
        if token {
            let o = apps::overview(&Ctx::new(), cluster.as_ref()).unwrap();
            doors[0].sync(&Ctx::new(), cluster.as_ref(), &o, &Want { open: true, ..Want::default() }, false).unwrap();
            mark = mark_of(&cluster).unwrap();
        }
        *cluster.listing.lock().unwrap() = listing(&[], &mark);
        World { cluster, cf, doors, mark, _dir: dir }
    }

    /// The cluster lists these apps now.
    fn runs(&self, apps: &[Listed]) {
        *self.cluster.listing.lock().unwrap() = listing(apps, &self.mark);
    }

    /// Once a manifest with has in it is applied, the cluster lists apps.
    fn then_runs(&self, has: &str, apps: &[Listed]) {
        self.cluster.after_apply.lock().unwrap().push((has.into(), listing(apps, &self.mark)));
    }

    /// The names dryserver's DNS records hold, sorted.
    fn dns(&self) -> Vec<String> {
        let mut n: Vec<String> = self.cf.cf.lock().unwrap().records.iter().filter(|r| r.comment == MARK).map(|r| r.name.clone()).collect();
        n.sort();
        n
    }

    /// The names the tunnel routes, in its order.
    fn routed(&self) -> Vec<String> {
        let cf = self.cf.cf.lock().unwrap();
        cf.configs.values().next().map(|r| r.iter().map(|(h, _)| h.clone()).filter(|h| !h.is_empty()).collect()).unwrap_or_default()
    }

    fn applies(&self) -> usize {
        self.cluster.calls.lock().unwrap().iter().filter(|(a, m)| a == "apply -f -" && !m.contains("cloudflared")).count()
    }

    fn last_manifest(&self) -> String {
        self.cluster.calls.lock().unwrap().iter().rev().find(|(a, m)| a == "apply -f -" && !m.contains("cloudflared")).unwrap().1.clone()
    }

    /// Runs f with an Io that answers every question with yes, and gives
    /// back what was printed, the questions asked and the result.
    fn run(&self, yes: bool, f: impl FnOnce(&Ctx, &dyn Cluster, &Entrances, &mut Io) -> Result<()>) -> (String, Vec<String>, Result<()>) {
        let mut out = Vec::new();
        let mut asked = Vec::new();
        let mut ask = |q: &str| {
            asked.push(q.to_string());
            yes
        };
        let res = {
            let mut io = Io { out: &mut out, ask: &mut ask };
            f(&Ctx::new(), self.cluster.as_ref(), &self.doors, &mut io)
        };
        (String::from_utf8(out).unwrap(), asked, res)
    }

    fn deploy(&self, file: &str, opts: Opts, yes: bool) -> (String, Result<()>) {
        let app = appfile::parse(file).unwrap();
        let (out, _, res) = self.run(yes, |ctx, c, d, io| deploy(ctx, c, d, None, None, &app, &opts, io));
        (out, res)
    }
}

const SHOP: &str = "NAME=shop\nIMAGE=shop:v1\nPORT=8080\nHOST=shop.example.com example.com www.example.net\nHOST=admin.example.com:9000\n";
const SHOP_NAMES: &[(&str, u16)] =
    &[("admin.example.com", 9000), ("example.com", 8080), ("shop.example.com", 8080), ("www.example.net", 8080)];

#[test]
fn deploy_shows_first_then_makes_exactly_that() {
    let w = World::new();
    // Asked and told no: nothing reaches the cluster or Cloudflare.
    let changes = w.cf.changes.load(std::sync::atomic::Ordering::SeqCst);
    let (out, res) = w.deploy(SHOP, Opts::default(), false);
    res.unwrap();
    for want in [
        "shop (new):",
        "  start it: shop:v1, port 8080, 1 copy",
        "  + admin.example.com (port 9000)",
        "  + example.com\n",
        "  + www.example.net\n",
        "Cloudflare Tunnel:\n",
        "  - route admin.example.com, example.com, shop.example.com, www.example.net through the tunnel",
        "  - add example.com to DNS, pointing at the tunnel",
        "  - add www.example.net to DNS",
        "Nothing changed.",
    ] {
        assert!(out.contains(want), "missing {want:?}:\n{out}");
    }
    assert_eq!(w.applies(), 0);
    assert_eq!(w.cf.changes.load(std::sync::atomic::Ordering::SeqCst), changes, "nothing changed in Cloudflare");

    // Yes: the app with every name, and each name in DNS and the tunnel.
    w.then_runs("name: \"shop\"", &[("shop", 8080, SHOP_NAMES)]);
    let (out, res) = w.deploy(SHOP, Opts::default(), true);
    res.unwrap();
    assert!(out.contains("shop: applied.") && out.contains("Cloudflare Tunnel: 5 changes made."), "{out}");
    assert!(out.contains("Whether each name answers: dryserver app list"), "{out}");
    let m = w.last_manifest();
    assert!(m.contains("- host: \"admin.example.com\"") && m.contains("number: 9000") && m.contains("- host: \"www.example.net\""), "{m}");
    assert_eq!(w.dns(), vec!["admin.example.com", "example.com", "shop.example.com", "www.example.net"]);
    assert_eq!(w.routed(), w.dns());

    // The same file again: nothing to change, nothing asked.
    let (out, _, res) = w.run(true, |ctx, c, d, io| deploy(ctx, c, d, None, None, &appfile::parse(SHOP).unwrap(), &Opts::default(), io));
    res.unwrap();
    assert_eq!(out, "shop: nothing to change (applied again, as the file says).\n");
    assert_eq!(w.applies(), 2, "applied again: what was changed by hand is put back");

    // A name dropped, one added, one moved to another port: the app
    // itself stays as it runs (no image or port changed for its copies)
    // unless a port goes away.
    let next = "NAME=shop\nIMAGE=shop:v1\nPORT=8080\nHOST=shop.example.com example.com\nHOST=admin.example.com:9000 api.example.com:9000\n";
    w.then_runs(
        "api.example.com",
        &[("shop", 8080, &[("admin.example.com", 9000), ("api.example.com", 9000), ("example.com", 8080), ("shop.example.com", 8080)])],
    );
    let (out, res) = w.deploy(next, Opts::default(), true);
    res.unwrap();
    for want in [
        "shop:\n",
        "  + api.example.com (port 9000)",
        "  - www.example.net (stops answering)",
        "  = 3 names stay as they are",
        "  The running copies stay as they are.",
        "  - delete the DNS record of www.example.net (no app uses it)",
        "  - add api.example.com to DNS",
    ] {
        assert!(out.contains(want), "missing {want:?}:\n{out}");
    }
    assert_eq!(w.dns(), vec!["admin.example.com", "api.example.com", "example.com", "shop.example.com"]);

    // A new image replaces the copies; the names stay.
    w.then_runs("shop:v2", &[("shop", 8080, &[("example.com", 8080)])]);
    let (out, res) = w.deploy("NAME=shop\nIMAGE=shop:v2\nPORT=8080\nHOST=example.com\n", Opts::default(), true);
    res.unwrap();
    assert!(out.contains("  image   shop:v1 -> shop:v2") && out.contains("Its copies are replaced one at a time"), "{out}");
    assert_eq!(w.dns(), vec!["example.com"]);
}

#[test]
fn names_that_cannot_be_served_stop_the_deploy() {
    let w = World::new();
    w.runs(&[("blog", 80, &[("blog.example.com", 80)])]);
    // Another app has it: every such name is named, nothing is sent.
    let (_, res) = w.deploy("NAME=shop\nIMAGE=s:1\nPORT=80\nHOST=shop.example.com blog.example.com\n", Opts::default(), true);
    let e = res.unwrap_err().to_string();
    assert!(e.contains("blog.example.com is already a public name of blog"), "{e}");
    // In no domain the token sees: not half public.
    let (_, res) = w.deploy("NAME=shop\nIMAGE=s:1\nPORT=80\nHOST=shop.example.com shop.example.org\n", Opts::default(), true);
    let e = res.unwrap_err().to_string();
    assert!(
        e.contains("shop.example.org is not in a domain your Cloudflare API token can see") && e.contains("Nothing was changed"),
        "{e}"
    );
    // A record dryserver did not make holds it: left alone unless the
    // admin lets it be taken over.
    w.cf.cf.lock().unwrap().records.push(Record {
        zone: ZONE.into(),
        id: "e".repeat(32),
        name: "shop.example.com".into(),
        kind: "A".into(),
        content: "203.0.113.7".into(),
        proxied: false,
        comment: String::new(),
    });
    let (out, res) = w.deploy("NAME=shop\nIMAGE=s:1\nPORT=80\nHOST=shop.example.com\n", Opts::default(), true);
    let e = res.unwrap_err().to_string();
    assert!(out.contains("held by something else: shop.example.com (shop) has a A record 203.0.113.7"), "{out}");
    assert!(e.contains("run this again with -take-over shop.example.com") && e.contains("Nothing was changed"), "{e}");
    assert_eq!(w.applies(), 0);
    // A take-over of a name the app does not have is refused.
    let (_, res) = w.deploy(
        "NAME=shop\nIMAGE=s:1\nPORT=80\nHOST=shop.example.com\n",
        Opts { take_over: vec!["x.example.com".into()], ..Opts::default() },
        true,
    );
    assert!(res.unwrap_err().to_string().contains("x.example.com is not a name of shop"));
    // Taken over: the plan says so, and does it.
    w.then_runs("name: \"shop\"", &[("blog", 80, &[("blog.example.com", 80)]), ("shop", 80, &[("shop.example.com", 80)])]);
    let (out, res) = w.deploy(
        "NAME=shop\nIMAGE=s:1\nPORT=80\nHOST=shop.example.com\n",
        Opts { take_over: vec!["Shop.Example.com".into()], ..Opts::default() },
        true,
    );
    res.unwrap();
    assert!(out.contains("delete the DNS record of shop.example.com (A record 203.0.113.7, taken over"), "{out}");
    assert!(w.dns().contains(&"shop.example.com".to_string()));
    // A name it already has, whose domain the token no longer sees, does
    // not hold the app back: only new names must be in a domain.
    w.runs(&[("old", 80, &[("old.example.org", 80)])]);
    w.then_runs("old:v2", &[("old", 80, &[("old.example.org", 80)])]);
    let (out, res) = w.deploy("NAME=old\nIMAGE=old:v2\nPORT=80\nHOST=old.example.org\n", Opts::default(), true);
    res.unwrap();
    assert!(
        out.contains("image   old:v1 -> old:v2") && out.contains("old.example.org (old) is not in a zone this API token can see"),
        "{out}"
    );
    // The VPS is not there yet: its names would not be served.
    let (_, res) = w.deploy("NAME=game\nIMAGE=g:1\nPORT=80\nHOST=play.example.com\nENTRANCE=vps\n", Opts::default(), true);
    assert!(res.unwrap_err().to_string().contains("Your VPS is not set up yet"));
}

#[test]
fn email_records_and_other_records_of_a_name_stay() {
    // The domain itself often has MX and TXT records (email, ownership
    // proofs): routing example.com to an app never touches them.
    let w = World::new();
    for (kind, content) in [("MX", "mail.example.com"), ("TXT", "v=spf1 -all")] {
        w.cf.cf.lock().unwrap().records.push(Record {
            zone: ZONE.into(),
            id: format!("{:032x}", content.len() + 900),
            name: "example.com".into(),
            kind: kind.into(),
            content: content.into(),
            proxied: false,
            comment: String::new(),
        });
    }
    w.then_runs("name: \"site\"", &[("site", 80, &[("example.com", 80)])]);
    let (out, res) = w.deploy("NAME=site\nIMAGE=s:1\nPORT=80\nHOST=example.com\n", Opts::default(), true);
    res.unwrap();
    assert!(!out.contains("held by something else"), "{out}");
    let kinds: Vec<String> = w.cf.cf.lock().unwrap().records.iter().filter(|r| r.name == "example.com").map(|r| r.kind.clone()).collect();
    assert!(kinds.contains(&"MX".to_string()) && kinds.contains(&"TXT".to_string()) && kinds.contains(&"CNAME".to_string()), "{kinds:?}");
}

#[test]
fn deep_names_and_waiting_domains_are_said() {
    let w = World::new();
    w.cf.cf.lock().unwrap().pending.push(NET.into());
    w.then_runs("name: \"api\"", &[("api", 80, &[("v1.api.example.com", 80), ("www.example.net", 80)])]);
    let (out, res) = w.deploy("NAME=api\nIMAGE=a:1\nPORT=80\nHOST=v1.api.example.com www.example.net\n", Opts::default(), true);
    res.unwrap();
    assert!(out.contains("v1.api.example.com (api) is two or more levels below example.com"), "{out}");
    assert!(out.contains("example.net is not active in Cloudflare yet (pending)"), "{out}");
    // Both are set up all the same: the admin was told.
    assert_eq!(w.dns(), vec!["v1.api.example.com", "www.example.net"]);
}

#[test]
fn when_cloudflare_does_not_take_part() {
    let w = World::new();
    // Down while looking: said; on yes the app starts, the names wait.
    w.cf.down.store(true, std::sync::atomic::Ordering::SeqCst);
    let (out, res) = w.deploy("NAME=shop\nIMAGE=s:1\nPORT=80\nHOST=shop.example.com\n", Opts::default(), true);
    assert!(out.contains("Cloudflare Tunnel: could not look") && out.contains("shop: applied."), "{out}");
    assert!(res.unwrap_err().to_string().contains("Cloudflare is not in step yet (see above): dryserver app sync"));
    assert!(w.dns().is_empty());
    // Back: sync shows the missing name and makes it.
    w.cf.down.store(false, std::sync::atomic::Ordering::SeqCst);
    w.runs(&[("shop", 80, &[("shop.example.com", 80)])]);
    let (out, asked, res) = w.run(true, |ctx, c, d, io| sync(ctx, c, d, &Opts::default(), io));
    res.unwrap();
    assert!(out.contains("add shop.example.com to DNS") && out.contains("Cloudflare Tunnel: 2 changes made."), "{out}");
    assert_eq!(asked, vec!["Make these changes? [y/N] "]);
    assert_eq!(w.dns(), vec!["shop.example.com"]);
    // Nothing left: nothing asked.
    let (out, asked, res) = w.run(true, |ctx, c, d, io| sync(ctx, c, d, &Opts::default(), io));
    res.unwrap();
    assert!(out.contains("Cloudflare Tunnel: nothing to change") && asked.is_empty(), "{out}");

    // Failing half way through the changes: said, and the next run
    // finishes it.
    let n = w.cf.changes.load(std::sync::atomic::Ordering::SeqCst);
    *w.cf.fail_at.lock().unwrap() = Some(n + 2);
    w.then_runs(
        "name: \"blog\"",
        &[("shop", 80, &[("shop.example.com", 80)]), ("blog", 80, &[("blog.example.com", 80), ("blog.example.net", 80)])],
    );
    let (out, res) = w.deploy("NAME=blog\nIMAGE=b:1\nPORT=80\nHOST=blog.example.com blog.example.net\n", Opts::default(), true);
    assert!(out.contains("Cloudflare Tunnel: not synced:") && out.contains("dryserver app sync shows what is left"), "{out}");
    assert!(res.is_err());
    let (_, _, res) = w.run(true, |ctx, c, d, io| sync(ctx, c, d, &Opts::default(), io));
    res.unwrap();
    assert_eq!(w.dns(), vec!["blog.example.com", "blog.example.net", "shop.example.com"]);

    // Something changed between the look and the yes: none of it is made
    // in Cloudflare (the cluster here gains an app nobody was shown).
    w.then_runs(
        "name: \"news\"",
        &[
            ("shop", 80, &[("shop.example.com", 80)]),
            ("blog", 80, &[("blog.example.com", 80), ("blog.example.net", 80)]),
            ("news", 80, &[("news.example.com", 80)]),
            ("late", 80, &[("late.example.com", 80)]),
        ],
    );
    let (out, res) = w.deploy("NAME=news\nIMAGE=n:1\nPORT=80\nHOST=news.example.com\n", Opts::default(), true);
    assert!(out.contains("something changed since you looked, so nothing was changed in Cloudflare"), "{out}");
    assert!(res.is_err() && !w.dns().contains(&"news.example.com".to_string()));
}

#[test]
fn without_an_api_token_the_names_are_routed_by_hand() {
    let w = World::with_token(false);
    w.then_runs("name: \"shop\"", &[("shop", 80, &[("shop.example.com", 80), ("www.example.com", 80)])]);
    let (out, res) = w.deploy("NAME=shop\nIMAGE=s:1\nPORT=80\nHOST=shop.example.com www.example.com\n", Opts::default(), true);
    res.unwrap();
    assert!(
        out.contains("routed by hand") && out.contains("add shop.example.com, www.example.com with the service http://traefik"),
        "{out}"
    );
    assert!(w.cf.calls.lock().unwrap().is_empty(), "nothing went to Cloudflare");
    let (out, _, res) = w.run(true, |ctx, c, d, io| remove(ctx, c, d, "shop", &Opts::default(), io));
    res.unwrap();
    assert!(out.contains("and remove shop.example.com, www.example.com there"), "{out}");
}

#[test]
fn remove_says_what_goes() {
    let w = World::new();
    w.then_runs("name: \"shop\"", &[("shop", 8080, SHOP_NAMES)]);
    w.deploy(SHOP, Opts::default(), true).1.unwrap();
    // No: nothing removed.
    let (out, asked, res) = w.run(false, |ctx, c, d, io| remove(ctx, c, d, "shop", &Opts::default(), io));
    res.unwrap();
    assert_eq!(asked, vec!["Remove? [y/N] "]);
    assert!(out.contains("Remove shop?") && out.contains("its containers stop on node-a") && out.contains("Nothing removed."), "{out}");
    assert!(out.contains("admin.example.com, example.com, shop.example.com, www.example.net stop answering from outside"), "{out}");
    assert!(out.contains("delete the DNS record of example.com (no app uses it)"), "{out}");
    assert_eq!(w.dns().len(), 4);
    // Yes, without asking.
    *w.cluster.after_delete.lock().unwrap() = Some(listing(&[], &w.mark));
    let (out, asked, res) = w.run(false, |ctx, c, d, io| remove(ctx, c, d, "shop", &Opts { yes: true, ..Opts::default() }, io));
    res.unwrap();
    assert!(asked.is_empty() && out.contains("shop: removed.") && out.contains("changes made"), "{out}");
    assert!(w.dns().is_empty() && w.routed().is_empty());
    let (_, _, res) = w.run(true, |ctx, c, d, io| remove(ctx, c, d, "shop", &Opts::default(), io));
    assert!(res.unwrap_err().to_string().contains("no app named shop runs"));
    let (_, _, res) = w.run(true, |ctx, c, d, io| remove(ctx, c, d, "shop -A", &Opts::default(), io));
    assert!(res.is_err());
}

#[test]
fn a_newer_dryserver_is_left_alone() {
    let w = World::new();
    let newer =
        listing(&[("shop", 80, &[("shop.example.com", 80)])], &w.mark).replace("\"dryserver/format\":\"2\"", "\"dryserver/format\":\"99\"");
    *w.cluster.listing.lock().unwrap() = newer;
    let (_, res) = w.deploy("NAME=blog\nIMAGE=b:1\nPORT=80\nHOST=blog.example.com\n", Opts::default(), true);
    assert!(res.unwrap_err().to_string().contains("shop was set up by a newer dryserver"));
    let (_, _, res) = w.run(true, |ctx, c, d, io| sync(ctx, c, d, &Opts::default(), io));
    assert!(res.unwrap_err().to_string().contains("newer dryserver"));
    let (_, _, res) = w.run(true, |ctx, c, d, io| remove(ctx, c, d, "shop", &Opts::default(), io));
    assert!(res.unwrap_err().to_string().contains("newer dryserver"));
    assert_eq!(w.applies(), 0);
    // The entrance itself refuses too (the screens go through it).
    let o = apps::overview(&Ctx::new(), w.cluster.as_ref()).unwrap();
    let e = w.doors[0].sync(&Ctx::new(), w.cluster.as_ref(), &o, &Want::default(), true).unwrap_err();
    assert!(e.to_string().contains("newer dryserver"), "{e}");
}

#[test]
fn show_and_list() {
    let w = World::new();
    w.runs(&[("shop", 8080, SHOP_NAMES), ("db", 5432, &[])]);
    let (out, _, res) = w.run(true, |ctx, c, _, io| show(ctx, c, "shop", io));
    res.unwrap();
    let back = appfile::parse(&out).unwrap();
    assert_eq!(back, appfile::parse(SHOP).unwrap(), "{out}");
    let (_, _, res) = w.run(true, |ctx, c, _, io| show(ctx, c, "nope", io));
    assert!(res.unwrap_err().to_string().contains("no app named nope"));

    let check = |h: &str| if h == "example.com" { "answers (HTTP 200)".to_string() } else { format!("checked {h}") };
    let (out, _, res) = w.run(true, |ctx, c, d, io| list(ctx, c, d, Some(&check), io));
    res.unwrap();
    for want in [
        "db  1 of 1 running  on node-a  db:v1\n    inside only\n",
        "shop  1 of 1 running  on node-a  shop:v1\n",
        "    admin.example.com -> port 9000  through Cloudflare Tunnel  checked admin.example.com\n",
        "    example.com  through Cloudflare Tunnel  answers (HTTP 200)\n",
    ] {
        assert!(out.contains(want), "missing {want:?}:\n{out}");
    }
    let (out, _, _) = w.run(true, |ctx, c, d, io| list(ctx, c, d, None, io));
    assert!(out.contains("    example.com  through Cloudflare Tunnel\n"), "{out}");
    w.runs(&[]);
    let (out, _, _) = w.run(true, |ctx, c, d, io| list(ctx, c, d, None, io));
    assert!(out.contains("No app runs yet"), "{out}");
}

#[test]
fn the_domains_the_token_sees() {
    let w = World::new();
    w.cf.cf.lock().unwrap().pending.push(NET.into());
    w.runs(&[("shop", 80, &[("shop.example.com", 80), ("a.b.example.com", 80), ("shop.example.org", 80)])]);
    let cf = entrance(w._dir.path(), &w.cf, true);
    let mut out = Vec::new();
    let mut ask = |_: &str| true;
    domains(&Ctx::new(), w.cluster.as_ref(), &cf, &mut Io { out: &mut out, ask: &mut ask }).unwrap();
    let out = String::from_utf8(out).unwrap();
    for want in [
        "example.com  active\n",
        "    a.b.example.com (shop)  (two levels deep",
        "    shop.example.com (shop)\n",
        "example.net  pending: at the company you bought it from",
        "Not in any domain the token sees: shop.example.org (shop)",
    ] {
        assert!(out.contains(want), "missing {want:?}:\n{out}");
    }
    let none = entrance(TempDir::new().path(), &w.cf, false);
    let e = domains(&Ctx::new(), w.cluster.as_ref(), &none, &mut Io { out: &mut Vec::new(), ask: &mut ask }).unwrap_err();
    assert!(e.to_string().contains("no Cloudflare API token on this computer"), "{e}");
}

#[test]
fn the_hosts_of_a_deploy_are_as_the_file_says() {
    // The overview the entrances are asked about is the cluster after
    // the change: the app's names in, its dropped ones out.
    let now = Overview {
        apps: vec![Running {
            name: "shop".into(),
            port: 80,
            hosts: vec![Host { name: "old.example.com".into(), port: 80 }],
            entrance: "cloudflare".into(),
            ..Running::default()
        }],
        ..Overview::default()
    };
    let app = appfile::parse("NAME=shop\nIMAGE=s:1\nPORT=80\nHOST=new.example.com\n").unwrap();
    let after = after_deploy(&now, &app);
    assert_eq!(after.apps[0].names(), vec!["new.example.com"]);
    assert!(after_remove(&now, "shop").apps.is_empty());
    assert_eq!(touched(now.apps.first(), Some(&app)), vec!["cloudflare"]);
    assert!(touched(None, Some(&appfile::parse("NAME=db\nIMAGE=p:1\nPORT=5432\n").unwrap())).is_empty());
}

/// The listing of one app whose pods run image (built as id).
fn runs_own(w: &World, name: &str, image: &str, id: &str) -> String {
    listing(&[(name, 80, &[])], &w.mark).replace(
        &format!(r#""template":{{"spec":{{"containers":[{{"image":"{name}:v1""#),
        &format!(r#""template":{{"metadata":{{"annotations":{{"dryserver/image-id":"{id}"}}}},"spec":{{"containers":[{{"image":"{image}""#),
    )
}

#[test]
fn an_image_of_your_own_goes_to_the_servers_first() {
    use crate::images::tests::{FakeDesk, FakeServers, ID, ID2};
    let w = World::new();
    let desk = FakeDesk::with(ID, "amd64");
    let servers = FakeServers::with(&["node-a"]);
    let own = Own { desk: &desk, servers: &servers };
    let file = "NAME=shop\nIMAGE=localhost/shop:v1\nPORT=80\n";
    let app = appfile::parse(file).unwrap();
    // Without a way to the servers: refused, nothing sent.
    let (_, _, res) = w.run(true, |ctx, c, d, io| deploy(ctx, c, d, None, None, &app, &Opts::default(), io));
    assert!(res.unwrap_err().to_string().contains("cannot reach your servers"));
    // Asked first; no: nothing copied, nothing applied.
    let (out, _, res) = w.run(false, |ctx, c, d, io| deploy(ctx, c, d, Some(&own), None, &app, &Opts::default(), io));
    res.unwrap();
    assert!(out.contains("  localhost/shop:v1 (30 MB): copy it to node-a") && out.contains("Nothing changed."), "{out}");
    assert!(servers.sent.lock().unwrap().is_empty() && w.applies() == 0);
    // Yes: copied, loaded, then applied with that build and never pulled.
    *w.cluster.after_apply.lock().unwrap() = vec![("localhost/shop:v1".into(), runs_own(&w, "shop", "localhost/shop:v1", ID))];
    let (out, _, res) = w.run(true, |ctx, c, d, io| deploy(ctx, c, d, Some(&own), None, &app, &Opts::default(), io));
    res.unwrap();
    assert!(out.contains("node-a: has localhost/shop:v1.") && out.contains("shop: applied."), "{out}");
    let m = w.last_manifest();
    assert!(m.contains("imagePullPolicy: Never") && m.contains(&format!("dryserver/image-id: \"{ID}\"")), "{m}");
    // The same build again: nothing to copy, nothing to change.
    let (out, _, res) = w.run(true, |ctx, c, d, io| deploy(ctx, c, d, Some(&own), None, &app, &Opts::default(), io));
    res.unwrap();
    assert!(out.contains("nothing to change"), "{out}");
    assert_eq!(servers.sent.lock().unwrap().len(), 1);
    // Built again under the same tag: copied, and the copies replaced.
    let desk2 = FakeDesk::with(ID2, "amd64");
    let own2 = Own { desk: &desk2, servers: &servers };
    let (out, _, res) = w.run(true, |ctx, c, d, io| deploy(ctx, c, d, Some(&own2), None, &app, &Opts::default(), io));
    res.unwrap();
    assert!(out.contains("  image   localhost/shop:v1 rebuilt: 111111111111 -> 222222222222"), "{out}");
    assert!(out.contains("Its copies are replaced one at a time"), "{out}");
    assert!(w.last_manifest().contains(&format!("dryserver/image-id: \"{ID2}\"")));
    // A server refuses it: the app is not changed.
    let applied = w.applies();
    *servers.refuse.lock().unwrap() = Some("not enough room on this server's disk".into());
    let desk3 = FakeDesk::with(&format!("sha256:{}", "3".repeat(64)), "amd64");
    let own3 = Own { desk: &desk3, servers: &servers };
    let (_, _, res) = w.run(true, |ctx, c, d, io| deploy(ctx, c, d, Some(&own3), None, &app, &Opts::default(), io));
    let e = res.unwrap_err().to_string();
    assert!(e.contains("shop was not applied, nothing changed in the cluster") && e.contains("refused it: not enough room"), "{e}");
    assert_eq!(w.applies(), applied);
    // A server of the cluster that is not in the server list would never
    // get it: refused before anything is copied.
    *servers.refuse.lock().unwrap() = None;
    let other = FakeServers::with(&["node-b"]);
    let own4 = Own { desk: &desk3, servers: &other };
    let (_, _, res) = w.run(true, |ctx, c, d, io| deploy(ctx, c, d, Some(&own4), None, &app, &Opts::default(), io));
    let e = res.unwrap_err().to_string();
    assert!(e.contains("node-a run apps but is not in your server list") && e.contains("dryserver ssh-config"), "{e}");
    assert!(other.sent.lock().unwrap().is_empty());
    // app push alone: the same, without the app.
    let (out, _, res) = w.run(true, |ctx, c, _, io| push(ctx, c, &own3, "localhost/shop:v1", &Opts::default(), io));
    res.unwrap();
    assert!(out.contains("copy it to node-a") && out.contains("localhost/shop:v1 is on every server."), "{out}");
    let (out, asked, res) = w.run(true, |ctx, c, _, io| push(ctx, c, &own3, "localhost/shop:v1", &Opts::default(), io));
    res.unwrap();
    assert!(out.contains("on every server already") && asked.is_empty(), "{out}");
    // Without a tag it is refused: say which build is meant.
    assert!(appfile::parse("NAME=shop\nIMAGE=localhost/shop\nPORT=80\n").is_err());
}

#[test]
fn secrets_reach_the_app_and_never_a_command_line() {
    let w = World::new();
    let file = "NAME=shop\nIMAGE=shop:v1\nPORT=80\nENV=NODE_ENV=production\nSECRET=DATABASE_URL\n";
    // No value yet: refused before anything changes.
    let (_, res) = w.deploy(file, Opts::default(), true);
    let e = res.unwrap_err().to_string();
    assert!(e.contains("shop has no value for DATABASE_URL yet") && e.contains("dryserver app secret shop NAME"), "{e}");
    assert_eq!(w.applies(), 0);
    // Set it: the Secret is made, the value goes on stdin only.
    let value = b"postgres://u:p@db.example.com/shop".to_vec();
    let (out, _, res) = w.run(true, |ctx, c, _, io| secret(ctx, c, "shop", SecretOp::Set("DATABASE_URL".into(), value.clone()), io));
    res.unwrap();
    assert!(out.contains("DATABASE_URL is set for shop"), "{out}");
    let calls = w.cluster.calls.lock().unwrap().clone();
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&value);
    assert!(
        calls.iter().any(|(a, m)| a == "apply -f -"
            && m.contains("kind: Namespace")
            && m.contains("kind: Secret")
            && m.contains("name: \"app-shop\"")
            && !m.contains("\ndata:")),
        "{calls:?}"
    );
    let patch = calls.iter().find(|(a, _)| a.contains("patch secret app-shop")).unwrap();
    assert!(patch.0.contains("--type merge --patch-file /dev/stdin -o go-template=") && patch.1.contains(&encoded), "{patch:?}");
    assert!(calls.iter().all(|(a, _)| !a.contains("postgres") && !a.contains(&encoded)), "never in a command line");
    // The cluster has it now: deploy goes ahead, the copies note its version.
    w.cluster.answers.lock().unwrap().push(("get secret app-shop".into(), "77 DATABASE_URL".into()));
    // Asked for its version and names, never its values.
    w.cluster.answers.lock().unwrap().push(("patch secret app-shop".into(), "78".into()));
    let (out, res) = w.deploy(file, Opts::default(), true);
    res.unwrap();
    assert!(out.contains("  ENV NODE_ENV") && out.contains("  SECRET DATABASE_URL"), "{out}");
    let m = w.last_manifest();
    assert!(
        m.contains("secretKeyRef:\n                  name: \"app-shop\"\n                  key: \"DATABASE_URL\"")
            && m.contains("dryserver/secrets: \"77\""),
        "{m}"
    );
    // A new value for a secret the running app uses replaces its copies.
    let running = listing(&[("shop", 80, &[])], &w.mark).replace(
        r#""resources":{"limits":{"memory":"512Mi","cpu":"1"}}"#,
        r#""resources":{"limits":{"memory":"512Mi","cpu":"1"}},"env":[{"name":"DATABASE_URL","valueFrom":{"secretKeyRef":{"name":"app-shop","key":"DATABASE_URL"}}}]"#,
    );
    *w.cluster.listing.lock().unwrap() = running;
    let (out, _, res) = w.run(true, |ctx, c, _, io| secret(ctx, c, "shop", SecretOp::Set("DATABASE_URL".into(), b"new".to_vec()), io));
    res.unwrap();
    assert!(out.contains("shop replaces its copies one at a time"), "{out}");
    let calls = w.cluster.calls.lock().unwrap().clone();
    let bump = calls.iter().rev().find(|(a, _)| a.contains("patch deployment shop")).unwrap();
    assert!(bump.1.contains("\"dryserver/secrets\":\"78\""), "the version after the change: {bump:?}");
    assert!(
        calls.iter().filter(|(a, _)| a.contains("secret app-shop") && !a.contains("patch")).all(|(a, _)| a.contains("go-template=")),
        "values are never read: {calls:?}"
    );
    // Removing one it uses is refused; listing names, never values.
    let (_, _, res) = w.run(true, |ctx, c, _, io| secret(ctx, c, "shop", SecretOp::Remove("DATABASE_URL".into()), io));
    assert!(res.unwrap_err().to_string().contains("shop uses DATABASE_URL"));
    let (out, _, res) = w.run(true, |ctx, c, _, io| secret(ctx, c, "shop", SecretOp::List, io));
    res.unwrap();
    assert_eq!(out, "DATABASE_URL\n");
    // Values that make no sense are refused before anything is sent.
    let before = w.cluster.calls.lock().unwrap().len();
    for (k, v, why) in [
        ("DATABASE_URL", vec![], "an empty value"),
        ("bad-name", b"x".to_vec(), "letters, digits"),
        ("BIG", vec![b'x'; MAX_SECRET + 1], "at most 64 KiB"),
    ] {
        let (_, _, res) = w.run(true, |ctx, c, _, io| secret(ctx, c, "shop", SecretOp::Set(k.into(), v.clone()), io));
        assert!(res.unwrap_err().to_string().contains(why), "{k}");
    }
    assert!(w.cluster.calls.lock().unwrap()[before..].iter().all(|(a, _)| !a.contains("patch")));
    // Removing the app says its secrets go too.
    let (out, _, _) = w.run(false, |ctx, c, d, io| remove(ctx, c, d, "shop", &Opts::default(), io));
    assert!(out.contains("its secrets are deleted from the cluster"), "{out}");
}

#[test]
fn only_names_are_read_of_a_secret() {
    let s = secrets_of("4711 DATABASE_URL TOKEN TOKEN bad-name");
    assert_eq!((s.version.as_str(), s.keys), ("4711", vec!["DATABASE_URL".to_string(), "TOKEN".to_string()]));
    assert_eq!(secrets_of(""), Secrets::default());
    assert_eq!(secrets_of("12;rm"), Secrets::default());
}

#[test]
fn what_changes_in_settings_and_limits() {
    let b = Running {
        name: "shop".into(),
        image: "shop:v1".into(),
        port: 80,
        run: apps::Runtime {
            env: vec![("A".into(), "1".into()), ("B".into(), "2".into())],
            secrets: vec!["S1".into()],
            memory_mib: 0,
            cpu_milli: 0,
            secrets_version: "5".into(),
        },
        ..Running::default()
    };
    let mut a =
        appfile::parse("NAME=shop\nIMAGE=shop:v1\nPORT=80\nENV=A=1\nENV=B=3\nENV=C=4\nSECRET=S2\nMEMORY=256Mi\nCPU=250m\n").unwrap();
    a.run.secrets_version = "6".into();
    let (lines, restart) = app_changes(Some(&b), &a);
    let text = lines.join("\n");
    for want in [
        "limits  no limit -> 256Mi memory, 250m CPU",
        "~ ENV B (new value)",
        "+ ENV C",
        "+ SECRET S2",
        "- SECRET S1",
        "replaced one at a time",
    ] {
        assert!(text.contains(want), "missing {want:?}:\n{text}");
    }
    assert!(restart && !text.contains("ENV A"), "{text}");
    // Same settings, only the secret values moved on.
    let same = Running {
        run: apps::Runtime {
            env: a.run.env.clone(),
            secrets: a.run.secrets.clone(),
            memory_mib: 256,
            cpu_milli: 250,
            secrets_version: "5".into(),
        },
        ..b
    };
    let (lines, restart) = app_changes(Some(&same), &a);
    assert!(restart && lines.iter().any(|l| l.contains("a value changed since the copies started")), "{lines:?}");
}

mod from_github {
    use super::*;
    use crate::github::tests::{DIGEST, DIGEST2, OneProof, SHA, SaysGood, claims, fake_keys, fake_proof};
    use crate::github::{self as g, Found};
    use std::sync::Mutex;

    const TOKEN: &str = "ghp_0123456789abcdefghijABCDEFGHIJ012345";

    fn proof_of(digest: &str, run: i64) -> Found {
        let mut c = claims();
        c["aud"] = format!("{}{digest}", g::AUDIENCE).into();
        c["run_number"] = run.to_string().into();
        Found { digest: digest.into(), proof: fake_proof(&c) }
    }

    /// Deploys file with the registry holding reg, as the CLI would.
    fn deploy_gh(
        w: &World,
        file: &str,
        reg: Option<std::result::Result<Option<Found>, String>>,
        token: Option<&str>,
    ) -> (String, Result<()>) {
        let app = appfile::parse(file).unwrap();
        let keys = fake_keys();
        let make = |_: String| -> Box<dyn g::Registry> { Box::new(OneProof(Mutex::new(reg.clone().map(|r| r.map_err(|e| errf!("{e}")))))) };
        let gh = GitHub { token: token.map(String::from), make: &make, keys: &keys, rsa: &SaysGood };
        let (out, _, res) = w.run(true, |ctx, c, d, io| deploy(ctx, c, d, None, Some(&gh), &app, &Opts::default(), io));
        (out, res)
    }

    /// The cluster runs shop, built from You/Shop main, image digest.
    fn running(w: &World, digest: &str, ann: serde_json::Value) {
        let mut l: serde_json::Value = serde_json::from_str(&listing(&[("shop", 80, &[])], &w.mark)).unwrap();
        for it in l["items"].as_array_mut().unwrap() {
            if it["kind"] == "Deployment" && it["metadata"]["name"] == "shop" {
                it["spec"]["template"]["spec"]["containers"][0]["image"] = format!("ghcr.io/you/shop@{digest}").into();
                let a = it["metadata"]["annotations"].as_object_mut().unwrap();
                a.insert(g::A_REPO.into(), "You/Shop".into());
                a.insert(g::A_BRANCH.into(), "main".into());
                for (k, v) in ann.as_object().unwrap() {
                    a.insert(k.clone(), v.clone());
                }
            }
        }
        *w.cluster.listing.lock().unwrap() = l.to_string();
    }

    const FILE: &str = "NAME=shop\nREPO=github.com/You/Shop\nPORT=80\n";

    #[test]
    fn the_newest_proved_build_starts() {
        let w = World::new();
        // No token here: said how to get one; nothing sent.
        let (_, res) = deploy_gh(&w, FILE, Some(Ok(Some(proof_of(DIGEST, 1000)))), None);
        assert!(res.unwrap_err().to_string().contains("dryserver app github token"));
        // No build yet: said what to do.
        let (_, res) = deploy_gh(&w, FILE, Some(Ok(None)), Some(TOKEN));
        let e = res.unwrap_err().to_string();
        assert!(e.contains("no build of main on GitHub yet") && e.contains("dryserver app github init"), "{e}");
        // A proof for another branch: refused, nothing applied.
        let mut bad = claims();
        bad["ref"] = "refs/heads/dev".into();
        let (_, res) = deploy_gh(&w, FILE, Some(Ok(Some(Found { digest: DIGEST.into(), proof: fake_proof(&bad) }))), Some(TOKEN));
        assert!(res.unwrap_err().to_string().contains("the branch refs/heads/dev"));
        assert_eq!(w.applies(), 0);
        // The newest build: its image by digest, where it came from, the
        // token for the servers, and a note while the coordinator does not
        // follow GitHub yet.
        let (out, res) = deploy_gh(&w, FILE, Some(Ok(Some(proof_of(DIGEST, 1000)))), Some(TOKEN));
        res.unwrap();
        assert!(out.contains("start it: build 0123456 of main (github.com/You/Shop)"), "{out}");
        assert!(out.contains("the coordinator does not follow GitHub yet"), "{out}");
        let m = w.last_manifest();
        for want in [
            &format!("image: \"ghcr.io/you/shop@{DIGEST}\""),
            "imagePullSecrets:\n        - name: dryserver-ghcr",
            "dryserver/repo: \"You/Shop\"",
            "dryserver/branch: \"main\"",
            "dryserver/repo-id: \"123456\"",
            "dryserver/run: \"1000\"",
            &format!("dryserver/rolling: \"{DIGEST}\""),
            &format!("dryserver/commit: \"{SHA}\""),
        ] {
            assert!(m.contains(want), "missing {want:?}:\n{m}");
        }
        let calls = w.cluster.calls.lock().unwrap().clone();
        assert!(calls.iter().any(|(a, m)| *a == g::PULL_APPLY.join(" ") && m.contains("type: kubernetes.io/dockerconfigjson")));
        assert!(calls.iter().all(|(a, _)| !a.contains(TOKEN)), "the token is never in a command line");
    }

    #[test]
    fn a_running_build_is_kept_unless_a_newer_one_is_proved() {
        let w = World::new();
        let ann = serde_json::json!({g::A_RUN: "2000", g::A_COMMIT: SHA, g::A_REPO_ID: "123456"});
        // The coordinator follows GitHub: no note.
        w.cluster.answers.lock().unwrap().push((
            "get configmap dryserver-github".into(),
            serde_json::json!({"data": {"last": chrono::Utc::now().timestamp().to_string()}}).to_string(),
        ));
        // An older proof: the running build stays, nothing to change.
        running(&w, DIGEST2, ann.clone());
        let (out, res) = deploy_gh(&w, FILE, Some(Ok(Some(proof_of(DIGEST, 1500)))), Some(TOKEN));
        res.unwrap();
        assert!(out.contains("nothing to change") && !out.contains("does not follow"), "{out}");
        assert!(out.contains("(run 1500) is older than the running one (run 2000)"), "a run of before, run again: {out}");
        assert!(w.last_manifest().contains(&format!("ghcr.io/you/shop@{DIGEST2}")));
        // GitHub down: the running build stays, and it is said.
        let (out, res) = deploy_gh(&w, &format!("{FILE}COPIES=2\n"), Some(Err("no answer from ghcr.io".into())), Some(TOKEN));
        res.unwrap();
        assert!(out.contains("GitHub's newest build was not taken (no answer from ghcr.io); the running build stays"), "{out}");
        // A newer one: deployed, the running one into the history.
        let (out, res) = deploy_gh(&w, FILE, Some(Ok(Some(proof_of(DIGEST, 3000)))), Some(TOKEN));
        res.unwrap();
        assert!(out.contains("build   0123456 -> 0123456 of main"), "{out}");
        let m = w.last_manifest();
        assert!(
            m.contains(&format!("ghcr.io/you/shop@{DIGEST}"))
                && m.contains(&format!("dryserver/history: \"2000@{}@{SHA}\"", DIGEST2.trim_start_matches("sha256:"))),
            "{m}"
        );
        // Held back (after a rollback): not deployed.
        running(&w, DIGEST2, serde_json::json!({g::A_RUN: "1000", g::A_HOLD: "3000", g::A_COMMIT: SHA}));
        let (out, res) = deploy_gh(&w, FILE, Some(Ok(Some(proof_of(DIGEST, 3000)))), Some(TOKEN));
        res.unwrap();
        assert!(out.contains("nothing to change"), "{out}");
        // Another repository number: refused.
        running(&w, DIGEST2, serde_json::json!({g::A_RUN: "1000", g::A_REPO_ID: "42", g::A_COMMIT: SHA}));
        let (out, res) = deploy_gh(&w, FILE, Some(Ok(Some(proof_of(DIGEST, 3000)))), Some(TOKEN));
        res.unwrap();
        assert!(out.contains("not taken") && out.contains("made anew") && w.last_manifest().contains(DIGEST2), "{out}");
        // Another repository: remove first.
        running(&w, DIGEST2, serde_json::json!({g::A_RUN: "1000"}));
        let (_, res) = deploy_gh(&w, "NAME=shop\nREPO=github.com/someone/other\nPORT=80\n", Some(Ok(None)), Some(TOKEN));
        assert!(res.unwrap_err().to_string().contains("remove it first"));
    }

    #[test]
    fn what_the_coordinator_did_meanwhile_is_not_undone() {
        let w = World::new();
        running(&w, DIGEST2, serde_json::json!({g::A_RUN: "2000", g::A_COMMIT: SHA, g::A_REPO_ID: "123456"}));
        // While the preview is read, the coordinator deploys build 2500.
        let app = appfile::parse(&format!("{FILE}COPIES=2\n")).unwrap();
        let keys = fake_keys();
        let make = |_: String| -> Box<dyn g::Registry> { Box::new(OneProof(Mutex::new(Some(Ok(Some(proof_of(DIGEST, 3000))))))) };
        let gh = GitHub { token: Some(TOKEN.into()), make: &make, keys: &keys, rsa: &SaysGood };
        let mut out = Vec::new();
        let mut ask = |_: &str| {
            running(&w, DIGEST2, serde_json::json!({g::A_RUN: "2500", g::A_COMMIT: SHA, g::A_REPO_ID: "123456"}));
            true
        };
        let res = deploy(
            &Ctx::new(),
            w.cluster.as_ref(),
            &w.doors,
            None,
            Some(&gh),
            &app,
            &Opts::default(),
            &mut Io { out: &mut out, ask: &mut ask },
        );
        assert!(res.unwrap_err().to_string().contains("the coordinator changed it while the preview was shown"));
        assert_eq!(w.applies(), 0);
    }

    #[test]
    fn a_build_with_new_settings_is_not_taken_back_by_itself() {
        let w = World::new();
        running(&w, DIGEST2, serde_json::json!({g::A_RUN: "2000", g::A_COMMIT: SHA, g::A_REPO_ID: "123456"}));
        // Only the build changes: the coordinator follows it.
        let (_, res) = deploy_gh(&w, FILE, Some(Ok(Some(proof_of(DIGEST, 3000)))), Some(TOKEN));
        res.unwrap();
        assert!(w.last_manifest().contains(&format!("dryserver/rolling: \"{DIGEST}\"")));
        // A setting too: it could not tell which one failed.
        let (out, res) = deploy_gh(&w, &format!("{FILE}ENV=MODE=new\n"), Some(Ok(Some(proof_of(DIGEST, 3000)))), Some(TOKEN));
        res.unwrap();
        assert!(!w.last_manifest().contains("dryserver/rolling"), "{}", w.last_manifest());
        assert!(out.contains("settings change too, so if build 0123456 does not start"), "{out}");
    }

    #[test]
    fn rollback_goes_back_and_holds_newer_builds() {
        let w = World::new();
        let history = format!("1000@{}@{}", DIGEST.trim_start_matches("sha256:"), "f".repeat(40));
        running(&w, DIGEST2, serde_json::json!({g::A_RUN: "2000", g::A_COMMIT: SHA, g::A_HISTORY: history}));
        let (out, asked, res) = w.run(true, |ctx, c, _, io| rollback(ctx, c, "shop", &Opts::default(), io));
        res.unwrap();
        assert_eq!(asked, vec!["Go back? [y/N] "]);
        assert!(out.contains("back from build 0123456 to build fffffff of main") && out.contains("going back to build fffffff"), "{out}");
        let calls = w.cluster.calls.lock().unwrap().clone();
        let p = calls.iter().find(|(a, _)| a.contains("patch deployment shop --type strategic")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&p.1).unwrap();
        let a = &v["metadata"]["annotations"];
        assert_eq!((a[g::A_RUN].as_str(), a[g::A_HOLD].as_str(), a[g::A_HISTORY].as_str()), (Some("1000"), Some("2000"), Some("")));
        assert_eq!(v["spec"]["template"]["spec"]["containers"][0]["image"], format!("ghcr.io/you/shop@{DIGEST}"));
        // Nothing before: said.
        running(&w, DIGEST2, serde_json::json!({g::A_RUN: "2000", g::A_COMMIT: SHA}));
        let (_, _, res) = w.run(true, |ctx, c, _, io| rollback(ctx, c, "shop", &Opts::default(), io));
        assert!(res.unwrap_err().to_string().contains("no build before 0123456"));
        // Not built by GitHub: said.
        w.runs(&[("shop", 80, &[])]);
        let (_, _, res) = w.run(true, |ctx, c, _, io| rollback(ctx, c, "shop", &Opts::default(), io));
        assert!(res.unwrap_err().to_string().contains("not built by GitHub"));
    }

    #[test]
    fn the_workflow_goes_into_the_repository() {
        let t = TempDir::new();
        let mut out = Vec::new();
        let mut ask = |_: &str| true;
        let e = github_init(t.path(), "main", false, &mut Io { out: &mut out, ask: &mut ask }).unwrap_err();
        assert!(e.to_string().contains("not a git repository"));
        std::fs::create_dir_all(t.join(".git")).unwrap();
        std::fs::write(t.join(".git/config"), "[remote \"origin\"]\n\turl = https://github.com/DryBearr/shop.git\n").unwrap();
        github_init(t.path(), "main", false, &mut Io { out: &mut out, ask: &mut ask }).unwrap();
        let text = String::from_utf8(std::mem::take(&mut out)).unwrap();
        assert!(text.contains("REPO=github.com/DryBearr/shop (no IMAGE line)") && text.contains("protect main"), "{text}");
        assert_eq!(std::fs::read_to_string(t.join(g::WORKFLOW)).unwrap(), g::workflow("main"));
        // Again: there already. Changed by hand: refused unless forced.
        github_init(t.path(), "main", false, &mut Io { out: &mut out, ask: &mut ask }).unwrap();
        assert!(String::from_utf8(std::mem::take(&mut out)).unwrap().contains("is there already"));
        std::fs::write(t.join(g::WORKFLOW), "mine").unwrap();
        assert!(github_init(t.path(), "main", false, &mut Io { out: &mut out, ask: &mut ask }).unwrap_err().to_string().contains("-force"));
        github_init(t.path(), "release/v2", true, &mut Io { out: &mut out, ask: &mut ask }).unwrap();
        assert!(std::fs::read_to_string(t.join(g::WORKFLOW)).unwrap().contains("branches: [\"release/v2\"]"));
        assert!(String::from_utf8(out).unwrap().contains("and BRANCH=release/v2"));
        assert!(github_init(t.path(), "bad..name", true, &mut Io { out: &mut Vec::new(), ask: &mut ask }).is_err());
    }

    #[test]
    fn app_files_of_apps_github_builds() {
        let a = appfile::parse("NAME=shop\nREPO=https://github.com/You/Shop.git\nBRANCH=release/v2\nPORT=80\n").unwrap();
        let src = a.source.clone().unwrap();
        assert_eq!((src.full(), src.branch.as_str(), a.image.as_str()), ("You/Shop".into(), "release/v2", "ghcr.io/you/shop"));
        let text = appfile::render(&a);
        assert!(text.contains("REPO=github.com/You/Shop\nBRANCH=release/v2\n") && !text.contains("IMAGE"), "{text}");
        assert_eq!(appfile::parse(&text).unwrap().source, a.source);
        for (text, why) in [
            ("NAME=shop\nREPO=you/shop\nIMAGE=x:1\nPORT=80\n", "leave IMAGE out"),
            ("NAME=shop\nIMAGE=x:1\nBRANCH=main\nPORT=80\n", "only with REPO"),
            ("NAME=shop\nREPO=gitlab.com/you/shop\nPORT=80\n", "a GitHub repository"),
            ("NAME=shop\nREPO=you/shop\nBRANCH=a..b\nPORT=80\n", "a branch name"),
        ] {
            let e = appfile::parse(text).unwrap_err().to_string();
            assert!(e.contains(why), "{text:?}: {e}");
        }
    }
}
