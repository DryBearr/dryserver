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
    let mut items = vec![format!(
        r#"{{"kind":"Deployment","metadata":{{"name":"cloudflared","namespace":"edge","labels":{{"app":"cloudflared"}}}},"spec":{{"replicas":2,"template":{{"metadata":{{"annotations":{{"dryserver/token-mark":"{mark}"}}}}}}}},"status":{{"readyReplicas":2}}}}"#
    )];
    for (name, port, hosts) in apps {
        items.push(format!(
            r#"{{"kind":"Deployment","metadata":{{"name":"{name}","namespace":"apps","labels":{{"app":"{name}"}},"annotations":{{"dryserver/format":"2"}}}},"spec":{{"replicas":1,"template":{{"spec":{{"containers":[{{"image":"{name}:v1","ports":[{{"containerPort":{port}}}]}}]}}}}}},"status":{{"readyReplicas":1}}}}"#
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
        let (out, _, res) = self.run(yes, |ctx, c, d, io| deploy(ctx, c, d, &app, &opts, io));
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
    let (out, _, res) = w.run(true, |ctx, c, d, io| deploy(ctx, c, d, &appfile::parse(SHOP).unwrap(), &Opts::default(), io));
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
        listing(&[("shop", 80, &[("shop.example.com", 80)])], &w.mark).replace("\"dryserver/format\":\"2\"", "\"dryserver/format\":\"3\"");
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
