//! `dryserver app ...`: apps from the command line, each kept as a file
//! (appfile.rs). Nothing here needs the screens.
//!
//! - deploy FILE starts or changes the app the file describes. It first
//!   shows every change: to the app, and in Cloudflare. It makes them on
//!   y, and only those: when Cloudflare would now make other changes than
//!   the ones shown, it makes none there and says so.
//! - list shows each app, where it runs, its names and whether each name
//!   answers from the internet (an HTTPS request to it).
//! - show NAME prints the app as a file, to keep or change.
//! - remove NAME stops an app and takes its names out of Cloudflare.
//! - sync makes Cloudflare match the apps (it also sets up the tunnel):
//!   after a deploy whose Cloudflare part failed, or a change by hand.
//! - domains lists the domains the Cloudflare API token can see.
//!
//! Nothing is changed while an app runs that a newer dryserver set up
//! (apps::Running::newer): this one would read its names wrong.

use std::io::Write;
use std::time::Duration;

use crate::apps::{self, App, Cluster, Overview, Running};
use crate::ctx::Ctx;
use crate::entrance::cloudflare::{Cloudflare, TARGET};
use crate::entrance::{self, Entrance, Entrances, Report};
use crate::err::{Error, Kind, Result};
use crate::{appfile, bail, errf, images};

/// How long a look at the cluster or Cloudflare may take.
pub const READ: Duration = Duration::from_secs(30);
/// How long a change may take (Cloudflare's part has many calls).
pub const CHANGE: Duration = Duration::from_secs(180);
/// Names app list asks at the same time, and in all.
const CHECKS_AT_ONCE: usize = 8;
const MAX_CHECKS: usize = 200;

#[derive(Debug, Clone, Default)]
pub struct Opts {
    /// Make the changes without asking.
    pub yes: bool,
    /// Names whose DNS records something else holds, which the admin
    /// lets dryserver take over.
    pub take_over: Vec<String>,
}

/// Where a command writes, and how it asks.
pub struct Io<'a> {
    pub out: &'a mut dyn Write,
    /// A yes or no question; true for yes.
    pub ask: &'a mut dyn FnMut(&str) -> bool,
}

impl Io<'_> {
    fn say(&mut self, s: impl AsRef<str>) {
        let _ = writeln!(self.out, "{}", s.as_ref());
    }
}

/// How a name answered from the internet, in words.
pub type Check<'a> = &'a (dyn Fn(&str) -> String + Sync);

fn timed(e: Error, d: Duration) -> Error {
    if e.is(Kind::DeadlineExceeded) { errf!("no answer within {} seconds: {e}", d.as_secs()) } else { e }
}

/// What the cluster runs now.
fn look(ctx: &Ctx, c: &dyn Cluster) -> Result<Overview> {
    apps::overview(&ctx.with_timeout(READ), c).map_err(|e| timed(e, READ).wrap("the cluster"))
}

/// A newer dryserver set up an app: this one changes nothing.
fn refuse_newer(o: &Overview) -> Result<()> {
    if let Some(a) = o.apps.iter().find(|a| a.newer) {
        bail!(
            "{} was set up by a newer dryserver than this one; update dryserver on this computer first (git pull && make \
             install). Nothing was changed",
            a.name
        );
    }
    Ok(())
}

/// What the cluster runs once app is applied, as far as the entrances
/// care: the app with its names, everything else as it is.
fn after_deploy(now: &Overview, app: &App) -> Overview {
    let mut o = now.clone();
    let at = o.apps.iter().position(|a| a.name == app.name);
    let mut r = at.map(|i| o.apps[i].clone()).unwrap_or_default();
    let mut hosts = app.hosts.clone();
    hosts.sort();
    r = Running {
        name: app.name.clone(),
        image: app.image.clone(),
        copies: app.copies,
        port: app.port,
        hosts,
        entrance: app.entrance.clone(),
        newer: false,
        ..r
    };
    match at {
        Some(i) => o.apps[i] = r,
        None => {
            o.apps.push(r);
            o.apps.sort_by(|a, b| a.name.cmp(&b.name));
        }
    }
    o
}

fn after_remove(now: &Overview, name: &str) -> Overview {
    let mut o = now.clone();
    o.apps.retain(|a| a.name != name);
    o
}

/// The entrances a change touches: the one an app's names came through,
/// and the one they come through now.
fn touched(before: Option<&Running>, app: Option<&App>) -> Vec<String> {
    let mut ids = Vec::new();
    if let Some(b) = before.filter(|b| b.public()) {
        ids.push(b.entrance.clone());
    }
    if let Some(a) = app.filter(|a| !a.hosts.is_empty()) {
        ids.push(a.entrance.clone());
    }
    ids.sort();
    ids.dedup();
    ids
}

/// One entrance's dry run: what its sync would change once the cluster
/// runs after.
struct Look {
    door: usize,
    res: Result<Report>,
}

fn dry_runs(ctx: &Ctx, c: &dyn Cluster, doors: &Entrances, after: &Overview, ids: &[String], take_over: &[String]) -> Vec<Look> {
    let (wants, _) = entrance::wants(&after.apps);
    let mut out = Vec::new();
    for (i, d) in doors.iter().enumerate().filter(|(_, d)| d.automatic() && ids.iter().any(|id| id == d.id())) {
        let mut want = wants.get(d.id()).cloned().unwrap_or_default();
        want.takeover = take_over.to_vec();
        let res = d.sync(&ctx.with_timeout(READ * 2), c, after, &want, true).map_err(|e| timed(e, READ * 2));
        out.push(Look { door: i, res });
    }
    out
}

/// Makes what the dry runs showed, from what the cluster runs now. Says
/// how it went; false when an entrance was not synced.
fn sync_shown(ctx: &Ctx, c: &dyn Cluster, doors: &Entrances, looks: &[Look], take_over: &[String], open: bool, io: &mut Io) -> bool {
    let shown: Vec<(usize, Vec<String>)> =
        looks.iter().filter_map(|l| l.res.as_ref().ok().filter(|r| r.held.is_none()).map(|r| (l.door, r.changes.clone()))).collect();
    if shown.is_empty() {
        return looks.iter().all(|l| l.res.is_ok());
    }
    let now = match look(ctx, c) {
        Ok(o) => o,
        Err(e) => {
            io.say(format!("Cloudflare: not synced, the cluster did not answer: {e}. dryserver app sync makes it."));
            return false;
        }
    };
    let (wants, _) = entrance::wants(&now.apps);
    let mut ok = looks.iter().all(|l| l.res.is_ok());
    for (i, changes) in shown {
        let d = &doors[i];
        if changes.is_empty() {
            continue;
        }
        let mut want = wants.get(d.id()).cloned().unwrap_or_default();
        want.takeover = take_over.to_vec();
        want.confirmed = Some(changes);
        want.open = open;
        match d.sync(&ctx.with_timeout(CHANGE), c, &now, &want, false).map_err(|e| timed(e, CHANGE)) {
            Ok(r) => io.say(format!("{}: {}.", d.title(), r.summary(false))),
            Err(e) => {
                ok = false;
                io.say(format!("{}: not synced: {e}", d.title()));
                io.say("  A sync cut off half way is finished by the next one: dryserver app sync shows what is left.");
            }
        }
    }
    ok
}

/// Prints a dry run. With app: an error when a name of it is held by a
/// record dryserver did not make (and the admin did not let it take that
/// one over), saying what to do.
fn show_look(door: &dyn Entrance, res: &Result<Report>, app: Option<&str>, take_over: &[String], io: &mut Io) -> Result<()> {
    let title = door.title();
    let r = match res {
        Ok(r) => r,
        Err(e) => {
            io.say(format!("{title}: could not look: {e}"));
            io.say("  If you go on, the app changes now and its names are synced later: dryserver app sync.");
            return Ok(());
        }
    };
    if let Some(why) = &r.held {
        io.say(format!("{title}: left as it is: {why}"));
        return Ok(());
    }
    if r.changes.is_empty() {
        io.say(format!("{title}: nothing to change"));
    } else {
        io.say(format!("{title}:"));
        for c in &r.changes {
            io.say(format!("  - {c}"));
        }
    }
    for n in &r.notes {
        io.say(format!("  note: {n}"));
    }
    for c in &r.conflicts {
        io.say(format!("  held by something else: {} ({}) has a {}", c.host, c.app, c.holder));
    }
    let Some(app) = app else { return Ok(()) };
    let held: Vec<&entrance::Conflict> = r.conflicts.iter().filter(|c| c.app == app && !take_over.contains(&c.host)).collect();
    if !held.is_empty() {
        let names: Vec<&str> = held.iter().map(|c| c.host.as_str()).collect();
        bail!(
            "{} {} a DNS record that dryserver did not make, and dryserver leaves it alone. To point {} at {app} \
             instead, run this again with -take-over {} (the change shows first). Nothing was changed",
            names.join(", "),
            if names.len() == 1 { "has" } else { "have" },
            if names.len() == 1 { "it" } else { "them" },
            names.join(",")
        );
    }
    Ok(())
}

/// New names of app that no zone of the token holds: such an app would
/// be half public, so it is not deployed. A name it already had (its
/// domain left the token since) only gets a note from the entrance: the
/// app can still be changed.
fn refuse_unrouted(looks: &[Look], before: Option<&Running>, app: &App) -> Result<()> {
    let names: Vec<String> = app.names().into_iter().filter(|h| !before.is_some_and(|b| b.has(h))).collect();
    let mut missing: Vec<&str> = Vec::new();
    for l in looks {
        if let Ok(r) = &l.res {
            missing.extend(r.unrouted.iter().filter(|h| names.contains(h)).map(String::as_str));
        }
    }
    if !missing.is_empty() {
        bail!(
            "{} {} not in a domain your Cloudflare API token can see. Add the domain to Cloudflare and to the token (Zone \
             Resources), then deploy again (dryserver domains lists what the token sees). Nothing was changed",
            missing.join(", "),
            if missing.len() == 1 { "is" } else { "are" }
        );
    }
    Ok(())
}

/// What changes for the app itself, one line each. Empty: nothing.
fn app_changes(before: Option<&Running>, app: &App) -> (Vec<String>, bool) {
    let mut lines = Vec::new();
    let port_of = |h: &apps::Host, main: u16| if h.port == main { String::new() } else { format!(" (port {})", h.port) };
    let Some(b) = before else {
        lines.push(format!(
            "  start it: {}, port {}, {} {}",
            app.image,
            app.port,
            app.copies,
            if app.copies == 1 { "copy" } else { "copies" }
        ));
        for h in &app.hosts {
            lines.push(format!("  + {}{}", h.name, port_of(h, app.port)));
        }
        if app.hosts.is_empty() {
            lines.push(format!("  inside only: your other apps reach it as http://{}", app.name));
        }
        return (lines, true);
    };
    let mut restart = false;
    if b.image != app.image {
        lines.push(format!("  image   {} -> {}", b.image, app.image));
        restart = true;
    } else if crate::images::is_local(&app.image) && b.image_id != app.image_id {
        let short = |id: &str| id.trim_start_matches("sha256:").chars().take(12).collect::<String>();
        let was = if b.image_id.is_empty() { "?".to_string() } else { short(&b.image_id) };
        lines.push(format!("  image   {} rebuilt: {was} -> {}", app.image, short(&app.image_id)));
        restart = true;
    }
    if b.port != app.port {
        lines.push(format!("  port    {} -> {}", b.port, app.port));
        restart = true;
    }
    if b.copies != app.copies {
        lines.push(format!("  copies  {} -> {}", b.copies, app.copies));
    }
    if !app.hosts.is_empty() && b.public() && b.entrance != app.entrance {
        lines.push(format!("  way in  {} -> {}", b.entrance, app.entrance));
    }
    let mut stay = 0;
    for h in &app.hosts {
        match b.hosts.iter().find(|o| o.name == h.name) {
            None => lines.push(format!("  + {}{}", h.name, port_of(h, app.port))),
            Some(o) if o.port != h.port => lines.push(format!("  {}: port {} -> {}", h.name, o.port, h.port)),
            Some(_) => stay += 1,
        }
    }
    for o in &b.hosts {
        if !app.hosts.iter().any(|h| h.name == o.name) {
            lines.push(format!("  - {} (stops answering)", o.name));
        }
    }
    let old_extra: Vec<u16> = {
        let mut p: Vec<u16> = b.hosts.iter().map(|h| h.port).filter(|p| *p != b.port).collect();
        p.sort_unstable();
        p.dedup();
        p
    };
    if old_extra != app.extra_ports() {
        restart = true;
    }
    if !lines.is_empty() && stay > 0 {
        lines.push(format!(
            "  = {stay} {} as {}",
            if stay == 1 { "name stays" } else { "names stay" },
            if stay == 1 { "it is" } else { "they are" }
        ));
    }
    if !lines.is_empty() {
        lines.push(if restart {
            "  Its copies are replaced one at a time (the image or a port changed).".to_string()
        } else {
            "  The running copies stay as they are.".to_string()
        });
    }
    (lines, restart)
}

/// Asks, unless the admin said yes already.
fn agreed(q: &str, opts: &Opts, io: &mut Io) -> bool {
    opts.yes || (io.ask)(q)
}

/// Starts or changes the app.
/// The desktop's own images and the servers they go to (images.rs).
pub struct Own<'a> {
    pub desk: &'a dyn images::Desk,
    pub servers: &'a dyn images::Servers,
}

/// For an image of the admin's own: which servers still need it, and
/// that every server of the cluster is one dryserver can reach.
fn own_image(ctx: &Ctx, c: &dyn Cluster, own: Option<&Own>, image: &str) -> Result<images::Push> {
    let Some(own) = own else { bail!("{image} is an image of your own, and this computer cannot reach your servers to bring it") };
    let p = images::plan(ctx, own.desk, own.servers, image)?;
    let listed = own.servers.names();
    let missing: Vec<String> = apps::servers(&ctx.with_timeout(READ), c)?.into_iter().filter(|s| !listed.contains(s)).collect();
    if !missing.is_empty() {
        bail!(
            "{} run apps but {} not in your server list, so {image} would not reach {}: run dryserver ssh-config, then again",
            missing.join(", "),
            if missing.len() == 1 { "is" } else { "are" },
            if missing.len() == 1 { "it" } else { "them" }
        );
    }
    Ok(p)
}

/// Copies an image of the admin's own to every server that lacks it.
pub fn push(ctx: &Ctx, c: &dyn Cluster, own: &Own, image: &str, opts: &Opts, io: &mut Io) -> Result<()> {
    let p = own_image(ctx, c, Some(own), image)?;
    io.say(p.line());
    if p.todo.is_empty() {
        return Ok(());
    }
    if !agreed("Copy it? [y/N] ", opts, io) {
        io.say("Nothing copied.");
        return Ok(());
    }
    let now = chrono::Utc::now().timestamp();
    images::send(ctx, own.desk, own.servers, &p, now, &mut |l| io.say(l))?;
    io.say(format!("{image} is on every server."));
    Ok(())
}

pub fn deploy(ctx: &Ctx, c: &dyn Cluster, doors: &Entrances, own: Option<&Own>, app: &App, opts: &Opts, io: &mut Io) -> Result<()> {
    let mut app = app.clone();
    app.hosts.sort();
    if app.hosts.is_empty() {
        app.entrance = entrance::DEFAULT.into();
    }
    app.validate()?;
    let take_over = clean_names(&opts.take_over)?;
    if let Some(h) = take_over.iter().find(|h| !app.hosts.iter().any(|a| a.name == **h)) {
        bail!("-take-over {h}: {h} is not a name of {}", app.name);
    }
    if !app.hosts.is_empty() {
        match doors.iter().find(|d| d.id() == app.entrance) {
            None => bail!("ENTRANCE {}: this dryserver does not know it", app.entrance),
            Some(d) if !d.ready() => bail!("ENTRANCE {}: {} is not set up yet, so its names would not be served", app.entrance, d.title()),
            Some(_) => {}
        }
    }
    let now = look(ctx, c)?;
    refuse_newer(&now)?;
    entrance::check_host(&app, &now.apps)?;
    // An image of the admin's own goes to the servers first; its build
    // is what the app runs.
    let push = if images::is_local(&app.image) {
        let p = own_image(ctx, c, own, &app.image)?;
        app.image_id = p.local.id.clone();
        Some(p)
    } else {
        None
    };
    let before = now.apps.iter().find(|a| a.name == app.name);
    let (lines, _) = app_changes(before, &app);
    let after = after_deploy(&now, &app);
    let ids = touched(before, Some(&app));
    let looks = dry_runs(ctx, c, doors, &after, &ids, &take_over);
    refuse_unrouted(&looks, before, &app)?;

    let cf_changes = looks.iter().any(|l| l.res.as_ref().is_ok_and(|r| !r.changes.is_empty() && r.held.is_none()));
    let copies = push.as_ref().is_some_and(|p| !p.todo.is_empty());
    if lines.is_empty() && !cf_changes && !copies && looks.iter().all(|l| l.res.is_ok()) {
        // Nothing that dryserver reads back differs; the objects are
        // applied again all the same, which changes nothing when they are
        // as the file says and puts back what was changed by hand or left
        // half applied (a service port, a wall).
        for l in &looks {
            if let Ok(r) = &l.res
                && let Some(why) = &r.held
            {
                io.say(format!("{}: left as it is: {why}", doors[l.door].title()));
            }
        }
        apps::deploy(&ctx.with_timeout(CHANGE), c, &app).map_err(|e| timed(e, CHANGE).wrap(format!("{} was not applied", app.name)))?;
        io.say(format!("{}: nothing to change (applied again, as the file says).", app.name));
        return Ok(());
    }
    io.say(format!("{}{}:", app.name, if before.is_none() { " (new)" } else { "" }));
    if lines.is_empty() {
        io.say("  no change to the app itself");
    }
    for l in &lines {
        io.say(l);
    }
    if let Some(p) = &push {
        io.say(format!("  {}", p.line()));
    }
    for l in &looks {
        show_look(doors[l.door].as_ref(), &l.res, Some(&app.name), &take_over, io)?;
    }
    by_hand(doors, before, Some(&app), io);
    if !agreed("Apply? [y/N] ", opts, io) {
        io.say("Nothing changed.");
        return Ok(());
    }
    if let (Some(p), Some(own)) = (&push, own) {
        let now = chrono::Utc::now().timestamp();
        images::send(ctx, own.desk, own.servers, p, now, &mut |l| io.say(l))
            .map_err(|e| e.wrap(format!("{} was not applied, nothing changed in the cluster", app.name)))?;
    }
    apps::deploy(&ctx.with_timeout(CHANGE), c, &app).map_err(|e| {
        timed(e, CHANGE).wrap(format!("{} was not applied (part of it may have reached the cluster: dryserver app list)", app.name))
    })?;
    io.say(format!("{}: applied. The cluster starts what changed now.", app.name));
    if !sync_shown(ctx, c, doors, &looks, &take_over, false, io) {
        bail!("{} runs, but Cloudflare is not in step yet (see above): dryserver app sync", app.name);
    }
    if !app.hosts.is_empty() {
        io.say("Whether each name answers: dryserver app list");
    }
    Ok(())
}

/// Without an API token the tunnel's names are routed in the dashboard:
/// say which names to add there and which to take away.
fn by_hand(doors: &Entrances, before: Option<&Running>, app: Option<&App>, io: &mut Io) {
    let Some(cf) = doors.iter().find(|d| d.id() == entrance::CLOUDFLARE && !d.automatic()) else { return };
    let was: Vec<&str> = before.filter(|b| b.entrance == cf.id()).map(|b| b.names()).unwrap_or_default();
    let now: Vec<String> = app.filter(|a| a.entrance == cf.id()).map(|a| a.names()).unwrap_or_default();
    let add: Vec<&str> = now.iter().map(String::as_str).filter(|h| !was.contains(h)).collect();
    let drop: Vec<&str> = was.iter().copied().filter(|h| !now.iter().any(|n| n == h)).collect();
    if add.is_empty() && drop.is_empty() {
        return;
    }
    io.say(format!("{} (no API token on this computer, so its names are routed by hand):", cf.title()));
    if !add.is_empty() {
        io.say(format!(
            "  in the dashboard (Zero Trust, Networks, Tunnels, your tunnel, Public Hostname) add {} with the service {TARGET}",
            add.join(", ")
        ));
    }
    if !drop.is_empty() {
        io.say(format!("  and remove {} there", drop.join(", ")));
    }
}

fn clean_names(names: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for n in names.iter().flat_map(|n| n.split(',')).map(str::trim).filter(|n| !n.is_empty()) {
        out.push(apps::clean_host(n).map_err(|e| e.wrap("-take-over"))?);
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Stops an app and takes its names out of Cloudflare.
pub fn remove(ctx: &Ctx, c: &dyn Cluster, doors: &Entrances, name: &str, opts: &Opts, io: &mut Io) -> Result<()> {
    apps::valid_app_name(name).map_err(|e| e.wrap("name"))?;
    let now = look(ctx, c)?;
    refuse_newer(&now)?;
    let Some(before) = now.apps.iter().find(|a| a.name == name) else {
        bail!("no app named {name} runs (dryserver app list shows them)");
    };
    io.say(format!("Remove {name}?"));
    let on = if before.nodes.is_empty() { String::new() } else { format!(" on {}", before.nodes.join(", ")) };
    io.say(format!("  its containers stop{on}; what they keep inside them is lost"));
    io.say(format!("  your other apps no longer reach http://{name}"));
    let shared: Vec<&str> = before.names().into_iter().filter(|h| now.apps.iter().any(|o| o.name != name && o.has(h))).collect();
    let own: Vec<&str> = before.names().into_iter().filter(|h| !shared.contains(h)).collect();
    if !own.is_empty() {
        io.say(format!("  {} {} answering from outside", own.join(", "), if own.len() == 1 { "stops" } else { "stop" }));
    }
    for h in &shared {
        io.say(format!("  {h} is claimed by another app too, which then gets it"));
    }
    let after = after_remove(&now, name);
    let looks = dry_runs(ctx, c, doors, &after, &touched(Some(before), None), &[]);
    for l in &looks {
        show_look(doors[l.door].as_ref(), &l.res, None, &[], io)?;
    }
    by_hand(doors, Some(before), None, io);
    if !agreed("Remove? [y/N] ", opts, io) {
        io.say("Nothing removed.");
        return Ok(());
    }
    apps::remove(&ctx.with_timeout(CHANGE), c, name)
        .map_err(|e| timed(e, CHANGE).wrap(format!("{name} was not removed (part of it may be gone: dryserver app list)")))?;
    io.say(format!("{name}: removed."));
    if !sync_shown(ctx, c, doors, &looks, &[], false, io) {
        bail!("{name} is gone, but Cloudflare is not in step yet (see above): dryserver app sync");
    }
    Ok(())
}

/// Makes every entrance that syncs by itself match the apps, after
/// showing what that changes. Sets up the tunnel when it is not there.
pub fn sync(ctx: &Ctx, c: &dyn Cluster, doors: &Entrances, opts: &Opts, io: &mut Io) -> Result<()> {
    let take_over = clean_names(&opts.take_over)?;
    let now = look(ctx, c)?;
    refuse_newer(&now)?;
    let (wants, problems) = entrance::wants(&now.apps);
    for p in &problems {
        io.say(format!("note: {p}"));
    }
    let mut looks = Vec::new();
    for (i, d) in doors.iter().enumerate().filter(|(_, d)| d.automatic()) {
        let mut want = wants.get(d.id()).cloned().unwrap_or_default();
        want.takeover = take_over.clone();
        want.open = true;
        let res = d.sync(&ctx.with_timeout(READ * 2), c, &now, &want, true).map_err(|e| timed(e, READ * 2));
        looks.push(Look { door: i, res });
    }
    if looks.is_empty() {
        io.say("No entrance here syncs by itself: without a Cloudflare API token on this computer, the names are routed in the dashboard.");
        let names: Vec<String> =
            wants.get(entrance::CLOUDFLARE).map(|w| w.names.iter().map(|n| n.host.clone()).collect()).unwrap_or_default();
        if !names.is_empty() {
            io.say(format!("Point each of {} at {TARGET} there.", names.join(", ")));
        }
        return Ok(());
    }
    for l in &looks {
        show_look(doors[l.door].as_ref(), &l.res, None, &take_over, io)?;
    }
    if let Some(e) = looks.iter().find_map(|l| l.res.as_ref().err()) {
        bail!("not synced: {e}");
    }
    let todo = looks.iter().any(|l| l.res.as_ref().is_ok_and(|r| !r.changes.is_empty() && r.held.is_none()));
    if !todo {
        return Ok(());
    }
    if !agreed("Make these changes? [y/N] ", opts, io) {
        io.say("Nothing changed.");
        return Ok(());
    }
    if !sync_shown(ctx, c, doors, &looks, &take_over, true, io) {
        bail!("not everything was synced (see above)");
    }
    Ok(())
}

/// Prints the app as a file.
pub fn show(ctx: &Ctx, c: &dyn Cluster, name: &str, io: &mut Io) -> Result<()> {
    apps::valid_app_name(name).map_err(|e| e.wrap("name"))?;
    let now = look(ctx, c)?;
    let Some(r) = now.apps.iter().find(|a| a.name == name) else {
        bail!("no app named {name} runs (dryserver app list shows them)");
    };
    if r.newer {
        bail!("{name} was set up by a newer dryserver; show it with that one");
    }
    if r.copies == 0 {
        bail!("{name} is scaled to 0 copies (by hand, with kubectl); an app file has 1 to 20. Scale it up first, or write its file anew");
    }
    let Some(app) = App::of(r) else {
        bail!(
            "{name} runs, but its objects do not say all an app file needs (its port, or an image that checks out); it was not made by dryserver"
        );
    };
    let _ = write!(io.out, "{}", appfile::render(&app));
    Ok(())
}

/// Every app, where it runs, its names and how each answers.
pub fn list(ctx: &Ctx, c: &dyn Cluster, doors: &Entrances, check: Option<Check>, io: &mut Io) -> Result<()> {
    let now = look(ctx, c)?;
    if now.apps.is_empty() {
        io.say("No app runs yet. Write an app file and start it: dryserver app deploy FILE (see docs/apps.md).");
        return Ok(());
    }
    let (_, problems) = entrance::wants(&now.apps);
    let all: Vec<&str> = now.apps.iter().flat_map(|a| a.names()).collect();
    let answers: Vec<String> = match check {
        // A few at a time, and not without end: the names come from the
        // cluster.
        Some(check) => all
            .iter()
            .enumerate()
            .collect::<Vec<_>>()
            .chunks(CHECKS_AT_ONCE)
            .flat_map(|chunk| {
                std::thread::scope(|s| {
                    let hs: Vec<_> = chunk
                        .iter()
                        .map(|(i, h)| {
                            let h = **h;
                            let i = *i;
                            s.spawn(move || if i < MAX_CHECKS { check(h) } else { "not checked (too many names)".into() })
                        })
                        .collect();
                    hs.into_iter().map(|h| h.join().unwrap_or_else(|_| "not checked".into())).collect::<Vec<_>>()
                })
            })
            .collect(),
        None => all.iter().map(|_| String::new()).collect(),
    };
    let mut answer = all.iter().zip(answers);
    for a in &now.apps {
        let state = match (a.ready, a.copies) {
            (_, 0) => "stopped".to_string(),
            (r, c) => format!("{r} of {c} running"),
        };
        let on = if a.nodes.is_empty() { "on no server yet".to_string() } else { format!("on {}", a.nodes.join(", ")) };
        let newer = if a.newer { "  (set up by a newer dryserver)" } else { "" };
        io.say(format!("{}  {state}  {on}  {}{newer}", a.name, a.image));
        if !a.public() {
            io.say("    inside only");
        }
        let way = doors.iter().find(|d| d.id() == a.entrance).map(|d| d.title()).unwrap_or("an unknown way in");
        for h in &a.hosts {
            let (_, said) = answer.next().unwrap_or((&"", String::new()));
            let port = if h.port == a.port { String::new() } else { format!(" -> port {}", h.port) };
            let said = if said.is_empty() { String::new() } else { format!("  {said}") };
            io.say(format!("    {}{port}  through {way}{said}", h.name));
        }
    }
    for p in &problems {
        io.say(format!("note: {p}"));
    }
    Ok(())
}

/// The domains the Cloudflare API token can see, and the apps' names in
/// each.
pub fn domains(ctx: &Ctx, c: &dyn Cluster, cf: &Cloudflare, io: &mut Io) -> Result<()> {
    let Some(zones) = cf.zones(&ctx.with_timeout(READ)).map_err(|e| timed(e, READ))? else {
        bail!(
            "no Cloudflare API token on this computer ({}); without one, names are routed in the Cloudflare dashboard",
            cf.api_token_file.display()
        );
    };
    let apps = match look(ctx, c) {
        Ok(o) => Some(o.apps),
        Err(e) => {
            io.say(format!("(the cluster did not answer, so the apps' names are not shown: {e})"));
            None
        }
    };
    let names: Vec<(String, String)> =
        apps.iter().flatten().flat_map(|a| a.hosts.iter().map(|h| (h.name.clone(), a.name.clone()))).collect();
    let zone_of = |h: &str| zones.iter().filter(|z| h == z.name || h.ends_with(&format!(".{}", z.name))).max_by_key(|z| z.name.len());
    for z in &zones {
        let state = match z.status.as_str() {
            "active" => "active".to_string(),
            "pending" => "pending: at the company you bought it from, set its nameservers to the two Cloudflare shows".into(),
            other => other.to_string(),
        };
        io.say(format!("{}  {state}", z.name));
        for (h, app) in names.iter().filter(|(h, _)| zone_of(h).is_some_and(|x| x.id == z.id)) {
            let deep = if entrance::cfsync::deep(h, &z.name) {
                "  (two levels deep: Cloudflare's free certificate does not cover it)"
            } else {
                ""
            };
            io.say(format!("    {h} ({app}){deep}"));
        }
    }
    let outside: Vec<String> = names.iter().filter(|(h, _)| zone_of(h).is_none()).map(|(h, a)| format!("{h} ({a})")).collect();
    if !outside.is_empty() {
        io.say(format!("Not in any domain the token sees: {}", outside.join(", ")));
    }
    if zones.is_empty() {
        io.say("The token sees no domain.");
    }
    Ok(())
}

#[cfg(test)]
mod tests;
