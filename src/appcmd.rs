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
use crate::{appfile, bail, errf, github, images};

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
    let port_text = |p: u16| if p == apps::NO_PORT { "no port".to_string() } else { format!("port {p}") };
    let Some(b) = before else {
        let what = match &app.source {
            Some(src) => format!("build {} of {} ({})", app.gh.commit.get(..7).unwrap_or("?"), src.branch, src.text()),
            None => app.image.clone(),
        };
        lines.push(format!(
            "  start it: {}, {}, {} {}",
            what,
            port_text(app.port),
            app.copies,
            if app.copies == 1 { "copy" } else { "copies" }
        ));
        for h in &app.hosts {
            lines.push(format!("  + {}{}", h.name, port_of(h, app.port)));
        }
        if app.hosts.is_empty() {
            if app.port == apps::NO_PORT {
                lines.push("  listens on no port: nothing reaches it".into());
            } else {
                lines.push(format!("  inside only: your other apps reach it as http://{}", app.name));
            }
        }
        lines.push(format!(
            "  each copy: up to {} memory, {} CPU",
            apps::memory_text(app.run.memory_mib),
            apps::cpu_text(app.run.cpu_milli)
        ));
        for (k, _) in &app.run.env {
            lines.push(format!("  ENV {k}"));
        }
        for k in &app.run.secrets {
            lines.push(format!("  SECRET {k}"));
        }
        return (lines, true);
    };
    let mut restart = false;
    // Settings, secrets and limits are in the copies' template: any change
    // replaces the copies (one at a time).
    let (br, ar) = (&b.run, &app.run);
    if (br.memory_mib, br.cpu_milli) != (ar.memory_mib, ar.cpu_milli) {
        let was = if br.memory_mib == 0 {
            "no limit".to_string()
        } else {
            format!("{} memory, {} CPU", apps::memory_text(br.memory_mib), apps::cpu_text(br.cpu_milli.max(1)))
        };
        lines.push(format!("  limits  {was} -> {} memory, {} CPU", apps::memory_text(ar.memory_mib), apps::cpu_text(ar.cpu_milli)));
        restart = true;
    }
    for (k, v) in &ar.env {
        match br.env.iter().find(|(x, _)| x == k) {
            None => lines.push(format!("  + ENV {k}")),
            Some((_, old)) if old != v => lines.push(format!("  ~ ENV {k} (new value)")),
            Some(_) => {}
        }
    }
    for (k, _) in &br.env {
        if !ar.env.iter().any(|(x, _)| x == k) {
            lines.push(format!("  - ENV {k}"));
        }
    }
    for k in &ar.secrets {
        if !br.secrets.contains(k) {
            lines.push(format!("  + SECRET {k}"));
        }
    }
    for k in &br.secrets {
        if !ar.secrets.contains(k) {
            lines.push(format!("  - SECRET {k}"));
        }
    }
    if br.env != ar.env || br.secrets != ar.secrets {
        restart = true;
    }
    if !ar.secrets.is_empty() && br.secrets_version != ar.secrets_version {
        lines.push("  ~ secrets: a value changed since the copies started".into());
        restart = true;
    }
    if let Some(src) = &app.source
        && b.image != app.image
    {
        let was = b.gh.commit.get(..7).unwrap_or("?");
        let new = app.gh.commit.get(..7).unwrap_or("?");
        lines.push(format!("  build   {was} -> {new} of {}", src.branch));
        restart = true;
    } else if b.image != app.image {
        lines.push(format!("  image   {} -> {}", b.image, app.image));
        restart = true;
    } else if crate::images::is_local(&app.image) && b.image_id != app.image_id {
        let short = |id: &str| id.trim_start_matches("sha256:").chars().take(12).collect::<String>();
        let was = if b.image_id.is_empty() { "?".to_string() } else { short(&b.image_id) };
        lines.push(format!("  image   {} rebuilt: {was} -> {}", app.image, short(&app.image_id)));
        restart = true;
    }
    if b.port != app.port {
        lines.push(format!(
            "  port    {} -> {}",
            port_text(b.port).trim_start_matches("port "),
            port_text(app.port).trim_start_matches("port ")
        ));
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
            "  Its copies are replaced one at a time (the image, a port, a setting or a limit changed).".to_string()
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

/// What this computer needs to deploy an app GitHub builds: the token
/// (classic, read:packages only) and the ways to check GitHub's proof.
pub struct GitHub<'a> {
    pub token: Option<String>,
    pub make: &'a dyn Fn(String) -> Box<dyn github::Registry>,
    pub keys: &'a dyn github::Keys,
    pub rsa: &'a dyn github::Rsa,
}

/// Whether the coordinator follows GitHub: it wrote its sign of life in
/// the last ten minutes.
fn follows(ctx: &Ctx, c: &dyn Cluster, now: i64) -> bool {
    let out = c
        .kubectl(
            &ctx.with_timeout(READ),
            &["-n", apps::NAMESPACE, "get", "configmap", github::HEARTBEAT, "-o", "json", "--ignore-not-found"],
            "",
        )
        .unwrap_or_default();
    let last =
        serde_json::from_str::<serde_json::Value>(&out).ok().and_then(|v| v["data"]["last"].as_str().and_then(|l| l.parse::<i64>().ok()));
    last.is_some_and(|l| now - l < 600)
}

/// Picks the build an app GitHub builds runs with: the newest one GitHub
/// proved, unless the app runs a newer one or that one is held back
/// (a rollback). Without an answer from GitHub, the running build stays.
/// Sets the app's image and build state; returns notes for the preview.
fn pick_build(ctx: &Ctx, gh: Option<&GitHub>, now: &crate::apps::Overview, app: &mut App) -> Result<Vec<String>> {
    let Some(src) = app.source.clone() else { return Ok(Vec::new()) };
    let Some(g) = gh else { bail!("{} is built by GitHub, and this computer cannot ask GitHub", app.name) };
    let Some(token) = g.token.clone() else {
        bail!("no GitHub token on this computer yet: dryserver app github token (a classic token with only read:packages)");
    };
    let running = now.apps.iter().find(|a| a.name == app.name);
    let rgh = running.map(|r| r.gh.clone()).unwrap_or_default();
    if let (Some(r), Some(rs)) = (running, &rgh.source)
        && !rs.full().eq_ignore_ascii_case(&src.full())
    {
        bail!(
            "{} runs builds of {}; to build it from {} instead, remove it first (dryserver app remove {}): its build history belongs to the other repository",
            r.name,
            rs.text(),
            src.text(),
            r.name
        );
    }
    let running_digest = running.and_then(|r| r.image.rsplit_once('@')).map(|(_, d)| d.to_string()).filter(|d| github::valid_digest(d));
    // Another branch starts its own line of builds.
    let same_branch = rgh.source.as_ref().is_some_and(|s| s.branch == src.branch);
    let (run, hold) = if same_branch { (rgh.run, rgh.hold) } else { (0, 0) };
    let keep = |app: &mut App| {
        if let (Some(d), true) = (&running_digest, same_branch) {
            app.image = format!("{}@{d}", src.image());
            // A rollout the coordinator follows stays followed.
            app.gh = github::State { watch: None, ..rgh.clone() };
            true
        } else {
            false
        }
    };
    let pin = Some(rgh.repo_id.as_str()).filter(|p| !p.is_empty());
    let reg = (g.make)(token);
    let mut notes = Vec::new();
    match github::newest(&ctx.with_timeout(READ), reg.as_ref(), g.keys, g.rsa, &src, pin) {
        Ok(Some(b)) if b.run > run && b.run > hold => {
            let history = match &running_digest {
                Some(d) if same_branch => github::history_after(&rgh, d),
                _ => Vec::new(),
            };
            app.image = format!("{}@{}", src.image(), b.digest);
            // The coordinator follows the copies and says when they run.
            let rolling = b.digest.clone();
            app.gh = github::State {
                source: Some(src.clone()),
                repo_id: b.repo_id,
                run: b.run,
                commit: b.commit,
                hold,
                history,
                rolling,
                ..Default::default()
            };
        }
        Ok(Some(b)) => {
            if !keep(app) {
                bail!("{}: GitHub's newest build of {} is held back here; nothing to start", app.name, src.branch);
            }
            if b.run < run {
                notes.push(format!(
                    "  note: the registry's build {} (run {}) is older than the running one (run {run}): a run of before was run \
                     again; the running build stays",
                    b.short(),
                    b.run
                ));
            } else if b.run <= hold && b.run > run {
                notes.push(format!("  note: build {} is held back (a rollback, or it did not start); the next push deploys", b.short()));
            }
        }
        Ok(None) => {
            if !keep(app) {
                bail!(
                    "no build of {} on GitHub yet. In the app's repository: dryserver app github init, commit the workflow, push to {}; when GitHub \
                     has built it (Actions tab), deploy again",
                    src.branch,
                    src.branch
                );
            }
        }
        Err(e) => {
            if !keep(app) {
                return Err(e.wrap(format!("{}'s newest build", app.name)));
            }
            notes.push(format!("  note: GitHub's newest build was not taken ({e}); the running build stays"));
        }
    }
    Ok(notes)
}

/// Goes back to the build before the running one, and holds back what
/// came after until the next push.
pub fn rollback(ctx: &Ctx, c: &dyn Cluster, name: &str, opts: &Opts, io: &mut Io) -> Result<()> {
    apps::valid_app_name(name).map_err(|e| e.wrap("name"))?;
    let now = look(ctx, c)?;
    refuse_newer(&now)?;
    let Some(r) = now.apps.iter().find(|a| a.name == name) else { bail!("no app named {name} runs (dryserver app list shows them)") };
    let Some(src) = r.gh.source.clone() else {
        bail!("{name} is not built by GitHub; to go back, deploy its file with the image you want");
    };
    let Some((t, digest, commit)) = r.gh.history.first().cloned() else {
        bail!("{name} has no build before {} to go back to", r.gh.commit.get(..7).unwrap_or("this one"));
    };
    io.say(format!(
        "{name}: back from build {} to build {} of {}. Newer builds wait until the next push to {}.",
        r.gh.commit.get(..7).unwrap_or("?"),
        &commit[..7],
        src.branch,
        src.branch
    ));
    if !agreed("Go back? [y/N] ", opts, io) {
        io.say("Nothing changed.");
        return Ok(());
    }
    let rest: Vec<String> = r.gh.history.iter().skip(1).map(|(t, d, c)| format!("{t}@{}@{c}", d.trim_start_matches("sha256:"))).collect();
    let patch = serde_json::json!({
        "metadata": {"annotations": {
            github::A_RUN: t.to_string(),
            github::A_COMMIT: commit,
            github::A_HOLD: r.gh.run.max(r.gh.hold).to_string(),
            github::A_HISTORY: rest.join(","),
            github::A_ROLLING: digest,
        }},
        "spec": {"template": {"spec": {"containers": [{"name": name, "image": format!("{}@{digest}", src.image())}]}}}
    })
    .to_string();
    c.kubectl(
        &ctx.with_timeout(CHANGE),
        &["-n", apps::NAMESPACE, "patch", "deployment", name, "--type", "strategic", "--patch-file", "/dev/stdin"],
        &patch,
    )
    .map_err(|e| timed(e, CHANGE).wrap(format!("{name} did not go back")))?;
    io.say(format!("{name}: going back to build {}; its copies are replaced one at a time.", &commit[..7]));
    Ok(())
}

/// Writes the build workflow into the app's repository at dir.
pub fn github_init(dir: &std::path::Path, branch: &str, force: bool, io: &mut Io) -> Result<()> {
    if !github::valid_branch(branch) {
        bail!("{branch}: a branch name, like main");
    }
    if !dir.join(".git").exists() {
        bail!("{} is not a git repository (no .git there): run this in your app's repository, or name it with -dir", dir.display());
    }
    let path = dir.join(github::WORKFLOW);
    let text = github::workflow(branch);
    match std::fs::read_to_string(&path) {
        Ok(old) if old == text => io.say(format!("{} is there already, as dryserver writes it.", github::WORKFLOW)),
        Ok(_) if !force => bail!("{} is there, and differs from dryserver's; -force writes dryserver's over it", path.display()),
        _ => {
            crate::fsx::mkdir_all(path.parent().unwrap_or(dir), 0o755)?;
            let tmp = path.with_extension("yml.tmp");
            let _ = std::fs::remove_file(&tmp);
            crate::fsx::write_new(&tmp, &text, 0o644)?;
            crate::fsx::rename(&tmp, &path)?;
            io.say(format!("Wrote {}: every push to {branch} builds the app on GitHub and proves it.", github::WORKFLOW));
        }
    }
    // Where it is on GitHub, from git's own config: the REPO line to use.
    let config = std::fs::read_to_string(dir.join(".git/config")).unwrap_or_default();
    let mut origin = false;
    let mut repo = None;
    for l in config.lines() {
        let t = l.trim();
        if t.starts_with('[') {
            origin = t == "[remote \"origin\"]";
        } else if origin && let Some(u) = t.strip_prefix("url").map(|r| r.trim_start().trim_start_matches('=').trim()) {
            repo = github::Source::parse(u, branch).ok();
        }
    }
    io.say("Next:");
    io.say(format!("  1. git add {} && git commit -m \"build with dryserver\" && git push", github::WORKFLOW));
    io.say("  2. once: dryserver app github token (a classic GitHub token with only read:packages)");
    match repo {
        Some(r) => io.say(format!(
            "  3. in the app file: REPO={}{} (no IMAGE line), then: dryserver app deploy FILE",
            r.text(),
            if branch == "main" { String::new() } else { format!(" and BRANCH={branch}") }
        )),
        None => io.say("  3. in the app file: REPO=github.com/YOU/REPO (no IMAGE line), then: dryserver app deploy FILE"),
    }
    io.say(format!("  On GitHub, protect {branch} (Settings, Branches): whoever can push to it can deploy."));
    Ok(())
}

/// Checks a GitHub token, keeps it on this computer (store) and in the
/// cluster (when it answers) for the servers to pull with.
pub fn github_token(
    ctx: &Ctx,
    c: &dyn Cluster,
    run: &dyn crate::runner::Runner,
    token: &str,
    store: &std::path::Path,
    io: &mut Io,
) -> Result<()> {
    let token = token.trim();
    github::valid_token(token)?;
    let (login, scopes) = github::token_info(&ctx.with_timeout(READ), run, token)?;
    if !scopes.iter().any(|s| s == "read:packages" || s == "write:packages") {
        bail!(
            "that token cannot read packages (its scopes: {}); make a classic token with read:packages",
            if scopes.is_empty() { "none".to_string() } else { scopes.join(", ") }
        );
    }
    let more: Vec<&String> = scopes.iter().filter(|s| *s != "read:packages").collect();
    if !more.is_empty() {
        io.say(format!(
            "note: this token can do more than read packages ({}); one with only read:packages is safer, since the cluster keeps it",
            more.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        ));
    }
    if let Some(dir) = store.parent() {
        crate::fsx::mkdir_all(dir, 0o700)?;
    }
    let tmp = store.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    crate::fsx::write_new(&tmp, format!("{token}\n"), 0o600)?;
    crate::fsx::rename(&tmp, store)?;
    io.say(format!("The token of {login} is kept in {} (yours alone).", store.display()));
    match c.kubectl(&ctx.with_timeout(CHANGE), &github::PULL_APPLY, &github::pull_secret(token)) {
        Ok(_) => io.say("The cluster has it too: the servers pull your apps' images with it."),
        Err(e) => io.say(format!("The cluster does not have it yet ({e}); the next app deploy brings it.")),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn deploy(
    ctx: &Ctx,
    c: &dyn Cluster,
    doors: &Entrances,
    own: Option<&Own>,
    gh: Option<&GitHub>,
    app: &App,
    opts: &Opts,
    io: &mut Io,
) -> Result<()> {
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
    // Its secrets: every name the file lists must have a value in the
    // cluster before the app starts with it; the copies note the values'
    // version, so a new value replaces them.
    if !app.run.secrets.is_empty() {
        let s = secret_state(ctx, c, &app.name)?;
        let missing: Vec<&str> = app.run.secrets.iter().filter(|k| !s.keys.contains(k)).map(String::as_str).collect();
        if !missing.is_empty() {
            bail!(
                "{} has no value for {} yet. Set {}: dryserver app secret {} NAME (it asks for the value). Nothing was changed",
                app.name,
                missing.join(", "),
                if missing.len() == 1 { "it" } else { "each" },
                app.name
            );
        }
        app.run.secrets_version = s.version;
    }
    // An app GitHub builds: which build it runs.
    let gh_notes = pick_build(ctx, gh, &now, &mut app)?;
    app.validate()?;
    let before = now.apps.iter().find(|a| a.name == app.name);
    let (mut lines, _) = app_changes(before, &app);
    lines.extend(gh_notes);
    // A build the coordinator follows, and takes back when it does not
    // start: only when the build is all that changes. With settings
    // changed too, it could not tell which of them failed.
    if let Some(b) = before
        && !app.gh.rolling.is_empty()
        && App::of(b).is_none_or(|o| o.run != app.run || o.port != app.port)
    {
        app.gh.rolling.clear();
        lines.push(format!(
            "  note: settings change too, so if build {} does not start the coordinator does not take it back by itself (dryserver \
             app rollback does)",
            app.gh.commit.get(..7).unwrap_or("?")
        ));
    }
    if app.source.is_some() && !follows(ctx, c, chrono::Utc::now().timestamp()) {
        lines.push(
            "  note: the coordinator does not follow GitHub yet (it needs this dryserver: dryserver release publish); until then, deploy \
             again after each push"
                .into(),
        );
    }
    // A setting whose name says secret: app files often go into git.
    let risky: Vec<&str> = app.run.env.iter().map(|(k, _)| k.as_str()).filter(|k| apps::looks_secret(k)).collect();
    if !risky.is_empty() && !lines.is_empty() {
        lines.push(format!(
            "  note: {} {} like {} secret; app files often end up in git. A SECRET= line keeps the value in the cluster only",
            risky.join(", "),
            if risky.len() == 1 { "looks" } else { "look" },
            if risky.len() == 1 { "a" } else { "" }
        ));
    }
    let after = after_deploy(&now, &app);
    let ids = touched(before, Some(&app));
    let looks = dry_runs(ctx, c, doors, &after, &ids, &take_over);
    refuse_unrouted(&looks, before, &app)?;

    let cf_changes = looks.iter().any(|l| l.res.as_ref().is_ok_and(|r| !r.changes.is_empty() && r.held.is_none()));
    let copies = push.as_ref().is_some_and(|p| !p.todo.is_empty());
    // Notes say something, but change nothing.
    let changes = lines.iter().any(|l| !l.starts_with("  note:"));
    if !changes && !cf_changes && !copies && looks.iter().all(|l| l.res.is_ok()) {
        for l in &lines {
            io.say(format!(
                "{}:{}",
                app.name,
                l.trim_start_matches(' ').strip_prefix("note:").map(|n| format!(" note:{n}")).unwrap_or_default()
            ));
        }
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
    if !changes {
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
    // The coordinator may have deployed or taken back a build while the
    // preview was read: then applying it would undo that.
    if app.source.is_some()
        && let Some(b) = before
    {
        let again = look(ctx, c)?;
        let r = again.apps.iter().find(|a| a.name == app.name);
        if r.map(|r| (&r.image, r.gh.run, r.gh.hold)) != Some((&b.image, b.gh.run, b.gh.hold)) {
            bail!(
                "{}: the coordinator changed it while the preview was shown (it deployed or took back a build); nothing was applied: \
                 deploy again",
                app.name
            );
        }
    }
    if app.source.is_some()
        && let Some(token) = gh.and_then(|g| g.token.as_deref())
    {
        c.kubectl(&ctx.with_timeout(CHANGE), &github::PULL_APPLY, &github::pull_secret(token))
            .map_err(|e| timed(e, CHANGE).wrap(format!("{} was not applied: the cluster did not take the GitHub token", app.name)))?;
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

/// The secrets an app has in the cluster: their names and the version of
/// the values (the Secret's resourceVersion). Values are never read.
#[derive(Debug, Default, PartialEq)]
pub struct Secrets {
    pub keys: Vec<String>,
    pub version: String,
}

fn secret_state(ctx: &Ctx, c: &dyn Cluster, app: &str) -> Result<Secrets> {
    let name = apps::secret_name(app);
    // Only its version and the names: the values stay in the cluster.
    let out = c
        .kubectl(&ctx.with_timeout(READ), &["-n", apps::NAMESPACE, "get", "secret", &name, "-o", SECRET_NAMES, "--ignore-not-found"], "")
        .map_err(|e| timed(e, READ).wrap("the app's secrets"))?;
    Ok(secrets_of(&out))
}

/// The version of a Secret, then the names in it: never a value.
const SECRET_NAMES: &str = "go-template={{.metadata.resourceVersion}}{{range $k, $v := .data}} {{$k}}{{end}}";

fn secrets_of(out: &str) -> Secrets {
    let mut words = out.split_whitespace();
    let Some(version) = words.next() else { return Secrets::default() };
    let version =
        if version.len() <= 64 && version.bytes().all(|b| b.is_ascii_alphanumeric()) { version.to_string() } else { String::new() };
    let mut keys: Vec<String> = words.filter(|k| apps::valid_env_name(k).is_ok()).map(String::from).collect();
    keys.sort();
    keys.dedup();
    Secrets { keys, version }
}

/// The largest secret value: a certificate chain or a JSON key file fits.
pub const MAX_SECRET: usize = 64 << 10;

/// What app secret does.
pub enum SecretOp {
    /// List the names (never the values).
    List,
    /// Set one: its value.
    Set(String, Vec<u8>),
    Remove(String),
}

/// Sets, removes or lists an app's secrets. A value goes to the cluster
/// on stdin, never in a command line (where every user of the machine
/// could read it). Copies that use a changed secret are replaced one at a
/// time, so they read the new value.
pub fn secret(ctx: &Ctx, c: &dyn Cluster, app: &str, op: SecretOp, io: &mut Io) -> Result<()> {
    apps::valid_app_name(app).map_err(|e| e.wrap("name"))?;
    let name = apps::secret_name(app);
    let now = look(ctx, c)?;
    refuse_newer(&now)?;
    let running = now.apps.iter().find(|a| a.name == app);
    let key = match &op {
        SecretOp::List => {
            let s = secret_state(ctx, c, app)?;
            let used: Vec<String> = running.map(|r| r.run.secrets.clone()).unwrap_or_default();
            if s.keys.is_empty() && used.is_empty() {
                io.say(format!("{app} has no secrets. Add one: a SECRET=NAME line in its app file, then dryserver app secret {app} NAME"));
            }
            for k in &s.keys {
                io.say(format!("{k}{}", if used.contains(k) { "" } else { "  (set, but the app does not use it)" }));
            }
            for k in used.iter().filter(|k| !s.keys.contains(k)) {
                io.say(format!("{k}  (used, but has no value: the app cannot start until it does)"));
            }
            return Ok(());
        }
        SecretOp::Set(k, v) => {
            apps::valid_env_name(k).map_err(|e| e.wrap("secret"))?;
            if v.is_empty() {
                bail!("{k}: an empty value; nothing was changed");
            }
            if v.len() > MAX_SECRET {
                bail!("{k}: at most {} KiB; nothing was changed", MAX_SECRET >> 10);
            }
            // The Secret first (once), then the value merged into it: the
            // app's other secrets stay as they are.
            let skeleton = format!(
                "{}---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: \"{name}\"\n  namespace: {}\n  labels:\n    app: \"{app}\"\ntype: \
                 Opaque\n",
                apps::namespace_yaml(),
                apps::NAMESPACE
            );
            c.kubectl(&ctx.with_timeout(CHANGE), &["apply", "-f", "-"], &skeleton)
                .map_err(|e| timed(e, CHANGE).wrap("the app's secrets"))?;
            use base64::Engine;
            let patch = serde_json::json!({"data": {k: base64::engine::general_purpose::STANDARD.encode(v)}}).to_string();
            // The answer is the Secret's new version, nothing of its values.
            let out = c
                .kubectl(
                    &ctx.with_timeout(CHANGE),
                    &[
                        "-n",
                        apps::NAMESPACE,
                        "patch",
                        "secret",
                        &name,
                        "--type",
                        "merge",
                        "--patch-file",
                        "/dev/stdin",
                        "-o",
                        "go-template={{.metadata.resourceVersion}}",
                    ],
                    &patch,
                )
                .map_err(|e| timed(e, CHANGE).wrap(format!("{k} was not set")))?;
            io.say(format!("{k} is set for {app} (kept encrypted in the cluster)."));
            (k.clone(), secrets_of(&out).version)
        }
        SecretOp::Remove(k) => {
            apps::valid_env_name(k).map_err(|e| e.wrap("secret"))?;
            if running.is_some_and(|r| r.run.secrets.contains(k)) {
                bail!("{app} uses {k}: take its SECRET={k} line out of the app file and deploy first, then remove the value");
            }
            let s = secret_state(ctx, c, app)?;
            if !s.keys.contains(k) {
                io.say(format!("{app} has no secret {k}; nothing to remove."));
                return Ok(());
            }
            let patch = serde_json::json!({"data": {k: null}}).to_string();
            c.kubectl(
                &ctx.with_timeout(CHANGE),
                &["-n", apps::NAMESPACE, "patch", "secret", &name, "--type", "merge", "--patch-file", "/dev/stdin"],
                &patch,
            )
            .map_err(|e| timed(e, CHANGE).wrap(format!("{k} was not removed")))?;
            io.say(format!("{k} is removed from {app}."));
            return Ok(());
        }
    };
    // Copies that read it start again with the new value.
    let (key, version) = key;
    if let Some(r) = running.filter(|r| r.run.secrets.contains(&key)) {
        let version = if version.is_empty() { secret_state(ctx, c, app)?.version } else { version };
        let patch =
            serde_json::json!({"spec": {"template": {"metadata": {"annotations": {apps::SECRETS_ANNOTATION: version}}}}}).to_string();
        c.kubectl(
            &ctx.with_timeout(CHANGE),
            &["-n", apps::NAMESPACE, "patch", "deployment", &r.name, "--type", "merge", "--patch-file", "/dev/stdin"],
            &patch,
        )
        .map_err(|e| timed(e, CHANGE).wrap(format!("{key} is set, but {app} was not told: deploy it again to use the new value")))?;
        io.say(format!("{app} replaces its copies one at a time, so they read the new value."));
    } else if running.is_some() {
        io.say(format!("{app} does not use {key} yet: add SECRET={key} to its app file and deploy."));
    }
    Ok(())
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
    if !before.run.secrets.is_empty() || !secret_state(ctx, c, name).map(|s| s.keys.is_empty()).unwrap_or(true) {
        io.say("  its secrets are deleted from the cluster (set them again if you start it again)");
    }
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
        if let Some(src) = &a.gh.source {
            let build = a.gh.commit.get(..7).map(|c| format!("build {c}")).unwrap_or_else(|| "no build yet".into());
            io.say(format!("    built by GitHub: {} {}, {build}", src.text(), src.branch));
            if let Some((t, w)) = &a.gh.watch {
                let ago = (chrono::Utc::now().timestamp() - t).max(0);
                io.say(format!("    coordinator, {} ago: {w}", crate::report::short_age(ago as u64)));
            }
        }
        if !a.public() {
            io.say("    inside only");
        }
        let way = doors.iter().find(|d| d.id() == a.entrance).map(|d| d.title()).unwrap_or("an unknown way in");
        for h in &a.hosts {
            let (_, said) = answer.next().unwrap_or((&"", String::new()));
            let port = if h.port == a.port { String::new() } else { format!(" -> port {}", h.port) };
            let said = match (said.is_empty(), a.entrance == entrance::VPN) {
                (true, _) => String::new(),
                (false, false) => format!("  {said}"),
                // Only a device on the VPN reaches it.
                (false, true) => format!("  {said} (from this computer; it answers on the VPN only)"),
            };
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
