//! Apps: what runs on the cluster and on which server, and how each app is
//! reached from outside. n starts one from a container image (a form by
//! steps, with every answer shown before it starts), d removes one, enter
//! shows an app's details and what can be done to it, and o goes to the
//! ways in from outside (Outside).
//!
//! Every question and change goes to the coordinator over SSH, which can
//! be slow or not answer at all. They run on the screen's worker thread,
//! one at a time, each with a time limit (15 seconds for a look, a minute
//! for a change); the screen keeps drawing and taking keys, says what it
//! waits for and how long, and shows a change's steps as it goes.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::app::{Place, PlaceScreen, Size};
use super::form::{Field, Form, Group, Status};
use super::frame::{self, Back, Focus, Help, Item, Notice, Overlay, Page, col};
use super::outside::{Look, look};
use super::theme::{self, Mark};
use super::worker::{Limits, Waiting, Worker, timed};
use super::{Doc, Emit, Event, Flow, Key, Seg};
use crate::apps::{self, App, Cluster, Overview, Running};
use crate::ctx::Ctx;
use crate::entrance::{self, Entrances, Health, State};
use crate::err::{Error, Kind, Result};

/// Each refresh asks the coordinator once, over the shared connection.
pub(super) const REFRESH: Duration = Duration::from_secs(15);

/// The label of a look at the cluster.
pub(super) const LOADING: &str = "asking the coordinator";

/// What the worker answers. Each job ends with exactly one Loaded or
/// Changed, in the order sent; a change sends its steps before that.
pub enum Msg {
    Loaded(Result<Look>),
    /// The change that runs reached a step: what it does now, and how far
    /// it is, 0 to 1.
    Step(String, f64),
    /// A change ended.
    Changed(Outcome),
}

/// How a change ended.
pub struct Outcome {
    notice: Notice,
    /// What did not work, for a card.
    failed: Option<Failure>,
    /// The answers of a new app that did not start, for n.
    retry: Option<Draft>,
}

/// Background work that did not finish, as a card: what happened, what to
/// do, and the key of the screen that does it.
#[derive(Debug, Clone)]
pub(super) struct Failure {
    pub problem: String,
    pub todo: String,
    pub key: (&'static str, &'static str),
}

/// How far the change that runs is.
pub(super) struct Step {
    pub what: String,
    pub pct: f64,
    pub since: Instant,
}

impl Step {
    /// A step message for the step before: it keeps the time the change
    /// started.
    pub fn next(old: Option<&Step>, what: String, pct: f64) -> Step {
        Step { what, pct, since: old.map(|s| s.since).unwrap_or_else(Instant::now) }
    }
}

/// What the worker does for the screen.
enum Job {
    Load,
    Deploy(Draft),
    Remove(String),
}

impl Job {
    fn label(&self) -> String {
        match self {
            Job::Load => LOADING.into(),
            Job::Deploy(d) => format!("starting {}", d.name.trim()),
            Job::Remove(n) => format!("removing {n}"),
        }
    }

    /// What stops half way when the app quits while it runs.
    fn noun(&self) -> String {
        match self {
            Job::Load => String::new(),
            Job::Deploy(d) => format!("the start of {}", d.name.trim()),
            Job::Remove(n) => format!("the removal of {n}"),
        }
    }
}

/// What the cluster says now.
fn listing(ctx: &Ctx, c: &dyn Cluster, limits: Limits) -> Result<Overview> {
    apps::overview(&ctx.with_timeout(limits.read), c).map_err(|e| timed(e, limits.read))
}

/// The entrance an app's public name came in through, if it had one.
fn came_through(before: &Overview, name: &str) -> Option<String> {
    before.apps.iter().find(|a| a.name == name && a.public()).map(|a| a.entrance.clone())
}

/// After an app changed: the entrances its name came or comes through
/// sync by themselves when they can (Cloudflare with an API token), from
/// what the cluster says now. Returns what to add to the notice, and what
/// did not work.
fn sync_after(
    ctx: &Ctx,
    c: &dyn Cluster,
    doors: &Entrances,
    limits: Limits,
    ids: &[String],
    app: &str,
    step: &dyn Fn(String, f64),
) -> (String, Option<Failure>) {
    let mut said = String::new();
    let mut failed = None;
    for d in doors.iter().filter(|d| d.automatic() && ids.iter().any(|id| id == d.id())) {
        step(format!("Syncing {}", d.title()), 0.7);
        let res = listing(ctx, c, limits).and_then(|o| {
            let want = entrance::wants(&o.apps).0.get(d.id()).cloned().unwrap_or_default();
            d.sync(&ctx.with_timeout(limits.change), c, &o, &want, false).map_err(|e| timed(e, limits.change))
        });
        match res {
            Ok(r) if r.conflicts.is_empty() => said += &format!("\n{}: {}.", d.title(), r.summary(false)),
            Ok(r) => said += &format!("\n{}: {} (Outside shows which: o).", d.title(), r.summary(false)),
            Err(e) => {
                failed = Some(Failure {
                    problem: format!("{}: not synced: {e}", d.title()),
                    todo: format!("{app} itself is done. On Outside, s syncs again and shows every change first."),
                    key: ("o", "open Outside"),
                })
            }
        }
    }
    (said, failed)
}

/// Starts the app the admin described, unless another app has its public
/// name: the check uses what the cluster says now, not what the screen saw
/// a while ago.
fn start(ctx: &Ctx, c: &dyn Cluster, doors: &Entrances, limits: Limits, d: Draft, step: &dyn Fn(String, f64)) -> Outcome {
    let app = d.app();
    let not_started = |e: Error, todo: &str| Outcome {
        notice: Notice::bad(format!("{} was not started.", app.name)),
        failed: Some(Failure {
            problem: format!("{} was not started: {e}", app.name),
            todo: todo.into(),
            key: ("n", "try again with your answers"),
        }),
        retry: Some(d.clone()),
    };
    step(
        if app.hosts.is_empty() { "Looking at the cluster".into() } else { format!("Checking that {} is free", app.names().join(", ")) },
        0.1,
    );
    let before = match listing(ctx, c, limits)
        .and_then(|o| entrance::check_host(&app, &o.apps).and_then(|_| form_may_change(&app, &o)).map(|_| o))
    {
        Ok(o) => o,
        Err(e) => return not_started(e, "Nothing was sent to the cluster."),
    };
    step(format!("Applying {}", app.name), 0.4);
    if let Err(e) = apps::deploy(&ctx.with_timeout(limits.change), c, &app).map_err(|e| timed(e, limits.change)) {
        return not_started(e, "Part of it may have reached the cluster: r shows what runs.");
    }
    let mut ids: Vec<String> = came_through(&before, &app.name).into_iter().collect();
    if !app.hosts.is_empty() {
        ids.push(app.entrance.clone());
    }
    let (synced, failed) = sync_after(ctx, c, doors, limits, &ids, &app.name, step);
    Outcome { notice: Notice::ok(format!("{} is starting. The cluster picks a server for it.{synced}", app.name)), failed, retry: None }
}

/// The form knows one public name and one port. An app that runs with
/// more (set up from an app file), or that a newer dryserver wrote, would
/// lose them when started again from here: that is done with its file.
fn form_may_change(app: &App, now: &Overview) -> Result<()> {
    // An image of the admin's own must reach the servers first; the form
    // cannot bring it there.
    if crate::images::is_local(&app.image) {
        crate::bail!(
            "{} is an image of your own: start it with an app file (dryserver app deploy FILE), which copies it to the servers first",
            app.image
        );
    }
    // Any app a newer dryserver set up: this one's sync would read its
    // names wrong, so nothing is started that would sync.
    if let Some(r) = now.apps.iter().find(|a| a.newer && a.name != app.name) {
        crate::bail!("{} was set up by a newer dryserver; update dryserver on this computer first (git pull && make install)", r.name);
    }
    let Some(r) = now.apps.iter().find(|a| a.name == app.name) else { return Ok(()) };
    let why = if r.newer {
        "a newer dryserver set it up".to_string()
    } else if r.hosts.len() > 1 {
        format!("it has {} public names", r.hosts.len())
    } else if r.hosts.iter().any(|h| h.port != r.port) {
        "its public name leads to a port of its own".to_string()
    } else {
        return Ok(());
    };
    crate::bail!(
        "{} already runs and {why}; starting it from this form would lose that. Change it with its app file: dryserver app \
         show {} > {}.app, edit it, then dryserver app deploy {}.app",
        app.name,
        app.name,
        app.name,
        app.name
    )
}

/// Removes an app, then syncs the way in its name came through.
fn remove(ctx: &Ctx, c: &dyn Cluster, doors: &Entrances, limits: Limits, name: &str, step: &dyn Fn(String, f64)) -> Outcome {
    // Which entrance to sync afterwards: only worth a look when one syncs
    // by itself. Without the look nothing is synced, and the admin hears
    // why.
    let before = if doors.iter().any(|d| d.automatic()) {
        step("Looking at what comes in from outside".into(), 0.1);
        Some(listing(ctx, c, limits))
    } else {
        None
    };
    step(format!("Removing {name}"), 0.4);
    if let Err(e) = apps::remove(&ctx.with_timeout(limits.change), c, name) {
        return Outcome {
            notice: Notice::bad(format!("{name} was not removed.")),
            failed: Some(Failure {
                problem: format!("{name} was not removed: {}", timed(e, limits.change)),
                todo: "Part of it may be gone: r shows what runs now, and d tries again.".into(),
                key: ("r", "look again"),
            }),
            retry: None,
        };
    }
    match before {
        Some(Err(e)) => Outcome {
            notice: Notice::ok(format!("{name} removed.")),
            failed: Some(Failure {
                problem: format!("The ways in from outside were not synced: {e}"),
                todo: format!("{name} is gone, but its public name may still point here. On Outside, s syncs them."),
                key: ("o", "open Outside"),
            }),
            retry: None,
        },
        before => {
            let ids: Vec<String> = before.and_then(|b| b.ok()).and_then(|b| came_through(&b, name)).into_iter().collect();
            let (synced, failed) = sync_after(ctx, c, doors, limits, &ids, name, step);
            Outcome { notice: Notice::ok(format!("{name} removed.{synced}")), failed, retry: None }
        }
    }
}

/// One job, on the worker thread.
fn run(ctx: &Ctx, c: &dyn Cluster, doors: &Entrances, limits: Limits, job: Job, step: &dyn Fn(String, f64)) -> Msg {
    match job {
        Job::Load => Msg::Loaded(look(ctx, c, doors, limits)),
        Job::Deploy(d) => Msg::Changed(start(ctx, c, doors, limits, d, step)),
        Job::Remove(name) => Msg::Changed(remove(ctx, c, doors, limits, &name, step)),
    }
}

/// What the admin types for a new app.
#[derive(Debug, Clone)]
struct Draft {
    name: String,
    image: String,
    port: String,
    host: String,
    entrance: String,
    copies: String,
}

impl Draft {
    fn new(entrance: String) -> Draft {
        Draft { name: String::new(), image: String::new(), port: String::new(), host: String::new(), entrance, copies: "1".into() }
    }

    fn app(&self) -> App {
        let port = self.port.trim().parse().unwrap_or(0);
        // The form checked it; what is left is the name as DNS has it.
        let host = apps::clean_host(&self.host).unwrap_or_else(|_| self.host.trim().to_ascii_lowercase());
        App {
            name: self.name.trim().into(),
            image: self.image.trim().into(),
            port,
            hosts: if host.is_empty() { vec![] } else { vec![apps::Host { name: host, port }] },
            entrance: self.entrance.clone(),
            copies: if self.copies.trim().is_empty() { 1 } else { self.copies.trim().parse().unwrap_or(0) },
            image_id: String::new(),
        }
    }
}

/// The form for a new app, starting from draft. taken: (host name, app)
/// pairs the cluster has now; doors: the entrances apps may choose (id,
/// title). With only one the choice is not asked.
fn new_app_form(draft: Draft, taken: Vec<(String, String)>, doors: Vec<(String, String)>) -> Form<Draft> {
    type D = Draft;
    let choose = doors.len() > 1;
    Form::new(
        draft,
        vec![
            Group::new(vec![
                Field::input("Name", |d: &D| d.name.clone(), |d, v| d.name = v)
                    .placeholder("blog")
                    .desc("Starts with a letter; lowercase letters, digits and -. Your other apps reach it as http://NAME.")
                    .validate(|v, _| apps::valid_app_name(v.trim())),
                Field::input("Image", |d: &D| d.image.clone(), |d, v| d.image = v)
                    .placeholder("nginx:1.27")
                    .desc("The container image to run, with its tag.")
                    .validate(|v, _| apps::valid_image(v.trim())),
                Field::input("Port", |d: &D| d.port.clone(), |d, v| d.port = v)
                    .placeholder("80")
                    .desc("The port the container listens on.")
                    .validate(|v, _| match v.trim().parse::<u16>() {
                        Ok(p) if p > 0 => Ok(()),
                        _ => Err("a number from 1 to 65535".into()),
                    }),
            ])
            .title("New app"),
            Group::new(vec![
                Field::input("Public host name (optional)", |d: &D| d.host.clone(), |d, v| d.host = v)
                    .placeholder("blog.example.com")
                    .desc("Leave it empty to keep the app inside the cluster. With a name, the ingress sends\nthat name to the app; Outside shows how it comes in.")
                    .validate(move |v, d| {
                        if v.trim().is_empty() {
                            return Ok(());
                        }
                        let host = apps::clean_host(v)?;
                        match taken.iter().find(|(h, a)| *h == host && *a != d.name.trim()) {
                            Some((_, other)) => Err(crate::errf!("already the public name of {other}")),
                            None => Ok(()),
                        }
                    }),
            ])
            .title("From outside"),
            Group::new(vec![
                Field::select("Way in from outside", move |_| doors.iter().map(|(id, t)| (t.clone(), id.clone())).collect(), |d: &D| d.entrance.clone(), |d, v| d.entrance = v)
                    .desc("Which entrance brings this name from the internet to the app."),
            ])
            .title("Way in")
            .hide_if(move |d| !choose || d.host.trim().is_empty()),
            Group::new(vec![
                Field::input("Copies", |d: &D| d.copies.clone(), |d, v| d.copies = v)
                    .placeholder("1")
                    .desc("How many to run, 1 to 20. Two or more keep it answering while one server is off.")
                    .validate(|v, _| match v.trim() {
                        "" => Ok(()),
                        n => match n.parse::<u32>() {
                            Ok(c) if (1..=20).contains(&c) => Ok(()),
                            _ => Err("1 to 20".into()),
                        },
                    }),
            ])
            .title("Copies"),
        ],
        "back",
    )
    .done_label("start the app")
}

// ---- parts both cluster screens share ----

/// "a minute", "15s": a time limit in words.
pub(super) fn span(d: Duration) -> String {
    match d.as_secs() {
        60 => "a minute".into(),
        s if s > 60 && s % 60 == 0 => format!("{} minutes", s / 60),
        s => format!("{s}s"),
    }
}

/// The first letter in capitals, for a label that starts a heading.
pub(super) fn capital(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// The header's right side: the coordinator, and whether it answers.
pub(super) fn coordinator_status(addr: &str, seen: bool, err: Option<&Error>, waiting: &Waiting, limits: Limits) -> Doc {
    let p = theme::palette();
    let mut d = Doc::new();
    d.add(Seg(if addr.is_empty() { "coordinator".into() } else { format!("coordinator {addr}") }, p.hint())).s("  ");
    let slow = waiting.running().is_some_and(|(l, _)| l == LOADING) && waiting.running_for() >= limits.slow;
    let (m, words) = if slow {
        (Mark::Wait, format!("no answer for {}s", waiting.running_for().as_secs()))
    } else if let Some(e) = err {
        let words = if e.is(Kind::HostKey) {
            "another host key"
        } else if e.is(Kind::DeadlineExceeded) {
            "does not answer"
        } else if e.to_string().starts_with("cannot log in") {
            "refuses your key"
        } else {
            "no usable answer"
        };
        (Mark::Bad, words.to_string())
    } else if seen {
        (Mark::Done, "answers".into())
    } else {
        (Mark::Wait, "asking".into())
    };
    d.add(theme::mark(m)).add(Seg(format!(" {words}"), p.text()));
    d
}

/// The cards for a look that failed and a change that did not finish.
pub(super) fn cards(b: &mut Doc, width: usize, err: Option<&Error>, seen: Option<Instant>, failed: Option<&Failure>) {
    if let Some(e) = err {
        let (problem, todo, key) = if e.is(Kind::HostKey) {
            (
                e.to_string(),
                "Machines looks at the machine that answers now, and trusts it only when you say so.".to_string(),
                ("m", "open Machines"),
            )
        } else {
            let when = seen.map(|t| format!("What you see is from {} ago. ", super::since(t))).unwrap_or_default();
            (
                format!("Cannot reach the cluster: {e}"),
                format!("{when}It is asked again every {} seconds.", REFRESH.as_secs()),
                ("r", "look again now"),
            )
        };
        b.nl();
        b.append(frame::card(width, &problem, &todo, Some(key)));
        b.nl();
    }
    if let Some(f) = failed {
        b.nl();
        b.append(frame::card(width, &f.problem, &f.todo, Some(f.key)));
        b.nl();
    }
}

/// The change that runs, with the ring and its step.
pub(super) fn change_progress(b: &mut Doc, width: usize, waiting: &Waiting, step: Option<&Step>, limits: Limits) {
    let Some(what) = waiting.change() else { return };
    let p = theme::palette();
    frame::section(b, &capital(what), None);
    let behind = waiting.running().is_some_and(|(_, change)| !change);
    let (pct, doing, took) = match step {
        Some(s) => (Some(s.pct), s.what.clone(), s.since.elapsed()),
        None if behind => (None, "Waits for the look that runs".to_string(), Duration::ZERO),
        None => (Some(0.0), "Starting".to_string(), Duration::ZERO),
    };
    b.append(frame::progress(width, pct, &doing, took)).nl();
    b.add(Seg(format!("A change gets up to {}; the screen keeps working meanwhile.", span(limits.change)), p.hint())).nl();
}

/// A look that runs: said once the coordinator is slow to answer, and at
/// once for any other look (they ask Cloudflare too).
pub(super) fn look_line(b: &mut Doc, waiting: &Waiting, limits: Limits) {
    let Some((label, false)) = waiting.running() else { return };
    let p = theme::palette();
    let t = waiting.running_for();
    let text = if label == LOADING {
        if t < limits.slow {
            return;
        }
        format!(" The coordinator is not answering ({}s). A look waits up to {}, then gives up.", t.as_secs(), span(limits.read))
    } else {
        format!(" {}{} {}s; a look waits up to {}.", capital(label), theme::ellipsis(), t.as_secs(), span(limits.change))
    };
    b.nl().add(theme::mark(Mark::Wait)).add(Seg(text, p.hint())).nl();
}

/// A mark and its words, the words wrapped to width and hanging under
/// their first line.
pub(super) fn hang(b: &mut Doc, indent: usize, m: Mark, segs: &[Seg], width: usize) {
    let pad = " ".repeat(indent);
    for (i, part) in frame::wrap_line(segs, width.saturating_sub(indent + 3).max(10)).into_iter().enumerate() {
        b.s(pad.clone());
        if i == 0 {
            b.add(theme::mark(m)).s("  ");
        } else {
            b.s("   ");
        }
        for s in part {
            b.add(s);
        }
        b.nl();
    }
}

/// An entrance's health as a mark.
pub(super) fn health_mark(h: Health) -> Mark {
    match h {
        Health::Up => Mark::Done,
        Health::Partly => Mark::Wait,
        Health::Down => Mark::Bad,
        Health::NotSetUp => Mark::Off,
    }
}

/// What can be done now in a sheet or a confirm.
enum Over {
    /// The selected app's details and actions, the cursor on an action.
    Sheet(usize),
    /// Remove this app? y removes it.
    Remove(String),
}

pub struct Screen {
    cluster: Arc<dyn Cluster>,
    doors: Entrances,
    limits: Limits,
    /// Started when the screen opens; dropped with it, which cancels the
    /// call that runs.
    worker: Option<Worker<Job>>,
    waiting: Waiting,
    /// The changes waiting or running, as quitting would stop them.
    nouns: VecDeque<String>,
    now: Overview,
    /// How each entrance is doing, in the order of doors.
    states: Vec<State>,
    /// When the coordinator last answered a look.
    seen: Option<Instant>,
    err: Option<Error>,
    cursor: usize,
    form: Option<Form<Draft>>,
    /// The answers of the last new app that did not start.
    retry: Option<Draft>,
    over: Option<Over>,
    notice: Option<Notice>,
    failed: Option<Failure>,
    step: Option<Step>,
    last_load: Option<Instant>,
    /// esc was pressed once while a change was still being sent.
    quit_armed: bool,
    /// Where to go after this screen closes.
    next: Option<Place>,
}

impl Screen {
    pub fn new(cluster: Arc<dyn Cluster>, doors: Entrances) -> Screen {
        Screen {
            cluster,
            doors,
            limits: Limits::default(),
            worker: None,
            waiting: Waiting::default(),
            nouns: VecDeque::new(),
            now: Overview::default(),
            states: Vec::new(),
            seen: None,
            err: None,
            cursor: 0,
            form: None,
            retry: None,
            over: None,
            notice: None,
            failed: None,
            step: None,
            last_load: None,
            quit_armed: false,
            next: None,
        }
    }

    #[cfg(test)]
    fn with_limits(mut self, limits: Limits) -> Screen {
        self.limits = limits;
        self
    }

    /// Starts the worker; its answers come back through emit.
    fn start(&mut self, emit: &Emit<Msg>) {
        let (c, doors, limits, emit) = (self.cluster.clone(), self.doors.clone(), self.limits, emit.clone());
        self.worker = Some(Worker::start(move |ctx, job| {
            let e = emit.clone();
            let step = move |what: String, pct: f64| e(Msg::Step(what, pct));
            emit(run(ctx, c.as_ref(), &doors, limits, job, &step))
        }));
    }

    fn send(&mut self, job: Job) {
        let (label, noun, change) = (job.label(), job.noun(), !matches!(job, Job::Load));
        if self.worker.as_ref().is_some_and(|w| w.send(job)) {
            self.waiting.push(label, change);
            if change {
                self.nouns.push_back(noun);
                self.failed = None;
                self.retry = None;
            }
        } else {
            self.notice = Some(Notice::bad("The background worker stopped: go back (esc) and open Apps again."));
        }
    }

    /// Asks the coordinator for the apps, unless that question is already
    /// on its way: refreshes never pile up.
    fn load(&mut self) -> bool {
        if self.waiting.has(LOADING) {
            return false;
        }
        self.last_load = Some(Instant::now());
        self.send(Job::Load);
        true
    }

    fn answer(&mut self, m: Msg) {
        match m {
            Msg::Step(what, pct) => {
                self.step = Some(Step::next(self.step.as_ref(), what, pct));
                return;
            }
            Msg::Loaded(res) => {
                self.waiting.pop();
                match res {
                    Ok((o, states)) => {
                        self.now = o;
                        self.states = states;
                        self.err = None;
                        self.seen = Some(Instant::now());
                    }
                    Err(e) => self.err = Some(e),
                }
            }
            Msg::Changed(out) => {
                self.waiting.pop();
                self.nouns.pop_front();
                self.step = None;
                self.quit_armed = false;
                self.notice = Some(out.notice);
                self.failed = out.failed;
                self.retry = out.retry;
                self.load();
            }
        }
        self.cursor = self.cursor.min(self.now.apps.len().saturating_sub(1));
    }

    fn host_key(&self) -> bool {
        self.err.as_ref().is_some_and(|e| e.is(Kind::HostKey))
    }

    fn open_form(&mut self) {
        let taken = self.now.apps.iter().flat_map(|a| a.hosts.iter().map(|h| (h.name.clone(), a.name.clone()))).collect();
        let doors: Vec<(String, String)> =
            self.doors.iter().filter(|d| d.ready()).map(|d| (d.id().to_string(), d.title().to_string())).collect();
        let first = doors.first().map(|d| d.0.clone()).unwrap_or_else(|| entrance::DEFAULT.into());
        // After a start that failed, its card's n brings the answers back.
        let again = if self.failed.as_ref().is_some_and(|f| f.key.0 == "n") {
            self.failed = None;
            self.retry.take()
        } else {
            None
        };
        self.form = Some(new_app_form(again.unwrap_or_else(|| Draft::new(first)), taken, doors));
    }

    /// Leaves for place, once no change runs: leaving stops the worker,
    /// and a deploy with the DNS sync after it would stop half way.
    fn go(&mut self, place: Place, key: &str) -> Flow {
        if let Some(what) = self.waiting.change() {
            self.notice = Some(Notice::info(format!("Still {what}. {key} goes to {} once that is done.", place.title())));
            return Flow::Continue;
        }
        self.next = Some(place);
        Flow::Quit
    }

    fn key(&mut self, k: Key) -> Flow {
        if let Some(f) = self.form.as_mut() {
            f.update(&k);
            match f.status {
                Status::Completed => {
                    if let Some(f) = self.form.take() {
                        self.notice = None;
                        self.send(Job::Deploy(f.state));
                    }
                }
                Status::Aborted => {
                    self.form = None;
                    self.notice = Some(Notice::info("Nothing started."));
                }
                Status::Active => {}
            }
            return Flow::Continue;
        }
        // A paste where a key is expected does nothing.
        if matches!(k, Key::Paste(_)) {
            return Flow::Continue;
        }
        if let Some(o) = self.over.take() {
            return self.over_key(o, k);
        }
        self.notice = None;
        let armed = std::mem::take(&mut self.quit_armed);
        match k {
            Key::Esc => match self.waiting.change() {
                // Leaving kills the call that runs. A look does not
                // matter; a change cut off half way would.
                Some(what) if !armed => {
                    self.notice = Some(Notice::info(format!("Still {what}. esc again goes back to Home, and that stops half way.")));
                    self.quit_armed = true;
                }
                _ => return Flow::Quit,
            },
            Key::Up | Key::Char('k') => self.cursor = self.cursor.saturating_sub(1),
            Key::Down | Key::Char('j') => self.cursor = (self.cursor + 1).min(self.now.apps.len().saturating_sub(1)),
            Key::Enter => match self.now.apps.get(self.cursor) {
                Some(_) => self.over = Some(Over::Sheet(0)),
                None => self.notice = Some(Notice::info("No app to show yet: n starts one.")),
            },
            Key::Char('n') => self.open_form(),
            Key::Char('d') => match self.now.apps.get(self.cursor) {
                Some(a) => self.over = Some(Over::Remove(a.name.clone())),
                None => self.notice = Some(Notice::info("No app to remove: n starts one.")),
            },
            Key::Char('o') => return self.go(Place::Outside, "o"),
            Key::Char('m') if self.host_key() => return self.go(Place::Machines, "m"),
            Key::Char('r') => {
                if self.failed.as_ref().is_some_and(|f| f.key.0 == "r") {
                    self.failed = None;
                }
                if !self.load() {
                    self.notice = Some(Notice::info("Already asking the coordinator."));
                }
            }
            _ => {}
        }
        Flow::Continue
    }

    fn over_key(&mut self, o: Over, k: Key) -> Flow {
        match o {
            Over::Remove(name) => {
                if k == Key::Char('y') {
                    self.notice = None;
                    self.send(Job::Remove(name));
                } else {
                    self.notice = Some(Notice::info("Nothing removed."));
                }
                Flow::Continue
            }
            Over::Sheet(cursor) => {
                let Some(a) = self.now.apps.get(self.cursor) else { return Flow::Continue };
                let items = self.items(a);
                let chosen = match k {
                    Key::Up | Key::Char('k') => {
                        self.over = Some(Over::Sheet(cursor.saturating_sub(1)));
                        None
                    }
                    Key::Down | Key::Char('j') => {
                        self.over = Some(Over::Sheet((cursor + 1).min(items.len().saturating_sub(1))));
                        None
                    }
                    Key::Enter => items.get(cursor).map(|i| i.key.clone()),
                    Key::Esc => None,
                    Key::Char(c) if items.iter().any(|i| i.key == c.to_string()) => Some(c.to_string()),
                    _ => {
                        self.over = Some(Over::Sheet(cursor));
                        None
                    }
                };
                // An action is its key: what cannot be done now says why.
                match chosen.and_then(|c| c.chars().next()) {
                    Some(c) => self.key(Key::Char(c)),
                    None => Flow::Continue,
                }
            }
        }
    }

    /// What can be done to an app, for its sheet.
    fn items(&self, a: &Running) -> Vec<Item> {
        vec![
            Item { key: "d".into(), label: format!("remove {}", a.name), why_not: None },
            Item {
                key: "o".into(),
                label: "see the ways in from outside".into(),
                why_not: self.waiting.change().map(|w| format!("once {w} is done")),
            },
        ]
    }

    /// The other apps that claim host, a name of a, too.
    fn claimed_by(&self, a: &Running, host: &str) -> Vec<&str> {
        self.now.apps.iter().filter(|o| o.has(host) && o.name != a.name).map(|o| o.name.as_str()).collect()
    }

    /// a's public names that another app claims too.
    fn claimed_too<'a>(&self, a: &'a Running) -> Vec<&'a str> {
        a.names().into_iter().filter(|h| !self.claimed_by(a, h).is_empty()).collect()
    }

    /// How an app is reached from outside, in words.
    fn outside_words(&self, a: &Running) -> String {
        if !a.public() {
            return "inside only: it has no public host name".into();
        }
        let twice = self.claimed_too(a);
        let served: Vec<&str> = a.names().into_iter().filter(|h| !twice.contains(h)).collect();
        let mut words: Vec<String> = Vec::new();
        if !served.is_empty() {
            let names = served.join(", ");
            words.push(match self.doors.iter().position(|d| d.id() == a.entrance) {
                None => format!("{names} asks for a way in this dryserver does not know, so it is not served"),
                Some(i) => match self.states.get(i) {
                    Some(s) => format!("{names} through {}: {}", self.doors[i].title(), s.summary),
                    None => format!("{names} through {}", self.doors[i].title()),
                },
            });
        }
        for h in twice {
            words.push(format!("{h} is claimed by {} too, so none of them gets it from outside", self.claimed_by(a, h).join(" and ")));
        }
        words.join("; ")
    }

    /// The sheet's title: the app and its details, each whole.
    fn details(&self, a: &Running) -> String {
        let runs = if a.copies == 0 { "stopped".to_string() } else { format!("{} of {} copies", a.ready, a.copies) };
        let on = if a.nodes.is_empty() { "on no server yet".to_string() } else { format!("on {}", a.nodes.join(", ")) };
        let image = if a.image == "?" { "not known: the cluster's answer did not check out".to_string() } else { a.image.clone() };
        frame::sheet_title(
            &a.name,
            &[
                ("Running", format!("{runs}, {on}")),
                ("Image", image),
                ("Inside", format!("your other apps reach it as http://{}", a.name)),
                ("Outside", self.outside_words(a)),
            ],
        )
    }

    /// Everything removing name does, for the confirm.
    fn remove_consequences(&self, name: &str) -> Vec<String> {
        let a = self.now.apps.iter().find(|a| a.name == name);
        let on = a.filter(|a| !a.nodes.is_empty()).map(|a| format!(" on {}", a.nodes.join(", "))).unwrap_or_default();
        let mut c = vec![
            format!("Its containers stop{on}; what they keep inside them is lost."),
            format!("Your other apps no longer reach http://{name}."),
        ];
        if let Some(a) = a.filter(|a| a.public()) {
            let twice = self.claimed_too(a);
            let own: Vec<&str> = a.names().into_iter().filter(|h| !twice.contains(h)).collect();
            if !own.is_empty() {
                c.push(format!("{} {} answering from outside.", own.join(", "), if own.len() == 1 { "stops" } else { "stop" }));
                match self.doors.iter().find(|d| d.id() == a.entrance) {
                    Some(d) if d.automatic() => c.push(format!(
                        "{}: dryserver deletes {} right after.",
                        d.title(),
                        if own.len() == 1 { "its DNS name" } else { "their DNS names" }
                    )),
                    Some(d) if d.id() == entrance::CLOUDFLARE && own.len() == 1 => {
                        c.push("Its public hostname in the Cloudflare dashboard stays until you remove it there.".into())
                    }
                    Some(d) if d.id() == entrance::CLOUDFLARE => {
                        c.push("Its public hostnames in the Cloudflare dashboard stay until you remove them there.".into())
                    }
                    _ => {}
                }
            }
            for h in twice {
                match self.claimed_by(a, h).as_slice() {
                    [one] => c.push(format!("{h} is claimed by {one} too: after this, {one} gets it from outside.")),
                    many => c.push(format!("{h} stays claimed by {}, so none of them gets it.", many.join(" and "))),
                }
            }
        }
        c
    }

    /// One app as a row: its state, its servers and its way in.
    fn row(&self, a: &Running, width: usize) -> Doc {
        let p = theme::palette();
        let (mut m, state) = match (a.ready, a.copies) {
            (_, 0) => (Mark::Off, "stopped".to_string()),
            (r, c) if r >= c => (Mark::Done, format!("{r} of {c} running")),
            (0, c) => (Mark::Bad, format!("0 of {c} running")),
            (r, c) => (Mark::Wait, format!("{r} of {c} running")),
        };
        let twice = !self.claimed_too(a).is_empty();
        let unknown = a.public() && !self.doors.iter().any(|d| d.id() == a.entrance);
        if twice || unknown {
            m = Mark::Bad;
        }
        let way = match () {
            _ if !a.public() => Seg("inside only".into(), p.hint()),
            _ if twice => Seg(format!("claimed twice: {}", self.claimed_too(a).join(", ")), p.text()),
            _ if unknown => Seg(format!("unknown way in: {}", a.names_text()), p.text()),
            _ => Seg(a.names_text(), p.text()),
        };
        let on = if a.nodes.is_empty() { "no server yet".to_string() } else { a.nodes.join(", ") };
        let servers = 14 + width.saturating_sub(75).min(6);
        frame::row(
            width,
            m,
            vec![col(Seg(a.name.clone(), p.text()), 16), col(Seg(state, p.hint()), 15), col(Seg(on, p.hint()), servers), col(way, 0)],
        )
    }

    /// The ways in that are open, a line each.
    fn ways_in(&self, b: &mut Doc) {
        let p = theme::palette();
        let label = |b: &mut Doc, first: bool| {
            b.add(Seg(if first { "From outside".into() } else { " ".repeat(12) }, p.hint())).s("  ");
        };
        b.nl();
        let open: Vec<(&str, &State)> =
            self.doors.iter().zip(&self.states).filter(|(_, s)| s.health != Health::NotSetUp).map(|(d, s)| (d.title(), s)).collect();
        if self.states.is_empty() {
            label(b, true);
            b.add(theme::mark(Mark::Wait)).add(Seg(" not known yet".into(), p.hint())).nl();
        } else if open.is_empty() {
            label(b, true);
            b.add(theme::mark(Mark::Off)).add(Seg(" closed: no way in is open. o shows the ways in.".into(), p.hint())).nl();
        }
        for (i, (title, s)) in open.iter().enumerate() {
            label(b, i == 0);
            b.add(theme::mark(health_mark(s.health))).s(" ").add(Seg(title.to_string(), p.text()));
            b.s("  ").add(Seg(s.summary.clone(), p.hint())).nl();
        }
    }

    fn form_page(&self, page: &mut Page, f: &Form<Draft>, size: Size) {
        let p = theme::palette();
        let (mut body, focus) = f.body(size.width);
        if let Some(what) = self.waiting.change() {
            body.nl().add(theme::mark(Mark::Wait)).add(Seg(format!(" Still {what} in the background."), p.hint())).nl();
        }
        page.body = body;
        page.focus = focus.map(Focus::keep);
        page.keys = f.keys();
        page.key("esc", &f.esc_label());
        page.back = Back::Nothing;
        if f.leaving() {
            page.overlay = Some(Overlay::Confirm {
                question: "Leave the new app?".into(),
                consequences: vec!["What you typed is lost, and nothing starts.".into()],
            });
        }
        page.help = Some(Help {
            about: "A new app: its name, the container image and the port it listens on, then a public host name if it \
                    should be reached from outside, and how many copies run. The last step shows every answer; enter there \
                    starts the app."
                .into(),
            keys: vec![
                ("enter".into(), "next field; on the review, start the app".into()),
                ("shift+tab".into(), "previous field".into()),
                ("esc".into(), "back one step; on the first, back to the apps".into()),
                ("↑↓".into(), "choose in a list".into()),
            ],
        });
        // In a text field ? is a letter: the footer does not offer it.
        if f.typing() {
            page.help = None;
        }
    }
}

fn help() -> Help {
    Help {
        about: "Your apps run on your servers, one or more copies each. The cluster picks a server for each, and moves an app \
                when its server stops; no app runs on the coordinator. An app with a public host name is reached from \
                outside through a way in, which Outside (o) shows.\n\
                Every question to the coordinator runs in the background with a time limit: 15 seconds for a look, a minute \
                for a change. The list is asked for again every 15 seconds."
            .into(),
        keys: vec![
            ("↑↓ j k".into(), "move".into()),
            ("enter".into(), "the app's details, and what you can do to it".into()),
            ("n".into(), "start a new app: the form, then a review".into()),
            ("d".into(), "remove the selected app (asks first)".into()),
            ("o".into(), "the ways in from outside".into()),
            ("r".into(), "look again now".into()),
            ("esc".into(), "back to Home".into()),
        ],
    }
}

impl PlaceScreen for Screen {
    type Msg = Msg;

    fn init(&mut self, emit: &Emit<Msg>) {
        self.start(emit);
        self.load();
    }

    fn update(&mut self, ev: Event<Msg>, _: &Emit<Msg>) -> Flow {
        match ev {
            Event::Key(k) => self.key(k),
            Event::Msg(m) => {
                self.answer(m);
                Flow::Continue
            }
            Event::Tick => {
                if self.waiting.is_empty() && self.last_load.is_none_or(|t| t.elapsed() >= REFRESH) {
                    self.load();
                }
                Flow::Continue
            }
            Event::Resize(..) | Event::Back(_) => Flow::Continue,
        }
    }

    fn page(&self, size: Size) -> Page {
        let p = theme::palette();
        let mut page = Page::new("Apps");
        page.status = coordinator_status(&self.cluster.address(), self.seen.is_some(), self.err.as_ref(), &self.waiting, self.limits);
        page.notice = self.notice.clone();
        page.help = Some(help());
        if let Some(f) = &self.form {
            self.form_page(&mut page, f, size);
            return page;
        }
        let w = size.width;
        let b = &mut page.body;
        b.add(Seg("The cluster picks a server for each app and moves it when the server stops.".into(), p.hint())).nl();
        cards(b, w, self.err.as_ref(), self.seen, self.failed.as_ref());
        change_progress(b, w, &self.waiting, self.step.as_ref(), self.limits);
        look_line(b, &self.waiting, self.limits);
        // The way in comes first: it decides who can reach anything below.
        self.ways_in(b);
        let apps = &self.now.apps;
        frame::section(b, "Apps", self.seen.map(|_| apps.len()));
        let mut focus = None;
        if apps.is_empty() {
            let text = match (self.seen, &self.err) {
                (None, None) => "Nothing known yet: asking the coordinator what runs.".to_string(),
                (None, Some(_)) => "What runs is not known until the coordinator answers.".to_string(),
                (Some(t), Some(_)) => format!("No app ran when the coordinator last answered, {} ago.", super::since(t)),
                (Some(_), None) => {
                    "No app runs yet. n starts one from a container image: its name, the image and the port it listens on.".to_string()
                }
            };
            b.append(frame::empty(&text)).nl();
        }
        for (i, a) in apps.iter().enumerate() {
            if i == self.cursor {
                focus = Some(Focus::row(b.lines.len() - 1));
            }
            b.append(self.row(a, w)).nl();
        }
        page.focus = focus;
        match &self.over {
            Some(Over::Sheet(c)) => {
                if let Some(a) = apps.get(self.cursor) {
                    page.overlay = Some(Overlay::Sheet { title: self.details(a), items: self.items(a), cursor: *c });
                }
            }
            Some(Over::Remove(name)) => {
                page.overlay = Some(Overlay::Confirm { question: format!("Remove {name}?"), consequences: self.remove_consequences(name) });
            }
            None => {}
        }
        if self.host_key() {
            page.key("m", "open Machines");
        }
        page.key("n", "new app");
        if !apps.is_empty() {
            page.key("enter", "details").key("d", "remove");
        }
        page.key("o", "outside").key("r", "look again");
        if apps.len() > 1 {
            page.key("↑↓", "move");
        }
        page.back = Back::Esc;
        page
    }

    fn busy(&self) -> Option<String> {
        self.nouns.front().cloned()
    }

    fn next(&self) -> Option<Place> {
        self.next
    }

    fn typing(&self) -> bool {
        self.form.as_ref().is_some_and(|f| f.typing())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::apps::tests::{Fake, LISTING};
    use crate::entrance::cloudflare::Cloudflare;
    use crate::entrance::{Entrance, Report, Traffic, Vps, Want};
    use crate::tui::frame::Scroll;
    use crate::tui::frame::tests::rows;
    use crate::tui::theme::Tier;
    use crate::tui::{collector, type_text};
    use std::sync::atomic::Ordering::SeqCst;
    use std::sync::mpsc::Receiver;
    use unicode_width::UnicodeWidthStr;

    /// A cluster screen opened as the hub opens it, drawn in the frame.
    pub struct Opened<S: PlaceScreen> {
        pub s: S,
        pub rx: Receiver<S::Msg>,
        pub emit: Emit<S::Msg>,
        pub scroll: Scroll,
        pub size: (u16, u16),
        pub tier: (Tier, bool),
    }

    /// Something still waits for the worker's answer.
    pub trait Pending {
        fn pending(&self) -> bool;
    }

    impl Pending for Screen {
        fn pending(&self) -> bool {
            !self.waiting.is_empty()
        }
    }

    impl<S: PlaceScreen + Pending> Opened<S> {
        pub fn new(mut s: S) -> Opened<S> {
            let (emit, rx) = collector();
            s.init(&emit);
            Opened { s, rx, emit, scroll: Scroll::default(), size: (80, 24), tier: (Tier::True, false) }
        }

        /// Feeds the worker's answers to the screen until nothing waits.
        pub fn settle(&mut self) {
            while self.s.pending() {
                let m = self.rx.recv_timeout(Duration::from_secs(10)).expect("the worker did not answer");
                self.s.update(Event::Msg(m), &self.emit);
            }
        }

        pub fn key(&mut self, k: Key) -> Flow {
            self.s.update(Event::Key(k), &self.emit)
        }

        pub fn type_in(&mut self, text: &str) {
            for k in type_text(text) {
                self.key(k);
            }
            self.key(Key::Enter);
        }

        pub fn page(&self) -> Page {
            let (w, h) = self.size;
            self.s.page(Size { width: frame::body_width(w), rows: frame::body_rows(h) })
        }

        /// The screen as the terminal shows it, a string per row.
        pub fn rows(&self) -> Vec<String> {
            let _g = theme::force(self.tier.0, self.tier.1);
            let (w, h) = self.size;
            let r = rows(&frame::draw(&self.page(), &self.scroll, w, h));
            assert_eq!(r.len(), h as usize);
            for l in &r {
                assert_eq!(l.width(), w as usize, "{l:?}");
            }
            r
        }

        pub fn view(&self) -> String {
            self.rows().join("\n")
        }

        /// The screen as one line, every run of spaces one space: wrapped
        /// text reads as it was written.
        pub fn flat(&self) -> String {
            let rows: Vec<String> = self.rows().into_iter().map(|l| l.trim_end_matches('▐').to_string()).collect();
            rows.join(" ").split_whitespace().collect::<Vec<_>>().join(" ")
        }

        pub fn notice(&self) -> String {
            self.page().notice.map(|n| n.text).unwrap_or_default()
        }

        pub fn resize(&mut self, w: u16, h: u16) {
            self.size = (w, h);
            self.s.update(Event::Resize(w, h), &self.emit);
        }
    }

    pub fn doors(dir: &crate::testutil::TempDir) -> Entrances {
        Arc::new(vec![Box::new(Cloudflare::new(dir.path())), Box::new(Vps)])
    }

    fn open_with(fake: &Arc<Fake>, dir: &crate::testutil::TempDir, limits: Limits) -> Opened<Screen> {
        Opened::new(Screen::new(fake.clone(), doors(dir)).with_limits(limits))
    }

    fn open(fake: &Arc<Fake>, dir: &crate::testutil::TempDir) -> Opened<Screen> {
        let mut o = open_with(fake, dir, Limits::default());
        o.settle();
        o
    }

    fn calls(fake: &Fake, what: &str) -> usize {
        fake.calls.lock().unwrap().iter().filter(|(a, _)| a.starts_with(what)).count()
    }

    /// The form for a new app, answered: name, image, port, host, copies,
    /// then the review's enter.
    fn new_app(s: &mut Opened<Screen>, answers: [&str; 5]) {
        s.key(Key::Char('n'));
        for t in &answers[..4] {
            s.type_in(t);
        }
        // Copies starts at 1.
        if !answers[4].is_empty() {
            s.key(Key::Backspace);
            for k in type_text(answers[4]) {
                s.key(k);
            }
        }
        s.key(Key::Enter);
        assert!(s.flat().contains("Step 4 of 4 Review"), "{}", s.view());
        s.key(Key::Enter);
    }

    fn listing() -> Overview {
        apps::overview(&Ctx::new(), &Fake { listing: LISTING.to_string().into(), ..Fake::default() }).unwrap()
    }

    #[test]
    fn list_new_and_remove() {
        let fake = Arc::new(Fake::default());
        let dir = crate::testutil::TempDir::new();
        let mut s = open(&fake, &dir);
        let v = s.flat();
        assert!(v.contains("dryserver Apps") && v.contains("✓ answers"), "{v}");
        assert!(v.contains("No app runs yet. n starts one from a container image"), "{v}");
        assert!(v.contains("From outside · closed: no way in is open. o shows the ways in"), "{v}");
        assert!(v.contains("n new app") && !v.contains("d remove"), "nothing to remove yet: {v}");

        // A new app, by steps: name, image, port, then a public name and
        // the copies. With one entrance there is no choice to make.
        s.key(Key::Char('n'));
        assert!(s.flat().contains("Step 1 of 4 New app"), "{}", s.view());
        assert!(s.s.typing(), "q and ? are letters in a text field");
        assert!(s.page().help.is_none() && !s.flat().contains("? help"), "so the footer does not offer ?");
        s.type_in("blog");
        s.type_in("ghcr.io/me/blog:v2");
        s.type_in("8080");
        assert!(s.flat().contains("Step 2 of 4 From outside"), "{}", s.view());
        s.type_in("Blog.Example.com");
        assert!(!s.view().contains("Way in from outside"), "{}", s.view());
        s.type_in("");
        // The review shows every answer before anything starts.
        let v = s.flat();
        assert!(v.contains("Step 4 of 4 Review") && v.contains("ghcr.io/me/blog:v2") && v.contains("Blog.Example.com"), "{v}");
        assert!(v.contains("enter start the app"), "{v}");
        assert!(!s.s.typing() && s.page().help.is_some());
        assert!(v.contains("Every answer, before anything is done: enter to start the app, esc to change one."), "{v}");
        assert_eq!(calls(&fake, "apply"), 0, "nothing before the review's enter");
        // esc goes back to change an answer, enter comes back.
        s.key(Key::Esc);
        assert!(s.flat().contains("Step 3 of 4 Copies"), "{}", s.view());
        s.key(Key::Enter);
        s.key(Key::Enter);
        s.settle();
        assert!(s.notice().contains("blog is starting"), "{:?}\n{}", s.notice(), s.view());
        let made = fake.calls.lock().unwrap().clone();
        let (_, manifest) = made.iter().find(|(a, _)| a == "apply -f -").expect("nothing applied");
        assert!(
            manifest.contains("image: \"ghcr.io/me/blog:v2\"")
                && manifest.contains("- host: \"blog.example.com\"")
                && manifest.contains("dryserver/entrance: \"cloudflare\"")
                && manifest.contains("replicas: 1"),
            "{manifest}"
        );
        assert!(made.last().unwrap().0.starts_with("get"), "the screen asks again after a change: {made:?}");

        // The cluster now has it (and one that is not healthy).
        *fake.listing.lock().unwrap() = LISTING.into();
        s.key(Key::Char('r'));
        s.settle();
        let v = s.flat();
        assert!(v.contains("Apps 2") && v.contains("blog") && v.contains("1 of 2 running") && v.contains("blog.example.com"), "{v}");
        assert!(v.contains("! api 0 of 1 running no server yet inside only"), "{v}");
        assert!(v.contains("From outside ○ Cloudflare Tunnel connected with 1 of 2 copies"), "{v}");
        assert!(v.contains("enter details") && v.contains("d remove"), "{v}");

        // Remove asks first, with what it does; the cursor is on api, the
        // first by name.
        s.key(Key::Char('d'));
        let v = s.flat();
        assert!(v.contains("Remove api?") && v.contains("Your other apps no longer reach http://api."), "{v}");
        assert!(v.contains("y yes") && v.contains("any other key no"), "{v}");
        s.key(Key::Char('n'));
        assert!(s.notice().contains("Nothing removed") && calls(&fake, "-n") == 0);
        s.key(Key::Down);
        s.key(Key::Char('d'));
        let v = s.flat();
        assert!(v.contains("Remove blog?") && v.contains("Its containers stop on node-a, node-b"), "{v}");
        assert!(v.contains("blog.example.com stops answering from outside."), "{v}");
        assert!(v.contains("Its public hostname in the Cloudflare dashboard stays until you remove it there"), "{v}");
        s.key(Key::Char('y'));
        s.settle();
        assert!(s.notice().contains("blog removed"), "{:?}", s.notice());
        assert!(fake.calls.lock().unwrap().iter().any(|(a, _)| a.contains("delete") && a.contains("-l app=blog")));

        // o goes to the Outside screen.
        assert_eq!(s.key(Key::Char('o')), Flow::Quit);
        assert_eq!(s.s.next(), Some(Place::Outside));
    }

    #[test]
    fn the_sheet_shows_an_app_whole() {
        let fake = Arc::new(Fake::default());
        let long = "a-name-that-is-long-enough-to-be-cut-in-a-row";
        let host = "a-very-long-public-host-name-for-this-app.example.com";
        *fake.listing.lock().unwrap() = LISTING.replace("blog", long).replace(&format!("{long}.example.com"), host);
        let dir = crate::testutil::TempDir::new();
        let mut s = open(&fake, &dir);
        let v = s.flat();
        assert!(!v.contains(long) && v.contains("a-name-that-is-…"), "cut in the row: {v}");
        // It sorts before api.
        s.key(Key::Enter);
        let v = s.flat();
        let joined: String = s.rows().iter().map(|l| l.trim().to_string()).collect::<Vec<_>>().join("");
        assert!(joined.contains(long) && joined.contains(host), "whole in the sheet:\n{}", s.view());
        assert!(v.contains(&format!("Image ghcr.io/me/{long}:v2")) && v.contains("Running 1 of 2 copies, on node-a, node-b"), "{v}");
        assert!(v.contains("through Cloudflare Tunnel: connected with 1 of 2 copies"), "{v}");
        assert!(v.contains("↑↓ move enter choose esc close"), "{v}");
        // A paste does nothing; esc closes it.
        s.key(Key::Paste("d".into()));
        assert!(matches!(s.s.over, Some(Over::Sheet(0))));
        s.key(Key::Esc);
        assert!(s.s.over.is_none());
        // enter on an action is its key.
        s.key(Key::Enter);
        s.key(Key::Enter);
        assert!(s.flat().contains(&format!("Remove {long}?")) || s.flat().contains("Remove a-name"), "{}", s.view());
        s.key(Key::Esc);
        // Its letter too; o leaves for Outside.
        s.key(Key::Enter);
        assert_eq!(s.key(Key::Char('o')), Flow::Quit);
        assert_eq!(s.s.next(), Some(Place::Outside));
    }

    #[test]
    fn the_form_does_not_drop_what_a_file_set_up() {
        use crate::apps::Host;
        let h = |n: &str, p: u16| Host { name: n.into(), port: p };
        let run = |name: &str, hosts: Vec<Host>, newer: bool| Running { name: name.into(), port: 80, hosts, newer, ..Running::default() };
        let now = Overview {
            apps: vec![
                run("one", vec![h("one.example.com", 80)], false),
                run("many", vec![h("a.example.com", 80), h("b.example.com", 80)], false),
                run("port", vec![h("admin.example.com", 9000)], false),
            ],
            ..Overview::default()
        };
        let draft = |name: &str| {
            Draft {
                name: name.into(),
                image: "nginx:1".into(),
                port: "80".into(),
                host: "x.example.com.".into(),
                entrance: "cloudflare".into(),
                copies: "1".into(),
            }
            .app()
        };
        assert_eq!(draft("new").hosts, vec![h("x.example.com", 80)], "the name as DNS has it");
        form_may_change(&draft("new"), &now).unwrap();
        form_may_change(&draft("one"), &now).unwrap();
        let e = form_may_change(&draft("many"), &now).unwrap_err().to_string();
        assert!(e.contains("many already runs and it has 2 public names") && e.contains("dryserver app show many > many.app"), "{e}");
        let e = form_may_change(&draft("port"), &now).unwrap_err().to_string();
        assert!(e.contains("leads to a port of its own"), "{e}");
        let mut newer = now.clone();
        newer.apps.push(run("next", vec![h("next.example.com", 80)], true));
        let e = form_may_change(&draft("new"), &newer).unwrap_err().to_string();
        assert!(e.contains("next was set up by a newer dryserver"), "{e}");
        let e = form_may_change(&draft("next"), &newer).unwrap_err().to_string();
        assert!(e.contains("a newer dryserver set it up"), "{e}");
    }

    #[test]
    fn one_name_one_app() {
        let fake = Arc::new(Fake::default());
        *fake.listing.lock().unwrap() = LISTING.into();
        let dir = crate::testutil::TempDir::new();
        let mut s = open(&fake, &dir);
        // The form says so at once.
        s.key(Key::Char('n'));
        for t in ["shop", "nginx:1.27", "80", "blog.example.com"] {
            s.type_in(t);
        }
        assert!(s.view().contains("already the public name of blog"), "{}", s.view());
        // Leaving after typing asks first.
        s.key(Key::Esc);
        s.key(Key::Esc);
        assert!(s.flat().contains("Leave the new app?"), "{}", s.view());
        s.key(Key::Char('y'));
        assert!(s.notice().contains("Nothing started"));
        // The same app may keep its name.
        new_app(&mut s, ["blog", "nginx:1.27", "80", "blog.example.com", ""]);
        s.settle();
        assert!(s.notice().contains("blog is starting"), "{:?}", s.notice());
        // The cluster changed while the form was open: the deploy checks
        // again before it applies anything, and says so on a card.
        s.key(Key::Char('n'));
        for t in ["news", "nginx:1.27", "80", "news.example.com", ""] {
            s.type_in(t);
        }
        *fake.listing.lock().unwrap() = LISTING.replace("\"host\":\"blog.example.com\"", "\"host\":\"news.example.com\"");
        let applied = calls(&fake, "apply");
        s.key(Key::Enter);
        s.settle();
        let v = s.flat();
        assert!(s.notice().contains("news was not started"), "{:?}", s.notice());
        assert!(v.contains("news was not started: news.example.com is already a public name of blog"), "{v}");
        assert!(v.contains("Nothing was sent to the cluster.") && v.contains("n try again with your answers"), "{v}");
        assert_eq!(calls(&fake, "apply"), applied, "nothing was applied");
        // n brings the answers back.
        s.key(Key::Char('n'));
        assert!(s.flat().contains("> news"), "{}", s.view());
        assert!(!s.flat().contains("was not started"), "the card went: {}", s.view());
    }

    /// An entrance that is set up, for the choice in the form.
    struct Ready;
    impl Entrance for Ready {
        fn id(&self) -> &'static str {
            entrance::VPS
        }
        fn title(&self) -> &'static str {
            "Your VPS"
        }
        fn carries(&self) -> &'static [Traffic] {
            &[Traffic::Web]
        }
        fn ready(&self) -> bool {
            true
        }
        fn automatic(&self) -> bool {
            false
        }
        fn state(&self, _: &Ctx, _: &Overview) -> State {
            State { health: Health::Up, summary: "up".into(), notes: vec![] }
        }
        fn open_question(&self, _: &Overview) -> Result<String> {
            Ok("open?".into())
        }
        fn open(&self, _: &Ctx, _: &dyn Cluster) -> Result<String> {
            Ok("opened".into())
        }
        fn sync(&self, _: &Ctx, _: &dyn Cluster, _: &Overview, _: &Want, _: bool) -> Result<Report> {
            Ok(Report::default())
        }
        fn close(&self, _: &Ctx, _: &dyn Cluster) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn the_way_in_is_chosen_when_there_is_a_choice() {
        let fake = Arc::new(Fake::default());
        let dir = crate::testutil::TempDir::new();
        let two: Entrances = Arc::new(vec![Box::new(Cloudflare::new(dir.path())), Box::new(Ready)]);
        let mut s = Opened::new(Screen::new(fake.clone(), two));
        s.settle();
        assert!(s.flat().contains("From outside ✓ Your VPS up"), "{}", s.view());
        s.key(Key::Char('n'));
        for t in ["game", "nginx:1.27", "80", "play.example.com"] {
            s.type_in(t);
        }
        let v = s.flat();
        assert!(v.contains("Step 3 of 5 Way in") && v.contains("> Cloudflare Tunnel") && v.contains("Your VPS"), "{v}");
        assert!(!s.s.typing(), "a list: q goes back");
        s.key(Key::Down);
        s.key(Key::Enter);
        s.type_in("");
        assert!(s.flat().contains("Way in from outside Your VPS"), "the review names it: {}", s.view());
        s.key(Key::Enter);
        s.settle();
        let calls = fake.calls.lock().unwrap().clone();
        let (_, manifest) = calls.iter().find(|(a, _)| a == "apply -f -").expect("nothing applied");
        assert!(manifest.contains("dryserver/entrance: \"vps\""), "{manifest}");
        // Without a public name the choice is not asked.
        s.key(Key::Char('n'));
        for t in ["inside", "nginx:1.27", "80", ""] {
            s.type_in(t);
        }
        assert!(s.flat().contains("Step 3 of 4 Copies") && !s.view().contains("Way in from outside"), "{}", s.view());
    }

    #[test]
    fn bad_input_and_errors() {
        let fake = Arc::new(Fake::default());
        let dir = crate::testutil::TempDir::new();
        let mut s = open(&fake, &dir);
        s.key(Key::Char('n'));
        // A bad name does not leave the field.
        s.type_in("My App");
        assert!(s.view().contains("lowercase letters, digits and -"), "{}", s.view());
        assert!(s.flat().contains("Step 1 of 4"));
        // Copies: 1 to 20.
        s.key(Key::Ctrl('u'));
        for t in ["web", "nginx:1.27", "80", ""] {
            s.type_in(t);
        }
        s.key(Key::Backspace);
        s.type_in("21");
        assert!(s.view().contains("* 1 to 20"), "{}", s.view());
        s.key(Key::Esc);
        s.key(Key::Esc);
        s.key(Key::Esc);
        s.key(Key::Char('y'));
        assert!(s.notice().contains("Nothing started") && calls(&fake, "apply") == 0);
        // The cluster is not reachable: a card, and the list it saw.
        *fake.fail.lock().unwrap() = Some("cannot log in to the coordinator at 10.1.0.60 with your SSH key: denied".into());
        s.key(Key::Char('r'));
        s.settle();
        let v = s.flat();
        assert!(v.contains("! Cannot reach the cluster: cannot log in"), "{v}");
        assert!(v.contains("What you see is from") && v.contains("r look again now"), "{v}");
        assert!(v.contains("! refuses your key"), "the header says it: {v}");
        assert!(v.contains("No app ran when the coordinator last answered"), "{v}");
        s.key(Key::Char('d'));
        assert!(s.notice().contains("No app to remove"));
        s.key(Key::Enter);
        assert!(s.notice().contains("No app to show yet"));
    }

    #[test]
    fn keys_work_while_the_coordinator_is_slow() {
        let fake = Arc::new(Fake::default());
        *fake.delay.lock().unwrap() = Duration::from_millis(400);
        *fake.listing.lock().unwrap() = LISTING.into();
        let dir = crate::testutil::TempDir::new();
        let mut s = open_with(&fake, &dir, Limits { slow: Duration::from_millis(100), ..Limits::default() });
        let v = s.flat();
        assert!(v.contains("asking the coordinator what runs") && v.contains("From outside ○ not known yet"), "{v}");
        assert!(v.contains("○ asking"), "{v}");
        // Every key answers at once while the call runs.
        let start = Instant::now();
        for k in [Key::Down, Key::Up, Key::Char('n'), Key::Esc, Key::Char('d'), Key::Char('x'), Key::Enter] {
            s.key(k);
        }
        assert!(start.elapsed() < Duration::from_millis(100), "keys waited for the coordinator: {:?}", start.elapsed());
        std::thread::sleep(Duration::from_millis(150));
        let v = s.flat();
        assert!(v.contains("The coordinator is not answering (0s). A look waits up to 15s, then gives up."), "{v}");
        assert!(v.contains("○ no answer for 0s"), "{v}");
        s.settle();
        assert!(s.flat().contains("1 of 2 running") && !s.view().contains("not answering"), "{}", s.view());
    }

    #[test]
    fn refreshes_do_not_pile_up() {
        let fake = Arc::new(Fake::default());
        *fake.delay.lock().unwrap() = Duration::from_millis(200);
        let dir = crate::testutil::TempDir::new();
        let mut s = open_with(&fake, &dir, Limits::default());
        for _ in 0..5 {
            s.key(Key::Char('r'));
            s.s.update(Event::Tick, &s.emit.clone());
        }
        assert_eq!(s.notice(), "Already asking the coordinator.");
        s.settle();
        assert_eq!(calls(&fake, "get"), 1, "{:?}", fake.calls.lock().unwrap());
        // Ticks right after an answer do not ask again either.
        s.s.update(Event::Tick, &s.emit.clone());
        assert!(s.s.waiting.is_empty());
    }

    #[test]
    fn a_change_shows_its_steps() {
        let fake = Arc::new(Fake::default());
        *fake.delay.lock().unwrap() = Duration::from_millis(200);
        let dir = crate::testutil::TempDir::new();
        let mut s = open_with(&fake, &dir, Limits::default());
        // The first look runs; the admin starts an app meanwhile.
        new_app(&mut s, ["blog", "nginx:1.27", "80", "", ""]);
        let v = s.flat();
        assert!(v.contains("Starting blog") && v.contains("Waits for the look that runs"), "{v}");
        assert!(v.contains("A change gets up to a minute; the screen keeps working meanwhile."), "{v}");
        assert_eq!(s.s.busy().as_deref(), Some("the start of blog"));
        // A look asked for now waits behind both, and only once.
        s.key(Key::Char('r'));
        s.key(Key::Char('r'));
        // The steps come as the change goes.
        let mut seen = Vec::new();
        while s.s.pending() {
            let m = s.rx.recv_timeout(Duration::from_secs(10)).unwrap();
            s.s.update(Event::Msg(m), &s.emit.clone());
            if let Some(st) = &s.s.step {
                seen.push(st.what.clone());
                assert!(s.flat().contains(&st.what), "{}", s.view());
            }
        }
        assert_eq!(seen.first().map(String::as_str), Some("Looking at the cluster"), "{seen:?}");
        assert!(seen.iter().any(|w| w == "Applying blog"), "{seen:?}");
        let order: Vec<String> = fake.calls.lock().unwrap().iter().map(|(a, _)| a.split(' ').next().unwrap_or("").to_string()).collect();
        // The deploy looks at the cluster first, then applies.
        assert_eq!(order, vec!["get", "get", "apply", "-n", "get"], "{order:?}");
        assert!(s.notice().contains("blog is starting") && s.s.busy().is_none(), "{:?}", s.notice());
        assert!(!s.flat().contains("Starting blog"), "{}", s.view());
    }

    #[test]
    fn the_coordinator_does_not_answer() {
        let fake = Arc::new(Fake::default());
        *fake.delay.lock().unwrap() = Duration::from_secs(30);
        let dir = crate::testutil::TempDir::new();
        let limits = Limits { read: Duration::from_millis(200), change: Duration::from_millis(300), slow: Duration::from_millis(50) };
        let start = Instant::now();
        let mut s = open_with(&fake, &dir, limits);
        s.settle();
        assert!(start.elapsed() < Duration::from_secs(5));
        let v = s.flat();
        assert!(v.contains("! Cannot reach the cluster: the coordinator did not answer within 0s. Is it on?"), "{v}");
        assert!(v.contains("It is asked again every 15 seconds.") && v.contains("! does not answer"), "{v}");
        assert!(v.contains("What runs is not known until the coordinator answers."), "{v}");
        // A change gives up too, and says what did not happen.
        s.s.now = listing();
        s.key(Key::Char('d'));
        s.key(Key::Char('y'));
        s.settle();
        let v = s.flat();
        assert!(v.contains("api was not removed: the coordinator did not answer"), "{v}");
        assert!(v.contains("r look again"), "{v}");
        assert_eq!(fake.cut_off.load(SeqCst), fake.calls.lock().unwrap().len(), "every call was cut off by its limit");
        // r looks again, and the card about the change goes.
        s.key(Key::Char('r'));
        assert!(!s.flat().contains("was not removed"));
        s.settle();
    }

    #[test]
    fn another_host_key_sends_to_machines() {
        let fake = Arc::new(Fake::default());
        let dir = crate::testutil::TempDir::new();
        let mut s = open(&fake, &dir);
        let key = Error::with_kind(
            Kind::HostKey,
            "The machine at 10.1.0.60 does not have the SSH key this computer saw before. Nothing was sent.",
        );
        s.s.waiting.push(LOADING, false);
        s.s.answer(Msg::Loaded(Err(key)));
        let v = s.flat();
        assert!(v.contains("! The machine at 10.1.0.60 does not have the SSH key this computer saw before."), "{v}");
        assert!(v.contains("m open Machines") && v.contains("! another host key"), "{v}");
        assert_eq!(s.key(Key::Char('m')), Flow::Quit);
        assert_eq!(s.s.next(), Some(Place::Machines));
    }

    #[test]
    fn closing_while_a_call_runs() {
        let fake = Arc::new(Fake::default());
        *fake.delay.lock().unwrap() = Duration::from_secs(30);
        let dir = crate::testutil::TempDir::new();
        let mut s = open_with(&fake, &dir, Limits::default());
        std::thread::sleep(Duration::from_millis(50));
        // Leaving during a look is immediate.
        assert_eq!(s.key(Key::Esc), Flow::Quit);
        let start = Instant::now();
        drop(s);
        assert!(start.elapsed() < Duration::from_secs(1), "closing waited {:?}", start.elapsed());
        assert_eq!(fake.cut_off.load(SeqCst), 1, "the call was cancelled, not left running");
    }

    #[test]
    fn leaving_during_a_change_asks_once() {
        let fake = Arc::new(Fake::default());
        let dir = crate::testutil::TempDir::new();
        let mut s = open(&fake, &dir);
        *fake.delay.lock().unwrap() = Duration::from_secs(30);
        s.s.now = listing();
        s.key(Key::Char('d'));
        s.key(Key::Char('y'));
        assert_eq!(s.s.busy().as_deref(), Some("the removal of api"), "ctrl+c asks first in the hub and names it");
        assert_eq!(s.key(Key::Esc), Flow::Continue);
        assert!(s.notice().contains("Still removing api. esc again goes back to Home, and that stops half way."), "{:?}", s.notice());
        // Another key disarms it; esc then asks again.
        s.key(Key::Down);
        assert_eq!(s.key(Key::Esc), Flow::Continue);
        assert_eq!(s.key(Key::Esc), Flow::Quit);
    }

    #[test]
    fn switching_screens_waits_for_a_change() {
        // o closes this screen and its worker. During a look that is
        // fine; during a deploy (and the DNS sync after it) it waits.
        let fake = Arc::new(Fake::default());
        let dir = crate::testutil::TempDir::new();
        let mut s = open(&fake, &dir);
        *fake.delay.lock().unwrap() = Duration::from_millis(300);
        new_app(&mut s, ["blog", "nginx:1.27", "80", "", ""]);
        assert_eq!(s.key(Key::Char('o')), Flow::Continue);
        assert!(s.notice().contains("Still starting blog. o goes to Outside once that is done"), "{:?}", s.notice());
        assert_eq!(s.s.next(), None);
        // The sheet says so too.
        s.s.now = listing();
        s.key(Key::Enter);
        assert!(s.flat().contains("see the ways in from outside: once starting blog is done"), "{}", s.view());
        s.key(Key::Esc);
        s.settle();
        assert!(s.notice().contains("blog is starting"), "{:?}", s.notice());
        assert_eq!((calls(&fake, "apply"), fake.cut_off.load(SeqCst)), (1, 0), "the deploy ran to its end");
        s.key(Key::Char('r'));
        assert_eq!(s.key(Key::Char('o')), Flow::Quit, "a look does not hold it");
        assert_eq!(s.s.next(), Some(Place::Outside));
    }

    #[test]
    fn an_answer_after_the_screen_closed() {
        // The coordinator answers late and the call ignores the cancel:
        // the answer goes to a closed channel, nothing panics, and the
        // worker ends.
        let fake = Arc::new(Fake::default());
        *fake.stubborn.lock().unwrap() = Duration::from_millis(300);
        let dir = crate::testutil::TempDir::new();
        let Opened { s, rx, .. } = open_with(&fake, &dir, Limits::default());
        while fake.calls.lock().unwrap().is_empty() {
            std::thread::sleep(Duration::from_millis(5));
        }
        drop(rx);
        drop(s);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(fake.ended.load(SeqCst), 1);
    }

    #[test]
    fn cloudflare_follows_the_apps() {
        use crate::entrance::cfsync::tests::{FakeCf, entrance, fresh, mark_of};
        // With an API token: starting an app with a Cloudflare name, then
        // removing it, syncs Cloudflare after each, while the cluster runs
        // the tunnel dryserver.
        let fake = Arc::new(Fake::default());
        *fake.listing.lock().unwrap() = LISTING.into();
        let dir = crate::testutil::TempDir::new();
        let cf: Arc<FakeCf> = Arc::new(fresh());
        let doors: Entrances = Arc::new(vec![Box::new(entrance(dir.path(), &cf, true)), Box::new(Vps)]);
        let mut s = Opened::new(Screen::new(fake.clone(), doors.clone()));
        s.settle();
        assert!(cf.calls.lock().unwrap().is_empty(), "a look does not ask Cloudflare");
        let names = |cf: &FakeCf| cf.cf.lock().unwrap().records.iter().map(|r| r.name.clone()).collect::<Vec<_>>();
        // The cluster runs a tunnel set up by hand (LISTING's token mark):
        // nothing in Cloudflare changes, and the screen says why. A tunnel
        // dryserver with DNS names that no connector serves would answer
        // every visitor with error 1033.
        new_app(&mut s, ["blog", "nginx:1.27", "80", "blog.example.com", ""]);
        s.settle();
        let n = s.notice();
        assert!(n.contains("blog is starting") && n.contains("Cloudflare Tunnel: left as it is: the cluster runs a tunnel"), "{n:?}");
        assert!(n.contains("(or s on the Outside screen) switches to the tunnel dryserver"), "{n:?}");
        assert_eq!(cf.changes.load(SeqCst), 0);
        assert!(cf.cf.lock().unwrap().tunnels.is_empty() && names(&cf).is_empty());
        assert!(!fake.calls.lock().unwrap().iter().any(|(a, m)| a == "apply -f -" && m.contains("cloudflared")), "left running");
        // The admin switches on purpose (s on the Outside screen); the
        // cluster then runs the tunnel dryserver.
        let o = apps::overview(&Ctx::new(), fake.as_ref()).unwrap();
        doors[0].sync(&Ctx::new(), fake.as_ref(), &o, &Want { open: true, ..Want::default() }, false).unwrap();
        let mark = mark_of(&fake).unwrap();
        *fake.listing.lock().unwrap() = LISTING.replace("00aa11bb22cc33dd", &mark);
        new_app(&mut s, ["blog", "nginx:1.27", "80", "blog.example.com", ""]);
        s.settle();
        let n = s.notice();
        assert!(n.contains("blog is starting") && n.contains("Cloudflare Tunnel: 2 changes made."), "{n:?}");
        assert_eq!(names(&cf), vec!["blog.example.com"]);
        // Removing it says the name goes, and it does.
        *fake.after_delete.lock().unwrap() =
            Some(LISTING.replace("00aa11bb22cc33dd", &mark).replace("\"host\":\"blog.example.com\"", "\"host\":\"\""));
        s.key(Key::Down);
        s.key(Key::Char('d'));
        assert!(s.flat().contains("Cloudflare Tunnel: dryserver deletes its DNS name right after."), "{}", s.view());
        s.key(Key::Char('y'));
        s.settle();
        assert!(s.notice().contains("blog removed.") && s.notice().contains("Cloudflare Tunnel: 2 changes made."), "{:?}", s.notice());
        assert!(names(&cf).is_empty());

        // Without an API token nothing goes to Cloudflare.
        let dir = crate::testutil::TempDir::new();
        let cf: Arc<FakeCf> = Arc::new(fresh());
        let doors: Entrances = Arc::new(vec![Box::new(entrance(dir.path(), &cf, false)), Box::new(Vps)]);
        let mut s = Opened::new(Screen::new(fake.clone(), doors));
        s.settle();
        new_app(&mut s, ["shop", "nginx:1.27", "80", "shop.example.com", ""]);
        s.settle();
        assert!(s.notice().contains("shop is starting") && !s.notice().contains("Cloudflare"), "{:?}", s.notice());
        assert!(cf.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn an_empty_answer_is_not_an_empty_cluster() {
        use crate::apps::tests::SILENT;
        use crate::entrance::cfsync::tests::{FakeCf, entrance, fresh};
        // The coordinator answers nothing (a cut connection, a kubectl
        // that printed nothing): the screen says so, and no sync reads it
        // as "no apps" and deletes their names.
        let fake = Arc::new(Fake::default());
        *fake.listing.lock().unwrap() = SILENT.into();
        let dir = crate::testutil::TempDir::new();
        let cf: Arc<FakeCf> = Arc::new(fresh());
        let doors: Entrances = Arc::new(vec![Box::new(entrance(dir.path(), &cf, true)), Box::new(Vps)]);
        let mut s = Opened::new(Screen::new(fake.clone(), doors));
        s.settle();
        assert!(s.flat().contains("Cannot reach the cluster: the cluster sent an empty answer"), "{}", s.view());
        assert!(!s.view().contains("No app runs yet"), "{}", s.view());
        // A deploy looks first, and stops.
        new_app(&mut s, ["blog", "nginx:1.27", "80", "blog.example.com", ""]);
        s.settle();
        assert!(s.flat().contains("blog was not started: the cluster sent an empty answer"), "{}", s.view());
        assert_eq!(calls(&fake, "apply"), 0);
        // A remove whose look comes back empty, or whose look afterwards
        // does: removed, not synced, and said.
        *fake.listing.lock().unwrap() = LISTING.into();
        s.key(Key::Char('r'));
        s.settle();
        *fake.after_delete.lock().unwrap() = Some(SILENT.into());
        s.key(Key::Down);
        s.key(Key::Char('d'));
        s.key(Key::Char('y'));
        s.settle();
        let v = s.flat();
        assert!(s.notice().contains("blog removed."), "{:?}", s.notice());
        assert!(v.contains("Cloudflare Tunnel: not synced: the cluster sent an empty answer") && v.contains("o open Outside"), "{v}");
        *fake.listing.lock().unwrap() = SILENT.into();
        s.s.now = listing();
        s.key(Key::Up);
        s.key(Key::Char('d'));
        s.key(Key::Char('y'));
        s.settle();
        assert!(s.notice().contains("api removed."), "{:?}", s.notice());
        assert!(s.flat().contains("The ways in from outside were not synced: the cluster sent an empty answer"), "{}", s.view());
        assert!(cf.calls.lock().unwrap().is_empty(), "nothing went to Cloudflare");
    }

    #[test]
    fn cloudflare_down_does_not_stop_a_deploy() {
        use crate::entrance::cfsync::tests::{FakeCf, entrance, fresh, mark_of};
        let fake = Arc::new(Fake::default());
        let dir = crate::testutil::TempDir::new();
        let cf: Arc<FakeCf> = Arc::new(fresh());
        let doors: Entrances = Arc::new(vec![Box::new(entrance(dir.path(), &cf, true)), Box::new(Vps)]);
        // The cluster runs the tunnel dryserver.
        doors[0].sync(&Ctx::new(), fake.as_ref(), &Overview::default(), &Want { open: true, ..Want::default() }, false).unwrap();
        *fake.listing.lock().unwrap() = LISTING.replace("00aa11bb22cc33dd", &mark_of(&fake).unwrap());
        cf.down.store(true, SeqCst);
        let mut s = Opened::new(Screen::new(fake.clone(), doors));
        s.settle();
        let applied = calls(&fake, "apply");
        new_app(&mut s, ["shop", "nginx:1.27", "80", "shop.example.com", ""]);
        s.settle();
        let v = s.flat();
        assert!(s.notice().contains("shop is starting"), "{:?}", s.notice());
        assert!(v.contains("! Cloudflare Tunnel: not synced:") && v.contains("having trouble"), "a card: {v}");
        assert!(v.contains("shop itself is done.") && v.contains("o open Outside"), "{v}");
        assert_eq!(calls(&fake, "apply"), applied + 1, "the app was started anyway");
        // The screen still works.
        s.key(Key::Char('r'));
        s.settle();
        assert!(s.flat().contains("shop"), "{}", s.view());
    }

    #[test]
    fn two_apps_claim_one_name() {
        let fake = Arc::new(Fake::default());
        let twice = LISTING.replace(
            r#"{"kind":"Pod","metadata":{"name":"blog-1""#,
            r#"{"kind":"Deployment","metadata":{"name":"shop","namespace":"apps","labels":{"app":"shop"}},"spec":{"replicas":1},"status":{"readyReplicas":1}},
      {"kind":"Ingress","metadata":{"name":"shop","namespace":"apps","labels":{"app":"shop"}},"spec":{"rules":[{"host":"blog.example.com"}]}},
      {"kind":"Pod","metadata":{"name":"blog-1""#,
        );
        *fake.listing.lock().unwrap() = twice;
        let dir = crate::testutil::TempDir::new();
        let mut s = open(&fake, &dir);
        s.resize(100, 32);
        let v = s.flat();
        assert!(v.contains("! shop 1 of 1 running") && v.contains("claimed twice: blog.example.com"), "{v}");
        assert!(v.contains("! blog 1 of 2 running"), "both are marked: {v}");
        // The sheet and the remove say what it means.
        s.key(Key::Down);
        s.key(Key::Enter);
        assert!(s.flat().contains("blog.example.com is claimed by shop too, so none of them gets it from outside"), "{}", s.view());
        s.key(Key::Char('d'));
        assert!(s.flat().contains("blog.example.com is claimed by shop too: after this, shop gets it from outside."), "{}", s.view());
    }

    #[test]
    fn many_apps_keep_the_selection_in_view() {
        let fake = Arc::new(Fake::default());
        let items: Vec<String> = (0..40)
            .map(|i| format!(r#"{{"kind":"Deployment","metadata":{{"name":"app{i:02}","namespace":"apps","labels":{{"app":"app{i:02}"}}}},"spec":{{"replicas":1}},"status":{{"readyReplicas":1}}}}"#))
            .collect();
        *fake.listing.lock().unwrap() = format!(r#"{{"items":[{}]}}"#, items.join(","));
        let dir = crate::testutil::TempDir::new();
        let mut s = open(&fake, &dir);
        for n in [0usize, 25, 39, 3] {
            while s.s.cursor < n {
                s.key(Key::Down);
            }
            while s.s.cursor > n {
                s.key(Key::Up);
            }
            let r = s.rows();
            let row = r.iter().find(|l| l.contains(&format!("app{n:02} "))).unwrap_or_else(|| panic!("app{n:02} not in view:\n{r:#?}"));
            assert!(row.starts_with(" ▌ ✓  app"), "{row:?}");
        }
        // Small and large windows, every tier.
        for (tier, console) in [(Tier::True, false), (Tier::C256, false), (Tier::Console, true), (Tier::Plain, false)] {
            s.tier = (tier, console);
            for (w, h) in [(80, 24), (100, 32), (200, 60)] {
                s.resize(w, h);
                assert!(s.rows().iter().any(|l| l.contains("app03")), "{tier:?} {w}x{h}");
            }
        }
        // Under 80 x 24 the frame says so.
        s.resize(70, 20);
        assert!(s.flat().contains("Make this window at least"));
    }
}
