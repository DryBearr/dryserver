//! The admin's screen for apps on the cluster: what runs where, start one
//! from an image, remove one. The ways in from outside have their own
//! screen (o goes there).
//!
//! Every question and change goes to the coordinator over SSH, which can
//! be slow or not answer at all. They run on the screen's worker thread,
//! one at a time, each with a time limit; the screen keeps drawing and
//! taking keys, and shows what it is waiting for.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::form::{Field, Form, Group, Status};
use super::outside::{Look, look};
use super::worker::{Limits, Waiting, Worker, timed};
use super::{Doc, Emit, Event, Flow, Key, Model, Place, dim, err, fit, ok, sel, theme, wrap};
use crate::apps::{self, App, Cluster, Overview};
use crate::ctx::Ctx;
use crate::entrance::{self, Entrances, Health, State};
use crate::err::{Error, Result};

/// Each refresh asks the coordinator once, over the shared connection.
const REFRESH: Duration = Duration::from_secs(15);

/// What the worker answers; one message per job, in the order sent.
pub enum Msg {
    Loaded(Result<Look>),
    /// A change ended: what to tell the admin.
    Changed(String),
}

/// What the worker does for the screen.
enum Job {
    Load,
    Deploy(App),
    Remove(String),
}

const LOADING: &str = "asking the coordinator";

impl Job {
    fn label(&self) -> String {
        match self {
            Job::Load => LOADING.into(),
            Job::Deploy(a) => format!("starting {}", a.name),
            Job::Remove(n) => format!("removing {n}"),
        }
    }
}

/// What the cluster says now.
fn listing(ctx: &Ctx, c: &dyn Cluster, limits: Limits) -> Result<Overview> {
    apps::overview(&ctx.with_timeout(limits.read), c).map_err(|e| timed(e, limits.read))
}

/// Starts app, unless another app has its public name. The check uses
/// what the cluster says now, not what the screen saw a while ago, which
/// it returns.
fn deploy(ctx: &Ctx, c: &dyn Cluster, limits: Limits, app: &App) -> Result<Overview> {
    let before = listing(ctx, c, limits)?;
    entrance::check_host(app, &before.apps)?;
    apps::deploy(&ctx.with_timeout(limits.change), c, app).map_err(|e| timed(e, limits.change))?;
    Ok(before)
}

/// The entrance an app's public name came in through, if it had one.
fn came_through(before: &Overview, name: &str) -> Option<String> {
    before.apps.iter().find(|a| a.name == name && !a.host.is_empty()).map(|a| a.entrance.clone())
}

/// After an app changed: the entrances its name came or comes through
/// sync by themselves when they can (Cloudflare with an API token), from
/// what the cluster says now. Returns what to add to the notice.
fn sync_after(ctx: &Ctx, c: &dyn Cluster, doors: &Entrances, limits: Limits, ids: &[String]) -> String {
    let mut said = String::new();
    for d in doors.iter().filter(|d| d.automatic() && ids.iter().any(|id| id == d.id())) {
        let res = listing(ctx, c, limits).and_then(|o| {
            let want = entrance::wants(&o.apps).0.get(d.id()).cloned().unwrap_or_default();
            d.sync(&ctx.with_timeout(limits.change), c, &o, &want, false).map_err(|e| timed(e, limits.change))
        });
        said += &match res {
            Ok(r) if r.conflicts.is_empty() => format!("\n{}: {}.", d.title(), r.summary(false)),
            Ok(r) => format!("\n{}: {} (the Outside screen shows which).", d.title(), r.summary(false)),
            Err(e) => format!("\n{}: not synced: {e}", d.title()),
        };
    }
    said
}

/// One job, on the worker thread.
fn run(ctx: &Ctx, c: &dyn Cluster, doors: &Entrances, limits: Limits, job: Job) -> Msg {
    let change = ctx.with_timeout(limits.change);
    let automatic = doors.iter().any(|d| d.automatic());
    match job {
        Job::Load => Msg::Loaded(look(ctx, c, doors, limits)),
        Job::Deploy(app) => Msg::Changed(match deploy(ctx, c, limits, &app) {
            Ok(before) => {
                let mut ids: Vec<String> = came_through(&before, &app.name).into_iter().collect();
                if !app.host.is_empty() {
                    ids.push(app.entrance.clone());
                }
                let synced = if automatic { sync_after(ctx, c, doors, limits, &ids) } else { String::new() };
                format!("{} is starting. The cluster picks a server for it.{synced}", app.name)
            }
            Err(e) => format!("Not started: {e}"),
        }),
        Job::Remove(name) => {
            // Which entrance to sync afterwards: only worth a look when one
            // syncs by itself. Without the look nothing is synced, and the
            // admin hears why.
            let before = if automatic { Some(listing(ctx, c, limits)) } else { None };
            Msg::Changed(match apps::remove(&change, c, &name) {
                Ok(()) => match before {
                    Some(Err(e)) => format!("{name} removed.\nThe ways in from outside were not synced: {e}"),
                    before => {
                        let ids: Vec<String> = before.and_then(|b| b.ok()).and_then(|b| came_through(&b, &name)).into_iter().collect();
                        format!("{name} removed.{}", sync_after(ctx, c, doors, limits, &ids))
                    }
                },
                Err(e) => format!("Not removed: {}", timed(e, limits.change)),
            })
        }
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
    fn app(&self) -> App {
        App {
            name: self.name.trim().into(),
            image: self.image.trim().into(),
            port: self.port.trim().parse().unwrap_or(0),
            host: self.host.trim().to_ascii_lowercase(),
            entrance: self.entrance.clone(),
            copies: if self.copies.trim().is_empty() { 1 } else { self.copies.trim().parse().unwrap_or(0) },
        }
    }
}

/// The form for a new app. taken: (host name, app) pairs the cluster has
/// now; doors: the entrances apps may choose (id, title). With only one
/// the choice is not asked.
fn new_app_form(taken: Vec<(String, String)>, doors: Vec<(String, String)>) -> Form<Draft> {
    type D = Draft;
    let first = doors.first().map(|d| d.0.clone()).unwrap_or_else(|| entrance::DEFAULT.into());
    let choose = doors.len() > 1;
    let draft = Draft {
        name: String::new(),
        image: String::new(),
        port: String::new(),
        host: String::new(),
        entrance: first,
        copies: String::new(),
    };
    Form::new(
        draft,
        vec![
            Group::new(vec![
                Field::input("Name", |d: &D| d.name.clone(), |d, v| d.name = v)
                    .placeholder("blog")
                    .desc("Starts with a letter; lowercase letters, digits and -. Other apps reach it as http://NAME.")
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
            ]),
            Group::new(vec![
                Field::input("Public host name (optional)", |d: &D| d.host.clone(), |d, v| d.host = v)
                    .placeholder("blog.example.com")
                    .desc("Leave empty to keep the app inside the cluster. With a name, the ingress\nroutes that name to it; the Outside screen shows how it comes in.")
                    .validate(move |v, d| {
                        let host = v.trim().to_ascii_lowercase();
                        apps::valid_host(&host)?;
                        match taken.iter().find(|(h, a)| *h == host && *a != d.name.trim()) {
                            Some((_, other)) => Err(crate::errf!("already the public name of {other}")),
                            None => Ok(()),
                        }
                    }),
            ]),
            Group::new(vec![
                Field::select("Way in from outside", move |_| doors.iter().map(|(id, t)| (t.clone(), id.clone())).collect(), |d: &D| d.entrance.clone(), |d, v| d.entrance = v)
                    .desc("Which entrance brings this name from the internet to the app."),
            ])
            .hide_if(move |d| !choose || d.host.trim().is_empty()),
            Group::new(vec![
                Field::input("Copies", |d: &D| d.copies.clone(), |d, v| d.copies = v)
                    .placeholder("1")
                    .desc("How many to run. More than one spreads over your servers.")
                    .validate(|v, _| match v.trim() {
                        "" => Ok(()),
                        n => match n.parse::<u32>() {
                            Ok(c) if (1..=20).contains(&c) => Ok(()),
                            _ => Err("1 to 20".into()),
                        },
                    }),
            ]),
        ],
        "back",
    )
}

pub struct Screen {
    cluster: Arc<dyn Cluster>,
    doors: Entrances,
    limits: Limits,
    /// Started when the screen opens; dropped with it, which cancels the
    /// call that runs.
    worker: Option<Worker<Job>>,
    waiting: Waiting,
    now: Overview,
    /// How each entrance is doing, in the order of doors.
    states: Vec<State>,
    /// When the coordinator last answered a refresh.
    seen: Option<Instant>,
    err: Option<Error>,
    cursor: usize,
    form: Option<Form<Draft>>,
    /// An app to remove once the admin says y.
    confirm: Option<String>,
    pub notice: String,
    last_load: Option<Instant>,
    /// q was pressed once while a change was still being sent.
    quit_armed: bool,
    width: usize,
    /// Where to go after this screen closes.
    pub next: Option<Place>,
}

impl Screen {
    pub fn new(cluster: Arc<dyn Cluster>, doors: Entrances) -> Screen {
        Screen {
            cluster,
            doors,
            limits: Limits::default(),
            worker: None,
            waiting: Waiting::default(),
            now: Overview::default(),
            states: Vec::new(),
            seen: None,
            err: None,
            cursor: 0,
            form: None,
            confirm: None,
            notice: String::new(),
            last_load: None,
            quit_armed: false,
            width: 80,
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
        self.worker = Some(Worker::start(move |ctx, job| emit(run(ctx, c.as_ref(), &doors, limits, job))));
    }

    fn send(&mut self, job: Job) {
        let (label, change) = (job.label(), !matches!(job, Job::Load));
        if self.worker.as_ref().is_some_and(|w| w.send(job)) {
            self.waiting.push(label, change);
        } else {
            self.notice = "The background worker stopped; quit and open the screen again.".into();
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
        self.waiting.pop();
        match m {
            Msg::Loaded(Ok((o, states))) => {
                self.now = o;
                self.states = states;
                self.err = None;
                self.seen = Some(Instant::now());
            }
            Msg::Loaded(Err(e)) => self.err = Some(e),
            Msg::Changed(notice) => {
                self.notice = notice;
                self.quit_armed = false;
                self.load();
            }
        }
        self.cursor = self.cursor.min(self.now.apps.len().saturating_sub(1));
    }

    fn open_form(&mut self) {
        let taken = self.now.apps.iter().filter(|a| !a.host.is_empty()).map(|a| (a.host.clone(), a.name.clone())).collect();
        let doors = self.doors.iter().filter(|d| d.ready()).map(|d| (d.id().to_string(), d.title().to_string())).collect();
        self.form = Some(new_app_form(taken, doors));
    }

    pub fn key(&mut self, k: Key) -> Flow {
        if let Some(f) = self.form.as_mut() {
            f.update(&k);
            match f.status {
                Status::Completed => {
                    let app = self.form.take().map(|f| f.state.app()).unwrap_or_default();
                    self.notice.clear();
                    self.send(Job::Deploy(app));
                }
                Status::Aborted => {
                    self.form = None;
                    self.notice = "Nothing started.".into();
                }
                Status::Active => {}
            }
            return Flow::Continue;
        }
        if let Some(name) = self.confirm.take() {
            if k == Key::Char('y') {
                self.notice.clear();
                self.send(Job::Remove(name));
            } else {
                self.notice = "Nothing removed.".into();
            }
            return Flow::Continue;
        }
        let armed = std::mem::take(&mut self.quit_armed);
        match k {
            Key::Ctrl('c') => return Flow::Quit,
            Key::Char('q') | Key::Esc => {
                // Quitting kills the call that runs. A refresh does not
                // matter; a change cut off half way would.
                match self.waiting.change() {
                    Some(what) if !armed => {
                        self.notice = format!("Still {what}. Press q again to quit anyway; it may stop half way.");
                        self.quit_armed = true;
                    }
                    _ => return Flow::Quit,
                }
            }
            Key::Char('o') => {
                self.next = Some(Place::Outside);
                return Flow::Quit;
            }
            Key::Up | Key::Char('k') => self.cursor = self.cursor.saturating_sub(1),
            Key::Down | Key::Char('j') => self.cursor = (self.cursor + 1).min(self.now.apps.len().saturating_sub(1)),
            Key::Char('n') => {
                self.notice.clear();
                self.open_form();
            }
            Key::Char('d') => match self.now.apps.get(self.cursor) {
                Some(a) => self.confirm = Some(a.name.clone()),
                None => self.notice = "No app selected.".into(),
            },
            Key::Char('r') => {
                self.notice = if self.load() { String::new() } else { "Already asking the coordinator.".into() };
            }
            _ => {}
        }
        Flow::Continue
    }

    /// The ways in that are set up, on one line.
    fn outside(&self, b: &mut Doc) {
        b.s("  From outside: ");
        let open: Vec<(&str, &State)> =
            self.doors.iter().zip(&self.states).filter(|(_, s)| s.health != Health::NotSetUp).map(|(d, s)| (d.title(), s)).collect();
        if self.seen.is_none() {
            b.add(dim("not known yet"));
        } else if open.is_empty() {
            b.add(dim("closed. o shows the ways in from the internet."));
        }
        for (i, (title, s)) in open.iter().enumerate() {
            if i > 0 {
                b.s("; ");
            }
            let text = format!("{title} {}", s.summary);
            if s.health == Health::Up {
                b.add(ok(text));
            } else {
                b.add(err(text));
            }
        }
        b.nl();
    }
}

impl Model for Screen {
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
            Event::Resize(w, _) => {
                self.width = (w as usize).max(40);
                Flow::Continue
            }
        }
    }

    fn view(&self) -> Doc {
        let mut b = Doc::new();
        let width = self.width.saturating_sub(2);
        if let Some(f) = &self.form {
            b.append(theme::header("new app")).s("\n\n");
            b.append(f.view());
            if let Some(w) = self.waiting.view(self.limits.slow, "the coordinator is not answering") {
                b.nl().append(w).nl();
            }
            return b;
        }
        b.append(theme::header("apps")).s("   ").add(dim("the cluster picks a server for each, and moves it")).s("\n\n");
        if let Some(e) = &self.err {
            b.add(err(wrap(&format!("Cannot reach the cluster: {e}"), width))).nl();
            match self.seen {
                Some(t) => b.add(dim(format!("  What you see is from {} ago. r asks again.", super::since(t)))),
                None => b.add(dim("  r asks again.")),
            };
            b.s("\n\n");
        }
        // The way in from outside comes first: it decides who can reach
        // anything below.
        self.outside(&mut b);
        b.nl();
        if self.now.apps.is_empty() && self.err.is_none() && self.seen.is_some() {
            b.add(dim("  No apps yet. Press n to start one from a container image.")).nl();
        }
        for (i, a) in self.now.apps.iter().enumerate() {
            let on = if a.nodes.is_empty() { "-".to_string() } else { a.nodes.join(",") };
            let host = if a.host.is_empty() { "inside only" } else { &a.host };
            let state = format!("{}/{} running", a.ready, a.copies);
            // Name, state and name from outside first: on a narrow screen
            // the image is what gets cut.
            // A wider screen gives the servers more room first.
            let nodes = 12 + width.saturating_sub(78).min(20);
            let on = fit(&on, nodes);
            let line = format!("{:<14} {:<12} {:<26} {on:<nodes$} {}", fit(&a.name, 14), state, fit(host, 26), a.image);
            let line = fit(&line, width.saturating_sub(2));
            let healthy = a.copies > 0 && a.ready == a.copies;
            if i == self.cursor {
                b.add(sel(format!("> {line}"))).nl();
            } else if healthy {
                b.s(format!("  {line}")).nl();
            } else {
                b.s("  ").add(err(line)).nl();
            }
        }
        if let Some(w) = self.waiting.view(self.limits.slow, "the coordinator is not answering") {
            b.nl().append(w).nl();
        }
        if let Some(name) = &self.confirm {
            b.nl().add(err(format!("Remove {name}? Its containers stop. y to confirm"))).nl();
        } else if !self.notice.is_empty() {
            b.nl().s(wrap(&self.notice, width)).nl();
        }
        b.nl()
            .append(theme::keys(&[("↑↓", "select"), ("n", "new app"), ("d", "remove"), ("o", "outside"), ("r", "refresh"), ("q", "quit")]))
            .nl();
        b
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::apps::tests::{Fake, LISTING};
    use crate::entrance::cloudflare::Cloudflare;
    use crate::entrance::{Entrance, Report, Traffic, Vps, Want};
    use crate::tui::collector;
    use std::sync::atomic::Ordering::SeqCst;
    use std::sync::mpsc::Receiver;

    pub struct Open<S: Model> {
        pub s: S,
        pub rx: Receiver<S::Msg>,
        pub emit: Emit<S::Msg>,
    }

    pub trait Busy {
        fn busy(&self) -> bool;
    }

    impl Busy for Screen {
        fn busy(&self) -> bool {
            !self.waiting.is_empty()
        }
    }

    impl<S: Model + Busy> Open<S> {
        pub fn new(mut s: S) -> Open<S> {
            let (emit, rx) = collector();
            s.init(&emit);
            Open { s, rx, emit }
        }

        /// Feeds the worker's answers to the screen until nothing waits.
        pub fn settle(&mut self) {
            while self.s.busy() {
                let m = self.rx.recv_timeout(Duration::from_secs(10)).expect("the worker did not answer");
                self.s.update(Event::Msg(m), &self.emit);
            }
        }

        pub fn key(&mut self, k: Key) -> Flow {
            self.s.update(Event::Key(k), &self.emit)
        }

        pub fn type_in(&mut self, text: &str) {
            for k in crate::tui::type_text(text) {
                self.key(k);
            }
            self.key(Key::Enter);
        }

        pub fn view(&self) -> String {
            self.s.view().plain()
        }

        /// The view as one line: wrapped text reads as it was written.
        pub fn flat(&self) -> String {
            self.view().replace('\n', " ")
        }

        /// The screen fits 80 columns and the given number of rows.
        pub fn fits(&self, rows: usize) {
            use unicode_width::UnicodeWidthStr;
            let v = self.view();
            for l in v.lines() {
                assert!(l.width() <= 80, "wider than 80 columns ({}): {l:?}\n{v}", l.width());
            }
            assert!(v.lines().count() <= rows, "more than {rows} rows:\n{v}");
        }
    }

    pub fn doors(dir: &crate::testutil::TempDir) -> Entrances {
        Arc::new(vec![Box::new(Cloudflare::new(dir.path())), Box::new(Vps)])
    }

    fn open_with(fake: &Arc<Fake>, dir: &crate::testutil::TempDir, limits: Limits) -> Open<Screen> {
        Open::new(Screen::new(fake.clone(), doors(dir)).with_limits(limits))
    }

    fn open(fake: &Arc<Fake>, dir: &crate::testutil::TempDir) -> Open<Screen> {
        let mut o = open_with(fake, dir, Limits::default());
        o.settle();
        o
    }

    fn calls(fake: &Fake, what: &str) -> usize {
        fake.calls.lock().unwrap().iter().filter(|(a, _)| a.starts_with(what)).count()
    }

    #[test]
    fn list_new_and_remove() {
        let fake = Arc::new(Fake::default());
        let dir = crate::testutil::TempDir::new();
        let mut s = open(&fake, &dir);
        assert!(s.view().contains("No apps yet. Press n"), "{}", s.view());
        assert!(s.view().contains("From outside: closed. o shows the ways in"), "{}", s.view());
        s.fits(24);

        // A new app: name, image, port, then a public name and one copy.
        // With one entrance there is no choice to make.
        s.key(Key::Char('n'));
        assert!(s.view().contains("dryserver  new app"));
        s.type_in("blog");
        s.type_in("ghcr.io/me/blog:v2");
        s.type_in("8080");
        s.type_in("Blog.Example.com");
        assert!(!s.view().contains("Way in from outside"), "{}", s.view());
        s.type_in("");
        s.settle();
        assert!(s.s.notice.contains("blog is starting"), "{:?}\n{}", s.s.notice, s.view());
        let calls = fake.calls.lock().unwrap().clone();
        let (args, manifest) = calls.iter().find(|(a, _)| a == "apply -f -").expect("nothing applied");
        assert_eq!(args, "apply -f -");
        assert!(
            manifest.contains("image: \"ghcr.io/me/blog:v2\"")
                && manifest.contains("- host: \"blog.example.com\"")
                && manifest.contains("dryserver/entrance: \"cloudflare\"")
                && manifest.contains("replicas: 1"),
            "{manifest}"
        );
        assert!(calls.last().unwrap().0.starts_with("get"), "the screen asks again after a change: {calls:?}");

        // The cluster now has it (and one that is not healthy).
        *fake.listing.lock().unwrap() = LISTING.into();
        s.key(Key::Char('r'));
        s.settle();
        let v = s.view();
        assert!(v.contains("blog") && v.contains("node-a,node") && v.contains("blog.example.com") && v.contains("1/2 running"), "{v}");
        assert!(v.contains("api") && v.contains("inside only") && v.contains("0/1 running"), "{v}");
        assert!(v.contains("From outside: Cloudflare Tunnel connected with 1 of 2 copies"), "{v}");
        s.fits(24);
        // A wider terminal shows all of it.
        s.s.update(Event::Resize(120, 40), &s.emit.clone());
        assert!(s.view().contains("node-a,node-b") && s.view().contains(" ghcr.io/me/blog:v2"), "{}", s.view());
        s.s.update(Event::Resize(80, 24), &s.emit.clone());

        // Remove asks first; the cursor is on api, the first by name.
        s.key(Key::Char('d'));
        assert!(s.view().contains("Remove api? Its containers stop. y to confirm"));
        s.key(Key::Char('n'));
        assert!(s.s.notice.contains("Nothing removed") && !fake.calls.lock().unwrap().iter().any(|(a, _)| a.contains("delete")));
        s.key(Key::Down);
        s.key(Key::Char('d'));
        s.key(Key::Char('y'));
        s.settle();
        assert!(s.s.notice.contains("blog removed"), "{:?}", s.s.notice);
        assert!(fake.calls.lock().unwrap().iter().any(|(a, _)| a.contains("delete") && a.contains("-l app=blog")));

        // o goes to the Outside screen.
        assert_eq!(s.key(Key::Char('o')), Flow::Quit);
        assert_eq!(s.s.next, Some(Place::Outside));
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
        s.key(Key::Esc);
        // The same app may keep its name.
        s.key(Key::Char('n'));
        for t in ["blog", "nginx:1.27", "80", "blog.example.com", ""] {
            s.type_in(t);
        }
        s.settle();
        assert!(s.s.notice.contains("blog is starting"), "{:?}", s.s.notice);
        // The cluster changed while the form was open: the deploy checks
        // again before it applies anything.
        s.key(Key::Char('n'));
        for t in ["news", "nginx:1.27", "80", "news.example.com"] {
            s.type_in(t);
        }
        let mut taken = LISTING.to_string();
        taken = taken.replace("\"host\":\"blog.example.com\"", "\"host\":\"news.example.com\"");
        *fake.listing.lock().unwrap() = taken;
        let applied = calls(&fake, "apply");
        s.type_in("");
        s.settle();
        assert!(s.s.notice.contains("Not started: news.example.com is already the public name of blog"), "{:?}", s.s.notice);
        assert_eq!(calls(&fake, "apply"), applied, "nothing was applied");
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
        let mut s = Open::new(Screen::new(fake.clone(), two));
        s.settle();
        assert!(s.view().contains("From outside: Your VPS up"), "{}", s.view());
        s.key(Key::Char('n'));
        for t in ["game", "nginx:1.27", "80", "play.example.com"] {
            s.type_in(t);
        }
        let v = s.view();
        assert!(v.contains("Way in from outside") && v.contains("> Cloudflare Tunnel") && v.contains("Your VPS"), "{v}");
        s.key(Key::Down);
        s.key(Key::Enter);
        s.type_in("");
        s.settle();
        let calls = fake.calls.lock().unwrap().clone();
        let (_, manifest) = calls.iter().find(|(a, _)| a == "apply -f -").expect("nothing applied");
        assert!(manifest.contains("dryserver/entrance: \"vps\""), "{manifest}");
        // Without a public name the choice is not asked.
        s.key(Key::Char('n'));
        for t in ["inside", "nginx:1.27", "80", ""] {
            s.type_in(t);
        }
        assert!(s.view().contains("Copies") && !s.view().contains("Way in from outside"), "{}", s.view());
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
        s.key(Key::Esc);
        assert!(s.s.notice.contains("Nothing started") && fake.calls.lock().unwrap().iter().all(|(a, _)| !a.contains("apply")));
        // The cluster is not reachable.
        *fake.fail.lock().unwrap() = Some("cannot log in to the coordinator".into());
        s.key(Key::Char('r'));
        s.settle();
        assert!(s.view().contains("Cannot reach the cluster: cannot log in"), "{}", s.view());
        assert!(s.view().contains("What you see is from"), "{}", s.view());
        s.key(Key::Char('d'));
        assert!(s.s.notice.contains("No app selected"));
    }

    #[test]
    fn keys_work_while_the_coordinator_is_slow() {
        let fake = Arc::new(Fake::default());
        *fake.delay.lock().unwrap() = Duration::from_millis(400);
        *fake.listing.lock().unwrap() = LISTING.into();
        let dir = crate::testutil::TempDir::new();
        let mut s = open_with(&fake, &dir, Limits { slow: Duration::from_millis(100), ..Limits::default() });
        assert!(s.view().contains("asking the coordinator…") && s.view().contains("From outside: not known yet"), "{}", s.view());
        // Every key answers at once while the call runs.
        let start = Instant::now();
        for k in [Key::Down, Key::Up, Key::Char('n'), Key::Esc, Key::Char('d'), Key::Char('x')] {
            s.key(k);
        }
        assert!(start.elapsed() < Duration::from_millis(100), "keys waited for the coordinator: {:?}", start.elapsed());
        std::thread::sleep(Duration::from_millis(150));
        assert!(s.view().contains("the coordinator is not answering ("), "{}", s.view());
        s.settle();
        assert!(s.view().contains("1/2 running") && !s.view().contains("not answering"), "{}", s.view());
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
        assert_eq!(s.s.notice, "Already asking the coordinator.");
        s.settle();
        assert_eq!(calls(&fake, "get"), 1, "{:?}", fake.calls.lock().unwrap());
        // Ticks right after an answer do not ask again either.
        s.s.update(Event::Tick, &s.emit.clone());
        assert!(s.s.waiting.is_empty());
    }

    #[test]
    fn a_change_waits_for_the_refresh_that_runs() {
        let fake = Arc::new(Fake::default());
        *fake.delay.lock().unwrap() = Duration::from_millis(200);
        let dir = crate::testutil::TempDir::new();
        let mut s = open_with(&fake, &dir, Limits::default());
        // The first refresh runs; the admin starts an app meanwhile.
        s.key(Key::Char('n'));
        for t in ["blog", "nginx:1.27", "80", "", ""] {
            s.type_in(t);
        }
        assert!(s.view().contains("asking the coordinator…  then starting blog"), "{}", s.view());
        // A refresh asked for now waits behind both, and only once.
        s.key(Key::Char('r'));
        s.key(Key::Char('r'));
        s.settle();
        let order: Vec<String> = fake.calls.lock().unwrap().iter().map(|(a, _)| a.split(' ').next().unwrap_or("").to_string()).collect();
        // The deploy looks at the cluster first, then applies.
        assert_eq!(order, vec!["get", "get", "apply", "-n", "get"], "{order:?}");
        assert!(s.s.notice.contains("blog is starting"), "{:?}", s.s.notice);
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
        assert!(s.view().contains("Cannot reach the cluster: the coordinator did not answer within 0s. Is it on?"), "{}", s.view());
        // A change gives up too, and says what did not happen.
        s.s.now = apps::overview(&Ctx::new(), &Fake { listing: LISTING.to_string().into(), ..Fake::default() }).unwrap();
        s.key(Key::Char('d'));
        s.key(Key::Char('y'));
        s.settle();
        assert!(s.s.notice.starts_with("Not removed: the coordinator did not answer"), "{:?}", s.s.notice);
        assert_eq!(fake.cut_off.load(SeqCst), fake.calls.lock().unwrap().len(), "every call was cut off by its limit");
    }

    #[test]
    fn closing_while_a_call_runs() {
        let fake = Arc::new(Fake::default());
        *fake.delay.lock().unwrap() = Duration::from_secs(30);
        let dir = crate::testutil::TempDir::new();
        let mut s = open_with(&fake, &dir, Limits::default());
        std::thread::sleep(Duration::from_millis(50));
        // Quitting during a refresh is immediate.
        assert_eq!(s.key(Key::Char('q')), Flow::Quit);
        let start = Instant::now();
        drop(s);
        assert!(start.elapsed() < Duration::from_secs(1), "closing waited {:?}", start.elapsed());
        assert_eq!(fake.cut_off.load(SeqCst), 1, "the call was cancelled, not left running");
    }

    #[test]
    fn quitting_during_a_change_asks_once() {
        let fake = Arc::new(Fake::default());
        let dir = crate::testutil::TempDir::new();
        let mut s = open(&fake, &dir);
        *fake.delay.lock().unwrap() = Duration::from_secs(30);
        s.s.now = apps::overview(&Ctx::new(), &Fake { listing: LISTING.to_string().into(), ..Fake::default() }).unwrap();
        s.key(Key::Char('d'));
        s.key(Key::Char('y'));
        assert_eq!(s.key(Key::Char('q')), Flow::Continue);
        assert!(s.s.notice.contains("Still removing api. Press q again"), "{:?}", s.s.notice);
        // Another key disarms it; q then asks again.
        s.key(Key::Down);
        assert_eq!(s.key(Key::Char('q')), Flow::Continue);
        assert_eq!(s.key(Key::Char('q')), Flow::Quit);
        // ctrl+c never asks.
        assert_eq!(s.key(Key::Ctrl('c')), Flow::Quit);
    }

    #[test]
    fn an_answer_after_the_screen_closed() {
        // The coordinator answers late and the call ignores the cancel:
        // the answer goes to a closed channel, nothing panics, and the
        // worker ends.
        let fake = Arc::new(Fake::default());
        *fake.stubborn.lock().unwrap() = Duration::from_millis(300);
        let dir = crate::testutil::TempDir::new();
        let Open { s, rx, .. } = open_with(&fake, &dir, Limits::default());
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
        let mut s = Open::new(Screen::new(fake.clone(), doors.clone()));
        s.settle();
        assert!(cf.calls.lock().unwrap().is_empty(), "a refresh does not ask Cloudflare");
        let deploy_blog = |s: &mut Open<Screen>| {
            s.key(Key::Char('n'));
            for t in ["blog", "nginx:1.27", "80", "blog.example.com", ""] {
                s.type_in(t);
            }
            s.settle();
        };
        let names = |cf: &FakeCf| cf.cf.lock().unwrap().records.iter().map(|r| r.name.clone()).collect::<Vec<_>>();
        // The cluster runs a tunnel set up by hand (LISTING's token mark):
        // nothing in Cloudflare changes, and the screen says why. A tunnel
        // dryserver with DNS names that no connector serves would answer
        // every visitor with error 1033.
        deploy_blog(&mut s);
        let n = &s.s.notice;
        assert!(n.contains("blog is starting") && n.contains("Cloudflare Tunnel: left as it is: the cluster runs a tunnel"), "{n:?}");
        assert!(n.contains("s on the Outside screen switches to the tunnel dryserver"), "{n:?}");
        assert_eq!(cf.changes.load(SeqCst), 0);
        assert!(cf.cf.lock().unwrap().tunnels.is_empty() && names(&cf).is_empty());
        assert!(!fake.calls.lock().unwrap().iter().any(|(a, m)| a == "apply -f -" && m.contains("cloudflared")), "left running");
        s.fits(24);
        // The admin switches on purpose (s on the Outside screen); the
        // cluster then runs the tunnel dryserver.
        let o = apps::overview(&Ctx::new(), fake.as_ref()).unwrap();
        doors[0].sync(&Ctx::new(), fake.as_ref(), &o, &Want { open: true, ..Want::default() }, false).unwrap();
        let mark = mark_of(&fake).unwrap();
        *fake.listing.lock().unwrap() = LISTING.replace("00aa11bb22cc33dd", &mark);
        deploy_blog(&mut s);
        let n = &s.s.notice;
        assert!(n.contains("blog is starting") && n.contains("Cloudflare Tunnel: 2 changes made."), "{n:?}");
        assert_eq!(names(&cf), vec!["blog.example.com"]);
        // Removed: its name goes too.
        *fake.after_delete.lock().unwrap() =
            Some(LISTING.replace("00aa11bb22cc33dd", &mark).replace("\"host\":\"blog.example.com\"", "\"host\":\"\""));
        s.key(Key::Down);
        s.key(Key::Char('d'));
        s.key(Key::Char('y'));
        s.settle();
        assert!(s.s.notice.contains("blog removed.") && s.s.notice.contains("Cloudflare Tunnel: 2 changes made."), "{:?}", s.s.notice);
        assert!(names(&cf).is_empty());
        s.fits(24);

        // Without an API token nothing goes to Cloudflare.
        let dir = crate::testutil::TempDir::new();
        let cf: Arc<FakeCf> = Arc::new(fresh());
        let doors: Entrances = Arc::new(vec![Box::new(entrance(dir.path(), &cf, false)), Box::new(Vps)]);
        let mut s = Open::new(Screen::new(fake.clone(), doors));
        s.settle();
        s.key(Key::Char('n'));
        for t in ["shop", "nginx:1.27", "80", "shop.example.com", ""] {
            s.type_in(t);
        }
        s.settle();
        assert!(s.s.notice.contains("shop is starting") && !s.s.notice.contains("Cloudflare"), "{:?}", s.s.notice);
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
        let mut s = Open::new(Screen::new(fake.clone(), doors));
        s.settle();
        assert!(s.flat().contains("Cannot reach the cluster: the cluster sent an empty answer"), "{}", s.view());
        assert!(!s.view().contains("No apps yet"), "{}", s.view());
        // A deploy looks first, and stops.
        s.key(Key::Char('n'));
        for t in ["blog", "nginx:1.27", "80", "blog.example.com", ""] {
            s.type_in(t);
        }
        s.settle();
        assert!(s.s.notice.contains("Not started: the cluster sent an empty answer"), "{:?}", s.s.notice);
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
        let n = &s.s.notice;
        assert!(n.contains("blog removed.") && n.contains("not synced: the cluster sent an empty answer"), "{n:?}");
        *fake.listing.lock().unwrap() = SILENT.into();
        s.s.now = apps::overview(&Ctx::new(), &Fake { listing: LISTING.to_string().into(), ..Fake::default() }).unwrap();
        s.key(Key::Up);
        s.key(Key::Char('d'));
        s.key(Key::Char('y'));
        s.settle();
        let n = &s.s.notice;
        assert!(n.contains("api removed.") && n.contains("were not synced: the cluster sent an empty answer"), "{n:?}");
        assert!(cf.calls.lock().unwrap().is_empty(), "nothing went to Cloudflare");
        s.fits(24);
    }

    #[test]
    fn cloudflare_down_does_not_stop_a_deploy() {
        use crate::entrance::cfsync::tests::{FakeCf, entrance, fresh};
        let fake = Arc::new(Fake::default());
        let dir = crate::testutil::TempDir::new();
        let cf: Arc<FakeCf> = Arc::new(fresh());
        cf.down.store(true, SeqCst);
        let doors: Entrances = Arc::new(vec![Box::new(entrance(dir.path(), &cf, true)), Box::new(Vps)]);
        let mut s = Open::new(Screen::new(fake.clone(), doors));
        s.settle();
        s.key(Key::Char('n'));
        for t in ["blog", "nginx:1.27", "80", "blog.example.com", ""] {
            s.type_in(t);
        }
        s.settle();
        let n = &s.s.notice;
        assert!(n.contains("blog is starting") && n.contains("Cloudflare Tunnel: not synced:") && n.contains("having trouble"), "{n:?}");
        assert_eq!(calls(&fake, "apply"), 1, "the app was started anyway");
    }
}
