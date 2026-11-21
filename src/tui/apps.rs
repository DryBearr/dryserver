//! The admin's screen for apps on the cluster: what runs where, start one
//! from an image, remove one, and open or close the way in from outside.
//!
//! Every question and change goes to the coordinator over SSH, which can
//! be slow or not answer at all. They run on the screen's worker thread,
//! one at a time, each with a time limit; the screen keeps drawing and
//! taking keys, and shows what it is waiting for.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::form::{Field, Form, Group, Status};
use super::worker::{Waiting, Worker};
use super::{Doc, Emit, Event, Flow, Key, Model, dim, err, ok, sel, theme};
use crate::apps::{self, App, Cluster, Overview};
use crate::ctx::Ctx;
use crate::err::{Error, Kind, Result};

/// Each refresh asks the coordinator once, over the shared connection.
const REFRESH: Duration = Duration::from_secs(15);

/// How long the coordinator may take to answer.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// A question: the listing.
    pub read: Duration,
    /// A change: kubectl apply waits for the cluster to take it.
    pub change: Duration,
    /// After this long without an answer the screen says so.
    pub slow: Duration,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { read: Duration::from_secs(15), change: Duration::from_secs(60), slow: Duration::from_secs(4) }
    }
}

/// What the worker answers; one message per job, in the order sent.
pub enum Msg {
    Loaded(Result<Overview>),
    /// A change ended: what to tell the admin.
    Changed(String),
}

/// What the worker does for the screen.
enum Job {
    Load,
    Deploy(App),
    Remove(String),
    Open(String),
    Close,
}

const LOADING: &str = "asking the coordinator";

impl Job {
    fn label(&self) -> String {
        match self {
            Job::Load => LOADING.into(),
            Job::Deploy(a) => format!("starting {}", a.name),
            Job::Remove(n) => format!("removing {n}"),
            Job::Open(_) => "opening the tunnel".into(),
            Job::Close => "closing the tunnel".into(),
        }
    }
}

/// A call that ran out of time says how long it was given.
fn timed(e: Error, limit: Duration) -> Error {
    if e.is(Kind::DeadlineExceeded) {
        Error::with_kind(Kind::DeadlineExceeded, format!("the coordinator did not answer within {}s. Is it on?", limit.as_secs()))
    } else {
        e
    }
}

/// One job, on the worker thread.
fn run(ctx: &Ctx, c: &dyn Cluster, limits: Limits, job: Job) -> Msg {
    let change = ctx.with_timeout(limits.change);
    let said = |r: Result<()>, done: String, failed: &str| match r {
        Ok(()) => done,
        Err(e) => format!("{failed}: {}", timed(e, limits.change)),
    };
    match job {
        Job::Load => Msg::Loaded(apps::overview(&ctx.with_timeout(limits.read), c).map_err(|e| timed(e, limits.read))),
        Job::Deploy(app) => Msg::Changed(said(
            apps::deploy(&change, c, &app),
            format!("{} is starting. The cluster picks a server for it.", app.name),
            "Not started",
        )),
        Job::Remove(name) => Msg::Changed(said(apps::remove(&change, c, &name), format!("{name} removed."), "Not removed")),
        Job::Open(token) => Msg::Changed(said(
            apps::connect_tunnel(&change, c, &token),
            format!("Tunnel starting. In the Cloudflare dashboard, point each public host name at\n{}", apps::TUNNEL_TARGET),
            "Tunnel not started",
        )),
        Job::Close => Msg::Changed(said(
            apps::remove_tunnel(&change, c),
            "Tunnel closed. Nothing from outside reaches your apps.".into(),
            "Tunnel not closed",
        )),
    }
}

/// What the admin types for a new app.
#[derive(Debug, Clone, Default)]
struct Draft {
    name: String,
    image: String,
    port: String,
    host: String,
    copies: String,
}

impl Draft {
    fn app(&self) -> App {
        App {
            name: self.name.trim().into(),
            image: self.image.trim().into(),
            port: self.port.trim().parse().unwrap_or(0),
            host: self.host.trim().to_ascii_lowercase(),
            copies: if self.copies.trim().is_empty() { 1 } else { self.copies.trim().parse().unwrap_or(0) },
        }
    }
}

fn new_app_form() -> Form<Draft> {
    type D = Draft;
    Form::new(
        Draft::default(),
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
                    .desc("Leave empty to keep the app inside the cluster. With a name, the ingress\nroutes that name to it; point the name at your tunnel.")
                    .validate(|v, _| apps::valid_host(&v.trim().to_ascii_lowercase())),
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

/// What waits for a "y".
#[derive(Debug, Clone, PartialEq)]
enum Confirm {
    None,
    /// Remove this app.
    Remove(String),
    /// Open the tunnel with this token.
    Open(String),
    Close,
}

pub struct Screen {
    cluster: Arc<dyn Cluster>,
    /// Where the admin saves the tunnel's token (in secrets/).
    token_file: PathBuf,
    limits: Limits,
    /// Started when the screen opens; dropped with it, which cancels the
    /// call that runs.
    worker: Option<Worker<Job>>,
    waiting: Waiting,
    now: Overview,
    /// When the coordinator last answered a refresh.
    seen: Option<Instant>,
    err: Option<Error>,
    cursor: usize,
    form: Option<Form<Draft>>,
    confirm: Confirm,
    pub notice: String,
    last_load: Option<Instant>,
    /// q was pressed once while a change was still being sent.
    quit_armed: bool,
}

impl Screen {
    pub fn new(cluster: Arc<dyn Cluster>, token_file: PathBuf) -> Screen {
        Screen {
            cluster,
            token_file,
            limits: Limits::default(),
            worker: None,
            waiting: Waiting::default(),
            now: Overview::default(),
            seen: None,
            err: None,
            cursor: 0,
            form: None,
            confirm: Confirm::None,
            notice: String::new(),
            last_load: None,
            quit_armed: false,
        }
    }

    #[cfg(test)]
    fn with_limits(mut self, limits: Limits) -> Screen {
        self.limits = limits;
        self
    }

    /// Starts the worker; its answers come back through emit.
    fn start(&mut self, emit: &Emit<Msg>) {
        let (c, limits, emit) = (self.cluster.clone(), self.limits, emit.clone());
        self.worker = Some(Worker::start(move |ctx, job| emit(run(ctx, c.as_ref(), limits, job))));
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
            Msg::Loaded(Ok(o)) => {
                self.now = o;
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

    /// "t": reads the token the admin saved and asks before opening.
    fn ask_open(&mut self) {
        let text = match std::fs::read_to_string(&self.token_file) {
            Ok(t) => t,
            Err(_) => {
                self.notice = format!(
                    "No tunnel token yet. In the Cloudflare dashboard (Zero Trust, Networks, Tunnels) create a tunnel\nand save its token as {}. Then press t again.",
                    self.token_file.display()
                );
                return;
            }
        };
        match apps::tunnel_token(&text) {
            Ok(t) => self.confirm = Confirm::Open(t),
            Err(e) => self.notice = format!("{}: {e}", self.token_file.display()),
        }
    }

    fn confirmed(&mut self, what: Confirm) {
        let job = match what {
            Confirm::None => return,
            Confirm::Remove(name) => Job::Remove(name),
            Confirm::Open(token) => Job::Open(token),
            Confirm::Close => Job::Close,
        };
        self.notice.clear();
        self.send(job);
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
        if self.confirm != Confirm::None {
            let what = std::mem::replace(&mut self.confirm, Confirm::None);
            if k == Key::Char('y') {
                self.confirmed(what);
            } else {
                self.notice = if matches!(what, Confirm::Remove(_)) { "Nothing removed." } else { "Tunnel left as it is." }.into();
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
            Key::Up | Key::Char('k') => self.cursor = self.cursor.saturating_sub(1),
            Key::Down | Key::Char('j') => self.cursor = (self.cursor + 1).min(self.now.apps.len().saturating_sub(1)),
            Key::Char('n') => {
                self.notice.clear();
                self.form = Some(new_app_form());
            }
            Key::Char('d') => match self.now.apps.get(self.cursor) {
                Some(a) => self.confirm = Confirm::Remove(a.name.clone()),
                None => self.notice = "No app selected.".into(),
            },
            Key::Char('t') => {
                self.notice.clear();
                self.ask_open();
            }
            Key::Char('T') => {
                self.notice.clear();
                if self.now.tunnel.is_some() {
                    self.confirm = Confirm::Close;
                } else {
                    self.notice = "No tunnel to close.".into();
                }
            }
            Key::Char('r') => {
                self.notice = if self.load() { String::new() } else { "Already asking the coordinator.".into() };
            }
            _ => {}
        }
        Flow::Continue
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
            Event::Resize(..) => Flow::Continue,
        }
    }

    fn view(&self) -> Doc {
        let mut b = Doc::new();
        if let Some(f) = &self.form {
            b.append(theme::header("new app")).s("\n\n");
            b.append(f.view());
            if let Some(w) = self.waiting.view(self.limits.slow, "the coordinator is not answering") {
                b.nl().append(w).nl();
            }
            return b;
        }
        b.append(theme::header("apps")).s("   ").add(dim("the cluster picks a server for each and moves it when one dies")).s("\n\n");
        if let Some(e) = &self.err {
            b.add(err(format!("Cannot reach the cluster: {e}"))).nl();
            match self.seen {
                Some(t) => b.add(dim(format!("  What you see is from {} ago. r asks again.", super::since(t)))),
                None => b.add(dim("  r asks again.")),
            };
            b.s("\n\n");
        }
        // The way in from outside comes first: it decides who can reach
        // anything below.
        b.s("  From outside: ");
        match self.now.tunnel {
            _ if self.seen.is_none() => b.add(dim("not known yet")),
            None => b.add(dim("closed. t opens a Cloudflare Tunnel to the apps with a public name.")),
            Some((ready, want)) if ready > 0 && ready == want => {
                b.add(ok(format!("Cloudflare Tunnel connected, {ready} of {want} copies")))
            }
            Some((0, want)) => {
                b.add(err(format!("Cloudflare Tunnel not connected, 0 of {want} copies (wrong token, or no way out to Cloudflare)")))
            }
            Some((ready, want)) => b.add(err(format!("Cloudflare Tunnel connected with {ready} of {want} copies"))),
        };
        b.s("\n\n");
        if self.now.apps.is_empty() && self.err.is_none() && self.seen.is_some() {
            b.add(dim("  No apps yet. Press n to start one from a container image.")).nl();
        }
        for (i, a) in self.now.apps.iter().enumerate() {
            let on = if a.nodes.is_empty() { "-".to_string() } else { a.nodes.join(",") };
            let text = format!("{:<16} {:<18} {:<26} {}", a.name, on, if a.host.is_empty() { "inside only" } else { &a.host }, a.image);
            if i == self.cursor {
                b.add(sel(format!("> {text}")));
            } else {
                b.s(format!("  {text}"));
            }
            let state = format!("  {}/{} running", a.ready, a.copies);
            if a.copies > 0 && a.ready == a.copies {
                b.add(ok(state)).nl()
            } else {
                b.add(err(state)).nl()
            };
        }
        if let Some(w) = self.waiting.view(self.limits.slow, "the coordinator is not answering") {
            b.nl().append(w).nl();
        }
        match &self.confirm {
            Confirm::Remove(name) => b.nl().add(err(format!("Remove {name}? Its containers stop. y to confirm"))).nl(),
            Confirm::Open(_) => {
                let what = if self.now.tunnel.is_some() { "Give the tunnel the token from" } else { "Open the tunnel with the token from" };
                b.nl()
                    .add(err(format!(
                        "{what} {}? Cloudflare then sends what arrives for your public host names to the ingress. y to confirm",
                        self.token_file.display()
                    )))
                    .nl()
            }
            Confirm::Close => b.nl().add(err("Close the tunnel? Nothing from outside reaches your apps after that. y to confirm")).nl(),
            Confirm::None if !self.notice.is_empty() => b.nl().s(&self.notice).nl(),
            Confirm::None => &mut b,
        };
        b.nl()
            .append(theme::keys(&[
                ("↑↓", "select"),
                ("n", "new app"),
                ("d", "remove"),
                ("t", "tunnel"),
                ("T", "close tunnel"),
                ("r", "refresh"),
                ("q", "quit"),
            ]))
            .nl();
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apps::tests::{Fake, LISTING};
    use crate::tui::collector;
    use std::sync::atomic::Ordering::SeqCst;
    use std::sync::mpsc::Receiver;

    struct Open {
        s: Screen,
        rx: Receiver<Msg>,
        emit: Emit<Msg>,
    }

    impl Open {
        /// Feeds the worker's answers to the screen until nothing waits.
        fn settle(&mut self) {
            while !self.s.waiting.is_empty() {
                let m = self.rx.recv_timeout(Duration::from_secs(10)).expect("the worker did not answer");
                self.s.update(Event::Msg(m), &self.emit);
            }
        }

        fn key(&mut self, k: Key) {
            self.s.update(Event::Key(k), &self.emit);
        }

        fn type_in(&mut self, text: &str) {
            for k in crate::tui::type_text(text) {
                self.key(k);
            }
            self.key(Key::Enter);
        }

        fn view(&self) -> String {
            self.s.view().plain()
        }
    }

    fn open_with(fake: &Arc<Fake>, dir: &crate::testutil::TempDir, limits: Limits) -> Open {
        let mut s = Screen::new(fake.clone(), dir.join("cloudflare_tunnel_token")).with_limits(limits);
        let (emit, rx) = collector();
        s.init(&emit);
        Open { s, rx, emit }
    }

    fn open(fake: &Arc<Fake>, dir: &crate::testutil::TempDir) -> Open {
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

        // A new app: name, image, port, then no public name and one copy.
        s.key(Key::Char('n'));
        assert!(s.view().contains("dryserver  new app"));
        s.type_in("blog");
        s.type_in("ghcr.io/me/blog:v2");
        s.type_in("8080");
        s.type_in("Blog.Example.com");
        s.type_in("");
        s.settle();
        assert!(s.s.notice.contains("blog is starting"), "{:?}\n{}", s.s.notice, s.view());
        let calls = fake.calls.lock().unwrap().clone();
        let (args, manifest) = calls.iter().find(|(a, _)| a == "apply -f -").expect("nothing applied");
        assert_eq!(args, "apply -f -");
        assert!(
            manifest.contains("image: \"ghcr.io/me/blog:v2\"")
                && manifest.contains("- host: \"blog.example.com\"")
                && manifest.contains("replicas: 1"),
            "{manifest}"
        );
        assert!(calls.last().unwrap().0.starts_with("get"), "the screen asks again after a change: {calls:?}");

        // The cluster now has it (and one that is not healthy).
        *fake.listing.lock().unwrap() = LISTING.into();
        s.key(Key::Char('r'));
        s.settle();
        let v = s.view();
        assert!(v.contains("blog") && v.contains("node-a,node-b") && v.contains("blog.example.com") && v.contains("1/2 running"), "{v}");
        assert!(v.contains("api") && v.contains("inside only") && v.contains("0/1 running"), "{v}");

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
    fn tunnel_from_the_saved_token() {
        let fake = Arc::new(Fake::default());
        let dir = crate::testutil::TempDir::new();
        let file = dir.join("cloudflare_tunnel_token");
        let mut s = open(&fake, &dir);
        let applied = |f: &Fake| f.calls.lock().unwrap().iter().filter(|(a, _)| a == "apply -f -").count();
        assert!(s.view().contains("From outside: closed. t opens a Cloudflare Tunnel"), "{}", s.view());

        // No token saved: says where it goes, starts nothing.
        s.key(Key::Char('t'));
        assert!(s.s.notice.contains("No tunnel token yet") && s.s.notice.contains("cloudflare_tunnel_token"), "{:?}", s.s.notice);
        s.key(Key::Char('T'));
        assert!(s.s.notice.contains("No tunnel to close"));
        // Something that is not a token.
        std::fs::write(&file, "my password\n").unwrap();
        s.key(Key::Char('t'));
        assert!(s.s.notice.contains("not a tunnel token"), "{:?}", s.s.notice);
        assert_eq!(applied(&fake), 0);

        // The dashboard's command line, pasted whole. Asks first.
        let token = "eyJhIjoiMTIzNDU2Nzg5MGFiY2RlZiIsInQiOiJhYmNkZWYiLCJzIjoiWldGemVTQjBieUJ6WldVPSJ9";
        std::fs::write(&file, format!("cloudflared service install {token}\n")).unwrap();
        s.key(Key::Char('t'));
        let v = s.view();
        assert!(v.contains("Open the tunnel with the token from") && v.contains("y to confirm"), "{v}");
        assert!(!v.contains(token), "the token is never shown");
        s.key(Key::Char('x'));
        assert!(s.s.notice.contains("Tunnel left as it is") && applied(&fake) == 0);
        s.key(Key::Char('t'));
        s.key(Key::Char('y'));
        assert!(!s.view().contains(token), "the token is never shown, also while it is sent");
        s.settle();
        assert!(
            s.s.notice.contains("Tunnel starting") && s.s.notice.contains("http://traefik.kube-system.svc.cluster.local:80"),
            "{:?}",
            s.s.notice
        );
        let calls = fake.calls.lock().unwrap().clone();
        let (_, manifest) = calls.iter().find(|(a, _)| a == "apply -f -").expect("nothing applied");
        assert!(manifest.contains(&format!("token: \"{token}\"")) && manifest.contains("kind: Secret"), "{manifest}");
        assert!(calls.iter().all(|(a, _)| !a.contains(token)), "the token travels on stdin, never in a command line");

        // One of two copies holds a connection.
        *fake.listing.lock().unwrap() = LISTING.into();
        s.key(Key::Char('r'));
        s.settle();
        assert!(s.view().contains("Cloudflare Tunnel connected with 1 of 2 copies"), "{}", s.view());

        // Close asks first.
        s.key(Key::Char('T'));
        assert!(s.view().contains("Close the tunnel? Nothing from outside reaches your apps"));
        s.key(Key::Esc);
        assert!(!fake.calls.lock().unwrap().iter().any(|(a, _)| a.contains("delete")));
        s.key(Key::Char('T'));
        s.key(Key::Char('y'));
        s.settle();
        assert!(s.s.notice.contains("Tunnel closed"), "{:?}", s.s.notice);
        assert!(
            fake.calls.lock().unwrap().iter().any(|(a, _)| a == "-n edge delete deployment/cloudflared secret/tunnel --ignore-not-found")
        );
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
        for k in [Key::Down, Key::Up, Key::Char('n'), Key::Esc, Key::Char('d'), Key::Char('t')] {
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
        assert_eq!(order, vec!["get", "apply", "-n", "get"], "{order:?}");
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
        std::fs::write(dir.join("cloudflare_tunnel_token"), "eyJhIjoiMTIzNDU2Nzg5MGFiY2RlZiIsInQiOiJhYmNkZWYifQ==\n").unwrap();
        s.key(Key::Char('t'));
        s.key(Key::Char('y'));
        s.settle();
        assert!(s.s.notice.starts_with("Tunnel not started: the coordinator did not answer"), "{:?}", s.s.notice);
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
        assert_eq!(s.s.update(Event::Key(Key::Char('q')), &s.emit.clone()), Flow::Quit);
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
        *fake.listing.lock().unwrap() = LISTING.into();
        s.s.now = apps::overview(&Ctx::new(), &Fake { listing: LISTING.to_string().into(), ..Fake::default() }).unwrap();
        s.key(Key::Char('d'));
        s.key(Key::Char('y'));
        assert_eq!(s.s.update(Event::Key(Key::Char('q')), &s.emit.clone()), Flow::Continue);
        assert!(s.s.notice.contains("Still removing api. Press q again"), "{:?}", s.s.notice);
        // Another key disarms it; q then asks again.
        s.key(Key::Down);
        assert_eq!(s.s.update(Event::Key(Key::Char('q')), &s.emit.clone()), Flow::Continue);
        assert_eq!(s.s.update(Event::Key(Key::Char('q')), &s.emit.clone()), Flow::Quit);
        // ctrl+c never asks.
        assert_eq!(s.s.update(Event::Key(Key::Ctrl('c')), &s.emit.clone()), Flow::Quit);
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
}
