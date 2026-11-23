//! The desktop app: Home and every place in one screen. A place opens
//! inside it and esc (or q) comes back to Home; nothing quits to the
//! shell on the way. The screens that need the coordinator are made by
//! factories main.rs hands in: when one cannot be made (no config, a
//! missing key), its place shows a card with what to do, and the app
//! stays up.
//!
//! A place is a PlaceScreen. The hub gives it keys, ticks and its own
//! messages, and draws the Page it returns in the frame. Each opened place
//! gets a generation: an answer from one that was closed is dropped.

use std::any::Any;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use super::backups::{self, Backups};
use super::build::Build;
use super::flash::{Flash, Sudo};
use super::form::{self, Field, Form, Group, Status};
use super::frame::{self, Back, Focus, Help, Notice, Overlay, Page, Scroll};
use super::home::{self, Cfg, Facts, ITEMS};
use super::kill::{self, Kill};
use super::{Doc, Emit, Event, Flow, Job, Key, Model, dim};
use crate::apps::Cluster;
use crate::config::{self, Config};
use crate::entrance::Entrances;
use crate::err::Result;
use crate::{iso, owner, packages};

/// The project files the app works with.
#[derive(Debug, Clone)]
pub struct Paths {
    /// config.env
    pub config: PathBuf,
    /// out/
    pub out_dir: PathBuf,
    /// secrets/
    pub secrets: PathBuf,
}

/// Where the app can be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    Home,
    Config,
    Installer,
    Stick,
    Machines,
    Apps,
    Outside,
    Updates,
    Backups,
    Kill,
}

impl Place {
    pub fn title(self) -> &'static str {
        match self {
            Place::Home => "Home",
            Place::Kill => "Kill switch",
            Place::Stick => "USB stick",
            p => ITEMS.iter().find(|(q, _)| *q == p).map(|(_, t)| *t).unwrap_or(""),
        }
    }
}

/// The room a place's page has: the body's width and rows.
#[derive(Debug, Clone, Copy)]
pub struct Size {
    pub width: usize,
    pub rows: usize,
}

/// A place inside the app.
pub trait PlaceScreen {
    type Msg: Send + 'static;

    /// Starts background work when the place opens.
    fn init(&mut self, _emit: &Emit<Self::Msg>) {}

    /// Flow::Quit leaves the place: to next(), or Home.
    fn update(&mut self, ev: Event<Self::Msg>, emit: &Emit<Self::Msg>) -> Flow;

    fn page(&self, size: Size) -> Page;

    /// A change runs: quitting asks first and says this stops.
    fn busy(&self) -> Option<String> {
        None
    }

    /// Work for the terminal itself (tui::Job); its end comes back as
    /// Event::Back.
    fn job(&mut self) -> Option<Job> {
        None
    }

    /// Where to go after leaving, instead of Home.
    fn next(&self) -> Option<Place> {
        None
    }

    /// What Home says after the place closed.
    fn after(&self) -> Option<Notice> {
        None
    }

    /// Text is being typed: q and ? are letters, home and end move the
    /// cursor.
    fn typing(&self) -> bool {
        false
    }
}

/// A message from a place, with the generation of the place that sent it.
pub struct Msg {
    generation: u64,
    body: Box<dyn Any + Send>,
}

/// A place with its messages hidden in the hub's.
trait Open {
    fn init(&mut self, emit: &Emit<Msg>);
    fn update(&mut self, ev: Event<Msg>) -> Flow;
    fn page(&self, size: Size) -> Page;
    fn busy(&self) -> Option<String>;
    fn job(&mut self) -> Option<Job>;
    fn next(&self) -> Option<Place>;
    fn after(&self) -> Option<Notice>;
    fn typing(&self) -> bool;
}

struct Hosted<P: PlaceScreen> {
    p: P,
    generation: u64,
    emit: Option<Emit<P::Msg>>,
}

impl<P: PlaceScreen> Open for Hosted<P> {
    fn init(&mut self, emit: &Emit<Msg>) {
        let (e, generation) = (emit.clone(), self.generation);
        let mine: Emit<P::Msg> = Arc::new(move |m| e(Msg { generation, body: Box::new(m) }));
        self.p.init(&mine);
        self.emit = Some(mine);
    }

    fn update(&mut self, ev: Event<Msg>) -> Flow {
        let Some(emit) = self.emit.clone() else { return Flow::Continue };
        let ev = match ev {
            // An answer to a place that was closed since.
            Event::Msg(m) if m.generation != self.generation => return Flow::Continue,
            Event::Msg(m) => match m.body.downcast::<P::Msg>() {
                Ok(b) => Event::Msg(*b),
                Err(_) => return Flow::Continue,
            },
            Event::Key(k) => Event::Key(k),
            Event::Tick => Event::Tick,
            Event::Resize(w, h) => Event::Resize(w, h),
            Event::Back(r) => Event::Back(r),
        };
        self.p.update(ev, &emit)
    }

    fn page(&self, size: Size) -> Page {
        self.p.page(size)
    }
    fn busy(&self) -> Option<String> {
        self.p.busy()
    }
    fn job(&mut self) -> Option<Job> {
        self.p.job()
    }
    fn next(&self) -> Option<Place> {
        self.p.next()
    }
    fn after(&self) -> Option<Notice> {
        self.p.after()
    }
    fn typing(&self) -> bool {
        self.p.typing()
    }
}

fn host<P: PlaceScreen + 'static>(p: P, generation: u64) -> Box<dyn Open> {
    Box::new(Hosted { p, generation, emit: None })
}

/// Makes the link to the cluster and the ways in.
pub type MakeCluster = Box<dyn Fn() -> Result<(Arc<dyn Cluster>, Entrances)>>;

/// What main.rs hands in: the screens and jobs that need the coordinator
/// or this computer's keys, made when their place opens.
pub struct Factories {
    /// The machines screen, with its link to the coordinator.
    pub machines: Box<dyn Fn() -> Result<super::admin::Screen>>,
    /// The cluster and the ways in, for Apps and Outside.
    pub cluster: MakeCluster,
    /// backup-pull.
    pub pull: backups::Pull,
    /// ssh-config: the server list the kill switch reaches.
    pub write_list: kill::WriteList,
    /// quarantine-all.
    pub quarantine: kill::Quarantine,
    /// ~/.ssh/config.d/dryserver; None without $HOME.
    pub server_list: Option<PathBuf>,
    /// This program, for sudo to run.
    pub exe: Option<PathBuf>,
}

/// What a card's key does.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Fix {
    Open(Place),
    Retry,
}

/// A place that could not open, as a card: what happened, what to do,
/// and the key that does it.
struct Problem {
    place: Place,
    problem: String,
    todo: String,
    fix: Option<(&'static str, &'static str, Fix)>,
}

/// How often Home reads the files again.
const REREAD: Duration = Duration::from_secs(2);

pub struct App {
    paths: Paths,
    make: Factories,
    exe_time: Option<SystemTime>,
    root: bool,
    facts: Facts,
    read_at: Instant,
    cursor: usize,
    /// Home's notice: what happened in the place that just closed.
    notice: Option<Notice>,
    /// Over any page: ctrl+c was pressed once while a change runs.
    armed: Option<Notice>,
    open: Option<(Place, Box<dyn Open>)>,
    problem: Option<Problem>,
    generation: u64,
    scroll: Scroll,
    w: u16,
    h: u16,
    help: bool,
    /// Apps and Outside share one link to the cluster while you go
    /// between them.
    cluster: Option<(Arc<dyn Cluster>, Entrances)>,
    /// A place to open once the app runs (`dryserver approve`).
    start: Option<Place>,
    /// Printed after the app closed.
    after: Vec<String>,
}

impl App {
    pub fn new(paths: Paths, make: Factories) -> App {
        let exe_time = make.exe.as_ref().and_then(|e| std::fs::metadata(e).and_then(|m| m.modified()).ok());
        let root = crate::fsx::is_root();
        let facts = Facts::read(&paths, exe_time, root);
        // Home starts on the next step.
        let cursor = home::next(&facts).place.and_then(|p| ITEMS.iter().position(|(q, _)| *q == p)).unwrap_or(0);
        App {
            paths,
            make,
            exe_time,
            root,
            facts,
            read_at: Instant::now(),
            cursor,
            notice: None,
            armed: None,
            open: None,
            problem: None,
            generation: 0,
            scroll: Scroll::default(),
            w: 80,
            h: 24,
            help: false,
            cluster: None,
            start: None,
            after: Vec::new(),
        }
    }

    /// Opens place first instead of Home.
    pub fn start_at(mut self, place: Place) -> App {
        self.start = Some(place);
        self
    }

    /// What to print once the app closed.
    pub fn after(&self) -> &[String] {
        &self.after
    }

    #[cfg(test)]
    fn with_root(mut self, root: bool) -> App {
        self.root = root;
        self.refresh();
        self
    }

    fn refresh(&mut self) {
        self.facts = Facts::read(&self.paths, self.exe_time, self.root);
        self.read_at = Instant::now();
    }

    fn size(&self) -> Size {
        Size { width: frame::body_width(self.w), rows: (self.h as usize).saturating_sub(4) }
    }

    /// The place on screen now.
    #[cfg(test)]
    fn place(&self) -> Place {
        match (&self.open, &self.problem) {
            (Some((p, _)), _) => *p,
            (None, Some(pr)) => pr.place,
            _ => Place::Home,
        }
    }

    /// The open place stays until the app is dropped, after the terminal
    /// is back: a build it stops may take a moment.
    fn quit(&mut self) -> Flow {
        if let Some((_, p)) = &self.open
            && let Some(n) = p.after()
        {
            self.after.push(n.text);
        }
        Flow::Quit
    }

    fn go_home(&mut self) {
        self.open = None;
        self.problem = None;
        self.cluster = None;
        self.help = false;
        self.scroll.reset();
        self.refresh();
    }

    fn open(&mut self, place: Place, emit: &Emit<Msg>) {
        self.refresh();
        self.notice = None;
        self.help = false;
        self.problem = None;
        self.scroll.reset();
        if place == Place::Home {
            return self.go_home();
        }
        if self.root && !home::works_as_root(place) {
            self.notice = Some(Notice::bad(format!(
                "{} works as your own user, not with sudo: quit (q) and open dryserver without sudo.",
                place.title()
            )));
            return;
        }
        self.generation += 1;
        match self.make(place, self.generation) {
            Ok(mut p) => {
                p.init(emit);
                self.open = Some((place, p));
            }
            Err(pr) => self.problem = Some(pr),
        }
    }

    /// The config is there and reads: its address is all the screens
    /// that talk to the coordinator need from it.
    fn needs_config(&self, place: Place) -> std::result::Result<(), Problem> {
        let fix = Some(("enter", "open Config", Fix::Open(Place::Config)));
        match &self.facts.cfg {
            Cfg::Ok(_) => Ok(()),
            Cfg::Broken(_) if self.facts.cfg_loads => Ok(()),
            Cfg::Missing => Err(Problem {
                place,
                problem: "There is no config yet.".into(),
                todo: format!("{} needs the coordinator's address from it. Make it in Config: it takes a minute.", place.title()),
                fix,
            }),
            Cfg::Broken(e) => {
                Err(Problem { place, problem: format!("The config has a problem: {e}"), todo: "Fix it in Config.".into(), fix })
            }
        }
    }

    fn needs_keys(&self, place: Place) -> std::result::Result<(), Problem> {
        match self.facts.missing_keys.iter().find(|k| home::ADMIN_KEYS.contains(&k.as_str())) {
            None => Ok(()),
            Some(k) => Err(Problem {
                place,
                problem: format!("A key is missing: {} is not there.", self.paths.secrets.join(k).display()),
                todo: "Build the installer (2): it makes your keys. Keep secrets/ safe: it is how this computer signs.".into(),
                fix: Some(("enter", "open Installer", Fix::Open(Place::Installer))),
            }),
        }
    }

    fn needs_met(&self, place: Place) -> std::result::Result<(), Problem> {
        if self.facts.met {
            return Ok(());
        }
        Err(Problem {
            place,
            problem: "This computer has not met the coordinator yet.".into(),
            todo: "Open Machines (4) once: it checks the coordinator and remembers its key.".into(),
            fix: Some(("enter", "open Machines", Fix::Open(Place::Machines))),
        })
    }

    fn failed(place: Place, e: crate::err::Error) -> Problem {
        Problem {
            place,
            problem: crate::report::printable(&e.to_string()),
            todo: "Fix that, then r tries again.".into(),
            fix: Some(("r", "try again", Fix::Retry)),
        }
    }

    /// The installer is out of date, in words.
    fn iso_warning(&self) -> Option<String> {
        self.facts.iso_problem().map(|p| format!("This installer is {}.", p.trim_end_matches(": build it again")))
    }

    fn make(&mut self, place: Place, generation: u64) -> std::result::Result<Box<dyn Open>, Problem> {
        match place {
            Place::Home => unreachable!("Home is not opened"),
            Place::Config => Ok(host(ConfigPlace::new(&self.paths, &self.facts), generation)),
            Place::Installer => Ok(host(Build::new(&self.paths, &self.facts), generation)),
            Place::Stick => {
                let Some((size, _)) = self.facts.iso else {
                    return Err(Problem {
                        place,
                        problem: "There is no installer to write yet.".into(),
                        todo: "Build it first in Installer (2): it takes a few minutes.".into(),
                        fix: Some(("enter", "open Installer", Fix::Open(Place::Installer))),
                    });
                };
                let iso = iso::iso_path(&self.paths.out_dir);
                let warn = self.iso_warning();
                if self.root {
                    return Ok(host(Flash::new(&iso.display().to_string(), size).warn(warn), generation));
                }
                match &self.make.exe {
                    Some(exe) => Ok(host(Sudo::new(iso, size, warn, exe.clone()), generation)),
                    None => Err(Problem {
                        place,
                        problem: "This program cannot find its own file, so sudo cannot run it.".into(),
                        todo: "Quit and open sudo dryserver from the terminal instead.".into(),
                        fix: None,
                    }),
                }
            }
            Place::Machines | Place::Updates => {
                self.needs_config(place)?;
                self.needs_keys(place)?;
                (self.make.machines)().map(|s| host(s, generation)).map_err(|e| App::failed(place, e))
            }
            Place::Apps | Place::Outside => {
                self.needs_config(place)?;
                self.needs_met(place)?;
                let (c, doors) = match self.cluster.clone() {
                    Some(c) => c,
                    None => (self.make.cluster)().map_err(|e| App::failed(place, e))?,
                };
                self.cluster = Some((c.clone(), doors.clone()));
                Ok(if place == Place::Apps {
                    host(super::apps::Screen::new(c, doors), generation)
                } else {
                    host(super::outside::Screen::new(c, doors), generation)
                })
            }
            Place::Backups => {
                let pull = match (self.needs_config(place), self.needs_met(place)) {
                    (Ok(()), Ok(())) => Ok(self.make.pull.clone()),
                    (Err(p), _) | (_, Err(p)) => Err((p.problem, p.todo)),
                };
                Ok(host(Backups::new(self.paths.secrets.join("backups"), pull), generation))
            }
            Place::Kill => {
                Ok(host(Kill::new(self.make.server_list.clone(), self.make.quarantine.clone(), self.make.write_list.clone()), generation))
            }
        }
    }

    fn leave(&mut self, emit: &Emit<Msg>) {
        let Some((place, p)) = self.open.take() else { return };
        let (next, after) = (p.next(), p.after());
        // Its workers stop here.
        drop(p);
        let between = matches!((place, next), (Place::Apps, Some(Place::Outside)) | (Place::Outside, Some(Place::Apps)));
        if !between {
            self.cluster = None;
        }
        match next {
            Some(n) => self.open(n, emit),
            None => self.go_home(),
        }
        if self.open.is_none() && after.is_some() {
            self.notice = after;
        }
    }

    fn key(&mut self, k: Key, emit: &Emit<Msg>) -> Flow {
        if frame::too_small(self.w, self.h) {
            // Nothing shows: only leaving works.
            return if matches!(k, Key::Char('q') | Key::Ctrl('c')) { self.quit() } else { Flow::Continue };
        }
        if self.help {
            self.help = false;
            return Flow::Continue;
        }
        let armed = self.armed.take().is_some();
        if k == Key::Ctrl('c') {
            if let Some((_, p)) = &self.open
                && let Some(what) = p.busy()
                && !armed
            {
                self.armed = Some(Notice::bad(format!("ctrl+c again quits, and {what} stops.")));
                return Flow::Continue;
            }
            // The place hears it first, to say what it cut off.
            if let Some((_, p)) = &mut self.open {
                p.update(Event::Key(Key::Ctrl('c')));
            }
            return self.quit();
        }
        let size = self.size();
        if let Some((_, p)) = &mut self.open {
            let typing = p.typing();
            let k = if k == Key::Char('q') && !typing { Key::Esc } else { k };
            if k == Key::Char('?') && !typing && p.page(size).help.is_some() {
                self.help = true;
                return Flow::Continue;
            }
            if (matches!(k, Key::PageUp | Key::PageDown) || (!typing && matches!(k, Key::Home | Key::End))) && self.scroll.key(&k) {
                return Flow::Continue;
            }
            if p.update(Event::Key(k)) == Flow::Quit {
                self.leave(emit);
            }
            return Flow::Continue;
        }
        if let Some(pr) = &self.problem {
            let fix = pr.fix;
            let place = pr.place;
            match k {
                Key::Esc | Key::Char('q') => self.go_home(),
                Key::Char('?') => self.help = true,
                k => {
                    if let Some((key, _, f)) = fix
                        && k.name() == key
                    {
                        match f {
                            Fix::Open(p) => self.open(p, emit),
                            Fix::Retry => self.open(place, emit),
                        }
                    }
                }
            }
            return Flow::Continue;
        }
        self.notice = None;
        match k {
            Key::Char('q') => return self.quit(),
            Key::Up | Key::Char('k') => self.cursor = self.cursor.saturating_sub(1),
            Key::Down | Key::Char('j') => self.cursor = (self.cursor + 1).min(ITEMS.len() - 1),
            Key::Enter => self.open(ITEMS[self.cursor].0, emit),
            Key::Char(c @ '1'..='9') => {
                self.cursor = c as usize - '1' as usize;
                self.open(ITEMS[self.cursor].0, emit);
            }
            Key::Char('?') => self.help = true,
            Key::Char('r') => self.refresh(),
            k => {
                self.scroll.key(&k);
            }
        }
        Flow::Continue
    }

    fn home_page(&self, size: Size) -> Page {
        let p = super::theme::palette();
        let mut page = Page::new("Home");
        if self.root {
            page.status.add(super::Seg("with sudo: only the installer and the stick".into(), p.hint()));
        }
        let (body, focus) = home::body(&self.facts, self.cursor, size.width, size.rows);
        page.body = body;
        page.focus = Some(Focus::row(focus));
        page.notice = self.notice.clone();
        page.key("↑↓", "move").key("enter", "open").key("1-9", "go to a place");
        page.back = Back::Quit;
        page.help = Some(Help {
            about: "dryserver turns old laptops into your own server swarm. Set up makes the USB stick that installs them; Run \
                    looks after them once they run; the kill switch is for when the coordinator may have been broken into.\n\
                    Everything on Home comes from files on this computer, so it shows at once. The Next line says what to do."
                .into(),
            keys: vec![
                ("↑↓ j k".into(), "move".into()),
                ("enter".into(), "open the place".into()),
                ("1-9".into(), "open that place".into()),
                ("r".into(), "read the files again".into()),
                ("q".into(), "quit (elsewhere q and esc go back)".into()),
                ("ctrl+c".into(), "quit from anywhere".into()),
            ],
        });
        page
    }

    fn problem_page(&self, pr: &Problem, size: Size) -> Page {
        let mut page = Page::new(pr.place.title());
        page.body = frame::card(size.width, &pr.problem, &pr.todo, pr.fix.map(|(k, d, _)| (k, d)));
        if let Some((k, d, _)) = pr.fix {
            page.key(k, d);
        }
        page.help = Some(Help {
            about: format!("{} could not open. The card says what is missing and which key fixes it.", pr.place.title()),
            keys: vec![("esc".into(), "back to Home".into())],
        });
        page
    }

    fn page(&self) -> Page {
        let size = self.size();
        let mut page = match (&self.open, &self.problem) {
            (Some((_, p)), _) => p.page(size),
            (None, Some(pr)) => self.problem_page(pr, size),
            (None, None) => self.home_page(size),
        };
        if let Some(n) = &self.armed {
            page.notice = Some(n.clone());
        }
        if self.help && page.help.is_some() {
            page.overlay = Some(Overlay::Help);
        }
        page
    }
}

impl Model for App {
    type Msg = Msg;

    fn init(&mut self, emit: &Emit<Msg>) {
        if let Some(p) = self.start.take() {
            self.open(p, emit);
        }
    }

    fn update(&mut self, ev: Event<Msg>, emit: &Emit<Msg>) -> Flow {
        let flow = match ev {
            Event::Key(k) => return self.key(k, emit),
            Event::Resize(w, h) => {
                (self.w, self.h) = (w, h);
                self.open.as_mut().map(|(_, p)| p.update(Event::Resize(w, h)))
            }
            Event::Tick => {
                if self.open.is_none() && self.read_at.elapsed() >= REREAD {
                    self.refresh();
                }
                self.open.as_mut().map(|(_, p)| p.update(Event::Tick))
            }
            ev @ (Event::Msg(_) | Event::Back(_)) => self.open.as_mut().map(|(_, p)| p.update(ev)),
        };
        if flow == Some(Flow::Quit) {
            self.leave(emit);
        }
        Flow::Continue
    }

    fn view(&self) -> Doc {
        frame::draw(&self.page(), &self.scroll, self.w, self.h)
    }

    fn job(&mut self) -> Option<Job> {
        self.open.as_mut().and_then(|(_, p)| p.job())
    }
}

// ---- the screens not drawn in the frame yet: their own text is the body ----

fn legacy_page(place: &str, body: Doc) -> Page {
    let mut p = Page::new(place);
    p.body = body;
    p.key("pgup pgdn", "scroll");
    p.back = Back::Esc;
    p
}

/// The old screens fit their lines to the width they are told: the body's.
fn legacy<M>(ev: Event<M>) -> Event<M> {
    match ev {
        Event::Resize(w, h) => Event::Resize(frame::body_width(w) as u16 + 2, h.saturating_sub(4)),
        ev => ev,
    }
}

impl PlaceScreen for super::admin::Screen {
    type Msg = super::admin::Msg;
    fn init(&mut self, emit: &Emit<Self::Msg>) {
        Model::init(self, emit);
    }
    fn update(&mut self, ev: Event<Self::Msg>, emit: &Emit<Self::Msg>) -> Flow {
        Model::update(self, legacy(ev), emit)
    }
    fn page(&self, _: Size) -> Page {
        legacy_page("Machines", Model::view(self))
    }
    fn after(&self) -> Option<Notice> {
        super::admin::Screen::after(self).map(Notice::bad)
    }
    fn typing(&self) -> bool {
        true
    }
}

impl PlaceScreen for super::apps::Screen {
    type Msg = super::apps::Msg;
    fn init(&mut self, emit: &Emit<Self::Msg>) {
        Model::init(self, emit);
    }
    fn update(&mut self, ev: Event<Self::Msg>, emit: &Emit<Self::Msg>) -> Flow {
        Model::update(self, legacy(ev), emit)
    }
    fn page(&self, _: Size) -> Page {
        legacy_page("Apps", Model::view(self))
    }
    fn next(&self) -> Option<Place> {
        self.next.map(|p| if p == super::Place::Outside { Place::Outside } else { Place::Apps })
    }
    fn typing(&self) -> bool {
        true
    }
}

impl PlaceScreen for super::outside::Screen {
    type Msg = super::outside::Msg;
    fn init(&mut self, emit: &Emit<Self::Msg>) {
        Model::init(self, emit);
    }
    fn update(&mut self, ev: Event<Self::Msg>, emit: &Emit<Self::Msg>) -> Flow {
        Model::update(self, legacy(ev), emit)
    }
    fn page(&self, _: Size) -> Page {
        legacy_page("Outside", Model::view(self))
    }
    fn next(&self) -> Option<Place> {
        self.next.map(|p| if p == super::Place::Apps { Place::Apps } else { Place::Outside })
    }
    fn typing(&self) -> bool {
        true
    }
}

// ---- Config ----

/// What the config form edits: the config plus the tool list, joined into
/// cfg.tools on save.
pub struct ConfigAnswers {
    cfg: Config,
    tools: Vec<String>,
}

struct ConfigPlace {
    form: Form<ConfigAnswers>,
    path: PathBuf,
    after: Option<Notice>,
}

impl ConfigPlace {
    fn new(paths: &Paths, facts: &Facts) -> ConfigPlace {
        // A config with a problem still loads what it can.
        let cfg = match &facts.cfg {
            Cfg::Ok(c) => (**c).clone(),
            _ => Config::load_partial(&paths.config).0,
        };
        let answers = ConfigAnswers { tools: cfg.tool_list(), cfg };
        ConfigPlace { form: config_form(answers), path: paths.config.clone(), after: None }
    }

    fn save(&mut self) {
        let a = &self.form.state;
        let mut c = a.cfg.clone();
        c.tools = packages::sort_tools(&a.tools).join(" ");
        c.extra_packages = c.extra_list().join(" ");
        c.admin_ssh_pubkey = config::normalize_pubkey(&c.admin_ssh_pubkey);
        self.after = Some(match c.save(&self.path) {
            Ok(()) => Notice::ok(format!("Config saved to {}. Build the installer again (2) to put it on the stick.", self.path.display())),
            Err(e) => Notice::bad(format!("The config was not saved: {e}")),
        });
        owner::fix(&[&self.path]);
    }
}

impl PlaceScreen for ConfigPlace {
    type Msg = ();

    fn update(&mut self, ev: Event<()>, _: &Emit<()>) -> Flow {
        let Event::Key(k) = ev else { return Flow::Continue };
        self.form.update(&k);
        match self.form.status {
            Status::Completed => {
                self.save();
                Flow::Quit
            }
            Status::Aborted => {
                self.after = Some(Notice::info("The config was not changed."));
                Flow::Quit
            }
            Status::Active => Flow::Continue,
        }
    }

    fn page(&self, size: Size) -> Page {
        let mut page = Page::new("Config");
        page.status.add(dim(self.path.display().to_string()));
        let (body, focus) = self.form.body(size.width);
        page.body = body;
        page.focus = focus.map(Focus::keep);
        page.keys = self.form.keys();
        page.key("esc", &self.form.esc_label());
        page.back = Back::Nothing;
        if self.form.leaving() {
            let (question, consequences) = form::leave_question();
            page.overlay = Some(Overlay::Confirm { question, consequences });
        }
        page.help = Some(Help {
            about: "The config says how your machines reach the internet and each other, and how you log in to them. It goes \
                    onto the installer stick; build the installer again after a change."
                .into(),
            keys: vec![
                ("enter".into(), "next field; on the review, save".into()),
                ("shift+tab".into(), "previous field".into()),
                ("esc".into(), "back one step; on the first, leave".into()),
                ("↑↓ space".into(), "choose in a list".into()),
            ],
        });
        page
    }

    fn after(&self) -> Option<Notice> {
        self.after.clone()
    }

    fn typing(&self) -> bool {
        self.form.typing()
    }
}

fn config_form(answers: ConfigAnswers) -> Form<ConfigAnswers> {
    let tool_opts: Vec<(String, String)> = packages::OPTIONAL.iter().map(|b| (b.title.to_string(), b.id.to_string())).collect();
    let transports = vec![
        ("Switch when plugged in, else WiFi/router (auto)".to_string(), config::TRANSPORT_AUTO.to_string()),
        ("WiFi/router network only".to_string(), config::TRANSPORT_LAN.to_string()),
    ];
    type A = ConfigAnswers;
    Form::new(
        answers,
        vec![
            Group::new(vec![
                Field::note("WiFi", "Used by the installer and the servers for internet.\nLeave SSID empty to use Ethernet only."),
                Field::input("WiFi SSID", |a: &A| a.cfg.wifi_ssid.clone(), |a, v| a.cfg.wifi_ssid = v),
                Field::input("WiFi password", |a: &A| a.cfg.wifi_pass.clone(), |a, v| a.cfg.wifi_pass = v)
                    .password()
                    .validate(|v, _| config::valid_wifi_pass(v)),
            ])
            .title("WiFi"),
            Group::new(vec![
                Field::note("Mesh", "The first laptop you install becomes the coordinator.\nReserve its IP in your router's DHCP settings."),
                Field::input("Coordinator LAN IP", |a: &A| a.cfg.coord_lan_ip.clone(), |a, v| a.cfg.coord_lan_ip = v)
                    .placeholder("192.168.1.50")
                    .desc("Its address on the WiFi/router network.")
                    .validate(|v, _| config::valid_ipv4(v)),
                Field::input("Mesh subnet", |a: &A| a.cfg.wg_subnet.clone(), |a, v| a.cfg.wg_subnet = v)
                    .desc("WireGuard addresses. Node N gets .N")
                    .validate(|v, a| config::valid_mesh_subnet(v, &a.cfg.coord_lan_ip)),
                Field::input("WireGuard UDP port", |a: &A| a.cfg.wg_port.clone(), |a, v| a.cfg.wg_port = v).validate(|v, _| config::valid_port(v)),
                Field::input("Extra ports open inside the mesh", |a: &A| a.cfg.mesh_ports.clone(), |a, v| a.cfg.mesh_ports = v)
                    .placeholder("8080/tcp 53/udp")
                    .desc("Between servers. SSH inside the mesh comes only from the coordinator. These never open to WiFi/router.")
                    .validate(|v, _| config::valid_mesh_ports(v)),
                Field::input("Extra outgoing ports", |a: &A| a.cfg.egress_ports.clone(), |a, v| a.cfg.egress_ports = v)
                    .placeholder("25565/tcp 27015/udp")
                    .desc("Servers and containers may only start connections for DNS, time and web (80, 443). Add what your apps need.")
                    .validate(|v, _| config::valid_mesh_ports(v)),
            ])
            .title("Mesh"),
            Group::new(vec![
                Field::select("WireGuard network", move |_| transports.clone(), |a: &A| a.cfg.wg_transport.clone(), |a, v| a.cfg.wg_transport = v)
                    .desc("Which cable or radio carries traffic between servers."),
            ])
            .title("Between the servers"),
            Group::new(vec![
                Field::note(
                    "Switch",
                    "Each Ethernet port gets a fixed IP here, so servers find each\nother on the switch. Works whether or not the switch is\nconnected to your router; if it is, the cable also gets\ninternet from the router.",
                ),
                Field::input("Switch subnet", |a: &A| a.cfg.switch_subnet.clone(), |a, v| a.cfg.switch_subnet = v)
                    .desc("Mesh node .N gets .N here too.")
                    .validate(|v, a| config::valid_switch_subnet(v, &a.cfg.wg_subnet, &a.cfg.coord_lan_ip)),
            ])
            .title("Switch")
            .hide_if(|a| a.cfg.wg_transport != config::TRANSPORT_AUTO),
            Group::new(vec![
                Field::multi("Tools", move |_| tool_opts.clone(), |a: &A| a.tools.clone(), |a, v| a.tools = v).desc(
                    "Always installed: ssh, git, cron, tmux, htop, curl, rsync,\nripgrep, fzf and other basics. Pick extras (space toggles).",
                ),
                Field::input("Extra packages", |a: &A| a.cfg.extra_packages.clone(), |a, v| a.cfg.extra_packages = v)
                    .placeholder("python nodejs")
                    .desc("Any other Arch packages, space-separated.")
                    .validate(|v, _| config::valid_extra_packages(v)),
            ])
            .title("Tools"),
            Group::new(vec![
                Field::note("Admin access", "SSH key login only, password login is off."),
                Field::input("Username", |a: &A| a.cfg.username.clone(), |a, v| a.cfg.username = v).validate(|v, _| config::valid_username(v)),
                Field::input("SSH public key", |a: &A| a.cfg.admin_ssh_pubkey.clone(), |a, v| a.cfg.admin_ssh_pubkey = v)
                    .placeholder("ssh-ed25519 AAAA...")
                    .desc("Paste the output of: cat ~/.ssh/id_ed25519.pub\nThe text after the key (often your email) is removed.")
                    .validate(|v, _| config::valid_pubkey(v)),
                Field::input("Key label", |a: &A| a.cfg.admin_key_label.clone(), |a, v| a.cfg.admin_key_label = v)
                    .placeholder("desktop")
                    .desc("Short name for this key on the servers, instead of an email.")
                    .validate(|v, _| config::valid_key_label(v)),
                Field::input("Timezone", |a: &A| a.cfg.timezone.clone(), |a, v| a.cfg.timezone = v)
                    .placeholder("Europe/Berlin")
                    .validate(|v, _| config::valid_timezone(v)),
            ])
            .title("Admin access"),
        ],
        "leave",
    )
    .done_label("save to config.env")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use crate::tui::collector;
    use crate::tui::frame::tests::rows;
    use crate::tui::theme::{self, Tier};
    use std::sync::Mutex;

    fn test_paths(dir: &TempDir) -> Paths {
        Paths { config: dir.join("config.env"), out_dir: dir.join("out"), secrets: dir.join("secrets") }
    }

    struct NoCluster;
    impl Cluster for NoCluster {
        fn kubectl(&self, _: &crate::ctx::Ctx, _: &[&str], _: &str) -> Result<String> {
            Err("the coordinator did not answer".into())
        }
    }

    /// Factories that need nothing: Machines fails like a missing key
    /// would, the cluster is one that never answers.
    fn fakes(calls: Arc<Mutex<Vec<String>>>) -> Factories {
        let c1 = calls.clone();
        let c2 = calls.clone();
        Factories {
            machines: Box::new(move || {
                c1.lock().unwrap().push("machines".into());
                Err("secrets/signing_ed25519 has a passphrase".into())
            }),
            cluster: Box::new(move || {
                c2.lock().unwrap().push("cluster".into());
                Ok((Arc::new(NoCluster) as Arc<dyn Cluster>, Arc::new(Vec::new()) as Entrances))
            }),
            pull: Arc::new(|_| Err("no".into())),
            write_list: Arc::new(|| Err("no".into())),
            quarantine: Arc::new(|_| Ok(())),
            server_list: None,
            exe: None,
        }
    }

    fn app(dir: &TempDir) -> (App, Arc<Mutex<Vec<String>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut a = App::new(test_paths(dir), fakes(calls.clone())).with_root(false);
        let (emit, _rx) = collector();
        Model::update(&mut a, Event::Resize(100, 32), &emit);
        (a, calls)
    }

    fn press(a: &mut App, keys: &[Key]) -> Flow {
        let (emit, _rx) = collector();
        let mut f = Flow::Continue;
        for k in keys {
            f = Model::update(a, Event::Key(k.clone()), &emit);
        }
        f
    }

    fn screen(a: &App) -> String {
        rows(&a.view()).join("\n")
    }

    /// A directory with a config, an installer and every key.
    fn ready(dir: &TempDir) {
        let p = test_paths(dir);
        let c = Config {
            coord_lan_ip: "192.168.1.50".into(),
            admin_ssh_pubkey: "ssh-ed25519 AAAA me@pc".into(),
            wifi_ssid: "home".into(),
            wifi_pass: "password123".into(),
            ..Config::default()
        };
        c.save(&p.config).unwrap();
        std::fs::create_dir_all(&p.secrets).unwrap();
        for k in home::KEYS {
            std::fs::write(p.secrets.join(k), "k").unwrap();
        }
        std::fs::create_dir_all(&p.out_dir).unwrap();
        std::fs::write(iso::iso_path(&p.out_dir), "iso").unwrap();
    }

    #[test]
    fn home_shows_every_place_and_the_next_step() {
        let _g = theme::force(Tier::True, false);
        let dir = TempDir::new();
        let (a, _) = app(&dir);
        let s = screen(&a);
        for (_, name) in ITEMS {
            assert!(s.contains(name), "{name}:\n{s}");
        }
        assert!(s.contains("Next  Make the config (1)"), "{s}");
        assert!(s.contains("▌ ●  1  Config"), "Home starts on the next step:\n{s}");
        assert!(rows(&a.view()).last().unwrap().trim_end().ends_with("q  quit"));
    }

    #[test]
    fn esc_goes_back_and_q_quits_only_on_home() {
        let dir = TempDir::new();
        let (mut a, _) = app(&dir);
        assert_eq!(press(&mut a, &[Key::Esc]), Flow::Continue, "esc on Home does nothing");
        assert_eq!(a.place(), Place::Home);
        for (key, place) in [('2', Place::Installer), ('8', Place::Backups), ('9', Place::Kill), ('4', Place::Machines)] {
            press(&mut a, &[Key::Char(key)]);
            assert_eq!(a.place(), place);
            assert_eq!(press(&mut a, &[Key::Char('q')]), Flow::Continue, "q goes back from {place:?}");
            assert_eq!(a.place(), Place::Home);
            press(&mut a, &[Key::Char(key)]);
            press(&mut a, &[Key::Esc]);
            assert_eq!(a.place(), Place::Home, "esc goes back from {place:?}");
        }
        // Config starts in a text field, where q is a letter: esc leaves.
        press(&mut a, &[Key::Char('1'), Key::Esc]);
        assert_eq!(a.place(), Place::Home);
        assert_eq!(press(&mut a, &[Key::Char('q')]), Flow::Quit);
        // ctrl+c quits from anywhere.
        let (mut a, _) = app(&dir);
        press(&mut a, &[Key::Char('9')]);
        assert_eq!(press(&mut a, &[Key::Ctrl('c')]), Flow::Quit);
    }

    #[test]
    fn a_place_that_cannot_open_is_a_card() {
        let _g = theme::force(Tier::True, false);
        let dir = TempDir::new();
        let (mut a, calls) = app(&dir);
        // No config: Machines says so, and enter opens Config.
        press(&mut a, &[Key::Char('4')]);
        assert_eq!(a.place(), Place::Machines);
        let s = screen(&a);
        assert!(s.contains("There is no config yet.") && s.contains("enter  open Config"), "{s}");
        assert!(calls.lock().unwrap().is_empty(), "nothing is asked of the coordinator first");
        press(&mut a, &[Key::Enter]);
        assert_eq!(a.place(), Place::Config);
        press(&mut a, &[Key::Esc]);
        // A config but no keys: build the installer.
        ready(&dir);
        std::fs::remove_file(test_paths(&dir).secrets.join(iso::SIGNING_KEY_NAME)).unwrap();
        press(&mut a, &[Key::Char('4')]);
        let s = screen(&a);
        assert!(s.contains("A key is missing") && s.contains("signing_ed25519") && s.contains("Build the installer (2)"), "{s}");
        press(&mut a, &[Key::Enter]);
        assert_eq!(a.place(), Place::Installer);
        press(&mut a, &[Key::Esc]);
        // Everything there, but the factory fails: its words, and r.
        ready(&dir);
        press(&mut a, &[Key::Char('4')]);
        let s = screen(&a);
        assert!(s.contains("has a passphrase") && s.contains("r  try again"), "{s}");
        press(&mut a, &[Key::Char('r')]);
        assert_eq!(*calls.lock().unwrap(), vec!["machines", "machines"]);
        assert_eq!(a.place(), Place::Machines, "the app stays up");
        press(&mut a, &[Key::Esc]);
        assert_eq!(a.place(), Place::Home);
        // Updates opens Machines too.
        press(&mut a, &[Key::Char('7')]);
        assert!(screen(&a).contains("has a passphrase"));
    }

    #[test]
    fn apps_and_outside_share_one_cluster() {
        let dir = TempDir::new();
        ready(&dir);
        std::fs::write(test_paths(&dir).secrets.join(crate::admin::KNOWN_HOSTS), "x").unwrap();
        let (mut a, calls) = app(&dir);
        press(&mut a, &[Key::Char('5')]);
        assert_eq!(a.place(), Place::Apps);
        assert!(screen(&a).contains("apps"), "{}", screen(&a));
        press(&mut a, &[Key::Char('o')]);
        assert_eq!(a.place(), Place::Outside, "o goes to Outside, as before");
        press(&mut a, &[Key::Char('a')]);
        assert_eq!(a.place(), Place::Apps);
        assert_eq!(*calls.lock().unwrap(), vec!["cluster"], "one link for both");
        press(&mut a, &[Key::Char('q')]);
        assert_eq!(a.place(), Place::Home);
        press(&mut a, &[Key::Char('6')]);
        assert_eq!(calls.lock().unwrap().len(), 2, "a new link after Home");
    }

    #[test]
    fn an_answer_from_a_closed_place_is_dropped() {
        let dir = TempDir::new();
        let (mut a, _) = app(&dir);
        let (emit, _rx) = collector();
        press(&mut a, &[Key::Char('8')]);
        let old = a.generation;
        press(&mut a, &[Key::Esc, Key::Char('8')]);
        assert_ne!(a.generation, old);
        // The old Backups' answer, then one that is no message of it.
        let stale = Msg { generation: old, body: Box::new(backups::Msg::Done(Err("late".into()))) };
        Model::update(&mut a, Event::Msg(stale), &emit);
        assert!(!screen(&a).contains("late"), "{}", screen(&a));
        let wrong = Msg { generation: a.generation, body: Box::new(42u32) };
        Model::update(&mut a, Event::Msg(wrong), &emit);
        let fresh = Msg { generation: a.generation, body: Box::new(backups::Msg::Done(Err("now".into()))) };
        Model::update(&mut a, Event::Msg(fresh), &emit);
        assert!(screen(&a).contains("The pull did not finish: now"), "{}", screen(&a));
    }

    #[test]
    fn under_sudo_only_the_installer_and_the_stick() {
        let _g = theme::force(Tier::True, false);
        let dir = TempDir::new();
        ready(&dir);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut a = App::new(test_paths(&dir), fakes(calls.clone())).with_root(true);
        let (emit, _rx) = collector();
        Model::update(&mut a, Event::Resize(100, 32), &emit);
        let s = screen(&a);
        assert_eq!(s.matches("open dryserver without sudo").count(), 7, "{s}");
        press(&mut a, &[Key::Char('4')]);
        assert_eq!(a.place(), Place::Home);
        assert!(screen(&a).contains("Machines works as your own user"));
        assert!(calls.lock().unwrap().is_empty());
        press(&mut a, &[Key::Char('2')]);
        assert_eq!(a.place(), Place::Installer);
        press(&mut a, &[Key::Esc, Key::Char('3')]);
        assert_eq!(a.place(), Place::Stick);
        assert!(screen(&a).contains("USB sticks"), "{}", screen(&a));
    }

    #[test]
    fn the_stick_without_root_hands_over_to_sudo() {
        let dir = TempDir::new();
        let (mut a, _) = app(&dir);
        press(&mut a, &[Key::Char('3')]);
        assert!(screen(&a).contains("There is no installer to write yet"), "{}", screen(&a));
        press(&mut a, &[Key::Esc]);
        ready(&dir);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut f = fakes(calls);
        f.exe = Some("/bin/false".into());
        let mut a = App::new(test_paths(&dir), f).with_root(false);
        press(&mut a, &[Key::Char('3')]);
        assert!(screen(&a).contains("Writing a stick needs root"), "{}", screen(&a));
        press(&mut a, &[Key::Enter]);
        let job = Model::job(&mut a).expect("sudo gets the terminal");
        assert!(job.title.contains("sudo"));
        let (emit, _rx) = collector();
        Model::update(&mut a, Event::Back(Err("the stick was not written (exit status 1)".into())), &emit);
        assert!(screen(&a).contains("the stick was not written"));
    }

    #[test]
    fn kill_switch_jobs_reach_quarantine() {
        let dir = TempDir::new();
        let list = dir.join("dryserver");
        std::fs::write(&list, "Host coord\n  HostName 10.1.0.60\nHost node-a.lan\n  HostName 10.1.0.71\n").unwrap();
        let ran = Arc::new(Mutex::new(Vec::new()));
        let r2 = ran.clone();
        let mut f = fakes(Arc::new(Mutex::new(Vec::new())));
        f.server_list = Some(list);
        f.quarantine = Arc::new(move |c| {
            r2.lock().unwrap().push(c);
            Ok(())
        });
        let mut a = App::new(test_paths(&dir), f).with_root(false);
        let (emit, _rx) = collector();
        Model::update(&mut a, Event::Resize(100, 32), &emit);
        press(&mut a, &[Key::Char('9'), Key::Enter]);
        assert!(screen(&a).contains("Cut the coordinator off on every server?"), "{}", screen(&a));
        assert!(Model::job(&mut a).is_none(), "nothing before the yes");
        press(&mut a, &[Key::Char('y')]);
        let job = Model::job(&mut a).expect("the cut gets the terminal");
        (job.run)().unwrap();
        Model::update(&mut a, Event::Back(Ok(())), &emit);
        assert_eq!(*ran.lock().unwrap(), vec![kill::Switch::Cut]);
        assert!(screen(&a).contains("Cut off on every server"), "{}", screen(&a));
    }

    #[test]
    fn too_small_and_resize() {
        let dir = TempDir::new();
        let (mut a, _) = app(&dir);
        let (emit, _rx) = collector();
        Model::update(&mut a, Event::Resize(60, 20), &emit);
        assert!(screen(&a).contains("Make this window at least"));
        press(&mut a, &[Key::Char('1')]);
        assert_eq!(a.place(), Place::Home, "keys do nothing while nothing shows");
        Model::update(&mut a, Event::Resize(80, 24), &emit);
        let r = rows(&a.view());
        assert_eq!(r.len(), 24);
        assert!(r.iter().any(|l| l.contains("Kill switch")));
        Model::update(&mut a, Event::Resize(60, 20), &emit);
        assert_eq!(press(&mut a, &[Key::Char('q')]), Flow::Quit);
    }

    #[test]
    fn help_and_paste() {
        let dir = TempDir::new();
        let (mut a, _) = app(&dir);
        press(&mut a, &[Key::Char('?')]);
        assert!(screen(&a).contains("Any key closes this."));
        press(&mut a, &[Key::Char('1')]);
        assert_eq!(a.place(), Place::Home, "the key only closed the help");
        press(&mut a, &[Key::Paste("4".into())]);
        assert_eq!(a.place(), Place::Home, "a paste is no key");
        press(&mut a, &[Key::Char('9'), Key::Paste("y".into())]);
        assert_eq!(a.place(), Place::Kill);
    }

    #[test]
    fn busy_places_ask_before_quitting() {
        let dir = TempDir::new();
        ready(&dir);
        let mut f = fakes(Arc::new(Mutex::new(Vec::new())));
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let rx = Mutex::new(rx);
        std::fs::write(test_paths(&dir).secrets.join(crate::admin::KNOWN_HOSTS), "x").unwrap();
        f.pull = Arc::new(move |_| {
            let _ = rx.lock().unwrap().recv_timeout(Duration::from_secs(5));
            Ok(crate::backup::Pulled::default())
        });
        let mut a = App::new(test_paths(&dir), f).with_root(false);
        let (emit, _rx) = collector();
        Model::update(&mut a, Event::Resize(100, 32), &emit);
        Model::init(&mut a, &emit);
        press(&mut a, &[Key::Char('8')]);
        Model::update(&mut a, Event::Key(Key::Char('p')), &emit);
        assert_eq!(press(&mut a, &[Key::Ctrl('c')]), Flow::Continue, "asks first");
        assert!(screen(&a).contains("ctrl+c again quits, and the pull from the coordinator stops."), "{}", screen(&a));
        assert_eq!(press(&mut a, &[Key::Ctrl('c')]), Flow::Quit);
        let _ = tx.send(());
    }

    #[test]
    fn config_form_steps_review_and_save() {
        let _g = theme::force(Tier::True, false);
        let dir = TempDir::new();
        let p = test_paths(&dir);
        let (mut a, _) = app(&dir);
        press(&mut a, &[Key::Char('1')]);
        assert_eq!(a.place(), Place::Config);
        assert!(screen(&a).contains("Step 1 of 7  WiFi"), "{}", screen(&a));
        // Leaving at once changes nothing.
        press(&mut a, &[Key::Esc]);
        assert_eq!(a.place(), Place::Home);
        assert!(screen(&a).contains("The config was not changed."));
        assert!(!p.config.exists(), "cancel must not write config");
        press(&mut a, &[Key::Char('1')]);
        // WiFi: SSID empty, no password.
        press(&mut a, &[Key::Enter, Key::Enter]);
        assert!(screen(&a).contains("Step 2 of 7  Mesh"));
        // Mesh: coordinator IP, then the defaults, and one outgoing port.
        press(&mut a, &crate::tui::type_text("192.168.1.50"));
        press(&mut a, &[Key::Enter, Key::Enter, Key::Enter, Key::Enter]);
        press(&mut a, &crate::tui::type_text("25565/tcp"));
        press(&mut a, &[Key::Enter]);
        // esc goes back one step, and enter comes forward again.
        press(&mut a, &[Key::Esc]);
        assert!(screen(&a).contains("Step 2 of 7  Mesh"), "{}", screen(&a));
        press(&mut a, &[Key::Enter, Key::Enter, Key::Enter, Key::Enter, Key::Enter, Key::Enter]);
        // Transport auto, switch subnet default, tools (all), extra packages.
        press(&mut a, &[Key::Enter, Key::Enter, Key::Enter, Key::Enter]);
        // Admin: username default, key, label, timezone.
        press(&mut a, &[Key::Enter]);
        press(&mut a, &[Key::Paste("ssh-ed25519 AAAAkey me@example.com".into())]);
        press(&mut a, &[Key::Enter, Key::Enter, Key::Enter]);
        let s = screen(&a);
        assert!(s.contains("Step 7 of 7  Review") && s.contains("192.168.1.50") && s.contains("enter  save to config.env"), "{s}");
        assert!(!p.config.exists(), "nothing is saved before the review's enter");
        press(&mut a, &[Key::Enter]);
        assert_eq!(a.place(), Place::Home, "{}", screen(&a));
        assert!(screen(&a).contains("Config saved"));
        let c = Config::load(&p.config).unwrap();
        assert_eq!(c.coord_lan_ip, "192.168.1.50");
        assert_eq!(c.admin_ssh_pubkey, "ssh-ed25519 AAAAkey");
        assert_eq!(c.tools, "docker go rust cpp neovim");
        assert_eq!(c.egress_ports, "25565/tcp");
        assert!(screen(&a).contains("coordinator 192.168.1.50"));
    }

    #[test]
    fn q_is_typed_in_a_text_field() {
        let dir = TempDir::new();
        let (mut a, _) = app(&dir);
        press(&mut a, &[Key::Char('1'), Key::Char('q'), Key::Char('?')]);
        assert_eq!(a.place(), Place::Config, "q and ? are letters of the SSID");
        assert!(screen(&a).contains("> q?"), "{}", screen(&a));
        // On the first step something changed now: leaving asks.
        press(&mut a, &[Key::Esc]);
        assert!(screen(&a).contains("Leave without saving?"));
        press(&mut a, &[Key::Char('y')]);
        assert_eq!(a.place(), Place::Home);
    }
}
