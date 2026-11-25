//! Installer: what will be built, then the build with the snake ring and
//! the last lines of its log. A failure is a card with the log's path and
//! r to try again; once built, enter goes on to the stick.

use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use super::app::{Paths, Place, PlaceScreen, Size};
use super::frame::{self, Back, Focus, Help, Notice, Page, col};
use super::home::{Cfg, Facts};
use super::theme::{self, Mark};
use super::{Emit, Event, Flow, Key, Seg, dim};
use crate::config::Config;
use crate::ctx::Ctx;
use crate::err::{Error, Result};
use crate::iso::{self, Options};
use crate::runner::LineWriter;

pub const KEEP_LINES: usize = 500;

/// Builds the image, writing its log (iso::run, or a fake in tests).
pub type Builder = Arc<dyn Fn(&Ctx, &Options, &mut (dyn Write + Send)) -> Result<()> + Send + Sync>;

pub enum Msg {
    Log(String),
    Done(Option<Error>),
}

/// How far the build is when a line starts with (or holds) the text. The
/// steps of build.sh and of mkarchiso, in order; the last one seen counts.
const STAGES: [(&str, f64); 11] = [
    ("==> Generating", 0.02),
    ("==> Starting", 0.05),
    ("==> Installing archiso", 0.1),
    ("==> Downloading k3s", 0.2),
    ("==> Running mkarchiso", 0.3),
    ("Installing packages", 0.35),
    ("Creating SquashFS image", 0.75),
    ("Creating checksum", 0.85),
    ("Creating ISO image", 0.9),
    ("==> Built", 0.97),
    ("==> Done", 1.0),
];

enum State {
    Ready,
    Running,
    Built(Duration),
    Failed(Error),
}

pub struct Build {
    /// The config, or what is wrong with it.
    cfg: std::result::Result<Config, String>,
    out_dir: PathBuf,
    secrets: PathBuf,
    missing_keys: Vec<String>,
    /// The swarm runs: a missing key is not made again (iso::ensure_keys).
    swarm_started: bool,
    image_before: Option<(u64, std::time::SystemTime)>,
    builder: Builder,
    lines: Vec<String>,
    ctx: Ctx,
    started: Instant,
    state: State,
    step: String,
    pct: f64,
    stop_armed: bool,
    /// Stopped by esc: leave once the build has ended.
    stopping: bool,
    /// Closed when the build's thread ends.
    ended: Option<mpsc::Receiver<()>>,
    notice: Option<Notice>,
    next: Option<Place>,
}

/// How long closing the app waits for a stopped build: podman takes its
/// container down within seconds, and is killed after thirty.
const STOP_WAIT: Duration = Duration::from_secs(40);

impl Build {
    pub fn new(paths: &Paths, facts: &Facts) -> Build {
        let cfg = match &facts.cfg {
            Cfg::Ok(c) => Ok((**c).clone()),
            Cfg::Missing => Err("there is no config yet".into()),
            Cfg::Broken(e) => Err(e.clone()),
        };
        Build {
            cfg,
            out_dir: paths.out_dir.clone(),
            secrets: paths.secrets.clone(),
            missing_keys: facts.missing_keys.clone(),
            swarm_started: facts.started,
            image_before: facts.iso,
            builder: Arc::new(|ctx, o, log| iso::run(ctx, o, log)),
            lines: Vec::new(),
            ctx: Ctx::new(),
            started: Instant::now(),
            state: State::Ready,
            step: String::new(),
            pct: 0.0,
            stop_armed: false,
            stopping: false,
            ended: None,
            notice: None,
            next: None,
        }
    }

    #[cfg(test)]
    fn with_builder(mut self, b: Builder) -> Build {
        self.builder = b;
        self
    }

    fn iso(&self) -> String {
        iso::iso_path(&self.out_dir).display().to_string()
    }

    fn log_path(&self) -> String {
        self.out_dir.join(iso::LOG_NAME).display().to_string()
    }

    /// Starts the build in the background.
    fn start(&mut self, emit: &Emit<Msg>) {
        let Ok(cfg) = self.cfg.clone() else { return };
        self.ctx = Ctx::new();
        self.state = State::Running;
        self.started = Instant::now();
        self.lines.clear();
        self.step = "Getting ready".into();
        self.pct = 0.0;
        self.notice = None;
        self.stop_armed = false;
        self.stopping = false;
        let opts = Options { config: cfg, out_dir: self.out_dir.clone(), secrets_dir: self.secrets.clone() };
        let (ctx, builder, emit) = (self.ctx.clone(), self.builder.clone(), emit.clone());
        let (end, ended) = mpsc::channel::<()>();
        self.ended = Some(ended);
        std::thread::spawn(move || {
            let _end = end;
            let e = emit.clone();
            let mut w = LineWriter::new(Arc::new(move |l: &str| e(Msg::Log(l.to_string()))));
            let res = builder(&ctx, &opts, &mut w);
            w.finish();
            emit(Msg::Done(res.err()));
        });
    }

    fn log(&mut self, l: String) {
        for (mark, pct) in STAGES {
            if (l.starts_with(mark) || l.contains(mark)) && pct >= self.pct {
                self.pct = pct;
                self.step = l.trim_start_matches("==> ").trim_start_matches("[mkarchiso] INFO: ").trim().to_string();
            }
        }
        self.lines.push(l);
        if self.lines.len() > KEEP_LINES {
            self.lines.drain(..self.lines.len() - KEEP_LINES);
        }
    }

    fn what(&self, b: &mut super::Doc, width: usize, cfg: &Config) {
        let p = theme::palette();
        frame::section(b, "What will be built", None);
        let net = if cfg.wifi_ssid.is_empty() { "Ethernet only".to_string() } else { format!("WiFi {}", cfg.wifi_ssid) };
        let mut tools = cfg.tool_list();
        tools.extend(cfg.extra_list());
        let tools = if tools.is_empty() { "the basics only".to_string() } else { format!("the basics, {}", tools.join(" ")) };
        let keys = if self.missing_keys.is_empty() {
            (Mark::Done, "kept: the same keys as before".to_string())
        } else if self.swarm_started {
            (Mark::Bad, format!("missing: restore {} from your backup (never made again)", self.missing_keys.join(", ")))
        } else {
            (Mark::Act, format!("made now: {}", self.missing_keys.join(", ")))
        };
        let image = match self.image_before {
            Some((size, made)) => {
                let when = chrono::DateTime::<chrono::Local>::from(made).format("%Y-%m-%d %H:%M");
                (Mark::Wait, format!("{}: replaces the one from {when} ({})", self.iso(), crate::disks::human_size(size)))
            }
            None => (Mark::Wait, format!("{}: made new", self.iso())),
        };
        let rows = [
            (Mark::Done, "Config", format!("coordinator {}, {net}, mesh {}", cfg.coord_lan_ip, cfg.wg_subnet)),
            (Mark::Done, "Tools", tools),
            (Mark::Done, "k3s", format!("{}, checked against its sha256", iso::K3S_VERSION)),
            (keys.0, "Keys", keys.1),
            (image.0, "Image", image.1),
        ];
        for (m, name, what) in rows {
            b.append(frame::row(width, m, vec![col(Seg(name.into(), p.text()), 8), col(Seg(what, p.hint()), 0)])).nl();
        }
        b.nl().add(dim("It builds Arch Linux in a podman container. The first build downloads about 1 GB and takes several minutes; \
             later ones use what it downloaded."));
        b.nl();
    }

    fn tail(&self, b: &mut super::Doc, width: usize, n: usize) {
        let p = theme::palette();
        for l in &self.lines[self.lines.len().saturating_sub(n)..] {
            b.add(Seg(super::fit(l, width.saturating_sub(2)), p.faint())).nl();
        }
    }
}

impl Drop for Build {
    /// A build left behind stops, and the app waits for it to end: a
    /// podman build it did not wait for would go on alone.
    fn drop(&mut self) {
        if !matches!(self.state, State::Running) {
            return;
        }
        self.ctx.cancel();
        if let Some(ended) = self.ended.take() {
            eprintln!("dryserver: stopping the build...");
            let _ = ended.recv_timeout(STOP_WAIT);
        }
    }
}

impl PlaceScreen for Build {
    type Msg = Msg;

    fn update(&mut self, ev: Event<Msg>, emit: &Emit<Msg>) -> Flow {
        match ev {
            Event::Msg(Msg::Log(l)) => self.log(l),
            Event::Msg(Msg::Done(e)) => {
                self.ended = None;
                if std::mem::take(&mut self.stopping) {
                    self.state = State::Ready;
                    self.notice = Some(Notice::info("The build was stopped."));
                    return Flow::Quit;
                }
                self.state = match e {
                    None => {
                        self.notice = Some(Notice::ok(format!("Built {} in {}.", self.iso(), super::dur(self.started.elapsed()))));
                        State::Built(self.started.elapsed())
                    }
                    Some(e) if e.is_canceled() => {
                        self.notice = Some(Notice::info("The build was stopped. enter builds again."));
                        State::Ready
                    }
                    Some(e) => State::Failed(e),
                };
            }
            Event::Key(k) => {
                let armed = std::mem::take(&mut self.stop_armed);
                match (&self.state, k) {
                    // It stops, and the place closes once it has.
                    (State::Running, Key::Esc) if armed || self.stopping => {
                        self.ctx.cancel();
                        self.stopping = true;
                        self.notice = Some(Notice::info("Stopping the build: the container is taken down first."));
                    }
                    (State::Running, Key::Esc) => {
                        self.stop_armed = true;
                        self.notice = Some(Notice::info("The build is still running. esc again stops it."));
                    }
                    (State::Running, _) => {}
                    (_, Key::Esc) => return Flow::Quit,
                    (State::Ready, Key::Enter) if self.cfg.is_err() => {
                        self.next = Some(Place::Config);
                        return Flow::Quit;
                    }
                    (State::Ready, Key::Enter) => self.start(emit),
                    (State::Built(_), Key::Enter) => {
                        self.next = Some(Place::Stick);
                        return Flow::Quit;
                    }
                    (State::Built(_) | State::Failed(_), Key::Char('r')) => self.start(emit),
                    _ => {}
                }
            }
            Event::Tick | Event::Resize(..) | Event::Back(_) => {}
        }
        Flow::Continue
    }

    fn page(&self, size: Size) -> Page {
        let p = theme::palette();
        let mut page = Page::new("Installer");
        page.status.add(dim(self.iso()));
        let w = size.width;
        let mut body = super::Doc::new();
        let b = &mut body;
        let mut focus = None;
        match (&self.state, &self.cfg) {
            (State::Ready, Err(e)) => {
                b.append(frame::card(
                    w,
                    &format!("The installer cannot be built yet: {e}."),
                    "The config says how the machines reach each other and you; fix it first.",
                    Some(("enter", "open Config")),
                ));
                page.key("enter", "open Config");
            }
            (State::Ready, Ok(cfg)) => {
                self.what(b, w, cfg);
                page.key("enter", "build");
            }
            (State::Running, _) => {
                b.append(frame::progress(w, Some(self.pct), &self.step, self.started.elapsed())).nl();
                frame::section(b, "Log", None);
                let n = size.rows.saturating_sub(theme::snake_height() + 4).max(3);
                self.tail(b, w, n);
                focus = Some(Focus::keep(b.lines.len().saturating_sub(2)..b.lines.len().saturating_sub(1)));
                if !self.stopping {
                    page.key("esc", "stop the build");
                }
                page.back = Back::Nothing;
            }
            (State::Built(took), _) => {
                b.append(frame::progress(w, Some(1.0), "The installer is built", *took)).nl().nl();
                b.add(Seg("Next".into(), p.selected())).s("  ").add(Seg(
                    "Write it to a USB stick (3): enter. Then boot your first laptop from it and choose coordinator.".into(),
                    p.text(),
                ));
                page.key("enter", "write a stick").key("r", "build again");
            }
            (State::Failed(e), _) => {
                b.append(frame::card(
                    w,
                    &format!("The build failed: {e}"),
                    &format!("The whole log is in {}. Fix what it says, then r tries again.", self.log_path()),
                    Some(("r", "try again")),
                ));
                if !self.lines.is_empty() {
                    frame::section(b, "The last lines of the log", None);
                    let n = size.rows.saturating_sub(12).max(3);
                    self.tail(b, w, n);
                }
                page.key("r", "try again");
            }
        }
        page.body = body;
        page.focus = focus;
        page.notice = self.notice.clone();
        page.help = Some(Help {
            about: "The installer is a USB stick image with your config, the keys this computer signs with, and everything a \
                    server needs, so machines install without the internet asking anything. Build it again whenever the config \
                    or dryserver changes."
                .into(),
            keys: vec![
                ("enter".into(), "build; once built, write a stick".into()),
                ("r".into(), "build again".into()),
                ("esc".into(), "back to Home (twice while it builds: stops it)".into()),
            ],
        });
        page
    }

    fn busy(&self) -> Option<String> {
        matches!(self.state, State::Running).then(|| "the build".into())
    }

    fn after(&self) -> Option<Notice> {
        self.notice.clone().filter(|n| n.text == "The build was stopped.")
    }

    fn next(&self) -> Option<Place> {
        self.next
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use crate::tui::collector;
    use std::sync::Mutex;

    fn facts(cfg: Cfg) -> Facts {
        Facts {
            cfg,
            cfg_loads: true,
            cfg_time: None,
            iso: None,
            exe_time: None,
            missing_keys: vec![iso::SIGNING_KEY_NAME.into()],
            started: false,
            signed: None,
            signed_time: None,
            release: None,
            backups: vec![],
            met: false,
            root: false,
            now: std::time::SystemTime::now(),
        }
    }

    fn good() -> Cfg {
        Cfg::Ok(Box::new(Config { coord_lan_ip: "10.1.0.60".into(), wifi_ssid: "SNET2".into(), ..Config::default() }))
    }

    fn text(b: &Build) -> String {
        b.page(Size { width: 90, rows: 28 }).body.plain()
    }

    #[test]
    fn shows_what_then_builds() {
        let dir = TempDir::new();
        let paths = Paths { config: dir.join("config.env"), out_dir: dir.join("out"), secrets: dir.join("secrets") };
        let fail = Arc::new(Mutex::new(true));
        let f2 = fail.clone();
        let mut b = Build::new(&paths, &facts(good())).with_builder(Arc::new(move |_, _, log| {
            writeln!(log, "==> Starting docker.io/library/archlinux:latest").unwrap();
            writeln!(log, "[mkarchiso] INFO: Creating SquashFS image, this may take some time...").unwrap();
            if *f2.lock().unwrap() { Err("container build failed (exit status 1), see out/build.log".into()) } else { Ok(()) }
        }));
        let t = text(&b);
        for want in ["What will be built", "coordinator 10.1.0.60, WiFi SNET2", "k3s", "made now: signing_ed25519", "made new"] {
            assert!(t.contains(want), "{want:?}:\n{t}");
        }
        let (emit, rx) = collector();
        b.update(Event::Key(Key::Enter), &emit);
        assert!(b.busy().is_some());
        assert!(text(&b).contains("Getting ready"));
        let pump = |b: &mut Build| {
            for m in rx.iter().take(3) {
                b.update(Event::Msg(m), &emit);
            }
        };
        pump(&mut b);
        assert!(b.pct >= 0.75 && b.step.starts_with("Creating SquashFS image"), "{} {}", b.pct, b.step);
        let t = text(&b);
        assert!(
            t.contains("The build failed: container build failed") && t.contains("out/build.log") && t.contains(" r  try again"),
            "{t}"
        );
        assert!(t.contains("Creating SquashFS image"), "the last lines of the log: {t}");
        *fail.lock().unwrap() = false;
        b.update(Event::Key(Key::Char('r')), &emit);
        pump(&mut b);
        assert!(
            b.busy().is_none() && b.notice.as_ref().is_some_and(|n| n.text.starts_with("Built")),
            "{:?}",
            b.notice.as_ref().map(|n| &n.text)
        );
        assert!(text(&b).contains("Next  Write it to a USB stick (3)"));
        assert_eq!(b.update(Event::Key(Key::Enter), &emit), Flow::Quit);
        assert_eq!(b.next(), Some(Place::Stick));
    }

    #[test]
    fn a_bad_config_sends_you_to_it() {
        let dir = TempDir::new();
        let paths = Paths { config: dir.join("config.env"), out_dir: dir.join("out"), secrets: dir.join("secrets") };
        let mut b = Build::new(&paths, &facts(Cfg::Missing));
        assert!(text(&b).contains("The installer cannot be built yet: there is no config yet."));
        let (emit, _rx) = collector();
        assert_eq!(b.update(Event::Key(Key::Enter), &emit), Flow::Quit);
        assert_eq!(b.next(), Some(Place::Config));
    }

    #[test]
    fn leaving_a_running_build_asks_and_stops_it() {
        let dir = TempDir::new();
        let paths = Paths { config: dir.join("config.env"), out_dir: dir.join("out"), secrets: dir.join("secrets") };
        let mut b = Build::new(&paths, &facts(good())).with_builder(Arc::new(|ctx, _, _| {
            while !ctx.done() {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(Error::canceled())
        }));
        let (emit, rx) = collector();
        b.update(Event::Key(Key::Enter), &emit);
        assert_eq!(b.update(Event::Key(Key::Char('x')), &emit), Flow::Continue, "keys do nothing while it builds");
        assert_eq!(b.update(Event::Key(Key::Esc), &emit), Flow::Continue);
        assert!(b.notice.as_ref().unwrap().text.contains("esc again stops it"));
        let ctx = b.ctx.clone();
        assert_eq!(b.update(Event::Key(Key::Esc), &emit), Flow::Continue, "it stays until the build has ended");
        assert!(ctx.done(), "the build was stopped");
        assert!(b.notice.as_ref().unwrap().text.starts_with("Stopping the build"));
        assert!(b.busy().is_some());
        let m = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(m, Msg::Done(Some(_))));
        assert_eq!(b.update(Event::Msg(m), &emit), Flow::Quit, "then it leaves");
        assert_eq!(b.after().map(|n| n.text), Some("The build was stopped.".to_string()));
        // Dropped while it runs (the app quits): it waits for the end.
        let mut b = Build::new(&paths, &facts(good())).with_builder(Arc::new(|ctx, _, _| {
            while !ctx.done() {
                std::thread::sleep(Duration::from_millis(5));
            }
            std::thread::sleep(Duration::from_millis(100));
            Err(Error::canceled())
        }));
        b.update(Event::Key(Key::Enter), &emit);
        let ctx = b.ctx.clone();
        let t = Instant::now();
        drop(b);
        assert!(ctx.done() && t.elapsed() >= Duration::from_millis(100), "the drop waited for the build");
    }
}
