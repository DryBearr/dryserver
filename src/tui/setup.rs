//! The installer's screens, on the machine being installed. It runs on the
//! Linux console (16 colours, the glyphs of code page 437) as its own
//! tui::run, in the frame: "dryserver  Install" with the step on the
//! right, the body, the notice and the keys. Five steps, each with the
//! ring grown that far:
//!
//!   1 This machine        what it has, its network (WiFi when it is not
//!                         online) and the role it will get
//!   2 Your answers        the form
//!   3 Checks              what can be checked before anything is erased
//!   4 Erase and install   typing YES, then the install and its progress
//!   5 Join the mesh       a server's pairing code in large digits until
//!                         the desktop approves it; a coordinator shows the
//!                         code to sign it with when it is done
//!
//! esc goes back one step; on the first it asks before leaving. A failure
//! is a card with what happened, what to do and the key that does it.
//! Nothing writes to a disk before YES: the probe, the WiFi and the checks
//! only read the machine or change the live system, which is in RAM.

use std::cell::Cell;
use std::ops::Range;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ratatui::style::{Modifier, Style};

use super::build::KEEP_LINES;
use super::form::{Field, Form, Group, Status};
use super::frame::{self, Back, Focus, Help, Notice, Overlay, Page, Scroll, col};
use super::theme::{self, Mark, Tier};
use super::{Doc, Emit, Event, Flow, Key, Model, Seg, TextInput, spinner};
use crate::config::Config;
use crate::ctx::Ctx;
use crate::disks::{Disk, human_size};
use crate::err::{Error, Kind, Result};
use crate::install::{self, Backend, Choices, Encryption, Machine, Step};
use crate::sysconf::{self, Role};

pub enum Msg {
    Probe(Result<Machine>),
    WifiList(Result<Vec<String>>),
    WifiConnected(Result<Machine>),
    Step(Step),
    CheckDone(Option<Error>),
    InstallDone(Option<Error>),
    JoinCode(String),
    JoinDone(Result<u32>),
}

/// A message from background work with the number of the job that sent
/// it: the answer of a job that was stopped or replaced since is dropped.
pub struct Tagged(u64, Msg);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Probe,
    Welcome,
    Wifi,
    /// Waiting on a background call (WiFi scan/connect).
    Busy,
    /// Prechecks with a live log.
    Check,
    Form,
    Confirm,
    Install,
    Join,
    Done,
    Failed,
}

/// What State::Busy waits for.
#[derive(Debug, Clone, PartialEq)]
enum Busy {
    Scan,
    Connect(String),
}

/// What r does on the failure card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Retry {
    No,
    /// Look at the machine again.
    Probe,
    /// The install again, with the same answers.
    Install,
}

struct StepView {
    name: String,
    done: bool,
    start: Instant,
    took: Duration,
}

/// Asking the coordinator to let this server in.
#[derive(Default)]
struct Joining {
    /// When the first request went out.
    first: Option<Instant>,
    /// Requests that did not go through.
    tries: u32,
    /// The next request, after one did not go through; None while one runs.
    again: Option<Instant>,
    /// s was pressed while a request ran.
    skipping: bool,
}

/// What the setup form edits.
pub struct Answers {
    pub ch: Choices,
    disk_confirm: String,
    user_confirm: String,
}

#[derive(Default)]
struct Wifi {
    ssid: String,
    pass: String,
}

pub struct Setup {
    be: Arc<dyn Backend>,
    cfg: Config,
    pub state: State,
    pub m: Machine,
    pub ch: Choices,
    form: Option<Form<Answers>>,
    wifi_form: Option<Form<Wifi>>,
    ssids: Vec<String>,
    /// The network of the last WiFi try, chosen again for the next one.
    wifi_ssid: String,
    pub confirm: TextInput,
    busy: Busy,
    /// When the background job on screen started.
    since: Instant,
    steps: Vec<StepView>,
    lines: Vec<String>,
    /// The downloads of the running step, from its log: (done, total) MiB.
    dl: Option<(f64, f64)>,
    ctx: Ctx,
    /// The number of the background job whose answers count.
    job: u64,
    /// The first ctrl+c during install was pressed.
    armed: bool,
    /// The install was told to stop.
    stopping: bool,
    pub code: String,
    pub host_num: u32,
    join: Joining,
    join_err: Option<Error>,
    check_err: Option<Error>,
    /// What r does on the failure card.
    retry: Retry,
    /// The step that failed, 1 to 5.
    failed_at: usize,
    pub err: Option<Error>,
    pub notice: Option<Notice>,
    w: u16,
    h: u16,
    scroll: Scroll,
    /// The screen the scroll position is for: a new one starts at the top.
    shown: Cell<Option<(State, bool)>>,
    help: bool,
    /// The log, whole, instead of the screen.
    log_open: bool,
    /// esc on the first step: asking whether to leave.
    leaving: bool,
}

const LOG_HINT: &str = "/tmp/dryserver-install.log";

/// The steps "Step n of 5" counts.
const STEPS: usize = 5;

/// How long a server waits before it asks the coordinator again after a
/// request did not go through, as it does at boot.
const ASK_AGAIN: Duration = Duration::from_secs(30);

fn step_name(n: usize, role: Role) -> &'static str {
    match n {
        1 => "This machine",
        2 => "Your answers",
        3 => "Checks",
        4 => "Erase and install",
        _ if role == Role::Coordinator => "Sign it",
        _ => "Join the mesh",
    }
}

impl Setup {
    pub fn new(be: Arc<dyn Backend>, cfg: Config) -> Setup {
        let mut confirm = TextInput::new(8);
        confirm.placeholder = String::new();
        Setup {
            be,
            cfg,
            state: State::Probe,
            m: Machine::default(),
            ch: Choices::default(),
            form: None,
            wifi_form: None,
            ssids: Vec::new(),
            wifi_ssid: String::new(),
            confirm,
            busy: Busy::Scan,
            since: Instant::now(),
            steps: Vec::new(),
            lines: Vec::new(),
            dl: None,
            ctx: Ctx::new(),
            job: 0,
            armed: false,
            stopping: false,
            code: String::new(),
            host_num: 0,
            join: Joining::default(),
            join_err: None,
            check_err: None,
            retry: Retry::No,
            failed_at: 1,
            err: None,
            notice: None,
            w: 80,
            h: 25,
            scroll: Scroll::default(),
            shown: Cell::new(None),
            help: false,
            log_open: false,
            leaving: false,
        }
    }

    /// Runs job in the background as the job whose answers count.
    fn spawn(&mut self, emit: &Emit<Tagged>, job: impl FnOnce(Ctx, Arc<dyn Backend>, Emit<Msg>) + Send + 'static) {
        self.ctx = Ctx::new();
        self.job += 1;
        self.since = Instant::now();
        let (ctx, be, n, e) = (self.ctx.clone(), self.be.clone(), self.job, emit.clone());
        let mine: Emit<Msg> = Arc::new(move |m| e(Tagged(n, m)));
        std::thread::spawn(move || job(ctx, be, mine));
    }

    /// Stops the background job and drops what it still answers.
    fn drop_job(&mut self) {
        self.ctx.cancel();
        self.job += 1;
    }

    pub fn handle(&mut self, ev: Event<Tagged>, emit: &Emit<Tagged>) -> Flow {
        match ev {
            Event::Resize(w, h) => (self.w, self.h) = (w, h),
            Event::Tick => self.tick(emit),
            Event::Key(k) => return self.key(k, emit),
            Event::Msg(Tagged(n, m)) => {
                if n == self.job {
                    self.message(m, emit);
                }
            }
            Event::Back(_) => {}
        }
        Flow::Continue
    }

    fn tick(&mut self, emit: &Emit<Tagged>) {
        if self.state == State::Join && self.join.again.is_some_and(|t| Instant::now() >= t) {
            self.start_join(emit);
        }
    }

    fn message(&mut self, msg: Msg, emit: &Emit<Tagged>) {
        match msg {
            Msg::Probe(Ok(m)) => {
                self.m = m;
                self.state = State::Welcome;
            }
            Msg::Probe(Err(e)) => self.fail(1, e, Retry::Probe),
            Msg::WifiList(res) => {
                match res {
                    Ok(l) => self.ssids = l,
                    Err(e) => {
                        self.notice = Some(Notice::bad(format!("The WiFi scan failed: {e}. Type the network's name instead.")));
                        self.ssids.clear();
                    }
                }
                self.open_wifi_form();
            }
            Msg::WifiConnected(res) => match res {
                Ok(m) => {
                    self.m = m;
                    self.state = State::Welcome;
                    self.notice = Some(Notice::ok(format!("Connected to {}.", self.wifi_ssid)));
                }
                Err(e) => {
                    self.notice =
                        Some(Notice::bad(format!("Could not connect to {}: {e}. Type the password again, or esc.", self.wifi_ssid)));
                    self.open_wifi_form();
                }
            },
            Msg::CheckDone(Some(e)) => self.check_err = Some(e),
            Msg::CheckDone(None) => {
                self.steps.clear();
                self.lines.clear();
                self.state = State::Confirm;
                self.confirm.set_value("");
                self.confirm.focus();
            }
            Msg::Step(st) => self.add_step(st),
            Msg::InstallDone(Some(e)) => self.fail(4, e, Retry::Install),
            Msg::InstallDone(None) => {
                self.armed = false;
                self.stopping = false;
                if self.ch.role() == Role::Coordinator {
                    self.code = self.be.coordinator_code();
                    self.state = State::Done;
                } else {
                    self.start_join(emit);
                }
            }
            Msg::JoinCode(c) => self.code = c,
            Msg::JoinDone(res) => match res {
                Ok(h) => {
                    self.host_num = h;
                    self.join_err = None;
                    self.state = State::Done;
                }
                Err(e) if e.is(Kind::Rejected) => self.fail(5, e, Retry::No),
                Err(e) if self.join.skipping || e.is_canceled() => {
                    self.join_err = Some(e);
                    self.state = State::Done;
                }
                // The coordinator did not answer, or not yet with a yes or
                // no: ask again in a while, as the server does at boot.
                Err(e) => {
                    self.join.tries += 1;
                    self.join.again = Some(Instant::now() + ASK_AGAIN);
                    self.code.clear();
                    self.join_err = Some(e);
                }
            },
        }
    }

    fn fail(&mut self, at: usize, e: Error, retry: Retry) {
        self.state = State::Failed;
        self.failed_at = at;
        self.err = Some(e);
        self.retry = retry;
        self.armed = false;
        self.stopping = false;
    }

    /// Text is being typed: q and ? are letters.
    fn typing(&self) -> bool {
        match self.state {
            State::Form => self.form.as_ref().is_some_and(|f| f.typing()),
            State::Wifi => self.wifi_form.as_ref().is_some_and(|f| f.typing()),
            State::Confirm => !self.leaving && !self.help,
            _ => false,
        }
    }

    fn key(&mut self, k: Key, emit: &Emit<Tagged>) -> Flow {
        // A paste types into a field of a form and nowhere else: where a
        // key is expected, and in the YES field, it does nothing.
        if matches!(k, Key::Paste(_)) && !(self.typing() && self.state != State::Confirm) {
            return Flow::Continue;
        }
        if self.help {
            self.help = false;
            return Flow::Continue;
        }
        if self.leaving {
            self.leaving = false;
            if matches!(k, Key::Char('y') | Key::Ctrl('c')) {
                return Flow::Quit;
            }
            self.notice = Some(Notice::info("The installer stays."));
            return Flow::Continue;
        }
        let typing = self.typing();
        if k == Key::Char('?') && !typing {
            self.help = true;
            return Flow::Continue;
        }
        if (matches!(k, Key::PageUp | Key::PageDown) || (!typing && matches!(k, Key::Home | Key::End))) && self.scroll.key(&k) {
            return Flow::Continue;
        }
        let k = if k == Key::Char('q') && !typing { Key::Esc } else { k };
        let armed = std::mem::take(&mut self.armed);
        self.notice = None;
        if self.log_open {
            match k {
                Key::Esc | Key::Char('l') => {
                    self.log_open = false;
                    return Flow::Continue;
                }
                Key::Ctrl('c') => {}
                _ => return Flow::Continue,
            }
        }
        match self.state {
            State::Probe => {
                if k == Key::Ctrl('c') {
                    return Flow::Quit;
                }
            }
            State::Busy => match k {
                Key::Ctrl('c') => return Flow::Quit,
                Key::Esc => {
                    self.drop_job();
                    match self.busy {
                        Busy::Scan => self.state = State::Welcome,
                        Busy::Connect(_) => self.open_wifi_form(),
                    }
                    self.notice = Some(Notice::info("Stopped."));
                }
                _ => {}
            },
            State::Welcome => match k {
                Key::Ctrl('c') => return Flow::Quit,
                Key::Esc => self.leaving = true,
                Key::Char('w') => self.scan_wifi(emit),
                Key::Char('r') => self.start_probe(emit),
                Key::Enter => {
                    if !self.m.online {
                        self.scan_wifi(emit);
                    } else if self.m.disks.is_empty() {
                        self.notice = Some(Notice::bad("There is no disk to install on: the card says what to do."));
                    } else {
                        self.open_form();
                    }
                }
                _ => {}
            },
            State::Wifi => {
                if k == Key::Ctrl('c') {
                    return Flow::Quit;
                }
                self.update_wifi_form(&k, emit);
            }
            State::Form => {
                if k == Key::Ctrl('c') {
                    return Flow::Quit;
                }
                self.update_form(&k, emit);
            }
            State::Check => {
                let failed = self.check_err.as_ref().map(|e| (e.is_canceled(), e.to_string()));
                match (failed, k) {
                    (None, Key::Esc | Key::Ctrl('c')) => {
                        self.ctx.cancel();
                        self.notice = Some(Notice::info("Stopping the checks."));
                    }
                    (Some(_), Key::Char('r')) => self.start_check(emit),
                    (Some(_), Key::Char('l')) => self.log_open = true,
                    (Some((stopped, e)), Key::Enter | Key::Esc) => {
                        self.open_form();
                        self.notice = Some(if stopped {
                            Notice::info("The checks were stopped. Nothing was erased.")
                        } else {
                            Notice::bad(format!("Check failed: {e}"))
                        });
                    }
                    (Some(_), Key::Ctrl('c')) => return Flow::Quit,
                    _ => {}
                }
            }
            State::Confirm => match k {
                Key::Ctrl('c') => return Flow::Quit,
                Key::Esc => self.open_form(),
                Key::Enter => {
                    if self.confirm.value.trim() != "YES" {
                        self.notice = Some(Notice::bad("Type YES in capital letters to erase and install, or esc to change the answers."));
                        return Flow::Continue;
                    }
                    self.start_install(emit);
                }
                k => {
                    self.confirm.handle(&k);
                }
            },
            State::Install => match k {
                Key::Ctrl('c') if armed => {
                    self.ctx.cancel();
                    self.stopping = true;
                }
                Key::Ctrl('c') => {
                    self.armed = true;
                    self.notice = Some(Notice::bad(
                        "ctrl+c again stops the install. The disks are left half-installed and do not start; r installs again.",
                    ));
                }
                Key::Char('l') => self.log_open = true,
                _ => {}
            },
            State::Join => match k {
                Key::Char('s') | Key::Ctrl('c') => self.skip_join(),
                Key::Char('r') if self.join.again.is_some() => self.start_join(emit),
                _ => {}
            },
            State::Done => match k {
                Key::Enter => match self.be.reboot() {
                    Ok(()) => return Flow::Quit,
                    Err(e) => {
                        self.notice = Some(Notice::bad(format!("The restart failed: {e}. enter tries again; or hold the power button.")))
                    }
                },
                Key::Esc | Key::Ctrl('c') => return Flow::Quit,
                _ => {}
            },
            State::Failed => match (self.retry, k) {
                (_, Key::Ctrl('c')) => return Flow::Quit,
                (Retry::Probe, Key::Char('r')) => self.start_probe(emit),
                (Retry::Probe, Key::Esc) => self.leaving = true,
                (Retry::Install, Key::Char('r')) => {
                    // Same answers; leftovers of the failed attempt are
                    // released by the partition step.
                    self.err = None;
                    self.retry = Retry::No;
                    self.start_install(emit);
                }
                (Retry::Install, Key::Esc) => {
                    self.err = None;
                    self.retry = Retry::No;
                    self.open_form();
                }
                (Retry::No, Key::Enter | Key::Esc) => return Flow::Quit,
                (_, Key::Char('l')) if !self.lines.is_empty() => self.log_open = true,
                _ => {}
            },
        }
        Flow::Continue
    }

    fn start_probe(&mut self, emit: &Emit<Tagged>) {
        self.state = State::Probe;
        self.err = None;
        self.retry = Retry::No;
        self.spawn(emit, |ctx, be, emit| emit(Msg::Probe(be.probe(&ctx))));
    }

    fn scan_wifi(&mut self, emit: &Emit<Tagged>) {
        self.state = State::Busy;
        self.busy = Busy::Scan;
        self.spawn(emit, |ctx, be, emit| emit(Msg::WifiList(be.scan_wifi(&ctx))));
    }

    fn open_wifi_form(&mut self) {
        let ssid = if self.ssids.is_empty() {
            Field::input("WiFi network name", |w: &Wifi| w.ssid.clone(), |w, v| w.ssid = v)
        } else {
            let opts: Vec<(String, String)> = self.ssids.iter().map(|s| (s.clone(), s.clone())).collect();
            Field::select("WiFi network", move |_| opts.clone(), |w: &Wifi| w.ssid.clone(), |w, v| w.ssid = v)
        };
        let group = Group::new(vec![
            Field::note("Connect to WiFi", "Used for this install only; the servers use the WiFi from your config."),
            ssid,
            Field::input("Password", |w: &Wifi| w.pass.clone(), |w, v| w.pass = v).password(),
        ]);
        // One step: nothing to review, and the screen keeps nothing typed
        // but the network, chosen again after a wrong password.
        let start = Wifi { ssid: self.wifi_ssid.clone(), pass: String::new() };
        let mut f = Form::new(start, vec![group], "back").without_review().keeps_answers();
        if !self.wifi_ssid.is_empty() && (self.ssids.is_empty() || self.ssids.contains(&self.wifi_ssid)) {
            // Straight to the password: the network is the one just tried.
            f.update(&Key::Enter);
        }
        self.wifi_form = Some(f);
        self.state = State::Wifi;
    }

    fn update_wifi_form(&mut self, k: &Key, emit: &Emit<Tagged>) {
        let Some(f) = self.wifi_form.as_mut() else {
            return;
        };
        f.update(k);
        match f.status {
            Status::Aborted => {
                self.wifi_form = None;
                self.state = State::Welcome;
            }
            Status::Completed => {
                let w = self.wifi_form.take().unwrap().state;
                self.wifi_ssid = w.ssid.clone();
                self.state = State::Busy;
                self.busy = Busy::Connect(w.ssid.clone());
                self.spawn(emit, move |ctx, be, emit| emit(Msg::WifiConnected(be.connect_wifi(&ctx, &w.ssid, &w.pass))));
            }
            Status::Active => {}
        }
    }

    pub fn open_form(&mut self) {
        if self.ch.role.is_none() {
            // First laptop (nobody answers at the coordinator address) is the
            // coordinator; later ones are servers.
            self.ch.role = Some(if self.m.coord_found { Role::Node } else { Role::Coordinator });
        }
        let opts = self.m.encryption_options();
        if !self.ch.encryption.is_some_and(|e| opts.contains(&e)) {
            self.ch.encryption = Some(opts[0]);
        }
        if self.ch.system_disk.is_empty()
            && let Some(d) = self.m.disks.first()
        {
            self.ch.system_disk = d.path.clone();
        }
        self.ch.disk_passphrase.clear();
        self.ch.user_password.clear();
        let answers = Answers { ch: self.ch.clone(), disk_confirm: String::new(), user_confirm: String::new() };
        self.form = Some(setup_form(&self.m, &self.cfg, answers));
        self.state = State::Form;
    }

    fn update_form(&mut self, k: &Key, emit: &Emit<Tagged>) {
        let Some(f) = self.form.as_mut() else {
            return;
        };
        f.update(k);
        match f.status {
            Status::Aborted => {
                self.ch = self.form.take().unwrap().state.ch;
                self.state = State::Welcome;
            }
            Status::Completed => {
                let mut ch = self.form.take().unwrap().state.ch;
                if ch.hostname.is_empty() {
                    ch.hostname = install::default_hostname(ch.role());
                }
                if ch.enc() == Encryption::None {
                    ch.disk_passphrase.clear();
                }
                let sys = ch.system_disk.clone();
                ch.data_disks.retain(|p| *p != sys);
                self.ch = ch;
                self.start_check(emit);
            }
            Status::Active => {}
        }
    }

    /// Runs the prechecks in the background, streaming steps and log lines
    /// to the screen.
    pub fn start_check(&mut self, emit: &Emit<Tagged>) {
        self.state = State::Check;
        self.check_err = None;
        self.steps.clear();
        self.lines.clear();
        self.dl = None;
        let (cfg, ch) = (self.cfg.clone(), self.ch.clone());
        self.spawn(emit, move |ctx, be, emit| {
            let e = emit.clone();
            let res = be.precheck(&ctx, &cfg, &ch, Arc::new(move |st| e(Msg::Step(st))));
            emit(Msg::CheckDone(res.err()));
        });
    }

    pub fn start_install(&mut self, emit: &Emit<Tagged>) {
        self.state = State::Install;
        self.steps.clear();
        self.lines.clear();
        self.dl = None;
        self.armed = false;
        self.stopping = false;
        self.confirm.blur();
        let (cfg, ch) = (self.cfg.clone(), self.ch.clone());
        self.spawn(emit, move |ctx, be, emit| {
            let e = emit.clone();
            let res = be.install(&ctx, &cfg, &ch, Arc::new(move |st| e(Msg::Step(st))));
            emit(Msg::InstallDone(res.err()));
        });
    }

    fn start_join(&mut self, emit: &Emit<Tagged>) {
        self.state = State::Join;
        self.join.again = None;
        self.join.skipping = false;
        self.join.first.get_or_insert_with(Instant::now);
        self.code.clear();
        let (cfg, ch) = (self.cfg.clone(), self.ch.clone());
        self.spawn(emit, move |ctx, be, emit| {
            let e = emit.clone();
            let res = be.join(&ctx, &cfg, &ch, &move |code| e(Msg::JoinCode(code)));
            emit(Msg::JoinDone(res));
        });
    }

    /// s while joining: the server asks again at every start until it is
    /// approved.
    fn skip_join(&mut self) {
        if self.join.again.take().is_some() {
            // Nothing runs: it was waiting to ask again.
            self.join.skipping = true;
            self.state = State::Done;
        } else if !self.join.skipping {
            self.join.skipping = true;
            self.ctx.cancel();
        }
    }

    fn add_step(&mut self, st: Step) {
        if !st.log.is_empty() {
            if let Some(d) = downloaded(&st.log) {
                self.dl = Some(d);
            }
            self.lines.push(st.log);
            if self.lines.len() > KEEP_LINES {
                self.lines.drain(..self.lines.len() - KEEP_LINES);
            }
            return;
        }
        if let Some(s) = self.steps.iter_mut().find(|s| s.name == st.name) {
            s.done = st.done;
            if st.done {
                s.took = s.start.elapsed();
                self.dl = None;
            }
            return;
        }
        self.dl = None;
        self.steps.push(StepView { name: st.name, done: st.done, start: Instant::now(), took: Duration::ZERO });
    }

    /// How far the install is: its finished steps, and the downloads of
    /// the one that runs.
    fn install_pct(&self) -> f64 {
        let done = self.steps.iter().filter(|s| s.done).count() as f64;
        let part = match (self.steps.last(), self.dl) {
            (Some(st), Some((got, total))) if !st.done && total > 0.0 => (got / total).clamp(0.0, 1.0) * 0.9,
            _ => 0.0,
        };
        ((done + part) / install::INSTALL_STEPS as f64).clamp(0.0, 1.0)
    }

    // ---- the screens ----

    /// The step on screen, 1 to 5, and 6 once done.
    fn at(&self) -> usize {
        match self.state {
            State::Probe | State::Welcome | State::Wifi | State::Busy => 1,
            State::Form => 2,
            State::Check => 3,
            State::Confirm | State::Install => 4,
            State::Join => 5,
            State::Done => STEPS + 1,
            State::Failed => self.failed_at,
        }
    }

    /// The role it gets: the answer, else what the network says.
    fn role(&self) -> Role {
        self.ch.role.unwrap_or(if self.m.coord_found { Role::Node } else { Role::Coordinator })
    }

    /// The ring grown as far as the steps, with the five steps beside it:
    /// done in gold, this one in ember with what it does, the rest in ash.
    fn banner(&self, width: usize, rows: usize) -> Doc {
        let p = theme::palette();
        let at = self.at();
        let role = self.role();
        let failed = self.state == State::Failed || (self.state == State::Check && self.check_err.is_some());
        let not_joined = self.state == State::Done && role == Role::Node && self.host_num == 0;
        let mut lines: Vec<Vec<Seg>> = Vec::new();
        for n in 1..=STEPS {
            let (mark, style, hint) = if n == at && failed {
                (Mark::Bad, p.text().add_modifier(Modifier::BOLD), "")
            } else if n == at {
                (Mark::Act, p.title(), self.step_hint())
            } else if n == STEPS && at > STEPS && role == Role::Coordinator {
                (Mark::Act, p.text(), "on your computer, after it restarts")
            } else if n == STEPS && not_joined {
                (Mark::Wait, p.text(), "it asks again after it restarts")
            } else if n < at {
                (Mark::Done, p.text(), "")
            } else {
                (Mark::Off, p.faint(), "")
            };
            let mut l = vec![theme::mark(mark), Seg("  ".into(), Style::new()), Seg(step_name(n, role).into(), style)];
            if !hint.is_empty() {
                l.push(Seg(format!("   {hint}"), p.hint()));
            }
            lines.push(l);
        }
        // The pixel snake where the colours and the rows allow it; the
        // block ring else; no ring where it does not fit beside the steps.
        let pixels = matches!(p.tier, Tier::True | Tier::C256) && rows >= 28;
        let spread = if pixels { 2 } else { 1 };
        let mut text = Doc::new();
        for (i, l) in lines.into_iter().enumerate() {
            for _ in 0..if i > 0 { spread } else { 0 } {
                text.nl();
            }
            for s in l {
                text.add(s);
            }
        }
        if width < 40 {
            return text;
        }
        let grown = if at > STEPS { 1.0 } else { (at - 1) as f64 / STEPS as f64 };
        let snake = if pixels { theme::snake(Some(grown)) } else { theme::ring(Some(grown)) };
        Doc::beside(snake, 3, text)
    }

    fn step_hint(&self) -> &'static str {
        match self.state {
            State::Probe | State::Welcome | State::Wifi | State::Busy => "what it has and what it becomes",
            State::Form | State::Check => "nothing is erased yet",
            State::Confirm | State::Install => "erases the disks you chose",
            State::Join => "approve it on your computer",
            State::Done | State::Failed => "",
        }
    }

    pub fn page(&self) -> Page {
        let p = theme::palette();
        let (w, rows) = (frame::any_body_width(self.w, self.h), frame::any_body_rows(self.w, self.h));
        // A new screen starts at its top.
        let screen = Some((self.state, self.log_open));
        if self.shown.get() != screen {
            self.shown.set(screen);
            self.scroll.reset();
        }
        let mut page = Page::new("Install");
        let at = self.at();
        if at > STEPS {
            page.status.add(Seg("Done".into(), p.ok()));
        } else {
            page.status.add(Seg(format!("Step {at} of {STEPS}"), p.hint()));
        }
        page.back = Back::Nothing;
        page.notice = self.notice.clone();
        page.help = Some(self.help_text());
        let mut b = Doc::new();
        let focus = if self.log_open {
            self.view_log(&mut b, &mut page, w);
            Some(Focus::keep(b.lines.len().saturating_sub(2)..b.lines.len().saturating_sub(1)))
        } else {
            if self.state != State::Install {
                b.append(self.banner(w, rows));
                b.nl();
            }
            self.body(&mut b, &mut page, w, rows)
        };
        page.body = b;
        page.focus = focus;
        // The arrows are not among the glyphs the console's font is
        // trusted with.
        if p.console {
            for (k, _) in &mut page.keys {
                *k = k.replace("↑↓", "up down");
            }
        }
        if self.leaving {
            page.overlay = Some(Overlay::Confirm {
                question: "Leave the installer?".into(),
                consequences: vec!["Nothing on this machine was changed.".into(), "To start it again, type: dryserver install".into()],
            });
        } else if self.help {
            page.overlay = Some(Overlay::Help);
        }
        page
    }

    /// The screen of the state under the banner; the lines to keep in view.
    fn body(&self, b: &mut Doc, page: &mut Page, w: usize, rows: usize) -> Option<Focus> {
        let p = theme::palette();
        let ip = &self.cfg.coord_lan_ip;
        match self.state {
            State::Probe => {
                b.nl();
                busy_line(b, "Looking at this machine", self.since);
                b.add(hint(format!(
                    "Its disks, its network, and whether a coordinator answers at {ip}. Up to half a minute when it \
                     connects to the WiFi from your config."
                )))
                .nl();
                page.key("ctrl+c", "leave");
            }
            State::Welcome => self.view_welcome(b, page, w),
            State::Busy => {
                b.nl();
                let (what, long) = match &self.busy {
                    Busy::Scan => ("Looking for WiFi networks".to_string(), "about five seconds"),
                    Busy::Connect(s) => (format!("Connecting to {s}"), "up to half a minute"),
                };
                busy_line(b, &what, self.since);
                b.add(hint(format!("This takes {long}."))).nl();
                page.key("esc", "stop");
            }
            State::Wifi => {
                let f = self.wifi_form.as_ref()?;
                frame::section(b, "Connect to WiFi", None);
                let (mut d, fr) = f.body(w);
                // The form's own "Step 1 of 1" line and the blank after it.
                d.lines.drain(..2.min(d.lines.len()));
                let fr = fr.map(|r| r.start.saturating_sub(2)..r.end.saturating_sub(2));
                let focus = put(b, d, fr);
                form_keys(page, f.keys(), &f.esc_label());
                return focus.map(Focus::keep);
            }
            State::Form => {
                let f = self.form.as_ref()?;
                let (mut d, fr) = f.body(w);
                // "Question 2 of 7": the steps are the installer's.
                if let Some(s) = d.lines.first_mut().and_then(|l| l.first_mut()) {
                    s.0 = s.0.replacen("Step", "Question", 1);
                }
                b.nl();
                let focus = put(b, d, fr);
                form_keys(page, f.keys(), &f.esc_label());
                return focus.map(Focus::keep);
            }
            State::Check => {
                let failed = self.check_err.is_some();
                if let Some(e) = &self.check_err {
                    let (problem, todo) = if e.is_canceled() {
                        ("The checks were stopped. Nothing was erased.".to_string(), "r checks again; esc goes back to the answers.")
                    } else {
                        (
                            format!("A check failed: {e}"),
                            "Nothing was erased. Fix what it says, then r checks again; esc goes back to the answers.",
                        )
                    };
                    b.nl();
                    b.append(frame::card(w, &problem, todo, Some(("r", "check again")))).nl();
                    page.key("r", "check again");
                    if !self.lines.is_empty() {
                        page.key("l", "the log");
                    }
                    page.key("esc", "back to the answers");
                } else {
                    page.key("esc", "stop the checks");
                }
                frame::section(b, "Before anything is erased", None);
                self.step_list(b, w, failed, None);
                let used = b.lines.len() + 2;
                if !self.lines.is_empty() {
                    frame::section(b, "Log", None);
                    self.tail(b, w, rows.saturating_sub(used).max(3), p.faint());
                }
            }
            State::Confirm => return Some(self.view_confirm(b, page, w)),
            State::Install => {
                let step = self.steps.iter().rev().find(|s| !s.done).map(|s| s.name.as_str()).unwrap_or("Getting ready");
                b.append(frame::progress(w, Some(self.install_pct()), step, self.since.elapsed())).nl();
                if self.stopping {
                    b.nl().add(Seg(format!("Stopping the install{}", theme::ellipsis()), p.text().add_modifier(Modifier::BOLD))).nl();
                }
                frame::section(b, "Steps", None);
                self.step_list(b, w, false, Some(install::INSTALL_STEPS));
                let used = b.lines.len() + 2;
                if !self.lines.is_empty() {
                    frame::section(b, "Log", None);
                    self.tail(b, w, rows.saturating_sub(used).max(3), p.faint());
                }
                if !self.stopping {
                    page.key("ctrl+c", "stop the install");
                }
                page.key("l", "the whole log");
            }
            State::Join => self.view_join(b, page, w),
            State::Done => self.view_done(b, page, w),
            State::Failed => self.view_failed(b, page, w, rows),
        }
        None
    }

    fn view_welcome(&self, b: &mut Doc, page: &mut Page, w: usize) {
        let p = theme::palette();
        let m = &self.m;
        let ip = &self.cfg.coord_lan_ip;
        // What stops the install comes first, with the key that fixes it.
        if !m.online {
            b.nl();
            b.append(frame::card(
                w,
                "This machine is not on the internet. The install downloads its packages.",
                "Connect it to WiFi, or plug in a network cable and look again (r).",
                Some(("enter", "connect to WiFi")),
            ))
            .nl();
        }
        if m.disks.is_empty() {
            b.nl();
            b.append(frame::card(
                w,
                "No disk to install on was found.",
                "If this laptop has one: in its BIOS setup, set the storage (SATA) mode from RAID or Intel RST to AHCI, and \
                 turn off VMD if it is listed. Then start it from the USB stick again.",
                Some(("r", "look again")),
            ))
            .nl();
        }
        frame::section(b, "This machine", None);
        let fact = |b: &mut Doc, mark: Mark, label: &str, value: String| {
            b.append(frame::row(w, mark, vec![col(Seg(label.into(), p.text()), 9), col(Seg(value, p.text()), 0)])).nl();
        };
        fact(b, Mark::Blank, "CPU", m.cpu.clone());
        fact(b, Mark::Blank, "Memory", human_size(m.ram));
        if m.uefi {
            fact(b, Mark::Done, "Firmware", "UEFI".into());
        } else {
            fact(b, Mark::Off, "Firmware", "legacy BIOS".into());
        }
        match (m.tpm2, m.tpm_chip, m.uefi) {
            (true, _, true) => fact(b, Mark::Done, "TPM 2.0", "yes: an encrypted disk can unlock itself".into()),
            (true, _, false) => fact(b, Mark::Off, "TPM 2.0", "yes, but unlocking by itself needs UEFI".into()),
            (false, true, _) => {
                fact(b, Mark::Off, "TPM 2.0", "a chip, but the firmware does not measure the boot (no unlocking by itself)".into())
            }
            _ => fact(b, Mark::Off, "TPM 2.0", "no".into()),
        }
        if m.online {
            fact(b, Mark::Done, "Network", m.net.clone());
        } else {
            fact(b, Mark::Bad, "Network", "not connected".into());
        }
        let role = match (self.ch.role, m.online, m.coord_found) {
            (Some(Role::Coordinator), ..) => "coordinator, as you chose".to_string(),
            (Some(Role::Node), ..) => "server, as you chose".to_string(),
            (None, true, true) => format!("server: a coordinator answers at {ip}"),
            (None, true, false) => format!("coordinator: nothing answers at {ip} yet, so this is the first machine"),
            (None, false, _) => "known once it is online".to_string(),
        };
        fact(b, Mark::Blank, "Role", role);
        frame::section(b, "Disks", Some(m.disks.len()));
        for d in &m.disks {
            b.append(frame::row(
                w,
                Mark::Blank,
                vec![
                    col(Seg(d.name.clone(), p.text()), 9),
                    col(Seg(human_size(d.size), p.text()), 9),
                    col(Seg(model(d), p.hint()), 24),
                    col(Seg(holds(d), p.hint()), 0),
                ],
            ))
            .nl();
        }
        if m.disks.is_empty() {
            b.add(Seg("None found. The card above says what to do.".into(), p.hint())).nl();
        }
        if !m.online {
            page.key("enter", "connect to WiFi");
        } else if !m.disks.is_empty() {
            b.nl();
            b.add(Seg("Next".into(), p.selected().add_modifier(Modifier::BOLD)))
                .s("  ")
                .add(Seg("Answer a few questions (enter). Nothing is erased until you type YES.".into(), p.text()))
                .nl();
            page.key("enter", "start");
        }
        if m.online {
            page.key("w", "other WiFi");
        }
        page.key("r", "look again").key("esc", "leave");
    }

    fn disk_by_path(&self, path: &str) -> Disk {
        self.m.disks.iter().find(|d| d.path == path).cloned().unwrap_or_else(|| Disk {
            path: path.into(),
            name: path.into(),
            ..Disk::default()
        })
    }

    /// The disks that are erased, what it becomes, then the YES field.
    fn view_confirm(&self, b: &mut Doc, page: &mut Page, w: usize) -> Focus {
        let p = theme::palette();
        let ch = &self.ch;
        let mut disks = vec![format!("  system  {}", disk_title(&self.disk_by_path(&ch.system_disk)))];
        for d in &ch.data_disks {
            disks.push(format!("  /data   {}", disk_title(&self.disk_by_path(d))));
        }
        b.nl();
        b.append(frame::card(w, "Everything on these disks is erased:", &disks.join("\n"), None)).nl();
        frame::section(b, "What it becomes", None);
        let role = if ch.role() == Role::Coordinator {
            "coordinator: the first machine, it approves the others"
        } else {
            "server: it joins the mesh once you approve it"
        };
        let mut tools = self.cfg.tool_list();
        tools.extend(self.cfg.extra_list());
        let tools = if tools.is_empty() { "the basics".to_string() } else { format!("the basics, {}", tools.join(" ")) };
        let rows = [
            ("Role", role.to_string()),
            ("Hostname", ch.hostname.clone()),
            ("Encryption", enc_title(ch.enc(), false)),
            ("User", format!("{}, password set", self.cfg.username)),
            ("Tools", tools),
        ];
        for (name, value) in rows {
            b.append(frame::row(w, Mark::Blank, vec![col(Seg(name.into(), p.text()), 10), col(Seg(value, p.text()), 0)])).nl();
        }
        let warn = role_warning(&self.m, &self.cfg, ch.role());
        if !warn.is_empty() {
            b.nl().add(theme::mark(Mark::Bad)).s("  ").add(Seg(warn.replace('\n', " "), p.text().add_modifier(Modifier::BOLD))).nl();
        }
        b.nl()
            .s("Type ")
            .add(Seg("YES".into(), p.selected().add_modifier(Modifier::BOLD)))
            .s(" and press enter to erase them and install.");
        b.nl();
        let at = b.lines.len() - 2;
        b.s("  ").append(self.confirm.view()).nl();
        page.key("enter", "erase and install").key("esc", "change answers");
        Focus::keep(at..at + 2)
    }

    fn view_join(&self, b: &mut Doc, page: &mut Page, w: usize) {
        let p = theme::palette();
        let ip = &self.cfg.coord_lan_ip;
        if let Some(again) = self.join.again {
            let why = self.join_err.as_ref().map(|e| e.to_string()).unwrap_or_default();
            let left = again.saturating_duration_since(Instant::now());
            let first = self.join.first.map(super::since).unwrap_or_default();
            let times = if self.join.tries == 1 { "once".to_string() } else { format!("{} times", self.join.tries) };
            b.nl();
            b.append(frame::card(
                w,
                &format!("The coordinator at {ip} did not let this machine in yet. {why}"),
                &format!(
                    "It asks again in {} (asked {times}, for {first}). Is the coordinator switched on, and on the same \
                     network as this machine?",
                    super::dur(left)
                ),
                Some(("r", "ask now")),
            ))
            .nl();
            page.key("r", "ask now").key("s", "skip");
            return;
        }
        if self.join.skipping {
            b.nl();
            busy_line(b, "Skipping: it asks again after it restarts", self.since);
            return;
        }
        if self.code.is_empty() {
            b.nl();
            busy_line(b, &format!("Asking the coordinator at {ip} to let this machine in"), self.since);
            b.add(hint("It waits for the coordinator's answer, and asks again if none comes.")).nl();
            page.key("s", "skip");
            return;
        }
        frame::section(b, "Approve it on your computer", None);
        b.add(Seg(
            format!(
                "Open dryserver there and go to Machines (4): this machine waits to join. Approve it (a) only if your \
                 computer shows the same code, {}:",
                self.code
            ),
            p.text(),
        ))
        .nl()
        .nl();
        code_view(b, &self.code, w);
        b.nl();
        busy_line(b, "Waiting for your approval", self.join.first.unwrap_or(self.since));
        b.add(hint(format!(
            "It asks the coordinator every {} seconds, and keeps asking while it does not answer. s skips: it then asks \
             again at every start until you approve it.",
            crate::node::JOIN_POLL.as_secs()
        )))
        .nl();
        page.key("s", "skip");
    }

    fn view_done(&self, b: &mut Doc, page: &mut Page, w: usize) {
        let p = theme::palette();
        let text = |b: &mut Doc, t: String| {
            b.add(Seg(t, p.text())).nl();
        };
        if self.ch.role() == Role::Coordinator {
            frame::section(b, "The coordinator is installed", None);
            if self.code.is_empty() {
                text(
                    b,
                    "After it restarts, its screen shows the code to sign it with. Sign it on your computer: open \
                         dryserver, go to Machines (4) and press s."
                        .into(),
                );
            } else {
                text(
                    b,
                    format!(
                        "After it restarts, sign it on your computer (dryserver, Machines, s), only if it shows the same \
                         code, {}:",
                        self.code
                    ),
                );
                b.nl();
                code_view(b, &self.code, w);
                b.nl();
                b.add(hint("Until you sign it no machine can join, and its screen shows this code.")).nl();
            }
        } else if self.host_num > 0 {
            frame::section(b, "The server is installed and approved", None);
            text(b, format!("It is in the mesh as {}.", mesh_ip(&self.cfg, self.host_num)));
        } else {
            frame::section(b, "The server is installed, and has not joined yet", None);
            let why = match &self.join_err {
                Some(e) if !self.join.skipping && !e.is_canceled() => format!("It could not join: {e}."),
                _ => "You skipped joining.".to_string(),
            };
            text(
                b,
                format!(
                    "{why} After it restarts it asks again by itself and shows its code on its screen; approve it on your \
                     computer then (dryserver, Machines)."
                ),
            );
        }
        if self.ch.enc() == Encryption::Tpm {
            if self.ch.role() != Role::Coordinator || self.code.is_empty() {
                b.nl();
            }
            text(b, "Type the disk passphrase once at the first start; then the TPM unlocks it.".into());
        }
        b.nl();
        b.add(Seg("Next".into(), p.selected().add_modifier(Modifier::BOLD)))
            .s("  ")
            .add(Seg("Take out the USB stick, then press enter to restart.".into(), p.text()))
            .nl();
        page.key("enter", "restart").key("esc", "stay in the live system");
    }

    fn view_failed(&self, b: &mut Doc, page: &mut Page, w: usize, rows: usize) {
        let p = theme::palette();
        let e = self.err.as_ref().map(|e| e.to_string()).unwrap_or_default();
        b.nl();
        match (self.failed_at, self.retry) {
            (1, _) => {
                b.append(frame::card(
                    w,
                    &format!("This machine could not be looked at: {e}"),
                    "Nothing was changed. r looks again.",
                    Some(("r", "look again")),
                ));
                page.key("r", "look again").key("esc", "leave");
            }
            (5, _) => {
                b.append(frame::card(
                    w,
                    &format!("{}.", capital(&e)),
                    "It is installed, but it is not a member and does not ask again. To try once more, leave to the shell \
                     and start over with: dryserver install",
                    Some(("esc", "leave to the shell")),
                ));
                page.key("esc", "leave to the shell");
            }
            (_, retry) => {
                let stopped = self.err.as_ref().is_some_and(|e| e.is_canceled());
                let problem = if stopped { "The install was stopped.".to_string() } else { format!("The install failed: {e}") };
                let can = retry == Retry::Install;
                let todo = match (stopped, can) {
                    (true, true) => "The disks are half-installed and do not start. r installs again with the same answers; \
                                     esc goes back to change them."
                        .to_string(),
                    (false, true) => format!(
                        "The disks are half-installed and do not start. Fix what it says if you can, then r tries again with \
                         the same answers; esc goes back to change them. The whole log is in {LOG_HINT}."
                    ),
                    _ => format!("The whole log is in {LOG_HINT}."),
                };
                b.append(frame::card(w, &problem, &todo, can.then_some(("r", "try again"))));
                if can {
                    page.key("r", "try again");
                }
                if !self.lines.is_empty() {
                    page.key("l", "the whole log");
                }
                if can {
                    page.key("esc", "change the answers");
                } else {
                    page.key("esc", "leave to the shell");
                }
                if !self.lines.is_empty() {
                    let used = b.lines.len() + 3;
                    frame::section(b, "The last lines of the log", None);
                    self.tail(b, w, rows.saturating_sub(used).max(3), p.faint());
                }
            }
        }
        b.nl();
    }

    /// Every line kept, for reading the whole of what went on.
    fn view_log(&self, b: &mut Doc, page: &mut Page, w: usize) {
        let p = theme::palette();
        frame::section(b, "The log", Some(self.lines.len()));
        b.add(hint(format!("The last {KEEP_LINES} lines at most. The whole log is in {LOG_HINT}."))).nl().nl();
        self.tail(b, w, self.lines.len(), p.text());
        page.keys.clear();
        page.key("pgup pgdn", "scroll").key("esc", "back");
    }

    /// The steps so far: done with their time, the one that runs with the
    /// spinner, the one that failed marked. Of total, the ones to come.
    fn step_list(&self, b: &mut Doc, w: usize, failed: bool, total: Option<usize>) {
        let p = theme::palette();
        let name_w = w.saturating_sub(16).min(44);
        for (i, st) in self.steps.iter().enumerate() {
            let last = i + 1 == self.steps.len();
            let (mark, time) = if st.done {
                (Mark::Done, super::dur(st.took))
            } else if last && failed {
                (Mark::Bad, String::new())
            } else {
                (Mark::Blank, super::since(st.start))
            };
            let mut r = frame::row(w, mark, vec![col(Seg(st.name.clone(), p.text()), name_w), col(Seg(time, p.hint()), 0)]);
            if mark == Mark::Blank
                && let Some(first) = r.lines.first_mut().and_then(|l| l.first_mut())
            {
                *first = Seg(spinner().into(), p.selected());
            }
            b.append(r).nl();
        }
        if let Some(n) = total
            && self.steps.len() < n
        {
            let more = n - self.steps.len();
            let s = if more == 1 { "1 more step".to_string() } else { format!("{more} more steps") };
            b.add(theme::mark(Mark::Off)).s("  ").add(Seg(s, p.faint())).nl();
        }
        if self.steps.is_empty() && total.is_none() {
            busy_line(b, "Getting ready", self.since);
        }
    }

    /// The last n lines of the log, each cut to the body.
    fn tail(&self, b: &mut Doc, w: usize, n: usize, style: Style) {
        for l in &self.lines[self.lines.len().saturating_sub(n)..] {
            b.add(Seg(super::fit(&printable(l), w.saturating_sub(2)), style)).nl();
        }
    }

    fn help_text(&self) -> Help {
        let k = |a: &str, b: &str| (a.to_string(), b.to_string());
        let (about, mut keys) = match self.state {
            State::Probe | State::Welcome | State::Busy | State::Wifi => (
                "The installer turns this machine into one of your servers. It looks at the machine first, then asks a few \
                 questions and checks what it can. It erases and installs only after you type YES."
                    .to_string(),
                vec![
                    k("enter", "start; without a network, connect to WiFi"),
                    k("w", "connect to another WiFi"),
                    k("r", "look at the machine again"),
                    k("esc", "leave the installer (asks first)"),
                ],
            ),
            State::Form => (
                "The answers decide what this machine becomes. Nothing is erased yet: after the checks, the next step shows \
                 every answer and erases only once you type YES."
                    .to_string(),
                vec![
                    k("enter", "next question"),
                    k("shift+tab", "previous field"),
                    k("up down", "choose in a list"),
                    k("space", "tick a disk for data"),
                    k("esc", "back one question; on the first, back to the machine"),
                ],
            ),
            State::Check => (
                "The checks run before anything is erased: the firewall the config makes, the clock, the package signing \
                 keys, the mirrors and the package lists, and for a server whether the coordinator answers."
                    .to_string(),
                vec![k("esc", "stop the checks; once failed, back to the answers"), k("r", "check again"), k("l", "the log")],
            ),
            State::Confirm => (
                "The last step before the disks are erased. Type YES in capital letters and press enter.".to_string(),
                vec![k("enter", "erase and install"), k("esc", "change the answers")],
            ),
            State::Install => (
                "The install erases the disks and writes the new system. It takes a few minutes, most of them for downloading \
                 the packages."
                    .to_string(),
                vec![k("l", "the whole log"), k("ctrl+c", "stop the install (asks first)")],
            ),
            State::Join => (
                "The server asks the coordinator to let it in. On your computer, open dryserver, go to Machines (4), and \
                 approve it if it shows the same code. Skipped, it asks again at every start until you approve it."
                    .to_string(),
                vec![k("s", "skip"), k("r", "ask now, after the coordinator did not answer")],
            ),
            State::Done => (
                "The installer is finished. Take out the USB stick and restart: the machine starts the system it installed.".to_string(),
                vec![k("enter", "restart"), k("esc", "stay in the live system")],
            ),
            State::Failed => (
                format!("Something went wrong; the card says what and what to do. The whole log is in {LOG_HINT}."),
                vec![k("r", "try again, when the card offers it"), k("l", "the log"), k("esc", "back, or leave")],
            ),
        };
        keys.push(k("pgup pgdn", "scroll"));
        keys.push(k("ctrl+c", "leave the installer (stops what runs)"));
        Help { about, keys }
    }
}

impl Model for Setup {
    type Msg = Tagged;

    fn init(&mut self, emit: &Emit<Tagged>) {
        self.start_probe(emit);
    }

    fn update(&mut self, ev: Event<Tagged>, emit: &Emit<Tagged>) -> Flow {
        self.handle(ev, emit)
    }

    fn view(&self) -> Doc {
        frame::draw_any(&self.page(), &self.scroll, self.w, self.h)
    }
}

/// A form's keys with esc before shift+tab, the least used: a footer too
/// narrow for all drops shift+tab, never the way back.
fn form_keys(page: &mut Page, keys: Vec<(String, String)>, esc: &str) {
    let (prev, rest): (Vec<_>, Vec<_>) = keys.into_iter().partition(|(k, _)| k == "shift+tab");
    page.keys = rest;
    page.key("esc", esc);
    page.keys.extend(prev);
}

/// Appends d to b, where b's last line is empty; the focus moves with it.
fn put(b: &mut Doc, d: Doc, focus: Option<Range<usize>>) -> Option<Range<usize>> {
    let at = b.lines.len() - 1;
    b.append(d);
    focus.map(|r| r.start + at..r.end + at)
}

fn hint(t: impl Into<String>) -> Seg {
    Seg(t.into(), theme::palette().hint())
}

/// The spinner, what runs and how long it has.
fn busy_line(b: &mut Doc, what: &str, since: Instant) {
    let p = theme::palette();
    b.add(Seg(spinner().into(), p.selected()))
        .s("  ")
        .add(Seg(what.into(), p.text().add_modifier(Modifier::BOLD)))
        .add(Seg(format!("   {}", super::since(since)), p.hint()))
        .nl();
}

/// A log line the screen can show: no control characters, and on the
/// console only the glyphs its font has.
fn printable(l: &str) -> String {
    let console = theme::palette().console;
    l.chars().map(|c| if c.is_control() || (console && !c.is_ascii() && !CP437.contains(c)) { '?' } else { c }).collect()
}

/// The glyphs of code page 437 above ASCII, which the console font has.
const CP437: &str =
    "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■•";

fn capital(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// The digits of a 3 × 5 pixel font, '#' lit.
const DIGITS: [[&str; 5]; 10] = [
    ["###", "#.#", "#.#", "#.#", "###"],
    [".#.", "##.", ".#.", ".#.", "###"],
    ["###", "..#", "###", "#..", "###"],
    ["###", "..#", ".##", "..#", "###"],
    ["#.#", "#.#", "###", "..#", "..#"],
    ["###", "#..", "###", "..#", "###"],
    ["###", "#..", "###", "#.#", "###"],
    ["###", "..#", "..#", ".#.", ".#."],
    ["###", "#.#", "###", "#.#", "###"],
    ["###", "#.#", "###", "..#", "###"],
];

/// The code in large digits, to read from a step away: each pixel of the
/// font is two cells of █, square on the screen; the digits are two cells
/// apart and the groups six. None when the code has other characters or
/// does not fit in width.
fn big_code(code: &str, width: usize) -> Option<Doc> {
    if !code.chars().any(|c| c.is_ascii_digit()) || !code.chars().all(|c| c.is_ascii_digit() || c == ' ') {
        return None;
    }
    let mut rows = vec![String::new(); 5];
    let mut first = true;
    for c in code.trim().chars() {
        if c == ' ' {
            for r in rows.iter_mut() {
                r.push_str("    ");
            }
            continue;
        }
        if !first {
            for r in rows.iter_mut() {
                r.push_str("  ");
            }
        }
        first = false;
        let d = DIGITS[c as usize - '0' as usize];
        for (r, bits) in rows.iter_mut().zip(d) {
            for bit in bits.chars() {
                r.push_str(if bit == '#' { "██" } else { "  " });
            }
        }
    }
    if rows[0].chars().count() + 2 > width {
        return None;
    }
    let p = theme::palette();
    let mut d = Doc::new();
    for (i, r) in rows.iter().enumerate() {
        if i > 0 {
            d.nl();
        }
        d.s("  ").add(Seg(r.trim_end().to_string(), p.selected()));
    }
    Some(d)
}

/// The code in large digits where they fit, else in bold.
fn code_view(b: &mut Doc, code: &str, w: usize) {
    match big_code(code, w) {
        Some(d) => {
            b.append(d);
            b.nl();
        }
        None => {
            b.s("  ").add(Seg(code.into(), theme::palette().selected().add_modifier(Modifier::BOLD))).nl();
        }
    }
}

/// How far the downloads are, from the installer's log line "downloaded
/// 120.3 MiB of 758.70 MiB": (done, total) in MiB.
fn downloaded(line: &str) -> Option<(f64, f64)> {
    let (got, total) = line.strip_prefix("downloaded ")?.split_once(" of ")?;
    let mib = |s: &str| -> Option<f64> {
        let mut it = s.split_whitespace();
        let n: f64 = it.next()?.parse().ok()?;
        let f = match it.next()? {
            "B" => 1.0 / 1048576.0,
            "KiB" => 1.0 / 1024.0,
            "MiB" => 1.0,
            "GiB" => 1024.0,
            "TiB" => 1048576.0,
            _ => return None,
        };
        Some(n * f)
    };
    Some((mib(got)?, mib(total)?))
}

/// The disk's maker and model.
fn model(d: &Disk) -> String {
    format!("{} {}", d.vendor, d.model).trim().to_string()
}

/// What is on a disk, in a few words.
fn holds(d: &Disk) -> String {
    let has = parts_named(d);
    match (has.is_empty(), d.parts.len()) {
        (false, _) => format!("has {}", has.join(", ")),
        (true, 0) => "no partitions".into(),
        (true, 1) => "1 partition".into(),
        (true, n) => format!("{n} partitions"),
    }
}

/// The labels, or else the filesystems, of a disk's partitions.
fn parts_named(d: &Disk) -> Vec<&str> {
    d.parts
        .iter()
        .filter_map(|p| {
            if !p.label.is_empty() {
                Some(p.label.as_str())
            } else if !p.fstype.is_empty() {
                Some(p.fstype.as_str())
            } else {
                None
            }
        })
        .collect()
}

/// Explains the role question with what the network says.
fn role_note(m: &Machine, cfg: &Config) -> String {
    let ip = &cfg.coord_lan_ip;
    if m.coord_found {
        return format!("A coordinator answers at {ip}, so this laptop is most likely a server.");
    }
    format!(
        "No coordinator answers at {ip}. If this is your first laptop, choose\ncoordinator. If you already installed one, check it is on and its IP is\nreserved in the router, then choose server."
    )
}

/// Flags a role that does not match the network.
fn role_warning(m: &Machine, cfg: &Config, role: Role) -> String {
    let ip = &cfg.coord_lan_ip;
    match role {
        Role::Node if !m.coord_found => {
            format!("No coordinator answers at {ip}. If this is your first laptop,\npress esc and choose coordinator.")
        }
        Role::Coordinator if m.coord_found => {
            format!(
                "A coordinator already answers at {ip}. A second one would start a\nseparate mesh. Press esc and choose server unless you replace it."
            )
        }
        _ => String::new(),
    }
}

fn enc_title(e: Encryption, recommended: bool) -> String {
    let t = match e {
        Encryption::Tpm => "Encrypted, unlocks itself with the TPM chip",
        Encryption::Passphrase => "Encrypted, type passphrase at every boot",
        Encryption::None => "Not encrypted",
    };
    if recommended { format!("{t} (recommended)") } else { t.to_string() }
}

fn disk_title(d: &Disk) -> String {
    let has = parts_named(d);
    let mut t = format!("{}  {}  {}", d.name, human_size(d.size), model(d));
    if !has.is_empty() {
        t += &format!("  (has: {})", has.join(", "));
    }
    t
}

/// A disk in the form's list, on one line of the console: the model and
/// what it holds cut to fit. The erase card shows it whole.
fn disk_option(d: &Disk) -> String {
    let has = parts_named(d);
    let mut t = format!("{}  {}  {}", d.name, human_size(d.size), super::fit(&model(d), 28));
    if !has.is_empty() {
        t += &format!("  ({})", super::fit(&format!("has: {}", has.join(", ")), 22));
    }
    t
}

fn setup_form(m: &Machine, cfg: &Config, answers: Answers) -> Form<Answers> {
    // Made when drawn: the cut's ellipsis is the tier's.
    let disks = m.disks.clone();
    let disk_opts = move |_: &Answers| -> Vec<(String, String)> { disks.iter().map(|d| (disk_option(d), d.path.clone())).collect() };
    let all_disks = disk_opts.clone();
    let enc_opts: Vec<(String, String)> =
        m.encryption_options().iter().enumerate().map(|(i, e)| (enc_title(*e, i == 0), e.as_str().to_string())).collect();
    let enc_note = if m.tpm2 && m.uefi {
        "TPM 2.0 chip found: the server can reboot on its own and the\ndisk stays unreadable if taken out. Choose \"every boot\" for a\nlaptop that may leave the house."
    } else {
        "No TPM 2.0 chip (or legacy BIOS): an encrypted disk needs the\npassphrase typed at every boot."
    };
    let few_disks = m.disks.len() < 2;
    let roles = vec![
        ("Coordinator: the first machine, approves the others".to_string(), "coordinator".to_string()),
        ("Server: joins the mesh after your approval".to_string(), "node".to_string()),
    ];

    Form::new(
        answers,
        vec![
            Group::new(vec![
                Field::select(
                    "What is this machine?",
                    move |_| roles.clone(),
                    |a: &Answers| a.ch.role().as_str().to_string(),
                    |a, v| a.ch.role = Role::parse(&v),
                )
                .desc(&role_note(m, cfg)),
            ]),
            Group::new(vec![
                Field::input("Hostname", |a: &Answers| a.ch.hostname.clone(), |a, v| a.ch.hostname = v)
                    .desc_fn(|a| {
                        if a.ch.role() == Role::Coordinator {
                            "Leave empty for: coord".into()
                        } else {
                            "Leave empty for a random name like node-3a2f".into()
                        }
                    })
                    .validate(|v, _| install::valid_hostname(v)),
            ]),
            Group::new(vec![
                Field::select("Install on which disk?", disk_opts, |a: &Answers| a.ch.system_disk.clone(), |a, v| a.ch.system_disk = v)
                    .desc("Everything on this disk will be erased."),
            ]),
            Group::new(vec![
                Field::multi(
                    "Also use these disks for data? (optional)",
                    move |a: &Answers| all_disks(a).into_iter().filter(|(_, p)| *p != a.ch.system_disk).collect(),
                    |a: &Answers| a.ch.data_disks.clone(),
                    |a, v| a.ch.data_disks = v,
                )
                .desc("Erased, encrypted like the system disk and mounted at /data."),
            ])
            .hide_if(move |_| few_disks),
            Group::new(vec![
                Field::note("Disk encryption", enc_note),
                Field::select(
                    "",
                    move |_| enc_opts.clone(),
                    |a: &Answers| a.ch.enc().as_str().to_string(),
                    |a, v| a.ch.encryption = Encryption::parse(&v),
                ),
            ]),
            Group::new(vec![
                Field::input("Disk passphrase", |a: &Answers| a.ch.disk_passphrase.clone(), |a, v| a.ch.disk_passphrase = v)
                    .desc(&format!(
                        "At least {} characters. Keep it safe: it is the only way in if the TPM\nor boot files change.",
                        install::MIN_DISK_PASSPHRASE
                    ))
                    .password()
                    .validate(|v, _| install::valid_disk_passphrase(v)),
                Field::input("Disk passphrase again", |a: &Answers| a.disk_confirm.clone(), |a, v| a.disk_confirm = v)
                    .password()
                    .validate(|v, a| if v != a.ch.disk_passphrase { Err("does not match".into()) } else { Ok(()) }),
            ])
            .hide_if(|a| a.ch.enc() == Encryption::None),
            Group::new(vec![
                Field::input(
                    &format!("Password for {}", cfg.username),
                    |a: &Answers| a.ch.user_password.clone(),
                    |a, v| a.ch.user_password = v,
                )
                .desc(&format!(
                    "For console login and sudo (at least {} characters).\nSSH login uses your key, never this password.",
                    install::MIN_USER_PASSWORD
                ))
                .password()
                .validate(|v, _| install::valid_user_password(v)),
                Field::input("Password again", |a: &Answers| a.user_confirm.clone(), |a, v| a.user_confirm = v)
                    .password()
                    .validate(|v, a| if v != a.ch.user_password { Err("does not match".into()) } else { Ok(()) }),
            ]),
        ],
        "back",
    )
    // The confirm step after the checks shows every answer, and the
    // screen keeps them when the form is left.
    .without_review()
    .keeps_answers()
}

fn mesh_ip(cfg: &Config, n: u32) -> String {
    match sysconf::host_addr(&cfg.wg_subnet, n) {
        Ok(a) => a.split('/').next().unwrap_or("").to_string(),
        Err(_) => format!("host {n}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disks::Part;
    use crate::tui::frame::tests::rows;
    use crate::tui::{collector, type_text};
    use ratatui::style::Color;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::Receiver;
    use unicode_width::UnicodeWidthStr;

    struct T {
        s: Setup,
        emit: Emit<Tagged>,
        rx: Receiver<Tagged>,
    }

    impl T {
        fn send(&mut self, ev: Event<Tagged>) -> Flow {
            self.s.handle(ev, &self.emit)
        }

        /// A message from the job on screen.
        fn msg(&mut self, m: Msg) {
            let n = self.s.job;
            self.send(Event::Msg(Tagged(n, m)));
        }

        fn keys(&mut self, keys: impl IntoIterator<Item = Key>) -> Flow {
            for k in keys {
                if self.send(Event::Key(k)) == Flow::Quit {
                    return Flow::Quit;
                }
            }
            Flow::Continue
        }

        /// Feeds background answers into the model while it waits.
        fn drain(&mut self, while_in: &[State]) {
            while while_in.contains(&self.s.state) {
                let m = self.rx.recv_timeout(Duration::from_secs(10)).expect("background job never finished");
                self.send(Event::Msg(m));
            }
        }

        /// The next background answer, fed in.
        fn next(&mut self) {
            let m = self.rx.recv_timeout(Duration::from_secs(10)).expect("no answer");
            self.send(Event::Msg(m));
        }

        /// The screen in a tier at a size, one string per row.
        fn screen(&mut self, tier: Tier, console: bool, w: u16, h: u16) -> Vec<String> {
            let _g = theme::force(tier, console);
            self.send(Event::Resize(w, h));
            rows(&self.s.view())
        }

        /// The words of the screen at 120 × 50 without colours (the keys
        /// in brackets), joined by single spaces: a wrapped sentence reads
        /// whole.
        fn words(&mut self) -> String {
            self.screen(Tier::Plain, false, 120, 50).join(" ").split_whitespace().collect::<Vec<_>>().join(" ")
        }

        /// Feeds the checks' answers in until they passed or failed.
        fn drain_check(&mut self) {
            while self.s.state == State::Check && self.s.check_err.is_none() {
                self.next();
            }
        }

        fn has(&mut self, want: &[&str]) {
            let v = self.words();
            for w in want {
                assert!(v.contains(w), "missing {w:?} in:\n{v}");
            }
        }
    }

    fn ago(secs: u64) -> Instant {
        Instant::now().checked_sub(Duration::from_secs(secs)).unwrap_or_else(Instant::now)
    }

    fn demo(f: impl FnOnce(&mut install::Demo)) -> Arc<install::Demo> {
        let mut d = install::Demo::new();
        d.delay = Duration::ZERO;
        f(&mut d);
        Arc::new(d)
    }

    fn setup(d: Arc<install::Demo>) -> T {
        let cfg = Config { coord_lan_ip: "192.168.1.50".into(), ..Config::default() };
        let m = d.machine.lock().unwrap().clone();
        let (emit, rx) = collector();
        let mut t = T { s: Setup::new(d, cfg), emit, rx };
        t.send(Event::Resize(120, 50));
        t.msg(Msg::Probe(Ok(m)));
        t
    }

    fn demo_setup(role: Role, enc: Encryption, d: Arc<install::Demo>) -> T {
        let mut t = setup(d);
        t.s.ch = Choices {
            role: Some(role),
            hostname: "node-test".into(),
            system_disk: "/dev/nvme0n1".into(),
            encryption: Some(enc),
            disk_passphrase: "a long passphrase".into(),
            user_password: "longpassword".into(),
            ..Choices::default()
        };
        t
    }

    fn many_disks() -> Vec<Disk> {
        (0..7u8)
            .map(|i| {
                let name = format!("sd{}", (b'a' + i) as char);
                Disk {
                    path: format!("/dev/{name}"),
                    name,
                    size: 1_000_204_886_016 * (i as u64 + 1),
                    vendor: "ATA".into(),
                    model: "Samsung SSD 870 EVO 1TB with a model name that goes on and on".into(),
                    tran: "sata".into(),
                    parts: if i % 2 == 0 {
                        vec![Part { path: String::new(), size: 1, fstype: "ext4".into(), label: "old backups".into(), mountpoints: vec![] }]
                    } else {
                        vec![]
                    },
                    ..Disk::default()
                }
            })
            .collect()
    }

    /// Lines of a log, as the install sends them.
    fn log(t: &mut T, lines: &[&str]) {
        for l in lines {
            t.msg(Msg::Step(Step::line(*l)));
        }
    }

    fn steps(t: &mut T, done: &[&str], running: Option<&str>) {
        for name in done {
            t.msg(Msg::Step(Step::start(name)));
            t.msg(Msg::Step(Step::finished(name)));
        }
        for (i, s) in t.s.steps.iter_mut().enumerate() {
            s.took = Duration::from_secs(3 + 7 * i as u64);
        }
        if let Some(name) = running {
            t.msg(Msg::Step(Step::start(name)));
            if let Some(s) = t.s.steps.last_mut() {
                s.start = ago(48);
            }
        }
    }

    const INSTALL_LOG: [&str; 6] = [
        ":: Synchronizing package databases...",
        "resolving dependencies...",
        "looking for conflicting packages...",
        "Total Download Size:   758.70 MiB",
        "downloaded 214.6 MiB of 758.70 MiB",
        "downloaded 312.4 MiB of 758.70 MiB",
    ];

    /// Every screen of the installer, by name.
    fn fixtures() -> Vec<(&'static str, T)> {
        let mut out = Vec::new();
        let (emit, rx) = collector();
        let mut t = T { s: Setup::new(demo(|_| {}), Config { coord_lan_ip: "192.168.1.50".into(), ..Config::default() }), emit, rx };
        t.s.since = ago(3);
        out.push(("01-probe", t));
        let mut t = setup(demo(|_| {}));
        t.s.ch.role = None;
        out.push(("02-welcome", t));
        let mut t = setup(demo(|d| {
            let m = d.machine.get_mut().unwrap();
            m.online = false;
            m.net.clear();
        }));
        t.s.ch.role = None;
        out.push(("03-welcome-offline", t));
        out.push(("04-welcome-no-disk", setup(demo(|d| d.machine.get_mut().unwrap().disks.clear()))));
        out.push(("05-welcome-many-disks", setup(demo(|d| d.machine.get_mut().unwrap().disks = many_disks()))));
        let mut t = setup(demo(|_| {}));
        t.s.state = State::Busy;
        t.s.since = ago(2);
        out.push(("06-wifi-scan", t));
        let mut t = setup(demo(|_| {}));
        t.s.ssids = vec!["Home".into(), "Neighbor 5G".into(), "CoffeeShop".into()];
        t.s.open_wifi_form();
        out.push(("07-wifi-form", t));
        let mut t = setup(demo(|_| {}));
        t.s.ssids = vec!["Home".into(), "Neighbor 5G".into()];
        t.s.wifi_ssid = "Home".into();
        t.s.state = State::Busy;
        t.s.busy = Busy::Connect("Home".into());
        t.msg(Msg::WifiConnected(Err("wrong password or network out of range".into())));
        out.push(("08-wifi-wrong-password", t));
        let mut t = setup(demo(|_| {}));
        t.s.open_form();
        out.push(("09-form-role", t));
        let mut t = setup(demo(|d| d.machine.get_mut().unwrap().disks = many_disks()));
        t.s.open_form();
        t.keys([Key::Enter, Key::Enter]);
        out.push(("10-form-disk-many", t));
        let mut t = setup(demo(|_| {}));
        t.s.open_form();
        t.keys([Key::Enter, Key::Enter, Key::Enter, Key::Enter, Key::Enter]);
        t.keys(type_text("short"));
        t.keys([Key::Enter]);
        out.push(("11-form-passphrase", t));
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        t.s.state = State::Check;
        steps(&mut t, &["Check the firewall", "Check the clock"], Some("Prepare package signing keys"));
        log(&mut t, &["==> Initializing the keyring", "gpg: /etc/pacman.d/gnupg/trustdb.gpg: trustdb created"]);
        out.push(("12-checks", t));
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        t.s.state = State::Check;
        steps(
            &mut t,
            &["Check the firewall", "Check the clock", "Prepare package signing keys", "Pick package mirrors"],
            Some("Update package lists"),
        );
        log(
            &mut t,
            &[
                ":: Synchronizing package databases...",
                "error: failed retrieving file 'core.db' from geo.mirror.pkgbuild.com : Could not resolve host",
            ],
        );
        t.msg(Msg::CheckDone(Some("Update package lists: cannot reach the package mirrors: exit status 1".into())));
        out.push(("13-checks-failed", t));
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        t.s.ch.data_disks = vec!["/dev/sda".into()];
        t.msg(Msg::CheckDone(None));
        t.keys(type_text("YE"));
        out.push(("14-confirm", t));
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        t.s.m.coord_found = false;
        t.msg(Msg::CheckDone(None));
        t.keys(type_text("yes"));
        t.keys([Key::Enter]);
        out.push(("15-confirm-wrong", t));
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        t.s.state = State::Install;
        t.s.since = ago(95);
        steps(&mut t, &["Partition disks", "Set up encryption and filesystems"], Some("Install packages (takes a while)"));
        log(&mut t, &INSTALL_LOG);
        out.push(("16-install", t));
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        t.s.state = State::Install;
        t.s.since = ago(95);
        steps(&mut t, &["Partition disks", "Set up encryption and filesystems"], Some("Install packages (takes a while)"));
        log(&mut t, &INSTALL_LOG);
        t.keys([Key::Ctrl('c')]);
        out.push(("17-install-ctrl-c", t));
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        t.s.state = State::Install;
        steps(&mut t, &["Partition disks", "Set up encryption and filesystems"], Some("Install packages (takes a while)"));
        log(&mut t, &INSTALL_LOG);
        log(
            &mut t,
            &["error: failed retrieving file 'linux-6.18.1.arch1-1-x86_64.pkg.tar.zst'", "waiting for the network (attempt 3 of 3)"],
        );
        t.msg(Msg::InstallDone(Some("Install packages (takes a while): downloads failed (attempt 3 of 3)".into())));
        out.push(("18-install-failed", t));
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        t.s.state = State::Install;
        steps(&mut t, &["Partition disks"], Some("Set up encryption and filesystems"));
        t.msg(Msg::InstallDone(Some(Error::canceled())));
        out.push(("19-install-stopped", t));
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        t.s.state = State::Join;
        t.s.since = ago(4);
        t.s.join.first = Some(ago(4));
        out.push(("20-join-asking", t));
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        t.s.state = State::Join;
        t.s.join.first = Some(ago(83));
        t.s.code = "482 913".into();
        out.push(("21-join-code", t));
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        t.s.state = State::Join;
        t.s.join.first = Some(ago(65));
        t.msg(Msg::JoinDone(Err(
            "request: cannot reach the coordinator at 192.168.1.50 (is it installed and switched on?): ssh: connect to host \
             192.168.1.50 port 22: No route to host"
                .into(),
        )));
        t.s.join.tries = 2;
        out.push(("22-join-unreachable", t));
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        t.s.host_num = 7;
        t.s.state = State::Done;
        out.push(("23-done-server", t));
        let mut t = demo_setup(Role::Coordinator, Encryption::Tpm, demo(|_| {}));
        t.s.code = "305 771".into();
        t.s.state = State::Done;
        out.push(("24-done-coordinator", t));
        let mut t = demo_setup(Role::Node, Encryption::Passphrase, demo(|_| {}));
        t.s.join.skipping = true;
        t.s.join_err = Some(Error::canceled());
        t.s.state = State::Done;
        out.push(("25-done-not-joined", t));
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        t.msg(Msg::JoinDone(Err(Error::with_kind(Kind::Rejected, install::REJECTED))));
        out.push(("26-rejected", t));
        let mut t = setup(demo(|_| {}));
        t.msg(Msg::Probe(Err("lsblk: exit status 32".into())));
        out.push(("27-probe-failed", t));
        let mut t = setup(demo(|_| {}));
        t.keys([Key::Esc]);
        out.push(("28-leave", t));
        let mut t = setup(demo(|_| {}));
        t.keys([Key::Char('?')]);
        out.push(("29-help", t));
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        t.s.state = State::Install;
        log(&mut t, &INSTALL_LOG);
        t.msg(Msg::InstallDone(Some("Install packages: downloads failed".into())));
        t.keys([Key::Char('l')]);
        out.push(("30-log", t));
        out
    }

    #[test]
    fn welcome_shows_machine() {
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        t.has(&[
            "dryserver Install",
            "Step 1 of 5",
            "This machine",
            "TPM 2.0 yes: an encrypted disk can unlock itself",
            "Firmware UEFI",
            "nvme0n1",
            "has vfat, Windows",
            "WiFi Home",
            "Disks 2",
            "Role server, as you chose",
            "Next Answer a few questions (enter). Nothing is erased until you type YES.",
            "[enter] start",
        ]);
        // Before the form, the role comes from the network.
        t.s.ch.role = None;
        t.has(&["Role server: a coordinator answers at 192.168.1.50"]);
        t.s.m.coord_found = false;
        t.has(&["coordinator: nothing answers at 192.168.1.50 yet, so this is the first machine"]);
    }

    #[test]
    fn check_shows_steps_then_confirm() {
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        let emit = t.emit.clone();
        t.s.start_check(&emit);
        t.has(&["Step 3 of 5", "nothing is erased yet", "[esc] stop the checks"]);
        t.drain(&[State::Check]);
        assert_eq!(t.s.state, State::Confirm, "err {:?}", t.s.check_err);
        assert!(t.s.steps.is_empty() && t.s.lines.is_empty(), "check log must be cleared before the install screen");
    }

    #[test]
    fn check_failure_offers_retry() {
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        t.s.state = State::Check;
        t.msg(Msg::Step(Step::start("Update package lists")));
        t.msg(Msg::Step(Step::line("error: failed retrieving file")));
        t.msg(Msg::CheckDone(Some("cannot reach the package mirrors".into())));
        t.has(&[
            "Update package lists",
            "failed retrieving file",
            "A check failed: cannot reach the package mirrors",
            "Nothing was erased",
            "[r] check again",
        ]);
        // r checks again; enter (or esc) goes back to the answers.
        t.keys([Key::Char('r')]);
        assert!(t.s.state == State::Check && t.s.check_err.is_none());
        t.drain_check();
        assert_eq!(t.s.state, State::Confirm, "checked again, and passed");
        t.s.state = State::Check;
        t.s.check_err = Some("cannot reach the package mirrors".into());
        t.keys([Key::Enter]);
        assert!(
            t.s.state == State::Form && t.s.notice.as_ref().is_some_and(|n| n.text.contains("cannot reach")),
            "enter must go back to the answers: {:?} {:?}",
            t.s.state,
            t.s.notice
        );
    }

    #[test]
    fn stopping_the_checks_erases_nothing() {
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|d| d.delay = Duration::from_secs(30)));
        let emit = t.emit.clone();
        t.s.start_check(&emit);
        t.keys([Key::Esc]);
        assert!(t.s.ctx.done(), "esc stops the checks");
        t.drain_check();
        assert_eq!(t.s.state, State::Check, "stopped, the checks stay on screen");
        t.has(&["The checks were stopped. Nothing was erased.", "[r] check again"]);
        t.keys([Key::Esc]);
        assert_eq!(t.s.state, State::Form);
        assert!(t.s.notice.as_ref().unwrap().text.contains("stopped"));
    }

    #[test]
    fn confirm_needs_yes() {
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        t.s.ch.data_disks = vec!["/dev/sda".into()];
        t.msg(Msg::CheckDone(None));
        assert_eq!(t.s.state, State::Confirm);
        t.has(&[
            "Step 4 of 5",
            "Everything on these disks is erased:",
            "system nvme0n1 256.1 GB SAMSUNG MZVLW256 (has: vfat, Windows)",
            "/data sda 500.1 GB ST500LM021",
            "Type YES and press enter to erase them and install.",
            "[enter] erase and install",
            "[esc] change answers",
        ]);
        t.keys(type_text("yes"));
        t.keys([Key::Enter]);
        assert!(t.s.state == State::Confirm && t.s.notice.is_some(), "lowercase yes must not start the install");
        t.s.confirm.set_value("");
        // A paste is not typing: YES has to be typed.
        t.keys([Key::Paste("YES".into()), Key::Enter]);
        assert!(t.s.state == State::Confirm && t.s.confirm.value.is_empty(), "a paste must not fill the YES field");
        t.keys(type_text("YESS"));
        t.keys([Key::Enter]);
        assert_eq!(t.s.state, State::Confirm, "only YES");
        t.s.confirm.set_value("");
        t.keys(type_text("YES"));
        t.keys([Key::Enter]);
        assert_eq!(t.s.state, State::Install);
        t.s.ctx.cancel();
    }

    #[test]
    fn nothing_erases_before_yes() {
        /// Counts the calls that write to a disk.
        struct Watch(Arc<install::Demo>, AtomicUsize);
        impl Backend for Watch {
            fn probe(&self, ctx: &Ctx) -> Result<Machine> {
                self.0.probe(ctx)
            }
            fn scan_wifi(&self, ctx: &Ctx) -> Result<Vec<String>> {
                self.0.scan_wifi(ctx)
            }
            fn connect_wifi(&self, ctx: &Ctx, s: &str, p: &str) -> Result<Machine> {
                self.0.connect_wifi(ctx, s, p)
            }
            fn precheck(&self, ctx: &Ctx, cfg: &Config, ch: &Choices, progress: install::Progress) -> Result<()> {
                self.0.precheck(ctx, cfg, ch, progress)
            }
            fn install(&self, ctx: &Ctx, cfg: &Config, ch: &Choices, progress: install::Progress) -> Result<()> {
                self.1.fetch_add(1, Ordering::SeqCst);
                self.0.install(ctx, cfg, ch, progress)
            }
            fn join(&self, ctx: &Ctx, cfg: &Config, ch: &Choices, code: &(dyn Fn(String) + Send + Sync)) -> Result<u32> {
                self.0.join(ctx, cfg, ch, code)
            }
            fn coordinator_code(&self) -> String {
                self.0.coordinator_code()
            }
            fn reboot(&self) -> Result<()> {
                self.0.reboot()
            }
        }
        let w = Arc::new(Watch(demo(|_| {}), AtomicUsize::new(0)));
        let (emit, rx) = collector();
        let mut t = T { s: Setup::new(w.clone(), Config { coord_lan_ip: "192.168.1.50".into(), ..Config::default() }), emit, rx };
        let emit = t.emit.clone();
        t.s.init(&emit);
        t.drain(&[State::Probe]);
        // Every key on every screen up to the YES field.
        t.keys([Key::Enter, Key::Enter, Key::Enter, Key::Enter, Key::Char(' '), Key::Enter, Key::Enter]);
        t.keys(type_text("a long passphrase"));
        t.keys([Key::Enter]);
        t.keys(type_text("a long passphrase"));
        t.keys([Key::Enter]);
        t.keys(type_text("longpassword"));
        t.keys([Key::Enter]);
        t.keys(type_text("longpassword"));
        t.keys([Key::Enter]);
        t.drain(&[State::Check]);
        assert_eq!(t.s.state, State::Confirm);
        for k in [Key::Enter, Key::Char('y'), Key::Paste("YES\n".into()), Key::Enter, Key::Tab, Key::Char('?'), Key::Char('x')] {
            t.keys([k]);
        }
        assert_eq!(w.1.load(Ordering::SeqCst), 0, "nothing may erase before YES");
        t.s.confirm.set_value("");
        t.keys(type_text("YES"));
        t.keys([Key::Enter]);
        t.drain(&[State::Install, State::Join]);
        assert_eq!(w.1.load(Ordering::SeqCst), 1);
        assert_eq!(t.s.state, State::Done);
    }

    #[test]
    fn node_install_and_join() {
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        let emit = t.emit.clone();
        t.s.start_install(&emit);
        t.drain(&[State::Install, State::Join]);
        assert!(t.s.state == State::Done && t.s.host_num == 7 && t.s.code == "482 913", "state {:?} err {:?}", t.s.state, t.s.err);
        assert!(t.s.steps.iter().all(|s| s.done), "steps not done");
        t.has(&[
            "Done",
            "The server is installed and approved",
            "It is in the mesh as 10.66.0.7.",
            "Type the disk passphrase once at the first start",
            "Next Take out the USB stick, then press enter to restart.",
        ]);
        assert_eq!(t.keys([Key::Enter]), Flow::Quit, "enter restarts");
    }

    #[test]
    fn coordinator_skips_join() {
        let mut t = demo_setup(Role::Coordinator, Encryption::Passphrase, demo(|_| {}));
        let emit = t.emit.clone();
        t.s.start_install(&emit);
        t.drain(&[State::Install, State::Join]);
        assert!(t.s.state == State::Done && t.s.code == "305 771", "the coordinator's own code must be shown: {:?}", t.s.code);
        let v = t.words();
        assert!(!v.contains("passphrase once"), "passphrase mode has no first-boot TPM step");
        t.has(&["The coordinator is installed", "sign it on your computer (dryserver, Machines, s)", "the same code, 305 771", "Sign it"]);
        assert!(!v.contains("sudo dryserver approve"));
        let screen = t.screen(Tier::True, false, 120, 50).join("\n");
        assert!(screen.contains("██"), "the code in large digits:\n{screen}");
    }

    #[test]
    fn join_rejected() {
        let d = demo(|d| d.approve = Some(Box::new(|| Err(Error::with_kind(Kind::Rejected, install::REJECTED)))));
        let mut t = demo_setup(Role::Node, Encryption::None, d);
        let emit = t.emit.clone();
        t.s.start_install(&emit);
        t.drain(&[State::Install, State::Join]);
        assert_eq!(t.s.state, State::Failed);
        t.has(&["Step 5 of 5", "The coordinator rejected this machine.", "dryserver install", "[esc] leave to the shell"]);
        assert_eq!(t.keys([Key::Char('r')]), Flow::Continue, "no retry: it is rejected");
        assert_eq!(t.keys([Key::Esc]), Flow::Quit);
    }

    #[test]
    fn coordinator_unreachable_while_pairing() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let d = demo(move |d| {
            d.approve = Some(Box::new(move || {
                if c.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err("cannot reach the coordinator at 192.168.1.50 (is it installed and switched on?)".into())
                } else {
                    Ok(9)
                }
            }))
        });
        let mut t = demo_setup(Role::Node, Encryption::None, d);
        let emit = t.emit.clone();
        t.s.start_join(&emit);
        t.has(&["Step 5 of 5", "Asking the coordinator at 192.168.1.50 to let this machine in", "[s] skip"]);
        while t.s.join.again.is_none() {
            t.next();
        }
        assert_eq!(t.s.state, State::Join, "it keeps trying");
        assert!(t.s.code.is_empty(), "a code from a request that did not go through is not shown");
        t.has(&[
            "The coordinator at 192.168.1.50 did not let this machine in yet.",
            "cannot reach the coordinator",
            "It asks again in",
            "asked once",
            "[r] ask now",
        ]);
        // Not yet: the tick waits.
        t.send(Event::Tick);
        assert!(t.s.join.again.is_some());
        // Its time: it asks again, by itself.
        t.s.join.again = Some(ago(1));
        t.send(Event::Tick);
        assert!(t.s.join.again.is_none() && t.s.state == State::Join);
        t.drain(&[State::Join]);
        assert!(t.s.state == State::Done && t.s.host_num == 9, "{:?} {:?}", t.s.state, t.s.join_err);
        assert_eq!(t.s.join.tries, 1);
    }

    #[test]
    fn waiting_for_approval_says_how_it_waits() {
        let mut t = demo_setup(Role::Node, Encryption::None, demo(|_| {}));
        t.s.state = State::Join;
        t.s.join.first = Some(ago(75));
        t.s.code = "482 913".into();
        t.has(&[
            "Approve it on your computer",
            "Machines (4)",
            "the same code, 482 913",
            "Waiting for your approval 1m15s",
            "every 8 seconds",
            "keeps asking",
        ]);
        let screen = t.screen(Tier::Console, true, 80, 25).join("\n");
        assert!(screen.contains("██"), "large digits on the console too:\n{screen}");
        // s skips: the server asks again at every start.
        t.s.join.again = None;
        t.keys([Key::Char('s')]);
        assert!(t.s.join.skipping && t.s.ctx.done());
        t.msg(Msg::JoinDone(Err(Error::canceled())));
        assert_eq!(t.s.state, State::Done);
        t.has(&["has not joined yet", "You skipped joining.", "it asks again after it restarts"]);
        // Skipped while waiting to ask again: done at once.
        let mut t = demo_setup(Role::Node, Encryption::None, demo(|_| {}));
        t.s.state = State::Join;
        t.s.join.again = Some(Instant::now() + ASK_AGAIN);
        t.s.join_err = Some("no route to host".into());
        t.keys([Key::Char('s')]);
        assert_eq!(t.s.state, State::Done);
    }

    #[test]
    fn role_defaults_from_network() {
        for (found, want) in [(false, Role::Coordinator), (true, Role::Node)] {
            let mut t = setup(demo(|d| d.machine.get_mut().unwrap().coord_found = found));
            t.s.open_form();
            assert_eq!(t.s.ch.role, Some(want), "coordinator found={found}");
        }
    }

    #[test]
    fn confirm_warns_about_role() {
        let mut t = demo_setup(Role::Node, Encryption::None, demo(|_| {}));
        t.s.m.coord_found = false;
        t.msg(Msg::CheckDone(None));
        t.has(&["choose coordinator", "server: it joins the mesh once you approve it"]);
        let mut t = demo_setup(Role::Coordinator, Encryption::None, demo(|_| {}));
        t.msg(Msg::CheckDone(None));
        t.has(&["separate mesh"]);
    }

    #[test]
    fn install_failure_offers_retry() {
        let mut t = demo_setup(Role::Node, Encryption::None, demo(|_| {}));
        t.s.state = State::Install;
        t.msg(Msg::Step(Step::line("error: failed retrieving file")));
        t.msg(Msg::InstallDone(Some("Install packages: downloads failed".into())));
        t.has(&[
            "Step 4 of 5",
            "The install failed: Install packages: downloads failed",
            "half-installed",
            "[r] try again",
            "The last lines of the log",
            "failed retrieving file",
        ]);
        // A failure never drops to the shell by itself.
        assert_eq!(t.keys([Key::Enter, Key::Char('q'), Key::Char('x')]), Flow::Continue);
        assert_eq!(t.s.state, State::Form, "q is esc: back to the answers");
        t.s.state = State::Failed;
        t.s.retry = Retry::Install;
        t.keys([Key::Char('r')]);
        assert_eq!(t.s.state, State::Install, "r must restart the install");
        t.drain(&[State::Install, State::Join]);
        assert_eq!(t.s.state, State::Done, "retry did not finish: {:?}", t.s.err);
    }

    #[test]
    fn ctrl_c_during_the_install_asks_once() {
        let mut t = demo_setup(Role::Node, Encryption::None, demo(|d| d.delay = Duration::from_secs(30)));
        let emit = t.emit.clone();
        t.s.start_install(&emit);
        t.keys([Key::Ctrl('c')]);
        assert!(!t.s.ctx.done(), "the first ctrl+c only asks");
        t.has(&["ctrl+c again stops the install", "half-installed"]);
        // Another key: the question is gone.
        t.keys([Key::Char('x')]);
        assert!(t.s.notice.is_none() && !t.s.armed);
        t.keys([Key::Ctrl('c'), Key::Ctrl('c')]);
        assert!(t.s.ctx.done() && t.s.stopping);
        t.has(&["Stopping the install"]);
        t.drain(&[State::Install]);
        assert_eq!(t.s.state, State::Failed);
        t.has(&["The install was stopped.", "r installs again with the same answers"]);
    }

    #[test]
    fn form_runs_to_the_check() {
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        t.s.ch = Choices::default();
        t.s.open_form();
        t.has(&["Step 2 of 5", "Question 1 of 7", "What is this machine?", "[esc] back"]);
        // role (server: coordinator found), hostname empty, disk, data disks,
        // encryption, passphrase twice, password twice.
        t.keys([Key::Enter, Key::Enter, Key::Enter, Key::Char(' '), Key::Enter, Key::Enter]);
        t.keys(type_text("a long passphrase"));
        t.keys([Key::Enter]);
        t.keys(type_text("a long passphrase"));
        t.keys([Key::Enter]);
        t.keys(type_text("longpassword"));
        t.keys([Key::Enter]);
        t.keys(type_text("wrong"));
        t.keys([Key::Enter]);
        assert_eq!(t.s.state, State::Form, "mismatched password accepted");
        t.has(&["does not match"]);
        t.keys(std::iter::repeat_n(Key::Backspace, 5));
        t.keys(type_text("longpassword"));
        t.keys([Key::Enter]);
        assert_eq!(t.s.state, State::Check);
        assert_eq!(t.s.ch.role, Some(Role::Node));
        assert!(t.s.ch.hostname.starts_with("node-"));
        assert_eq!(t.s.ch.system_disk, "/dev/nvme0n1");
        assert_eq!(t.s.ch.data_disks, vec!["/dev/sda"]);
        assert_eq!(t.s.ch.encryption, Some(Encryption::Tpm));
        assert_eq!(t.s.ch.disk_passphrase, "a long passphrase");
        t.s.ctx.cancel();
    }

    #[test]
    fn steps_count_and_the_ring_grows() {
        let _g = theme::force(Tier::Console, true);
        let ash = theme::palette().ash;
        let lit = |s: &Setup| -> usize {
            s.banner(75, 21)
                .lines
                .iter()
                .flatten()
                .filter(|g| g.0.chars().all(|c| matches!(c, '█' | '▀' | '▄')) && g.1.fg != Some(ash))
                .count()
        };
        let mut t = demo_setup(Role::Node, Encryption::None, demo(|_| {}));
        let mut seen = Vec::new();
        for (state, want) in [
            (State::Welcome, "Step 1 of 5"),
            (State::Form, "Step 2 of 5"),
            (State::Check, "Step 3 of 5"),
            (State::Confirm, "Step 4 of 5"),
            (State::Join, "Step 5 of 5"),
            (State::Done, "Done"),
        ] {
            if state == State::Form {
                t.s.open_form();
            }
            t.s.state = state;
            t.s.host_num = 7;
            let top = t.screen(Tier::Console, true, 80, 25)[0].clone();
            assert!(top.starts_with(" dryserver  Install") && top.trim_end().ends_with(want), "{state:?}: {top:?}");
            let _g = theme::force(Tier::Console, true);
            seen.push(lit(&t.s));
        }
        assert_eq!(seen[0], 0, "nothing done on the first step");
        assert!(seen.windows(2).all(|w| w[0] < w[1]), "the ring grows with each step: {seen:?}");
        let all = theme::ring(None).lines.iter().flatten().filter(|g| g.0.trim() != "").count();
        assert_eq!(*seen.last().unwrap(), all, "it bites its tail when done");
    }

    /// The console's font: ASCII, the upper half of code page 437, and the
    /// bullet the design uses for the next step.
    fn console_glyph(c: char) -> bool {
        c == ' ' || c.is_ascii_graphic() || CP437.contains(c)
    }

    #[test]
    fn every_screen_fits_every_tier_and_the_console_font() {
        for (name, mut t) in fixtures() {
            for (tier, console, w, h) in [
                (Tier::Console, true, 80, 25),
                (Tier::Console, true, 80, 24),
                (Tier::Console, true, 60, 20),
                (Tier::Console, true, 40, 12),
                (Tier::Plain, true, 80, 25),
                (Tier::True, false, 100, 32),
                (Tier::C256, false, 80, 24),
            ] {
                let r = t.screen(tier, console, w, h);
                assert_eq!(r.len(), h as usize, "{name} {tier:?} {w}x{h}");
                for l in &r {
                    assert_eq!(l.width(), w as usize, "{name} {tier:?} {w}x{h}: {l:?}");
                    if console {
                        assert!(l.chars().all(console_glyph), "{name} {w}x{h}: a glyph the console font has not: {l:?}");
                    }
                }
                assert!(r[0].starts_with(" dryserver  Install"), "{name} {w}x{h}: {:?}", r[0]);
                let keys = &r[h as usize - 1];
                assert!(["help", "yes", "close"].iter().any(|k| keys.contains(k)), "{name} {w}x{h}: the keys: {keys:?}");
                if !matches!(tier, Tier::True | Tier::C256) {
                    assert!(keys.contains('['), "{name} {w}x{h}: caps in brackets: {keys:?}");
                }
            }
            // The console paints no background and NO_COLOR no colour.
            let _g = theme::force(Tier::Console, true);
            let d = t.s.view();
            assert!(!d.lines.iter().flatten().any(|s| s.1.bg.is_some() && s.1.bg != Some(Color::Red)), "{name}: a background");
            let _g = theme::force(Tier::Plain, true);
            let d = t.s.view();
            assert!(!d.lines.iter().flatten().any(|s| s.1.fg.is_some() || s.1.bg.is_some()), "{name}: NO_COLOR coloured");
        }
    }

    #[test]
    fn a_small_console_still_works() {
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        t.msg(Msg::CheckDone(None));
        t.keys(type_text("YE"));
        for (w, h) in [(80, 25), (60, 20), (40, 12)] {
            let r = t.screen(Tier::Console, true, w, h);
            assert!(r.iter().any(|l| l.contains("> YE")), "{w}x{h}: the YES field stays in view: {r:#?}");
            assert!(!r.join("").contains("Make this window"), "{w}x{h}: no request for a bigger window");
        }
        // A resize: the next screen is laid out for it.
        t.send(Event::Resize(200, 60));
        assert_eq!(t.s.view().lines.len(), 60);
        t.send(Event::Resize(80, 25));
        assert_eq!(t.s.view().lines.len(), 25);
    }

    #[test]
    fn no_disk_never_opens_the_form() {
        let mut t = setup(demo(|d| d.machine.get_mut().unwrap().disks.clear()));
        t.has(&["Disks 0", "No disk to install on was found.", "AHCI", "[r] look again"]);
        t.keys([Key::Enter]);
        assert!(t.s.state == State::Welcome && t.s.form.is_none());
        assert!(t.s.notice.as_ref().unwrap().text.contains("no disk"));
        t.keys([Key::Char('r')]);
        assert_eq!(t.s.state, State::Probe, "r looks again");
    }

    #[test]
    fn many_disks_with_long_names_are_cut_in_the_table() {
        let mut t = setup(demo(|d| d.machine.get_mut().unwrap().disks = many_disks()));
        let r = t.screen(Tier::Console, true, 80, 25);
        let shown: Vec<&String> = r.iter().filter(|l| l.contains("sda") || l.contains("sdb")).collect();
        assert!(!shown.is_empty() && shown.iter().all(|l| l.contains("...") && !l.contains('…')), "{r:#?}");
        // Cut to a line in the form, where a disk is chosen.
        t.s.open_form();
        t.keys([Key::Enter, Key::Enter]);
        t.has(&["Install on which disk?", "sdg 7.0 TB ATA Samsung SSD 870 EVO 1TB… (has: old backups)"]);
        let r = t.screen(Tier::Console, true, 80, 25);
        assert!(r.iter().any(|l| l.contains("> sda  1.0 TB  ATA Samsung SSD 870 EVO 1...  (has: old backups)")), "{r:#?}");
        assert!(r.last().unwrap().contains("[esc] back one step"), "the way back stays in the footer: {r:#?}");
        t.keys([Key::Down, Key::Down, Key::Enter]);
        assert_eq!(t.s.form.as_ref().unwrap().state.ch.system_disk, "/dev/sdc");
        // Whole on the card of what is erased.
        t.s.ch.system_disk = "/dev/sdc".into();
        t.msg(Msg::CheckDone(None));
        t.has(&["system sdc 3.0 TB ATA Samsung SSD 870 EVO 1TB with a model name that goes on and on", "(has: old backups)"]);
    }

    #[test]
    fn wifi_when_needed_and_a_wrong_password() {
        let mut t = setup(demo(|d| {
            let m = d.machine.get_mut().unwrap();
            m.online = false;
            m.net.clear();
        }));
        t.has(&["Network not connected", "This machine is not on the internet.", "[enter] connect to WiFi"]);
        t.keys([Key::Enter]);
        assert_eq!(t.s.state, State::Busy);
        t.has(&["Looking for WiFi networks", "about five seconds", "[esc] stop"]);
        t.drain(&[State::Busy]);
        assert_eq!(t.s.state, State::Wifi);
        t.has(&["Step 1 of 5", "Connect to WiFi", "Home", "Neighbor 5G"]);
        t.keys([Key::Enter]);
        t.keys(type_text("wrong"));
        t.keys([Key::Enter]);
        assert_eq!(t.s.state, State::Busy);
        t.has(&["Connecting to Home", "up to half a minute"]);
        t.drain(&[State::Busy]);
        assert_eq!(t.s.state, State::Wifi, "a wrong password goes back to the WiFi");
        assert!(t.s.notice.as_ref().is_some_and(|n| n.tone == frame::Tone::Bad && n.text.contains("Could not connect to Home")));
        assert!(t.s.wifi_form.as_ref().unwrap().typing(), "straight to the password, the network chosen again");
        t.keys(type_text("right"));
        t.keys([Key::Enter]);
        t.drain(&[State::Busy]);
        assert!(t.s.state == State::Welcome && t.s.m.online);
        assert!(t.s.notice.as_ref().is_some_and(|n| n.text == "Connected to Home."));
        t.has(&["Network WiFi Home"]);
        // esc in the WiFi form goes back.
        t.s.open_wifi_form();
        t.keys([Key::BackTab, Key::Esc]);
        assert_eq!(t.s.state, State::Welcome);
    }

    #[test]
    fn a_stopped_job_answers_into_nothing() {
        let mut t = setup(demo(|d| {
            d.machine.get_mut().unwrap().online = false;
        }));
        t.keys([Key::Enter]);
        assert_eq!(t.s.state, State::Busy);
        t.keys([Key::Esc]);
        assert_eq!(t.s.state, State::Welcome);
        t.next();
        assert_eq!(t.s.state, State::Welcome, "the scan's late answer is dropped");
        // Nor does an old check count once a new one runs.
        t.s.state = State::Check;
        let old = t.s.job;
        t.s.job += 1;
        t.send(Event::Msg(Tagged(old, Msg::CheckDone(None))));
        assert_eq!(t.s.state, State::Check);
    }

    #[test]
    fn esc_on_the_first_step_asks_before_leaving() {
        let mut t = setup(demo(|_| {}));
        t.keys([Key::Esc]);
        assert!(t.s.leaving);
        t.has(&["Leave the installer?", "Nothing on this machine was changed.", "dryserver install"]);
        assert_eq!(t.keys([Key::Char('n')]), Flow::Continue);
        assert!(!t.s.leaving && t.s.state == State::Welcome);
        // q is esc.
        t.keys([Key::Char('q')]);
        assert!(t.s.leaving);
        assert_eq!(t.keys([Key::Char('y')]), Flow::Quit);
        // ctrl+c leaves at once: nothing runs.
        let mut t = setup(demo(|_| {}));
        assert_eq!(t.keys([Key::Ctrl('c')]), Flow::Quit);
    }

    #[test]
    fn esc_goes_back_one_step() {
        let mut t = demo_setup(Role::Node, Encryption::None, demo(|_| {}));
        t.s.open_form();
        t.keys([Key::Enter]);
        t.keys([Key::Esc, Key::Esc]);
        assert_eq!(t.s.state, State::Welcome, "from the answers to the machine");
        assert_eq!(t.s.ch.hostname, "node-test", "the answers are kept");
        t.msg(Msg::CheckDone(None));
        t.keys([Key::Esc]);
        assert_eq!(t.s.state, State::Form, "from YES to the answers");
        let mut t = setup(demo(|_| {}));
        t.msg(Msg::Probe(Err("lsblk failed".into())));
        t.keys([Key::Esc]);
        assert!(t.s.leaving, "a failure on the first step asks before leaving");
    }

    #[test]
    fn probe_failure_is_a_card() {
        let mut t = setup(demo(|_| {}));
        t.msg(Msg::Probe(Err("lsblk: exit status 32".into())));
        assert_eq!(t.s.state, State::Failed);
        t.has(&["Step 1 of 5", "This machine could not be looked at: lsblk: exit status 32", "[r] look again"]);
        t.keys([Key::Char('r')]);
        assert_eq!(t.s.state, State::Probe);
        t.drain(&[State::Probe]);
        assert_eq!(t.s.state, State::Welcome);
    }

    #[test]
    fn paste_does_nothing_where_a_key_is_expected() {
        let mut t = setup(demo(|_| {}));
        t.keys([Key::Paste("w".into()), Key::Paste("\n".into())]);
        assert!(t.s.state == State::Welcome && !t.s.leaving);
        t.keys([Key::Esc, Key::Paste("y".into())]);
        assert!(t.s.leaving, "a pasted y is not a yes, and not a no either");
        t.keys([Key::Char('n')]);
        t.keys([Key::Char('?'), Key::Paste("x".into())]);
        assert!(t.s.help, "a paste does not close the help");
        t.keys([Key::Char('x')]);
        assert!(!t.s.help);
        // In a field it types.
        t.s.open_form();
        t.keys([Key::Enter, Key::Paste("node-x".into())]);
        assert_eq!(t.s.form.as_ref().unwrap().state.ch.hostname, "node-x");
        // q and ? are letters there.
        t.keys(type_text("q?"));
        assert_eq!(t.s.form.as_ref().unwrap().state.ch.hostname, "node-xq?");
        assert!(!t.s.help);
    }

    #[test]
    fn the_log_whole() {
        let mut t = demo_setup(Role::Node, Encryption::None, demo(|_| {}));
        t.s.state = State::Install;
        for i in 0..60 {
            t.msg(Msg::Step(Step::line(format!("line {i}"))));
        }
        t.msg(Msg::InstallDone(Some("Configure system: exit status 1".into())));
        t.keys([Key::Char('l')]);
        assert!(t.s.log_open);
        let r = t.screen(Tier::Console, true, 80, 25).join("\n");
        assert!(r.contains("line 59") && r.contains("[esc] back"), "the last line in view: {r}");
        t.keys([Key::PageUp, Key::PageUp]);
        let r = t.screen(Tier::Console, true, 80, 25).join("\n");
        assert!(!r.contains("line 59"), "pgup looks further up");
        t.keys([Key::Esc]);
        assert!(!t.s.log_open && t.s.state == State::Failed);
    }

    #[test]
    fn a_log_line_is_shown_safely() {
        let _g = theme::force(Tier::Console, true);
        assert_eq!(printable("ok\x1b[1m \u{2713} done…"), "ok?[1m ? done?");
        let _g = theme::force(Tier::True, false);
        assert_eq!(printable("a\tb ✓"), "a?b ✓");
    }

    #[test]
    fn large_digits() {
        let _g = theme::force(Tier::Console, true);
        let d = big_code("482 913", 80).unwrap();
        let t = d.plain();
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines.len(), 5);
        assert!(lines.iter().all(|l| l.chars().all(|c| c == '█' || c == ' ')), "{t}");
        assert!(lines.iter().all(|l| l.width() <= 52), "{t}");
        // The groups stand apart: six columns of nothing between them.
        let gap = |l: &str| l.chars().collect::<Vec<_>>().windows(6).any(|w| w.iter().all(|c| *c == ' '));
        assert!(lines.iter().all(|l| gap(&l[2..])));
        let mut seen = std::collections::HashSet::new();
        for d in DIGITS {
            assert!(seen.insert(d.join("")), "two digits look the same");
            assert!(d.iter().all(|r| r.len() == 3));
        }
        assert!(big_code("482 913", 40).is_none(), "too wide for the body");
        assert!(big_code("", 80).is_none() && big_code("48a", 80).is_none());
        let mut b = Doc::new();
        code_view(&mut b, "482 913", 30);
        assert_eq!(b.plain().trim(), "482 913", "in text when the digits do not fit");
    }

    #[test]
    fn downloads_move_the_install_on() {
        assert_eq!(downloaded("downloaded 120.5 MiB of 1.5 GiB"), Some((120.5, 1536.0)));
        assert_eq!(downloaded("downloaded 512.0 KiB of 2.0 MiB"), Some((0.5, 2.0)));
        assert_eq!(downloaded("downloaded lots"), None);
        assert_eq!(downloaded("resolving dependencies..."), None);
        let mut t = demo_setup(Role::Node, Encryption::None, demo(|_| {}));
        t.s.state = State::Install;
        steps(&mut t, &["Partition disks", "Set up encryption and filesystems"], Some("Install packages (takes a while)"));
        let before = t.s.install_pct();
        assert!((before - 0.4).abs() < 1e-9);
        log(&mut t, &["downloaded 379.35 MiB of 758.70 MiB"]);
        let after = t.s.install_pct();
        assert!(after > before && after < 0.6, "{after}");
        t.msg(Msg::Step(Step::finished("Install packages (takes a while)")));
        assert!((t.s.install_pct() - 0.6).abs() < 1e-9);
        t.has(&["Step 4 of 5", "Partition disks 3s", "2 more steps", "60%"]);
    }

    #[test]
    fn done_restarts_or_stays() {
        let mut t = demo_setup(Role::Node, Encryption::None, demo(|_| {}));
        t.s.state = State::Done;
        t.s.host_num = 7;
        assert_eq!(t.keys([Key::Char('x'), Key::Paste("y".into())]), Flow::Continue);
        assert_eq!(t.keys([Key::Esc]), Flow::Quit, "esc stays in the live system");
        let mut t = demo_setup(Role::Node, Encryption::None, demo(|_| {}));
        t.s.state = State::Done;
        assert_eq!(t.keys([Key::Enter]), Flow::Quit, "enter restarts");
    }

    #[test]
    fn help_says_every_key() {
        let mut t = setup(demo(|_| {}));
        t.keys([Key::Char('?')]);
        t.has(&["Help", "turns this machine into one of your servers", "look at the machine again", "Any key closes this."]);
        t.keys([Key::Enter]);
        assert!(!t.s.help && t.s.form.is_none(), "the key that closes the help does nothing else");
    }

    /// The screens as ANSI text for a visual review, written when
    /// DRYSERVER_SETUP_SCREENS names a directory:
    /// cargo test screens_for_review -- --ignored
    #[test]
    #[ignore = "writes screenshots when DRYSERVER_SETUP_SCREENS is set"]
    fn screens_for_review() {
        let Some(dir) = std::env::var_os("DRYSERVER_SETUP_SCREENS").map(std::path::PathBuf::from) else {
            return;
        };
        std::fs::create_dir_all(&dir).unwrap();
        for (name, mut t) in fixtures() {
            for (tag, tier, console, w, h) in
                [("console", Tier::Console, true, 80, 25), ("true", Tier::True, false, 100, 32), ("nocolor", Tier::Plain, true, 80, 25)]
            {
                if tag == "nocolor" && !["02-welcome", "14-confirm", "16-install", "21-join-code"].contains(&name) {
                    continue;
                }
                let _g = theme::force(tier, console);
                t.send(Event::Resize(w, h));
                std::fs::write(dir.join(format!("{name}-{tag}.ansi")), ansi(&t.s.view())).unwrap();
            }
            if ["02-welcome", "14-confirm", "21-join-code"].contains(&name) {
                let _g = theme::force(Tier::Console, true);
                t.send(Event::Resize(60, 20));
                std::fs::write(dir.join(format!("{name}-small.ansi")), ansi(&t.s.view())).unwrap();
            }
        }
    }

    /// A drawn screen as the terminal gets it: the screen's own style under
    /// each cell, as the event loop draws it.
    fn ansi(d: &Doc) -> String {
        let base = theme::palette().base();
        let code = |c: Color, fg: bool| -> String {
            let lead = if fg { 38 } else { 48 };
            let n = match c {
                Color::Reset => return String::new(),
                Color::Rgb(r, g, b) => return format!(";{lead};2;{r};{g};{b}"),
                Color::Indexed(n) => n,
                Color::Black => 0,
                Color::Red => 1,
                Color::Green => 2,
                Color::Yellow => 3,
                Color::Blue => 4,
                Color::Magenta => 5,
                Color::Cyan => 6,
                Color::Gray => 7,
                Color::DarkGray => 8,
                Color::LightRed => 9,
                Color::LightGreen => 10,
                Color::LightYellow => 11,
                Color::LightBlue => 12,
                Color::LightMagenta => 13,
                Color::LightCyan => 14,
                Color::White => 15,
            };
            format!(";{lead};5;{n}")
        };
        let mut out = String::new();
        for (i, line) in d.lines.iter().enumerate() {
            if i > 0 {
                out.push('\n');
            }
            for s in line {
                let st = base.patch(s.1);
                out.push_str("\x1b[0");
                if st.add_modifier.contains(Modifier::BOLD) {
                    out.push_str(";1");
                }
                if st.add_modifier.contains(Modifier::REVERSED) {
                    out.push_str(";7");
                }
                if st.add_modifier.contains(Modifier::UNDERLINED) {
                    out.push_str(";4");
                }
                if let Some(c) = st.fg {
                    out.push_str(&code(c, true));
                }
                if let Some(c) = st.bg {
                    out.push_str(&code(c, false));
                }
                out.push('m');
                out.push_str(&s.0);
            }
            out.push_str("\x1b[0m");
        }
        out
    }
}
