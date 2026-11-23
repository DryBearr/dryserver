//! USB stick: removable disks only, each with its size, model and what is
//! on it; choosing one asks for its name to be typed; then the write and
//! the read-back check, with the snake ring. Without root the place hands
//! the terminal to sudo for `dryserver flash`, and comes back after.

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use super::app::{PlaceScreen, Size};
use super::frame::{self, Back, Focus, Help, Notice, Page, Scroll, col};
use super::theme::{self, Mark};
use super::{Doc, Emit, Event, Flow, Job, Key, Model, Seg, TextInput, dim};
use crate::ctx::Ctx;
use crate::disks::{self, Disk, human_size};
use crate::err::{Error, Result};
use crate::flash::{self, Phase};

const REFRESH: Duration = Duration::from_secs(2);

pub enum Msg {
    Disks(Result<Vec<Disk>>),
    Progress(Phase, u64, u64),
    Done(Option<Error>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Selecting,
    Confirming,
    Flashing,
    Finished,
}

pub struct Flash {
    iso: String,
    iso_size: u64,
    /// The image is older than the config or than this dryserver.
    warn: Option<String>,
    pub state: State,
    usb: Vec<Disk>,
    list_err: Option<Error>,
    cursor: usize,
    pub notice: Option<Notice>,
    pub target: Disk,
    input: TextInput,
    last_scan: Option<Instant>,
    phase: Phase,
    done: u64,
    total: u64,
    ctx: Ctx,
    stopping: bool,
    stop_armed: bool,
    started: Instant,
    err: Option<Error>,
    /// On its own (`dryserver flash`): the window and the scroll.
    size: (u16, u16),
    scroll: Scroll,
}

/// Lists USB disks in the background.
fn list_disks(emit: &Emit<Msg>) {
    let emit = emit.clone();
    std::thread::spawn(move || emit(Msg::Disks(disks::list().map(|all| disks::usb(&all)))));
}

impl Flash {
    pub fn new(iso: &str, iso_size: u64) -> Flash {
        Flash {
            iso: iso.into(),
            iso_size,
            warn: None,
            state: State::Selecting,
            usb: Vec::new(),
            list_err: None,
            cursor: 0,
            notice: None,
            target: Disk::default(),
            input: TextInput::new(32),
            last_scan: None,
            phase: Phase::Writing,
            done: 0,
            total: 0,
            ctx: Ctx::new(),
            stopping: false,
            stop_armed: false,
            started: Instant::now(),
            err: None,
            size: (80, 24),
            scroll: Scroll::default(),
        }
    }

    /// Says on the page that the image is out of date.
    pub fn warn(mut self, w: Option<String>) -> Flash {
        self.warn = w;
        self
    }

    /// The flash result after the screen closes: Ok only when written and
    /// verified.
    pub fn result(&self) -> Result<()> {
        if self.state != State::Finished {
            return Err("aborted".into());
        }
        match &self.err {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }

    pub fn start_scanning(&mut self, emit: &Emit<Msg>) {
        self.last_scan = Some(Instant::now());
        list_disks(emit);
    }

    fn step(&mut self, ev: Event<Msg>, emit: &Emit<Msg>) -> Flow {
        match ev {
            Event::Resize(w, h) => self.size = (w, h),
            Event::Msg(Msg::Disks(res)) => {
                match res {
                    Ok(l) => {
                        self.usb = l;
                        self.list_err = None;
                    }
                    Err(e) => {
                        self.usb.clear();
                        self.list_err = Some(e);
                    }
                }
                self.cursor = self.cursor.min(self.usb.len().saturating_sub(1));
            }
            Event::Msg(Msg::Progress(p, done, total)) => {
                (self.phase, self.done, self.total) = (p, done, total);
            }
            Event::Msg(Msg::Done(e)) => {
                self.state = State::Finished;
                self.err = e;
            }
            Event::Tick => {
                // Keep rescanning so a stick plugged in after start shows up.
                if self.state == State::Selecting && self.last_scan.is_none_or(|t| t.elapsed() >= REFRESH) {
                    self.start_scanning(emit);
                }
            }
            Event::Key(k) => return self.key(k, emit),
            Event::Back(_) => {}
        }
        Flow::Continue
    }

    fn key(&mut self, k: Key, emit: &Emit<Msg>) -> Flow {
        let armed = std::mem::take(&mut self.stop_armed);
        match self.state {
            State::Selecting => {
                self.notice = None;
                match k {
                    Key::Ctrl('c') | Key::Char('q') | Key::Esc => return Flow::Quit,
                    Key::Up | Key::Char('k') => self.cursor = self.cursor.saturating_sub(1),
                    Key::Down | Key::Char('j') => self.cursor = (self.cursor + 1).min(self.usb.len().saturating_sub(1)),
                    Key::Char('r') => self.start_scanning(emit),
                    Key::Enter => {
                        let Some(d) = self.usb.get(self.cursor).cloned() else {
                            return Flow::Continue;
                        };
                        if d.size < self.iso_size {
                            self.notice = Some(Notice::bad(format!(
                                "{} is too small for the installer: it needs {}.",
                                d.path,
                                human_size(self.iso_size)
                            )));
                            return Flow::Continue;
                        }
                        self.input.set_value("");
                        self.input.placeholder = d.name.clone();
                        self.input.focus();
                        self.target = d;
                        self.state = State::Confirming;
                    }
                    _ => {}
                }
            }
            State::Confirming => match k {
                Key::Ctrl('c') => return Flow::Quit,
                Key::Esc => {
                    self.state = State::Selecting;
                    self.notice = None;
                    self.input.blur();
                    self.start_scanning(emit);
                }
                Key::Enter => {
                    if self.input.value.trim() != self.target.name {
                        self.notice =
                            Some(Notice::bad(format!("Type {} exactly to write to it, or esc to choose again.", self.target.name)));
                        return Flow::Continue;
                    }
                    self.notice = None;
                    self.start(emit);
                }
                k => {
                    self.input.handle(&k);
                }
            },
            State::Flashing => {
                if matches!(k, Key::Esc | Key::Ctrl('c')) && !self.stopping {
                    if armed {
                        self.stopping = true;
                        self.ctx.cancel();
                    } else {
                        self.stop_armed = true;
                        self.notice = Some(Notice::info(format!(
                            "Still writing. {} again stops it: the stick then needs writing again.",
                            if k == Key::Esc { "esc" } else { "ctrl+c" }
                        )));
                    }
                }
            }
            State::Finished => match k {
                Key::Ctrl('c') | Key::Char('q') | Key::Esc | Key::Enter => return Flow::Quit,
                _ => {}
            },
        }
        Flow::Continue
    }

    fn start(&mut self, emit: &Emit<Msg>) {
        self.state = State::Flashing;
        self.started = Instant::now();
        self.input.blur();
        let (ctx, iso, target, emit) = (self.ctx.clone(), self.iso.clone(), self.target.clone(), emit.clone());
        std::thread::spawn(move || {
            let e = emit.clone();
            let res = flash::write(&ctx, &iso, &target, &mut |p, done, total| e(Msg::Progress(p, done, total)));
            emit(Msg::Done(res.err()));
        });
    }

    fn image(&self, b: &mut Doc, w: usize) {
        let p = theme::palette();
        b.append(frame::row(
            w,
            Mark::Done,
            vec![col(Seg("Installer".into(), p.text()), 10), col(Seg(format!("{}  {}", self.iso, human_size(self.iso_size)), p.hint()), 0)],
        ))
        .nl();
        if let Some(warn) = &self.warn {
            b.nl()
                .append(frame::card(
                    w,
                    warn,
                    "A stick written now installs that older one. Build it again (2) first, unless you mean to.",
                    None,
                ))
                .nl();
        }
    }

    pub fn page(&self, size: Size) -> Page {
        let p = theme::palette();
        let w = size.width;
        let mut page = Page::new("USB stick");
        page.status.add(dim("removable disks only"));
        let mut b = Doc::new();
        let mut focus = None;
        match self.state {
            State::Selecting => {
                self.image(&mut b, w);
                if let Some(e) = &self.list_err {
                    b.nl().append(frame::card(w, &format!("The disks cannot be listed: {e}"), "", Some(("r", "look again")))).nl();
                }
                frame::section(&mut b, "USB sticks", Some(self.usb.len()));
                if self.usb.is_empty() && self.list_err.is_none() {
                    b.append(frame::empty("No USB stick is plugged in. Plug one in: it shows up here by itself.")).nl();
                }
                for (i, d) in self.usb.iter().enumerate() {
                    let small = d.size < self.iso_size;
                    let model = format!("{} {}", d.vendor, d.model).trim().to_string();
                    let model = if model.is_empty() { "unknown model".to_string() } else { model };
                    let what = if small { format!("too small: the installer needs {}", human_size(self.iso_size)) } else { on_it(d) };
                    if i == self.cursor {
                        focus = Some(Focus::row(b.lines.len() - 1));
                    }
                    b.append(frame::row(
                        w,
                        if small { Mark::Bad } else { Mark::Blank },
                        vec![
                            col(Seg(d.name.clone(), p.text()), 8),
                            col(Seg(human_size(d.size), p.text()), 9),
                            col(Seg(model, p.hint()), 22),
                            col(Seg(what, p.hint()), 0),
                        ],
                    ))
                    .nl();
                }
                b.nl().add(dim("Internal and system disks are never listed."));
                if !self.usb.is_empty() {
                    page.key("↑↓", "move").key("enter", "choose");
                }
                page.key("r", "look again");
            }
            State::Confirming => {
                self.image(&mut b, w);
                b.nl();
                let mut lines = vec![format!("Everything on {} is erased:", self.target.name)];
                for part in &self.target.parts {
                    lines.push(format!("  {}  {}  {}", part.path, human_size(part.size), part_text(part)));
                }
                if self.target.parts.is_empty() {
                    lines.push("  it has no partitions".into());
                }
                b.append(frame::card(w, &lines[0], &lines[1..].join("\n"), None)).nl().nl();
                b.s("Type ").add(Seg(self.target.name.clone(), p.selected())).s(" and press enter to write the installer to it.").nl();
                focus = Some(Focus::keep(b.lines.len() - 1..b.lines.len()));
                b.s("  ").append(self.input.view()).nl();
                page.key("enter", "write it");
            }
            State::Flashing => {
                let pct = if self.total > 0 { self.done as f64 / self.total as f64 } else { 0.0 };
                let step = match self.phase {
                    Phase::Writing => format!("Writing to {}", self.target.path),
                    Phase::Verifying => format!("Reading {} back to check it", self.target.path),
                };
                b.append(frame::progress(w, Some(pct), &step, self.started.elapsed())).nl().nl();
                b.add(dim(format!("{} of {}. Do not unplug the stick.", human_size(self.done), human_size(self.total))));
                if self.stopping {
                    b.nl().nl().add(Seg("Stopping: the stick will need writing again.".into(), p.alarm()));
                }
                page.key("esc", "stop");
                page.back = Back::Nothing;
            }
            State::Finished => match &self.err {
                Some(e) if e.is_canceled() => {
                    b.append(frame::card(
                        w,
                        &format!("Stopped. {} is only partly written.", self.target.path),
                        "Write it again before you boot from it.",
                        Some(("enter", "back")),
                    ));
                }
                Some(e) => {
                    b.append(frame::card(
                        w,
                        &format!("The stick was not written: {e}"),
                        "Try another stick, or the same one again.",
                        Some(("enter", "back")),
                    ));
                }
                None => {
                    b.append(frame::progress(w, Some(1.0), &format!("Written and checked: {}", self.target.path), self.started.elapsed()));
                    b.nl().nl().add(Seg("Next".into(), p.selected())).s("  ").add(Seg(
                        "You can unplug it. Boot your first laptop from it and choose coordinator; every later one becomes a server."
                            .into(),
                        p.text(),
                    ));
                    page.key("enter", "done");
                    page.back = Back::Nothing;
                }
            },
        }
        page.body = b;
        page.focus = focus;
        page.notice = self.notice.clone();
        page.help = Some(Help {
            about: "Writes the installer to a USB stick. Only removable disks are listed, and the one you choose is only written \
                    once you type its name. After writing, the stick is read back and compared with the image."
                .into(),
            keys: vec![
                ("↑↓".into(), "move".into()),
                ("enter".into(), "choose; then type its name".into()),
                ("r".into(), "look for sticks again".into()),
                ("esc".into(), "back (twice while writing: stops it)".into()),
            ],
        });
        page
    }

    fn typing(&self) -> bool {
        self.state == State::Confirming
    }
}

/// What a disk holds, in words.
fn on_it(d: &Disk) -> String {
    if d.parts.is_empty() {
        return "empty".into();
    }
    let parts: Vec<String> = d.parts.iter().map(part_text).collect();
    format!("has {}", parts.join("; "))
}

fn part_text(p: &disks::Part) -> String {
    let mut t = [p.fstype.clone(), p.label.clone()].join(" ").trim().to_string();
    if t.is_empty() {
        t = "no filesystem".into();
    }
    if !p.mountpoints.is_empty() {
        t += &format!(", mounted at {}", p.mountpoints.join(", "));
    }
    t
}

impl Drop for Flash {
    /// A write left behind stops: nothing would show its end.
    fn drop(&mut self) {
        if self.state == State::Flashing {
            self.ctx.cancel();
        }
    }
}

impl PlaceScreen for Flash {
    type Msg = Msg;

    fn init(&mut self, emit: &Emit<Msg>) {
        self.start_scanning(emit);
    }

    fn update(&mut self, ev: Event<Msg>, emit: &Emit<Msg>) -> Flow {
        self.step(ev, emit)
    }

    fn page(&self, size: Size) -> Page {
        Flash::page(self, size)
    }

    fn busy(&self) -> Option<String> {
        (self.state == State::Flashing).then(|| format!("writing {}", self.target.path))
    }

    fn typing(&self) -> bool {
        Flash::typing(self)
    }
}

/// The stick screen on its own (`dryserver flash`): leaving it quits.
impl Model for Flash {
    type Msg = Msg;

    fn init(&mut self, emit: &Emit<Msg>) {
        self.start_scanning(emit);
    }

    fn update(&mut self, ev: Event<Msg>, emit: &Emit<Msg>) -> Flow {
        if let Event::Key(k) = &ev {
            // Nothing shows in a window that small: only leaving works,
            // and ctrl+c still stops a write first.
            if frame::too_small(self.size.0, self.size.1) && *k != Key::Ctrl('c') {
                return if *k == Key::Char('q') && self.state != State::Flashing { Flow::Quit } else { Flow::Continue };
            }
            if !self.typing() && self.scroll.key(k) {
                return Flow::Continue;
            }
        }
        self.step(ev, emit)
    }

    fn view(&self) -> Doc {
        let (w, h) = self.size;
        let page = Flash::page(self, Size { width: frame::body_width(w), rows: (h as usize).saturating_sub(4) });
        frame::draw(&page, &self.scroll, w, h)
    }
}

/// Without root: the stick is written by `sudo dryserver flash`, which
/// asks for the password on the terminal.
pub struct Sudo {
    iso: PathBuf,
    iso_size: u64,
    warn: Option<String>,
    exe: PathBuf,
    job: Option<Job>,
    notice: Option<Notice>,
}

impl Sudo {
    pub fn new(iso: PathBuf, iso_size: u64, warn: Option<String>, exe: PathBuf) -> Sudo {
        Sudo { iso, iso_size, warn, exe, job: None, notice: None }
    }
}

impl PlaceScreen for Sudo {
    type Msg = ();

    fn update(&mut self, ev: Event<()>, _: &Emit<()>) -> Flow {
        match ev {
            Event::Key(Key::Esc) => return Flow::Quit,
            Event::Key(Key::Enter) => {
                let (exe, iso) = (self.exe.clone(), self.iso.clone());
                self.notice = None;
                self.job = Some(Job {
                    title: "USB stick: sudo asks for your password, then the stick screen opens".into(),
                    run: Box::new(move || {
                        let st = std::process::Command::new("sudo")
                            .arg(&exe)
                            .arg("flash")
                            .arg("--iso")
                            .arg(&iso)
                            .status()
                            .map_err(|e| Error::from(e).wrap("sudo"))?;
                        if st.success() {
                            Ok(())
                        } else {
                            Err(crate::errf!("the stick was not written ({})", crate::runner::exit_text(st)))
                        }
                    }),
                });
            }
            Event::Back(Ok(())) => self.notice = Some(Notice::ok("The stick is written and checked. You can unplug it.")),
            Event::Back(Err(e)) => self.notice = Some(Notice::bad(e.to_string())),
            _ => {}
        }
        Flow::Continue
    }

    fn page(&self, size: Size) -> Page {
        let p = theme::palette();
        let mut page = Page::new("USB stick");
        let mut b = Doc::new();
        let made = std::fs::metadata(&self.iso).and_then(|m| m.modified()).unwrap_or(SystemTime::UNIX_EPOCH);
        let when = chrono::DateTime::<chrono::Local>::from(made).format("%Y-%m-%d %H:%M");
        b.append(frame::row(
            size.width,
            Mark::Done,
            vec![
                col(Seg("Installer".into(), p.text()), 10),
                col(Seg(format!("{}  {}  built {when}", self.iso.display(), human_size(self.iso_size)), p.hint()), 0),
            ],
        ))
        .nl();
        if let Some(warn) = &self.warn {
            b.nl()
                .append(frame::card(
                    size.width,
                    warn,
                    "A stick written now installs that older one. Build it again (2) first, unless you mean to.",
                    None,
                ))
                .nl();
        }
        b.nl().s("Writing a stick needs root: it writes to the disk itself. enter hands the terminal to sudo, which asks for your password; the stick screen opens there, and you come back here after.").nl();
        page.body = b;
        page.notice = self.notice.clone();
        page.key("enter", "write a stick (asks for sudo)");
        page.help = Some(Help {
            about: "Writes the installer to a USB stick. That needs root, so sudo runs the stick screen; dryserver itself stays as \
                    your user."
                .into(),
            keys: vec![("enter".into(), "write a stick".into()), ("esc".into(), "back to Home".into())],
        });
        page
    }

    fn job(&mut self) -> Option<Job> {
        self.job.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::{collector, type_text};

    fn send(m: &mut Flash, keys: impl IntoIterator<Item = Key>) {
        let (emit, _rx) = collector();
        for k in keys {
            m.step(Event::Key(k), &emit);
        }
    }

    fn with_disks(m: &mut Flash, l: Vec<Disk>) {
        let (emit, _rx) = collector();
        m.step(Event::Msg(Msg::Disks(Ok(l))), &emit);
    }

    fn text(m: &Flash) -> String {
        m.page(Size { width: 90, rows: 28 }).body.plain()
    }

    #[test]
    fn select_and_confirm() {
        let small = Disk { name: "sdb".into(), path: "/dev/sdb".into(), size: 1 << 20, tran: "usb".into(), ..Disk::default() };
        let big = Disk {
            name: "sdc".into(),
            path: "/dev/sdc".into(),
            size: 32 << 30,
            tran: "usb".into(),
            model: "Stick".into(),
            parts: vec![disks::Part {
                path: "/dev/sdc1".into(),
                size: 32 << 30,
                fstype: "vfat".into(),
                label: "USB".into(),
                mountpoints: vec![],
            }],
            ..Disk::default()
        };
        let mut m = Flash::new("x.iso", 1 << 30);
        with_disks(&mut m, vec![small, big]);
        let t = text(&m);
        assert!(t.contains("USB sticks  2") && t.contains("too small: the installer needs") && t.contains("has vfat USB"), "{t}");

        send(&mut m, [Key::Enter]);
        assert!(m.state == State::Selecting && m.notice.as_ref().is_some_and(|n| n.text.contains("too small")), "small disk accepted");

        send(&mut m, [Key::Down, Key::Enter]);
        assert_eq!(m.state, State::Confirming);
        assert_eq!(m.target.path, "/dev/sdc");
        assert!(text(&m).contains("Everything on sdc is erased") && text(&m).contains("/dev/sdc1"), "{}", text(&m));
        assert!(m.typing(), "q and ? are typed here");

        send(&mut m, type_text("sdb"));
        send(&mut m, [Key::Enter]);
        assert!(m.state == State::Confirming && m.notice.is_some(), "wrong device name must not start flashing");

        send(&mut m, [Key::Esc]);
        assert_eq!(m.state, State::Selecting);
    }

    #[test]
    fn empty_list() {
        let mut m = Flash::new("x.iso", 1);
        with_disks(&mut m, vec![]);
        send(&mut m, [Key::Enter]);
        assert_eq!(m.state, State::Selecting, "enter with no disks must do nothing");
        assert!(text(&m).contains("No USB stick is plugged in"));
        let (emit, _rx) = collector();
        m.step(Event::Msg(Msg::Disks(Err("lsblk: not found".into()))), &emit);
        assert!(text(&m).contains("The disks cannot be listed: lsblk: not found"));
    }

    #[test]
    fn progress_and_the_end() {
        let mut m = Flash::new("x.iso", 1 << 30).warn(Some("This installer is older than the config.".into()));
        assert!(text(&m).contains("This installer is older than the config."));
        let (emit, _rx) = collector();
        m.state = State::Flashing;
        m.target = Disk { name: "sdc".into(), path: "/dev/sdc".into(), ..Disk::default() };
        m.step(Event::Msg(Msg::Progress(Phase::Verifying, 1 << 29, 1 << 30)), &emit);
        let t = text(&m);
        assert!(t.contains("Reading /dev/sdc back to check it") && t.contains("50%"), "{t}");
        // Leaving asks first.
        send(&mut m, [Key::Esc]);
        assert!(!m.stopping && m.notice.as_ref().unwrap().text.contains("esc again stops it"));
        send(&mut m, [Key::Esc]);
        assert!(m.stopping && m.ctx.done());
        m.step(Event::Msg(Msg::Done(Some(Error::canceled()))), &emit);
        assert!(text(&m).contains("Stopped. /dev/sdc is only partly written."));
        assert!(m.result().is_err());
        let mut m = Flash::new("x.iso", 1);
        m.state = State::Flashing;
        m.step(Event::Msg(Msg::Done(None)), &emit);
        assert!(text(&m).contains("Written and checked") && m.result().is_ok());
    }

    #[test]
    fn on_its_own_in_a_small_window() {
        let mut m = Flash::new("x.iso", 1);
        let (emit, _rx) = collector();
        Model::update(&mut m, Event::Resize(60, 20), &emit);
        assert!(Model::view(&m).plain().contains("Make this window at least"));
        assert_eq!(Model::update(&mut m, Event::Key(Key::Enter), &emit), Flow::Continue);
        assert_eq!(m.state, State::Selecting);
        assert_eq!(Model::update(&mut m, Event::Key(Key::Char('q')), &emit), Flow::Quit);
        Model::update(&mut m, Event::Resize(100, 30), &emit);
        let v = Model::view(&m).plain();
        assert_eq!(v.lines().count(), 30);
        assert!(v.contains("USB sticks"), "{v}");
    }

    #[test]
    fn without_root_sudo_gets_the_terminal() {
        let mut s = Sudo::new("out/dryserver.iso".into(), 1, None, "/bin/false".into());
        let (emit, _rx) = collector();
        assert!(s.page(Size { width: 90, rows: 28 }).body.plain().contains("enter hands the terminal to sudo"));
        s.update(Event::Key(Key::Enter), &emit);
        assert!(s.job().is_some_and(|j| j.title.contains("sudo")));
        s.update(Event::Back(Err("the stick was not written (exit status 1)".into())), &emit);
        assert!(s.notice.as_ref().is_some_and(|n| n.tone == frame::Tone::Bad));
        assert_eq!(s.update(Event::Key(Key::Esc), &emit), Flow::Quit);
    }
}
