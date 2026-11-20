//! The USB selection, confirmation and write screen.

use std::time::{Duration, Instant};

use super::build::Out;
use super::{Border, Doc, Emit, Event, Flow, Key, Model, TextInput, dim, err, err_bold, ok, progress_bar, sel, theme};
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
    pub state: State,
    usb: Vec<Disk>,
    list_err: Option<Error>,
    cursor: usize,
    pub notice: String,
    pub target: Disk,
    input: TextInput,
    last_scan: Option<Instant>,
    bar_width: usize,
    phase: Phase,
    done: u64,
    total: u64,
    ctx: Ctx,
    stopping: bool,
    err: Option<Error>,
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
            state: State::Selecting,
            usb: Vec::new(),
            list_err: None,
            cursor: 0,
            notice: String::new(),
            target: Disk::default(),
            input: TextInput::new(32),
            last_scan: None,
            bar_width: 60,
            phase: Phase::Writing,
            done: 0,
            total: 0,
            ctx: Ctx::new(),
            stopping: false,
            err: None,
        }
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

    pub fn update(&mut self, ev: Event<Msg>, emit: &Emit<Msg>) -> Out {
        match ev {
            Event::Resize(w, _) => self.bar_width = (w as usize).saturating_sub(4).min(60),
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
        }
        Out::Stay
    }

    fn key(&mut self, k: Key, emit: &Emit<Msg>) -> Out {
        match self.state {
            State::Selecting => match k {
                Key::Ctrl('c') => return Out::Quit,
                Key::Char('q') | Key::Esc => return Out::Back,
                Key::Up | Key::Char('k') => self.cursor = self.cursor.saturating_sub(1),
                Key::Down | Key::Char('j') => self.cursor = (self.cursor + 1).min(self.usb.len().saturating_sub(1)),
                Key::Char('r') => self.start_scanning(emit),
                Key::Enter => {
                    let Some(d) = self.usb.get(self.cursor).cloned() else {
                        return Out::Stay;
                    };
                    if d.size < self.iso_size {
                        self.notice = format!("{} is too small for this image ({} needed)", d.path, human_size(self.iso_size));
                        return Out::Stay;
                    }
                    self.notice.clear();
                    self.input.set_value("");
                    self.input.placeholder = d.name.clone();
                    self.input.focus();
                    self.target = d;
                    self.state = State::Confirming;
                }
                _ => {}
            },
            State::Confirming => match k {
                Key::Ctrl('c') => return Out::Quit,
                Key::Esc => {
                    self.state = State::Selecting;
                    self.notice.clear();
                    self.input.blur();
                    self.start_scanning(emit);
                }
                Key::Enter => {
                    if self.input.value.trim() != self.target.name {
                        self.notice = format!("type {:?} exactly to continue, or esc to go back", self.target.name);
                        return Out::Stay;
                    }
                    self.notice.clear();
                    self.start(emit);
                }
                k => {
                    self.input.handle(&k);
                }
            },
            State::Flashing => {
                if k == Key::Ctrl('c') && !self.stopping {
                    self.stopping = true;
                    self.ctx.cancel();
                }
            }
            State::Finished => match k {
                Key::Ctrl('c') => return Out::Quit,
                Key::Char('q') | Key::Esc | Key::Enter => return Out::Back,
                _ => {}
            },
        }
        Out::Stay
    }

    fn start(&mut self, emit: &Emit<Msg>) {
        self.state = State::Flashing;
        self.input.blur();
        let (ctx, iso, target, emit) = (self.ctx.clone(), self.iso.clone(), self.target.clone(), emit.clone());
        std::thread::spawn(move || {
            let e = emit.clone();
            let res = flash::write(&ctx, &iso, &target, &mut |p, done, total| e(Msg::Progress(p, done, total)));
            emit(Msg::Done(res.err()));
        });
    }

    pub fn view(&self) -> Doc {
        let mut b = Doc::new();
        b.append(theme::header("flash installer USB")).nl();
        b.add(dim(format!("image: {} ({})", self.iso, human_size(self.iso_size)))).s("\n\n");
        match self.state {
            State::Selecting => self.view_select(&mut b),
            State::Confirming => self.view_confirm(&mut b),
            State::Flashing => self.view_flashing(&mut b),
            State::Finished => self.view_finished(&mut b),
        }
        if !self.notice.is_empty() {
            b.nl().add(err(&self.notice)).nl();
        }
        b
    }

    fn view_select(&self, b: &mut Doc) {
        b.s("Select USB drive to turn into installer:\n\n");
        if let Some(e) = &self.list_err {
            b.add(err(format!("cannot list disks: {e}"))).nl();
        }
        if self.usb.is_empty() {
            b.add(dim("  No USB drives found. Plug one in, it shows up here automatically.")).nl();
        }
        for (i, d) in self.usb.iter().enumerate() {
            if i == self.cursor {
                b.add(sel(format!("> {}", d.title()))).nl();
                write_parts(b, d);
            } else {
                b.s(format!("  {}", d.title())).nl();
            }
        }
        b.nl().append(theme::keys(&[("↑↓", "move"), ("enter", "select"), ("r", "rescan"), ("q", "back")])).nl();
        b.add(dim("Internal and system disks are never listed.")).nl();
    }

    fn view_confirm(&self, b: &mut Doc) {
        let mut w = Doc::new();
        w.add(err_bold("ALL DATA ON THIS DRIVE WILL BE DESTROYED")).s("\n\n");
        w.s(self.target.title()).nl();
        write_parts(&mut w, &self.target);
        b.append(w.boxed(Border::Rounded, theme::palette().ember, 1, 0, false)).s("\n\n");
        b.s("Type ").add(sel(&self.target.name)).s(" to confirm: ").append(self.input.view()).nl();
        b.nl().append(theme::keys(&[("enter", "confirm"), ("esc", "back")])).nl();
    }

    fn view_flashing(&self, b: &mut Doc) {
        let pct = if self.total > 0 { self.done as f64 / self.total as f64 } else { 0.0 };
        b.s(format!("{} {}\n\n", self.phase, self.target.path));
        b.append(progress_bar(pct, self.bar_width)).nl();
        b.s(format!("{} / {}  ({:.0}%)\n", human_size(self.done), human_size(self.total), pct * 100.0));
        if self.stopping {
            b.nl().add(err("Stopping… the drive will need flashing again.")).nl();
        } else {
            b.nl().add(dim("Do not unplug. ctrl+c cancels.")).nl();
        }
    }

    fn view_finished(&self, b: &mut Doc) {
        match &self.err {
            Some(e) if e.is_canceled() => {
                b.add(err(format!("Cancelled. {} is only partly written; flash it again before use.", self.target.path))).nl();
            }
            Some(e) => {
                b.add(err(format!("Failed: {e}"))).nl();
            }
            None => {
                b.add(ok(format!("Done. Installer written and verified on {}.", self.target.path))).nl();
                b.s("Safe to unplug.\n");
            }
        }
        b.nl().add(dim("enter continue")).nl();
    }
}

fn write_parts(b: &mut Doc, d: &Disk) {
    for p in &d.parts {
        let desc = [p.fstype.clone(), p.label.clone(), p.mountpoints.join(",")].join(" ").trim().to_string();
        let desc = if desc.is_empty() { "no filesystem".to_string() } else { desc };
        b.add(dim(format!("      {}  {}  {desc}", p.path, human_size(p.size)))).nl();
    }
}

/// The flash screen on its own (`dryserver flash`): leaving it quits.
impl Model for Flash {
    type Msg = Msg;

    fn init(&mut self, emit: &Emit<Msg>) {
        self.start_scanning(emit);
    }

    fn update(&mut self, ev: Event<Msg>, emit: &Emit<Msg>) -> Flow {
        match Flash::update(self, ev, emit) {
            Out::Stay => Flow::Continue,
            Out::Back | Out::Quit => Flow::Quit,
        }
    }

    fn view(&self) -> Doc {
        Flash::view(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::{collector, type_text};

    fn send(m: &mut Flash, keys: impl IntoIterator<Item = Key>) {
        let (emit, _rx) = collector();
        for k in keys {
            Flash::update(m, Event::Key(k), &emit);
        }
    }

    fn with_disks(m: &mut Flash, l: Vec<Disk>) {
        let (emit, _rx) = collector();
        Flash::update(m, Event::Msg(Msg::Disks(Ok(l))), &emit);
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
            ..Disk::default()
        };
        let mut m = Flash::new("x.iso", 1 << 30);
        with_disks(&mut m, vec![small, big]);

        send(&mut m, [Key::Enter]);
        assert!(m.state == State::Selecting && m.notice.contains("too small"), "small disk accepted");

        send(&mut m, [Key::Down, Key::Enter]);
        assert_eq!(m.state, State::Confirming);
        assert_eq!(m.target.path, "/dev/sdc");
        assert!(m.view().plain().contains("ALL DATA ON THIS DRIVE WILL BE DESTROYED"));

        send(&mut m, type_text("sdb"));
        send(&mut m, [Key::Enter]);
        assert!(m.state == State::Confirming && !m.notice.is_empty(), "wrong device name must not start flashing");

        send(&mut m, [Key::Esc]);
        assert_eq!(m.state, State::Selecting);
    }

    #[test]
    fn empty_list() {
        let mut m = Flash::new("x.iso", 1);
        with_disks(&mut m, vec![]);
        send(&mut m, [Key::Enter]);
        assert_eq!(m.state, State::Selecting, "enter with no disks must do nothing");
        assert!(m.view().plain().contains("No USB drives found"));
    }
}
