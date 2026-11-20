//! Runs the ISO build and shows the tail of its log.

use std::time::{Duration, Instant};

use super::{Doc, Emit, Event, Key, dim, err, faint, ok, sel, spinner, theme, truncate};
use crate::ctx::Ctx;
use crate::err::Error;
use crate::iso::{self, Options};
use crate::runner::LineWriter;

pub const KEEP_LINES: usize = 500;

pub enum Msg {
    Log(String),
    Done(Option<Error>),
}

/// What the build screen asks its parent to do.
#[derive(Debug, PartialEq)]
pub enum Out {
    Stay,
    Back,
    Quit,
}

pub struct Build {
    opts: Options,
    lines: Vec<String>,
    ctx: Ctx,
    started: Instant,
    elapsed: Duration,
    running: bool,
    stopping: bool,
    err: Option<Error>,
    pub height: u16,
}

impl Build {
    pub fn new(opts: Options) -> Build {
        Build {
            opts,
            lines: Vec::new(),
            ctx: Ctx::new(),
            started: Instant::now(),
            elapsed: Duration::ZERO,
            running: false,
            stopping: false,
            err: None,
            height: 24,
        }
    }

    /// Launches the build in the background. Called once when the screen opens.
    pub fn start(&mut self, emit: Emit<Msg>) {
        self.running = true;
        self.started = Instant::now();
        let (ctx, opts) = (self.ctx.clone(), self.opts.clone());
        std::thread::spawn(move || {
            let e = emit.clone();
            let mut w = LineWriter::new(std::sync::Arc::new(move |l: &str| e(Msg::Log(l.to_string()))));
            let res = iso::run(&ctx, &opts, &mut w);
            w.finish();
            emit(Msg::Done(res.err()));
        });
    }

    pub fn update(&mut self, ev: Event<Msg>) -> Out {
        match ev {
            Event::Resize(_, h) => self.height = h,
            Event::Msg(Msg::Log(l)) => {
                self.lines.push(l);
                if self.lines.len() > KEEP_LINES {
                    self.lines.drain(..self.lines.len() - KEEP_LINES);
                }
            }
            Event::Msg(Msg::Done(e)) => {
                self.running = false;
                self.err = e;
                self.elapsed = self.started.elapsed();
            }
            Event::Key(k) => {
                if self.running {
                    if k == Key::Ctrl('c') && !self.stopping {
                        self.stopping = true;
                        self.ctx.cancel();
                    }
                } else {
                    match k {
                        Key::Ctrl('c') => return Out::Quit,
                        Key::Enter | Key::Esc | Key::Char('q') => return Out::Back,
                        _ => {}
                    }
                }
            }
            Event::Tick => {}
        }
        Out::Stay
    }

    pub fn view(&self) -> Doc {
        let mut b = Doc::new();
        let iso = iso::iso_path(&self.opts.out_dir).display().to_string();
        b.append(theme::header("build installer ISO")).s("\n\n");
        match (&self.err, self.running) {
            (_, true) if self.stopping => {
                b.add(err("Stopping build…")).nl();
            }
            (_, true) => {
                b.add(sel(spinner())).s(format!(" Building {iso}  ")).add(dim(super::since(self.started))).nl();
            }
            (Some(e), false) if e.is_canceled() => {
                b.add(err("Build cancelled.")).nl();
            }
            (Some(e), false) => {
                b.add(err(format!("Build failed: {e}"))).nl();
            }
            (None, false) => {
                b.add(ok(format!("ISO built in {}: {iso}", super::dur(self.elapsed)))).nl();
            }
        }
        b.nl();
        // Show as much of the log tail as fits under the header and above the footer.
        let n = (self.height as usize).saturating_sub(8).max(5);
        for l in &self.lines[self.lines.len().saturating_sub(n)..] {
            b.add(faint(truncate(l, 200))).nl();
        }
        b.nl();
        if self.running {
            b.add(dim("First build downloads ~1 GB and takes several minutes. ctrl+c cancels.")).nl();
        } else {
            b.append(theme::keys(&[("enter", "back to menu")]))
                .add(dim(format!("   full log in {}/{}", self.opts.out_dir.display(), iso::LOG_NAME)))
                .nl();
        }
        b
    }
}
