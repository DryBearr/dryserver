//! Runs external commands for the installer and node tools, logging each
//! command line and its output. Secrets travel in stdin or env, which are
//! never logged.

use std::fmt;
use std::io::{self, Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::ctx::Ctx;
use crate::err::{Error, Result, os_msg};
use crate::errf;

/// One command to run.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Cmd {
    pub name: String,
    pub args: Vec<String>,
    pub stdin: String,
    pub env: Vec<String>,
    /// Do not log output (key material).
    pub quiet: bool,
    /// Return only stdout (e.g. JSON replies); stderr is still logged
    /// unless quiet.
    pub stdout_only: bool,
}

impl Cmd {
    pub fn new<S: AsRef<str>>(name: &str, args: &[S]) -> Cmd {
        Cmd { name: name.to_string(), args: args.iter().map(|a| a.as_ref().to_string()).collect(), ..Cmd::default() }
    }

    pub fn stdin(mut self, s: impl Into<String>) -> Cmd {
        self.stdin = s.into();
        self
    }

    pub fn quiet(mut self) -> Cmd {
        self.quiet = true;
        self
    }

    pub fn stdout_only(mut self) -> Cmd {
        self.stdout_only = true;
        self
    }
}

impl fmt::Display for Cmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = format!("{} {}", self.name, self.args.join(" "));
        f.write_str(s.trim())
    }
}

/// Runs commands. Tests use fakes that record them.
pub trait Runner: Send + Sync {
    /// Runs c and returns its output, also when it fails.
    fn run(&self, ctx: &Ctx, c: &Cmd) -> (String, Result<()>);

    /// Runs c and returns its output only when it succeeds.
    fn output(&self, ctx: &Ctx, c: &Cmd) -> Result<String> {
        let (out, res) = self.run(ctx, c);
        res.map(|_| out)
    }

    /// Runs c for its success only.
    fn ok(&self, ctx: &Ctx, c: &Cmd) -> Result<()> {
        self.run(ctx, c).1
    }
}

pub type LogFn = Arc<dyn Fn(&str) + Send + Sync>;

/// Runs commands for real and sends the command line and each output line
/// to log.
#[derive(Clone)]
pub struct ExecRunner {
    pub log: LogFn,
}

impl ExecRunner {
    pub fn new(log: LogFn) -> ExecRunner {
        ExecRunner { log }
    }

    /// A runner that logs nothing.
    pub fn silent() -> ExecRunner {
        ExecRunner { log: Arc::new(|_| {}) }
    }
}

impl Runner for ExecRunner {
    fn run(&self, ctx: &Ctx, c: &Cmd) -> (String, Result<()>) {
        (self.log)(&format!("$ {c}"));
        let emit: LogFn = if c.quiet { Arc::new(|_| {}) } else { self.log.clone() };
        let (out, err_out, res) = match exec(ctx, c, emit) {
            Ok(r) => r,
            Err(e) => (String::new(), String::new(), Err(e)),
        };
        match res {
            Ok(()) => (out, Ok(())),
            Err(e) => {
                let tail = last_line(&format!("{out}{err_out}"), c.quiet);
                let e = errf!("{} failed: {e}{tail}", c.name);
                (out, Err(e))
            }
        }
    }
}

type Exec = (String, String, Result<()>);

fn exec(ctx: &Ctx, c: &Cmd, emit: LogFn) -> Result<Exec> {
    let mut cmd = Command::new(&c.name);
    cmd.args(&c.args);
    for e in &c.env {
        if let Some((k, v)) = e.split_once('=') {
            cmd.env(k, v);
        }
    }
    cmd.stdin(if c.stdin.is_empty() { Stdio::null() } else { Stdio::piped() });
    // Without stdout_only, stdout and stderr share one pipe so their lines
    // keep their order.
    let (out_r, out_w) = io::pipe()?;
    let err_r = if c.stdout_only {
        let (r, w) = io::pipe()?;
        cmd.stderr(w);
        Some(r)
    } else {
        cmd.stderr(out_w.try_clone()?);
        None
    };
    cmd.stdout(out_w);
    // A program written a moment ago (a new dryserver binary before its
    // self check, a test's fake tool) can still be open for writing in a
    // child that another thread forked at that instant, until that child
    // execs. Linux refuses to run it meanwhile (ETXTBSY), so try again
    // briefly instead of failing.
    let mut busy = 0;
    let mut child = loop {
        match cmd.spawn() {
            Ok(ch) => break ch,
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) && busy < 40 => {
                busy += 1;
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok((String::new(), String::new(), Err(errf!("exec: {:?}: executable file not found in $PATH", c.name))));
            }
            Err(e) => return Ok((String::new(), String::new(), Err(Error::new(os_msg(&e))))),
        }
    };
    drop(cmd); // closes this side's copies of the pipe write ends

    let out = Arc::new(Mutex::new(Lines::new(emit.clone())));
    let err_lines = Arc::new(Mutex::new(Lines::new(emit)));
    let status = std::thread::scope(|s| {
        if let Some(mut stdin) = child.stdin.take() {
            let data = c.stdin.clone();
            s.spawn(move || {
                let _ = stdin.write_all(data.as_bytes());
            });
        }
        let o = out.clone();
        s.spawn(move || copy_lines(out_r, &o));
        if let Some(r) = err_r {
            let e = err_lines.clone();
            s.spawn(move || copy_lines(r, &e));
        }
        wait_child(ctx, &mut child)
    });
    let out = std::mem::take(&mut out.lock().unwrap().all);
    let err_out = std::mem::take(&mut err_lines.lock().unwrap().all);
    let res = match status {
        Ok(st) if st.success() => Ok(()),
        Ok(st) => Err(Error::new(exit_text(st))),
        Err(e) => Err(e),
    };
    Ok((String::from_utf8_lossy(&out).into_owned(), String::from_utf8_lossy(&err_out).into_owned(), res))
}

/// Waits for the child, killing it when ctx is done.
fn wait_child(ctx: &Ctx, child: &mut std::process::Child) -> Result<ExitStatus> {
    loop {
        if let Some(st) = child.try_wait()? {
            return Ok(st);
        }
        if ctx.done() {
            let _ = child.kill();
            return Ok(child.wait()?);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn copy_lines(mut r: io::PipeReader, lines: &Mutex<Lines>) {
    let mut buf = [0u8; 8192];
    loop {
        match r.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => lines.lock().unwrap().write(&buf[..n]),
        }
    }
    lines.lock().unwrap().flush();
}

/// Describes how a process ended, like Go's exec.ExitError.
pub fn exit_text(st: ExitStatus) -> String {
    if let Some(code) = st.code() {
        return format!("exit status {code}");
    }
    match st.signal() {
        Some(9) => "signal: killed".into(),
        Some(15) => "signal: terminated".into(),
        Some(2) => "signal: interrupt".into(),
        Some(6) => "signal: aborted".into(),
        Some(n) => format!("signal {n}"),
        None => "exit status unknown".into(),
    }
}

fn last_line(s: &str, quiet: bool) -> String {
    let s = s.trim();
    if quiet || s.is_empty() {
        return String::new();
    }
    let last = s.rsplit('\n').next().unwrap_or(s);
    format!(": {last}")
}

/// Collects output and emits it line by line; carriage returns (progress
/// bars) also end a line.
/// The most output kept from one command (the rest is still logged line
/// by line).
pub const MAX_KEPT: usize = 32 << 20;
/// The longest line logged in one piece.
pub const MAX_LINE: usize = 64 << 10;

pub struct Lines {
    emit: LogFn,
    pub all: Vec<u8>,
    pending: Vec<u8>,
}

impl Lines {
    pub fn new(emit: LogFn) -> Lines {
        Lines { emit, all: Vec::new(), pending: Vec::new() }
    }

    pub fn write(&mut self, p: &[u8]) {
        // Kept up to a limit: what a command prints may come from another
        // machine (ssh), and nobody gets to fill this one's memory.
        let room = MAX_KEPT.saturating_sub(self.all.len());
        self.all.extend_from_slice(&p[..p.len().min(room)]);
        self.pending.extend_from_slice(p);
        while let Some(i) = self.pending.iter().position(|&b| b == b'\r' || b == b'\n') {
            let line = String::from_utf8_lossy(&self.pending[..i]).trim().to_string();
            if !line.is_empty() {
                (self.emit)(&line);
            }
            self.pending.drain(..=i);
        }
        // A line that never ends (one more way to fill this one's memory)
        // is logged in pieces.
        if self.pending.len() > MAX_LINE {
            self.flush();
        }
    }

    pub fn flush(&mut self) {
        let line = String::from_utf8_lossy(&self.pending).trim().to_string();
        if !line.is_empty() {
            (self.emit)(&line);
        }
        self.pending.clear();
    }
}

/// An io::Write that splits what it gets into lines for emit.
pub struct LineWriter(pub Lines);

impl LineWriter {
    pub fn new(emit: LogFn) -> LineWriter {
        LineWriter(Lines::new(emit))
    }

    pub fn finish(&mut self) {
        self.0.flush();
        self.0.all.clear();
    }
}

impl Write for LineWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf);
        self.0.all.clear();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kept_output_has_a_ceiling() {
        let mut l = Lines::new(Arc::new(|_| {}));
        let chunk = vec![b'x'; 1 << 20];
        for _ in 0..40 {
            l.write(&chunk);
            l.write(b"\n");
        }
        assert_eq!(l.all.len(), MAX_KEPT, "a command that prints for ever must not fill the memory");
        // Nor one line that never ends.
        let (emit, got) = collect();
        let mut l = Lines::new(emit);
        for _ in 0..40 {
            l.write(&chunk);
        }
        assert!(l.pending.len() <= MAX_LINE + chunk.len(), "{}", l.pending.len());
        assert!(got.lock().unwrap().len() >= 39 && l.all.len() == MAX_KEPT);
    }

    fn collect() -> (LogFn, Arc<Mutex<Vec<String>>>) {
        let got = Arc::new(Mutex::new(Vec::new()));
        let g = got.clone();
        (Arc::new(move |l: &str| g.lock().unwrap().push(l.to_string())), got)
    }

    #[test]
    fn line_writer_splits_on_cr_and_lf() {
        let (emit, got) = collect();
        let mut w = LineWriter::new(emit);
        w.write_all(b"one\ntw").unwrap();
        w.write_all(b"o\r\n 50%\r100%\nlast").unwrap();
        w.finish();
        assert_eq!(got.lock().unwrap().join("|"), "one|two|50%|100%|last");
    }

    #[test]
    fn exec_runner_output_and_errors() {
        let (log, got) = collect();
        let r = ExecRunner::new(log);
        let ctx = Ctx::new();
        let out = r.output(&ctx, &Cmd::new("sh", &["-c", "echo out; echo err >&2"])).unwrap();
        assert!(out.contains("out") && out.contains("err"), "{out:?}");
        let logged = got.lock().unwrap().join("\n");
        assert!(logged.starts_with("$ sh -c"), "{logged}");

        let out = r.output(&ctx, &Cmd::new("sh", &["-c", "echo json; echo noise >&2"]).stdout_only()).unwrap();
        assert_eq!(out, "json\n");

        let (_, res) = r.run(&ctx, &Cmd::new("sh", &["-c", "echo first; echo boom; exit 3"]));
        assert_eq!(res.unwrap_err().to_string(), "sh failed: exit status 3: boom");

        let (_, res) = r.run(&ctx, &Cmd::new("sh", &["-c", "echo secret; exit 1"]).quiet());
        assert_eq!(res.unwrap_err().to_string(), "sh failed: exit status 1");

        let out = r.output(&ctx, &Cmd::new("cat", &[] as &[&str]).stdin("from stdin")).unwrap();
        assert_eq!(out, "from stdin");

        let (_, res) = r.run(&ctx, &Cmd::new("no-such-command-dryserver", &[] as &[&str]));
        assert!(res.unwrap_err().to_string().contains("executable file not found"));
    }

    #[test]
    fn exec_runner_cancel_kills() {
        let r = ExecRunner::silent();
        let ctx = Ctx::new();
        let c2 = ctx.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            c2.cancel();
        });
        let start = std::time::Instant::now();
        let (_, res) = r.run(&ctx, &Cmd::new("sleep", &["10"]));
        assert!(res.unwrap_err().to_string().contains("signal: killed"));
        assert!(start.elapsed() < Duration::from_secs(5));
    }
}
