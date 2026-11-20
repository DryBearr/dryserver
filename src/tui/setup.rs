//! The laptop setup screen shown when booting the installer USB.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ratatui::style::Color;

use super::build::KEEP_LINES;
use super::form::{Field, Form, Group, Status};
use super::{Border, Doc, Emit, Event, Flow, Key, Model, Seg, TextInput, dim, err, err_bold, ok, sel, spinner, title, truncate};
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

struct StepView {
    name: String,
    done: bool,
    start: Instant,
    took: Duration,
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
    pub confirm: TextInput,
    /// What State::Busy waits for.
    busy: String,
    steps: Vec<StepView>,
    lines: Vec<String>,
    ctx: Ctx,
    /// The first ctrl+c during install was pressed.
    armed: bool,
    pub code: String,
    pub host_num: u32,
    join_err: Option<Error>,
    check_err: Option<Error>,
    /// The install failed; r runs it again.
    can_retry: bool,
    pub err: Option<Error>,
    pub notice: String,
    height: u16,
}

const LOG_HINT: &str = "/tmp/dryserver-install.log";

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
            confirm,
            busy: String::new(),
            steps: Vec::new(),
            lines: Vec::new(),
            ctx: Ctx::new(),
            armed: false,
            code: String::new(),
            host_num: 0,
            join_err: None,
            check_err: None,
            can_retry: false,
            err: None,
            notice: String::new(),
            height: 24,
        }
    }

    fn spawn(&mut self, emit: &Emit<Msg>, job: impl FnOnce(Ctx, Arc<dyn Backend>, Emit<Msg>) + Send + 'static) {
        self.ctx = Ctx::new();
        let (ctx, be, emit) = (self.ctx.clone(), self.be.clone(), emit.clone());
        std::thread::spawn(move || job(ctx, be, emit));
    }

    pub fn handle(&mut self, ev: Event<Msg>, emit: &Emit<Msg>) -> Flow {
        match ev {
            Event::Resize(_, h) => self.height = h,
            Event::Tick => {}
            Event::Key(k) => return self.key(k, emit),
            Event::Msg(m) => self.message(m, emit),
        }
        Flow::Continue
    }

    fn message(&mut self, msg: Msg, emit: &Emit<Msg>) {
        match msg {
            Msg::Probe(Ok(m)) => {
                self.m = m;
                self.state = State::Welcome;
            }
            Msg::Probe(Err(e)) => {
                self.err = Some(e);
                self.state = State::Failed;
            }
            Msg::WifiList(res) => {
                match res {
                    Ok(l) => self.ssids = l,
                    Err(e) => {
                        self.notice = format!("WiFi scan failed: {e}");
                        self.ssids.clear();
                    }
                }
                self.open_wifi_form();
            }
            Msg::WifiConnected(res) => {
                self.state = State::Welcome;
                match res {
                    Ok(m) => {
                        self.m = m;
                        self.notice.clear();
                    }
                    Err(e) => self.notice = format!("Could not connect: {e}"),
                }
            }
            Msg::CheckDone(Some(e)) => self.check_err = Some(e),
            Msg::CheckDone(None) => {
                self.steps.clear();
                self.lines.clear();
                self.state = State::Confirm;
                self.confirm.set_value("");
                self.confirm.focus();
            }
            Msg::Step(st) => self.add_step(st),
            Msg::InstallDone(Some(e)) => {
                self.state = State::Failed;
                self.err = Some(e);
                self.can_retry = true;
            }
            Msg::InstallDone(None) => {
                if self.ch.role() == Role::Coordinator {
                    self.code = self.be.coordinator_code();
                    self.state = State::Done;
                } else {
                    self.start_join(emit);
                }
            }
            Msg::JoinCode(c) => self.code = c,
            Msg::JoinDone(res) => {
                self.state = State::Done;
                match res {
                    Ok(h) => self.host_num = h,
                    Err(e) if e.is(Kind::Rejected) => {
                        self.state = State::Failed;
                        self.err = Some(e);
                    }
                    Err(e) => self.join_err = Some(e),
                }
            }
        }
    }

    fn key(&mut self, k: Key, emit: &Emit<Msg>) -> Flow {
        match self.state {
            State::Probe | State::Busy => {
                if k == Key::Ctrl('c') {
                    return Flow::Quit;
                }
            }
            State::Check => match (&self.check_err, &k) {
                (None, Key::Ctrl('c')) => self.ctx.cancel(),
                (Some(_), Key::Char('r')) => self.start_check(emit),
                (Some(e), Key::Enter | Key::Esc) => {
                    self.notice = format!("Check failed: {e}");
                    self.open_form();
                }
                (Some(_), Key::Ctrl('c')) => return Flow::Quit,
                _ => {}
            },
            State::Welcome => match k {
                Key::Ctrl('c') | Key::Char('q') => return Flow::Quit,
                Key::Char('w') => self.scan_wifi(emit),
                Key::Enter => {
                    if !self.m.online {
                        self.scan_wifi(emit);
                    } else if self.m.disks.is_empty() {
                        self.notice = "No internal disk found to install on.".into();
                    } else {
                        self.open_form();
                    }
                }
                _ => {}
            },
            State::Form => self.update_form(&k, emit),
            State::Wifi => self.update_wifi_form(&k, emit),
            State::Confirm => match k {
                Key::Ctrl('c') => return Flow::Quit,
                Key::Esc => {
                    self.notice.clear();
                    self.open_form();
                }
                Key::Enter => {
                    if self.confirm.value.trim() != "YES" {
                        self.notice = "Type YES in capital letters, or press esc to change answers.".into();
                        return Flow::Continue;
                    }
                    self.notice.clear();
                    self.start_install(emit);
                }
                k => {
                    self.confirm.handle(&k);
                }
            },
            State::Install => {
                if k == Key::Ctrl('c') {
                    if self.armed {
                        self.ctx.cancel();
                    } else {
                        self.armed = true;
                        self.notice = "Press ctrl+c again to abort. The disk is left half-installed.".into();
                    }
                }
            }
            State::Join => {
                if k == Key::Char('s') || k == Key::Ctrl('c') {
                    self.ctx.cancel();
                }
            }
            State::Done => match k {
                Key::Enter => match self.be.reboot() {
                    Ok(()) => return Flow::Quit,
                    Err(e) => self.notice = format!("Reboot failed: {e}"),
                },
                Key::Char('q') | Key::Ctrl('c') => return Flow::Quit,
                _ => {}
            },
            State::Failed => match k {
                Key::Char('r') if self.can_retry => {
                    // Same answers; leftovers of the failed attempt are
                    // released by the partition step.
                    self.can_retry = false;
                    self.err = None;
                    self.notice.clear();
                    self.start_install(emit);
                }
                Key::Char('q') | Key::Ctrl('c') | Key::Enter => return Flow::Quit,
                _ => {}
            },
        }
        Flow::Continue
    }

    fn scan_wifi(&mut self, emit: &Emit<Msg>) {
        self.state = State::Busy;
        self.busy = "Scanning WiFi networks…".into();
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
        self.wifi_form = Some(Form::new(Wifi::default(), vec![group], "back"));
        self.state = State::Wifi;
    }

    fn update_wifi_form(&mut self, k: &Key, emit: &Emit<Msg>) {
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
                self.state = State::Busy;
                self.busy = format!("Connecting to {}…", w.ssid);
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

    fn update_form(&mut self, k: &Key, emit: &Emit<Msg>) {
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
                self.notice.clear();
                self.start_check(emit);
            }
            Status::Active => {}
        }
    }

    /// Runs the prechecks in the background, streaming steps and log lines
    /// to the screen.
    pub fn start_check(&mut self, emit: &Emit<Msg>) {
        self.state = State::Check;
        self.check_err = None;
        self.steps.clear();
        self.lines.clear();
        let (cfg, ch) = (self.cfg.clone(), self.ch.clone());
        self.spawn(emit, move |ctx, be, emit| {
            let e = emit.clone();
            let res = be.precheck(&ctx, &cfg, &ch, Arc::new(move |st| e(Msg::Step(st))));
            emit(Msg::CheckDone(res.err()));
        });
    }

    pub fn start_install(&mut self, emit: &Emit<Msg>) {
        self.state = State::Install;
        self.steps.clear();
        self.lines.clear();
        self.confirm.blur();
        let (cfg, ch) = (self.cfg.clone(), self.ch.clone());
        self.spawn(emit, move |ctx, be, emit| {
            let e = emit.clone();
            let res = be.install(&ctx, &cfg, &ch, Arc::new(move |st| e(Msg::Step(st))));
            emit(Msg::InstallDone(res.err()));
        });
    }

    fn start_join(&mut self, emit: &Emit<Msg>) {
        self.state = State::Join;
        self.notice.clear();
        let (cfg, ch) = (self.cfg.clone(), self.ch.clone());
        self.spawn(emit, move |ctx, be, emit| {
            let e = emit.clone();
            let res = be.join(&ctx, &cfg, &ch, &move |code| e(Msg::JoinCode(code)));
            emit(Msg::JoinDone(res));
        });
    }

    fn add_step(&mut self, st: Step) {
        if !st.log.is_empty() {
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
            }
            return;
        }
        self.steps.push(StepView { name: st.name, done: st.done, start: Instant::now(), took: Duration::ZERO });
    }

    pub fn view(&self) -> Doc {
        let mut b = Doc::new();
        b.add(title("dryserver · server setup")).s("\n\n");
        match self.state {
            State::Probe => {
                b.s(format!("{} Looking at this machine…\n", spinner()));
            }
            State::Busy => {
                b.s(format!("{} {}\n", spinner(), self.busy));
            }
            State::Check => {
                b.s("Checking before anything is erased:\n\n");
                self.view_install(&mut b);
                match &self.check_err {
                    Some(e) => {
                        b.nl().add(err(e.to_string())).nl();
                        b.add(dim(format!("r retry · enter back to the answers · full log: {LOG_HINT}"))).nl();
                    }
                    None => {
                        b.nl().add(dim("Nothing has been changed yet. ctrl+c stops the check.")).nl();
                    }
                }
            }
            State::Welcome => self.view_welcome(&mut b),
            State::Form => {
                if let Some(f) = &self.form {
                    b.append(f.view());
                }
            }
            State::Wifi => {
                if let Some(f) = &self.wifi_form {
                    b.append(f.view());
                }
            }
            State::Confirm => self.view_confirm(&mut b),
            State::Install => self.view_install(&mut b),
            State::Join => self.view_join(&mut b),
            State::Done => self.view_done(&mut b),
            State::Failed => {
                let e = self.err.as_ref().map(|e| e.to_string()).unwrap_or_default();
                b.add(err(format!("Setup failed: {e}"))).s("\n\n");
                if !self.lines.is_empty() {
                    for l in &self.lines[self.lines.len().saturating_sub(10)..] {
                        b.add(dim(truncate(l, 200))).nl();
                    }
                    b.nl();
                }
                if self.can_retry {
                    b.add(dim(format!("r: retry the install with the same answers · enter/q: leave to a shell (log: {LOG_HINT})"))).nl();
                } else {
                    b.add(dim(format!("enter/q: leave to a shell (log: {LOG_HINT}) · run 'dryserver install' to start over"))).nl();
                }
            }
        }
        if !self.notice.is_empty() {
            b.nl().add(err(&self.notice)).nl();
        }
        b
    }

    fn view_welcome(&self, b: &mut Doc) {
        let m = &self.m;
        let row = |b: &mut Doc, name: &str, value: Seg| {
            b.s(format!("  {name:<9} ")).add(value).nl();
        };
        row(b, "CPU", Seg(m.cpu.clone(), Default::default()));
        row(b, "Memory", Seg(human_size(m.ram), Default::default()));
        row(b, "Firmware", if m.uefi { ok("UEFI") } else { dim("legacy BIOS") });
        row(
            b,
            "TPM 2.0",
            if m.tpm2 {
                ok("yes")
            } else if m.tpm_chip {
                dim("chip found, but the firmware does not measure boot (no auto-unlock)")
            } else {
                dim("no")
            },
        );
        row(b, "Network", if m.online { ok(&m.net) } else { err("not connected") });
        let ip = &self.cfg.coord_lan_ip;
        if m.coord_found {
            row(b, "Mesh", ok(format!("coordinator {ip} answers: install this laptop as a server")));
        } else if m.online {
            row(b, "Mesh", dim(format!("no coordinator at {ip} yet: the first laptop becomes the coordinator")));
        }
        b.s("\n  Disks:\n");
        if m.disks.is_empty() {
            b.add(err("    none found")).nl();
            b.add(dim("    If the laptop has a disk: in its BIOS setup, set the storage/SATA mode\n    from RAID or Intel RST to AHCI (and turn off VMD if listed).")).nl();
        }
        for d in &m.disks {
            b.s(format!("    {}\n", disk_title(d)));
        }
        b.nl();
        if m.online {
            b.add(dim("enter start setup · w other WiFi · q quit to shell")).nl();
        } else {
            b.add(dim("enter connect to WiFi (or plug in a cable and restart) · q quit to shell")).nl();
        }
    }

    fn disk_by_path(&self, path: &str) -> Disk {
        self.m.disks.iter().find(|d| d.path == path).cloned().unwrap_or_else(|| Disk {
            path: path.into(),
            name: path.into(),
            ..Disk::default()
        })
    }

    fn view_confirm(&self, b: &mut Doc) {
        let ch = &self.ch;
        let mut w = Doc::new();
        w.add(err_bold("THESE DISKS WILL BE ERASED")).s("\n\n");
        w.s(disk_title(&self.disk_by_path(&ch.system_disk))).nl();
        for d in &ch.data_disks {
            w.s(format!("{}  → /data\n", disk_title(&self.disk_by_path(d))));
        }
        b.append(w.boxed(Border::Rounded, Color::LightRed, 1, 0, false)).s("\n\n");

        let row = |b: &mut Doc, name: &str, value: Seg| {
            b.s(format!("  {name:<11} ")).add(value).nl();
        };
        let role =
            if ch.role() == Role::Coordinator { "COORDINATOR (first machine)" } else { "SERVER (joins the mesh after your approval)" };
        row(b, "Role", sel(role));
        row(b, "Hostname", super::plain(&ch.hostname));
        row(b, "Encryption", super::plain(enc_title(ch.enc(), false)));
        row(b, "User", super::plain(format!("{} (password set)", self.cfg.username)));
        let mut tools = self.cfg.tool_list();
        tools.extend(self.cfg.extra_list());
        row(b, "Tools", super::plain(format!("basics {}", tools.join(" "))));
        let w = role_warning(&self.m, &self.cfg, ch.role());
        if !w.is_empty() {
            b.nl().add(err(w)).nl();
        }
        b.nl();
        b.s("Type ").add(sel("YES")).s(" to erase and install: ").append(self.confirm.view()).nl();
        b.nl().add(dim("enter confirm · esc change answers")).nl();
    }

    fn view_install(&self, b: &mut Doc) {
        for (i, st) in self.steps.iter().enumerate() {
            if st.done {
                b.add(ok("  ✓ ")).s(&st.name).add(dim(format!("  {}", super::dur(st.took)))).nl();
            } else if i == self.steps.len() - 1 {
                b.s(format!("  {} {}", spinner(), st.name)).add(dim(format!("  {}", super::since(st.start)))).nl();
            } else {
                b.s(format!("    {}\n", st.name));
            }
        }
        b.nl();
        let n = (self.height as usize).saturating_sub(self.steps.len() + 9).max(3);
        for l in &self.lines[self.lines.len().saturating_sub(n)..] {
            b.add(dim(truncate(l, 200))).nl();
        }
    }

    fn view_join(&self, b: &mut Doc) {
        if self.code.is_empty() {
            b.s(format!("{} Sending join request to the coordinator at {}…\n", spinner(), self.cfg.coord_lan_ip));
            return;
        }
        b.s("Installed. Now approve this machine on your own computer:\n\n");
        b.s("  ").add(sel("./dryserver approve")).s("\n\n");
        b.s("Approve only if it shows the same code:\n\n");
        let mut code = Doc::new();
        code.s(&self.code);
        b.append(code.boxed(Border::Double, Color::LightBlue, 4, 1, true)).s("\n\n");
        b.s(format!("{} Waiting for approval…\n\n", spinner()));
        b.add(dim("s skip: the server asks again after reboot and shows the code on its screen")).nl();
    }

    fn view_done(&self, b: &mut Doc) {
        if self.ch.role() == Role::Coordinator {
            b.add(ok("Coordinator installed.")).s("\n\n");
            b.s("No machine can join until you sign this coordinator. On your own computer run:\n\n");
            b.s("  ").add(sel("./dryserver approve")).s("   and press S\n\n");
            if !self.code.is_empty() {
                b.s("Sign only if it shows the same code:\n\n");
                let mut code = Doc::new();
                code.s(&self.code);
                b.append(code.boxed(Border::Double, Color::LightBlue, 4, 1, true)).s("\n\n");
                b.add(dim("The code is also on this machine's screen after it restarts, until you signed.")).nl();
            }
        } else if let Some(e) = &self.join_err {
            b.add(ok("Installed.")).s(format!(" Joining was skipped or failed: {e}\n"));
            b.s("After reboot the server asks again and shows the code on its screen.\n");
        } else {
            b.add(ok("Installed and approved.")).s(format!(" Mesh address: {}\n", mesh_ip(&self.cfg, self.host_num)));
        }
        if self.ch.enc() == Encryption::Tpm {
            b.s("\nAt the first boot, type the disk passphrase once. After that the TPM\nunlocks the disk by itself.\n");
        }
        b.s("\nRemove the USB stick, then press ").add(sel("enter")).s(" to reboot.\n");
        b.add(dim("q: stay in the live system")).nl();
    }
}

impl Model for Setup {
    type Msg = Msg;

    fn init(&mut self, emit: &Emit<Msg>) {
        self.spawn(emit, |ctx, be, emit| emit(Msg::Probe(be.probe(&ctx))));
    }

    fn update(&mut self, ev: Event<Msg>, emit: &Emit<Msg>) -> Flow {
        self.handle(ev, emit)
    }

    fn view(&self) -> Doc {
        Setup::view(self)
    }
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
    let has: Vec<&str> = d
        .parts
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
        .collect();
    let mut t = format!("{}  {}  {}", d.name, human_size(d.size), format!("{} {}", d.vendor, d.model).trim());
    if !has.is_empty() {
        t += &format!("  (has: {})", has.join(", "));
    }
    t
}

fn setup_form(m: &Machine, cfg: &Config, answers: Answers) -> Form<Answers> {
    let disk_opts: Vec<(String, String)> = m.disks.iter().map(|d| (disk_title(d), d.path.clone())).collect();
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
                Field::select(
                    "Install on which disk?",
                    move |_| disk_opts.clone(),
                    |a: &Answers| a.ch.system_disk.clone(),
                    |a, v| a.ch.system_disk = v,
                )
                .desc("Everything on this disk will be erased."),
            ]),
            Group::new(vec![
                Field::multi(
                    "Also use these disks for data? (optional)",
                    move |a: &Answers| all_disks.iter().filter(|(_, p)| *p != a.ch.system_disk).cloned().collect(),
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
    use crate::tui::{collector, type_text};
    use std::sync::mpsc::Receiver;

    struct T {
        s: Setup,
        emit: Emit<Msg>,
        rx: Receiver<Msg>,
    }

    impl T {
        fn send(&mut self, ev: Event<Msg>) {
            self.s.handle(ev, &self.emit);
        }

        fn keys(&mut self, keys: impl IntoIterator<Item = Key>) {
            for k in keys {
                self.send(Event::Key(k));
            }
        }

        /// Feeds background events into the model while it waits.
        fn drain(&mut self, while_in: &[State]) {
            while while_in.contains(&self.s.state) {
                let m = self.rx.recv_timeout(Duration::from_secs(10)).expect("background job never finished");
                self.send(Event::Msg(m));
            }
        }

        fn view(&self) -> String {
            self.s.view().plain()
        }
    }

    fn demo(f: impl FnOnce(&mut install::Demo)) -> Arc<install::Demo> {
        let mut d = install::Demo::new();
        d.delay = Duration::ZERO;
        f(&mut d);
        Arc::new(d)
    }

    fn demo_setup(role: Role, enc: Encryption, d: Arc<install::Demo>) -> T {
        let cfg = Config { coord_lan_ip: "192.168.1.50".into(), ..Config::default() };
        let m = d.probe(&Ctx::new()).unwrap();
        let (emit, rx) = collector();
        let mut t = T { s: Setup::new(d, cfg), emit, rx };
        t.send(Event::Msg(Msg::Probe(Ok(m))));
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

    #[test]
    fn welcome_shows_machine() {
        let t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        let v = t.view();
        for want in ["TPM 2.0   yes", "UEFI", "nvme0n1", "has: vfat, Windows", "WiFi Home"] {
            assert!(v.contains(want), "welcome missing {want:?}:\n{v}");
        }
    }

    #[test]
    fn check_shows_steps_then_confirm() {
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        let emit = t.emit.clone();
        t.s.start_check(&emit);
        t.drain(&[State::Check]);
        assert_eq!(t.s.state, State::Confirm, "err {:?}", t.s.check_err);
        assert!(t.s.steps.is_empty() && t.s.lines.is_empty(), "check log must be cleared before the install screen");
    }

    #[test]
    fn check_failure_offers_retry() {
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        t.s.state = State::Check;
        t.send(Event::Msg(Msg::Step(Step::start("Update package lists"))));
        t.send(Event::Msg(Msg::Step(Step::line("error: failed retrieving file"))));
        t.send(Event::Msg(Msg::CheckDone(Some("cannot reach the package mirrors".into()))));
        let v = t.view();
        for want in ["Update package lists", "failed retrieving file", "cannot reach the package mirrors", "r retry"] {
            assert!(v.contains(want), "check screen missing {want:?}:\n{v}");
        }
        t.keys([Key::Enter]);
        assert!(
            t.s.state == State::Form && t.s.notice.contains("cannot reach"),
            "enter must go back to the answers: {:?} {:?}",
            t.s.state,
            t.s.notice
        );
    }

    #[test]
    fn confirm_needs_yes() {
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        t.send(Event::Msg(Msg::CheckDone(None)));
        assert!(t.s.state == State::Confirm && t.view().contains("THESE DISKS WILL BE ERASED"));
        t.keys(type_text("yes"));
        t.keys([Key::Enter]);
        assert!(t.s.state == State::Confirm && !t.s.notice.is_empty(), "lowercase yes must not start the install");
        t.s.confirm.set_value("");
        t.keys(type_text("YES"));
        t.keys([Key::Enter]);
        assert_eq!(t.s.state, State::Install);
        t.s.ctx.cancel();
    }

    #[test]
    fn node_install_and_join() {
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        let emit = t.emit.clone();
        t.s.start_install(&emit);
        t.drain(&[State::Install, State::Join]);
        assert!(t.s.state == State::Done && t.s.host_num == 7 && t.s.code == "482 913", "state {:?} err {:?}", t.s.state, t.s.err);
        assert!(t.s.steps.iter().all(|s| s.done), "steps not done");
        let v = t.view();
        assert!(v.contains("passphrase once"), "TPM mode must tell about the first-boot passphrase:\n{v}");
        assert!(v.contains("Mesh address: 10.66.0.7"), "done screen:\n{v}");
    }

    #[test]
    fn coordinator_skips_join() {
        let mut t = demo_setup(Role::Coordinator, Encryption::Passphrase, demo(|_| {}));
        let emit = t.emit.clone();
        t.s.start_install(&emit);
        t.drain(&[State::Install, State::Join]);
        assert!(t.s.state == State::Done && t.s.code == "305 771", "the coordinator's own code must be shown: {:?}", t.s.code);
        let v = t.view();
        assert!(!v.contains("passphrase once"), "passphrase mode has no first-boot TPM step");
        assert!(
            v.contains("./dryserver approve") && v.contains("press S") && v.contains("305 771") && !v.contains("sudo dryserver approve"),
            "coordinator done screen must explain approving:\n{v}"
        );
    }

    #[test]
    fn join_rejected() {
        let d = demo(|d| d.approve = Some(Box::new(|| Err(Error::with_kind(Kind::Rejected, install::REJECTED)))));
        let mut t = demo_setup(Role::Node, Encryption::None, d);
        let emit = t.emit.clone();
        t.s.start_install(&emit);
        t.drain(&[State::Install, State::Join]);
        assert!(t.s.state == State::Failed && t.view().contains("rejected"), "{:?}\n{}", t.s.state, t.view());
    }

    #[test]
    fn role_defaults_from_network() {
        for (found, want) in [(false, Role::Coordinator), (true, Role::Node)] {
            let d = demo(|d| d.machine.get_mut().unwrap().coord_found = found);
            let cfg = Config { coord_lan_ip: "10.1.0.60".into(), ..Config::default() };
            let m = d.probe(&Ctx::new()).unwrap();
            let (emit, _rx) = collector();
            let mut s = Setup::new(d, cfg);
            s.handle(Event::Msg(Msg::Probe(Ok(m))), &emit);
            s.open_form();
            assert_eq!(s.ch.role, Some(want), "coordinator found={found}");
        }
    }

    #[test]
    fn confirm_warns_about_role() {
        let mut t = demo_setup(Role::Node, Encryption::None, demo(|_| {}));
        t.s.m.coord_found = false;
        t.send(Event::Msg(Msg::CheckDone(None)));
        let v = t.view();
        assert!(v.contains("choose coordinator") && v.contains("SERVER"), "server without coordinator must warn:\n{v}");
        let mut t = demo_setup(Role::Coordinator, Encryption::None, demo(|_| {}));
        t.send(Event::Msg(Msg::CheckDone(None)));
        assert!(t.view().contains("separate mesh"), "second coordinator must warn:\n{}", t.view());
    }

    #[test]
    fn install_failure_offers_retry() {
        let mut t = demo_setup(Role::Node, Encryption::None, demo(|_| {}));
        t.s.state = State::Install;
        t.send(Event::Msg(Msg::InstallDone(Some("Install packages: downloads failed".into()))));
        assert!(t.view().contains("r: retry the install"), "no retry offered:\n{}", t.view());
        t.keys([Key::Char('r')]);
        assert_eq!(t.s.state, State::Install, "r must restart the install");
        t.drain(&[State::Install, State::Join]);
        assert_eq!(t.s.state, State::Done, "retry did not finish: {:?}", t.s.err);
    }

    #[test]
    fn form_runs_to_the_check() {
        let mut t = demo_setup(Role::Node, Encryption::Tpm, demo(|_| {}));
        t.s.ch = Choices::default();
        t.s.open_form();
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
        assert!(t.view().contains("does not match"));
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
}
