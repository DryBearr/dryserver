//! The main menu tying config, build and flash together.

use std::path::PathBuf;
use std::time::SystemTime;

use super::build::{Build, Out};
use super::flash::Flash;
use super::form::{Field, Form, Group, Status};
use super::{Doc, Emit, Event, Flow, Key, Model, Seg, build, dim, err, flash, ok, sel, theme};
use crate::config::{self, Config};
use crate::err::Error;
use crate::iso::{self, Options};
use crate::{fsx, owner, packages};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Menu,
    Config,
    Build,
    Flash,
}

const MENU: [(&str, &str); 7] = [
    ("1", "Edit config"),
    ("2", "Build installer ISO"),
    ("3", "Flash USB"),
    ("4", "Machines: approve, remove, replace"),
    ("5", "Apps: what runs on your cluster"),
    ("6", "Outside: the ways in from the internet"),
    ("q", "Quit"),
];

pub enum Msg {
    Build(build::Msg),
    Flash(flash::Msg),
}

/// What the config form edits: the config plus the tool list, joined into
/// cfg.tools on save.
pub struct ConfigAnswers {
    cfg: Config,
    tools: Vec<String>,
}

pub struct App {
    paths: Paths,
    pub screen: Screen,
    cursor: usize,
    pub notice: String,
    cfg: Config,
    cfg_err: Option<Error>,
    /// Size and modification time of the built ISO.
    iso: Option<(u64, SystemTime)>,
    root: bool,
    form: Option<Form<ConfigAnswers>>,
    build: Option<Build>,
    flash: Option<Flash>,
    width: u16,
    height: u16,
    /// Set when the menu closes to open the machines screen; the caller
    /// runs it and comes back.
    pub open_machines: bool,
    /// The same for the apps or outside screen.
    pub open_cluster: Option<super::Place>,
}

fn build_emit(emit: &Emit<Msg>) -> Emit<build::Msg> {
    let e = emit.clone();
    std::sync::Arc::new(move |m| e(Msg::Build(m)))
}

fn flash_emit(emit: &Emit<Msg>) -> Emit<flash::Msg> {
    let e = emit.clone();
    std::sync::Arc::new(move |m| e(Msg::Flash(m)))
}

impl App {
    pub fn new(paths: Paths) -> App {
        let mut a = App {
            paths,
            screen: Screen::Menu,
            cursor: 0,
            notice: String::new(),
            cfg: Config::default(),
            cfg_err: None,
            iso: None,
            root: fsx::is_root(),
            form: None,
            build: None,
            flash: None,
            width: 0,
            height: 24,
            open_machines: false,
            open_cluster: None,
        };
        a.refresh();
        a
    }

    fn refresh(&mut self) {
        let (cfg, e) = Config::load_partial(&self.paths.config);
        self.cfg = cfg;
        self.cfg_err = e.or_else(|| self.cfg.validate().err());
        self.iso =
            std::fs::metadata(iso::iso_path(&self.paths.out_dir)).ok().map(|m| (m.len(), m.modified().unwrap_or(SystemTime::UNIX_EPOCH)));
    }

    fn back(&mut self, notice: String) {
        self.screen = Screen::Menu;
        self.notice = notice;
        self.build = None;
        self.flash = None;
        self.form = None;
        self.refresh();
    }

    fn choose(&mut self, k: &str, emit: &Emit<Msg>) -> Flow {
        self.notice.clear();
        match k {
            "1" => self.open_form(),
            "2" => {
                if self.cfg_err.is_some() {
                    self.notice = "Fix the config first (1).".into();
                    return Flow::Continue;
                }
                let mut b = Build::new(Options {
                    config: self.cfg.clone(),
                    out_dir: self.paths.out_dir.clone(),
                    secrets_dir: self.paths.secrets.clone(),
                });
                b.height = self.height;
                b.start(build_emit(emit));
                self.build = Some(b);
                self.screen = Screen::Build;
            }
            "3" => {
                let Some((size, _)) = self.iso else {
                    self.notice = "Build the ISO first (2).".into();
                    return Flow::Continue;
                };
                if !self.root {
                    let me = std::env::args().next().unwrap_or_else(|| "dryserver".into());
                    self.notice = format!("Flashing writes to raw disks and needs root. Quit and run: sudo {me}");
                    return Flow::Continue;
                }
                let fe = flash_emit(emit);
                let mut f = Flash::new(&iso::iso_path(&self.paths.out_dir).display().to_string(), size);
                f.update(Event::Resize(self.width, self.height), &fe);
                f.start_scanning(&fe);
                self.flash = Some(f);
                self.screen = Screen::Flash;
            }
            "4" => {
                if self.root {
                    self.notice = "Machines are approved as your normal user, not with sudo.".into();
                    return Flow::Continue;
                }
                self.open_machines = true;
                return Flow::Quit;
            }
            "5" | "6" => {
                if self.root {
                    self.notice = "Apps are managed as your normal user, not with sudo.".into();
                    return Flow::Continue;
                }
                self.open_cluster = Some(if k == "5" { super::Place::Apps } else { super::Place::Outside });
                return Flow::Quit;
            }
            "q" => return Flow::Quit,
            _ => {}
        }
        Flow::Continue
    }

    fn open_form(&mut self) {
        let answers = ConfigAnswers { cfg: self.cfg.clone(), tools: self.cfg.tool_list() };
        self.form = Some(config_form(answers));
        self.screen = Screen::Config;
    }

    fn update_form(&mut self, k: &Key) {
        let Some(f) = self.form.as_mut() else {
            return;
        };
        f.update(k);
        match f.status {
            Status::Completed => {
                let a = self.form.take().unwrap().state;
                let mut c = a.cfg;
                c.tools = packages::sort_tools(&a.tools).join(" ");
                c.extra_packages = c.extra_list().join(" ");
                c.admin_ssh_pubkey = config::normalize_pubkey(&c.admin_ssh_pubkey);
                let notice = match c.save(&self.paths.config) {
                    Ok(()) => format!("Config saved to {}.", self.paths.config.display()),
                    Err(e) => format!("Saving config failed: {e}"),
                };
                owner::fix(&[&self.paths.config]);
                self.back(notice);
            }
            Status::Aborted => self.back("Config not changed.".into()),
            Status::Active => {}
        }
    }

    fn status(&self, b: &mut Doc) {
        let row = |b: &mut Doc, name: &str, value: Seg| {
            b.s(format!("  {name:<8} ")).add(value).nl();
        };
        match &self.cfg_err {
            Some(e) if e.is_not_found() => row(b, "Config", err("not created yet")),
            Some(e) => {
                row(b, "Config", err("invalid"));
                for line in e.to_string().lines() {
                    row(b, "", err(format!("· {line}")));
                }
            }
            None => {
                let c = &self.cfg;
                let wifi = if c.wifi_ssid.is_empty() { "Ethernet only".to_string() } else { format!("WiFi {}", c.wifi_ssid) };
                let over = if c.wg_transport == config::TRANSPORT_AUTO {
                    format!("over switch {} when plugged in", c.switch_subnet)
                } else {
                    "over WiFi/router".to_string()
                };
                b.s(format!("  {:<8} ", "Config")).add(ok("ok")).add(dim(format!("  coordinator {}, {wifi}", c.coord_lan_ip))).nl();
                row(b, "", dim(format!("  mesh {} {over}", c.wg_subnet)));
                let mut tools = c.tool_list();
                tools.extend(c.extra_list());
                let tools = if tools.is_empty() { "basics only".to_string() } else { tools.join(" ") };
                row(b, "", dim(format!("  tools: {tools}")));
            }
        }

        match self.iso {
            None => row(b, "ISO", dim("not built")),
            Some((_, mtime)) => {
                let when = chrono::DateTime::<chrono::Local>::from(mtime).format("%Y-%m-%d %H:%M");
                b.s(format!("  {:<8} ", "ISO"))
                    .add(ok("ready"))
                    .add(dim(format!("  {}, built {when}", iso::iso_path(&self.paths.out_dir).display())))
                    .nl();
                if self.cfg_err.is_none() {
                    let changed = std::fs::metadata(&self.paths.config).and_then(|m| m.modified()).is_ok_and(|t| t > mtime);
                    if changed {
                        row(b, "", err("config changed after build, rebuild (2)"));
                    }
                }
            }
        }
        if self.root {
            row(b, "Root", ok("yes"));
        } else {
            row(b, "Root", dim("no (flashing needs sudo)"));
        }
    }
}

impl Model for App {
    type Msg = Msg;

    fn update(&mut self, ev: Event<Msg>, emit: &Emit<Msg>) -> Flow {
        if let Event::Resize(w, h) = ev {
            (self.width, self.height) = (w, h);
        }
        match self.screen {
            Screen::Config => {
                if let Event::Key(k) = &ev {
                    self.update_form(k);
                }
                return Flow::Continue;
            }
            Screen::Build => {
                let ev = match ev {
                    Event::Msg(Msg::Build(m)) => Event::Msg(m),
                    Event::Msg(Msg::Flash(_)) => return Flow::Continue,
                    Event::Key(k) => Event::Key(k),
                    Event::Tick => Event::Tick,
                    Event::Resize(w, h) => Event::Resize(w, h),
                };
                return match self.build.as_mut().map(|b| b.update(ev)) {
                    Some(Out::Quit) => Flow::Quit,
                    Some(Out::Back) | None => {
                        self.back(String::new());
                        Flow::Continue
                    }
                    Some(Out::Stay) => Flow::Continue,
                };
            }
            Screen::Flash => {
                let fe = flash_emit(emit);
                let ev = match ev {
                    Event::Msg(Msg::Flash(m)) => Event::Msg(m),
                    Event::Msg(Msg::Build(_)) => return Flow::Continue,
                    Event::Key(k) => Event::Key(k),
                    Event::Tick => Event::Tick,
                    Event::Resize(w, h) => Event::Resize(w, h),
                };
                return match self.flash.as_mut().map(|f| f.update(ev, &fe)) {
                    Some(Out::Quit) => Flow::Quit,
                    Some(Out::Back) | None => {
                        self.back(String::new());
                        Flow::Continue
                    }
                    Some(Out::Stay) => Flow::Continue,
                };
            }
            Screen::Menu => {}
        }
        if let Event::Key(k) = ev {
            match k {
                Key::Ctrl('c') | Key::Char('q') | Key::Esc => return Flow::Quit,
                Key::Up | Key::Char('k') => self.cursor = self.cursor.saturating_sub(1),
                Key::Down | Key::Char('j') => self.cursor = (self.cursor + 1).min(MENU.len() - 1),
                Key::Enter => return self.choose(MENU[self.cursor].0, emit),
                k => return self.choose(&k.name(), emit),
            }
        }
        Flow::Continue
    }

    fn view(&self) -> Doc {
        match self.screen {
            Screen::Config => {
                let mut b = Doc::new();
                b.append(theme::header("config")).s("\n\n");
                if let Some(f) = &self.form {
                    b.append(f.view());
                }
                return b;
            }
            Screen::Build => return self.build.as_ref().map(|b| b.view()).unwrap_or_default(),
            Screen::Flash => return self.flash.as_ref().map(|f| f.view()).unwrap_or_default(),
            Screen::Menu => {}
        }
        let mut b = Doc::new();
        b.append(theme::brand("your own server swarm", "one USB stick, machines that guard each other")).s("\n\n");
        self.status(&mut b);
        b.nl();
        for (i, (k, label)) in MENU.iter().enumerate() {
            let line = format!("{k}  {label}");
            if i == self.cursor {
                b.add(sel(format!("> {line}"))).nl();
            } else {
                b.s(format!("  {line}\n"));
            }
        }
        if !self.notice.is_empty() {
            b.nl().s(&self.notice).nl();
        }
        b.nl().append(theme::keys(&[("↑↓", "move"), ("enter", "open"), ("1-6", "jump"), ("q", "quit")])).nl();
        b
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
            ]),
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
            ]),
            Group::new(vec![
                Field::select("WireGuard network", move |_| transports.clone(), |a: &A| a.cfg.wg_transport.clone(), |a, v| a.cfg.wg_transport = v)
                    .desc("Which cable or radio carries traffic between servers."),
            ]),
            Group::new(vec![
                Field::note(
                    "Switch",
                    "Each Ethernet port gets a fixed IP here, so servers find each\nother on the switch. Works whether or not the switch is\nconnected to your router; if it is, the cable also gets\ninternet from the router.",
                ),
                Field::input("Switch subnet", |a: &A| a.cfg.switch_subnet.clone(), |a, v| a.cfg.switch_subnet = v)
                    .desc("Mesh node .N gets .N here too.")
                    .validate(|v, a| config::valid_switch_subnet(v, &a.cfg.wg_subnet, &a.cfg.coord_lan_ip)),
            ])
            .hide_if(|a| a.cfg.wg_transport != config::TRANSPORT_AUTO),
            Group::new(vec![
                Field::multi("Tools", move |_| tool_opts.clone(), |a: &A| a.tools.clone(), |a, v| a.tools = v).desc(
                    "Always installed: ssh, git, cron, tmux, htop, curl, rsync,\nripgrep, fzf and other basics. Pick extras (space toggles).",
                ),
                Field::input("Extra packages", |a: &A| a.cfg.extra_packages.clone(), |a, v| a.cfg.extra_packages = v)
                    .placeholder("python nodejs")
                    .desc("Any other Arch packages, space-separated.")
                    .validate(|v, _| config::valid_extra_packages(v)),
            ]),
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
            ]),
        ],
        "cancel",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use crate::tui::collector;

    fn test_paths(dir: &TempDir) -> Paths {
        Paths { config: dir.join("config.env"), out_dir: dir.join("out"), secrets: dir.join("secrets") }
    }

    fn press(a: &mut App, keys: &[Key]) {
        let (emit, _rx) = collector();
        for k in keys {
            Model::update(a, Event::Key(k.clone()), &emit);
        }
    }

    #[test]
    fn menu_guards() {
        let dir = TempDir::new();
        let mut a = App::new(test_paths(&dir));
        assert!(a.view().plain().contains("not created yet"), "missing config not shown");
        press(&mut a, &[Key::Char('2')]);
        assert!(a.screen == Screen::Menu && a.notice.contains("config first"), "build allowed without config: {:?}", a.notice);
        press(&mut a, &[Key::Char('3')]);
        assert!(a.screen == Screen::Menu && a.notice.contains("ISO first"), "flash allowed without ISO: {:?}", a.notice);
    }

    #[test]
    fn flash_needs_root() {
        if fsx::is_root() {
            return;
        }
        let dir = TempDir::new();
        let p = test_paths(&dir);
        std::fs::create_dir_all(&p.out_dir).unwrap();
        std::fs::write(p.out_dir.join("dryserver.iso"), "iso").unwrap();
        let mut a = App::new(p);
        press(&mut a, &[Key::Char('3')]);
        assert!(a.screen == Screen::Menu && a.notice.contains("needs root"), "{:?}", a.notice);
    }

    #[test]
    fn config_form_cancel() {
        let dir = TempDir::new();
        let p = test_paths(&dir);
        let mut a = App::new(p.clone());
        press(&mut a, &[Key::Char('1')]);
        assert_eq!(a.screen, Screen::Config);
        press(&mut a, &[Key::Esc]);
        assert!(a.screen == Screen::Menu && a.notice == "Config not changed.", "{:?} {:?}", a.screen, a.notice);
        assert!(!p.config.exists(), "cancel must not write config");
    }

    #[test]
    fn config_form_saves() {
        let dir = TempDir::new();
        let p = test_paths(&dir);
        let mut a = App::new(p.clone());
        press(&mut a, &[Key::Char('1')]);
        // WiFi: SSID empty, no password.
        press(&mut a, &[Key::Enter, Key::Enter]);
        // Mesh: coordinator IP, then accept the defaults (subnet, port,
        // mesh ports), and one extra outgoing port.
        press(&mut a, &crate::tui::type_text("192.168.1.50"));
        press(&mut a, &[Key::Enter, Key::Enter, Key::Enter, Key::Enter]);
        press(&mut a, &crate::tui::type_text("25565/tcp"));
        press(&mut a, &[Key::Enter]);
        // Transport auto, switch subnet default, tools (all), extra packages.
        press(&mut a, &[Key::Enter, Key::Enter, Key::Enter, Key::Enter]);
        // Admin: username default, key, label, timezone.
        press(&mut a, &[Key::Enter]);
        press(&mut a, &[Key::Paste("ssh-ed25519 AAAAkey me@example.com".into())]);
        press(&mut a, &[Key::Enter, Key::Enter, Key::Enter]);
        assert_eq!(a.screen, Screen::Menu, "{}", a.view().plain());
        assert!(a.notice.starts_with("Config saved"), "{:?}", a.notice);
        let c = Config::load(&p.config).unwrap();
        assert_eq!(c.coord_lan_ip, "192.168.1.50");
        assert_eq!(c.admin_ssh_pubkey, "ssh-ed25519 AAAAkey");
        assert_eq!(c.tools, "docker go rust cpp neovim");
        assert_eq!(c.egress_ports, "25565/tcp");
        assert!(a.view().plain().contains("coordinator 192.168.1.50"));
    }

    #[test]
    fn valid_config_shown() {
        let dir = TempDir::new();
        let p = test_paths(&dir);
        let c = Config {
            coord_lan_ip: "192.168.1.50".into(),
            admin_ssh_pubkey: "ssh-ed25519 AAAA me@pc".into(),
            wifi_ssid: "home".into(),
            wifi_pass: "password123".into(),
            ..Config::default()
        };
        c.save(&p.config).unwrap();
        let v = App::new(p).view().plain();
        for want in ["ok", "coordinator 192.168.1.50", "WiFi home", "not built"] {
            assert!(v.contains(want), "menu missing {want:?}:\n{v}");
        }
    }
}
