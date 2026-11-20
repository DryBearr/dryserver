//! dryserver builds and flashes the Arch + WireGuard installer USB, and runs
//! the setup screen and mesh tools on the servers it installs.

mod admin;
mod assets;
mod cidr;
mod config;
mod ctx;
mod disks;
mod err;
mod flash;
mod fsx;
mod gotime;
mod install;
mod iso;
mod mesh;
mod node;
mod owner;
mod packages;
mod quarantine;
mod registry;
mod runner;
mod signed;
mod sysconf;
#[cfg(test)]
mod testutil;
mod tui;

use std::collections::HashMap;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::ctx::Ctx;
use crate::err::{Context, Result};
use crate::gotime::Time;
use crate::node::Node;
use crate::runner::{Cmd, ExecRunner, Runner};
use crate::sysconf::{Params, Role};

const USAGE: &str = r#"usage: dryserver [command] [flags]

Run without a command for the interactive menu (config, build, flash).
Use sudo when you want to flash: sudo dryserver

commands:
  install [--demo]    laptop setup screen (runs from the installer USB);
                      --demo only shows the screens, nothing is changed
  build               build out/dryserver.iso from config.env, log to stdout
  disks               list disks and show which ones may be flashed
  flash --iso FILE    select a USB drive and write FILE to it (needs root)
  sysconf --out DIR   write the system files a server would get (for review)
  ssh-config          write ~/.ssh/config.d/dryserver so "ssh <server>" works
  quarantine-all      kill switch: cut the coordinator off on every server,
                      over the WiFi/router network, never through it;
                      -name a,b cuts those members instead, -lift undoes,
                      -status shows

  approve             approve or reject machines, remove members; every
                      decision is signed with secrets/signing_ed25519

on servers:
  join                ask the coordinator to join (runs at boot until approved)
  sync                update the mesh from the member list (runs every minute)
  quarantine          cut the coordinator (or -name a,b) off this server;
                      -lift undoes it, -status shows it
  scan                coordinator: report unknown devices on the network
  tpm-enroll          let the TPM unlock the disk again (after a firmware change)
  registry            coordinator: SSH forced command for joining machines
"#;

/// Where the ISO build puts the config.
const LIVE_CONFIG: &str = "/etc/dryserver/config.env";
const INSTALL_LOG: &str = "/tmp/dryserver-install.log";

fn paths() -> tui::app::Paths {
    tui::app::Paths { config: "config.env".into(), out_dir: "out".into(), secrets: "secrets".into() }
}

fn main() -> ExitCode {
    // Die quietly when the reader of our output goes away (`| head`),
    // instead of panicking on the failed write.
    // SAFETY: setting a signal disposition before any threads start.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        return finish(run_app());
    };
    let rest = &args[1..];
    let res = match cmd.as_str() {
        "install" => run_install(rest),
        "build" => run_build(rest),
        "disks" => run_disks(rest),
        "flash" => run_flash(rest),
        "sysconf" => run_sysconf(rest),
        "ssh-config" => run_ssh_config(rest),
        "quarantine-all" => run_quarantine_all(rest),
        "quarantine" => run_quarantine(rest),
        "registry" => run_registry(rest),
        "join" => run_join(rest),
        "sync" => run_sync(rest),
        "scan" => run_scan(rest),
        "approve" => run_approve(rest),
        "tpm-enroll" => run_tpm_enroll(rest),
        "help" | "-h" | "--help" => {
            print!("{USAGE}");
            Ok(())
        }
        other => {
            eprint!("unknown command {other:?}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    finish(res)
}

fn finish(res: Result<()>) -> ExitCode {
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("dryserver: {e}");
            ExitCode::FAILURE
        }
    }
}

// ---- flags ----

/// Parses Go-style flags: -name value, --name=value, -bool. Unknown flags
/// and stray arguments print the command's usage and exit with status 2.
struct Flags {
    values: HashMap<&'static str, String>,
}

impl Flags {
    /// spec: (name, default, help); a default of "false" makes a bool flag.
    fn parse(cmd: &str, args: &[String], spec: &[(&'static str, &str, &str)]) -> Flags {
        let usage = || {
            let mut u = format!("Usage of {cmd}:\n");
            for (name, def, help) in spec {
                if *def == "false" {
                    u += &format!("  -{name}\n    \t{help}\n");
                } else {
                    u += &format!("  -{name} string\n    \t{help} (default {def:?})\n");
                }
            }
            u
        };
        let fail = |msg: String| -> ! {
            eprint!("{msg}\n{}", usage());
            std::process::exit(2);
        };
        let mut values: HashMap<&'static str, String> = spec.iter().map(|(n, d, _)| (*n, d.to_string())).collect();
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if a == "-h" || a == "--help" {
                print!("{}", usage());
                std::process::exit(0);
            }
            let Some(body) = a.strip_prefix("--").or_else(|| a.strip_prefix('-')) else {
                fail(format!("unexpected argument {a:?}"));
            };
            let (name, inline) = match body.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (body, None),
            };
            let Some((key, def, _)) = spec.iter().find(|(n, _, _)| *n == name) else {
                fail(format!("flag provided but not defined: -{name}"));
            };
            let v = if *def == "false" {
                inline.unwrap_or_else(|| "true".into())
            } else if let Some(v) = inline {
                v
            } else {
                i += 1;
                match args.get(i) {
                    Some(v) => v.clone(),
                    None => fail(format!("flag needs an argument: -{name}")),
                }
            };
            values.insert(key, v);
            i += 1;
        }
        Flags { values }
    }

    fn get(&self, name: &str) -> &str {
        self.values.get(name).map(String::as_str).unwrap_or("")
    }

    fn on(&self, name: &str) -> bool {
        matches!(self.get(name), "true" | "1" | "t" | "T" | "TRUE" | "True")
    }
}

// ---- desktop commands ----

fn run_app() -> Result<()> {
    tui::run(&mut tui::app::App::new(paths()))
}

fn run_install(args: &[String]) -> Result<()> {
    let f = Flags::parse("install", args, &[("demo", "false", "show the setup screens without changing anything")]);
    let live = Config::load(LIVE_CONFIG);
    let (be, cfg): (Arc<dyn install::Backend>, Config) = if f.on("demo") {
        let cfg = live
            .or_else(|_| Config::load(paths().config))
            .unwrap_or_else(|_| Config { coord_lan_ip: "192.168.1.50".into(), ..Config::default() });
        (Arc::new(install::Demo::new()), cfg)
    } else {
        let cfg = live.map_err(|e| errf!("this is not the installer USB ({e}); try: dryserver install --demo"))?;
        if !fsx::is_root() {
            bail!("the installer must run as root");
        }
        (Arc::new(new_real_backend(&cfg)?), cfg)
    };
    tui::run(&mut tui::setup::Setup::new(be, cfg))
}

fn new_real_backend(cfg: &Config) -> Result<install::Real> {
    let me = std::env::current_exe()?;
    let rootfs = assets::ROOTFS.iter().map(|(p, d)| (p.to_string(), d.to_vec())).collect();
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode_600()
        .open(INSTALL_LOG)
        .map_err(|e| err::Error::from(e).wrap(format!("open {INSTALL_LOG}")))?;
    let r = install::Real::new(cfg.clone(), rootfs, me, "/etc/dryserver/registry_ed25519");
    *r.log.file.lock().unwrap() = Some(log);
    Ok(r)
}

trait Mode600 {
    fn mode_600(&mut self) -> &mut Self;
}

impl Mode600 for std::fs::OpenOptions {
    fn mode_600(&mut self) -> &mut Self {
        std::os::unix::fs::OpenOptionsExt::mode(self, 0o600)
    }
}

fn run_build(args: &[String]) -> Result<()> {
    Flags::parse("build", args, &[]);
    let p = paths();
    let cfg = Config::load(&p.config).map_err(|e| errf!("load {}: {e} (create it with the menu: dryserver)", p.config.display()))?;
    let ctx = Ctx::on_signals();
    let mut out = std::io::stdout();
    iso::run(&ctx, &iso::Options { config: cfg, out_dir: p.out_dir, secrets_dir: p.secrets }, &mut out)
}

fn run_disks(args: &[String]) -> Result<()> {
    Flags::parse("disks", args, &[]);
    let all = disks::list()?;
    let usb: Vec<String> = disks::usb(&all).into_iter().map(|d| d.path).collect();
    for d in &all {
        let tag = if usb.contains(&d.path) {
            "USB   "
        } else if d.is_system() {
            "system"
        } else {
            "other "
        };
        print!("[{tag}] {}", d.title());
        let m = d.mounts();
        if !m.is_empty() {
            print!("  mounted: {}", m.join(", "));
        }
        println!();
    }
    Ok(())
}

fn run_flash(args: &[String]) -> Result<()> {
    let f = Flags::parse("flash", args, &[("iso", "", "installer image to write")]);
    let iso = f.get("iso");
    if iso.is_empty() {
        bail!("flash: --iso is required");
    }
    let st = std::fs::metadata(iso).wrap(format!("stat {iso}"))?;
    if !st.is_file() || st.len() == 0 {
        bail!("{iso} is not an image file");
    }
    if !fsx::is_root() {
        let me = std::env::args().next().unwrap_or_else(|| "dryserver".into());
        bail!("flash writes to raw disks and needs root:\n  sudo {me} flash --iso {iso}");
    }
    let mut screen = tui::flash::Flash::new(iso, st.len());
    tui::run(&mut screen)?;
    screen.result()
}

fn run_sysconf(args: &[String]) -> Result<()> {
    let f = Flags::parse(
        "sysconf",
        args,
        &[
            ("out", "", "directory to write the files into"),
            ("config", "config.env", "config file"),
            ("role", "node", "node or coordinator"),
            ("hostname", "node-0000", "machine hostname"),
            ("host", "0", "mesh host number (0 = not approved yet)"),
        ],
    );
    let out = f.get("out");
    if out.is_empty() {
        bail!("sysconf: --out is required");
    }
    let role = Role::parse(f.get("role")).ok_or_else(|| errf!("sysconf: --role must be node or coordinator"))?;
    let host: u32 = f.get("host").parse().map_err(|_| errf!("sysconf: --host must be a number"))?;
    let cfg = Config::load(f.get("config"))?;
    let plan = packages::resolve(&cfg.tool_list(), &cfg.extra_list())?;
    let files = sysconf::render(&Params {
        config: cfg,
        plan,
        hostname: f.get("hostname").into(),
        role,
        host_num: host,
        switch_mac: String::new(),
    })?;
    for file in files {
        let dst = fsx::under(out, &file.path);
        fsx::mkdir_all(fsx::dir(&dst), 0o755)?;
        fsx::write_file(&dst, &file.content, file.mode)?;
        println!("{:04o} {}", file.mode, file.path);
    }
    Ok(())
}

fn run_ssh_config(args: &[String]) -> Result<()> {
    let f = Flags::parse("ssh-config", args, DESKTOP_FLAGS);
    let (mut a, host) = desktop_admin(&f, "ssh-config")?;
    let port = f.get("port");
    // Names and SSH host keys come from the list you signed, never from
    // what the coordinator says; only LAN addresses are its word.
    let view = a.load()?;
    for w in &view.warnings {
        eprintln!("warning: {w}");
    }
    let servers = a.servers();
    let coord_ip = mesh::ip(&a.subnet, 1);
    let Some(coord_name) = servers.iter().find(|s| s.mesh_ip == coord_ip).map(|s| s.name.clone()) else {
        bail!("nothing is signed yet. Approve your machines first: ./dryserver approve");
    };
    let cfg = Config::load(f.get("config"))?;
    let home = PathBuf::from(std::env::var("HOME").map_err(|_| errf!("$HOME is not defined"))?);
    let conf_path = home.join(".ssh/config.d/dryserver");
    let kh_path = home.join(".ssh/known_hosts.d/dryserver");
    for p in [&conf_path, &kh_path] {
        fsx::mkdir_all(fsx::dir(p), 0o700)?;
    }
    fsx::write_file(&kh_path, mesh::desktop_known_hosts(&servers, &coord_name, &host, port), 0o644)?;
    let conf = mesh::desktop_ssh_config(&cfg.username, &coord_name, &host, port, "~/.ssh/known_hosts.d/dryserver", &servers);
    fsx::write_file(&conf_path, conf, 0o600)?;
    println!("Wrote {} ({} servers) and {}.", conf_path.display(), servers.len(), kh_path.display());
    let no_lan: Vec<&str> = servers.iter().filter(|s| s.name != coord_name && s.lan_ip.is_empty()).map(|s| s.name.as_str()).collect();
    if !no_lan.is_empty() {
        println!(
            "No LAN address yet for: {} (not reported to the coordinator yet).\n\
             The kill switch (dryserver quarantine-all) cannot reach them; run ssh-config again later.",
            no_lan.join(", ")
        );
    }
    if !fsx::read_or_empty(home.join(".ssh/config")).contains("config.d/") {
        println!("Add this line at the top of ~/.ssh/config to use it:\n  Include config.d/*");
    }
    for s in &servers {
        println!("  ssh {}", s.name);
    }
    Ok(())
}

const DESKTOP_FLAGS: &[(&str, &str, &str)] = &[
    ("config", "config.env", "config file"),
    ("host", "", "coordinator address (default: COORD_LAN_IP)"),
    ("port", "22", "coordinator SSH port"),
];

/// The admin's link to the coordinator, with the keys from secrets/.
/// Returns it with the coordinator's address.
fn desktop_admin(f: &Flags, cmd: &str) -> Result<(admin::Admin, String)> {
    if fsx::is_root() {
        bail!("run {cmd} as your normal user, not with sudo");
    }
    let cfg = Config::load(f.get("config"))?;
    let secrets = paths().secrets;
    let need = |name: &str, what: &str| -> Result<PathBuf> {
        let p = secrets.join(name);
        if !p.exists() {
            bail!("{} is missing ({what}). It is created when you build the USB stick: ./dryserver build", p.display());
        }
        Ok(p)
    };
    let registry_key = need(iso::KEY_NAME, "the key machines use to reach the coordinator's registry")?;
    let signing_key = need(iso::SIGNING_KEY_NAME, "the key that signs your decisions")?;
    let signing_pub = need(iso::SIGNING_PUB, "the public half of the signing key")?;
    need(iso::JOIN_SECRET, "the secret that proves a machine was installed from your stick")?;
    let host = if f.get("host").is_empty() { cfg.coord_lan_ip.clone() } else { f.get("host").to_string() };
    let link = admin::SshLink {
        key: registry_key,
        known_hosts: secrets.join(admin::KNOWN_HOSTS),
        host: host.clone(),
        port: f.get("port").to_string(),
    };
    let a = admin::Admin::new(
        Box::new(link),
        Box::new(signed::SshSigner { key: signing_key }),
        Box::new(signed::SshVerifier { pubkey: signing_pub, tmp_dir: std::env::temp_dir() }),
        &secrets,
        &cfg.wg_subnet,
    );
    Ok((a, host))
}

// ---- server commands ----

/// What the node commands need on an installed server.
fn server_node() -> Result<(Node, Config)> {
    if !fsx::is_root() {
        bail!("run as root (sudo)");
    }
    let cfg = Config::load(LIVE_CONFIG).map_err(|e| e.wrap("not a dryserver server"))?;
    let host = fsx::read_or_empty("/proc/sys/kernel/hostname").trim().to_string();
    let n = Node::new(cfg.clone(), &host, Path::new("/"), Arc::new(ExecRunner::silent()));
    Ok((n, cfg))
}

fn is_coordinator() -> bool {
    fsx::read_or_empty("/etc/dryserver/role").trim() == Role::Coordinator.as_str()
}

fn run_registry(args: &[String]) -> Result<()> {
    // The flags come from the forced command in authorized_keys, never
    // from the caller: what the caller asks for is SSH_ORIGINAL_COMMAND.
    let f = Flags::parse("registry", args, &[("subnet", "", "mesh subnet"), ("root", "/", "directory holding this server's files")]);
    let root = Path::new(f.get("root"));
    let host_key = fsx::read_string(fsx::under(root, "/etc/ssh/ssh_host_ed25519_key.pub"))?;
    let env = |k: &str| std::env::var(k).unwrap_or_default();
    registry::serve(
        &registry::Store::new(fsx::under(root, registry::DEFAULT_PATH)),
        &mesh::Subnet(f.get("subnet").to_string()),
        &signed::SshVerifier::installed(root, std::env::temp_dir()),
        &host_key,
        &env("SSH_ORIGINAL_COMMAND"),
        &env("SSH_CLIENT"),
        &mut std::io::stdin(),
        &mut std::io::stdout(),
        Time::now(),
    )
}

fn run_join(args: &[String]) -> Result<()> {
    Flags::parse("join", args, &[]);
    let (n, cfg) = server_node()?;
    let plan = packages::resolve(&cfg.tool_list(), &cfg.extra_list())?;
    let ctx = Ctx::on_signals();
    let params = Params { config: cfg, plan, hostname: n.hostname.clone(), role: Role::Node, host_num: 0, switch_mac: String::new() };
    node::join_loop(&ctx, &n, &params, &mut std::io::stdout())
}

fn run_sync(args: &[String]) -> Result<()> {
    Flags::parse("sync", args, &[]);
    let (n, _) = server_node()?;
    let ctx = Ctx::on_signals().with_timeout(Duration::from_secs(50));
    if !node::sync(&ctx, &n, is_coordinator(), &registry::Store::default_path())? {
        println!("quarantined: the coordinator is cut off, sync is paused (sudo dryserver quarantine -lift resumes it)");
    }
    Ok(())
}

const QUARANTINE_FLAGS: &[(&str, &str, &str)] = &[
    ("name", "", "members to cut, comma separated (default: the coordinator)"),
    ("lift", "false", "undo every cut"),
    ("status", "false", "show what is cut"),
];

/// The -lift/-status/-name combination, checked.
fn quarantine_action(f: &Flags) -> Result<(Vec<String>, bool, bool)> {
    let names = quarantine::parse_names(f.get("name"))?;
    let (lift, status) = (f.on("lift"), f.on("status"));
    if lift && status {
        bail!("use -lift or -status, not both");
    }
    if (lift || status) && !names.is_empty() {
        bail!("-lift and -status cover every cut; they take no -name");
    }
    Ok((names, lift, status))
}

fn run_quarantine(args: &[String]) -> Result<()> {
    let f = Flags::parse("quarantine", args, QUARANTINE_FLAGS);
    let (names, lift, status) = quarantine_action(&f)?;
    let (n, _) = server_node()?;
    // The admin's session may run through the machine being cut and hang
    // up half way: finish anyway. Output errors are ignored for the same
    // reason.
    // SAFETY: setting signal dispositions; no handlers are installed.
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    let ctx = Ctx::new();
    let mut out = std::io::stdout();
    if status {
        quarantine::status(&ctx, &n, &mut out)
    } else if lift {
        quarantine::lift(&ctx, &n, is_coordinator(), &mut out)
    } else {
        quarantine::cut(&ctx, &n, is_coordinator(), &names, &mut out)
    }
}

fn run_quarantine_all(args: &[String]) -> Result<()> {
    let f = Flags::parse("quarantine-all", args, QUARANTINE_FLAGS);
    let (names, lift, status) = quarantine_action(&f)?;
    if fsx::is_root() {
        bail!("run quarantine-all as your normal user, not with sudo");
    }
    let home = PathBuf::from(std::env::var("HOME").map_err(|_| errf!("$HOME is not defined"))?);
    let conf_path = home.join(".ssh/config.d/dryserver");
    let kh_path = home.join(".ssh/known_hosts.d/dryserver");
    let conf = fsx::read_string(&conf_path)
        .map_err(|e| e.wrap("no server list; run dryserver ssh-config while the coordinator is still trusted"))?;
    let all = quarantine::remotes(&conf);
    if !all.iter().any(|r| !r.coordinator) {
        bail!(
            "{} has no <name>.lan entries, so no server can be reached without the coordinator.\n\
             Run dryserver ssh-config again once the servers run this dryserver version.",
            conf_path.display()
        );
    }
    let age = std::fs::metadata(&conf_path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .map(|d| gotime::duration_string(d.as_secs() as i64))
        .unwrap_or_else(|| "?".into());
    println!("Server list: {} (written {age} ago). Servers added since then are not in it.", conf_path.display());
    let mut action = Vec::new();
    if lift {
        action.push("-lift".to_string());
    } else if status {
        action.push("-status".to_string());
    } else if !names.is_empty() {
        action.extend(["-name".to_string(), names.join(",")]);
    }
    let targets = if lift || status { all.clone() } else { quarantine::targets(&all, &names) };
    let mut failed = Vec::new();
    for r in &targets {
        println!("\n== {} ({}){}", r.name, r.addr, if r.coordinator { ", the coordinator" } else { "" });
        let st = Command::new("ssh").args(quarantine::remote_args(r, &kh_path.display().to_string(), &action)).status();
        match st {
            Ok(s) if s.success() => {}
            Ok(s) if s.code() == Some(255) => failed.push(format!("{}: cannot connect over ssh to {}", r.name, r.addr)),
            Ok(s) => failed.push(format!("{}: {}", r.name, runner::exit_text(s))),
            Err(e) => bail!("ssh: {e}"),
        }
    }
    println!();
    if !lift && !status && names.is_empty() {
        println!(
            "Next: delete the tunnel in the Cloudflare dashboard, power off the coordinator and keep its disk \
             for investigation. Reinstall it from the USB stick before lifting."
        );
    }
    if !failed.is_empty() {
        let still = if !lift && !status && names.is_empty() {
            "\nThese servers still trust what was cut. Power the coordinator off now, and run this again \
             when they are reachable (each server can also run: sudo dryserver quarantine)."
        } else {
            ""
        };
        bail!("not done on {} server(s):\n  {}{still}", failed.len(), failed.join("\n  "));
    }
    println!("Done on {} server(s).", targets.len());
    Ok(())
}

fn run_scan(args: &[String]) -> Result<()> {
    Flags::parse("scan", args, &[]);
    let (n, cfg) = server_node()?;
    if !is_coordinator() {
        bail!("scan runs on the coordinator");
    }
    let ctx = Ctx::on_signals().with_timeout(Duration::from_secs(120));
    let mut found = Vec::new();
    let mut ports: Vec<String> = std::fs::read_dir("/sys/class/net")
        .map(|d| d.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default();
    ports.sort();
    for name in ports {
        // Only physical ports: WiFi/router and switch.
        if !Path::new("/sys/class/net").join(&name).join("device").exists() {
            continue;
        }
        let c = Cmd::new("arp-scan", &["--localnet", "--plain", "--quiet", "--interface", &name, "--format", "${ip}\t${mac}\t${vendor}"])
            .quiet();
        let (out, _) = n.run.run(&ctx, &c);
        found.extend(registry::parse_arp_scan(&out));
    }
    let store = registry::Store::default_path();
    let st = store.read()?;
    let mut known = Vec::new();
    for m in &st.members {
        known.extend([m.lan_ip.clone(), mesh::ip(&cfg.switch_subnet, m.host), mesh::ip(&cfg.wg_subnet, m.host)]);
    }
    let mut unknown = registry::unknown(&found, &known, Time::now());
    for d in unknown.iter_mut() {
        if let Ok(ip) = d.ip.parse::<std::net::IpAddr>() {
            d.ssh = TcpStream::connect_timeout(&SocketAddr::new(ip, 22), Duration::from_secs(1)).is_ok();
        }
    }
    store.update(|s| {
        s.unknown = unknown;
        s.scanned = Time::now();
        Ok(())
    })
}

fn run_approve(args: &[String]) -> Result<()> {
    let f = Flags::parse("approve", args, DESKTOP_FLAGS);
    if Path::new(LIVE_CONFIG).exists() {
        // A server cannot let anyone in, the coordinator included: only
        // the computer that holds the signing key can.
        bail!("approve runs on your own computer, where the signing key is:\n  ./dryserver approve");
    }
    let (a, _) = desktop_admin(&f, "approve")?;
    tui::run(&mut tui::admin::Screen::new(a))
}

/// The LUKS container of the root filesystem, from /etc/crypttab.
fn root_device() -> Result<String> {
    let text = fsx::read_string("/etc/crypttab").map_err(|e| e.wrap("no encrypted disk here"))?;
    for l in text.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() >= 2
            && f[0] == install::ROOT_MAPPER
            && let Some(uuid) = f[1].strip_prefix("UUID=")
        {
            return Ok(format!("/dev/disk/by-uuid/{uuid}"));
        }
    }
    bail!("no root entry in /etc/crypttab")
}

fn run_tpm_enroll(args: &[String]) -> Result<()> {
    let f = Flags::parse("tpm-enroll", args, &[("first-boot", "false", "use the one-time key from the installer, then remove it")]);
    let first_boot = f.on("first-boot");
    if !fsx::is_root() {
        bail!("run as root (sudo)");
    }
    let dev = root_device()?;
    let mut enroll = install::tpm_enroll_args(&dev);
    if first_boot {
        enroll.insert(0, format!("--unlock-key-file={}", install::FIRST_BOOT_KEY));
    } else {
        println!("Enter the disk passphrase to let the TPM unlock this boot's configuration.");
    }
    let st = Command::new("systemd-cryptenroll").args(&enroll).status().map_err(|e| err::Error::from(e).wrap("systemd-cryptenroll"))?;
    if !st.success() {
        bail!("systemd-cryptenroll: {}", runner::exit_text(st));
    }
    if !first_boot {
        return Ok(());
    }
    // The one-time key has done its job: remove its key slot and the file.
    let ctx = Ctx::new();
    ExecRunner::silent()
        .output(&ctx, &Cmd::new("cryptsetup", &["luksRemoveKey", "--batch-mode", &dev, install::FIRST_BOOT_KEY]))
        .map_err(|e| e.wrap("remove one-time key"))?;
    fsx::remove(install::FIRST_BOOT_KEY)?;
    let _ = Command::new("systemctl").args(["disable", "dryserver-tpm-enroll.service"]).status();
    println!("TPM enrolled; the disk now unlocks by itself.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(l: &[&str]) -> Vec<String> {
        l.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn flags_like_go() {
        let spec: &[(&'static str, &str, &str)] = &[("out", "", "dir"), ("host", "0", "n"), ("demo", "false", "b")];
        let f = Flags::parse("x", &args(&["--out", "/tmp/a", "-host=5", "-demo"]), spec);
        assert_eq!(f.get("out"), "/tmp/a");
        assert_eq!(f.get("host"), "5");
        assert!(f.on("demo"));
        let f = Flags::parse("x", &args(&["--demo=false"]), spec);
        assert!(!f.on("demo"));
        assert_eq!(f.get("host"), "0");
    }
}
