//! dryserver builds and flashes the Arch + WireGuard installer USB, and runs
//! the setup screen and mesh tools on the servers it installs.

mod admin;
mod apps;
mod assets;
mod backup;
mod cidr;
mod config;
mod coredns;
mod ctx;
mod disks;
mod entrance;
mod err;
mod flash;
mod fsx;
mod gotime;
mod homedir;
mod install;
mod iso;
mod k3stoken;
mod mesh;
mod node;
mod osupdate;
mod owner;
mod packages;
mod publish;
mod quarantine;
mod registry;
// Not called yet: later steps run the relay on the VPS entrance and wire
// releases into the machines.
#[allow(dead_code)]
mod relay;
#[allow(dead_code)]
mod release;
mod report;
mod rollout;
mod runner;
mod signed;
mod sysconf;
#[cfg(test)]
mod testutil;
mod tui;
mod update;

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

Run without a command for the desktop app: config, installer, USB stick,
machines, apps, the ways in, updates, backups and the kill switch.

It works from any folder. Your config and keys are in ~/.config/dryserver,
the installer image in ~/.cache/dryserver (DRYSERVER_HOME=DIR keeps all of
it in DIR instead).

commands:
  init [--from DIR]   set this computer up: make the keys of a new swarm, or
                      copy the swarm an older version kept in DIR (its
                      config.env and secrets/) to where it belongs now
  where               the folders that hold your config, keys and images
  install [--demo]    laptop setup screen (runs from the installer USB);
                      --demo only shows the screens, nothing is changed
  build               build the installer image from your config, log to stdout
  disks               list disks and show which ones may be flashed
  flash --iso FILE    select a USB drive and write FILE to it (needs root)
  sysconf --out DIR   write the system files a server would get (for review)
  ssh-config          write ~/.ssh/config.d/dryserver so "ssh <server>" works
  quarantine-all      kill switch: cut the coordinator off on every server,
                      over the WiFi/router network, never through it;
                      -name a,b cuts those members instead, -lift undoes
                      (onto the coordinator you signed last; -lift -same
                      after a false alarm), -status shows

  approve             the app at Machines: approve or reject machines,
                      remove members, publish an update (u); every
                      decision is signed with your signing key
  apps                the app at Apps: what runs on your cluster
  backup-pull         copy the coordinator's newest backups into the
                      backups folder next to your keys (encrypted; signed
                      by the coordinator)
  outside             the app at Outside: the ways in from the internet
  release publish     check a release of this dryserver, show what changes,
                      sign it and send it to the coordinator: it updates
                      itself, then one server at a time (-urgent: at once,
                      -notes TEXT, -rollback; release help for the rest)
  release status      the release, one line per machine, what to do
  release resume      let a stopped rollout go on: the server it stopped at
                      tries again (-skip: pass it over for this release)

on servers:
  join                ask the coordinator to join (runs at boot until approved)
  sync                update the mesh from the member list (runs every minute)
  quarantine          cut the coordinator (or -name a,b) off this server;
                      -lift undoes it (-same: trust the same coordinator
                      again), -status shows it
  scan                coordinator: report unknown devices on the network
  report              this machine's health as JSON (versions, reboot, disk,
                      k3s, firewall, WireGuard); root shows everything
  tpm-enroll          let the TPM unlock the disk again (after a firmware change)
  registry            coordinator: SSH forced command for joining machines
  cluster-dns         coordinator: keep the cluster's DNS on two machines
                      (run by a timer)
  backup              coordinator: encrypted backup into /var/lib/dryserver-backup
                      (run by a timer every night)
  update apply --release FILE --binary FILE [--k3s FILE] [--brain-k3s V]
               [--window SECS] [--reboot] [--detach]
                      install a release the admin signed (dryserver, k3s,
                      Arch packages); it reverts by itself unless confirmed
                      within the window
  update confirm [--serial N] | revert | status [--json]
                      keep the applied release, undo it, or show the state
  selfcheck           check this binary, config.env, the firewall, SSH,
                      wg0.conf and the state files (no network needed)
  boot status         which kernel runs, its boot images and whether the
                      fallback kernel waits (boot place, mark and check run
                      from mkinitcpio, pacman and systemd)
"#;

/// Where the ISO build puts the config.
const LIVE_CONFIG: &str = "/etc/dryserver/config.env";
const INSTALL_LOG: &str = "/tmp/dryserver-install.log";

/// The desktop's folders (see homedir), the same from any working
/// directory. Refuses while the swarm is still in the folder an older
/// version kept it in and nothing is here yet: whatever ran now would
/// start a new swarm beside it. Made once, with the folders.
fn paths() -> Result<tui::app::Paths> {
    desktop().map(|(p, _)| p)
}

/// The paths, and a word about a folder of an older version that is not
/// used any more (printed once, and shown on Home).
fn desktop() -> Result<(tui::app::Paths, Option<String>)> {
    type Made = std::result::Result<(tui::app::Paths, Option<String>), String>;
    static PATHS: std::sync::OnceLock<Made> = std::sync::OnceLock::new();
    PATHS
        .get_or_init(|| {
            let r = desktop_paths().map_err(|e| e.to_string());
            if let Ok((_, Some(note))) = &r {
                eprintln!("note: {note}");
            }
            r
        })
        .clone()
        .map_err(err::Error::new)
}

fn desktop_paths() -> Result<(tui::app::Paths, Option<String>)> {
    let l = homedir::layout(&homedir::Env::current())?;
    let note = match homedir::look(&l, &homedir::candidates()) {
        Some(homedir::Stray::Other(d)) => bail!("{}", homedir::other_swarm(&l, &d)),
        Some(homedir::Stray::Waiting(d)) => bail!(
            "dryserver keeps your swarm in {} now, and works from any folder. Your swarm is still in {}: bring it \
             there once (it is copied, {} stays as it is):\n  dryserver init --from {}",
            l.home.display(),
            d.display(),
            d.display(),
            d.display()
        ),
        Some(homedir::Stray::Old(d)) => Some(format!(
            "{d}/config.env and {d}/secrets are an old copy, not used; dryserver uses {} (dryserver where). Delete \
             them once you are sure it works from there.",
            l.home.display(),
            d = d.display()
        )),
        None => None,
    };
    homedir::prepare(&l)?;
    Ok((tui::app::Paths { config: l.config, out_dir: l.out_dir, secrets: l.secrets }, note))
}

/// The config file: -config FILE, or the one in the home folder.
fn config_file(f: &Flags) -> Result<PathBuf> {
    match f.get("config") {
        "" => Ok(paths()?.config),
        c => Ok(PathBuf::from(c)),
    }
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
        "init" => run_init(rest),
        "where" => run_where(rest),
        "install" => run_install(rest),
        "build" => run_build(rest),
        "disks" => run_disks(rest),
        "flash" => run_flash(rest),
        "sysconf" => run_sysconf(rest),
        "ssh-config" => run_ssh_config(rest),
        "apps" => run_apps(rest, tui::Place::Apps),
        "outside" => run_apps(rest, tui::Place::Outside),
        "quarantine-all" => run_quarantine_all(rest),
        "quarantine" => run_quarantine(rest),
        "registry" => run_registry(rest),
        "join" => run_join(rest),
        "sync" => run_sync(rest),
        "scan" => run_scan(rest),
        "report" => run_report(rest),
        "approve" => run_approve(rest),
        "release" => run_release(rest),
        "tpm-enroll" => run_tpm_enroll(rest),
        "cluster-dns" => run_cluster_dns(rest),
        "backup" => run_backup(rest),
        "backup-pull" => run_backup_pull(rest),
        "update" => run_update(rest),
        "selfcheck" => run_selfcheck(rest),
        "boot" => install::boot::cli(rest),
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
            eprintln!("dryserver: {}", report::printable(&e.to_string()));
            ExitCode::FAILURE
        }
    }
}

// ---- flags ----

/// Parses Go-style flags: -name value, --name=value, -bool. Unknown flags
/// and stray arguments print the command's usage and exit with status 2.
#[derive(Clone)]
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
    run_hub(&Flags::parse("dryserver", &[], DESKTOP_FLAGS), None)
}

/// The desktop app, at Home or at place. Every place runs inside it.
fn run_hub(f: &Flags, place: Option<tui::app::Place>) -> Result<()> {
    let (mut p, note) = desktop()?;
    p.config = config_file(f)?;
    let mut app = tui::app::App::new(p, factories(f));
    if let Some(n) = note {
        app = app.with_notice(tui::frame::Notice::info(n));
    }
    if let Some(place) = place {
        app = app.start_at(place);
    }
    let res = tui::run(&mut app);
    for m in app.after() {
        eprintln!("{}", report::printable(m));
    }
    res
}

/// What the app needs from this computer and the coordinator, made when
/// a place opens.
fn factories(f: &Flags) -> tui::app::Factories {
    let (machines, cluster, pull, list) = (f.clone(), f.clone(), f.clone(), f.clone());
    let home = std::env::var_os("HOME").filter(|h| !h.is_empty()).map(PathBuf::from);
    tui::app::Factories {
        machines: Box::new(move || machines_model(&machines)),
        cluster: Box::new(move || {
            let c: Arc<dyn apps::Cluster> = Arc::new(desktop_cluster(&cluster, "apps")?);
            Ok((c, desktop_doors()?))
        }),
        pull: Arc::new(move |out| backup_pull(&pull, out)),
        write_list: Arc::new(move || {
            let done = ssh_config(&list)?;
            Ok(done.summary)
        }),
        quarantine: Arc::new(|cut| {
            use tui::kill::Switch;
            let (lift, same, status) = match cut {
                Switch::Cut => (false, false, false),
                Switch::Status => (false, false, true),
                Switch::Lift => (true, false, false),
                Switch::LiftSame => (true, true, false),
            };
            quarantine_all(&[], lift, same, status)
        }),
        server_list: home.map(|h| h.join(".ssh/config.d/dryserver")),
        exe: std::env::current_exe().ok(),
    }
}

/// Sets this computer up: copies a swarm from the folder an older version
/// kept it in, or makes the keys of a new one. Running it again is safe.
fn run_init(args: &[String]) -> Result<()> {
    let f = Flags::parse(
        "init",
        args,
        &[
            ("from", "", "the folder an older dryserver kept your swarm in (its config.env and secrets/): copied, never changed"),
            ("new", "false", "make a new swarm even though one was found in this folder or next to this program"),
        ],
    );
    if fsx::is_root() {
        bail!("run init as your normal user, not with sudo: the files must be yours");
    }
    if Path::new(LIVE_CONFIG).exists() {
        bail!("init runs on your own computer, not on a server");
    }
    let l = homedir::layout(&homedir::Env::current())?;
    let mut out = std::io::stdout();
    if !f.get("from").is_empty() {
        let from = Path::new(f.get("from"));
        let b = homedir::bring(from, &l)?;
        for p in &b.copied {
            println!("Copied {}", p.display());
        }
        for p in &b.same {
            println!("Already there: {}", p.display());
        }
        println!(
            "The files in {} are not used any more; delete them once dryserver works from here. The installer image is \
             not copied: build it again.",
            std::path::absolute(from)?.display()
        );
    } else if !f.on("new")
        && let Some(homedir::Stray::Waiting(d)) = homedir::look(&l, &homedir::candidates())
    {
        bail!(
            "{} holds a swarm (config.env, secrets/). Bring it here:\n  dryserver init --from {}\nOr make a new swarm \
             anyway: dryserver init --new",
            d.display(),
            d.display()
        );
    }
    homedir::prepare(&l)?;
    // A config that does not load yet names no key to sign with: the
    // build takes it from the config later.
    let admin = Config::load(&l.config).ok().map(|c| c.admin_ssh_pubkey).filter(|k| !k.is_empty());
    let keys = iso::ensure_keys(&Ctx::on_signals(), &l.secrets, admin.as_deref(), &mut out)?;
    println!("Ready. Your swarm on this computer:");
    homedir::describe(&l, homedir::look(&l, &homedir::candidates()).as_ref(), &mut out)?;
    if keys.signing_pub.is_none() {
        println!("\nSigning key: your SSH key, once it is in the config.");
    }
    if !l.config.exists() {
        println!("\nNext: dryserver, then Config.");
    }
    Ok(())
}

fn run_where(args: &[String]) -> Result<()> {
    Flags::parse("where", args, &[]);
    let l = homedir::layout(&homedir::Env::current())?;
    homedir::describe(&l, homedir::look(&l, &homedir::candidates()).as_ref(), &mut std::io::stdout())?;
    Ok(())
}

fn run_install(args: &[String]) -> Result<()> {
    let f = Flags::parse("install", args, &[("demo", "false", "show the setup screens without changing anything")]);
    let live = Config::load(LIVE_CONFIG);
    let (be, cfg): (Arc<dyn install::Backend>, Config) = if f.on("demo") {
        let cfg = live
            .or_else(|e| paths().and_then(|p| Config::load(p.config)).map_err(|_| e))
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
    let log = open_log(Path::new(INSTALL_LOG))?;
    let r = install::Real::new(cfg.clone(), rootfs, me, "/etc/dryserver/registry_ed25519");
    *r.log.file.lock().unwrap() = Some(log);
    Ok(r)
}

/// The installer's log, appended to: made for root alone when it is new,
/// and never opened through a link (/tmp is anyone's to put one in).
fn open_log(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| err::Error::from(e).wrap(format!("open {}", path.display())))
}

fn run_build(args: &[String]) -> Result<()> {
    Flags::parse("build", args, &[]);
    let p = paths()?;
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
            ("config", "", "config file (default: the one dryserver where shows)"),
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
    let cfg = Config::load(config_file(&f)?)?;
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
    let done = ssh_config(&f)?;
    for w in &done.warnings {
        eprintln!("warning: {}", report::printable(w));
    }
    for l in &done.lines {
        println!("{l}");
    }
    Ok(())
}

/// What ssh-config wrote: one line for the app, all of them for the
/// terminal.
struct SshConfigDone {
    summary: String,
    warnings: Vec<String>,
    lines: Vec<String>,
}

/// Writes ~/.ssh/config.d/dryserver so "ssh <server>" works, and the
/// kill switch can reach every server without the coordinator.
fn ssh_config(f: &Flags) -> Result<SshConfigDone> {
    let (mut a, host) = desktop_admin(f, "ssh-config")?;
    let port = f.get("port");
    // Names and SSH host keys come from the list you signed, never from
    // what the coordinator says; only LAN addresses are its word.
    let view = a.load()?;
    let servers = a.servers();
    let coord_ip = mesh::ip(&a.subnet, 1);
    let Some(coord_name) = servers.iter().find(|s| s.mesh_ip == coord_ip).map(|s| s.name.clone()) else {
        bail!("nothing is signed yet: sign the coordinator in Machines first");
    };
    let cfg = Config::load(config_file(f)?)?;
    let home = PathBuf::from(std::env::var("HOME").map_err(|_| errf!("$HOME is not defined"))?);
    let conf_path = home.join(".ssh/config.d/dryserver");
    let kh_path = home.join(".ssh/known_hosts.d/dryserver");
    for p in [&conf_path, &kh_path] {
        fsx::mkdir_all(fsx::dir(p), 0o700)?;
    }
    fsx::write_file(&kh_path, mesh::desktop_known_hosts(&servers, &coord_name, &host, port), 0o644)?;
    let conf = mesh::desktop_ssh_config(&cfg.username, &coord_name, &host, port, "~/.ssh/known_hosts.d/dryserver", &servers);
    fsx::write_file(&conf_path, conf, 0o600)?;
    let mut summary = format!("Wrote the server list {} ({} servers).", conf_path.display(), servers.len());
    let mut lines = vec![format!("Wrote {} ({} servers) and {}.", conf_path.display(), servers.len(), kh_path.display())];
    let no_lan: Vec<&str> = servers.iter().filter(|s| s.name != coord_name && s.lan_ip.is_empty()).map(|s| s.name.as_str()).collect();
    if !no_lan.is_empty() {
        let names = no_lan.join(", ");
        summary += &format!(" No LAN address yet for {names}: the kill switch cannot reach them; write it again later.");
        lines.push(format!(
            "No LAN address yet for: {names} (not reported to the coordinator yet).\n\
             The kill switch (dryserver quarantine-all) cannot reach them; run ssh-config again later."
        ));
    }
    if !fsx::read_or_empty(home.join(".ssh/config")).contains("config.d/") {
        lines.push("Add this line at the top of ~/.ssh/config to use it:\n  Include config.d/*".into());
    }
    for s in &servers {
        lines.push(format!("  ssh {}", s.name));
    }
    Ok(SshConfigDone { summary, warnings: view.warnings, lines })
}

const DESKTOP_FLAGS: &[(&str, &str, &str)] = &[
    ("config", "", "config file (default: the one dryserver where shows)"),
    ("host", "", "coordinator address (default: COORD_LAN_IP)"),
    ("port", "22", "coordinator SSH port"),
];

/// What signs: an older swarm's own key in secrets/, or else the admin's
/// SSH key (ssh-agent or ~/.ssh) whose public half the machines trust.
fn signer(secrets: &Path) -> Box<dyn signed::Signer> {
    let legacy = secrets.join(iso::SIGNING_KEY_NAME);
    if legacy.exists() {
        return Box::new(signed::SshSigner { key: legacy });
    }
    Box::new(signed::OwnKeySigner::for_user(secrets.join(iso::SIGNING_PUB)))
}

/// Whether signing works without a terminal (the screens sign every few
/// seconds and cannot ask a passphrase), or what to do.
fn signs_without_terminal(secrets: &Path) -> Result<()> {
    let legacy = secrets.join(iso::SIGNING_KEY_NAME);
    if legacy.exists() {
        if publish::has_passphrase(&legacy) {
            bail!(
                "{k} has a passphrase, and Machines signs every few seconds: it cannot ask for it. In a terminal, \
                 dryserver release publish, status and resume ask for it at each signature. Or remove the passphrase: \
                 ssh-keygen -p -f {k}",
                k = legacy.display()
            );
        }
        return Ok(());
    }
    signed::OwnKeySigner::for_user(secrets.join(iso::SIGNING_PUB)).ready_without_terminal()
}

/// The admin's link to the coordinator, with the keys from secrets/.
/// Returns it with the coordinator's address.
fn desktop_admin(f: &Flags, cmd: &str) -> Result<(admin::Admin, String)> {
    if fsx::is_root() {
        bail!("run {cmd} as your normal user, not with sudo");
    }
    let cfg = Config::load(config_file(f)?)?;
    let secrets = paths()?.secrets;
    let need = |name: &str, what: &str| -> Result<PathBuf> {
        let p = secrets.join(name);
        if !p.exists() {
            if iso::swarm_started(&secrets) {
                bail!("{} is missing ({what}). Restore it from your backup into {}", p.display(), secrets.display());
            }
            bail!("{} is missing ({what}). Building the installer makes it: dryserver, then Installer", p.display());
        }
        Ok(p)
    };
    let registry_key = need(iso::KEY_NAME, "the key machines use to reach the coordinator's registry")?;
    let signing_pub = need(iso::SIGNING_PUB, "the public half of the key your machines trust")?;
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
        signer(&secrets),
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
    let env = |k: &str| std::env::var(k).unwrap_or_default();
    // Every command here is a read or a small write, but for moving a
    // release, which takes as long as the network needs. A caller that
    // sends nothing, or never finishes, does not get to keep a session.
    // An upload gets longer only once its header's signature checked out
    // (registry::extend_deadline).
    registry::set_deadline(registry::deadline(&env("SSH_ORIGINAL_COMMAND")));
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            if registry::past_deadline() {
                eprintln!("dryserver: registry command took too long");
                std::process::exit(1);
            }
        }
    });
    let host_key = fsx::read_string(fsx::under(root, "/etc/ssh/ssh_host_ed25519_key.pub"))?;
    let store = registry::Store::new(fsx::under(root, registry::DEFAULT_PATH));
    registry::serve(
        &store,
        &rollout::Served::beside(&store, fsx::under(root, rollout::K3S_BIN)),
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
    ("same", "false", "with -lift: the coordinator was not reinstalled (a false alarm); trust it again"),
    ("status", "false", "show what is cut"),
];
/// On a server: quarantine-all also passes -min-version.
const QUARANTINE_SERVER_FLAGS: &[(&str, &str, &str)] = &[
    ("name", "", "members to cut, comma separated (default: the coordinator)"),
    ("lift", "false", "undo every cut"),
    ("same", "false", "with -lift: the coordinator was not reinstalled (a false alarm); trust it again"),
    ("min-version", "0", "with -lift: refuse member lists older than this version (the newest you signed)"),
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
    if f.on("same") && !lift {
        bail!("-same goes with -lift");
    }
    Ok((names, lift, status))
}

fn run_quarantine(args: &[String]) -> Result<()> {
    let f = Flags::parse("quarantine", args, QUARANTINE_SERVER_FLAGS);
    let (names, lift, status) = quarantine_action(&f)?;
    let min_version: u64 = f.get("min-version").parse().map_err(|_| errf!("-min-version must be a number"))?;
    if min_version > 0 && !lift {
        bail!("-min-version goes with -lift");
    }
    let how = quarantine::LiftOptions { min_version, same: f.on("same") };
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
        quarantine::lift(&ctx, &n, is_coordinator(), how, &mut out)
    } else {
        quarantine::cut(&ctx, &n, is_coordinator(), &names, &mut out)
    }
}

fn run_quarantine_all(args: &[String]) -> Result<()> {
    let f = Flags::parse("quarantine-all", args, QUARANTINE_FLAGS);
    let (names, lift, status) = quarantine_action(&f)?;
    quarantine_all(&names, lift, f.on("same"), status)
}

/// The kill switch: cuts (or lifts, or shows) on every server in the
/// server list, over the WiFi/router network. ssh runs on this terminal:
/// sudo asks for the password on each server.
fn quarantine_all(names: &[String], lift: bool, same: bool, status: bool) -> Result<()> {
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
        // No server takes a list older than the newest one signed here.
        let copy_path = paths()?.secrets.join(admin::SIGNED_COPY);
        let copy = fsx::read_string(&copy_path).map_err(|e| {
            e.wrap(format!(
                "no copy of the member list you signed last ({}). Lift on each server by hand: \
                 sudo dryserver quarantine -lift (with -same after a false alarm)",
                copy_path.display()
            ))
        })?;
        action = quarantine::lift_args(&copy, same).map_err(|e| e.wrap(copy_path.display().to_string()))?;
    } else if status {
        action.push("-status".to_string());
    } else if !names.is_empty() {
        action.extend(["-name".to_string(), names.join(",")]);
    }
    let targets = if lift || status { all.clone() } else { quarantine::targets(&all, names) };
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
    // Where WireGuard here sees each member's packets come from: on the
    // LAN, that is its LAN address, whatever it says (an address on the
    // switch says nothing about it).
    let endpoints = n.run.output(&ctx, &Cmd::new("wg", &["show", "wg0", "endpoints"]).quiet().stdout_only()).unwrap_or_default();
    let switch = cidr::Cidr::parse(&cfg.switch_subnet).filter(|_| cfg.wg_transport == config::TRANSPORT_AUTO);
    let seen: std::collections::BTreeMap<String, std::net::Ipv4Addr> = mesh::live_peers(&endpoints, "")
        .into_iter()
        .filter_map(|(key, live)| Some((key, live.endpoint.rsplit_once(':')?.0.parse().ok()?)))
        .filter(|(_, ip)| !switch.is_some_and(|s| s.contains(*ip)))
        .collect();
    let fixed = |host: u32| {
        let mut v = vec![mesh::ip(&cfg.switch_subnet, host), mesh::ip(&cfg.wg_subnet, host)];
        if host == 1 {
            v.push(cfg.coord_lan_ip.clone());
        }
        v
    };
    let (known, notes) = registry::member_addresses(&st.members, &seen, fixed);
    let mut unknown = registry::unknown(&found, &known, Time::now());
    for d in unknown.iter_mut() {
        // A member's claim to it that was not taken.
        if let Some(note) = notes.get(&d.ip) {
            d.vendor = format!("{note}; {}", d.vendor).chars().take(64).collect();
        }
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

/// What this machine reports about itself with every sync, as JSON. Needs
/// no root; without it the firewall and WireGuard stay unknown.
fn run_report(args: &[String]) -> Result<()> {
    Flags::parse("report", args, &[]);
    // The config holds the WiFi password and only root reads it; the
    // mesh subnet names WireGuard peers, which only root sees anyway.
    let subnet = Config::load(LIVE_CONFIG).map(|c| c.wg_subnet).unwrap_or_default();
    let ctx = Ctx::on_signals();
    let mut r = report::gather(&ctx, &ExecRunner::silent(), Path::new("/"), &subnet);
    // Where its update stands: root only reads that.
    if fsx::is_root()
        && let Ok(cfg) = Config::load(LIVE_CONFIG)
    {
        let n = Node::new(cfg, "", Path::new("/"), Arc::new(ExecRunner::silent()));
        rollout::Machine::new(&n, is_coordinator()).describe(&mut r);
    }
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

fn run_cluster_dns(args: &[String]) -> Result<()> {
    Flags::parse("cluster-dns", args, &[]);
    if !fsx::is_root() {
        bail!("run as root (sudo)");
    }
    if !is_coordinator() {
        bail!("cluster-dns runs on the coordinator");
    }
    let ctx = Ctx::on_signals().with_timeout(coredns::RUN_TIMEOUT);
    let run = ExecRunner::silent();
    if run.ok(&ctx, &Cmd::new("systemctl", &["is-active", "--quiet", "k3s.service"])).is_err() {
        println!("k3s is not running here; nothing to do");
        return Ok(());
    }
    coredns::tend(&ctx, &run, Time::now(), &mut std::io::stdout()).map(|_| ())
}

fn run_backup(args: &[String]) -> Result<()> {
    Flags::parse("backup", args, &[]);
    if !fsx::is_root() {
        bail!("run as root (sudo)");
    }
    let host = fsx::read_or_empty("/proc/sys/kernel/hostname").trim().to_string();
    let run = ExecRunner::silent();
    let ctx = Ctx::on_signals();
    let res = backup::Job::new(&run, &host).run(&ctx, Time::now(), &mut std::io::stdout());
    if let Err(e) = &res
        && std::env::var_os("JOURNAL_STREAM").is_some()
    {
        // In the journal at error level, for whoever looks (a future
        // monitor reads the status file).
        eprintln!("<3>dryserver backup failed: {e}");
    }
    res.map(|_| ())
}

fn run_backup_pull(args: &[String]) -> Result<()> {
    let f = Flags::parse("backup-pull", args, DESKTOP_FLAGS);
    if Path::new(LIVE_CONFIG).exists() {
        bail!("backup-pull runs on your own computer:\n  dryserver backup-pull");
    }
    let r = backup_pull(&f, &mut std::io::stdout())?;
    for n in &r.removed {
        println!("removed {n} (older than the {} daily and {} weekly kept)", backup::KEEP_DAILY, backup::KEEP_WEEKLY);
    }
    println!("{} new backup(s) in {}.", r.fetched.len(), paths()?.secrets.join("backups").display());
    if !r.problems.is_empty() {
        bail!("not everything was copied:\n  {}", r.problems.join("\n  "));
    }
    Ok(())
}

/// Copies the coordinator's newest backups into secrets/backups, writing
/// a line for each to out.
fn backup_pull(f: &Flags, out: &mut dyn std::io::Write) -> Result<backup::Pulled> {
    use crate::admin::Link;
    if fsx::is_root() {
        bail!("run backup-pull as your normal user, not with sudo");
    }
    let cfg = Config::load(config_file(f)?)?;
    let secrets = paths()?.secrets;
    let host = if f.get("host").is_empty() { cfg.coord_lan_ip.clone() } else { f.get("host").to_string() };
    let known_hosts = secrets.join(admin::KNOWN_HOSTS);
    // The coordinator's host key as this computer pinned it (approve):
    // it signs every backup, and only what it signed is kept.
    let link = admin::SshLink {
        key: secrets.join(iso::KEY_NAME),
        known_hosts: known_hosts.clone(),
        host: host.clone(),
        port: f.get("port").into(),
    };
    let host_key = link.host_key().map_err(|e| e.wrap("this computer has not met the coordinator yet; open Machines once first"))?;
    let dir = secrets.join("backups");
    fsx::mkdir_all(&dir, 0o700)?;
    let signer = dir.join(".coordinator.pub");
    fsx::write_new(&signer, format!("{host_key}\n"), 0o600)?;
    let verifier = signed::SshVerifier { pubkey: signer.clone(), tmp_dir: std::env::temp_dir() };
    let brain = backup::SshBrain::new(&host, f.get("port"), &cfg.username, known_hosts);
    let res = backup::pull(&brain, &verifier, &dir, chrono::Utc::now(), out);
    let _ = fsx::remove(&signer);
    res
}

/// kubectl on the coordinator over the admin's SSH login, with the host
/// key this desktop pinned for it.
fn desktop_cluster(f: &Flags, cmd: &str) -> Result<apps::SshCluster> {
    if fsx::is_root() {
        bail!("run {cmd} as your normal user, not with sudo");
    }
    let cfg = Config::load(config_file(f)?)?;
    let host = if f.get("host").is_empty() { cfg.coord_lan_ip.clone() } else { f.get("host").to_string() };
    Ok(apps::SshCluster {
        host,
        port: f.get("port").to_string(),
        user: cfg.username,
        known_hosts: paths()?.secrets.join(admin::KNOWN_HOSTS),
    })
}

fn run_apps(args: &[String], place: tui::Place) -> Result<()> {
    let cmd = if place == tui::Place::Apps { "apps" } else { "outside" };
    let f = Flags::parse(cmd, args, DESKTOP_FLAGS);
    if Path::new(LIVE_CONFIG).exists() {
        bail!("{cmd} runs on your own computer:\n  dryserver {cmd}\nOn the coordinator itself, use: k3s kubectl");
    }
    run_hub(&f, Some(if place == tui::Place::Apps { tui::app::Place::Apps } else { tui::app::Place::Outside }))
}

/// The ways in from outside this desktop knows, with its secrets.
fn desktop_doors() -> Result<entrance::Entrances> {
    let secrets = paths()?.secrets;
    Ok(Arc::new(vec![Box::new(entrance::cloudflare::Cloudflare::new(&secrets)), Box::new(entrance::Vps)]))
}

fn run_approve(args: &[String]) -> Result<()> {
    let f = Flags::parse("approve", args, DESKTOP_FLAGS);
    if Path::new(LIVE_CONFIG).exists() {
        // A server cannot let anyone in, the coordinator included: only
        // the computer that holds the signing key can.
        bail!("approve runs on your own computer, where the signing key is:\n  dryserver approve");
    }
    run_hub(&f, Some(tui::app::Place::Machines))
}

/// The Machines screen, which also publishes releases, lets a stopped
/// rollout go on and writes the server list.
fn machines_model(f: &Flags) -> Result<tui::admin::Screen> {
    let (a, host) = desktop_admin(f, "approve")?;
    // ssh-keygen would ask for a passphrase on the terminal the screen
    // draws on.
    signs_without_terminal(&paths()?.secrets)?;
    let again = f.clone();
    let publisher = tui::admin::Publisher {
        admin: Arc::new(move || desktop_admin(&again, "approve").map(|(a, _)| a)),
        days: Arc::new(publish::Archive::new()),
        parts: publish::Parts::this_program(&paths()?.out_dir, None)?,
        today: || chrono::Utc::now().date_naive(),
    };
    let list = f.clone();
    let write_list: tui::kill::WriteList = Arc::new(move || Ok(ssh_config(&list)?.summary));
    Ok(tui::admin::Screen::new(a).at(&host).with_publisher(publisher).with_write_list(write_list))
}

const RELEASE_USAGE: &str = r#"usage: dryserver release publish|status|resume [flags]

  publish   sign a release of this dryserver and send it to the
            coordinator. Everything is checked first and you see what
            changes before you say yes. The coordinator updates itself
            first, then one server at a time: normal releases in the
            update window 03:00-05:00 on its clock, urgent ones at once.
              -notes "TEXT"   what it is for, shown with it
              -urgent         roll out at once (a security fix)
              -rollback       allow older versions: the way back
              -arch-date D    the Arch snapshot day YYYY/MM/DD (default: the
                              newest day on archive.archlinux.org)
              -k3s FILE       the pinned k3s (default: pkgcache/k3s-VERSION in
                              the images folder, from dryserver build)
              -yes            do not ask
  status    the release, where its rollout stands, one line per machine,
            and what to do when it stopped
  resume    let a stopped rollout go on (it says what that does first):
            the server it stopped at tries again (once it is back, if it is
            off), one that could not be drained updates without
              -skip           pass that server over for this release
                              instead; it keeps its release until the
                              next one

  every command also takes -config FILE, -host ADDRESS and -port N
"#;

fn run_release(args: &[String]) -> Result<()> {
    let Some(sub) = args.first() else {
        eprint!("{RELEASE_USAGE}");
        std::process::exit(2);
    };
    let rest = &args[1..];
    if matches!(sub.as_str(), "-h" | "--help" | "help") {
        print!("{RELEASE_USAGE}");
        return Ok(());
    }
    if Path::new(LIVE_CONFIG).exists() {
        // Only the computer with the signing key makes releases.
        bail!("release runs on your own computer, where the signing key is:\n  dryserver release {sub}");
    }
    match sub.as_str() {
        "publish" => release_publish(rest),
        "status" => {
            let f = Flags::parse("release status", rest, DESKTOP_FLAGS);
            let (mut a, _) = release_admin(&f, "release status")?;
            print_rollout(&mut a)
        }
        "resume" => {
            let mut spec = DESKTOP_FLAGS.to_vec();
            spec.push(("skip", "false", "pass the server the rollout stopped at over for this release, instead of trying it again"));
            let f = Flags::parse("release resume", rest, &spec);
            let (mut a, _) = release_admin(&f, "release resume")?;
            let what = if f.on("skip") { publish::skip(&mut a) } else { publish::resume(&mut a) };
            let what = what.map_err(|e| e.wrap("not resumed"))?;
            println!("Resumed: the coordinator {}, at its next sync (within a minute).\n", report::printable(&what));
            print_rollout(&mut a)
        }
        other => {
            eprint!("unknown release command {other:?}\n\n{RELEASE_USAGE}");
            std::process::exit(2);
        }
    }
}

/// The admin's link for a release command, with a word first when
/// ssh-keygen is going to ask for the signing key's passphrase.
fn release_admin(f: &Flags, cmd: &str) -> Result<(admin::Admin, String)> {
    let a = desktop_admin(f, cmd)?;
    let secrets = paths()?.secrets;
    let legacy = secrets.join(iso::SIGNING_KEY_NAME);
    let asks = if legacy.exists() {
        publish::has_passphrase(&legacy).then(|| legacy.display().to_string())
    } else {
        match signed::OwnKeySigner::for_user(secrets.join(iso::SIGNING_PUB)).locate()? {
            signed::KeyAt::File { path, passphrase: true } => {
                Some(format!("{} (ssh-add {} once, and it asks no more)", path.display(), path.display()))
            }
            _ => None,
        }
    };
    if let Some(k) = asks {
        eprintln!("{k} has a passphrase: ssh-keygen asks for it at each signature (to read the coordinator's state, and to sign).");
    }
    Ok(a)
}

/// The newest release, where its rollout stands, one line per machine.
fn print_rollout(a: &mut admin::Admin) -> Result<()> {
    let v = a.load()?;
    for w in &v.warnings {
        eprintln!("warning: {}", report::printable(w));
    }
    for l in publish::status_lines(&v, Time::now().0.timestamp()) {
        println!("{l}");
    }
    Ok(())
}

fn release_publish(args: &[String]) -> Result<()> {
    let mut spec = DESKTOP_FLAGS.to_vec();
    spec.extend([
        ("notes", "", "what the release is for, shown with it (printable ASCII, at most 200 bytes)"),
        ("urgent", "false", "roll out at once, not in the nightly update window (a security fix)"),
        ("rollback", "false", "allow older versions than the machines run: the way back from a bad release"),
        ("arch-date", "", "the Arch snapshot day YYYY/MM/DD (default: the newest day on archive.archlinux.org)"),
        ("k3s", "", "the pinned k3s binary (default: pkgcache/k3s-VERSION in the images folder, from dryserver build)"),
        ("yes", "false", "sign and send without asking"),
    ]);
    let f = Flags::parse("release publish", args, &spec);
    let (mut a, host) = release_admin(&f, "release publish")?;
    let v = a.load().map_err(|e| e.wrap("not published, nothing was signed"))?;
    for w in &v.warnings {
        eprintln!("warning: {}", report::printable(w));
    }
    // The release is this binary: the one the admin runs now.
    let k3s = match f.get("k3s") {
        "" => None,
        p => Some(PathBuf::from(p)),
    };
    let parts = publish::Parts::this_program(&paths()?.out_dir, k3s)?;
    let choice = publish::Choice {
        arch_date: f.get("arch-date").into(),
        notes: f.get("notes").into(),
        urgent: f.on("urgent"),
        rollback: f.on("rollback"),
    };
    println!("Checking the release: the binary, the k3s file, the Arch archive, the coordinator...");
    let today = chrono::Utc::now().date_naive();
    let plan = publish::plan(&Ctx::new(), &a, &v, &publish::Archive::new(), &parts, &choice, today)
        .map_err(|e| e.wrap("not published, nothing was signed"))?;
    for l in plan.lines() {
        println!("{l}");
    }
    if !f.on("yes") {
        print!("Sign it and send it to the coordinator at {host}? [y/N] ");
        use std::io::Write;
        let _ = std::io::stdout().flush();
        let mut answer = String::new();
        let _ = std::io::stdin().read_line(&mut answer);
        if !matches!(answer.trim(), "y" | "Y" | "yes") {
            println!("Nothing signed.");
            return Ok(());
        }
    }
    let r = publish::publish(&mut a, &plan).map_err(|e| e.wrap("not published"))?;
    println!("Release {} is on the coordinator. It updates itself first, then one server at a time.", r.serial);
    println!("Watch it: dryserver release status, or dryserver approve");
    println!("Stop or go back: publish a fixed release, or the old dryserver with -rollback.");
    Ok(())
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

// ---- updates ----

fn update_machine() -> Result<update::Machine> {
    if !fsx::is_root() {
        bail!("run as root (sudo)");
    }
    Ok(update::Machine::installed(Arc::new(ExecRunner::silent())))
}

/// An update keeps going when the admin's SSH session drops half way (a
/// firewall reload may do that); output errors are ignored for the same
/// reason.
fn keep_going_on_hangup() {
    // SAFETY: setting signal dispositions; no handlers are installed.
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

fn run_update(args: &[String]) -> Result<()> {
    const HELP: &str = "usage: dryserver update apply|confirm|revert|status (see dryserver help)";
    let Some((sub, rest)) = args.split_first() else { bail!("{HELP}") };
    let name = format!("update {sub}");
    let now = chrono::Utc::now().timestamp();
    let mut out = std::io::stdout();
    match sub.as_str() {
        "apply" => {
            let window = update::WINDOW.to_string();
            let f = Flags::parse(
                &name,
                rest,
                &[
                    ("release", "", "the signed release (JSON envelope)"),
                    ("binary", "", "the dryserver binary it names"),
                    ("k3s", "", "the k3s binary it names (needed when this machine runs another k3s)"),
                    ("brain-k3s", "", "the k3s version the coordinator runs (default: this server's own)"),
                    ("window", &window, "seconds from the end of the apply until an unconfirmed update reverts by itself"),
                    ("reboot", "false", "reboot when the new packages need it and the machine can come back by itself"),
                    ("detach", "false", "run in a service of its own and return at once (dryserver update status follows it)"),
                ],
            );
            if f.get("release").is_empty() || f.get("binary").is_empty() {
                bail!("update apply: --release and --binary are required");
            }
            let window = f.get("window").parse().map_err(|_| errf!("update apply: --window must be a number of seconds"))?;
            let m = update_machine()?;
            keep_going_on_hangup();
            let a = update::Apply {
                release: f.get("release").into(),
                binary: f.get("binary").into(),
                k3s: Some(f.get("k3s")).filter(|k| !k.is_empty()).map(PathBuf::from),
                brain_k3s: f.get("brain-k3s").into(),
                window,
                reboot: f.on("reboot"),
            };
            if f.on("detach") {
                return update::start_detached(&m, &Ctx::new().with_timeout(Duration::from_secs(60)), &a, &mut out);
            }
            update::apply(&m, &Ctx::on_signals(), &a, now, &mut out)
        }
        "confirm" => {
            let f = Flags::parse(&name, rest, &[("serial", "", "the release that must be the one waiting")]);
            let serial = match f.get("serial") {
                "" => None,
                s => Some(s.parse().map_err(|_| errf!("update confirm: --serial must be a number"))?),
            };
            let m = update_machine()?;
            keep_going_on_hangup();
            update::confirm(&m, &Ctx::new(), serial, now, &mut out)
        }
        "revert" => {
            Flags::parse(&name, rest, &[]);
            let m = update_machine()?;
            keep_going_on_hangup();
            update::revert_by_hand(&m, &Ctx::new(), now, &mut out)
        }
        "status" => {
            let f = Flags::parse(&name, rest, &[("json", "false", "print JSON, for the machine report and the monitor")]);
            let s = update::status(&update_machine()?, now);
            if f.on("json") {
                println!("{}", serde_json::to_string_pretty(&s)?);
            } else {
                update::print_status(&s, &mut out);
            }
            Ok(())
        }
        // Run by the revert timer and the boot unit.
        "guard" => {
            let f = Flags::parse(
                &name,
                rest,
                &[
                    ("id", "", "the update the timer was armed for"),
                    ("applying", "false", "the timer armed when the apply started"),
                    ("boot", "false", "the machine just started"),
                    ("started-it", "false", "go on only as the binary that started the update"),
                ],
            );
            let m = update_machine()?;
            keep_going_on_hangup();
            if f.on("started-it") {
                // The running program's file (a hard link, no symbolic one);
                // one replaced since it started does not read, and the next
                // binary in line goes.
                let own = std::env::current_exe().map_err(|e| err::Error::from(e).wrap("find the running program"))?;
                update::started_it(&m, &own)?;
            }
            match (f.get("id"), f.on("boot")) {
                ("", true) => update::guard_boot(&m, &Ctx::new(), now, &mut out),
                (id, false) if !id.is_empty() => update::guard_timer(&m, &Ctx::new(), id, f.on("applying"), now, &mut out),
                _ => bail!("update guard: give --id or --boot"),
            }
        }
        // The new binary's half of apply; apply runs it (see update.rs,
        // the handover). handover says which protocol this binary speaks.
        "handover" => {
            Flags::parse(&name, rest, &[]);
            println!("{}", update::HANDOVER);
            Ok(())
        }
        "prepare" => {
            let f = Flags::parse(&name, rest, &[("id", "", "the update being applied")]);
            let m = update_machine()?;
            keep_going_on_hangup();
            update::prepare(&m, &Ctx::on_signals(), f.get("id"), &mut out)
        }
        "activate" => {
            let f = Flags::parse(&name, rest, &[("id", "", "the update being applied")]);
            let m = update_machine()?;
            keep_going_on_hangup();
            update::activate(&m, &Ctx::on_signals(), f.get("id"), &mut out)
        }
        _ => bail!("unknown update command {sub:?}\n{HELP}"),
    }
}

fn run_selfcheck(args: &[String]) -> Result<()> {
    Flags::parse("selfcheck", args, &[]);
    let m = update_machine()?;
    let ctx = Ctx::on_signals().with_timeout(Duration::from_secs(30));
    update::print_checks(&update::selfcheck(&m, &ctx), &mut std::io::stdout())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(l: &[&str]) -> Vec<String> {
        l.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_install_log_is_never_opened_through_a_link() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let dir = testutil::TempDir::new();
        let log = dir.join("install.log");
        open_log(&log).unwrap().write_all(b"one\n").unwrap();
        open_log(&log).unwrap().write_all(b"two\n").unwrap();
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "one\ntwo\n", "appended to");
        assert_eq!(std::fs::metadata(&log).unwrap().permissions().mode() & 0o777, 0o600);
        // A link put in its place, to a file the installer must not touch.
        let target = dir.join("shadow");
        std::fs::write(&target, "untouched").unwrap();
        let link = dir.join("linked.log");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(open_log(&link).is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched");
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
