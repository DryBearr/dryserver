//! The real backend: runs inside the live installer system as root.

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;

use super::{Layout, Machine};
use crate::config::Config;
use crate::ctx::Ctx;
use crate::disks;
use crate::err::Result;
use crate::runner::{Cmd, ExecRunner, Runner};
use crate::{fsx, sysconf};

/// Receives log lines while a step runs.
pub type Sink = Arc<dyn Fn(&str) + Send + Sync>;

/// Where every log line goes: always the log file, and the setup screen
/// while a step runs.
#[derive(Default)]
pub struct LogSink {
    pub file: Mutex<Option<File>>,
    sink: Mutex<Option<Sink>>,
    /// "758.70 MiB", from pacman's output.
    dl_total: Mutex<String>,
}

impl LogSink {
    pub fn log(&self, line: &str) {
        if let Some(total) = line.strip_prefix("Total Download Size:") {
            *self.dl_total.lock().unwrap() = total.trim().to_string();
        }
        if let Some(f) = self.file.lock().unwrap().as_mut() {
            let _ = writeln!(f, "{line}");
        }
        let sink = self.sink.lock().unwrap().clone();
        if let Some(s) = sink {
            s(line);
        }
    }

    pub fn set_sink(&self, f: Option<Sink>) {
        *self.sink.lock().unwrap() = f;
    }

    pub fn dl_total(&self) -> String {
        self.dl_total.lock().unwrap().clone()
    }
}

/// What install leaves for join and reboot.
#[derive(Debug, Clone, Default)]
pub(super) struct InstallState {
    pub layout: Layout,
    /// Opened LUKS mappers, closed on reboot.
    pub mapped: Vec<String>,
    pub wg_public: String,
    /// The new system's SSH host public key.
    pub host_key: String,
    pub data_uuids: Vec<String>,
    pub switch_mac: String,
    pub first_boot_key: Option<Vec<u8>>,
    pub installed: bool,
}

pub type NetCheck = Box<dyn Fn(&Ctx) -> bool + Send + Sync>;

/// Installs for real.
pub struct Real {
    pub cfg: Config,
    pub run: Arc<dyn Runner>,
    /// Files for the installed system, by path without the leading slash.
    pub rootfs: HashMap<String, Vec<u8>>,
    /// This binary, copied into the installed system.
    pub self_path: PathBuf,
    /// The private key nodes use to reach the coordinator's registry; baked
    /// into the ISO by the build.
    pub registry_key: PathBuf,
    /// Mount point of the new system, normally /mnt.
    pub target: PathBuf,
    /// RAM-backed dir for temporary keyfiles, normally /run.
    pub key_dir: PathBuf,
    /// The live system's pacman mirror list.
    pub mirror_list: PathBuf,
    pub log: Arc<LogSink>,
    pub(super) machine: Mutex<Machine>,
    pub(super) state: Mutex<InstallState>,
    /// Whether the mirrors can be reached; None means a real connection
    /// test (tests replace it).
    pub(super) net_check: Option<NetCheck>,
    /// How often wait_network checks again.
    pub(super) net_poll: Duration,
}

impl Real {
    pub fn new(cfg: Config, rootfs: HashMap<String, Vec<u8>>, self_path: impl Into<PathBuf>, registry_key: impl Into<PathBuf>) -> Real {
        let log = Arc::new(LogSink::default());
        let l = log.clone();
        let run: Arc<dyn Runner> = Arc::new(ExecRunner::new(Arc::new(move |line: &str| l.log(line))));
        Real {
            cfg,
            run,
            rootfs,
            self_path: self_path.into(),
            registry_key: registry_key.into(),
            target: PathBuf::from("/mnt"),
            key_dir: PathBuf::from("/run"),
            mirror_list: PathBuf::from("/etc/pacman.d/mirrorlist"),
            log,
            machine: Mutex::new(Machine::default()),
            state: Mutex::new(InstallState::default()),
            net_check: None,
            net_poll: Duration::from_secs(5),
        }
    }

    pub(super) fn log(&self, line: &str) {
        self.log.log(line);
    }

    /// path inside the new system.
    pub(super) fn target(&self, path: &str) -> PathBuf {
        fsx::under(&self.target, path)
    }

    pub(super) fn cmd(&self, ctx: &Ctx, name: &str, args: &[&str]) -> Result<()> {
        self.run.ok(ctx, &Cmd::new(name, args))
    }

    pub(super) fn chroot(&self, ctx: &Ctx, args: &[&str]) -> Result<()> {
        let target = self.target.display().to_string();
        let mut all = vec![target.as_str()];
        all.extend_from_slice(args);
        self.cmd(ctx, "arch-chroot", &all)
    }

    pub(super) fn probe_impl(&self, ctx: &Ctx) -> Result<Machine> {
        let tpm_chip = fsx::read_or_empty("/sys/class/tpm/tpm0/tpm_version_major").trim() == "2";
        let mut m = Machine {
            cpu: cpu_model(),
            ram: mem_total(),
            uefi: fsx::exists("/sys/firmware/efi"),
            tpm_chip,
            // The firmware's event log exists only if it measured the boot.
            tpm2: tpm_chip && fsx::exists("/sys/kernel/security/tpm0/binary_bios_measurements"),
            ..Machine::default()
        };
        m.disks = disks::installable(&disks::list()?);
        (m.online, m.net) = self.online(ctx);
        if !m.online && !self.cfg.wifi_ssid.is_empty() {
            // iwd connects to known networks by itself once the file exists.
            if self.add_wifi(&self.cfg.wifi_ssid, &self.cfg.wifi_pass).is_ok() {
                (m.online, m.net) = self.wait_online(ctx, Duration::from_secs(25));
            }
        }
        if m.online {
            m.coord_found = tcp_answers(&self.cfg.coord_lan_ip, 22, Duration::from_secs(3));
        }
        *self.machine.lock().unwrap() = m.clone();
        Ok(m)
    }

    fn online(&self, ctx: &Ctx) -> (bool, String) {
        if !tcp_answers("archlinux.org", 443, Duration::from_secs(4)) {
            return (false, String::new());
        }
        (true, self.describe_route(ctx))
    }

    fn wait_online(&self, ctx: &Ctx, limit: Duration) -> (bool, String) {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline {
            let (ok, desc) = self.online(ctx);
            if ok {
                return (true, desc);
            }
            if ctx.sleep(Duration::from_secs(2)).is_err() {
                return (false, String::new());
            }
        }
        (false, String::new())
    }

    /// Which link carries internet, e.g. "WiFi wlan0 (192.168.1.23)".
    fn describe_route(&self, ctx: &Ctx) -> String {
        #[derive(Deserialize)]
        struct Route {
            #[serde(default)]
            dev: String,
            #[serde(default)]
            prefsrc: String,
        }
        let Ok(out) = self.run.output(ctx, &Cmd::new("ip", &["-j", "route", "get", "1.1.1.1"]).quiet()) else {
            return "connected".into();
        };
        let routes: Vec<Route> = serde_json::from_str(&out).unwrap_or_default();
        let Some(r) = routes.first() else {
            return "connected".into();
        };
        let kind = if fsx::exists(format!("/sys/class/net/{}/wireless", r.dev)) { "WiFi" } else { "Ethernet" };
        format!("{kind} {} ({})", r.dev, r.prefsrc)
    }

    /// Stores the network for the live system's iwd only (RAM).
    fn add_wifi(&self, ssid: &str, pass: &str) -> Result<()> {
        let f = sysconf::iwd_file(ssid, pass);
        fsx::mkdir_all("/var/lib/iwd", 0o700)?;
        fsx::write_file(&f.path, &f.content, 0o600)
    }

    pub(super) fn scan_wifi_impl(&self, ctx: &Ctx) -> Result<Vec<String>> {
        let dev = wifi_device()?;
        let _ = self.run.run(ctx, &Cmd::new("iwctl", &["station", &dev, "scan"]).quiet());
        ctx.sleep(Duration::from_secs(4))?;
        let out = self.run.output(ctx, &Cmd::new("iwctl", &["station", &dev, "get-networks"]).quiet())?;
        Ok(parse_networks(&out))
    }

    pub(super) fn connect_wifi_impl(&self, ctx: &Ctx, ssid: &str, pass: &str) -> Result<Machine> {
        let dev = wifi_device()?;
        self.add_wifi(ssid, pass)?;
        if self.cmd(ctx, "iwctl", &["station", &dev, "connect", ssid]).is_err() {
            return Err("wrong password or network out of range".into());
        }
        let (ok, desc) = self.wait_online(ctx, Duration::from_secs(20));
        if !ok {
            return Err("connected to WiFi but no internet".into());
        }
        let mut m = self.machine.lock().unwrap();
        m.online = true;
        m.net = desc;
        m.coord_found = tcp_answers(&self.cfg.coord_lan_ip, 22, Duration::from_secs(3));
        Ok(m.clone())
    }

    pub(super) fn reboot_impl(&self) -> Result<()> {
        let ctx = Ctx::new();
        let target = self.target.display().to_string();
        let _ = self.cmd(&ctx, "sync", &[]);
        let _ = self.cmd(&ctx, "umount", &["-R", &target]);
        let mapped = self.state.lock().unwrap().mapped.clone();
        for m in mapped {
            let _ = self.cmd(&ctx, "cryptsetup", &["close", &m]);
        }
        self.cmd(&ctx, "systemctl", &["reboot"])
    }
}

/// Whether something accepts TCP connections at host:port within timeout.
pub(crate) fn tcp_answers(host: &str, port: u16, timeout: Duration) -> bool {
    let Ok(addrs) = (host, port).to_socket_addrs() else {
        return false;
    };
    addrs.into_iter().any(|a| TcpStream::connect_timeout(&a, timeout).is_ok())
}

/// The same with the error, for log messages.
pub(crate) fn tcp_dial(host: &str, port: u16, timeout: Duration) -> std::result::Result<(), String> {
    let addrs = (host, port).to_socket_addrs().map_err(|e| crate::err::os_msg(&e))?;
    let mut last = String::from("no address");
    for a in addrs {
        match TcpStream::connect_timeout(&a, timeout) {
            Ok(_) => return Ok(()),
            Err(e) => last = format!("dial tcp {a}: {}", crate::err::os_msg(&e)),
        }
    }
    Err(last)
}

fn wifi_device() -> Result<String> {
    if let Ok(ents) = std::fs::read_dir("/sys/class/net") {
        let mut names: Vec<String> = ents.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        for n in names {
            if Path::new("/sys/class/net").join(&n).join("wireless").exists() {
                return Ok(n);
            }
        }
    }
    Err("no WiFi adapter found".into())
}

/// Removes ANSI escape sequences like "\x1b[1;90m".
fn strip_ansi(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == 0x1b && i + 1 < b.len() && b[i + 1] == b'[' {
            let mut j = i + 2;
            while j < b.len() && (b[j].is_ascii_digit() || b[j] == b';') {
                j += 1;
            }
            if j < b.len() && b[j].is_ascii_alphabetic() {
                i = j + 1;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Reads SSIDs from `iwctl station DEV get-networks`, a fixed-width table
/// whose "Network name" column ends where "Security" starts.
pub fn parse_networks(out: &str) -> Vec<String> {
    let mut ssids = Vec::new();
    let (mut start, mut end): (Option<usize>, Option<usize>) = (None, None);
    for line in strip_ansi(out).lines() {
        if let Some(i) = line.find("Network name") {
            start = Some(i);
            end = line.find("Security");
            continue;
        }
        let (Some(s), Some(e)) = (start, end) else {
            continue;
        };
        let b = line.as_bytes();
        if e <= s || line.trim().starts_with("---") || b.len() <= s {
            continue;
        }
        let name = String::from_utf8_lossy(&b[s..e.min(b.len())]).trim().to_string();
        if !name.is_empty() {
            ssids.push(name);
        }
    }
    ssids
}

fn cpu_model() -> String {
    for line in fsx::read_or_empty("/proc/cpuinfo").lines() {
        if let Some((k, v)) = line.split_once(':')
            && k.trim() == "model name"
        {
            return v.trim().to_string();
        }
    }
    "unknown".into()
}

fn mem_total() -> u64 {
    for line in fsx::read_or_empty("/proc/meminfo").lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 2 && f[0] == "MemTotal:" {
            return f[1].parse::<u64>().unwrap_or(0) * 1024;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn networks_from_iwctl() {
        let out = "                               Available networks\n\
                   --------------------------------------------------------------------------------\n\
                   \x20     Network name                      Security            Signal\n\
                   --------------------------------------------------------------------------------\n\
                   \x20 \x1b[1;90m> \x1b[0m  Home                              psk                 ****\n\
                   \x20     My Neighbor 5G                    psk                 ***\n\
                   \x20     Cafe                              open                *\n";
        assert_eq!(parse_networks(out).join("|"), "Home|My Neighbor 5G|Cafe");
    }
}
