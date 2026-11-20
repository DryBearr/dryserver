//! What the laptop setup screen needs: the machine description, the user's
//! choices and the Backend that does the work. The real backend wipes and
//! installs; the demo backend only pretends, so the screens can be tried
//! and tested anywhere.

mod demo;
mod layout;
mod precheck;
mod real;
mod release;
mod steps;

use std::sync::Arc;

pub use demo::Demo;
pub use layout::*;
pub use real::Real;

use crate::config::Config;
use crate::ctx::Ctx;
use crate::disks::Disk;
use crate::err::Result;
use crate::errf;
use crate::fsx;
use crate::sysconf::Role;

/// The laptop the installer runs on.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Machine {
    pub cpu: String,
    /// Bytes.
    pub ram: u64,
    pub uefi: bool,
    /// A TPM 2.0 chip whose firmware measures the boot, which TPM unlock
    /// needs. tpm_chip alone means the chip exists but the firmware does not
    /// measure (TPM unlock would never work).
    pub tpm2: bool,
    pub tpm_chip: bool,
    /// Install targets: internal disks, live USB excluded.
    pub disks: Vec<Disk>,
    pub online: bool,
    /// e.g. "WiFi wlan0 (192.168.1.23)"
    pub net: String,
    /// Something answers SSH at the configured coordinator address, so this
    /// laptop is most likely not the first one.
    pub coord_found: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Encryption {
    /// LUKS2, unlocked by the TPM; passphrase as fallback.
    Tpm,
    /// LUKS2, passphrase at every boot.
    #[default]
    Passphrase,
    None,
}

impl Encryption {
    pub fn as_str(&self) -> &'static str {
        match self {
            Encryption::Tpm => "tpm",
            Encryption::Passphrase => "passphrase",
            Encryption::None => "none",
        }
    }

    pub fn parse(s: &str) -> Option<Encryption> {
        match s {
            "tpm" => Some(Encryption::Tpm),
            "passphrase" => Some(Encryption::Passphrase),
            "none" => Some(Encryption::None),
            _ => None,
        }
    }
}

impl Machine {
    /// The modes this machine supports, best first. TPM unlock needs UEFI
    /// (signed UKI) and a TPM 2.0 chip.
    pub fn encryption_options(&self) -> Vec<Encryption> {
        if self.uefi && self.tpm2 {
            vec![Encryption::Tpm, Encryption::Passphrase, Encryption::None]
        } else {
            vec![Encryption::Passphrase, Encryption::None]
        }
    }
}

/// The answers from the setup screen.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Choices {
    /// None until the setup screen picks a default from the network.
    pub role: Option<Role>,
    pub hostname: String,
    /// Device path.
    pub system_disk: String,
    /// Device paths, encrypted and mounted under /data.
    pub data_disks: Vec<String>,
    /// None until the setup screen picks the machine's best option.
    pub encryption: Option<Encryption>,
    pub disk_passphrase: String,
    pub user_password: String,
}

impl Choices {
    pub fn role(&self) -> Role {
        self.role.unwrap_or_default()
    }

    pub fn enc(&self) -> Encryption {
        self.encryption.unwrap_or_default()
    }
}

/// Install progress. A step is sent when it starts (done false) and when it
/// ends; log carries output lines in between.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Step {
    pub name: String,
    pub done: bool,
    pub log: String,
}

impl Step {
    pub fn start(name: &str) -> Step {
        Step { name: name.into(), ..Step::default() }
    }

    pub fn finished(name: &str) -> Step {
        Step { name: name.into(), done: true, ..Step::default() }
    }

    pub fn line(log: impl Into<String>) -> Step {
        Step { log: log.into(), ..Step::default() }
    }
}

pub type Progress = Arc<dyn Fn(Step) + Send + Sync>;

/// How many steps Backend::install reports. The setup screen draws its
/// progress ring from it.
pub const INSTALL_STEPS: usize = 5;

pub trait Backend: Send + Sync {
    fn probe(&self, ctx: &Ctx) -> Result<Machine>;
    fn scan_wifi(&self, ctx: &Ctx) -> Result<Vec<String>>;
    fn connect_wifi(&self, ctx: &Ctx, ssid: &str, pass: &str) -> Result<Machine>;
    /// Runs before anything is written: clock, package mirrors, extra
    /// packages, coordinator (node role). Reports steps and log lines like
    /// install.
    fn precheck(&self, ctx: &Ctx, cfg: &Config, ch: &Choices, progress: Progress) -> Result<()>;
    fn install(&self, ctx: &Ctx, cfg: &Config, ch: &Choices, progress: Progress) -> Result<()>;
    /// Sends the join request, reports the pairing code and blocks until
    /// the coordinator approves (returns the mesh host number) or rejects.
    /// Cancelling ctx skips joining; the server retries at boot.
    fn join(&self, ctx: &Ctx, cfg: &Config, ch: &Choices, code: &(dyn Fn(String) + Send + Sync)) -> Result<u32>;
    /// After a coordinator install: the code the admin compares on the
    /// desktop before signing this coordinator. "" when not known.
    fn coordinator_code(&self) -> String;
    fn reboot(&self) -> Result<()>;
}

pub const REJECTED: &str = "the coordinator rejected this machine";

pub fn valid_hostname(s: &str) -> Result<()> {
    if !s.is_empty() && !crate::registry::valid_name(s) {
        return Err("lowercase letters, digits and -, not starting or ending with -".into());
    }
    Ok(())
}

pub const MIN_DISK_PASSPHRASE: usize = 12;
pub const MIN_USER_PASSWORD: usize = 10;

pub fn valid_disk_passphrase(s: &str) -> Result<()> {
    if s.len() < MIN_DISK_PASSPHRASE {
        return Err(errf!("at least {MIN_DISK_PASSPHRASE} characters; a few random words work well"));
    }
    Ok(())
}

pub fn valid_user_password(s: &str) -> Result<()> {
    if s.len() < MIN_USER_PASSWORD {
        return Err(errf!("at least {MIN_USER_PASSWORD} characters"));
    }
    Ok(())
}

/// "coord" for the coordinator and node-<4 hex> otherwise.
pub fn default_hostname(role: Role) -> String {
    if role == Role::Coordinator {
        return "coord".into();
    }
    format!("node-{}", fsx::hex(&fsx::random_bytes(2)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_options() {
        let m = Machine { uefi: true, tpm2: true, ..Machine::default() };
        assert_eq!(m.encryption_options()[0], Encryption::Tpm);
        for m in [Machine { uefi: true, ..Machine::default() }, Machine { tpm2: true, ..Machine::default() }] {
            assert!(!m.encryption_options().contains(&Encryption::Tpm), "{m:?} must not offer TPM unlock");
        }
    }

    #[test]
    fn validators() {
        for h in ["", "node-1", "coord", "a"] {
            valid_hostname(h).unwrap_or_else(|e| panic!("{h:?} rejected: {e}"));
        }
        for h in ["Node", "-x", "x-", "a_b", "node.lan"] {
            assert!(valid_hostname(h).is_err(), "{h:?} accepted");
        }
        assert!(valid_disk_passphrase("short").is_err() && valid_user_password("short").is_err());
        let h = default_hostname(Role::Node);
        assert!(h.starts_with("node-") && h.len() == 9, "default hostname {h:?}");
    }
}
