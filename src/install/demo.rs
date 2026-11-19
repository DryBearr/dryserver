//! Pretends to install so the setup screen can be tried on any machine. It
//! never touches a disk or the network.

use std::sync::Mutex;
use std::time::Duration;

use super::{Backend, Choices, Machine, Progress, Step};
use crate::config::Config;
use crate::ctx::Ctx;
use crate::disks::{Disk, Part};
use crate::err::Result;

pub type ApproveFn = Box<dyn Fn() -> Result<u32> + Send + Sync>;

pub struct Demo {
    pub machine: Mutex<Machine>,
    /// Pause per fake step; 0 in tests.
    pub delay: Duration,
    /// Decides the join result; None approves as host 7.
    pub approve: Option<ApproveFn>,
}

impl Default for Demo {
    fn default() -> Self {
        Demo::new()
    }
}

impl Demo {
    pub fn new() -> Demo {
        let part = |path: &str, size, fstype: &str, label: &str| Part {
            path: path.into(),
            size,
            fstype: fstype.into(),
            label: label.into(),
            mountpoints: vec![],
        };
        Demo {
            delay: Duration::from_millis(400),
            approve: None,
            machine: Mutex::new(Machine {
                cpu: "Intel Core i5-6300U (demo)".into(),
                ram: 8 << 30,
                uefi: true,
                tpm2: true,
                tpm_chip: true,
                disks: vec![
                    Disk {
                        name: "nvme0n1".into(),
                        path: "/dev/nvme0n1".into(),
                        size: 256_060_514_304,
                        model: "SAMSUNG MZVLW256".into(),
                        tran: "nvme".into(),
                        parts: vec![
                            part("/dev/nvme0n1p1", 272_629_760, "vfat", ""),
                            part("/dev/nvme0n1p3", 255_000_000_000, "ntfs", "Windows"),
                        ],
                        ..Disk::default()
                    },
                    Disk {
                        name: "sda".into(),
                        path: "/dev/sda".into(),
                        size: 500_107_862_016,
                        model: "ST500LM021".into(),
                        tran: "sata".into(),
                        ..Disk::default()
                    },
                ],
                online: true,
                net: "WiFi Home (192.168.1.23)".into(),
                coord_found: true,
            }),
        }
    }

    fn sleep(&self, ctx: &Ctx) -> Result<()> {
        ctx.sleep(self.delay)
    }
}

const DEMO_STEPS: [&str; 5] = ["Partition disk", "Set up encryption", "Install packages", "Configure system", "Install boot loader"];

impl Backend for Demo {
    fn probe(&self, ctx: &Ctx) -> Result<Machine> {
        self.sleep(ctx)?;
        Ok(self.machine.lock().unwrap().clone())
    }

    fn scan_wifi(&self, ctx: &Ctx) -> Result<Vec<String>> {
        self.sleep(ctx)?;
        Ok(vec!["Home".into(), "Neighbor 5G".into(), "CoffeeShop".into()])
    }

    fn connect_wifi(&self, ctx: &Ctx, ssid: &str, pass: &str) -> Result<Machine> {
        self.sleep(ctx)?;
        if pass == "wrong" {
            return Err("wrong password or network out of range".into());
        }
        let mut m = self.machine.lock().unwrap();
        m.online = true;
        m.net = format!("WiFi {ssid} (192.168.1.23)");
        Ok(m.clone())
    }

    fn precheck(&self, ctx: &Ctx, _: &Config, _: &Choices, progress: Progress) -> Result<()> {
        for name in ["Check the clock", "Pick package mirrors", "Update package lists", "Check the coordinator"] {
            progress(Step::start(name));
            progress(Step { name: name.into(), done: false, log: format!("demo: {name}") });
            self.sleep(ctx)?;
            progress(Step::finished(name));
        }
        Ok(())
    }

    fn install(&self, ctx: &Ctx, _: &Config, ch: &Choices, progress: Progress) -> Result<()> {
        for name in DEMO_STEPS {
            progress(Step::start(name));
            progress(Step { name: name.into(), done: false, log: format!("demo: {name} on {}", ch.system_disk) });
            self.sleep(ctx)?;
            progress(Step::finished(name));
        }
        Ok(())
    }

    fn join(&self, ctx: &Ctx, _: &Config, _: &Choices, code: &(dyn Fn(String) + Send + Sync)) -> Result<u32> {
        code("482 913".into());
        self.sleep(ctx)?;
        self.sleep(ctx)?;
        match &self.approve {
            Some(f) => f(),
            None => Ok(7),
        }
    }

    fn reboot(&self) -> Result<()> {
        Ok(())
    }
}
