//! Frees an old disk before it is repartitioned, and checks the kernel sees
//! the new partition table afterwards.

use serde::Deserialize;

use super::Real;
use crate::ctx::Ctx;
use crate::err::Result;
use crate::errf;
use crate::runner::Cmd;

/// One node of `lsblk -J -p -o NAME,TYPE,SIZE,MOUNTPOINTS`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub(super) struct BlockDev {
    pub name: String,
    #[serde(rename = "type")]
    pub typ: String,
    pub size: Option<u64>,
    pub mountpoints: Option<Vec<Option<String>>>,
    pub children: Option<Vec<BlockDev>>,
}

impl Real {
    fn lsblk(&self, ctx: &Ctx, dev: &str) -> Result<BlockDev> {
        let out =
            self.run.output(ctx, &Cmd::new("lsblk", &["-J", "-b", "-p", "-o", "NAME,TYPE,SIZE,MOUNTPOINTS", dev]).quiet().stdout_only())?;
        #[derive(Deserialize)]
        struct Doc {
            #[serde(default)]
            blockdevices: Vec<BlockDev>,
        }
        match serde_json::from_str::<Doc>(&out) {
            Ok(d) if d.blockdevices.len() == 1 => Ok(d.blockdevices.into_iter().next().unwrap()),
            _ => Err(errf!("cannot read the layout of {dev}")),
        }
    }

    /// Stops everything the live system started on an old disk before it is
    /// repartitioned: mounts and swap, LVM volumes, encrypted mappings (also
    /// ones left open by an earlier setup attempt) and RAID sets. Otherwise
    /// sfdisk refuses: "This disk is currently in use".
    pub(super) fn release_disk(&self, ctx: &Ctx, disk: &str) -> Result<()> {
        let top = self.lsblk(ctx, disk)?;
        // Children before parents, so stacked devices come apart top-down.
        fn walk(d: &BlockDev, order: &mut Vec<BlockDev>) {
            for c in d.children.iter().flatten() {
                walk(c, order);
            }
            order.push(d.clone());
        }
        let mut order = Vec::new();
        walk(&top, &mut order);

        for d in &order {
            for m in d.mountpoints.iter().flatten().flatten() {
                match m.as_str() {
                    "" => {}
                    "[SWAP]" => self.cmd(ctx, "swapoff", &[&d.name])?,
                    _ => self.cmd(ctx, "umount", &["-R", m])?,
                }
            }
            let t = d.typ.as_str();
            let res = if d.name == top.name || t == "part" {
                Ok(())
            } else if matches!(t, "lvm" | "crypt" | "dm" | "mpath") {
                self.cmd(ctx, "dmsetup", &["remove", "--retry", &d.name])
            } else if t.starts_with("raid") || t == "md" || t == "linear" {
                self.cmd(ctx, "mdadm", &["--stop", &d.name])
            } else {
                Ok(())
            };
            // A RAID container built from whole disks shows up as a child of
            // each member disk; stopping it here also frees the disk itself.
            res.map_err(|e| e.wrap(format!("{disk} is still in use by {} ({t})", d.name)))?;
        }
        Ok(())
    }

    /// Makes sure the kernel sees the new partition table: the expected
    /// number of partitions, the first one first_size bytes (the boot
    /// partition) when first_size is not 0.
    pub(super) fn check_layout(&self, ctx: &Ctx, disk: &str, parts: usize, first_size: u64) -> Result<()> {
        let d = self.lsblk(ctx, disk)?;
        let got: Vec<&BlockDev> = d.children.iter().flatten().filter(|c| c.typ == "part").collect();
        if got.len() != parts || (first_size > 0 && got[0].size.unwrap_or(0) != first_size) {
            return Err(errf!("the kernel still sees the old partitions of {disk}; reboot from the USB and run the setup again"));
        }
        Ok(())
    }
}
