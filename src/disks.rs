//! Lists block devices via lsblk and decides which ones are safe targets for
//! flashing and installing.

use std::process::Command;

use serde::Deserialize;

use crate::err::{Error, Result};
use crate::errf;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Disk {
    /// sdb
    pub name: String,
    /// /dev/sdb
    pub path: String,
    /// Bytes.
    pub size: u64,
    pub model: String,
    pub vendor: String,
    /// usb, nvme, sata, ...
    pub tran: String,
    pub removable: bool,
    pub read_only: bool,
    pub parts: Vec<Part>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Part {
    pub path: String,
    pub size: u64,
    pub fstype: String,
    pub label: String,
    pub mountpoints: Vec<String>,
}

/// Every whole disk with its partitions flattened (LVM, crypt and other
/// nested devices are folded into their parent disk).
pub fn list() -> Result<Vec<Disk>> {
    let out = Command::new("lsblk")
        .args(["-J", "-b", "-o", "NAME,PATH,SIZE,MODEL,VENDOR,TRAN,RM,RO,TYPE,FSTYPE,LABEL,MOUNTPOINTS"])
        .output()
        .map_err(|e| Error::from(e).wrap("lsblk"))?;
    if !out.status.success() {
        return Err(errf!("lsblk: {}", crate::runner::exit_text(out.status)));
    }
    parse(&out.stdout)
}

/// The disks that may be flashed: USB or removable, writable, non-empty,
/// and not holding any system mount.
pub fn usb(all: &[Disk]) -> Vec<Disk> {
    all.iter()
        .filter(|d| {
            // Floppy drives report as removable; skip them.
            !d.name.starts_with("fd") && (d.tran == "usb" || d.removable) && !d.read_only && d.size > 0 && !d.is_system()
        })
        .cloned()
        .collect()
}

/// The start of the installer ISO's filesystem label.
pub const LIVE_LABEL_PREFIX: &str = "DRYSRV_";

/// The smallest disk offered for installing (16 GB).
pub const MIN_INSTALL_SIZE: u64 = 16_000_000_000;

/// The disks the installer may use: real, writable disks of at least
/// MIN_INSTALL_SIZE, excluding the USB the installer booted from and disks
/// mounted anywhere but the installer's /mnt.
pub fn installable(all: &[Disk]) -> Vec<Disk> {
    all.iter()
        .filter(|d| {
            let virt = ["zram", "loop", "fd", "sr", "ram"].iter().any(|p| d.name.starts_with(p));
            !(virt || d.read_only || d.size < MIN_INSTALL_SIZE || d.is_live_media() || d.mounted_outside_target())
        })
        .cloned()
        .collect()
}

/// The disk with the given path from a fresh listing.
pub fn find(path: &str) -> Result<Disk> {
    list()?.into_iter().find(|d| d.path == path).ok_or_else(|| errf!("{path} not found"))
}

impl Disk {
    /// Something other than the installer's own target (/mnt, left over from
    /// a failed attempt) is mounted from the disk.
    fn mounted_outside_target(&self) -> bool {
        self.mounts().iter().any(|m| m != "/mnt" && !m.starts_with("/mnt/"))
    }

    fn is_live_media(&self) -> bool {
        self.parts.iter().any(|p| p.label.starts_with(LIVE_LABEL_PREFIX) || p.mountpoints.iter().any(|m| m.starts_with("/run/archiso")))
    }

    /// Anything on the disk is mounted outside the usual removable-media
    /// locations. Such a disk is never offered as a target.
    pub fn is_system(&self) -> bool {
        self.parts.iter().any(|p| p.mountpoints.iter().any(|m| !is_media_mount(m)))
    }

    pub fn mounts(&self) -> Vec<String> {
        self.parts.iter().flat_map(|p| p.mountpoints.iter().cloned()).collect()
    }

    pub fn title(&self) -> String {
        let name = format!("{} {}", self.vendor, self.model).trim().to_string();
        let name = if name.is_empty() { "unknown device".to_string() } else { name };
        format!("{}  {}  {}", self.path, human_size(self.size), name)
    }
}

fn is_media_mount(m: &str) -> bool {
    ["/run/media/", "/media/", "/mnt/"].iter().any(|p| m.starts_with(p))
}

/// 32015679488 -> "32.0 GB".
pub fn human_size(b: u64) -> String {
    const UNIT: u64 = 1000;
    if b < UNIT {
        return format!("{b} B");
    }
    let (mut div, mut exp) = (UNIT, 0);
    let mut n = b / UNIT;
    while n >= UNIT {
        div *= UNIT;
        exp += 1;
        n /= UNIT;
    }
    format!("{:.1} {}B", b as f64 / div as f64, "kMGTPE".as_bytes()[exp] as char)
}

/// Accepts true/false as well as "0"/"1" and 0/1, which older lsblk
/// versions emit.
fn flex_bool<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<bool, D::Error> {
    let v = serde_json::Value::deserialize(d)?;
    match v {
        serde_json::Value::Bool(b) => Ok(b),
        serde_json::Value::Null => Ok(false),
        serde_json::Value::Number(n) => match n.as_u64() {
            Some(1) => Ok(true),
            Some(0) => Ok(false),
            _ => Err(serde::de::Error::custom(format!("unexpected boolean {n}"))),
        },
        serde_json::Value::String(s) => match s.as_str() {
            "true" | "1" => Ok(true),
            "false" | "0" | "" => Ok(false),
            _ => Err(serde::de::Error::custom(format!("unexpected boolean {s:?}"))),
        },
        other => Err(serde::de::Error::custom(format!("unexpected boolean {other}"))),
    }
}

#[derive(Deserialize)]
struct LsblkDev {
    #[serde(default)]
    name: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    vendor: Option<String>,
    #[serde(default)]
    tran: Option<String>,
    #[serde(default, deserialize_with = "flex_bool")]
    rm: bool,
    #[serde(default, deserialize_with = "flex_bool")]
    ro: bool,
    #[serde(default, rename = "type")]
    typ: String,
    #[serde(default)]
    fstype: Option<String>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    mountpoints: Option<Vec<Option<String>>>,
    #[serde(default)]
    children: Option<Vec<LsblkDev>>,
}

#[derive(Deserialize)]
struct LsblkDoc {
    #[serde(default)]
    blockdevices: Vec<LsblkDev>,
}

fn s(v: &Option<String>) -> String {
    v.as_deref().unwrap_or("").trim().to_string()
}

fn parse(data: &[u8]) -> Result<Vec<Disk>> {
    let doc: LsblkDoc = serde_json::from_slice(data).map_err(|e| errf!("parse lsblk output: {e}"))?;
    let mut out = Vec::new();
    for dev in &doc.blockdevices {
        if dev.typ != "disk" {
            continue;
        }
        let mut d = Disk {
            name: dev.name.clone(),
            path: dev.path.clone(),
            size: dev.size.unwrap_or(0),
            model: s(&dev.model),
            vendor: s(&dev.vendor),
            tran: s(&dev.tran),
            removable: dev.rm,
            read_only: dev.ro,
            parts: Vec::new(),
        };
        // The whole disk can carry a filesystem too (e.g. a stick formatted
        // without a partition table), so include it as a pseudo-partition.
        collect(dev, &mut d.parts);
        out.push(d);
    }
    Ok(out)
}

fn collect(dev: &LsblkDev, parts: &mut Vec<Part>) {
    let p = Part {
        path: dev.path.clone(),
        size: dev.size.unwrap_or(0),
        fstype: s(&dev.fstype),
        label: s(&dev.label),
        mountpoints: dev.mountpoints.iter().flatten().flatten().filter(|m| !m.is_empty()).cloned().collect(),
    };
    if dev.typ != "disk" || !p.fstype.is_empty() || !p.mountpoints.is_empty() {
        parts.push(p);
    }
    for c in dev.children.iter().flatten() {
        collect(c, parts);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{"blockdevices":[
 {"name":"zram0","path":"/dev/zram0","size":8341946368,"model":null,"vendor":null,"tran":null,"rm":false,"ro":false,"type":"disk","fstype":"swap","label":"zram0","mountpoints":["[SWAP]"]},
 {"name":"nvme0n1","path":"/dev/nvme0n1","size":1000204886016,"model":"Samsung SSD 980 PRO 1TB","vendor":null,"tran":"nvme","rm":false,"ro":false,"type":"disk","fstype":null,"label":null,"mountpoints":[],"children":[
   {"name":"nvme0n1p1","path":"/dev/nvme0n1p1","size":629145600,"tran":"nvme","rm":false,"ro":false,"type":"part","fstype":"vfat","label":null,"mountpoints":["/boot/efi"]},
   {"name":"nvme0n1p3","path":"/dev/nvme0n1p3","size":997426462720,"tran":"nvme","rm":false,"ro":false,"type":"part","fstype":"btrfs","label":"fedora","mountpoints":["/sysroot","/var","/home"]}]},
 {"name":"sdb","path":"/dev/sdb","size":32015679488,"model":"Ultra Fit","vendor":"SanDisk ","tran":"usb","rm":true,"ro":false,"type":"disk","fstype":null,"label":null,"mountpoints":[null],"children":[
   {"name":"sdb1","path":"/dev/sdb1","size":32014630912,"tran":"usb","rm":true,"ro":false,"type":"part","fstype":"exfat","label":"STICK","mountpoints":["/run/media/me/STICK"]}]},
 {"name":"sdc","path":"/dev/sdc","size":500107862016,"model":"Portable SSD","vendor":"Samsung","tran":"usb","rm":false,"ro":false,"type":"disk","fstype":null,"label":null,"mountpoints":[null],"children":[
   {"name":"sdc1","path":"/dev/sdc1","size":500106813440,"tran":"usb","rm":false,"ro":false,"type":"part","fstype":"ext4","label":null,"mountpoints":["/srv/backup"]}]},
 {"name":"sdd","path":"/dev/sdd","size":0,"model":"Card Reader","vendor":"Generic","tran":"usb","rm":"1","ro":"0","type":"disk","fstype":null,"label":null,"mountpoints":[null]},
 {"name":"fd0","path":"/dev/fd0","size":4096,"model":null,"vendor":null,"tran":null,"rm":true,"ro":false,"type":"disk","fstype":null,"label":null,"mountpoints":[null]},
 {"name":"sr0","path":"/dev/sr0","size":1073741312,"model":"DVD","vendor":"HL-DT-ST","tran":"sata","rm":true,"ro":true,"type":"rom","fstype":null,"label":null,"mountpoints":[null]}
]}"#;

    fn names(ds: &[Disk]) -> Vec<String> {
        ds.iter().map(|d| d.name.clone()).collect()
    }

    #[test]
    fn parse_and_filter() {
        let all = parse(SAMPLE.as_bytes()).unwrap();
        assert_eq!(all.len(), 6, "rom must be skipped");
        let by = |n: &str| all.iter().find(|d| d.name == n).unwrap().clone();
        assert!(by("nvme0n1").is_system(), "nvme0n1 holds /sysroot");
        assert!(by("zram0").is_system(), "zram0 is swap");
        assert!(!by("sdb").is_system(), "sdb only mounted under /run/media");
        assert!(by("sdd").removable, r#"rm "1" must parse as removable"#);
        assert_eq!(by("sdb").vendor, "SanDisk", "vendor not trimmed");

        let u = usb(&all);
        assert_eq!(names(&u), vec!["sdb"], "sdc mounted at /srv, sdd empty, fd0 floppy");
        assert_eq!(u[0].mounts(), vec!["/run/media/me/STICK"]);
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(32015679488), "32.0 GB");
        assert_eq!(human_size(1000204886016), "1.0 TB");
    }

    #[test]
    fn installable_disks() {
        let d = |name: &str, size: u64, parts: Vec<Part>| Disk {
            name: name.into(),
            path: format!("/dev/{name}"),
            size,
            parts,
            ..Disk::default()
        };
        let mp = |path: &str, label: &str, m: &[&str]| Part {
            path: path.into(),
            label: label.into(),
            mountpoints: m.iter().map(|s| s.to_string()).collect(),
            ..Part::default()
        };
        let all = vec![
            d("sda", 500_000_000_000, vec![]),
            Disk {
                removable: true,
                tran: "usb".into(),
                ..d("sdb", 32_000_000_000, vec![mp("/dev/sdb1", "DRYSRV_202609", &["/run/archiso/bootmnt"])])
            },
            d("mmcblk0", 8_000_000_000, vec![]),
            d("zram0", 50_000_000_000, vec![]),
            d("nvme0n1", 256_000_000_000, vec![]),
            // left mounted by a failed install attempt: still offered
            d("vda", 21_000_000_000, vec![mp("/dev/vda1", "", &["/mnt/boot"]), mp("/dev/mapper/root", "", &["/mnt"])]),
            // mounted elsewhere: not offered
            d("vdb", 21_000_000_000, vec![mp("/dev/vdb1", "", &["/run/media/x"])]),
        ];
        assert_eq!(names(&installable(&all)), vec!["sda", "nvme0n1", "vda"]);
    }
}
