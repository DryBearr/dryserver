//! The partition plan and the boot and encryption files derived from it.

use super::Encryption;

/// The partition plan for the system disk.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Layout {
    pub uefi: bool,
    /// UEFI: ESP mounted at /boot. BIOS: ext4 /boot.
    pub boot: String,
    /// LUKS container or plain ext4.
    pub root: String,
    /// The sfdisk input that creates the table.
    pub script: String,
}

/// Partition n of disk: /dev/sda -> /dev/sda1, /dev/nvme0n1 ->
/// /dev/nvme0n1p1, /dev/mmcblk0 -> /dev/mmcblk0p1.
pub fn part_path(disk: &str, n: u32) -> String {
    match disk.chars().last() {
        Some(c) if c.is_numeric() => format!("{disk}p{n}"),
        _ => format!("{disk}{n}"),
    }
}

/// Picks the partition table for the firmware.
///
/// UEFI: GPT with a 1 GiB ESP (systemd-boot, kernel, UKI) and the rest
/// root. BIOS: MBR with a bootable 1 GiB /boot and the rest root. MBR rather
/// than GPT because some old BIOSes refuse to boot GPT disks.
pub fn plan_layout(disk: &str, uefi: bool) -> Layout {
    let script = if uefi {
        "label: gpt\nsize=1GiB, type=uefi, name=EFI\ntype=linux, name=root\n"
    } else {
        "label: dos\nsize=1GiB, type=linux, bootable\ntype=linux\n"
    };
    Layout { uefi, boot: part_path(disk, 1), root: part_path(disk, 2), script: script.into() }
}

/// The sfdisk input for a data disk: one partition.
pub const DATA_SCRIPT: &str = "label: gpt\ntype=linux, name=data\n";

/// Mapper name of the opened root LUKS container.
pub const ROOT_MAPPER: &str = "root";
/// Data disks: data0, data1, ...
pub const DATA_MAPPER: &str = "data";

/// Unlocks the root container once, at the first boot of the installed
/// system, so the TPM can be enrolled there. It lives only on the encrypted
/// root and is removed after enrolling.
pub const FIRST_BOOT_KEY: &str = "/etc/cryptsetup-keys.d/tpm-enroll.key";

/// Verifies the signed PCR 11 values baked into each UKI.
pub const PCR_PUBLIC_KEY: &str = "/etc/systemd/tpm2-pcr-public-key.pem";

/// The systemd-cryptenroll arguments for TPM unlock: the signed PCR 11
/// policy (the UKI itself, re-signed on kernel updates), PCR 7 (Secure Boot
/// state and firmware keys) and PCR 12 (kernel command line overrides).
/// Enrolling on the installed system itself binds the real values of that
/// boot; an edited command line or other boot chain changes them and the
/// TPM refuses, so the passphrase is asked instead.
pub fn tpm_enroll_args(device: &str) -> Vec<String> {
    vec![
        "--wipe-slot=tpm2".into(),
        "--tpm2-device=auto".into(),
        format!("--tpm2-public-key={PCR_PUBLIC_KEY}"),
        "--tpm2-public-key-pcrs=11".into(),
        "--tpm2-pcrs=7+12".into(),
        device.into(),
    ]
}

/// /etc/crypttab: the root container, unlocked in the initramfs
/// (x-initrd.attach), and data disks, unlocked later with keyfiles stored on
/// the encrypted root.
pub fn crypttab(root_uuid: &str, enc: Encryption, data_uuids: &[String]) -> String {
    let mut opts = String::from("luks,discard,x-initrd.attach");
    if enc == Encryption::Tpm {
        opts += ",tpm2-device=auto";
    }
    let mut b = format!("# Root filesystem, unlocked in the initramfs.\n{ROOT_MAPPER} UUID={root_uuid} none {opts}\n");
    if !data_uuids.is_empty() {
        b += "\n# Data disks, unlocked with keyfiles on the encrypted root.\n";
    }
    for (i, u) in data_uuids.iter().enumerate() {
        b += &format!("{DATA_MAPPER}{i} UUID={u} /etc/cryptsetup-keys.d/{DATA_MAPPER}{i}.key luks,discard\n");
    }
    b
}

/// Embedded in the UKI (UEFI) or passed by GRUB (BIOS).
pub fn kernel_cmdline(encrypted: bool, root_uuid: &str) -> String {
    if encrypted { format!("root=/dev/mapper/{ROOT_MAPPER} rw quiet") } else { format!("root=UUID={root_uuid} rw quiet") }
}

/// The systemd initramfs, which handles LUKS with TPM or passphrase
/// (sd-encrypt).
pub const MKINITCPIO_HOOKS: &str =
    "HOOKS=(base systemd autodetect microcode modconf kms keyboard sd-vconsole block sd-encrypt filesystems fsck)";

/// Builds only the default UKI (no fallback image, keeps the ESP small)
/// into the path systemd-boot finds on its own.
pub const UKI_PRESET: &str = r#"# dryserver: build a signed unified kernel image for systemd-boot.
ALL_kver="/boot/vmlinuz-linux"
PRESETS=('default')
default_uki="/boot/EFI/Linux/arch-linux.efi"
"#;

/// Makes ukify sign the expected PCR 11 values, so the TPM policy survives
/// kernel updates without re-enrolling.
pub const UKI_CONF: &str = "[UKI]

[PCRSignature:initrd]
PCRPrivateKey=/etc/systemd/tpm2-pcr-private-key.pem
PCRPublicKey=/etc/systemd/tpm2-pcr-public-key.pem
Phases=enter-initrd
";

/// No menu delay, and no editing the kernel command line.
pub const LOADER_CONF: &str = "timeout 0\neditor no\n";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_paths() {
        for (disk, want) in
            [("/dev/sda", "/dev/sda2"), ("/dev/vda", "/dev/vda2"), ("/dev/nvme0n1", "/dev/nvme0n1p2"), ("/dev/mmcblk0", "/dev/mmcblk0p2")]
        {
            assert_eq!(part_path(disk, 2), want);
        }
    }

    #[test]
    fn layouts() {
        let u = plan_layout("/dev/nvme0n1", true);
        assert!(
            u.boot == "/dev/nvme0n1p1" && u.root == "/dev/nvme0n1p2" && u.script.contains("label: gpt") && u.script.contains("type=uefi")
        );
        let b = plan_layout("/dev/sda", false);
        assert!(b.script.contains("label: dos") && b.script.contains("bootable"), "BIOS layout must be MBR with a bootable /boot");
    }

    #[test]
    fn crypttab_lines() {
        let tpm = crypttab("abcd", Encryption::Tpm, &[]);
        assert!(tpm.contains("root UUID=abcd none luks,discard,x-initrd.attach,tpm2-device=auto"), "{tpm}");
        assert!(!crypttab("abcd", Encryption::Passphrase, &[]).contains("tpm2"), "passphrase mode must not try the TPM");
        let data = crypttab("abcd", Encryption::Passphrase, &["u0".into(), "u1".into()]);
        assert!(data.contains("data1 UUID=u1 /etc/cryptsetup-keys.d/data1.key luks,discard\n"), "{data}");
    }

    #[test]
    fn tpm_args() {
        let args = tpm_enroll_args("/dev/sda2").join(" ");
        for want in ["--wipe-slot=tpm2", "--tpm2-public-key-pcrs=11", "--tpm2-pcrs=7+12", "/dev/sda2"] {
            assert!(args.contains(want), "missing {want:?} in {args}");
        }
    }

    #[test]
    fn cmdlines() {
        assert_eq!(kernel_cmdline(true, "x"), "root=/dev/mapper/root rw quiet");
        assert_eq!(kernel_cmdline(false, "x"), "root=UUID=x rw quiet");
    }
}
