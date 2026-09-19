package install

import (
	"fmt"
	"strings"
	"unicode"
)

// Layout is the partition plan for the system disk.
type Layout struct {
	UEFI bool
	// Parts in creation order.
	Boot string // UEFI: ESP mounted at /boot. BIOS: ext4 /boot.
	Root string // LUKS container or plain ext4
	// Script is the sfdisk input that creates the table.
	Script string
}

// PartPath returns partition n of disk: /dev/sda -> /dev/sda1,
// /dev/nvme0n1 -> /dev/nvme0n1p1, /dev/mmcblk0 -> /dev/mmcblk0p1.
func PartPath(disk string, n int) string {
	if r := []rune(disk); len(r) > 0 && unicode.IsDigit(r[len(r)-1]) {
		return fmt.Sprintf("%sp%d", disk, n)
	}
	return fmt.Sprintf("%s%d", disk, n)
}

// PlanLayout picks the partition table for the firmware.
//
// UEFI: GPT with a 1 GiB ESP (systemd-boot, kernel, UKI) and the rest root.
// BIOS: MBR with a bootable 1 GiB /boot and the rest root. MBR rather than
// GPT because some old BIOSes refuse to boot GPT disks.
func PlanLayout(disk string, uefi bool) Layout {
	if uefi {
		return Layout{
			UEFI: true,
			Boot: PartPath(disk, 1),
			Root: PartPath(disk, 2),
			Script: strings.Join([]string{
				"label: gpt",
				"size=1GiB, type=uefi, name=EFI",
				"type=linux, name=root",
			}, "\n") + "\n",
		}
	}
	return Layout{
		Boot: PartPath(disk, 1),
		Root: PartPath(disk, 2),
		Script: strings.Join([]string{
			"label: dos",
			"size=1GiB, type=linux, bootable",
			"type=linux",
		}, "\n") + "\n",
	}
}

// DataScript is the sfdisk input for a data disk: one partition.
const DataScript = "label: gpt\ntype=linux, name=data\n"

// Mapper names for opened LUKS containers.
const (
	RootMapper = "root"
	DataMapper = "data" // data disks: data0, data1, ...
)

// FirstBootKey unlocks the root container once, at the first boot of the
// installed system, so the TPM can be enrolled there. It lives only on the
// encrypted root and is removed after enrolling.
const FirstBootKey = "/etc/cryptsetup-keys.d/tpm-enroll.key"

// PCRPublicKey verifies the signed PCR 11 values baked into each UKI.
const PCRPublicKey = "/etc/systemd/tpm2-pcr-public-key.pem"

// TPMEnrollArgs are the systemd-cryptenroll arguments for TPM unlock:
// the signed PCR 11 policy (the UKI itself, re-signed on kernel updates),
// PCR 7 (Secure Boot state and firmware keys) and PCR 12 (kernel command
// line overrides). Enrolling on the installed system itself binds the real
// values of that boot; an edited command line or other boot chain changes
// them and the TPM refuses, so the passphrase is asked instead.
func TPMEnrollArgs(device string) []string {
	return []string{
		"--wipe-slot=tpm2",
		"--tpm2-device=auto",
		"--tpm2-public-key=" + PCRPublicKey,
		"--tpm2-public-key-pcrs=11",
		"--tpm2-pcrs=7+12",
		device,
	}
}

// Crypttab returns /etc/crypttab: the root container, unlocked in the
// initramfs (x-initrd.attach), and data disks, unlocked later with keyfiles
// stored on the encrypted root.
func Crypttab(rootUUID string, enc Encryption, dataUUIDs []string) string {
	opts := "luks,discard,x-initrd.attach"
	if enc == EncTPM {
		opts += ",tpm2-device=auto"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Root filesystem, unlocked in the initramfs.\n%s UUID=%s none %s\n", RootMapper, rootUUID, opts)
	if len(dataUUIDs) > 0 {
		b.WriteString("\n# Data disks, unlocked with keyfiles on the encrypted root.\n")
	}
	for i, u := range dataUUIDs {
		fmt.Fprintf(&b, "%s%d UUID=%s /etc/cryptsetup-keys.d/%s%d.key luks,discard\n", DataMapper, i, u, DataMapper, i)
	}
	return b.String()
}

// KernelCmdline is embedded in the UKI (UEFI) or passed by GRUB (BIOS).
func KernelCmdline(encrypted bool, rootUUID string) string {
	if encrypted {
		return "root=/dev/mapper/" + RootMapper + " rw quiet"
	}
	return "root=UUID=" + rootUUID + " rw quiet"
}

// MkinitcpioHooks uses the systemd initramfs, which handles LUKS with TPM
// or passphrase (sd-encrypt).
const MkinitcpioHooks = "HOOKS=(base systemd autodetect microcode modconf kms keyboard sd-vconsole block sd-encrypt filesystems fsck)"

// UKIPreset builds only the default UKI (no fallback image, keeps the ESP
// small) into the path systemd-boot finds on its own.
const UKIPreset = `# dryserver: build a signed unified kernel image for systemd-boot.
ALL_kver="/boot/vmlinuz-linux"
PRESETS=('default')
default_uki="/boot/EFI/Linux/arch-linux.efi"
`

// UKIConf makes ukify sign the expected PCR 11 values, so the TPM policy
// survives kernel updates without re-enrolling.
const UKIConf = `[UKI]

[PCRSignature:initrd]
PCRPrivateKey=/etc/systemd/tpm2-pcr-private-key.pem
PCRPublicKey=/etc/systemd/tpm2-pcr-public-key.pem
Phases=enter-initrd
`

// LoaderConf: no menu delay, and no editing the kernel command line.
const LoaderConf = "timeout 0\neditor no\n"
