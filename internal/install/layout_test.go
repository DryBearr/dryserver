package install

import (
	"strings"
	"testing"
)

func TestPartPath(t *testing.T) {
	for disk, want := range map[string]string{
		"/dev/sda":     "/dev/sda2",
		"/dev/vda":     "/dev/vda2",
		"/dev/nvme0n1": "/dev/nvme0n1p2",
		"/dev/mmcblk0": "/dev/mmcblk0p2",
	} {
		if got := PartPath(disk, 2); got != want {
			t.Errorf("PartPath(%s) = %s, want %s", disk, got, want)
		}
	}
}

func TestPlanLayout(t *testing.T) {
	u := PlanLayout("/dev/nvme0n1", true)
	if u.Boot != "/dev/nvme0n1p1" || u.Root != "/dev/nvme0n1p2" || !strings.Contains(u.Script, "label: gpt") || !strings.Contains(u.Script, "type=uefi") {
		t.Errorf("UEFI layout: %+v", u)
	}
	b := PlanLayout("/dev/sda", false)
	if !strings.Contains(b.Script, "label: dos") || !strings.Contains(b.Script, "bootable") {
		t.Errorf("BIOS layout must be MBR with a bootable /boot: %q", b.Script)
	}
}

func TestCrypttab(t *testing.T) {
	tpm := Crypttab("abcd", EncTPM, nil)
	if !strings.Contains(tpm, "root UUID=abcd none luks,discard,x-initrd.attach,tpm2-device=auto") {
		t.Errorf("tpm crypttab: %q", tpm)
	}
	if strings.Contains(Crypttab("abcd", EncPassphrase, nil), "tpm2") {
		t.Error("passphrase mode must not try the TPM")
	}
	data := Crypttab("abcd", EncPassphrase, []string{"u0", "u1"})
	if !strings.Contains(data, "data1 UUID=u1 /etc/cryptsetup-keys.d/data1.key luks,discard\n") {
		t.Errorf("data crypttab: %q", data)
	}
}

func TestTPMEnrollArgs(t *testing.T) {
	args := strings.Join(TPMEnrollArgs("/dev/sda2"), " ")
	for _, want := range []string{"--wipe-slot=tpm2", "--tpm2-public-key-pcrs=11", "--tpm2-pcrs=7+12", "/dev/sda2"} {
		if !strings.Contains(args, want) {
			t.Errorf("missing %q in %s", want, args)
		}
	}
}

func TestKernelCmdline(t *testing.T) {
	if got := KernelCmdline(true, "x"); got != "root=/dev/mapper/root rw quiet" {
		t.Error(got)
	}
	if got := KernelCmdline(false, "x"); got != "root=UUID=x rw quiet" {
		t.Error(got)
	}
}
