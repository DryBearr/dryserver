package install

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/DryBearr/dryserver/internal/config"
	"github.com/DryBearr/dryserver/internal/sysconf"
)

// fakeRunner records commands and returns canned output. lsblk answers
// with old[disk] until sfdisk has written that disk, then with the new
// layout.
type fakeRunner struct {
	cmds        []Cmd
	old         map[string]string
	partitioned map[string]string // disk -> sfdisk script
}

func (f *fakeRunner) Run(ctx context.Context, c Cmd) (string, error) {
	f.cmds = append(f.cmds, c)
	if f.partitioned == nil {
		f.partitioned = map[string]string{}
	}
	switch {
	case c.Name == "sfdisk":
		f.partitioned[c.Args[len(c.Args)-1]] = c.Stdin
		return "", nil
	case c.Name == "lsblk":
		dev := c.Args[len(c.Args)-1]
		script, done := f.partitioned[dev]
		switch {
		case done && strings.Contains(script, "size=1GiB"):
			return `{"blockdevices":[{"name":"` + dev + `","type":"disk","size":21474836480,"children":[` +
				`{"name":"` + PartPath(dev, 1) + `","type":"part","size":1073741824},` +
				`{"name":"` + PartPath(dev, 2) + `","type":"part","size":20400000000}]}]}`, nil
		case done:
			return `{"blockdevices":[{"name":"` + dev + `","type":"disk","size":21474836480,"children":[` +
				`{"name":"` + PartPath(dev, 1) + `","type":"part","size":21474000000}]}]}`, nil
		case f.old[dev] != "":
			return f.old[dev], nil
		}
		return `{"blockdevices":[{"name":"` + dev + `","type":"disk","size":21474836480,"mountpoints":[null]}]}`, nil
	case c.Name == "blkid":
		return "1111-uuid\n", nil
	case c.Name == "wg" && c.Args[0] == "genkey":
		return "PRIVATEKEY=\n", nil
	case c.Name == "wg" && c.Args[0] == "pubkey":
		return "PUBLICKEY=\n", nil
	case c.Name == "genfstab":
		return "UUID=1111-uuid / ext4 rw 0 1\n", nil
	}
	return "", nil
}

func (f *fakeRunner) index(t *testing.T, prefix string) int {
	t.Helper()
	for i, c := range f.cmds {
		if strings.HasPrefix(c.String(), prefix) {
			return i
		}
	}
	t.Fatalf("command %q never ran", prefix)
	return -1
}

const (
	diskPass = "disk passphrase 123"
	userPass = "user password 456"
)

func testReal(t *testing.T, uefi bool) (*Real, *fakeRunner) {
	t.Helper()
	dir := t.TempDir()
	target := filepath.Join(dir, "mnt")
	for path, content := range map[string]string{
		"etc/mkinitcpio.conf":              "MODULES=()\nHOOKS=(base udev autodetect)\n",
		"etc/default/grub":                 "GRUB_TIMEOUT=5\n",
		"etc/ssh/ssh_host_ed25519_key.pub": "ssh-ed25519 AAAAhost root@new\n",
	} {
		os.MkdirAll(filepath.Join(target, filepath.Dir(path)), 0o755)
		os.WriteFile(filepath.Join(target, path), []byte(content), 0o644)
	}
	self := filepath.Join(dir, "dryserver")
	os.WriteFile(self, []byte("binary"), 0o755)
	key := filepath.Join(dir, "registry_ed25519")
	os.WriteFile(key, []byte("private"), 0o600)
	os.WriteFile(key+".pub", []byte("ssh-ed25519 AAAAreg dryserver-registry\n"), 0o644)

	cfg := config.Default()
	cfg.CoordLanIP = "192.168.1.50"
	cfg.AdminSSHPubkey = "ssh-ed25519 AAAAadmin me@desktop"
	rootfs := fstest.MapFS{}
	for _, f := range []string{"etc/skel/.tmux.conf", "etc/skel/.config/nvim/init.lua", "etc/profile.d/editor.sh"} {
		rootfs[f] = &fstest.MapFile{Data: []byte("# " + f)}
	}
	fr := &fakeRunner{}
	r := NewReal(cfg, fr, rootfs, self, key)
	r.Target = target
	r.KeyDir = dir
	r.machine = Machine{UEFI: uefi, TPM2: uefi}
	return r, fr
}

func TestInstallUEFITPM(t *testing.T) {
	r, fr := testReal(t, true)
	ch := Choices{Role: sysconf.Node, Hostname: "node-3a2f", SystemDisk: "/dev/nvme0n1",
		DataDisks: []string{"/dev/sda"}, Encryption: EncTPM, DiskPassphrase: diskPass, UserPassword: userPass}
	var steps []string
	if err := r.Install(t.Context(), r.Cfg, ch, func(s Step) {
		if s.Done {
			steps = append(steps, s.Name)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if len(steps) != 5 {
		t.Errorf("steps = %v", steps)
	}

	// Order: wipe before format, format before mount, packages before config.
	order := []string{
		"wipefs --all --force /dev/nvme0n1",
		"sfdisk --wipe always --wipe-partitions always /dev/nvme0n1",
		"cryptsetup luksFormat --type luks2 --pbkdf argon2id --batch-mode --key-file=- /dev/nvme0n1p2",
		"cryptsetup open --key-file=- /dev/nvme0n1p2 root",
		"cryptsetup luksAddKey --key-file=- /dev/nvme0n1p2",
		"mkfs.ext4 -F -q -L root /dev/mapper/root",
		"mkfs.fat -F 32 -n EFI /dev/nvme0n1p1",
		"cryptsetup luksAddKey --key-file=- /dev/sda1",
		"mount /dev/mapper/root",
		"pacstrap -K",
		"arch-chroot " + r.Target + " useradd -m -G wheel,docker",
		"arch-chroot " + r.Target + " chpasswd",
		"arch-chroot " + r.Target + " passwd -l root",
		"arch-chroot " + r.Target + " ukify genkey",
		"arch-chroot " + r.Target + " mkinitcpio -P",
		"arch-chroot " + r.Target + " bootctl install",
	}
	last := -1
	for _, prefix := range order {
		i := fr.index(t, prefix)
		if i < last {
			t.Errorf("%q ran out of order", prefix)
		}
		last = i
	}

	pac := fr.cmds[fr.index(t, "pacstrap")].Args
	for _, p := range []string{"efibootmgr", "systemd-ukify", "tpm2-tss", "docker", "openssh"} {
		if !slices.Contains(pac, p) {
			t.Errorf("pacstrap missing %s", p)
		}
	}
	if slices.Contains(pac, "grub") {
		t.Error("UEFI install must not use grub")
	}

	// Secrets only through stdin/env, never in arguments.
	for _, c := range fr.cmds {
		if strings.Contains(c.String(), diskPass) || strings.Contains(c.String(), userPass) {
			t.Errorf("secret in command line: %s", c)
		}
	}
	if fr.cmds[fr.index(t, "cryptsetup luksFormat")].Stdin != diskPass {
		t.Error("luksFormat must read the passphrase from stdin")
	}
	if !strings.Contains(fr.cmds[fr.index(t, "arch-chroot "+r.Target+" chpasswd")].Stdin, "admin:"+userPass) {
		t.Error("chpasswd must get the user password on stdin")
	}
	for _, c := range fr.cmds {
		if c.Name == "systemd-cryptenroll" {
			t.Error("the TPM is enrolled at first boot, not from the live system")
		}
	}
	fr.index(t, "arch-chroot "+r.Target+" systemctl enable dryserver-tpm-enroll.service")
	if st, err := os.Stat(filepath.Join(r.Target, FirstBootKey)); err != nil || st.Mode().Perm() != 0o400 || st.Size() != 64 {
		t.Errorf("first-boot key: %v %v", st, err)
	}

	// Files in the new system.
	read := func(p string) string { b, _ := os.ReadFile(filepath.Join(r.Target, p)); return string(b) }
	if !strings.Contains(read("/etc/crypttab"), "x-initrd.attach,tpm2-device=auto") {
		t.Error("crypttab missing TPM unlock in the initramfs")
	}
	if !strings.Contains(read("/etc/mkinitcpio.conf"), "sd-encrypt") {
		t.Error("mkinitcpio hooks not replaced")
	}
	if !strings.Contains(read("/etc/kernel/uki.conf"), "PCRPrivateKey") {
		t.Error("UKI not signed for TPM")
	}
	if read("/boot/loader/loader.conf") != LoaderConf {
		t.Error("loader.conf must disable the editor")
	}
	if st, err := os.Stat(filepath.Join(r.Target, "/etc/cryptsetup-keys.d/data0.key")); err != nil || st.Mode().Perm() != 0o400 || st.Size() != 512 {
		t.Errorf("data keyfile: %v %v", st, err)
	}
	if !strings.Contains(read("/etc/crypttab"), "data0 UUID=1111-uuid /etc/cryptsetup-keys.d/data0.key") {
		t.Errorf("crypttab: %q", read("/etc/crypttab"))
	}
	if read("/etc/wireguard/wg0.key") != "PRIVATEKEY=\n" || r.state.wgPublic != "PUBLICKEY=" {
		t.Error("wireguard key not stored")
	}
	if link, _ := os.Readlink(filepath.Join(r.Target, "/etc/resolv.conf")); link != "/run/systemd/resolve/stub-resolv.conf" {
		t.Errorf("resolv.conf -> %q", link)
	}
	if read("/etc/skel/.tmux.conf") == "" {
		t.Error("bundle files not installed")
	}
}

func TestInstallBIOSPlainCoordinator(t *testing.T) {
	r, fr := testReal(t, false)
	ch := Choices{Role: sysconf.Coordinator, Hostname: "coord", SystemDisk: "/dev/sda",
		Encryption: EncNone, UserPassword: userPass}
	if err := r.Install(t.Context(), r.Cfg, ch, func(Step) {}); err != nil {
		t.Fatal(err)
	}
	for _, c := range fr.cmds {
		if c.Name == "cryptsetup" || c.Name == "systemd-cryptenroll" || strings.Contains(c.String(), "bootctl") {
			t.Errorf("unexpected for BIOS/unencrypted: %s", c)
		}
	}
	fr.index(t, "arch-chroot "+r.Target+" grub-install --target=i386-pc /dev/sda")
	fr.index(t, "mkfs.ext4 -F -q -L boot /dev/sda1")
	fr.index(t, "arch-chroot "+r.Target+" useradd --system -m -d /var/lib/dryreg -s /bin/sh dryreg")

	ak, _ := os.ReadFile(filepath.Join(r.Target, "/var/lib/dryreg/.ssh/authorized_keys"))
	if !strings.HasPrefix(string(ak), `restrict,command="/usr/local/bin/dryserver registry --subnet 10.66.0.0/24" ssh-ed25519 AAAAreg`) {
		t.Errorf("registry authorized_keys: %q", ak)
	}
	sshd, _ := os.ReadFile(filepath.Join(r.Target, "/etc/ssh/sshd_config.d/10-dryserver.conf"))
	if !strings.Contains(string(sshd), "AllowUsers admin dryreg") {
		t.Error("coordinator sshd must allow dryreg")
	}
	if _, err := os.Stat(filepath.Join(r.Target, "/etc/crypttab")); err == nil {
		t.Error("unencrypted install must not write crypttab")
	}

	// Coordinator: registry with itself as member 1, mesh config, services.
	reg, _ := os.ReadFile(filepath.Join(r.Target, "/var/lib/dryserver/registry.json"))
	if !strings.Contains(string(reg), `"host": 1`) || !strings.Contains(string(reg), `"wg_key": "PUBLICKEY="`) {
		t.Errorf("registry: %s", reg)
	}
	wg, _ := os.ReadFile(filepath.Join(r.Target, "/etc/wireguard/wg0.conf"))
	if !strings.Contains(string(wg), "Address = 10.66.0.1/24") {
		t.Errorf("coordinator wg0.conf: %s", wg)
	}
	fr.index(t, "arch-chroot "+r.Target+" systemctl enable wg-quick@wg0.service dryserver-sync.timer")
	fr.index(t, "arch-chroot "+r.Target+" chown -R dryreg:dryreg /var/lib/dryserver")
}

func TestParseNetworks(t *testing.T) {
	out := "                               Available networks\n" +
		"--------------------------------------------------------------------------------\n" +
		"      Network name                      Security            Signal\n" +
		"--------------------------------------------------------------------------------\n" +
		"  \x1b[1;90m> \x1b[0m  Home                              psk                 ****\n" +
		"      My Neighbor 5G                    psk                 ***\n" +
		"      Cafe                              open                *\n"
	got := ParseNetworks(out)
	if strings.Join(got, "|") != "Home|My Neighbor 5G|Cafe" {
		t.Fatalf("got %q", got)
	}
}

// A used laptop: an old LVM volume (mounted), swap, and a LUKS mapping left
// open by an earlier setup attempt. All must be released before sfdisk.
func TestInstallReleasesOldDisk(t *testing.T) {
	r, fr := testReal(t, true)
	fr.old = map[string]string{"/dev/nvme0n1": `{"blockdevices":[{"name":"/dev/nvme0n1","type":"disk","size":256060514304,"mountpoints":[null],"children":[
		{"name":"/dev/nvme0n1p1","type":"part","size":536870912,"mountpoints":[null]},
		{"name":"/dev/nvme0n1p2","type":"part","size":8589934592,"mountpoints":["[SWAP]"]},
		{"name":"/dev/nvme0n1p3","type":"part","size":200000000000,"mountpoints":[null],"children":[
			{"name":"/dev/mapper/oldvg-root","type":"lvm","size":100000000000,"mountpoints":["/run/old"]}]},
		{"name":"/dev/nvme0n1p4","type":"part","size":40000000000,"mountpoints":[null],"children":[
			{"name":"/dev/mapper/root","type":"crypt","size":39000000000,"mountpoints":["/mnt"]}]}]}]}`}
	ch := Choices{Role: sysconf.Node, Hostname: "node-x", SystemDisk: "/dev/nvme0n1", Encryption: EncNone, UserPassword: userPass}
	if err := r.Install(t.Context(), r.Cfg, ch, func(Step) {}); err != nil {
		t.Fatal(err)
	}
	order := []string{
		"swapoff /dev/nvme0n1p2",
		"umount -R /run/old",
		"dmsetup remove --retry /dev/mapper/oldvg-root",
		"umount -R /mnt",
		"dmsetup remove --retry /dev/mapper/root",
		"wipefs --all --force /dev/nvme0n1",
		"sfdisk --wipe always",
	}
	last := -1
	for _, prefix := range order {
		i := -1
		for j, c := range fr.cmds {
			if j > last && strings.HasPrefix(c.String(), prefix) {
				i = j
				break
			}
		}
		if i < 0 {
			t.Fatalf("%q missing or out of order", prefix)
		}
		last = i
	}
}

func TestInstallStopsWhenKernelKeepsOldPartitions(t *testing.T) {
	r, _ := testReal(t, true)
	stuck := &stuckRunner{fakeRunner: &fakeRunner{}}
	r.Run = stuck
	ch := Choices{Role: sysconf.Node, Hostname: "node-x", SystemDisk: "/dev/sda", Encryption: EncNone, UserPassword: userPass}
	err := r.Install(t.Context(), r.Cfg, ch, func(Step) {})
	if err == nil || !strings.Contains(err.Error(), "still sees the old partitions") {
		t.Fatalf("err = %v", err)
	}
	for _, c := range stuck.cmds {
		if c.Name == "mkfs.ext4" || c.Name == "cryptsetup" {
			t.Fatalf("formatted despite a stale partition table: %s", c)
		}
	}
}

// stuckRunner pretends sfdisk worked but the kernel kept the old table.
type stuckRunner struct{ *fakeRunner }

func (s *stuckRunner) Run(ctx context.Context, c Cmd) (string, error) {
	out, err := s.fakeRunner.Run(ctx, c)
	if c.Name == "sfdisk" {
		delete(s.partitioned, c.Args[len(c.Args)-1])
	}
	return out, err
}
