package install

import (
	"context"
	"crypto/rand"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/DryBearr/dryserver/internal/config"
	"github.com/DryBearr/dryserver/internal/mesh"
	"github.com/DryBearr/dryserver/internal/node"
	"github.com/DryBearr/dryserver/internal/packages"
	"github.com/DryBearr/dryserver/internal/registry"
	"github.com/DryBearr/dryserver/internal/sysconf"
)

// Install wipes the chosen disks and installs the server. The new system
// stays mounted at Target so Join can finish its mesh config; Reboot
// unmounts it.
func (r *Real) Install(ctx context.Context, cfg config.Config, ch Choices, progress func(Step)) error {
	plan, err := packages.Resolve(cfg.ToolList(), cfg.ExtraList())
	if err != nil {
		return err
	}
	enc := ch.Encryption != EncNone
	lay := PlanLayout(ch.SystemDisk, r.machine.UEFI)
	r.state = installState{layout: lay}
	r.sink = func(l string) { progress(Step{Log: l}) }
	defer func() { r.sink = nil }()

	run := func(name string, args ...string) error {
		_, err := r.Run.Run(ctx, Cmd{Name: name, Args: args})
		return err
	}
	chroot := func(args ...string) error { return run("arch-chroot", append([]string{r.Target}, args...)...) }

	type step struct {
		name string
		fn   func() error
	}
	var dataMounts []dataDisk
	steps := []step{
		{"Partition disks", func() error {
			// Leftovers from an earlier attempt; not mounted is fine.
			r.Run.Run(ctx, Cmd{Name: "umount", Args: []string{"-R", r.Target}, Quiet: true})
			all := append([]string{ch.SystemDisk}, ch.DataDisks...)
			for _, d := range all {
				if err := r.releaseDisk(ctx, d); err != nil {
					return err
				}
			}
			for _, d := range all {
				if err := run("wipefs", "--all", "--force", d); err != nil {
					return err
				}
				script := DataScript
				if d == ch.SystemDisk {
					script = lay.Script
				}
				if _, err := r.Run.Run(ctx, Cmd{Name: "sfdisk", Args: []string{"--wipe", "always", "--wipe-partitions", "always", d}, Stdin: script}); err != nil {
					return fmt.Errorf("%w (something still uses %s; reboot from the USB and run the setup again)", err, d)
				}
			}
			if err := run("udevadm", "settle"); err != nil {
				return err
			}
			if err := r.checkLayout(ctx, ch.SystemDisk, 2, 1<<30); err != nil {
				return err
			}
			for _, d := range ch.DataDisks {
				if err := r.checkLayout(ctx, d, 1, 0); err != nil {
					return err
				}
			}
			return nil
		}},
		{"Set up encryption and filesystems", func() error {
			rootDev := lay.Root
			if enc {
				if err := r.luksFormat(ctx, lay.Root, ch.DiskPassphrase); err != nil {
					return err
				}
				if _, err := r.Run.Run(ctx, Cmd{Name: "cryptsetup", Args: []string{"open", "--key-file=-", lay.Root, RootMapper}, Stdin: ch.DiskPassphrase}); err != nil {
					return err
				}
				r.state.mapped = append(r.state.mapped, RootMapper)
				rootDev = "/dev/mapper/" + RootMapper
				if ch.Encryption == EncTPM {
					if err := r.addFirstBootKey(ctx, lay.Root, ch.DiskPassphrase); err != nil {
						return err
					}
				}
			}
			if err := run("mkfs.ext4", "-F", "-q", "-L", "root", rootDev); err != nil {
				return err
			}
			if lay.UEFI {
				err = run("mkfs.fat", "-F", "32", "-n", "EFI", lay.Boot)
			} else {
				err = run("mkfs.ext4", "-F", "-q", "-L", "boot", lay.Boot)
			}
			if err != nil {
				return err
			}
			dataMounts, err = r.prepareData(ctx, ch, enc)
			if err != nil {
				return err
			}

			if err := run("mount", rootDev, r.Target); err != nil {
				return err
			}
			os.MkdirAll(r.target("/boot"), 0o755)
			bootOpts := "defaults"
			if lay.UEFI {
				bootOpts = "umask=0077" // ESP holds the random seed; keep it private
			}
			if err := run("mount", "-o", bootOpts, lay.Boot, r.target("/boot")); err != nil {
				return err
			}
			for _, d := range dataMounts {
				os.MkdirAll(r.target(d.mount), 0o755)
				if err := run("mount", d.dev, r.target(d.mount)); err != nil {
					return err
				}
			}
			return nil
		}},
		{"Install packages (takes a while)", func() error {
			pkgs := slices.Clone(plan.Packages)
			if lay.UEFI {
				pkgs = append(pkgs, "efibootmgr", "systemd-ukify")
			} else {
				pkgs = append(pkgs, "grub")
			}
			if ch.Encryption == EncTPM {
				pkgs = append(pkgs, "tpm2-tss")
			}
			return run("pacstrap", append([]string{"-K", r.Target}, pkgs...)...)
		}},
		{"Configure system", func() error { return r.configure(ctx, cfg, ch, plan, dataMounts, chroot) }},
		{"Install boot loader", func() error { return r.bootloader(ctx, ch, chroot) }},
	}

	for _, s := range steps {
		progress(Step{Name: s.name})
		if err := s.fn(); err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
		progress(Step{Name: s.name, Done: true})
	}
	r.state.installed = true
	return nil
}

// addFirstBootKey adds a random one-time key to the root container. The
// installed system uses it at first boot to enroll the TPM, then removes it.
func (r *Real) addFirstBootKey(ctx context.Context, dev, passphrase string) error {
	key := make([]byte, 64)
	rand.Read(key)
	tmp := filepath.Join(r.KeyDir, "dryserver-tpm-enroll.key")
	if err := os.WriteFile(tmp, key, 0o400); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err := r.Run.Run(ctx, Cmd{Name: "cryptsetup", Args: []string{"luksAddKey", "--key-file=-", dev, tmp}, Stdin: passphrase}); err != nil {
		return err
	}
	r.state.firstBootKey = key
	return nil
}

func (r *Real) luksFormat(ctx context.Context, dev, passphrase string) error {
	_, err := r.Run.Run(ctx, Cmd{
		Name:  "cryptsetup",
		Args:  []string{"luksFormat", "--type", "luks2", "--pbkdf", "argon2id", "--batch-mode", "--key-file=-", dev},
		Stdin: passphrase,
	})
	return err
}

type dataDisk struct {
	dev   string // block device holding the filesystem
	mount string // mount point inside the new system
	key   []byte // keyfile for the LUKS container, nil if not encrypted
	part  string
}

// prepareData formats data disks. Encrypted ones get the passphrase (for
// recovery) plus a random keyfile, stored on the encrypted root, that
// unlocks them at boot.
func (r *Real) prepareData(ctx context.Context, ch Choices, enc bool) ([]dataDisk, error) {
	var out []dataDisk
	for i, disk := range ch.DataDisks {
		d := dataDisk{part: PartPath(disk, 1), dev: PartPath(disk, 1), mount: "/data"}
		if i > 0 {
			d.mount = fmt.Sprintf("/data%d", i+1)
		}
		if enc {
			if err := r.luksFormat(ctx, d.part, ch.DiskPassphrase); err != nil {
				return nil, err
			}
			d.key = make([]byte, 512)
			rand.Read(d.key)
			keyPath := filepath.Join(r.KeyDir, fmt.Sprintf("dryserver-%s%d.key", DataMapper, i))
			if err := os.WriteFile(keyPath, d.key, 0o400); err != nil {
				return nil, err
			}
			defer os.Remove(keyPath)
			if _, err := r.Run.Run(ctx, Cmd{Name: "cryptsetup", Args: []string{"luksAddKey", "--key-file=-", d.part, keyPath}, Stdin: ch.DiskPassphrase}); err != nil {
				return nil, err
			}
			mapper := fmt.Sprintf("%s%d", DataMapper, i)
			if _, err := r.Run.Run(ctx, Cmd{Name: "cryptsetup", Args: []string{"open", "--key-file", keyPath, d.part, mapper}}); err != nil {
				return nil, err
			}
			r.state.mapped = append(r.state.mapped, mapper)
			d.dev = "/dev/mapper/" + mapper
		}
		if _, err := r.Run.Run(ctx, Cmd{Name: "mkfs.ext4", Args: []string{"-F", "-q", "-L", strings.TrimPrefix(d.mount, "/"), d.dev}}); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

func (r *Real) blkid(ctx context.Context, dev string) (string, error) {
	out, err := r.Run.Run(ctx, Cmd{Name: "blkid", Args: []string{"-s", "UUID", "-o", "value", dev}})
	return strings.TrimSpace(out), err
}

func (r *Real) write(path string, mode fs.FileMode, content string) error {
	dst := r.target(path)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(dst, []byte(content), mode); err != nil {
		return err
	}
	return os.Chmod(dst, mode) // WriteFile keeps the old mode of an existing file
}

func (r *Real) configure(ctx context.Context, cfg config.Config, ch Choices, plan packages.Plan, data []dataDisk, chroot func(...string) error) error {
	// fstab from what is mounted now.
	fstab, err := r.Run.Run(ctx, Cmd{Name: "genfstab", Args: []string{"-U", r.Target}, Quiet: true})
	if err != nil {
		return err
	}
	if err := r.write("/etc/fstab", 0o644, fstab); err != nil {
		return err
	}

	// Files from the tool bundles; /etc/skel ones must exist before the
	// user is created.
	for _, f := range plan.Files {
		b, err := fs.ReadFile(r.Rootfs, strings.TrimPrefix(f, "/"))
		if err != nil {
			return fmt.Errorf("bundle file %s: %w", f, err)
		}
		if err := r.write(f, 0o644, string(b)); err != nil {
			return err
		}
	}

	// Locale and time.
	if err := r.write("/etc/locale.gen", 0o644, "en_US.UTF-8 UTF-8\n"); err != nil {
		return err
	}
	r.write("/etc/locale.conf", 0o644, "LANG=en_US.UTF-8\n")
	r.write("/etc/vconsole.conf", 0o644, "KEYMAP=us\n")
	for _, args := range [][]string{
		{"locale-gen"},
		{"ln", "-sf", "/usr/share/zoneinfo/" + cfg.Timezone, "/etc/localtime"},
		{"hwclock", "--systohc"},
	} {
		if err := chroot(args...); err != nil {
			return err
		}
	}

	// Admin user: groups from the bundles, password from the setup screen,
	// root locked.
	groups := append([]string{"wheel"}, plan.Groups...)
	if err := chroot("useradd", "-m", "-G", strings.Join(groups, ","), "-s", "/bin/bash", cfg.Username); err != nil {
		return err
	}
	if _, err := r.Run.Run(ctx, Cmd{Name: "arch-chroot", Args: []string{r.Target, "chpasswd"}, Stdin: cfg.Username + ":" + ch.UserPassword + "\n"}); err != nil {
		return err
	}
	if err := chroot("passwd", "-l", "root"); err != nil {
		return err
	}

	// System files: firewall, SSH, sysctl, network, docker...
	r.state.switchMAC = node.SwitchPort(ctx, r.Run)
	if err := r.write(node.SwitchMACFile, 0o644, r.state.switchMAC+"\n"); err != nil {
		return err
	}
	files, err := sysconf.Render(sysconf.Params{Config: cfg, Plan: plan, Hostname: ch.Hostname, Role: ch.Role,
		HostNum: hostNumFor(ch.Role), SwitchMAC: r.state.switchMAC})
	if err != nil {
		return err
	}
	for _, f := range files {
		if err := r.write(f.Path, f.Mode, f.Content); err != nil {
			return err
		}
	}
	home := "/home/" + cfg.Username
	if err := chroot("chown", "-R", cfg.Username+":"+cfg.Username, home+"/.ssh"); err != nil {
		return err
	}
	os.Chmod(r.target(home+"/.ssh"), 0o700)

	// One-time key for enrolling the TPM at first boot.
	if r.state.firstBootKey != nil {
		if err := r.write(FirstBootKey, 0o400, string(r.state.firstBootKey)); err != nil {
			return err
		}
		os.Chmod(r.target(filepath.Dir(FirstBootKey)), 0o700)
		if err := chroot("systemctl", "enable", "dryserver-tpm-enroll.service"); err != nil {
			return err
		}
	}

	// Data disk keyfiles; crypttab is written with the boot loader.
	r.state.dataUUIDs = nil
	if len(data) > 0 && data[0].key != nil {
		for i, d := range data {
			u, err := r.blkid(ctx, d.part)
			if err != nil {
				return err
			}
			r.state.dataUUIDs = append(r.state.dataUUIDs, u)
			if err := r.write(fmt.Sprintf("/etc/cryptsetup-keys.d/%s%d.key", DataMapper, i), 0o400, string(d.key)); err != nil {
				return err
			}
		}
		os.Chmod(r.target("/etc/cryptsetup-keys.d"), 0o700)
	}

	// dryserver itself, the registry key and this machine's keys.
	self, err := os.ReadFile(r.Self)
	if err != nil {
		return err
	}
	if err := r.write("/usr/local/bin/dryserver", 0o755, string(self)); err != nil {
		return err
	}
	for _, k := range []struct {
		src  string
		mode fs.FileMode
	}{{r.RegistryKey, 0o600}, {r.RegistryKey + ".pub", 0o644}} {
		b, err := os.ReadFile(k.src)
		if err != nil {
			return err
		}
		if err := r.write("/etc/dryserver/"+filepath.Base(k.src), k.mode, string(b)); err != nil {
			return err
		}
	}
	os.Chmod(r.target("/etc/dryserver"), 0o700)
	if err := chroot("ssh-keygen", "-A"); err != nil {
		return err
	}
	hostKey, err := os.ReadFile(r.target("/etc/ssh/ssh_host_ed25519_key.pub"))
	if err != nil {
		return err
	}
	r.state.hostKey = strings.TrimSpace(string(hostKey))
	if err := r.wireguardKey(ctx); err != nil {
		return err
	}
	if ch.Role == sysconf.Coordinator {
		if err := r.setupRegistryUser(chroot); err != nil {
			return err
		}
		if err := r.setupCoordinatorMesh(ch, chroot); err != nil {
			return err
		}
	}

	// Services from the bundles.
	if err := chroot(append([]string{"systemctl", "enable"}, plan.Services...)...); err != nil {
		return err
	}
	for _, c := range plan.UserCommands {
		if err := chroot("runuser", "-u", cfg.Username, "--", "bash", "-lc", c); err != nil {
			return err
		}
	}
	// Last: DNS for the chroot came from the live system until now.
	os.Remove(r.target("/etc/resolv.conf"))
	return os.Symlink("/run/systemd/resolve/stub-resolv.conf", r.target("/etc/resolv.conf"))
}

// hostNumFor: the coordinator is always host 1; nodes learn theirs when
// approved.
func hostNumFor(role sysconf.Role) int {
	if role == sysconf.Coordinator {
		return 1
	}
	return 0
}

func (r *Real) wireguardKey(ctx context.Context) error {
	priv, err := r.Run.Run(ctx, Cmd{Name: "wg", Args: []string{"genkey"}, Quiet: true})
	if err != nil {
		return err
	}
	pub, err := r.Run.Run(ctx, Cmd{Name: "wg", Args: []string{"pubkey"}, Stdin: priv, Quiet: true})
	if err != nil {
		return err
	}
	r.state.wgPublic = strings.TrimSpace(pub)
	if err := r.write("/etc/wireguard/wg0.key", 0o600, priv); err != nil {
		return err
	}
	os.Chmod(r.target("/etc/wireguard"), 0o700)
	return r.write("/etc/wireguard/wg0.pub", 0o644, pub)
}

// setupRegistryUser creates the locked account that runs the registry as a
// forced SSH command. Its authorized_keys is owned by root so the account
// cannot change it.
func (r *Real) setupRegistryUser(chroot func(...string) error) error {
	home := "/var/lib/" + sysconf.RegistryUser
	if err := chroot("useradd", "--system", "-m", "-d", home, "-s", "/bin/sh", sysconf.RegistryUser); err != nil {
		return err
	}
	if err := chroot("passwd", "-l", sysconf.RegistryUser); err != nil {
		return err
	}
	pub, err := os.ReadFile(r.RegistryKey + ".pub")
	if err != nil {
		return err
	}
	line := fmt.Sprintf("restrict,command=\"/usr/local/bin/dryserver registry --subnet %s\" %s\n", r.Cfg.WGSubnet, strings.TrimSpace(string(pub)))
	if err := r.write(home+"/.ssh/authorized_keys", 0o644, line); err != nil {
		return err
	}
	os.Chmod(r.target(home+"/.ssh"), 0o755)
	return nil
}

func (r *Real) bootloader(ctx context.Context, ch Choices, chroot func(...string) error) error {
	lay := r.state.layout
	enc := ch.Encryption != EncNone
	rootUUID, err := r.blkid(ctx, lay.Root)
	if err != nil {
		return err
	}
	if enc {
		if err := r.write("/etc/crypttab", 0o600, Crypttab(rootUUID, ch.Encryption, r.state.dataUUIDs)); err != nil {
			return err
		}
	}
	// The systemd initramfs handles LUKS with TPM or passphrase.
	conf, err := os.ReadFile(r.target("/etc/mkinitcpio.conf"))
	if err != nil {
		return err
	}
	var lines []string
	for _, l := range strings.Split(string(conf), "\n") {
		if strings.HasPrefix(l, "HOOKS=") {
			l = MkinitcpioHooks
		}
		lines = append(lines, l)
	}
	if err := r.write("/etc/mkinitcpio.conf", 0o644, strings.Join(lines, "\n")); err != nil {
		return err
	}

	if !lay.UEFI {
		grub, _ := os.ReadFile(r.target("/etc/default/grub"))
		r.write("/etc/default/grub", 0o644, strings.ReplaceAll(string(grub), `GRUB_TIMEOUT=5`, `GRUB_TIMEOUT=1`))
		for _, args := range [][]string{
			{"mkinitcpio", "-P"},
			{"grub-install", "--target=i386-pc", ch.SystemDisk},
			{"grub-mkconfig", "-o", "/boot/grub/grub.cfg"},
		} {
			if err := chroot(args...); err != nil {
				return err
			}
		}
		return nil
	}

	// UEFI: one unified kernel image, found by systemd-boot on its own.
	if err := r.write("/etc/kernel/cmdline", 0o644, KernelCmdline(enc, rootUUID)+"\n"); err != nil {
		return err
	}
	if err := r.write("/etc/mkinitcpio.d/linux.preset", 0o644, UKIPreset); err != nil {
		return err
	}
	if ch.Encryption == EncTPM {
		if err := r.write("/etc/kernel/uki.conf", 0o644, UKIConf); err != nil {
			return err
		}
		if err := chroot("ukify", "genkey",
			"--pcr-private-key=/etc/systemd/tpm2-pcr-private-key.pem",
			"--pcr-public-key=/etc/systemd/tpm2-pcr-public-key.pem"); err != nil {
			return err
		}
		os.Chmod(r.target("/etc/systemd/tpm2-pcr-private-key.pem"), 0o600)
	}
	os.MkdirAll(r.target("/boot/EFI/Linux"), 0o755)
	for _, args := range [][]string{
		{"mkinitcpio", "-P"},
		{"bootctl", "install"},
	} {
		if err := chroot(args...); err != nil {
			return err
		}
	}
	// The default preset's plain initramfs files are not used with a UKI.
	for _, f := range []string{"/boot/initramfs-linux.img", "/boot/initramfs-linux-fallback.img"} {
		os.Remove(r.target(f))
	}
	return r.write("/boot/loader/loader.conf", 0o644, LoaderConf)
}

// setupCoordinatorMesh creates the registry with the coordinator as member
// 1 and starts its WireGuard side of the mesh.
func (r *Real) setupCoordinatorMesh(ch Choices, chroot func(...string) error) error {
	self := registry.Member{
		Host: 1, Name: ch.Hostname, WGKey: r.state.wgPublic, SSHHostKey: r.state.hostKey,
		LanIP: r.Cfg.CoordLanIP, Switch: node.PortLink(r.state.switchMAC), Approved: time.Now(), LastSeen: time.Now(),
	}
	store := registry.Store{Path: r.target(registry.DefaultPath)}
	if err := store.Update(func(s *registry.State) error {
		s.Members = []registry.Member{self}
		return nil
	}); err != nil {
		return err
	}
	if err := chroot("chown", "-R", sysconf.RegistryUser+":"+sysconf.RegistryUser, filepath.Dir(registry.DefaultPath)); err != nil {
		return err
	}
	os.Chmod(r.target(filepath.Dir(registry.DefaultPath)), 0o700)
	n := node.Node{Cfg: r.Cfg, Hostname: ch.Hostname, Root: r.Target, Run: r.Run}
	if err := n.Apply(mesh.Self{Host: 1, Switch: self.Switch}, []registry.Member{self}); err != nil {
		return err
	}
	return chroot("systemctl", "enable", "wg-quick@wg0.service", "dryserver-sync.timer")
}

// Join asks the coordinator to let the new server in, shows the pairing
// code and waits for approval. If joining does not finish here (skipped,
// coordinator off), the server keeps trying at boot.
func (r *Real) Join(ctx context.Context, cfg config.Config, ch Choices, code func(string)) (int, error) {
	chroot := func(args ...string) error {
		_, err := r.Run.Run(context.Background(), Cmd{Name: "arch-chroot", Args: append([]string{r.Target}, args...)})
		return err
	}
	// Until approved, the installed system retries at every boot.
	if err := chroot("systemctl", "enable", "dryserver-join.service"); err != nil {
		return 0, err
	}
	n := node.Node{Cfg: cfg, Hostname: ch.Hostname, Root: r.Target, Run: r.Run}
	lan, err := node.LocalIP(ctx, r.Run, cfg.CoordLanIP)
	if err != nil {
		return 0, err
	}
	sw := node.PortLink(r.state.switchMAC)
	c, err := n.Request(ctx, lan, sw)
	if err != nil {
		return 0, err
	}
	code(c)
	reply, err := n.Wait(ctx, 3*time.Second)
	if err != nil {
		if node.IsRejected(err) {
			return 0, ErrRejected
		}
		return 0, err
	}
	plan, err := packages.Resolve(cfg.ToolList(), cfg.ExtraList())
	if err != nil {
		return 0, err
	}
	params := sysconf.Params{Config: cfg, Plan: plan, Hostname: ch.Hostname, Role: sysconf.Node, SwitchMAC: r.state.switchMAC}
	if err := n.Activate(reply, mesh.Self{Switch: sw}, params); err != nil {
		return 0, err
	}
	if err := chroot("systemctl", "enable", "wg-quick@wg0.service", "dryserver-sync.timer"); err != nil {
		return 0, err
	}
	return reply.Host, chroot("systemctl", "disable", "dryserver-join.service")
}
