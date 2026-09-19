// Command dryserver builds and flashes the Arch + WireGuard installer USB.
package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/DryBearr/dryserver/assets"
	"github.com/DryBearr/dryserver/internal/build"
	"github.com/DryBearr/dryserver/internal/config"
	"github.com/DryBearr/dryserver/internal/disks"
	"github.com/DryBearr/dryserver/internal/install"
	"github.com/DryBearr/dryserver/internal/mesh"
	"github.com/DryBearr/dryserver/internal/node"
	"github.com/DryBearr/dryserver/internal/packages"
	"github.com/DryBearr/dryserver/internal/registry"
	"github.com/DryBearr/dryserver/internal/runner"
	"github.com/DryBearr/dryserver/internal/sysconf"
	"github.com/DryBearr/dryserver/internal/tui"
)

const usage = `usage: dryserver [command] [flags]

Run without a command for the interactive menu (config, build, flash).
Use sudo when you want to flash: sudo dryserver

commands:
  install [--demo]    laptop setup screen (runs from the installer USB);
                      --demo only shows the screens, nothing is changed
  build               build out/dryserver.iso from config.env, log to stdout
  disks               list disks and show which ones may be flashed
  flash --iso FILE    select a USB drive and write FILE to it (needs root)
  sysconf --out DIR   write the system files a server would get (for review)
  ssh-config          write ~/.ssh/config.d/dryserver so "ssh <server>" works

on servers:
  approve             coordinator: approve or reject machines, remove members
  join                ask the coordinator to join (runs at boot until approved)
  sync                update the mesh from the member list (runs every minute)
  scan                coordinator: report unknown devices on the network
  tpm-enroll          let the TPM unlock the disk again (after a firmware change)
  registry            coordinator: SSH forced command for joining machines
`

var paths = tui.Paths{Config: "config.env", OutDir: "out", Secrets: "secrets"}

func main() {
	if len(os.Args) < 2 {
		if err := runApp(); err != nil {
			fmt.Fprintln(os.Stderr, "dryserver:", err)
			os.Exit(1)
		}
		return
	}
	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "install":
		err = runInstall(args)
	case "build":
		err = runBuild()
	case "disks":
		err = runDisks()
	case "flash":
		err = runFlash(args)
	case "sysconf":
		err = runSysconf(args)
	case "ssh-config":
		err = runSSHConfig(args)
	case "registry":
		err = runRegistry(args)
	case "join":
		err = runJoin()
	case "sync":
		err = runSync()
	case "scan":
		err = runScan()
	case "approve":
		err = runApprove()
	case "tpm-enroll":
		err = runTPMEnroll(args)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "dryserver:", err)
		os.Exit(1)
	}
}

func runApp() error {
	_, err := tea.NewProgram(tui.NewApp(paths), tea.WithAltScreen()).Run()
	return err
}

// liveConfig is where the ISO build puts the config.
const liveConfig = "/etc/dryserver/config.env"

func runInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	demo := fs.Bool("demo", false, "show the setup screens without changing anything")
	fs.Parse(args)

	var be install.Backend
	cfg, err := config.Load(liveConfig)
	switch {
	case *demo:
		be = install.NewDemo()
		if err != nil {
			if cfg, err = config.Load(paths.Config); err != nil {
				cfg = config.Default()
				cfg.CoordLanIP = "192.168.1.50"
			}
		}
	case err != nil:
		return fmt.Errorf("this is not the installer USB (%v); try: dryserver install --demo", err)
	case os.Geteuid() != 0:
		return fmt.Errorf("the installer must run as root")
	default:
		real, err := newRealBackend(cfg)
		if err != nil {
			return err
		}
		be = real
	}
	_, err = tea.NewProgram(tui.NewSetup(be, cfg), tea.WithAltScreen()).Run()
	return err
}

const installLog = "/tmp/dryserver-install.log"

// serverNode loads what the node commands need on an installed server.
func serverNode() (node.Node, config.Config, error) {
	if os.Geteuid() != 0 {
		return node.Node{}, config.Config{}, fmt.Errorf("run as root (sudo)")
	}
	cfg, err := config.Load(liveConfig)
	if err != nil {
		return node.Node{}, cfg, fmt.Errorf("not a dryserver server: %w", err)
	}
	host, _ := os.Hostname()
	return node.Node{Cfg: cfg, Hostname: host, Root: "/", Run: runner.ExecRunner{Log: func(string) {}}}, cfg, nil
}

func isCoordinator() bool {
	b, _ := os.ReadFile("/etc/dryserver/role")
	return strings.TrimSpace(string(b)) == string(sysconf.Coordinator)
}

func runRegistry(args []string) error {
	fs := flag.NewFlagSet("registry", flag.ExitOnError)
	subnet := fs.String("subnet", "", "mesh subnet")
	fs.Parse(args)
	hostKey, err := os.ReadFile("/etc/ssh/ssh_host_ed25519_key.pub")
	if err != nil {
		return err
	}
	return registry.Serve(registry.Store{Path: registry.DefaultPath}, mesh.Subnet(*subnet), string(hostKey),
		os.Getenv("SSH_ORIGINAL_COMMAND"), os.Getenv("SSH_CLIENT"), os.Stdin, os.Stdout, time.Now())
}

func runJoin() error {
	n, cfg, err := serverNode()
	if err != nil {
		return err
	}
	plan, err := packages.Resolve(cfg.ToolList(), cfg.ExtraList())
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return node.JoinLoop(ctx, n, sysconf.Params{Config: cfg, Plan: plan, Hostname: n.Hostname, Role: sysconf.Node}, os.Stdout)
}

func runSync() error {
	n, _, err := serverNode()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	return node.Sync(ctx, n, isCoordinator(), registry.Store{Path: registry.DefaultPath})
}

func runScan() error {
	n, cfg, err := serverNode()
	if err != nil {
		return err
	}
	if !isCoordinator() {
		return fmt.Errorf("scan runs on the coordinator")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var found []registry.Device
	ents, _ := os.ReadDir("/sys/class/net")
	for _, e := range ents {
		if _, err := os.Stat("/sys/class/net/" + e.Name() + "/device"); err != nil {
			continue // only physical ports: WiFi/router and switch
		}
		out, _ := n.Run.Run(ctx, runner.Cmd{Name: "arp-scan", Args: []string{"--localnet", "--plain", "--quiet",
			"--interface", e.Name(), "--format", "${ip}	${mac}	${vendor}"}, Quiet: true})
		found = append(found, registry.ParseArpScan(out)...)
	}
	store := registry.Store{Path: registry.DefaultPath}
	st, err := store.Read()
	if err != nil {
		return err
	}
	var known []string
	for _, m := range st.Members {
		known = append(known, m.LanIP, mesh.IP(cfg.SwitchSubnet, m.Host), mesh.IP(cfg.WGSubnet, m.Host))
	}
	unknown := registry.Unknown(found, known, time.Now())
	for i := range unknown {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(unknown[i].IP, "22"), time.Second)
		if err == nil {
			c.Close()
			unknown[i].SSH = true
		}
	}
	return store.Update(func(s *registry.State) error {
		s.Unknown, s.Scanned = unknown, time.Now()
		return nil
	})
}

// rootDevice finds the LUKS container of the root filesystem in /etc/crypttab.
func rootDevice() (string, error) {
	b, err := os.ReadFile("/etc/crypttab")
	if err != nil {
		return "", fmt.Errorf("no encrypted disk here: %w", err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == install.RootMapper && strings.HasPrefix(f[1], "UUID=") {
			return "/dev/disk/by-uuid/" + strings.TrimPrefix(f[1], "UUID="), nil
		}
	}
	return "", fmt.Errorf("no root entry in /etc/crypttab")
}

func runTPMEnroll(args []string) error {
	fs := flag.NewFlagSet("tpm-enroll", flag.ExitOnError)
	firstBoot := fs.Bool("first-boot", false, "use the one-time key from the installer, then remove it")
	fs.Parse(args)
	if os.Geteuid() != 0 {
		return fmt.Errorf("run as root (sudo)")
	}
	dev, err := rootDevice()
	if err != nil {
		return err
	}
	enroll := install.TPMEnrollArgs(dev)
	if *firstBoot {
		enroll = append([]string{"--unlock-key-file=" + install.FirstBootKey}, enroll...)
	} else {
		fmt.Println("Enter the disk passphrase to let the TPM unlock this boot's configuration.")
	}
	cmd := exec.Command("systemd-cryptenroll", enroll...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemd-cryptenroll: %w", err)
	}
	if !*firstBoot {
		return nil
	}
	// The one-time key has done its job: remove its key slot and the file.
	if out, err := exec.Command("cryptsetup", "luksRemoveKey", "--batch-mode", dev, install.FirstBootKey).CombinedOutput(); err != nil {
		return fmt.Errorf("remove one-time key: %v: %s", err, out)
	}
	if err := os.Remove(install.FirstBootKey); err != nil {
		return err
	}
	exec.Command("systemctl", "disable", "dryserver-tpm-enroll.service").Run()
	fmt.Println("TPM enrolled; the disk now unlocks by itself.")
	return nil
}

func runApprove() error {
	_, cfg, err := serverNode()
	if err != nil {
		return err
	}
	if !isCoordinator() {
		return fmt.Errorf("approve runs on the coordinator (%s)", cfg.CoordLanIP)
	}
	_, ipnet, err := net.ParseCIDR(cfg.WGSubnet)
	if err != nil {
		return err
	}
	ones, bits := ipnet.Mask.Size()
	m := tui.NewApprove(registry.Store{Path: registry.DefaultPath}, cfg.WGSubnet, 1<<(bits-ones)-2)
	_, err = tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}

func newRealBackend(cfg config.Config) (*install.Real, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	rootfs, err := fs.Sub(assets.Rootfs, "rootfs")
	if err != nil {
		return nil, err
	}
	logFile, err := os.OpenFile(installLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	r := install.NewReal(cfg, nil, rootfs, self, "/etc/dryserver/registry_ed25519")
	r.LogFile = logFile
	r.Run = install.ExecRunner{Log: r.Log}
	return r, nil
}

func runBuild() error {
	cfg, err := config.Load(paths.Config)
	if err != nil {
		return fmt.Errorf("load %s: %w (create it with the menu: dryserver)", paths.Config, err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return build.Run(ctx, build.Options{Config: cfg, OutDir: paths.OutDir, SecretsDir: paths.Secrets}, os.Stdout)
}

func runSysconf(args []string) error {
	fs := flag.NewFlagSet("sysconf", flag.ExitOnError)
	out := fs.String("out", "", "directory to write the files into")
	cfgPath := fs.String("config", paths.Config, "config file")
	role := fs.String("role", string(sysconf.Node), "node or coordinator")
	hostname := fs.String("hostname", "node-0000", "machine hostname")
	host := fs.Int("host", 0, "mesh host number (0 = not approved yet)")
	fs.Parse(args)
	if *out == "" {
		return fmt.Errorf("sysconf: --out is required")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	plan, err := packages.Resolve(cfg.ToolList(), cfg.ExtraList())
	if err != nil {
		return err
	}
	files, err := sysconf.Render(sysconf.Params{Config: cfg, Plan: plan, Hostname: *hostname, Role: sysconf.Role(*role), HostNum: *host})
	if err != nil {
		return err
	}
	for _, f := range files {
		dst := filepath.Join(*out, f.Path)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, []byte(f.Content), f.Mode); err != nil {
			return err
		}
		fmt.Printf("%04o %s\n", f.Mode, f.Path)
	}
	return nil
}

func runSSHConfig(args []string) error {
	fs := flag.NewFlagSet("ssh-config", flag.ExitOnError)
	cfgPath := fs.String("config", paths.Config, "config file")
	host := fs.String("host", "", "coordinator address (default: COORD_LAN_IP)")
	port := fs.String("port", "22", "coordinator SSH port")
	fs.Parse(args)
	if os.Geteuid() == 0 {
		return fmt.Errorf("run ssh-config as your normal user, not with sudo")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if *host == "" {
		*host = cfg.CoordLanIP
	}
	out, err := exec.Command("ssh", "-p", *port, "-o", "StrictHostKeyChecking=accept-new",
		cfg.Username+"@"+*host, "cat /etc/hosts /etc/ssh/ssh_known_hosts").Output()
	if err != nil {
		return fmt.Errorf("cannot read the server list from the coordinator %s: %w", *host, err)
	}
	servers := mesh.ParseHostsBlock(string(out))
	coordIP := mesh.IP(cfg.WGSubnet, 1)
	coordName := ""
	for _, s := range servers {
		if s.MeshIP == coordIP {
			coordName = s.Name
		}
	}
	if coordName == "" {
		return fmt.Errorf("the coordinator has no mesh list yet (is dryserver-sync running?)")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	confPath := filepath.Join(home, ".ssh", "config.d", "dryserver")
	khPath := filepath.Join(home, ".ssh", "known_hosts.d", "dryserver")
	for _, d := range []string{filepath.Dir(confPath), filepath.Dir(khPath)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	if err := os.WriteFile(khPath, []byte(mesh.DesktopKnownHosts(string(out), coordName, *host, *port)), 0o644); err != nil {
		return err
	}
	conf := mesh.DesktopSSHConfig(cfg.Username, coordName, *host, *port, "~/.ssh/known_hosts.d/dryserver", servers)
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		return err
	}
	fmt.Printf("Wrote %s (%d servers) and %s.\n", confPath, len(servers), khPath)
	main, _ := os.ReadFile(filepath.Join(home, ".ssh", "config"))
	if !strings.Contains(string(main), "config.d/") {
		fmt.Println("Add this line at the top of ~/.ssh/config to use it:\n  Include config.d/*")
	}
	for _, s := range servers {
		fmt.Printf("  ssh %s\n", s.Name)
	}
	return nil
}

func runDisks() error {
	all, err := disks.List()
	if err != nil {
		return err
	}
	usb := map[string]bool{}
	for _, d := range disks.USB(all) {
		usb[d.Path] = true
	}
	for _, d := range all {
		tag := "other "
		switch {
		case usb[d.Path]:
			tag = "USB   "
		case d.IsSystem():
			tag = "system"
		}
		fmt.Printf("[%s] %s", tag, d.Title())
		if m := d.Mounts(); len(m) > 0 {
			fmt.Printf("  mounted: %s", strings.Join(m, ", "))
		}
		fmt.Println()
	}
	return nil
}

func runFlash(args []string) error {
	fs := flag.NewFlagSet("flash", flag.ExitOnError)
	iso := fs.String("iso", "", "installer image to write")
	fs.Parse(args)
	if *iso == "" {
		return fmt.Errorf("flash: --iso is required")
	}
	st, err := os.Stat(*iso)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() == 0 {
		return fmt.Errorf("%s is not an image file", *iso)
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("flash writes to raw disks and needs root:\n  sudo %s flash --iso %s", os.Args[0], *iso)
	}

	final, err := tea.NewProgram(tui.NewFlash(*iso, st.Size()), tea.WithAltScreen()).Run()
	if err != nil {
		return err
	}
	return final.(tui.Flash).Err()
}
