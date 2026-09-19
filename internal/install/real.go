package install

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DryBearr/dryserver/internal/config"
	"github.com/DryBearr/dryserver/internal/disks"
	"github.com/DryBearr/dryserver/internal/sysconf"
)

// Real installs for real. It runs inside the live installer system as root.
type Real struct {
	Cfg    config.Config
	Run    Runner
	Rootfs fs.FS  // files for the installed system (assets.Rootfs, rooted at "rootfs")
	Self   string // this binary, copied into the installed system
	// RegistryKey is the private key nodes use to reach the coordinator's
	// registry; baked into the ISO by the build.
	RegistryKey string
	Target      string // mount point of the new system, normally /mnt
	KeyDir      string // RAM-backed dir for temporary keyfiles, normally /run

	// LogFile receives every command and its output.
	LogFile io.Writer
	// MirrorList is the live system's pacman mirror list.
	MirrorList string

	machine Machine
	state   installState
	sink    func(string) // current step's log, set during Install
	mu      sync.Mutex
	dlTotal string // "758.70 MiB", from pacman's output
}

// Log records one line: always to LogFile, and to the setup screen while
// installing. Use it as the ExecRunner's Log.
func (r *Real) Log(line string) {
	if total, ok := strings.CutPrefix(line, "Total Download Size:"); ok {
		r.mu.Lock()
		r.dlTotal = strings.TrimSpace(total)
		r.mu.Unlock()
	}
	if r.LogFile != nil {
		io.WriteString(r.LogFile, line+"\n")
	}
	if r.sink != nil {
		r.sink(line)
	}
}

// installState is what Install leaves for Join and Reboot.
type installState struct {
	layout       Layout
	mapped       []string // opened LUKS mappers, closed on reboot
	wgPublic     string
	hostKey      string // new system's SSH host public key
	dataUUIDs    []string
	switchMAC    string
	firstBootKey []byte
	installed    bool
}

func NewReal(cfg config.Config, run Runner, rootfs fs.FS, self, registryKey string) *Real {
	return &Real{Cfg: cfg, Run: run, Rootfs: rootfs, Self: self, RegistryKey: registryKey, Target: "/mnt", KeyDir: "/run",
		MirrorList: "/etc/pacman.d/mirrorlist"}
}

func (r *Real) Probe(ctx context.Context) (Machine, error) {
	m := Machine{
		CPU:     cpuModel(),
		RAM:     memTotal(),
		UEFI:    exists("/sys/firmware/efi"),
		TPMChip: strings.TrimSpace(readFile("/sys/class/tpm/tpm0/tpm_version_major")) == "2",
	}
	// The firmware's event log exists only if it measured the boot.
	m.TPM2 = m.TPMChip && exists("/sys/kernel/security/tpm0/binary_bios_measurements")
	all, err := disks.List()
	if err != nil {
		return m, err
	}
	m.Disks = disks.Installable(all)

	m.Online, m.Net = r.online(ctx)
	if !m.Online && r.Cfg.WifiSSID != "" {
		// iwd connects to known networks by itself once the file exists.
		if err := r.addWifi(r.Cfg.WifiSSID, r.Cfg.WifiPass); err == nil {
			m.Online, m.Net = r.waitOnline(ctx, 25*time.Second)
		}
	}
	if m.Online {
		m.CoordFound = coordinatorAnswers(ctx, r.Cfg.CoordLanIP, 3*time.Second)
	}
	r.machine = m
	return m, nil
}

// coordinatorAnswers reports whether the coordinator's SSH port answers.
func coordinatorAnswers(ctx context.Context, ip string, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, "22"))
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func (r *Real) online(ctx context.Context) (bool, string) {
	d := net.Dialer{Timeout: 4 * time.Second}
	c, err := d.DialContext(ctx, "tcp", "archlinux.org:443")
	if err != nil {
		return false, ""
	}
	c.Close()
	return true, r.describeRoute(ctx)
}

func (r *Real) waitOnline(ctx context.Context, limit time.Duration) (bool, string) {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if ok, desc := r.online(ctx); ok {
			return true, desc
		}
		select {
		case <-ctx.Done():
			return false, ""
		case <-time.After(2 * time.Second):
		}
	}
	return false, ""
}

// describeRoute says which link carries internet, e.g. "WiFi wlan0 (192.168.1.23)".
func (r *Real) describeRoute(ctx context.Context) string {
	out, err := r.Run.Run(ctx, Cmd{Name: "ip", Args: []string{"-j", "route", "get", "1.1.1.1"}, Quiet: true})
	if err != nil {
		return "connected"
	}
	var routes []struct {
		Dev     string `json:"dev"`
		Prefsrc string `json:"prefsrc"`
	}
	if json.Unmarshal([]byte(out), &routes) != nil || len(routes) == 0 {
		return "connected"
	}
	kind := "Ethernet"
	if exists("/sys/class/net/" + routes[0].Dev + "/wireless") {
		kind = "WiFi"
	}
	return fmt.Sprintf("%s %s (%s)", kind, routes[0].Dev, routes[0].Prefsrc)
}

func wifiDevice() (string, error) {
	ents, _ := os.ReadDir("/sys/class/net")
	for _, e := range ents {
		if exists("/sys/class/net/" + e.Name() + "/wireless") {
			return e.Name(), nil
		}
	}
	return "", errors.New("no WiFi adapter found")
}

// addWifi stores the network for the live system's iwd only (RAM).
func (r *Real) addWifi(ssid, pass string) error {
	f := sysconf.IwdFile(ssid, pass)
	if err := os.MkdirAll("/var/lib/iwd", 0o700); err != nil {
		return err
	}
	return os.WriteFile(f.Path, []byte(f.Content), 0o600)
}

func (r *Real) ScanWiFi(ctx context.Context) ([]string, error) {
	dev, err := wifiDevice()
	if err != nil {
		return nil, err
	}
	r.Run.Run(ctx, Cmd{Name: "iwctl", Args: []string{"station", dev, "scan"}, Quiet: true})
	time.Sleep(4 * time.Second)
	out, err := r.Run.Run(ctx, Cmd{Name: "iwctl", Args: []string{"station", dev, "get-networks"}, Quiet: true})
	if err != nil {
		return nil, err
	}
	return ParseNetworks(out), nil
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// ParseNetworks reads SSIDs from `iwctl station DEV get-networks`, a
// fixed-width table whose "Network name" column ends where "Security"
// starts.
func ParseNetworks(out string) []string {
	var ssids []string
	start, end := -1, -1
	sc := bufio.NewScanner(strings.NewReader(ansi.ReplaceAllString(out, "")))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "Network name"); i >= 0 {
			start, end = i, strings.Index(line, "Security")
			continue
		}
		if start < 0 || end <= start || strings.HasPrefix(strings.TrimSpace(line), "---") || len(line) <= start {
			continue
		}
		name := strings.TrimSpace(line[start:min(end, len(line))])
		if name != "" {
			ssids = append(ssids, name)
		}
	}
	return ssids
}

func (r *Real) ConnectWiFi(ctx context.Context, ssid, pass string) (Machine, error) {
	dev, err := wifiDevice()
	if err != nil {
		return r.machine, err
	}
	if err := r.addWifi(ssid, pass); err != nil {
		return r.machine, err
	}
	if _, err := r.Run.Run(ctx, Cmd{Name: "iwctl", Args: []string{"station", dev, "connect", ssid}}); err != nil {
		return r.machine, errors.New("wrong password or network out of range")
	}
	ok, desc := r.waitOnline(ctx, 20*time.Second)
	if !ok {
		return r.machine, errors.New("connected to WiFi but no internet")
	}
	r.machine.Online, r.machine.Net = true, desc
	r.machine.CoordFound = coordinatorAnswers(ctx, r.Cfg.CoordLanIP, 3*time.Second)
	return r.machine, nil
}

func (r *Real) Reboot() error {
	ctx := context.Background()
	r.Run.Run(ctx, Cmd{Name: "sync"})
	r.Run.Run(ctx, Cmd{Name: "umount", Args: []string{"-R", r.Target}})
	for _, m := range r.state.mapped {
		r.Run.Run(ctx, Cmd{Name: "cryptsetup", Args: []string{"close", m}})
	}
	_, err := r.Run.Run(ctx, Cmd{Name: "systemctl", Args: []string{"reboot"}})
	return err
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func readFile(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

func cpuModel() string {
	for _, line := range strings.Split(readFile("/proc/cpuinfo"), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "model name" {
			return strings.TrimSpace(v)
		}
	}
	return "unknown"
}

func memTotal() uint64 {
	for _, line := range strings.Split(readFile("/proc/meminfo"), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "MemTotal:" {
			kb, _ := strconv.ParseUint(f[1], 10, 64)
			return kb * 1024
		}
	}
	return 0
}

// target returns path inside the new system.
func (r *Real) target(path string) string { return filepath.Join(r.Target, path) }
