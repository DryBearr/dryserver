package node

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/DryBearr/dryserver/internal/runner"
)

// SwitchMACFile records which Ethernet port is the switch port.
const SwitchMACFile = "/etc/dryserver/switch.mac"

type port struct{ name, mac string }

// wiredPorts lists physical Ethernet ports. Virtual links (Docker,
// WireGuard, bridges) and WiFi are left out.
func wiredPorts() []port {
	var out []port
	ents, _ := os.ReadDir("/sys/class/net")
	for _, e := range ents {
		dir := filepath.Join("/sys/class/net", e.Name())
		if _, err := os.Stat(filepath.Join(dir, "device")); err != nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, "wireless")); err == nil {
			continue
		}
		mac, _ := os.ReadFile(filepath.Join(dir, "address"))
		out = append(out, port{e.Name(), strings.TrimSpace(string(mac))})
	}
	return out
}

// SwitchPort picks the Ethernet port for the switch and returns its MAC:
// with several ports, one that does not carry the default route (that one
// leads to the router). Empty when there is no Ethernet port.
func SwitchPort(ctx context.Context, run runner.Runner) string {
	ports := wiredPorts()
	if len(ports) == 0 {
		return ""
	}
	out, _ := run.Run(ctx, runner.Cmd{Name: "ip", Args: []string{"-j", "route", "show", "default"}, Quiet: true})
	var routes []struct {
		Dev string `json:"dev"`
	}
	json.Unmarshal([]byte(out), &routes)
	for _, p := range ports {
		if !slices.ContainsFunc(routes, func(r struct {
			Dev string `json:"dev"`
		}) bool {
			return r.Dev == p.name
		}) {
			return p.mac
		}
	}
	return ports[0].mac
}

// PortLink reports whether the port with this MAC has a cable link.
func PortLink(mac string) bool {
	for _, p := range wiredPorts() {
		if mac != "" && p.mac == mac {
			b, err := os.ReadFile(filepath.Join("/sys/class/net", p.name, "carrier"))
			return err == nil && strings.TrimSpace(string(b)) == "1"
		}
	}
	return false
}

// LocalIP returns this machine's address on the route towards dst, e.g.
// its LAN IP when dst is the coordinator.
func LocalIP(ctx context.Context, run runner.Runner, dst string) (string, error) {
	out, err := run.Run(ctx, runner.Cmd{Name: "ip", Args: []string{"-j", "route", "get", dst}, Quiet: true})
	if err != nil {
		return "", err
	}
	var routes []struct {
		Prefsrc string `json:"prefsrc"`
	}
	if json.Unmarshal([]byte(out), &routes) != nil || len(routes) == 0 || routes[0].Prefsrc == "" {
		return "", errors.New("no route to " + dst)
	}
	return routes[0].Prefsrc, nil
}
