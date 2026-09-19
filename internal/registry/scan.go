package registry

import (
	"bufio"
	"net"
	"slices"
	"strings"
	"time"
)

// ParseArpScan reads `arp-scan --plain` output: "IP<tab>MAC<tab>vendor".
func ParseArpScan(out string) []Device {
	var devs []Device
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		f := strings.SplitN(sc.Text(), "\t", 3)
		if len(f) < 2 || net.ParseIP(f[0]) == nil {
			continue
		}
		d := Device{IP: f[0], MAC: strings.ToLower(f[1])}
		if len(f) == 3 {
			d.Vendor = strings.TrimSpace(f[2])
		}
		if !slices.ContainsFunc(devs, func(x Device) bool { return x.IP == d.IP }) {
			devs = append(devs, d)
		}
	}
	return devs
}

// Unknown keeps the devices whose address belongs to no member. known
// holds every member address (LAN and switch).
func Unknown(found []Device, known []string, now time.Time) []Device {
	var out []Device
	for _, d := range found {
		if !slices.Contains(known, d.IP) {
			d.Seen = now
			out = append(out, d)
		}
	}
	return out
}
