// Package mesh turns the registry's member list into this machine's
// WireGuard config, /etc/hosts names and SSH trust files.
package mesh

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/DryBearr/dryserver/internal/config"
	"github.com/DryBearr/dryserver/internal/registry"
	"github.com/DryBearr/dryserver/internal/sysconf"
)

// Self is what this machine knows about itself.
type Self struct {
	Host   int  // mesh host number
	Switch bool // has a cable link on its Ethernet port
}

// IP returns the mesh or switch address of host n, without prefix.
func IP(cidr string, n int) string {
	addr, err := sysconf.HostAddr(cidr, n)
	if err != nil {
		return ""
	}
	return strings.Split(addr, "/")[0]
}

// HostOf returns the host number of ip inside cidr, or 0.
func HostOf(cidr string, ip net.IP) int {
	_, n, err := net.ParseCIDR(cidr)
	ip4 := ip.To4()
	if err != nil || ip4 == nil || !n.Contains(ip4) {
		return 0
	}
	base := n.IP.To4()
	v := int(ip4[0]-base[0])<<24 | int(ip4[1]-base[1])<<16 | int(ip4[2]-base[2])<<8 | int(ip4[3]-base[3])
	ones, bits := n.Mask.Size()
	if v <= 0 || v >= 1<<(bits-ones)-1 {
		return 0
	}
	return v
}

// Subnet implements registry.Mesh for the configured mesh subnet.
type Subnet string

func (s Subnet) HostOf(ip net.IP) int { return HostOf(string(s), ip) }

// Endpoint picks where to send WireGuard packets for peer: its switch
// address when both machines have a cable link (auto mode), otherwise its
// LAN address.
func Endpoint(cfg config.Config, self Self, peer registry.Member) string {
	ip := peer.LanIP
	if cfg.WGTransport == config.TransportAuto && self.Switch && peer.Switch {
		ip = IP(cfg.SwitchSubnet, peer.Host)
	}
	if ip == "" {
		return ""
	}
	return ip + ":" + cfg.WGPort
}

// WGConfig renders /etc/wireguard/wg0.conf. The private key stays in its
// own file and is loaded by PostUp, so this file holds nothing secret.
func WGConfig(cfg config.Config, self Self, members []registry.Member) string {
	addr, _ := sysconf.HostAddr(cfg.WGSubnet, self.Host)
	var b strings.Builder
	fmt.Fprintf(&b, `# dryserver mesh, rewritten by "dryserver sync" from the coordinator's list.
[Interface]
Address = %s
ListenPort = %s
PostUp = wg set %%i private-key /etc/wireguard/wg0.key
`, addr, cfg.WGPort)
	for _, m := range sorted(members) {
		if m.Host == self.Host {
			continue
		}
		fmt.Fprintf(&b, "\n# %s\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n", m.Name, m.WGKey, IP(cfg.WGSubnet, m.Host))
		if ep := Endpoint(cfg, self, m); ep != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", ep)
		}
		b.WriteString("PersistentKeepalive = 25\n")
	}
	return b.String()
}

const (
	hostsBegin = "# dryserver mesh begin"
	hostsEnd   = "# dryserver mesh end"
)

// Hosts returns /etc/hosts with the mesh block replaced by current names.
func Hosts(current string, cfg config.Config, members []registry.Member) string {
	var keep []string
	skip := false
	for _, l := range strings.Split(strings.TrimRight(current, "\n"), "\n") {
		switch {
		case l == hostsBegin:
			skip = true
		case l == hostsEnd:
			skip = false
		case !skip:
			keep = append(keep, l)
		}
	}
	keep = append(keep, hostsBegin)
	for _, m := range sorted(members) {
		keep = append(keep, fmt.Sprintf("%s %s", IP(cfg.WGSubnet, m.Host), m.Name))
	}
	keep = append(keep, hostsEnd)
	return strings.Join(keep, "\n") + "\n"
}

// KnownHosts lists every member's SSH host key under its name and mesh IP,
// so SSH between servers never asks to trust a key.
func KnownHosts(cfg config.Config, members []registry.Member) string {
	var b strings.Builder
	b.WriteString("# dryserver mesh host keys, from the coordinator.\n")
	for _, m := range sorted(members) {
		if m.SSHHostKey == "" {
			continue
		}
		fields := strings.Fields(m.SSHHostKey)
		fmt.Fprintf(&b, "%s,%s %s %s\n", m.Name, IP(cfg.WGSubnet, m.Host), fields[0], fields[1])
	}
	return b.String()
}

// SSHConfig lets `ssh <name>` reach any member over the mesh and forwards
// the agent (the desktop key) for the next hop. No private keys live on
// servers.
func SSHConfig(cfg config.Config, members []registry.Member) string {
	var names []string
	for _, m := range sorted(members) {
		names = append(names, m.Name)
	}
	return fmt.Sprintf(`# dryserver mesh hosts: ssh <name> works between servers using the key
# forwarded from your desktop (connect with ssh -A).
Host %s
    User %s
    ForwardAgent yes
    StrictHostKeyChecking yes
`, strings.Join(names, " "), cfg.Username)
}

func sorted(members []registry.Member) []registry.Member {
	out := append([]registry.Member(nil), members...)
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}
