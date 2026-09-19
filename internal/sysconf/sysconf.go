// Package sysconf renders the system files written to every installed
// server: firewall, SSH, kernel hardening, network, Docker and login
// settings. Rendering is pure so the output can be golden-tested and
// validated with the real tools (nft -c, sshd -t).
package sysconf

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net"
	"slices"
	"strings"
	"text/template"

	"github.com/DryBearr/dryserver/internal/config"
	"github.com/DryBearr/dryserver/internal/packages"
)

type Role string

const (
	Node        Role = "node"
	Coordinator Role = "coordinator"
)

// RegistryUser is the locked account on the coordinator that runs the
// registry as an SSH forced command.
const RegistryUser = "dryreg"

type Params struct {
	Config   config.Config
	Plan     packages.Plan
	Hostname string
	Role     Role
	// HostNum is this machine's mesh host number (10.66.0.N). 0 means not
	// approved yet: files that need it are rendered without it.
	HostNum int
	// SwitchMAC is the Ethernet port that gets the switch address (auto
	// mode). Empty when the machine has no Ethernet port.
	SwitchMAC string
}

type File struct {
	Path    string
	Mode    fs.FileMode
	Content string
}

// Render returns every system file for the machine described by p.
func Render(p Params) ([]File, error) {
	c := p.Config
	if err := c.Validate(); err != nil {
		return nil, err
	}
	meshPorts, _ := config.ParsePorts(c.MeshPorts)

	var switchAddr string
	if c.WGTransport == config.TransportAuto && p.HostNum > 0 {
		addr, err := HostAddr(c.SwitchSubnet, p.HostNum)
		if err != nil {
			return nil, fmt.Errorf("switch address: %w", err)
		}
		switchAddr = addr
	}

	// The node keeps the settings it needs for sync, but not the WiFi
	// password: iwd has its own copy.
	nodeCfg := c
	nodeCfg.WifiPass = ""
	var cfgBuf bytes.Buffer
	if err := nodeCfg.Write(&cfgBuf); err != nil {
		return nil, err
	}

	files := []File{
		{"/etc/hostname", 0o644, p.Hostname + "\n"},
		{"/etc/hosts", 0o644, hosts(p.Hostname)},
		{"/etc/nftables.conf", 0o600, exec(nftTmpl, nftData{
			WGPort:  c.WGPort,
			Switch:  switchSubnet(c),
			MeshTCP: portsOf(meshPorts, "tcp"),
			MeshUDP: portsOf(meshPorts, "udp"),
		})},
		{"/etc/ssh/sshd_config.d/10-dryserver.conf", 0o644, sshd(c.Username, p.Role)},
		{"/home/" + c.Username + "/.ssh/authorized_keys", 0o600, strings.TrimSpace(config.NormalizePubkey(c.AdminSSHPubkey)+" "+c.AdminKeyLabel) + "\n"},
		{"/etc/sudoers.d/10-wheel", 0o440, "# Members of wheel may use sudo after typing their password.\n%wheel ALL=(ALL:ALL) ALL\n"},
		{"/etc/sysctl.d/90-dryserver.conf", 0o644, sysctl},
		{"/etc/systemd/network/20-wired.network", 0o644, wired},
		{"/etc/systemd/network/25-wireless.network", 0o644, wireless},
		{"/etc/systemd/system/systemd-networkd-wait-online.service.d/any.conf", 0o644, waitOnline},
		{"/etc/systemd/logind.conf.d/10-lid.conf", 0o644, lid},
		{"/etc/systemd/resolved.conf.d/10-dryserver.conf", 0o644, resolved},
		{"/etc/systemd/zram-generator.conf", 0o644, zram},
		{"/etc/dryserver/config.env", 0o600, cfgBuf.String()},
		{"/etc/dryserver/role", 0o644, string(p.Role) + "\n"},
		{"/etc/systemd/system/dryserver-join.service", 0o644, joinUnit},
		{"/etc/systemd/system/dryserver-sync.service", 0o644, syncUnit},
		{"/etc/systemd/system/dryserver-sync.timer", 0o644, syncTimer},
		{"/etc/systemd/system/dryserver-tpm-enroll.service", 0o644, tpmEnrollUnit},
	}
	if p.Role == Coordinator {
		files = append(files, File{"/etc/cron.d/dryserver-scan", 0o644, scanCron})
	}
	if switchAddr != "" && p.SwitchMAC != "" {
		files = append(files, File{"/etc/systemd/network/10-switch.network", 0o644, switchNetwork(p.SwitchMAC, switchAddr)})
	}
	if c.WifiSSID != "" {
		files = append(files, IwdFile(c.WifiSSID, c.WifiPass))
	}
	if slices.Contains(p.Plan.Packages, "docker") {
		files = append(files, File{"/etc/docker/daemon.json", 0o644, dockerDaemon})
	}
	return files, nil
}

// HostAddr returns host n of cidr with the prefix, e.g. ("10.66.0.0/24", 5)
// -> "10.66.0.5/24".
func HostAddr(cidr string, n int) (string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	ones, bits := ipnet.Mask.Size()
	if n < 1 || n >= (1<<(bits-ones))-1 {
		return "", fmt.Errorf("host %d does not fit in %s", n, cidr)
	}
	ip := ipnet.IP.To4()
	v := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	v += uint32(n)
	return fmt.Sprintf("%d.%d.%d.%d/%d", v>>24, v>>16&0xff, v>>8&0xff, v&0xff, ones), nil
}

func switchSubnet(c config.Config) string {
	if c.WGTransport == config.TransportAuto {
		return c.SwitchSubnet
	}
	return ""
}

func portsOf(ports []config.Port, proto string) []int {
	var out []int
	for _, p := range ports {
		if p.Proto == proto && !slices.Contains(out, p.Num) {
			out = append(out, p.Num)
		}
	}
	return out
}

func hosts(hostname string) string {
	return fmt.Sprintf(`127.0.0.1 localhost
::1       localhost
127.0.1.1 %s
`, hostname)
}

type nftData struct {
	WGPort  string
	Switch  string
	MeshTCP []int
	MeshUDP []int
}

var nftTmpl = template.Must(template.New("nft").Parse(`#!/usr/bin/nft -f
# dryserver firewall, generated from config.env. To open more ports to the
# mesh, change MESH_PORTS there. Only this table is touched, so Docker's own
# rules survive reloads.

destroy table inet dryserver

table inet dryserver {
	# Addresses that opened too many SSH connections in the last minute.
	set ssh_meter4 {
		type ipv4_addr
		flags dynamic
		timeout 1m
	}
	set ssh_meter6 {
		type ipv6_addr
		flags dynamic
		timeout 1m
	}

	chain input {
		type filter hook input priority filter; policy drop;
		ct state vmap { established : accept, related : accept, invalid : drop }
		iif lo accept

		icmp type echo-request limit rate 10/second accept
		icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept
		icmpv6 type echo-request limit rate 10/second accept

		iifname "wg0" jump mesh

		# WireGuard from the WiFi/router network and the switch.
		udp dport {{.WGPort}} accept
{{- if .Switch}}

		# Switch network: WireGuard only.
		ip saddr {{.Switch}} drop
{{- end}}

		# SSH from the WiFi/router network, at most 10 new connections a
		# minute per address. Logins need the admin SSH key.
		tcp dport 22 ct state new add @ssh_meter4 { ip saddr limit rate over 10/minute burst 20 packets } drop
		tcp dport 22 ct state new add @ssh_meter6 { ip6 saddr limit rate over 10/minute burst 20 packets } drop
		tcp dport 22 accept
	}

	# Traffic from other servers over WireGuard.
	chain mesh {
		tcp dport { 22{{range .MeshTCP}}, {{.}}{{end}} } accept
{{- if .MeshUDP}}
		udp dport { {{range $i, $p := .MeshUDP}}{{if $i}}, {{end}}{{$p}}{{end}} } accept
{{- end}}
		icmp type echo-request accept
		icmpv6 type echo-request accept
	}
}
`))

func sshd(user string, role Role) string {
	users := user
	if role == Coordinator {
		users += " " + RegistryUser
	}
	return fmt.Sprintf(`# dryserver SSH hardening. Login with the admin SSH key only.
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
PermitRootLogin no
PermitEmptyPasswords no
AllowUsers %s
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
PermitTunnel no
# Agent forwarding lets you hop between servers with your desktop key;
# TCP forwarding is needed for ProxyJump through a server.
AllowAgentForwarding yes
AllowTcpForwarding yes
ClientAliveInterval 300
ClientAliveCountMax 2
`, users)
}

const sysctl = `# dryserver kernel hardening
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.yama.ptrace_scope = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# Loose reverse-path filter: strict mode breaks machines with WiFi and a
# cable in the same network.
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
`

const wired = `# Ethernet ports: DHCP when the cable reaches a router (then the cable
# also carries internet). The switch port has its own file, 10-switch.network.
[Match]
Type=ether
Kind=!*

[Network]
DHCP=yes

[DHCPv4]
RouteMetric=100

[IPv6AcceptRA]
RouteMetric=100
`

// switchNetwork gives the chosen port its fixed switch address next to
// DHCP, so an isolated switch and a router-connected one both work.
func switchNetwork(mac, addr string) string {
	return fmt.Sprintf(`# The Ethernet port used for the switch: fixed address %s (no gateway)
# plus DHCP in case the switch is connected to the router.
[Match]
MACAddress=%s

[Network]
DHCP=yes
Address=%s

[DHCPv4]
RouteMetric=100

[IPv6AcceptRA]
RouteMetric=100
`, addr, mac, addr)
}

const wireless = `# WiFi (iwd connects, networkd does DHCP). Higher metric than Ethernet,
# so a cable to the router wins for internet when present.
[Match]
Type=wlan

[Network]
DHCP=yes

[DHCPv4]
RouteMetric=600

[IPv6AcceptRA]
RouteMetric=600
`

const waitOnline = `# Boot does not wait for every link: an isolated switch or missing WiFi
# must not hold up startup.
[Service]
ExecStart=
ExecStart=/usr/lib/systemd/systemd-networkd-wait-online --any --timeout=30
`

const lid = `# Laptop as server: keep running with the lid closed.
[Login]
HandleLidSwitch=ignore
HandleLidSwitchExternalPower=ignore
HandleLidSwitchDocked=ignore
`

const resolved = `# No LLMNR or mDNS: both answer name lookups from anyone on the network
# and are a common way to poison names on a LAN.
[Resolve]
LLMNR=no
MulticastDNS=no
`

const joinUnit = `[Unit]
Description=Ask the coordinator to let this server join the mesh
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dryserver join
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
`

// tpmEnrollUnit runs once, at the first boot of a TPM-mode install: the
// disk was unlocked with the passphrase, now the TPM learns this boot.
const tpmEnrollUnit = `[Unit]
Description=Let the TPM unlock the disk from now on
ConditionPathExists=/etc/cryptsetup-keys.d/tpm-enroll.key
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/dryserver tpm-enroll --first-boot

[Install]
WantedBy=multi-user.target
`

const syncUnit = `[Unit]
Description=Update the WireGuard mesh from the coordinator's member list
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/dryserver sync
`

const syncTimer = `[Unit]
Description=Update the WireGuard mesh every minute

[Timer]
OnBootSec=20s
OnUnitActiveSec=60s

[Install]
WantedBy=timers.target
`

// scanCron lists unknown devices on the coordinator's networks every 15
// minutes, for the approval screen. Report only: nothing is ever added.
const scanCron = `# dryserver: look for unknown devices on the network (report only).
*/15 * * * * root /usr/local/bin/dryserver scan >/dev/null 2>&1
`

const zram = `# Compressed swap in RAM. No swap partition, so nothing from memory is
# written unencrypted to disk.
[zram0]
zram-size = min(ram / 2, 8192)
compression-algorithm = zstd
`

const dockerDaemon = `{
  "ip": "127.0.0.1",
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" }
}
`

// IwdFile names the network file the way iwd expects: plain SSIDs as-is,
// anything else hex-encoded after "=".
func IwdFile(ssid, pass string) File {
	name := ssid
	for _, r := range ssid {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			name = "=" + hex.EncodeToString([]byte(ssid))
			break
		}
	}
	if pass == "" {
		return File{"/var/lib/iwd/" + name + ".open", 0o600, "[Settings]\nAutoConnect=true\n"}
	}
	return File{"/var/lib/iwd/" + name + ".psk", 0o600,
		"[Security]\nPassphrase=" + pass + "\n\n[Settings]\nAutoConnect=true\n"}
}

func exec(t *template.Template, data any) string {
	var b bytes.Buffer
	if err := t.Execute(&b, data); err != nil {
		panic(err) // templates are fixed; a failure is a programming error
	}
	return b.String()
}
