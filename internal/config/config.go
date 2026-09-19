// Package config loads, validates and saves config.env, the settings baked
// into the installer ISO. The file is plain KEY='value' lines so shell
// scripts on the nodes can source it.
package config

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/DryBearr/dryserver/internal/packages"
)

// WireGuard transport between two nodes.
const (
	// TransportAuto uses the switch when both nodes have a cable link on
	// their Ethernet port, and the WiFi/router network otherwise.
	TransportAuto = "auto"
	// TransportLAN always uses the WiFi/router network.
	TransportLAN = "lan"
)

type Config struct {
	WifiSSID       string
	WifiPass       string
	CoordLanIP     string
	WGSubnet       string
	WGPort         string
	WGTransport    string
	SwitchSubnet   string
	MeshPorts      string // space-separated port/proto opened on wg0, e.g. "8080/tcp 53/udp"
	Tools          string // space-separated optional bundle IDs, see packages.Optional
	ExtraPackages  string // space-separated extra Arch packages
	Username       string
	AdminSSHPubkey string // key type and key only, no comment
	AdminKeyLabel  string // short name shown after the key on servers
	Timezone       string
}

func Default() Config {
	return Config{
		WGSubnet:      "10.66.0.0/24",
		WGPort:        "51820",
		WGTransport:   TransportAuto,
		SwitchSubnet:  "172.16.66.0/24",
		Tools:         strings.Join(packages.DefaultTools(), " "),
		Username:      "admin",
		AdminKeyLabel: "desktop",
		Timezone:      "UTC",
	}
}

// fields maps each env key to its struct field, in file order.
func (c *Config) fields() []struct {
	key string
	val *string
} {
	return []struct {
		key string
		val *string
	}{
		{"WIFI_SSID", &c.WifiSSID},
		{"WIFI_PASS", &c.WifiPass},
		{"COORD_LAN_IP", &c.CoordLanIP},
		{"WG_SUBNET", &c.WGSubnet},
		{"WG_PORT", &c.WGPort},
		{"WG_TRANSPORT", &c.WGTransport},
		{"SWITCH_SUBNET", &c.SwitchSubnet},
		{"MESH_PORTS", &c.MeshPorts},
		{"TOOLS", &c.Tools},
		{"EXTRA_PACKAGES", &c.ExtraPackages},
		{"USERNAME", &c.Username},
		{"ADMIN_SSH_PUBKEY", &c.AdminSSHPubkey},
		{"ADMIN_KEY_LABEL", &c.AdminKeyLabel},
		{"TIMEZONE", &c.Timezone},
	}
}

// Load reads path. A missing file returns Default() and an error wrapping
// os.ErrNotExist.
func Load(path string) (Config, error) {
	c := Default()
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()

	byKey := map[string]*string{}
	for _, fl := range c.fields() {
		byKey[fl.key] = fl.val
	}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return c, fmt.Errorf("%s:%d: expected KEY=value", path, n)
		}
		if dst, known := byKey[strings.TrimSpace(k)]; known {
			*dst = unquote(strings.TrimSpace(v))
		}
	}
	c.AdminSSHPubkey = NormalizePubkey(c.AdminSSHPubkey)
	return c, sc.Err()
}

func (c Config) Save(path string) error {
	var b bytes.Buffer
	if err := c.Write(&b); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Write writes the config in env-file form.
func (c Config) Write(w io.Writer) error {
	c.AdminSSHPubkey = NormalizePubkey(c.AdminSSHPubkey)
	var b strings.Builder
	b.WriteString("# dryserver config. Keep private: may contain the WiFi password.\n")
	for _, fl := range c.fields() {
		fmt.Fprintf(&b, "%s=%s\n", fl.key, quote(*fl.val))
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func (c Config) Validate() error {
	var errs []error
	check := func(name string, err error) {
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	if c.WifiSSID != "" {
		check("WiFi password", ValidWifiPass(c.WifiPass))
	}
	check("coordinator IP", ValidIPv4(c.CoordLanIP))
	check("mesh subnet", ValidMeshSubnet(c.WGSubnet, c.CoordLanIP))
	check("WireGuard port", ValidPort(c.WGPort))
	check("WireGuard transport", ValidTransport(c.WGTransport))
	if c.WGTransport == TransportAuto {
		check("switch subnet", ValidSwitchSubnet(c.SwitchSubnet, c.WGSubnet, c.CoordLanIP))
	}
	check("mesh ports", ValidMeshPorts(c.MeshPorts))
	check("tools", packages.ValidTools(c.ToolList()))
	check("extra packages", packages.ValidExtra(c.ExtraList()))
	check("username", ValidUsername(c.Username))
	check("SSH key", ValidPubkey(c.AdminSSHPubkey))
	check("key label", ValidKeyLabel(c.AdminKeyLabel))
	check("timezone", ValidTimezone(c.Timezone))
	return errors.Join(errs...)
}

func (c Config) ToolList() []string  { return strings.Fields(c.Tools) }
func (c Config) ExtraList() []string { return strings.Fields(c.ExtraPackages) }

// ValidExtraPackages checks the space-separated form field.
func ValidExtraPackages(s string) error { return packages.ValidExtra(strings.Fields(s)) }

func ValidWifiPass(s string) error {
	// WPA2-PSK passphrases are 8 to 63 characters. Empty means an open network.
	if s != "" && (len(s) < 8 || len(s) > 63) {
		return errors.New("must be 8 to 63 characters (or empty for an open network)")
	}
	return nil
}

func ValidIPv4(s string) error {
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return errors.New("must be an IPv4 address like 192.168.1.50")
	}
	return nil
}

func ValidSubnet(s string) error {
	ip, n, err := net.ParseCIDR(s)
	if err != nil || ip.To4() == nil {
		return errors.New("must be an IPv4 CIDR like 10.66.0.0/24")
	}
	if ones, _ := n.Mask.Size(); ones > 29 {
		return errors.New("too small, use /29 or bigger (e.g. /24)")
	}
	if !ip.Equal(n.IP) {
		return fmt.Errorf("use the network address %s", n)
	}
	return nil
}

// ValidMeshSubnet also rejects a mesh subnet holding the coordinator's LAN
// IP, which would break routing to the coordinator.
func ValidMeshSubnet(s, coordIP string) error {
	if err := ValidSubnet(s); err != nil {
		return err
	}
	_, n, _ := net.ParseCIDR(s)
	if ip := net.ParseIP(coordIP); ip != nil && n.Contains(ip) {
		return fmt.Errorf("contains the coordinator LAN IP %s, pick another range", coordIP)
	}
	return nil
}

// ValidSwitchSubnet checks the switch range against the mesh range: node N
// in the mesh gets host N on the switch, so both need the same size, and
// they must not overlap each other or the coordinator's LAN IP.
func ValidSwitchSubnet(s, meshSubnet, coordIP string) error {
	if err := ValidMeshSubnet(s, coordIP); err != nil {
		return err
	}
	_, sw, _ := net.ParseCIDR(s)
	_, mesh, err := net.ParseCIDR(meshSubnet)
	if err != nil {
		return nil // reported on the mesh subnet field
	}
	if sw.Contains(mesh.IP) || mesh.Contains(sw.IP) {
		return fmt.Errorf("overlaps the mesh subnet %s", mesh)
	}
	swBits, _ := sw.Mask.Size()
	meshBits, _ := mesh.Mask.Size()
	if swBits != meshBits {
		return fmt.Errorf("must be the same size as the mesh subnet (/%d)", meshBits)
	}
	return nil
}

// Port is one firewall opening: number and protocol.
type Port struct {
	Num   int
	Proto string // tcp or udp
}

// ParsePorts parses "8080/tcp 53/udp 9000" (protocol defaults to tcp).
func ParsePorts(s string) ([]Port, error) {
	var out []Port
	for _, f := range strings.Fields(s) {
		num, proto, _ := strings.Cut(f, "/")
		if proto == "" {
			proto = "tcp"
		}
		n, err := strconv.Atoi(num)
		if err != nil || n < 1 || n > 65535 || (proto != "tcp" && proto != "udp") {
			return nil, fmt.Errorf("%q: use PORT/tcp or PORT/udp, e.g. 8080/tcp", f)
		}
		out = append(out, Port{n, proto})
	}
	return out, nil
}

func ValidMeshPorts(s string) error {
	_, err := ParsePorts(s)
	return err
}

func ValidTransport(s string) error {
	if s != TransportAuto && s != TransportLAN {
		return fmt.Errorf("must be %q or %q", TransportAuto, TransportLAN)
	}
	return nil
}

func ValidPort(s string) error {
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return errors.New("must be a number from 1 to 65535")
	}
	return nil
}

var usernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func ValidUsername(s string) error {
	if !usernameRe.MatchString(s) || s == "root" {
		return errors.New("lowercase letters, digits, _ and -, not root")
	}
	return nil
}

func ValidPubkey(s string) error {
	f := strings.Fields(s)
	if len(f) < 2 || !(strings.HasPrefix(f[0], "ssh-") || strings.HasPrefix(f[0], "ecdsa-") || strings.HasPrefix(f[0], "sk-")) {
		return errors.New("paste the line from ~/.ssh/id_ed25519.pub (starts with ssh-ed25519)")
	}
	if strings.Contains(s, "PRIVATE KEY") {
		return errors.New("that is a private key, use the .pub file")
	}
	return nil
}

func ValidTimezone(s string) error {
	if s == "" || strings.HasPrefix(s, "/") || strings.Contains(s, "..") {
		return errors.New("use a zone name like Europe/Berlin or UTC")
	}
	if _, err := time.LoadLocation(s); err != nil {
		return errors.New("unknown zone, use a name like Europe/Berlin or UTC")
	}
	return nil
}

// NormalizePubkey keeps only the key type and key of an OpenSSH public key
// line and drops the trailing comment, which is often an email address.
func NormalizePubkey(s string) string {
	if f := strings.Fields(s); len(f) >= 2 {
		return f[0] + " " + f[1]
	}
	return strings.TrimSpace(s)
}

var labelRe = regexp.MustCompile(`^[A-Za-z0-9._-]{0,32}$`)

// ValidKeyLabel allows a short name like "desktop"; no spaces or @.
func ValidKeyLabel(s string) error {
	if !labelRe.MatchString(s) {
		return errors.New("letters, digits, . _ - only (up to 32), e.g. desktop")
	}
	return nil
}

func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], `'\''`, "'")
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		r := strings.NewReplacer(`\"`, `"`, `\\`, `\`, `\$`, `$`, "\\`", "`")
		return r.Replace(s[1 : len(s)-1])
	}
	return s
}
