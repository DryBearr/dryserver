package sysconf

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DryBearr/dryserver/internal/config"
	"github.com/DryBearr/dryserver/internal/packages"
)

var update = flag.Bool("update", false, "rewrite golden files")

func baseConfig() config.Config {
	c := config.Default()
	c.CoordLanIP = "192.168.1.50"
	c.AdminSSHPubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest admin@desktop"
	return c
}

func cases() map[string]Params {
	node := baseConfig()
	node.WifiSSID, node.WifiPass = "Home Net!", "correct horse"
	node.MeshPorts = "8080/tcp 53/udp 9000/tcp"
	nodePlan, _ := packages.Resolve(node.ToolList(), nil)

	coord := baseConfig()
	coord.WGTransport = config.TransportLAN
	coord.Tools = "go"
	coordPlan, _ := packages.Resolve(coord.ToolList(), nil)

	return map[string]Params{
		"node":        {Config: node, Plan: nodePlan, Hostname: "node-3a2f", Role: Node, HostNum: 5, SwitchMAC: "52:54:66:aa:bb:cc"},
		"node-new":    {Config: node, Plan: nodePlan, Hostname: "node-9c1d", Role: Node, HostNum: 0, SwitchMAC: "52:54:66:aa:bb:dd"},
		"coordinator": {Config: coord, Plan: coordPlan, Hostname: "coord", Role: Coordinator, HostNum: 1, SwitchMAC: "52:54:66:aa:bb:ee"},
	}
}

func dump(files []File) string {
	var b strings.Builder
	for _, f := range files {
		fmt.Fprintf(&b, "===== %s (%04o)\n%s", f.Path, f.Mode, f.Content)
	}
	return b.String()
}

func TestGolden(t *testing.T) {
	for name, p := range cases() {
		files, err := Render(p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := dump(files)
		path := filepath.Join("testdata", name+".golden")
		if *update {
			os.MkdirAll("testdata", 0o755)
			os.WriteFile(path, []byte(got), 0o644)
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v (run go test ./internal/sysconf -update)", name, err)
		}
		if got != string(want) {
			t.Errorf("%s differs from %s; run with -update and review the diff", name, path)
		}
	}
}

func find(t *testing.T, files []File, path string) File {
	t.Helper()
	for _, f := range files {
		if f.Path == path {
			return f
		}
	}
	t.Fatalf("%s not rendered", path)
	return File{}
}

func has(files []File, path string) bool {
	for _, f := range files {
		if f.Path == path {
			return true
		}
	}
	return false
}

func TestSecurityProperties(t *testing.T) {
	cs := cases()
	node, _ := Render(cs["node"])
	coord, _ := Render(cs["coordinator"])
	fresh, _ := Render(cs["node-new"])

	nft := find(t, node, "/etc/nftables.conf").Content
	for _, want := range []string{"policy drop", "destroy table inet dryserver", "ip saddr 172.16.66.0/24 drop", "tcp dport { 22, 8080, 9000 } accept", "udp dport { 53 } accept"} {
		if !strings.Contains(nft, want) {
			t.Errorf("node nftables missing %q", want)
		}
	}
	if strings.Contains(nft, "flush ruleset") {
		t.Error("nftables must not flush Docker's rules")
	}
	if strings.Contains(find(t, coord, "/etc/nftables.conf").Content, "ip saddr 172.16") {
		t.Error("lan transport must not add a switch rule")
	}

	sshd := find(t, node, "/etc/ssh/sshd_config.d/10-dryserver.conf").Content
	for _, want := range []string{"PasswordAuthentication no", "PermitRootLogin no", "AllowUsers admin\n"} {
		if !strings.Contains(sshd, want) {
			t.Errorf("sshd missing %q", want)
		}
	}
	if !strings.Contains(find(t, coord, "/etc/ssh/sshd_config.d/10-dryserver.conf").Content, "AllowUsers admin dryreg") {
		t.Error("coordinator must allow the registry user")
	}

	sw := find(t, node, "/etc/systemd/network/10-switch.network").Content
	if !strings.Contains(sw, "Address=172.16.66.5/24") || !strings.Contains(sw, "MACAddress=52:54:66:aa:bb:cc") {
		t.Errorf("approved node needs its switch address on the switch port:\n%s", sw)
	}
	if strings.Contains(find(t, node, "/etc/systemd/network/20-wired.network").Content, "Address=") {
		t.Error("other Ethernet ports must not get the switch address")
	}
	if has(fresh, "/etc/systemd/network/10-switch.network") {
		t.Error("unapproved node must not guess a switch address")
	}
	if has(coord, "/etc/systemd/network/10-switch.network") {
		t.Error("lan transport must not configure a switch port")
	}

	cfg := find(t, node, "/etc/dryserver/config.env")
	if cfg.Mode != 0o600 || strings.Contains(cfg.Content, "correct horse") {
		t.Error("node config must be private and must not keep the WiFi password")
	}
	iwd := find(t, node, "/var/lib/iwd/=486f6d65204e657421.psk")
	if iwd.Mode != 0o600 || !strings.Contains(iwd.Content, "Passphrase=correct horse") {
		t.Errorf("iwd file wrong: %+v", iwd)
	}
	if find(t, node, "/etc/sudoers.d/10-wheel").Mode != 0o440 {
		t.Error("sudoers drop-in must be 0440")
	}

	if !strings.Contains(find(t, node, "/etc/docker/daemon.json").Content, `"ip": "127.0.0.1"`) {
		t.Error("docker must publish ports on localhost by default")
	}
	if has(coord, "/etc/docker/daemon.json") {
		t.Error("no docker bundle, no daemon.json")
	}
}

func TestHostAddr(t *testing.T) {
	for _, tc := range []struct {
		cidr string
		n    int
		want string
	}{
		{"10.66.0.0/24", 1, "10.66.0.1/24"},
		{"172.16.66.0/24", 254, "172.16.66.254/24"},
		{"10.66.0.0/23", 300, "10.66.1.44/23"},
	} {
		got, err := HostAddr(tc.cidr, tc.n)
		if err != nil || got != tc.want {
			t.Errorf("HostAddr(%s, %d) = %s, %v; want %s", tc.cidr, tc.n, got, err, tc.want)
		}
	}
	for _, n := range []int{0, 255, -1} {
		if _, err := HostAddr("10.66.0.0/24", n); err == nil {
			t.Errorf("host %d accepted in /24", n)
		}
	}
}
