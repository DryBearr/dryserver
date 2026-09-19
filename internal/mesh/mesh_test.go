package mesh

import (
	"net"
	"strings"
	"testing"

	"github.com/DryBearr/dryserver/internal/config"
	"github.com/DryBearr/dryserver/internal/registry"
)

func cfg(transport string) config.Config {
	c := config.Default()
	c.CoordLanIP = "192.168.1.50"
	c.WGTransport = transport
	return c
}

var members = []registry.Member{
	{Host: 3, Name: "node-c", WGKey: "KEYC", LanIP: "192.168.1.30", Switch: false, SSHHostKey: "ssh-ed25519 AAAAc root@node-c"},
	{Host: 1, Name: "coord", WGKey: "KEYA", LanIP: "192.168.1.50", Switch: true, SSHHostKey: "ssh-ed25519 AAAAa root@coord"},
	{Host: 2, Name: "node-b", WGKey: "KEYB", LanIP: "192.168.1.20", Switch: true, SSHHostKey: "ssh-ed25519 AAAAb root@node-b"},
}

func TestEndpointChoice(t *testing.T) {
	auto := cfg(config.TransportAuto)
	self := Self{Host: 2, Switch: true}
	if got := Endpoint(auto, self, members[1]); got != "172.16.66.1:51820" {
		t.Errorf("both on switch: %s", got)
	}
	if got := Endpoint(auto, self, members[0]); got != "192.168.1.30:51820" {
		t.Errorf("peer without cable must use LAN: %s", got)
	}
	if got := Endpoint(auto, Self{Host: 2}, members[1]); got != "192.168.1.50:51820" {
		t.Errorf("self without cable must use LAN: %s", got)
	}
	if got := Endpoint(cfg(config.TransportLAN), self, members[1]); got != "192.168.1.50:51820" {
		t.Errorf("lan mode must use LAN: %s", got)
	}
}

func TestWGConfig(t *testing.T) {
	out := WGConfig(cfg(config.TransportAuto), Self{Host: 2, Switch: true}, members)
	for _, want := range []string{
		"Address = 10.66.0.2/24", "ListenPort = 51820", "private-key /etc/wireguard/wg0.key",
		"# coord\n[Peer]\nPublicKey = KEYA\nAllowedIPs = 10.66.0.1/32\nEndpoint = 172.16.66.1:51820",
		"AllowedIPs = 10.66.0.3/32\nEndpoint = 192.168.1.30:51820",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("wg0.conf missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "KEYB") || strings.Contains(out, "PrivateKey") {
		t.Error("must not list itself or hold the private key")
	}
	if strings.Index(out, "# coord") > strings.Index(out, "# node-c") {
		t.Error("peers not sorted by host")
	}
}

func TestHostsBlock(t *testing.T) {
	cur := "127.0.0.1 localhost\n# dryserver mesh begin\n10.66.0.9 old-node\n# dryserver mesh end\n192.168.1.5 printer\n"
	out := Hosts(cur, cfg(config.TransportLAN), members)
	if strings.Contains(out, "old-node") || !strings.Contains(out, "printer") || !strings.Contains(out, "10.66.0.3 node-c") {
		t.Errorf("hosts:\n%s", out)
	}
	if Hosts(out, cfg(config.TransportLAN), members) != out {
		t.Error("hosts rewrite must be stable")
	}
}

func TestKnownHostsAndSSHConfig(t *testing.T) {
	kh := KnownHosts(cfg(config.TransportLAN), members)
	if !strings.Contains(kh, "coord,10.66.0.1 ssh-ed25519 AAAAa\n") || strings.Contains(kh, "root@") {
		t.Errorf("known_hosts:\n%s", kh)
	}
	sc := SSHConfig(cfg(config.TransportLAN), members)
	if !strings.Contains(sc, "Host coord node-b node-c") || !strings.Contains(sc, "ForwardAgent yes") {
		t.Errorf("ssh_config:\n%s", sc)
	}
}

func TestHostOf(t *testing.T) {
	for ip, want := range map[string]int{"10.66.0.7": 7, "10.66.0.0": 0, "10.66.0.255": 0, "10.66.1.7": 0, "192.168.1.7": 0} {
		if got := HostOf("10.66.0.0/24", net.ParseIP(ip)); got != want {
			t.Errorf("HostOf(%s) = %d, want %d", ip, got, want)
		}
	}
	if IP("172.16.66.0/24", 5) != "172.16.66.5" {
		t.Error("IP")
	}
}

func TestDesktopExport(t *testing.T) {
	c := cfg(config.TransportLAN)
	hosts := Hosts("127.0.0.1 localhost\n", c, members)
	servers := ParseHostsBlock(hosts)
	if len(servers) != 3 || servers[0].Name != "coord" || servers[2].MeshIP != "10.66.0.3" {
		t.Fatalf("servers = %+v", servers)
	}
	conf := DesktopSSHConfig("admin", "coord", "192.168.1.50", "22", "~/.ssh/known_hosts.d/dryserver", servers)
	for _, want := range []string{
		"Host coord\n    HostName 192.168.1.50\n",
		"Host node-b\n    HostName 10.66.0.2\n    User admin\n    ProxyJump coord\n    ForwardAgent yes",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("config missing %q:\n%s", want, conf)
		}
	}
	kh := DesktopKnownHosts(KnownHosts(c, members), "coord", "192.168.1.50", "22")
	if !strings.Contains(kh, "coord,10.66.0.1,192.168.1.50 ssh-ed25519 AAAAa\n") || !strings.Contains(kh, "node-c,10.66.0.3 ssh-ed25519 AAAAc\n") {
		t.Errorf("known hosts:\n%s", kh)
	}
	if kh := DesktopKnownHosts(KnownHosts(c, members), "coord", "127.0.0.1", "2201"); !strings.Contains(kh, "coord,10.66.0.1,[127.0.0.1]:2201 ") {
		t.Errorf("non-22 port:\n%s", kh)
	}
}
