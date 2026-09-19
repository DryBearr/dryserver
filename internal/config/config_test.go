package config

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func valid() Config {
	c := Default()
	c.WifiSSID = "home"
	c.WifiPass = `it's "tricky" $HOME`
	c.CoordLanIP = "192.168.1.50"
	c.AdminSSHPubkey = "ssh-ed25519 AAAAC3Nza"
	return c
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.env")
	want := valid()
	if err := want.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("round trip:\n got %+v\nwant %+v", got, want)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600 (file holds WiFi password)", st.Mode().Perm())
	}
}

// Node scripts source config.env with bash, so quoting must survive that.
func TestShellSourcing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.env")
	c := valid()
	c.Save(path)
	out, err := exec.Command("bash", "-c", `. "$1" && printf %s "$WIFI_PASS"`, "_", path).Output()
	if err != nil {
		t.Skip("bash not available:", err)
	}
	if string(out) != c.WifiPass {
		t.Fatalf("bash sees %q, want %q", out, c.WifiPass)
	}
}

func TestLoadExample(t *testing.T) {
	c, err := Load("../../config.example.env")
	if err != nil {
		t.Fatal(err)
	}
	if c.AdminSSHPubkey != "ssh-ed25519 AAAA..." || c.AdminKeyLabel != "desktop" || c.WGPort != "51820" {
		t.Fatalf("parsed %+v", c)
	}
}

func TestLoadMissing(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "nope.env"))
	if !os.IsNotExist(err) {
		t.Fatalf("err = %v, want not-exist", err)
	}
	if c != Default() {
		t.Fatal("missing file must give defaults")
	}
}

func TestValidate(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatal(err)
	}
	bad := valid()
	bad.CoordLanIP = "300.1.1.1"
	bad.WGSubnet = "10.66.0.5/24"
	bad.Username = "root"
	bad.WifiPass = "short"
	err := bad.Validate()
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{"coordinator IP", "mesh subnet", "username", "WiFi password"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
	open := valid()
	open.WifiPass = ""
	if err := open.Validate(); err != nil {
		t.Errorf("open network rejected: %v", err)
	}
}

func TestTransportValidation(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Config)
		want   string // substring of the error, "" = valid
	}{
		{"defaults", func(c *Config) {}, ""},
		{"lan ignores switch subnet", func(c *Config) { c.WGTransport = TransportLAN; c.SwitchSubnet = "junk" }, ""},
		{"bad transport", func(c *Config) { c.WGTransport = "carrier-pigeon" }, "WireGuard transport"},
		{"switch overlaps mesh", func(c *Config) { c.SwitchSubnet = "10.66.0.0/25" }, "overlaps the mesh subnet"},
		{"switch size differs", func(c *Config) { c.SwitchSubnet = "172.16.66.0/25" }, "same size"},
		{"switch holds coordinator", func(c *Config) { c.SwitchSubnet = "192.168.1.0/24" }, "switch subnet: contains the coordinator"},
		{"mesh holds coordinator", func(c *Config) { c.CoordLanIP = "10.66.0.9" }, "mesh subnet: contains the coordinator"},
	}
	for _, tc := range cases {
		c := valid()
		tc.change(&c)
		err := c.Validate()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: unexpected error %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: error %v, want %q", tc.name, err, tc.want)
		}
	}
}

// Configs saved before WG_TRANSPORT existed load with the defaults.
func TestLoadOldConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.env")
	os.WriteFile(path, []byte("COORD_LAN_IP='192.168.1.50'\n"), 0o600)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.WGTransport != TransportAuto || c.SwitchSubnet != "172.16.66.0/24" {
		t.Fatalf("got %+v", c)
	}
}

func TestToolsValidation(t *testing.T) {
	c := valid()
	if got := c.ToolList(); len(got) != 5 {
		t.Fatalf("default tools = %v, want all 5 bundles", got)
	}
	c.Tools = "docker basic"
	c.ExtraPackages = "python node;rm"
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), `unknown tool "basic"`) || !strings.Contains(err.Error(), `"node;rm" is not a valid package name`) {
		t.Fatalf("err = %v", err)
	}
	c.Tools, c.ExtraPackages = "", ""
	if err := c.Validate(); err != nil {
		t.Fatalf("no tools must be valid: %v", err)
	}
}

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts("8080/tcp 53/udp 9000")
	if err != nil {
		t.Fatal(err)
	}
	want := []Port{{8080, "tcp"}, {53, "udp"}, {9000, "tcp"}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v", got)
	}
	for _, bad := range []string{"0/tcp", "70000", "80/sctp", "http"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// The comment after a pasted key (often an email) never reaches the file.
func TestPubkeyCommentDropped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.env")
	c := valid()
	c.AdminSSHPubkey = "ssh-ed25519 AAAAC3NzaKEY someone@example.com"
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), "example.com") {
		t.Fatalf("email saved:\n%s", b)
	}
	os.WriteFile(path, []byte("ADMIN_SSH_PUBKEY='ssh-ed25519 AAAAC3NzaKEY old@example.com'\n"), 0o600)
	got, _ := Load(path)
	if got.AdminSSHPubkey != "ssh-ed25519 AAAAC3NzaKEY" {
		t.Errorf("loaded %q", got.AdminSSHPubkey)
	}
	for _, bad := range []string{"me@example.com", "two words", strings.Repeat("x", 33)} {
		if ValidKeyLabel(bad) == nil {
			t.Errorf("label %q accepted", bad)
		}
	}
}
