package node

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DryBearr/dryserver/internal/config"
	"github.com/DryBearr/dryserver/internal/mesh"
	"github.com/DryBearr/dryserver/internal/packages"
	"github.com/DryBearr/dryserver/internal/registry"
	"github.com/DryBearr/dryserver/internal/runner"
	"github.com/DryBearr/dryserver/internal/sysconf"
)

const (
	coordKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIcoord"
	nodeKey  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInode root@node-a"
	wgPub    = "bm9kZS1hLXB1YmxpYy1rZXktMzItYnl0ZXMtbG9uZyE="
)

// fakeCoord answers registry commands like the coordinator would, and
// records the host key the way ssh accept-new does.
type fakeCoord struct {
	root     string
	statuses []registry.StatusReply
	calls    []string
}

func (f *fakeCoord) Run(ctx context.Context, c runner.Cmd) (string, error) {
	cmd := c.Args[len(c.Args)-1]
	host := c.Args[len(c.Args)-2]
	f.calls = append(f.calls, host+" "+cmd)
	kh := filepath.Join(f.root, KnownHosts)
	if _, err := os.Stat(kh); err != nil {
		os.WriteFile(kh, []byte(strings.TrimPrefix(host, "dryreg@")+" "+coordKey+"\n"), 0o600)
	}
	switch {
	case cmd == "request":
		var r registry.Request
		if err := json.Unmarshal([]byte(c.Stdin), &r); err != nil || r.Name != "node-a" {
			return "", errors.New("bad request")
		}
		return `{"id":"0123456789abcdef"}`, nil
	case strings.HasPrefix(cmd, "status "):
		r := f.statuses[0]
		if len(f.statuses) > 1 {
			f.statuses = f.statuses[1:]
		}
		b, _ := json.Marshal(r)
		return string(b), nil
	case cmd == "peers":
		return `{"members":[{"host":1,"name":"coord","wg_key":"C","lan_ip":"192.168.1.50"},{"host":2,"name":"node-a","wg_key":"A"}]}`, nil
	}
	return "", errors.New("unknown")
}

func setup(t *testing.T, statuses ...registry.StatusReply) (Node, *fakeCoord) {
	root := t.TempDir()
	for p, c := range map[string]string{WGPub: wgPub, HostKeyPub: nodeKey, "/etc/hosts": "127.0.0.1 localhost\n"} {
		os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755)
		os.WriteFile(filepath.Join(root, p), []byte(c+"\n"), 0o644)
	}
	os.MkdirAll(filepath.Join(root, "/etc/dryserver"), 0o700)
	cfg := config.Default()
	cfg.CoordLanIP = "192.168.1.50"
	cfg.AdminSSHPubkey = "ssh-ed25519 AAAA me@desktop"
	fc := &fakeCoord{root: root, statuses: statuses}
	return Node{Cfg: cfg, Hostname: "node-a", Root: root, Run: fc}, fc
}

func TestJoinFlow(t *testing.T) {
	coord := registry.Member{Host: 1, Name: "coord", WGKey: "COORDWG", LanIP: "192.168.1.50", Switch: true, SSHHostKey: coordKey}
	n, fc := setup(t,
		registry.StatusReply{Status: registry.Pending},
		registry.StatusReply{Status: registry.Approved, Host: 4, Coordinator: &coord})

	code, err := n.Request(t.Context(), "192.168.1.23", true)
	if err != nil {
		t.Fatal(err)
	}
	if code != registry.PairingCode(wgPub, nodeKey, coordKey) {
		t.Errorf("code %s does not match what the coordinator computes", code)
	}
	if n.LoadState().RequestID != "0123456789abcdef" {
		t.Error("request id not saved")
	}

	r, err := n.Wait(t.Context(), time.Millisecond)
	if err != nil || r.Host != 4 {
		t.Fatalf("wait: %+v %v", r, err)
	}
	plan, _ := packages.Resolve(nil, nil)
	params := sysconf.Params{Config: n.Cfg, Plan: plan, Hostname: "node-a", Role: sysconf.Node, SwitchMAC: "52:54:66:00:00:04"}
	if err := n.Activate(r, mesh.Self{Switch: true}, params); err != nil {
		t.Fatal(err)
	}
	read := func(p string) string { b, _ := os.ReadFile(filepath.Join(n.Root, p)); return string(b) }
	if !strings.Contains(read(WGConf), "Address = 10.66.0.4/24") || !strings.Contains(read(WGConf), "Endpoint = 172.16.66.1:51820") {
		t.Errorf("wg0.conf:\n%s", read(WGConf))
	}
	if !strings.Contains(read("/etc/systemd/network/10-switch.network"), "Address=172.16.66.4/24") {
		t.Error("switch address not set after approval")
	}
	if !strings.Contains(read(KnownHosts), "192.168.1.50,10.66.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIcoord") {
		t.Errorf("coordinator pin: %q", read(KnownHosts))
	}
	if !strings.Contains(read("/etc/hosts"), "10.66.0.1 coord") || n.LoadState().Host != 4 {
		t.Error("hosts/state not updated")
	}

	members, err := n.FetchMembers(t.Context(), Heartbeat{LanIP: "192.168.1.23"})
	if err != nil || len(members) != 2 {
		t.Fatalf("members %v %v", members, err)
	}
	if last := fc.calls[len(fc.calls)-1]; last != "dryreg@10.66.0.1 peers" {
		t.Errorf("sync must go over the mesh, went to %q", last)
	}
}

func TestRejected(t *testing.T) {
	n, _ := setup(t, registry.StatusReply{Status: registry.Rejected})
	if _, err := n.Request(t.Context(), "192.168.1.23", false); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Wait(t.Context(), time.Millisecond); !IsRejected(err) {
		t.Fatalf("err = %v", err)
	}
}

func TestSSHArgs(t *testing.T) {
	n, fc := setup(t, registry.StatusReply{Status: registry.Pending})
	var got runner.Cmd
	n.Run = recordRunner{fc, &got}
	n.Request(t.Context(), "192.168.1.23", false)
	args := strings.Join(got.Args, " ")
	for _, want := range []string{"BatchMode=yes", "StrictHostKeyChecking=accept-new", "HostKeyAlgorithms=ssh-ed25519", "GlobalKnownHostsFile=/dev/null", "LogLevel=ERROR", "dryreg@192.168.1.50 request"} {
		if !strings.Contains(args, want) {
			t.Errorf("ssh args missing %q: %s", want, args)
		}
	}
}

type recordRunner struct {
	inner runner.Runner
	last  *runner.Cmd
}

func (r recordRunner) Run(ctx context.Context, c runner.Cmd) (string, error) {
	*r.last = c
	return r.inner.Run(ctx, c)
}

func TestWithPrivateKey(t *testing.T) {
	got := WithPrivateKey("[Interface]\nListenPort = 51820\n\n[Peer]\nPublicKey = X\n", "SECRET=\n")
	if !strings.HasPrefix(got, "[Interface]\nPrivateKey = SECRET=\nListenPort = 51820\n") || strings.Count(got, "PrivateKey") != 1 {
		t.Fatalf("got %q", got)
	}
}

// syncRunner fakes systemctl/wg-quick/wg and captures what syncconf gets.
type syncRunner struct {
	fakeCoord
	applied string
}

func (s *syncRunner) Run(ctx context.Context, c runner.Cmd) (string, error) {
	switch c.Name {
	case "systemctl", "ping", "ip":
		return "", nil
	case "wg-quick":
		return "[Interface]\nListenPort = 51820\n", nil
	case "wg":
		b, _ := os.ReadFile(c.Args[2])
		s.applied = string(b)
		return "", nil
	}
	return s.fakeCoord.Run(ctx, c)
}

func TestSyncKeepsPrivateKey(t *testing.T) {
	n, _ := setup(t)
	n.SaveState(State{Host: 2})
	os.WriteFile(filepath.Join(n.Root, WGKey), []byte("PRIVKEY=\n"), 0o600)
	os.WriteFile(filepath.Join(n.Root, KnownHosts), []byte("192.168.1.50,10.66.0.1 "+coordKey+"\n"), 0o600)
	sr := &syncRunner{fakeCoord: fakeCoord{root: n.Root}}
	n.Run = sr
	n.TmpDir = t.TempDir()
	if err := Sync(t.Context(), n, false, registry.Store{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sr.applied, "PrivateKey = PRIVKEY=") {
		t.Fatalf("syncconf input lost the private key:\n%s", sr.applied)
	}
	if b, _ := os.ReadFile(filepath.Join(n.Root, WGConf)); strings.Contains(string(b), "PRIVKEY") {
		t.Error("wg0.conf must not hold the private key")
	}
}
