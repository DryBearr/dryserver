package registry

import (
	"bytes"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

type fakeMesh map[string]int

func (m fakeMesh) HostOf(ip net.IP) int { return m[ip.String()] }

func call(t *testing.T, st Store, cmd, client, stdin string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := Serve(st, fakeMesh{"10.66.0.2": 2}, coordKey, cmd, client, strings.NewReader(stdin), &out, t0)
	return out.String(), err
}

func TestServeJoinFlow(t *testing.T) {
	st := Store{Path: filepath.Join(t.TempDir(), "registry.json")}
	st.Update(func(s *State) error {
		s.Members = []Member{{Host: 1, Name: "coord", WGKey: wgKey(), LanIP: "192.168.1.50"}}
		return nil
	})

	r := req("node-a")
	body, _ := json.Marshal(r)
	out, err := call(t, st, "request", "192.168.1.23 5000 22", string(body))
	if err != nil {
		t.Fatal(err)
	}
	var idReply struct{ ID string }
	json.Unmarshal([]byte(out), &idReply)
	if len(idReply.ID) != 16 || strings.Contains(out, "code") {
		t.Fatalf("request reply %q (must not reveal the code)", out)
	}

	out, _ = call(t, st, "status "+idReply.ID, "192.168.1.23 5000 22", "")
	if !strings.Contains(out, `"status":"pending"`) || strings.Contains(out, "coordinator") {
		t.Fatalf("pending status %q", out)
	}
	st.Update(func(s *State) error { _, err := s.Approve(idReply.ID, 254, t0); return err })
	out, _ = call(t, st, "status "+idReply.ID, "192.168.1.23 5000 22", "")
	var sr StatusReply
	json.Unmarshal([]byte(out), &sr)
	if sr.Status != Approved || sr.Host != 2 || sr.Coordinator == nil || sr.Coordinator.LanIP != "192.168.1.50" {
		t.Fatalf("approved status %q", out)
	}

	// peers: only from the member's mesh address.
	if _, err := call(t, st, "peers", "192.168.1.23 5000 22", `{"lan_ip":"192.168.1.23"}`); err == nil {
		t.Error("peers answered over the LAN")
	}
	if _, err := call(t, st, "peers", "10.66.0.9 5000 22", `{}`); err == nil {
		t.Error("peers answered to a non-member mesh address")
	}
	out, err = call(t, st, "peers", "10.66.0.2 5000 22", `{"lan_ip":"192.168.1.99","switch":true}`)
	if err != nil || !strings.Contains(out, "node-a") || !strings.Contains(out, "192.168.1.99") {
		t.Fatalf("peers %q %v", out, err)
	}
}

func TestServeRejectsJunk(t *testing.T) {
	st := Store{Path: filepath.Join(t.TempDir(), "registry.json")}
	for _, cmd := range []string{"", "sh", "status ../../etc/passwd", "status abc", "request extra", "approve 1234567890abcdef"} {
		if _, err := call(t, st, cmd, "192.168.1.23 1 22", "{}"); err == nil {
			t.Errorf("%q accepted", cmd)
		}
	}
	if _, err := call(t, st, "request", "192.168.1.23 1 22", strings.Repeat("x", 20000)); err == nil {
		t.Error("oversized input accepted")
	}
}
