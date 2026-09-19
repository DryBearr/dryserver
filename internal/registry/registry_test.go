package registry

import (
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const coordKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIcoordinatorkey root@coord"

var t0 = time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)

func wgKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func req(name string) Request {
	return Request{Name: name, WGKey: wgKey(), SSHHostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInodekey root@" + name, LanIP: "192.168.1.23"}
}

func TestPairingCode(t *testing.T) {
	k := wgKey()
	a := PairingCode(k, "ssh-ed25519 AAAAnode root@x", coordKey)
	if len(a) != 7 || a[3] != ' ' {
		t.Fatalf("code format %q", a)
	}
	if b := PairingCode(k, "ssh-ed25519 AAAAnode other-comment", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIcoordinatorkey"); a != b {
		t.Error("key comments must not change the code")
	}
	if PairingCode(k, "ssh-ed25519 AAAAnode root@x", "ssh-ed25519 AAAAfakecoordinator") == a {
		t.Error("a different coordinator key must change the code")
	}
	if PairingCode(wgKey(), "ssh-ed25519 AAAAnode root@x", coordKey) == a {
		t.Error("a different node key must change the code")
	}
}

func TestValidateRequest(t *testing.T) {
	good := req("node-1")
	if err := ValidateRequest(good); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Request){
		"hostname injection": func(r *Request) { r.Name = "x; rm -rf /" },
		"short wg key":       func(r *Request) { r.WGKey = "AAAA" },
		"ssh key newline":    func(r *Request) { r.SSHHostKey += "\ncommand=\"sh\" ssh-ed25519 AAAA" },
		"ssh key options":    func(r *Request) { r.SSHHostKey = `command="sh" ` + r.SSHHostKey },
		"ipv6 lan":           func(r *Request) { r.LanIP = "fe80::1" },
	} {
		r := good
		change(&r)
		if ValidateRequest(r) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestApproveFlow(t *testing.T) {
	var s State
	s.Members = []Member{{Host: 1, Name: "coord", WGKey: wgKey()}}

	r := req("node-a")
	id, err := s.AddRequest(r, coordKey, t0)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Pending(); len(got) != 1 || got[0].Code != PairingCode(r.WGKey, r.SSHHostKey, coordKey) {
		t.Fatalf("pending = %+v", got)
	}
	m, err := s.Approve(id, 254, t0)
	if err != nil || m.Host != 2 {
		t.Fatalf("approve: %+v %v", m, err)
	}
	if st, _ := s.RequestStatus(id, t0); st.Status != Approved || st.Host != 2 {
		t.Errorf("status = %+v", st)
	}
	if _, err := s.Approve(id, 254, t0); err == nil {
		t.Error("double approve")
	}

	// Same name again is refused; after removal the host number is reused.
	if _, err := s.AddRequest(req("node-a"), coordKey, t0); err == nil {
		t.Error("duplicate member name accepted")
	}
	if err := s.Remove("node-a"); err != nil {
		t.Fatal(err)
	}
	id2, _ := s.AddRequest(req("node-b"), coordKey, t0)
	if m, _ := s.Approve(id2, 254, t0); m.Host != 2 {
		t.Errorf("freed host number not reused: %d", m.Host)
	}
	if s.Remove("coord") == nil {
		t.Error("coordinator removed")
	}
}

func TestRejectAndExpiry(t *testing.T) {
	var s State
	id, _ := s.AddRequest(req("node-x"), coordKey, t0)
	if err := s.Reject(id); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.RequestStatus(id, t0); st.Status != Rejected {
		t.Errorf("status %s", st.Status)
	}
	if _, err := s.RequestStatus(id, t0.Add(2*time.Hour)); err == nil {
		t.Error("request did not expire")
	}
}

func TestPendingLimit(t *testing.T) {
	var s State
	for i := range MaxPending {
		if _, err := s.AddRequest(req("n"+strings.Repeat("x", i+1)), coordKey, t0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.AddRequest(req("one-more"), coordKey, t0); err == nil {
		t.Error("pending limit not enforced")
	}
}

func TestSubnetFull(t *testing.T) {
	var s State
	s.Members = []Member{{Host: 1, Name: "coord"}}
	// maxHost 2: room for the coordinator and one node.
	id, _ := s.AddRequest(req("a"), coordKey, t0)
	if _, err := s.Approve(id, 2, t0); err != nil {
		t.Fatal(err)
	}
	id, _ = s.AddRequest(req("b"), coordKey, t0)
	if _, err := s.Approve(id, 2, t0); err == nil {
		t.Error("full subnet not detected")
	}
}

func TestHeartbeat(t *testing.T) {
	var s State
	s.Members = []Member{{Host: 1, Name: "coord"}, {Host: 2, Name: "a", LanIP: "192.168.1.5"}}
	if err := s.Heartbeat(2, "192.168.1.77", true, t0); err != nil {
		t.Fatal(err)
	}
	if m := s.Members[1]; m.LanIP != "192.168.1.77" || !m.Switch || !m.LastSeen.Equal(t0) {
		t.Errorf("member = %+v", m)
	}
	if s.Heartbeat(9, "1.2.3.4", false, t0) == nil {
		t.Error("unknown host accepted")
	}
}

func TestStoreConcurrent(t *testing.T) {
	st := Store{Path: filepath.Join(t.TempDir(), "registry.json")}
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := st.Update(func(s *State) error {
				_, err := s.AddRequest(req("node-"+string(rune('a'+i))), coordKey, time.Now())
				return err
			})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	s, err := st.Read()
	if err != nil || len(s.Requests) != 10 {
		t.Fatalf("requests = %d, %v (lost updates?)", len(s.Requests), err)
	}
}

func TestScanReport(t *testing.T) {
	out := "192.168.1.1\tAA:BB:CC:00:00:01\tTP-LINK\n" +
		"192.168.1.23\t52:54:00:12:34:56\tQEMU\n" +
		"192.168.1.23\t52:54:00:12:34:56\tQEMU (DUP: 2)\n" +
		"junk line\n" +
		"172.16.66.2\t52:54:00:aa:bb:cc\n"
	found := ParseArpScan(out)
	if len(found) != 3 || found[0].MAC != "aa:bb:cc:00:00:01" || found[0].Vendor != "TP-LINK" {
		t.Fatalf("found = %+v", found)
	}
	unknown := Unknown(found, []string{"192.168.1.23", "172.16.66.2"}, t0)
	if len(unknown) != 1 || unknown[0].IP != "192.168.1.1" || !unknown[0].Seen.Equal(t0) {
		t.Fatalf("unknown = %+v", unknown)
	}
}

func TestRequestRetryIsIdempotent(t *testing.T) {
	var s State
	r := req("node-a")
	id1, err := s.AddRequest(r, coordKey, t0)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := s.AddRequest(r, coordKey, t0)
	if err != nil || id2 != id1 || len(s.Requests) != 1 {
		t.Fatalf("retry made a new request: %s %s %v", id1, id2, err)
	}
	if _, err := s.AddRequest(req("node-a"), coordKey, t0); err == nil {
		t.Error("a different machine with the same name was accepted while one is pending")
	}
}

func TestApproveSettlesDuplicates(t *testing.T) {
	var s State
	r := req("node-a")
	// Two pending requests from the same machine (made before retries were
	// deduplicated), and an impostor asking under the same name.
	s.Requests = []Request{
		{ID: "a1", Name: r.Name, WGKey: r.WGKey, SSHHostKey: r.SSHHostKey, LanIP: r.LanIP, Status: Pending, Created: t0},
		{ID: "a2", Name: r.Name, WGKey: r.WGKey, SSHHostKey: r.SSHHostKey, LanIP: r.LanIP, Status: Pending, Created: t0},
		{ID: "x", Name: r.Name, WGKey: wgKey(), SSHHostKey: r.SSHHostKey, LanIP: r.LanIP, Status: Pending, Created: t0},
	}
	if _, err := s.Approve("a1", 254, t0); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.RequestStatus("a2", t0); st.Status != Approved || st.Host != 2 {
		t.Errorf("duplicate from the same machine: %+v", st)
	}
	if st, _ := s.RequestStatus("x", t0); st.Status != Rejected {
		t.Errorf("impostor: %+v", st)
	}
	if len(s.Pending()) != 0 {
		t.Error("requests left pending")
	}
}
