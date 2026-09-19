package tui

import (
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/DryBearr/dryserver/internal/registry"
)

func wgKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func approveStep(a Approve, msgs ...tea.Msg) Approve {
	for _, msg := range msgs {
		next, cmd := a.Update(msg)
		a = next.(Approve)
		if cmd != nil {
			if m, ok := cmd().(stateMsg); ok {
				next, _ = a.Update(m)
				a = next.(Approve)
			}
		}
	}
	return a
}

func TestApproveScreen(t *testing.T) {
	store := registry.Store{Path: filepath.Join(t.TempDir(), "registry.json")}
	now := time.Now()
	store.Update(func(s *registry.State) error {
		s.Members = []registry.Member{{Host: 1, Name: "coord", LanIP: "192.168.1.50", Switch: true, LastSeen: now}}
		for _, n := range []string{"node-a", "node-b"} {
			if _, err := s.AddRequest(registry.Request{Name: n, WGKey: wgKey(), SSHHostKey: "ssh-ed25519 AAAAnode", LanIP: "192.168.1.23"}, "ssh-ed25519 AAAAcoord", now); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	})
	a := NewApprove(store, "10.66.0.0/24", 254)
	a = approveStep(a, a.load())
	v := a.View()
	if !strings.Contains(v, "node-a") || !strings.Contains(v, "code ") || !strings.Contains(v, "coord") {
		t.Fatalf("view:\n%s", v)
	}

	a = approveStep(a, press("a"))
	if !strings.Contains(a.notice, "node-a approved as 10.66.0.2") {
		t.Fatalf("notice %q", a.notice)
	}
	a = approveStep(a, press("r"))
	if !strings.Contains(a.notice, "node-b rejected") {
		t.Fatalf("notice %q", a.notice)
	}
	st, _ := store.Read()
	if len(st.Members) != 2 || len(st.Pending()) != 0 {
		t.Fatalf("state: %+v", st)
	}

	// Remove needs confirmation; the coordinator cannot be removed.
	a = approveStep(a, press("d"))
	if !strings.Contains(a.notice, "cannot be removed") {
		t.Errorf("coordinator remove: %q", a.notice)
	}
	a = approveStep(a, tea.KeyMsg{Type: tea.KeyDown}, press("d"))
	if a.confirm != "node-a" {
		t.Fatalf("confirm = %q", a.confirm)
	}
	a = approveStep(a, press("y"))
	if st, _ := store.Read(); len(st.Members) != 1 {
		t.Errorf("node-a not removed: %+v", st.Members)
	}
}
