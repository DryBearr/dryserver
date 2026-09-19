package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/DryBearr/dryserver/internal/config"
)

func testPaths(t *testing.T) Paths {
	dir := t.TempDir()
	return Paths{
		Config:  filepath.Join(dir, "config.env"),
		OutDir:  filepath.Join(dir, "out"),
		Secrets: filepath.Join(dir, "secrets"),
	}
}

func step(a App, msgs ...tea.Msg) App {
	for _, msg := range msgs {
		next, cmd := a.Update(msg)
		a = next.(App)
		// Follow backMsg so tests see the menu the user would land on.
		if cmd != nil {
			if b, ok := cmd().(backMsg); ok {
				next, _ = a.Update(b)
				a = next.(App)
			}
		}
	}
	return a
}

func TestMenuGuards(t *testing.T) {
	a := NewApp(testPaths(t))
	if !strings.Contains(a.View(), "not created yet") {
		t.Error("missing config not shown")
	}

	a = step(a, press("2"))
	if a.screen != menuScreen || !strings.Contains(a.notice, "config first") {
		t.Fatalf("build allowed without config: screen=%v notice=%q", a.screen, a.notice)
	}
	a = step(a, press("3"))
	if a.screen != menuScreen || !strings.Contains(a.notice, "ISO first") {
		t.Fatalf("flash allowed without ISO: screen=%v notice=%q", a.screen, a.notice)
	}
}

func TestFlashNeedsRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	p := testPaths(t)
	os.MkdirAll(p.OutDir, 0o755)
	os.WriteFile(filepath.Join(p.OutDir, "dryserver.iso"), []byte("iso"), 0o644)
	a := step(NewApp(p), press("3"))
	if a.screen != menuScreen || !strings.Contains(a.notice, "needs root") {
		t.Fatalf("screen=%v notice=%q", a.screen, a.notice)
	}
}

func TestConfigFormCancel(t *testing.T) {
	p := testPaths(t)
	a := step(NewApp(p), press("1"))
	if a.screen != configScreen {
		t.Fatalf("screen=%v", a.screen)
	}
	a = step(a, tea.KeyMsg{Type: tea.KeyEsc})
	if a.screen != menuScreen || a.notice != "Config not changed." {
		t.Fatalf("screen=%v notice=%q", a.screen, a.notice)
	}
	if _, err := os.Stat(p.Config); !os.IsNotExist(err) {
		t.Error("cancel must not write config")
	}
}

func TestValidConfigShown(t *testing.T) {
	p := testPaths(t)
	c := config.Default()
	c.CoordLanIP = "192.168.1.50"
	c.AdminSSHPubkey = "ssh-ed25519 AAAA me@pc"
	c.WifiSSID, c.WifiPass = "home", "password123"
	if err := c.Save(p.Config); err != nil {
		t.Fatal(err)
	}
	v := NewApp(p).View()
	for _, want := range []string{"ok", "coordinator 192.168.1.50", "WiFi home", "not built"} {
		if !strings.Contains(v, want) {
			t.Errorf("menu missing %q:\n%s", want, v)
		}
	}
}

func TestLineWriter(t *testing.T) {
	var got []string
	w := &lineWriter{emit: func(s string) { got = append(got, s) }}
	w.Write([]byte("one\ntw"))
	w.Write([]byte("o\r\n 50%\r100%\nlast"))
	w.Flush()
	want := []string{"one", "two", "50%", "100%", "last"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q, want %q", got, want)
	}
}
