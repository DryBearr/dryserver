package tui

import (
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/DryBearr/dryserver/internal/config"
	"github.com/DryBearr/dryserver/internal/install"
	"github.com/DryBearr/dryserver/internal/sysconf"
)

func demoSetup(t *testing.T, role sysconf.Role, enc install.Encryption) (Setup, *install.Demo) {
	t.Helper()
	d := install.NewDemo()
	d.Delay = 0
	cfg := config.Default()
	cfg.CoordLanIP = "192.168.1.50"
	s := NewSetup(d, cfg)
	m, _ := d.Probe(t.Context())
	s = stepSetup(s, probeMsg{m: m})
	s.ch = &install.Choices{
		Role: role, Hostname: "node-test", SystemDisk: "/dev/nvme0n1",
		Encryption: enc, DiskPassphrase: "a long passphrase", UserPassword: "longpassword",
	}
	return s, d
}

func stepSetup(s Setup, msgs ...tea.Msg) Setup {
	for _, msg := range msgs {
		next, _ := s.Update(msg)
		s = next.(Setup)
	}
	return s
}

// drain feeds background events into the model until it stops waiting.
func drain(t *testing.T, s Setup) Setup {
	t.Helper()
	for s.state == suInstall || s.state == suJoin {
		s = stepSetup(s, <-s.events)
	}
	return s
}

func typeText(s string) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)} }

func TestWelcomeShowsMachine(t *testing.T) {
	s, _ := demoSetup(t, sysconf.Node, install.EncTPM)
	v := s.View()
	for _, want := range []string{"TPM 2.0   yes", "UEFI", "nvme0n1", "has: vfat, Windows", "WiFi Home"} {
		if !strings.Contains(v, want) {
			t.Errorf("welcome missing %q:\n%s", want, v)
		}
	}
}

func TestEncryptionOptions(t *testing.T) {
	if got := (install.Machine{UEFI: true, TPM2: true}).EncryptionOptions(); got[0] != install.EncTPM {
		t.Errorf("TPM machine should default to TPM, got %v", got)
	}
	for _, m := range []install.Machine{{UEFI: true}, {TPM2: true}} {
		for _, e := range m.EncryptionOptions() {
			if e == install.EncTPM {
				t.Errorf("%+v must not offer TPM unlock", m)
			}
		}
	}
}

func TestCheckShowsStepsAndLogs(t *testing.T) {
	s, _ := demoSetup(t, sysconf.Node, install.EncTPM)
	next, _ := s.startCheck()
	s = next.(Setup)
	for s.state == suCheck {
		s = stepSetup(s, <-s.events)
	}
	if s.state != suConfirm {
		t.Fatalf("state=%v err=%v", s.state, s.checkErr)
	}
	if len(s.steps) != 0 || len(s.lines) != 0 {
		t.Error("check log must be cleared before the install screen")
	}
}

func TestCheckFailureOffersRetry(t *testing.T) {
	s, _ := demoSetup(t, sysconf.Node, install.EncTPM)
	s.state = suCheck
	s = stepSetup(s, stepMsg{Name: "Update package lists"}, stepMsg{Log: "error: failed retrieving file"})
	s = stepSetup(s, checkMsg{err: errors.New("cannot reach the package mirrors")})
	v := s.View()
	for _, want := range []string{"Update package lists", "failed retrieving file", "cannot reach the package mirrors", "r retry"} {
		if !strings.Contains(v, want) {
			t.Errorf("check screen missing %q:\n%s", want, v)
		}
	}
	s = stepSetup(s, tea.KeyMsg{Type: tea.KeyEnter})
	if s.state != suForm || !strings.Contains(s.notice, "cannot reach") {
		t.Fatalf("enter must go back to the answers: state=%v notice=%q", s.state, s.notice)
	}
}

func TestConfirmNeedsYES(t *testing.T) {
	s, _ := demoSetup(t, sysconf.Node, install.EncTPM)
	s = stepSetup(s, checkMsg{})
	if s.state != suConfirm || !strings.Contains(s.View(), "THESE DISKS WILL BE ERASED") {
		t.Fatalf("state=%v", s.state)
	}
	s = stepSetup(s, typeText("yes"), tea.KeyMsg{Type: tea.KeyEnter})
	if s.state != suConfirm || s.notice == "" {
		t.Fatal("lowercase yes must not start the install")
	}
	s.confirm.SetValue("")
	s = stepSetup(s, typeText("YES"), tea.KeyMsg{Type: tea.KeyEnter})
	if s.state != suInstall {
		t.Fatalf("YES must start install, state=%v", s.state)
	}
	s.cancel()
}

func TestNodeInstallAndJoin(t *testing.T) {
	s, _ := demoSetup(t, sysconf.Node, install.EncTPM)
	next, _ := s.startInstall()
	s = drain(t, next.(Setup))
	if s.state != suDone || s.hostNum != 7 || s.code != "482 913" {
		t.Fatalf("state=%v host=%d code=%q err=%v", s.state, s.hostNum, s.code, s.err)
	}
	for _, st := range s.steps {
		if !st.done {
			t.Errorf("step %s not done", st.name)
		}
	}
	if !strings.Contains(s.View(), "passphrase once") {
		t.Errorf("TPM mode must tell about the first-boot passphrase:\n%s", s.View())
	}
	if !strings.Contains(s.View(), "Mesh address: 10.66.0.7") {
		t.Errorf("done screen:\n%s", s.View())
	}
}

func TestCoordinatorSkipsJoin(t *testing.T) {
	s, _ := demoSetup(t, sysconf.Coordinator, install.EncPassphrase)
	next, _ := s.startInstall()
	s = drain(t, next.(Setup))
	if s.state != suDone || s.code != "" {
		t.Fatalf("state=%v code=%q", s.state, s.code)
	}
	if strings.Contains(s.View(), "passphrase once") {
		t.Error("passphrase mode has no first-boot TPM step")
	}
	if !strings.Contains(s.View(), "sudo dryserver approve") {
		t.Error("coordinator done screen must explain approving")
	}
}

func TestJoinRejected(t *testing.T) {
	s, d := demoSetup(t, sysconf.Node, install.EncNone)
	d.Approve = func() (int, error) { return 0, install.ErrRejected }
	next, _ := s.startInstall()
	s = drain(t, next.(Setup))
	if s.state != suFailed || !strings.Contains(s.View(), "rejected") {
		t.Fatalf("state=%v view:\n%s", s.state, s.View())
	}
}

func TestValidators(t *testing.T) {
	for _, h := range []string{"", "node-1", "coord", "a"} {
		if err := install.ValidHostname(h); err != nil {
			t.Errorf("%q rejected: %v", h, err)
		}
	}
	for _, h := range []string{"Node", "-x", "x-", "a_b", "node.lan"} {
		if install.ValidHostname(h) == nil {
			t.Errorf("%q accepted", h)
		}
	}
	if install.ValidDiskPassphrase("short") == nil || install.ValidUserPassword("short") == nil {
		t.Error("short secrets accepted")
	}
	if h := install.DefaultHostname(sysconf.Node); !strings.HasPrefix(h, "node-") || len(h) != 9 {
		t.Errorf("default hostname %q", h)
	}
}
