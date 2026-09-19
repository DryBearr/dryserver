package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/DryBearr/dryserver/internal/disks"
)

func press(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func send(t *testing.T, m Flash, msgs ...tea.Msg) Flash {
	t.Helper()
	for _, msg := range msgs {
		next, _ := m.Update(msg)
		m = next.(Flash)
	}
	return m
}

func TestSelectAndConfirm(t *testing.T) {
	small := disks.Disk{Name: "sdb", Path: "/dev/sdb", Size: 1 << 20, Tran: "usb"}
	big := disks.Disk{Name: "sdc", Path: "/dev/sdc", Size: 32 << 30, Tran: "usb", Model: "Stick"}
	m := send(t, NewFlash("x.iso", 1<<30), disksMsg{list: []disks.Disk{small, big}})

	m = send(t, m, press("enter"))
	if m.state != selecting || !strings.Contains(m.notice, "too small") {
		t.Fatalf("small disk accepted: state=%v notice=%q", m.state, m.notice)
	}

	m = send(t, m, press("down"), press("enter"))
	if m.state != confirming || m.target.Path != "/dev/sdc" {
		t.Fatalf("state=%v target=%s", m.state, m.target.Path)
	}
	if !strings.Contains(m.View(), "ALL DATA ON THIS DRIVE WILL BE DESTROYED") {
		t.Error("confirm screen missing warning")
	}

	m = send(t, m, press("sdb"), press("enter"))
	if m.state != confirming || m.notice == "" {
		t.Fatal("wrong device name must not start flashing")
	}

	m = send(t, m, press("esc"))
	if m.state != selecting {
		t.Fatalf("esc: state=%v", m.state)
	}
}

func TestEmptyList(t *testing.T) {
	m := send(t, NewFlash("x.iso", 1), disksMsg{}, press("enter"))
	if m.state != selecting {
		t.Fatal("enter with no disks must do nothing")
	}
	if !strings.Contains(m.View(), "No USB drives found") {
		t.Error("missing empty-list hint")
	}
}
