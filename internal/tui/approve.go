package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/DryBearr/dryserver/internal/mesh"
	"github.com/DryBearr/dryserver/internal/registry"
)

type approveTick struct{}

type stateMsg struct {
	st  registry.State
	err error
}

// Approve is the coordinator's screen for join requests and members.
type Approve struct {
	store   registry.Store
	subnet  string
	maxHost int
	now     func() time.Time

	st      registry.State
	err     error
	cursor  int
	confirm string // member name awaiting remove confirmation
	notice  string
}

func NewApprove(store registry.Store, subnet string, maxHost int) Approve {
	return Approve{store: store, subnet: subnet, maxHost: maxHost, now: time.Now}
}

func (a Approve) load() tea.Msg {
	st, err := a.store.Read()
	return stateMsg{st, err}
}

func (a Approve) Init() tea.Cmd {
	return tea.Batch(a.load, tea.Tick(2*time.Second, func(time.Time) tea.Msg { return approveTick{} }))
}

// items: pending requests first, then members.
func (a Approve) items() (pending []registry.Request, members []registry.Member) {
	return a.st.Pending(), a.st.Members
}

func (a Approve) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case stateMsg:
		a.st, a.err = msg.st, msg.err
		p, m := a.items()
		a.cursor = min(a.cursor, max(len(p)+len(m)-1, 0))
		return a, nil
	case approveTick:
		return a, a.Init()
	case tea.KeyMsg:
		return a.key(msg.String())
	}
	return a, nil
}

func (a Approve) key(k string) (tea.Model, tea.Cmd) {
	pending, members := a.items()
	n := len(pending) + len(members)
	if a.confirm != "" {
		name := a.confirm
		a.confirm = ""
		if k == "y" {
			err := a.store.Update(func(s *registry.State) error { return s.Remove(name) })
			a.notice = name + " removed; servers drop it within a minute."
			if err != nil {
				a.notice = "Remove failed: " + err.Error()
			}
			return a, a.load
		}
		a.notice = "Not removed."
		return a, nil
	}
	switch k {
	case "q", "esc", "ctrl+c":
		return a, tea.Quit
	case "up", "k":
		a.cursor = max(a.cursor-1, 0)
	case "down", "j":
		a.cursor = min(a.cursor+1, max(n-1, 0))
	case "a", "r":
		if a.cursor >= len(pending) {
			a.notice = "Select a waiting request first."
			return a, nil
		}
		req := pending[a.cursor]
		var err error
		if k == "a" {
			var m registry.Member
			err = a.store.Update(func(s *registry.State) (err error) {
				m, err = s.Approve(req.ID, a.maxHost, a.now())
				return err
			})
			a.notice = fmt.Sprintf("%s approved as %s.", req.Name, mesh.IP(a.subnet, m.Host))
		} else {
			err = a.store.Update(func(s *registry.State) error { return s.Reject(req.ID) })
			a.notice = req.Name + " rejected."
		}
		if err != nil {
			a.notice = "Failed: " + err.Error()
		}
		return a, a.load
	case "d":
		if a.cursor < len(pending) {
			return a, nil
		}
		m := members[a.cursor-len(pending)]
		if m.Host == 1 {
			a.notice = "The coordinator cannot be removed."
			return a, nil
		}
		a.confirm = m.Name
	}
	return a, nil
}

func ago(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := now.Sub(t).Round(time.Second)
	if d < time.Minute {
		return d.String() + " ago"
	}
	return d.Round(time.Minute).String() + " ago"
}

func (a Approve) View() string {
	var b strings.Builder
	now := a.now()
	b.WriteString(titleStyle.Render("dryserver · machines") + "\n\n")
	if a.err != nil {
		b.WriteString(errStyle.Render("Cannot read the registry: "+a.err.Error()) + "\n")
		return b.String()
	}
	pending, members := a.items()
	line := func(i int, text string) {
		if i == a.cursor {
			b.WriteString(selStyle.Render("> "+text) + "\n")
		} else {
			b.WriteString("  " + text + "\n")
		}
	}

	b.WriteString("Waiting to join:\n")
	if len(pending) == 0 {
		b.WriteString(dimStyle.Render("  none. New machines show up here after their setup finishes.") + "\n")
	}
	for i, r := range pending {
		line(i, fmt.Sprintf("%-14s %-15s code %s   %s", r.Name, r.LanIP, selStyle.Render(r.Code), dimStyle.Render(ago(r.Created, now))))
	}
	if len(pending) > 0 {
		b.WriteString(dimStyle.Render("  Approve only if the code matches the one on the new machine's screen.") + "\n")
	}

	b.WriteString("\nMembers:\n")
	for i, m := range members {
		link := "WiFi/router"
		if m.Switch {
			link = "switch"
		}
		line(len(pending)+i, fmt.Sprintf("%-14s %-12s LAN %-15s %-11s seen %s",
			m.Name, mesh.IP(a.subnet, m.Host), m.LanIP, link, ago(m.LastSeen, now)))
	}

	if len(a.st.Unknown) > 0 {
		fmt.Fprintf(&b, "\nUnknown devices on the network (scan %s):\n", ago(a.st.Scanned, now))
		for _, d := range a.st.Unknown {
			ssh := ""
			if d.SSH {
				ssh = "  SSH open"
			}
			b.WriteString(dimStyle.Render(fmt.Sprintf("  %-15s %s  %s%s", d.IP, d.MAC, d.Vendor, ssh)) + "\n")
		}
	}

	if a.confirm != "" {
		b.WriteString("\n" + errStyle.Render("Remove "+a.confirm+" from the mesh? y to confirm") + "\n")
	} else if a.notice != "" {
		b.WriteString("\n" + a.notice + "\n")
	}
	b.WriteString("\n" + dimStyle.Render("↑/↓ select · a approve · r reject · d remove member · q quit") + "\n")
	return b.String()
}
