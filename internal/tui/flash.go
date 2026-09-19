// Package tui holds the bubbletea screens.
package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/DryBearr/dryserver/internal/disks"
	"github.com/DryBearr/dryserver/internal/flash"
)

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	dimStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	selStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("10"))
	errStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	okStyle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("10"))
	warnBox     = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("9")).Padding(0, 1)
	refreshRate = 2 * time.Second
)

type state int

const (
	selecting state = iota
	confirming
	flashing
	finished
)

type disksMsg struct {
	list []disks.Disk
	err  error
}

type tickMsg struct{ gen int }

// tickGen tells apart the rescan loops of successive Flash screens, so a
// stale tick from a screen already left does not start a second loop.
var tickGen int

type progressMsg struct {
	phase       flash.Phase
	done, total int64
}

type flashDoneMsg struct{ err error }

// Flash is the USB selection, confirmation and write screen.
type Flash struct {
	iso     string
	isoSize int64

	state   state
	usb     []disks.Disk
	listErr error
	cursor  int
	notice  string

	target disks.Disk
	input  textinput.Model

	gen  int
	back tea.Cmd // nil when standalone: leaving quits the program

	bar      progress.Model
	phase    flash.Phase
	done     int64
	total    int64
	events   chan tea.Msg
	cancel   context.CancelFunc
	stopping bool
	err      error
}

func NewFlash(iso string, isoSize int64) Flash {
	in := textinput.New()
	in.CharLimit = 32
	in.Width = 20
	tickGen++
	return Flash{
		gen:     tickGen,
		iso:     iso,
		isoSize: isoSize,
		input:   in,
		bar:     progress.New(progress.WithDefaultGradient(), progress.WithoutPercentage()),
	}
}

// Embedded makes leaving the screen run back instead of quitting.
func (m Flash) Embedded(back tea.Cmd) Flash {
	m.back = back
	return m
}

func (m Flash) exit() tea.Cmd {
	if m.back != nil {
		return m.back
	}
	return tea.Quit
}

// Err returns the flash error after the program exits, nil on success.
func (m Flash) Err() error {
	if m.state != finished {
		return errors.New("aborted")
	}
	return m.err
}

func (m Flash) Init() tea.Cmd {
	return tea.Batch(listDisks, tick(m.gen))
}

func listDisks() tea.Msg {
	all, err := disks.List()
	return disksMsg{disks.USB(all), err}
}

func tick(gen int) tea.Cmd {
	return tea.Tick(refreshRate, func(time.Time) tea.Msg { return tickMsg{gen} })
}

func wait(ch chan tea.Msg) tea.Cmd {
	return func() tea.Msg { return <-ch }
}

func (m Flash) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.bar.Width = min(msg.Width-4, 60)
		return m, nil

	case disksMsg:
		m.usb, m.listErr = msg.list, msg.err
		m.cursor = min(m.cursor, max(len(m.usb)-1, 0))
		return m, nil

	case tickMsg:
		if msg.gen != m.gen {
			return m, nil
		}
		// Keep rescanning so a stick plugged in after start shows up.
		if m.state == selecting {
			return m, tea.Batch(listDisks, tick(m.gen))
		}
		return m, tick(m.gen)

	case progressMsg:
		m.phase, m.done, m.total = msg.phase, msg.done, msg.total
		return m, wait(m.events)

	case flashDoneMsg:
		m.state, m.err = finished, msg.err
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	if m.state == confirming {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m Flash) handleKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.state {
	case selecting:
		switch k.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "q", "esc":
			return m, m.exit()
		case "up", "k":
			m.cursor = max(m.cursor-1, 0)
		case "down", "j":
			m.cursor = min(m.cursor+1, max(len(m.usb)-1, 0))
		case "r":
			return m, listDisks
		case "enter":
			if len(m.usb) == 0 {
				return m, nil
			}
			d := m.usb[m.cursor]
			if d.Size < uint64(m.isoSize) {
				m.notice = fmt.Sprintf("%s is too small for this image (%s needed)", d.Path, disks.HumanSize(uint64(m.isoSize)))
				return m, nil
			}
			m.notice = ""
			m.target = d
			m.state = confirming
			m.input.SetValue("")
			m.input.Placeholder = d.Name
			return m, m.input.Focus()
		}
		return m, nil

	case confirming:
		switch k.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			m.state = selecting
			m.notice = ""
			m.input.Blur()
			return m, listDisks
		case "enter":
			if strings.TrimSpace(m.input.Value()) != m.target.Name {
				m.notice = fmt.Sprintf("type %q exactly to continue, or esc to go back", m.target.Name)
				return m, nil
			}
			m.notice = ""
			return m.start()
		}
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(k)
		return m, cmd

	case flashing:
		if k.String() == "ctrl+c" && !m.stopping {
			m.stopping = true
			m.cancel()
		}
		return m, nil

	case finished:
		switch k.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "q", "esc", "enter":
			return m, m.exit()
		}
	}
	return m, nil
}

func (m Flash) start() (tea.Model, tea.Cmd) {
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.events = make(chan tea.Msg, 16)
	m.state = flashing
	m.input.Blur()

	events, iso, target := m.events, m.iso, m.target
	go func() {
		defer cancel()
		err := flash.Write(ctx, iso, target, func(p flash.Phase, done, total int64) {
			events <- progressMsg{p, done, total}
		})
		events <- flashDoneMsg{err}
	}()
	return m, wait(m.events)
}

func (m Flash) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("dryserver · flash installer USB") + "\n")
	b.WriteString(dimStyle.Render(fmt.Sprintf("image: %s (%s)", m.iso, disks.HumanSize(uint64(m.isoSize)))) + "\n\n")

	switch m.state {
	case selecting:
		m.viewSelect(&b)
	case confirming:
		m.viewConfirm(&b)
	case flashing:
		m.viewFlashing(&b)
	case finished:
		m.viewFinished(&b)
	}

	if m.notice != "" {
		b.WriteString("\n" + errStyle.Render(m.notice) + "\n")
	}
	return b.String()
}

func (m Flash) viewSelect(b *strings.Builder) {
	b.WriteString("Select USB drive to turn into installer:\n\n")
	if m.listErr != nil {
		b.WriteString(errStyle.Render("cannot list disks: "+m.listErr.Error()) + "\n")
	}
	if len(m.usb) == 0 {
		b.WriteString(dimStyle.Render("  No USB drives found. Plug one in, it shows up here automatically.") + "\n")
	}
	for i, d := range m.usb {
		line := "  " + d.Title()
		if i == m.cursor {
			line = selStyle.Render("> " + d.Title())
		}
		b.WriteString(line + "\n")
		if i == m.cursor {
			writeParts(b, d)
		}
	}
	b.WriteString("\n" + dimStyle.Render("↑/↓ move · enter select · r rescan · q back") + "\n")
	b.WriteString(dimStyle.Render("Internal and system disks are never listed.") + "\n")
}

func writeParts(b *strings.Builder, d disks.Disk) {
	for _, p := range d.Parts {
		desc := strings.TrimSpace(strings.Join([]string{p.FSType, p.Label, strings.Join(p.Mountpoints, ",")}, " "))
		if desc == "" {
			desc = "no filesystem"
		}
		b.WriteString(dimStyle.Render(fmt.Sprintf("      %s  %s  %s", p.Path, disks.HumanSize(p.Size), desc)) + "\n")
	}
}

func (m Flash) viewConfirm(b *strings.Builder) {
	var w strings.Builder
	w.WriteString(errStyle.Bold(true).Render("ALL DATA ON THIS DRIVE WILL BE DESTROYED") + "\n\n")
	w.WriteString(m.target.Title() + "\n")
	writeParts(&w, m.target)
	b.WriteString(warnBox.Render(strings.TrimRight(w.String(), "\n")) + "\n\n")
	fmt.Fprintf(b, "Type %s to confirm: %s\n", selStyle.Render(m.target.Name), m.input.View())
	b.WriteString("\n" + dimStyle.Render("enter confirm · esc back") + "\n")
}

func (m Flash) viewFlashing(b *strings.Builder) {
	pct := 0.0
	if m.total > 0 {
		pct = float64(m.done) / float64(m.total)
	}
	fmt.Fprintf(b, "%s %s\n\n", m.phase, m.target.Path)
	b.WriteString(m.bar.ViewAs(pct) + "\n")
	fmt.Fprintf(b, "%s / %s  (%.0f%%)\n", disks.HumanSize(uint64(m.done)), disks.HumanSize(uint64(m.total)), pct*100)
	if m.stopping {
		b.WriteString("\n" + errStyle.Render("Stopping… the drive will need flashing again.") + "\n")
	} else {
		b.WriteString("\n" + dimStyle.Render("Do not unplug. ctrl+c cancels.") + "\n")
	}
}

func (m Flash) viewFinished(b *strings.Builder) {
	switch {
	case errors.Is(m.err, context.Canceled):
		b.WriteString(errStyle.Render("Cancelled. "+m.target.Path+" is only partly written; flash it again before use.") + "\n")
	case m.err != nil:
		b.WriteString(errStyle.Render("Failed: "+m.err.Error()) + "\n")
	default:
		b.WriteString(okStyle.Render("Done. Installer written and verified on "+m.target.Path+".") + "\n")
		b.WriteString("Safe to unplug.\n")
	}
	b.WriteString("\n" + dimStyle.Render("enter continue") + "\n")
}
