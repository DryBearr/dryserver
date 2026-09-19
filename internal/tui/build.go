package tui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/DryBearr/dryserver/internal/build"
)

const keepLines = 500

type logMsg string

type buildDoneMsg struct{ err error }

// Build runs the ISO build and shows the tail of its log.
type Build struct {
	opts    build.Options
	spin    spinner.Model
	lines   []string
	events  chan tea.Msg
	cancel  context.CancelFunc
	started time.Time
	elapsed time.Duration

	running  bool
	stopping bool
	err      error
	height   int
	back     tea.Cmd
}

func NewBuild(opts build.Options, back tea.Cmd) Build {
	return Build{
		opts:   opts,
		spin:   spinner.New(spinner.WithSpinner(spinner.Dot)),
		back:   back,
		height: 24,
	}
}

func (m Build) Init() tea.Cmd { return nil }

// Start launches the build in the background. Called once when the screen opens.
func (m Build) Start() (Build, tea.Cmd) {
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.events = make(chan tea.Msg, 256)
	m.running = true
	m.started = time.Now()

	events, opts := m.events, m.opts
	go func() {
		defer cancel()
		w := &lineWriter{emit: func(s string) { events <- logMsg(s) }}
		err := build.Run(ctx, opts, w)
		w.Flush()
		events <- buildDoneMsg{err}
	}()
	return m, tea.Batch(wait(m.events), m.spin.Tick)
}

func (m Build) Update(msg tea.Msg) (Build, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.height = msg.Height

	case logMsg:
		m.lines = append(m.lines, string(msg))
		if len(m.lines) > keepLines {
			m.lines = m.lines[len(m.lines)-keepLines:]
		}
		return m, wait(m.events)

	case buildDoneMsg:
		m.running, m.err = false, msg.err
		m.elapsed = time.Since(m.started)
		return m, nil

	case spinner.TickMsg:
		if !m.running {
			return m, nil
		}
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case tea.KeyMsg:
		switch {
		case m.running && msg.String() == "ctrl+c" && !m.stopping:
			m.stopping = true
			m.cancel()
		case !m.running:
			switch msg.String() {
			case "ctrl+c":
				return m, tea.Quit
			case "enter", "esc", "q":
				return m, m.back
			}
		}
	}
	return m, nil
}

func (m Build) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("dryserver · build installer ISO") + "\n\n")

	switch {
	case m.running && m.stopping:
		b.WriteString(errStyle.Render("Stopping build…") + "\n")
	case m.running:
		fmt.Fprintf(&b, "%s Building %s  %s\n", m.spin.View(), build.ISOPath(m.opts.OutDir),
			dimStyle.Render(time.Since(m.started).Round(time.Second).String()))
	case errors.Is(m.err, context.Canceled):
		b.WriteString(errStyle.Render("Build cancelled.") + "\n")
	case m.err != nil:
		b.WriteString(errStyle.Render("Build failed: "+m.err.Error()) + "\n")
	default:
		b.WriteString(okStyle.Render(fmt.Sprintf("ISO built in %s: %s", m.elapsed.Round(time.Second), build.ISOPath(m.opts.OutDir))) + "\n")
	}
	b.WriteString("\n")

	// Show as much of the log tail as fits under the header and above the footer.
	n := max(m.height-8, 5)
	start := max(len(m.lines)-n, 0)
	for _, l := range m.lines[start:] {
		b.WriteString(dimStyle.Render(truncate(l, 200)) + "\n")
	}

	b.WriteString("\n")
	if m.running {
		b.WriteString(dimStyle.Render("First build downloads ~1 GB and takes several minutes. ctrl+c cancels.") + "\n")
	} else {
		b.WriteString(dimStyle.Render("enter back to menu · full log in "+m.opts.OutDir+"/"+build.LogName) + "\n")
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// lineWriter turns a byte stream into lines. Carriage returns (progress bars)
// also end a line so the latest state shows up.
type lineWriter struct {
	emit func(string)
	buf  []byte
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexAny(w.buf, "\r\n")
		if i < 0 {
			return len(p), nil
		}
		if line := strings.TrimSpace(string(w.buf[:i])); line != "" {
			w.emit(line)
		}
		w.buf = w.buf[i+1:]
	}
}

func (w *lineWriter) Flush() {
	if line := strings.TrimSpace(string(w.buf)); line != "" {
		w.emit(line)
	}
	w.buf = nil
}
