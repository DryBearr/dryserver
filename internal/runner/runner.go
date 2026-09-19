// Package runner runs external commands for the installer and node tools,
// logging each command line and its output. Secrets travel in Stdin or Env,
// which are never logged.
package runner

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Cmd is one command the installer runs. Secrets travel in Stdin or Env,
// which are never logged.
type Cmd struct {
	Name  string
	Args  []string
	Stdin string
	Env   []string
	Quiet bool // do not log output (key material)
	// StdoutOnly returns only stdout (e.g. JSON replies); stderr is still
	// logged unless Quiet.
	StdoutOnly bool
}

func (c Cmd) String() string { return strings.TrimSpace(c.Name + " " + strings.Join(c.Args, " ")) }

// Runner runs installer commands. Tests use a fake that records them.
type Runner interface {
	Run(ctx context.Context, c Cmd) (string, error)
}

// ExecRunner runs commands for real and sends the command line and each
// output line to Log.
type ExecRunner struct {
	Log func(string)
}

func (r ExecRunner) Run(ctx context.Context, c Cmd) (string, error) {
	r.Log("$ " + c.String())
	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
	cmd.Env = append(os.Environ(), c.Env...)
	if c.Stdin != "" {
		cmd.Stdin = strings.NewReader(c.Stdin)
	}
	var out, errOut bytes.Buffer
	emit := func(l string) {
		if !c.Quiet {
			r.Log(l)
		}
	}
	w := &lines{emit: emit, buf: &out}
	ew := w
	if c.StdoutOnly {
		ew = &lines{emit: emit, buf: &errOut}
	}
	cmd.Stdout, cmd.Stderr = w, ew
	err := cmd.Run()
	w.flush()
	ew.flush()
	if err != nil {
		return out.String(), fmt.Errorf("%s failed: %w%s", c.Name, err, lastLine(out.String()+errOut.String(), c.Quiet))
	}
	return out.String(), nil
}

func lastLine(s string, quiet bool) string {
	s = strings.TrimSpace(s)
	if quiet || s == "" {
		return ""
	}
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	return ": " + s
}

// lines copies output into buf and emits it line by line; carriage
// returns (progress bars) also end a line.
type lines struct {
	emit    func(string)
	buf     *bytes.Buffer
	pending []byte
}

func (w *lines) Write(p []byte) (int, error) {
	w.buf.Write(p)
	w.pending = append(w.pending, p...)
	for {
		i := bytes.IndexAny(w.pending, "\r\n")
		if i < 0 {
			return len(p), nil
		}
		if l := strings.TrimSpace(string(w.pending[:i])); l != "" {
			w.emit(l)
		}
		w.pending = w.pending[i+1:]
	}
}

func (w *lines) flush() {
	if l := strings.TrimSpace(string(w.pending)); l != "" {
		w.emit(l)
	}
	w.pending = nil
}
