package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DryBearr/dryserver/internal/config"
	"github.com/DryBearr/dryserver/internal/sysconf"
)

type checkRunner struct {
	cmds    []Cmd
	missing string // package pacman -Si does not know
}

func (c *checkRunner) Run(ctx context.Context, cmd Cmd) (string, error) {
	c.cmds = append(c.cmds, cmd)
	switch {
	case cmd.Name == "timedatectl" && cmd.Args[0] == "show":
		return "yes\n", nil
	case cmd.Name == "pacman" && cmd.Args[0] == "-Si" && c.missing != "":
		return "error: package '" + c.missing + "' was not found\n", errors.New("exit status 1")
	}
	return "", nil
}

func precheckReal(t *testing.T) (*Real, *checkRunner) {
	dir := t.TempDir()
	var list strings.Builder
	list.WriteString("# mirrors\n")
	for i := range 50 {
		list.WriteString("Server = https://mirror" + string(rune('a'+i%26)) + ".example/$repo/os/$arch\n")
	}
	ml := filepath.Join(dir, "mirrorlist")
	os.WriteFile(ml, []byte(list.String()), 0o644)
	cr := &checkRunner{}
	r := NewReal(config.Default(), cr, nil, "", "")
	r.MirrorList = ml
	return r, cr
}

func TestPrecheck(t *testing.T) {
	r, cr := precheckReal(t)
	cfg := config.Default()
	cfg.CoordLanIP = "192.0.2.1" // TEST-NET: never answers
	cfg.ExtraPackages = "python"
	var steps, logs []string
	err := r.Precheck(t.Context(), cfg, Choices{Role: sysconf.Node}, func(s Step) {
		switch {
		case s.Log != "":
			logs = append(logs, s.Log)
		case s.Done:
			steps = append(steps, s.Name)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "Check the clock,Prepare package signing keys,Pick package mirrors,Update package lists,Check extra packages,Check the coordinator"
	if strings.Join(steps, ",") != want {
		t.Errorf("steps = %v", steps)
	}
	all := strings.Join(logs, "\n")
	for _, w := range []string{"clock synced", "package signing keys ready", "using 10 mirrors", "warning: coordinator 192.0.2.1 does not answer"} {
		if !strings.Contains(all, w) {
			t.Errorf("log missing %q:\n%s", w, all)
		}
	}
	b, _ := os.ReadFile(r.MirrorList)
	if n := strings.Count(string(b), "Server ="); n != keepMirrors {
		t.Errorf("mirrorlist has %d servers", n)
	}
	var pacman []string
	for _, c := range cr.cmds {
		if c.Name == "pacman" {
			pacman = append(pacman, c.String())
		}
	}
	if len(pacman) != 2 || pacman[0] != "pacman -Sy --noconfirm" {
		t.Errorf("pacman calls: %v", pacman)
	}
}

func TestPrecheckUnknownPackage(t *testing.T) {
	r, cr := precheckReal(t)
	cr.missing = "pyhton"
	cfg := config.Default()
	cfg.ExtraPackages = "pyhton"
	err := r.Precheck(t.Context(), cfg, Choices{Role: sysconf.Coordinator}, func(Step) {})
	if err == nil || !strings.Contains(err.Error(), "unknown extra packages: pyhton") {
		t.Fatalf("err = %v", err)
	}
}
