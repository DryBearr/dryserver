package install

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/DryBearr/dryserver/internal/config"
	"github.com/DryBearr/dryserver/internal/sysconf"
)

const (
	clockWait     = 60 * time.Second
	mirrorTimeout = 3 * time.Minute
	keepMirrors   = 10
)

var missingPkg = regexp.MustCompile(`package '([^']+)' was not found`)

// Precheck gets the live system ready to download and checks what can be
// checked before the disk is touched. Each part is a step with its own log
// on the setup screen.
func (r *Real) Precheck(ctx context.Context, cfg config.Config, ch Choices, progress func(Step)) error {
	r.sink = func(l string) { progress(Step{Log: l}) }
	defer func() { r.sink = nil }()
	step := func(name string, fn func() error) error {
		progress(Step{Name: name})
		if err := fn(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		progress(Step{Name: name, Done: true})
		return nil
	}

	if err := step("Check the clock", func() error { return r.syncClock(ctx) }); err != nil {
		return err
	}
	if err := step("Prepare package signing keys", func() error { return r.waitKeyring(ctx) }); err != nil {
		return err
	}
	if err := step("Pick package mirrors", r.trimMirrors); err != nil {
		return err
	}
	if err := step("Update package lists", func() error {
		c, cancel := context.WithTimeout(ctx, mirrorTimeout)
		defer cancel()
		if _, err := r.Run.Run(c, Cmd{Name: "pacman", Args: []string{"-Sy", "--noconfirm"}}); err != nil {
			if c.Err() != nil && ctx.Err() == nil {
				return fmt.Errorf("the package mirrors did not answer within %s; check the internet connection", mirrorTimeout)
			}
			return fmt.Errorf("cannot reach the package mirrors: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}
	if extra := cfg.ExtraList(); len(extra) > 0 {
		if err := step("Check extra packages", func() error {
			out, err := r.Run.Run(ctx, Cmd{Name: "pacman", Args: append([]string{"-Si"}, extra...), Quiet: true})
			if err != nil {
				var missing []string
				for _, m := range missingPkg.FindAllStringSubmatch(out, -1) {
					missing = append(missing, m[1])
				}
				return fmt.Errorf("unknown extra packages: %s (fix EXTRA_PACKAGES in the desktop config)", strings.Join(missing, " "))
			}
			r.Log("found: " + strings.Join(extra, " "))
			return nil
		}); err != nil {
			return err
		}
	}
	if ch.Role == sysconf.Node {
		// Only a warning: the server keeps asking to join after it boots.
		step("Check the coordinator", func() error {
			addr := net.JoinHostPort(cfg.CoordLanIP, "22")
			d := net.Dialer{Timeout: 5 * time.Second}
			c, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				r.Log(fmt.Sprintf("warning: coordinator %s does not answer (%v). Install it first, or this server asks to join after it boots.", cfg.CoordLanIP, err))
				return nil
			}
			c.Close()
			r.Log("coordinator " + cfg.CoordLanIP + " answers")
			return nil
		})
	}
	return nil
}

// syncClock waits for NTP. Laptops with a dead clock battery boot with a
// wrong date, and then every HTTPS download fails its certificate check.
func (r *Real) syncClock(ctx context.Context) error {
	r.Run.Run(ctx, Cmd{Name: "timedatectl", Args: []string{"set-ntp", "true"}, Quiet: true})
	deadline := time.Now().Add(clockWait)
	next := time.Now()
	for {
		out, _ := r.Run.Run(ctx, Cmd{Name: "timedatectl", Args: []string{"show", "-p", "NTPSynchronized", "--value"}, Quiet: true, StdoutOnly: true})
		now := time.Now().UTC().Format("2006-01-02 15:04 MST")
		if strings.TrimSpace(out) == "yes" {
			r.Log("clock synced: " + now)
			return nil
		}
		if time.Now().After(deadline) {
			r.Log("warning: the clock did not sync (it says " + now + "); if that is wrong, downloads will fail")
			return nil
		}
		if time.Now().After(next) {
			r.Log("waiting for the clock to sync from the internet (it says " + now + ")")
			next = time.Now().Add(10 * time.Second)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// waitKeyring waits for the live system's pacman-init service, which
// sets up the keys that verify downloaded packages.
func (r *Real) waitKeyring(ctx context.Context) error {
	deadline := time.Now().Add(clockWait)
	for {
		if _, err := r.Run.Run(ctx, Cmd{Name: "systemctl", Args: []string{"is-active", "--quiet", "pacman-init.service"}, Quiet: true}); err == nil {
			r.Log("package signing keys ready")
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("the package signing keys were not set up (pacman-init.service); reboot from the USB")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// trimMirrors keeps the first mirrors of the live system's list (Arch's
// worldwide CDN comes first). With hundreds of entries, pacman walks the
// whole list when the network is bad, which looks like a hang.
func (r *Real) trimMirrors() error {
	b, err := os.ReadFile(r.MirrorList)
	if err != nil {
		return err
	}
	var servers []string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "Server") {
			servers = append(servers, strings.TrimSpace(l))
		}
	}
	if len(servers) == 0 {
		return errors.New("no package mirrors configured")
	}
	if len(servers) > keepMirrors {
		servers = servers[:keepMirrors]
		out := "# dryserver: the first mirrors of the live system's list.\n" + strings.Join(servers, "\n") + "\n"
		if err := os.WriteFile(r.MirrorList, []byte(out), 0o644); err != nil {
			return err
		}
	}
	r.Log(fmt.Sprintf("using %d mirrors, first: %s", len(servers), strings.TrimSpace(strings.SplitN(servers[0], "=", 2)[1])))
	return nil
}

// reportDownloads logs how much pacstrap has downloaded, every few
// seconds, until done is closed: pacman prints nothing while downloading
// when it has no terminal.
func (r *Real) reportDownloads(done <-chan struct{}, every time.Duration) {
	cache := r.target("/var/cache/pacman/pkg")
	var last int64
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
		}
		var size int64
		filepath.WalkDir(cache, func(_ string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				if info, err := d.Info(); err == nil {
					size += info.Size()
				}
			}
			return nil
		})
		if size == last {
			continue
		}
		last = size
		r.mu.Lock()
		total := r.dlTotal
		r.mu.Unlock()
		// MiB like pacman's "Total Download Size".
		msg := fmt.Sprintf("downloaded %.1f MiB", float64(size)/(1<<20))
		if total != "" {
			msg += " of " + total
		}
		r.Log(msg)
	}
}
