package install

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// pacstrapAttempts: one download hiccup on WiFi should not end the
// install. Packages already downloaded stay in the target's cache, so a
// new attempt continues where the last one stopped.
const pacstrapAttempts = 3

// networkWait is how long a retry waits for the internet to come back.
const networkWait = 3 * time.Minute

// waitNetwork waits until the package mirrors can be reached, so a retry
// does not run (and fail) while WiFi is still down.
func (r *Real) waitNetwork(ctx context.Context, limit time.Duration) error {
	check := r.netCheck
	if check == nil {
		check = func(ctx context.Context) bool {
			d := net.Dialer{Timeout: 4 * time.Second}
			c, err := d.DialContext(ctx, "tcp", "geo.mirror.pkgbuild.com:443")
			if err != nil {
				return false
			}
			c.Close()
			return true
		}
	}
	deadline := time.Now().Add(limit)
	logged := false
	for !check(ctx) {
		if time.Now().After(deadline) {
			return fmt.Errorf("the internet did not come back within %s; check WiFi, then press r to retry", limit)
		}
		if !logged {
			r.Log("waiting for the network to come back")
			logged = true
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	return nil
}

// pacstrap installs the packages into the target, retrying on failure. A
// signature problem first refreshes the live system's signing keys.
func (r *Real) pacstrap(ctx context.Context, pkgs []string) error {
	var out string
	var err error
	for attempt := 1; attempt <= pacstrapAttempts; attempt++ {
		if attempt > 1 {
			r.Log(fmt.Sprintf("package install failed (%s); trying again, attempt %d of %d", pacmanProblem(out), attempt, pacstrapAttempts))
			if err := r.waitNetwork(ctx, networkWait); err != nil {
				return err
			}
			if signatureProblem(out) {
				r.Log("updating the package signing keys first")
				r.Run.Run(ctx, Cmd{Name: "pacman", Args: []string{"-Sy", "--noconfirm", "archlinux-keyring"}})
			}
		}
		out, err = r.Run.Run(ctx, Cmd{Name: "pacstrap", Args: append([]string{"-K", r.Target}, pkgs...)})
		if err == nil || ctx.Err() != nil {
			return err
		}
	}
	return fmt.Errorf("%s (after %d attempts): %w", pacmanProblem(out), pacstrapAttempts, err)
}

func signatureProblem(out string) bool {
	// Specific pacman error texts only: package names like
	// "archlinux-keyring" appear in every package list.
	for _, s := range []string{"PGP signature", "unknown trust", "invalid signature", "signature from", "keyring is not writable", "public key not found"} {
		if strings.Contains(out, s) {
			return true
		}
	}
	return false
}

// pacmanProblem turns pacman's output into a short explanation.
func pacmanProblem(out string) string {
	switch {
	case strings.Contains(out, "No space left"):
		return "the disk is full"
	case signatureProblem(out):
		return "package signatures could not be checked (wrong clock or outdated signing keys)"
	case strings.Contains(out, "failed to retrieve some files"), strings.Contains(out, "failed retrieving file"),
		strings.Contains(out, "Operation too slow"), strings.Contains(out, "Could not resolve host"):
		return "downloads failed; the network may be unstable (move closer to the router or use a cable)"
	case strings.Contains(out, "conflicting files"), strings.Contains(out, "could not satisfy dependencies"),
		strings.Contains(out, "are in conflict"):
		return "packages conflict; check EXTRA_PACKAGES in the config"
	}
	return "pacman failed; see the log"
}
