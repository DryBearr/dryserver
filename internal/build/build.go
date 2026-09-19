// Package build produces the installer ISO by running mkarchiso inside an
// Arch Linux container, since the build host (Fedora) cannot run archiso.
package build

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/DryBearr/dryserver/assets"
	"github.com/DryBearr/dryserver/internal/config"
	"github.com/DryBearr/dryserver/internal/owner"
)

const (
	Image   = "docker.io/library/archlinux:latest"
	ISOName = "dryserver.iso"
	LogName = "build.log"
	KeyName = "registry_ed25519"
)

type Options struct {
	Config     config.Config
	OutDir     string // receives dryserver.iso, build.log and the pacman cache
	SecretsDir string // holds the registry SSH keypair, created on first build
}

func ISOPath(outDir string) string { return filepath.Join(outDir, ISOName) }

// Run builds OutDir/dryserver.iso and streams progress lines to log.
func Run(ctx context.Context, o Options, log io.Writer) (err error) {
	if err := o.Config.Validate(); err != nil {
		return fmt.Errorf("config is not valid:\n%w", err)
	}
	if _, err := exec.LookPath("podman"); err != nil {
		return errors.New("podman not found, install it first")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := checkStatic(self); err != nil {
		return err
	}

	outDir, err := filepath.Abs(o.OutDir)
	if err != nil {
		return err
	}
	cache := filepath.Join(outDir, "pkgcache")
	if err := os.MkdirAll(cache, 0o755); err != nil {
		return err
	}
	// A go.mod makes Go tooling (go test ./...) skip the build output, which
	// holds root-owned temp dirs during a build.
	os.WriteFile(filepath.Join(outDir, "go.mod"), []byte("// Build output, not Go code.\nmodule dryserver-out\n"), 0o644)
	defer owner.Fix(outDir, o.SecretsDir)

	logFile, err := os.Create(filepath.Join(outDir, LogName))
	if err != nil {
		return err
	}
	defer logFile.Close()
	log = io.MultiWriter(logFile, log)

	key, err := ensureRegistryKey(ctx, o.SecretsDir, log)
	if err != nil {
		return err
	}

	stage := filepath.Join(outDir, "stage")
	defer os.RemoveAll(stage)
	if err := writeStage(stage, self, o.Config, key); err != nil {
		return fmt.Errorf("prepare build files: %w", err)
	}

	fmt.Fprintf(log, "==> Starting %s (first run downloads ~1 GB)\n", Image)
	start := time.Now()
	name := fmt.Sprintf("dryserver-build-%d", os.Getpid())
	cmd := exec.CommandContext(ctx, "podman", "run", "--rm", "--name", name,
		"--privileged", "--security-opt", "label=disable",
		"-v", stage+":/stage:ro",
		"-v", outDir+":/out",
		"-v", cache+":/var/cache/pacman/pkg",
		Image, "bash", "/stage/build.sh")
	cmd.Stdout, cmd.Stderr = log, log
	// bash runs as PID 1 in the container and ignores forwarded SIGINT, so
	// stop this container by name; podman run then exits and --rm cleans up.
	cmd.Cancel = func() error {
		return exec.Command("podman", "stop", "--time", "2", name).Run()
	}
	cmd.WaitDelay = 30 * time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("container build failed (%v), see %s", err, filepath.Join(o.OutDir, LogName))
	}
	if _, err := os.Stat(ISOPath(outDir)); err != nil {
		return fmt.Errorf("build finished but %s is missing", ISOPath(o.OutDir))
	}
	fmt.Fprintf(log, "==> Done in %s\n", time.Since(start).Round(time.Second))
	return nil
}

// checkStatic refuses a dynamically linked binary: it is copied into the
// ISO and may not find its loader or libc there.
func checkStatic(path string) error {
	f, err := elf.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if f.Section(".interp") != nil {
		return errors.New("this dryserver binary is dynamically linked; rebuild with `make` (CGO_ENABLED=0) so it can run inside the ISO")
	}
	return nil
}

// ensureRegistryKey creates the SSH keypair nodes use to register with the
// coordinator. The same key is baked into every ISO, so it is kept across builds.
func ensureRegistryKey(ctx context.Context, dir string, log io.Writer) (string, error) {
	key := filepath.Join(dir, KeyName)
	if _, err := os.Stat(key); err == nil {
		return key, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	fmt.Fprintf(log, "==> Generating registry key %s\n", key)
	out, err := exec.CommandContext(ctx, "ssh-keygen", "-q", "-t", "ed25519", "-N", "",
		"-C", "dryserver-registry", "-f", key).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ssh-keygen: %v: %s", err, out)
	}
	return key, nil
}

// writeStage lays out the directory mounted at /stage in the container:
// the embedded assets plus this binary, the config and the registry key.
func writeStage(stage, self string, cfg config.Config, key string) error {
	if err := os.RemoveAll(stage); err != nil {
		return err
	}
	src, err := fs.Sub(assets.Archiso, "archiso")
	if err != nil {
		return err
	}
	if err := os.CopyFS(stage, src); err != nil {
		return err
	}

	root := filepath.Join(stage, "overlay", "airootfs")
	etc := filepath.Join(root, "etc", "dryserver")
	bin := filepath.Join(root, "usr", "local", "bin")
	for _, d := range []string{etc, bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	if err := copyFile(self, filepath.Join(bin, "dryserver"), 0o755); err != nil {
		return err
	}
	if err := cfg.Save(filepath.Join(etc, "config.env")); err != nil {
		return err
	}
	if err := copyFile(key, filepath.Join(etc, KeyName), 0o600); err != nil {
		return err
	}
	return copyFile(key+".pub", filepath.Join(etc, KeyName+".pub"), 0o644)
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
