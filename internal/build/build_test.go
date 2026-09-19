package build

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DryBearr/dryserver/internal/config"
)

func TestWriteStage(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, KeyName)
	os.WriteFile(key, []byte("private"), 0o600)
	os.WriteFile(key+".pub", []byte("public"), 0o644)
	self := filepath.Join(dir, "self")
	os.WriteFile(self, []byte("binary"), 0o755)

	cfg := config.Default()
	cfg.WifiSSID = "home"
	stage := filepath.Join(dir, "stage")
	if err := writeStage(stage, self, cfg, key); err != nil {
		t.Fatal(err)
	}

	for path, mode := range map[string]os.FileMode{
		"build.sh":                  0,
		"packages.extra":            0,
		"overlay/airootfs/etc/motd": 0,
		"overlay/airootfs/usr/local/bin/dryserver":           0o755,
		"overlay/airootfs/etc/dryserver/config.env":          0o600,
		"overlay/airootfs/etc/dryserver/" + KeyName:          0o600,
		"overlay/airootfs/etc/dryserver/" + KeyName + ".pub": 0o644,
	} {
		st, err := os.Stat(filepath.Join(stage, path))
		if err != nil {
			t.Errorf("missing %s", path)
			continue
		}
		if mode != 0 && st.Mode().Perm() != mode {
			t.Errorf("%s mode %v, want %v", path, st.Mode().Perm(), mode)
		}
	}
	got, err := config.Load(filepath.Join(stage, "overlay/airootfs/etc/dryserver/config.env"))
	if err != nil || got.WifiSSID != "home" {
		t.Errorf("baked config = %+v, %v", got, err)
	}
}

func TestCheckStatic(t *testing.T) {
	// /bin/sh is dynamically linked on every normal distro.
	if err := checkStatic("/bin/sh"); err == nil {
		t.Error("dynamic binary accepted")
	}
}
