package assets

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/DryBearr/dryserver/internal/packages"
)

// Every file a bundle promises must exist in the embedded rootfs.
func TestBundleFilesExist(t *testing.T) {
	bundles := append([]packages.Bundle{packages.System, packages.Essentials}, packages.Optional...)
	for _, b := range bundles {
		for _, f := range b.Files {
			if _, err := fs.Stat(Rootfs, "rootfs"+f); err != nil {
				t.Errorf("bundle %s: %s missing from assets/rootfs", b.ID, f)
			}
		}
	}
}

func TestNoStrayRootfsFiles(t *testing.T) {
	used := map[string]bool{}
	for _, b := range append([]packages.Bundle{packages.System, packages.Essentials}, packages.Optional...) {
		for _, f := range b.Files {
			used[f] = true
		}
	}
	fs.WalkDir(Rootfs, "rootfs", func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && !used[strings.TrimPrefix(path, "rootfs")] {
			t.Errorf("%s is not installed by any bundle", path)
		}
		return nil
	})
}
