// Package owner hands files created under sudo back to the invoking user.
package owner

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
)

// Fix chowns each path (recursively) to SUDO_UID:SUDO_GID when running as
// root via sudo, so the project directory stays usable without root.
// Missing paths are skipped.
func Fix(paths ...string) {
	if os.Geteuid() != 0 {
		return
	}
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 != nil || err2 != nil {
		return
	}
	for _, p := range paths {
		filepath.WalkDir(p, func(path string, _ fs.DirEntry, err error) error {
			if err == nil {
				os.Lchown(path, uid, gid)
			}
			return nil
		})
	}
}
