// Package assets embeds files used to build the ISO and set up servers.
package assets

import "embed"

// Archiso holds build.sh (run inside the Arch container), packages.extra
// (appended to the releng package list) and overlay/ (copied over the
// releng profile).
//
//go:embed all:archiso
var Archiso embed.FS

// Rootfs holds files copied into each installed server, at the same path
// under /. Which ones get copied is decided by the package bundles.
//
//go:embed all:rootfs
var Rootfs embed.FS
