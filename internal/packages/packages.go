// Package packages defines what gets installed on every server: the base
// system plus optional tool bundles picked in the config.
package packages

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Bundle is a group of packages with the setup they need.
type Bundle struct {
	ID       string
	Title    string
	Packages []string
	Services []string // enabled with systemctl
	Groups   []string // admin user joins these
	// UserCommands run as the admin user in the installed system
	// (via arch-chroot), after packages are installed.
	UserCommands []string
	// Files are paths inside the installed system, copied from the embedded
	// rootfs assets.
	Files []string
}

// System is always installed: boot, network, mesh and SSH.
var System = Bundle{
	ID: "system",
	Packages: []string{
		"base", "linux", "linux-firmware", "intel-ucode", "amd-ucode",
		"cryptsetup", "iwd", "openssh", "wireguard-tools", "nftables",
		"sudo", "zram-generator",
	},
	Services: []string{"systemd-networkd", "systemd-resolved", "iwd", "sshd", "nftables", "systemd-timesyncd"},
}

// Essentials is always installed: everyday tools for running a server.
var Essentials = Bundle{
	ID: "essentials",
	Packages: []string{
		"git", "cronie", "tmux", "htop", "btop",
		"curl", "wget", "rsync", "jq", "ripgrep", "fd", "fzf", "tree",
		"unzip", "zip", "less", "man-db", "man-pages", "bash-completion",
		"lsof", "strace", "bind", "inetutils", "tcpdump", "smartmontools", "lm_sensors",
		"arch-audit", "arp-scan",
	},
	Services: []string{"cronie"},
	Files:    []string{"/etc/skel/.tmux.conf"},
}

// Optional bundles, in display order. IDs are stored in config TOOLS.
var Optional = []Bundle{
	{
		ID:       "docker",
		Title:    "Docker + Compose",
		Packages: []string{"docker", "docker-compose", "docker-buildx"},
		Services: []string{"docker"},
		Groups:   []string{"docker"},
	},
	{
		ID:       "go",
		Title:    "Go",
		Packages: []string{"go", "gopls"},
	},
	{
		ID:           "rust",
		Title:        "Rust (rustup, stable toolchain)",
		Packages:     []string{"rustup"},
		UserCommands: []string{"rustup default stable"},
	},
	{
		ID:       "cpp",
		Title:    "C/C++ (gcc, clang, cmake, gdb, make)",
		Packages: []string{"base-devel", "clang", "cmake", "ninja", "gdb"},
	},
	{
		ID:       "neovim",
		Title:    "Neovim (clipboard shared over SSH)",
		Packages: []string{"neovim"},
		Files:    []string{"/etc/skel/.config/nvim/init.lua", "/etc/profile.d/editor.sh"},
	},
}

// DefaultTools is every optional bundle.
func DefaultTools() []string {
	ids := make([]string, len(Optional))
	for i, b := range Optional {
		ids[i] = b.ID
	}
	return ids
}

// Plan is the merged install list for a server.
type Plan struct {
	Packages     []string
	Services     []string
	Groups       []string
	UserCommands []string
	Files        []string
}

// Resolve merges System, Essentials, the chosen bundles and extra packages.
func Resolve(tools, extra []string) (Plan, error) {
	if err := ValidTools(tools); err != nil {
		return Plan{}, err
	}
	if err := ValidExtra(extra); err != nil {
		return Plan{}, err
	}
	var p Plan
	add := func(b Bundle) {
		p.Packages = append(p.Packages, b.Packages...)
		p.Services = append(p.Services, b.Services...)
		p.Groups = append(p.Groups, b.Groups...)
		p.UserCommands = append(p.UserCommands, b.UserCommands...)
		p.Files = append(p.Files, b.Files...)
	}
	add(System)
	add(Essentials)
	for _, b := range Optional {
		if slices.Contains(tools, b.ID) {
			add(b)
		}
	}
	p.Packages = dedup(append(p.Packages, extra...))
	p.Services = dedup(p.Services)
	p.Groups = dedup(p.Groups)
	return p, nil
}

func ValidTools(tools []string) error {
	for _, t := range tools {
		if !slices.ContainsFunc(Optional, func(b Bundle) bool { return b.ID == t }) {
			return fmt.Errorf("unknown tool %q", t)
		}
	}
	return nil
}

// Arch package names: lowercase letters, digits and @._+-
var pkgName = regexp.MustCompile(`^[a-z0-9@_+][a-z0-9@._+-]*$`)

func ValidExtra(extra []string) error {
	for _, p := range extra {
		if !pkgName.MatchString(p) {
			return fmt.Errorf("%q is not a valid package name", p)
		}
	}
	return nil
}

// SortTools orders tool IDs like Optional so the config stays stable.
func SortTools(tools []string) []string {
	var out []string
	for _, b := range Optional {
		if slices.Contains(tools, b.ID) {
			out = append(out, b.ID)
		}
	}
	return out
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
