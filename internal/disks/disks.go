// Package disks lists block devices via lsblk and decides which ones are
// safe targets for flashing.
package disks

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

type Disk struct {
	Name      string // sdb
	Path      string // /dev/sdb
	Size      uint64 // bytes
	Model     string
	Vendor    string
	Tran      string // usb, nvme, sata, ...
	Removable bool
	ReadOnly  bool
	Parts     []Part
}

type Part struct {
	Path        string
	Size        uint64
	FSType      string
	Label       string
	Mountpoints []string
}

// List returns every whole disk with its partitions flattened (LVM, crypt
// and other nested devices are folded into their parent disk).
func List() ([]Disk, error) {
	out, err := exec.Command("lsblk", "-J", "-b",
		"-o", "NAME,PATH,SIZE,MODEL,VENDOR,TRAN,RM,RO,TYPE,FSTYPE,LABEL,MOUNTPOINTS").Output()
	if err != nil {
		return nil, fmt.Errorf("lsblk: %w", err)
	}
	return parse(out)
}

// USB returns the disks that may be flashed: USB or removable, writable,
// non-empty, and not holding any system mount.
func USB(all []Disk) []Disk {
	var out []Disk
	for _, d := range all {
		// Floppy drives report as removable; skip them.
		if strings.HasPrefix(d.Name, "fd") {
			continue
		}
		if (d.Tran == "usb" || d.Removable) && !d.ReadOnly && d.Size > 0 && !d.IsSystem() {
			out = append(out, d)
		}
	}
	return out
}

// LiveLabelPrefix is the start of the installer ISO's filesystem label.
const LiveLabelPrefix = "DRYSRV_"

// MinInstallSize is the smallest disk offered for installing (16 GB).
const MinInstallSize = 16_000_000_000

// Installable returns the disks the installer may use: real, writable
// disks of at least MinInstallSize, excluding the USB the installer booted
// from and disks mounted anywhere but the installer's /mnt.
func Installable(all []Disk) []Disk {
	var out []Disk
	for _, d := range all {
		virtual := false
		for _, prefix := range []string{"zram", "loop", "fd", "sr", "ram"} {
			if strings.HasPrefix(d.Name, prefix) {
				virtual = true
			}
		}
		if virtual || d.ReadOnly || d.Size < MinInstallSize || d.isLiveMedia() || d.mountedOutsideTarget() {
			continue
		}
		out = append(out, d)
	}
	return out
}

// mountedOutsideTarget: something other than the installer's own target
// (/mnt, left over from a failed attempt) is mounted from the disk.
func (d Disk) mountedOutsideTarget() bool {
	for _, m := range d.Mounts() {
		if m != "/mnt" && !strings.HasPrefix(m, "/mnt/") {
			return true
		}
	}
	return false
}

func (d Disk) isLiveMedia() bool {
	for _, p := range d.Parts {
		if strings.HasPrefix(p.Label, LiveLabelPrefix) {
			return true
		}
		for _, m := range p.Mountpoints {
			if strings.HasPrefix(m, "/run/archiso") {
				return true
			}
		}
	}
	return false
}

// Find returns the disk with the given path from a fresh listing.
func Find(path string) (Disk, error) {
	all, err := List()
	if err != nil {
		return Disk{}, err
	}
	for _, d := range all {
		if d.Path == path {
			return d, nil
		}
	}
	return Disk{}, fmt.Errorf("%s not found", path)
}

// IsSystem reports whether anything on the disk is mounted outside the
// usual removable-media locations. Such a disk is never offered as a target.
func (d Disk) IsSystem() bool {
	for _, p := range d.Parts {
		for _, m := range p.Mountpoints {
			if !isMediaMount(m) {
				return true
			}
		}
	}
	return false
}

func (d Disk) Mounts() []string {
	var out []string
	for _, p := range d.Parts {
		out = append(out, p.Mountpoints...)
	}
	return out
}

func (d Disk) Title() string {
	name := strings.TrimSpace(d.Vendor + " " + d.Model)
	if name == "" {
		name = "unknown device"
	}
	return fmt.Sprintf("%s  %s  %s", d.Path, HumanSize(d.Size), name)
}

func isMediaMount(m string) bool {
	for _, prefix := range []string{"/run/media/", "/media/", "/mnt/"} {
		if strings.HasPrefix(m, prefix) {
			return true
		}
	}
	return false
}

func HumanSize(b uint64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "kMGTPE"[exp])
}

type lsblkDev struct {
	Name        string     `json:"name"`
	Path        string     `json:"path"`
	Size        uint64     `json:"size"`
	Model       *string    `json:"model"`
	Vendor      *string    `json:"vendor"`
	Tran        *string    `json:"tran"`
	RM          flexBool   `json:"rm"`
	RO          flexBool   `json:"ro"`
	Type        string     `json:"type"`
	FSType      *string    `json:"fstype"`
	Label       *string    `json:"label"`
	Mountpoints []*string  `json:"mountpoints"`
	Children    []lsblkDev `json:"children"`
}

func parse(data []byte) ([]Disk, error) {
	var doc struct {
		BlockDevices []lsblkDev `json:"blockdevices"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse lsblk output: %w", err)
	}
	var out []Disk
	for _, dev := range doc.BlockDevices {
		if dev.Type != "disk" {
			continue
		}
		d := Disk{
			Name:      dev.Name,
			Path:      dev.Path,
			Size:      dev.Size,
			Model:     str(dev.Model),
			Vendor:    str(dev.Vendor),
			Tran:      str(dev.Tran),
			Removable: bool(dev.RM),
			ReadOnly:  bool(dev.RO),
		}
		// The whole disk can carry a filesystem too (e.g. a stick formatted
		// without a partition table), so include it as a pseudo-partition.
		collect(dev, &d.Parts)
		out = append(out, d)
	}
	return out, nil
}

func collect(dev lsblkDev, parts *[]Part) {
	p := Part{Path: dev.Path, Size: dev.Size, FSType: str(dev.FSType), Label: str(dev.Label)}
	for _, m := range dev.Mountpoints {
		if m != nil && *m != "" {
			p.Mountpoints = append(p.Mountpoints, *m)
		}
	}
	if dev.Type != "disk" || p.FSType != "" || len(p.Mountpoints) > 0 {
		*parts = append(*parts, p)
	}
	for _, c := range dev.Children {
		collect(c, parts)
	}
}

func str(s *string) string {
	if s == nil {
		return ""
	}
	return strings.TrimSpace(*s)
}

// flexBool accepts true/false as well as "0"/"1" and 0/1, which older
// lsblk versions emit.
type flexBool bool

func (b *flexBool) UnmarshalJSON(data []byte) error {
	switch strings.Trim(string(data), `"`) {
	case "true", "1":
		*b = true
	case "false", "0", "null", "":
		*b = false
	default:
		return fmt.Errorf("unexpected boolean %s", data)
	}
	return nil
}
