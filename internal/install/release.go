package install

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// blockDev is one node of `lsblk -J -p -o NAME,TYPE,SIZE,MOUNTPOINTS`.
type blockDev struct {
	Name        string     `json:"name"`
	Type        string     `json:"type"`
	Size        uint64     `json:"size"`
	Mountpoints []*string  `json:"mountpoints"`
	Children    []blockDev `json:"children"`
}

func (r *Real) lsblk(ctx context.Context, dev string) (blockDev, error) {
	out, err := r.Run.Run(ctx, Cmd{Name: "lsblk", Args: []string{"-J", "-b", "-p", "-o", "NAME,TYPE,SIZE,MOUNTPOINTS", dev}, Quiet: true, StdoutOnly: true})
	if err != nil {
		return blockDev{}, err
	}
	var doc struct {
		BlockDevices []blockDev `json:"blockdevices"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || len(doc.BlockDevices) != 1 {
		return blockDev{}, fmt.Errorf("cannot read the layout of %s", dev)
	}
	return doc.BlockDevices[0], nil
}

// releaseDisk stops everything the live system started on an old disk
// before it is repartitioned: mounts and swap, LVM volumes, encrypted
// mappings (also ones left open by an earlier setup attempt) and RAID sets.
// Otherwise sfdisk refuses: "This disk is currently in use".
func (r *Real) releaseDisk(ctx context.Context, disk string) error {
	top, err := r.lsblk(ctx, disk)
	if err != nil {
		return err
	}
	// Children before parents, so stacked devices come apart top-down.
	var order []blockDev
	var walk func(d blockDev)
	walk = func(d blockDev) {
		for _, c := range d.Children {
			walk(c)
		}
		order = append(order, d)
	}
	walk(top)

	for _, d := range order {
		for _, m := range d.Mountpoints {
			switch {
			case m == nil || *m == "":
			case *m == "[SWAP]":
				if _, err := r.Run.Run(ctx, Cmd{Name: "swapoff", Args: []string{d.Name}}); err != nil {
					return err
				}
			default:
				if _, err := r.Run.Run(ctx, Cmd{Name: "umount", Args: []string{"-R", *m}}); err != nil {
					return err
				}
			}
		}
		var err error
		switch {
		case d.Name == top.Name, d.Type == "part":
		case d.Type == "lvm" || d.Type == "crypt" || d.Type == "dm" || d.Type == "mpath":
			_, err = r.Run.Run(ctx, Cmd{Name: "dmsetup", Args: []string{"remove", "--retry", d.Name}})
		case strings.HasPrefix(d.Type, "raid") || d.Type == "md" || d.Type == "linear":
			_, err = r.Run.Run(ctx, Cmd{Name: "mdadm", Args: []string{"--stop", d.Name}})
		}
		if err != nil {
			return fmt.Errorf("%s is still in use by %s (%s): %w", disk, d.Name, d.Type, err)
		}
	}
	// A RAID container built from whole disks shows up as a child of each
	// member disk; stopping it above also frees the disk itself.
	return nil
}

// checkLayout makes sure the kernel sees the new partition table: the
// expected number of partitions, the first one 1 GiB (the boot partition).
func (r *Real) checkLayout(ctx context.Context, disk string, parts int, firstSize uint64) error {
	d, err := r.lsblk(ctx, disk)
	if err != nil {
		return err
	}
	var got []blockDev
	for _, c := range d.Children {
		if c.Type == "part" {
			got = append(got, c)
		}
	}
	if len(got) != parts || (firstSize > 0 && got[0].Size != firstSize) {
		return fmt.Errorf("the kernel still sees the old partitions of %s; reboot from the USB and run the setup again", disk)
	}
	return nil
}
