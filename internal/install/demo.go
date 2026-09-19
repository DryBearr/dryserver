package install

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/DryBearr/dryserver/internal/config"
	"github.com/DryBearr/dryserver/internal/disks"
)

// Demo pretends to install so the setup screen can be tried on any
// machine. It never touches a disk or the network.
type Demo struct {
	Machine Machine
	Delay   time.Duration // pause per fake step; 0 in tests
	// Approve decides the join result; nil approves as host 7.
	Approve func() (int, error)
}

func NewDemo() *Demo {
	return &Demo{
		Delay: 400 * time.Millisecond,
		Machine: Machine{
			CPU:     "Intel Core i5-6300U (demo)",
			RAM:     8 << 30,
			UEFI:    true,
			TPM2:    true,
			TPMChip: true,
			Disks: []disks.Disk{
				{Name: "nvme0n1", Path: "/dev/nvme0n1", Size: 256_060_514_304, Model: "SAMSUNG MZVLW256", Tran: "nvme",
					Parts: []disks.Part{{Path: "/dev/nvme0n1p1", Size: 272_629_760, FSType: "vfat"}, {Path: "/dev/nvme0n1p3", Size: 255_000_000_000, FSType: "ntfs", Label: "Windows"}}},
				{Name: "sda", Path: "/dev/sda", Size: 500_107_862_016, Model: "ST500LM021", Tran: "sata"},
			},
			Online: true,
			Net:    "WiFi Home (192.168.1.23)",
		},
	}
}

func (d *Demo) sleep(ctx context.Context) error {
	select {
	case <-time.After(d.Delay):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *Demo) Probe(ctx context.Context) (Machine, error) {
	return d.Machine, d.sleep(ctx)
}

func (d *Demo) ScanWiFi(ctx context.Context) ([]string, error) {
	return []string{"Home", "Neighbor 5G", "CoffeeShop"}, d.sleep(ctx)
}

func (d *Demo) ConnectWiFi(ctx context.Context, ssid, pass string) (Machine, error) {
	if err := d.sleep(ctx); err != nil {
		return d.Machine, err
	}
	if pass == "wrong" {
		return d.Machine, errors.New("wrong password or network out of range")
	}
	d.Machine.Online = true
	d.Machine.Net = fmt.Sprintf("WiFi %s (192.168.1.23)", ssid)
	return d.Machine, nil
}

func (d *Demo) Precheck(ctx context.Context, cfg config.Config, ch Choices) error {
	return d.sleep(ctx)
}

var demoSteps = []string{
	"Partition disk", "Set up encryption", "Install packages",
	"Configure system", "Install boot loader",
}

func (d *Demo) Install(ctx context.Context, cfg config.Config, ch Choices, progress func(Step)) error {
	for _, name := range demoSteps {
		progress(Step{Name: name})
		progress(Step{Name: name, Log: "demo: " + name + " on " + ch.SystemDisk})
		if err := d.sleep(ctx); err != nil {
			return err
		}
		progress(Step{Name: name, Done: true})
	}
	return nil
}

func (d *Demo) Join(ctx context.Context, cfg config.Config, ch Choices, code func(string)) (int, error) {
	code("482 913")
	if err := d.sleep(ctx); err != nil {
		return 0, err
	}
	if err := d.sleep(ctx); err != nil {
		return 0, err
	}
	if d.Approve != nil {
		return d.Approve()
	}
	return 7, nil
}

func (d *Demo) Reboot() error { return nil }
