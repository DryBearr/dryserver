package disks

import (
	"strings"
	"testing"
)

const sample = `{"blockdevices":[
 {"name":"zram0","path":"/dev/zram0","size":8341946368,"model":null,"vendor":null,"tran":null,"rm":false,"ro":false,"type":"disk","fstype":"swap","label":"zram0","mountpoints":["[SWAP]"]},
 {"name":"nvme0n1","path":"/dev/nvme0n1","size":1000204886016,"model":"Samsung SSD 980 PRO 1TB","vendor":null,"tran":"nvme","rm":false,"ro":false,"type":"disk","fstype":null,"label":null,"mountpoints":[],"children":[
   {"name":"nvme0n1p1","path":"/dev/nvme0n1p1","size":629145600,"tran":"nvme","rm":false,"ro":false,"type":"part","fstype":"vfat","label":null,"mountpoints":["/boot/efi"]},
   {"name":"nvme0n1p3","path":"/dev/nvme0n1p3","size":997426462720,"tran":"nvme","rm":false,"ro":false,"type":"part","fstype":"btrfs","label":"fedora","mountpoints":["/sysroot","/var","/home"]}]},
 {"name":"sdb","path":"/dev/sdb","size":32015679488,"model":"Ultra Fit","vendor":"SanDisk ","tran":"usb","rm":true,"ro":false,"type":"disk","fstype":null,"label":null,"mountpoints":[null],"children":[
   {"name":"sdb1","path":"/dev/sdb1","size":32014630912,"tran":"usb","rm":true,"ro":false,"type":"part","fstype":"exfat","label":"STICK","mountpoints":["/run/media/me/STICK"]}]},
 {"name":"sdc","path":"/dev/sdc","size":500107862016,"model":"Portable SSD","vendor":"Samsung","tran":"usb","rm":false,"ro":false,"type":"disk","fstype":null,"label":null,"mountpoints":[null],"children":[
   {"name":"sdc1","path":"/dev/sdc1","size":500106813440,"tran":"usb","rm":false,"ro":false,"type":"part","fstype":"ext4","label":null,"mountpoints":["/srv/backup"]}]},
 {"name":"sdd","path":"/dev/sdd","size":0,"model":"Card Reader","vendor":"Generic","tran":"usb","rm":"1","ro":"0","type":"disk","fstype":null,"label":null,"mountpoints":[null]},
 {"name":"fd0","path":"/dev/fd0","size":4096,"model":null,"vendor":null,"tran":null,"rm":true,"ro":false,"type":"disk","fstype":null,"label":null,"mountpoints":[null]},
 {"name":"sr0","path":"/dev/sr0","size":1073741312,"model":"DVD","vendor":"HL-DT-ST","tran":"sata","rm":true,"ro":true,"type":"rom","fstype":null,"label":null,"mountpoints":[null]}
]}`

func TestParseAndFilter(t *testing.T) {
	all, err := parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 6 {
		t.Fatalf("got %d disks, want 6 (rom skipped)", len(all))
	}

	byName := map[string]Disk{}
	for _, d := range all {
		byName[d.Name] = d
	}
	if !byName["nvme0n1"].IsSystem() {
		t.Error("nvme0n1 holds /sysroot, must be system")
	}
	if !byName["zram0"].IsSystem() {
		t.Error("zram0 is swap, must be system")
	}
	if byName["sdb"].IsSystem() {
		t.Error("sdb only mounted under /run/media, must not be system")
	}
	if !byName["sdd"].Removable {
		t.Error(`rm "1" must parse as removable`)
	}
	if got := byName["sdb"].Vendor; got != "SanDisk" {
		t.Errorf("vendor not trimmed: %q", got)
	}

	usb := USB(all)
	if len(usb) != 1 || usb[0].Name != "sdb" {
		t.Fatalf("USB() = %v, want only sdb (sdc mounted at /srv, sdd empty, fd0 floppy)", names(usb))
	}
	if got := usb[0].Mounts(); len(got) != 1 || got[0] != "/run/media/me/STICK" {
		t.Errorf("Mounts() = %v", got)
	}
}

func TestHumanSize(t *testing.T) {
	for in, want := range map[uint64]string{
		512:           "512 B",
		32015679488:   "32.0 GB",
		1000204886016: "1.0 TB",
	} {
		if got := HumanSize(in); got != want {
			t.Errorf("HumanSize(%d) = %q, want %q", in, got, want)
		}
	}
}

func names(ds []Disk) []string {
	var out []string
	for _, d := range ds {
		out = append(out, d.Name)
	}
	return out
}

func TestInstallable(t *testing.T) {
	all := []Disk{
		{Name: "sda", Path: "/dev/sda", Size: 500e9, Tran: "sata"},
		{Name: "sdb", Path: "/dev/sdb", Size: 32e9, Tran: "usb", Removable: true,
			Parts: []Part{{Path: "/dev/sdb1", Label: "DRYSRV_202609", Mountpoints: []string{"/run/archiso/bootmnt"}}}},
		{Name: "mmcblk0", Path: "/dev/mmcblk0", Size: 8e9},
		{Name: "zram0", Path: "/dev/zram0", Size: 50e9},
		{Name: "nvme0n1", Path: "/dev/nvme0n1", Size: 256e9, Tran: "nvme"},
		// left mounted by a failed install attempt: still offered
		{Name: "vda", Path: "/dev/vda", Size: 21e9, Parts: []Part{
			{Path: "/dev/vda1", Mountpoints: []string{"/mnt/boot"}}, {Path: "/dev/mapper/root", Mountpoints: []string{"/mnt"}}}},
		// mounted elsewhere: not offered
		{Name: "vdb", Path: "/dev/vdb", Size: 21e9, Parts: []Part{{Path: "/dev/vdb1", Mountpoints: []string{"/run/media/x"}}}},
	}
	got := names(Installable(all))
	if strings.Join(got, " ") != "sda nvme0n1 vda" {
		t.Fatalf("Installable = %v, want [sda nvme0n1 vda] (live USB, small eMMC, zram and mounted vdb excluded)", got)
	}
}
