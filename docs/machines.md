# <img src="img/ring-5.svg" width="33" alt=""> On the machines

What the setup screen asks, what each machine gets, how its networks fit together, and what it reports.

Part of the [dryserver README](../README.md).

## The setup screen

Starts by itself after booting the USB. It shows CPU, memory, disks, whether
the laptop has a usable TPM chip, and the network. Then:

| Step | What you choose |
|---|---|
| Role | coordinator (first machine) or server |
| Hostname | empty gives `coord` or `node-xxxx` |
| Disk | internal disks only; the USB itself is never offered. Other disks can become encrypted data disks at `/data` |
| Encryption | see below |
| Disk passphrase | at least 12 characters, typed twice |
| User password | at least 10 characters, for console login and sudo (SSH uses your key) |
| Confirm | a summary of what gets erased; type `YES` |

**Encryption options** (per laptop):

- **Unlocks itself with the TPM chip** (offered when the chip and firmware
  support it). Type the passphrase **once at the first boot**; after that the
  server reboots on its own. The disk cannot be read outside this laptop, and
  a changed boot (edited kernel command line, other boot loader) makes it ask
  for the passphrase instead.
- **Passphrase at every boot**. Most secure; for laptops that leave the house.
- **Not encrypted**.

Passwords are typed on the laptop and never stored on the USB.

## What gets installed

**Always**: SSH, git, cron, tmux, htop/btop, curl, wget, rsync, jq, ripgrep,
fd, fzf, man pages, network and disk-health tools, WireGuard, `arch-audit`,
`age` (encrypts the coordinator's backups).

**Chosen in the config** (all on by default): Docker + Compose, Go, Rust
(rustup, stable toolchain), C/C++ (gcc, clang, cmake, ninja, gdb), Neovim.
Plus any Arch package under *Extra packages* (checked before the disk is
wiped, so a typo cannot leave a half-installed laptop).

**Clipboard**: Neovim and tmux on a server copy to your desktop clipboard over
SSH (OSC 52; Alacritty, kitty, WezTerm, foot and Ghostty support it). Paste
into a server with your terminal's paste key.

**Two kernels**: `linux` and `linux-lts` (the fallback, see below). pacman on
the new machine reads the Arch archive of the day the USB stick was built
(`/etc/pacman.d/mirrorlist`), so `pacman -Syu` by hand installs nothing
newer than your releases give it; the first release moves it forward. The
packages themselves come from fast mirrors at install time, that day's or
newer. A stick built by an older dryserver keeps the mirrors until the
first release. If you rebuild the stick after your last release, machines
installed from it refuse that release's older Arch day until you publish a
newer one.

### When a kernel update does not boot

On UEFI machines each kernel has its own signed boot image in
`/boot/EFI/Linux`, and its own modules, so an update of `linux` leaves
`linux-lts` untouched. A new image is first made under a name the boot loader
never starts (`arch-linux.efi.new`), checked, written to disk, and only then
renamed into place with a boot counter: `arch-linux+3.efi`. systemd-boot
takes one try off the name at each start; once the boot check passes, the
counter goes and it is `arch-linux.efi` again. After 3 failed tries the image
is passed over and `linux-lts` starts.

A boot passes when `/` is writable, the running kernel's modules are on
disk, sshd runs, the kernel found a network device, the firewall is loaded
and the WireGuard module loads (a kernel that cannot do either would leave
the machine open on the LAN, or off the mesh). Nothing else counts:
the coordinator, the mesh, the internet, a cable, a router or k3s being down
never makes a good kernel bad (a missing driver does, an unplugged cable does
not). A kernel panic restarts the machine after 10 seconds, a hang restarts
it through the hardware watchdog when it has one, emergency mode in the
initramfs (a kernel that finds no disk) restarts it after 30 seconds, and a
failed check restarts it while another image has tries left, so this needs
nobody at the machine. When nothing else is left, the machine stays up as it is.

New firmware or a new systemd rebuild every image; `linux-lts` keeps the one
it was made with (the installer's too) until `linux-lts` itself is updated,
so one bad initramfs cannot reach both kernels. While the fallback kernel
runs, or the main image failed, every update looks at each kernel's image:
one that was never made (a power cut before pacman's hook) is made again,
and the machine reboots into the main kernel. `sudo dryserver boot status`
shows the images, which one started and whether the fallback waits; `dryserver approve` shows
"running fallback kernel" or "no fallback kernel" for a machine.

Limits: two kernels that are both broken (both updated in one go, or new
firmware both need) leave the machine as it is. Machines installed before
this have no `linux-lts`: nothing is counted there, and they show "no
fallback kernel" until they are installed again. BIOS machines (GRUB) have
`linux-lts` under *Advanced options* in GRUB's menu and restart after a
panic, but someone has to pick the fallback kernel there. Pinning the boot
entry by hand (`bootctl set-default`, or `d` in the boot menu) turns the
fallback off: `bootctl set-default ""` undoes it.

## Networks

| Network | Addresses | Used for |
|---|---|---|
| Home WiFi / router | from your router, e.g. `10.1.0.x` | internet, installing, joining, your desktop |
| WireGuard mesh | `10.66.0.N` | encrypted traffic between servers, names like `node-a` |
| Switch (optional) | `172.16.66.N` | carries the WireGuard traffic when servers are cabled |

- **Switch when plugged in (auto)**: one Ethernet port per laptop gets a fixed
  switch address. Servers that reach each other on the switch use it; the
  others use WiFi. The switch can be isolated (not connected to the router)
  or connected to it; no setting needed.
- **WiFi/router network only**: WireGuard always goes over the router.

Where WireGuard sends its packets is never taken from the coordinator's
list alone (the registry account keeps it, see [Security](security.md)):
servers find the coordinator at the address in their own config
(`COORD_LAN_IP`), or at its switch address when a ping there answers; the
coordinator names no address for anyone and answers each server where its
packets come from. Between two servers, the address each one reports is
tried until their link is up; from then on the link stays where it works,
and the switch is used whenever a ping over it answers.

## Health reports

With every sync, once a minute, each machine tells the coordinator how it
is: its dryserver and k3s versions, the running kernel and whether a newer
one waits for a reboot, when it was last fully upgraded (`pacman -Syu`),
uptime, load, memory, root disk, its hottest temperature sensor, whether
k3s runs and the firewall is loaded, when it last shook hands with
each WireGuard peer, which release it runs and how its update stands, and
whether it booted the fallback kernel (`boot`). `dryserver approve` shows it under each member:
problems in red (a disk or memory 90% full, 85 °C, k3s or the firewall
down, a reboot due, a clock more than two minutes off, no upgrade for 30
days, a peer silent for five minutes, the fallback kernel running, missing
or broken). `i` shows everything about the
selected machine.

It is each machine's own word, relayed by the coordinator. A machine that
lies, or was broken into, can only change its own line: the coordinator
and the desktop both check every field, and nothing in a report names
another machine. Reports go to your desktop only; no server sees another
one's report. A machine with an older dryserver sends none.

Each server signs its report (its release, how its update stands, its
LAN address, when) with its own SSH host key, as the registry account
relays it. Root on the coordinator checks the signature with the key in
the list you signed before the rollout takes a server for updated, and
takes none older than one it took before; your desktop checks it too and
does not show a report that fails. A server of an older version signs
nothing: its report is shown as "Unsigned report" and taken as before,
until it runs a release that signs (from the release the coordinator ran
when it first checked, `/etc/dryserver/signed-reports.json`). Your
desktop takes no unsigned report again from a machine that signed one.
