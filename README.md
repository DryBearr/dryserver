# dryserver

**Turn old laptops into a private, encrypted server cluster with one USB stick.**

dryserver builds an Arch Linux installer USB on your desktop. Plug it into a
laptop and boot: a setup screen asks a few questions, you type `YES`, and the
laptop is wiped, gets an encrypted Arch install with your dev tools, and asks
to join a WireGuard mesh with your other servers. Nothing joins without your
approval.

![license: MIT](https://img.shields.io/badge/license-MIT-blue)
![rust](https://img.shields.io/badge/rust-1.88%2B-B7410E)
![arch linux](https://img.shields.io/badge/installs-Arch%20Linux-1793D1)

> **Status: early.** Tested end to end in QEMU virtual machines (UEFI with a
> TPM chip, legacy BIOS, a shared switch network, three servers). Not yet
> tested on real laptops and real WiFi. Installing **erases the laptop's disk**.

## Contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [The setup screen](#the-setup-screen)
- [What gets installed](#what-gets-installed)
- [Networks](#networks)
- [SSH between machines](#ssh-between-machines)
- [Kill switch](#kill-switch)
- [Security](#security)
- [Commands](#commands)
- [FAQ](#faq)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [License](#license)

## How it works

```
  your desktop                         home router (WiFi)
  ./dryserver  ── build + flash ──►  USB stick       │  internet, setup, joining
                                       │ boot         │
                     ┌─────────────────┼──────────────┤
                     ▼                 ▼              ▼
                 coord (1st)        node-a          node-b      laptops
                 10.66.0.1         10.66.0.2       10.66.0.3    (WireGuard mesh)
                     └──────────── switch (optional) ────┘
```

1. **Desktop**: a menu to fill in the config, build the installer ISO and
   flash it to a USB stick.
2. **First laptop**: install it as the **coordinator**. It keeps the list of
   servers and hands it out. It cannot let anyone in by itself, and it does
   not route traffic.
3. **Other laptops**: install them as **servers**. Each one shows a 6-digit
   pairing code; you approve it on your desktop (`./dryserver approve`) if
   the code matches. Your desktop signs the list of machines; servers accept
   only what you signed.
4. All servers talk to each other directly over WireGuard, by name
   (`ssh node-a`, `ping node-b`), over a switch when cabled or else over WiFi.

## Requirements

**Desktop (to build and flash)**
- Linux with `podman` (the ISO is built inside an Arch Linux container)
- Rust 1.88 or newer (`cargo`), `make`, `ssh-keygen`, `lsblk`. The binary
  must be static: `make` builds it for musl, with the local
  `x86_64-unknown-linux-musl` target if installed, else inside a Rust Alpine
  container (podman)
- About 5 GB free disk space; `sudo` only for writing the USB stick

**Laptops (to become servers)**
- 64-bit x86, UEFI or legacy BIOS
- **Secure Boot turned off** in the firmware settings
- A disk of at least 16 GB (it will be erased), 2 GB RAM or more
- Internet over WiFi or an Ethernet cable to the router
- Optional: a TPM 2.0 chip (most laptops from about 2016 on) for disks that
  unlock by themselves; an Ethernet port for the switch

**Network**
- A free address on your home network for the coordinator, reserved in the
  router (see [FAQ](#which-ip-do-i-use-for-the-coordinator))

## Quick start

```sh
git clone https://github.com/DryBearr/dryserver && cd dryserver
make                 # builds ./dryserver
./dryserver          # menu: 1 config, 2 build ISO   (no sudo)
sudo ./dryserver     # menu: 3 flash USB             (writing to a USB drive needs root)
```

1. **Config**: WiFi, coordinator LAN IP, mesh settings, tools, admin username
   and SSH public key. To copy your key run `wl-copy < ~/.ssh/id_ed25519.pub`
   (or `cat` it and copy the line) and paste it with Ctrl+Shift+V. The email at
   the end of the key is removed; a short label like `desktop` is used instead.
2. **Build installer ISO**: about 6 minutes (the first build downloads ~1 GB).
3. **Flash USB**: only USB drives are listed; type the device name to confirm.
   The image is read back and verified.
4. **First laptop**: boot from the USB (boot menu key is usually F12, F9, F2
   or Esc) and choose **coordinator**.
5. In your router, **reserve the coordinator's IP** (the device named `coord`),
   then reboot the coordinator once.
6. **Desktop**: run `./dryserver approve` once and press `S` to sign the
   coordinator, if it shows the same code as the coordinator's screen. From
   now on servers accept only the machines you approve here.
7. **Other laptops**: boot the same USB and choose **server**. When the code
   appears on the laptop, find the machine in `./dryserver approve` on your
   desktop and press `a` if the code matches.
8. **Desktop**: `./dryserver ssh-config`, then `ssh coord` or `ssh node-xxxx`.

Try the laptop setup screen without touching anything: `./dryserver install --demo`.

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
fd, fzf, man pages, network and disk-health tools, WireGuard, `arch-audit`.

**Chosen in the config** (all on by default): Docker + Compose, Go, Rust
(rustup, stable toolchain), C/C++ (gcc, clang, cmake, ninja, gdb), Neovim.
Plus any Arch package under *Extra packages* (checked before the disk is
wiped, so a typo cannot leave a half-installed laptop).

**Clipboard**: Neovim and tmux on a server copy to your desktop clipboard over
SSH (OSC 52; Alacritty, kitty, WezTerm, foot and Ghostty support it). Paste
into a server with your terminal's paste key.

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

## SSH between machines

No private keys are stored on servers, and your desktop key is never forwarded
to them. A hacked server, the coordinator included, cannot use your key to log
into the others. Connect to each server from the desktop:

```sh
./dryserver ssh-config     # writes ~/.ssh/config.d/dryserver
ssh node-a                 # jumps through the coordinator
scp -3 node-a:file node-b: # copy between servers through the desktop
```

Add `Include config.d/*` at the top of `~/.ssh/config` if it is not there.
Servers refuse agent forwarding even if you ask for it with `ssh -A`.

`ssh-config` also writes `<name>.lan` entries, for example `ssh node-a.lan`:
straight to the server's WiFi/router address, not through the coordinator,
checked against the same pinned host key. The kill switch uses them.

## Kill switch

If you think the coordinator is hacked, cut it off from every server:

```sh
./dryserver quarantine-all     # on the desktop
```

It connects to each server over the WiFi/router network (the `.lan` entries),
never through the coordinator, and runs `sudo dryserver quarantine` there
(sudo asks for your password on each one). On each server that:

- removes the coordinator from WireGuard,
- drops all traffic from and to its mesh, switch and WiFi/router addresses,
  also connections that are already open,
- pauses sync and join, so the coordinator cannot push anything,
- stays in place after a reboot.

The servers keep running and keep talking to each other. Then:

1. delete the tunnel in the Cloudflare dashboard, if you use one,
2. power off the coordinator and keep its disk for investigation,
3. reinstall it from the USB stick.

`quarantine` also prints the WireGuard peers each server keeps. A hacked
coordinator may have added its own; cut any you do not know by name:
`./dryserver quarantine-all -name rogue`. The same works for a hacked server:
it is cut off on all the others.

| Command | What it does |
|---|---|
| `./dryserver quarantine-all` | desktop: cut the coordinator off on every server |
| `./dryserver quarantine-all -name a,b` | desktop: cut members a and b off on every other server |
| `./dryserver quarantine-all -status` / `-lift` | desktop: show or undo on every server |
| `sudo dryserver quarantine [-name a,b]` | on one server |
| `sudo dryserver quarantine -status` / `-lift` | on one server |

Run `./dryserver ssh-config` again after adding servers, while the
coordinator is still trusted: `quarantine-all` only reaches servers in that
list. Give servers a fixed address in your router (DHCP reservation), so the
`.lan` entries stay right.

Limits for now:

- `-lift` is for a false alarm. After reinstalling the coordinator its keys
  are new, and servers have to be paired with it again (not automated yet).
- Servers installed by an older dryserver keep the cut over a reboot only for
  WireGuard and sync; run `quarantine` again after a reboot to block the
  addresses too, or reinstall them.
- The coordinator's IPv6 addresses on the WiFi/router network are not
  blocked. WireGuard is cut, and SSH still needs your key.

## Security

- **Firewall first.** The live USB accepts no incoming connections and runs no
  SSH server. Servers drop all incoming traffic except:
  - from WiFi/router: SSH and WireGuard
  - from the switch: WireGuard only
  - over the mesh: SSH, ping and the ports you list in *Extra ports* (`MESH_PORTS`)

  Docker publishes container ports on `127.0.0.1` unless you give an address.
- **SSH**: key login only, no root login, `MaxAuthTries 3`, rate limited.
- **Accounts**: root is locked; sudo asks for your password.
- **Disk encryption**: LUKS2 with argon2id; TPM unlock bound to the signed
  kernel image, Secure Boot state and kernel command line; no disk swap
  (zram only).
- **Joining**: needs your approval on your desktop with a matching pairing
  code. The code covers both machines' keys, so a fake coordinator or a
  swapped request shows a different code. A new machine joins only when it
  finds itself, with its own keys, in a list you signed. After approval, the
  member list is only served over the mesh. Removing a machine (`d` in
  `./dryserver approve`) drops it from all servers within a minute.
- **Unknown devices**: the coordinator scans its networks every 15 minutes and
  lists unknown devices in `./dryserver approve` (report only).
- **Hardening**: kernel sysctl hardening, no LLMNR/mDNS, WireGuard peers
  locked to their own mesh address.
- **Nothing from the coordinator is used unchecked.** Servers check every
  name, key and address in the member list before it reaches `/etc/hosts`,
  WireGuard or the SSH trust files, and drop entries that are malformed or
  appear twice.
- **Signed member list**: building the USB stick creates
  `secrets/signing_ed25519` on your computer; its public half is installed
  on every server. `./dryserver approve` on your computer signs every
  decision (approve, reject, remove) with it. The coordinator stores and
  hands out the signed list but cannot make or change one. Servers use only
  the machines in the signed list: one the coordinator adds by itself is
  ignored and logged, and an older list is refused, so a removed machine
  cannot be brought back. Nobody can approve on a server, the coordinator
  included, and a machine that shows up on the coordinator without a join
  request cannot be signed at all. `./dryserver ssh-config` takes server
  names and SSH host keys from the signed list too. Limit: a hacked
  coordinator can hold back a newer list from servers that have not seen it
  yet, so a removal may not arrive; cut the machine off with
  `./dryserver quarantine-all -name NAME` then.
- **The USB stick** holds the WiFi password and the key that lets machines ask
  to join. Keep it safe, or re-flash it after installing.

## Commands

On your desktop:

| Command | What it does |
|---|---|
| `./dryserver` | menu: config, build, flash |
| `./dryserver build` | build the ISO, log to stdout |
| `./dryserver disks` | list disks and which ones may be flashed |
| `sudo ./dryserver flash --iso FILE` | flash any image to a USB drive |
| `./dryserver approve` | approve, reject or remove machines and see unknown devices; every decision is signed |
| `./dryserver ssh-config` | SSH config for all servers |
| `./dryserver quarantine-all` | kill switch: cut the coordinator off on every server |
| `./dryserver install --demo` | try the laptop setup screen; changes nothing |

On servers:

| Command | What it does |
|---|---|
| `sudo dryserver tpm-enroll` | let the TPM unlock the disk again (after a firmware change) |
| `sudo dryserver quarantine` | kill switch on this server (`-name`, `-status`, `-lift`) |
| `dryserver sync`, `join`, `scan`, `registry` | run automatically by systemd, cron and SSH |

## FAQ

### What is the coordinator?
The first laptop you install. New servers ask it to join, and every server
fetches the member list from it once a minute. You approve machines on your
desktop, which signs the list; the coordinator only stores and hands it out.
Traffic between servers does not go through it.

### Which IP do I use for the coordinator?
A free address on your home network. Run `ip -br addr` on your desktop: if it
shows `10.1.0.195/24`, your network is `10.1.0.x`, so pick something like
`10.1.0.60`. After installing the coordinator, reserve that address for the
device `coord` in your router's DHCP settings.

### Why WireGuard?
Encrypted traffic between servers even on your home WiFi, a real identity per
server (nobody can pretend to be `node-a`), addresses that never change, and a
way to open services to your servers only. WireGuard works at layer 3 (IP): it
carries normal traffic like SSH, web and databases, but not network broadcasts,
which servers do not need.

### What are "Extra ports open inside the mesh"?
Ports your servers may use on each other, e.g. `8080/tcp` for a web app on
one server that the others need. They are never opened to WiFi. Leave empty
if unsure: only SSH and ping work between servers then.

### Does the switch need to be connected to the router?
No. Internet stays on WiFi; the switch only carries traffic between servers.

### Why does flashing need sudo?
Only root may write a whole disk. Config and build run as your normal user.

### What if I forget the disk passphrase?
The data is gone; that is what encryption means. With TPM unlock the server
keeps booting on its own, but keep the passphrase somewhere safe for when the
TPM refuses (firmware update, changed boot settings).

## Troubleshooting

| Problem | What to do |
|---|---|
| Laptop does not boot the USB | turn Secure Boot off; use the boot menu key (F12, F9, F2 or Esc) |
| Setup shows no disk | in the BIOS setup, set the storage/SATA mode from RAID or Intel RST to AHCI (turn off VMD if listed) |
| Setup fails | press `q` for a shell; the full log is in `/tmp/dryserver-install.log`. Old LVM, RAID, swap or encrypted volumes on the disk are released automatically |
| New server cannot reach the coordinator | coordinator switched on? IP reserved in the router and matching the config? same WiFi? The server keeps retrying and shows its code on the login screen |
| TPM laptop asks for the passphrase at boot | firmware or boot settings changed: type the passphrase, then `sudo dryserver tpm-enroll` |
| `ssh node-a` asks for a password or fails | run `./dryserver ssh-config` again; check `Include config.d/*` in `~/.ssh/config` |

## Development

```sh
make test                           # unit tests (cargo test)
test/validate-sysconf.sh            # check generated firewall/SSH/sudo files with real nft and sshd
test/live-quarantine.sh             # kill switch with real WireGuard and nftables, in private namespaces
test/live-approve.sh                # signed approval: the real screen against a real sshd and registry
test/qemu.sh coord                  # boot out/dryserver.iso in a UEFI VM with a blank disk
BIOS=1 test/qemu.sh node            # legacy BIOS
TPM=1 OVMF_CODE=... test/qemu.sh    # TPM tests need firmware that measures boot (Arch's edk2-ovmf)
SWITCH=1 SSH_PORT=2201 ...          # shared switch NIC between VMs, SSH on localhost:2201
```

Layout: `src/main.rs` (CLI), `src/tui` (screens), `src/install`
(installer), `src/sysconf.rs` (generated system files), `src/registry.rs`
and `src/node.rs` (joining and sync), `src/mesh.rs` (WireGuard and SSH
config), `src/quarantine.rs` (kill switch), `src/signed.rs` and
`src/admin.rs` (signed member list and approval from the desktop), `assets/` (files embedded into the ISO and servers by `build.rs`).
Golden files for the generated system files are in `testdata/sysconf`;
`UPDATE_GOLDEN=1 cargo test` rewrites them.

| Path | What |
|---|---|
| `config.env` | your settings, contains the WiFi password; not committed |
| `secrets/registry_ed25519` | key machines use to ask to join; not committed |
| `secrets/signing_ed25519` | key that signs the list of machines in your swarm; created by the first build, never leaves this computer, not committed. **Back it up.** Only `signing_ed25519.pub` goes onto the USB stick and the servers |
| `out/dryserver.iso`, `out/build.log` | built installer image and its log |

## License

[MIT](LICENSE)
