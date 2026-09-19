# dryserver

Turn old laptops into servers. dryserver builds an Arch Linux installer USB.
Plug it into a laptop and boot: a setup screen asks a few questions, you type
`YES`, and the laptop is wiped, gets an encrypted Arch install with your tools,
and asks to join a WireGuard mesh with your other servers. Nothing joins
without your approval.

## Quick start

```sh
make                 # builds ./dryserver
./dryserver          # desktop menu: 1 config, 2 build ISO
sudo ./dryserver     # 3 flash USB (writing to a USB drive needs root)
```

1. **Config** (desktop menu): WiFi, coordinator LAN IP, mesh settings, tools,
   your admin username and SSH public key (paste the output of
   `cat ~/.ssh/id_ed25519.pub`; the email at its end is removed and a short
   label like `desktop` is used instead). Saved to `config.env`.
2. **Build installer ISO**: about 6 minutes (the first build downloads ~1 GB).
3. **Flash USB**: only USB drives are listed; type the device name to confirm.
4. Reserve an IP for the first laptop in your router (the coordinator), e.g.
   `192.168.1.50`, the same address as in the config.
5. Boot the **first laptop** from the USB and choose *coordinator*.
6. Boot every **other laptop** from the USB and choose *server*. At the end it
   shows a 6-digit code. On the coordinator run `sudo dryserver approve` and
   approve the machine if it shows the same code.
7. On the desktop: `./dryserver ssh-config`, then `ssh <server-name>`.

## The setup screen (on the laptop)

Starts by itself after booting the USB. It shows CPU, memory, disks, whether
the laptop has a TPM chip, and the network. Then:

- **Role**: coordinator (first machine) or server.
- **Hostname**: empty gives `coord` or `node-xxxx`.
- **Disk**: internal disks only; the USB itself is never offered. Other disks
  can be added as encrypted data disks at `/data`.
- **Encryption**, per machine:
  - *Unlocks itself with the TPM chip* (offered when the chip and firmware
    support it): type the passphrase once at the first boot; after that the
    server reboots on its own. The disk is unreadable outside this laptop, and
    a changed boot (edited kernel command line, other boot loader) makes it
    ask for the passphrase again.
  - *Passphrase at every boot*: most secure; for laptops that leave the house.
  - *Not encrypted*.
- **Disk passphrase** and **user password** (console login and sudo), typed
  on the laptop. Nothing secret about the machine is stored on the USB.
- Checks, a summary, and `YES` to erase and install.

## What gets installed

Always: SSH, git, cron, tmux, htop/btop, curl, wget, rsync, jq, ripgrep, fd,
fzf, man pages, network and disk-health tools, WireGuard, `arch-audit`.

Pick in the config (all on by default): Docker + Compose, Go, Rust (rustup),
C/C++ (gcc, clang, cmake, ninja, gdb), Neovim. Plus any "Extra packages".

Neovim and tmux copy to your desktop clipboard over SSH (OSC 52; Alacritty,
kitty, WezTerm, foot and Ghostty support it). Paste into a server with your
terminal's paste key.

## Networks

- WiFi (or a cable to the router) carries internet and setup.
- WireGuard traffic between servers, set in the config:
  - **Switch when plugged in (auto)**: one Ethernet port gets a fixed address
    from `SWITCH_SUBNET` (server `10.66.0.N` gets `172.16.66.N`). Servers that
    reach each other on the switch use it; others use WiFi/router. The switch
    may be isolated or connected to the router.
  - **WiFi/router network only**.
- Servers find each other by name: `ping node-3a2f`, `ssh coord`.

## SSH between machines

No private keys are stored on servers. Your desktop key is forwarded:

```sh
./dryserver ssh-config     # writes ~/.ssh/config.d/dryserver
ssh node-3a2f              # goes through the coordinator
ssh -A node-3a2f           # then on it: ssh node-7b1c
```

Add `Include config.d/*` at the top of `~/.ssh/config` if it is not there.
Tip: `ssh-add -c` asks you before each use of the forwarded key.

## Security

- **Firewall first**: the live USB accepts no incoming connections and runs no
  SSH server. Servers drop all incoming traffic except SSH and WireGuard from
  WiFi/router, WireGuard only from the switch, and SSH plus `MESH_PORTS` over
  the mesh. Docker publishes ports on `127.0.0.1` unless you give an address.
- **SSH**: key login only, no root login, `MaxAuthTries 3`, rate limited.
- **Accounts**: root is locked; sudo asks for your password.
- **Joining**: a new machine needs your approval with a matching pairing code.
  The code covers both machines' keys, so a fake coordinator or a swapped
  request shows a different code. After approval, the member list is only
  served over the mesh. `d` in `dryserver approve` removes a machine; others
  drop it within a minute.
- **Unknown devices**: the coordinator scans its networks every 15 minutes
  and lists unknown devices in `dryserver approve` (report only).
- **Kernel/network hardening**: sysctl hardening, no LLMNR/mDNS, zram instead
  of disk swap.
- **The USB stick** holds the WiFi password and the key that lets machines ask
  to join. Keep it safe.

## Commands

Desktop:

| Command | What |
|---|---|
| `dryserver` | menu: config, build, flash |
| `dryserver build` | build the ISO, log to stdout |
| `dryserver disks` | show disks and which ones may be flashed |
| `sudo dryserver flash --iso FILE` | flash any image |
| `dryserver ssh-config` | SSH config for all servers |
| `dryserver install --demo` | try the laptop setup screen, changes nothing |

Servers:

| Command | What |
|---|---|
| `sudo dryserver approve` | coordinator: approve, reject, remove machines |
| `sudo dryserver tpm-enroll` | let the TPM unlock again (after a firmware change) |
| `dryserver sync`, `join`, `scan`, `registry` | run by systemd, cron and SSH |

## Testing in VMs

```sh
test/qemu.sh coord                  # UEFI VM with a blank disk
BIOS=1 test/qemu.sh node            # legacy BIOS
TPM=1 OVMF_CODE=... test/qemu.sh    # TPM (needs firmware that measures boot)
SWITCH=1 SSH_PORT=2201 ...          # shared switch NIC, SSH on localhost:2201
test/validate-sysconf.sh            # check firewall/SSH/sudo files with nft/sshd
```

## Files

| Path | What |
|---|---|
| `config.env` | Your settings. Contains the WiFi password. Not committed. |
| `secrets/registry_ed25519` | Key machines use to ask to join. Not committed. |
| `out/dryserver.iso` | Built installer image |
| `out/build.log` | Full log of the last build |
