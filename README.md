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
- [Apps](#apps)
- [Backups](#backups)
- [Updates](#updates)
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
5. On top of that mesh they form one k3s cluster. You hand it apps from your
   desktop (`./dryserver apps`); it decides where they run.

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
shows the images, which one started and whether the fallback waits; `./dryserver approve` shows
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
list alone (the registry account keeps it, see [Security](#security)):
servers find the coordinator at the address in their own config
(`COORD_LAN_IP`), or at its switch address when a ping there answers; the
coordinator names no address for anyone and answers each server where its
packets come from. Between two servers, the address each one reports is
tried until their link is up; from then on the link stays where it works,
and the switch is used whenever a ping over it answers.

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

Host keys are checked against `~/.ssh/known_hosts.d/dryserver` alone, which
holds the keys from the list you signed, and a server with any other key
is refused. A key you once accepted in `~/.ssh/known_hosts` (say of an old
coordinator at the same address) never counts. After a machine is
reinstalled and approved, run `./dryserver ssh-config` again.

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
- stops k3s and every container on that server: the coordinator runs the
  cluster's control plane, and what it started there is not trusted,
- stays in place after a reboot.

The servers keep running and keep talking to each other. Your apps are down
until you lift the cut. Then:

1. delete the tunnel in the Cloudflare dashboard, if you use one,
2. power off the coordinator and keep its disk for investigation,
3. reinstall it from the USB stick, as coordinator, at the same address,
4. `./dryserver approve`: it says the machine there has another SSH key.
   Press `N`, compare the code with the new coordinator's screen, confirm.
   Your desktop signs a new list with the new coordinator in the old one's
   place; every machine you signed before stays in it,
5. `./dryserver quarantine-all -lift`: each server reads the signed list
   from the coordinator's address, takes the new coordinator's keys from it
   and follows it. The old coordinator stays out.
6. `./dryserver ssh-config`, once the servers have synced with the new
   coordinator: `ssh coord` checks its new key from then on.

A server lifts its quarantine only onto a coordinator that serves a list you
signed, which holds that server and is not older than the newest one your
desktop signed (`-lift` passes its version, from
`secrets/members.signed.json`) or one the server has seen. The coordinator
it cut off comes back only with `-lift -same`: whoever kept the keys of the
old coordinator can still hand out the lists you signed for it, and answer
at its address. Whatever else answers there, the quarantine stays.
The new coordinator must also carry the proof from your USB stick, so a
machine that was not installed from it cannot take the coordinator's place.
A server that was switched off during all this runs
`sudo dryserver quarantine -lift` once to follow the new coordinator.

After a false alarm (the coordinator was not reinstalled):
`./dryserver quarantine-all -lift -same`. Do that only when you are sure.

`quarantine` also prints the WireGuard peers each server keeps. A hacked
coordinator may have added its own; cut any you do not know by name:
`./dryserver quarantine-all -name rogue`. The same works for a hacked server:
it is cut off on all the others.

| Command | What it does |
|---|---|
| `./dryserver quarantine-all` | desktop: cut the coordinator off on every server |
| `./dryserver quarantine-all -name a,b` | desktop: cut members a and b off on every other server |
| `./dryserver quarantine-all -status` / `-lift` | desktop: show or undo on every server |
| `./dryserver quarantine-all -lift -same` | desktop: undo after a false alarm, trusting the same coordinator again |
| `sudo dryserver quarantine [-name a,b]` | on one server |
| `sudo dryserver quarantine -status` / `-lift [-same]` | on one server |

Run `./dryserver ssh-config` again after adding servers, while the
coordinator is still trusted: `quarantine-all` only reaches servers in that
list. Give servers a fixed address in your router (DHCP reservation), so the
`.lan` entries stay right.

Limits for now:

- The coordinator runs the control plane of your cluster. Whoever takes it
  over can start containers with full rights on every server, until you cut
  it off. The cut stops them, but they may have changed the servers before.
  After a real break-in (not a false alarm), reinstall the servers too.
- A server that ran a copy of the Cloudflare Tunnel knows the tunnel's
  token. After you cut off or removed a server you do not trust, make a new
  token in the Cloudflare dashboard, save it and press `o` in
  `./dryserver outside`.
- After a false alarm, `-lift -same` trusts the same machine again, with
  whatever was done to it.
- Servers on an older dryserver do not know `-same` and `-min-version`
  (`quarantine-all -lift` passes them): lift there by hand with
  `sudo dryserver quarantine -lift`.
- The coordinator's IPv6 addresses on the WiFi/router network are not
  blocked. WireGuard is cut, and SSH still needs your key.

## Apps

Your servers run as one k3s cluster over the mesh: the control plane on the
coordinator, an agent on every server. It needs no setup. A server joins the
cluster by itself once you approved it, and leaves it when you remove it.
You give the cluster an app; it picks a server, and moves the app when that
server dies. Apps never run on the coordinator.

When a server loses power, an app with one copy is back on another server
after about a minute and a half (40 seconds until the cluster calls the
server dead, 30 more until it moves the app). With two copies the app keeps
answering; for the first 45 seconds about every second request still goes to
the dead copy and fails.

```sh
./dryserver apps           # or "Apps" in the menu
```

`n` starts an app from a container image: a name (it starts with a letter),
the image, the port it listens on, and, if it should be reachable from outside, a public host name.
The screen shows what runs on which server; `d` removes an app; `o` goes to
the ways in from outside. Under it is plain Kubernetes: on the coordinator,
`k3s kubectl` works for you without sudo.

The screen never waits for the coordinator: every question and change runs
in the background with a time limit (15 seconds for a look, a minute for a
change), and the screen says when the coordinator does not answer. Both
screens share one SSH connection, which ends by itself 20 seconds after the
last call. Its socket lives in `dryserver/` in your runtime directory
(`$XDG_RUNTIME_DIR`), made for you alone; when that directory is a link,
someone else's or open to others, nothing is shared and each call connects
by itself. Switching between the two screens (`o`, `a`) waits until a
change that runs (a deploy and its DNS sync) is done.

What dryserver sets up around every app (namespace `apps`):

- nothing reaches an app unless allowed; an app takes connections on its
  port from the ingress and from your other apps,
- an app reaches your other apps, DNS and the internet, and nothing else:
  not the cluster's own services, not the machines,
- an app cannot send raw packets, so it cannot pose as another address on
  the pod network,
- the cluster's DNS runs as two copies on different machines, on servers
  rather than on the coordinator once there are two servers, so apps and
  the tunnel keep finding each other when one machine is off, the
  coordinator included,
- a public host name makes the built-in ingress (Traefik) route that name to
  the app. The ingress has no port on any machine: what comes in from
  outside reaches it through a tunnel that runs inside the cluster. It runs
  on every machine, so it does not go down with one server,
- containers cannot gain privileges and get no cluster credentials,
- the firewall on every machine is a wall around all pods: web out, never
  your home network, never SSH on the machines; a NodePort or hostPort is
  not a door from the mesh or the home network,
- no machine is a router into the cluster: what arrives from the home
  network, the switch or the mesh is never passed on to pods elsewhere,
- servers join the cluster with a token that is for agents only. It does
  not open the control plane, and only the server it was sealed for can
  read it (see [Security](#security)).

k3s is one pinned release, downloaded from its GitHub releases when the USB
stick is built and checked against the checksum dryserver was built with.

### Reaching apps from outside

No machine opens a port to the internet. What comes in arrives through an
entrance, and the Outside screen shows them all, how each is doing and
which host names come in through it:

```sh
./dryserver outside        # or "Outside" in the menu, or o on the apps screen
```

- **Cloudflare Tunnel**: two pods in the cluster dial out to Cloudflare,
  which sends what arrives for your host names through them to the ingress.
- **Your VPS**: not built yet. A server you rent will relay web and game
  ports (TCP and UDP) to the cluster over WireGuard.

Each public host name belongs to one app and comes in through one entrance.
The choice is stored on the app's Ingress as the annotation
`dryserver/entrance`; an Ingress without it comes in through Cloudflare, so
apps started before there was a choice keep working. The apps form asks
for it only when more than one entrance is set up. A host name that
another app already has is refused; one that two apps claim anyway (made
with kubectl) is served by neither, and the Outside screen says so.

The Cloudflare Tunnel can be set up two ways: from your computer with one
API token, or by hand in the dashboard.

#### Cloudflare from your computer

With one API token, dryserver sets up the rest: no more visits to the
dashboard.

1. In the Cloudflare dashboard, My Profile, API Tokens, Create Token,
   Create Custom Token. Give it these permissions:

   | Scope | Item | Access |
   |---|---|---|
   | Account | Cloudflare Tunnel | Edit |
   | Zone | DNS | Edit |
   | Zone | Zone | Read |

   Under Account Resources pick your account, under Zone Resources the
   zone (domain) your apps' host names are in. Newer dashboards call Edit
   "Write". Expiry and an IP filter (your home address) are a good idea.
2. Save the token on your computer as `secrets/cloudflare_api_token` and
   make it yours alone: `chmod 600 secrets/cloudflare_api_token`. dryserver
   refuses it while other users can read it.
3. In `./dryserver outside` press `s` on the Cloudflare Tunnel. It lists
   every change it would make, in order (`↑↓` scrolls a long list): a
   token it replaces and a tunnel it switches the cluster to are named as
   such. `y` makes exactly those; when something changed since the look,
   it makes none and says so.

What `s` does, every time, so running it again changes nothing and a run
cut off half way is finished by the next one:

- checks the token (a revoked or expired one is named as such), finds the
  zone of each host name (only names inside a zone the token can see are
  routed) and the account,
- makes or reuses the tunnel `dryserver`, configured in Cloudflare.
  Deleted in the dashboard, it is made again,
- saves its token as `secrets/cloudflare_tunnel_token` (for you only) and
  starts the tunnel in the cluster with it, as `o` does,
- routes each host name that comes in through Cloudflare to the ingress,
  sorted, and answers 404 for anything else,
- adds a proxied CNAME `<host> -> <tunnel id>.cfargotunnel.com` per name,
  with the comment `managed by dryserver`, and deletes the ones whose app
  is gone.

dryserver only ever changes or deletes DNS records that carry that comment
and point at a dryserver tunnel of your account. A record of the same name
that points elsewhere (your home IP, another service) is shown as held by
something else (every record there is named) and left alone. `t` takes
the name over: like `s`, it lists every change first and asks. A single
CNAME is changed into dryserver's in place, so the name keeps resolving.
Other records are deleted first and dryserver's CNAME is added right
after: a CNAME shares its name with no other record, so the name does not
resolve for that moment, and the list says so. When a call is refused, the message names the
permission the token lacks. When Cloudflare is down, nothing is changed and
the running tunnel keeps working. With the API token saved, starting or
removing an app with a Cloudflare host name syncs by itself, but only while
the cluster runs the tunnel `dryserver`: a name pointed at a tunnel that no
connector serves answers every visitor with Cloudflare's error 1033. While
the tunnel is closed (`x`) or one you set up by hand runs, that sync changes
nothing in Cloudflare and the apps screen says why; `s` sets it up.

Without an API token, the way by hand below keeps working. Coming from it:
a sync after an app changed never touches Cloudflare, the token of the
tunnel you made in the dashboard, the cluster or
`secrets/cloudflare_tunnel_token`. `s` says that it would switch to the
tunnel `dryserver`, and does on `y`; the names you pointed at your own
tunnel in the dashboard show as held by something else until you take them
over with `t`.

#### Cloudflare by hand

1. In the Cloudflare dashboard (Zero Trust, Networks, Tunnels) create a
   tunnel and copy its token. Save it on your computer as
   `secrets/cloudflare_tunnel_token` (the whole
   `cloudflared service install ...` line works too).
2. In `./dryserver outside` press `o`. The tunnel's line shows how many
   copies hold a connection to Cloudflare.
3. In the dashboard, add a public host name per app and point each at
   `http://traefik.kube-system.svc.cluster.local:80`. The ingress then
   routes by the host name you gave the app.

`x` closes the tunnel (it names the apps that still come in through it);
the apps keep running, reachable only inside the cluster. `o` again after
you changed the token file gives the tunnel the new token.

#### The tunnel in the cluster

The token is stored in the cluster as an encrypted secret. The tunnel
pods run as a plain user with a read-only file system, no privileges and no
cluster credentials, from one cloudflared image pinned by its digest.
Nothing in the cluster may connect to them, and they may connect only to
Cloudflare, DNS and the ingress.

### When a machine leaves

Remove a server in `./dryserver approve` and the cluster follows: the
coordinator deletes it from the cluster, and its apps start on the servers
that are left. The removed server stops k3s and every container as soon as
it sees the signed list without itself (it asks the coordinator on the home
network when the mesh no longer answers). From then on every sync checks
that nothing of k3s is left on it (its token, k3s.service, processes in its
cgroups, pods' mounts) and stops it again if something is, until nothing
is: a stop that timed out or a k3s started again by hand does not stay.
That needs the record the leave writes first (`/etc/dryserver/left`, when
and why; the next approval removes it): a server whose
`/etc/dryserver/join.json` is lost or damaged stops nothing, and its sync
says so every minute.
A server that only lost contact
keeps its apps running. To bring a removed server back, run
`sudo dryserver join` on it and approve it like a new machine. A machine
installed again under a name the cluster knows takes that name over: the
coordinator forgets the old machine first.

A removed server still knows the cluster token it joined with. If you do
not trust it, make a new token (below).

### A new cluster token

The token servers join the cluster with is made from the secret in
`/etc/rancher/k3s/agent-token` on the coordinator. Make a new one when you
removed a server you do not trust, or when your cluster is older than
sealed tokens (the registry account could read the token then, see
[Security](#security)). On the coordinator:

```sh
sudo sh -c 'umask 077; head -c 32 /dev/urandom | sha256sum | cut -d" " -f1 > /etc/rancher/k3s/agent-token'
sudo systemctl restart k3s
```

k3s writes the new token to `/var/lib/rancher/k3s/server/agent-token`;
within a minute the coordinator's sync seals it for every server, and each
server writes it and restarts its k3s (apps keep running while k3s
restarts). The old token joins nothing from then on. Machines the cluster
knows already stay in it, but one that is no member is removed by the
coordinator's sync within a minute anyway. k3s's documentation allows
changing the agent token of a running cluster this way; it is not tested on
real machines yet.

## Backups

The coordinator backs itself up every night, around 02:30: the cluster's
datastore and token, the list of machines, its WireGuard and SSH keys and
dryserver's settings. Each backup is encrypted to
`secrets/backup_ed25519.pub`, a key the first USB build makes on your
computer. The coordinator has only that public half: it can make backups
but cannot read one. For the copy of the cluster's datastore k3s pauses
for a moment; the apps keep running.

```sh
./dryserver backup-pull    # copy the newest backups into secrets/backups/
```

It copies them over your own SSH login, checks each one's size and the
coordinator's signature, and never replaces a file you already have. Both
sides keep the newest backup of each of the last 7 days and of each of the
last 4 weeks that have one. Your copies are thinned only by backups that
are on your computer or checked out in this pull, never by names the
coordinator lists: a hacked coordinator listing backups it cannot deliver
removes nothing. Names dated more than a day after your computer's clock,
and files listed above 4 GiB, are not copied. Pull now and then: if the
coordinator's disk dies, the backups on it die with it.

A coordinator hacked as root can sign anything with its host key and make
backups that open (it has the public key they are encrypted to), so a
backup that checks out is no proof that it is a good one. What it cannot
change is your computer's clock. So a pull takes only backups dated after
the newest copy you have, oldest first, and says which older ones it did
not copy: your copies are pushed out only by newer days and weeks, as time
would push them out anyway, never by backups dated back into their days.
And the weekly copies you had before a pull stay through that pull
(they go at the next one when newer weeks took their place): one pull
never removes every copy you have. The copies from before a break-in are
the ones you need, so pull often and look at what each pull says.

On the coordinator, the backups are in `/var/lib/dryserver-backup` (root's,
readable by your login; not inside `/var/lib/dryserver`, which belongs to
the account every server reaches), `sudo dryserver backup` makes one now,
`/var/lib/dryserver-backup/last.json` says how the last one went, and
`journalctl -u dryserver-backup` has the details. On a coordinator
installed when backups were kept in `/var/lib/dryserver/backups`, the next
backup moves them over, removes that directory and the ACL entry it had for
your login, and touches nothing there it did not make. Restoring is not built
yet; to look inside one:
`age -d -i secrets/backup_ed25519 FILE | tar -tv`.

**Back up `secrets/backup_ed25519`** with your other secrets: without it no
backup can be opened.

## Updates

A fix reaches every machine from your desktop, without a reinstall and
without anyone at the machines.

### How to update the swarm

One command, in the dryserver folder on your desktop:

```sh
make                                                  # the static binary to ship
./dryserver release publish -notes "fixes the join timeout"
```

It checks the release, shows what changes and asks before anything is
signed:

```
Release 1795400000 for 3 machines:
  dryserver  0.1.0 -> 0.2.0
  k3s        same (v1.37.2+k3s1)
  Arch       2026/11/19 -> 2026/11/21 (the newest on archive.archlinux.org; ...)
  urgent     no: machines update only 03:00-05:00 on the coordinator's clock
  rollback   no
  notes      fixes the join timeout
Compared with release 1795000000, the newest on the coordinator.
coord updates itself first, then the servers one at a time: node-a and
node-b (node-a is the canary, watched for 5m).
Sign it and send it to the coordinator at 192.168.1.50? [y/N]
```

Or press `u` in `./dryserver approve`: the same checks and the same
summary, `y` sends it.

The summary compares with the newest release on the coordinator. When
that one failed on the coordinator and went back, it compares with the
release the machines still run instead, and says so; for that this
computer keeps a copy of each release it signs in `secrets/releases/`.
Without a release (or without the copy) it compares with what the
machines report, which is a version and not a build: the same version
is shown as maybe another build, never as the same.

- **Checked before signing**: the binary is the static one `make`
  builds; nothing is older than what the swarm runs (unless you go back,
  below); the k3s binary has the checksum this dryserver pins
  (`out/pkgcache/k3s-VERSION`, downloaded by `./dryserver build`; when it
  is missing and the coordinator needs it you are told how to get it);
  the Arch snapshot day is on archive.archlinux.org. The day is the
  newest one there (today's, or a few days back while today's is not
  out); name one with `-arch-date YYYY/MM/DD`. Only the day goes to the
  archive, nothing about you or the swarm.
- **What happens**: the coordinator updates itself first, then one server
  at a time, each one drained first and kept on the new release only once
  it is healthy (below).
- **Watch it**: `./dryserver release status` (one line per machine), or
  Updates in `./dryserver approve`.
- **Urgent** (`-urgent`): the rollout starts at once instead of in the
  update window 03:00-05:00 on the coordinator's clock. It is still the
  coordinator first and one server at a time; the canary is watched for a
  minute instead of five. It keeps the swarm's Arch day (no package update
  on any machine, so the fix is not held up by pacman) unless you name one
  with `-arch-date`. For security fixes.
- **When it stops**: a rollout stops by itself at a server whose update
  fails. `release status` says where and what to do: look at the machine,
  then `./dryserver release resume` (it says what that does first: the
  server tries again), `./dryserver release resume -skip` (the server is
  passed over for this release), or publish a fixed release (it gets a
  higher serial and replaces the rollout).
- **Stop it or go back**: build the dryserver the swarm ran before and
  publish it with `-rollback`. That replaces the rollout, and machines
  that updated already go back to it. Add `-arch-date` with the older day
  to take the Arch packages back too.

`publish` signs with `secrets/signing_ed25519`, like the machine list:
only what you signed is ever installed. If that key has a passphrase,
`ssh-keygen` asks for it in the terminal at each signature; the approve
screen cannot ask, so it refuses to start.

Then the coordinator rolls it out:

1. **The coordinator updates itself first.** It keeps the new binary only
   once it runs and is healthy (k3s up, firewall loaded); otherwise it
   goes back to the old one by itself after 10 minutes. If its update
   fails, no server is touched.
2. **Then one server at a time.** The coordinator drains the server
   (`kubectl drain`, keeping to PodDisruptionBudgets: its apps move first),
   gives it its turn, and the server loads the release over the mesh (in
   pieces, a few per minute; on a slow link each sync goes on where the
   last one ended), checks the signature and the checksums itself,
   installs it, and keeps it once the new binary runs, is healthy and
   reaches the coordinator. Then the coordinator uncordons it and moves
   to the next one.
3. **The first server is the canary**: it is watched for 5 minutes before
   the next one gets its turn.

Normal releases update machines only from 03:00 to 05:00 on the
coordinator's clock; urgent ones start at once. Both go one machine at a
time. A newer release replaces a rollout that runs: machines go straight
to the newest (a server in the middle of the old one finishes first).
Time the coordinator was down, or a jump of its clock, does not count
against a server's turn or the canary's watch. A server that joins
during a rollout, or after it, gets the release too.

The rollout **stops** at a server whose update fails, goes back, is
refused by its own checks, or does not finish in an hour (one never heard
from since its turn came is passed over after 20 minutes instead), and at a
canary that is not well. A server that finishes after all lets the rollout
go on by itself. `./dryserver approve` shows why, and the release
on every machine. A stopped server stays cordoned while it is up and not
well, and is uncordoned once it runs its old release well again. Look at
it, then publish a fixed release, or:

- `./dryserver release resume`: the server tries the release once more
  (drained again, at once for an urgent release or in the window for a
  normal one; when it is switched off, the others go on and it tries once
  it is back). What it loaded so far stays. A server that could not be
  drained updates without draining; after a canary that was not well the
  rollout goes on; when the coordinator's own update failed, it tries
  again.
- `./dryserver release resume -skip`: the server is passed over. It keeps
  its release until the next one, and the others go on. The coordinator
  is never passed over: no server updates before it does.

Passed over without stopping, and shown: a server that is switched off
(it updates when it is back, still one at a time), one whose kill switch
is on (it updates nothing until it is lifted), and one with an older
dryserver that cannot update itself. A server whose turn ends that way
three times in one rollout (switched off, or its kill switch on, each
time its turn comes) stops the rollout there, for you to look. A server
removed from the swarm while the rollout is stopped at it lets the
rollout go on. The rollout also stops before the first server when the
coordinator's copy of the release's k3s is gone or damaged. Only the
members you signed take part: one the coordinator lists on its own never
gets a turn.

A hacked coordinator cannot change a release, make a server install an
older one, or hand it a binary other than the signed one: each server
checks for itself. One that never took an update counts the dryserver and
k3s it was installed with and the Arch day its installer pinned as its own,
and goes below them only for a rollback you signed after it began to take
releases (its install, as the installer records it): an old signed
rollback sent again does not move it back. The
coordinator does decide when machines update (the window and the turns are
its doing). A hacked server can fail or stall only its own turn, and a
stalled turn ends after an hour. But a failed or stalled
turn stops the whole rollout there until you act: a hacked server can
hold every release up until you look and pass it over (`release resume
-skip`; a plain resume lets it fail again).

### On each machine

One signed release updates the whole machine: the dryserver binary, the
k3s binary and the Arch Linux packages (the snapshot day), in that order,
then a reboot when the packages need one. A release that keeps the k3s
binary and the day restarts no k3s and runs no pacman, so a dryserver fix
stays quick. The rollout runs it as `sudo dryserver update apply --detach
--reboot ...` (in a service of its own, `dryserver-update-apply`, so the
minute sync goes on and stopping the sync never stops pacman), and follows
it with `dryserver update status`. By hand, `sudo dryserver update apply
--release FILE --binary FILE [--k3s FILE]` runs in the terminal and reboots
only with `--reboot`.

The dryserver that runs checks the release and the new binary, then hands
over: everything after that is the new binary's code. So a fix to how k3s
or the packages are updated (or to the reboot) works already with the
release that brings it. Step by step:

1. **Checks, nothing changed yet.** The signature and the checksums (the
   binaries are copied into a directory only root can write first). A
   refusal changes nothing and says whether it is worth another try
   (*postponed*: a busy pacman, a full disk) or not (*refused*).
2. **A revert is armed** (a timer, and a boot unit that carries it across
   a power cut). From here on the machine goes back by itself unless the
   update finishes and is confirmed.
3. **The new dryserver** is copied beside the old one and checks itself
   there.
4. **The packages are loaded first**, by the new dryserver: it checks
   pacman's settings (package signatures required, every repository on
   the pinned snapshot only), `/boot` mounted, room on `/` and `/boot`, no
   other pacman at work; then pacman's mirrorlist is pinned to the
   release's day of the Arch archive and pacman refreshes its lists, takes
   newer signing keys and downloads everything. A dead or slow mirror ends
   the update here with the mirrorlist put back: *postponed*, tried again
   at the next sync (10 times), not a failed release.
5. **The new dryserver takes the old one's place** in one rename (a power
   cut leaves one of the two, never half a file). It rewrites the system
   files it manages from `/etc/dryserver/config.env`, each validated first
   (`nft -c`, `sshd -t`, `systemd-analyze verify`), and reloads only what
   changed.
6. **k3s**, when this machine runs another binary than the release's: put
   in place the same way, the old one kept as `k3s.prev`, and k3s must
   come back healthy with it (the kubelet, and on the coordinator the API
   server); otherwise the old one goes back and the update reverts.
7. **The packages are installed** (`pacman -Su`, `-Suu` for a rollback),
   the one step a revert cannot undo, so it comes last. pacman is never
   killed while it installs: stopped, it gets SIGINT and finishes the
   package it is at; and no shutdown is let in meanwhile. After a new
   openssh, sshd restarts (running sessions stay) once `sshd -t` accepts
   its settings. The two kernels never change in one run: everything but
   the fallback kernel (linux-lts) first, linux-lts in a run of its own and
   only once the main kernel has booted well, else at the next update that
   finds it booted well (a release that keeps the Arch day runs pacman for
   it only then, so a machine that waits for a reboot by hand is not sent
   through pacman at every release); so one kernel is always known good. Boot images that were not made (a power
   cut in pacman's hooks) are made again with `mkinitcpio -P`. When pacman
   refuses (files in the way, a damaged package), the update says pacman's
   own error lines; it changed nothing then, and rebooting stays safe.
   Files in the way are taken over in two cases only, each file named: a
   rollback across a package split (Arch moved files into a new package
   the older day does not have, like openssl-3; the older package takes
   them back, the new one leaves pacman's database, and what the older day
   lacks and nothing needs is removed), and an install cut off by a power
   cut in the middle of a package (its own files, owned by no package).
   Anything else is refused with the files, for you to look at. A machine
   installed after the release, whose packages are of a newer day, keeps
   them; the next release moves them. A rollback brings the packages to
   exactly its day, also on a machine installed from that day's stick
   (its packages came from mirrors of that day or newer).
8. **The confirm window starts** (10 minutes, from the end of the apply,
   however long it took). Unless `sudo dryserver update confirm` follows,
   the machine puts back the old binary, the files, the mirrorlist and the
   old k3s by itself. That needs no network and no coordinator. The
   packages stay where they are: the way back for them is a release signed
   with `-rollback` and the older `-arch-date`.
9. **A reboot**, when a new kernel or glibc, systemd and the like came,
   pacman finished cleanly and the boot images are current, and the machine
   can come back by itself (a disk that asks for its passphrase at boot
   cannot): once, with the update still waiting for its confirm, which
   then comes after the restart (the window grows by 15 minutes). Otherwise
   `dryserver update status` says `reboot needed`, `reboot by hand`, or
   `do NOT reboot` (a package update that stopped part way: the next one
   finishes it).

A machine whose kill switch has cut the coordinator off takes no update,
and one whose cut lands during the update stops before the packages.

**The first release after the handover came in** is still applied by
dryservers without it, which update k3s and the packages with their own
code: publish it with the k3s and the Arch day the swarm runs
(dryserver only). From the next release on, the new code does it all. A
rollback to a dryserver from before the handover works too: the running
one then does those steps itself, as that one expects.
`dryserver update status` shows what runs now, the pinned Arch day and
the last package update, the reboot that is due, and how the last update
ended.

## Security

- **Firewall first.** The live USB accepts no incoming connections and runs no
  SSH server. Servers drop all incoming traffic except:
  - from WiFi/router: SSH and WireGuard
  - from the switch: WireGuard only
  - over the mesh: ping and the ports you list in *Extra ports*
    (`MESH_PORTS`); SSH only from the coordinator (that is the path of
    `ssh node-a` from your desktop), on the coordinator from every member

  Docker publishes container ports on `127.0.0.1` unless you give an address.
- **Outgoing traffic is limited too.** A server may start connections only
  for DNS, time, web (80, 443), DHCP, WireGuard, the mesh, and the
  coordinator's registry. Everything else is refused at once and logged.
  Containers get the same internet ports, reach the mesh only on
  `MESH_PORTS`, and never reach your home network (DNS excepted). Add ports
  your apps need with *Extra outgoing ports* (`EGRESS_PORTS`).
  On the coordinator only root (k3s, sync) may start connections into the
  mesh on any port: other accounts only SSH (your `ssh node-a` through it)
  and ping, system accounts (the registry's among them) none. What the
  registry account runs has no network at all (`IPAddressDeny=any` on its
  slice, on coordinators installed from now on; the SSH connections it
  serves belong to sshd). Pods there reach servers only on the ports
  servers keep open (kubelet, `MESH_PORTS`).
- **A member that tries closed ports is cut off.** More than 30 tries in a
  minute and the firewall blocks that member at once; within a minute the
  server makes it a quarantine that lasts until you lift it, writes it to
  `/var/log/dryserver-cuts.log` and its console, and tells the coordinator,
  so `./dryserver approve` shows who cut whom. Each server decides this for
  itself only and tells no other server to cut, so a hacked server can cut
  off only itself. Only tries to open something count (a TCP SYN, UDP,
  other protocols), not late packets of a connection a restarted machine
  forgot. The coordinator is counted on its own and needs more than 100
  tries: its cut stops every app on that server, and on it nothing but root
  may try a server's closed ports, so an account or a pod there cannot
  trigger it. A scan by its root still does.
- **Blocked traffic is logged** (at a limit) with the prefixes
  `dryserver-mesh-drop`, `dryserver-out-drop`, `dryserver-container-drop`
  and `dryserver-autocut`: `journalctl -k -g dryserver-`.
- **SSH**: key login only, no root login, `MaxAuthTries 3`, rate limited.
  The coordinator's registry account (whose key is on every stick) runs
  only the registry whatever key it has: sshd forces the command and gives
  it no terminal and no forwarding, and its key lives where only root
  writes (`/etc/ssh/authorized_keys.d/dryreg`; its home belongs to root).
- **The firewall always loads**: ports and addresses from the config are
  taken only in their plain form (`51820`, `192.168.1.50`), and the setup
  lets nft check the machine's firewall before it touches the disk.
- **Accounts**: root is locked; sudo asks for your password.
- **Disk encryption**: LUKS2 with argon2id; TPM unlock bound to the signed
  kernel image, Secure Boot state and kernel command line; no disk swap
  (zram only). Both kernels' images are signed for the TPM with the same
  key, so the fallback kernel unlocks the disk too.
- **Joining**: needs your approval on your desktop with a matching pairing
  code. The code covers both machines' keys, so a fake coordinator or a
  swapped request shows a different code. A new machine joins only when it
  finds itself, with its own keys, in a list you signed. Each request also
  carries a proof made by the installer with a secret from your USB stick
  (`secrets/join_secret`); no installed machine keeps that secret. Without
  the proof a request cannot be approved, so a hacked coordinator cannot
  swap its own keys into a waiting request. After approval, the
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
  cannot be brought back. A server that finds itself gone from a newer
  signed list stops k3s and its containers and no longer counts itself a
  member. Nobody can approve on a server, the coordinator
  included, and a machine that shows up on the coordinator without a join
  request cannot be signed at all. `./dryserver ssh-config` takes server
  names and SSH host keys from the signed list too. Limit: a hacked
  coordinator can hold back a newer list from servers that have not seen it
  yet, so a removal may not arrive; cut the machine off with
  `./dryserver quarantine-all -name NAME` then.
- **The cluster token never reaches the registry.** Servers get the member
  list from an account on the coordinator that every server reaches over
  SSH, so whatever that account can read counts as known. The token k3s
  agents join with is not among it: with it, the account could join a
  machine of its own to the cluster and draw apps and their secrets there.
  Root on the coordinator encrypts the token with `age` for each server in
  the signed list, to that server's SSH host key, and signs it with the
  coordinator's host key; the account only passes on what it cannot read.
  A server takes only a token made for its own key and signed by the
  coordinator in the signed list. Anything else changes nothing (nothing
  written, k3s not restarted) and is logged once. Encrypting alone would
  not do: anyone can encrypt to a public key, and a token carrying the hash
  of another certificate authority would have the server trust whoever
  answers on the coordinator's k3s port. A token without that hash is
  refused for the same reason. A server whose SSH host key is not
  ssh-ed25519 gets no token, and the coordinator logs why.
  - Coming from an older dryserver, which kept the token in the registry in
    plain text: the updated coordinator's first sync removes it. Servers
    that joined keep the token they hold. A server on an older dryserver
    that has not joined the cluster yet joins once it is updated (a rollout
    updates the coordinator first); an updated server never takes a token
    from an older coordinator. The registry account could read the old
    token: make a new one ([A new cluster token](#a-new-cluster-token)).
  - Limit: the registry account can send a server a token the coordinator
    sealed for it earlier. Until the token is changed that is the same
    token; after a change it is the old one, and that server's k3s stops
    working until it gets the new one again.
- **The USB stick** holds the WiFi password, the key that lets machines ask
  to join and the join secret. Whoever has it can make a join request that
  looks installed from your stick; it still needs your approval and a
  matching code. Keep it safe, or re-flash it after installing.

## Commands

On your desktop:

| Command | What it does |
|---|---|
| `./dryserver` | menu: config, build, flash, machines, apps, outside |
| `./dryserver build` | build the ISO, log to stdout |
| `./dryserver disks` | list disks and which ones may be flashed |
| `sudo ./dryserver flash --iso FILE` | flash any image to a USB drive |
| `./dryserver approve` | approve, reject or remove machines and see unknown devices; every decision is signed. `u` publishes an update, `R` resumes a stopped rollout |
| `./dryserver apps` | what runs on your cluster: start an app from a container image, remove one |
| `./dryserver outside` | the ways in from the internet: open, sync or close the Cloudflare Tunnel, and which host names use it |
| `./dryserver release publish` | check a release of this dryserver, show what changes, sign it and roll it out (`-urgent`, `-notes`, `-rollback`, `-arch-date`, `-k3s`) |
| `./dryserver release status` / `resume` | the release, one line per machine, and what to do when it stopped; let a stopped one go on (the server tries again; `-skip` passes it over) |
| `./dryserver ssh-config` | SSH config for all servers |
| `./dryserver quarantine-all` | kill switch: cut the coordinator off on every server |
| `./dryserver backup-pull` | copy the coordinator's newest encrypted backups into `secrets/backups/` |
| `./dryserver install --demo` | try the laptop setup screen; changes nothing |

On servers:

| Command | What it does |
|---|---|
| `sudo dryserver tpm-enroll` | let the TPM unlock the disk again (after a firmware change) |
| `sudo dryserver quarantine` | kill switch on this server (`-name`, `-status`, `-lift`) |
| `dryserver report` | this machine's health as JSON, the same report it sends with every sync (`sudo` adds the firewall and WireGuard) |
| `sudo dryserver backup` | coordinator: make an encrypted backup now (a timer does it every night) |
| `sudo dryserver update apply` | install a release the admin signed (dryserver, k3s, Arch packages, a reboot when needed); it reverts by itself unless `update confirm` follows in time (`update status`, `update revert`) |
| `sudo dryserver selfcheck` | check this binary, its settings, the firewall, SSH and wg0.conf, without the network |
| `sudo dryserver boot status` | which kernel runs, its boot images and whether the fallback kernel waits (`boot place`, `mark` and `check` run from mkinitcpio, pacman and systemd) |
| `dryserver sync`, `join`, `scan`, `registry`, `cluster-dns` | run automatically by systemd, cron and SSH |

### Health reports

With every sync, once a minute, each machine tells the coordinator how it
is: its dryserver and k3s versions, the running kernel and whether a newer
one waits for a reboot, when it was last fully upgraded (`pacman -Syu`),
uptime, load, memory, root disk, its hottest temperature sensor, whether
k3s runs and the firewall is loaded, when it last shook hands with
each WireGuard peer, which release it runs and how its update stands, and
whether it booted the fallback kernel (`boot`). `./dryserver approve` shows it under each member:
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
if unsure: only ping works between servers then, and SSH from the
coordinator.

### What are "Extra outgoing ports"?
Ports on the internet that your servers and their containers may connect to,
besides DNS, time and web (80, 443), e.g. `25565/tcp` for a game server that
calls out on that port. Leave empty if unsure; a refused connection shows up
in `journalctl -k -g dryserver-out-drop`.

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
| `./dryserver approve` says "running fallback kernel" | the main kernel did not boot (`sudo dryserver boot status`, `journalctl -b -1 -u dryserver-boot-check`); the next release with a fixed kernel, or a rollback, makes it boot the main kernel again |
| `ssh node-a` asks for a password or fails | run `./dryserver ssh-config` again; check `Include config.d/*` in `~/.ssh/config` |

## Development

```sh
make test                           # unit tests (cargo test)
test/validate-sysconf.sh            # check generated firewall/SSH/sudo files with real nft and sshd
test/validate-boot.sh               # both kernels' images with the real mkinitcpio, ukify and pacman hooks
test/live-firewall.sh               # the generated firewall with real connections: mesh, home network, containers
test/live-quarantine.sh             # kill switch with real WireGuard and nftables, in private namespaces
test/live-approve.sh                # signed approval: the real screen against a real sshd and registry
test/qemu.sh coord                  # boot out/dryserver.iso in a UEFI VM with a blank disk
test/qemu-lan.sh coord c1           # VMs wired like a swarm (own router each, shared switch); see its header
BIOS=1 test/qemu.sh node            # legacy BIOS
TPM=1 OVMF_CODE=... test/qemu.sh    # TPM tests need firmware that measures boot (Arch's edk2-ovmf)
SWITCH=1 SSH_PORT=2201 ...          # shared switch NIC between VMs, SSH on localhost:2201
```

Layout: `src/main.rs` (CLI), `src/tui` (screens), `src/install`
(installer), `src/sysconf.rs` (generated system files), `src/registry.rs`
and `src/node.rs` (joining and sync), `src/mesh.rs` (WireGuard and SSH
config), `src/quarantine.rs` (kill switch), `src/signed.rs` and
`src/admin.rs` (signed member list and approval from the desktop),
`src/release.rs` and `src/rollout.rs` (signed releases and their rollout),
`src/apps.rs` (apps on the cluster), `src/entrance.rs` (the ways in from outside), `assets/` (files embedded into the ISO and servers by `build.rs`).
Golden files for the generated system files are in `testdata/sysconf`;
`UPDATE_GOLDEN=1 cargo test` rewrites them.

| Path | What |
|---|---|
| `config.env` | your settings, contains the WiFi password; not committed |
| `secrets/registry_ed25519` | key machines use to ask to join; not committed |
| `secrets/join_secret` | proves a join request comes from a machine installed from your stick; on the stick and here, never on an installed machine; not committed. **Back it up** |
| `secrets/members.signed.json` | this computer's copy of the last machine list you signed: the backup of who is in your swarm |
| `secrets/release.signed.json` | the last release you signed; serials go on from it |
| `secrets/signing_ed25519` | key that signs the list of machines in your swarm; created by the first build, never leaves this computer, not committed. **Back it up.** Only `signing_ed25519.pub` goes onto the USB stick and the servers |
| `secrets/backup_ed25519` | opens the coordinator's backups; created by the first build, never leaves this computer, not committed. **Back it up.** Only `backup_ed25519.pub` goes onto the USB stick and the coordinator |
| `secrets/backups/` | the coordinator's backups, copied by `./dryserver backup-pull` (encrypted) |
| `out/dryserver.iso`, `out/build.log` | built installer image and its log |

## License

[MIT](LICENSE)
