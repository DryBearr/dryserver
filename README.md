<p align="center">
  <img src="docs/img/banner.svg" width="860" alt="dryserver: an ouroboros, a snake biting its own tail, ember red at the head, gold along the body, violet at the tail">
</p>

<p align="center">
  <b>Turn old laptops into a private, encrypted server swarm with one USB stick.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-D2A23A?labelColor=140C0A" alt="license: MIT">
  <img src="https://img.shields.io/badge/rust-1.88%2B-EE8434?labelColor=140C0A" alt="rust 1.88+">
  <img src="https://img.shields.io/badge/installs-Arch%20Linux-9A85D0?labelColor=140C0A" alt="installs Arch Linux">
</p>

dryserver is one program on your desktop. It builds an installer USB stick.
Boot a laptop from it, answer a few questions and type `YES`: the laptop is
wiped and comes back as an encrypted Arch Linux server that asks to join
your swarm. Nothing joins until you approve it on your desktop. The servers
then run your apps as one cluster, and you update all of them from your
desktop with one command.

> [!WARNING]
> **Early software.** Tested end to end on QEMU virtual machines: UEFI with
> a TPM chip, legacy BIOS, a shared switch, three servers, updates forward
> and back. Not yet tested on real laptops and real WiFi. Installing
> **erases the laptop's disk**.

## How it fits together

```
  your desktop                          home router (WiFi)
  ./dryserver  ── build + flash ──►  USB stick       │  internet, setup, joining
                                       │ boot         │
                     ┌─────────────────┼──────────────┤
                     ▼                 ▼              ▼
                 coord (1st)        node-a          node-b      laptops
                 10.66.0.1         10.66.0.2       10.66.0.3    (WireGuard mesh)
                     └──────────── switch (optional) ────┘
```

- **Your desktop** holds the keys. It builds the stick, approves machines
  and signs every update. Nothing is installed or let in without its
  signature.
- **The coordinator** is the first laptop you install. It keeps the list of
  machines and hands it out, and it runs the cluster. It cannot let anyone
  in by itself.
- **Servers** are every other laptop. They talk to each other directly over
  WireGuard, by name (`ssh node-a`), over a switch when cabled or else over
  WiFi, and run your apps.

## The circle

The snake on the installer screen is also its progress bar: it grows around
the ring while work is done and bites its tail when it is finished. Setting
up a swarm goes around the same way.

| | Stage | Where |
|:-:|---|---|
| <img src="docs/img/ring-1.svg" width="40" alt="Stage 1 of 5"> | [1. Get ready](#1-get-ready) | your desktop and the laptops |
| <img src="docs/img/ring-2.svg" width="40" alt="Stage 2 of 5"> | [2. Build the stick](#2-build-the-stick) | your desktop, about 6 minutes |
| <img src="docs/img/ring-3.svg" width="40" alt="Stage 3 of 5"> | [3. Install the coordinator](#3-install-the-coordinator) | the first laptop |
| <img src="docs/img/ring-4.svg" width="40" alt="Stage 4 of 5"> | [4. Add servers](#4-add-servers) | every other laptop |
| <img src="docs/img/ring-5.svg" width="40" alt="Stage 5 of 5"> | [5. Run apps and keep them updated](#5-run-apps-and-keep-them-updated) | your desktop, from then on |

Want to see the laptop's setup screen first? `./dryserver install --demo`
shows it and changes nothing.

## 1. Get ready

**Your desktop** builds and flashes the stick:

- Linux with `podman` (the ISO is built inside an Arch Linux container)
- Rust 1.88 or newer (`cargo`), `make`, `ssh-keygen`, `lsblk`
- About 5 GB of free disk space; `sudo` only for writing the USB stick
- An SSH key in `~/.ssh/id_ed25519.pub`. No key yet? `ssh-keygen -t ed25519`

**Each laptop** becomes a server, and its disk is erased:

- 64-bit x86, UEFI or legacy BIOS. UEFI is better: when a kernel update
  does not start, a UEFI machine falls back to the older kernel by itself,
  while on BIOS someone has to pick it in the boot menu.
- **Secure Boot turned off** in the firmware settings
- A disk of at least 16 GB and 2 GB of memory or more
- Internet over WiFi, or an Ethernet cable to the router
- Optional: a TPM 2.0 chip (most laptops from about 2016 on), so the disk
  unlocks by itself; an Ethernet port, to link servers over a switch

**Your network** needs one free address for the coordinator, such as
`10.1.0.60`. [Which address do I pick?](#which-ip-do-i-use-for-the-coordinator)

## 2. Build the stick

```sh
git clone https://github.com/DryBearr/dryserver && cd dryserver
make                 # builds ./dryserver
./dryserver          # menu: 1 Config, 2 Build installer ISO   (no sudo)
sudo ./dryserver     # menu: 3 Flash USB                      (writing a USB drive needs root)
```

1. **Config.** WiFi, the coordinator's address, the mesh, your tools, the
   admin user name and your SSH public key. Copy the key with
   `wl-copy < ~/.ssh/id_ed25519.pub` (or `cat` it and copy the line) and
   paste it with Ctrl+Shift+V. The email at the end of the key is dropped;
   a short label like `desktop` is used instead.
2. **Build installer ISO.** About 6 minutes; the first build downloads
   about 1 GB.
3. **Save your keys.** The first build makes the keys of your swarm in
   `secrets/`. Copy that folder somewhere safe now (see the box below).
4. **Flash USB.** Only USB drives are listed. Type the device name to
   confirm; the image is read back and checked.

> [!IMPORTANT]
> **Back up `secrets/`**, to a second USB stick or a password manager.
> `signing_ed25519` is the key of your swarm: without it you cannot
> approve a machine or publish an update, and every machine has to be
> installed again. `backup_ed25519` is the only key that opens the
> coordinator's backups. Neither is ever on the stick or a server.

After a `git pull`, build the stick again before you install a new
machine: a stick carries the dryserver it was built with.

## 3. Install the coordinator

1. Plug the stick into the first laptop and boot from it. The boot menu
   key is usually F12, F9, F2 or Esc.
2. The setup screen starts by itself. It shows the CPU, memory, disks,
   whether the laptop has a usable TPM chip, and the network. Then:

   | Step | What you choose |
   |---|---|
   | Role | **coordinator** |
   | Hostname | leave it empty for `coord` |
   | Disk | internal disks only; the USB stick itself is never offered. Other disks can become encrypted data disks at `/data` |
   | Encryption | see below |
   | Disk passphrase | at least 12 characters, typed twice |
   | User password | at least 10 characters, for the console and sudo (SSH uses your key) |
   | Confirm | a summary of what gets erased; type `YES` |

3. When it has restarted, **reserve its address in your router** for the
   device named `coord` (DHCP reservation), then restart the coordinator
   once.
4. On your desktop, run `./dryserver approve` and press `S` to sign the
   coordinator, if it shows the same code as the coordinator's screen.
   From now on, servers accept only the machines you approve here.

**Encryption**, chosen per laptop:

- **Unlocks itself with the TPM chip**, offered when the chip and firmware
  support it. Type the passphrase once at the first boot; after that the
  laptop restarts on its own. The disk cannot be read outside this laptop,
  and a changed boot (an edited kernel command line, another boot loader)
  makes it ask for the passphrase instead.
- **Passphrase at every boot.** Most secure; for laptops that leave the
  house. Such a laptop does not restart by itself after an update; it says
  when a restart is due.
- **Not encrypted.**

Passwords are typed on the laptop and never stored on the stick. Keep the
disk passphrase somewhere safe: without it, the data is gone.

More about the setup screen and what each machine gets:
[docs/machines.md](docs/machines.md).

## 4. Add servers

1. Boot the same stick on the next laptop and choose **server**. Leave the
   hostname empty for `node-xxxx`, or name it.
2. When it is installed, the laptop shows a 6-digit code.
3. On your desktop, run `./dryserver approve`, find the machine and press
   `a` if the code matches. Within a minute it is in the mesh, and soon
   after in the cluster.
4. Give it a fixed address in your router too: the
   [kill switch](#the-coordinator-may-be-hacked) reaches servers there.
5. Connect to it:

   ```sh
   ./dryserver ssh-config     # writes ~/.ssh/config.d/dryserver
   ssh node-a                 # through the coordinator
   ssh coord
   ```

   Add `Include config.d/*` at the top of `~/.ssh/config` if it is not
   there. Run `./dryserver ssh-config` again after each new machine.

No private keys are stored on servers, and your key is never forwarded to
them: a hacked server cannot use it to log into the others. To copy a file
from one server to another, go through your desktop:
`scp -3 node-a:file node-b:`.

## 5. Run apps and keep them updated

The ring is closed. From here it goes around again with every release:
you publish one, each machine sheds its old skin for the new one, and a
machine whose new skin does not fit goes back to the old one by itself.

### Run an app

```sh
./dryserver apps           # or "Apps" in the menu
```

Press `n` and give the app a name, its container image, the port it
listens on and, if it should be reachable from outside, a public host
name. The cluster picks a server for it. The screen shows what runs where;
`d` removes an app.

- When a server loses power, an app with one copy runs on another server
  after about a minute and a half. With two copies it keeps answering.
- Apps never run on the coordinator.
- Each app is fenced in: it takes connections only from the ingress and
  your other apps, and reaches only your other apps, DNS and the internet,
  never your home network.

Under it is plain Kubernetes (k3s): on the coordinator, `k3s kubectl` works
for you without sudo. More: [docs/apps.md](docs/apps.md).

### Reaching apps from outside

No machine opens a port to the internet. Apps are reached through a
**Cloudflare Tunnel**: two pods in the cluster dial out to Cloudflare,
which sends what arrives for your host names through them. A relay on a
VPS you rent is planned and not built yet.

```sh
./dryserver outside        # or "Outside" in the menu, or o on the apps screen
```

**With an API token** (recommended), dryserver sets up the tunnel and the
DNS records for you:

1. In the Cloudflare dashboard, open My Profile, API Tokens, Create Token,
   Create Custom Token. Give it these permissions:

   | Scope | Item | Access |
   |---|---|---|
   | Account | Cloudflare Tunnel | Edit |
   | Zone | DNS | Edit |
   | Zone | Zone | Read |

   Under Account Resources pick your account, under Zone Resources the
   zone (domain) your apps' host names are in. Newer dashboards call Edit
   "Write". An expiry date and an IP filter (your home address) are a good
   idea.
2. Save the token on your computer as `secrets/cloudflare_api_token`, and
   make it yours alone: `chmod 600 secrets/cloudflare_api_token`.
   dryserver refuses it while other users can read it.
3. In `./dryserver outside`, press `s` on the Cloudflare Tunnel. It lists
   every change it would make, in order (`pgdn` scrolls a long list). `y`
   makes exactly those; when something changed since it looked, it makes
   none and says so.

From then on, starting or removing an app with a host name updates
Cloudflare by itself. dryserver changes only the DNS records it made;
a record that points elsewhere is shown and left alone, until you take
the name over with `t`.

**By hand**, without an API token:

1. In the Cloudflare dashboard (Zero Trust, Networks, Tunnels), create a
   tunnel and copy its token. Save it as `secrets/cloudflare_tunnel_token`
   (the whole `cloudflared service install ...` line works too).
2. In `./dryserver outside`, press `o`. The tunnel's line shows how many
   copies hold a connection to Cloudflare.
3. In the dashboard, add a public host name per app and point each at
   `http://traefik.kube-system.svc.cluster.local:80`.

`x` closes the tunnel; the apps keep running, reachable only inside the
cluster. After you change the token file, `o` again gives the tunnel the
new token. How the tunnel and the DNS sync work:
[docs/apps.md](docs/apps.md#reaching-apps-from-outside).

### Update the swarm

One command fixes or updates every machine: dryserver, k3s and the Arch
Linux packages. Nobody has to be at the machines, and nothing is
reinstalled.

```sh
git pull && make
./dryserver release publish -notes "fixes the join timeout"
```

Or press `u` in `./dryserver approve`. Either way you see what changes
before anything is signed:

```
Release 1795400000 for 3 machines:
  dryserver  0.1.0 -> 0.2.0
  k3s        same (v1.37.2+k3s1)
  Arch       2026/11/19 -> 2026/11/21 (the newest on archive.archlinux.org; ...)
  urgent     no: machines update only 03:00-05:00 on the coordinator's clock
  rollback   no
  notes      fixes the join timeout
coord updates itself first, then the servers one at a time: node-a and
node-b (node-a is the canary, watched for 5m).
Sign it and send it to the coordinator at 192.168.1.50? [y/N]
```

Then it goes around the swarm, one machine at a time:

1. **The coordinator updates itself first.** It keeps the new release only
   when it is healthy and you can still get in: the servers still sync
   through it, and SSH still answers from your home network. Otherwise it
   goes back by itself and no server is touched.
2. **Then one server at a time.** Its apps move away first; it checks your
   signature itself, updates, reboots when a new kernel needs it, and
   keeps the release only when it comes back healthy.
3. **The first server is the canary**: the others wait 5 minutes to see
   that it stays well.

Releases install between 03:00 and 05:00 on the coordinator's clock. Add
`-urgent` to start at once (for security fixes); an urgent release keeps
the Arch packages where they are unless you name a day with `-arch-date`.

Watch it with `./dryserver release status`, or under Updates in
`./dryserver approve`.

**A machine that fails goes back by itself.** Every update waits for a
confirm; without one, the machine puts back its old dryserver, k3s and
settings after 10 minutes, also after a power cut. The rollout then stops
at that machine and tells you why. Then:

| You want to | Run |
|---|---|
| let that machine try again | `./dryserver release resume` |
| pass over that machine for this release | `./dryserver release resume -skip` |
| ship a fix | publish a new release: it replaces the rollout |
| go back to an older release | build the older dryserver and publish it with `-rollback` (add `-arch-date` with the older day to take the packages back too) |

Each step, every check and every edge case:
[docs/updates.md](docs/updates.md).

### See how machines are doing

`./dryserver approve` shows every machine with its health, sent once a
minute: versions, kernel, memory, disk, temperature, k3s, firewall, the
release it runs and how its update went. Problems show in red (a full
disk, k3s down, a reboot due, the fallback kernel running, and so on).
Press `i` for everything about one machine. More:
[docs/machines.md](docs/machines.md#health-reports).

### Back up the coordinator

The coordinator backs itself up every night at about 02:30: the cluster,
the list of machines, its keys and settings. Each backup is encrypted to a
key only your desktop has. Copy them home now and then; if the
coordinator's disk dies, the backups on it die with it:

```sh
./dryserver backup-pull    # copies the newest backups into secrets/backups/
```

Restoring is not built yet. To look inside one:
`age -d -i secrets/backup_ed25519 FILE | tar -tv`. More:
[docs/backups.md](docs/backups.md).

### Remove a machine

Press `d` on it in `./dryserver approve`. Within a minute every server
drops it, the cluster moves its apps to the servers that are left, and the
removed machine stops k3s and its containers. To bring it back, run
`sudo dryserver join` on it and approve it like a new machine. More:
[docs/apps.md](docs/apps.md#when-a-machine-leaves).

## When something goes wrong

| Problem | What to do |
|---|---|
| The laptop does not boot the stick | turn Secure Boot off; use the boot menu key (F12, F9, F2 or Esc) |
| The setup shows no disk | in the firmware settings, set the storage (SATA) mode from RAID or Intel RST to AHCI, and turn off VMD if listed |
| The setup fails | press `q` for a shell; the full log is in `/tmp/dryserver-install.log`. Old LVM, RAID, swap or encrypted volumes on the disk are released by themselves |
| A new server cannot reach the coordinator | is the coordinator on? Is its address reserved in the router and the same as in the config? Same WiFi? The server keeps trying and shows its code on the login screen |
| A TPM laptop asks for the passphrase at boot | the firmware or the boot settings changed: type the passphrase, then run `sudo dryserver tpm-enroll` |
| `./dryserver approve` says "running fallback kernel" | the main kernel did not boot (`sudo dryserver boot status`, `journalctl -b -1 -u dryserver-boot-check`). The next release with a fixed kernel, or a rollback, makes it boot the main kernel again. See [When a kernel update does not boot](docs/machines.md#when-a-kernel-update-does-not-boot) |
| An update stopped | `./dryserver release status` says where and why; see [Update the swarm](#update-the-swarm) |
| `ssh node-a` asks for a password or fails | run `./dryserver ssh-config` again; check for `Include config.d/*` in `~/.ssh/config` |

### The coordinator may be hacked

Cut it off from every server, from your desktop:

```sh
./dryserver quarantine-all
```

It goes to each server straight over your home network, never through the
coordinator, and runs `sudo dryserver quarantine` there (sudo asks for
your password on each one). Each server then drops all traffic with the
coordinator, stops taking anything from it, and stops k3s and its
containers. The servers keep running and talking to each other; your apps
are down until you lift the cut. Then:

1. delete the tunnel in the Cloudflare dashboard, if you use one,
2. power the coordinator off and keep its disk to look at,
3. install it again from the stick, as coordinator, at the same address,
4. in `./dryserver approve`, which says the machine there has another SSH
   key, press `N`, compare the code with the new coordinator's screen and
   confirm,
5. run `./dryserver quarantine-all -lift`: the servers follow the new
   coordinator, and the old one stays out,
6. run `./dryserver ssh-config` once the servers have synced with it.

After a false alarm (nothing was installed again), lift with
`./dryserver quarantine-all -lift -same`, and only when you are sure. To
cut off a server instead: `./dryserver quarantine-all -name node-a`.

What a hacked coordinator could do before the cut, and every detail:
[docs/kill-switch.md](docs/kill-switch.md).

### A new cluster token

Each server joins with a token of its own (`k3s token create`, good for a
day): the coordinator's sync makes one for every server the admin signed
that is not in the cluster yet, seals it for that server and deletes it
once the server's node is there. With the token goes a node password made
for that server's name: k3s gives a certificate for a name only to the
machine with its password, so no token takes another server's name.

A server that was in the cluster never gets a token again, also when its
node is gone (`k3s kubectl delete node NAME`, or the server deleted it
itself): with one, a hacked server could leave the cluster and take the
name of a server that has not joined yet. The coordinator's console says
so. Its node comes back when k3s starts again on it (`sudo systemctl
restart k3s` there), with its certificate. A server whose certificate is
gone or ran out: remove it in `./dryserver approve`, run `sudo dryserver
join` on it and approve it again.

A name that a machine registered in the cluster without that name's
password (a server that held a token before it joined, or one of an older
dryserver with the shared token) is taken: k3s gave that machine a
certificate for the name, good for a year. The coordinator deletes a node
under it at every sync, gives no server a token for it, and its console
shows an alarm (`/etc/dryserver/k3s-taken.json` holds when and how). Find
the server that did it; to have a server under that name in the cluster,
install it again under another name.

Older versions handed every server one shared token, made from the secret
in `/etc/rancher/k3s/agent-token` on the coordinator. With it, any of those
servers could register a machine under the name of a server you approve
next, before that server does. Until you make a new secret, the
coordinator's sync says so (`journalctl -u dryserver-sync`) and its console
shows it. On the coordinator:

```sh
sudo sh -c 'umask 077; head -c 32 /dev/urandom | sha256sum | cut -d" " -f1 > /etc/rancher/k3s/agent-token'
sudo systemctl restart k3s
```

Nobody gets the new one: servers in the cluster go on with their own
certificates, and k3s's own documentation allows changing the agent token
of a running cluster. Apps keep running while k3s restarts. This is not
tested on real machines yet.

## How it stays safe

- **You decide who joins.** A machine joins only after you compare its
  6-digit code and approve it on your desktop, which signs the list of
  machines. The coordinator stores the list but cannot change it.
- **Only what you sign is installed.** Every release carries your
  signature, and each machine checks it itself. A hacked coordinator
  cannot hand out an old or altered release.
- **Encrypted disks.** LUKS2 with argon2id, unlocked by the TPM chip or a
  passphrase; no swap on disk.
- **A firewall both ways on every machine.** Only SSH and WireGuard come
  in from the home network. Going out, only DNS, time, web, the mesh and
  the ports you add. A machine that knocks on closed ports of the others
  is cut off by them.
- **No keys to steal on servers.** SSH takes keys only; your key stays on
  your desktop and is never forwarded.
- **A kill switch that works without the coordinator**, from your desktop.
- **Backups only your desktop can open.**

Honest limit: the coordinator runs the cluster. Whoever takes it over can
start containers on every server until you cut it off. After a real
break-in, install the servers again too.

Every protection, and what a hacked coordinator or server can and cannot
do: [docs/security.md](docs/security.md).

## Commands

On your desktop:

| Command | What it does |
|---|---|
| `./dryserver` | the menu: config, build, flash, machines, apps, outside |
| `./dryserver build` | build the ISO, with its log in the terminal |
| `./dryserver disks` | list disks and which ones may be flashed |
| `sudo ./dryserver flash --iso FILE` | flash any image to a USB drive |
| `./dryserver approve` | approve, reject or remove machines and see unknown devices; every decision is signed. `u` publishes an update, `R` resumes a stopped rollout |
| `./dryserver apps` | start an app from a container image, remove one, see what runs where |
| `./dryserver outside` | the ways in from the internet: open, sync or close the Cloudflare Tunnel |
| `./dryserver release publish` | check a release, show what changes, sign it and roll it out (`-urgent`, `-notes`, `-rollback`, `-arch-date`, `-k3s`) |
| `./dryserver release status` | the release on every machine, and what to do when it stopped |
| `./dryserver release resume` | let a stopped rollout go on: the machine tries again (`-skip` passes it over) |
| `./dryserver ssh-config` | SSH config for all your machines |
| `./dryserver quarantine-all` | kill switch: cut the coordinator off on every server (`-name`, `-status`, `-lift`) |
| `./dryserver backup-pull` | copy the coordinator's newest encrypted backups into `secrets/backups/` |
| `./dryserver install --demo` | try the laptop's setup screen; changes nothing |

On a machine:

| Command | What it does |
|---|---|
| `sudo dryserver tpm-enroll` | let the TPM unlock the disk again (after a firmware change) |
| `sudo dryserver quarantine` | kill switch on this server (`-name`, `-status`, `-lift`) |
| `dryserver report` | this machine's health as JSON, as it sends it every minute (`sudo` adds the firewall and WireGuard) |
| `sudo dryserver backup` | coordinator: make an encrypted backup now |
| `dryserver update status` | the release this machine runs, its Arch day, and how the last update went |
| `sudo dryserver update apply` | install a release you signed by hand; it goes back by itself unless `update confirm` follows in time (`update revert`) |
| `sudo dryserver selfcheck` | check this binary, its settings, the firewall, SSH and WireGuard, without the network |
| `sudo dryserver boot status` | which kernel runs, its boot images and whether the fallback kernel waits |
| `dryserver sync`, `join`, `scan`, `registry`, `cluster-dns` | run by systemd, cron and SSH by themselves |

## FAQ

### What is the coordinator?

The first laptop you install. New servers ask it to join, and every server
fetches the list of machines from it once a minute. You approve machines on
your desktop, which signs the list; the coordinator only stores and hands
it out. Traffic between servers does not go through it.

### Which IP do I use for the coordinator?

A free address on your home network. Run `ip -br addr` on your desktop: if
it shows `10.1.0.195/24`, your network is `10.1.0.x`, so pick something
like `10.1.0.60`. After installing the coordinator, reserve that address
for the device `coord` in your router's DHCP settings.

### Can I start with one laptop?

Yes. It becomes the coordinator, and you can try approving, updates and
the setup itself. Apps need a server, since they never run on the
coordinator, and an update only goes from machine to machine once there
is a second laptop.

### Why WireGuard?

Encrypted traffic between servers even on your home WiFi, a real identity
per server (nobody can pretend to be `node-a`), addresses that never
change, and a way to open services to your servers only. It carries normal
traffic like SSH, web and databases, but no network broadcasts, which
servers do not need.

### What are "Extra ports open inside the mesh"?

Ports your servers may use on each other, such as `8080/tcp` for a web app
on one server that the others need. They are never opened to WiFi. Leave
it empty if unsure: then only ping works between servers, and SSH from the
coordinator.

### What are "Extra outgoing ports"?

Ports on the internet that your servers and their containers may connect
to, besides DNS, time and web (80, 443), such as `25565/tcp` for a game
server that calls out on that port. Leave it empty if unsure; a refused
connection shows up in `journalctl -k -g dryserver-out-drop`.

### Does the switch need to be connected to the router?

No. The internet stays on WiFi; the switch only carries traffic between
servers.

### Why does flashing need sudo?

Only root may write a whole disk. Config and build run as your normal
user.

### What if I forget the disk passphrase?

The data is gone; that is what encryption means. With TPM unlock the
server keeps booting on its own, but keep the passphrase somewhere safe
for when the TPM refuses (a firmware update, changed boot settings).

### What does the USB stick hold?

The WiFi password, the key that lets machines ask to join, and the join
secret. Whoever has it can make a join request; it still needs your
approval and a matching code. Keep it safe, or flash it again after
installing.

## Your files

Everything here stays on your desktop and is never committed.

| Path | What | Back it up? |
|---|---|---|
| `config.env` | your settings, with the WiFi password | |
| `secrets/signing_ed25519` | signs the list of machines and every release; only its `.pub` half leaves this computer | **yes** |
| `secrets/backup_ed25519` | opens the coordinator's backups; only its `.pub` half leaves this computer | **yes** |
| `secrets/join_secret` | proves a join request comes from a machine installed from your stick; never on an installed machine | **yes** |
| `secrets/registry_ed25519` | the key machines use to ask to join | |
| `secrets/members.signed.json` | the last list of machines you signed: who is in your swarm | yes |
| `secrets/release.signed.json`, `secrets/releases/` | the last release you signed, and a copy of each; serials go on from it | |
| `secrets/backups/` | the coordinator's backups, copied by `./dryserver backup-pull` (encrypted) | |
| `out/dryserver.iso`, `out/build.log` | the installer image and its build log | |

## Development

```sh
make test                           # unit tests (cargo test)
test/validate-sysconf.sh            # generated firewall/SSH/sudo files with real nft and sshd
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

The release binary must be static: `make` builds it for musl, with the
local `x86_64-unknown-linux-musl` target if installed, else inside a Rust
Alpine container (podman). `cargo test` builds against glibc only, so run
`make` too before you ship.

Layout: `src/main.rs` (CLI), `src/tui` (screens; `theme.rs` holds the
ouroboros palette), `src/install` (installer), `src/sysconf.rs` (generated
system files), `src/registry.rs` and `src/node.rs` (joining and sync),
`src/mesh.rs` (WireGuard and SSH config), `src/quarantine.rs` (kill
switch), `src/signed.rs` and `src/admin.rs` (signed member list and
approval from the desktop), `src/release.rs`, `src/publish.rs`,
`src/rollout.rs`, `src/update.rs` and `src/osupdate.rs` (signed releases,
their rollout and how each machine applies them), `src/apps.rs` (apps on
the cluster), `src/entrance.rs` (the ways in from outside), `assets/`
(files embedded into the ISO and servers by `build.rs`). Golden files for
the generated system files are in `testdata/sysconf`;
`UPDATE_GOLDEN=1 cargo test` rewrites them.

The reference docs are in [`docs/`](docs): [machines](docs/machines.md),
[updates](docs/updates.md), [apps](docs/apps.md),
[security](docs/security.md), [kill switch](docs/kill-switch.md),
[backups](docs/backups.md). The README art in `docs/img` is the installer's
ouroboros as pixel art, drawn by `docs/img/draw.py`.

## License

[MIT](LICENSE)
