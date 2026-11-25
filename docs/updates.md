# <img src="img/ring-5.svg" width="33" alt=""> Updates

How a release goes from your desktop to every machine, and what each machine does with it.

Part of the [dryserver README](../README.md).

A fix reaches every machine from your desktop, without a reinstall and
without anyone at the machines.

## How to update the swarm

One command, in the dryserver folder on your desktop:

```sh
make                                                  # the static binary to ship
dryserver release publish -notes "fixes the join timeout"
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

Or press `p` in `dryserver approve` (Machines, any tab): the notes,
then the same checks and the same summary, `y` sends it.

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
  (`pkgcache/k3s-VERSION` in `~/.cache/dryserver`, downloaded by `dryserver build`; when it
  is missing and the coordinator needs it you are told how to get it);
  the Arch snapshot day is on archive.archlinux.org. The day is the
  newest one there (today's, or a few days back while today's is not
  out); name one with `-arch-date YYYY/MM/DD`. Only the day goes to the
  archive, nothing about you or the swarm.
- **What happens**: the coordinator updates itself first, then one server
  at a time, each one drained first and kept on the new release only once
  it is healthy (below).
- **Watch it**: `dryserver release status` (one line per machine), or
  Updates in `dryserver approve`.
- **Urgent** (`-urgent`): the rollout starts at once instead of in the
  update window 03:00-05:00 on the coordinator's clock. It is still the
  coordinator first and one server at a time; the canary is watched for a
  minute instead of five. It keeps the swarm's Arch day (no package update
  on any machine, so the fix is not held up by pacman) unless you name one
  with `-arch-date`. Machines the last rollout did not reach yet (it
  stopped, or still runs) get that day's packages with it all the same:
  the summary names them. For security fixes.
- **When it stops**: a rollout stops by itself at a server whose update
  fails. `release status` says where and what to do: look at the machine,
  then `dryserver release resume` (it says what that does first: the
  server tries again), `dryserver release resume -skip` (the server is
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
   once it runs and is healthy (k3s up, firewall loaded) and the ways in
   still work: the servers sync through it, sshd lets you in, and a server
   on the home network reaches its SSH at its LAN address, the way your
   desktop comes in (a server with no way of its own to that address does
   not count; with no server that can try, its firewall's rules must take
   SSH from there, and `release status` says it was not proven from
   outside). Otherwise it goes back to the old one by itself after 10
   minutes, and the rollout stops there with the reason. If its update
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
go on by itself. `dryserver approve` shows why, and the release
on every machine. A stopped server stays cordoned while it is up and not
well, and is uncordoned once it runs its old release well again. Look at
it, then publish a fixed release, or:

- `dryserver release resume`: the server tries the release once more
  (drained again, at once for an urgent release or in the window for a
  normal one; when it is switched off, the others go on and it tries once
  it is back). What it loaded so far stays. A server that could not be
  drained updates without draining; after a canary that was not well the
  rollout goes on; when the coordinator's own update failed, it tries
  again.
- `dryserver release resume -skip`: the server is passed over. It keeps
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

## On each machine

One signed release updates the whole machine: the dryserver binary, the
k3s binary and the Arch Linux packages (the snapshot day), in that order,
then a reboot when the packages need one. A release that keeps the k3s
binary and the day restarts no k3s and runs no pacman, so a dryserver fix
stays quick. The rollout runs it as `sudo dryserver update apply --detach
--reboot ...` (in a service of its own, `dryserver-update-apply`, so the
minute sync goes on and stopping the sync never stops pacman; the new
dryserver's steps and pacman go on even when the apply itself dies, and
its revert timer settles the update after them), and follows
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
   Files in the way are taken over in three cases only, each file named: a
   rollback across a package split (Arch moved files into a new package
   the older day does not have, like openssl-3; the older package takes
   them back, the new one leaves pacman's database once the older package's
   own file list has them, and the rest of its files, now owned by no
   package, are deleted as `pacman -R` would: only regular files and links
   in /usr, /etc, /var/lib and /opt, never through a link, an edited config
   file kept as `.pacsave`, then its empty directories; its file list is
   noted before its entry goes, so a power cut loses nothing, and what
   stays is said. What the older day lacks and nothing needs
   is removed, never a package that shares a file with another one and
   never before the split is done; an edited config file it had stays as
   `.pacsave`; a split left half done is finished before the next update
   goes forward, or that update refuses with the reason), an install
   cut off by a power
   cut in the middle of a package (its own files, owned by no package; a
   package that left pacman's database that way, the main kernel among
   them, is installed again by name: each install run notes what it
   installs), and files owned by no package that are byte for byte what
   the incoming package writes there (left by an earlier install of it,
   such as a split rollback by an older dryserver: each is compared with
   the package file pacman loaded, a link by where it points, and one file
   that differs, lies under a link or is missing from the package refuses
   them all).
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
   with `-rollback` and the older `-arch-date`. The old dryserver does not
   take the new one's word that it is done: it checks the update is in
   place (else it goes back at once), and the timers and the boot unit
   that revert it are its own, so a new dryserver with a bug there cannot
   keep an update nobody confirms.
9. **A reboot**, when a new kernel or glibc, systemd and the like came,
   pacman finished cleanly and the boot images are current, and the machine
   can come back by itself (a disk that asks for its passphrase at boot
   cannot): once, with the update still waiting for its confirm, which
   then comes after the restart (the window grows by 15 minutes). Otherwise
   `dryserver update status` says `reboot needed`, `reboot by hand`, or
   `do NOT reboot` (a package update that stopped part way, a power cut in
   pacman among them: the next update runs pacman whatever day it brings,
   also one that goes back to the day before, and finishes it).

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

A machine whose new kernel does not boot starts the fallback kernel by itself: see [When a kernel update does not boot](machines.md#when-a-kernel-update-does-not-boot).
