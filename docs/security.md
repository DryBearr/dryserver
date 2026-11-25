# <img src="img/ring-5.svg" width="33" alt=""> Security

What protects the swarm, and what a hacked coordinator or server can and cannot do.

Part of the [dryserver README](../README.md).

## What protects the swarm

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
  so `dryserver approve` shows who cut whom. Each server decides this for
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
  swap its own keys into a waiting request. A waiting server whose
  coordinator answers five times in a row with another SSH host key than
  the one it saw when it asked (something else answered in its place then,
  or the coordinator was installed again) forgets that key, asks again
  and shows a new code on its screen, saying why. After approval, the
  member list is only served over the mesh. Removing a machine (`d` in
  `dryserver approve`) drops it from all servers within a minute.
  The approval screen signs exactly the request you chose (its keys, not
  only its id), and shows none of the requests the coordinator lists more
  than once under one id, name or key. A request the coordinator turns
  down because its name is a member's, or another machine waits under it,
  shows on the machine's screen with the reason and its code, and on the
  approval screen with that code and what to do (remove the old member,
  or reject the other request). One address may have three requests
  waiting at most: every server holds the key that asks.
- **Unknown devices**: the coordinator scans its networks every 15 minutes and
  lists unknown devices in `dryserver approve` (report only). A server's
  own word about its address does not hide a device there: it counts only
  where WireGuard on the coordinator sees that server's packets come from
  (when it talks over the WiFi/router network), and an address two servers
  claim, or one claims that is not where it talks from, is listed with a
  note. Limit: a server that talks to the coordinator over the switch can
  still name one address as its own.
- **Hardening**: kernel sysctl hardening, no LLMNR/mDNS, WireGuard peers
  locked to their own mesh address.
- **Nothing from the coordinator is used unchecked.** Servers check every
  name, key and address in the member list before it reaches `/etc/hosts`,
  WireGuard or the SSH trust files, and drop entries that are malformed or
  appear twice.
- **Signed member list**: your own SSH key, the one in the config, signs
  the swarm: building the USB stick copies its public half to
  `secrets/signing_ed25519.pub` and onto every server. `dryserver approve`
  on your computer signs every decision (approve, reject, remove) with it,
  through ssh-agent or `~/.ssh`. The same key logs you in to the machines;
  that is safe because every signature is made for one named use
  (`dryserver-members`, `dryserver-release`...) and an SSH login signs
  data of another form, so no signature passes for another. Servers do not
  allow agent forwarding, so a server cannot borrow your agent to sign.
- **Replacing the key** (`dryserver replace-key`): the old key signs a key
  change ("trust this key from now on"), carried in every member list
  after it, which the new key signs. Each machine follows the changes from
  the key it trusts, checking each with the key it replaces, and trusts
  the key at the end: the newest list it took (root's, only ever newer)
  says which, so a key once handed on is never trusted again, after a
  reboot too. The coordinator refuses a list that leaves a change out, so
  a machine that was off, or installed from an older stick, still follows.
  A change that also logs in puts the new key in place of the old one in
  the admin's `authorized_keys`. Limit: only the holder of the key trusted
  now can hand the trust on. A lost key with no backup cannot be replaced,
  and a thief with your key can replace it too; whoever does so first
  holds the swarm. The coordinator stores and
  hands out the signed list but cannot make or change one. Servers use only
  the machines in the signed list: one the coordinator adds by itself is
  ignored and logged, and an older list is refused, so a removed machine
  cannot be brought back. A server that finds itself gone from a newer
  signed list stops k3s and its containers and no longer counts itself a
  member. Nobody can approve on a server, the coordinator
  included, and a machine that shows up on the coordinator without a join
  request cannot be signed at all. `dryserver ssh-config` takes server
  names and SSH host keys from the signed list too. The registry account
  can stall the registry (hold its lock, fill it, drop or roll back the
  list): the coordinator's own sync then keeps to the newest list it has
  seen, so a server you removed stays out of its mesh and out of the
  cluster, and its console shows an alarm until the registry is right
  again (servers get no newer list meanwhile, and updates wait). The
  registry account could also take your newest list, answer your desktop
  with it and never keep it: root on the coordinator leaves a receipt for
  the list it follows, signed with its SSH host key, and `dryserver
  approve` and `release status` check it against the coordinator's key in
  the list you signed. Three minutes after you signed a list the
  coordinator does not follow, they say so plainly (also with no receipt,
  a forged one, or none newer than 15 minutes). Limit: a
  hacked coordinator can hold back a newer list from servers that have not
  seen it yet, so a removal may not arrive; cut the machine off with
  `dryserver quarantine-all -name NAME` then.
- **The registry account cannot steer an update.** A release installs
  only with your signature, checked by each machine itself. The order of
  the rollout is not the registry's either: root on the coordinator signs
  each server's turn (that server, that release, a few minutes) with its
  SSH host key, and a server updates only on a turn signed for it. A
  resume or a skip counts only with your signature, checked by root, once,
  for the stop it is at. Each machine signs its own report (release,
  update state, LAN address), so the registry cannot mark a server updated
  or hide one that went back.
- **Each server joins the cluster with a token of its own, and the
  registry never holds one.** Servers get the member list from an account
  on the coordinator that every server reaches over SSH, so whatever that
  account can read counts as known. The tokens k3s agents join with are not
  among it: with one, the account could join a machine of its own to the
  cluster and draw apps and their secrets there. Root on the coordinator
  makes a token for each server in the signed list that is not in the
  cluster yet, encrypts it with `age` to that server's SSH host key, and
  signs it with the coordinator's host key; the account only passes on
  what it cannot read. Once the server's node is in the cluster the token
  is deleted, and the server goes on with its kubelet certificate, which
  k3s takes for its own name only. One token for all servers would let a
  hacked server register a node under the name of a server you just
  approved, before that one does: k3s would then turn the real one away
  and send that server's pods and their secrets to the hacked one. A token
  of its own alone is not enough either, as a bootstrap token registers
  any name: a server holding one before it joined could take another
  name with it. So each token comes with a node password made for that
  server's name, sealed with it; root puts the password's hash into the
  cluster (k3s's secret `NAME.node-password.k3s`, marked as root's and
  kept until the server leaves) before it hands out the token, and k3s
  gives a certificate for the name only to the machine that shows the
  password. A node under a server's name counts as that server's only
  with that password; a name a machine took without it is kept from every
  server for a year (see [A new cluster token](../README.md#a-new-cluster-token)). A
  server that was in the cluster never gets a token again, so leaving the
  cluster on purpose gets a hacked server nothing. A server takes only a
  token made for its own key and signed by the coordinator in the signed
  list. Anything else changes nothing (nothing written, k3s not
  restarted) and is logged once. Encrypting alone would not do: anyone can
  encrypt to a public key, and a token carrying the hash of another
  certificate authority would have the server trust whoever answers on the
  coordinator's k3s port. A token without that hash is refused for the
  same reason. A server whose SSH host key is not ssh-ed25519 gets no
  token, and the coordinator logs why.
  - Coming from an older dryserver: servers that joined stay in the cluster
    and need nothing new. They hold the token older versions shared among
    all servers (once in the registry in plain text, so the registry
    account could read it too): make a new one ([A new cluster
    token](../README.md#a-new-cluster-token)); the coordinator says so until you do. A
    server on an older dryserver that has not joined yet joins once it is
    updated (a rollout updates the coordinator first); an updated server
    never takes a token from an older coordinator. Servers in the cluster
    keep the node passwords k3s made for them.
  - Limit: a machine that got a certificate for a name while the
    coordinator's sync did not run for ten minutes (k3s forgets the
    password of a name without a node then) is not seen.
  - Limit: the registry account can send a server an older token the
    coordinator sealed for it, which then fails; the next one arrives at
    the next sync the account lets through.
- **The USB stick** holds the WiFi password, the key that lets machines ask
  to join and the join secret. Whoever has it can make a join request that
  looks installed from your stick; it still needs your approval and a
  matching code. Keep it safe, or re-flash it after installing.

## SSH between machines

No private keys are stored on servers, and your desktop key is never forwarded
to them. A hacked server, the coordinator included, cannot use your key to log
into the others. Connect to each server from the desktop:

```sh
dryserver ssh-config     # writes ~/.ssh/config.d/dryserver
ssh node-a                 # jumps through the coordinator
scp -3 node-a:file node-b: # copy between servers through the desktop
```

Add `Include config.d/*` at the top of `~/.ssh/config` if it is not there.
Servers refuse agent forwarding even if you ask for it with `ssh -A`.

`ssh-config` also writes `<name>.lan` entries, for example `ssh node-a.lan`:
straight to the server's WiFi/router address, not through the coordinator,
checked against the same pinned host key. The kill switch uses them. The
address is the one the server signed in its report with its own host key
(your desktop remembers the newest one), so the coordinator's registry
account cannot point the kill switch elsewhere; for a server of an older
version, which signs nothing, it is the coordinator's word.

Host keys are checked against `~/.ssh/known_hosts.d/dryserver` alone, which
holds the keys from the list you signed, and a server with any other key
is refused. A key you once accepted in `~/.ssh/known_hosts` (say of an old
coordinator at the same address) never counts. After a machine is
reinstalled and approved, run `dryserver ssh-config` again.
