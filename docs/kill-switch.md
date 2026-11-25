# <img src="img/ring-5.svg" width="33" alt=""> Kill switch

Cut the coordinator, or any machine, off from every server, straight from your desktop.

Part of the [dryserver README](../README.md).

If you think the coordinator is hacked, cut it off from every server:

```sh
dryserver quarantine-all     # on the desktop
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
4. `dryserver approve`: it says the machine there has another SSH key.
   Press `n`, compare the code with the new coordinator's screen, confirm.
   Your desktop signs a new list with the new coordinator in the old one's
   place; every machine you signed before stays in it,
5. `dryserver quarantine-all -lift`: each server reads the signed list
   from the coordinator's address, takes the new coordinator's keys from it
   and follows it. The old coordinator stays out.
6. `dryserver ssh-config`, once the servers have synced with the new
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
`dryserver quarantine-all -lift -same`. Do that only when you are sure.

`quarantine` also prints the WireGuard peers each server keeps. A hacked
coordinator may have added its own; cut any you do not know by name:
`dryserver quarantine-all -name rogue`. The same works for a hacked server:
it is cut off on all the others.

| Command | What it does |
|---|---|
| `dryserver quarantine-all` | desktop: cut the coordinator off on every server |
| `dryserver quarantine-all -name a,b` | desktop: cut members a and b off on every other server |
| `dryserver quarantine-all -status` / `-lift` | desktop: show or undo on every server |
| `dryserver quarantine-all -lift -same` | desktop: undo after a false alarm, trusting the same coordinator again |
| `sudo dryserver quarantine [-name a,b]` | on one server |
| `sudo dryserver quarantine -status` / `-lift [-same]` | on one server |

Run `dryserver ssh-config` again after adding servers, while the
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
  `dryserver outside`.
- After a false alarm, `-lift -same` trusts the same machine again, with
  whatever was done to it.
- Servers on an older dryserver do not know `-same` and `-min-version`
  (`quarantine-all -lift` passes them): lift there by hand with
  `sudo dryserver quarantine -lift`.
- The coordinator's IPv6 addresses on the WiFi/router network are not
  blocked. WireGuard is cut, and SSH still needs your key.
