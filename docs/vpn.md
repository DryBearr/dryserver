# VPN for your devices

Your phone and laptop reach chosen apps (Matrix, an admin page, a NAS page)
over a WireGuard VPN of their own, from anywhere. No Cloudflare, no VPS,
nothing in between: the connection is encrypted from your device to your
gateway server, and the app's https certificate is your own.

Part of the [dryserver README](../README.md).

## Set it up

1. **Choose the gateway**: one server (not the coordinator) your router can
   forward a port to. Give it a fixed address on your network (DHCP
   reservation in the router), if it has none yet.
2. **Check that your line has its own public address**:

   ```sh
   curl -s https://ifconfig.me; echo
   ```

   Compare with the WAN (internet) address on your router's status page.
   The same: good. Different, or the router shows `100.64.x.x` to
   `100.127.x.x`, `10.x.x.x`, `172.16.x.x` to `172.31.x.x` or `192.168.x.x`:
   your provider shares one address among many customers (CGNAT), and no
   port forward on your router reaches you. Ask your provider for a public
   IPv4 address, or wait for the VPS entrance.
3. **Turn it on** (signs the member list; the gateway follows within a
   minute):

   ```sh
   dryserver vpn on node-a --endpoint 203.0.113.7
   ```

   `--endpoint` is what devices dial: that public address, or a DNS name
   for it (one you keep pointed at your line, like `vpn.example.com`).
   `--vpn-port` (default 51821) is the UDP port on the gateway; `--public-port`
   when your router forwards another outside port to it; `--subnet`
   (default `10.99.0.0/24`) when that one is in use where your devices go.
4. **Forward the port on your router**: UDP 51821 (or `--public-port`) to
   the gateway's address, port 51821. On a TP-Link: Transmission (or NAT),
   Virtual Servers. Only this one UDP port; WireGuard answers nothing to
   anyone without a key, so the port looks closed to everyone else.
5. **The certificates' token**, once: in the Cloudflare dashboard, My
   Profile, API Tokens, Create Token, with **Zone: DNS: Edit** and **Zone:
   Zone: Read**, for the domains of your VPN's apps only. Then, on the
   gateway itself (a minute after step 3):

   ```sh
   dryserver ssh-config       # once, on your computer: the machines by name
   ssh node-a
   sudo dryserver vpn token   # asks for it (not shown), or pipe it in
   ```

   It is checked with Cloudflare and kept in a file only the VPN's Traefik
   reads (`/var/lib/dryserver-vpn/secrets`), never in the cluster: there,
   the cluster's own ingress on every machine may read every secret. It
   goes when the server stops being the gateway; a new gateway needs it
   again.
6. **Add your devices**, one name each:

   ```sh
   dryserver vpn add phone
   ```

   prints the device's config: import it in the WireGuard app (Android, iOS,
   Windows, macOS, Linux: "add tunnel", from file or by typing it). It holds
   the device's private key, which dryserver does not keep. With
   `--out phone.conf` it goes to a file (yours alone) instead; delete it
   after the import. A device that made its own key (the WireGuard app's
   "create from scratch" shows its public key) keeps its private key to
   itself:

   ```sh
   dryserver vpn add laptop --key 'PUBLIC KEY FROM THE APP='
   ```

   then type the printed `[Peer]` part into the app.
7. **Put an app on the VPN**: `ENTRANCE=vpn` in its app file, then deploy:

   ```sh
   # admin.app
   NAME=admin
   IMAGE=ghcr.io/you/admin-panel:v1
   PORT=8080
   HOST=admin.example.com
   ENTRANCE=vpn
   ```

   ```sh
   dryserver app deploy admin.app
   ```

   Its name goes into Cloudflare DNS as an A record to the gateway's VPN
   address (`10.99.0.1`), DNS only (grey cloud): Cloudflare answers the
   name, and sees nothing of the traffic. The first visit can take a
   minute or two while Let's Encrypt issues its certificate.

```sh
dryserver vpn                 # the gateway, and when each device was last seen
dryserver vpn remove phone    # cut a device off (within a minute)
dryserver vpn off             # no VPN; the devices stay listed for later
```

## What a device can reach

Exactly the apps with `ENTRANCE=vpn`, on https (http goes to https), and
nothing else:

- not SSH or anything else on the gateway (a ping, yes),
- not the mesh, the other servers or the cluster,
- not your home network or the router,
- not the other devices,
- not the internet through the gateway: only the VPN's own address goes
  through the tunnel; everything else the device does goes out as before.

The device's config has no DNS server: with the gateway down, only the
VPN's apps stop, never the device's internet.

## How it works

- **The signed list.** Which server is the gateway, its port and subnet,
  and every device with its key and address are in the member list you
  sign. The coordinator cannot add a device or move the gateway; a device
  you remove is gone from the gateway within a minute.
- **The gateway** runs a second WireGuard interface (`wgp`), kept by its
  sync each minute: made, given `10.99.0.1` and exactly the listed devices,
  taken down when it is not the gateway any more. It uses the server's mesh
  key, whose public half is in the signed list already: a device's config
  needs nothing only the coordinator says. Each device is locked to its own
  address.
- **The firewall** on every machine has the VPN's rules (inert without
  `wgp`): from `wgp`, a ping to the gateway and the VPN's ingress, nothing
  else, logged as `dryserver-vpn-drop` (`journalctl -k -g dryserver-vpn`).
  The port it listens on is a set the gateway's sync fills.
- **The VPN's ingress** is a Traefik of its own (namespace `vpn`), on the
  gateway, listening only on `10.99.0.1` ports 80 and 443. It serves only
  Ingresses labelled `dryserver/vpn`, and the cluster's own Traefik (which
  the tunnel reaches) serves none of them: a VPN app is never one Host
  header away through the tunnel. Its certificates come from Let's
  Encrypt by DNS challenge with the token from step 5, and are kept on the
  gateway (`/var/lib/dryserver-vpn/acme`, its account's alone). A network
  policy lets only the devices' addresses reach it: no other pod, no
  machine, not the gateway's own accounts.
- **A VPN app** takes connections only from the VPN's Traefik: not from
  the cluster's ingress, not from the other apps.
- An app moving between the tunnel and the VPN takes its DNS name with it:
  each side deletes the other's record of dryserver's (and nothing else's).

## Limits

- **One gateway.** When it is down, the VPN is down (the apps keep running
  for the rest). Moving it: `dryserver vpn on node-b`, then change the
  router's port forward and give the devices their new config.
- **A changing home address.** The WireGuard apps look the endpoint's name
  up only when the tunnel starts: after your address changed, turn the
  tunnel off and on. A DNS name kept up to date (your router's DDNS, for
  example) beats a bare address here.
- **CGNAT** (step 2): no port forward reaches you; the VPS entrance will.
- Names on the VPN are in public certificate logs (as every certificate's
  name is) and their DNS record shows the private address `10.99.0.1`.
  Neither shows any traffic.
- Some home routers drop DNS answers with private addresses ("DNS rebind
  protection"). If a VPN app's name does not resolve on such a network,
  set a public DNS server in the device's settings, or an exception in that
  router.
- The token from step 5 can change DNS of its domains: give it those
  domains only. It is on the gateway, where root can read it.
- **A hacked coordinator** cannot add a device or move the gateway (both
  are in the list you sign), but it runs the cluster: it could replace the
  VPN's Traefik, see what devices send to the VPN's apps, and read the
  gateway's files. A removed device is cut off once the gateway has the
  newer list, which the coordinator could hold back (`dryserver approve`
  then says the coordinator has not followed it). Removing the gateway
  machine itself (`d` in `dryserver approve`) ends the VPN at once.
