# <img src="img/ring-5.svg" width="33" alt=""> Apps

How the cluster runs your apps, how they are reached from outside, and what happens when a machine leaves.

Part of the [dryserver README](../README.md).

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

## An app as a file

Each app is a small text file you keep, in the style of `config.env`:

```sh
# shop.app
NAME=shop
IMAGE=ghcr.io/you/shop:v1
PORT=8080
COPIES=2
HOST=shop.example.com
HOST=www.example.com example.com shop.example.net
HOST=admin.example.com:9000
```

| Key | What | |
|---|---|---|
| `NAME` | the app's name: a-z, 0-9 and -, starting with a letter, at most 40 | needed |
| `IMAGE` | an image you built on this computer, `localhost/NAME:TAG` (see below), or one from a registry, best pinned: `ghcr.io/you/shop@sha256:...` | needed, unless `REPO` |
| `REPO` | the GitHub repository that builds the app on every push: `github.com/you/shop` (see [Built by GitHub](#built-by-github)) | instead of `IMAGE` |
| `BRANCH` | the branch whose pushes deploy | `main` |
| `PORT` | the port the app listens on. Inside the cluster `http://shop` leads there, and so does every name without a port of its own. `none` for an app that takes no connections (a bot, a worker): then no `HOST` lines | needed |
| `COPIES` | how many run, 1 to 20 | 1 |
| `HOST` | public names, as many lines as you need, several per line (spaces or commas between). `name:port` leads that name to another port of the app | none: inside only |
| `ENTRANCE` | the way in from outside: `cloudflare`, or `vpn`: only your own devices, over the [VPN](vpn.md) (the VPS comes later) | `cloudflare` |
| `ENV` | a setting the app reads: `ENV=NODE_ENV=production`, as many lines as you need. The value is taken as written, `#` and all; quotes around it keep spaces at its ends | none |
| `SECRET` | the name of a secret the app reads, like `SECRET=DATABASE_URL`; its value never goes in the file (see [Settings and secrets](#settings-and-secrets)) | none |
| `MEMORY` | the most memory one copy may use: `256Mi`, `1Gi` | `512Mi` |
| `CPU` | the most CPU one copy may use: `1`, `0.5`, `250m` | `1` |

Keys may be written in any case; `#` starts a comment. Anything else is
refused with its line number, never passed over: an app started without a
line you wrote would be another app. A name is written the way DNS has it:
`Shop.Example.COM.` becomes `shop.example.com`; a name with letters outside
a-z goes in its `xn--` form; `*.example.com`, an IP address, `https://` or a
path are refused. One app has at most 50 names and 10 ports, and port 80
can only be its `PORT`; the ingress speaks plain http to the app, so port
443 is refused as a name's own port too.

```sh
dryserver app deploy shop.app    # show every change, make them on y (-yes: without asking)
dryserver app list               # each app, its servers, its names, and how each answers
dryserver app show shop          # the app as a file: dryserver app show shop > shop.app
dryserver app remove shop        # stop it, take its names out of Cloudflare
dryserver app sync               # bring Cloudflare in step (and set up the tunnel)
dryserver domains                # the domains your Cloudflare API token sees
```

## Your own image

Build it on your desktop and name it in the app file as `localhost/NAME:TAG`:

```sh
podman build -t shop:v1 .        # podman calls it localhost/shop:v1
docker build -t shop:v1 .        # docker too: dryserver tags it localhost/shop:v1
```

`app deploy` (or `app push localhost/shop:v1` alone) then:

1. asks every server which images it holds, and stops when one cannot be
   asked or is in the cluster but not in your server list (run
   `dryserver ssh-config`): an app landing there would not start,
2. saves the image to one file and signs what it is (its name, its build,
   the file's sha256 and size) with your key, like every other order,
3. sends file and signature over your own SSH login on the home network
   into `~/.dryserver/images` on each server that lacks it,
4. waits until each server took it. A server's sync looks every minute; as
   root it checks your signature, the size and the sha256, that its disk
   has room, keeps the file in `/var/lib/dryserver-images` and loads it
   into the cluster,
5. starts the app with that build. The cluster never tries to download a
   `localhost/` image from anywhere, so it runs only what you signed.

A tag is needed (`v1`, `2026-11-26`, ...). A new build under the same tag
is another build: `deploy` copies it and replaces the running copies one at
a time. To be able to go back, give each release its own tag: each server
keeps the three newest tags of an image, and every tag a pod on it runs,
pinned so the cluster's own cleanup leaves them alone (one dropped all the
same is loaded again from the kept file). The image must be built for
amd64 (x86-64). When podman and docker both have the name as different
builds, dryserver does not guess: remove the one you do not use.

A server checks, before it loads anything: your signature, the file's size
and sha256, that the file loads as exactly the one name you signed and as
that build (so it never overwrites another image), that nothing newer was
signed for the name before, that the document is not dated ahead of its
clock, and that its disk keeps room (three times the image, and a fifth of
the disk). A refused file is deleted; `sudo dryserver images` on the server
says what it holds and why it refused the last ones. Files a send left half
way are deleted after a day.
Your servers need this dryserver for it: publish a release once.

## Changing an app

`deploy` looks at what runs now and shows the difference before it changes
anything:

```
shop:
  image   ghcr.io/you/shop:v1 -> ghcr.io/you/shop:v2
  + www.example.com
  - old.example.com (stops answering)
  = 3 names stay as they are
  Its copies are replaced one at a time (the image or a port changed).
Cloudflare Tunnel:
  - route admin.example.com, example.com, shop.example.com, www.example.com through the tunnel
  - add www.example.com to DNS, pointing at the tunnel
  - delete the DNS record of old.example.com (no app uses it)
Apply? [y/N]
```

On `y` it applies the app, then makes exactly the Cloudflare changes shown.
When Cloudflare would now make other ones (something changed in between),
it makes none there and says so; `dryserver app sync` looks again. Adding
or dropping a name that leads to the main port leaves the running copies
alone; a new image, another `PORT` or a port that comes or goes replaces
them one at a time (with two copies, nobody notices).

It stops before anything changes when:

- a name belongs to another app (each such name is listed),
- a name is in no domain your API token can see (it would be half public),
- a name has an A or CNAME record dryserver did not make: it is listed with
  what it points at. `-take-over NAME` lets dryserver replace that record;
  the change shows first. A name's other records (MX, TXT) are never
  touched, so email on `example.com` keeps working,
- the entrance is not set up (the VPS, for now),
- an app in the cluster was set up by a newer dryserver: this one would
  read its names wrong. Update this computer first.

It warns, and goes on after `y`, when a name is two levels below its domain
(`a.b.example.com`: Cloudflare's free certificate does not cover it, so
browsers refuse it) and when a domain is not active in Cloudflare yet. When
Cloudflare does not answer while it looks, it says so: on `y` the app starts
and its names are synced later with `dryserver app sync`. A change cut off
half way is finished by the next `deploy` or `sync`. Without an API token
it says which names to add or remove in the Cloudflare dashboard.

`app list` asks each name over https, the way a visitor's browser does:
`answers (HTTP 200)`, `HTTP 502: the app does not answer yet`, `HTTP 530`
(Cloudflare cannot reach the tunnel), `not in DNS yet`, `certificate
error`. `-no-check` leaves that out.

**Apps with a reverse proxy of their own** (nginx or Caddy inside the
container, choosing by name) work as they are: the name the visitor typed
reaches the app unchanged (the `Host` header). Let it speak plain http on
`PORT`, with its own https and certificates off: Cloudflare already did
that part. What the app sees of the visit:

- The ingress tells every app `X-Forwarded-Proto: http`, since the tunnel
  reaches it over plain http. An app that sends http visitors on to https
  (nginx `return 301 https://...`, Django's `SECURE_SSL_REDIRECT`) would
  send them round and round: leave that to Cloudflare instead (SSL/TLS,
  Edge Certificates, Always Use HTTPS). Cloudflare's own `CF-Visitor`
  header says `{"scheme":"https"}` when the visitor used https.
- The visitor's address is in `CF-Connecting-IP`, which Cloudflare sets
  itself. `X-Forwarded-For` and `X-Real-Ip` carry the tunnel's address.
- Many apps check the name they are called by (Django's `ALLOWED_HOSTS`,
  Nextcloud's `trusted_domains`, Vite's `allowedHosts`): list your names
  there too.
- Cookies and logins belong to one name: logged in on `example.com` is
  not logged in on `example.net`.

## Settings and secrets

`ENV=` lines are settings: they live in the app file, so put nothing secret
there (app files often end up in git; `deploy` points at names like
`*_TOKEN` or `*PASSWORD`). dryserver sets `PORT` to the app's `PORT`, and
nothing else: an image's own settings (its `ENV` lines) stay as they are
unless the file sets the same name. Node.js 20 and newer size their heap to
`MEMORY` by themselves; to set it anyway:
`ENV=NODE_OPTIONS=--max-old-space-size=384`.

A secret's name goes in the file (`SECRET=DATABASE_URL`), its value only
into the cluster, where it is kept encrypted:

```sh
dryserver app secret shop DATABASE_URL          # asks for it twice, not shown
echo "$VALUE" | dryserver app secret shop TOKEN  # from a pipe
dryserver app secret shop TLS_KEY -file key.pem  # a whole file
dryserver app secret shop                        # the names, never the values
dryserver app secret shop OLD_TOKEN -remove
```

A value never goes into a command line (where the shell's history and every
process listing would keep it): it goes to the cluster on stdin. Setting a
secret the running app reads replaces its copies one at a time, so they read
the new one. `deploy` refuses an app whose secret has no value yet; removing a
secret the app still lists is refused; `app remove` deletes the app's
secrets. A value is at most 64 KiB and never empty.

## Limits

Every copy gets at most `MEMORY` and `CPU` (512Mi and 1 CPU unless the file
says): a runaway app is stopped at its limit, never takes a machine. The
machine sets half of `MEMORY` aside for the copy, so busy apps fit, and the
cluster places copies only where that half fits. An app started by an older
dryserver has no limits until its file is deployed again (`dryserver app
show shop > shop.app`, then `deploy`: the preview says `limits  no limit ->
512Mi memory, 1 CPU`).

A new version starts beside the old one and takes over only once it takes
connections on its `PORT` and has kept running for 20 seconds: no moment
without a copy, and a version that never answers (or stops right after it
starts) never takes over. An app with `PORT=none` takes over once it has
run for 20 seconds.

## Built by GitHub

Push to `main`, and the app runs the new version a few minutes later (the
build on GitHub, then a minute at most for the coordinator):

```sh
cd ~/code/shop
dryserver app github init        # writes .github/workflows/dryserver.yml
git add .github/workflows/dryserver.yml && git commit -m "build with dryserver" && git push
dryserver app github token       # once: a classic token with only read:packages
```

```sh
# shop.app
NAME=shop
REPO=github.com/you/shop
PORT=3000
HOST=shop.example.com
SECRET=DATABASE_URL
```

```sh
dryserver app deploy shop.app
```

What happens on each push to the branch:

1. GitHub Actions builds the app on GitHub's machines: with its own
   `Dockerfile`, or with [Railpack](https://railpack.com) when it has none
   (Next.js, Vite, React, Express, ... detected by themselves). The image
   goes to GitHub's registry, private.
2. A second job, which runs none of the app's code, asks GitHub to sign a
   statement about exactly that image: this repository, this branch, this
   workflow file, this commit, a machine of GitHub's own. It puts the
   statement next to the image.
3. The coordinator asks the registry every minute (it dials out: no open
   port, no webhook), checks GitHub's signature and every part of the
   statement, and only then replaces the app's copies, one at a time.
4. A version whose copies never answer within 10 minutes is taken back to
   the last build that ran, by itself (by its image; settings and secrets
   stay as they are now); that build is not tried again. A deploy that
   changes settings and the build at once is not taken back by itself
   (which of them failed?): `dryserver app rollback` does that.

So only a push to the branch deploys. A pull request, another branch,
another repository, another workflow file, a run started by hand, a
self-hosted runner, or someone who can only write to the registry cannot:
the statement would not check out. Builds are ordered by GitHub's run
number, which a re-run keeps: running an old run again (Actions, "Re-run
jobs") never brings its old version back, nor lifts a rollback. To build
again, push: `git commit --allow-empty -m rebuild && git push`. Whoever can push to the branch can deploy, which is what push to deploy
means: protect the branch on GitHub (Settings, Branches). A repository made
anew under the same name is another one (GitHub's repository number is
remembered from the first build).

- `dryserver app list` shows which build runs and what the coordinator last
  said ("deploying build 0123456 of main", "build ... did not start").
- `dryserver app rollback shop` goes back to the build before; newer builds
  wait until the next push.
- `deploy` again after changing the file keeps the running build unless
  GitHub proved a newer one; when GitHub does not answer, the running build
  stays.
- The token can only read packages; it is kept in
  `~/.config/dryserver/secrets/github_token` (yours alone) and in the
  cluster for the servers to pull with. GitHub's registry takes only classic
  tokens. A token that can do more is taken, with a note.
- Your servers need this dryserver to follow GitHub (`dryserver release
  publish`); until then `deploy` says so, and deploying again after each push
  does the same by hand.
- Build-time settings (Next.js `NEXT_PUBLIC_*`) belong in the repository
  (`.env.production`), since the build runs on GitHub.

**Coming from dryserver 0.2.0**: run `make install` on every computer you
run dryserver on. An older dryserver reads only an app's first name, and
its next Cloudflare sync would delete the others' DNS records. The machines
need nothing new for this. Apps started from the menu keep working, as
files with one name.

## The menu

```sh
dryserver apps           # or "Apps" in the menu
```

`n` starts an app from a container image, one step at a time: a name (it
starts with a letter), the image, the port it listens on, a public host name
if it should be reachable from outside, and how many copies run. The last
step shows every answer; `enter` there starts the app, `esc` goes back to
change one. The screen shows what runs on which server and how each app is
reached from outside; `enter` shows an app's details, long names whole, and
what can be done to it; `d` removes an app after saying what that does (its
containers stop, its host name stops answering); `o` goes to the ways in from
outside. Under it is plain Kubernetes: on the coordinator, `k3s kubectl`
works for you without sudo. The form knows one name and one port: an app
with more (from its file) is changed with its file, and the form says so.

What an app file does is here too, run on the terminal as `dryserver app`
runs it (the screen comes back after, once you press enter):

- `f` deploys an app file: you type its path, then see every change and
  say `y` there. A `SECRET` without a value yet is asked for first (not
  shown).
- `s` (on an app) sets one of its secrets: its value is asked for, twice,
  not shown.
- `b` (on an app GitHub builds) goes back to the build before.
- `w` (on an app) writes its file, `~/NAME.app`, to change and deploy
  again with `f`; never over a file that is there.

The screen never waits for the coordinator: every question and change runs
in the background with a time limit (15 seconds for a look, a minute for a
change), a change shows its steps as it goes, and the screen says when the
coordinator does not answer, or answers with another host key (then `m`
opens Machines to look at it). What did not work stays on a card with the
key that tries again. Both
screens share one SSH connection, which ends by itself 20 seconds after the
last call. Its socket lives in `dryserver/` in your runtime directory
(`$XDG_RUNTIME_DIR`), made for you alone; when that directory is a link,
someone else's or open to others, nothing is shared and each call connects
by itself. Switching between the two screens (`o`, `a`) waits until a
change that runs (a deploy and its DNS sync) is done; going back (`esc`)
while one runs asks once, since it would stop half way.

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
- each public host name makes the built-in ingress (Traefik) route that name
  to the app, on the port the name leads to. The ingress has no port on any machine: what comes in from
  outside reaches it through a tunnel that runs inside the cluster. It runs
  on every machine, so it does not go down with one server,
- containers cannot gain privileges and get no cluster credentials,
- the firewall on every machine is a wall around all pods: web out, never
  your home network, never SSH on the machines; a NodePort or hostPort is
  not a door from the mesh or the home network,
- no machine is a router into the cluster: what arrives from the home
  network, the switch or the mesh is never passed on to pods elsewhere,
- each server joins the cluster with a token of its own, made for it
  alone and deleted once it is in. From then on it shows its own
  certificate, which k3s takes for its own name only: no server can
  register a machine under the name of another, also not one you just
  approved. The token does not open the control plane, and the registry
  account cannot read it (see [Security](security.md)).

k3s is one pinned release, downloaded from its GitHub releases when the USB
stick is built and checked against the checksum dryserver was built with.

## Reaching apps from outside

Setting it up, step by step, is in the README:
[Reaching apps from outside](../README.md#reaching-apps-from-outside). How it works:

No machine opens a port to the internet. What comes in arrives through an
entrance, and the Outside screen shows them all, how each is doing and
which host names come in through it. `enter` on one shows its details and
what can be done to it: open it with the token you saved (`o`), sync it
(`s`), take a name over (`t`), close it (`x`); `a` goes back to the apps:

```sh
dryserver outside        # or "Outside" in the menu, or o on the apps screen
```

- **Cloudflare Tunnel**: two pods in the cluster dial out to Cloudflare,
  which sends what arrives for your host names through them to the ingress.
- **VPN (your devices)**: your phone and laptop over WireGuard to one
  gateway server, and only they; Cloudflare only answers the names (DNS
  only). See [VPN for your devices](vpn.md).
- **Your VPS**: not built yet. A server you rent will relay web and game
  ports (TCP and UDP) to the cluster over WireGuard.

Each public host name belongs to one app and comes in through one entrance;
an app may have many names, all through its entrance.
The choice is stored on the app's Ingress as the annotation
`dryserver/entrance`; an Ingress without it comes in through Cloudflare, so
apps started before there was a choice keep working. The apps form asks
for it only when more than one entrance is set up. A host name that
another app already has is refused; one that two apps claim anyway (made
with kubectl) is served by neither, and the Outside screen says so.

The Cloudflare Tunnel can be set up two ways: from your computer with one
API token, or by hand in the dashboard.

### What `s` does in `dryserver outside`

It first lists every change it would make, in order, and makes exactly
those on `y` (any other key changes nothing; a plan that changed since is
not made). The same every time, so running it again changes nothing and a
run cut off half way is finished by the next one:

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
resolve for that moment, and the list says so. When a call is refused, the card names the
permission the token lacks, or says the token was revoked. When Cloudflare is down, nothing is changed and
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

### The tunnel in the cluster

The token is stored in the cluster as an encrypted secret. The tunnel
pods run as a plain user with a read-only file system, no privileges and no
cluster credentials, from one cloudflared image pinned by its digest.
Nothing in the cluster may connect to them, and they may connect only to
Cloudflare, DNS and the ingress.

## When a machine leaves

Remove a server in `dryserver approve` and the cluster follows: the
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

A removed server holds no token: its own was deleted when it joined. Its
certificate is good for its own name only, and that machine is out of the
mesh, so it no longer reaches the cluster.

A server whose node is gone, or a name that is taken: see [A new cluster token](../README.md#a-new-cluster-token).
