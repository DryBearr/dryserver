#!/bin/bash
# Live check of the server firewall dryserver generates: real nftables and
# real connections between network namespaces, inside an unprivileged user
# namespace, so nothing on the host changes.
#
#   srv   the server (10.66.0.2 on "wg0", 192.168.1.20 on "eth0", a
#         "docker0" bridge with one container behind it)
#   mesh  the coordinator (10.66.0.1) and another server (10.66.0.3)
#   lan   the router (192.168.1.1), the coordinator's LAN address (.50),
#         the admin's desktop (.99) and "the internet" (8.8.8.8)
#   ct    a container (172.17.0.2)
#
# Needs nft, ip, python3 and unprivileged user namespaces.
#
#   cargo build && test/live-firewall.sh [path/to/dryserver]
set -uo pipefail
BIN=$(realpath "${1:-$(dirname "$0")/../target/debug/dryserver}")
if [ -z "${DRYSERVER_LIVE_NS:-}" ]; then
    exec env DRYSERVER_LIVE_NS=1 unshare -rmu --propagation private bash "$0" "$BIN"
fi
W=$(mktemp -d)
pass=0 fail=0
ok() { echo "  PASS $*"; pass=$((pass + 1)); }
bad() { echo "  FAIL $*"; fail=$((fail + 1)); }

cat > "$W/config.env" <<'EOF'
COORD_LAN_IP='192.168.1.50'
WG_SUBNET='10.66.0.0/24'
WG_PORT='51820'
WG_TRANSPORT='auto'
SWITCH_SUBNET='172.16.66.0/24'
MESH_PORTS='8080/tcp 5353/udp'
EGRESS_PORTS='25565/tcp 27015/udp'
USERNAME='admin'
ADMIN_SSH_PUBKEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVmCw4JXa0JQ1x0Z3ZJ3vY3lMSa7p4rG5Q6k8hO2c3d me@desk'
TOOLS=''
EOF
"$BIN" sysconf --config "$W/config.env" --out "$W/node" --role node --hostname node-b --host 2 >/dev/null || exit 1
"$BIN" sysconf --config "$W/config.env" --out "$W/coord" --role coordinator --hostname coord --host 1 >/dev/null || exit 1

pids=()
ns() { unshare -n sleep 900 & pids+=($!); eval "$1=$!"; }
ns SRV; ns MESH; ns LAN; ns CT
sleep 0.3
trap 'kill "${pids[@]}" $(jobs -p) 2>/dev/null; rm -rf "$W"' EXIT
in_() { local p=$1; shift; nsenter -t "$p" -n "$@"; }
for p in $SRV $MESH $LAN $CT; do in_ $p ip link set lo up; done

# The mesh: named wg0 on the server so the rules match it.
in_ $SRV ip link add wg0 type veth peer name m0 netns $MESH
in_ $SRV ip addr add 10.66.0.2/24 dev wg0; in_ $SRV ip link set wg0 up
in_ $MESH ip addr add 10.66.0.1/24 dev m0; in_ $MESH ip addr add 10.66.0.3/24 dev m0; in_ $MESH ip link set m0 up
# The home network and the internet behind its router.
in_ $SRV ip link add eth0 type veth peer name l0 netns $LAN
in_ $SRV ip addr add 192.168.1.20/24 dev eth0; in_ $SRV ip link set eth0 up
for a in 192.168.1.1 192.168.1.50 192.168.1.99; do in_ $LAN ip addr add $a/24 dev l0; done
in_ $LAN ip link set l0 up
in_ $LAN ip addr add 8.8.8.8/32 dev lo
in_ $SRV ip route add default via 192.168.1.1
in_ $LAN ip route add 172.17.0.0/16 via 192.168.1.20   # never used: the server hides containers
# A container behind docker0, hidden behind the server's addresses like
# Docker does it.
in_ $SRV ip link add docker0 type bridge
in_ $SRV ip addr add 172.17.0.1/16 dev docker0; in_ $SRV ip link set docker0 up
in_ $SRV ip link add vethc type veth peer name c0 netns $CT
in_ $SRV ip link set vethc master docker0; in_ $SRV ip link set vethc up
in_ $CT ip addr add 172.17.0.2/16 dev c0; in_ $CT ip link set c0 up
in_ $CT ip route add default via 172.17.0.1
in_ $SRV sysctl -qw net.ipv4.ip_forward=1
in_ $SRV nft -f - <<'EOF'
table ip dockernat {
	chain post { type nat hook postrouting priority srcnat; ip saddr 172.17.0.0/16 oifname != "docker0" masquerade; }
}
EOF

# One listener for every address and port the checks use. TCP answers
# "ok", UDP echoes.
listen() { # pid, then ip:port[/udp] ...
    local p=$1; shift
    in_ $p python3 -I - "$@" <<'PY' &
import socket, sys, threading
def tcp(ip, port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((ip, port)); s.listen(64)
    while True:
        c, _ = s.accept()
        try: c.sendall(b"ok")
        except OSError: pass
        c.close()
def udp(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((ip, port))
    while True:
        d, a = s.recvfrom(100); s.sendto(d, a)
for spec in sys.argv[1:]:
    addr, _, proto = spec.partition("/")
    ip, port = addr.rsplit(":", 1)
    threading.Thread(target=udp if proto == "udp" else tcp, args=(ip, int(port)), daemon=True).start()
threading.Event().wait()
PY
}
listen $SRV 0.0.0.0:22 0.0.0.0:8080 0.0.0.0:9000 0.0.0.0:5353/udp 0.0.0.0:7000/udp
listen $MESH 10.66.0.1:22 10.66.0.1:9999 10.66.0.3:8080 10.66.0.3:22 10.66.0.3:5353/udp
listen $LAN 8.8.8.8:443 8.8.8.8:80 8.8.8.8:53 8.8.8.8:25 8.8.8.8:25565 8.8.8.8:6667 8.8.8.8:53/udp 8.8.8.8:123/udp 8.8.8.8:27015/udp 8.8.8.8:9/udp \
    192.168.1.50:22 192.168.1.99:22 192.168.1.99:80 192.168.1.1:53/udp 192.168.1.1:80
sleep 0.5

# reach PID [SRC] DST PORT [udp] -> "open", "refused" (answered at once) or
# "silent" (no answer in 1.5 s).
reach() {
    local p=$1; shift
    in_ $p python3 -I - "$@" <<'PY'
import socket, sys, time
a = sys.argv[1:]
src = a.pop(0) if len(a) >= 3 and a[2] != "udp" or len(a) == 4 else None
dst, port = a[0], int(a[1]); udp = len(a) > 2 and a[2] == "udp"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
s.settimeout(1.5)
if src: s.bind((src, 0))
t = time.time()
try:
    if udp:
        s.sendto(b"x", (dst, port)); s.recvfrom(10)
    else:
        s.connect((dst, port)); s.recv(2)
    print("open")
except socket.timeout:
    print("silent")
except OSError:
    print("refused" if time.time() - t < 1.0 else "silent")
PY
}
want() { # description, expected, then reach arguments
    local msg=$1 exp=$2; shift 2
    local got; got=$(reach "$@")
    if [ "$got" = "$exp" ]; then ok "$msg ($got)"; else bad "$msg (wanted $exp, got $got)"; fi
}

echo "== without the firewall everything connects (the checks themselves work)"
want "node -> server:22" open $MESH 10.66.0.3 10.66.0.2 22
want "server -> internet:25" open $SRV 8.8.8.8 25
want "container -> home network:80" open $CT 192.168.1.99 80
want "container -> mesh:22" open $CT 10.66.0.3 22

echo "== server role"
in_ $SRV nft -f "$W/node/etc/nftables.conf" || { echo "the generated firewall does not load"; exit 1; }
echo "-- into the server, over the mesh"
want "coordinator -> :22 (the admin's way in)" open $MESH 10.66.0.1 10.66.0.2 22
want "another server -> :22" silent $MESH 10.66.0.3 10.66.0.2 22
want "another server -> :8080 (MESH_PORTS)" open $MESH 10.66.0.3 10.66.0.2 8080
want "another server -> :5353/udp (MESH_PORTS)" open $MESH 10.66.0.3 10.66.0.2 5353 udp
want "another server -> :9000 (not opened)" silent $MESH 10.66.0.3 10.66.0.2 9000
want "coordinator -> :9000 (not opened)" silent $MESH 10.66.0.1 10.66.0.2 9000
if in_ $MESH ping -c1 -W1 -I 10.66.0.3 10.66.0.2 >/dev/null 2>&1; then ok "ping from a member"; else bad "ping from a member"; fi
echo "-- into the server, from the home network"
want "desktop -> :22" open $LAN 192.168.1.99 192.168.1.20 22
want "desktop -> :8080 (mesh ports stay inside the mesh)" silent $LAN 192.168.1.99 192.168.1.20 8080
want "desktop -> :9000" silent $LAN 192.168.1.99 192.168.1.20 9000
echo "-- out of the server"
want "-> internet:443" open $SRV 8.8.8.8 443
want "-> internet:80" open $SRV 8.8.8.8 80
want "-> internet:53" open $SRV 8.8.8.8 53
want "-> internet:53/udp" open $SRV 8.8.8.8 53 udp
want "-> internet:123/udp (time)" open $SRV 8.8.8.8 123 udp
want "-> internet:25565 (EGRESS_PORTS)" open $SRV 8.8.8.8 25565
want "-> internet:27015/udp (EGRESS_PORTS)" open $SRV 8.8.8.8 27015 udp
want "-> internet:25 (mail), told at once" refused $SRV 8.8.8.8 25
want "-> internet:6667" refused $SRV 8.8.8.8 6667
want "-> internet:9/udp" refused $SRV 8.8.8.8 9 udp
want "-> coordinator's registry over the LAN" open $SRV 192.168.1.50 22
want "-> another machine at home :22" refused $SRV 192.168.1.99 22
want "-> the mesh, any port (the other side decides)" open $SRV 10.66.0.1 9999
echo "-- out of a container"
want "-> internet:443" open $CT 8.8.8.8 443
want "-> internet:25565 (EGRESS_PORTS)" open $CT 8.8.8.8 25565
want "-> internet:27015/udp (EGRESS_PORTS)" open $CT 8.8.8.8 27015 udp
want "-> internet:25" silent $CT 8.8.8.8 25
want "-> router:53/udp (DNS)" open $CT 192.168.1.1 53 udp
want "-> router:80 (home network)" silent $CT 192.168.1.1 80
want "-> desktop:80 (home network)" silent $CT 192.168.1.99 80
want "-> coordinator's LAN address :22" silent $CT 192.168.1.50 22
want "-> mesh :8080 (MESH_PORTS)" open $CT 10.66.0.3 8080
want "-> mesh :22" silent $CT 10.66.0.3 22

echo "== a member that knocks on closed ports is blocked"
in_ $MESH python3 -I - <<'PY'
import socket
for port in range(9100, 9160):
    s = socket.socket(); s.setblocking(False); s.bind(("10.66.0.3", 0))
    try: s.connect(("10.66.0.2", port))
    except OSError: pass
    s.close()
PY
sleep 0.5
if in_ $SRV nft list set inet dryserver offenders4 | grep -q "10.66.0.3"; then ok "the knocker is in the blocked set"; else bad "the knocker is in the blocked set"; fi
if in_ $SRV nft list set inet dryserver offenders4 | grep -q "10.66.0.1"; then bad "the coordinator was blocked too"; else ok "the coordinator is not in it"; fi
want "the knocker -> :8080 (was open for it)" silent $MESH 10.66.0.3 10.66.0.2 8080
want "coordinator -> :22 still" open $MESH 10.66.0.1 10.66.0.2 22
# A reload must not hand it a clean slate: the table is rebuilt, so sync
# has to have made the block lasting before (checked in the unit tests).

echo "== coordinator role"
in_ $SRV nft -f "$W/coord/etc/nftables.conf" || { echo "the coordinator firewall does not load"; exit 1; }
want "a server -> :22 (member list over SSH)" open $MESH 10.66.0.3 10.66.0.2 22
want "a server -> :9000" silent $MESH 10.66.0.3 10.66.0.2 9000
want "desktop -> :22" open $LAN 192.168.1.99 192.168.1.20 22
want "-> internet:25" refused $SRV 8.8.8.8 25
want "-> another machine at home :22" refused $SRV 192.168.1.99 22

echo "== $pass passed, $fail failed"
[ "$fail" = 0 ]
