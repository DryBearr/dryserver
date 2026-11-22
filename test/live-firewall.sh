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
#   pod   a k3s pod (10.42.1.2) behind a bridge named cni0, and one on
#         another machine (10.42.9.2) reached over VXLAN on "flannel.1"
#
# Needs nft, ip, bridge, python3 and unprivileged user namespaces; for the
# checks of accounts other than root (967 like the registry's, 1000 like
# the admin's) also newuidmap and this user's ids in /etc/subuid and
# /etc/subgid.
#
#   cargo build && test/live-firewall.sh [path/to/dryserver]
set -uo pipefail
BIN=$(realpath "${1:-$(dirname "$0")/../target/debug/dryserver}")
if [ -z "${DRYSERVER_LIVE_NS:-}" ]; then
    # Accounts besides root in here, from this user's subordinate ids.
    ids=()
    me=$(id -un)
    su=$(awk -F: -v u="$me" '$1 == u && $3 > 1000 { print $2 ":" ($3 > 65535 ? 65535 : $3); exit }' /etc/subuid 2>/dev/null)
    sg=$(awk -F: -v u="$me" '$1 == u && $3 > 1000 { print $2 ":" ($3 > 65535 ? 65535 : $3); exit }' /etc/subgid 2>/dev/null)
    if [ -n "$su" ] && [ -n "$sg" ] && unshare -r --map-users="1:$su" --map-groups="1:$sg" true 2>/dev/null; then
        ids=(--map-users="1:$su" --map-groups="1:$sg")
    fi
    exec env DRYSERVER_LIVE_NS=1 DRYSERVER_LIVE_IDS=${#ids[@]} unshare -rmu "${ids[@]}" --propagation private bash "$0" "$BIN"
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
ns SRV; ns MESH; ns LAN; ns CT; ns POD
sleep 0.3
trap 'kill "${pids[@]}" $(jobs -p) 2>/dev/null; rm -rf "$W"' EXIT
in_() { local p=$1; shift; nsenter -t "$p" -n "$@"; }
for p in $SRV $MESH $LAN $CT $POD; do in_ $p ip link set lo up; done

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
# A pod behind cni0, hidden behind the server's addresses when it leaves
# the cluster, like flannel does it. A NodePort (30080) and a hostPort
# (8443) lead to it, like kube-proxy and the CNI set them up.
in_ $SRV ip link add cni0 type bridge
in_ $SRV ip addr add 10.42.1.1/24 dev cni0; in_ $SRV ip link set cni0 up
in_ $SRV ip link add vethp type veth peer name p0 netns $POD
in_ $SRV ip link set vethp master cni0; in_ $SRV ip link set vethp up
in_ $POD ip addr add 10.42.1.2/24 dev p0; in_ $POD ip link set p0 up
in_ $POD ip route add default via 10.42.1.1
in_ $SRV sysctl -qw net.ipv4.ip_forward=1
# The pod network to another machine, like flannel sets it up: VXLAN over
# the mesh to 10.66.0.3, where a pod 10.42.9.2 answers.
in_ $SRV ip link add flannel.1 type vxlan id 1 local 10.66.0.2 dstport 8472 dev wg0 nolearning
in_ $SRV ip link set flannel.1 address 02:00:00:00:00:02 up
in_ $SRV ip addr add 10.42.1.0/32 dev flannel.1
in_ $SRV ip route add 10.42.9.0/24 via 10.42.9.0 dev flannel.1 onlink
in_ $SRV ip neigh add 10.42.9.0 lladdr 02:00:00:00:00:09 dev flannel.1 nud permanent
in_ $SRV bridge fdb add 02:00:00:00:00:09 dev flannel.1 dst 10.66.0.3 self permanent
in_ $MESH ip link add vx type vxlan id 1 local 10.66.0.3 dstport 8472 dev m0 nolearning
in_ $MESH ip link set vx address 02:00:00:00:00:09 up
in_ $MESH ip addr add 10.42.9.0/32 dev vx; in_ $MESH ip addr add 10.42.9.2/32 dev vx
in_ $MESH ip route add 10.42.1.0/24 via 10.42.1.0 dev vx onlink
in_ $MESH ip neigh add 10.42.1.0 lladdr 02:00:00:00:00:02 dev vx nud permanent
in_ $MESH bridge fdb add 02:00:00:00:00:02 dev vx dst 10.66.0.2 self permanent
# Every account may ping (ping sockets), like with ping's capability on a
# real machine.
if [ "${DRYSERVER_LIVE_IDS:-0}" != 0 ]; then
    in_ $SRV sysctl -qw net.ipv4.ping_group_range="0 65535"
else
    in_ $SRV sysctl -qw net.ipv4.ping_group_range="0 0"
fi
# A service address (10.43.0.20) whose endpoint is a server's mesh
# address, like a hostNetwork pod's.
in_ $SRV nft -f - <<'EOF'
table ip dockernat {
	chain post { type nat hook postrouting priority srcnat; ip saddr 172.17.0.0/16 oifname != "docker0" masquerade; ip saddr 10.42.0.0/16 ip daddr != 10.42.0.0/16 masquerade; ct status dnat oifname "wg0" masquerade; }
	chain pre { type nat hook prerouting priority dstnat; tcp dport { 30080, 8443 } dnat to 10.42.1.2:80; }
	chain out { type nat hook output priority -100; ip daddr 10.43.0.10 tcp dport 80 dnat to 10.42.1.2:80; ip daddr 10.43.0.20 tcp dport 443 dnat to 10.66.0.3:8080; }
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
listen $SRV 0.0.0.0:22 0.0.0.0:8080 0.0.0.0:9000 0.0.0.0:10250 0.0.0.0:6443 0.0.0.0:5353/udp 0.0.0.0:7000/udp
listen $POD 10.42.1.2:80
listen $MESH 10.66.0.1:22 10.66.0.1:9999 10.66.0.1:6443 10.66.0.3:8080 10.66.0.3:22 10.66.0.3:10250 10.66.0.3:5353/udp 10.42.9.2:80
listen $LAN 8.8.8.8:443 8.8.8.8:80 8.8.8.8:53 8.8.8.8:25 8.8.8.8:25565 8.8.8.8:6667 8.8.8.8:7844 8.8.8.8:53/udp 8.8.8.8:123/udp 8.8.8.8:27015/udp 8.8.8.8:9/udp 8.8.8.8:7844/udp \
    192.168.1.50:22 192.168.1.99:22 192.168.1.99:80 192.168.1.1:53/udp 192.168.1.1:80
sleep 0.5

# reach PID [SRC] DST PORT [udp|icmp] -> "open", "refused" (answered at
# once) or "silent" (no answer in 1.5 s). icmp: a ping (PORT is ignored).
# Runs as the account in RUNAS (a setpriv command), root when empty.
RUNAS=()
reach() {
    local p=$1; shift
    in_ $p "${RUNAS[@]}" python3 -I - "$@" <<'PY'
import socket, sys, time
a = sys.argv[1:]
src = a.pop(0) if len(a) >= 3 and a[2] not in ("udp", "icmp") or len(a) == 4 else None
dst, port = a[0], int(a[1]); proto = a[2] if len(a) > 2 else "tcp"
if proto == "icmp":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
else:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM)
s.settimeout(1.5)
if src: s.bind((src, 0))
t = time.time()
try:
    if proto == "icmp":
        s.sendto(b"\x08\x00\x00\x00\x00\x01\x00\x01ping", (dst, 0)); s.recvfrom(64)
    elif proto == "udp":
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
want_as() { # uid, then want arguments
    local uid=$1; shift
    RUNAS=(setpriv --reuid "$uid" --regid "$uid" --clear-groups)
    want "$@"
    RUNAS=()
}
# knock PID SRC DST FIRST LAST [ack]: a try on each port (a SYN), or with
# "ack" a late packet of a connection the other side forgot (an ACK).
knock() {
    in_ $1 python3 -I - "${@:2}" <<'PY'
import socket, struct, sys
src, dst, first, last = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
late = len(sys.argv) > 5 and sys.argv[5] == "ack"
def csum(b):
    if len(b) % 2: b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff
if late:
    r = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP); r.bind((src, 0))
    for port in range(first, last + 1):
        hdr = struct.pack("!HHIIBBHHH", 41000, port, 1000, 2000, 5 << 4, 0x10, 64240, 0, 0)
        pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(hdr))
        hdr = hdr[:16] + struct.pack("!H", csum(pseudo + hdr)) + hdr[18:]
        r.sendto(hdr, (dst, 0))
else:
    for port in range(first, last + 1):
        s = socket.socket(); s.setblocking(False); s.bind((src, 0))
        try: s.connect((dst, port))
        except OSError: pass
        s.close()
PY
}
in_set() { in_ $SRV nft list set inet dryserver "$1" 2>/dev/null | grep -q "$2"; }

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

echo "-- k3s: out of a pod"
want "-> internet:443" open $POD 8.8.8.8 443
want "-> internet:25" silent $POD 8.8.8.8 25
want "-> internet:7844 (Cloudflare Tunnel)" open $POD 8.8.8.8 7844
want "-> internet:7844/udp (Cloudflare Tunnel)" open $POD 8.8.8.8 7844 udp
want "-> router:53/udp (DNS)" open $POD 192.168.1.1 53 udp
want "-> desktop:80 (home network)" silent $POD 192.168.1.99 80
want "-> API server on the coordinator, over the mesh" open $POD 10.66.0.1 6443
want "-> coordinator :22 over the mesh" silent $POD 10.66.0.1 22
want "-> a kubelet over the mesh" open $POD 10.66.0.3 10250
want "-> mesh :8080 (MESH_PORTS)" open $POD 10.66.0.3 8080
want "-> this machine's kubelet" open $POD 10.42.1.1 10250
want "-> this machine's SSH" silent $POD 10.42.1.1 22
want "-> this machine's API port (a server has none for pods)" silent $POD 10.42.1.1 6443
want "-> a pod on another machine (VXLAN over the mesh)" open $POD 10.42.9.2 80
echo "-- k3s: into the cluster"
want "another server -> kubelet" open $MESH 10.66.0.3 10.66.0.2 10250
want "another server -> :6443 (a server is no API server)" silent $MESH 10.66.0.3 10.66.0.2 6443
want "this machine -> its pod" open $SRV 10.42.1.2 80
want "this machine -> a service address" open $SRV 10.43.0.10 80
want "another server -> NodePort" silent $MESH 10.66.0.3 10.66.0.2 30080
want "home network -> NodePort" silent $LAN 192.168.1.99 192.168.1.20 30080
want "home network -> hostPort" silent $LAN 192.168.1.99 192.168.1.20 8443
want "a container -> a pod" silent $CT 10.42.1.2 80

echo "== late packets are no tries"
# A machine that restarted forgot its connections; the other side's
# packets for them (ACKs to its old ports) keep coming for a while.
knock $MESH 10.66.0.3 10.66.0.2 41000 41079 ack
sleep 0.3
if in_set offenders4 10.66.0.3; then bad "80 late packets blocked the member"; else ok "80 late packets do not block the member"; fi
want "the member -> :8080 still" open $MESH 10.66.0.3 10.66.0.2 8080

echo "== a member that knocks on closed ports is blocked"
knock $MESH 10.66.0.3 10.66.0.2 9100 9159
sleep 0.5
if in_set offenders4 10.66.0.3; then ok "the knocker is in the blocked set"; else bad "the knocker is in the blocked set"; fi
if in_set offenders4 10.66.0.1; then bad "the coordinator was blocked too"; else ok "the coordinator is not in it"; fi
want "the knocker -> :8080 (was open for it)" silent $MESH 10.66.0.3 10.66.0.2 8080
want "coordinator -> :22 still" open $MESH 10.66.0.1 10.66.0.2 22

echo "== the coordinator is counted on its own, against a higher bar"
knock $MESH 10.66.0.1 10.66.0.2 9200 9259
sleep 0.3
if in_set coord_offender4 10.66.0.1 || in_set offenders4 10.66.0.1; then
    bad "60 tries from the coordinator blocked it (that stops every app)"
else
    ok "60 tries from the coordinator do not block it"
fi
want "coordinator -> :22 still" open $MESH 10.66.0.1 10.66.0.2 22
# A scan by its root: on the coordinator nothing else may try these.
knock $MESH 10.66.0.1 10.66.0.2 9300 9499
sleep 0.5
if in_set coord_offender4 10.66.0.1; then ok "a scan of 200 ports blocks the coordinator"; else bad "a scan of 200 ports blocks the coordinator"; fi
if in_set offenders4 10.66.0.1; then bad "the coordinator landed with the members"; else ok "not in the members' set"; fi
want "coordinator -> :22 (blocked now)" silent $MESH 10.66.0.1 10.66.0.2 22
# A reload must not hand it a clean slate: the table is rebuilt, so sync
# has to have made the block lasting before (checked in the unit tests).

echo "== coordinator role"
in_ $SRV nft -f "$W/coord/etc/nftables.conf" || { echo "the coordinator firewall does not load"; exit 1; }
want "a server -> :22 (member list over SSH)" open $MESH 10.66.0.3 10.66.0.2 22
want "a server -> :9000" silent $MESH 10.66.0.3 10.66.0.2 9000
want "desktop -> :22" open $LAN 192.168.1.99 192.168.1.20 22
want "a server -> API server :6443" open $MESH 10.66.0.3 10.66.0.2 6443
want "a pod -> this machine's API port" open $POD 10.42.1.1 6443
want "home network -> API server :6443" silent $LAN 192.168.1.99 192.168.1.20 6443
want "-> internet:25" refused $SRV 8.8.8.8 25
want "-> another machine at home :22" refused $SRV 192.168.1.99 22
echo "-- into the mesh: a server cuts the coordinator off for tries on closed ports"
want "root -> a server, any port (k3s, sync; the server decides)" open $SRV 10.66.0.1 9999
want "root -> a server's kubelet" open $SRV 10.66.0.3 10250
want "root -> a pod on a server (VXLAN)" open $SRV 10.42.9.2 80
want "root -> a service whose endpoint is a server" open $SRV 10.43.0.20 443
want "root -> ping a server" open $SRV 10.66.0.2 10.66.0.3 0 icmp
want "a pod here -> a pod on a server (VXLAN, sent by the kernel)" open $POD 10.42.9.2 80
want "a pod here -> a server's kubelet" open $POD 10.66.0.3 10250
want "a pod here -> a server's closed port (dropped here, never a try there)" silent $POD 10.66.0.3 9000
want "a pod here -> a server's SSH" silent $POD 10.66.0.3 22
if [ "${DRYSERVER_LIVE_IDS:-0}" != 0 ]; then
    want_as 1000 "the admin (uid 1000) -> a server's SSH (ssh <server> jumps through here)" open $SRV 10.66.0.3 22
    want_as 1000 "the admin -> ping a server" open $SRV 10.66.0.2 10.66.0.3 0 icmp
    want_as 1000 "the admin -> a server :8080, told at once" refused $SRV 10.66.0.3 8080
    want_as 1000 "the admin -> a server :5353/udp" refused $SRV 10.66.0.3 5353 udp
    want_as 1000 "the admin -> a server :443 through a service address" refused $SRV 10.43.0.20 443
    want_as 1000 "the admin -> a pod on a server (its own VXLAN is not sent)" silent $SRV 10.42.9.2 80
    want_as 1000 "the admin -> internet:443 (not the mesh)" open $SRV 8.8.8.8 443
    want_as 967 "the registry account (uid 967) -> a server's SSH" refused $SRV 10.66.0.3 22
    want_as 967 "the registry account -> a server's closed port" refused $SRV 10.66.0.1 9999
    want_as 967 "the registry account -> a server's kubelet" refused $SRV 10.66.0.3 10250
    want_as 967 "the registry account -> ping a server" refused $SRV 10.66.0.2 10.66.0.3 0 icmp
    want_as 967 "the registry account -> its own machine (loopback)" open $SRV 127.0.0.1 9000
else
    echo "  SKIP accounts other than root: this user has no subordinate ids (/etc/subuid, /etc/subgid, newuidmap)"
fi

echo "== $pass passed, $fail failed"
[ "$fail" = 0 ]
