#!/bin/bash
# Live check of `dryserver quarantine` with real WireGuard and nftables:
# a "brain" and a "worker" network namespace joined by a veth cable,
# inside an unprivileged user namespace. /etc and /run are private
# (overlay + tmpfs), so nothing on the host changes. Needs wg, wg-quick,
# nft, ip, python3 and unprivileged user namespaces.
#
#   cargo build && test/live-quarantine.sh [path/to/dryserver]
set -uo pipefail
BIN=$(realpath "${1:-$(dirname "$0")/../target/debug/dryserver}")
# Re-run inside a private user, mount and hostname namespace.
if [ -z "${DRYSERVER_LIVE_NS:-}" ]; then
    exec env DRYSERVER_LIVE_NS=1 unshare -rmu --propagation private bash "$0" "$BIN"
fi
W=$(mktemp -d)
pass=0 fail=0
ok() { echo "  PASS $*"; pass=$((pass + 1)); }
bad() { echo "  FAIL $*"; fail=$((fail + 1)); }
check() { local msg=$1; shift; if "$@" >/dev/null 2>&1; then ok "$msg"; else bad "$msg"; fi; }
check_not() { local msg=$1; shift; if "$@" >/dev/null 2>&1; then bad "$msg"; else ok "$msg"; fi; }

# Private /etc and /run.
mkdir -p "$W/up" "$W/work"
mount -t overlay overlay -o "lowerdir=/etc,upperdir=$W/up,workdir=$W/work" /etc
mount -t tmpfs tmpfs /run
[ -d /etc/wireguard ] && mount -t tmpfs tmpfs /etc/wireguard
hostname node-b

# Stand-ins for systemd and agetty (no init in here).
mkdir -p "$W/bin"
printf '#!/bin/sh\necho "systemctl $*" >> %s/systemctl.log\nexit 0\n' "$W" > "$W/bin/systemctl"
printf '#!/bin/sh\nexit 0\n' > "$W/bin/agetty"
chmod +x "$W/bin/"*
export PATH="$W/bin:$PATH"

unshare -n sleep 600 & BR=$!
unshare -n sleep 600 & WK=$!
sleep 0.3
inb() { nsenter -t "$BR" -n "$@"; }
inw() { nsenter -t "$WK" -n "$@"; }

inb ip link add vb type veth peer name vw netns "$WK"
inb ip addr add 192.168.1.50/24 dev vb
inb ip addr add 192.168.1.99/24 dev vb   # stands in for the admin's desktop
inw ip addr add 192.168.1.20/24 dev vw
for x in inb inw; do $x ip link set lo up; done
inb ip link set vb up; inw ip link set vw up

BK=$(wg genkey); BP=$(echo "$BK" | wg pubkey)
WKEY=$(wg genkey); WP=$(echo "$WKEY" | wg pubkey)
CK=$(wg genkey); CP=$(echo "$CK" | wg pubkey)   # node-c, not running

# Brain side, configured by hand.
inb ip link add wg0 type wireguard
echo "$BK" > "$W/bk"
inb wg set wg0 listen-port 51820 private-key "$W/bk" peer "$WP" allowed-ips 10.66.0.2/32 endpoint 192.168.1.20:51820
inb ip addr add 10.66.0.1/24 dev wg0
inb ip link set wg0 up

# Worker side: the files dryserver writes on a node.
mkdir -p /etc/dryserver /etc/wireguard
cat > /etc/dryserver/config.env <<EOF
COORD_LAN_IP='192.168.1.50'
WG_SUBNET='10.66.0.0/24'
WG_PORT='51820'
WG_TRANSPORT='auto'
SWITCH_SUBNET='172.16.66.0/24'
USERNAME='admin'
EOF
echo '{"host":2}' > /etc/dryserver/join.json
echo node > /etc/dryserver/role
echo "$WKEY" > /etc/wireguard/wg0.key
cat > /etc/wireguard/wg0.conf <<EOF
# dryserver mesh, rewritten by "dryserver sync" from the coordinator's list.
[Interface]
Address = 10.66.0.2/24
ListenPort = 51820
PostUp = wg set %i private-key /etc/wireguard/wg0.key

# coord
[Peer]
PublicKey = $BP
AllowedIPs = 10.66.0.1/32
Endpoint = 192.168.1.50:51820
PersistentKeepalive = 25

# node-c
[Peer]
PublicKey = $CP
AllowedIPs = 10.66.0.3/32
Endpoint = 192.168.1.30:51820
PersistentKeepalive = 25
EOF
cat > /etc/nftables.conf <<'EOF'
#!/usr/bin/nft -f
destroy table inet dryserver
table inet dryserver {
	chain input {
		type filter hook input priority filter; policy accept;
	}
}

# Kill switch rules from "dryserver quarantine", when there are any.
include "/etc/dryserver/nft.d/*.nft"
EOF
inw nft -f /etc/nftables.conf
inw ip link add wg0 type wireguard
inw bash -c "wg-quick strip wg0 > $W/strip && wg setconf wg0 $W/strip && wg set wg0 private-key /etc/wireguard/wg0.key"
inw ip addr add 10.66.0.2/24 dev wg0
inw ip link set wg0 up

# A connection that is open before the cut.
inb python3 -c '
import socket,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("10.66.0.1",9000)); s.listen(1); s.settimeout(10)
c,_=s.accept(); c.settimeout(8)
got=b""
try:
    while True:
        b=c.recv(100)
        if not b: break
        got+=b
except Exception: pass
open(sys.argv[1],"wb").write(got)
' "$W/received" & LISTEN=$!
sleep 0.3
inw python3 -c '
import socket,time,sys
s=socket.create_connection(("10.66.0.1",9000),timeout=3); s.sendall(b"before;")
open(sys.argv[1],"w").write("connected")
time.sleep(3)
try: s.sendall(b"after;")
except Exception: pass
time.sleep(4)
' "$W/sent" & SENDER=$!

echo "== before the cut"
check "worker reaches brain over the mesh" inw ping -c1 -W1 10.66.0.1
check "brain reaches worker over the LAN" inb ping -c1 -W1 192.168.1.20
sleep 0.5
check "a connection to the brain is open" test -s "$W/sent"

echo "== dryserver quarantine (with a hangup sent while it runs)"
# exec: nsenter becomes dryserver, so $Q is dryserver itself. The hangup
# comes once it starts reporting, like a session through the brain that
# dies as the cut begins.
(exec nsenter -t "$WK" -n "$BIN" quarantine > "$W/cut.out" 2>&1) & Q=$!
for _ in $(seq 100); do grep -q "Cutting off" "$W/cut.out" 2>/dev/null && break; sleep 0.01; done
check "signal reached the dryserver process" kill -HUP $Q
wait $Q; rc=$?
sed 's/^/    | /' "$W/cut.out"
check "exit status 0 despite SIGHUP (got $rc)" test "$rc" = 0

echo "== after the cut"
check_not "brain peer gone from the running wg0" bash -c "nsenter -t $WK -n wg show wg0 peers | grep -qF '$BP'"
check "node-c peer kept" bash -c "nsenter -t $WK -n wg show wg0 peers | grep -qF '$CP'"
check_not "brain peer gone from wg0.conf" grep -qF "$BP" /etc/wireguard/wg0.conf
check "quarantine table loaded" inw nft list table inet dryserver_quarantine
check_not "worker cannot reach brain over the mesh" inw ping -c1 -W1 10.66.0.1
check_not "brain cannot reach worker over the LAN" inb ping -c1 -W1 192.168.1.20
check "desktop (another LAN address) still reaches worker" inb ping -c1 -W1 -I 192.168.1.99 192.168.1.20
wait $SENDER; wait $LISTEN
check "data sent before the cut arrived" grep -q "before;" "$W/received"
check_not "data on the open connection after the cut did not arrive" grep -q "after;" "$W/received"

echo "== sync and reboots"
out=$(inw "$BIN" sync 2>&1); rc=$?
check "sync exits 0 and says paused ($out)" bash -c "[ $rc = 0 ] && grep -q paused <<<'$out'"
inw nft flush ruleset
check_not "(flush, like a firewall restart)" inw nft list table inet dryserver_quarantine
inw nft -f /etc/nftables.conf
check "nftables.conf brings the quarantine table back" inw nft list table inet dryserver_quarantine
check_not "still blocked after the reload" inw ping -c1 -W1 10.66.0.1

echo "== again, status, bad name"
check "second run succeeds" inw "$BIN" quarantine
check "status runs" bash -c "nsenter -t $WK -n $BIN quarantine -status | grep -q 'firewall rules loaded'"
out=$(inw "$BIN" quarantine -name ghost 2>&1)
check "unknown name is refused with the member list" grep -q "members here: node-c" <<<"$out"
out=$(inw "$BIN" quarantine -lift -name node-c 2>&1)
check "-lift with -name is refused" grep -q "take no -name" <<<"$out"

echo "== lift"
inw "$BIN" quarantine -lift > "$W/lift.out" 2>&1; rc=$?
sed 's/^/    | /' "$W/lift.out"
check "lift exits 0" test "$rc" = 0
check "brain peer back in the running wg0" bash -c "nsenter -t $WK -n wg show wg0 peers | grep -qF '$BP'"
check "brain peer back in wg0.conf" grep -qF "$BP" /etc/wireguard/wg0.conf
check_not "quarantine table gone" inw nft list table inet dryserver_quarantine
check_not "rules file gone" test -e /etc/dryserver/nft.d/quarantine.nft
check "worker reaches brain again" inw ping -c1 -W1 10.66.0.1
check "sync restarted" grep -q "start --no-block dryserver-sync.service" "$W/systemctl.log"

echo "== cut a worker by name"
check "cut node-c" inw "$BIN" quarantine -name node-c
check_not "node-c peer gone" bash -c "nsenter -t $WK -n wg show wg0 peers | grep -qF '$CP'"
check "brain still reachable" inw ping -c1 -W1 10.66.0.1
check "node-c's mesh address blocked" bash -c "nsenter -t $WK -n nft list table inet dryserver_quarantine | grep -q '10.66.0.3'"
check_not "brain's address not blocked" bash -c "nsenter -t $WK -n nft list table inet dryserver_quarantine | grep -q '10.66.0.1[,} ]'"
check "status shows sync running" bash -c "nsenter -t $WK -n $BIN quarantine -status | grep -q 'is running'"
check "lift" inw "$BIN" quarantine -lift

kill $BR $WK 2>/dev/null
echo "== $pass passed, $fail failed"
[ "$fail" = 0 ]
