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
# Directories from the real system cannot be written to in here: empty
# ones are mounted over those the server tools write.
for d in /etc/wireguard /etc/ssh; do [ -d "$d" ] && mount -t tmpfs tmpfs "$d"; done
# A private place for the signing public key (/usr/local may be a symlink).
# A directory from the real system cannot be written to in here, so an
# empty one is mounted over it.
UL=$(realpath /usr/local)
if [ -d "$UL/share" ]; then
    mount -t tmpfs tmpfs "$UL/share"
else
    mkdir -p "$W/ul-up" "$W/ul-work"
    mount -t overlay overlay -o "lowerdir=$UL,upperdir=$W/ul-up,workdir=$W/ul-work" "$UL"
fi
hostname node-b

# Stand-ins for systemd and agetty (no init in here).
mkdir -p "$W/bin"
printf '#!/bin/sh\necho "systemctl $*" >> %s/systemctl.log\nexit 0\n' "$W" > "$W/bin/systemctl"
printf '#!/bin/sh\nexit 0\n' > "$W/bin/agetty"
# Stand-in for the coordinator's registry over SSH: "signed" answers with
# $W/signed-reply, but only if the coordinator's LAN address is reachable
# from the worker (so the firewall block must be gone before it is asked).
cat > "$W/bin/ssh" <<EOF
#!/bin/sh
for a in "\$@"; do last=\$a; done
[ "\$last" = signed ] || exit 255
ping -c1 -W1 192.168.1.50 >/dev/null 2>&1 || { echo "ssh: connect to host 192.168.1.50: no route" >&2; exit 255; }
[ -f "$W/signed-reply" ] || { echo "ssh: connection refused" >&2; exit 255; }
cat "$W/signed-reply"
EOF
chmod +x "$W/bin/"*
export PATH="$W/bin:$PATH"

# The admin's signing key, and a way to make a signed member list:
#   sign_list KEY VERSION COORD_WG COORD_SSH > reply
ssh-keygen -q -t ed25519 -N '' -f "$W/signing"
ssh-keygen -q -t ed25519 -N '' -f "$W/thief"
mkdir -p /usr/local/share/dryserver
cp "$W/signing.pub" /usr/local/share/dryserver/signing_ed25519.pub
OLD_SSH="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIoldcoordinatoroldcoordinatoroldcoordinato"
NEW_SSH="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInewcoordinatornewcoordinatornewcoordinato"
sign_list() {
    python3 -I -c '
import json, sys
ver, cwg, cssh, wwg, nwg = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
print(json.dumps({"version": ver, "members": [
    {"host": 1, "name": "coord", "wg_key": cwg, "ssh_host_key": cssh},
    {"host": 2, "name": "node-b", "wg_key": wwg, "ssh_host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInodeb"},
    {"host": 3, "name": "node-c", "wg_key": nwg, "ssh_host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInodec"}], "rejected": []}), end="")' "$2" "$3" "$4" "$WP" "$CP" > "$W/doc"
    ssh-keygen -Y sign -f "$1" -n dryserver-members < "$W/doc" > "$W/sig" 2>/dev/null
    python3 -I -c 'import json,sys; print(json.dumps({"signed": {"doc": open(sys.argv[1]).read(), "sig": open(sys.argv[2]).read()}}))' "$W/doc" "$W/sig"
}

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
# This server pins the coordinator's SSH key and has seen signed version 5.
echo "192.168.1.50,10.66.0.1 $OLD_SSH" > /etc/dryserver/known_hosts
sign_list "$W/signing" 5 "$BP" "$OLD_SSH" > "$W/v5"
python3 -I -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))["signed"]))' "$W/v5" > /etc/dryserver/members.signed.json
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
out=$(inw "$BIN" quarantine -same 2>&1)
check "-same without -lift is refused" grep -q "goes with -lift" <<<"$out"
out=$(inw "$BIN" quarantine -min-version 9 2>&1)
check "-min-version without -lift is refused" grep -q "goes with -lift" <<<"$out"

echo "== lift needs a member list signed by the admin"
out=$(inw "$BIN" quarantine -lift 2>&1); rc=$?
check "refused when the coordinator has no list ($rc)" bash -c "[ $rc != 0 ] && grep -q 'the quarantine stays' <<<'$out'"
sign_list "$W/thief" 9 "$BP" "$OLD_SSH" > "$W/signed-reply"
out=$(inw "$BIN" quarantine -lift 2>&1); rc=$?
check "refused when the list is signed by someone else" bash -c "[ $rc != 0 ] && grep -q 'bad signature' <<<'$out'"
check "the firewall block is back" inw nft list table inet dryserver_quarantine
check_not "still cut off" inw ping -c1 -W1 10.66.0.1
check_not "brain peer still out" bash -c "nsenter -t $WK -n wg show wg0 peers | grep -qF '$BP'"

echo "== the same coordinator comes back only with -same"
# Whoever kept a reinstalled coordinator's keys answers with the list this
# server has; it does not take the old machine back by itself.
cp "$W/v5" "$W/signed-reply"
out=$(inw "$BIN" quarantine -lift 2>&1); rc=$?
check "refused without -same ($rc)" bash -c "[ $rc != 0 ] && grep -q 'lift with -same' <<<'$out' && grep -q 'the quarantine stays' <<<'$out'"
check "the firewall block is back" inw nft list table inet dryserver_quarantine
check_not "brain peer still out" bash -c "nsenter -t $WK -n wg show wg0 peers | grep -qF '$BP'"
out=$(inw "$BIN" quarantine -lift -same -min-version 6 2>&1); rc=$?
check "refused below the version the desktop signed last ($rc)" bash -c "[ $rc != 0 ] && grep -q 'older than version 6 your desktop signed last' <<<'$out'"
check_not "still cut off" inw ping -c1 -W1 10.66.0.1

echo "== lift -same (false alarm: the same coordinator)"
inw "$BIN" quarantine -lift -same -min-version 5 > "$W/lift.out" 2>&1; rc=$?
sed 's/^/    | /' "$W/lift.out"
check "lift exits 0" test "$rc" = 0
check "says it is the same machine" grep -q "same machine as before" "$W/lift.out"
check "brain peer back in the running wg0" bash -c "nsenter -t $WK -n wg show wg0 peers | grep -qF '$BP'"
check "brain peer back in wg0.conf" grep -qF "$BP" /etc/wireguard/wg0.conf
check_not "quarantine table gone" inw nft list table inet dryserver_quarantine
check_not "rules file gone" test -e /etc/dryserver/nft.d/quarantine.nft
check "worker reaches brain again" inw ping -c1 -W1 10.66.0.1
check "sync restarted" grep -q "start --no-block dryserver-sync.service" "$W/systemctl.log"

echo "== the coordinator is reinstalled: new keys, signed by the admin"
check "cut again" inw "$BIN" quarantine
BK2=$(wg genkey); BP2=$(echo "$BK2" | wg pubkey)
echo "$BK2" > "$W/bk2"
inb wg set wg0 private-key "$W/bk2"
sign_list "$W/signing" 9 "$BP2" "$NEW_SSH" > "$W/signed-reply"
out=$(inw "$BIN" quarantine -lift -min-version 10 2>&1); rc=$?
check "refused when the desktop signed a newer one ($rc)" bash -c "[ $rc != 0 ] && grep -q 'older than version 10' <<<'$out'"
inw "$BIN" quarantine -lift -min-version 9 > "$W/lift2.out" 2>&1; rc=$?
sed 's/^/    | /' "$W/lift2.out"
check "lift exits 0" test "$rc" = 0
check "says it follows the new coordinator" grep -q "follows the new coordinator you signed" "$W/lift2.out"
check "new coordinator key in the running wg0" bash -c "nsenter -t $WK -n wg show wg0 peers | grep -qF '$BP2'"
check_not "old coordinator key stays out" bash -c "nsenter -t $WK -n wg show wg0 peers | grep -qF '$BP'"
check_not "old coordinator key not in wg0.conf" grep -qF "$BP" /etc/wireguard/wg0.conf
check "new SSH key pinned" grep -qF "192.168.1.50,10.66.0.1 $NEW_SSH" /etc/dryserver/known_hosts
check_not "old SSH key gone" grep -qF "$OLD_SSH" /etc/dryserver/known_hosts
check "worker reaches the new coordinator over the mesh" inw ping -c1 -W2 10.66.0.1
check "version 9 remembered" grep -q 'version.*9' /etc/dryserver/members.signed.json
# The old list cannot take it back.
check "cut once more" inw "$BIN" quarantine
cp "$W/v5" "$W/signed-reply"
out=$(inw "$BIN" quarantine -lift 2>&1); rc=$?
check "the old list is refused after the new one was seen" bash -c "[ $rc != 0 ] && grep -q 'older than version 9' <<<'$out'"
sign_list "$W/signing" 9 "$BP2" "$NEW_SSH" > "$W/signed-reply"
check "lift -same with the current list" inw "$BIN" quarantine -lift -same

echo "== cut a worker by name"
check "cut node-c" inw "$BIN" quarantine -name node-c
check_not "node-c peer gone" bash -c "nsenter -t $WK -n wg show wg0 peers | grep -qF '$CP'"
check "brain still reachable" inw ping -c1 -W2 10.66.0.1
check "node-c's mesh address blocked" bash -c "nsenter -t $WK -n nft list table inet dryserver_quarantine | grep -q '10.66.0.3'"
check_not "brain's address not blocked" bash -c "nsenter -t $WK -n nft list table inet dryserver_quarantine | grep -q '10.66.0.1[,} ]'"
check "status shows sync running" bash -c "nsenter -t $WK -n $BIN quarantine -status | grep -q 'is running'"
check "lift" inw "$BIN" quarantine -lift

echo "== the generated firewall: a member that tries closed ports is cut off for good"
cat > "$W/fw.env" <<EOF
COORD_LAN_IP='192.168.1.50'
WG_SUBNET='10.66.0.0/24'
WG_PORT='51820'
WG_TRANSPORT='auto'
SWITCH_SUBNET='172.16.66.0/24'
USERNAME='admin'
ADMIN_SSH_PUBKEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVmCw4JXa0JQ1x0Z3ZJ3vY3lMSa7p4rG5Q6k8hO2c3d me@desk'
TOOLS=''
EOF
"$BIN" sysconf --config "$W/fw.env" --out "$W/fw" --role node --hostname node-b --host 2 >/dev/null
cp "$W/fw/etc/nftables.conf" /etc/nftables.conf
check "the generated firewall loads" inw nft -f /etc/nftables.conf
check "the coordinator still reaches the server over WireGuard" inb ping -c1 -W2 10.66.0.2
out=$(inw "$BIN" sync 2>&1)
check_not "sync cuts nobody while nobody knocks" grep -q "by itself" <<<"$out"
check_not "no quarantine" test -e /etc/dryserver/quarantine.json
scan() { # first last: the coordinator tries each port once
    inb python3 -I -c '
import socket, sys
for port in range(int(sys.argv[1]), int(sys.argv[2])):
    s = socket.socket(); s.setblocking(False)
    try: s.connect(("10.66.0.2", port))
    except OSError: pass
    s.close()' "$1" "$2"
}
# What a member's tries would be (60 in a minute) does not cut the
# coordinator: that stops every app.
scan 9000 9060
sleep 0.5
check_not "60 tries do not block the coordinator" bash -c "nsenter -t $WK -n nft list set inet dryserver offenders4 | grep -q 10.66.0.1 || nsenter -t $WK -n nft list set inet dryserver coord_offender4 | grep -q 10.66.0.1"
check "the coordinator still reaches the server" inb ping -c1 -W2 10.66.0.2
# Counted with the members (an older firewall did that): reported, not cut.
inw nft add element inet dryserver offenders4 '{ 10.66.0.1 }'
out=$(inw "$BIN" sync 2>&1)
check "sync says why it does not cut" grep -q "not cut for it" <<<"$out"
check_not "no quarantine for it" test -e /etc/dryserver/quarantine.json
inw nft flush set inet dryserver offenders4
# The coordinator (hacked, say) scans the server through the tunnel.
scan 9100 9300
sleep 0.5
check "the firewall blocked it at once" bash -c "nsenter -t $WK -n nft list set inet dryserver coord_offender4 | grep -q 10.66.0.1"
check_not "not among the members" bash -c "nsenter -t $WK -n nft list set inet dryserver offenders4 | grep -q 10.66.0.1"
check_not "it cannot even ping any more" inb ping -c1 -W1 10.66.0.2
out=$(inw "$BIN" sync 2>&1); rc=$?
check "sync made it a quarantine and says so ($rc)" grep -q "cut off the coordinator (10.66.0.1) by itself: more than 100 tries" <<<"$out"
check "sync is paused" grep -q "paused" <<<"$out"
check "saved as an automatic cut" grep -q '"auto": true' /etc/dryserver/quarantine.json
check_not "coordinator peer out of the running wg0" bash -c "nsenter -t $WK -n wg show wg0 peers | grep -qF '$BP2'"
check "status tells why" bash -c "nsenter -t $WK -n $BIN quarantine -status | grep -q 'by this server itself'"
# The one-hour entry in the firewall is gone after a reload; the cut is not.
inw nft -f /etc/nftables.conf
check_not "the firewall's own entry is gone after a reload" bash -c "nsenter -t $WK -n nft list set inet dryserver coord_offender4 | grep -q 10.66.0.1"
check "the quarantine table is loaded with it" inw nft list table inet dryserver_quarantine
check_not "still cut off" inw ping -c1 -W1 10.66.0.1
out=$(inw "$BIN" sync 2>&1)
check_not "a second sync does not cut again" grep -q "by itself" <<<"$out"
# Lifting forgives: the firewall's entry goes too, or the next sync would
# cut the same member again (seen on a real install).
for port in 9200 9201 9202; do inb python3 -I -c "
import socket
s = socket.socket(); s.setblocking(False)
try: s.connect(('10.66.0.2', $port))
except OSError: pass"; done
inw nft add element inet dryserver coord_offender4 '{ 10.66.0.1 }'
check "lift -same (a false alarm)" inw "$BIN" quarantine -lift -same
check_not "the firewall's entry is gone after the lift" bash -c "nsenter -t $WK -n nft list set inet dryserver coord_offender4 | grep -q 10.66.0.1"
out=$(inw "$BIN" sync 2>&1)
check_not "the next sync does not cut the lifted member again" grep -q "by itself" <<<"$out"
check_not "no quarantine after it" test -e /etc/dryserver/quarantine.json
check "the coordinator is reachable again" inw ping -c1 -W2 10.66.0.1

kill $BR $WK 2>/dev/null
echo "== $pass passed, $fail failed"
[ "$fail" = 0 ]
