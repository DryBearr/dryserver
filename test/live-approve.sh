#!/bin/bash
# Live check of signed approval: the real `dryserver approve` screen on a
# "desktop" (driven through a pty), a real sshd with the registry forced
# command as the "coordinator", real OpenSSH keys and signatures.
#
# Needs sshd, ssh-keygen, wg and python3. Changes nothing on this machine
# (a temporary directory and sshd on 127.0.0.1:2209).
#
#   cargo build && test/live-approve.sh [path/to/dryserver]
set -uo pipefail
BIN=$(realpath "${1:-$(dirname "$0")/../target/debug/dryserver}")
S=$(mktemp -d)
PORT=2209
pass=0 fail=0
ok() { echo "  PASS $*"; pass=$((pass + 1)); }
bad() { echo "  FAIL $*"; fail=$((fail + 1)); }
check() { local msg=$1; shift; if "$@" >/dev/null 2>&1; then ok "$msg"; else bad "$msg"; fi; }
check_not() { local msg=$1; shift; if "$@" >/dev/null 2>&1; then bad "$msg"; else ok "$msg"; fi; }
cleanup() { [ -f "$S/sshd.pid" ] && kill "$(cat "$S/sshd.pid")" 2>/dev/null; rm -rf "$S"; }
trap cleanup EXIT

mkdir -p "$S"/{root/etc/ssh,root/usr/local/share/dryserver,root/var/lib/dryserver,desk/secrets,thief/secrets,bin}
keygen() { ssh-keygen -q -t ed25519 -N '' -C "$2" -f "$1"; }
keygen "$S/hostkey" coord
keygen "$S/desk/secrets/registry_ed25519" dryserver-registry
keygen "$S/desk/secrets/signing_ed25519" dryserver-signing
# A thief has the USB stick: the registry key and the public signing key,
# but not the private signing key.
cp "$S/desk/secrets/registry_ed25519"* "$S/thief/secrets/"
keygen "$S/thief/secrets/signing_ed25519" thief

cp "$S/hostkey.pub" "$S/root/etc/ssh/ssh_host_ed25519_key.pub"
cp "$S/desk/secrets/signing_ed25519.pub" "$S/root/usr/local/share/dryserver/"
COORD_WG=$(wg genkey | wg pubkey)
NODE_WG=$(wg genkey | wg pubkey)
HOSTKEY=$(cut -d' ' -f1,2 "$S/hostkey.pub")
cat > "$S/root/var/lib/dryserver/registry.json" <<EOF
{"members":[{"host":1,"name":"coord","wg_key":"$COORD_WG","ssh_host_key":"$HOSTKEY root@coord","lan_ip":"127.0.0.1"}]}
EOF
for d in desk thief; do
    printf "COORD_LAN_IP='127.0.0.1'\nWG_SUBNET='10.66.0.0/24'\nWG_PORT='51820'\nUSERNAME='admin'\n" > "$S/$d/config.env"
done

start_sshd() { # hostkey
    cat > "$S/sshd.conf" <<EOF
Port $PORT
ListenAddress 127.0.0.1
HostKey $1
PidFile $S/sshd.pid
AuthorizedKeysFile $S/authorized_keys
StrictModes no
UsePAM no
AllowUsers $USER
EOF
    [ -f "$S/sshd.pid" ] && kill "$(cat "$S/sshd.pid")" 2>/dev/null && sleep 0.3
    /usr/sbin/sshd -f "$S/sshd.conf"
    sleep 0.3
}
echo "restrict,command=\"$BIN registry --subnet 10.66.0.0/24 --root $S/root\" $(cat "$S/desk/secrets/registry_ed25519.pub")" > "$S/authorized_keys"
start_sshd "$S/hostkey"

# The registry user does not exist here: send dryreg@ to this user. All
# other ssh arguments are passed through untouched.
cat > "$S/bin/ssh" <<EOF
#!/bin/bash
args=()
for a in "\$@"; do args+=("\${a/dryreg@/$USER@}"); done
exec /usr/bin/ssh "\${args[@]}"
EOF
chmod +x "$S/bin/ssh"
export PATH="$S/bin:$PATH"

reg() { # command, stdin -> registry answer, like a node or anyone with the stick
    /usr/bin/ssh -i "$S/desk/secrets/registry_ed25519" -p $PORT -o BatchMode=yes -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$USER@127.0.0.1" "$1"
}
jqr() { python3 -I -c "import json,sys; d=json.load(open('$S/root/var/lib/dryserver/registry.json')); print($1)"; }

# Drives the approve screen: waits for text, sends keys, returns what was drawn.
screen_raw() { # dir, then pairs: WAIT_FOR KEYS ...
    python3 -I - "$BIN" "$PORT" "$@" <<'PY'
import os, pty, re, select, sys, time
binp, port, cwd, steps = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
pid, fd = pty.fork()
if pid == 0:
    import fcntl, struct, termios
    fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 45, 160, 0, 0))
    os.chdir(cwd)
    os.environ["TERM"] = "xterm-256color"
    os.execv(binp, [binp, "approve", "--config", "config.env", "--host", "127.0.0.1", "--port", port])
seen = ""
def read_until(pat, timeout=20):
    global seen
    end = time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try: data = os.read(fd, 65536)
            except OSError: return False
            # The screen is drawn with cursor moves between words: turn
            # every escape sequence into a space and squeeze the spaces.
            seen += re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b[()][A-Z0-9]|\x1b[=>]", " ", data.decode("utf-8", "replace"))
            seen = re.sub(r"\s+", " ", seen)
        if re.search(pat, seen): return True
    return False
okay = True
for i in range(0, len(steps), 2):
    if not read_until(steps[i]):
        okay = False
        break
    time.sleep(0.3)
    os.write(fd, steps[i + 1].encode())
time.sleep(1.0)
read_until(r"\Z", 0.5)
try: os.write(fd, b"q")
except OSError: pass
time.sleep(0.3)
print(seen)
sys.exit(0 if okay else 1)
PY
}
# Keeps every screen capture for debugging when DEBUG_DIR is set.
screen() { local o; o=$(screen_raw "$@" 2>&1); local rc=$?; [ -n "${DEBUG_DIR:-}" ] && printf '%s\n' "$o" > "$DEBUG_DIR/screen-$(date +%s%N).txt"; printf '%s\n' "$o"; return $rc; }

echo "== a machine asks to join"
REQ=$(printf '{"name":"node-a","wg_key":"%s","ssh_host_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVmCw4JXa0JQ1x0Z3ZJ3vY3lMSa7p4rG5Q6k8hO2c3d root@node-a","lan_ip":"192.168.1.23","switch":true}' "$NODE_WG")
out=$(echo "$REQ" | reg request)
check "request accepted ($out)" grep -q '"id"' <<<"$out"
CODE=$(jqr "d['requests'][0]['code']")

echo "== anyone with the USB stick's key, without the signing key"
out=$(echo '{}' | reg admin 2>&1)
check "registry stays closed without a signature" grep -qi "bad admin request\|not signed\|bad signature" <<<"$out"
out=$(screen "$S/thief" "talk to the coordinator|Waiting to join" "" 2>&1)
check "approve screen with a wrong signing key is refused" grep -q "refused" <<<"$out"
check_not "it saw no machine names" grep -q "node-a" <<<"$out"

echo "== the admin approves on the desktop"
out=$(screen "$S/desk" "node-a" "a" "approved and signed|Failed" "")
check "screen showed the waiting machine" grep -q "node-a" <<<"$out"
check "screen showed the same code the coordinator computed ($CODE)" grep -qF "$CODE" <<<"$out"
check "screen says approved and signed" grep -q "approved and signed as 10.66.0.2" <<<"$out"
check "coordinator has 2 members" test "$(jqr "len(d['members'])")" = 2
check "node-a got host 2 and its address from the request" test "$(jqr "[m for m in d['members'] if m['name']=='node-a'][0]['host'], [m for m in d['members'] if m['name']=='node-a'][0]['lan_ip']")" = "2 192.168.1.23"
check "request settled as approved" test "$(jqr "d['requests'][0]['status']")" = approved
V1=$(jqr "d['signed_version']")
check "coordinator stores a signed list (version $V1)" test "$V1" -gt 1600000000
check "desktop kept its own copy" test -s "$S/desk/secrets/members.signed.json"
check "desktop pinned the coordinator's SSH key" grep -q "^\[127.0.0.1\]:$PORT ssh-ed25519" "$S/desk/secrets/coordinator_known_hosts"
check "the node gets approved status" bash -c "echo | /usr/bin/ssh -i $S/desk/secrets/registry_ed25519 -p $PORT -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR $USER@127.0.0.1 'status $(jqr "d['requests'][0]['id']")' | grep -q approved"

# The stored signature verifies with plain OpenSSH, outside dryserver.
python3 -I -c "
import json; e=json.load(open('$S/root/var/lib/dryserver/registry.json'))['signed']
open('$S/doc','w').write(e['doc']); open('$S/sig','w').write(e['sig'])"
echo "dryserver namespaces=\"dryserver-members\" $(cut -d' ' -f1,2 "$S/desk/secrets/signing_ed25519.pub")" > "$S/allowed"
check "plain ssh-keygen verifies the stored list" bash -c "ssh-keygen -Y verify -f $S/allowed -I dryserver -n dryserver-members -s $S/sig < $S/doc"
cp "$S/desk/secrets/members.signed.json" "$S/old.json"

echo "== forged and replayed lists"
python3 -I -c "
import json; e=json.load(open('$S/old.json')); d=json.loads(e['doc']); d['version']+=10
d['members'].append({'host':9,'name':'rogue','wg_key':'$COORD_WG'[:-2]+'A=','ssh_host_key':''}); e['doc']=json.dumps(d); print(json.dumps(e))" > "$S/forged.json"
out=$(reg publish < "$S/forged.json" 2>&1)
check "a changed list with the old signature is refused ($out)" grep -q "bad signature" <<<"$out"
cd "$S/thief" && printf '%s' "$(python3 -I -c "import json; print(json.loads(json.load(open('$S/forged.json'))['doc']) and json.load(open('$S/forged.json'))['doc'])")" > "$S/tdoc"
ssh-keygen -Y sign -f "$S/thief/secrets/signing_ed25519" -n dryserver-members < "$S/tdoc" > "$S/tsig" 2>/dev/null
python3 -I -c "import json; print(json.dumps({'doc':open('$S/tdoc').read(),'sig':open('$S/tsig').read()}))" > "$S/thief.json"
out=$(reg publish < "$S/thief.json" 2>&1)
check "a list signed with another key is refused" grep -q "bad signature" <<<"$out"
check "coordinator still has 2 members" test "$(jqr "len(d['members'])")" = 2

echo "== remove, then replay the old list"
out=$(screen "$S/desk" "node-a" "jd" "y to confirm" "y" "removed|Failed" "")
check "screen confirmed the removal" grep -q "node-a removed" <<<"$out"
check "coordinator has 1 member" test "$(jqr "len(d['members'])")" = 1
V2=$(jqr "d['signed_version']")
check "version went up ($V1 -> $V2)" test "$V2" -gt "$V1"
out=$(reg publish < "$S/old.json" 2>&1)
check "the old signed list cannot bring node-a back ($out)" grep -q "not newer" <<<"$out"
check "coordinator still has 1 member" test "$(jqr "len(d['members'])")" = 1

echo "== the coordinator is replaced by another machine"
keygen "$S/hostkey2" other
start_sshd "$S/hostkey2"
out=$(screen "$S/desk" "talk to the coordinator|Waiting to join" "" 2>&1)
check "approve refuses a machine with another SSH key" grep -q "does not have the SSH key this computer saw before" <<<"$out"

echo "== $pass passed, $fail failed"
[ "$fail" = 0 ]
