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
PORT=${PORT:-2209}  # another with PORT=NNNN when two runs share a machine
pass=0 fail=0
ok() { echo "  PASS $*"; pass=$((pass + 1)); }
bad() { echo "  FAIL $*"; fail=$((fail + 1)); }
check() { local msg=$1; shift; if "$@" >/dev/null 2>&1; then ok "$msg"; else bad "$msg"; fi; }
check_not() { local msg=$1; shift; if "$@" >/dev/null 2>&1; then bad "$msg"; else ok "$msg"; fi; }
cleanup() { [ -f "$S/sshd.pid" ] && { pkill -P "$(cat "$S/sshd.pid")" 2>/dev/null; kill "$(cat "$S/sshd.pid")" 2>/dev/null; }; rm -rf "$S"; }
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

# The join secret from the stick: the desktop has it, and so does the thief.
SECRET=$(openssl rand -hex 32)
echo "$SECRET" > "$S/desk/secrets/join_secret"
cp "$S/desk/secrets/join_secret" "$S/thief/secrets/"
cp "$S/hostkey.pub" "$S/root/etc/ssh/ssh_host_ed25519_key.pub"
cp "$S/desk/secrets/signing_ed25519.pub" "$S/root/usr/local/share/dryserver/"
COORD_WG=$(wg genkey | wg pubkey)
NODE_WG=$(wg genkey | wg pubkey)
HOSTKEY=$(cut -d' ' -f1,2 "$S/hostkey.pub")
# What the installer of a coordinator leaves: itself as member 1 and its
# proof, made with the join secret from the stick.
proof() { printf 'dryserver-join-v1\n%s\n%s\n%s' "$1" "$2" "$3" | openssl dgst -sha256 -hmac "$SECRET" -r | cut -d' ' -f1; }
registry() { # root, wg key, host key
    mkdir -p "$1"/{etc/ssh,usr/local/share/dryserver,var/lib/dryserver}
    cp "$S/desk/secrets/signing_ed25519.pub" "$1/usr/local/share/dryserver/"
    cat > "$1/var/lib/dryserver/registry.json" <<EOF
{"members":[{"host":1,"name":"coord","wg_key":"$2","ssh_host_key":"$3 root@coord","lan_ip":"127.0.0.1"}],"coordinator_proof":"$(proof coord "$2" "$3")"}
EOF
}
registry "$S/root" "$COORD_WG" "$HOSTKEY"
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
    # Its sessions go with it: the desktop keeps one connection open, and a
    # reinstalled machine would not keep the old one's connections alive.
    [ -f "$S/sshd.pid" ] && { pkill -P "$(cat "$S/sshd.pid")" 2>/dev/null; kill "$(cat "$S/sshd.pid")" 2>/dev/null; sleep 0.5; }
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
NODE_HK="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVmCw4JXa0JQ1x0Z3ZJ3vY3lMSa7p4rG5Q6k8hO2c3d"
# What the installer does on the new machine: HMAC over its name and keys.
PROOF=$(proof node-a "$NODE_WG" "$NODE_HK")
REQ=$(printf '{"name":"node-a","wg_key":"%s","ssh_host_key":"%s root@node-a","lan_ip":"192.168.1.23","switch":true,"proof":"%s"}' "$NODE_WG" "$NODE_HK" "$PROOF")
out=$(echo "$REQ" | reg request)
check "request accepted ($out)" grep -q '"id"' <<<"$out"
CODE=$(jqr "d['requests'][0]['code']")

echo "== anyone with the USB stick's key, without the signing key"
out=$(echo '{}' | reg admin 2>&1)
check "registry stays closed without a signature" grep -qi "bad admin request\|not signed\|bad signature" <<<"$out"
out=$(screen "$S/thief" "talk to the coordinator|Waiting to join" "" 2>&1)
check "approve screen with a wrong signing key is refused" grep -q "refused" <<<"$out"
check_not "it saw no machine names" grep -q "node-a" <<<"$out"

echo "== the admin signs the coordinator, then approves on the desktop"
out=$(screen "$S/desk" "Press S to sign the coordinator" "S" "Its screen must show the code [0-9]{3} [0-9]{3}" "y" "Coordinator signed|Failed" "")
check "first signature asks for the coordinator's code" grep -Eq "Its screen must show the code [0-9]{3} [0-9]{3}" <<<"$out"
check "coordinator signed" grep -q "Coordinator signed" <<<"$out"
check "nobody else became a member" test "$(jqr "len(d['members'])")" = 1
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

echo "== a request without the stick's proof (a swapped key, or a machine not installed from the stick)"
EVIL_WG=$(wg genkey | wg pubkey)
out=$(printf '{"name":"node-b","wg_key":"%s","ssh_host_key":"%s root@node-b","lan_ip":"192.168.1.24","proof":"%s"}' "$EVIL_WG" "$NODE_HK" "$PROOF" | reg request)
check "the coordinator takes it (it cannot tell)" grep -q '"id"' <<<"$out"
out=$(screen "$S/desk" "NO PROOF" "a" "no valid proof|approved and signed" "")
check "screen marks it NO PROOF" grep -q "NO PROOF: not installed from your USB stick" <<<"$out"
check "approving it is refused" grep -q "no valid proof from your USB stick" <<<"$out"
check "still 2 members" test "$(jqr "len(d['members'])")" = 2
out=$(screen "$S/desk" "NO PROOF" "r" "node-b rejected|Failed" "")
check "it can be rejected" grep -q "node-b rejected" <<<"$out"

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

echo "== something else answers at the coordinator's address"
keygen "$S/hostkey2" other
start_sshd "$S/hostkey2"
out=$(screen "$S/desk" "press N to look at the new one" "N" "Not a coordinator of yours|y to confirm" "" 2>&1)
check "approve refuses a machine with another SSH key" grep -q "does not have the SSH key this computer saw before" <<<"$out"
check "N finds no coordinator of yours (it serves the old registry)" grep -q "Not a coordinator of yours" <<<"$out"
check "the pin is still the old key" grep -qF "$HOSTKEY" "$S/desk/secrets/coordinator_known_hosts"

echo "== the coordinator is reinstalled from the stick"
# A member to carry over.
start_sshd "$S/hostkey"
NODE2_WG=$(wg genkey | wg pubkey)
printf '{"name":"node-c","wg_key":"%s","ssh_host_key":"%s root@node-c","lan_ip":"192.168.1.25","proof":"%s"}' "$NODE2_WG" "$NODE_HK" "$(proof node-c "$NODE2_WG" "$NODE_HK")" | reg request >/dev/null
out=$(screen "$S/desk" "node-c" "a" "approved and signed|Failed" "")
check "node-c approved on the old coordinator" grep -q "node-c approved and signed" <<<"$out"
VOLD=$(jqr "d['signed_version']")
# Fresh install: new SSH key, new WireGuard key, empty registry, own proof.
NEW_WG=$(wg genkey | wg pubkey)
HOSTKEY2=$(cut -d' ' -f1,2 "$S/hostkey2.pub")
registry "$S/root2" "$NEW_WG" "$HOSTKEY2"
cp "$S/hostkey2.pub" "$S/root2/etc/ssh/ssh_host_ed25519_key.pub"
echo "restrict,command=\"$BIN registry --subnet 10.66.0.0/24 --root $S/root2\" $(cat "$S/desk/secrets/registry_ed25519.pub")" > "$S/authorized_keys"
start_sshd "$S/hostkey2"
jq2() { python3 -I -c "import json,sys; d=json.load(open('$S/root2/var/lib/dryserver/registry.json')); print($1)"; }
out=$(screen "$S/desk" "press N to look at the new one" "N" "Its screen must show the code [0-9]{3} [0-9]{3}" "y" "is your coordinator now|Failed" "")
check "N shows the new coordinator's code" grep -Eq "Its screen must show the code [0-9]{3} [0-9]{3}" <<<"$out"
check "the new coordinator is taken over" grep -q "coord is your coordinator now" <<<"$out"
check "the new key is pinned" grep -qF "$HOSTKEY2" "$S/desk/secrets/coordinator_known_hosts"
check "the new coordinator has node-c back" test "$(jq2 "sorted(m['name'] for m in d['members'])")" = "['coord', 'node-c']"
check "its entry carries the new keys" test "$(jq2 "d['members'][0]['wg_key']")" = "$NEW_WG"
check "version went up ($VOLD -> $(jq2 "d['signed_version']"))" test "$(jq2 "d['signed_version']")" -gt "$VOLD"
out=$(echo | reg signed)
check "servers can read the signed list from it" grep -q "BEGIN SSH SIGNATURE" <<<"$out"
out=$(screen "$S/desk" "node-c" "" 2>&1)
check_not "the screen is clean afterwards" grep -q "NOT SIGNED\|Cannot talk" <<<"$out"

echo "== releases"
desk() { (cd "$S/desk" && "$BIN" "$@" --config config.env --host 127.0.0.1 --port $PORT 2>&1); }
REL=$S/root2/var/lib/dryserver/release
out=$(desk release status)
check "release status: nothing published yet" grep -q "No release published yet" <<<"$out"
if ldd "$BIN" >/dev/null 2>&1; then
    out=$(desk release publish -yes -notes "dev build")
    check "publish refuses a binary that is not static" grep -q "linked against this computer's libraries" <<<"$out"
    check_not "nothing reached the coordinator" test -e "$REL/current"
    check_not "nothing was signed" test -e "$S/desk/secrets/release.signed.json"
fi
# A release signed with real OpenSSH, sent over ssh as the desktop sends
# it: the header line, then the binaries. A 3 MiB binary, a 1 MiB k3s.
head -c 3145728 /dev/urandom > "$S/bin.new"
head -c 1048576 /dev/urandom > "$S/k3s.new"
mkrel() { # serial offset -> $S/rel.doc, $S/rel.sig
    python3 -I - "$S" "$1" <<'PY'
import hashlib, json, sys, time
s, off = sys.argv[1], int(sys.argv[2])
b, k = open(s + "/bin.new", "rb").read(), open(s + "/k3s.new", "rb").read()
now = int(time.time())
doc = {"serial": now + off, "created": now - 60, "expires": now + 30 * 86400,
       "dryserver": {"version": "0.2.0", "sha256": hashlib.sha256(b).hexdigest(), "size": len(b)},
       "k3s": {"version": "v1.37.2+k3s1", "sha256": hashlib.sha256(k).hexdigest()},
       "arch_date": time.strftime("%Y/%m/%d", time.gmtime(now - 86400)),
       "rollback": False, "urgent": True, "notes": "live test"}
open(s + "/rel.doc", "w").write(json.dumps(doc, separators=(",", ":")))
PY
    ssh-keygen -Y sign -f "$S/desk/secrets/signing_ed25519" -n dryserver-release < "$S/rel.doc" > "$S/rel.sig" 2>/dev/null
}
upload() { # k3s size
    python3 -I -c "import json; print(json.dumps({'release': {'doc': open('$S/rel.doc').read(), 'sig': open('$S/rel.sig').read()}, 'k3s_size': $1}))"
    cat "$S/bin.new"
    if [ "$1" != 0 ]; then cat "$S/k3s.new"; fi
}
K3S_SIZE=$(stat -c %s "$S/k3s.new")
mkrel 0
out=$(upload 0 | reg release-put 2>&1)
check "a coordinator without the release's k3s asks for it" grep -q "send k3s" <<<"$out"
out=$(upload "$K3S_SIZE" | reg release-put 2>&1)
check "a release with its binaries arrives over ssh ($out)" grep -q '"serial"' <<<"$out"
SER=$(cat "$REL/current" 2>/dev/null)
check "the binary arrived whole" cmp "$S/bin.new" "$REL/$SER/dryserver"
check "and k3s" cmp "$S/k3s.new" "$REL/$SER/k3s"
out=$(upload "$K3S_SIZE" | reg release-put 2>&1)
check "the same release again is refused" grep -q "on the coordinator already" <<<"$out"
mkrel 10
out=$(upload "$K3S_SIZE" | head -c 2000000 | reg release-put 2>&1)
check "a cut-off upload is refused ($out)" grep -q "ended after" <<<"$out"
check "the newest stays" test "$(cat "$REL/current")" = "$SER"
check_not "nothing of it is left" bash -c "ls -d $REL/staging-* 2>/dev/null | grep -q ."
# Signed by someone else.
ssh-keygen -Y sign -f "$S/thief/secrets/signing_ed25519" -n dryserver-release < "$S/rel.doc" > "$S/rel.sig" 2>/dev/null
out=$(upload "$K3S_SIZE" | reg release-put 2>&1)
check "a release signed with another key is refused" grep -q "bad signature" <<<"$out"
out=$(desk release status)
check "release status shows the release and its notes" grep -q "Release $SER (urgent), made .*: live test" <<<"$out"
check "release status has a line per machine" grep -Eq "^[ !] coord +coordinator +" <<<"$out"
out=$(desk release resume)
check "resume without a rollout is refused" grep -q "no rollout to resume" <<<"$out"
# The screen checks a release on its worker; this one is refused before
# anything is signed (a build for this desktop, or older than 0.2.0).
# The screen redraws only what changed: wait for text drawn fresh.
out=$(screen "$S/desk" "u publish an update" "u" "esc cancel" $'\r' "nothing was signed|y sign and send" "R" "rollout to resume|y to confirm" "")
check "u on the screen checks the release and says why not" grep -q "nothing was signed" <<<"$out"
check "R on the screen with nothing stopped resumes nothing" grep -q "no rollout to resume" <<<"$out"
check_not "nothing was signed from the screen" test -e "$S/desk/secrets/release.signed.json"
out=$(desk release resume -skip)
check "resume -skip without a rollout is refused" grep -q "no rollout to resume" <<<"$out"
out=$(echo x | reg release-skip 2>&1)
check "release-skip needs the admin's signature" grep -q "bad admin request" <<<"$out"
out=$(reg "release-get $SER release" 2>&1)
check "release-get is not answered outside the mesh" grep -q "only answered over the mesh" <<<"$out"

echo "== connections"
# The screen asks the coordinator every few seconds over one shared
# connection. Open for 20 seconds (four rounds), it must not leave a
# connection per round behind, here or on the coordinator.
conns() { pgrep -fc "[s]sh .*-p $PORT .*-N -f" || true; }
screen "$S/desk" "this text never shows up" "" >/dev/null 2>&1
n=$(conns)
if [ "$n" -le 1 ]; then ok "four rounds of the screen share one connection ($n)"; else bad "the screen left $n connections behind"; fi
# Nobody asks any more: the shared connection ends by itself.
for _ in $(seq 30); do [ "$(conns)" -eq 0 ] && break; sleep 1; done
check "the shared connection ends after the screen is closed" test "$(conns)" -eq 0

echo "== $pass passed, $fail failed"
[ "$fail" = 0 ]
