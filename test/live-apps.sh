#!/bin/bash
# Live check of the apps screen over real SSH: the real `dryserver apps`
# on a "desktop" (driven through a pty), a real sshd as the "coordinator"
# whose forced command plays k3s kubectl: quick, slow, or not at all.
#
# It checks that the screen never freezes, that a call that does not
# answer gives up, that quitting while a call runs leaves no ssh behind,
# and that the screen keeps one shared connection that ends by itself.
#
# Needs sshd, ssh-keygen and python3. Changes nothing on this machine (a
# temporary directory and sshd on 127.0.0.1:2211). Takes about a minute
# and a half.
#
#   cargo build && test/live-apps.sh [path/to/dryserver]
set -uo pipefail
BIN=$(realpath "${1:-$(dirname "$0")/../target/debug/dryserver}")
# Short: the shared connection's socket lives in here.
S=$(mktemp -d /tmp/dsa.XXXXXX)
PORT=${PORT:-2211}  # another with PORT=NNNN when two runs share a machine
pass=0 fail=0
ok() { echo "  PASS $*"; pass=$((pass + 1)); }
bad() { echo "  FAIL $*"; fail=$((fail + 1)); }
check() { local msg=$1; shift; if "$@" >/dev/null 2>&1; then ok "$msg"; else bad "$msg"; fi; }
cleanup() {
    [ -f "$S/sshd.pid" ] && { pkill -P "$(cat "$S/sshd.pid")" 2>/dev/null; kill "$(cat "$S/sshd.pid")" 2>/dev/null; }
    pkill -f "ControlPath=$S/r/" 2>/dev/null
    rm -rf "$S"
}
trap cleanup EXIT

mkdir -p "$S"/{desk/secrets,bin} && mkdir -m 700 "$S/r"
ssh-keygen -q -t ed25519 -N '' -C coord -f "$S/hostkey"
ssh-keygen -q -t ed25519 -N '' -C admin -f "$S/userkey"
printf "COORD_LAN_IP='127.0.0.1'\nWG_SUBNET='10.66.0.0/24'\nWG_PORT='51820'\nUSERNAME='%s'\n" "$USER" > "$S/desk/config.env"
echo "[127.0.0.1]:$PORT $(cut -d' ' -f1,2 "$S/hostkey.pub")" > "$S/desk/secrets/coordinator_known_hosts"

# The coordinator's k3s: logs each call, answers like kubectl. $S/mode
# says how: ok, or slow (never answers in time).
echo ok > "$S/mode"
cat > "$S/k3s" <<EOF
#!/bin/bash
echo "\$SSH_ORIGINAL_COMMAND" >> "$S/calls"
[ "\$(cat "$S/mode")" = slow ] && exec sleep 120
case "\$SSH_ORIGINAL_COMMAND" in
  "k3s kubectl "*" get "*) cat <<'JSON'
{"items":[{"kind":"Deployment","metadata":{"name":"blog","namespace":"apps","labels":{"app":"blog"}},"spec":{"replicas":1,"template":{"spec":{"containers":[{"image":"nginx:1.27"}]}}},"status":{"readyReplicas":1}}]}
JSON
  ;;
  "k3s kubectl "*" apply -f -") cat > "$S/applied"; echo applied ;;
  *) cat > /dev/null ;;
esac
EOF
chmod +x "$S/k3s"
echo "restrict,command=\"$S/k3s\" $(cat "$S/userkey.pub")" > "$S/authorized_keys"
cat > "$S/sshd.conf" <<EOF
Port $PORT
ListenAddress 127.0.0.1
HostKey $S/hostkey
PidFile $S/sshd.pid
AuthorizedKeysFile $S/authorized_keys
StrictModes no
UsePAM no
AllowUsers $USER
EOF
/usr/sbin/sshd -f "$S/sshd.conf"
sleep 0.3

# The desktop logs in with the test key, and nothing from ~/.ssh.
cat > "$S/bin/ssh" <<EOF
#!/bin/bash
exec /usr/bin/ssh -F /dev/null -i "$S/userkey" -o IdentitiesOnly=yes "\$@"
EOF
chmod +x "$S/bin/ssh"
export PATH="$S/bin:$PATH" XDG_RUNTIME_DIR="$S/r"

# Drives the apps screen (or SCREEN=outside) at 80x24: pairs of WAIT_FOR
# KEYS, then q. A small terminal in Python keeps what is on the screen,
# since only changed cells are drawn. Prints every screen it saw (squeezed
# to one line each), then "exit after N ms" for how long the last q took.
screen_raw() {
    python3 -I - "$BIN" "$PORT" "$S/desk" "$@" <<'PY'
import os, pty, re, select, sys, time
binp, port, cwd, steps = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
pid, fd = pty.fork()
if pid == 0:
    import fcntl, struct, termios
    fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    os.chdir(cwd)
    os.environ["TERM"] = "xterm-256color"
    os.execv(binp, [binp, os.environ.get("SCREEN", "apps"), "--config", "config.env", "--host", "127.0.0.1", "--port", port])
rows, cols = 24, 80
cells = [[" "] * cols for _ in range(rows)]
y = x = 0
pending = ""
screens = []
def feed(text):
    global y, x, pending
    text = pending + text
    pending = ""
    i = 0
    while i < len(text):
        c = text[i]
        if c == "\x1b":
            m = re.match(r"\x1b\[([0-9;?]*)([ -/]*)([@-~])", text[i:])
            if not m:
                if len(text) - i < 16: pending = text[i:]; return
                i += 1; continue
            args, cmd = m.group(1), m.group(3)
            nums = [int(n) if n.isdigit() else 0 for n in args.replace("?", "").split(";")] if args else []
            if cmd in "Hf":
                y = max((nums[0] if nums else 1) - 1, 0); x = max((nums[1] if len(nums) > 1 else 1) - 1, 0)
            elif cmd == "J" and not args.startswith("?"):
                for r in cells: r[:] = [" "] * cols
            elif cmd == "K":
                cells[min(y, rows - 1)][x:] = [" "] * (cols - x)
            elif cmd == "C":
                x += nums[0] if nums and nums[0] else 1
            i += len(m.group(0)); continue
        if c == "\r": x = 0
        elif c == "\n": y = min(y + 1, rows - 1)
        elif c >= " ":
            if y < rows and x < cols: cells[y][x] = c
            x += 1
        i += 1
def now():
    return re.sub(r"\s+", " ", " ".join("".join(r) for r in cells))
def read_until(pat, timeout):
    end = time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try: data = os.read(fd, 65536)
            except OSError: return False
            feed(data.decode("utf-8", "replace"))
            s = now()
            if not screens or screens[-1] != s: screens.append(s)
        if re.search(pat, now()): return True
    return False
okay = True
for i in range(0, len(steps), 2):
    if not read_until(steps[i], 40):
        okay = False
        break
    time.sleep(0.2)
    os.write(fd, steps[i + 1].encode())
time.sleep(0.3)
start = time.time()
try: os.write(fd, b"q")
except OSError: pass
gone = None
while time.time() - start < 10:
    if os.waitpid(pid, os.WNOHANG)[0] == pid:
        gone = time.time() - start
        break
    try: os.read(fd, 65536)
    except OSError: pass
    time.sleep(0.02)
print("\n".join(screens))
print("exit after %d ms" % (gone * 1000) if gone is not None else "did not exit")
sys.exit(0 if okay else 1)
PY
}
# Keeps every screen capture for debugging when DEBUG_DIR is set.
screen() { local o; o=$(screen_raw "$@" 2>&1); local rc=$?; [ -n "${DEBUG_DIR:-}" ] && printf '%s\n' "$o" > "$DEBUG_DIR/screen-$(date +%s%N).txt"; printf '%s\n' "$o"; return $rc; }
clients() { pgrep -fc "[s]sh .*-p $PORT .*k3s kubectl" || true; }
masters() { pgrep -fc "[s]sh .*-p $PORT .*-M -N -f" || true; }

echo "== the screen lists the apps over one shared connection"
out=$(screen "blog" "r" "1/1 running" "" 2>&1)
check "the screen shows the app from the coordinator" grep -q "blog .*1/1 running" <<<"$out"
check "it ended at once" grep -Eq "exit after [0-9]{1,3} ms" <<<"$out"
check "the calls went through the shared connection ($(masters))" test "$(masters)" -eq 1
check "no call is left running" test "$(clients)" -eq 0

echo "== a new app"
out=$(screen "blog" "n" "Name" $'web\r' "Image" $'nginx:1.27\r' "Port" $'80\r' "Public host name" $'\r\r' "web is starting|Not started" "" 2>&1)
check "the screen says it is starting" grep -q "web is starting" <<<"$out"
check "the coordinator got the manifest on stdin" grep -q 'name: "web"' "$S/applied"
check "still one shared connection ($(masters))" test "$(masters)" -eq 1

echo "== the ways in from outside"
out=$(screen "blog" "o" "Your VPS +not set up" "a" "n new app" "" 2>&1)
check "o goes to the Outside screen" grep -q "Cloudflare Tunnel .*not set up" <<<"$out"
check "a comes back to the apps" grep -Eq "Your VPS.*n new app" <<<"$(tr '\n' ' ' <<<"$out")"
out=$(SCREEN=outside screen "Your VPS +not set up" "j" "> Your VPS" "x" "nothing to close" "" 2>&1)
check "./dryserver outside opens it directly" grep -q "Your VPS is not set up; there is nothing to close" <<<"$out"
check "both screens share one connection" test "$(masters)" -eq 1

echo "== three rounds of refreshes (about 35 seconds)"
before=$(wc -l < "$S/calls")
out=$(screen "this text never shows up" "" 2>&1)
after=$(wc -l < "$S/calls")
check "it asked every 15 seconds ($((after - before)) calls)" test $((after - before)) -ge 3 -a $((after - before)) -le 4
check "one shared connection after three rounds ($(masters))" test "$(masters)" -le 1

echo "== the coordinator stops answering"
echo slow > "$S/mode"
out=$(screen "asking the coordinator" "r" "Already asking the coordinator" "" "not answering \([0-9]+s\)" "" "did not answer within 15s" "" 2>&1)
check "keys work while the call hangs" grep -q "Already asking the coordinator" <<<"$out"
check "the screen says the coordinator is not answering" grep -q "the coordinator is not answering (" <<<"$out"
check "the call gives up after 15 seconds" grep -q "did not answer within 15s" <<<"$out"
check "no call is left running after the give-up" test "$(clients)" -eq 0
out=$(screen "not answering \([0-9]+s\)" "" 2>&1)
check "quitting while a call runs is immediate" grep -Eq "exit after [0-9]{1,3} ms" <<<"$out"
sleep 0.3
check "and leaves no ssh behind" test "$(clients)" -eq 0

echo "== the shared connection ends by itself"
for _ in $(seq 40); do [ "$(masters)" -eq 0 ] && break; sleep 1; done
check "no ssh is left once nobody asks" test "$(masters)" -eq 0

echo "== $pass passed, $fail failed"
[ "$fail" = 0 ]
