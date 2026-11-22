#!/bin/bash
# Render the server system files for a node and a coordinator and check
# them with the real tools inside an Arch container:
#   nft -c (firewall), sshd -t/-T (SSH), visudo -c, jq (Docker), sysctl keys.
#
#   test/validate-sysconf.sh [config.env]
set -euo pipefail
cd "$(dirname "$0")/.."

cfg=${1:-config.env}
[[ -f $cfg ]] || { echo "missing $cfg" >&2; exit 1; }
[[ -x ./dryserver ]] || make -s

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
./dryserver sysconf --config "$cfg" --out "$work/node" --role node --hostname node-3a2f --host 5 >/dev/null
./dryserver sysconf --config "$cfg" --out "$work/coord" --role coordinator --hostname coord --host 1 >/dev/null

# The coordinator's registry account against a real sshd: only the registry
# runs for it, whatever key it has (one it swapped in itself too), with no
# terminal and nothing forwarded; tmpfiles makes its home root's on machines
# installed before, and the key under /etc/ssh/authorized_keys.d (new
# installs) works.
cat >"$work/registry.sh" <<'EOF'
set -euo pipefail
fail() { echo "registry: FAIL: $*" >&2; exit 1; }
subnet=$(sed -n 's/^\tForceCommand .* --subnet //p' /r/coord/etc/ssh/sshd_config.d/10-dryserver.conf)
[[ -n $subnet ]] || fail "no ForceCommand for the registry account"
usermod -d /var/lib/dryreg -s /bin/sh dryreg
printf '#!/bin/sh\necho "ran:$*:$SSH_ORIGINAL_COMMAND"\n[ -t 0 ] && echo "on a terminal"\nexit 0\n' >/usr/local/bin/dryserver
chmod 755 /usr/local/bin/dryserver
ssh-keygen -q -t ed25519 -N "" -f /tmp/reg
ssh-keygen -q -t ed25519 -N "" -f /tmp/own
chmod 644 /tmp/own.pub
line="restrict,command=\"/usr/local/bin/dryserver registry --subnet $subnet\" $(cat /tmp/reg.pub)"
# A coordinator installed before: the key in the account's home, which the
# account owns.
install -d -o dryreg -g dryreg -m 755 /var/lib/dryreg
install -d -m 755 /var/lib/dryreg/.ssh
echo "$line" >/var/lib/dryreg/.ssh/authorized_keys
rm -f /etc/ssh/sshd_config.d/10-dryserver.conf
cp /r/coord/etc/ssh/sshd_config.d/10-dryserver.conf /etc/ssh/sshd_config.d/
/usr/bin/sshd -p 2311
s() { ssh -p 2311 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$@"; }
want="ran:registry --subnet $subnet:peers"
[[ "$(s -i /tmp/reg dryreg@127.0.0.1 peers)" == "$want" ]] || fail "the registry key does not reach the registry"
# The account swaps in a key of its own, without the forced command.
runuser -u dryreg -- sh -c 'mv /var/lib/dryreg/.ssh /var/lib/dryreg/.old && mkdir /var/lib/dryreg/.ssh && cat /tmp/own.pub >/var/lib/dryreg/.ssh/authorized_keys'
[[ "$(s -i /tmp/own dryreg@127.0.0.1 id)" == "ran:registry --subnet $subnet:id" ]] || fail "a swapped-in key ran another command"
if s -tt -i /tmp/own dryreg@127.0.0.1 peers 2>/dev/null | grep -q "on a terminal"; then fail "a swapped-in key got a terminal"; fi
# Refused at once (255); a forward that works would wait for the timeout.
rc=0
timeout 15 ssh -p 2311 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ExitOnForwardFailure=yes \
    -i /tmp/own -N -R 9999:127.0.0.1:22 dryreg@127.0.0.1 2>/dev/null || rc=$?
[[ $rc == 255 ]] || fail "a swapped-in key forwarded a port (ssh ended with $rc)"
# At boot, tmpfiles makes the home root's: no more swapping.
rm -rf /var/lib/dryreg/.ssh
mv /var/lib/dryreg/.old /var/lib/dryreg/.ssh
systemd-tmpfiles --create /r/coord/etc/tmpfiles.d/dryserver-registry.conf
[[ "$(stat -c %U:%a /var/lib/dryreg /var/lib/dryreg/.ssh /var/lib/dryreg/.ssh/authorized_keys | tr '\n' ' ')" == "root:755 root:755 root:644 " ]] ||
    fail "tmpfiles left $(stat -c %n=%U:%a /var/lib/dryreg /var/lib/dryreg/.ssh /var/lib/dryreg/.ssh/authorized_keys | tr '\n' ' ')"
if runuser -u dryreg -- mv /var/lib/dryreg/.ssh /var/lib/dryreg/.x 2>/dev/null; then fail "the account still moves .ssh"; fi
[[ "$(s -i /tmp/reg dryreg@127.0.0.1 peers)" == "$want" ]] || fail "the registry key no longer works after tmpfiles"
# A new install: the key under /etc/ssh/authorized_keys.d, none in the home.
rm -rf /var/lib/dryreg/.ssh
install -d -m 755 /etc/ssh/authorized_keys.d
echo "$line" >/etc/ssh/authorized_keys.d/dryreg
[[ "$(s -i /tmp/reg dryreg@127.0.0.1 peers)" == "$want" ]] || fail "the key under /etc/ssh/authorized_keys.d does not work"
echo "registry account: ok"
EOF

podman run --rm --name "dryserver-validate-$$" --cap-add NET_ADMIN \
    --security-opt label=disable -v "$work:/r:ro" \
    docker.io/library/archlinux:latest bash -c '
set -euo pipefail
pacman -Syu --noconfirm --needed nftables openssh sudo jq >/dev/null 2>&1
ssh-keygen -A >/dev/null
useradd -m admin; useradd -m dryreg
fail=0
for r in node coord; do
    echo "== $r"
    nft -c -f /r/$r/etc/nftables.conf && echo "nft: ok" || fail=1
    visudo -cq -f /r/$r/etc/sudoers.d/10-wheel && echo "sudoers: ok" || fail=1
    rm -f /etc/ssh/sshd_config.d/10-dryserver.conf; cp /r/$r/etc/ssh/sshd_config.d/10-dryserver.conf /etc/ssh/sshd_config.d/
    /usr/bin/sshd -t && echo "sshd: ok" || fail=1
    /usr/bin/sshd -T 2>/dev/null | grep -iE "^(passwordauthentication|kbdinteractiveauthentication|permitrootlogin|allowusers|maxauthtries|authenticationmethods) " | sed "s/^/  /" || true
    if [[ -f /r/$r/etc/docker/daemon.json ]]; then jq -e .ip /r/$r/etc/docker/daemon.json >/dev/null && echo "docker: ok" || fail=1; fi
done
/usr/bin/sshd -T -C user=dryreg,host=x,addr=192.168.1.9 2>/dev/null | grep -iE "^(authorizedkeysfile|forcecommand|disableforwarding|permittty) " | sed "s/^/  dryreg: /" || true
bash /r/registry.sh || fail=1
exit $fail
'

# Some sysctl keys are not visible inside a container network namespace, so
# check them against the host kernel.
while IFS="=" read -r k _; do
    k=${k// /}; [[ -z $k || $k == \#* ]] && continue
    [[ -e /proc/sys/${k//.//} ]] || { echo "sysctl: unknown key $k" >&2; exit 1; }
done < "$work/node/etc/sysctl.d/90-dryserver.conf"
echo "sysctl keys: ok"
