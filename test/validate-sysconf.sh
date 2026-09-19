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

podman run --rm --name "dryserver-validate-$$" --cap-add NET_ADMIN \
    --security-opt label=disable -v "$work:/r:ro" \
    docker.io/library/archlinux:latest bash -c '
set -euo pipefail
pacman -Sy --noconfirm --needed nftables openssh sudo jq >/dev/null 2>&1
ssh-keygen -A >/dev/null
useradd -m admin; useradd -m dryreg
fail=0
for r in node coord; do
    echo "== $r"
    nft -c -f /r/$r/etc/nftables.conf && echo "nft: ok" || fail=1
    visudo -cq -f /r/$r/etc/sudoers.d/10-wheel && echo "sudoers: ok" || fail=1
    rm -f /etc/ssh/sshd_config.d/*; cp /r/$r/etc/ssh/sshd_config.d/10-dryserver.conf /etc/ssh/sshd_config.d/
    /usr/bin/sshd -t && echo "sshd: ok" || fail=1
    /usr/bin/sshd -T 2>/dev/null | grep -iE "^(passwordauthentication|kbdinteractiveauthentication|permitrootlogin|allowusers|maxauthtries|authenticationmethods) " | sed "s/^/  /" || true
    if [[ -f /r/$r/etc/docker/daemon.json ]]; then jq -e .ip /r/$r/etc/docker/daemon.json >/dev/null && echo "docker: ok" || fail=1; fi
done
exit $fail
'

# Some sysctl keys are not visible inside a container network namespace, so
# check them against the host kernel.
while IFS="=" read -r k _; do
    k=${k// /}; [[ -z $k || $k == \#* ]] && continue
    [[ -e /proc/sys/${k//.//} ]] || { echo "sysctl: unknown key $k" >&2; exit 1; }
done < "$work/node/etc/sysctl.d/90-dryserver.conf"
echo "sysctl keys: ok"
