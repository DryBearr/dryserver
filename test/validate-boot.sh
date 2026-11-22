#!/bin/bash
# The fallback kernel with the real tools, in an Arch container: the
# installer's presets and the rendered mkinitcpio post hook make both
# kernels' unified images with ukify, `dryserver boot place` puts them in
# place under their counted names, the fallback kernel keeps its image when
# only the initramfs changed, pacman reads the mark hook and runs it when a
# kernel goes, and systemd accepts the boot check unit.
#
#   test/validate-boot.sh
#
# Downloads linux, linux-lts and ukify into the container (a few hundred MB).
# Needs no config.env: it renders the files from a made-up one.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build -q
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp target/debug/dryserver "$work/dryserver"
cat >"$work/config.env" <<'EOF'
COORD_LAN_IP=192.168.1.50
ADMIN_SSH_PUBKEY=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest admin@desktop
EOF
"$work/dryserver" sysconf --config "$work/config.env" --out "$work/root" --role node --hostname node-test --host 5 >/dev/null

# The installer's presets (src/install/layout.rs; a unit test keeps these
# copies the same).
cat >"$work/linux.preset" <<'EOF'
# dryserver: a signed unified kernel image for systemd-boot. It is made under a
# name systemd-boot does not start; `dryserver boot place` (a mkinitcpio post
# hook) checks it and renames it into place, with a boot counter while new.
ALL_kver="/boot/vmlinuz-linux"
PRESETS=('default')
default_uki="/boot/EFI/Linux/arch-linux.efi"
default_options="--uki /boot/EFI/Linux/arch-linux.efi.new"
EOF
cat >"$work/linux-lts.preset" <<'EOF'
# dryserver: a signed unified kernel image for systemd-boot. It is made under a
# name systemd-boot does not start; `dryserver boot place` (a mkinitcpio post
# hook) checks it and renames it into place, with a boot counter while new.
ALL_kver="/boot/vmlinuz-linux-lts"
PRESETS=('default')
default_uki="/boot/EFI/Linux/arch-linux-lts.efi"
default_options="--uki /boot/EFI/Linux/arch-linux-lts.efi.new"
EOF

cat >"$work/check.sh" <<'EOF'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
images() { ls /boot/EFI/Linux | tr '\n' ' ' | sed 's/ $//'; }
want() { [[ "$(images)" == "$1" ]] || fail "images are '$(images)', want '$1'"; echo "ok: $1"; }

pacman-key --init >/dev/null 2>&1
pacman-key --populate >/dev/null 2>&1
pacman -Syu --noconfirm --needed linux linux-lts mkinitcpio systemd-ukify >/dev/null 2>&1

install -m755 /w/dryserver /usr/local/bin/dryserver
for f in etc/initcpio/post/dryserver-boot etc/pacman.d/hooks/55-dryserver-boot-mark.hook \
    etc/systemd/system/dryserver-boot-check.service etc/systemd/system/boot-complete.target.d/10-dryserver.conf \
    etc/systemd/system/emergency.service.d/10-dryserver.conf; do
    install -D -m "$(stat -c %a "/w/root/$f")" "/w/root/$f" "/$f"
done
sh -n /etc/initcpio/post/dryserver-boot
install -m644 /w/linux.preset /w/linux-lts.preset /etc/mkinitcpio.d/
echo "root=/dev/vda2 rw quiet panic=10" >/etc/kernel/cmdline
mkdir -p /boot/EFI/Linux
rm -f /boot/initramfs-linux*.img

echo "== both kernels, counted"
mkinitcpio -P >/tmp/out 2>&1 || { cat /tmp/out; fail "mkinitcpio -P"; }
grep -q "arch-linux+3.efi is in place" /tmp/out || { cat /tmp/out; fail "no place for linux"; }
want "arch-linux+3.efi arch-linux-lts+3.efi"
for i in /boot/EFI/Linux/*.efi; do
    ukify inspect "$i" | grep -q '^\.linux:' || fail "$i has no kernel"
done
du -h /boot/EFI/Linux/*.efi

echo "== a new initramfs: the fallback keeps the image it was made with"
mv /boot/EFI/Linux/arch-linux+3.efi /boot/EFI/Linux/arch-linux.efi
mv /boot/EFI/Linux/arch-linux-lts+3.efi /boot/EFI/Linux/arch-linux-lts.efi
before=$(sha256sum /boot/EFI/Linux/arch-linux-lts.efi)
mkinitcpio -P >/tmp/out 2>&1 || { cat /tmp/out; fail "mkinitcpio -P again"; }
grep -q "kept arch-linux-lts.efi" /tmp/out || { cat /tmp/out; fail "fallback image not kept"; }
want "arch-linux+3.efi arch-linux-lts.efi"
[[ "$(sha256sum /boot/EFI/Linux/arch-linux-lts.efi)" == "$before" ]] || fail "the fallback image changed"
dryserver boot status

echo "== a kernel goes: pacman runs the mark hook first"
mv /boot/EFI/Linux/arch-linux+3.efi /boot/EFI/Linux/arch-linux.efi
pacman -R --noconfirm linux-lts >/tmp/out 2>&1 || { cat /tmp/out; fail "pacman -R linux-lts"; }
grep -q "arch-linux-lts.efi is now arch-linux-lts+1.efi" /tmp/out || { cat /tmp/out; fail "mark hook did not run"; }
! grep -qi "hook.*invalid\|invalid.*hook" /tmp/out || { cat /tmp/out; fail "pacman did not take the hook"; }
want "arch-linux-lts+1.efi arch-linux.efi"
dryserver boot status | grep -q "no fallback kernel" || fail "status does not say there is no fallback"

echo "== the boot check unit"
systemd-analyze verify --man=no dryserver-boot-check.service boot-complete.target emergency.service

echo "== emergency mode in the initramfs restarts the machine"
for d in /usr/lib/modules/*; do [[ "$(cat "$d/pkgbase" 2>/dev/null)" == linux ]] && kver=${d##*/}; done
mkinitcpio -k "$kver" -g /tmp/initramfs.img >/tmp/out 2>&1 || { cat /tmp/out; fail "mkinitcpio -g"; }
lsinitcpio /tmp/initramfs.img | sed 's|^\./||' >/tmp/files
for f in etc/systemd/system/emergency.service.d/10-dryserver.conf etc/initrd-release usr/bin/sh usr/bin/sleep usr/bin/systemctl; do
    grep -qx "$f" /tmp/files || fail "$f is not in the initramfs"
done
# Outside the initramfs the drop-in's command does nothing, at once.
cmd=$(sed -n "s/^ExecStartPre=-//p" /etc/systemd/system/emergency.service.d/10-dryserver.conf)
start=$SECONDS
eval "timeout 5 $cmd" || fail "the emergency drop-in failed outside the initramfs"
(( SECONDS - start < 3 )) || fail "the emergency drop-in waited outside the initramfs"
echo "all ok"
EOF

podman run --rm --name "dryserver-validate-boot-$$" --security-opt label=disable \
    -v "$work:/w:ro" docker.io/library/archlinux:latest bash /w/check.sh
