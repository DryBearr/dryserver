#!/bin/bash
# Runs inside the archlinux container started by `dryserver build`.
# Input:  /stage (build.sh, packages.extra, overlay/), read-only
# Output: /out/dryserver.iso
set -euo pipefail

# pacman leaves download-* temp dirs owned by its sandbox user in the shared
# cache; the host user cannot remove those. Clean up leftovers from a killed
# build first, then again on exit.
rm -rf /var/cache/pacman/pkg/download-*
trap 'rm -rf /var/cache/pacman/pkg/download-*' EXIT

echo "==> Installing archiso"
pacman -Syu --noconfirm --needed archiso

# Rootless podman cannot mount devtmpfs, which pacstrap uses for the chroot
# /dev. In that case bind-mount the container's /dev instead (non-recursive,
# so teardown can unmount it). Rootful builds keep the stock tools.
mkdir -p /tmp/devtest
if mount -t devtmpfs devtmpfs /tmp/devtest 2>/dev/null; then
    umount /tmp/devtest
else
    echo "==> Rootless container: bind-mounting /dev for pacstrap"
    stock='chroot_add_mount udev "$1/dev" -t devtmpfs -o mode=0755,nosuid'
    grep -qF "$stock" /usr/bin/pacstrap || { echo "pacstrap changed, cannot patch /dev mount; build with sudo" >&2; exit 1; }
    sed -i "s|$stock|chroot_add_mount /dev \"\$1/dev\" --bind|" /usr/bin/pacstrap /usr/bin/arch-chroot
fi

profile=/tmp/profile
rm -rf "$profile" /tmp/work /tmp/iso
cp -r /usr/share/archiso/configs/releng "$profile"
cp -rT /stage/overlay "$profile"
grep -v '^#' /stage/packages.extra >> "$profile/packages.x86_64"

# Lock down the live system: no listening services, no cloud-init, no VM
# agents. Only outgoing connections are needed by the installer.
wants=$profile/airootfs/etc/systemd/system
rm -f "$wants"/multi-user.target.wants/{sshd,hv_fcopy_daemon,hv_kvp_daemon,hv_vss_daemon,vboxservice,vmtoolsd,vmware-vmblock-fuse}.service \
      "$wants"/sockets.target.wants/pcscd.socket
rm -rf "$wants"/cloud-init.target.wants
sed -i '/^cloud-init$/d' "$profile/packages.x86_64"
ln -sf /usr/lib/systemd/system/nftables.service "$wants"/multi-user.target.wants/nftables.service

# Start the setup screen on tty1 after autologin.
cat /stage/zlogin.append >> "$profile/airootfs/root/.zlogin"

# Boot the default entry after 3 seconds.
sed -i 's/^timeout .*/timeout 3/' "$profile/efiboot/loader/loader.conf"
sed -i 's/^TIMEOUT .*/TIMEOUT 30/' "$profile/syslinux/archiso_sys.cfg"
sed -i 's/^timeout=.*/timeout=3/' "$profile/grub/grub.cfg" "$profile/grub/loopback.cfg"

sed -i \
    -e 's/^iso_name=.*/iso_name="dryserver"/' \
    -e 's/^iso_label="ARCH_/iso_label="DRYSRV_/' \
    -e 's/^iso_publisher=.*/iso_publisher="dryserver"/' \
    -e 's/^iso_application=.*/iso_application="dryserver installer"/' \
    "$profile/profiledef.sh"
cat >> "$profile/profiledef.sh" <<'PERMS'
file_permissions+=(
  ["/usr/local/bin/dryserver"]="0:0:755"
  ["/etc/dryserver"]="0:0:700"
  ["/etc/dryserver/config.env"]="0:0:600"
  ["/etc/dryserver/registry_ed25519"]="0:0:600"
)
PERMS

echo "==> Running mkarchiso"
mkarchiso -v -w /tmp/work -o /tmp/iso "$profile"

mv /tmp/iso/dryserver-*.iso /out/dryserver.iso.tmp
mv /out/dryserver.iso.tmp /out/dryserver.iso
echo "==> Built /out/dryserver.iso"
