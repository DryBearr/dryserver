#!/bin/bash
# Boot the installer ISO in a VM with a blank 20 GB disk. Once something is
# installed on the disk, the VM boots from the disk instead.
#
#   test/qemu.sh [name]        UEFI VM, disk out/vm-<name>.qcow2 (default name: node)
#   BIOS=1 test/qemu.sh        legacy BIOS instead of UEFI
#   TPM=1 test/qemu.sh         add an emulated TPM 2.0 chip (swtpm)
#   DATA=1 test/qemu.sh        add a second 20 GB disk (data disk tests)
#   HEADLESS=1 test/qemu.sh    no window; QMP socket at out/vm-<name>.qmp
#   RESET=1 test/qemu.sh       start from blank disks (and a fresh TPM)
#   SWITCH=1 test/qemu.sh      add a second NIC on a shared "switch" network
#                              (all VMs started with SWITCH=1 see each other)
#   SSH_PORT=2201 test/qemu.sh forward host port 2201 to the VM's SSH
#   MEM=1536 test/qemu.sh      memory in MiB (default 2048)
#   OVMF_CODE=... OVMF_VARS=... other UEFI firmware. Fedora's OVMF does not
#                              measure boot into the TPM; for TPM unlock tests
#                              use Arch's (edk2-ovmf, OVMF_CODE.4m.fd).
set -euo pipefail
cd "$(dirname "$0")/.."

name=${1:-node}
iso=${ISO:-out/dryserver.iso}
disk=out/vm-$name.qcow2
data=out/vm-$name-data.qcow2
vars=out/vm-$name.vars.fd
tpm=out/vm-$name.tpm
ovmf=/usr/share/edk2/ovmf

[[ -f $iso ]] || { echo "missing $iso, build it first" >&2; exit 1; }
mkdir -p out
[[ ${RESET:-} ]] && rm -rf "$disk" "$data" "$vars" "$tpm"
[[ -f $disk ]] || qemu-img create -q -f qcow2 "$disk" 20G

args=(
    -name "dryserver-$name"
    -enable-kvm -cpu host -smp 2 -m "${MEM:-2048}"
    -drive "file=$disk,if=none,id=disk0" -device virtio-blk-pci,drive=disk0,bootindex=1
    -drive "file=$iso,media=cdrom,readonly=on,if=none,id=cd0" -device ide-cd,drive=cd0,bootindex=2
)
nic=user,model=virtio-net-pci
[[ ${SSH_PORT:-} ]] && nic+=",hostfwd=tcp:127.0.0.1:$SSH_PORT-:22"
args+=(-nic "$nic")
if [[ ${SWITCH:-} ]]; then
    # Stable per-VM MAC from the name, so the switch sees distinct machines.
    mac=$(printf '%s' "$name" | md5sum | sed 's/^\(..\)\(..\)\(..\).*/52:54:66:\1:\2:\3/')
    args+=(-netdev socket,id=sw,mcast=230.0.66.1:16601 -device "virtio-net-pci,netdev=sw,mac=$mac")
fi
if [[ ${DATA:-} ]]; then
    # 20 GB: the installer hides disks under 16 GB.
    [[ -f $data ]] || qemu-img create -q -f qcow2 "$data" 20G
    args+=(-drive "file=$data,if=none,id=disk1" -device virtio-blk-pci,drive=disk1)
fi
if [[ -z ${BIOS:-} ]]; then
    [[ -f $vars ]] || cp "${OVMF_VARS:-$ovmf/OVMF_VARS.fd}" "$vars"
    args+=(
        -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE:-$ovmf/OVMF_CODE.fd}"
        -drive "if=pflash,format=raw,file=$vars"
    )
fi
if [[ ${TPM:-} ]]; then
    mkdir -p "$tpm"
    swtpm socket --tpm2 --daemon --tpmstate "dir=$tpm" \
        --ctrl "type=unixio,path=$tpm/sock" --pid "file=$tpm/pid" --log "file=$tpm/log"
    args+=(
        -chardev "socket,id=chrtpm,path=$tpm/sock"
        -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0
    )
fi
if [[ ${HEADLESS:-} ]]; then
    args+=(-display none -qmp "unix:out/vm-$name.qmp,server,nowait")
fi

exec qemu-system-x86_64 "${args[@]}"
