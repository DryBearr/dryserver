#!/bin/bash
# Boot installer VMs wired like a small swarm, for testing joins, the mesh
# and the kill switch end to end. Every VM has two network cards:
#
#   1. its own router (QEMU's user network): DHCP, internet, and its SSH on
#      a port of this computer. The routers are separate, so every VM is
#      10.0.2.15 behind its own.
#   2. a shared switch: the coordinator's VM holds the hub, the others plug
#      in through sockets on 127.0.0.1. dryserver picks this card as the
#      switch port and runs WireGuard over it.
#
# A server reaches the coordinator's registry at 10.0.2.100, which its
# router forwards to the coordinator's SSH. So build the ISO with
#
#   COORD_LAN_IP='10.0.2.100'
#   WG_TRANSPORT='auto'
#
#   test/qemu-lan.sh coord NAME       the coordinator; start it first
#   test/qemu-lan.sh server NAME N    a server on switch socket N (1, 2, 3)
#
# SSH from this computer: the coordinator is 127.0.0.1:2201, server N is
# 127.0.0.1:220(N+1). No window: QMP socket at DIR/vm-NAME.qmp, PID in
# DIR/vm-NAME.pid. Once something is installed on the disk, the VM boots
# from the disk. Nothing of this reaches your real network.
#
# (One shared router for all VMs does not work: QEMU's user network answers
# connections between two VMs itself and resets them.)
#
#   DIR=out      where the disks and the ISO (DIR/out/dryserver.iso or
#                DIR/dryserver.iso) are
#   MEM=2048     memory in MiB
set -euo pipefail
kind=${1:?coord or server}
name=${2:?VM name}
dir=$(realpath "${DIR:-$(dirname "$0")/../out}")
iso=${ISO:-$dir/out/dryserver.iso}
[[ -f $iso ]] || iso=$dir/dryserver.iso
[[ -f $iso ]] || { echo "no dryserver.iso under $dir, build it first" >&2; exit 1; }
ovmf=/usr/share/edk2/ovmf
disk=$dir/vm-$name.qcow2
vars=$dir/vm-$name.vars.fd
[[ -f $disk ]] || qemu-img create -q -f qcow2 "$disk" 20G
[[ -f $vars ]] || cp "$ovmf/OVMF_VARS.fd" "$vars"
mac() { printf '%s' "$1" | md5sum | sed 's/^\(..\)\(..\)\(..\).*/52:54:77:\1:\2:\3/'; }

args=(
    -name "dryserver-$name"
    -enable-kvm -cpu host -smp 2 -m "${MEM:-2048}"
    -drive "file=$disk,if=none,id=disk0" -device virtio-blk-pci,drive=disk0,bootindex=1
    -drive "file=$iso,media=cdrom,readonly=on,if=none,id=cd0" -device ide-cd,drive=cd0,bootindex=2
    -drive "if=pflash,format=raw,readonly=on,file=$ovmf/OVMF_CODE.fd"
    -drive "if=pflash,format=raw,file=$vars"
    -display none -qmp "unix:$dir/vm-$name.qmp,server,nowait"
    -daemonize -pidfile "$dir/vm-$name.pid"
)
case $kind in
coord)
    args+=(
        -netdev user,id=router,hostfwd=tcp:127.0.0.1:2201-:22
        -device "virtio-net-pci,netdev=router,mac=$(mac "$name-router")"
        -netdev hubport,id=sw,hubid=0
        -device "virtio-net-pci,netdev=sw,mac=$(mac "$name-switch")"
    )
    for n in 1 2 3; do
        args+=(-netdev "socket,id=sock$n,listen=127.0.0.1:1670$n" -netdev "hubport,id=p$n,hubid=0,netdev=sock$n")
    done
    ;;
server)
    n=${3:?switch socket number: 1, 2 or 3}
    [[ $n == [123] ]] || { echo "socket number must be 1, 2 or 3" >&2; exit 1; }
    args+=(
        -netdev "user,id=router,hostfwd=tcp:127.0.0.1:220$((n + 1))-:22,guestfwd=tcp:10.0.2.100:22-cmd:nc 127.0.0.1 2201"
        -device "virtio-net-pci,netdev=router,mac=$(mac "$name-router")"
        -netdev "socket,id=sw,connect=127.0.0.1:1670$n"
        -device "virtio-net-pci,netdev=sw,mac=$(mac "$name-switch")"
    )
    ;;
*)
    echo "coord or server" >&2
    exit 1
    ;;
esac
exec qemu-system-x86_64 "${args[@]}"
