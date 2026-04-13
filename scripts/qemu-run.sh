#!/usr/bin/env bash
set -euo pipefail

# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/kjit-env.sh"

detach=0
gdb_wait=0
extra_args=()

usage() {
    cat <<EOF
Usage: $(basename "$0") [options] [-- <extra qemu args>]

Boot the locally built ARM64 kernel under QEMU with QMP enabled.

Options:
  --detach       Run QEMU in the background
  --gdb-wait     Start paused and expose a GDB stub on tcp::$QEMU_GDB_PORT
  --help         Show this message
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --detach)
            detach=1
            shift
            ;;
        --gdb-wait)
            gdb_wait=1
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        --)
            shift
            extra_args+=("$@")
            break
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

require_cmd "$QEMU_BINARY"

if [[ ! -f "$QEMU_KERNEL_IMAGE" ]]; then
    echo "Kernel image not found: $QEMU_KERNEL_IMAGE" >&2
    echo "Run ./scripts/setup-kernel-build.sh --build first." >&2
    exit 1
fi

mkdir -p "$QEMU_STATE_DIR"
rm -f "$QEMU_QMP_SOCKET"

machine_args=(-machine virt)
case "$(uname -s)" in
    Linux)
        if [[ -e /dev/kvm ]]; then
            machine_args=(-machine virt,accel=kvm)
        fi
        ;;
    Darwin)
        machine_args=(-machine virt,accel=hvf)
        ;;
esac

qemu_args=(
    "${machine_args[@]}"
    -cpu cortex-a72
    -smp "$QEMU_CPUS"
    -m "$QEMU_MEMORY"
    -nographic
    -kernel "$QEMU_KERNEL_IMAGE"
    -append "$QEMU_APPEND"
    -pidfile "$QEMU_PID_FILE"
    -qmp "unix:$QEMU_QMP_SOCKET,server=on,wait=off"
    -device virtio-net-pci,netdev=net0
    -netdev "user,id=net0,hostfwd=tcp::${QEMU_SSH_PORT}-:22"
    -virtfs "local,path=$QEMU_SHARE_DIR,mount_tag=hostshare,security_model=none"
)

if [[ -n "$QEMU_ROOTFS_IMAGE" ]]; then
    qemu_args+=(
        -drive "if=virtio,format=qcow2,file=$QEMU_ROOTFS_IMAGE"
    )
fi

if [[ -n "$QEMU_INITRAMFS" ]]; then
    qemu_args+=(-initrd "$QEMU_INITRAMFS")
fi

if (( gdb_wait )); then
    qemu_args+=(-S -gdb "tcp::$QEMU_GDB_PORT")
fi

if (( detach )); then
    qemu_args+=(
        -daemonize
        -serial "file:$QEMU_SERIAL_LOG"
        -monitor none
    )
else
    qemu_args+=(-serial mon:stdio)
fi

exec "$QEMU_BINARY" "${qemu_args[@]}" "${extra_args[@]}"

