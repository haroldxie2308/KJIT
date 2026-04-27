#!/usr/bin/env bash

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${KJIT_IGNORE_LOCAL_ENV:-0}" != "1" && -f "$ROOT_DIR/.kjit.env" ]]; then
    # shellcheck disable=SC1091
    source "$ROOT_DIR/.kjit.env"
fi

: "${KDIR:=$ROOT_DIR/dep/linux}"
: "${KBUILD_OUTPUT:=$KDIR}"
: "${ARCH:=arm64}"
: "${LLVM:=1}"
: "${DEFCONFIG:=tinyconfig}"
: "${KJIT_KERNEL_PROFILE:=tiny-qemu-debug}"
: "${KJIT_ENABLE_CAPSTONE_STUB:=0}"

: "${QEMU_BINARY:=qemu-system-aarch64}"
: "${QEMU_MEMORY:=4096}"
: "${QEMU_CPUS:=4}"
: "${QEMU_SSH_PORT:=10022}"
: "${QEMU_GDB_PORT:=1234}"
: "${QEMU_STATE_DIR:=$ROOT_DIR/.kjit/qemu}"
: "${QEMU_QMP_SOCKET:=$QEMU_STATE_DIR/qmp.sock}"
: "${QEMU_PID_FILE:=$QEMU_STATE_DIR/qemu.pid}"
: "${QEMU_SERIAL_LOG:=$QEMU_STATE_DIR/serial.log}"
: "${QEMU_APPEND:=console=ttyAMA0 panic=-1 nokaslr}"
: "${QEMU_KERNEL_IMAGE:=$KBUILD_OUTPUT/arch/$ARCH/boot/Image}"
: "${QEMU_ROOTFS_IMAGE:=}"
: "${QEMU_INITRAMFS:=}"
: "${QEMU_SHARE_DIR:=$ROOT_DIR}"

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Missing required command: $cmd" >&2
        exit 1
    fi
}

ensure_linux_host() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        cat >&2 <<EOF
This step expects a Linux host or Linux VM/container.
Current host: $(uname -s)

The repo layout is still valid on this machine, but run the kernel build steps
inside your Linux development environment.
EOF
        exit 1
    fi
}

qmp_send() {
    local socket="$1"
    local payload="$2"

    if command -v socat >/dev/null 2>&1; then
        printf '%s' "$payload" | socat - UNIX-CONNECT:"$socket"
        return
    fi

    if command -v nc >/dev/null 2>&1; then
        printf '%s' "$payload" | nc -U "$socket"
        return
    fi

    echo "Missing required command: socat or nc" >&2
    exit 1
}
