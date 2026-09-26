#!/usr/bin/env bash

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${KJIT_IGNORE_LOCAL_ENV:-0}" != "1" && -f "$ROOT_DIR/.kjit.env" ]]; then
    # shellcheck disable=SC1091
    source "$ROOT_DIR/.kjit.env"
fi

: "${ARCH:=arm64}"
: "${LLVM:=1}"
: "${DEFCONFIG:=tinyconfig}"
: "${KJIT_KERNEL_PROFILE:=tiny-qemu-debug}"
: "${KJIT_ENABLE_CAPSTONE_STUB:=0}"
# Kernels are only built out of tree: KDIR stays a clean source tree and each
# profile builds in $KJIT_BUILD_ROOT/<profile> (O=). Set KJIT_BUILD_ROOT to a
# directory outside the repo to share builds between worktrees; docker-dev.sh
# mounts it at the same absolute path in the container. The Makefile derives
# the same defaults.
: "${KJIT_BUILD_ROOT:=$ROOT_DIR/.kjit/build}"
# Every profile builds from the patched tree: a git worktree of the dep/linux
# submodule ($KJIT_LINUX_GIT, never modified) at the pinned commit with
# kernel-patches/*.patch applied (scripts/kjit-kernel-tree.sh).
: "${KJIT_LINUX_GIT:=$ROOT_DIR/dep/linux}"
: "${KJIT_PATCHED_KDIR:=$KJIT_BUILD_ROOT/linux-kjit}"
: "${KDIR:=$KJIT_PATCHED_KDIR}"
: "${KBUILD_OUTPUT:=$KJIT_BUILD_ROOT/$KJIT_KERNEL_PROFILE}"
# kjit.ko is built next to its kernel (Kbuild MO=), so a module can never be
# paired with a kernel it was not built against.
: "${KJIT_MODULE_DIR:=$KBUILD_OUTPUT/kjit-module}"
# K0 golden initramfs (scripts/mk-initramfs.sh) for this profile.
: "${KJIT_INITRAMFS:=$KBUILD_OUTPUT/kjit-initramfs/kjit-initramfs.cpio}"

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
# Set QEMU_INITRAMFS= (empty) to boot without an initramfs.
: "${QEMU_INITRAMFS=$KJIT_INITRAMFS}"
: "${QEMU_SHARE_DIR:=$ROOT_DIR}"
# 1 = virtio-net with user networking and an ssh host forward; 0 = no NIC.
: "${QEMU_USER_NET:=1}"

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
