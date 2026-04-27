#!/usr/bin/env bash
set -euo pipefail

# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/kjit-env.sh"

build_image=0
clean_first=0
build_targets=(Image modules)
profile_stamp_name=".kjit-kernel-profile"

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Prepare a local ARM64 Linux build directory for KJIT development.

Options:
  --build                 Build kernel Image/modules after prepare
  --clean                 Clean the kernel build tree and exit
  --src-dir <path>        Kernel source tree (default: $KDIR)
  --build-dir <path>      Kernel output directory (default: $KBUILD_OUTPUT)
  --defconfig <target>    Defconfig target (default: $DEFCONFIG)
  --help                  Show this message
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build)
            build_image=1
            shift
            ;;
        --clean)
            clean_first=1
            shift
            ;;
        --src-dir)
            KDIR="$2"
            shift 2
            ;;
        --build-dir)
            KBUILD_OUTPUT="$2"
            shift 2
            ;;
        --defconfig)
            DEFCONFIG="$2"
            shift 2
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

ensure_linux_host
require_cmd make
require_cmd python3

if [[ ! -f "$KDIR/Makefile" ]]; then
    echo "Kernel source tree not found: $KDIR" >&2
    exit 1
fi

if [[ "$KJIT_ENABLE_CAPSTONE_STUB" == "1" ]]; then
    bash "$ROOT_DIR/scripts/ensure-kernel-capstone-stub.sh" "$KDIR"
fi

kernel_make=(make -C "$KDIR" ARCH="$ARCH" LLVM="$LLVM")
if [[ "$KBUILD_OUTPUT" != "$KDIR" ]]; then
    mkdir -p "$KBUILD_OUTPUT"
    kernel_make+=(O="$KBUILD_OUTPUT")
fi

profile_stamp="$KBUILD_OUTPUT/$profile_stamp_name"
profile="$KJIT_KERNEL_PROFILE"

case "$profile" in
    tiny-qemu)
        profile_fragments=(
            "$ROOT_DIR/kernel-config/tiny-qemu-base.conf"
            "$ROOT_DIR/kernel-config/tiny-qemu-rust.conf"
        )
        ;;
    tiny-qemu-debug)
        profile_fragments=(
            "$ROOT_DIR/kernel-config/tiny-qemu-base.conf"
            "$ROOT_DIR/kernel-config/tiny-qemu-rust.conf"
            "$ROOT_DIR/kernel-config/tiny-qemu-debug.conf"
        )
        ;;
    none|"")
        profile_fragments=()
        ;;
    *)
        echo "Unknown KJIT kernel profile: $profile" >&2
        exit 1
        ;;
esac

if (( clean_first )); then
    "${kernel_make[@]}" clean
    rm -f "$profile_stamp"
    exit 0
fi

"${kernel_make[@]}" rustavailable

needs_profile_refresh=0
if [[ ${#profile_fragments[@]} -gt 0 ]]; then
    if [[ ! -f "$profile_stamp" ]] || [[ "$(<"$profile_stamp")" != "$profile" ]]; then
        needs_profile_refresh=1
    fi
fi

if (( needs_profile_refresh )); then
    "${kernel_make[@]}" clean
fi

if [[ ${#profile_fragments[@]} -gt 0 ]]; then
    "${kernel_make[@]}" "$DEFCONFIG"
    merged_config="$(mktemp)"
    trap 'rm -f "$merged_config"' EXIT
    cp "$KBUILD_OUTPUT/.config" "$merged_config"
    KCONFIG_CONFIG="$KBUILD_OUTPUT/.config" \
        "$KDIR/scripts/kconfig/merge_config.sh" -m -O "$KBUILD_OUTPUT" \
        "$merged_config" "${profile_fragments[@]}"
    printf '%s' "$profile" > "$profile_stamp"
elif [[ ! -f "$KBUILD_OUTPUT/.config" ]]; then
    "${kernel_make[@]}" "$DEFCONFIG"
fi

"${kernel_make[@]}" olddefconfig
"${kernel_make[@]}" prepare modules_prepare

if (( build_image )); then
    "${kernel_make[@]}" "${build_targets[@]}"
fi

cat <<EOF
Kernel source: $KDIR
Kernel build:  $KBUILD_OUTPUT
Kernel image:  $QEMU_KERNEL_IMAGE
EOF
