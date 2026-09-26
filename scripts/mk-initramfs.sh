#!/usr/bin/env bash
set -euo pipefail

# Build the QEMU bring-up initramfs: a static /init that insmods /kjit.ko,
# rmmods it, and powers off. Run inside the Linux dev container after
# `make kernel-build` and `make module-build` for the same profile
# (`make initramfs`). Written next to that profile's kernel build.

# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/kjit-env.sh"

ensure_linux_host
require_cmd cc

gen_init_cpio="$KBUILD_OUTPUT/usr/gen_init_cpio"
module="$KJIT_MODULE_DIR/kjit.ko"
out="$KJIT_INITRAMFS"
out_dir="$(dirname "$out")"

if [[ ! -x "$gen_init_cpio" ]]; then
    echo "Missing $gen_init_cpio; run make kernel-build first." >&2
    exit 1
fi
if [[ ! -f "$module" ]]; then
    echo "Missing $module; run make module-build first." >&2
    exit 1
fi

mkdir -p "$out_dir"
cc -static -O2 -Wall -Werror -o "$out_dir/init" "$ROOT_DIR/scripts/qemu-initramfs/init.c"

cat > "$out_dir/cpio.list" <<LIST
dir /dev 0755 0 0
nod /dev/console 0600 0 0 c 5 1
file /init $out_dir/init 0755 0 0
file /kjit.ko $module 0644 0 0
LIST

"$gen_init_cpio" "$out_dir/cpio.list" > "$out.tmp"
mv "$out.tmp" "$out"
echo "Initramfs: $out"
