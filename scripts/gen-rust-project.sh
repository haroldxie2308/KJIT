#!/usr/bin/env bash
set -euo pipefail

# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/kjit-env.sh"

if [[ ! -f "$KBUILD_OUTPUT/.config" ]]; then
    echo "Kernel build directory is not prepared: $KBUILD_OUTPUT" >&2
    echo "Run ./scripts/setup-kernel-build.sh first." >&2
    exit 1
fi

require_cmd python3
require_cmd rustc

rust_obj_dir="$KDIR/rust"
if [[ "$KBUILD_OUTPUT" != "$KDIR" && -f "$KBUILD_OUTPUT/rust/libmacros.so" ]]; then
    rust_obj_dir="$KBUILD_OUTPUT/rust"
fi

if [[ ! -f "$KBUILD_OUTPUT/include/generated/rustc_cfg" ]]; then
    echo "Missing generated Rust cfgs under $KBUILD_OUTPUT/include/generated/rustc_cfg" >&2
    echo "Run ./scripts/setup-kernel-build.sh first." >&2
    exit 1
fi

if [[ ! -f "$rust_obj_dir/libmacros.so" ]]; then
    echo "Kernel Rust artifacts are not built under $KBUILD_OUTPUT/rust" >&2
    echo "Run ./scripts/setup-kernel-build.sh --build first." >&2
    exit 1
fi

rustc_sysroot="$(rustc --print sysroot)"
rust_lib_src="${RUST_LIB_SRC:-$rustc_sysroot/lib/rustlib/src/rust/library}"

if [[ ! -d "$rust_lib_src" ]]; then
    echo "Rust source tree not found: $rust_lib_src" >&2
    echo "Install rust-src on the host or set RUST_LIB_SRC in .kjit.env." >&2
    exit 1
fi

python3 "$KDIR/scripts/generate_rust_analyzer.py" \
    --cfgs="core=--cfg no_fp_fmt_parse" \
    --cfgs="alloc=--cfg no_global_oom_handling --cfg no_rc --cfg no_sync" \
    "$KDIR" \
    "$KBUILD_OUTPUT" \
    "$rust_lib_src" \
    "$ROOT_DIR" > "$ROOT_DIR/rust-project.json"

echo "Generated $ROOT_DIR/rust-project.json"
