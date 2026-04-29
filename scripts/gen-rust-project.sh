#!/usr/bin/env bash
set -euo pipefail

# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/kjit-env.sh"

if [[ ! -f "$KBUILD_OUTPUT/.config" ]]; then
    echo "Kernel build directory is not prepared: $KBUILD_OUTPUT" >&2
    echo "Run ./scripts/setup-kernel-build.sh first." >&2
    exit 1
fi

if [[ "$(uname -s)" != "Linux" ]]; then
    cat >&2 <<EOF
rust-project.json must be generated inside the Linux dev environment.
Current host: $(uname -s)

Run:
  ./scripts/docker-dev.sh -- make rust-analyzer
EOF
    exit 1
fi

require_cmd python3
require_cmd rustc

: "${RUSTC:=rustc}"
export RUSTC

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

rustc_sysroot="$("$RUSTC" --print sysroot)"
rust_lib_src="${RUST_LIB_SRC:-$rustc_sysroot/lib/rustlib/src/rust/library}"
core_edition="${KJIT_RUST_CORE_EDITION:-2021}"

if [[ ! -d "$rust_lib_src" ]]; then
    echo "Rust source tree not found: $rust_lib_src" >&2
    echo "Install rust-src on the host or set RUST_LIB_SRC in .kjit.env." >&2
    exit 1
fi

tmp_project="$(mktemp)"
trap 'rm -f "$tmp_project"' EXIT

python3 "$KDIR/scripts/generate_rust_analyzer.py" \
    --cfgs="core=--cfg no_fp_fmt_parse" \
    --cfgs="alloc=--cfg no_global_oom_handling --cfg no_rc --cfg no_sync" \
    --cfgs='proc_macro2=--cfg feature="proc-macro" --cfg wrap_proc_macro' \
    --cfgs='quote=--cfg feature="proc-macro"' \
    --cfgs='syn=--cfg feature="clone-impls" --cfg feature="derive" --cfg feature="full" --cfg feature="parsing" --cfg feature="printing" --cfg feature="proc-macro" --cfg feature="visit-mut"' \
    --cfgs="pin_init_internal=--cfg kernel --cfg USE_RUSTC_FEATURES" \
    --cfgs="pin_init=--cfg kernel --cfg USE_RUSTC_FEATURES" \
    "$core_edition" \
    "$KDIR" \
    "$KBUILD_OUTPUT" \
    "$rustc_sysroot" \
    "$rust_lib_src" \
    "$ROOT_DIR" > "$tmp_project"

python3 - "$tmp_project" "$ROOT_DIR/rust-project.json" <<'PY'
import json
import sys

src, dst = sys.argv[1:3]
with open(src, "r", encoding="utf-8") as f:
    project = json.load(f)

crate_indices = {
    crate.get("display_name"): index
    for index, crate in enumerate(project["crates"])
}
alloc_index = crate_indices.get("alloc")

for crate in project["crates"]:
    if crate.get("display_name") == "rust_kjit":
        cfg = crate.setdefault("cfg", [])
        if "--cfg" not in cfg or "rust_analyzer" not in cfg:
            cfg.extend(["--cfg", "rust_analyzer"])
        deps = crate.setdefault("deps", [])
        if alloc_index is not None and not any(dep.get("name") == "alloc" for dep in deps):
            deps.append({"crate": alloc_index, "name": "alloc"})
        break

with open(dst, "w", encoding="utf-8") as f:
    json.dump(project, f, indent=4)
    f.write("\n")
PY

echo "Generated $ROOT_DIR/rust-project.json"
