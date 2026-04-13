#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Missing required command: $cmd" >&2
        exit 1
    fi
}

require_cmd rustup
require_cmd rustc

host_triple="$(rustc -vV | sed -n 's/^host: //p')"
if [[ -z "$host_triple" ]]; then
    echo "Failed to determine rustc host triple." >&2
    exit 1
fi

component="rust-analyzer-${host_triple}"
rustup component add "$component" >/dev/null

ra_bin="$(rustup which rust-analyzer)"
if [[ -z "$ra_bin" ]] || [[ ! -x "$ra_bin" ]]; then
    echo "Failed to locate a runnable rust-analyzer from rustup." >&2
    exit 1
fi

install_dir="$ROOT_DIR/.kjit/bin"
mkdir -p "$install_dir"
ln -sfn "$ra_bin" "$install_dir/rust-analyzer"

echo "Configured rust-analyzer:"
echo "  component: $component"
echo "  binary:    $ra_bin"
echo "  link:      $install_dir/rust-analyzer"
