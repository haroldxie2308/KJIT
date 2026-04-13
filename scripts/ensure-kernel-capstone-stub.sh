#!/usr/bin/env bash
set -euo pipefail

kernel_dir="${1:-}"

if [[ -z "$kernel_dir" ]]; then
    echo "Usage: $(basename "$0") <kernel-source-dir>" >&2
    exit 1
fi

capstone_dir="$kernel_dir/lib/capstone"
if [[ -f "$capstone_dir/Kconfig" ]]; then
    exit 0
fi

mkdir -p "$capstone_dir"

cat >"$capstone_dir/Kconfig" <<'EOF'
config CAPSTONE
	bool "Capstone compatibility stub"
	default n
	help
	  Placeholder entry for kernel trees that reference lib/capstone/Kconfig
	  without vendoring the actual in-kernel Capstone sources.
EOF

cat >"$capstone_dir/Makefile" <<'EOF'
obj-$(CONFIG_CAPSTONE) += stub.o
EOF

cat >"$capstone_dir/stub.c" <<'EOF'
// SPDX-License-Identifier: GPL-2.0
/*
 * Placeholder object for linux-w-capstone trees that keep the Kconfig/Makefile
 * hooks but do not vendor the actual Capstone library sources.
 */
EOF
