#!/usr/bin/env bash
set -euo pipefail

# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/kjit-env.sh"

if [[ ! -S "$QEMU_QMP_SOCKET" ]]; then
    echo "QMP socket not found: $QEMU_QMP_SOCKET" >&2
    echo "Start QEMU first with ./scripts/qemu-run.sh." >&2
    exit 1
fi

payload=$'{"execute":"qmp_capabilities"}\n{"execute":"system_reset"}\n'
qmp_send "$QEMU_QMP_SOCKET" "$payload"

