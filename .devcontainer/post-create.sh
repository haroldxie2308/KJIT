#!/usr/bin/env bash
set -euo pipefail

bash /workspace/scripts/setup-dev-editor.sh

cat <<'EOF'
Dev container ready.

Suggested setup:
  make prepare
  make rust-analyzer
  make module-build

QEMU remains a host-side workflow unless you explicitly wire it into the container.
EOF
