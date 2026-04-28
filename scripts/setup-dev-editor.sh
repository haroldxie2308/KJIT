#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if command -v git >/dev/null 2>&1; then
    if ! git config --global --get-all safe.directory | grep -qx /workspace; then
        git config --global --add safe.directory /workspace
    fi
fi

bash "$ROOT_DIR/scripts/setup-dev-rust-analyzer.sh"

if command -v nvim >/dev/null 2>&1 && [[ -f /opt/kjit/nvim/init.lua ]]; then
    mkdir -p "${HOME}/.config/nvim"
    ln -sfn /opt/kjit/nvim/init.lua "${HOME}/.config/nvim/init.lua"
fi

touch "${HOME}/.bashrc"
if ! grep -q 'alias vim=nvim' "${HOME}/.bashrc"; then
    printf '\n# KJIT dev container editor defaults\n' >> "${HOME}/.bashrc"
    printf 'if command -v nvim >/dev/null 2>&1; then alias vim=nvim; fi\n' >> "${HOME}/.bashrc"
fi

if [[ -n "${KJIT_DEV_PROMPT:-}" ]] && ! grep -q 'KJIT dev container prompt' "${HOME}/.bashrc"; then
    cat >> "${HOME}/.bashrc" <<'EOF'

# KJIT dev container prompt
if [[ -n "${KJIT_DEV_PROMPT:-}" ]]; then
    PS1="${KJIT_DEV_PROMPT}:\w\$ "
fi
EOF
fi

if [[ ! -f "$ROOT_DIR/rust-project.json" ]]; then
    cat <<'EOF'
Neovim is configured. For full Rust-for-Linux LSP quality, run:
  make prepare
  make rust-analyzer
EOF
fi
