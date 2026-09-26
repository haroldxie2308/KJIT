#!/usr/bin/env bash
set -euo pipefail

# Create or update the patched kernel tree the K2 guest profiles build from:
# a git worktree of dep/linux ($KJIT_LINUX_GIT) at the pinned base commit, with
# kernel-patches/*.patch applied by `git am`. It shares dep/linux's objects, so
# it costs a checkout, not a second clone. dep/linux itself is never modified.
#
# Idempotent: $KJIT_PATCHED_KDIR.stamp records the base commit and the sha256
# of every patch; when it matches, nothing runs (and no git access is needed,
# so a container without the superproject's git dir can build from the tree).
# Fail-fast: a tree with local changes, a half-applied series, or a patch that
# does not apply stops the script; nothing is reset or discarded.
#
#   scripts/kjit-kernel-tree.sh          ensure the tree is current
#   scripts/kjit-kernel-tree.sh --check  only verify the stamp (exit 1 if stale)

# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/kjit-env.sh"

# The commit dep/linux is pinned to (Linux 7.1-rc1); the patches apply to it.
KJIT_KERNEL_BASE=254f49634ee16a731174d2ae34bc50bd5f45e731

check_only=0
case "${1:-}" in
    --check) check_only=1 ;;
    "") ;;
    *) echo "Usage: $(basename "$0") [--check]" >&2; exit 2 ;;
esac

tree="$KJIT_PATCHED_KDIR"
stamp="$tree.stamp"
patches=("$ROOT_DIR"/kernel-patches/*.patch)
if [[ ! -f "${patches[0]}" ]]; then
    echo "No patches in $ROOT_DIR/kernel-patches" >&2
    exit 1
fi

expected_stamp() {
    echo "base $KJIT_KERNEL_BASE"
    local p
    for p in "${patches[@]}"; do
        echo "patch $(sha256sum "$p" | cut -d' ' -f1) $(basename "$p")"
    done
}
expected="$(expected_stamp)"

if [[ -f "$stamp" && "$(<"$stamp")" == "$expected" && -f "$tree/Makefile" ]]; then
    echo "Patched kernel tree up to date: $tree"
    exit 0
fi
if (( check_only )); then
    echo "Patched kernel tree $tree is missing or stale (stamp $stamp)." >&2
    echo "Run scripts/kjit-kernel-tree.sh where $KJIT_LINUX_GIT is a git checkout (e.g. on the host)." >&2
    exit 1
fi

require_cmd git
if [[ "$(git -C "$KJIT_LINUX_GIT" rev-parse --show-toplevel 2>/dev/null)" != "$(cd "$KJIT_LINUX_GIT" 2>/dev/null && pwd -P)" ]] \
    || ! git -C "$KJIT_LINUX_GIT" rev-parse -q --verify "$KJIT_KERNEL_BASE^{commit}" >/dev/null; then
    cat >&2 <<MSG
Cannot create the patched kernel tree $tree: $KJIT_LINUX_GIT is not a git
checkout of the Linux submodule containing $KJIT_KERNEL_BASE. In a git worktree
of this repo or in a container, run this script where the submodule is checked
out, e.g. on the host:
  KJIT_LINUX_GIT=/path/to/KJIT/dep/linux KJIT_BUILD_ROOT=$KJIT_BUILD_ROOT scripts/kjit-kernel-tree.sh
MSG
    exit 1
fi

if [[ -e "$tree" ]]; then
    # Empty when $tree is not a git work tree at all.
    common="$(git -C "$tree" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || true)"
    expected_common="$(git -C "$KJIT_LINUX_GIT" rev-parse --path-format=absolute --git-common-dir)"
    if [[ "$common" != "$expected_common" ]]; then
        echo "$tree exists but is not a git worktree of $KJIT_LINUX_GIT; move it away." >&2
        exit 1
    fi
    if [[ -e "$(git -C "$tree" rev-parse --git-path rebase-apply)" ]]; then
        echo "$tree has a git am in progress; resolve or 'git -C $tree am --abort' first." >&2
        exit 1
    fi
    if [[ -n "$(git -C "$tree" status --porcelain --untracked-files=no)" ]]; then
        echo "$tree has local changes; commit them to kernel-patches/ or discard them first:" >&2
        git -C "$tree" status --short --untracked-files=no >&2
        exit 1
    fi
    git -C "$tree" checkout -q --detach "$KJIT_KERNEL_BASE"
else
    mkdir -p "$(dirname "$tree")"
    git -C "$KJIT_LINUX_GIT" worktree add -q --detach "$tree" "$KJIT_KERNEL_BASE"
fi

rm -f "$stamp"
if ! git -C "$tree" -c user.name=kjit -c user.email=kjit@localhost \
        am -q --committer-date-is-author-date "${patches[@]}"; then
    # Leave the tree at the base commit, not half-patched; the failure is
    # reported below either way.
    git -C "$tree" am --abort || true
    echo "kernel-patches/ does not apply to $KJIT_KERNEL_BASE in $tree" >&2
    exit 1
fi
printf '%s\n' "$expected" > "$stamp"
echo "Patched kernel tree: $tree ($(git -C "$tree" rev-list --count "$KJIT_KERNEL_BASE"..HEAD) patches on ${KJIT_KERNEL_BASE:0:12})"
