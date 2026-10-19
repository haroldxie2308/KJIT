#!/usr/bin/env bash
# Host driver of one A22 measurement boot: three states (off, a21 = 56bc781 module, a22) paired in the boot.
#   a22-boot.sh KPTI BOOT REPS CELL...        KPTI: 0 or 1; CELL as in tests/guest/cond-sweep.sh
# Label a22-k<KPTI>-b<BOOT>, run directory $KJIT_BUILD_ROOT/runs/ub-<label> (via host/ub-run.sh, which waits
# for a quiet host). Environment: KJIT_BUILD_ROOT, QEMU_SSH_PORT, QEMU_GDB_PORT, MOD_A21, MOD_A22 (kjit.ko paths), WT.
set -euo pipefail
kpti=$1 boot=$2 reps=$3
shift 3
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
build_root="${KJIT_BUILD_ROOT:?}"
label="${LABEL_PREFIX:-a22}-k$kpti-b$boot"
run_dir="$build_root/runs/ub-$label"
mkdir -p "$run_dir"
cp "$here/a22-sweep.sh" "$here/cond-info.sh" "$run_dir/"
cp "${MOD_A21:?}" "$run_dir/kjit-a21.ko"
cp "${MOD_A22:?}" "$run_dir/kjit-a22.ko"
cells=("$@")
# Blocks: consecutive cells of the same SRV; rotate the blocks and the cells of each block by the boot number.
order=()
blocks=() block=() cur=""
for c in "${cells[@]}"; do
    srv=$(cut -d: -f2 <<< "$c")
    if [[ "$srv" != "$cur" ]]; then
        [[ -z "$cur" ]] || blocks+=("${block[*]}")
        block=() cur=$srv
    fi
    block+=("$c")
done
blocks+=("${block[*]}")
nb=${#blocks[@]}
for ((k = 0; k < nb; k++)); do
    read -r -a block <<< "${blocks[$(( (k + boot - 1) % nb ))]}"
    off=$(( ((boot - 1) * 5) % ${#block[@]} ))
    for ((i = 0; i < ${#block[@]}; i++)); do order+=("${block[$(( (i + off) % ${#block[@]} ))]}"); done
done
echo "a22-boot: $label ($(date '+%H:%M:%S')) kpti=$kpti cells: ${order[*]}"
# Take the host: wait (0.05 s poll) for a gap between other agents' boots, then hold it with a placeholder process
# named qemu-system-aarch64 (which their ub-run.sh waits on) until this boot's own guest is running.
lock_dir=/tmp/a22m-lock
mkdir -p "$lock_dir"
ln -sf /bin/sleep "$lock_dir/qemu-system-aarch64"
count() { { pgrep -x qemu-system-aarch64 || true; } | wc -l | tr -d ' '; }
while true; do
    if [[ $(count) -eq 0 && $(sysctl -n vm.loadavg | awk '{ print $2 }' | awk -v m="${UB_MAX_LOAD:-6}" '{ exit !($1 <= m) }'; echo $?) -eq 0 ]]; then
        "$lock_dir/qemu-system-aarch64" 3600 &
        placeholder=$!
        sleep 0.2
        if [[ $(count) -gt 1 ]]; then kill "$placeholder" 2> /dev/null; wait "$placeholder" 2> /dev/null || true; continue; fi
        break
    fi
    sleep 0.05
done
( until [[ $(count) -gt 1 ]]; do sleep 0.2; done; kill "$placeholder" 2> /dev/null ) &
UB_MODULE="$MOD_A22" UB_APPEND_EXTRA="rodata=off" UB_TIMEOUT="${UB_TIMEOUT:-3000}" \
    "$here/a22-ub-run.sh" "$label" "$kpti" "sh /kjit/cond-info.sh 5; sh /kjit/a22-sweep.sh /tmp/cond $reps $boot ${order[*]}"
kill "$placeholder" 2> /dev/null || true
