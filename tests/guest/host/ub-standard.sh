#!/usr/bin/env bash
# Host driver of the redis run under the Userspace Bypass benchmark protocol
# (guest side: tests/guest/ub-standard.sh): boots, with KPTI off and forced on
# alternating, each running
#   - the null-syscall round trip (ub-bench.sh sys), the native ceiling,
#   - the size sweep, server pinned to CPU 0 and the client to CPUs 1-3,
#   - one size unpinned.
#
#   host/ub-standard.sh TAG BOOTS [REPS]
#
# BOOTS boots per KPTI setting (order k0 k1 k0 k1 ...), REPS passes per size per boot
# (default 1). Every boot goes through host/ub-run.sh (waits for a quiet host), label
# std-TAG-k<kpti>-b<boot>, run directory $KJIT_BUILD_ROOT/runs/ub-<label>. Both KPTI
# settings run with UB_APPEND_EXTRA=rodata=off (see ub-run.sh: kpti=1 does not boot
# without it) unless UB_APPEND_EXTRA is set. A boot that does not show the KPTI state it
# was asked for in its serial log (the kernel line "page table isolation forced ON", or
# its absence) stops the driver. Environment: UB_STD_SIZES (default 1 2 4 ... 16384),
# UB_STD_UNPINNED_SIZE (default 4), UB_STD_REQUESTS (default 1000000), UB_TIMEOUT
# (seconds per boot, default of ub-run.sh); as ub-run.sh otherwise. Summary:
#   host/ub-summarize.py std LABEL=SERIAL_LOG...
set -euo pipefail

[[ $# -ge 2 && $# -le 3 ]] || { echo "usage: ub-standard.sh TAG BOOTS [REPS]" >&2; exit 2; }
tag=$1
boots=$2
reps=${3:-1}

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
build_root="${KJIT_BUILD_ROOT:?set KJIT_BUILD_ROOT}"
export UB_APPEND_EXTRA="${UB_APPEND_EXTRA-rodata=off}"
sizes="${UB_STD_SIZES:-1 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192 16384}"
unpinned_size="${UB_STD_UNPINNED_SIZE:-4}"
requests="${UB_STD_REQUESTS:-1000000}"

t=/opt/kjit-tests
cmd="sh $t/ub-bench.sh sys 7; sh $t/ub-standard.sh /tmp/ubs pinned $requests $reps $sizes; sh $t/ub-standard.sh /tmp/ubu unpinned $requests $reps $unpinned_size"

for ((b = 1; b <= boots; b++)); do
    for kpti in 0 1; do
        label="std-$tag-k$kpti-b$b"
        echo "ub-standard: boot $label ($(date '+%H:%M:%S'))"
        "$here/ub-run.sh" "$label" "$kpti" "$cmd"
        log="$build_root/runs/ub-$label/serial.log"
        forced=$(grep -c 'kernel page table isolation forced ON' "$log" || true)
        if [[ "$kpti" == 1 && "$forced" == 0 ]] || [[ "$kpti" == 0 && "$forced" != 0 ]]; then
            echo "ub-standard: FAIL $label: KPTI $kpti requested, serial log shows forced-ON lines: $forced" >&2
            exit 1
        fi
    done
done
echo "ub-standard: done"
