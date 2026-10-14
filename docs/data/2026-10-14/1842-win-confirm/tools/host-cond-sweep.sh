#!/usr/bin/env bash
# Host driver of the operating-condition sweep (guest side: tests/guest/cond-sweep.sh):
# BOOTS boots of one kernel setting, each running a set of cells, KJIT off/on paired in the
# boot. The guest script is copied into each run directory (9p share /kjit).
#
#   host/cond-sweep.sh TAG SETTING BOOTS SET [REPS]
#
# SETTING  NAME:PROFILE:KERNEL_ARGS   (rodata=off is always added, as for host/ub-standard.sh;
#                                      kpti=1 does not boot without it)
# SET      dens   full density/command/persistence/transport set (28 cells)
#          key    short set at the reference conditions (SET/GET c50 P1 d1, GET/SET P16)
#          cmds   dens minus the persistence and unix-socket cells
#          dbg    the K = 2 cells at half the requests, for the debug kernel
#          unixx  unix-domain-socket cells (10)
#          unixwin 6 unix cells near zero under KPTI (use REPS 4)
#          uf     unixx + fan in one boot (all of these share a boot because boots are scarce)
#          dbgx   dbg + three unix-socket cells
#          fan    PUBLISH fan-out to 0, 4, 16 subscribers (guest script: TEST pub<N><l|r>)
#          custom the cell list in CONDSW_CELLS
# REPS     reps per cell per boot (default 2)
# Every boot first runs tests/guest/cond-info.sh (what the kernel enables + the null-syscall round
# trip, KJIT off and on), so each boot carries its own syscall cost.
#
# Boot label cond-TAG-NAME-b<boot>, run directory $KJIT_BUILD_ROOT/runs/ub-<label> (via
# host/ub-run.sh, which waits for a quiet host). Order: the cells of one server profile stay
# together; the blocks and the cells of the base block are rotated per boot. Environment:
# CONDSW_FIRST (number of the first boot, default 1), UB_TIMEOUT (default 2700), else as
# ub-run.sh (KJIT_BUILD_ROOT, QEMU_SSH_PORT, QEMU_GDB_PORT, UB_MODULE).
set -euo pipefail

[[ $# -ge 4 && $# -le 5 ]] || { echo "usage: cond-sweep.sh TAG NAME:PROFILE:ARGS BOOTS SET [REPS]" >&2; exit 2; }
tag=$1
IFS=: read -r sname sprofile sargs <<< "$2"
boots=$3
set_name=$4
reps=${5:-2}

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
build_root="${KJIT_BUILD_ROOT:?set KJIT_BUILD_ROOT}"
first="${CONDSW_FIRST:-1}"
export UB_TIMEOUT="${UB_TIMEOUT:-2700}"

# NAME:SRV:TEST:N:C:P:D:THR:SCPUS:CCPUS:XPORT
# Reference: the UB protocol (server on CPU 0, client on CPUs 1-3, --threads 2, -c 50).
ref_set=(
    set_c50_p1_d1:base:set:1000000:50:1:1:2:0:1-3:tcp
    get_c50_p1_d1:base:get:1000000:50:1:1:2:0:1-3:tcp
)
density=(
    set_c50_p1_d1024:base:set:1000000:50:1:1024:2:0:1-3:tcp
    get_c50_p1_d1024:base:get:1000000:50:1:1024:2:0:1-3:tcp
    set_c50_p4_d1:base:set:1000000:50:4:1:2:0:1-3:tcp
    get_c50_p4_d1:base:get:1000000:50:4:1:2:0:1-3:tcp
    set_c50_p16_d1:base:set:2000000:50:16:1:2:0:1-3:tcp
    get_c50_p16_d1:base:get:2000000:50:16:1:2:0:1-3:tcp
    set_c1_p1_d1:base:set:100000:1:1:1:0:0:1-3:tcp
    get_c1_p1_d1:base:get:100000:1:1:1:0:0:1-3:tcp
    set_c10_p1_d1:base:set:500000:10:1:1:2:0:1-3:tcp
    get_c10_p1_d1:base:get:500000:10:1:1:2:0:1-3:tcp
    set_c50_p1_d1_t0:base:set:500000:50:1:1:0:0:1-3:tcp
    get_c50_p1_d1_t0:base:get:500000:50:1:1:0:0:1-3:tcp
    incr_c50_p1:base:incr:600000:50:1:1:2:0:1-3:tcp
    lpush_c50_p1:base:lpush:600000:50:1:1:2:0:1-3:tcp
    pingi_c50_p1:base:ping_inline:600000:50:1:1:2:0:1-3:tcp
    pingm_c50_p1:base:ping_mbulk:600000:50:1:1:2:0:1-3:tcp
    mset_c50_p1:base:mset:500000:50:1:1:2:0:1-3:tcp
)
persist=(
    aofalw_set_c50_p1:aof_always:set:300000:50:1:1:2:0:1-3:tcp
    aofalw_set_c50_p16:aof_always:set:600000:50:16:1:2:0:1-3:tcp
    aofalw_incr_c50_p1:aof_always:incr:300000:50:1:1:2:0:1-3:tcp
    aofesec_set_c50_p1:aof_everysec:set:600000:50:1:1:2:0:1-3:tcp
    aofesec_set_c50_p16:aof_everysec:set:600000:50:16:1:2:0:1-3:tcp
    aofno_set_c50_p1:aof_no:set:600000:50:1:1:2:0:1-3:tcp
    aof9p_set_c50_p1:aof9p_always:set:60000:50:1:1:2:0:1-3:tcp
)
unixs=(
    unix_set_c50_p1:unix:set:1000000:50:1:1:2:0:1-3:unix
    unix_get_c50_p1:unix:get:1000000:50:1:1:2:0:1-3:unix
)
# Debug-kernel set: the K = 2 cells, half the requests (the kernel is several times slower).
dbg=(
    set_c50_p1_d1:base:set:500000:50:1:1:2:0:1-3:tcp
    get_c50_p1_d1:base:get:500000:50:1:1:2:0:1-3:tcp
    set_c50_p4_d1:base:set:500000:50:4:1:2:0:1-3:tcp
    get_c50_p4_d1:base:get:500000:50:4:1:2:0:1-3:tcp
    set_c50_p16_d1:base:set:1000000:50:16:1:2:0:1-3:tcp
    get_c50_p16_d1:base:get:1000000:50:16:1:2:0:1-3:tcp
    get_c50_p1_d1_t0:base:get:300000:50:1:1:0:0:1-3:tcp
    incr_c50_p1:base:incr:300000:50:1:1:2:0:1-3:tcp
    pingi_c50_p1:base:ping_inline:300000:50:1:1:2:0:1-3:tcp
    aofalw_set_c50_p1:aof_always:set:150000:50:1:1:2:0:1-3:tcp
    unix_get_c50_p1:unix:get:500000:50:1:1:2:0:1-3:unix
)
# Fan-out: PUBLISH to N subscribers (N writes per request); l = subscribers on the server's CPU
# (local wake-ups), r = on the client CPUs (remote wake-ups, an IPI each in this VM).
fan=(
    pub0_c50:base:pub0r:500000:50:1:1:2:0:1-3:tcp
    pub4l_c50:base:pub4l:100000:50:1:1:2:0:1-3:tcp
    pub16l_c50:base:pub16l:40000:50:1:1:2:0:1-3:tcp
    pub4r_c50:base:pub4r:50000:50:1:1:2:0:1-3:tcp
    pub16r_c50:base:pub16r:20000:50:1:1:2:0:1-3:tcp
    pub0_c1:base:pub0r:50000:1:1:1:0:0:1-3:tcp
    pub16l_c1:base:pub16l:20000:1:1:1:0:0:1-3:tcp
    pub64l_c1:base:pub64l:10000:1:1:1:0:0:1-3:tcp
)
# Unix-domain socket set (redis-benchmark -s), server on CPU 0: the nearest cells to a win in dens.
unixx=(
    unix_get_c50_p1_d1:unix:get:1000000:50:1:1:2:0:1-3:unix
    unix_set_c50_p1_d1:unix:set:1000000:50:1:1:2:0:1-3:unix
    unix_get_c50_p1_d1024:unix:get:1000000:50:1:1024:2:0:1-3:unix
    unix_set_c50_p1_d1024:unix:set:1000000:50:1:1024:2:0:1-3:unix
    unix_incr_c50_p1:unix:incr:600000:50:1:1:2:0:1-3:unix
    unix_pingi_c50_p1:unix:ping_inline:600000:50:1:1:2:0:1-3:unix
    unix_get_c50_p4_d1:unix:get:1000000:50:4:1:2:0:1-3:unix
    unix_get_c10_p1_d1:unix:get:500000:10:1:1:2:0:1-3:unix
    unix_get_c50_p1_d1_t0:unix:get:500000:50:1:1:0:0:1-3:unix
    unix_get_c1_p1_d1:unix:get:100000:1:1:1:0:0:1-3:unix
)
# Debug kernel: dbg plus the unix-socket GET/SET at half the requests, and the -c 1 fan-out pair.
dbgx=("${dbg[@]}"
    unix_set_c50_p1_d1:unix:set:500000:50:1:1:2:0:1-3:unix
    unix_get_c50_p1_d1:unix:get:500000:50:1:1:2:0:1-3:unix
    unix_get_c50_p4_d1:unix:get:500000:50:4:1:2:0:1-3:unix
    pub0_c1:base:pub0r:20000:1:1:1:0:0:1-3:tcp
    pub16l_c1:base:pub16l:10000:1:1:1:0:0:1-3:tcp)
# The unix-socket cells closest to zero under KPTI, for more boots (run with REPS 4).
unixwin=(
    unix_get_c50_p1_d1:unix:get:1000000:50:1:1:2:0:1-3:unix
    unix_get_c50_p1_d1024:unix:get:1000000:50:1:1024:2:0:1-3:unix
    unix_pingi_c50_p1:unix:ping_inline:1000000:50:1:1:2:0:1-3:unix
    unix_pingm_c50_p1:unix:ping_mbulk:1000000:50:1:1:2:0:1-3:unix
    unix_incr_c50_p1:unix:incr:1000000:50:1:1:2:0:1-3:unix
    unix_get_c50_p1_d1_t0:unix:get:500000:50:1:1:0:0:1-3:unix
)
case "$set_name" in
    unixwin) cells=("${unixwin[@]}") ;;
    uf) cells=("${unixx[@]}" "${fan[@]}") ;;
    dbgx) cells=("${dbgx[@]}") ;;
    unixx) cells=("${unixx[@]}") ;;
    dbg) cells=("${dbg[@]}") ;;
    fan) cells=("${fan[@]}") ;;
    dens) cells=("${ref_set[@]}" "${density[@]}" "${persist[@]}" "${unixs[@]}") ;;
    cmds) cells=("${ref_set[@]}" "${density[@]}") ;;
    key) cells=("${ref_set[@]}" set_c50_p16_d1:base:set:2000000:50:16:1:2:0:1-3:tcp get_c50_p16_d1:base:get:2000000:50:16:1:2:0:1-3:tcp) ;;
    custom) read -r -a cells <<< "${CONDSW_CELLS:?set CONDSW_CELLS}" ;;
    *) echo "unknown SET $set_name" >&2; exit 2 ;;
esac

# Blocks: consecutive cells of the same SRV.
rotate_cells() { # BOOT -> echoes the cells in this boot's order
    local b=$1 i n srv cur="" blocks=() block=() order=() k off
    n=${#cells[@]}
    for ((i = 0; i < n; i++)); do
        srv=$(cut -d: -f2 <<< "${cells[$i]}")
        if [[ "$srv" != "$cur" ]]; then
            [[ -z "$cur" ]] || blocks+=("${block[*]}")
            block=()
            cur=$srv
        fi
        block+=("${cells[$i]}")
    done
    blocks+=("${block[*]}")
    local nb=${#blocks[@]}
    for ((k = 0; k < nb; k++)); do
        local bi=$(( (k + b - 1) % nb ))
        read -r -a block <<< "${blocks[$bi]}"
        off=$(( ((b - 1) * 5) % ${#block[@]} ))
        for ((i = 0; i < ${#block[@]}; i++)); do
            order+=("${block[$(( (i + off) % ${#block[@]} ))]}")
        done
    done
    echo "${order[*]}"
}

for ((b = first; b < first + boots; b++)); do
    label="cond-$tag-$sname-b$b"
    run_dir="$build_root/runs/ub-$label"
    mkdir -p "$run_dir"
    cp "$here/../cond-sweep.sh" "$here/../cond-info.sh" "$run_dir/"
    order=$(rotate_cells "$b")
    echo "cond-sweep: boot $label ($(date '+%H:%M:%S')) profile=$sprofile args='$sargs' set=$set_name"
    GUEST_PROFILE="$sprofile" UB_APPEND_EXTRA="rodata=off $sargs" "$here/ub-run.sh" "$label" 0 "sh /kjit/cond-info.sh 5; sh /kjit/cond-sweep.sh /tmp/cond $reps $order"
done
echo "cond-sweep: done"
