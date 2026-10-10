#!/bin/bash
# usage: meas.sh OUTDIR START_INDEX VARIANT...
# One measurement boot per VARIANT, in the order given. Before each boot: wait until no
# qemu-system-aarch64 process is running (none of them is ours: boots are sequential)
# and the 1-minute load average is <= 6, polling every 20 s; the waits and loads are
# recorded in OUTDIR/boot-NN-vV.wait.
S=/private/tmp/claude-501/-Volumes-CaseSentitiveLocal-KJIT/b06f19aa-bc63-41a1-912e-50230c2c0e32/scratchpad
out=$1; idx=$2; shift 2
mkdir -p "$out"
cmdfile=$S/meas.cmd
for v in "$@"; do
    n=$(printf '%02d' $idx)
    name=boot-$n-v$v
    start=$(date +%s)
    waits=0
    while :; do
        q=$(pgrep -x qemu-system-aarch64 | wc -l | tr -d ' ')
        load=$(sysctl -n vm.loadavg | awk '{print $2}')
        if [ "$q" = 0 ] && awk -v l="$load" 'BEGIN{exit !(l <= 6)}'; then break; fi
        waits=$((waits + 1))
        sleep 20
    done
    now=$(date +%s)
    echo "boot=$n variant=$v waited_s=$((now - start)) polls=$waits load1_at_start=$load qemu_others=$q date=$(date +%Y%m%dT%H%M%S)" | tee "$out/$name.wait"
    run_dir=$out/$name.run
    $S/grun.sh $v 1800 "@$cmdfile" meas > "$out/$name.log" 2>&1
    rc=$?
    # grun.sh puts the run under the build root; copy what matters.
    rd=$(grep -o 'run_dir=.*' "$out/$name.log" | tail -1 | cut -d= -f2)
    cp "$rd/serial.log" "$out/$name.serial.log" 2>/dev/null
    echo "boot=$n variant=$v rc=$rc load1_at_end=$(sysctl -n vm.loadavg | awk '{print $2}') duration_s=$(( $(date +%s) - now ))" | tee -a "$out/$name.wait"
    rm -rf "$rd"
    idx=$((idx + 1))
done
