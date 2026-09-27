#!/usr/bin/env bash
set -euo pipefail

# K4: redis under KJIT, one non-interactive campaign (host; QEMU/HVF guests
# through scripts/guest-run.sh, which fails a run on a kernel BUG/WARNING/
# KASAN/lockdep/oops/RCU-stall line). Steps, each in its own guest boot:
#
#   suite-off  redis's test suite (tests/guest/k4-suite.sh) without kjit.ko
#   suite-on   the same with kjit.ko, enable=1 auto=1 for the whole run
#              -> the per-test results must be identical to suite-off
#   campaign   tests/guest/k4-campaign.sh: per iteration the K2 micro tests in
#              auto mode (incl. munmap_race), k4-bench.sh (redis-benchmark
#              default/pipelined/256 clients + a KJIT off/on dataset digest
#              check) and k4-adversarial.sh (kill -9, signals, DEBUG
#              SEGFAULT, BGSAVE/AOF rewrite forks, CONFIG SET + MODULE
#              LOAD/UNLOAD, kjit.ko reload under load, maxmemory eviction),
#              plus its dmesg checked like the serial log
#
# Prints a PASS/FAIL line per step and "k4-campaign: RESULT PASS|FAIL"; exits
# non-zero on any failure. Everything lands in
# $KJIT_BUILD_ROOT/runs/k4-<profile>-<time>/ (one guest run dir per step).

# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/kjit-env.sh"

profile=kjit-guest
iterations=1
requests=100000
run_suite=1
suite_args="--clients 16 --dump-logs"
require_hot=1

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --profile <name>       kjit-guest (default) or kjit-guest-debug
  --iterations <n>       benchmark+adversarial iterations (default $iterations)
  --requests <n>         requests per redis-benchmark test (default $requests)
  --no-suite             skip the two redis test-suite runs
  --suite-args '<args>'  runtest options (default: $suite_args)
  --no-require-hot       only report, do not require, fragment entries under load
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile) profile="$2"; shift 2 ;;
        --iterations) iterations="$2"; shift 2 ;;
        --requests) requests="$2"; shift 2 ;;
        --no-suite) run_suite=0; shift ;;
        --suite-args) suite_args="$2"; shift 2 ;;
        --no-require-hot) require_hot=0; shift ;;
        --help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

out="$KJIT_BUILD_ROOT/runs/k4-$profile-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$out"
summary=()
failed=0

# Same kernel-report pattern as guest-run.sh, for the guest's dmesg dump.
splat_re='^\[ *[0-9]+\.[0-9]+\] .*(BUG:|WARNING:|Oops|Kernel panic|Call trace:|INFO: (possible|inconsistent|trying|task)|detected stall)'

# guest NAME TIMEOUT MODULE CMD: one guest boot; MODULE is "kjit" or "none".
guest() {
    local name=$1 timeout=$2 module=$3 cmd=$4 args=()
    [[ "$module" == kjit ]] || args=(--module none)
    echo "k4-campaign: $name: guest-run (log $out/$name.log)"
    bash "$ROOT_DIR/scripts/guest-run.sh" --profile "$profile" --run-dir "$out/$name" \
        --timeout "$timeout" ${args[@]+"${args[@]}"} -- "$cmd" > "$out/$name.log" 2>&1
}

result() {
    summary+=("$(printf '%-11s %s' "$1" "$2")")
    [[ "$2" == PASS* ]] || failed=1
}

# counts FILE: "ok=N err=N skip=N ignore=N" of a k4-suite results file.
counts() {
    awk '{ n[$1]++ } END { printf "ok=%d err=%d skip=%d ignore=%d", n["ok"], n["err"], n["skip"], n["ignore"] }' "$1"
}

# kjit_deltas DIR: in-kernel fraction, entries and the top stopping words
# between DIR/stats.before and DIR/stats.after (k4-suite.sh snapshots).
kjit_deltas() {
    awk 'FILENAME == ARGV[1] { a[$1] = $2; next } { d[$1] = $2 - a[$1] }
         END { printf "in_kernel=%d/%d syscalls (%.1f%%) entries=%d translated=%d exit_unsupported=%d exit_mem=%d exit_invalid=%d verify_rejected=%d",
                   d["syscalls_in_kernel"], d["hook_calls"],
                   d["hook_calls"] ? 100 * d["syscalls_in_kernel"] / d["hook_calls"] : 0,
                   d["fragment_entries"], d["translate_ok"], d["exit_unsupported"], d["exit_mem"],
                   d["exit_invalid"], d["translate_verify_rejected"] }' "$1/stats.before" "$1/stats.after"
    printf '; unsupported_top: %s' "$(awk 'FILENAME == ARGV[1] { e[$1] = $2; s[$1] = $3; next }
        { de = $2 - e[$1]; ds = $3 - s[$1]; if (de + ds > 0) printf "%d %s(%d/%d)\n", de + ds, $1, de, ds }' \
        "$1/unsupported_top.before" "$1/unsupported_top.after" | sort -rn | head -6 | cut -d' ' -f2 | tr '\n' ' ')"
}

if (( run_suite )); then
    suite_cmd="sh /opt/kjit-tests/k4-suite.sh /kjit/suite $suite_args"
    for mode in off on; do
        module=none
        [[ "$mode" == on ]] && module=kjit
        if guest "suite-$mode" 14400 "$module" "$suite_cmd"; then
            result "suite-$mode" "PASS $(counts "$out/suite-$mode/suite/results")$(
                [[ "$mode" == on ]] && printf '; %s' "$(kjit_deltas "$out/suite-$mode/suite")")"
        else
            result "suite-$mode" "FAIL: $(grep -E '^(k4-suite|guest-run|  )' "$out/suite-$mode.log" | tail -5 | tr '\n' ' ')"
        fi
    done
    # Compared: the distinct outcomes with digits masked (results.norm, see
    # k4-suite.sh: time-bounded tests repeat a varying number of times under
    # varying names), and the failed tests exactly (grep finds no "err" line
    # when nothing failed, which is not an error).
    off="$out/suite-off/suite" on="$out/suite-on/suite"
    if [[ -f "$off/results.norm" && -f "$on/results.norm" ]]; then
        if cmp -s "$off/results.norm" "$on/results.norm" \
                && cmp -s <(grep '^err ' "$off/results" || true) <(grep '^err ' "$on/results" || true); then
            result "suite-same" "PASS: same outcome for every test with and without KJIT ($(wc -l < "$on/results.norm") distinct outcomes, $(wc -l < "$on/results") vs $(wc -l < "$off/results") raw)"
        else
            # diff exits 1 for "differs", which is what this branch reports.
            { diff "$off/results.norm" "$on/results.norm"; diff <(grep '^err ' "$off/results") <(grep '^err ' "$on/results"); } \
                > "$out/suite.diff" || true
            result "suite-same" "FAIL: results differ ($out/suite.diff): $(grep '^[<>]' "$out/suite.diff" | head -5 | tr '\n' ' ')"
        fi
    else
        result "suite-same" "FAIL: a suite run left no results"
    fi
fi

camp_timeout=$(( 1800 + iterations * 3600 ))
if guest campaign "$camp_timeout" kjit \
        "K4_REQUIRE_HOT=$require_hot sh /opt/kjit-tests/k4-campaign.sh /kjit/campaign $iterations $requests"; then
    if grep -Eq "$splat_re" "$out/campaign/campaign/dmesg.txt"; then
        result campaign "FAIL: kernel report in the guest dmesg: $(grep -E "$splat_re" "$out/campaign/campaign/dmesg.txt" | head -3 | tr '\n' ' ')"
    else
        result campaign "PASS: $iterations iterations; $(grep -Ec '^k4-adv: [a-z0-9]+ PASS' "$out/campaign.log") adversarial tests, $(grep -c 'k4-bench: consistency PASS' "$out/campaign.log") consistency checks; dmesg clean"
    fi
else
    result campaign "FAIL: $(grep -E '^k4: FAIL|^k2: FAIL|^guest-run|^  ' "$out/campaign.log" | head -6 | tr '\n' ' ')"
fi

# Benchmark numbers of the last iteration (absent if the campaign failed
# before it).
bench_log="$out/campaign/campaign/iter-$iterations/bench.log"
[[ -f "$bench_log" ]] || bench_log=""

echo
echo "k4-campaign: profile=$profile out=$out"
printf 'k4-campaign: %s\n' "${summary[@]}"
if [[ -n "$bench_log" ]]; then
    echo "k4-campaign: benchmark (last iteration, $bench_log):"
    grep -E '^k4-bench: |^k4:   [a-z0-9]+: (in_kernel|exits|unsupported_top)' "$bench_log" | sed 's/^/k4-campaign:   /'
fi
if (( failed )); then
    echo "k4-campaign: RESULT FAIL"
    exit 1
fi
echo "k4-campaign: RESULT PASS"
