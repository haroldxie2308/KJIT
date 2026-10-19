#!/usr/bin/env bash
# summary.txt: kernel-report scan and runtime-refusal counters of every serial log in serial/ (run from gates/)
for f in serial/*.serial.log; do
  echo "== $f ($(wc -l < "$f") lines)"
  echo "kernel reports: $(grep -E 'BUG:|WARNING:|WARN_ON|Oops|Call trace|lockdep|possible (circular|recursive|irq)|inconsistent lock|INFO: rcu|rcu.*stall|soft lockup|hung task|KASAN|Kernel panic|cut here|suspicious RCU' "$f" | grep -vc 'RCU lockdep checking is enabled')"
  echo "RCU lockdep banner lines: $(grep -c 'RCU lockdep checking is enabled' "$f")"
  echo "translate_verify_rejected values: $(grep -E 'translate_verify_rejected [0-9]' "$f" | awk '{print $NF}' | sort -u | tr '\n' ' ')  verify_falls_off_end: $(grep -E 'translate_verify_falls_off_end [0-9]' "$f" | awk '{print $NF}' | sort -u | tr '\n' ' ')  exit_invalid: $(grep -E ' exit_invalid [0-9]' "$f" | awk '{print $NF}' | sort -u | tr '\n' ' ')  verify= values: $(grep -o 'verify=[0-9]*' "$f" | sort -u | tr '\n' ' ')"
  echo "pass lines: $(grep -E 'ALL PASS|RESULT PASS|campaign +PASS' "$f" | sort -u | tr '\n' ';')"
done
