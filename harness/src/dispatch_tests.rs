//! A11 dispatch behaviours the cold/warm fixture suite does not assert on its own
//! (tmp/pipeline.md, "A11 contract", "Harness (A11a)"): which transfers hit, which
//! always miss, what the tables hold. Each test runs one `tests/arm64/dispatch_*.s`
//! case through `run_cached_differential` (so every run is also compared with the
//! original following its branches).

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::asm_fixture::{compile_case, CompiledCase};
use crate::cached_run::{compare_cached, new_interpreter_cache, run_cached_differential, CachedRun};
use crate::code_cache::{CacheStats, CodeCache};
use crate::model::{HaltReason, MachineState};
use crate::runtime::URuntimeHalt;
use crate::shared::abi::RetStatus;
use crate::shared::trans::cfg::{admit_at, RuntimeExitReason};
use crate::{fixture_state, MockCodeProvider};

fn case(fixture: &str, symbol: &str) -> (CompiledCase, MachineState) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("harness manifest dir has a parent");
    // Unique per call: the tests of one binary run in parallel on the same cases.
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let out_dir = root.join("tmp").join(format!(
        "dispatch-tests.{}.{}.{fixture}.{symbol}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let compiled = compile_case(
        root,
        &root.join("tests/arm64").join(format!("{fixture}.s")),
        symbol,
        &out_dir,
    )
    .unwrap_or_else(|err| panic!("compile {fixture} {symbol}: {err}"));
    std::fs::remove_dir_all(&out_dir).expect("remove dispatch test work dir");
    let state = fixture_state(compiled.text_base, &compiled.text_bytes).expect("fixture state");
    (compiled, state)
}

/// One cached run, compared with the original; the cache is handed back.
fn run(
    cache: CodeCache,
    case: &CompiledCase,
    state: &MachineState,
    phase: &str,
) -> (CachedRun, CodeCache) {
    let (run, cache) =
        run_cached_differential(cache, case.text_base, &case.text_bytes, case.entry_pc, state)
            .unwrap_or_else(|err| panic!("{phase}: {err}"));
    compare_cached(phase, &run).unwrap_or_else(|mismatch| panic!("{}", mismatch.message));
    (run, cache)
}

/// The cold run, the warm run, and the cache's statistics after the cold one (the
/// cache itself is returned after the warm one).
fn cold_and_warm(
    fixture: &str,
    symbol: &str,
) -> (CompiledCase, CachedRun, CachedRun, CacheStats, CodeCache) {
    let (case, state) = case(fixture, symbol);
    let cache = new_interpreter_cache(case.text_base, &case.text_bytes);
    let (cold, cache) = run(cache, &case, &state, "cold");
    let cold_stats = cache.stats;
    let (warm, cache) = run(cache, &case, &state, "warm");
    (case, cold, warm, cold_stats, cache)
}

/// The BL target of the `bl` at `pc`.
fn bl_target(case: &CompiledCase, pc: u64) -> u64 {
    let provider = MockCodeProvider::new(case.text_base, case.text_bytes.as_slice());
    match admit_at(&provider, pc).unwrap().unwrap().inner.runtime_exit_reason(pc) {
        Some(RuntimeExitReason::Bl { target_pc, .. }) => target_pc,
        other => panic!("no bl at {pc:#x}: {other:?}"),
    }
}

#[test]
fn nested_calls_leave_the_runtime_once_the_cache_is_warm() {
    let (_, cold, warm, _, cache) = cold_and_warm("dispatch_calls", "nested_calls_mark");
    assert!(cold.runtime_entries > 0, "the cold run resolves every callee");
    assert_eq!(warm.runtime_entries, 0, "every transfer of the warm run hits");
    assert!(cache.stats.ibtc_insert > 0);
    assert_eq!(cache.stats.ibtc_fpsimd_boundary, 0);
    cache.check_invariants().unwrap();
}

#[test]
fn plt_stub_calls_hit_after_the_first_resolution() {
    let (_, cold, warm, _, _) = cold_and_warm("dispatch_plt", "plt_call_mark");
    assert!(cold.runtime_entries > 0);
    assert_eq!(warm.runtime_entries, 0);
}

#[test]
fn blr_x30_and_ret_x5_dispatch_through_their_registers() {
    for symbol in ["blr_x30_mark", "ret_x5_mark", "br_x30_mark"] {
        let (_, cold, warm, _, _) = cold_and_warm("dispatch_lr_forms", symbol);
        assert!(cold.runtime_entries > 0, "{symbol}");
        assert_eq!(warm.runtime_entries, 0, "{symbol}");
    }
}

/// Two callees 16 KiB apart share a table slot: every call finds the other
/// callee's record, so it misses and the runtime's resolution replaces the slot.
/// The warm run misses just the same.
#[test]
fn aliasing_targets_replace_each_others_slot_and_keep_missing() {
    let (_, cold, warm, _, cache) = cold_and_warm("dispatch_alias", "alias_blr_mark");
    // 8 iterations x 2 calls, each a replace after the first of each callee.
    assert!(cache.stats.ibtc_replace >= 14, "{:?}", cache.stats);
    assert!(cold.runtime_entries >= 14, "{}", cold.runtime_entries);
    assert!(
        warm.runtime_entries >= 14,
        "the warm run still ping-pongs: {} runtime entries",
        warm.runtime_entries
    );
    cache.check_invariants().unwrap();
}

/// A non-FP/SIMD caller never dispatches into an FP/SIMD callee: `table_nofp`
/// holds no record of it (every call goes through the runtime, counted as a
/// boundary), `table_all` does, and the callee's return hits.
#[test]
fn a_non_fpsimd_caller_reaches_an_fpsimd_callee_only_through_the_runtime() {
    let (_, cold, warm, cold_stats, cache) = cold_and_warm("dispatch_fpsimd", "fp_callee_mark");
    let fp = cache
        .fragments
        .iter()
        .position(|frag| frag.uses_fpsimd)
        .expect("the callee is an FP/SIMD fragment");
    let entry = cache.fragments[fp].entry_pc;
    assert_eq!(cache.slot_target(true, entry).map(|(frag, _)| frag), Some(fp));
    assert_eq!(cache.slot_target(false, entry), None);
    // Cold: both calls come from a non-FP/SIMD run and miss. Warm: the first call
    // misses again; the run it starts is an FP/SIMD one, so the second call, made
    // from non-FP/SIMD code that run continued into, dispatches through `table_all`
    // and hits.
    assert_eq!(cold_stats.ibtc_fpsimd_boundary, 2);
    assert_eq!(cache.stats.ibtc_fpsimd_boundary, 3);
    assert!(warm.runtime_entries >= 1, "the first call is never a hit");
    assert!(cold.runtime_entries > warm.runtime_entries);
    cache.check_invariants().unwrap();
}

/// An FP/SIMD run may continue into non-FP/SIMD code: its table is `table_all`.
#[test]
fn an_fpsimd_caller_dispatches_into_plain_callees() {
    let (_, _, warm, cold_stats, cache) = cold_and_warm("dispatch_fpsimd", "fp_caller_mark");
    assert_eq!(warm.runtime_entries, 0, "{:?}", cache.stats);
    // Only the cold run crosses the boundary: a plain callee's `ret` into the
    // FP/SIMD code after the call (a non-FP/SIMD run reaching an FP/SIMD fragment).
    assert_eq!(cache.stats.ibtc_fpsimd_boundary, cold_stats.ibtc_fpsimd_boundary);
}

/// 5000 nested calls exhaust the 4096-unit budget: the budget check of a `bl`
/// exits with `Budget` at that `bl`, with the state from before it.
#[test]
fn recursion_exhausts_the_budget_at_a_call() {
    let (case, cold, warm, _, cache) = cold_and_warm("dispatch_recursion", "recursion_budget_mark");
    for run in [&cold, &warm] {
        let URuntimeHalt::ReturnedToUserspace {
            status: RetStatus::Budget,
            target_pc,
        } = run.report.halt
        else {
            panic!("{:?}", run.report.halt);
        };
        let HaltReason::InstanceCap { pc, instance } = run.original.halt_reason else {
            panic!("{:?}", run.original.halt_reason);
        };
        assert_eq!(pc, target_pc);
        assert!(instance >= 4000, "{instance}");
        // The exit is at the recursive call: a `bl` to the function the first call
        // translated.
        assert_eq!(bl_target(&case, pc), cache.fragments[1].entry_pc);
        // Userspace resumes at the `bl` with the call counter as it was before it.
        assert!(run.report.state.read_x(1) > 4000);
    }
}

/// A callee retired between the cold and the warm run: its records are cleared, so
/// the warm run misses on it (and the runtime translates it again).
#[test]
fn a_retired_callee_misses_in_the_warm_run() {
    let (case, state) = case("dispatch_calls", "nested_calls_mark");
    let cache = new_interpreter_cache(case.text_base, &case.text_bytes);
    let (cold, mut cache) = run(cache, &case, &state, "cold");
    let func_f = bl_target(&case, case.entry_pc + 12);
    let fragment = cache.fragment_for_entry(func_f).expect("func_f has a fragment");
    assert!(cache.slot_target(false, func_f).is_some(), "func_f was published");

    let translations = cache.stats.translations;
    cache.retire(fragment);
    assert!(cache.stats.ibtc_clear >= 1);
    assert!(cache.slot_target(true, func_f).is_none());
    assert!(cache.slot_target(false, func_f).is_none());
    assert!(cache.fragment_for_entry(func_f).is_none());
    cache.check_invariants().unwrap();

    let (warm, cache) = run(cache, &case, &state, "warm");
    assert_eq!(cache.stats.translations, translations + 1, "func_f is translated again");
    assert!(warm.runtime_entries >= 1, "the call into the retired callee misses");
    assert!(warm.runtime_entries < cold.runtime_entries);
    assert!(cache.slot_target(false, func_f).is_some(), "and is published again");
    cache.check_invariants().unwrap();
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[test]
fn a_retired_callee_matches_native() {
    let session = crate::native::NativeSession::new().expect("set up native runner");
    let (case, state) = case("dispatch_calls", "nested_calls_mark");
    let func_f = bl_target(&case, case.entry_pc + 12);
    crate::native::check_cached_case_between(
        &session,
        case.text_base,
        &case.text_bytes,
        case.entry_pc,
        &state,
        &|cache| {
            let fragment = cache
                .fragment_for_entry(func_f)
                .ok_or("func_f has no fragment")?;
            cache.retire(fragment);
            Ok(())
        },
    )
    .unwrap();
}
