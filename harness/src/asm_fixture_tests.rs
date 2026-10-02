//! Differential check of every case in every `tests/arm64/*.s` fixture.
//!
//! A case is a defined symbol ending in `_mark`: its address is the hot SVC PC
//! and translation starts at the next instruction. Assembling and symbol
//! resolution stay in `scripts/compile-asm-fixture.sh`; the interpreter check is
//! the same `run_entry_fixture` call `trace-tui --check` makes, from the same
//! initial state. On Linux arm64 the same cases also run on the host CPU.
//!
//! Each interpreter case also runs the fault self-check (`check_fault_injection`)
//! and the fragment fault differential (`check_fragment_fault_injection`).
//! `run_entry_fixture` runs the verifier (V3) on every fragment before executing it.

use std::collections::BTreeMap;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use crate::arm64::LoggedAccess;
use crate::asm_fixture::{compile_case, list_cases, panic_message, CompiledCase};
use crate::cached_run::{compare_cached, new_interpreter_cache, run_cached_differential, CachedRun};
use crate::model::{AccessKind, HaltReason, MachineState, Privilege};
use crate::runtime::{URuntime, URuntimeHalt};
use crate::shared::abi::RetStatus;
use crate::{
    compile_fixture_fragment, fixture_state, fragment_instance_cap, run_entry_fixture,
    run_original_with_mocked_svc,
};

const LLVM_TOOLS: [&str; 3] = ["llvm-mc", "llvm-nm", "llvm-objcopy"];

struct CaseFailure {
    fixture: String,
    symbol: String,
    message: String,
}

#[test]
fn every_asm_fixture_case_matches_original() {
    run_every_case("interp", &mut |case| {
        let initial_state = fixture_state(case.text_base, &case.text_bytes)?;
        let report = run_entry_fixture(
            "asm-fixture",
            case.text_base,
            case.text_bytes.clone(),
            case.entry_pc,
            &initial_state,
        )?;
        let user_accesses = check_fault_injection(
            case.text_base,
            &case.text_bytes,
            case.entry_pc,
            &initial_state,
        )
        .map_err(|message| format!("fault self-check: {message}"))?;
        let fragment_faults = check_fragment_fault_injection(
            case.text_base,
            &case.text_bytes,
            case.entry_pc,
            &initial_state,
        )
        .map_err(|message| format!("fragment fault differential: {message}"))?;
        let cached = check_cached_case(&case.text_base, &case.text_bytes, case.entry_pc, &initial_state)
            .map_err(|message| format!("cached run: {message}"))?;
        Ok(format!(
            "halt={:?} injected_user_accesses={user_accesses} \
             injected_fragment_faults={fragment_faults} {cached}",
            report.fragment_halt
        ))
    });
}

/// A11: the case runs cold (an empty code cache: every branch exit misses and is
/// resolved by the runtime, which translates and publishes) and warm (the cache the
/// cold run left: transfers hit in the dispatch tables), each equal to the original
/// following its branches. The warm run takes at most as many runtime round trips.
fn check_cached_case(
    text_base: &u64,
    text: &[u8],
    entry_pc: u64,
    initial_state: &MachineState,
) -> Result<String, String> {
    let cache = new_interpreter_cache(*text_base, text);
    let (cold, cache) = run_cached_differential(cache, *text_base, text, entry_pc, initial_state)
        .map_err(|err| format!("cold: {err}"))?;
    compare_cached("cold", &cold).map_err(|mismatch| mismatch.message)?;
    let (warm, cache) = run_cached_differential(cache, *text_base, text, entry_pc, initial_state)
        .map_err(|err| format!("warm: {err}"))?;
    compare_cached("warm", &warm).map_err(|mismatch| mismatch.message)?;
    if warm.runtime_entries > cold.runtime_entries {
        return Err(format!(
            "the warm run took {} runtime entries, more than the cold run's {}",
            warm.runtime_entries, cold.runtime_entries
        ));
    }
    let stats = cache.stats;
    let summary = |run: &CachedRun| format!("{:?}/{} entries", run.report.halt, run.runtime_entries);
    Ok(format!(
        "cold=[{}] warm=[{}] fragments={} ibtc_insert={} ibtc_replace={}",
        summary(&cold),
        summary(&warm),
        cache.fragments.len(),
        stats.ibtc_insert,
        stats.ibtc_replace
    ))
}

/// Three-way check on the host CPU: interpreter original == native original ==
/// native fragment. Linux arm64 only (see `crate::native`); run it through
/// `make harness-test-native`.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[test]
fn every_asm_fixture_case_matches_native() {
    let session = crate::native::NativeSession::new().expect("set up native runner");
    run_every_case("native", &mut |case| {
        let initial_state = fixture_state(case.text_base, &case.text_bytes)?;
        let single = crate::native::check_case(
            &session,
            case.text_base,
            &case.text_bytes,
            case.entry_pc,
            &initial_state,
        )?;
        let cached = crate::native::check_cached_case(
            &session,
            case.text_base,
            &case.text_bytes,
            case.entry_pc,
            &initial_state,
        )
        .map_err(|message| format!("cached run: {message}"))?;
        Ok(format!("{single} | cached {cached}"))
    });
}

/// Runs `check` on every `_mark` case of every `tests/arm64/*.s` fixture and
/// fails listing every failed case. `check` returns a detail line on success.
pub(crate) fn run_every_case(
    suite: &str,
    check: &mut dyn FnMut(&CompiledCase) -> Result<String, String>,
) {
    require_llvm_tools();

    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("harness manifest dir has a parent")
        .to_path_buf();
    let fixtures = fixture_paths(&root.join("tests/arm64"));
    // Per-suite, per-process directory so concurrent test runs never share outputs.
    let work_dir = root
        .join("tmp")
        .join(format!("asm-fixture-suite.{suite}.{}", std::process::id()));
    if work_dir.exists() {
        std::fs::remove_dir_all(&work_dir).expect("remove stale fixture work dir");
    }

    let mut cases = 0usize;
    let mut failures = Vec::new();
    for fixture in &fixtures {
        let name = fixture
            .file_name()
            .expect("fixture path has a file name")
            .to_string_lossy()
            .into_owned();
        let fixture_dir = work_dir.join(&name);

        let symbols = match list_cases(&root, fixture, &fixture_dir.join("_list")) {
            Ok(symbols) => symbols,
            Err(message) => {
                failures.push(CaseFailure {
                    fixture: name,
                    symbol: "<case discovery>".to_string(),
                    message,
                });
                continue;
            }
        };

        for symbol in symbols {
            cases += 1;
            match run_case(&root, fixture, &symbol, &fixture_dir.join(&symbol), check) {
                Ok((entry_pc, detail)) => println!(
                    "{suite} asm fixture pass: {name} {symbol} entry={entry_pc:#x} {detail}"
                ),
                Err(message) => {
                    println!("{suite} asm fixture FAIL: {name} {symbol}\n{message}");
                    failures.push(CaseFailure {
                        fixture: name.clone(),
                        symbol,
                        message,
                    });
                }
            }
        }
    }

    println!(
        "{suite} asm fixture suite: {cases} cases across {} fixtures, {} failed",
        fixtures.len(),
        failures.len()
    );
    if failures.is_empty() {
        std::fs::remove_dir_all(&work_dir).expect("remove fixture work dir");
        return;
    }
    let list = failures
        .iter()
        .map(|f| format!("  {} {}: {}", f.fixture, f.symbol, first_line(&f.message)))
        .collect::<Vec<_>>()
        .join("\n");
    panic!(
        "{} {suite} asm fixture case(s) failed (outputs kept in {}):\n{list}",
        failures.len(),
        work_dir.display()
    );
}

fn require_llvm_tools() {
    let path = std::env::var_os("PATH").expect("PATH is not set; LLVM tools must be on PATH");
    for tool in LLVM_TOOLS {
        if !std::env::split_paths(&path).any(|dir| dir.join(tool).is_file()) {
            panic!(
                "`{tool}` not found on PATH. The asm fixture suite requires llvm-mc, llvm-nm and \
                 llvm-objcopy on PATH (e.g. Homebrew llvm: export PATH=\"$(brew --prefix llvm)/bin:$PATH\")"
            );
        }
    }
}

fn fixture_paths(dir: &Path) -> Vec<PathBuf> {
    let mut fixtures = std::fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("failed to read fixture dir {}: {err}", dir.display()))
        .map(|entry| entry.expect("read fixture dir entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "s"))
        .collect::<Vec<_>>();
    fixtures.sort();
    assert!(!fixtures.is_empty(), "no .s fixtures under {}", dir.display());
    fixtures
}

/// Returns the entry PC and `check`'s detail line on success.
fn run_case(
    root: &Path,
    fixture: &Path,
    symbol: &str,
    out_dir: &Path,
    check: &mut dyn FnMut(&CompiledCase) -> Result<String, String>,
) -> Result<(u64, String), String> {
    let case = compile_case(root, fixture, symbol, out_dir)?;

    match panic::catch_unwind(AssertUnwindSafe(|| check(&case))) {
        Ok(Ok(detail)) => Ok((case.entry_pc, detail)),
        Ok(Err(message)) => Err(message),
        // A translator panic is a case failure; record it so the remaining cases still run.
        Err(payload) => Err(format!("panicked: {}", panic_message(payload.as_ref()))),
    }
}

/// Interpreter self-check for precise faults. Runs the original code once
/// uninjected, recording the state before every step and how many user
/// accesses preceded it; then, for every dynamic user access k, reruns with k
/// injected and requires a fault at the instruction owning access k with the
/// state from just before that instruction. Returns the number of user accesses.
fn check_fault_injection(
    text_base: u64,
    text_bytes: &[u8],
    entry_pc: u64,
    initial_state: &MachineState,
) -> Result<u64, String> {
    struct PreStep {
        pc: u64,
        state: MachineState,
        accesses_before: u64,
    }

    let cap = fragment_instance_cap(text_base, text_bytes, entry_pc, initial_state)?;
    let mut pre_steps = Vec::new();
    let clean = run_original_with_mocked_svc(
        text_bytes,
        text_base,
        entry_pc,
        initial_state,
        None,
        cap,
        None,
        &mut |stepper| {
            pre_steps.push(PreStep {
                pc: stepper.pc(),
                state: stepper.state().clone(),
                accesses_before: stepper.user_accesses(),
            })
        },
    )?;
    // The halting step is a runtime exit, the end of the text, an undecodable
    // word or an instance-capped instruction (none of which accesses memory in
    // the run), or an instruction that faults on its own. `total` counts the
    // accesses before it.
    let halting = pre_steps.last().ok_or("uninjected run took no steps")?;
    let total = halting.accesses_before;

    let past_end = run_original_with_mocked_svc(
        text_bytes,
        text_base,
        entry_pc,
        initial_state,
        Some(total + 1),
        cap,
        None,
        &mut |_| {},
    )?;
    match clean.halt_reason {
        // Injecting the faulting instruction's first access must fault it at the
        // same pc with the same state (the natural fault may be a later access).
        HaltReason::Fault(_) => match past_end.halt_reason {
            HaltReason::Fault(fault)
                if fault.pc == halting.pc && past_end.state == clean.state => {}
            other => {
                return Err(format!(
                    "injecting access {} of the naturally faulting instruction at pc={:#x} \
                     gave {other}",
                    total + 1,
                    halting.pc
                ))
            }
        },
        // Injecting one past the total must not change a run that never faults.
        _ if past_end != clean => {
            return Err(format!(
                "injecting access {} (past the {total} counted) changed the run",
                total + 1
            ));
        }
        _ => {}
    }

    for k in 1..=total {
        // The owner is the last step that started with fewer than k accesses.
        let owner = pre_steps
            .iter()
            .rev()
            .find(|step| step.accesses_before < k)
            .expect("the first step starts with zero accesses");
        let injected = run_original_with_mocked_svc(
            text_bytes,
            text_base,
            entry_pc,
            initial_state,
            Some(k),
            cap,
            None,
            &mut |_| {},
        )?;
        match injected.halt_reason {
            HaltReason::Fault(fault) if fault.pc == owner.pc => {}
            other => {
                return Err(format!(
                    "access {k}: expected a fault at pc={:#x}, got {other}",
                    owner.pc
                ))
            }
        }
        if injected.state != owner.state {
            return Err(format!(
                "access {k}: faulting instruction at pc={:#x} changed state\n\
                 before: {:#?}\nafter: {:#?}",
                owner.pc, owner.state, injected.state
            ));
        }
    }
    Ok(total)
}

/// The A5 acceptance check (tmp/pipeline.md, "Fault sites (A5)").
///
/// Uninjected, the fragment's accesses must be sandboxed: no runtime access
/// touches user memory, and every user access is an `LDTR`/`STTR` with a
/// fault-site entry. Its user accesses are matched to the original's by
/// (original PC, dynamic instance, sub-access), never by position. Then, for
/// every original user access k, the fragment runs with a fault injected on the
/// matching fragment access and must exit with `Mem` at the original faulting
/// instruction, with the user state the original had just before it, except
/// that each unit of that instruction's store footprint may be old or new.
/// Returns the number of injected fragment faults (== original accesses).
fn check_fragment_fault_injection(
    text_base: u64,
    text_bytes: &[u8],
    entry_pc: u64,
    initial_state: &MachineState,
) -> Result<u64, String> {
    // Original clean run: pre-instruction states and the access log.
    struct PreStep {
        pc: u64,
        state: MachineState,
        accesses_before: u64,
    }
    let cap = fragment_instance_cap(text_base, text_bytes, entry_pc, initial_state)?;
    let mut pre_steps = Vec::new();
    let mut original_log: Vec<LoggedAccess> = Vec::new();
    let clean = run_original_with_mocked_svc(
        text_bytes,
        text_base,
        entry_pc,
        initial_state,
        None,
        cap,
        None,
        &mut |stepper| {
            let log = stepper.access_log().expect("original runs record accesses");
            original_log.extend_from_slice(&log[original_log.len()..]);
            pre_steps.push(PreStep {
                pc: stepper.pc(),
                state: stepper.state().clone(),
                accesses_before: stepper.user_accesses(),
            });
        },
    )?;
    // A natural fault ends the run at its instruction; its accesses are not counted.
    let natural_fault_pc = match clean.halt_reason {
        HaltReason::Fault(fault) => Some(fault.pc),
        _ => None,
    };
    let total = pre_steps
        .last()
        .ok_or("original run took no steps")?
        .accesses_before;
    if original_log.len() as u64 != total {
        return Err(format!(
            "original log has {} accesses, counter says {total}",
            original_log.len()
        ));
    }

    // Key of original access k: (pc, dynamic instance of that pc, sub-access).
    let mut original_keys = Vec::with_capacity(total as usize);
    let mut owners = Vec::with_capacity(total as usize);
    for k in 1..=total {
        let owner = pre_steps
            .iter()
            .rposition(|step| step.accesses_before < k)
            .expect("the first step starts with zero accesses");
        let pc = pre_steps[owner].pc;
        let instance = pre_steps[..owner]
            .iter()
            .filter(|step| step.pc == pc)
            .count();
        let sub = (k - pre_steps[owner].accesses_before - 1) as usize;
        original_keys.push((pc, instance, sub));
        owners.push(owner);
    }

    // Fragment clean run.
    let fragment =
        compile_fixture_fragment(text_base, text_bytes.to_vec(), entry_pc, initial_state)?;
    let mut runtime = URuntime::new(fragment, initial_state.clone()).record_accesses();
    let report = runtime.run();
    if let URuntimeHalt::ExecutionError { pc, message } = &report.halt {
        return Err(format!(
            "uninjected fragment run failed at {pc:#x}: {message}"
        ));
    }
    let base_pc = runtime.config.base_pc;
    let fragment_log = runtime
        .access_log()
        .expect("recording was enabled")
        .to_vec();

    let mut fragment_keys = BTreeMap::new();
    let mut site_executions: BTreeMap<usize, usize> = BTreeMap::new();
    let mut user_index = 0u64;
    // A9a: one window SIMD&FP instruction makes several accesses (LD1/ST1: one per
    // element). They are consecutive log entries at one offset; an instruction
    // executes again only after other logged work (a budget check's runtime
    // accesses, a re-entry's prologue), so a repeated offset right after itself
    // continues the same execution.
    let mut previous_offset = None;
    let mut within = 0usize;
    for logged in &fragment_log {
        let offset = (logged.pc - base_pc) as usize;
        let continues = previous_offset == Some(offset);
        previous_offset = Some(offset);
        match logged.privilege {
            Privilege::Runtime => {
                let last = logged.access.addr + logged.access.size as u64 - 1;
                if [logged.access.addr, last]
                    .iter()
                    .any(|addr| initial_state.user_page_perm(*addr).is_some())
                {
                    return Err(format!(
                        "runtime access at fragment offset {offset:#x} touched user memory: {:?}",
                        logged.access
                    ));
                }
            }
            privilege @ (Privilege::User | Privilege::Window) => {
                user_index += 1;
                let insn = runtime.fragment().insns[offset / 4];
                let tagged = match privilege {
                    Privilege::User => insn.is_unprivileged_access(),
                    _ => insn.is_pan_window_access(),
                };
                if !tagged {
                    return Err(format!(
                        "{privilege:?} access at {offset:#x} is neither LDTR/STTR nor a \
                         window access"
                    ));
                }
                let site = runtime
                    .fragment()
                    .fault_site(offset)
                    .ok_or_else(|| format!("user access at {offset:#x} has no fault site"))?;
                let rank = runtime
                    .fragment()
                    .fault_sites
                    .iter()
                    .filter(|other| other.ori_pc == site.ori_pc)
                    .position(|other| other.access_offset == offset)
                    .expect("the site is among its own pc's sites");
                let executions = site_executions.entry(offset).or_default();
                if continues {
                    within += 1;
                } else {
                    within = 0;
                    *executions += 1;
                }
                fragment_keys.insert(
                    (site.ori_pc, *executions - 1, rank + within),
                    (user_index, *logged),
                );
            }
        }
    }
    // Beyond the original's count, only the naturally faulting instruction's
    // own accesses may appear (the last of them faulted into its stub).
    let extras_ok = fragment_log
        .iter()
        .filter(|logged| logged.privilege != Privilege::Runtime)
        .skip(total as usize)
        .all(|logged| {
            let offset = (logged.pc - base_pc) as usize;
            runtime.fragment().fault_site(offset).map(|site| site.ori_pc) == natural_fault_pc
        });
    if user_index < total || !extras_ok {
        return Err(format!(
            "fragment made {user_index} user accesses, original made {total} \
             (natural fault at {natural_fault_pc:x?})"
        ));
    }

    for k in 1..=total {
        let key = original_keys[k as usize - 1];
        let &(f, logged) = fragment_keys
            .get(&key)
            .ok_or_else(|| format!("original access {k} {key:x?} has no fragment access"))?;
        let original_access = original_log[k as usize - 1];
        if logged.access != original_access.access {
            return Err(format!(
                "access {k}: fragment {:?} != original {:?}",
                logged.access, original_access.access
            ));
        }

        let owner = &pre_steps[owners[k as usize - 1]];
        let fragment =
            compile_fixture_fragment(text_base, text_bytes.to_vec(), entry_pc, initial_state)?;
        let mut injected = URuntime::new(fragment, initial_state.clone()).fail_user_access(f);
        let report = injected.run();
        let expected_halt = URuntimeHalt::ReturnedToUserspace {
            status: RetStatus::Mem,
            target_pc: owner.pc,
        };
        if report.halt != expected_halt {
            return Err(format!(
                "access {k} (fragment access {f}): expected {expected_halt:?}, got {:?}",
                report.halt
            ));
        }
        if injected.user_accesses() != f {
            return Err(format!(
                "access {k}: the fragment continued past the injected access {f}"
            ));
        }

        // Store footprint: every store unit of the faulting instruction may hold
        // its old or its new value; normalize new units back to old, then the
        // state must be exactly the pre-instruction state.
        let post = &pre_steps
            .get(owners[k as usize - 1] + 1)
            .ok_or("faulting instruction is the halting step")?
            .state;
        let mut state = report.state.clone();
        let first = owner.accesses_before as usize;
        // Byte by byte: a SIMD&FP store unit may be 16 or 32 bytes (A9a).
        for unit in original_log[first..]
            .iter()
            .take_while(|logged| logged.pc == owner.pc)
            .filter(|logged| logged.access.kind == AccessKind::Write)
        {
            for addr in unit.access.addr..unit.access.addr + u64::from(unit.access.size) {
                let (got, old) = (state.read_le(addr, 1), owner.state.read_le(addr, 1));
                if got != old && got == post.read_le(addr, 1) {
                    state.write_le(addr, 1, old);
                }
            }
        }
        if state != owner.state {
            return Err(format!(
                "access {k}: user state after the Mem exit at pc={:#x} differs from the \
                 state before the instruction\nexpected: {:#?}\ngot: {:#?}",
                owner.pc, owner.state, report.state
            ));
        }
    }
    Ok(total)
}

fn first_line(message: &str) -> &str {
    message.lines().next().unwrap_or("")
}
