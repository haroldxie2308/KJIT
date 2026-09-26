//! Differential check of every case in every `tests/arm64/*.s` fixture.
//!
//! A case is a defined symbol ending in `_mark`: its address is the hot SVC PC
//! and translation starts at the next instruction. Assembling and symbol
//! resolution stay in `scripts/compile-asm-fixture.sh`; the interpreter check is
//! the same `run_entry_fixture` call `trace-tui --check` makes, from the same
//! initial state. On Linux arm64 the same cases also run on the host CPU.
//!
//! Each interpreter case also runs the fault self-check (`check_fault_injection`).

use std::collections::BTreeMap;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::model::{HaltReason, MachineState};
use crate::{default_fixture_state, run_entry_fixture, run_original_with_mocked_svc};

const LLVM_TOOLS: [&str; 3] = ["llvm-mc", "llvm-nm", "llvm-objcopy"];

struct CaseFailure {
    fixture: String,
    symbol: String,
    message: String,
}

/// One assembled fixture case, as `compile-asm-fixture.sh` resolved it.
struct CompiledCase {
    text_base: u64,
    text_bytes: Vec<u8>,
    entry_pc: u64,
}

#[test]
fn every_asm_fixture_case_matches_original() {
    run_every_case("interp", &mut |case| {
        let initial_state = default_fixture_state();
        run_entry_fixture(
            "asm-fixture",
            case.text_base,
            case.text_bytes.clone(),
            case.entry_pc,
            &initial_state,
        )?;
        let user_accesses =
            check_fault_injection(case.text_base, &case.text_bytes, case.entry_pc, &initial_state)
                .map_err(|message| format!("fault self-check: {message}"))?;
        Ok(format!("injected_user_accesses={user_accesses}"))
    });
}

/// Three-way check on the host CPU: interpreter original == native original ==
/// native fragment. Linux arm64 only (see `crate::native`); run it through
/// `make harness-test-native`.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[test]
fn every_asm_fixture_case_matches_native() {
    let session = crate::native::NativeSession::new().expect("set up native runner");
    run_every_case("native", &mut |case| {
        crate::native::check_case(
            &session,
            case.text_base,
            &case.text_bytes,
            case.entry_pc,
            &default_fixture_state(),
        )
    });
}

/// Runs `check` on every `_mark` case of every `tests/arm64/*.s` fixture and
/// fails listing every failed case. `check` returns a detail line on success.
fn run_every_case(suite: &str, check: &mut dyn FnMut(&CompiledCase) -> Result<String, String>) {
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

fn list_cases(root: &Path, fixture: &Path, out_dir: &Path) -> Result<Vec<String>, String> {
    let vars = compile_fixture(root, fixture, out_dir, None)?;
    // Non-empty: the script fails on a fixture with no `_mark` symbol, and
    // parse_key_values rejects empty values.
    let symbols = required(&vars, "COMPILED_CASE_SYMBOLS")?;
    Ok(symbols.split(':').map(str::to_string).collect())
}

/// Returns the entry PC and `check`'s detail line on success.
fn run_case(
    root: &Path,
    fixture: &Path,
    symbol: &str,
    out_dir: &Path,
    check: &mut dyn FnMut(&CompiledCase) -> Result<String, String>,
) -> Result<(u64, String), String> {
    let vars = compile_fixture(root, fixture, out_dir, Some(symbol))?;
    let bin_path = required(&vars, "COMPILED_BIN_PATH")?;
    let case = CompiledCase {
        text_base: parse_u64("COMPILED_TEXT_BASE", required(&vars, "COMPILED_TEXT_BASE")?)?,
        entry_pc: parse_u64("COMPILED_ENTRY_PC", required(&vars, "COMPILED_ENTRY_PC")?)?,
        text_bytes: std::fs::read(bin_path)
            .map_err(|err| format!("failed to read {bin_path}: {err}"))?,
    };

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

    let mut pre_steps = Vec::new();
    let clean = run_original_with_mocked_svc(
        text_bytes,
        text_base,
        entry_pc,
        initial_state,
        None,
        &mut |stepper| {
            pre_steps.push(PreStep {
                pc: stepper.pc(),
                state: stepper.state().clone(),
                accesses_before: stepper.user_accesses(),
            })
        },
    )?;
    if let HaltReason::Fault(fault) = clean.halt_reason {
        return Err(format!("uninjected run faulted: {fault}"));
    }
    // The halting step is a runtime exit, the end of the text or an
    // undecodable word; none of them accesses memory. Injecting one past the
    // total below confirms it.
    let total = pre_steps
        .last()
        .ok_or("uninjected run took no steps")?
        .accesses_before;

    let past_end = run_original_with_mocked_svc(
        text_bytes,
        text_base,
        entry_pc,
        initial_state,
        Some(total + 1),
        &mut |_| {},
    )?;
    if past_end != clean {
        return Err(format!(
            "injecting access {} (past the {total} counted) changed the run",
            total + 1
        ));
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

fn compile_fixture(
    root: &Path,
    fixture: &Path,
    out_dir: &Path,
    hot_svc_symbol: Option<&str>,
) -> Result<BTreeMap<String, String>, String> {
    let mut command = Command::new("bash");
    command.arg(root.join("scripts/compile-asm-fixture.sh"));
    match hot_svc_symbol {
        Some(symbol) => {
            command.env("HOT_SVC_SYMBOL", symbol);
        }
        None => {
            command.arg("--list-cases");
        }
    }
    command.arg(fixture).arg(out_dir);

    let output = command
        .output()
        .map_err(|err| format!("failed to spawn compile-asm-fixture.sh: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "compile-asm-fixture.sh failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|err| format!("compile-asm-fixture.sh printed non-UTF-8 output: {err}"))?;
    parse_key_values(&stdout)
}

fn parse_key_values(stdout: &str) -> Result<BTreeMap<String, String>, String> {
    let mut vars = BTreeMap::new();
    for line in stdout.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("compile-asm-fixture.sh printed a non KEY=VALUE line: `{line}`"))?;
        let plain = !value.is_empty()
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_./:+@-".contains(c));
        if !plain {
            return Err(format!(
                "compile-asm-fixture.sh printed a shell-quoted or empty value for {key}: `{value}`; \
                 fixture paths and symbols must be plain tokens"
            ));
        }
        vars.insert(key.to_string(), value.to_string());
    }
    Ok(vars)
}

fn required<'a>(vars: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, String> {
    vars.get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("compile-asm-fixture.sh did not print {key}"))
}

fn parse_u64(key: &str, value: &str) -> Result<u64, String> {
    let parsed = match value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => value.parse::<u64>(),
    };
    parsed.map_err(|err| format!("{key}=`{value}` is not a u64: {err}"))
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

fn first_line(message: &str) -> &str {
    message.lines().next().unwrap_or("")
}
