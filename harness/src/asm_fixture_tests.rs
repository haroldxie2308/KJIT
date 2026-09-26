//! Differential check of every case in every `tests/arm64/*.s` fixture.
//!
//! A case is a defined symbol ending in `_mark`: its address is the hot SVC PC
//! and translation starts at the next instruction. Assembling and symbol
//! resolution stay in `scripts/compile-asm-fixture.sh`; the check itself is the
//! same `run_entry_fixture` call `trace-tui --check` makes, from the same
//! initial state.

use std::collections::BTreeMap;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{default_fixture_state, run_entry_fixture};

const LLVM_TOOLS: [&str; 3] = ["llvm-mc", "llvm-nm", "llvm-objcopy"];

struct CaseFailure {
    fixture: String,
    symbol: String,
    message: String,
}

#[test]
fn every_asm_fixture_case_matches_original() {
    require_llvm_tools();

    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("harness manifest dir has a parent")
        .to_path_buf();
    let fixtures = fixture_paths(&root.join("tests/arm64"));
    // Per-process directory so concurrent test runs never share outputs.
    let work_dir = root
        .join("tmp")
        .join(format!("asm-fixture-suite.{}", std::process::id()));
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
            match run_case(&root, fixture, &symbol, &fixture_dir.join(&symbol)) {
                Ok(entry_pc) => println!("asm fixture pass: {name} {symbol} entry={entry_pc:#x}"),
                Err(message) => {
                    println!("asm fixture FAIL: {name} {symbol}");
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
        "asm fixture suite: {cases} cases across {} fixtures, {} failed",
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
        "{} asm fixture case(s) failed (outputs kept in {}):\n{list}",
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

/// Returns the entry PC on success.
fn run_case(root: &Path, fixture: &Path, symbol: &str, out_dir: &Path) -> Result<u64, String> {
    let vars = compile_fixture(root, fixture, out_dir, Some(symbol))?;
    let bin_path = required(&vars, "COMPILED_BIN_PATH")?;
    let text_base = parse_u64("COMPILED_TEXT_BASE", required(&vars, "COMPILED_TEXT_BASE")?)?;
    let entry_pc = parse_u64("COMPILED_ENTRY_PC", required(&vars, "COMPILED_ENTRY_PC")?)?;
    let text_bytes =
        std::fs::read(bin_path).map_err(|err| format!("failed to read {bin_path}: {err}"))?;

    let initial_state = default_fixture_state();
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        run_entry_fixture("asm-fixture", text_base, text_bytes, entry_pc, &initial_state)
    }));
    match outcome {
        Ok(Ok(_report)) => Ok(entry_pc),
        Ok(Err(message)) => Err(message),
        // A translator panic is a case failure; record it so the remaining cases still run.
        Err(payload) => Err(format!("panicked: {}", panic_message(payload.as_ref()))),
    }
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
