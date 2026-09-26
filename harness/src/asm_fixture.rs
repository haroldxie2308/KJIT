//! Assembling `.s` fixture cases through `scripts/compile-asm-fixture.sh`.
//! Shared by the fixture suite and the fuzzer, which verifies every regression
//! fixture it writes assembles to the exact program it minimized.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

/// One assembled fixture case, as `compile-asm-fixture.sh` resolved it.
pub(crate) struct CompiledCase {
    pub(crate) text_base: u64,
    pub(crate) text_bytes: Vec<u8>,
    pub(crate) entry_pc: u64,
}

/// Assembles `fixture` and resolves the case whose hot SVC is `symbol`.
pub(crate) fn compile_case(
    root: &Path,
    fixture: &Path,
    symbol: &str,
    out_dir: &Path,
) -> Result<CompiledCase, String> {
    let vars = compile_fixture(root, fixture, out_dir, Some(symbol))?;
    let bin_path = required(&vars, "COMPILED_BIN_PATH")?;
    Ok(CompiledCase {
        text_base: parse_u64("COMPILED_TEXT_BASE", required(&vars, "COMPILED_TEXT_BASE")?)?,
        entry_pc: parse_u64("COMPILED_ENTRY_PC", required(&vars, "COMPILED_ENTRY_PC")?)?,
        text_bytes: std::fs::read(bin_path)
            .map_err(|err| format!("failed to read {bin_path}: {err}"))?,
    })
}

#[cfg(test)]
pub(crate) fn list_cases(
    root: &Path,
    fixture: &Path,
    out_dir: &Path,
) -> Result<Vec<String>, String> {
    let vars = compile_fixture(root, fixture, out_dir, None)?;
    // Non-empty: the script fails on a fixture with no `_mark` symbol, and
    // parse_key_values rejects empty values.
    let symbols = required(&vars, "COMPILED_CASE_SYMBOLS")?;
    Ok(symbols.split(':').map(str::to_string).collect())
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
        let (key, value) = line.split_once('=').ok_or_else(|| {
            format!("compile-asm-fixture.sh printed a non KEY=VALUE line: `{line}`")
        })?;
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
    let parsed = match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => value.parse::<u64>(),
    };
    parsed.map_err(|err| format!("{key}=`{value}` is not a u64: {err}"))
}

pub(crate) fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_string()
    }
}
