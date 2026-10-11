//! `check-case <text-bin> <text-base> <entry-pc>`: the differential check of one
//! assembled fixture case (`make harness-test-asm`). The same `run_entry_fixture`
//! call the fixture suite makes, from the same initial state. Exits 1 on a mismatch.

use kjit_harness::{fixture_state, run_entry_fixture};

fn parse_u64(name: &str, value: &str) -> Result<u64, String> {
    let parsed = match value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => value.parse::<u64>(),
    };
    parsed.map_err(|err| format!("{name} `{value}` is not a number: {err}"))
}

fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [text_bin, text_base, entry_pc] = args.as_slice() else {
        return Err("usage: check-case <text-bin> <text-base> <entry-pc>".to_string());
    };
    let text_base = parse_u64("text-base", text_base)?;
    let entry_pc = parse_u64("entry-pc", entry_pc)?;
    let text =
        std::fs::read(text_bin).map_err(|err| format!("failed to read {text_bin}: {err}"))?;
    let state = fixture_state(text_base, &text)
        .map_err(|err| format!("cannot map the fixture text: {err}"))?;
    let report = run_entry_fixture("check-case", text_base, text, entry_pc, &state)?;
    Ok(format!(
        "pipeline_check: pass original_steps={} fragment_steps={} encoded_bytes={} halt={:?}",
        report.original.steps,
        report.fragment_steps,
        report.encoded_fragment.len(),
        report.fragment_halt
    ))
}

fn main() {
    match run() {
        Ok(line) => println!("{line}"),
        Err(message) => {
            eprintln!("check-case: {message}");
            std::process::exit(1);
        }
    }
}
