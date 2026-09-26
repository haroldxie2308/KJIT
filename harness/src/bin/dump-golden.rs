//! Emits a kernel golden Rust source file on stdout.
//!
//! Inputs are the outputs of `scripts/compile-asm-fixture.sh`; see the
//! `kernel-golden` Makefile target.

use kjit_harness::golden::{render_golden, GoldenInput};

fn parse_hex_u64(name: &str, text: &str) -> Result<u64, String> {
    let hex = text
        .strip_prefix("0x")
        .ok_or_else(|| format!("{name} must be 0x-prefixed hex, got `{text}`"))?;
    u64::from_str_radix(hex, 16).map_err(|err| format!("invalid {name} `{text}`: {err}"))
}

fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [fixture, hot_svc_symbol, text_bin, text_base, entry_pc] = args.as_slice() else {
        return Err(
            "usage: dump-golden <fixture.s> <hot-svc-symbol> <text.bin> <text-base> <entry-pc>"
                .to_string(),
        );
    };
    let text_base = parse_hex_u64("text-base", text_base)?;
    let entry_pc = parse_hex_u64("entry-pc", entry_pc)?;
    let bytes =
        std::fs::read(text_bin).map_err(|err| format!("failed to read {text_bin}: {err}"))?;
    if bytes.len() % 4 != 0 {
        return Err(format!(
            "{text_bin} is {} bytes, not a whole number of A64 words",
            bytes.len()
        ));
    }
    let words: Vec<u32> = bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect();

    render_golden(&GoldenInput {
        fixture,
        hot_svc_symbol,
        text_base,
        entry_pc,
        text_words: &words,
    })
}

fn main() {
    match run() {
        Ok(source) => print!("{source}"),
        Err(err) => {
            eprintln!("dump-golden: {err}");
            std::process::exit(1);
        }
    }
}
