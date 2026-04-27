use std::path::PathBuf;

use userspace_harness::model::MachineState;
use userspace_harness::run_entry_fixture;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        eprintln!("usage: asm-fixture <text-bin> <text-base> <entry-pc>");
        std::process::exit(2);
    }

    let text_path = PathBuf::from(&args[0]);
    let text_base = parse_u64(&args[1]).unwrap_or_else(|err| {
        eprintln!("invalid text-base: {err}");
        std::process::exit(2);
    });
    let entry_pc = parse_u64(&args[2]).unwrap_or_else(|err| {
        eprintln!("invalid entry-pc: {err}");
        std::process::exit(2);
    });

    let text_bytes = std::fs::read(&text_path).unwrap_or_else(|err| {
        eprintln!("failed to read {}: {err}", text_path.display());
        std::process::exit(1);
    });

    let mut initial_state = MachineState::new();
    initial_state.write_reg(10, 0x9000);

    match run_entry_fixture(
        "asm-fixture",
        text_base,
        text_bytes,
        entry_pc,
        &initial_state,
    ) {
        Ok(report) => {
            println!(
                "PASS asm-fixture\tentry_pc={entry_pc:#x}\tir_insns={}\tencoded_bytes={}",
                report.ir_program.len(),
                report.encoded_program.len()
            );
        }
        Err(err) => {
            eprintln!("FAIL asm-fixture\n{err}");
            std::process::exit(1);
        }
    }
}

fn parse_u64(value: &str) -> Result<u64, String> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).map_err(|err| err.to_string())
    } else {
        value.parse::<u64>().map_err(|err| err.to_string())
    }
}
