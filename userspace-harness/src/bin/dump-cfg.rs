use std::fs;
use std::path::PathBuf;

use userspace_harness::trans_core::arm64::decode_program;
use userspace_harness::trans_core::cfg::{build_cfg, BlockTerminator};

fn parse_base_pc(text: &str) -> Result<u64, String> {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|err| format!("invalid hex base pc `{text}`: {err}"))
    } else {
        text.parse::<u64>()
            .map_err(|err| format!("invalid decimal base pc `{text}`: {err}"))
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = match args.next() {
        Some(arg) => PathBuf::from(arg),
        None => {
            eprintln!("usage: dump-cfg <raw-bin> [base-pc]");
            std::process::exit(2);
        }
    };
    let base_pc = match args.next() {
        Some(arg) => match parse_base_pc(&arg) {
            Ok(value) => value,
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(2);
            }
        },
        None => 0x4000,
    };

    let bytes = match fs::read(&path) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("failed to read {}: {err}", path.display());
            std::process::exit(1);
        }
    };

    let decoded = match decode_program(&bytes, base_pc) {
        Ok(program) => program,
        Err(err) => {
            eprintln!("decode failed: {err}");
            std::process::exit(1);
        }
    };

    let cfg = match build_cfg(&decoded) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("cfg build failed: {err}");
            std::process::exit(1);
        }
    };

    println!(
        "CFG blocks={} entry=b{} base_pc={:#x}",
        cfg.blocks.len(),
        cfg.entry.0,
        base_pc
    );
    for block in &cfg.blocks {
        println!(
            "block b{} start_pc={:#x} insn_range=[{}, {})",
            block.id.0, block.start_pc, block.start_index, block.end_index
        );
        for insn in &block.insns {
            println!("  {:#06x}: {:#010x} {:?}", insn.pc, insn.word, insn.kind);
        }
        match block.terminator {
            BlockTerminator::Fallthrough { next } => match next {
                Some(next) => println!("  terminator: fallthrough -> b{}", next.0),
                None => println!("  terminator: exit"),
            },
            BlockTerminator::Branch { target } => {
                println!("  terminator: branch -> b{}", target.0);
            }
            BlockTerminator::CondBranch { taken, fallthrough } => {
                println!(
                    "  terminator: cond -> b{} else b{}",
                    taken.0, fallthrough.0
                );
            }
        }
    }
}
