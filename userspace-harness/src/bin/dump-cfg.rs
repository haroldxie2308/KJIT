use std::fs;
use std::path::PathBuf;

use userspace_harness::shared::trans::cfg::{build_cfg, BlockTerminator};
use userspace_harness::shared::trans::input::{TranslationRequest, TranslationTrigger};
use userspace_harness::MockCodeProvider;

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

    let code = MockCodeProvider::new(base_pc, bytes);
    let request = TranslationRequest {
        entry_pc: base_pc,
        trigger: TranslationTrigger::Manual,
        regs: None,
    };
    let cfg = match build_cfg(&request, &code) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("cfg build failed: {err}");
            std::process::exit(1);
        }
    };

    println!(
        "CFG blocks={} entry_pc={:#x} base_pc={:#x}",
        cfg.blocks.len(),
        cfg.entry_pc,
        base_pc
    );
    for (index, block) in cfg.blocks.iter().enumerate() {
        println!(
            "block #{} start_pc={:#x} end_pc={:#x} insns={}",
            index,
            block.start_addr,
            block.end_addr,
            block.insns.len()
        );
        for insn in &block.insns {
            println!("  {:#06x}: {:#010x} {:?}", insn.pc, insn.word, insn.insn);
        }
        match block.terminator {
            BlockTerminator::Fallthrough { next_pc } => match next_pc {
                Some(next_pc) => println!("  terminator: fallthrough -> pc {next_pc:#x}"),
                None => println!("  terminator: exit"),
            },
            BlockTerminator::Branch { target_pc } => {
                println!("  terminator: branch -> pc {target_pc:#x}");
            }
            BlockTerminator::CondBranch {
                taken_pc,
                fallthrough_pc,
            } => {
                println!("  terminator: cond -> pc {taken_pc:#x} else pc {fallthrough_pc:#x}");
            }
            BlockTerminator::RuntimeExit { reason } => {
                println!("  terminator: runtime-exit {:?}", reason);
            }
        }
    }
}
