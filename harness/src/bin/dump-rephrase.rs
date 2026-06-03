use std::fs;
use std::path::PathBuf;

use kjit_harness::shared::trans::cfg::build_cfg;
use kjit_harness::shared::trans::input::{TranslationRequest, TranslationTrigger};
use kjit_harness::shared::trans::rephrase::{rephrase, RephrasedInsnKind};
use kjit_harness::MockCodeProvider;

fn parse_pc(text: &str, name: &str) -> Result<u64, String> {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|err| format!("invalid hex {name} `{text}`: {err}"))
    } else {
        text.parse::<u64>()
            .map_err(|err| format!("invalid decimal {name} `{text}`: {err}"))
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = match args.next() {
        Some(arg) => PathBuf::from(arg),
        None => {
            eprintln!("usage: dump-rephrase <raw-bin> [text-base] [entry-pc]");
            std::process::exit(2);
        }
    };
    let text_base = match args.next() {
        Some(arg) => parse_pc(&arg, "text base").unwrap_or_else(|err| {
            eprintln!("{err}");
            std::process::exit(2);
        }),
        None => 0x4000,
    };
    let entry_pc = match args.next() {
        Some(arg) => parse_pc(&arg, "entry pc").unwrap_or_else(|err| {
            eprintln!("{err}");
            std::process::exit(2);
        }),
        None => text_base,
    };

    let bytes = fs::read(&path).unwrap_or_else(|err| {
        eprintln!("failed to read {}: {err}", path.display());
        std::process::exit(1);
    });

    let code = MockCodeProvider::new(text_base, bytes);
    let request = TranslationRequest {
        entry_pc,
        trigger: TranslationTrigger::Manual,
        regs: None,
    };
    let cfg = build_cfg(&request, &code).unwrap_or_else(|err| {
        eprintln!("cfg build failed: {err}");
        std::process::exit(1);
    });
    let rephrased = rephrase(cfg).unwrap_or_else(|err| {
        eprintln!("rephrase failed: {err:?}");
        std::process::exit(1);
    });

    println!(
        "Rephrased blocks={} entry_pc={entry_pc:#x} text_base={text_base:#x}",
        rephrased.len(),
    );
    for (block_index, block) in rephrased.iter().enumerate() {
        println!(
            "block #{} start_pc={:#x} end_pc={:#x} insns={}",
            block_index,
            block.start_addr,
            block.end_addr,
            block.insns.len(),
        );
        print!("  prev:");
        for pc in &block.prev {
            print!(" {pc:#x}");
        }
        println!();
        print!("  next:");
        for pc in &block.next {
            print!(" {pc:#x}");
        }
        println!();

        for (insn_index, insn) in block.insns.iter().enumerate() {
            let kind = match insn.kind {
                RephrasedInsnKind::Original => "original",
                RephrasedInsnKind::UserSynthetic => "user-syn",
                RephrasedInsnKind::RegVirtHelper => "rv-helper",
                RephrasedInsnKind::RuntimeExitPayload => "rt-payload",
                RephrasedInsnKind::RuntimeExitBranch => "rt-branch",
            };
            match insn.insn.encode() {
                Ok(word) => println!(
                    "  [{insn_index:02}] kind={kind:>9} ori_pc={:#x} word={word:#010x} {:?}",
                    insn.ori_pc,
                    insn.insn
                ),
                Err(err) => println!(
                    "  [{insn_index:02}] kind={kind:>9} ori_pc={:#x} word=<encode error: {err:?}> {:?}",
                    insn.ori_pc,
                    insn.insn
                ),
            }
        }
    }
}
