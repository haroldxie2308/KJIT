//! Differential fuzzer driver (roadmap V2). See `kjit_harness::fuzz`.
//!
//!   fuzz --seed S --iters N [--max-len L] [--start I] [--fault-per-mille F]
//!        [--regress-dir DIR] [--max-minimize K] [--minimize-budget B]
//!        [--progress P] [--no-fall-off] [--sp-aligned] [--native]
//!
//! Prints stats and per-form coverage. Every failure is reported; the first K
//! (at most 3 per failure kind) are minimized and written as `.s` regression
//! fixtures under DIR (default `tmp/fuzz-regress`, untracked). Promote one per
//! bug by hand: to `tests/arm64/fuzz-pending/` while it fails (the fixture
//! suite does not pick that directory up), to `tests/arm64/` once fixed.
//! Exits 1 if any program failed.

use std::collections::BTreeMap;
use std::panic;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Mutex;

use kjit_harness::a64_pretty::pretty_insn;
use kjit_harness::fuzz::forms::Catalog;
use kjit_harness::fuzz::gen::GenConfig;
use kjit_harness::fuzz::minimize::{minimize_failure, write_fixture, FixtureOrigin};
use kjit_harness::fuzz::program::{slot_pc, Program};
use kjit_harness::fuzz::{fuzz, halt_label, Checker, FailureKind, FailureReport, FuzzConfig};
use kjit_harness::model::MachineState;
use kjit_harness::shared::arm64::A64Insn;

const USAGE: &str = "usage: fuzz --seed S --iters N [--max-len L] [--start I] \
[--fault-per-mille F] [--regress-dir DIR] [--max-minimize K] [--minimize-budget B] \
[--progress P] [--no-fall-off] [--sp-aligned] [--native]";

struct Args {
    config: FuzzConfig,
    regress_dir: PathBuf,
    max_minimize: usize,
    minimize_budget: usize,
    progress: u64,
    native: bool,
}

/// Last panic message and location. Checked programs panic inside
/// `catch_unwind` (a translator panic is a finding); the hook records instead
/// of printing so minimizing a panic does not flood stderr.
static LAST_PANIC: Mutex<Option<String>> = Mutex::new(None);

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1).collect()) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("fuzz: {message}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    panic::set_hook(Box::new(|info| {
        *LAST_PANIC.lock().unwrap_or_else(|p| p.into_inner()) = Some(info.to_string());
    }));
    match panic::catch_unwind(|| run(&args)) {
        Ok(Ok(failed)) if failed == 0 => ExitCode::SUCCESS,
        Ok(Ok(_)) => ExitCode::from(1),
        Ok(Err(message)) => {
            eprintln!("fuzz: {message}");
            ExitCode::from(2)
        }
        Err(_) => {
            eprintln!("fuzz: internal panic: {}", last_panic());
            ExitCode::from(101)
        }
    }
}

fn last_panic() -> String {
    LAST_PANIC
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone()
        .unwrap_or_else(|| "<no panic recorded>".to_string())
}

fn run(args: &Args) -> Result<u64, String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("harness manifest dir has no parent")?
        .to_path_buf();
    let regress_dir = if args.regress_dir.is_absolute() {
        args.regress_dir.clone()
    } else {
        root.join(&args.regress_dir)
    };
    let catalog = Catalog::from_generated();

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    let session = if args.native {
        Some(kjit_harness::native::NativeSession::new()?)
    } else {
        None
    };
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    let checker = match &session {
        Some(session) => Checker::with_native(session),
        None => Checker::interpreter_only(),
    };
    #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
    let checker = if args.native {
        return Err(
            "--native needs Linux arm64 (on macOS run it in the container used by \
                    `make harness-test-native`)"
                .to_string(),
        );
    } else {
        Checker::interpreter_only()
    };

    println!(
        "fuzz: seed={:#x} start={} iters={} max_len={} fault_per_mille={} fall_off={} sp_aligned={} native={}",
        args.config.seed,
        args.config.start,
        args.config.iters,
        args.config.gen.max_len,
        args.config.gen.fault_per_mille,
        args.config.gen.fall_off,
        args.config.gen.sp_aligned,
        checker.native_enabled()
    );

    let mut minimized_per_kind: BTreeMap<FailureKind, usize> = BTreeMap::new();
    let mut minimized_total = 0usize;
    let mut fixtures = Vec::new();
    let mut on_failure = |report: FailureReport| {
        let panic_note = if report.failure.kind == FailureKind::Panic {
            format!(" [{}]", last_panic().replace('\n', " "))
        } else {
            String::new()
        };
        println!(
            "FAIL program {}: {:?} (original halt: {}): {}{panic_note}",
            report.index,
            report.failure.kind,
            report.original_halt.as_ref().map_or("none", halt_label),
            first_line(&report.failure.message)
        );
        let per_kind = minimized_per_kind.entry(report.failure.kind).or_default();
        if minimized_total >= args.max_minimize || *per_kind >= 3 {
            return;
        }
        *per_kind += 1;
        minimized_total += 1;

        let minimized = minimize_failure(&catalog, &checker, &report, args.minimize_budget);
        println!(
            "  minimized in {} runs: {} -> {} slots",
            minimized.runs,
            report.program.len(),
            minimized.program.len()
        );
        match minimized.fixture {
            Ok(program) => {
                let origin = FixtureOrigin {
                    seed: args.config.seed,
                    index: report.index,
                    gen: args.config.gen,
                    failure: &report.failure,
                };
                match write_fixture(&root, &regress_dir, &program, &origin) {
                    Ok(path) => {
                        println!("  regression fixture: {}", path.display());
                        print_program("  ", &program);
                        fixtures.push(path);
                    }
                    Err(message) => println!("  fixture NOT written: {message}"),
                }
            }
            Err(reason) => {
                println!("  not liftable to a fixture: {reason}");
                print_program("  ", &minimized.program);
                print_state("  ", &minimized.state);
            }
        }
    };
    let progress = args.progress;
    let stats = fuzz(
        &catalog,
        &args.config,
        &checker,
        &mut on_failure,
        &mut |index, stats| {
            if progress != 0 && (index + 1) % progress == 0 {
                eprintln!(
                    "fuzz: program {index}: passed={} failed={} chained={} discarded={}",
                    stats.passed, stats.failed, stats.chained, stats.discarded_nonterminating
                );
            }
        },
    );

    println!("\n{stats}");
    if !fixtures.is_empty() {
        println!("regression fixtures written:");
        for path in &fixtures {
            println!("  {}", path.display());
        }
    }
    Ok(stats.failed)
}

fn print_program(indent: &str, program: &Program) {
    match program.words() {
        Ok(words) => {
            for (index, word) in words.iter().enumerate() {
                let pc = slot_pc(index);
                let asm = A64Insn::decode(*word)
                    .map(|insn| pretty_insn(insn, Some(pc)))
                    .unwrap_or_else(|| "(not in the supported subset)".to_string());
                println!("{indent}  {pc:#x}: {word:#010x} {asm}");
            }
        }
        Err(message) => println!("{indent}  <does not encode: {message}>"),
    }
}

fn print_state(indent: &str, state: &MachineState) {
    let regs = (0..31u8)
        .filter(|&reg| state.read_x(reg) != 0)
        .map(|reg| format!("x{reg}={:#x}", state.read_x(reg)))
        .collect::<Vec<_>>()
        .join(" ");
    println!(
        "{indent}  state: {regs} sp={:#x} nzcv={:?} memory_bytes={}",
        state.sp(),
        state.flags,
        state.memory().len()
    );
}

fn first_line(message: &str) -> &str {
    message.lines().next().unwrap_or("")
}

fn parse_args(raw: Vec<String>) -> Result<Args, String> {
    let mut seed = None;
    let mut iters = None;
    let mut gen = GenConfig::default();
    let mut start = 0;
    let mut regress_dir = PathBuf::from("tmp/fuzz-regress");
    let mut max_minimize = 8;
    let mut minimize_budget = 3_000;
    let mut progress = 0;
    let mut native = false;

    let mut iter = raw.into_iter();
    while let Some(flag) = iter.next() {
        if flag == "--native" {
            native = true;
            continue;
        }
        if flag == "--no-fall-off" {
            gen.fall_off = false;
            continue;
        }
        if flag == "--sp-aligned" {
            gen.sp_aligned = true;
            continue;
        }
        let value = iter.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--seed" => seed = Some(parse_u64(&flag, &value)?),
            "--iters" => iters = Some(parse_u64(&flag, &value)?),
            "--start" => start = parse_u64(&flag, &value)?,
            "--max-len" => gen.max_len = parse_u64(&flag, &value)? as usize,
            "--fault-per-mille" => gen.fault_per_mille = parse_u64(&flag, &value)? as u32,
            "--regress-dir" => regress_dir = PathBuf::from(value),
            "--max-minimize" => max_minimize = parse_u64(&flag, &value)? as usize,
            "--minimize-budget" => minimize_budget = parse_u64(&flag, &value)? as usize,
            "--progress" => progress = parse_u64(&flag, &value)?,
            _ => return Err(format!("unknown argument `{flag}`")),
        }
    }
    if gen.max_len == 0 {
        return Err("--max-len must be at least 1".to_string());
    }
    if gen.fault_per_mille > 1000 {
        return Err("--fault-per-mille must be at most 1000".to_string());
    }
    Ok(Args {
        config: FuzzConfig {
            seed: seed.ok_or("--seed is required")?,
            start,
            iters: iters.ok_or("--iters is required")?,
            gen,
        },
        regress_dir,
        max_minimize,
        minimize_budget,
        progress,
        native,
    })
}

fn parse_u64(flag: &str, value: &str) -> Result<u64, String> {
    let parsed = match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => value.parse::<u64>(),
    };
    parsed.map_err(|err| format!("{flag} `{value}` is not a u64: {err}"))
}
