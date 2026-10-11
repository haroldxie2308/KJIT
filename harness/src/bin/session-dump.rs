//! `session-dump <text-bin> <text-base> <entry-pc> [--hot N] [--no-links] [--max-steps N]`
//!
//! Records one whole-program session (`kjit_harness::session`) of an assembled
//! fixture program and prints its outcome, the translations and the events as text.
//! `make session-dump ASM=... ENTRY_SYMBOL=...` assembles the program first.

use kjit_harness::session::{
    Event, EventKind, Outcome, Rejection, Session, SessionConfig, TransferVia, Trigger,
};

const USAGE: &str =
    "usage: session-dump <text-bin> <text-base> <entry-pc> [--hot N] [--no-links] [--max-steps N]";

fn parse_u64(name: &str, value: &str) -> Result<u64, String> {
    let parsed = match value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => value.parse::<u64>(),
    };
    parsed.map_err(|err| format!("{name} `{value}` is not a number: {err}"))
}

struct Args {
    text_bin: String,
    text_base: u64,
    entry_pc: u64,
    hot: Option<u32>,
    links: bool,
    max_steps: Option<u64>,
}

fn parse_args() -> Result<Args, String> {
    let mut positional = Vec::new();
    let (mut hot, mut links, mut max_steps) = (None, true, None);
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |flag: &str| {
            args.next()
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        match arg.as_str() {
            "--hot" => {
                let hot_threshold = parse_u64("--hot", &value("--hot")?)?;
                hot = Some(u32::try_from(hot_threshold).map_err(|err| err.to_string())?);
            }
            "--no-links" => links = false,
            "--max-steps" => max_steps = Some(parse_u64("--max-steps", &value("--max-steps")?)?),
            flag if flag.starts_with("--") => return Err(format!("unknown option {flag}")),
            _ => positional.push(arg),
        }
    }
    let [text_bin, text_base, entry_pc] = positional.as_slice() else {
        return Err("expected <text-bin> <text-base> <entry-pc>".to_string());
    };
    Ok(Args {
        text_bin: text_bin.clone(),
        text_base: parse_u64("text-base", text_base)?,
        entry_pc: parse_u64("entry-pc", entry_pc)?,
        hot,
        links,
        max_steps,
    })
}

fn describe(event: &Event) -> String {
    let via = |via: TransferVia| match via {
        TransferVia::Dispatch => "dispatch",
        TransferVia::Link => "link",
        TransferVia::Runtime => "runtime",
    };
    match event.kind {
        EventKind::UserSpan {
            from_pc,
            to_pc,
            steps,
        } => format!("user-span {from_pc:#x} -> {to_pc:#x} ({steps} steps)"),
        EventKind::Syscall { k, pc } => format!("syscall #{k} at {pc:#x}"),
        EventKind::ProfileHit { pc, kind, count } => {
            let kind = match kind {
                Trigger::SvcResume => "svc-resume",
                Trigger::ExitTarget => "exit-target",
            };
            format!("profile {pc:#x} {kind} hits={count}")
        }
        EventKind::Hot { pc } => format!("hot {pc:#x}"),
        EventKind::Translated { translation } => format!("translated #{translation}"),
        EventKind::Installed {
            fragment,
            translation,
        } => format!("installed fragment {fragment} (translation #{translation})"),
        EventKind::Published {
            table,
            slot,
            pc,
            fragment,
            replaced,
        } => {
            let replaced = replaced
                .map(|old| format!(", replaced {:#x} of fragment {}", old.pc, old.fragment))
                .unwrap_or_default();
            format!("published {table:?}[{slot}] = {pc:#x} of fragment {fragment}{replaced}")
        }
        EventKind::Linked {
            fragment,
            slot_offset,
            target,
        } => format!(
            "linked fragment {fragment}+{slot_offset:#x} -> {:#x} of fragment {}",
            target.pc, target.fragment
        ),
        EventKind::Restored {
            fragment,
            slot_offset,
            target,
        } => format!(
            "restored fragment {fragment}+{slot_offset:#x} (was -> {:#x} of fragment {})",
            target.pc, target.fragment
        ),
        EventKind::Retired { fragment } => format!("retired fragment {fragment}"),
        EventKind::RunBegin { fragment, entry_pc } => {
            format!("run-begin fragment {fragment} entry {entry_pc:#x}")
        }
        EventKind::Transfer {
            from,
            to,
            via: how,
        } => format!(
            "transfer {}: fragment {}+{:#x} -> fragment {}+{:#x}",
            via(how),
            from.fragment,
            from.offset,
            to.fragment,
            to.offset
        ),
        EventKind::Exit {
            fragment,
            offset,
            status,
            param0,
            param1,
        } => format!(
            "exit fragment {fragment}+{offset:#x} {status:?} x10={param0:#x} x11={param1:#x}"
        ),
        EventKind::FaultRedirect {
            fragment,
            access_offset,
            stub_offset,
        } => format!(
            "fault-redirect fragment {fragment}+{access_offset:#x} -> stub {stub_offset:#x}"
        ),
        EventKind::RunEnd {
            user_pc,
            entries,
            chain_capped,
        } => format!(
            "run-end user pc {user_pc:#x} entries={entries}{}",
            if chain_capped { " (chain budget)" } else { "" }
        ),
        EventKind::Divergence => "DIVERGENCE".to_string(),
    }
}

fn print_session(session: &Session) {
    // The states of a divergence are long; the summary line is enough here.
    let outcome = match session.outcome() {
        Outcome::Divergence(divergence) => format!(
            "Divergence at syscall {:?}, t={}, {:?}, diff {:?}",
            divergence.syscall, divergence.t, divergence.kind, divergence.diff
        ),
        other => format!("{other:?}"),
    };
    println!("outcome: {outcome}");
    println!(
        "ticks={} syscalls={} events={} translations={} fragments={}",
        session.ticks(),
        session.syscalls().len(),
        session.events().len(),
        session.translations().len(),
        session.final_cache().fragments.len()
    );
    println!("translations:");
    for record in session.translations() {
        let outcome = match (&record.installed, &record.rejection) {
            (Some(fragment), _) => format!("installed as fragment {fragment}"),
            (None, Some(Rejection::EntryUnsupported(exit))) => {
                format!("refused: entry word unsupported ({exit:?})")
            }
            (None, Some(rejection)) => format!("rejected: {rejection:?}"),
            (None, None) => unreachable!("a finished record is installed or rejected"),
        };
        println!(
            "  #{} t={} entry {:#x} {:?} from {:#x}: {} decoded, {} cfg blocks, {} words -> {outcome}",
            record.index,
            record.t,
            record.entry_pc,
            record.trigger,
            record.source_pc,
            record.decoded.len(),
            record.cfg.len(),
            record.layout.len()
        );
    }
    println!("events:");
    for event in session.events() {
        println!("  t={:<7} {}", event.t, describe(event));
    }
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    let text = std::fs::read(&args.text_bin)
        .map_err(|err| format!("failed to read {}: {err}", args.text_bin))?;
    let mut config =
        SessionConfig::fixture(args.text_base, text, args.entry_pc).map_err(|err| err.to_string())?;
    if let Some(hot) = args.hot {
        config.policy.hot_threshold = hot;
    }
    config.policy.links = args.links;
    if let Some(max_steps) = args.max_steps {
        config.limits.max_steps = max_steps;
    }
    let session = Session::record(config).map_err(|err| err.to_string())?;
    print_session(&session);
    match session.outcome() {
        Outcome::Exited | Outcome::Halted(_) | Outcome::StepLimit => Ok(()),
        Outcome::Divergence(_) => Err("the worlds diverged".to_string()),
    }
}

fn main() {
    if let Err(message) = run() {
        eprintln!("session-dump: {message}");
        if message.starts_with("expected") || message.starts_with("unknown") {
            eprintln!("{USAGE}");
        }
        std::process::exit(1);
    }
}
