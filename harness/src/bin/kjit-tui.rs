//! `kjit-tui <text-bin> <text-base> <entry-pc> [--hot N] [--no-links] [--max-steps N]
//! [--label TEXT]`: records a session like `session-dump` (the command line and the
//! recording are `kjit_harness::session::cli`) and opens it in the TUI.
//! `make tui ASM=... ENTRY_SYMBOL=...` assembles the program first.

use kjit_harness::session::cli;

fn main() {
    let args = cli::parse(std::env::args().skip(1)).unwrap_or_else(|message| {
        eprintln!("kjit-tui: {message}\n{}", cli::USAGE);
        std::process::exit(2);
    });
    let session = args.record().unwrap_or_else(|message| {
        eprintln!("kjit-tui: {message}");
        std::process::exit(1);
    });
    if let Err(err) = kjit_harness::tui::run(&session, args.label()) {
        eprintln!("kjit-tui: {err}");
        std::process::exit(1);
    }
}
