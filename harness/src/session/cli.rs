//! The command line shared by the session binaries (`session-dump`, `kjit-tui`):
//! `<text-bin> <text-base> <entry-pc> [--hot N] [--no-links] [--max-steps N]
//! [--label TEXT]`, and the recording it describes.

use super::{Session, SessionConfig};

pub const USAGE: &str = "usage: <bin> <text-bin> <text-base> <entry-pc> \
                         [--hot N] [--no-links] [--max-steps N] [--label TEXT]";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Args {
    pub text_bin: String,
    pub text_base: u64,
    pub entry_pc: u64,
    pub hot: Option<u32>,
    pub links: bool,
    pub max_steps: Option<u64>,
    /// What the program is called on screen (`make` passes `ASM:ENTRY_SYMBOL`).
    pub label: Option<String>,
}

fn parse_u64(name: &str, value: &str) -> Result<u64, String> {
    let parsed = match value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => value.parse::<u64>(),
    };
    parsed.map_err(|err| format!("{name} `{value}` is not a number: {err}"))
}

/// Parses the arguments after the binary's name.
pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Args, String> {
    let mut positional = Vec::new();
    let (mut hot, mut links, mut max_steps, mut label) = (None, true, None, None);
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let mut value = |flag: &str| args.next().ok_or_else(|| format!("{flag} needs a value"));
        match arg.as_str() {
            "--hot" => {
                let threshold = parse_u64("--hot", &value("--hot")?)?;
                hot = Some(u32::try_from(threshold).map_err(|err| err.to_string())?);
            }
            "--no-links" => links = false,
            "--max-steps" => max_steps = Some(parse_u64("--max-steps", &value("--max-steps")?)?),
            "--label" => label = Some(value("--label")?),
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
        label,
    })
}

impl Args {
    /// The program's name for the screen: `--label`, else the text file's path.
    pub fn label(&self) -> &str {
        // Display only: with no `--label` the path is the only name there is.
        self.label.as_deref().unwrap_or(&self.text_bin)
    }

    /// Reads the text and records the session with the default fixture state.
    pub fn record(&self) -> Result<Session, String> {
        let text = std::fs::read(&self.text_bin)
            .map_err(|err| format!("failed to read {}: {err}", self.text_bin))?;
        let mut config = SessionConfig::fixture(self.text_base, text, self.entry_pc)
            .map_err(|err| err.to_string())?;
        if let Some(hot) = self.hot {
            config.policy.hot_threshold = hot;
        }
        config.policy.links = self.links;
        if let Some(max_steps) = self.max_steps {
            config.limits.max_steps = max_steps;
        }
        Session::record(config).map_err(|err| err.to_string())
    }
}
