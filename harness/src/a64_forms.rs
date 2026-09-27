//! Word -> instruction-form classification for measurement tools
//! (`coverage-scan`, `e1-report`).
//!
//! Words are disassembled with `llvm-mc --disassemble` (override the tool with
//! `LLVM_MC`) and reduced to an operand shape, e.g. `ldrb w0, [x1, #8]` ->
//! `ldrb w, [x, #imm]`. Harness-only: this shells out and must stay out of
//! `shared/`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::process::{Command, Stdio};

/// Form (and text) of words llvm-mc reports as invalid encodings.
pub const INVALID_FORM: &str = "<invalid encoding>";

pub struct WordForm {
    /// Operand shape, e.g. `ldrb w, [x, #imm]`.
    pub form: String,
    /// llvm-mc text of the word, e.g. `ldrb w0, [x1, #8]`.
    pub text: String,
}

/// Classifies every word in `words` with one `llvm-mc` run.
pub fn classify_words(words: &[u32]) -> Result<BTreeMap<u32, WordForm>, String> {
    let disasm = disassemble(words)?;
    Ok(words
        .iter()
        .zip(disasm)
        .map(|(&word, text)| match text {
            Some(text) => (
                word,
                WordForm {
                    form: normalize_form(&text),
                    text,
                },
            ),
            None => (
                word,
                WordForm {
                    form: INVALID_FORM.to_string(),
                    text: INVALID_FORM.to_string(),
                },
            ),
        })
        .collect())
}

/// Disassembles `words` in one `llvm-mc` run. Returns one line per word, or
/// `None` for words llvm-mc reports as invalid encodings.
pub fn disassemble(words: &[u32]) -> Result<Vec<Option<String>>, String> {
    if words.is_empty() {
        return Ok(Vec::new());
    }
    let tool = std::env::var("LLVM_MC").unwrap_or_else(|_| "llvm-mc".into());
    let mut input = String::new();
    for word in words {
        let b = word.to_le_bytes();
        writeln!(
            input,
            "{:#04x} {:#04x} {:#04x} {:#04x}",
            b[0], b[1], b[2], b[3]
        )
        .unwrap();
    }
    let mut child = Command::new(&tool)
        .args(["--disassemble", "-triple=aarch64", "-mattr=+all"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to run `{tool}` (set LLVM_MC to override): {err}"))?;
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()));
    let output = child
        .wait_with_output()
        .map_err(|err| format!("failed to wait for `{tool}`: {err}"))?;
    writer
        .join()
        .expect("llvm-mc stdin writer panicked")
        .map_err(|err| format!("failed to write llvm-mc input: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "`{tool}` exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Invalid words produce `<stdin>:LINE:COL: warning: invalid instruction
    // encoding` on stderr and no stdout line; every other word yields exactly
    // one stdout instruction line, in input order.
    let stderr = String::from_utf8_lossy(&output.stderr);
    let mut invalid = vec![false; words.len()];
    for line in stderr.lines() {
        if !line.contains("invalid instruction encoding") {
            continue;
        }
        let line_no = line
            .strip_prefix("<stdin>:")
            .and_then(|rest| rest.split(':').next())
            .and_then(|n| n.parse::<usize>().ok())
            .ok_or_else(|| format!("unparseable llvm-mc diagnostic: {line}"))?;
        let slot = invalid
            .get_mut(line_no - 1)
            .ok_or_else(|| format!("llvm-mc diagnostic for unknown input line: {line}"))?;
        *slot = true;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let insn_lines: Vec<&str> = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('.'))
        .collect();
    let valid = invalid.iter().filter(|&&bad| !bad).count();
    if insn_lines.len() != valid {
        return Err(format!(
            "llvm-mc output misaligned: {} instruction lines for {valid} valid words",
            insn_lines.len()
        ));
    }
    // Keep only the instruction text: drop llvm-mc `// =...` comments and tabs.
    let mut lines = insn_lines.into_iter().map(|line| {
        let text = line.split("//").next().unwrap_or("").trim();
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    });
    Ok(invalid
        .into_iter()
        .map(|bad| if bad { None } else { lines.next() })
        .collect())
}

const CONDITIONS: [&str; 18] = [
    "eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le",
    "al", "nv",
];

fn normalize_token(token: &str) -> String {
    if CONDITIONS.contains(&token) {
        return "cond".into();
    }
    if token.bytes().all(|b| b.is_ascii_digit()) {
        return "i".into();
    }
    let mut chars = token.chars();
    let first = chars.next().expect("token is non-empty");
    if "xwqdshbvzp".contains(first) {
        let rest = chars.as_str();
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        let suffix = &rest[digits..];
        if digits > 0
            && rest[..digits].parse::<u32>().is_ok_and(|n| n <= 31)
            && (suffix.is_empty() || suffix.starts_with('.'))
        {
            return format!("{first}{suffix}");
        }
    }
    token.to_string()
}

/// Reduces a disassembled instruction to its operand shape, e.g.
/// `ldrb w0, [x1, #8]` -> `ldrb w, [x, #imm]`.
pub fn normalize_form(line: &str) -> String {
    let (mnemonic, operands) = match line.find(char::is_whitespace) {
        Some(split) => (&line[..split], line[split..].trim()),
        None => return line.to_string(),
    };
    let mut out = String::from(mnemonic);
    out.push(' ');
    let bytes = operands.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '#' {
            i += 1;
            while i < bytes.len()
                && matches!(bytes[i], b'-' | b'+' | b'.' | b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' | b'x')
            {
                i += 1;
            }
            out.push_str("#imm");
        } else if c.is_ascii_alphanumeric() || c == '_' {
            let start = i;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'_' | b'.'))
            {
                i += 1;
            }
            out.push_str(&normalize_token(&operands[start..i]));
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::normalize_form;

    #[test]
    fn normalize_form_keeps_operand_shape() {
        assert_eq!(normalize_form("ldrb w0, [x1, #8]"), "ldrb w, [x, #imm]");
        assert_eq!(normalize_form("b.ne #16"), "b.ne #imm");
        assert_eq!(normalize_form("csel x0, x1, x2, eq"), "csel x, x, x, cond");
        assert_eq!(
            normalize_form("ldp x29, x30, [sp], #16"),
            "ldp x, x, [sp], #imm"
        );
        assert_eq!(
            normalize_form("add v0.4s, v1.4s, v2.4s"),
            "add v.4s, v.4s, v.4s"
        );
        assert_eq!(normalize_form("ret"), "ret");
    }
}
