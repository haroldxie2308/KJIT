//! Offline coverage scan: translate from every `SVC` site in an AArch64 ELF and
//! report how far the current translator gets.
//!
//! Usage: coverage-scan <elf> <out-dir>
//!
//! Every 4-byte-aligned word in an executable section that encodes `SVC #imm`
//! is a site. Each site is compiled with `compile_request` from `site + 4`
//! (HotSvc, no register snapshot). Runtime exits are read from `build_cfg`,
//! which rephrase lowers one-to-one, so failed compiles keep their exit data.
//! Unsupported words and compile-error PCs are grouped by an operand-shape form
//! derived from `llvm-mc --disassemble` (override the tool with `LLVM_MC`).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use kjit_harness::shared::arm64::DecodeError;
use kjit_harness::shared::emit::layout::LayoutError;
use kjit_harness::shared::trans::cfg::{build_cfg, Cfg, CfgError, RuntimeExitReason};
use kjit_harness::shared::trans::input::{
    CodeProvider, CodeReadError, TranslationRequest, TranslationTrigger,
};
use kjit_harness::shared::trans::reg_virt::RegVirtError;
use kjit_harness::shared::trans::translate::{compile_request, CompileError};

const SVC_MASK: u32 = 0xFFE0_001F;
const SVC_BITS: u32 = 0xD400_0001;
const TOP_UNSUPPORTED_FORMS: usize = 40;
const TOP_ERROR_FORMS: usize = 25;
const EXAMPLE_WORDS: usize = 3;

// ---------------------------------------------------------------------------
// ELF64 little-endian executable-section loader
// ---------------------------------------------------------------------------

const SHT_PROGBITS: u32 = 1;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;
const EM_AARCH64: u16 = 183;

struct ExecSection {
    name: String,
    addr: u64,
    bytes: Vec<u8>,
}

fn rd_u16(data: &[u8], off: usize) -> Result<u16, String> {
    data.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| format!("malformed ELF: u16 read at {off:#x} past end of file"))
}

fn rd_u32(data: &[u8], off: usize) -> Result<u32, String> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| format!("malformed ELF: u32 read at {off:#x} past end of file"))
}

fn rd_u64(data: &[u8], off: usize) -> Result<u64, String> {
    data.get(off..off + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| format!("malformed ELF: u64 read at {off:#x} past end of file"))
}

fn to_usize(value: u64, what: &str) -> Result<usize, String> {
    usize::try_from(value).map_err(|_| format!("malformed ELF: {what} {value:#x} overflows usize"))
}

fn load_exec_sections(data: &[u8]) -> Result<Vec<ExecSection>, String> {
    if data.get(0..4) != Some(b"\x7fELF".as_slice()) {
        return Err("not an ELF file (bad magic)".into());
    }
    if data[4] != 2 {
        return Err(format!(
            "unsupported ELF class {} (need ELFCLASS64)",
            data[4]
        ));
    }
    if data[5] != 1 {
        return Err(format!(
            "unsupported ELF data encoding {} (need little-endian)",
            data[5]
        ));
    }
    let machine = rd_u16(data, 18)?;
    if machine != EM_AARCH64 {
        return Err(format!(
            "unsupported e_machine {machine} (need EM_AARCH64 = 183)"
        ));
    }
    let shoff = to_usize(rd_u64(data, 0x28)?, "e_shoff")?;
    let shentsize = rd_u16(data, 0x3A)? as usize;
    let shnum = rd_u16(data, 0x3C)? as usize;
    let shstrndx = rd_u16(data, 0x3E)? as usize;
    if shoff == 0 || shnum == 0 {
        return Err("ELF has no section headers (extended numbering not supported)".into());
    }
    if shentsize != 64 {
        return Err(format!("unexpected e_shentsize {shentsize} (need 64)"));
    }
    if shstrndx >= shnum {
        return Err(format!(
            "e_shstrndx {shstrndx} out of range (shnum {shnum})"
        ));
    }

    let header = |index: usize| -> usize { shoff + index * 64 };
    let strtab_off = to_usize(rd_u64(data, header(shstrndx) + 24)?, "shstrtab offset")?;
    let strtab_size = to_usize(rd_u64(data, header(shstrndx) + 32)?, "shstrtab size")?;
    let strtab = data
        .get(strtab_off..strtab_off + strtab_size)
        .ok_or("malformed ELF: section name table past end of file")?;

    let mut sections = Vec::new();
    for index in 0..shnum {
        let h = header(index);
        let name_off = rd_u32(data, h)? as usize;
        let sh_type = rd_u32(data, h + 4)?;
        let flags = rd_u64(data, h + 8)?;
        let addr = rd_u64(data, h + 16)?;
        let offset = to_usize(rd_u64(data, h + 24)?, "sh_offset")?;
        let size = to_usize(rd_u64(data, h + 32)?, "sh_size")?;
        if flags & (SHF_ALLOC | SHF_EXECINSTR) != (SHF_ALLOC | SHF_EXECINSTR) {
            continue;
        }
        let name_bytes = strtab
            .get(name_off..)
            .and_then(|rest| rest.split(|&b| b == 0).next())
            .ok_or_else(|| format!("malformed ELF: section {index} name offset out of range"))?;
        let name = String::from_utf8_lossy(name_bytes).into_owned();
        if sh_type != SHT_PROGBITS {
            return Err(format!(
                "executable section `{name}` has type {sh_type}, expected SHT_PROGBITS"
            ));
        }
        if addr % 4 != 0 || size % 4 != 0 {
            return Err(format!(
                "executable section `{name}` is not word-aligned: addr={addr:#x} size={size:#x}"
            ));
        }
        let bytes = data
            .get(offset..offset + size)
            .ok_or_else(|| format!("malformed ELF: section `{name}` contents past end of file"))?
            .to_vec();
        sections.push(ExecSection { name, addr, bytes });
    }
    if sections.is_empty() {
        return Err("ELF has no SHF_ALLOC|SHF_EXECINSTR sections".into());
    }
    sections.sort_by_key(|s| s.addr);
    for pair in sections.windows(2) {
        if pair[0].addr + pair[0].bytes.len() as u64 > pair[1].addr {
            return Err(format!(
                "executable sections `{}` and `{}` overlap",
                pair[0].name, pair[1].name
            ));
        }
    }
    Ok(sections)
}

struct ElfCode {
    sections: Vec<ExecSection>,
}

impl ElfCode {
    fn word(&self, pc: u64) -> Option<u32> {
        let mut bytes = [0_u8; 4];
        self.read_exact(pc, &mut bytes).ok()?;
        Some(u32::from_le_bytes(bytes))
    }
}

impl CodeProvider for ElfCode {
    fn entry_addr(&self) -> u64 {
        self.sections[0].addr
    }

    fn read_exact(&self, pc: u64, dst: &mut [u8]) -> Result<(), CodeReadError> {
        let unmapped = CodeReadError::Unmapped { pc, len: dst.len() };
        for section in &self.sections {
            let Some(start) = pc.checked_sub(section.addr) else {
                continue;
            };
            let Ok(start) = usize::try_from(start) else {
                continue;
            };
            let Some(end) = start.checked_add(dst.len()) else {
                return Err(unmapped);
            };
            if let Some(src) = section.bytes.get(start..end) {
                dst.copy_from_slice(src);
                return Ok(());
            }
        }
        Err(unmapped)
    }
}

// ---------------------------------------------------------------------------
// Per-site analysis
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ExitKind {
    Svc,
    Bl,
    Blr,
    Br,
    Ret,
    Unsupported,
    /// Block ends because the next PC is outside executable sections and the
    /// last instruction is not an exit: the fragment would fall off its end.
    NoExitEndOfText,
}

impl ExitKind {
    fn name(self) -> &'static str {
        match self {
            Self::Svc => "Svc",
            Self::Bl => "Bl",
            Self::Blr => "Blr",
            Self::Br => "Br",
            Self::Ret => "Ret",
            Self::Unsupported => "Unsupported",
            Self::NoExitEndOfText => "NoExitEndOfText",
        }
    }
}

struct SiteExit {
    kind: ExitKind,
    pc: u64,
    /// Raw word for Unsupported exits.
    word: Option<u32>,
}

struct ErrInfo {
    variant: String,
    pc: Option<u64>,
    insn_key: Option<&'static str>,
    detail: String,
}

struct Site {
    pc: u64,
    imm: u16,
    /// CFG-level result: original instruction count and exits, or the error.
    cfg: Result<(usize, Vec<SiteExit>), ErrInfo>,
    compile: Result<(), ErrInfo>,
}

fn cfg_exits(cfg: &Cfg) -> Vec<SiteExit> {
    let mut exits = Vec::new();
    for block in &cfg.blocks {
        if let Some(unsupported) = block.unsupported_exit {
            exits.push(SiteExit {
                kind: ExitKind::Unsupported,
                pc: unsupported.pc(),
                // `None`: the text ended there (no word to report).
                word: unsupported.word(),
            });
            continue;
        }
        let last = block.insns.last();
        let reason = last.and_then(|insn| insn.inner.runtime_exit_reason(insn.pc));
        let kind = match reason {
            Some(RuntimeExitReason::Svc { .. }) => ExitKind::Svc,
            Some(RuntimeExitReason::Bl { .. }) => ExitKind::Bl,
            Some(RuntimeExitReason::Blr { .. }) => ExitKind::Blr,
            Some(RuntimeExitReason::Br { .. }) => ExitKind::Br,
            Some(RuntimeExitReason::Ret { .. }) => ExitKind::Ret,
            Some(RuntimeExitReason::Unsupported { .. }) => {
                unreachable!("build_cfg records unsupported words in BasicBlock.unsupported_exit")
            }
            None if block.next.is_empty() => ExitKind::NoExitEndOfText,
            None => continue,
        };
        let pc = match kind {
            ExitKind::NoExitEndOfText => block.end_addr,
            _ => last.expect("exit reason implies a last insn").pc,
        };
        exits.push(SiteExit {
            kind,
            pc,
            word: None,
        });
    }
    exits
}

fn cfg_err_info(err: CfgError) -> ErrInfo {
    match err {
        CfgError::CodeRead(CodeReadError::Unmapped { pc, len }) => ErrInfo {
            variant: "Cfg::CodeRead::Unmapped".into(),
            pc: Some(pc),
            insn_key: None,
            detail: format!("len={len}"),
        },
        CfgError::Decode(DecodeError::UnsupportedWord { pc, word }) => ErrInfo {
            variant: "Cfg::Decode::UnsupportedWord".into(),
            pc: Some(pc),
            insn_key: None,
            detail: format!("word={word:#010x}"),
        },
        CfgError::Decode(DecodeError::Alloc(e)) => ErrInfo {
            variant: "Cfg::Decode::Alloc".into(),
            pc: None,
            insn_key: None,
            detail: format!("{e:?}"),
        },
        CfgError::Alloc(e) => ErrInfo {
            variant: "Cfg::Alloc".into(),
            pc: None,
            insn_key: None,
            detail: format!("{e:?}"),
        },
        CfgError::EmptyBlock { start_addr } => ErrInfo {
            variant: "Cfg::EmptyBlock".into(),
            pc: Some(start_addr),
            insn_key: None,
            detail: String::new(),
        },
        CfgError::RegVirt(e) => {
            let info = reg_virt_err_info(e);
            ErrInfo {
                variant: format!("Cfg::{}", info.variant),
                ..info
            }
        }
    }
}

fn reg_virt_err_info(err: RegVirtError) -> ErrInfo {
    let (name, pc, insn_key, detail): (&str, Option<u64>, Option<&'static str>, String) = match err
    {
        RegVirtError::Allocation(e) => ("Allocation", None, None, format!("{e:?}")),
        RegVirtError::UnexpectedRegVirtHelper { pc } => {
            ("UnexpectedRegVirtHelper", Some(pc), None, String::new())
        }
        RegVirtError::MalformedRuntimeExitGroup { pc } => {
            ("MalformedRuntimeExitGroup", Some(pc), None, String::new())
        }
        RegVirtError::RuntimeExitPcMismatch {
            expected_pc,
            actual_pc,
        } => (
            "RuntimeExitPcMismatch",
            Some(expected_pc),
            None,
            format!("actual_pc={actual_pc:#x}"),
        ),
        RegVirtError::MultipleRuntimeExitParam0Captures { pc } => (
            "MultipleRuntimeExitParam0Captures",
            Some(pc),
            None,
            String::new(),
        ),
        RegVirtError::MissingRegisterAccessor { pc, insn, field } => (
            "MissingRegisterAccessor",
            Some(pc),
            Some(insn),
            format!("field={field}"),
        ),
        RegVirtError::MissingRegisterSetter { pc, insn, field } => (
            "MissingRegisterSetter",
            Some(pc),
            Some(insn),
            format!("field={field}"),
        ),
        RegVirtError::UnsupportedOperandRole { pc, insn, role } => (
            "UnsupportedOperandRole",
            Some(pc),
            Some(insn),
            format!("role={role:?}"),
        ),
        RegVirtError::UnsupportedImplicitRegWrite {
            pc,
            insn,
            reg,
            width,
        } => (
            "UnsupportedImplicitRegWrite",
            Some(pc),
            Some(insn),
            format!("reg={reg} width={width:?}"),
        ),
        RegVirtError::ScratchPoolExhausted { pc, insn, limit } => (
            "ScratchPoolExhausted",
            Some(pc),
            Some(insn),
            format!("limit={limit}"),
        ),
        RegVirtError::StackBackedRewriteNotImplemented { pc, insn, reg } => (
            "StackBackedRewriteNotImplemented",
            Some(pc),
            Some(insn),
            format!("reg={reg:?}"),
        ),
        RegVirtError::StableMappedRewriteNotImplemented { pc, insn, reg } => (
            "StableMappedRewriteNotImplemented",
            Some(pc),
            Some(insn),
            format!("reg={reg:?}"),
        ),
        RegVirtError::UnsupportedStackBackedWriteWidth {
            pc,
            insn,
            field,
            reg,
            width,
        } => (
            "UnsupportedStackBackedWriteWidth",
            Some(pc),
            Some(insn),
            format!("field={field} reg={reg:?} width={width:?}"),
        ),
        RegVirtError::UnsupportedSpOperand {
            pc,
            insn,
            field,
            reg,
        } => (
            "UnsupportedSpOperand",
            Some(pc),
            Some(insn),
            format!("field={field} reg={reg:?}"),
        ),
        RegVirtError::UnpredictableMemoryOp { pc, insn } => {
            ("UnpredictableMemoryOp", Some(pc), Some(insn), String::new())
        }
        RegVirtError::UnprivilegedUserAccess { pc, insn } => (
            "UnprivilegedUserAccess",
            Some(pc),
            Some(insn),
            String::new(),
        ),
        RegVirtError::UnencodableMemOffset { pc, insn, offset } => (
            "UnencodableMemOffset",
            Some(pc),
            Some(insn),
            format!("offset={offset}"),
        ),
        RegVirtError::UnloweredMemoryForm { pc, insn } => {
            ("UnloweredMemoryForm", Some(pc), Some(insn), String::new())
        }
        RegVirtError::UnsupportedRuntimeExitSource {
            pc,
            insn,
            field,
            reg,
        } => (
            "UnsupportedRuntimeExitSource",
            Some(pc),
            Some(insn),
            format!("field={field} reg={reg:?}"),
        ),
    };
    ErrInfo {
        variant: format!("RegVirt::{name}"),
        pc,
        insn_key,
        detail,
    }
}

fn layout_err_info(err: LayoutError) -> ErrInfo {
    let (name, detail) = match err {
        LayoutError::Alloc(e) => ("Alloc", format!("{e:?}")),
        LayoutError::EmptyProgram => ("EmptyProgram", String::new()),
        LayoutError::MissingLabel { target_original_pc } => {
            ("MissingLabel", format!("target={target_original_pc:#x}"))
        }
        LayoutError::BranchOutOfRange {
            insn_index,
            target_original_pc,
        } => (
            "BranchOutOfRange",
            format!("insn_index={insn_index} target={target_original_pc:#x}"),
        ),
        LayoutError::UnalignedBranchTarget {
            insn_index,
            target_original_pc,
        } => (
            "UnalignedBranchTarget",
            format!("insn_index={insn_index} target={target_original_pc:#x}"),
        ),
        LayoutError::UnsupportedBranchField { insn_index, field } => (
            "UnsupportedBranchField",
            format!("insn_index={insn_index} field={field}"),
        ),
        LayoutError::MissingFaultStub { insn_index, ori_pc } => (
            "MissingFaultStub",
            format!("insn_index={insn_index} pc={ori_pc:#x}"),
        ),
        LayoutError::UntaggedUserAccess { insn_index } => {
            ("UntaggedUserAccess", format!("insn_index={insn_index}"))
        }
        LayoutError::DuplicateFaultStub { ori_pc } => {
            ("DuplicateFaultStub", format!("pc={ori_pc:#x}"))
        }
        LayoutError::MissingBudgetStub { insn_index, ori_pc } => (
            "MissingBudgetStub",
            format!("insn_index={insn_index} pc={ori_pc:#x}"),
        ),
        LayoutError::UnguardedBackEdge {
            insn_index,
            target_original_pc,
        } => (
            "UnguardedBackEdge",
            format!("insn_index={insn_index} target={target_original_pc:#x}"),
        ),
        LayoutError::FallthroughNotAdjacent {
            block_start,
            end_addr,
        } => (
            "FallthroughNotAdjacent",
            format!("block={block_start:#x} end={end_addr:#x}"),
        ),
    };
    ErrInfo {
        variant: format!("Layout::{name}"),
        pc: None,
        insn_key: None,
        detail,
    }
}

fn compile_err_info(err: CompileError) -> ErrInfo {
    match err {
        CompileError::Cfg(e) => cfg_err_info(e),
        CompileError::Rephrase(e) => ErrInfo {
            variant: "Rephrase::Alloc".into(),
            pc: None,
            insn_key: None,
            detail: format!("{e:?}"),
        },
        CompileError::RegVirt(e) => reg_virt_err_info(e),
        CompileError::Layout(e) => layout_err_info(e),
    }
}

fn find_sites(code: &ElfCode) -> Vec<(u64, u16)> {
    let mut sites = Vec::new();
    for section in &code.sections {
        for (index, chunk) in section.bytes.chunks_exact(4).enumerate() {
            let word = u32::from_le_bytes(chunk.try_into().unwrap());
            if word & SVC_MASK == SVC_BITS {
                let imm = ((word >> 5) & 0xFFFF) as u16;
                sites.push((section.addr + index as u64 * 4, imm));
            }
        }
    }
    sites
}

fn analyze_site(code: &ElfCode, pc: u64, imm: u16) -> Site {
    let request = TranslationRequest {
        entry_pc: pc + 4,
        trigger: TranslationTrigger::HotSvc,
        regs: None,
    };
    let cfg = build_cfg(&request, code)
        .map(|cfg| {
            let insns = cfg.blocks.iter().map(|block| block.insns.len()).sum();
            (insns, cfg_exits(&cfg))
        })
        .map_err(cfg_err_info);
    let compile = compile_request(&request, code)
        .map(|_| ())
        .map_err(compile_err_info);
    Site {
        pc,
        imm,
        cfg,
        compile,
    }
}

// ---------------------------------------------------------------------------
// llvm-mc disassembly and operand-shape normalization
// ---------------------------------------------------------------------------

const INVALID_FORM: &str = "<invalid encoding>";

/// Disassembles `words` in one `llvm-mc` run. Returns one line per word, or
/// `None` for words llvm-mc reports as invalid encodings.
fn disassemble(words: &[u32]) -> Result<Vec<Option<String>>, String> {
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
fn normalize_form(line: &str) -> String {
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

// ---------------------------------------------------------------------------
// Aggregation and reports
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ExitStat {
    sites_all: usize,
    sites_compile_ok: usize,
    total: usize,
    distinct_pcs: std::collections::BTreeSet<u64>,
}

#[derive(Default)]
struct FormStat {
    sites: std::collections::BTreeSet<u64>,
    pcs: std::collections::BTreeSet<u64>,
    words: std::collections::BTreeSet<u32>,
}

#[derive(Default)]
struct ErrFormStat {
    sites: usize,
    example_site: u64,
    example_pc: Option<u64>,
    example_word: Option<u32>,
    example_detail: String,
}

struct Dist {
    n: usize,
    min: usize,
    median: usize,
    p90: usize,
    max: usize,
}

fn dist(mut values: Vec<usize>) -> Option<Dist> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let n = values.len();
    let rank = |p: f64| values[((p * n as f64).ceil() as usize).clamp(1, n) - 1];
    Some(Dist {
        n,
        min: values[0],
        median: rank(0.5),
        p90: rank(0.9),
        max: values[n - 1],
    })
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => write!(out, "\\u{:04x}", c as u32).unwrap(),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_dist(d: &Option<Dist>) -> String {
    match d {
        None => "null".into(),
        Some(d) => format!(
            "{{\"n\":{},\"min\":{},\"median\":{},\"p90\":{},\"max\":{}}}",
            d.n, d.min, d.median, d.p90, d.max
        ),
    }
}

fn md_dist(label: &str, d: &Option<Dist>) -> String {
    match d {
        None => format!("| {label} | 0 | - | - | - | - |\n"),
        Some(d) => format!(
            "| {label} | {} | {} | {} | {} | {} |\n",
            d.n, d.min, d.median, d.p90, d.max
        ),
    }
}

fn run(elf_path: &Path, out_dir: &Path) -> Result<(), String> {
    let data = std::fs::read(elf_path)
        .map_err(|err| format!("failed to read {}: {err}", elf_path.display()))?;
    let code = ElfCode {
        sections: load_exec_sections(&data)?,
    };
    let sites: Vec<Site> = find_sites(&code)
        .into_iter()
        .map(|(pc, imm)| analyze_site(&code, pc, imm))
        .collect();

    // Disassemble every word we need a form for, in one llvm-mc batch.
    let mut needed: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    for site in &sites {
        if let Ok((_, exits)) = &site.cfg {
            needed.extend(exits.iter().filter_map(|exit| exit.word));
        }
        if let Err(err) = &site.compile {
            if let Some(word) = err.pc.and_then(|pc| code.word(pc)) {
                needed.insert(word);
            }
        }
    }
    let needed: Vec<u32> = needed.into_iter().collect();
    let disasm = disassemble(&needed)?;
    let form_of: BTreeMap<u32, (String, String)> = needed
        .iter()
        .zip(disasm)
        .map(|(&word, text)| match text {
            Some(text) => (word, (normalize_form(&text), text)),
            None => (word, (INVALID_FORM.to_string(), INVALID_FORM.to_string())),
        })
        .collect();

    // Aggregate.
    let mut imm_hist: BTreeMap<u16, usize> = BTreeMap::new();
    let mut exit_stats: BTreeMap<ExitKind, ExitStat> = BTreeMap::new();
    let mut unsupported_forms: BTreeMap<String, FormStat> = BTreeMap::new();
    let mut cfg_err_hist: BTreeMap<String, usize> = BTreeMap::new();
    let mut compile_err_hist: BTreeMap<String, usize> = BTreeMap::new();
    let mut compile_err_forms: BTreeMap<(String, String, String), ErrFormStat> = BTreeMap::new();
    let mut cfg_sizes_all = Vec::new();
    let mut cfg_sizes_ok = Vec::new();
    let mut compile_ok = 0usize;
    let mut compile_ok_no_unsupported = 0usize;
    let mut cfg_ok_no_unsupported = 0usize;

    for site in &sites {
        *imm_hist.entry(site.imm).or_default() += 1;
        let ok = site.compile.is_ok();
        if ok {
            compile_ok += 1;
        }
        match &site.cfg {
            Ok((insns, exits)) => {
                cfg_sizes_all.push(*insns);
                if ok {
                    cfg_sizes_ok.push(*insns);
                }
                let has_unsupported = exits.iter().any(|e| e.kind == ExitKind::Unsupported);
                if !has_unsupported {
                    cfg_ok_no_unsupported += 1;
                    if ok {
                        compile_ok_no_unsupported += 1;
                    }
                }
                let mut kinds_seen = std::collections::BTreeSet::new();
                for exit in exits {
                    let stat = exit_stats.entry(exit.kind).or_default();
                    stat.total += 1;
                    stat.distinct_pcs.insert(exit.pc);
                    if kinds_seen.insert(exit.kind) {
                        stat.sites_all += 1;
                        if ok {
                            stat.sites_compile_ok += 1;
                        }
                    }
                    if let Some(word) = exit.word {
                        let form = form_of[&word].0.clone();
                        let fs = unsupported_forms.entry(form).or_default();
                        fs.sites.insert(site.pc);
                        fs.pcs.insert(exit.pc);
                        fs.words.insert(word);
                    }
                }
            }
            Err(err) => *cfg_err_hist.entry(err.variant.clone()).or_default() += 1,
        }
        if let Err(err) = &site.compile {
            *compile_err_hist.entry(err.variant.clone()).or_default() += 1;
            let word = err.pc.and_then(|pc| code.word(pc));
            let form = match word {
                Some(word) => form_of[&word].0.clone(),
                None => "-".into(),
            };
            let key = (
                err.variant.clone(),
                err.insn_key.unwrap_or("-").to_string(),
                form,
            );
            let stat = compile_err_forms.entry(key).or_default();
            if stat.sites == 0 {
                stat.example_site = site.pc;
                stat.example_pc = err.pc;
                stat.example_word = word;
                stat.example_detail = err.detail.clone();
            }
            stat.sites += 1;
        }
    }

    let mut unsupported_ranked: Vec<(&String, &FormStat)> = unsupported_forms.iter().collect();
    unsupported_ranked.sort_by(|a, b| {
        b.1.sites
            .len()
            .cmp(&a.1.sites.len())
            .then(b.1.pcs.len().cmp(&a.1.pcs.len()))
            .then(a.0.cmp(b.0))
    });
    let mut err_forms_ranked: Vec<(&(String, String, String), &ErrFormStat)> =
        compile_err_forms.iter().collect();
    err_forms_ranked.sort_by(|a, b| b.1.sites.cmp(&a.1.sites).then(a.0.cmp(b.0)));
    let mut compile_err_ranked: Vec<(&String, &usize)> = compile_err_hist.iter().collect();
    compile_err_ranked.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    let dist_all = dist(cfg_sizes_all);
    let dist_ok = dist(cfg_sizes_ok);
    let cfg_ok = sites.iter().filter(|s| s.cfg.is_ok()).count();

    // ---- JSON ----
    let mut j = String::new();
    j.push_str("{\n");
    writeln!(
        j,
        "  \"elf\": {},",
        json_str(&elf_path.display().to_string())
    )
    .unwrap();
    j.push_str("  \"exec_sections\": [");
    for (i, s) in code.sections.iter().enumerate() {
        if i > 0 {
            j.push(',');
        }
        write!(
            j,
            "{{\"name\":{},\"addr\":\"{:#x}\",\"size\":{}}}",
            json_str(&s.name),
            s.addr,
            s.bytes.len()
        )
        .unwrap();
    }
    j.push_str("],\n");
    writeln!(j, "  \"sites_total\": {},", sites.len()).unwrap();
    writeln!(j, "  \"sites_skipped\": 0,").unwrap();
    j.push_str("  \"svc_imm_histogram\": {");
    for (i, (imm, n)) in imm_hist.iter().enumerate() {
        if i > 0 {
            j.push(',');
        }
        write!(j, "\"{imm:#x}\":{n}").unwrap();
    }
    j.push_str("},\n");
    writeln!(
        j,
        "  \"compile\": {{\"ok\":{compile_ok},\"err\":{},\"ok_without_unsupported_exit\":{compile_ok_no_unsupported}}},",
        sites.len() - compile_ok
    )
    .unwrap();
    writeln!(
        j,
        "  \"cfg\": {{\"ok\":{cfg_ok},\"err\":{},\"ok_without_unsupported_exit\":{cfg_ok_no_unsupported}}},",
        sites.len() - cfg_ok
    )
    .unwrap();
    j.push_str("  \"compile_errors_by_variant\": {");
    for (i, (v, n)) in compile_err_ranked.iter().enumerate() {
        if i > 0 {
            j.push(',');
        }
        write!(j, "{}:{n}", json_str(v)).unwrap();
    }
    j.push_str("},\n");
    j.push_str("  \"cfg_errors_by_variant\": {");
    for (i, (v, n)) in cfg_err_hist.iter().enumerate() {
        if i > 0 {
            j.push(',');
        }
        write!(j, "{}:{n}", json_str(v)).unwrap();
    }
    j.push_str("},\n");
    j.push_str("  \"compile_errors_by_form\": [\n");
    for (i, ((variant, key, form), stat)) in err_forms_ranked.iter().enumerate() {
        write!(
            j,
            "    {{\"variant\":{},\"insn_key\":{},\"form\":{},\"sites\":{},\"example_site\":\"{:#x}\",\"example_pc\":{},\"example_word\":{},\"example_detail\":{}}}",
            json_str(variant),
            json_str(key),
            json_str(form),
            stat.sites,
            stat.example_site,
            stat.example_pc.map_or("null".into(), |pc| format!("\"{pc:#x}\"")),
            stat.example_word.map_or("null".into(), |w| format!("\"{w:#010x}\"")),
            json_str(&stat.example_detail)
        )
        .unwrap();
        j.push_str(if i + 1 < err_forms_ranked.len() {
            ",\n"
        } else {
            "\n"
        });
    }
    j.push_str("  ],\n");
    j.push_str("  \"exits\": [\n");
    for (i, (kind, stat)) in exit_stats.iter().enumerate() {
        write!(
            j,
            "    {{\"reason\":{},\"sites_all\":{},\"sites_compile_ok\":{},\"total\":{},\"distinct_pcs\":{}}}",
            json_str(kind.name()),
            stat.sites_all,
            stat.sites_compile_ok,
            stat.total,
            stat.distinct_pcs.len()
        )
        .unwrap();
        j.push_str(if i + 1 < exit_stats.len() {
            ",\n"
        } else {
            "\n"
        });
    }
    j.push_str("  ],\n");
    j.push_str("  \"unsupported_forms\": [\n");
    for (i, (form, stat)) in unsupported_ranked.iter().enumerate() {
        let examples: Vec<String> = stat
            .words
            .iter()
            .map(|w| {
                format!(
                    "{{\"word\":\"{w:#010x}\",\"text\":{}}}",
                    json_str(&form_of[w].1)
                )
            })
            .collect();
        write!(
            j,
            "    {{\"form\":{},\"sites\":{},\"distinct_pcs\":{},\"words\":[{}]}}",
            json_str(form),
            stat.sites.len(),
            stat.pcs.len(),
            examples.join(",")
        )
        .unwrap();
        j.push_str(if i + 1 < unsupported_ranked.len() {
            ",\n"
        } else {
            "\n"
        });
    }
    j.push_str("  ],\n");
    writeln!(j, "  \"cfg_insns_all_cfg_ok\": {},", json_dist(&dist_all)).unwrap();
    writeln!(j, "  \"cfg_insns_compile_ok\": {},", json_dist(&dist_ok)).unwrap();
    j.push_str("  \"sites\": [\n");
    for (i, site) in sites.iter().enumerate() {
        write!(j, "    {{\"pc\":\"{:#x}\",\"imm\":{},", site.pc, site.imm).unwrap();
        match &site.compile {
            Ok(()) => j.push_str("\"compile\":\"ok\","),
            Err(err) => write!(
                j,
                "\"compile\":{{\"variant\":{},\"pc\":{},\"insn_key\":{},\"detail\":{}}},",
                json_str(&err.variant),
                err.pc.map_or("null".into(), |pc| format!("\"{pc:#x}\"")),
                err.insn_key.map_or("null".into(), json_str),
                json_str(&err.detail)
            )
            .unwrap(),
        }
        match &site.cfg {
            Ok((insns, exits)) => {
                let exits: Vec<String> = exits
                    .iter()
                    .map(|e| match e.word {
                        Some(w) => format!(
                            "{{\"reason\":\"{}\",\"pc\":\"{:#x}\",\"word\":\"{w:#010x}\"}}",
                            e.kind.name(),
                            e.pc
                        ),
                        None => format!(
                            "{{\"reason\":\"{}\",\"pc\":\"{:#x}\"}}",
                            e.kind.name(),
                            e.pc
                        ),
                    })
                    .collect();
                write!(j, "\"cfg_insns\":{insns},\"exits\":[{}]}}", exits.join(",")).unwrap();
            }
            Err(err) => write!(j, "\"cfg_error\":{}}}", json_str(&err.variant)).unwrap(),
        }
        j.push_str(if i + 1 < sites.len() { ",\n" } else { "\n" });
    }
    j.push_str("  ]\n}\n");

    // ---- Markdown ----
    let mut m = String::new();
    writeln!(m, "# Coverage scan: `{}`\n", elf_path.display()).unwrap();
    m.push_str(
        "Sites are `SVC` words in executable sections; each is compiled from `site + 4` \
(HotSvc, no register snapshot). Exits come from `build_cfg`, so they are known even when \
`compile_request` fails. A CFG stops at the first unsupported word on each path, so \
unsupported counts are first blockers, not every unsupported instruction.\n\n",
    );
    m.push_str("Executable sections: ");
    let secs: Vec<String> = code
        .sections
        .iter()
        .map(|s| format!("`{}` {:#x}+{:#x}", s.name, s.addr, s.bytes.len()))
        .collect();
    m.push_str(&secs.join(", "));
    m.push_str("\n\n");
    writeln!(m, "| metric | count |\n|---|---|").unwrap();
    writeln!(m, "| SVC sites | {} |", sites.len()).unwrap();
    writeln!(m, "| sites skipped | 0 |").unwrap();
    let imms: Vec<String> = imm_hist
        .iter()
        .map(|(i, n)| format!("#{i:#x}: {n}"))
        .collect();
    writeln!(
        m,
        "| SVC immediates | {} |",
        if imms.is_empty() {
            "-".into()
        } else {
            imms.join(", ")
        }
    )
    .unwrap();
    writeln!(m, "| `build_cfg` ok | {cfg_ok} |").unwrap();
    writeln!(
        m,
        "| `build_cfg` ok, no Unsupported exit | {cfg_ok_no_unsupported} |"
    )
    .unwrap();
    writeln!(m, "| `compile_request` ok | {compile_ok} |").unwrap();
    writeln!(
        m,
        "| `compile_request` ok, no Unsupported exit | {compile_ok_no_unsupported} |\n"
    )
    .unwrap();

    m.push_str("## Runtime exits (CFG level)\n\n");
    m.push_str("| reason | sites (all CFG-ok) | sites (compile ok) | total exits | distinct PCs |\n|---|---|---|---|---|\n");
    for (kind, stat) in &exit_stats {
        writeln!(
            m,
            "| {} | {} | {} | {} | {} |",
            kind.name(),
            stat.sites_all,
            stat.sites_compile_ok,
            stat.total,
            stat.distinct_pcs.len()
        )
        .unwrap();
    }
    m.push('\n');

    writeln!(
        m,
        "## Unsupported forms (top {TOP_UNSUPPORTED_FORMS} of {}, by sites affected)\n",
        unsupported_ranked.len()
    )
    .unwrap();
    m.push_str("| # | form | sites | distinct PCs | example words |\n|---|---|---|---|---|\n");
    for (i, (form, stat)) in unsupported_ranked
        .iter()
        .take(TOP_UNSUPPORTED_FORMS)
        .enumerate()
    {
        let examples: Vec<String> = stat
            .words
            .iter()
            .take(EXAMPLE_WORDS)
            .map(|w| format!("`{w:08x}` {}", form_of[w].1))
            .collect();
        writeln!(
            m,
            "| {} | `{}` | {} | {} | {} |",
            i + 1,
            form,
            stat.sites.len(),
            stat.pcs.len(),
            examples.join("; ")
        )
        .unwrap();
    }
    m.push('\n');

    m.push_str("## Compile errors by variant\n\n| variant | sites |\n|---|---|\n");
    for (variant, n) in &compile_err_ranked {
        writeln!(m, "| {variant} | {n} |").unwrap();
    }
    if !cfg_err_hist.is_empty() {
        m.push_str("\n`build_cfg` errors (these sites have no exit data):\n\n| variant | sites |\n|---|---|\n");
        for (variant, n) in &cfg_err_hist {
            writeln!(m, "| {variant} | {n} |").unwrap();
        }
    }
    m.push('\n');

    writeln!(
        m,
        "## Compile errors by offending form (top {TOP_ERROR_FORMS} of {})\n",
        err_forms_ranked.len()
    )
    .unwrap();
    m.push_str("| variant | insn key | form | sites | example (pc, word, detail) |\n|---|---|---|---|---|\n");
    for ((variant, key, form), stat) in err_forms_ranked.iter().take(TOP_ERROR_FORMS) {
        writeln!(
            m,
            "| {variant} | `{key}` | `{form}` | {} | {} {} {} |",
            stat.sites,
            stat.example_pc.map_or("-".into(), |pc| format!("{pc:#x}")),
            stat.example_word
                .map_or("-".into(), |w| format!("`{w:08x}`")),
            stat.example_detail
        )
        .unwrap();
    }
    m.push('\n');

    m.push_str("## CFG size (original instructions reachable from site + 4)\n\n");
    m.push_str("| population | n | min | median | p90 | max |\n|---|---|---|---|---|---|\n");
    m.push_str(&md_dist("`build_cfg` ok", &dist_all));
    m.push_str(&md_dist("`compile_request` ok", &dist_ok));

    std::fs::create_dir_all(out_dir)
        .map_err(|err| format!("failed to create {}: {err}", out_dir.display()))?;
    let stem = elf_path
        .file_name()
        .ok_or_else(|| format!("ELF path {} has no file name", elf_path.display()))?
        .to_string_lossy()
        .into_owned();
    let json_path = out_dir.join(format!("{stem}.coverage.json"));
    let md_path = out_dir.join(format!("{stem}.coverage.md"));
    std::fs::write(&json_path, j)
        .map_err(|err| format!("failed to write {}: {err}", json_path.display()))?;
    std::fs::write(&md_path, &m)
        .map_err(|err| format!("failed to write {}: {err}", md_path.display()))?;
    print!("{m}");
    eprintln!("wrote {} and {}", json_path.display(), md_path.display());
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [elf, out] = args.as_slice() else {
        eprintln!("usage: coverage-scan <elf> <out-dir>");
        std::process::exit(2);
    };
    if let Err(err) = run(&PathBuf::from(elf), &PathBuf::from(out)) {
        eprintln!("coverage-scan: {err}");
        std::process::exit(1);
    }
}
