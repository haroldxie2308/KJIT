//! Failure minimization and `.s` regression fixtures.
//!
//! 1. Delta-debug the slots (drop chunks, then single slots), replace slots
//!    with NOP, zero free fields, and pull the initial state toward
//!    `default_fixture_state()`, keeping every change under which the program
//!    still fails with the same `FailureKind` and the original still halts the
//!    same way (RET, fault, fall off the end, ...).
//! 2. Lift what is left of the state into a prelude (memory via `str`, SP via
//!    `add sp`, NZCV via `subs xzr`, registers via `movz`/`movk`) so the case
//!    runs from `default_fixture_state()` like every fixture, re-check that it
//!    still fails, and minimize again with the state fixed.
//! 3. Write it as `.inst` words after `hot_svc_mark` and verify that
//!    `compile-asm-fixture.sh` assembles it to exactly those bytes.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::forms::{Catalog, FieldKind};
use super::gen::GenConfig;
use super::program::{nop_word, slot_pc, Program, Slot, ENTRY_PC, TEXT_BASE};
use super::{halt_label, Checker, Failure, FailureKind, FailureReport, Outcome};
use crate::a64_pretty::pretty_insn;
use crate::arm64::add_with_carry;
use crate::asm_fixture::compile_case;
use crate::model::{Flags, HaltReason, MachineState};
use crate::shared::arm64::{A64Imm, A64Insn, A64Mem, A64Reg};
use crate::{default_fixture_state, FIXTURE_DATA_BASE, FIXTURE_DATA_LEN};

pub struct Minimized {
    pub program: Program,
    pub state: MachineState,
    /// The lifted, re-minimized program that fails from
    /// `default_fixture_state()`, or why lifting did not reproduce.
    pub fixture: Result<Program, String>,
    pub runs: usize,
}

pub fn minimize_failure(
    catalog: &Catalog,
    checker: &Checker<'_>,
    report: &FailureReport,
    budget: usize,
) -> Minimized {
    let mut minimizer = Minimizer {
        catalog,
        checker,
        kind: report.failure.kind,
        verify_rule: verify_rule(&report.failure),
        halt: report.original_halt,
        runs: 0,
        budget,
    };
    let (program, state) = minimizer.minimize(report.program.clone(), report.state.clone(), true);
    let fixture = lift(&program, &state).and_then(|lifted| {
        let base = default_fixture_state();
        if !minimizer.reproduces(&lifted, &base) {
            return Err(format!(
                "the lifted program does not fail with {:?} from default_fixture_state()",
                minimizer.kind
            ));
        }
        Ok(minimizer.minimize(lifted, base, false).0)
    });
    Minimized {
        program,
        state,
        fixture,
        runs: minimizer.runs,
    }
}

struct Minimizer<'a> {
    catalog: &'a Catalog,
    checker: &'a Checker<'a>,
    kind: FailureKind,
    /// For a verifier rejection, the rule it broke: a different rule is a
    /// different bug.
    verify_rule: Option<String>,
    /// How the original halted. Part of the failure signature: without it,
    /// deleting the exit of a program that fails for one reason can turn it
    /// into a fall-off-the-end program that fails for another.
    halt: Option<HaltReason>,
    runs: usize,
    budget: usize,
}

impl Minimizer<'_> {
    fn reproduces(&mut self, program: &Program, state: &MachineState) -> bool {
        if self.runs >= self.budget || program.validate().is_err() {
            return false;
        }
        self.runs += 1;
        let (outcome, halt) = self.checker.check(program, state, &mut |_| {});
        matches!(&outcome, Outcome::Fail(failure)
            if failure.kind == self.kind && verify_rule(failure) == self.verify_rule)
            && halt.as_ref().map(halt_label) == self.halt.as_ref().map(halt_label)
    }

    fn minimize(
        &mut self,
        mut program: Program,
        mut state: MachineState,
        simplify_state: bool,
    ) -> (Program, MachineState) {
        loop {
            let before = (program.clone(), state.clone());
            program = self.remove_slots(program, &state);
            program = self.simplify_slots(program, &state);
            if simplify_state {
                state = self.simplify_state(&program, state);
            }
            if (&program, &state) == (&before.0, &before.1) || self.runs >= self.budget {
                return (program, state);
            }
        }
    }

    fn remove_slots(&mut self, mut program: Program, state: &MachineState) -> Program {
        let mut chunk = (program.len() / 2).max(1);
        loop {
            let mut progressed = false;
            let mut start = 0;
            while start < program.len() {
                let end = (start + chunk).min(program.len());
                let candidate = program.without(start..end);
                if self.reproduces(&candidate, state) {
                    program = candidate;
                    progressed = true;
                } else {
                    start += chunk;
                }
            }
            if chunk == 1 {
                if !progressed || self.runs >= self.budget {
                    return program;
                }
            } else {
                chunk = (chunk / 2).max(1);
            }
        }
    }

    fn simplify_slots(&mut self, mut program: Program, state: &MachineState) -> Program {
        let nop = nop_word();
        for index in 0..program.len() {
            if program.slots[index] == Slot::Word(nop) {
                continue;
            }
            let mut candidate = program.clone();
            candidate.slots[index] = Slot::Word(nop);
            if self.reproduces(&candidate, state) {
                program = candidate;
                continue;
            }
            let Slot::Word(word) = program.slots[index] else {
                continue;
            };
            let Some(form) = self.catalog.form_for_word(word) else {
                continue;
            };
            let mut word = word;
            for field in &form.fields {
                if matches!(field.kind, FieldKind::BranchTarget(_)) {
                    continue;
                }
                let zeroed = field.set(word, 0);
                if zeroed == word || form.decode(zeroed).is_none() {
                    continue;
                }
                let mut candidate = program.clone();
                candidate.slots[index] = Slot::Word(zeroed);
                if self.reproduces(&candidate, state) {
                    program = candidate;
                    word = zeroed;
                }
            }
        }
        program
    }

    fn simplify_state(&mut self, program: &Program, mut state: MachineState) -> MachineState {
        let base = default_fixture_state();
        let try_state = |this: &mut Self, state: &mut MachineState, candidate: MachineState| {
            if candidate != *state && this.reproduces(program, &candidate) {
                *state = candidate;
            }
        };

        let mut candidate = state.clone();
        candidate.flags = base.flags;
        try_state(self, &mut state, candidate);

        let mut candidate = state.clone();
        candidate.set_sp(base.sp());
        try_state(self, &mut state, candidate);

        let candidate = state.without_memory_ranges(&[(0, u64::MAX)]);
        try_state(self, &mut state, candidate);
        for group in memory_groups(&state) {
            let candidate = state.without_memory_ranges(&[(group, group + 8)]);
            try_state(self, &mut state, candidate);
        }

        for reg in 0..31 {
            let mut candidate = state.clone();
            candidate.write_x(reg, base.read_x(reg));
            try_state(self, &mut state, candidate);
        }
        state
    }
}

/// `rule: <Name>` of a `VerifyError` message.
fn verify_rule(failure: &Failure) -> Option<String> {
    if failure.kind != FailureKind::Verify {
        return None;
    }
    let rest = failure.message.split("rule: ").nth(1)?;
    Some(
        rest.chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect(),
    )
}

fn memory_groups(state: &MachineState) -> BTreeSet<u64> {
    state.memory().keys().map(|addr| addr & !7).collect()
}

/// `program` with a prelude that turns `default_fixture_state()` into `state`
/// (memory only in the read-write data window, where the prelude can store).
fn lift(program: &Program, state: &MachineState) -> Result<Program, String> {
    let base = default_fixture_state();
    let window = FIXTURE_DATA_BASE..FIXTURE_DATA_BASE + FIXTURE_DATA_LEN;
    let mut prelude = Vec::new();

    // x12 still holds the window base here (default_fixture_state()).
    for group in memory_groups(state) {
        if !window.contains(&group) {
            return Err(format!(
                "initial memory at {group:#x} is outside the fixture data window"
            ));
        }
        materialize(&mut prelude, 0, state.read_le(group, 8));
        prelude.push(encode(A64Insn::StrImmGenStr64LdstPos {
            rt: A64Reg::x(0),
            mem: A64Mem::offset(
                A64Reg::x_sp(12),
                A64Imm::scaled_unsigned(((group - FIXTURE_DATA_BASE) / 8) as u32, 12, 3),
            ),
        }));
    }
    if state.sp() != base.sp() {
        materialize(&mut prelude, 0, state.sp());
        prelude.push(encode(A64Insn::AddAddsubImmAdd64AddsubImm {
            sh: 0,
            imm12: A64Imm::unsigned(0, 12),
            rn: A64Reg::x_sp(0),
            rd: A64Reg::x_sp(31),
        }));
    }
    if state.flags != base.flags {
        let (lhs, imm) = subs_setting(state.flags).ok_or_else(|| {
            format!(
                "NZCV {:?} is not reachable with `subs xzr, xN, #imm`",
                state.flags
            )
        })?;
        materialize(&mut prelude, 0, lhs);
        prelude.push(encode(A64Insn::SubsAddsubImmSubs64sAddsubImm {
            sh: 0,
            imm12: A64Imm::unsigned(imm, 12),
            rn: A64Reg::x_sp(0),
            rd: A64Reg::x(31),
        }));
    }
    let x0_clobbered = !prelude.is_empty();
    for reg in 0..31u8 {
        let value = state.read_x(reg);
        if value != base.read_x(reg) || (reg == 0 && x0_clobbered) {
            materialize(&mut prelude, reg, value);
        }
    }
    Ok(program.with_prefix(&prelude))
}

fn materialize(out: &mut Vec<u32>, reg: u8, value: u64) {
    out.push(encode(A64Insn::MovzMovz64Movewide {
        hw: 0,
        imm16: A64Imm::unsigned((value & 0xffff) as u32, 16),
        rd: A64Reg::x(reg),
    }));
    for hw in 1..4u8 {
        let chunk = (value >> (16 * hw as u32)) & 0xffff;
        if chunk != 0 {
            out.push(encode(A64Insn::MovkMovk64Movewide {
                hw,
                imm16: A64Imm::unsigned(chunk as u32, 16),
                rd: A64Reg::x(reg),
            }));
        }
    }
}

/// `(lhs, imm)` such that `subs xzr, lhs, #imm` leaves `flags`.
fn subs_setting(flags: Flags) -> Option<(u64, u32)> {
    const LHS: [u64; 7] = [
        0,
        1,
        2,
        0x7fff_ffff_ffff_ffff,
        1 << 63,
        (1 << 63) + 1,
        u64::MAX,
    ];
    for lhs in LHS {
        for imm in 0..=2u32 {
            // SUBS is AddWithCarry(lhs, NOT(imm), 1).
            if add_with_carry(lhs, !(imm as u64), true, 64).1 == flags {
                return Some((lhs, imm));
            }
        }
    }
    None
}

fn encode(insn: A64Insn) -> u32 {
    insn.encode()
        .unwrap_or_else(|err| panic!("{} does not encode: {err:?}", insn.key()))
}

pub struct FixtureOrigin<'a> {
    pub seed: u64,
    pub index: u64,
    pub gen: GenConfig,
    pub failure: &'a Failure,
}

/// Writes `program` as `<dir>/fuzz_regress_<hash>.s` and verifies that the
/// fixture script assembles it to exactly `program.text_bytes()`.
pub fn write_fixture(
    repo_root: &Path,
    dir: &Path,
    program: &Program,
    origin: &FixtureOrigin<'_>,
) -> Result<PathBuf, String> {
    let words = program.words()?;
    let path = dir.join(format!("fuzz_regress_{:016x}.s", fnv1a(&words)));

    let mut text = String::new();
    text.push_str("// Differential-fuzzer regression (roadmap V2), minimized and lifted.\n");
    text.push_str(&format!(
        "// Failure: {:?}: {}\n",
        origin.failure.kind,
        origin.failure.message.lines().next().unwrap_or("")
    ));
    text.push_str(&format!(
        "// Found by: cargo run --release --manifest-path harness/Cargo.toml --bin fuzz -- \\\n\
         //   --seed {:#x} --start {} --iters 1 --max-len {} --fault-per-mille {}{}{}\n",
        origin.seed,
        origin.index,
        origin.gen.max_len,
        origin.gen.fault_per_mille,
        if origin.gen.fall_off {
            ""
        } else {
            " --no-fall-off"
        },
        if origin.gen.sp_aligned {
            " --sp-aligned"
        } else {
            ""
        },
    ));
    text.push_str(
        "// Runs from default_fixture_state(); the leading movz/movk/str/add/subs\n\
         // words materialize the minimized fuzz initial state.\n\n",
    );
    text.push_str(".text\n.global hot_svc_mark\nhot_svc_mark:\n    svc #0\n");
    for (index, word) in words.iter().enumerate() {
        let pc = slot_pc(index);
        let asm = A64Insn::decode(*word)
            .map(|insn| pretty_insn(insn, Some(pc)))
            .unwrap_or_else(|| "(not in the supported subset)".to_string());
        text.push_str(&format!("    .inst {word:#010x} // {pc:#x}: {asm}\n"));
    }

    std::fs::create_dir_all(dir)
        .map_err(|err| format!("failed to create {}: {err}", dir.display()))?;
    std::fs::write(&path, text)
        .map_err(|err| format!("failed to write {}: {err}", path.display()))?;

    let work = repo_root
        .join("tmp")
        .join(format!("fuzz-fixture-verify.{}", std::process::id()));
    let case = compile_case(repo_root, &path, "hot_svc_mark", &work);
    std::fs::remove_dir_all(&work)
        .map_err(|err| format!("failed to remove {}: {err}", work.display()))?;
    let case = case?;
    let expected = program.text_bytes()?;
    if case.text_base != TEXT_BASE || case.entry_pc != ENTRY_PC || case.text_bytes != expected {
        return Err(format!(
            "{} does not assemble to the minimized program (text_base={:#x} entry={:#x} {} bytes)",
            path.display(),
            case.text_base,
            case.entry_pc,
            case.text_bytes.len()
        ));
    }
    Ok(path)
}

fn fnv1a(words: &[u32]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in words.iter().flat_map(|word| word.to_le_bytes()) {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}
