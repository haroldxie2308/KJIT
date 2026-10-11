//! The step log: one record per executed instruction of the KJIT world, as diffs.

use crate::model::{Flags, MachineState};

/// A register the log tracks. `Sp` is the stack pointer of the machine that executed
/// the tick (a fragment runs on its own stack); `V` registers, FPCR and FPSR are the
/// user's own (A9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegId {
    X(u8),
    Sp,
    V(u8),
    Fpcr,
    Fpsr,
}

/// A register that holds another value after the tick than before it. A V register
/// uses all 128 bits, every other register the low 64.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegWrite {
    pub reg: RegId,
    pub old: u128,
    pub new: u128,
}

/// Where a tick executed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepAt {
    /// Original code, natively in userspace.
    User { pc: u64 },
    /// Fragment code of the code cache's fragment `fragment`, at byte `offset`.
    Fragment { fragment: usize, offset: usize },
}

/// A store of a tick. `runtime_owned`: into the runtime's own memory (the dispatch
/// tables and records, `pt_regs`, the extra params, the runtime frame), which the
/// session's states leave out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepMemWrite {
    pub addr: u64,
    pub size: u8,
    pub old: u64,
    pub new: u64,
    pub runtime_owned: bool,
}

/// One tick, read back from the log.
#[derive(Clone, Copy, Debug)]
pub struct StepView<'a> {
    /// 1-based: tick `n` takes the machine from `state_at(n - 1)` to `state_at(n)`.
    pub tick: u64,
    pub at: StepAt,
    /// The instruction word executed (for a fragment, as patched by the cache at
    /// that time).
    pub word: u32,
    pub flags_before: Flags,
    pub flags_after: Flags,
    pub reg_writes: &'a [RegWrite],
    pub mem_writes: &'a [StepMemWrite],
}

/// The registers of a machine, for diffing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RegFile {
    x: [u64; 31],
    sp: u64,
    pub(crate) flags: Flags,
    v: [u128; 32],
    fpcr: u64,
    fpsr: u64,
}

impl RegFile {
    pub(crate) fn of(state: &MachineState) -> Self {
        let mut x = [0; 31];
        for (reg, value) in x.iter_mut().enumerate() {
            *value = state.read_x(reg as u8);
        }
        Self {
            x,
            sp: state.sp(),
            flags: state.flags,
            v: state.v,
            fpcr: state.fpcr,
            fpsr: state.fpsr,
        }
    }

    /// The registers whose value differs in `next`.
    pub(crate) fn diff(&self, next: &RegFile) -> Vec<RegWrite> {
        let mut writes = Vec::new();
        let mut note = |reg: RegId, old: u128, new: u128| {
            if old != new {
                writes.push(RegWrite { reg, old, new });
            }
        };
        for reg in 0..31 {
            note(
                RegId::X(reg as u8),
                u128::from(self.x[reg]),
                u128::from(next.x[reg]),
            );
        }
        note(RegId::Sp, u128::from(self.sp), u128::from(next.sp));
        for reg in 0..32 {
            note(RegId::V(reg as u8), self.v[reg], next.v[reg]);
        }
        note(RegId::Fpcr, u128::from(self.fpcr), u128::from(next.fpcr));
        note(RegId::Fpsr, u128::from(self.fpsr), u128::from(next.fpsr));
        writes
    }
}

pub(crate) fn set_reg(state: &mut MachineState, reg: RegId, value: u128) {
    match reg {
        RegId::X(index) => state.write_x(index, value as u64),
        RegId::Sp => state.set_sp(value as u64),
        RegId::V(index) => state.v[usize::from(index)] = value,
        RegId::Fpcr => state.fpcr = value as u64,
        RegId::Fpsr => state.fpsr = value as u64,
    }
}

/// The registers of `state` that differ from `other`, as (register, state, other).
pub(crate) fn reg_diff(state: &MachineState, other: &MachineState) -> Vec<(RegId, u128, u128)> {
    RegFile::of(state)
        .diff(&RegFile::of(other))
        .into_iter()
        .map(|write| (write.reg, write.old, write.new))
        .collect()
}

/// Replays one tick onto `state`: the registers, the flags and the stores outside the
/// runtime's memory.
pub(crate) fn apply_step(state: &mut MachineState, step: &StepView<'_>) {
    for write in step.reg_writes {
        set_reg(state, write.reg, write.new);
    }
    state.flags = step.flags_after;
    for write in step.mem_writes.iter().filter(|write| !write.runtime_owned) {
        state.write_le(write.addr, write.size, write.new);
    }
}

#[derive(Debug)]
struct StepRec {
    at: StepAt,
    word: u32,
    flags_before: Flags,
    flags_after: Flags,
    /// End (exclusive) of this step's writes in the pools.
    regs_end: u32,
    mems_end: u32,
}

/// The ticks of a session, in two shared pools so a tick costs no allocation of its
/// own.
#[derive(Debug, Default)]
pub(crate) struct StepLog {
    steps: Vec<StepRec>,
    regs: Vec<RegWrite>,
    mems: Vec<StepMemWrite>,
}

impl StepLog {
    pub(crate) fn len(&self) -> u64 {
        self.steps.len() as u64
    }

    pub(crate) fn push(
        &mut self,
        at: StepAt,
        word: u32,
        flags_before: Flags,
        flags_after: Flags,
        regs: Vec<RegWrite>,
        mems: impl IntoIterator<Item = StepMemWrite>,
    ) {
        self.regs.extend(regs);
        self.mems.extend(mems);
        self.steps.push(StepRec {
            at,
            word,
            flags_before,
            flags_after,
            regs_end: u32::try_from(self.regs.len()).expect("fewer than 2^32 register writes"),
            mems_end: u32::try_from(self.mems.len()).expect("fewer than 2^32 memory writes"),
        });
    }

    /// Tick `tick` (1-based).
    pub(crate) fn get(&self, tick: u64) -> Option<StepView<'_>> {
        let index = usize::try_from(tick.checked_sub(1)?).ok()?;
        let rec = self.steps.get(index)?;
        let (regs_start, mems_start) = match index.checked_sub(1) {
            Some(previous) => (
                self.steps[previous].regs_end as usize,
                self.steps[previous].mems_end as usize,
            ),
            None => (0, 0),
        };
        Some(StepView {
            tick,
            at: rec.at,
            word: rec.word,
            flags_before: rec.flags_before,
            flags_after: rec.flags_after,
            reg_writes: &self.regs[regs_start..rec.regs_end as usize],
            mem_writes: &self.mems[mems_start..rec.mems_end as usize],
        })
    }
}
