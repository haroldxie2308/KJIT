use std::collections::BTreeSet;

use crate::arm64::execute_insn;
use crate::model::{Flags, HaltReason, MachineState};
use crate::runtime::{
    OwnedURuntimeStepper, URuntime, URuntimeHalt, URuntimeStep, URuntimeTransition,
};
use crate::shared::arm64::decode_word;
use crate::shared::emit::layout::ExecutionFragment;
use crate::shared::platform::{SharedVec, GFP_KERNEL};
use crate::shared::trans::cfg::RuntimeExitReason;
use crate::trace::TraceFragment;

const MAX_GROUP_TRANSLATED_STEPS: usize = 100_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveStepOrigin {
    pub offset: usize,
    pub ori_pc: Option<u64>,
}

impl ActiveStepOrigin {
    pub fn from_trace_fragment(fragment: &TraceFragment) -> Vec<Self> {
        fragment
            .insns
            .iter()
            .map(|insn| Self {
                offset: insn.offset,
                ori_pc: insn.ori_pc,
            })
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateSnapshot {
    pub previous: MachineState,
    pub current: MachineState,
}

impl StateSnapshot {
    fn new(state: MachineState) -> Self {
        Self {
            previous: state.clone(),
            current: state,
        }
    }

    fn advance(&mut self, state: MachineState) {
        self.previous = self.current.clone();
        self.current = state;
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginalSideState {
    pub pc: u64,
    pub next_pc: Option<u64>,
    pub executed: bool,
    pub runtime_exit: Option<RuntimeExitReason>,
    pub halt_reason: Option<HaltReason>,
    pub resumed_at: Option<u64>,
    pub state: MachineState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranslatedSideState {
    pub offset: Option<usize>,
    pub insn_index: Option<usize>,
    pub next_offset: Option<usize>,
    pub ori_pc: Option<u64>,
    pub executed: bool,
    pub runtime_transition: Option<URuntimeTransition>,
    pub halt: Option<URuntimeHalt>,
    pub state: MachineState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActiveStepKind {
    TranslatedInstruction,
    OriginalGroup,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveStepEvent {
    pub kind: ActiveStepKind,
    pub group_pc: Option<u64>,
    pub original: Option<OriginalSideState>,
    pub translated: Vec<TranslatedSideState>,
    pub original_mismatch: Option<OriginalPcMismatch>,
    pub halt: ActiveStepHalt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginalPcMismatch {
    pub expected_pc: u64,
    pub actual_pc: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActiveStepHalt {
    Running,
    Original(HaltReason),
    Translated(URuntimeHalt),
    Both {
        original: HaltReason,
        translated: URuntimeHalt,
    },
    Error(String),
}

#[derive(Debug)]
pub struct ActiveStepSession {
    text_base: u64,
    entry_pc: u64,
    text_bytes: Vec<u8>,
    initial_state: MachineState,
    fragment_seed: ExecutionFragment,
    origins: Vec<ActiveStepOrigin>,
    original: ActiveOriginalStepper,
    translated: OwnedURuntimeStepper,
    original_steps: usize,
    translated_steps: usize,
    original_snapshot: StateSnapshot,
    translated_snapshot: StateSnapshot,
    current_original: Option<OriginalSideState>,
    current_translated: Option<TranslatedSideState>,
    current_group_pc: Option<u64>,
    original_advanced_for_group: bool,
    original_halt: Option<HaltReason>,
    translated_halt: Option<URuntimeHalt>,
    error: Option<String>,
}

impl ActiveStepSession {
    pub fn new(
        text_base: u64,
        text_bytes: Vec<u8>,
        entry_pc: u64,
        initial_state: MachineState,
        fragment: &ExecutionFragment,
        origins: Vec<ActiveStepOrigin>,
    ) -> Result<Self, String> {
        let fragment_seed = copy_fragment(fragment)?;
        let original =
            ActiveOriginalStepper::new(text_bytes.clone(), text_base, entry_pc, &initial_state)?;
        let translated = OwnedURuntimeStepper::new(URuntime::new(
            copy_fragment(&fragment_seed)?,
            initial_state.clone(),
        ))?;
        let translated_snapshot = StateSnapshot::new(translated.current_state());
        let mut session = Self {
            text_base,
            entry_pc,
            text_bytes,
            initial_state: initial_state.clone(),
            fragment_seed,
            origins,
            original,
            translated,
            original_steps: 0,
            translated_steps: 0,
            original_snapshot: StateSnapshot::new(initial_state),
            translated_snapshot,
            current_original: None,
            current_translated: None,
            current_group_pc: None,
            original_advanced_for_group: false,
            original_halt: None,
            translated_halt: None,
            error: None,
        };
        session.sync_current_group();
        Ok(session)
    }

    pub fn reset(&mut self) -> Result<(), String> {
        self.original = ActiveOriginalStepper::new(
            self.text_bytes.clone(),
            self.text_base,
            self.entry_pc,
            &self.initial_state,
        )?;
        self.translated = OwnedURuntimeStepper::new(URuntime::new(
            copy_fragment(&self.fragment_seed)?,
            self.initial_state.clone(),
        ))?;
        self.original_steps = 0;
        self.translated_steps = 0;
        self.original_snapshot = StateSnapshot::new(self.initial_state.clone());
        self.translated_snapshot = StateSnapshot::new(self.translated.current_state());
        self.current_original = None;
        self.current_translated = None;
        self.current_group_pc = None;
        self.original_advanced_for_group = false;
        self.original_halt = None;
        self.translated_halt = None;
        self.error = None;
        self.sync_current_group();
        Ok(())
    }

    pub fn step_translated(&mut self) -> ActiveStepEvent {
        self.step_translated_inner(ActiveStepKind::TranslatedInstruction)
    }

    pub fn step_group(&mut self) -> ActiveStepEvent {
        if self.translated_halt.is_some() || self.error.is_some() {
            return ActiveStepEvent {
                kind: ActiveStepKind::OriginalGroup,
                group_pc: self.current_group_pc,
                original: None,
                translated: Vec::new(),
                original_mismatch: None,
                halt: self.halt(),
            };
        }

        self.sync_current_group();
        let group_pc = self.current_group_pc;
        if group_pc.is_none() {
            return self.step_translated_inner(ActiveStepKind::OriginalGroup);
        }

        let expected_pc = group_pc.expect("group_pc is Some above");
        let mut original = None;
        let mut original_mismatch = None;
        if !self.original_advanced_for_group {
            match self.step_original_for_group(expected_pc) {
                OriginalGroupOutcome::Stepped(step) => {
                    original = Some(step);
                    self.original_advanced_for_group = true;
                }
                OriginalGroupOutcome::Mismatch(mismatch) => {
                    original_mismatch = Some(mismatch);
                    self.original_advanced_for_group = true;
                }
                OriginalGroupOutcome::Unavailable => {}
            }
        }

        let mut translated = Vec::new();
        for _ in 0..MAX_GROUP_TRANSLATED_STEPS {
            let Some(current_pc) = self.current_origin_pc() else {
                break;
            };
            if current_pc != expected_pc {
                break;
            }

            match self.step_one_translated() {
                Ok(Some(step)) => {
                    translated.push(step);
                    if self.translated_halt.is_some() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(message) => {
                    self.error = Some(message);
                    break;
                }
            }
        }
        if translated.len() == MAX_GROUP_TRANSLATED_STEPS {
            self.error = Some("active group step exceeded translated step limit".to_string());
        }
        self.sync_current_group();

        ActiveStepEvent {
            kind: ActiveStepKind::OriginalGroup,
            group_pc,
            original,
            translated,
            original_mismatch,
            halt: self.halt(),
        }
    }

    pub fn original_steps(&self) -> usize {
        self.original_steps
    }

    pub fn translated_steps(&self) -> usize {
        self.translated_steps
    }

    pub fn original_pc(&self) -> u64 {
        self.original.pc()
    }

    pub fn translated_pc(&self) -> u64 {
        self.translated.pc()
    }

    pub fn translated_offset(&self) -> Option<usize> {
        self.translated.current_offset()
    }

    pub fn current_origin_pc(&self) -> Option<u64> {
        self.translated_offset()
            .and_then(|offset| self.origin_for_offset(offset))
    }

    pub fn original_snapshot(&self) -> &StateSnapshot {
        &self.original_snapshot
    }

    pub fn translated_snapshot(&self) -> &StateSnapshot {
        &self.translated_snapshot
    }

    pub fn current_original(&self) -> Option<&OriginalSideState> {
        self.current_original.as_ref()
    }

    pub fn current_translated(&self) -> Option<&TranslatedSideState> {
        self.current_translated.as_ref()
    }

    pub fn halt(&self) -> ActiveStepHalt {
        if let Some(message) = &self.error {
            return ActiveStepHalt::Error(message.clone());
        }
        match (&self.original_halt, &self.translated_halt) {
            (Some(original), Some(translated)) => ActiveStepHalt::Both {
                original: *original,
                translated: translated.clone(),
            },
            (Some(original), None) => ActiveStepHalt::Original(*original),
            (None, Some(translated)) => ActiveStepHalt::Translated(translated.clone()),
            (None, None) => ActiveStepHalt::Running,
        }
    }

    pub fn runtime_owned_ranges(&self) -> [(u64, u64); 3] {
        self.translated.runtime_owned_ranges()
    }

    fn step_translated_inner(&mut self, kind: ActiveStepKind) -> ActiveStepEvent {
        let mut translated = Vec::new();
        match self.step_one_translated() {
            Ok(Some(step)) => translated.push(step),
            Ok(None) => {}
            Err(message) => {
                self.error = Some(message);
            }
        }
        self.current_original = None;
        self.sync_current_group();
        ActiveStepEvent {
            kind,
            group_pc: translated.last().and_then(|step| step.ori_pc),
            original: None,
            translated,
            original_mismatch: None,
            halt: self.halt(),
        }
    }

    fn step_one_translated(&mut self) -> Result<Option<TranslatedSideState>, String> {
        if self.translated_halt.is_some() || self.error.is_some() {
            return Ok(None);
        }

        let Some(step) = self.translated.step()? else {
            return Ok(None);
        };
        let side = self.translated_side_state(step);
        self.translated_steps = self.translated.steps();
        self.translated_snapshot.advance(side.state.clone());
        if let Some(halt) = &side.halt {
            self.translated_halt = Some(halt.clone());
        }
        self.current_translated = Some(side.clone());
        Ok(Some(side))
    }

    fn translated_side_state(&self, step: URuntimeStep) -> TranslatedSideState {
        let ori_pc = step
            .offset
            .and_then(|offset| self.origin_for_offset(offset));
        TranslatedSideState {
            offset: step.offset,
            insn_index: step.insn_index,
            next_offset: step.next_offset,
            ori_pc,
            executed: step.executed,
            runtime_transition: step.runtime_transition,
            halt: step.halt,
            state: step.state,
        }
    }

    fn step_original_for_group(&mut self, expected_pc: u64) -> OriginalGroupOutcome {
        if self.original_halt.is_some() || self.error.is_some() {
            return OriginalGroupOutcome::Unavailable;
        }
        let actual_pc = self.original.pc();
        if actual_pc != expected_pc {
            return OriginalGroupOutcome::Mismatch(OriginalPcMismatch {
                expected_pc,
                actual_pc,
            });
        }

        match self.original.step() {
            Ok(Some(step)) => {
                if step.executed {
                    self.original_steps += 1;
                }
                self.original_snapshot.advance(step.state.clone());
                let resumed_at = match step.runtime_exit {
                    Some(RuntimeExitReason::Svc { resume_pc, .. }) => {
                        self.original.resume_at(resume_pc);
                        Some(resume_pc)
                    }
                    _ => None,
                };
                if step.halt_reason.is_some() && resumed_at.is_none() {
                    self.original_halt = step.halt_reason;
                }
                let side = OriginalSideState {
                    pc: step.pc,
                    next_pc: step.next_pc,
                    executed: step.executed,
                    runtime_exit: step.runtime_exit,
                    halt_reason: step.halt_reason,
                    resumed_at,
                    state: step.state,
                };
                self.current_original = Some(side.clone());
                OriginalGroupOutcome::Stepped(side)
            }
            Ok(None) => OriginalGroupOutcome::Unavailable,
            Err(message) => {
                self.error = Some(message);
                OriginalGroupOutcome::Unavailable
            }
        }
    }

    fn origin_for_offset(&self, offset: usize) -> Option<u64> {
        self.origins
            .iter()
            .find_map(|origin| (origin.offset == offset).then_some(origin.ori_pc))
            .flatten()
    }

    fn sync_current_group(&mut self) {
        let origin = self.current_origin_pc();
        if self.current_group_pc != origin {
            self.current_group_pc = origin;
            self.original_advanced_for_group = false;
        }
    }
}

enum OriginalGroupOutcome {
    Stepped(OriginalSideState),
    Mismatch(OriginalPcMismatch),
    Unavailable,
}

#[derive(Debug)]
struct ActiveOriginalStepper {
    program: Vec<u8>,
    base_pc: u64,
    pc: u64,
    state: MachineState,
    stopped: bool,
}

impl ActiveOriginalStepper {
    fn new(
        program: Vec<u8>,
        base_pc: u64,
        entry_pc: u64,
        initial_state: &MachineState,
    ) -> Result<Self, String> {
        if program.len() % 4 != 0 {
            return Err("program length must be a multiple of 4 bytes".to_string());
        }
        Ok(Self {
            program,
            base_pc,
            pc: entry_pc,
            state: initial_state.clone(),
            stopped: false,
        })
    }

    fn pc(&self) -> u64 {
        self.pc
    }

    fn resume_at(&mut self, pc: u64) {
        self.pc = pc;
        self.stopped = false;
    }

    fn step(&mut self) -> Result<Option<ActiveOriginalStep>, String> {
        if self.stopped {
            return Ok(None);
        }

        if self.pc < self.base_pc {
            return Err(format!("pc moved before base address: {:#x}", self.pc));
        }

        let offset = self.pc - self.base_pc;
        if offset % 4 != 0 {
            return Err(format!("pc is not word-aligned: {:#x}", self.pc));
        }

        let insn_index = (offset / 4) as usize;
        if insn_index >= self.program.len() / 4 {
            self.stopped = true;
            return Ok(Some(ActiveOriginalStep {
                pc: self.pc,
                next_pc: None,
                executed: false,
                runtime_exit: None,
                halt_reason: Some(HaltReason::FellOffEnd),
                state: self.state.clone(),
            }));
        }

        let chunk = &self.program[insn_index * 4..insn_index * 4 + 4];
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        let decoded = decode_word(word, self.pc).map_err(|err| err.to_string())?;

        if let Some(reason) = decoded.inner.runtime_exit_reason(self.pc) {
            self.stopped = true;
            return Ok(Some(ActiveOriginalStep {
                pc: self.pc,
                next_pc: None,
                executed: true,
                runtime_exit: Some(reason),
                halt_reason: Some(HaltReason::RuntimeExit { reason }),
                state: self.state.clone(),
            }));
        }

        let pc = self.pc;
        let next_pc = execute_insn(decoded.inner, pc, &mut self.state)?;
        self.pc = next_pc;
        Ok(Some(ActiveOriginalStep {
            pc,
            next_pc: Some(next_pc),
            executed: true,
            runtime_exit: None,
            halt_reason: None,
            state: self.state.clone(),
        }))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ActiveOriginalStep {
    pc: u64,
    next_pc: Option<u64>,
    executed: bool,
    runtime_exit: Option<RuntimeExitReason>,
    halt_reason: Option<HaltReason>,
    state: MachineState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisterComparisonRow {
    pub name: String,
    pub original: ComparisonValue,
    pub translated: ComparisonValue,
    pub equal: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ComparisonValue {
    U64(u64),
    Flags(Flags),
}

pub fn register_comparison(
    original: &MachineState,
    translated: &MachineState,
) -> Vec<RegisterComparisonRow> {
    let mut rows = Vec::with_capacity(33);
    for reg in 0..31 {
        let original_value = original.read_x(reg);
        let translated_value = translated.read_x(reg);
        rows.push(RegisterComparisonRow {
            name: format!("x{reg}"),
            original: ComparisonValue::U64(original_value),
            translated: ComparisonValue::U64(translated_value),
            equal: original_value == translated_value,
        });
    }
    rows.push(RegisterComparisonRow {
        name: "sp".to_string(),
        original: ComparisonValue::U64(original.sp()),
        translated: ComparisonValue::U64(translated.sp()),
        equal: original.sp() == translated.sp(),
    });
    rows.push(RegisterComparisonRow {
        name: "NZCV".to_string(),
        original: ComparisonValue::Flags(original.flags),
        translated: ComparisonValue::Flags(translated.flags),
        equal: original.flags == translated.flags,
    });
    rows
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryComparisonRow {
    pub addr: u64,
    pub before: Option<u8>,
    pub original: Option<u8>,
    pub translated: Option<u8>,
    pub original_changed: bool,
    pub translated_changed: bool,
    pub equal: bool,
}

pub fn memory_comparison(
    initial: &MachineState,
    original: &MachineState,
    translated: &MachineState,
    ignored_ranges: &[(u64, u64)],
) -> Vec<MemoryComparisonRow> {
    let mut addrs = BTreeSet::new();
    addrs.extend(initial.memory().keys().copied());
    addrs.extend(original.memory().keys().copied());
    addrs.extend(translated.memory().keys().copied());

    addrs
        .into_iter()
        .filter(|addr| !addr_in_ranges(*addr, ignored_ranges))
        .filter_map(|addr| {
            let before = initial.memory().get(&addr).copied();
            let original_value = original.memory().get(&addr).copied();
            let translated_value = translated.memory().get(&addr).copied();
            let original_changed = before != original_value;
            let translated_changed = before != translated_value;
            (original_changed || translated_changed).then_some(MemoryComparisonRow {
                addr,
                before,
                original: original_value,
                translated: translated_value,
                original_changed,
                translated_changed,
                equal: original_value == translated_value,
            })
        })
        .collect()
}

fn addr_in_ranges(addr: u64, ranges: &[(u64, u64)]) -> bool {
    ranges
        .iter()
        .any(|(start, end)| *start <= addr && addr < *end)
}

fn copy_fragment(fragment: &ExecutionFragment) -> Result<ExecutionFragment, String> {
    let mut insns = SharedVec::with_capacity(fragment.insns.len(), GFP_KERNEL)
        .map_err(|err| format!("{err:?}"))?;
    for insn in &fragment.insns {
        insns
            .push(*insn, GFP_KERNEL)
            .map_err(|err| format!("{err:?}"))?;
    }
    let mut vlabels = SharedVec::with_capacity(fragment.vlabels.len(), GFP_KERNEL)
        .map_err(|err| format!("{err:?}"))?;
    for label in &fragment.vlabels {
        vlabels
            .push(*label, GFP_KERNEL)
            .map_err(|err| format!("{err:?}"))?;
    }
    Ok(ExecutionFragment {
        insns,
        entry_offset: fragment.entry_offset,
        vlabels,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::arm64::ergo::{uimm, x};
    use crate::shared::arm64::{A64Imm, A64Insn, A64Mem, A64Reg};
    use crate::shared::trans::input::TranslationTrigger;
    use crate::trace::{request_for_trace, PipelineTrace};

    fn encode_insns(insns: &[A64Insn]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(insns.len() * 4);
        for insn in insns {
            bytes.extend_from_slice(&insn.encode().unwrap().to_le_bytes());
        }
        bytes
    }

    fn session_for(insns: &[A64Insn], state: MachineState) -> ActiveStepSession {
        let text_base = 0x4000;
        let entry_pc = text_base;
        let bytes = encode_insns(insns);
        let request = request_for_trace(entry_pc, TranslationTrigger::Manual, &state);
        let trace = PipelineTrace::build(text_base, bytes.clone(), request, &state, false).unwrap();
        ActiveStepSession::new(
            text_base,
            bytes,
            entry_pc,
            state,
            &trace.execution_fragment,
            ActiveStepOrigin::from_trace_fragment(&trace.fragment),
        )
        .unwrap()
    }

    fn step_to_first_body_group(session: &mut ActiveStepSession) {
        while session.current_origin_pc().is_none() {
            session.step_translated();
        }
    }

    #[test]
    fn active_session_starts_at_original_entry_and_translated_prologue() {
        let session = session_for(
            &[
                A64Insn::MovzMovz64Movewide {
                    hw: 0,
                    imm16: uimm(1, 16),
                    rd: x(0),
                },
                A64Insn::RetRet64rBranchReg { rn: x(30) },
            ],
            MachineState::new(),
        );

        assert_eq!(session.original_pc(), 0x4000);
        assert_eq!(session.translated_offset(), Some(0));
        assert_eq!(session.original_steps(), 0);
        assert_eq!(session.translated_steps(), 0);
    }

    #[test]
    fn one_translated_step_advances_only_translated_state() {
        let mut session = session_for(
            &[
                A64Insn::MovzMovz64Movewide {
                    hw: 0,
                    imm16: uimm(1, 16),
                    rd: x(0),
                },
                A64Insn::RetRet64rBranchReg { rn: x(30) },
            ],
            MachineState::new(),
        );

        let original_pc = session.original_pc();
        let event = session.step_translated();

        assert_eq!(event.kind, ActiveStepKind::TranslatedInstruction);
        assert_eq!(session.translated_steps(), 1);
        assert_eq!(session.original_steps(), 0);
        assert_eq!(session.original_pc(), original_pc);
        assert!(event.original.is_none());
    }

    #[test]
    fn group_step_advances_original_once_for_current_origin_group() {
        let mut state = MachineState::new();
        state.write_x(30, 0xfeed_0000);
        let mut session = session_for(
            &[
                A64Insn::MovzMovz64Movewide {
                    hw: 0,
                    imm16: uimm(7, 16),
                    rd: x(0),
                },
                A64Insn::RetRet64rBranchReg { rn: x(30) },
            ],
            state,
        );
        step_to_first_body_group(&mut session);

        let event = session.step_group();

        assert_eq!(event.group_pc, Some(0x4000));
        assert!(event.original.is_some());
        assert_eq!(session.original_steps(), 1);
        assert_eq!(session.original_snapshot().current.read_x(0), 7);
    }

    #[test]
    fn wrapper_only_translated_step_leaves_original_blank() {
        let mut session = session_for(
            &[
                A64Insn::MovzMovz64Movewide {
                    hw: 0,
                    imm16: uimm(1, 16),
                    rd: x(0),
                },
                A64Insn::RetRet64rBranchReg { rn: x(30) },
            ],
            MachineState::new(),
        );

        let event = session.step_group();

        assert_eq!(event.group_pc, None);
        assert!(event.original.is_none());
        assert!(session.current_original().is_none());
        assert_eq!(session.original_steps(), 0);
    }

    #[test]
    fn reset_returns_both_sides_to_initial_state() {
        let mut session = session_for(
            &[
                A64Insn::MovzMovz64Movewide {
                    hw: 0,
                    imm16: uimm(3, 16),
                    rd: x(0),
                },
                A64Insn::RetRet64rBranchReg { rn: x(30) },
            ],
            MachineState::new(),
        );
        session.step_translated();
        session.reset().unwrap();

        assert_eq!(session.original_pc(), 0x4000);
        assert_eq!(session.translated_offset(), Some(0));
        assert_eq!(session.original_steps(), 0);
        assert_eq!(session.translated_steps(), 0);
        assert_eq!(session.halt(), ActiveStepHalt::Running);
    }

    #[test]
    fn register_comparison_detects_equal_and_different_values() {
        let mut original = MachineState::new();
        let mut translated = MachineState::new();
        original.write_x(0, 1);
        translated.write_x(0, 1);
        original.write_x(9, 2);
        translated.write_x(9, 3);
        original.set_sp(0x1000);
        translated.set_sp(0x2000);
        original.flags.z = true;

        let rows = register_comparison(&original, &translated);

        assert!(rows.iter().find(|row| row.name == "x0").unwrap().equal);
        assert!(!rows.iter().find(|row| row.name == "x9").unwrap().equal);
        assert!(!rows.iter().find(|row| row.name == "sp").unwrap().equal);
        assert!(!rows.iter().find(|row| row.name == "NZCV").unwrap().equal);
    }

    #[test]
    fn memory_comparison_ignores_runtime_ranges_and_catches_user_writes() {
        let mut initial = MachineState::new();
        let mut original = MachineState::new();
        let mut translated = MachineState::new();
        initial.seed_memory_u64(0x1000, 0x11);
        original.write_u64(0x1000, 0x22);
        translated.write_u64(0x1000, 0x22);
        original.write_u64(0x7fe000, 0xaa);
        translated.write_u64(0x7fe000, 0xbb);

        let rows = memory_comparison(&initial, &original, &translated, &[(0x7fe000, 0x7fe100)]);

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].addr, 0x1000);
        assert!(rows[0].equal);
    }

    #[test]
    fn group_step_catches_user_memory_writes() {
        let mut state = MachineState::new();
        state.write_x(12, 0x9000);
        state.write_x(30, 0xfeed_0000);
        let mut session = session_for(
            &[
                A64Insn::MovzMovz64Movewide {
                    hw: 0,
                    imm16: uimm(5, 16),
                    rd: x(0),
                },
                A64Insn::StrImmGenStr64LdstPos {
                    rt: x(0),
                    mem: A64Mem::offset(A64Reg::x(12), A64Imm::scaled_unsigned(2, 12, 3)),
                },
                A64Insn::RetRet64rBranchReg { rn: x(30) },
            ],
            state.clone(),
        );

        while session.current_origin_pc() != Some(0x4004) {
            session.step_group();
        }
        session.step_group();
        let rows = memory_comparison(
            &state,
            &session.original_snapshot().current,
            &session.translated_snapshot().current,
            &session.runtime_owned_ranges(),
        );

        assert!(rows.iter().any(|row| row.addr == 0x9010 && row.equal));
    }
}
