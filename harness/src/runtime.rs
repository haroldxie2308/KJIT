use crate::arm64::execute_insn;
use crate::model::MachineState;
use crate::shared::abi::{
    RetStatus, ABI_EXTRA_PARAMS_ARG_REG, ABI_LINK_REG, ABI_PT_REGS_ARG_REG,
    PROLOGUE_ENTRY_BRANCH_OFFSET, RET_PARAM0_REG, RET_PARAM1_REG, RET_STATUS_REG,
};
use crate::shared::emit::layout::ExecutionFragment;

pub const DEFAULT_BASE_PC: u64 = 0x400000;
pub const DEFAULT_PT_REGS_ADDR: u64 = 0x7fe000;
pub const DEFAULT_EXTRA_PARAMS_ADDR: u64 = 0x7ff000;
pub const DEFAULT_RETURN_PC: u64 = 0x123456;
pub const DEFAULT_STACK_TOP: u64 = 0x800000;

const PT_REGS_BYTES: u64 = 256;
const PT_REGS_SP_OFFSET: u64 = 31 * 8;
const EXTRA_PARAMS_BYTES: u64 = 16;
const RUNTIME_FRAME_BYTES: u64 = 192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct URuntimeConfig {
    pub base_pc: u64,
    pub pt_regs_addr: u64,
    pub extra_params_addr: u64,
    pub return_pc: u64,
    pub stack_top: u64,
}

impl Default for URuntimeConfig {
    fn default() -> Self {
        Self {
            base_pc: DEFAULT_BASE_PC,
            pt_regs_addr: DEFAULT_PT_REGS_ADDR,
            extra_params_addr: DEFAULT_EXTRA_PARAMS_ADDR,
            return_pc: DEFAULT_RETURN_PC,
            stack_top: DEFAULT_STACK_TOP,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct URuntime {
    pub state: MachineState,
    pub fragment: ExecutionFragment,
    pub config: URuntimeConfig,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct URuntimeReport {
    pub state: MachineState,
    pub halt: URuntimeHalt,
    pub steps: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum URuntimeHalt {
    FellOffFragment {
        pc: u64,
    },
    NeedsTranslation {
        status: RetStatus,
        target_pc: u64,
        resume_offset: Option<usize>,
    },
    ReturnedToUserspace {
        status: RetStatus,
        target_pc: u64,
    },
    InvalidReturnStatus {
        raw: u64,
    },
    UnsupportedRuntimeExit {
        status: RetStatus,
    },
    ExecutionError {
        pc: u64,
        message: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct URuntimeStep {
    pub offset: Option<usize>,
    pub insn_index: Option<usize>,
    pub next_offset: Option<usize>,
    pub executed: bool,
    pub runtime_transition: Option<URuntimeTransition>,
    pub halt: Option<URuntimeHalt>,
    pub state: MachineState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum URuntimeTransition {
    Continued { offset: usize },
}

impl URuntime {
    pub fn new(fragment: ExecutionFragment, initial_state: MachineState) -> Self {
        Self::with_config(fragment, initial_state, URuntimeConfig::default())
    }

    pub fn with_config(
        fragment: ExecutionFragment,
        mut initial_state: MachineState,
        config: URuntimeConfig,
    ) -> Self {
        seed_pt_regs(&mut initial_state, &config);
        initial_state.write_x(ABI_PT_REGS_ARG_REG, config.pt_regs_addr);
        initial_state.write_x(ABI_EXTRA_PARAMS_ARG_REG, config.extra_params_addr);
        initial_state.write_x(ABI_LINK_REG, config.return_pc);
        initial_state.set_sp(config.stack_top);
        Self {
            state: initial_state,
            fragment,
            config,
        }
    }

    pub fn run(&mut self) -> URuntimeReport {
        match URuntimeStepper::new(self) {
            Ok(mut stepper) => stepper.run_to_halt(),
            Err(message) => self.report(
                URuntimeHalt::ExecutionError {
                    pc: self.config.base_pc,
                    message,
                },
                0,
            ),
        }
    }

    fn handle_runtime_return(&mut self) -> RuntimeAction {
        let raw_status = self.state.read_x(RET_STATUS_REG);
        let status = RetStatus::from_reg(raw_status);
        let param0 = self.state.read_x(RET_PARAM0_REG);
        let param1 = self.state.read_x(RET_PARAM1_REG);
        let resume_pc = param1;
        let resume_offset = self.fragment.offset_for_pc(resume_pc);

        match status {
            RetStatus::Svc => {
                if let Some(offset) = resume_offset {
                    RuntimeAction::ContinueAt(offset)
                } else {
                    RuntimeAction::Stop(URuntimeHalt::ReturnedToUserspace {
                        status,
                        target_pc: resume_pc,
                    })
                }
            }
            RetStatus::Bl | RetStatus::Blr => {
                self.write_user_x(ABI_LINK_REG, resume_pc);
                self.continue_or_request_translation(status, param0, resume_offset)
            }
            RetStatus::Br => self.continue_or_request_translation(status, param0, resume_offset),
            RetStatus::Ret => {
                if let Some(offset) = self.fragment.offset_for_pc(param0) {
                    RuntimeAction::ContinueAt(offset)
                } else {
                    RuntimeAction::Stop(URuntimeHalt::ReturnedToUserspace {
                        status,
                        target_pc: param0,
                    })
                }
            }
            RetStatus::Invalid(_) => {
                RuntimeAction::Stop(URuntimeHalt::InvalidReturnStatus { raw: raw_status })
            }
            RetStatus::Mem | RetStatus::Debug => {
                RuntimeAction::Stop(URuntimeHalt::UnsupportedRuntimeExit { status })
            }
        }
    }

    fn prepare_entry_at(&mut self, offset: usize) -> Result<(), String> {
        self.validate_offset(offset)?;
        self.state
            .write_x(ABI_PT_REGS_ARG_REG, self.config.pt_regs_addr);
        self.state
            .write_x(ABI_EXTRA_PARAMS_ARG_REG, self.config.extra_params_addr);
        self.state.write_x(ABI_LINK_REG, self.config.return_pc);
        self.state.set_sp(self.config.stack_top);
        Ok(())
    }

    fn continue_or_request_translation(
        &self,
        status: RetStatus,
        target_pc: u64,
        resume_offset: Option<usize>,
    ) -> RuntimeAction {
        if let Some(offset) = self.fragment.offset_for_pc(target_pc) {
            RuntimeAction::ContinueAt(offset)
        } else {
            RuntimeAction::Stop(URuntimeHalt::NeedsTranslation {
                status,
                target_pc,
                resume_offset,
            })
        }
    }

    fn validate_offset(&self, offset: usize) -> Result<(), String> {
        if offset % 4 != 0 || offset >= self.fragment.len_bytes() {
            return Err(format!("invalid runtime entry offset: {offset:#x}"));
        }
        Ok(())
    }

    fn pc_to_index(&self, pc: u64) -> Option<usize> {
        let offset = self.emitted_pc_to_offset(pc)?;
        let index = offset / 4;
        (index < self.fragment.insns.len()).then_some(index)
    }

    fn emitted_pc_to_offset(&self, pc: u64) -> Option<usize> {
        let offset = pc.checked_sub(self.config.base_pc)?;
        if offset % 4 != 0 {
            return None;
        }
        usize::try_from(offset).ok()
    }

    fn report(&self, halt: URuntimeHalt, steps: usize) -> URuntimeReport {
        URuntimeReport {
            state: self.user_state_from_pt_regs(),
            halt,
            steps,
        }
    }

    fn write_user_x(&mut self, reg: u8, value: u64) {
        self.state
            .write_u64(self.config.pt_regs_addr + (reg as u64) * 8, value);
    }

    pub(crate) fn user_state_from_pt_regs(&self) -> MachineState {
        let ranges = self.runtime_owned_ranges();
        let mut state = self.state.without_memory_ranges(&ranges);
        for reg in 0..31 {
            state.write_x(
                reg,
                self.state
                    .read_u64(self.config.pt_regs_addr + (reg as u64) * 8),
            );
        }
        state.set_sp(
            self.state
                .read_u64(self.config.pt_regs_addr + PT_REGS_SP_OFFSET),
        );
        state.flags = self.state.flags;
        state
    }

    pub(crate) fn physical_user_state(&self) -> MachineState {
        self.state
            .without_memory_ranges(&self.runtime_owned_ranges())
    }

    pub(crate) fn runtime_owned_ranges(&self) -> [(u64, u64); 3] {
        [
            (
                self.config.pt_regs_addr,
                self.config.pt_regs_addr + PT_REGS_BYTES,
            ),
            (
                self.config.extra_params_addr,
                self.config.extra_params_addr + EXTRA_PARAMS_BYTES,
            ),
            (
                self.config.stack_top.saturating_sub(RUNTIME_FRAME_BYTES),
                self.config.stack_top,
            ),
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct URuntimeCursor {
    pc: u64,
    steps: usize,
    stopped: bool,
    pending_entry_offset: Option<usize>,
}

impl URuntimeCursor {
    fn new(runtime: &mut URuntime) -> Result<Self, String> {
        let entry_offset = runtime.fragment.entry_offset;
        let base_pc = runtime.config.base_pc;
        runtime.prepare_entry_at(entry_offset)?;
        let prologue_branch_index = PROLOGUE_ENTRY_BRANCH_OFFSET / 4;
        if runtime.fragment.insns.len() <= prologue_branch_index {
            return Err("fragment is missing the ABI prologue".to_string());
        }

        Ok(Self {
            pc: base_pc,
            steps: 0,
            stopped: false,
            pending_entry_offset: Some(entry_offset),
        })
    }

    fn pc(&self) -> u64 {
        self.pc
    }

    fn current_offset(&self, runtime: &URuntime) -> Option<usize> {
        runtime.emitted_pc_to_offset(self.pc)
    }

    fn steps(&self) -> usize {
        self.steps
    }

    fn step(&mut self, runtime: &mut URuntime) -> Result<Option<URuntimeStep>, String> {
        if self.stopped {
            return Ok(None);
        }

        if self.pc == runtime.config.return_pc {
            return Ok(Some(
                self.apply_runtime_return(runtime, None, None, None, false)?,
            ));
        }

        let Some(index) = runtime.pc_to_index(self.pc) else {
            self.stopped = true;
            let halt = URuntimeHalt::FellOffFragment { pc: self.pc };
            return Ok(Some(URuntimeStep {
                offset: None,
                insn_index: None,
                next_offset: None,
                executed: false,
                runtime_transition: None,
                halt: Some(halt),
                state: runtime.physical_user_state(),
            }));
        };

        let offset = index * 4;
        let insn_pc = self.pc;
        let insn = runtime.fragment.insns[index];
        self.steps += 1;

        let mut next_pc = match execute_insn(insn, insn_pc, &mut runtime.state) {
            Ok(next_pc) => next_pc,
            Err(message) => {
                self.stopped = true;
                let halt = URuntimeHalt::ExecutionError {
                    pc: insn_pc,
                    message,
                };
                return Ok(Some(URuntimeStep {
                    offset: Some(offset),
                    insn_index: Some(index),
                    next_offset: None,
                    executed: true,
                    runtime_transition: None,
                    halt: Some(halt),
                    state: runtime.physical_user_state(),
                }));
            }
        };

        if offset == PROLOGUE_ENTRY_BRANCH_OFFSET {
            let entry_offset = self
                .pending_entry_offset
                .take()
                .unwrap_or(runtime.fragment.entry_offset);
            next_pc = runtime.config.base_pc + entry_offset as u64;
        }

        self.pc = next_pc;
        if self.pc == runtime.config.return_pc {
            return Ok(Some(self.apply_runtime_return(
                runtime,
                Some(offset),
                Some(index),
                runtime.emitted_pc_to_offset(next_pc),
                true,
            )?));
        }

        Ok(Some(URuntimeStep {
            offset: Some(offset),
            insn_index: Some(index),
            next_offset: runtime.emitted_pc_to_offset(self.pc),
            executed: true,
            runtime_transition: None,
            halt: None,
            state: runtime.physical_user_state(),
        }))
    }

    fn apply_runtime_return(
        &mut self,
        runtime: &mut URuntime,
        offset: Option<usize>,
        insn_index: Option<usize>,
        next_offset: Option<usize>,
        executed: bool,
    ) -> Result<URuntimeStep, String> {
        match runtime.handle_runtime_return() {
            RuntimeAction::ContinueAt(offset_to_enter) => {
                runtime.prepare_entry_at(offset_to_enter)?;
                self.pc = runtime.config.base_pc;
                self.pending_entry_offset = Some(offset_to_enter);
                Ok(URuntimeStep {
                    offset,
                    insn_index,
                    next_offset,
                    executed,
                    runtime_transition: Some(URuntimeTransition::Continued {
                        offset: offset_to_enter,
                    }),
                    halt: None,
                    state: runtime.user_state_from_pt_regs(),
                })
            }
            RuntimeAction::Stop(halt) => {
                self.stopped = true;
                Ok(URuntimeStep {
                    offset,
                    insn_index,
                    next_offset,
                    executed,
                    runtime_transition: None,
                    halt: Some(halt),
                    state: runtime.user_state_from_pt_regs(),
                })
            }
        }
    }
}

pub struct URuntimeStepper<'a> {
    runtime: &'a mut URuntime,
    cursor: URuntimeCursor,
}

impl<'a> URuntimeStepper<'a> {
    pub fn new(runtime: &'a mut URuntime) -> Result<Self, String> {
        let cursor = URuntimeCursor::new(runtime)?;
        Ok(Self { runtime, cursor })
    }

    pub fn pc(&self) -> u64 {
        self.cursor.pc()
    }

    pub fn current_offset(&self) -> Option<usize> {
        self.cursor.current_offset(self.runtime)
    }

    pub fn steps(&self) -> usize {
        self.cursor.steps()
    }

    pub fn report_for_halt(&self, halt: URuntimeHalt) -> URuntimeReport {
        self.runtime.report(halt, self.cursor.steps())
    }

    pub fn step(&mut self) -> Result<Option<URuntimeStep>, String> {
        self.cursor.step(self.runtime)
    }

    pub fn run_to_halt(&mut self) -> URuntimeReport {
        run_cursor_to_halt(self.runtime, &mut self.cursor)
    }
}

#[derive(Debug)]
pub struct OwnedURuntimeStepper {
    runtime: URuntime,
    cursor: URuntimeCursor,
}

impl OwnedURuntimeStepper {
    pub fn new(mut runtime: URuntime) -> Result<Self, String> {
        let cursor = URuntimeCursor::new(&mut runtime)?;
        Ok(Self { runtime, cursor })
    }

    pub fn pc(&self) -> u64 {
        self.cursor.pc()
    }

    pub fn current_offset(&self) -> Option<usize> {
        self.cursor.current_offset(&self.runtime)
    }

    pub fn steps(&self) -> usize {
        self.cursor.steps()
    }

    pub fn current_state(&self) -> MachineState {
        self.runtime.physical_user_state()
    }

    pub fn runtime_owned_ranges(&self) -> [(u64, u64); 3] {
        self.runtime.runtime_owned_ranges()
    }

    pub fn report_for_halt(&self, halt: URuntimeHalt) -> URuntimeReport {
        self.runtime.report(halt, self.cursor.steps())
    }

    pub fn step(&mut self) -> Result<Option<URuntimeStep>, String> {
        self.cursor.step(&mut self.runtime)
    }

    pub fn run_to_halt(&mut self) -> URuntimeReport {
        run_cursor_to_halt(&mut self.runtime, &mut self.cursor)
    }
}

fn run_cursor_to_halt(runtime: &mut URuntime, cursor: &mut URuntimeCursor) -> URuntimeReport {
    loop {
        match cursor.step(runtime) {
            Ok(Some(step)) => {
                if let Some(halt) = step.halt {
                    return runtime.report(halt, cursor.steps());
                }
            }
            Ok(None) => {
                return runtime.report(
                    URuntimeHalt::ExecutionError {
                        pc: cursor.pc(),
                        message: "runtime stepper stopped without a halt reason".to_string(),
                    },
                    cursor.steps(),
                );
            }
            Err(message) => {
                return runtime.report(
                    URuntimeHalt::ExecutionError {
                        pc: cursor.pc(),
                        message,
                    },
                    cursor.steps(),
                );
            }
        }
    }
}

enum RuntimeAction {
    ContinueAt(usize),
    Stop(URuntimeHalt),
}

fn seed_pt_regs(state: &mut MachineState, config: &URuntimeConfig) {
    for reg in 0..31 {
        state.write_u64(config.pt_regs_addr + (reg as u64) * 8, state.read_x(reg));
    }
    state.write_u64(config.pt_regs_addr + PT_REGS_SP_OFFSET, state.sp());
    state.write_u64(config.extra_params_addr, 0);
    state.write_u64(config.extra_params_addr + 8, 0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::abi::PROLOGUE_ENTRY_BRANCH_OFFSET;
    use crate::shared::arm64::ergo::{uimm, x};
    use crate::shared::arm64::{A64Imm, A64Insn};
    use crate::shared::trans::input::{TranslationRequest, TranslationTrigger};
    use crate::shared::trans::translate::compile_request;
    use crate::MockCodeProvider;

    fn compile_insns(base_pc: u64, insns: &[A64Insn]) -> ExecutionFragment {
        let mut bytes = Vec::with_capacity(insns.len() * 4);
        for insn in insns {
            bytes.extend_from_slice(&insn.encode().unwrap().to_le_bytes());
        }
        let code = MockCodeProvider::new(base_pc, bytes);
        let request = TranslationRequest {
            entry_pc: base_pc,
            trigger: TranslationTrigger::Manual,
            regs: None,
        };
        compile_request(&request, &code).unwrap()
    }

    #[test]
    fn runtime_stepper_executes_prologue_before_body() {
        let base_pc = 0x3000;
        let fragment = compile_insns(
            base_pc,
            &[
                A64Insn::MovzMovz64Movewide {
                    hw: 0,
                    imm16: uimm(2, 16),
                    rd: x(2),
                },
                A64Insn::RetRet64rBranchReg { rn: x(30) },
            ],
        );
        let entry_offset = fragment.entry_offset;
        let mut runtime = URuntime::new(fragment, MachineState::new());
        let mut stepper = URuntimeStepper::new(&mut runtime).unwrap();

        let first = stepper.step().unwrap().unwrap();
        assert_eq!(first.offset, Some(0));

        let mut branch = first;
        for _ in 1..=PROLOGUE_ENTRY_BRANCH_OFFSET / 4 {
            branch = stepper.step().unwrap().unwrap();
        }

        assert_eq!(branch.offset, Some(PROLOGUE_ENTRY_BRANCH_OFFSET));
        assert_eq!(stepper.current_offset(), Some(entry_offset));

        let body = stepper.step().unwrap().unwrap();
        assert_eq!(body.offset, Some(entry_offset));
        assert_eq!(body.state.read_x(2), 2);
    }

    #[test]
    fn runtime_stepper_runtime_return_preserves_run_behavior() {
        let base_pc = 0x4000;
        let insns = [
            A64Insn::MovzMovz64Movewide {
                hw: 0,
                imm16: uimm(172, 16),
                rd: x(8),
            },
            A64Insn::SvcSvcExException {
                imm16: A64Imm::unsigned(0, 16),
            },
            A64Insn::MovzMovz64Movewide {
                hw: 0,
                imm16: uimm(2, 16),
                rd: x(2),
            },
            A64Insn::RetRet64rBranchReg { rn: x(30) },
        ];
        let fragment = compile_insns(base_pc, &insns);
        let resume_offset = fragment.offset_for_pc(base_pc + 8).unwrap();
        let mut initial_state = MachineState::new();
        initial_state.write_x(30, 0xfeed_0000);

        let mut stepped_runtime = URuntime::new(fragment, initial_state.clone());
        let stepped_report = {
            let mut stepper = URuntimeStepper::new(&mut stepped_runtime).unwrap();
            let mut saw_svc_continue = false;
            loop {
                let step = stepper.step().unwrap().unwrap();
                if step.runtime_transition
                    == Some(URuntimeTransition::Continued {
                        offset: resume_offset,
                    })
                {
                    saw_svc_continue = true;
                }
                if let Some(halt) = step.halt {
                    assert!(saw_svc_continue);
                    break stepper.report_for_halt(halt);
                }
            }
        };

        let mut direct_runtime = URuntime::new(compile_insns(base_pc, &insns), initial_state);
        let direct_report = direct_runtime.run();

        assert_eq!(stepped_report.state, direct_report.state);
        assert_eq!(stepped_report.halt, direct_report.halt);
    }

    #[test]
    fn svc_runtime_exit_continues_at_original_resume_pc() {
        let base_pc = 0x4000;
        let fragment = compile_insns(
            base_pc,
            &[
                A64Insn::MovzMovz64Movewide {
                    hw: 0,
                    imm16: uimm(172, 16),
                    rd: x(8),
                },
                A64Insn::SvcSvcExException {
                    imm16: A64Imm::unsigned(0, 16),
                },
                A64Insn::MovzMovz64Movewide {
                    hw: 0,
                    imm16: uimm(2, 16),
                    rd: x(2),
                },
                A64Insn::RetRet64rBranchReg { rn: x(30) },
            ],
        );
        let mut initial_state = MachineState::new();
        initial_state.write_x(30, 0xfeed_0000);

        let mut runtime = URuntime::new(fragment, initial_state);
        let report = runtime.run();

        assert_eq!(report.state.read_x(2), 2);
        assert_eq!(
            report.halt,
            URuntimeHalt::ReturnedToUserspace {
                status: RetStatus::Ret,
                target_pc: 0xfeed_0000
            }
        );
    }

    #[test]
    fn ret_to_unknown_original_pc_returns_to_userspace() {
        let base_pc = 0x5000;
        let fragment = compile_insns(base_pc, &[A64Insn::RetRet64rBranchReg { rn: x(30) }]);
        let mut initial_state = MachineState::new();
        initial_state.write_x(30, 0x7777_0000);

        let mut runtime = URuntime::new(fragment, initial_state);
        let report = runtime.run();

        assert_eq!(
            report.halt,
            URuntimeHalt::ReturnedToUserspace {
                status: RetStatus::Ret,
                target_pc: 0x7777_0000
            }
        );
    }
}
