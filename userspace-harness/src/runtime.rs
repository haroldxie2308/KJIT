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

#[derive(Debug, PartialEq, Eq)]
pub struct URuntimeReport {
    pub state: MachineState,
    pub halt: URuntimeHalt,
    pub steps: usize,
}

#[derive(Debug, PartialEq, Eq)]
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
        let mut steps = 0usize;
        let mut pc = match self.enter_fragment_at(self.fragment.entry_offset) {
            Ok((pc, prologue_steps)) => {
                steps += prologue_steps;
                pc
            }
            Err(message) => {
                return self.report(
                    URuntimeHalt::ExecutionError {
                        pc: self.config.base_pc,
                        message,
                    },
                    steps,
                );
            }
        };

        loop {
            if pc == self.config.return_pc {
                match self.handle_runtime_return() {
                    RuntimeAction::ContinueAt(offset) => match self.enter_fragment_at(offset) {
                        Ok((next_pc, prologue_steps)) => {
                            steps += prologue_steps;
                            pc = next_pc;
                        }
                        Err(message) => {
                            return self
                                .report(URuntimeHalt::ExecutionError { pc, message }, steps);
                        }
                    },
                    RuntimeAction::Stop(halt) => return self.report(halt, steps),
                }
                continue;
            }

            let Some(index) = self.pc_to_index(pc) else {
                return self.report(URuntimeHalt::FellOffFragment { pc }, steps);
            };

            let insn = self.fragment.insns[index];
            steps += 1;
            match execute_insn(insn, pc, &mut self.state) {
                Ok(next_pc) => pc = next_pc,
                Err(message) => {
                    return self.report(URuntimeHalt::ExecutionError { pc, message }, steps);
                }
            }
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

    fn enter_fragment_at(&mut self, offset: usize) -> Result<(u64, usize), String> {
        self.validate_offset(offset)?;
        let prologue_branch_index = PROLOGUE_ENTRY_BRANCH_OFFSET / 4;
        if self.fragment.insns.len() <= prologue_branch_index {
            return Err("fragment is missing the ABI prologue".to_string());
        }

        self.state
            .write_x(ABI_PT_REGS_ARG_REG, self.config.pt_regs_addr);
        self.state
            .write_x(ABI_EXTRA_PARAMS_ARG_REG, self.config.extra_params_addr);
        self.state.write_x(ABI_LINK_REG, self.config.return_pc);
        self.state.set_sp(self.config.stack_top);

        let mut pc = self.config.base_pc;
        for index in 0..prologue_branch_index {
            pc = execute_insn(self.fragment.insns[index], pc, &mut self.state)?;
        }

        Ok((self.config.base_pc + offset as u64, prologue_branch_index))
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

    fn user_state_from_pt_regs(&self) -> MachineState {
        let ranges = [
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
        ];
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
