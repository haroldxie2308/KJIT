use crate::arm64::execute_insn;
use crate::model::MachineState;
use crate::shared::abi::{RetStatus, ABI_LINK_REG, RET_PARAM0_REG, RET_PARAM1_REG, RET_STATUS_REG};
use crate::shared::emit::layout::ExecutionFragment;

pub const DEFAULT_BASE_PC: u64 = 0x400000;
pub const DEFAULT_RETURN_PC: u64 = 0x123456;
pub const DEFAULT_STACK_TOP: u64 = 0x800000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct URuntimeConfig {
    pub base_pc: u64,
    pub return_pc: u64,
    pub stack_top: u64,
}

impl Default for URuntimeConfig {
    fn default() -> Self {
        Self {
            base_pc: DEFAULT_BASE_PC,
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
        if initial_state.sp() == 0 {
            initial_state.set_sp(config.stack_top);
        }
        Self {
            state: initial_state,
            fragment,
            config,
        }
    }

    pub fn run(&mut self) -> URuntimeReport {
        self.state.write_x(ABI_LINK_REG, self.config.return_pc);
        let mut pc = self.config.base_pc + self.fragment.entry_offset as u64;
        let mut steps = 0usize;

        loop {
            if pc == self.config.return_pc {
                match self.handle_runtime_return() {
                    RuntimeAction::ContinueAt(offset) => {
                        if let Err(message) = self.validate_offset(offset) {
                            return self
                                .report(URuntimeHalt::ExecutionError { pc, message }, steps);
                        }
                        self.state.write_x(ABI_LINK_REG, self.config.return_pc);
                        pc = self.config.base_pc + offset as u64;
                    }
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
        let resume_offset = self.emitted_pc_to_offset(param1.wrapping_add(4));

        match status {
            RetStatus::Svc => {
                if let Some(offset) = resume_offset {
                    RuntimeAction::ContinueAt(offset)
                } else {
                    RuntimeAction::Stop(URuntimeHalt::ReturnedToUserspace {
                        status,
                        target_pc: param1.wrapping_add(4),
                    })
                }
            }
            RetStatus::Bl | RetStatus::Blr => {
                self.state.write_x(ABI_LINK_REG, param1.wrapping_add(4));
                self.continue_or_request_translation(status, param0, resume_offset)
            }
            RetStatus::Br => self.continue_or_request_translation(status, param0, resume_offset),
            RetStatus::Ret => {
                if let Some(offset) = self.emitted_pc_to_offset(param0) {
                    RuntimeAction::ContinueAt(offset)
                } else {
                    self.continue_or_request_translation(status, param0, resume_offset)
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
            state: self.state.clone(),
            halt,
            steps,
        }
    }
}

enum RuntimeAction {
    ContinueAt(usize),
    Stop(URuntimeHalt),
}
