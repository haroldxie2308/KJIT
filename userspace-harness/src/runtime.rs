use crate::arm64::execute_insn;
use crate::model::MachineState;
use crate::shared::arm64::A64Insn;
use crate::shared::utils::vlabel::VLabels;

pub const DEFAULT_BASE_PC: u64 = 0x400000;
pub const DEFAULT_RETURN_PC: u64 = 0x123456;

const RET_STATUS_REG: u8 = 9;
const RET_PARAM0_REG: u8 = 10;
const RET_PARAM1_REG: u8 = 11;
const LR_REG: u8 = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum URetStatus {
    Svc,
    Bl,
    Blr,
    Br,
    Ret,
    Mem,
    Debug,
    Invalid(u64),
}

impl URetStatus {
    pub fn from_reg(value: u64) -> Self {
        match value & 0xFFFF {
            0 => Self::Svc,
            1 => Self::Bl,
            2 => Self::Blr,
            3 => Self::Br,
            4 => Self::Ret,
            5 => Self::Mem,
            8 => Self::Debug,
            other => Self::Invalid(other),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct UFragment {
    pub insns: Vec<A64Insn>,
    pub vlabels: VLabels,
}

impl UFragment {
    pub fn new(insns: Vec<A64Insn>, vlabels: VLabels) -> Self {
        Self { insns, vlabels }
    }

    pub fn len_bytes(&self) -> usize {
        self.insns.len() * 4
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct URuntimeConfig {
    pub base_pc: u64,
    pub return_pc: u64,
    pub prologue_branch_index: Option<usize>,
}

impl Default for URuntimeConfig {
    fn default() -> Self {
        Self {
            base_pc: DEFAULT_BASE_PC,
            return_pc: DEFAULT_RETURN_PC,
            prologue_branch_index: None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct URuntime {
    pub state: MachineState,
    pub fragment: UFragment,
    pub config: URuntimeConfig,
    entry_offset: usize,
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
        status: URetStatus,
        target_pc: u64,
        resume_offset: Option<usize>,
    },
    ReturnedToUserspace {
        status: URetStatus,
        target_pc: u64,
    },
    InvalidReturnStatus {
        raw: u64,
    },
    UnsupportedRuntimeExit {
        status: URetStatus,
    },
    ExecutionError {
        pc: u64,
        message: String,
    },
}

impl URuntime {
    pub fn new(fragment: UFragment, initial_state: MachineState) -> Self {
        Self::with_config(fragment, initial_state, URuntimeConfig::default())
    }

    pub fn with_config(
        fragment: UFragment,
        initial_state: MachineState,
        config: URuntimeConfig,
    ) -> Self {
        Self {
            state: initial_state,
            fragment,
            config,
            entry_offset: 0,
        }
    }

    pub fn set_entry_offset(&mut self, offset: usize) -> Result<(), String> {
        self.select_entry_offset(offset)
    }

    pub fn run(&mut self) -> URuntimeReport {
        self.state.write_reg(LR_REG, self.config.return_pc);
        let mut pc = self.config.base_pc + self.entry_offset as u64;
        let mut steps = 0usize;

        loop {
            if pc == self.config.return_pc {
                match self.handle_runtime_return() {
                    RuntimeAction::ContinueAt(offset) => {
                        if let Err(message) = self.select_entry_offset(offset) {
                            return self
                                .report(URuntimeHalt::ExecutionError { pc, message }, steps);
                        }
                        self.state.write_reg(LR_REG, self.config.return_pc);
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
                    return self.report(URuntimeHalt::ExecutionError { pc, message }, steps)
                }
            }
        }
    }

    fn handle_runtime_return(&mut self) -> RuntimeAction {
        let raw_status = self.state.read_reg(RET_STATUS_REG);
        let status = URetStatus::from_reg(raw_status);
        let param0 = self.state.read_reg(RET_PARAM0_REG);
        let param1 = self.state.read_reg(RET_PARAM1_REG);
        let resume_offset = self.emitted_pc_to_offset(param1.wrapping_add(4));

        match status {
            URetStatus::Svc => {
                if let Some(offset) = resume_offset {
                    RuntimeAction::ContinueAt(offset)
                } else {
                    RuntimeAction::Stop(URuntimeHalt::ReturnedToUserspace {
                        status,
                        target_pc: param1.wrapping_add(4),
                    })
                }
            }
            URetStatus::Bl | URetStatus::Blr => {
                self.state.write_reg(LR_REG, param1.wrapping_add(4));
                self.continue_or_request_translation(status, param0, resume_offset)
            }
            URetStatus::Br => self.continue_or_request_translation(status, param0, resume_offset),
            URetStatus::Ret => {
                if let Some(offset) = self.emitted_pc_to_offset(param0) {
                    RuntimeAction::ContinueAt(offset)
                } else {
                    self.continue_or_request_translation(status, param0, resume_offset)
                }
            }
            URetStatus::Invalid(_) => {
                RuntimeAction::Stop(URuntimeHalt::InvalidReturnStatus { raw: raw_status })
            }
            URetStatus::Mem | URetStatus::Debug => {
                RuntimeAction::Stop(URuntimeHalt::UnsupportedRuntimeExit { status })
            }
        }
    }

    fn continue_or_request_translation(
        &self,
        status: URetStatus,
        target_pc: u64,
        resume_offset: Option<usize>,
    ) -> RuntimeAction {
        if let Some(offset) = self.fragment.vlabels.offset_for_pc(target_pc) {
            RuntimeAction::ContinueAt(offset)
        } else {
            RuntimeAction::Stop(URuntimeHalt::NeedsTranslation {
                status,
                target_pc,
                resume_offset,
            })
        }
    }

    fn select_entry_offset(&mut self, offset: usize) -> Result<(), String> {
        if offset % 4 != 0 || offset >= self.fragment.len_bytes() {
            return Err(format!("invalid runtime entry offset: {offset:#x}"));
        }
        self.entry_offset = offset;

        if let Some(index) = self.config.prologue_branch_index {
            self.patch_prologue_branch(index, offset)?;
        }
        Ok(())
    }

    fn patch_prologue_branch(&mut self, index: usize, target_offset: usize) -> Result<(), String> {
        if index >= self.fragment.insns.len() {
            return Err(format!("invalid prologue branch index: {index}"));
        }
        let branch_pc = self.config.base_pc + (index * 4) as u64;
        let target_pc = self.config.base_pc + target_offset as u64;
        let delta = target_pc as i128 - branch_pc as i128;
        if delta % 4 != 0 {
            return Err(format!(
                "unaligned branch target offset: {target_offset:#x}"
            ));
        }
        let imm = delta / 4;
        let min = -(1_i128 << 25);
        let max = (1_i128 << 25) - 1;
        if !(min..=max).contains(&imm) {
            return Err(format!(
                "prologue branch target out of range: {target_offset:#x}"
            ));
        }

        self.fragment.insns[index] = A64Insn::BUncondBOnlyBranchImm {
            imm26: (imm & ((1_i128 << 26) - 1)) as u32,
        };
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
