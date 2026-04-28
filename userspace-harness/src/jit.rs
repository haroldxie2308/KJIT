use std::collections::BTreeMap;

use crate::ir::{IrInsn, IrInsnKind, IrProgram, LinkSlot};
use crate::model::{ExecutionResult, HaltReason, MachineState};
use crate::trans_core::cfg::RuntimeExitReason;
use crate::trans_core::input::{TranslationRequest, TranslationTrigger};
use crate::trans_core::translate::translate_request;
use crate::MockCodeProvider;

const MAX_JIT_STEPS: usize = 4096;

pub trait SyscallHandler {
    fn handle_svc(&mut self, imm16: u16, state: &mut MachineState) -> Result<(), String>;
}

#[derive(Default)]
pub struct NoopSyscallHandler;

impl SyscallHandler for NoopSyscallHandler {
    fn handle_svc(&mut self, _imm16: u16, _state: &mut MachineState) -> Result<(), String> {
        Ok(())
    }
}

pub struct JitRuntime<H: SyscallHandler> {
    code: MockCodeProvider,
    program: IrProgram,
    entry_by_pc: BTreeMap<u64, usize>,
    ir_index_by_pc: BTreeMap<u64, usize>,
    link_slots: BTreeMap<LinkSlot, usize>,
    next_link_slot: usize,
    syscall_handler: H,
}

impl<H: SyscallHandler> JitRuntime<H> {
    pub fn new(code: MockCodeProvider, syscall_handler: H) -> Self {
        Self {
            code,
            program: Vec::new(),
            entry_by_pc: BTreeMap::new(),
            ir_index_by_pc: BTreeMap::new(),
            link_slots: BTreeMap::new(),
            next_link_slot: 0,
            syscall_handler,
        }
    }

    pub fn execute(
        &mut self,
        entry_pc: u64,
        initial_state: &MachineState,
    ) -> Result<ExecutionResult, String> {
        let mut state = initial_state.clone();
        let mut pc = self.translate_entry(entry_pc)?;
        let mut steps = 0usize;

        loop {
            if steps >= MAX_JIT_STEPS {
                return Ok(ExecutionResult {
                    state,
                    halt_reason: HaltReason::StepLimitExceeded,
                    steps,
                });
            }

            if pc == self.program.len() {
                return Ok(ExecutionResult {
                    state,
                    halt_reason: HaltReason::FellOffEnd,
                    steps,
                });
            }

            let insn = *self
                .program
                .get(pc)
                .ok_or_else(|| format!("JIT IR pc out of range: {pc}"))?;
            steps += 1;

            match insn.kind {
                IrInsnKind::Nop => pc += 1,
                IrInsnKind::LoadImm64 { rd, value } => {
                    state.write_reg(rd, value);
                    pc += 1;
                }
                IrInsnKind::AddImm { rd, rn, imm12 } => {
                    let value = state.read_reg(rn).wrapping_add(imm12 as u64);
                    state.write_reg(rd, value);
                    pc += 1;
                }
                IrInsnKind::AddReg { rd, rn, rm } => {
                    let value = state.read_reg(rn).wrapping_add(state.read_reg(rm));
                    state.write_reg(rd, value);
                    pc += 1;
                }
                IrInsnKind::SubImm { rd, rn, imm12 } => {
                    let value = state.read_reg(rn).wrapping_sub(imm12 as u64);
                    state.write_reg(rd, value);
                    pc += 1;
                }
                IrInsnKind::SubReg { rd, rn, rm } => {
                    let value = state.read_reg(rn).wrapping_sub(state.read_reg(rm));
                    state.write_reg(rd, value);
                    pc += 1;
                }
                IrInsnKind::CmpImm { rn, imm12 } => {
                    let lhs = state.read_reg(rn);
                    let rhs = imm12 as u64;
                    let result = lhs.wrapping_sub(rhs);
                    state.update_sub_flags(lhs, rhs, result);
                    pc += 1;
                }
                IrInsnKind::CmpReg { rn, rm } => {
                    let lhs = state.read_reg(rn);
                    let rhs = state.read_reg(rm);
                    let result = lhs.wrapping_sub(rhs);
                    state.update_sub_flags(lhs, rhs, result);
                    pc += 1;
                }
                IrInsnKind::B { target_pc } => pc = self.resolve_ir_pc(target_pc)?,
                IrInsnKind::BCond { cond, target_pc } => {
                    if crate::ir::eval_condition_for_jit(cond, &state) {
                        pc = self.resolve_ir_pc(target_pc)?;
                    } else {
                        pc += 1;
                    }
                }
                IrInsnKind::Cbz { rt, target_pc } => {
                    if state.read_reg(rt) == 0 {
                        pc = self.resolve_ir_pc(target_pc)?;
                    } else {
                        pc += 1;
                    }
                }
                IrInsnKind::Cbnz { rt, target_pc } => {
                    if state.read_reg(rt) != 0 {
                        pc = self.resolve_ir_pc(target_pc)?;
                    } else {
                        pc += 1;
                    }
                }
                IrInsnKind::StrImm { rt, rn, offset } => {
                    let addr = state.read_reg(rn).wrapping_add(offset as u64);
                    let value = state.read_reg(rt);
                    state.write_u64(addr, value);
                    pc += 1;
                }
                IrInsnKind::LdrImm { rt, rn, offset } => {
                    let addr = state.read_reg(rn).wrapping_add(offset as u64);
                    let value = state.read_u64(addr);
                    state.write_reg(rt, value);
                    pc += 1;
                }
                IrInsnKind::RuntimeExit { slot, reason } => {
                    pc = self.handle_runtime_exit(slot, reason, &mut state)?;
                }
            }
        }
    }

    pub fn is_link_slot_resolved(&self, slot: LinkSlot) -> bool {
        self.link_slots.contains_key(&slot)
    }

    fn handle_runtime_exit(
        &mut self,
        slot: LinkSlot,
        reason: RuntimeExitReason,
        state: &mut MachineState,
    ) -> Result<usize, String> {
        match reason {
            RuntimeExitReason::Svc { imm16, resume_pc } => {
                self.syscall_handler.handle_svc(imm16, state)?;
                self.resolve_or_translate(slot, resume_pc)
            }
            RuntimeExitReason::Bl {
                target_pc,
                resume_pc,
            } => {
                state.write_reg(30, resume_pc);
                self.resolve_or_translate(slot, target_pc)
            }
            RuntimeExitReason::Blr {
                target_reg,
                resume_pc,
            } => {
                state.write_reg(30, resume_pc);
                self.resolve_or_translate(slot, state.read_reg(target_reg))
            }
            RuntimeExitReason::Br { target_reg } => {
                self.resolve_or_translate(slot, state.read_reg(target_reg))
            }
            RuntimeExitReason::Ret { lr_reg } => {
                self.resolve_or_translate(slot, state.read_reg(lr_reg))
            }
            RuntimeExitReason::Unsupported => Err("unsupported runtime exit".to_string()),
        }
    }

    fn resolve_or_translate(&mut self, slot: LinkSlot, target_pc: u64) -> Result<usize, String> {
        if let Some(target) = self.link_slots.get(&slot).copied() {
            return Ok(target);
        }
        let target = self.resolve_ir_pc(target_pc)?;
        self.link_slots.insert(slot, target);
        Ok(target)
    }

    fn resolve_ir_pc(&mut self, target_pc: u64) -> Result<usize, String> {
        if let Some(target) = self.ir_index_by_pc.get(&target_pc).copied() {
            return Ok(target);
        }
        self.translate_entry(target_pc)
    }

    fn translate_entry(&mut self, entry_pc: u64) -> Result<usize, String> {
        if let Some(entry) = self.entry_by_pc.get(&entry_pc).copied() {
            return Ok(entry);
        }

        let request = TranslationRequest {
            entry_pc,
            trigger: TranslationTrigger::BranchDiscovery {
                source_pc: entry_pc,
            },
            regs: None,
        };
        let mut fragment = translate_request(&request, &self.code)?;
        let base = self.program.len();
        let slot_base = self.next_link_slot;
        let slot_count = relocate_fragment(slot_base, &mut fragment);
        self.next_link_slot += slot_count;
        for (offset, insn) in fragment.iter().enumerate() {
            if self.ir_index_by_pc.contains_key(&insn.pc) {
                return Err(format!(
                    "translated fragment overlaps existing pc: {:#x}",
                    insn.pc
                ));
            }
            self.ir_index_by_pc.insert(insn.pc, base + offset);
        }
        self.program.extend(fragment);
        self.entry_by_pc.insert(entry_pc, base);
        Ok(base)
    }
}

fn relocate_fragment(slot_base: usize, fragment: &mut [IrInsn]) -> usize {
    let mut slot_count = 0usize;
    for insn in fragment {
        if let IrInsnKind::RuntimeExit { slot, .. } = &mut insn.kind {
            if slot.0 >= slot_count {
                slot_count = slot.0 + 1;
            }
            slot.0 += slot_base;
        }
    }
    slot_count
}
