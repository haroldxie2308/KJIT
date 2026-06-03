use crate::shared::abi::{
    reg_virt_scratch_gpr, reg_virt_stack_backed_slot_offset, REG_VIRT_SCRATCH_GPR_LIMIT,
    REG_VIRT_STABLE_MAPPED_SP_PHYS_REG, REG_VIRT_STABLE_MAPPED_X29_PHYS_REG,
    REG_VIRT_STABLE_MAPPED_X29_REG, REG_VIRT_STACK_BACKED_REG_END, REG_VIRT_STACK_BACKED_REG_START,
    RET_PARAM0_REG, RET_PARAM1_REG, RET_STATUS_REG,
};
use crate::shared::arm64::ergo::{ldst64_offset, mem_off, sp, x};
use crate::shared::arm64::{A64Insn, A64OperandRole, A64Reg, A64Reg31Mode, A64RegWidth};
use crate::shared::platform::{SharedAllocError, SharedResult, SharedVec, GFP_KERNEL};
use crate::shared::trans::rephrase::{RephrasedInsn, RephrasedInsnKind, RephrasedProgram};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegVirtError {
    Allocation(SharedAllocError),
    UnexpectedRegVirtHelper {
        pc: u64,
    },
    MissingRegisterAccessor {
        pc: u64,
        insn: &'static str,
        field: &'static str,
    },
    MissingRegisterSetter {
        pc: u64,
        insn: &'static str,
        field: &'static str,
    },
    UnsupportedOperandRole {
        pc: u64,
        insn: &'static str,
        role: A64OperandRole,
    },
    UnsupportedImplicitRegWrite {
        pc: u64,
        insn: &'static str,
        reg: u8,
        width: A64RegWidth,
    },
    TooManyStackBackedRegs {
        pc: u64,
        insn: &'static str,
        limit: usize,
    },
    StackBackedRewriteNotImplemented {
        pc: u64,
        insn: &'static str,
        reg: A64Reg,
    },
    StableMappedRewriteNotImplemented {
        pc: u64,
        insn: &'static str,
        reg: A64Reg,
    },
    RuntimeReservedRegNotPreserved {
        pc: u64,
        insn: &'static str,
        reg: A64Reg,
    },
    UnsupportedStackBackedWriteWidth {
        pc: u64,
        insn: &'static str,
        field: &'static str,
        reg: A64Reg,
        width: A64RegWidth,
    },
    UnsupportedSpOperand {
        pc: u64,
        insn: &'static str,
        field: &'static str,
        reg: A64Reg,
    },
    UnsupportedWritebackMemory {
        pc: u64,
        insn: &'static str,
    },
    UnsupportedPairOp {
        pc: u64,
        insn: &'static str,
    },
    UnsupportedRuntimeExitSource {
        pc: u64,
        insn: &'static str,
        field: &'static str,
        reg: A64Reg,
    },
}

pub fn virtualize_registers(
    mut program: RephrasedProgram,
) -> SharedResult<RephrasedProgram, RegVirtError> {
    for block in program.iter_mut() {
        let original_insns = core::mem::replace(&mut block.insns, SharedVec::new());
        let mut rewritten = SharedVec::with_capacity(original_insns.len(), GFP_KERNEL)
            .map_err(RegVirtError::Allocation)?;

        for insn in &original_insns {
            virtualize_insn(*insn, &mut rewritten)?;
        }

        block.insns = rewritten;
    }

    Ok(program)
}

fn virtualize_insn(
    rephrased: RephrasedInsn,
    out: &mut SharedVec<RephrasedInsn>,
) -> SharedResult<(), RegVirtError> {
    match rephrased.kind {
        kind if kind.is_user_semantic() => rewrite_user_semantic(rephrased, out),
        RephrasedInsnKind::RuntimeExitPayload => {
            validate_runtime_exit_payload(rephrased)?;
            push_rephrased(out, rephrased)
        }
        RephrasedInsnKind::RuntimeExitBranch => push_rephrased(out, rephrased),
        RephrasedInsnKind::RegVirtHelper => Err(RegVirtError::UnexpectedRegVirtHelper {
            pc: rephrased.ori_pc,
        }),
        RephrasedInsnKind::Original | RephrasedInsnKind::UserSynthetic => unreachable!(),
    }
}

fn rewrite_user_semantic(
    rephrased: RephrasedInsn,
    out: &mut SharedVec<RephrasedInsn>,
) -> SharedResult<(), RegVirtError> {
    let plan = RewritePlan::build(rephrased)?;
    let rewritten = plan.rewrite_insn(rephrased)?;

    plan.emit_fills(rephrased.ori_pc, out)?;
    push_rephrased(
        out,
        RephrasedInsn {
            insn: rewritten,
            ..rephrased
        },
    )?;
    plan.emit_spills(rephrased.ori_pc, out)
}

fn push_rephrased(
    out: &mut SharedVec<RephrasedInsn>,
    insn: RephrasedInsn,
) -> SharedResult<(), RegVirtError> {
    out.push(insn, GFP_KERNEL).map_err(RegVirtError::Allocation)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AccessMode {
    Read,
    Write,
    ReadWrite,
}

impl AccessMode {
    const fn reads(self) -> bool {
        matches!(self, Self::Read | Self::ReadWrite)
    }

    const fn writes(self) -> bool {
        matches!(self, Self::Write | Self::ReadWrite)
    }
}

fn access_mode_from_role(role: A64OperandRole) -> Option<(&'static str, A64RegWidth, AccessMode)> {
    match role {
        A64OperandRole::RegRead { field, width } => Some((field, width, AccessMode::Read)),
        A64OperandRole::RegWrite { field, width } => Some((field, width, AccessMode::Write)),
        A64OperandRole::RegReadWrite { field, width } => {
            Some((field, width, AccessMode::ReadWrite))
        }
        A64OperandRole::MemBase { field } => Some((field, A64RegWidth::X64, AccessMode::Read)),
        A64OperandRole::ImplicitRegWrite { .. }
        | A64OperandRole::MemOffset { .. }
        | A64OperandRole::BranchTarget { .. }
        | A64OperandRole::FlagsRead
        | A64OperandRole::FlagsWrite
        | A64OperandRole::ControlFlow
        | A64OperandRole::Memory => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StackRegMapping {
    virt: u8,
    scratch: u8,
    read: bool,
    write: bool,
}

struct RewritePlan {
    pc: u64,
    insn: &'static str,
    stack_backed: [StackRegMapping; REG_VIRT_SCRATCH_GPR_LIMIT],
    stack_backed_len: usize,
    runtime_reserved_write: Option<A64Reg>,
}

impl RewritePlan {
    const fn new(pc: u64, insn: &'static str) -> Self {
        Self {
            pc,
            insn,
            stack_backed: [StackRegMapping {
                virt: 0,
                scratch: 0,
                read: false,
                write: false,
            }; REG_VIRT_SCRATCH_GPR_LIMIT],
            stack_backed_len: 0,
            runtime_reserved_write: None,
        }
    }

    fn build(rephrased: RephrasedInsn) -> SharedResult<Self, RegVirtError> {
        let insn = rephrased.insn;
        let insn_key = insn.key();
        if is_pair_op(insn) {
            return Err(RegVirtError::UnsupportedPairOp {
                pc: rephrased.ori_pc,
                insn: insn_key,
            });
        }
        if is_writeback_memory_op(insn) {
            return Err(RegVirtError::UnsupportedWritebackMemory {
                pc: rephrased.ori_pc,
                insn: insn_key,
            });
        }

        let mut plan = Self::new(rephrased.ori_pc, insn_key);
        for role in insn.operand_roles() {
            match *role {
                A64OperandRole::ImplicitRegWrite { reg, width } => {
                    return Err(RegVirtError::UnsupportedImplicitRegWrite {
                        pc: rephrased.ori_pc,
                        insn: insn_key,
                        reg,
                        width,
                    });
                }
                role => {
                    if let Some((field, width, access)) = access_mode_from_role(role) {
                        plan.add_field_access(rephrased, field, width, access)?;
                    }
                }
            }
        }

        if let Some(reg) = plan.runtime_reserved_write {
            return Err(RegVirtError::RuntimeReservedRegNotPreserved {
                pc: plan.pc,
                insn: plan.insn,
                reg,
            });
        }

        Ok(plan)
    }

    fn add_field_access(
        &mut self,
        rephrased: RephrasedInsn,
        field: &'static str,
        width: A64RegWidth,
        access: AccessMode,
    ) -> SharedResult<(), RegVirtError> {
        let reg = require_reg(rephrased, field)?;
        if access.writes() {
            require_setter(rephrased, field, reg)?;
        }

        match classify_reg(reg) {
            RegClass::Zero | RegClass::Direct => Ok(()),
            RegClass::RuntimeReserved => {
                if access.writes() && self.runtime_reserved_write.is_none() {
                    self.runtime_reserved_write = Some(reg);
                }
                Ok(())
            }
            RegClass::StableMapped | RegClass::Sp => {
                require_setter(rephrased, field, reg)?;
                Ok(())
            }
            RegClass::StackBacked => {
                require_setter(rephrased, field, reg)?;
                if access.writes() && width == A64RegWidth::Unknown {
                    return Err(RegVirtError::UnsupportedStackBackedWriteWidth {
                        pc: rephrased.ori_pc,
                        insn: rephrased.insn.key(),
                        field,
                        reg,
                        width,
                    });
                }
                self.add_stack_backed(reg, access)
            }
        }
    }

    fn add_stack_backed(
        &mut self,
        reg: A64Reg,
        access: AccessMode,
    ) -> SharedResult<(), RegVirtError> {
        for mapping in &mut self.stack_backed[..self.stack_backed_len] {
            if mapping.virt == reg.enc {
                mapping.read |= access.reads();
                mapping.write |= access.writes();
                return Ok(());
            }
        }

        if self.stack_backed_len == REG_VIRT_SCRATCH_GPR_LIMIT {
            return Err(RegVirtError::TooManyStackBackedRegs {
                pc: self.pc,
                insn: self.insn,
                limit: REG_VIRT_SCRATCH_GPR_LIMIT,
            });
        }

        let scratch = reg_virt_scratch_gpr(self.stack_backed_len).ok_or(
            RegVirtError::TooManyStackBackedRegs {
                pc: self.pc,
                insn: self.insn,
                limit: REG_VIRT_SCRATCH_GPR_LIMIT,
            },
        )?;
        self.stack_backed[self.stack_backed_len] = StackRegMapping {
            virt: reg.enc,
            scratch,
            read: access.reads(),
            write: access.writes(),
        };
        self.stack_backed_len += 1;
        Ok(())
    }

    fn rewrite_insn(&self, rephrased: RephrasedInsn) -> SharedResult<A64Insn, RegVirtError> {
        let mut rewritten = rephrased.insn;
        for role in rephrased.insn.operand_roles() {
            let Some((field, _, _)) = access_mode_from_role(*role) else {
                continue;
            };
            let reg = require_reg(rephrased, field)?;
            let Some(physical) = self.physical_reg(reg) else {
                continue;
            };
            rewritten = rewritten.set_reg(field, physical).map_err(|_| {
                RegVirtError::MissingRegisterSetter {
                    pc: rephrased.ori_pc,
                    insn: rephrased.insn.key(),
                    field,
                }
            })?;
        }
        Ok(rewritten)
    }

    fn physical_reg(&self, reg: A64Reg) -> Option<A64Reg> {
        match classify_reg(reg) {
            RegClass::StackBacked => self
                .stack_mapping(reg.enc)
                .map(|mapping| A64Reg::new(mapping.scratch, reg.width, A64Reg31Mode::Xzr)),
            RegClass::StableMapped => Some(A64Reg::new(
                REG_VIRT_STABLE_MAPPED_X29_PHYS_REG,
                reg.width,
                A64Reg31Mode::Xzr,
            )),
            RegClass::Sp => Some(A64Reg::new(
                REG_VIRT_STABLE_MAPPED_SP_PHYS_REG,
                reg.width,
                A64Reg31Mode::Xzr,
            )),
            RegClass::Zero | RegClass::Direct | RegClass::RuntimeReserved => None,
        }
    }

    fn stack_mapping(&self, reg: u8) -> Option<StackRegMapping> {
        self.stack_backed[..self.stack_backed_len]
            .iter()
            .copied()
            .find(|mapping| mapping.virt == reg)
    }

    fn emit_fills(
        &self,
        ori_pc: u64,
        out: &mut SharedVec<RephrasedInsn>,
    ) -> SharedResult<(), RegVirtError> {
        for mapping in &self.stack_backed[..self.stack_backed_len] {
            if mapping.read {
                push_rephrased(
                    out,
                    RephrasedInsn::reg_virt_helper(ori_pc, self.load_slot(*mapping)?),
                )?;
            }
        }
        Ok(())
    }

    fn emit_spills(
        &self,
        ori_pc: u64,
        out: &mut SharedVec<RephrasedInsn>,
    ) -> SharedResult<(), RegVirtError> {
        for mapping in &self.stack_backed[..self.stack_backed_len] {
            if mapping.write {
                push_rephrased(
                    out,
                    RephrasedInsn::reg_virt_helper(ori_pc, self.store_slot(*mapping)?),
                )?;
            }
        }
        Ok(())
    }

    fn load_slot(&self, mapping: StackRegMapping) -> SharedResult<A64Insn, RegVirtError> {
        let offset = self.stack_slot_offset(mapping)?;
        Ok(A64Insn::LdrImmGenLdr64LdstPos {
            rt: x(mapping.scratch),
            mem: mem_off(sp(), ldst64_offset(offset)),
        })
    }

    fn store_slot(&self, mapping: StackRegMapping) -> SharedResult<A64Insn, RegVirtError> {
        let offset = self.stack_slot_offset(mapping)?;
        Ok(A64Insn::StrImmGenStr64LdstPos {
            rt: x(mapping.scratch),
            mem: mem_off(sp(), ldst64_offset(offset)),
        })
    }

    fn stack_slot_offset(&self, mapping: StackRegMapping) -> SharedResult<u32, RegVirtError> {
        reg_virt_stack_backed_slot_offset(mapping.virt).ok_or(
            RegVirtError::StackBackedRewriteNotImplemented {
                pc: self.pc,
                insn: self.insn,
                reg: x(mapping.virt),
            },
        )
    }
}

fn validate_runtime_exit_payload(rephrased: RephrasedInsn) -> SharedResult<(), RegVirtError> {
    let insn = rephrased.insn;
    for role in insn.operand_roles() {
        match *role {
            A64OperandRole::RegRead { field, .. } => {
                let reg = require_reg(rephrased, field)?;
                if runtime_field_is_owned_by_payload(insn, field, reg) || is_zero_reg(reg) {
                    continue;
                }
                if !classify_reg(reg).is_direct() {
                    return Err(RegVirtError::UnsupportedRuntimeExitSource {
                        pc: rephrased.ori_pc,
                        insn: insn.key(),
                        field,
                        reg,
                    });
                }
            }
            A64OperandRole::RegReadWrite { field, .. } => {
                let reg = require_reg(rephrased, field)?;
                if !runtime_field_is_owned_by_payload(insn, field, reg) {
                    return Err(RegVirtError::UnsupportedRuntimeExitSource {
                        pc: rephrased.ori_pc,
                        insn: insn.key(),
                        field,
                        reg,
                    });
                }
            }
            A64OperandRole::RegWrite { field, .. } => {
                require_reg(rephrased, field)?;
            }
            A64OperandRole::ImplicitRegWrite { reg, width } => {
                return Err(RegVirtError::UnsupportedImplicitRegWrite {
                    pc: rephrased.ori_pc,
                    insn: insn.key(),
                    reg,
                    width,
                });
            }
            A64OperandRole::MemBase { field } => {
                let reg = require_reg(rephrased, field)?;
                if !classify_reg(reg).is_direct() {
                    return Err(RegVirtError::UnsupportedRuntimeExitSource {
                        pc: rephrased.ori_pc,
                        insn: insn.key(),
                        field,
                        reg,
                    });
                }
            }
            A64OperandRole::MemOffset { .. }
            | A64OperandRole::BranchTarget { .. }
            | A64OperandRole::FlagsRead
            | A64OperandRole::FlagsWrite
            | A64OperandRole::ControlFlow
            | A64OperandRole::Memory => {}
        }
    }
    Ok(())
}

fn require_reg(
    rephrased: RephrasedInsn,
    field: &'static str,
) -> SharedResult<A64Reg, RegVirtError> {
    rephrased
        .insn
        .get_reg(field)
        .ok_or(RegVirtError::MissingRegisterAccessor {
            pc: rephrased.ori_pc,
            insn: rephrased.insn.key(),
            field,
        })
}

fn require_setter(
    rephrased: RephrasedInsn,
    field: &'static str,
    reg: A64Reg,
) -> SharedResult<(), RegVirtError> {
    rephrased.insn.set_reg(field, reg).map(|_| ()).map_err(|_| {
        RegVirtError::MissingRegisterSetter {
            pc: rephrased.ori_pc,
            insn: rephrased.insn.key(),
            field,
        }
    })
}

fn runtime_field_is_owned_by_payload(insn: A64Insn, field: &'static str, reg: A64Reg) -> bool {
    is_runtime_return_reg(reg) && field_has_write_role(insn, field)
}

fn field_has_write_role(insn: A64Insn, field: &'static str) -> bool {
    insn.operand_roles().iter().any(|role| {
        matches!(
            *role,
            A64OperandRole::RegWrite { field: role_field, .. }
                | A64OperandRole::RegReadWrite { field: role_field, .. }
                if role_field == field
        )
    })
}

fn is_runtime_return_reg(reg: A64Reg) -> bool {
    reg.enc == RET_STATUS_REG || reg.enc == RET_PARAM0_REG || reg.enc == RET_PARAM1_REG
}

fn is_zero_reg(reg: A64Reg) -> bool {
    reg.enc == 31 && reg.reg31 != crate::shared::arm64::A64Reg31Mode::Sp
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RegClass {
    Zero,
    Direct,
    RuntimeReserved,
    StackBacked,
    StableMapped,
    Sp,
}

impl RegClass {
    const fn is_direct(self) -> bool {
        matches!(self, Self::Zero | Self::Direct)
    }
}

fn classify_reg(reg: A64Reg) -> RegClass {
    if reg.enc == 31 {
        if reg.reg31 == crate::shared::arm64::A64Reg31Mode::Sp {
            return RegClass::Sp;
        }
        return RegClass::Zero;
    }
    if is_runtime_return_reg(reg) {
        return RegClass::RuntimeReserved;
    }
    if (REG_VIRT_STACK_BACKED_REG_START..=REG_VIRT_STACK_BACKED_REG_END).contains(&reg.enc) {
        return RegClass::StackBacked;
    }
    if reg.enc == REG_VIRT_STABLE_MAPPED_X29_REG {
        return RegClass::StableMapped;
    }
    RegClass::Direct
}

fn is_writeback_memory_op(insn: A64Insn) -> bool {
    matches!(
        insn,
        A64Insn::LdrImmGenLdr32LdstImmpost { .. }
            | A64Insn::LdrImmGenLdr64LdstImmpost { .. }
            | A64Insn::LdrImmGenLdr32LdstImmpre { .. }
            | A64Insn::LdrImmGenLdr64LdstImmpre { .. }
            | A64Insn::StrImmGenStr32LdstImmpost { .. }
            | A64Insn::StrImmGenStr64LdstImmpost { .. }
            | A64Insn::StrImmGenStr32LdstImmpre { .. }
            | A64Insn::StrImmGenStr64LdstImmpre { .. }
    )
}

fn is_pair_op(insn: A64Insn) -> bool {
    matches!(
        insn,
        A64Insn::LdpGenLdp64LdstpairPost { .. }
            | A64Insn::LdpGenLdp64LdstpairPre { .. }
            | A64Insn::LdpGenLdp64LdstpairOff { .. }
            | A64Insn::StpGenStp64LdstpairPost { .. }
            | A64Insn::StpGenStp64LdstpairPre { .. }
            | A64Insn::StpGenStp64LdstpairOff { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::arm64::ergo::{uimm, x, xzr};
    use crate::shared::arm64::{A64Imm, A64Mem, A64Reg31Mode};
    use crate::shared::platform::{SharedVec, GFP_KERNEL};
    use crate::shared::trans::rephrase::{RephrasedBlock, RephrasedInsn};

    fn one_insn(insn: RephrasedInsn) -> RephrasedProgram {
        let mut insns = SharedVec::new();
        insns.push(insn, GFP_KERNEL).unwrap();
        let mut program = SharedVec::new();
        program
            .push(
                RephrasedBlock {
                    start_addr: insn.ori_pc,
                    end_addr: insn.ori_pc + 4,
                    prev: SharedVec::new(),
                    next: SharedVec::new(),
                    insns,
                },
                GFP_KERNEL,
            )
            .unwrap();
        program
    }

    fn validate_one(insn: RephrasedInsn) -> Result<RephrasedProgram, RegVirtError> {
        virtualize_registers(one_insn(insn))
    }

    fn movz(rd: A64Reg) -> A64Insn {
        A64Insn::MovzMovz64Movewide {
            hw: 0,
            imm16: uimm(1, 16),
            rd,
        }
    }

    fn frame_slot(offset_bytes: u32) -> A64Mem {
        A64Mem::offset(
            A64Reg::x_sp(31),
            A64Imm::scaled_unsigned(offset_bytes / 8, 12, 3),
        )
    }

    #[test]
    fn direct_user_semantic_registers_pass_validation() {
        let program = validate_one(RephrasedInsn::original(
            0x1000,
            A64Insn::AddAddsubImmAdd64AddsubImm {
                sh: 0,
                imm12: uimm(1, 12),
                rn: x(1),
                rd: x(2),
            },
        ))
        .unwrap();

        assert_eq!(
            program[0].insns[0].insn.key(),
            "ADD_addsub_imm.ADD_64_addsub_imm"
        );
    }

    #[test]
    fn runtime_payload_can_write_return_channel_registers() {
        validate_one(RephrasedInsn::runtime_exit_payload(0x1000, movz(x(9)))).unwrap();
    }

    #[test]
    fn rejects_user_semantic_runtime_reserved_registers_until_preserved() {
        assert_eq!(
            validate_one(RephrasedInsn::original(0x1000, movz(x(9)))),
            Err(RegVirtError::RuntimeReservedRegNotPreserved {
                pc: 0x1000,
                insn: "MOVZ.MOVZ_64_movewide",
                reg: x(9),
            })
        );
    }

    #[test]
    fn stack_backed_write_spills_to_frame_slot() {
        let program = validate_one(RephrasedInsn::original(0x1000, movz(x(12)))).unwrap();

        assert_eq!(
            &program[0].insns[..],
            [
                RephrasedInsn::original(0x1000, movz(x(12))),
                RephrasedInsn::reg_virt_helper(
                    0x1000,
                    A64Insn::StrImmGenStr64LdstPos {
                        rt: x(12),
                        mem: frame_slot(16),
                    },
                ),
            ]
        );
    }

    #[test]
    fn stack_backed_read_fills_from_frame_slot() {
        let original = A64Insn::StrImmGenStr64LdstPos {
            rt: x(12),
            mem: A64Mem::offset(x(1), A64Imm::scaled_unsigned(0, 12, 3)),
        };
        let program = validate_one(RephrasedInsn::original(0x1000, original)).unwrap();

        assert_eq!(
            &program[0].insns[..],
            [
                RephrasedInsn::reg_virt_helper(
                    0x1000,
                    A64Insn::LdrImmGenLdr64LdstPos {
                        rt: x(12),
                        mem: frame_slot(16),
                    },
                ),
                RephrasedInsn::original(0x1000, original),
            ]
        );
    }

    #[test]
    fn stack_backed_registers_without_current_physical_shadow_use_scratch() {
        let program = validate_one(RephrasedInsn::original(
            0x1000,
            A64Insn::OrrLogShiftOrr64LogShift {
                shift: 0,
                rm: x(16),
                imm6: uimm(0, 6),
                rn: xzr(),
                rd: x(0),
            },
        ))
        .unwrap();

        assert_eq!(
            &program[0].insns[..],
            [
                RephrasedInsn::reg_virt_helper(
                    0x1000,
                    A64Insn::LdrImmGenLdr64LdstPos {
                        rt: x(12),
                        mem: frame_slot(48),
                    },
                ),
                RephrasedInsn::original(
                    0x1000,
                    A64Insn::OrrLogShiftOrr64LogShift {
                        shift: 0,
                        rm: x(12),
                        imm6: uimm(0, 6),
                        rn: xzr(),
                        rd: x(0),
                    },
                ),
            ]
        );
    }

    #[test]
    fn stack_backed_32_bit_writes_spill_zero_extended_physical_register() {
        let program = validate_one(RephrasedInsn::original(
            0x1000,
            A64Insn::MovzMovz32Movewide {
                hw: 0,
                imm16: uimm(1, 16),
                rd: A64Reg::w(12),
            },
        ))
        .unwrap();

        assert_eq!(
            &program[0].insns[..],
            [
                RephrasedInsn::original(
                    0x1000,
                    A64Insn::MovzMovz32Movewide {
                        hw: 0,
                        imm16: uimm(1, 16),
                        rd: A64Reg::w(12),
                    },
                ),
                RephrasedInsn::reg_virt_helper(
                    0x1000,
                    A64Insn::StrImmGenStr64LdstPos {
                        rt: x(12),
                        mem: frame_slot(16),
                    },
                ),
            ]
        );
    }

    #[test]
    fn stable_mapped_x29_rewrites_to_physical_x16() {
        let program = validate_one(RephrasedInsn::original(0x1000, movz(x(29)))).unwrap();

        assert_eq!(
            &program[0].insns[..],
            [RephrasedInsn::original(0x1000, movz(x(16)))]
        );
    }

    #[test]
    fn stable_mapped_sp_rewrites_to_physical_x17() {
        let program = validate_one(RephrasedInsn::original(
            0x1000,
            A64Insn::AddAddsubImmAdd64AddsubImm {
                sh: 0,
                imm12: uimm(1, 12),
                rn: A64Reg::x_sp(31),
                rd: x(0),
            },
        ))
        .unwrap();

        assert_eq!(
            &program[0].insns[..],
            [RephrasedInsn::original(
                0x1000,
                A64Insn::AddAddsubImmAdd64AddsubImm {
                    sh: 0,
                    imm12: uimm(1, 12),
                    rn: A64Reg::new(17, A64RegWidth::X64, A64Reg31Mode::Sp),
                    rd: x(0),
                },
            )]
        );
    }

    #[test]
    fn rejects_pre_and_post_index_memory_until_writeback_ordering_is_defined() {
        assert_eq!(
            validate_one(RephrasedInsn::original(
                0x1000,
                A64Insn::LdrImmGenLdr64LdstImmpost {
                    rt: x(0),
                    mem: A64Mem::post_index(x(1), A64Imm::signed(8, 9)),
                },
            )),
            Err(RegVirtError::UnsupportedWritebackMemory {
                pc: 0x1000,
                insn: "LDR_imm_gen.LDR_64_ldst_immpost",
            })
        );
    }

    #[test]
    fn rejects_pair_ops_until_overlap_policy_is_defined() {
        assert_eq!(
            validate_one(RephrasedInsn::original(
                0x1000,
                A64Insn::StpGenStp64LdstpairOff {
                    rt2: x(1),
                    rt: x(0),
                    mem: A64Mem::offset(x(2), A64Imm::scaled_signed(0, 7, 3)),
                },
            )),
            Err(RegVirtError::UnsupportedPairOp {
                pc: 0x1000,
                insn: "STP_gen.STP_64_ldstpair_off",
            })
        );
    }

    #[test]
    fn rejects_implicit_register_writes_left_on_user_path() {
        assert_eq!(
            validate_one(RephrasedInsn::original(
                0x1000,
                A64Insn::BlBlOnlyBranchImm {
                    imm26: A64Imm::scaled_signed(1, 26, 2),
                },
            )),
            Err(RegVirtError::UnsupportedImplicitRegWrite {
                pc: 0x1000,
                insn: "BL.BL_only_branch_imm",
                reg: 30,
                width: A64RegWidth::X64,
            })
        );
    }

    #[test]
    fn rejects_runtime_exit_sources_that_need_capture() {
        assert_eq!(
            validate_one(RephrasedInsn::runtime_exit_payload(
                0x1000,
                A64Insn::OrrLogShiftOrr64LogShift {
                    shift: 0,
                    rm: x(16),
                    imm6: uimm(0, 6),
                    rn: xzr(),
                    rd: x(10),
                },
            )),
            Err(RegVirtError::UnsupportedRuntimeExitSource {
                pc: 0x1000,
                insn: "ORR_log_shift.ORR_64_log_shift",
                field: "Rm",
                reg: x(16),
            })
        );
    }

    #[test]
    fn rejects_more_than_four_stack_backed_registers() {
        let mut plan = RewritePlan::new(0x1000, "test");
        for reg in 12..=15 {
            plan.add_stack_backed(x(reg), AccessMode::Read).unwrap();
        }

        assert_eq!(
            plan.add_stack_backed(x(16), AccessMode::Read),
            Err(RegVirtError::TooManyStackBackedRegs {
                pc: 0x1000,
                insn: "test",
                limit: REG_VIRT_SCRATCH_GPR_LIMIT,
            })
        );
    }

    #[test]
    fn zero_register_operands_do_not_require_virtualization() {
        validate_one(RephrasedInsn::original(
            0x1000,
            A64Insn::OrrLogShiftOrr64LogShift {
                shift: 0,
                rm: xzr(),
                imm6: uimm(0, 6),
                rn: xzr(),
                rd: x(0),
            },
        ))
        .unwrap();

        assert_eq!(
            classify_reg(A64Reg::new(31, A64RegWidth::X64, A64Reg31Mode::Xzr)),
            RegClass::Zero
        );
    }
}
