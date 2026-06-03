use crate::shared::abi::{
    REG_VIRT_SCRATCH_GPR_LIMIT, REG_VIRT_STABLE_MAPPED_X29_REG, REG_VIRT_STACK_BACKED_REG_END,
    REG_VIRT_STACK_BACKED_REG_START, RET_PARAM0_REG, RET_PARAM1_REG, RET_STATUS_REG,
};
use crate::shared::arm64::{A64Insn, A64OperandRole, A64Reg, A64RegWidth};
use crate::shared::platform::SharedResult;
use crate::shared::trans::rephrase::{RephrasedInsn, RephrasedInsnKind, RephrasedProgram};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegVirtError {
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
    program: RephrasedProgram,
) -> SharedResult<RephrasedProgram, RegVirtError> {
    validate_program(&program)?;
    Ok(program)
}

fn validate_program(program: &RephrasedProgram) -> SharedResult<(), RegVirtError> {
    for block in program {
        for insn in &block.insns {
            validate_insn(*insn)?;
        }
    }
    Ok(())
}

fn validate_insn(rephrased: RephrasedInsn) -> SharedResult<(), RegVirtError> {
    match rephrased.kind {
        kind if kind.is_user_semantic() => validate_user_semantic(rephrased),
        RephrasedInsnKind::RuntimeExitPayload => validate_runtime_exit_payload(rephrased),
        RephrasedInsnKind::RuntimeExitBranch => Ok(()),
        RephrasedInsnKind::RegVirtHelper => Err(RegVirtError::UnexpectedRegVirtHelper {
            pc: rephrased.ori_pc,
        }),
        RephrasedInsnKind::Original | RephrasedInsnKind::UserSynthetic => unreachable!(),
    }
}

fn validate_user_semantic(rephrased: RephrasedInsn) -> SharedResult<(), RegVirtError> {
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

    let mut access = AccessSummary::new(rephrased.ori_pc, insn_key);
    for role in insn.operand_roles() {
        match *role {
            A64OperandRole::RegRead { field, width } => {
                let reg = require_reg(rephrased, field)?;
                validate_user_reg(rephrased, &mut access, field, reg, width, false)?;
            }
            A64OperandRole::RegWrite { field, width } => {
                let reg = require_reg(rephrased, field)?;
                require_setter(rephrased, field, reg)?;
                validate_user_reg(rephrased, &mut access, field, reg, width, true)?;
            }
            A64OperandRole::RegReadWrite { field, width } => {
                let reg = require_reg(rephrased, field)?;
                require_setter(rephrased, field, reg)?;
                validate_user_reg(rephrased, &mut access, field, reg, width, true)?;
            }
            A64OperandRole::ImplicitRegWrite { reg, width } => {
                return Err(RegVirtError::UnsupportedImplicitRegWrite {
                    pc: rephrased.ori_pc,
                    insn: insn_key,
                    reg,
                    width,
                });
            }
            A64OperandRole::MemBase { field } => {
                let reg = require_reg(rephrased, field)?;
                validate_user_reg(rephrased, &mut access, field, reg, A64RegWidth::X64, false)?;
            }
            A64OperandRole::MemOffset { .. }
            | A64OperandRole::BranchTarget { .. }
            | A64OperandRole::FlagsRead
            | A64OperandRole::FlagsWrite
            | A64OperandRole::ControlFlow
            | A64OperandRole::Memory => {}
        }
    }

    access.reject_unimplemented_virtual_regs()
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

fn validate_user_reg(
    rephrased: RephrasedInsn,
    access: &mut AccessSummary,
    field: &'static str,
    reg: A64Reg,
    width: A64RegWidth,
    is_write: bool,
) -> SharedResult<(), RegVirtError> {
    match classify_reg(reg) {
        RegClass::Zero | RegClass::Direct => Ok(()),
        RegClass::Sp => Err(RegVirtError::UnsupportedSpOperand {
            pc: rephrased.ori_pc,
            insn: rephrased.insn.key(),
            field,
            reg,
        }),
        RegClass::RuntimeReserved => {
            access.add_runtime_reserved(reg);
            Ok(())
        }
        RegClass::StableMapped => {
            access.add_stable_mapped(reg);
            Ok(())
        }
        RegClass::StackBacked => {
            access.add_stack_backed(reg)?;
            if is_write && width != A64RegWidth::X64 {
                return Err(RegVirtError::UnsupportedStackBackedWriteWidth {
                    pc: rephrased.ori_pc,
                    insn: rephrased.insn.key(),
                    field,
                    reg,
                    width,
                });
            }
            if is_write || reg.enc >= 16 {
                access.add_stack_backed_rewrite_required(reg);
            }
            Ok(())
        }
    }
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

struct AccessSummary {
    pc: u64,
    insn: &'static str,
    stack_backed: [u8; REG_VIRT_SCRATCH_GPR_LIMIT],
    stack_backed_len: usize,
    stack_backed_rewrite_required: Option<A64Reg>,
    runtime_reserved: Option<A64Reg>,
    stable_mapped: Option<A64Reg>,
}

impl AccessSummary {
    const fn new(pc: u64, insn: &'static str) -> Self {
        Self {
            pc,
            insn,
            stack_backed: [0; REG_VIRT_SCRATCH_GPR_LIMIT],
            stack_backed_len: 0,
            stack_backed_rewrite_required: None,
            runtime_reserved: None,
            stable_mapped: None,
        }
    }

    fn add_stack_backed(&mut self, reg: A64Reg) -> SharedResult<(), RegVirtError> {
        if self.stack_backed[..self.stack_backed_len].contains(&reg.enc) {
            return Ok(());
        }
        if self.stack_backed_len == REG_VIRT_SCRATCH_GPR_LIMIT {
            return Err(RegVirtError::TooManyStackBackedRegs {
                pc: self.pc,
                insn: self.insn,
                limit: REG_VIRT_SCRATCH_GPR_LIMIT,
            });
        }
        self.stack_backed[self.stack_backed_len] = reg.enc;
        self.stack_backed_len += 1;
        Ok(())
    }

    fn add_stack_backed_rewrite_required(&mut self, reg: A64Reg) {
        if self.stack_backed_rewrite_required.is_none() {
            self.stack_backed_rewrite_required = Some(reg);
        }
    }

    fn add_runtime_reserved(&mut self, reg: A64Reg) {
        if self.runtime_reserved.is_none() {
            self.runtime_reserved = Some(reg);
        }
    }

    fn add_stable_mapped(&mut self, reg: A64Reg) {
        if self.stable_mapped.is_none() {
            self.stable_mapped = Some(reg);
        }
    }

    fn reject_unimplemented_virtual_regs(self) -> SharedResult<(), RegVirtError> {
        if let Some(reg) = self.runtime_reserved {
            return Err(RegVirtError::RuntimeReservedRegNotPreserved {
                pc: self.pc,
                insn: self.insn,
                reg,
            });
        }
        if let Some(reg) = self.stack_backed_rewrite_required {
            return Err(RegVirtError::StackBackedRewriteNotImplemented {
                pc: self.pc,
                insn: self.insn,
                reg,
            });
        }
        if let Some(reg) = self.stable_mapped {
            return Err(RegVirtError::StableMappedRewriteNotImplemented {
                pc: self.pc,
                insn: self.insn,
                reg,
            });
        }
        Ok(())
    }
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
    fn rejects_stack_backed_registers_until_rewrite_templates_exist() {
        assert_eq!(
            validate_one(RephrasedInsn::original(0x1000, movz(x(12)))),
            Err(RegVirtError::StackBackedRewriteNotImplemented {
                pc: 0x1000,
                insn: "MOVZ.MOVZ_64_movewide",
                reg: x(12),
            })
        );
    }

    #[test]
    fn read_only_shadowed_stack_backed_registers_pass_for_current_no_helper_path() {
        validate_one(RephrasedInsn::original(
            0x1000,
            A64Insn::StrImmGenStr64LdstPos {
                rt: x(12),
                mem: A64Mem::offset(x(1), A64Imm::scaled_unsigned(0, 12, 3)),
            },
        ))
        .unwrap();
    }

    #[test]
    fn rejects_stack_backed_registers_without_current_physical_shadow() {
        assert_eq!(
            validate_one(RephrasedInsn::original(
                0x1000,
                A64Insn::OrrLogShiftOrr64LogShift {
                    shift: 0,
                    rm: x(16),
                    imm6: uimm(0, 6),
                    rn: xzr(),
                    rd: x(0),
                },
            )),
            Err(RegVirtError::StackBackedRewriteNotImplemented {
                pc: 0x1000,
                insn: "ORR_log_shift.ORR_64_log_shift",
                reg: x(16),
            })
        );
    }

    #[test]
    fn rejects_32_bit_writes_to_stack_backed_registers() {
        assert_eq!(
            validate_one(RephrasedInsn::original(
                0x1000,
                A64Insn::MovzMovz32Movewide {
                    hw: 0,
                    imm16: uimm(1, 16),
                    rd: A64Reg::w(12),
                },
            )),
            Err(RegVirtError::UnsupportedStackBackedWriteWidth {
                pc: 0x1000,
                insn: "MOVZ.MOVZ_32_movewide",
                field: "Rd",
                reg: A64Reg::w(12),
                width: A64RegWidth::W32,
            })
        );
    }

    #[test]
    fn rejects_stable_mapped_x29_until_rewrite_templates_exist() {
        assert_eq!(
            validate_one(RephrasedInsn::original(0x1000, movz(x(29)))),
            Err(RegVirtError::StableMappedRewriteNotImplemented {
                pc: 0x1000,
                insn: "MOVZ.MOVZ_64_movewide",
                reg: x(29),
            })
        );
    }

    #[test]
    fn rejects_sp_operands_until_stable_mapping_is_implemented() {
        assert_eq!(
            validate_one(RephrasedInsn::original(
                0x1000,
                A64Insn::AddAddsubImmAdd64AddsubImm {
                    sh: 0,
                    imm12: uimm(1, 12),
                    rn: A64Reg::x_sp(31),
                    rd: x(0),
                },
            )),
            Err(RegVirtError::UnsupportedSpOperand {
                pc: 0x1000,
                insn: "ADD_addsub_imm.ADD_64_addsub_imm",
                field: "Rn",
                reg: A64Reg::x_sp(31),
            })
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
        let mut access = AccessSummary::new(0x1000, "test");
        for reg in 12..=15 {
            access.add_stack_backed(x(reg)).unwrap();
        }

        assert_eq!(
            access.add_stack_backed(x(16)),
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
