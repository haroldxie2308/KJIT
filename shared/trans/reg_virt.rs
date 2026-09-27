use crate::shared::abi::{
    pt_regs_x_slot_offset, reg_virt_scratch_gpr, reg_virt_stack_backed_slot_offset,
    PAN_WINDOW_RANGE_TOP_BIT, REG_VIRT_SCRATCH_GPR_LIMIT, REG_VIRT_STABLE_MAPPED_SP_PHYS_REG,
    REG_VIRT_STABLE_MAPPED_X29_PHYS_REG, REG_VIRT_STABLE_MAPPED_X29_REG,
    REG_VIRT_STACK_BACKED_REG_END, REG_VIRT_STACK_BACKED_REG_START, RET_PARAM0_REG, RET_PARAM1_REG,
    RET_STATUS_REG, RUNTIME_FRAME_PT_REGS_PTR_OFFSET, USER_VA_BITS,
};
use crate::shared::arm64::ergo::{ldst64_offset, mem_off, scaled_simm, simm, sp, uimm, x, xzr};
use crate::shared::arm64::{
    A64Atomic, A64Insn, A64Mem, A64OperandRole, A64Reg, A64Reg31Mode, A64RegWidth, IrInsn,
};
use crate::shared::platform::{SharedAllocError, SharedResult, SharedVec, GFP_KERNEL};
use crate::shared::trans::rephrase::{
    atomic_needs_check_stub, rephrase_insn, RephrasedInsn, RephrasedInsnKind, RephrasedProgram,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegVirtError {
    Allocation(SharedAllocError),
    UnexpectedRegVirtHelper {
        pc: u64,
    },
    MalformedRuntimeExitGroup {
        pc: u64,
    },
    RuntimeExitPcMismatch {
        expected_pc: u64,
        actual_pc: u64,
    },
    MultipleRuntimeExitParam0Captures {
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
    ScratchPoolExhausted {
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
    UnpredictableMemoryOp {
        pc: u64,
        insn: &'static str,
    },
    UnsupportedRuntimeExitSource {
        pc: u64,
        insn: &'static str,
        field: &'static str,
        reg: A64Reg,
    },
    /// User code containing `LDTR`/`STTR`. Their EL0 semantics differ from the
    /// fragment's (which runs them at EL1 as the user-access instruction), so they
    /// are never translated.
    UnprivilegedUserAccess {
        pc: u64,
        insn: &'static str,
    },
    /// A memory offset the ADD/SUB (imm, optional `lsl #12`) pair cannot materialize.
    UnencodableMemOffset {
        pc: u64,
        insn: &'static str,
        offset: i64,
    },
    /// Generated metadata says the form accesses memory but reg-virt has no lowering
    /// for it: a new memory form was added to the subset without one.
    UnloweredMemoryForm {
        pc: u64,
        insn: &'static str,
    },
    /// User code containing `MSR PAN, #imm` (A8). At EL0 it is UNDEFINED natively;
    /// in a fragment it would change the kernel's PSTATE.PAN. Only the translator
    /// emits it (the PAN window), so it is never translated.
    PanUserForm {
        pc: u64,
        insn: &'static str,
    },
}

impl RegVirtError {
    /// `true`: the rejection is a property of the user instruction and its registers,
    /// so executing it natively in userspace (an Unsupported exit) is exact.
    /// `false`: a bug in rephrase, generated metadata, or ABI tables; must fail hard.
    pub const fn is_instruction_intrinsic(&self) -> bool {
        match self {
            Self::UnpredictableMemoryOp { .. }
            | Self::ScratchPoolExhausted { .. }
            | Self::UnprivilegedUserAccess { .. }
            | Self::PanUserForm { .. }
            | Self::UnencodableMemOffset { .. }
            | Self::UnsupportedImplicitRegWrite { .. }
            | Self::UnsupportedStackBackedWriteWidth { .. }
            | Self::UnsupportedSpOperand { .. }
            | Self::StableMappedRewriteNotImplemented { .. }
            | Self::UnsupportedOperandRole { .. } => true,
            Self::Allocation(_)
            | Self::UnexpectedRegVirtHelper { .. }
            | Self::MalformedRuntimeExitGroup { .. }
            | Self::RuntimeExitPcMismatch { .. }
            | Self::MultipleRuntimeExitParam0Captures { .. }
            | Self::MissingRegisterAccessor { .. }
            | Self::MissingRegisterSetter { .. }
            | Self::UnloweredMemoryForm { .. }
            // Only raised when an ABI slot table has no entry for a register that
            // `classify_reg` already mapped (or for the fixed x9-x11): table mismatch.
            | Self::StackBackedRewriteNotImplemented { .. }
            // Payload sources are synthesized by rephrase; the one user-chosen source
            // (the param0 capture) accepts every register class and is never validated.
            | Self::UnsupportedRuntimeExitSource { .. } => false,
        }
    }
}

/// Admission check for one decoded instruction, run by `build_cfg` before the
/// instruction joins a block. It applies `RewritePlan::build` -- the same check
/// `rewrite_user_semantic` runs -- to every user-semantic instruction rephrase
/// lowers `insn` into, so admission and rewriting cannot drift. Invariant: reg-virt
/// rewrites each original instruction independently of its neighbours.
///
/// Runtime-exit payloads are not checked: they are synthesized from fixed return
/// registers plus the param0 capture, which accepts every register class, so they
/// cannot reject for an instruction-intrinsic reason. A failure there is a translator
/// bug and still surfaces from `virtualize_registers`.
pub fn admit_insn(insn: IrInsn) -> SharedResult<(), RegVirtError> {
    let lowered = rephrase_insn(insn).map_err(RegVirtError::Allocation)?;
    for rephrased in lowered.iter().filter(|r| r.kind.is_user_semantic()) {
        RewritePlan::build(*rephrased)?;
    }
    Ok(())
}

pub fn virtualize_registers(
    mut program: RephrasedProgram,
) -> SharedResult<RephrasedProgram, RegVirtError> {
    for block in program.iter_mut() {
        let body = core::mem::replace(&mut block.insns, SharedVec::new());
        block.insns = virtualize_insns(&body, false)?;
        let cold = core::mem::replace(&mut block.cold, SharedVec::new());
        block.cold = virtualize_insns(&cold, true)?;
    }

    Ok(program)
}

/// `cold`: the region holds only runtime-exit groups (fault and budget stubs).
fn virtualize_insns(
    insns: &[RephrasedInsn],
    cold: bool,
) -> SharedResult<SharedVec<RephrasedInsn>, RegVirtError> {
    let mut rewritten =
        SharedVec::with_capacity(insns.len(), GFP_KERNEL).map_err(RegVirtError::Allocation)?;

    let mut index = 0;
    while index < insns.len() {
        let insn = insns[index];
        if insn.kind.is_runtime_exit_payload() {
            index = virtualize_runtime_exit_group(insns, index, &mut rewritten)?;
        } else if cold && insn.kind == RephrasedInsnKind::PanRestore {
            // A PAN stub (A8): `msr pan, #1`, then the exit group it guards. Runtime-owned,
            // nothing to map; it must not be separated from its group.
            let group_follows = insns.get(index + 1).is_some_and(|next| {
                next.kind.is_runtime_exit_payload() && next.ori_pc == insn.ori_pc
            });
            if !group_follows || insn.insn.msr_pan() != Some(true) {
                return Err(RegVirtError::MalformedRuntimeExitGroup { pc: insn.ori_pc });
            }
            push_rephrased(&mut rewritten, insn)?;
            index += 1;
        } else if cold {
            return Err(RegVirtError::MalformedRuntimeExitGroup { pc: insn.ori_pc });
        } else {
            virtualize_insn(insn, &mut rewritten)?;
            index += 1;
        }
    }
    Ok(rewritten)
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
        // Runtime-owned (frame counter + branch to its stub) and placed at an
        // instruction boundary, where every scratch register is dead: nothing to map.
        RephrasedInsnKind::BudgetCheck => push_rephrased(out, rephrased),
        // These kinds are reg-virt output (or, for `PanRestore`, only valid at the
        // start of a cold PAN stub); seeing one here is a pipeline bug.
        RephrasedInsnKind::RegVirtHelper
        | RephrasedInsnKind::UserAccess
        | RephrasedInsnKind::AlignCheck
        | RephrasedInsnKind::RangeCheck
        | RephrasedInsnKind::PanToggle
        | RephrasedInsnKind::WindowAccess
        | RephrasedInsnKind::PanRestore => Err(RegVirtError::UnexpectedRegVirtHelper {
            pc: rephrased.ori_pc,
        }),
        RephrasedInsnKind::Original | RephrasedInsnKind::UserSynthetic => unreachable!(),
    }
}

fn virtualize_runtime_exit_group(
    insns: &[RephrasedInsn],
    start: usize,
    out: &mut SharedVec<RephrasedInsn>,
) -> SharedResult<usize, RegVirtError> {
    let pc = insns[start].ori_pc;
    let mut end = start;
    while end < insns.len() {
        let insn = insns[end];
        if insn.ori_pc != pc {
            return Err(RegVirtError::RuntimeExitPcMismatch {
                expected_pc: pc,
                actual_pc: insn.ori_pc,
            });
        }

        match insn.kind {
            RephrasedInsnKind::RuntimeExitPayload | RephrasedInsnKind::UserSynthetic => end += 1,
            RephrasedInsnKind::RuntimeExitBranch => {
                emit_runtime_exit_group(pc, &insns[start..end], insn, out)?;
                return Ok(end + 1);
            }
            _ => return Err(RegVirtError::MalformedRuntimeExitGroup { pc }),
        }
    }

    Err(RegVirtError::MalformedRuntimeExitGroup { pc })
}

fn emit_runtime_exit_group(
    pc: u64,
    payloads: &[RephrasedInsn],
    branch: RephrasedInsn,
    out: &mut SharedVec<RephrasedInsn>,
) -> SharedResult<(), RegVirtError> {
    // Capture writes through x10, so preserve user x9/x10/x11 before any payload setup.
    emit_preserve_runtime_reserved_user_regs(pc, out)?;

    let mut capture = None;
    for payload in payloads {
        if let Some(source) = runtime_param0_capture_source(payload.insn) {
            if capture.is_some() {
                return Err(RegVirtError::MultipleRuntimeExitParam0Captures { pc });
            }
            capture = Some(source);
        }
    }

    if let Some(source) = capture {
        emit_runtime_param0_capture(pc, source, out)?;
    }

    for payload in payloads {
        match payload.kind {
            RephrasedInsnKind::RuntimeExitPayload
                if runtime_param0_capture_source(payload.insn).is_some() => {}
            RephrasedInsnKind::RuntimeExitPayload => {
                validate_runtime_exit_payload(*payload)?;
                push_rephrased(out, *payload)?;
            }
            RephrasedInsnKind::UserSynthetic => {
                rewrite_user_semantic(*payload, out)?;
            }
            _ => return Err(RegVirtError::MalformedRuntimeExitGroup { pc }),
        }
    }

    push_rephrased(out, branch)
}

fn emit_preserve_runtime_reserved_user_regs(
    pc: u64,
    out: &mut SharedVec<RephrasedInsn>,
) -> SharedResult<(), RegVirtError> {
    let ptr_scratch = reg_virt_scratch_gpr(0).ok_or(RegVirtError::ScratchPoolExhausted {
        pc,
        insn: "runtime_exit_preserve",
        limit: REG_VIRT_SCRATCH_GPR_LIMIT,
    })?;

    push_rephrased(
        out,
        RephrasedInsn::reg_virt_helper(
            pc,
            A64Insn::LdrImmGenLdr64LdstPos {
                rt: x(ptr_scratch),
                mem: mem_off(sp(), ldst64_offset(RUNTIME_FRAME_PT_REGS_PTR_OFFSET)),
            },
        ),
    )?;

    for reg in [RET_STATUS_REG, RET_PARAM0_REG, RET_PARAM1_REG] {
        let offset =
            pt_regs_x_slot_offset(reg).ok_or(RegVirtError::StackBackedRewriteNotImplemented {
                pc,
                insn: "runtime_exit_preserve",
                reg: x(reg),
            })?;
        push_rephrased(
            out,
            RephrasedInsn::reg_virt_helper(
                pc,
                A64Insn::StrImmGenStr64LdstPos {
                    rt: x(reg),
                    mem: mem_off(x(ptr_scratch), ldst64_offset(offset)),
                },
            ),
        )?;
    }

    Ok(())
}

fn runtime_param0_capture_source(insn: A64Insn) -> Option<A64Reg> {
    match insn {
        A64Insn::OrrLogShiftOrr64LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } if shift == 0 && imm6.raw() == 0 && is_zero_reg(rn) && rd.enc == RET_PARAM0_REG => {
            Some(rm)
        }
        _ => None,
    }
}

fn emit_runtime_param0_capture(
    pc: u64,
    source: A64Reg,
    out: &mut SharedVec<RephrasedInsn>,
) -> SharedResult<(), RegVirtError> {
    match classify_reg(source) {
        RegClass::StackBacked => {
            let offset = reg_virt_stack_backed_slot_offset(source.enc).ok_or(
                RegVirtError::StackBackedRewriteNotImplemented {
                    pc,
                    insn: "runtime_param0_capture",
                    reg: source,
                },
            )?;
            push_rephrased(
                out,
                RephrasedInsn::runtime_exit_payload(
                    pc,
                    A64Insn::LdrImmGenLdr64LdstPos {
                        rt: x(RET_PARAM0_REG),
                        mem: mem_off(sp(), ldst64_offset(offset)),
                    },
                ),
            )
        }
        RegClass::StableMapped => {
            push_runtime_param0_copy(pc, x(REG_VIRT_STABLE_MAPPED_X29_PHYS_REG), out)
        }
        RegClass::Sp => push_runtime_param0_copy(pc, x(REG_VIRT_STABLE_MAPPED_SP_PHYS_REG), out),
        RegClass::Zero | RegClass::Direct | RegClass::RuntimeReserved => {
            push_runtime_param0_copy(pc, source, out)
        }
    }
}

fn push_runtime_param0_copy(
    pc: u64,
    source: A64Reg,
    out: &mut SharedVec<RephrasedInsn>,
) -> SharedResult<(), RegVirtError> {
    push_rephrased(
        out,
        RephrasedInsn::runtime_exit_payload(
            pc,
            A64Insn::OrrLogShiftOrr64LogShift {
                shift: 0,
                rm: A64Reg::new(source.enc, A64RegWidth::X64, source.reg31),
                imm6: uimm(0, 6),
                rn: xzr(),
                rd: x(RET_PARAM0_REG),
            },
        ),
    )
}

fn rewrite_user_semantic(
    rephrased: RephrasedInsn,
    out: &mut SharedVec<RephrasedInsn>,
) -> SharedResult<(), RegVirtError> {
    let plan = RewritePlan::build(rephrased)?;

    plan.emit_fills(rephrased.ori_pc, out)?;
    match plan.mem {
        Some(MemPlan::Unpriv(mem)) => plan.emit_mem_lowering(rephrased, mem, out)?,
        Some(MemPlan::Atomic(atomic)) => plan.emit_atomic_window(rephrased, atomic, out)?,
        None => {
            let rewritten = plan.rewrite_insn(rephrased)?;
            push_rephrased(
                out,
                RephrasedInsn {
                    insn: rewritten,
                    ..rephrased
                },
            )?;
        }
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemDir {
    Load,
    Store,
}

/// The `LDTR*`/`STTR*` instruction that performs one access of a lowered user
/// load/store. It has the user form's element size and load extension, so the
/// access and the value it produces are exactly the original's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UserAccessOp {
    Ldtrb,
    Ldtrh,
    Ldtr32,
    Ldtr64,
    Ldtrsb32,
    Ldtrsb64,
    Ldtrsh32,
    Ldtrsh64,
    Ldtrsw,
    Sttrb,
    Sttrh,
    Sttr32,
    Sttr64,
}

impl UserAccessOp {
    const fn dir(self) -> MemDir {
        match self {
            Self::Sttrb | Self::Sttrh | Self::Sttr32 | Self::Sttr64 => MemDir::Store,
            Self::Ldtrb
            | Self::Ldtrh
            | Self::Ldtr32
            | Self::Ldtr64
            | Self::Ldtrsb32
            | Self::Ldtrsb64
            | Self::Ldtrsh32
            | Self::Ldtrsh64
            | Self::Ldtrsw => MemDir::Load,
        }
    }

    /// Bytes per access.
    const fn size(self) -> u8 {
        match self {
            Self::Ldtrb | Self::Ldtrsb32 | Self::Ldtrsb64 | Self::Sttrb => 1,
            Self::Ldtrh | Self::Ldtrsh32 | Self::Ldtrsh64 | Self::Sttrh => 2,
            Self::Ldtr32 | Self::Ldtrsw | Self::Sttr32 => 4,
            Self::Ldtr64 | Self::Sttr64 => 8,
        }
    }

    /// `log2(size)`: the shift a register-offset form applies when `S == 1`.
    const fn scale(self) -> u8 {
        match self.size() {
            1 => 0,
            2 => 1,
            4 => 2,
            _ => 3,
        }
    }

    /// The access `[base, #offset]`; `offset` must fit the unscaled `simm9`.
    fn insn(self, rt: A64Reg, base: u8, offset: i64) -> A64Insn {
        debug_assert!(fits_simm9(offset));
        let mem = mem_off(A64Reg::x_sp(base), simm((offset as u32) & 0x1FF, 9));
        match self {
            Self::Ldtrb => A64Insn::LdtrbLdtrb32LdstUnpriv { rt, mem },
            Self::Ldtrh => A64Insn::LdtrhLdtrh32LdstUnpriv { rt, mem },
            Self::Ldtr32 => A64Insn::LdtrLdtr32LdstUnpriv { rt, mem },
            Self::Ldtr64 => A64Insn::LdtrLdtr64LdstUnpriv { rt, mem },
            Self::Ldtrsb32 => A64Insn::LdtrsbLdtrsb32LdstUnpriv { rt, mem },
            Self::Ldtrsb64 => A64Insn::LdtrsbLdtrsb64LdstUnpriv { rt, mem },
            Self::Ldtrsh32 => A64Insn::LdtrshLdtrsh32LdstUnpriv { rt, mem },
            Self::Ldtrsh64 => A64Insn::LdtrshLdtrsh64LdstUnpriv { rt, mem },
            Self::Ldtrsw => A64Insn::LdtrswLdtrsw64LdstUnpriv { rt, mem },
            Self::Sttrb => A64Insn::SttrbSttrb32LdstUnpriv { rt, mem },
            Self::Sttrh => A64Insn::SttrhSttrh32LdstUnpriv { rt, mem },
            Self::Sttr32 => A64Insn::SttrSttr32LdstUnpriv { rt, mem },
            Self::Sttr64 => A64Insn::SttrSttr64LdstUnpriv { rt, mem },
        }
    }
}

/// How a user load/store forms its address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemAddr {
    /// Base register plus immediate, with pre/post-index writeback for those forms.
    Imm(A64Mem),
    /// `[base, index, <extend> #shift]`: register offset, never written back.
    RegOffset {
        base: A64Reg,
        index: A64Reg,
        option: u8,
        shift: u8,
    },
    /// PC-relative literal: the absolute address, fixed at translation time.
    Literal(u64),
    /// `[base]`: the acquire/release forms (LDAR, STLR, LDAPR), no offset, never
    /// written back.
    Base(A64Reg),
}

/// A user load/store as reg-virt lowers it: one access, or two at consecutive
/// addresses for a pair, each performed by `op`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MemShape {
    op: UserAccessOp,
    rt: A64Reg,
    rt2: Option<A64Reg>,
    addr: MemAddr,
    /// Acquire/release (LDAR*, STLR*, LDAPR*): the access is fenced by `DMB ISH`
    /// on both sides and guarded by the 16-byte-block alignment rule (see
    /// `emit_mem_lowering`).
    ordered: bool,
}

/// `pc` is the instruction's own PC (literal forms address relative to it).
fn mem_shape(insn: A64Insn, pc: u64) -> Option<MemShape> {
    use UserAccessOp::*;
    let imm = |op, rt, mem| (op, rt, None, MemAddr::Imm(mem));
    let pair = |op, rt, rt2, mem| (op, rt, Some(rt2), MemAddr::Imm(mem));
    let reg = |op: UserAccessOp, rt, base, index, option, s: u8| {
        let shift = if s == 1 { op.scale() } else { 0 };
        let addr = MemAddr::RegOffset {
            base,
            index,
            option,
            shift,
        };
        (op, rt, None, addr)
    };
    // The `*BL` byte forms are the `LSL` (option = UXTX) encoding of the same load.
    const LSL: u8 = 0b011;
    let ordered = |op, rt, base| (op, rt, None, MemAddr::Base(base));
    let (op, rt, rt2, addr) = match insn {
        A64Insn::LdrImmGenLdr32LdstPos { rt, mem }
        | A64Insn::LdrImmGenLdr32LdstImmpre { rt, mem }
        | A64Insn::LdrImmGenLdr32LdstImmpost { rt, mem }
        | A64Insn::LdurGenLdur32LdstUnscaled { rt, mem } => imm(Ldtr32, rt, mem),
        A64Insn::LdrImmGenLdr64LdstPos { rt, mem }
        | A64Insn::LdrImmGenLdr64LdstImmpre { rt, mem }
        | A64Insn::LdrImmGenLdr64LdstImmpost { rt, mem }
        | A64Insn::LdurGenLdur64LdstUnscaled { rt, mem } => imm(Ldtr64, rt, mem),
        A64Insn::StrImmGenStr32LdstPos { rt, mem }
        | A64Insn::StrImmGenStr32LdstImmpre { rt, mem }
        | A64Insn::StrImmGenStr32LdstImmpost { rt, mem }
        | A64Insn::SturGenStur32LdstUnscaled { rt, mem } => imm(Sttr32, rt, mem),
        A64Insn::StrImmGenStr64LdstPos { rt, mem }
        | A64Insn::StrImmGenStr64LdstImmpre { rt, mem }
        | A64Insn::StrImmGenStr64LdstImmpost { rt, mem }
        | A64Insn::SturGenStur64LdstUnscaled { rt, mem } => imm(Sttr64, rt, mem),
        A64Insn::LdrbImmLdrb32LdstPos { rt, mem }
        | A64Insn::LdrbImmLdrb32LdstImmpre { rt, mem }
        | A64Insn::LdrbImmLdrb32LdstImmpost { rt, mem }
        | A64Insn::LdurbLdurb32LdstUnscaled { rt, mem } => imm(Ldtrb, rt, mem),
        A64Insn::StrbImmStrb32LdstPos { rt, mem }
        | A64Insn::StrbImmStrb32LdstImmpre { rt, mem }
        | A64Insn::StrbImmStrb32LdstImmpost { rt, mem }
        | A64Insn::SturbSturb32LdstUnscaled { rt, mem } => imm(Sttrb, rt, mem),
        A64Insn::LdrhImmLdrh32LdstPos { rt, mem }
        | A64Insn::LdrhImmLdrh32LdstImmpre { rt, mem }
        | A64Insn::LdrhImmLdrh32LdstImmpost { rt, mem }
        | A64Insn::LdurhLdurh32LdstUnscaled { rt, mem } => imm(Ldtrh, rt, mem),
        A64Insn::StrhImmStrh32LdstPos { rt, mem }
        | A64Insn::StrhImmStrh32LdstImmpre { rt, mem }
        | A64Insn::StrhImmStrh32LdstImmpost { rt, mem }
        | A64Insn::SturhSturh32LdstUnscaled { rt, mem } => imm(Sttrh, rt, mem),
        A64Insn::LdrsbImmLdrsb32LdstPos { rt, mem }
        | A64Insn::LdrsbImmLdrsb32LdstImmpre { rt, mem }
        | A64Insn::LdrsbImmLdrsb32LdstImmpost { rt, mem }
        | A64Insn::LdursbLdursb32LdstUnscaled { rt, mem } => imm(Ldtrsb32, rt, mem),
        A64Insn::LdrsbImmLdrsb64LdstPos { rt, mem }
        | A64Insn::LdrsbImmLdrsb64LdstImmpre { rt, mem }
        | A64Insn::LdrsbImmLdrsb64LdstImmpost { rt, mem }
        | A64Insn::LdursbLdursb64LdstUnscaled { rt, mem } => imm(Ldtrsb64, rt, mem),
        A64Insn::LdrshImmLdrsh32LdstPos { rt, mem }
        | A64Insn::LdrshImmLdrsh32LdstImmpre { rt, mem }
        | A64Insn::LdrshImmLdrsh32LdstImmpost { rt, mem }
        | A64Insn::LdurshLdursh32LdstUnscaled { rt, mem } => imm(Ldtrsh32, rt, mem),
        A64Insn::LdrshImmLdrsh64LdstPos { rt, mem }
        | A64Insn::LdrshImmLdrsh64LdstImmpre { rt, mem }
        | A64Insn::LdrshImmLdrsh64LdstImmpost { rt, mem }
        | A64Insn::LdurshLdursh64LdstUnscaled { rt, mem } => imm(Ldtrsh64, rt, mem),
        A64Insn::LdrswImmLdrsw64LdstPos { rt, mem }
        | A64Insn::LdrswImmLdrsw64LdstImmpre { rt, mem }
        | A64Insn::LdrswImmLdrsw64LdstImmpost { rt, mem }
        | A64Insn::LdurswLdursw64LdstUnscaled { rt, mem } => imm(Ldtrsw, rt, mem),

        A64Insn::LdpGenLdp32LdstpairOff { rt2, rt, mem }
        | A64Insn::LdpGenLdp32LdstpairPre { rt2, rt, mem }
        | A64Insn::LdpGenLdp32LdstpairPost { rt2, rt, mem } => pair(Ldtr32, rt, rt2, mem),
        A64Insn::LdpGenLdp64LdstpairOff { rt2, rt, mem }
        | A64Insn::LdpGenLdp64LdstpairPre { rt2, rt, mem }
        | A64Insn::LdpGenLdp64LdstpairPost { rt2, rt, mem } => pair(Ldtr64, rt, rt2, mem),
        A64Insn::LdpswLdpsw64LdstpairOff { rt2, rt, mem }
        | A64Insn::LdpswLdpsw64LdstpairPre { rt2, rt, mem }
        | A64Insn::LdpswLdpsw64LdstpairPost { rt2, rt, mem } => pair(Ldtrsw, rt, rt2, mem),
        A64Insn::StpGenStp32LdstpairOff { rt2, rt, mem }
        | A64Insn::StpGenStp32LdstpairPre { rt2, rt, mem }
        | A64Insn::StpGenStp32LdstpairPost { rt2, rt, mem } => pair(Sttr32, rt, rt2, mem),
        A64Insn::StpGenStp64LdstpairOff { rt2, rt, mem }
        | A64Insn::StpGenStp64LdstpairPre { rt2, rt, mem }
        | A64Insn::StpGenStp64LdstpairPost { rt2, rt, mem } => pair(Sttr64, rt, rt2, mem),

        A64Insn::LdrRegGenLdr32LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => reg(Ldtr32, rt, rn, rm, option, s),
        A64Insn::LdrRegGenLdr64LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => reg(Ldtr64, rt, rn, rm, option, s),
        A64Insn::StrRegGenStr32LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => reg(Sttr32, rt, rn, rm, option, s),
        A64Insn::StrRegGenStr64LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => reg(Sttr64, rt, rn, rm, option, s),
        A64Insn::LdrbRegLdrb32bLdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => reg(Ldtrb, rt, rn, rm, option, s),
        A64Insn::LdrbRegLdrb32blLdstRegoff { rm, s, rn, rt } => reg(Ldtrb, rt, rn, rm, LSL, s),
        A64Insn::StrbRegStrb32bLdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => reg(Sttrb, rt, rn, rm, option, s),
        A64Insn::StrbRegStrb32blLdstRegoff { rm, s, rn, rt } => reg(Sttrb, rt, rn, rm, LSL, s),
        A64Insn::LdrhRegLdrh32LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => reg(Ldtrh, rt, rn, rm, option, s),
        A64Insn::StrhRegStrh32LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => reg(Sttrh, rt, rn, rm, option, s),
        A64Insn::LdrsbRegLdrsb32bLdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => reg(Ldtrsb32, rt, rn, rm, option, s),
        A64Insn::LdrsbRegLdrsb32blLdstRegoff { rm, s, rn, rt } => reg(Ldtrsb32, rt, rn, rm, LSL, s),
        A64Insn::LdrsbRegLdrsb64bLdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => reg(Ldtrsb64, rt, rn, rm, option, s),
        A64Insn::LdrsbRegLdrsb64blLdstRegoff { rm, s, rn, rt } => reg(Ldtrsb64, rt, rn, rm, LSL, s),
        A64Insn::LdrshRegLdrsh32LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => reg(Ldtrsh32, rt, rn, rm, option, s),
        A64Insn::LdrshRegLdrsh64LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => reg(Ldtrsh64, rt, rn, rm, option, s),
        A64Insn::LdrswRegLdrsw64LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => reg(Ldtrsw, rt, rn, rm, option, s),

        A64Insn::LdrLitGenLdr32Loadlit { rt, .. } => (
            Ldtr32,
            rt,
            None,
            MemAddr::Literal(insn.literal_address(pc)?),
        ),
        A64Insn::LdrLitGenLdr64Loadlit { rt, .. } => (
            Ldtr64,
            rt,
            None,
            MemAddr::Literal(insn.literal_address(pc)?),
        ),
        A64Insn::LdrswLitLdrsw64Loadlit { rt, .. } => (
            Ldtrsw,
            rt,
            None,
            MemAddr::Literal(insn.literal_address(pc)?),
        ),

        // Acquire/release: the same element size and extension as the plain form.
        A64Insn::LdarLdarLr32Ldstord { rn, rt } | A64Insn::LdaprLdapr32lMemop { rn, rt } => {
            ordered(Ldtr32, rt, rn)
        }
        A64Insn::LdarLdarLr64Ldstord { rn, rt } | A64Insn::LdaprLdapr64lMemop { rn, rt } => {
            ordered(Ldtr64, rt, rn)
        }
        A64Insn::LdarbLdarbLr32Ldstord { rn, rt } | A64Insn::LdaprbLdaprb32lMemop { rn, rt } => {
            ordered(Ldtrb, rt, rn)
        }
        A64Insn::LdarhLdarhLr32Ldstord { rn, rt } | A64Insn::LdaprhLdaprh32lMemop { rn, rt } => {
            ordered(Ldtrh, rt, rn)
        }
        A64Insn::StlrStlrSl32Ldstord { rn, rt } => ordered(Sttr32, rt, rn),
        A64Insn::StlrStlrSl64Ldstord { rn, rt } => ordered(Sttr64, rt, rn),
        A64Insn::StlrbStlrbSl32Ldstord { rn, rt } => ordered(Sttrb, rt, rn),
        A64Insn::StlrhStlrhSl32Ldstord { rn, rt } => ordered(Sttrh, rt, rn),
        _ => return None,
    };
    let ordered = matches!(addr, MemAddr::Base(_));
    Some(MemShape {
        op,
        rt,
        rt2,
        addr,
        ordered,
    })
}

/// Where the lowered accesses take their address from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AccessAddr {
    /// The (mapped) user base register; the first access is at `offset` and every
    /// access offset fits `simm9`.
    Base { base: A64Reg, offset: i64 },
    /// `scratch = base + offset` (`ADD`/`SUB` imm): an access offset is outside `simm9`.
    BasePlusImm {
        scratch: u8,
        base: A64Reg,
        offset: i64,
    },
    /// `scratch = base + ExtendReg(index, option, shift)` (`ADD` extended register).
    BasePlusIndex {
        scratch: u8,
        base: A64Reg,
        index: A64Reg,
        option: u8,
        shift: u8,
    },
    /// `scratch = address` (`MOVZ`/`MOVK`): a literal load.
    Absolute { scratch: u8, address: u64 },
}

/// Pre/post-index base update, applied after every access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Writeback {
    base: A64Reg,
    amount: i64,
}

/// How one user load/store becomes `LDTR*`/`STTR*` (see `emit_mem_lowering`). The
/// scratch registers come from the plan's single scratch pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MemLowering {
    shape: MemShape,
    addr: AccessAddr,
    writeback: Option<Writeback>,
    /// Pair loads only: the first load's destination when `rt` cannot take it
    /// without writing a user-visible location or the access base.
    first_load_scratch: Option<u8>,
    /// SP-based user access: scratch for the SP alignment check
    /// (`RephrasedInsnKind::AlignCheck`), which runs before anything else of
    /// the instruction, so it may share the address or first-load scratch.
    sp_align_scratch: Option<u8>,
    /// Acquire/release access wider than a byte whose base is not SP: scratch for
    /// the 16-byte-block alignment check (`RephrasedInsnKind::AlignCheck`). An SP
    /// base needs none: the SP check already requires SP 16-byte aligned, and the
    /// access is at SP itself.
    block_align_scratch: Option<u8>,
}

/// How one LSE atomic (A8) runs inside a PAN window (see `emit_atomic_window`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AtomicLowering {
    atomic: A64Atomic,
    /// `sA`: the scratch register holding the address the window checks and the
    /// atomic uses as its base. A stack-backed base's own fill scratch, or a fresh
    /// scratch loaded by `mov sA, <mapped base>` (`copy_base`).
    addr: u8,
    copy_base: Option<A64Reg>,
    /// `sB`: the range check's result; also the SP / block alignment check's
    /// scratch, which run first.
    check: u8,
    /// SP base: `and sB, x17, #15; cbnz sB, <Mem stub>` (EL0 SP alignment check).
    sp_check: bool,
    /// Wider than a byte, base not SP: the 16-byte block alignment check.
    block_check: bool,
}

/// The memory lowering of one user instruction: `LDTR*`/`STTR*` accesses, or an LSE
/// atomic in a PAN window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemPlan {
    Unpriv(MemLowering),
    Atomic(AtomicLowering),
}

const fn fits_simm9(offset: i64) -> bool {
    offset >= -256 && offset <= 255
}

/// `ADD`/`SUB` (imm) sequence adding `value`: at most `imm12, lsl #12` then `imm12`.
/// Returns `(subtract, [(sh, imm12); 2], len)`; `len == 0` for zero.
fn add_sub_imm_parts(value: i64) -> Option<(bool, [(u8, u32); 2], usize)> {
    let magnitude = value.unsigned_abs();
    if magnitude >= 1 << 24 {
        return None;
    }
    let (hi, lo) = ((magnitude >> 12) as u32, (magnitude & 0xFFF) as u32);
    let mut parts = [(0, 0); 2];
    let mut len = 0;
    if hi != 0 {
        parts[len] = (1, hi);
        len += 1;
    }
    if lo != 0 {
        parts[len] = (0, lo);
        len += 1;
    }
    Some((value < 0, parts, len))
}

struct RewritePlan {
    pc: u64,
    insn: &'static str,
    stack_backed: [StackRegMapping; REG_VIRT_SCRATCH_GPR_LIMIT],
    stack_backed_len: usize,
    /// Scratch registers handed out so far: stack-backed mappings first, then the
    /// memory lowering's address/first-load scratch.
    scratch_used: usize,
    mem: Option<MemPlan>,
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
            scratch_used: 0,
            mem: None,
        }
    }

    /// The whole per-instruction decision, shared by admission and rewriting: register
    /// classes, scratch assignment and, for loads/stores, the `LDTR`/`STTR` lowering.
    /// Any instruction-intrinsic reason it cannot be lowered surfaces here.
    fn build(rephrased: RephrasedInsn) -> SharedResult<Self, RegVirtError> {
        let insn = rephrased.insn;
        let insn_key = insn.key();
        if insn.is_unprivileged_access() {
            return Err(RegVirtError::UnprivilegedUserAccess {
                pc: rephrased.ori_pc,
                insn: insn_key,
            });
        }
        if insn.msr_pan().is_some() {
            return Err(RegVirtError::PanUserForm {
                pc: rephrased.ori_pc,
                insn: insn_key,
            });
        }
        reject_constrained_unpredictable(rephrased)?;

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

        if insn.accesses_memory() {
            plan.mem = Some(match insn.lse_atomic() {
                Some(atomic) => MemPlan::Atomic(plan.plan_atomic(atomic)?),
                None => {
                    let shape = mem_shape(insn, rephrased.ori_pc).ok_or(
                        RegVirtError::UnloweredMemoryForm {
                            pc: rephrased.ori_pc,
                            insn: insn_key,
                        },
                    )?;
                    MemPlan::Unpriv(plan.plan_mem(shape)?)
                }
            });
        }

        Ok(plan)
    }

    fn alloc_scratch(&mut self) -> SharedResult<u8, RegVirtError> {
        let scratch =
            reg_virt_scratch_gpr(self.scratch_used).ok_or(RegVirtError::ScratchPoolExhausted {
                pc: self.pc,
                insn: self.insn,
                limit: REG_VIRT_SCRATCH_GPR_LIMIT,
            })?;
        self.scratch_used += 1;
        Ok(scratch)
    }

    fn plan_mem(&mut self, shape: MemShape) -> SharedResult<MemLowering, RegVirtError> {
        let unencodable = |offset| RegVirtError::UnencodableMemOffset {
            pc: self.pc,
            insn: self.insn,
            offset,
        };
        let size = i64::from(shape.op.size());
        let (addr, writeback) = match shape.addr {
            MemAddr::Imm(mem) => {
                let (first_offset, writeback) = match mem {
                    A64Mem::Offset { offset, .. } => (offset.value(), None),
                    A64Mem::PreIndex { offset, .. } => (offset.value(), Some(offset.value())),
                    A64Mem::PostIndex { offset, .. } => (0, Some(offset.value())),
                };
                if let Some(amount) = writeback {
                    add_sub_imm_parts(amount).ok_or(unencodable(amount))?;
                }
                let last_offset = match shape.rt2 {
                    Some(_) => first_offset + size,
                    None => first_offset,
                };
                let addr = if fits_simm9(first_offset) && fits_simm9(last_offset) {
                    AccessAddr::Base {
                        base: mem.base(),
                        offset: first_offset,
                    }
                } else {
                    add_sub_imm_parts(first_offset).ok_or(unencodable(first_offset))?;
                    AccessAddr::BasePlusImm {
                        scratch: self.alloc_scratch()?,
                        base: mem.base(),
                        offset: first_offset,
                    }
                };
                let writeback = writeback.map(|amount| Writeback {
                    base: mem.base(),
                    amount,
                });
                (addr, writeback)
            }
            MemAddr::RegOffset {
                base,
                index,
                option,
                shift,
            } => {
                let addr = AccessAddr::BasePlusIndex {
                    scratch: self.alloc_scratch()?,
                    base,
                    index,
                    option,
                    shift,
                };
                (addr, None)
            }
            MemAddr::Literal(address) => {
                let addr = AccessAddr::Absolute {
                    scratch: self.alloc_scratch()?,
                    address,
                };
                (addr, None)
            }
            MemAddr::Base(base) => (AccessAddr::Base { base, offset: 0 }, None),
        };

        let access_base = self.access_base(addr);
        let first_load_scratch = match (shape.op.dir(), shape.rt2) {
            (MemDir::Load, Some(_)) if !self.can_take_first_load(shape.rt, access_base) => {
                Some(self.alloc_scratch()?)
            }
            _ => None,
        };

        let sp_based = match shape.addr {
            MemAddr::Imm(mem) => classify_reg(mem.base()) == RegClass::Sp,
            MemAddr::RegOffset { base, .. } | MemAddr::Base(base) => {
                classify_reg(base) == RegClass::Sp
            }
            MemAddr::Literal(_) => false,
        };
        let sp_align_scratch = if sp_based {
            let shared = match addr {
                AccessAddr::BasePlusImm { scratch, .. }
                | AccessAddr::BasePlusIndex { scratch, .. } => Some(scratch),
                AccessAddr::Base { .. } | AccessAddr::Absolute { .. } => first_load_scratch,
            };
            Some(match shared {
                Some(scratch) => scratch,
                None => self.alloc_scratch()?,
            })
        } else {
            None
        };
        let block_align_scratch = if shape.ordered && shape.op.size() > 1 && !sp_based {
            Some(self.alloc_scratch()?)
        } else {
            None
        };

        Ok(MemLowering {
            shape,
            addr,
            writeback,
            first_load_scratch,
            sp_align_scratch,
            block_align_scratch,
        })
    }

    /// Scratch for an LSE atomic's PAN window (A8). Stack-backed operands were
    /// mapped first (role order), so the worst case is three of them plus `sB`, or
    /// two plus `sA` and `sB`: four.
    fn plan_atomic(&mut self, atomic: A64Atomic) -> SharedResult<AtomicLowering, RegVirtError> {
        let base_class = classify_reg(atomic.rn);
        let (addr, copy_base) = if base_class == RegClass::StackBacked {
            // Mapped by the `MemBase` role in `build`; missing is a translator bug.
            let mapping = self.stack_mapping(atomic.rn.enc).ok_or(
                RegVirtError::StackBackedRewriteNotImplemented {
                    pc: self.pc,
                    insn: self.insn,
                    reg: atomic.rn,
                },
            )?;
            (mapping.scratch, None)
        } else {
            (self.alloc_scratch()?, Some(x(self.phys(atomic.rn).enc)))
        };
        let check = self.alloc_scratch()?;
        let sp_check = base_class == RegClass::Sp;
        let block_check = atomic.size > 1 && !sp_check;
        debug_assert_eq!(sp_check || block_check, atomic_needs_check_stub(atomic));
        Ok(AtomicLowering {
            atomic,
            addr,
            copy_base,
            check,
            sp_check,
            block_check,
        })
    }

    /// Emits one LSE atomic (A8; tmp/pipeline.md, "A8 contract") between its fills
    /// and spills:
    ///
    /// ```text
    ///   [and sB, x17, #15; cbnz sB, <Mem stub>]         SP base: EL0 SP alignment
    ///   [mov sA, <mapped base>]                          unless the base is stack-backed
    ///   [and sB, sA, #15; add sB, sB, #(size - 1);
    ///    and sB, sB, #16; cbnz sB, <Mem stub>]           wider than a byte, base not SP
    ///   ubfx sB, sA, #48, #8                             VA bits [55:48]
    ///   cbnz sB, <PAN stub>                              not a TTBR0 user address
    ///   msr  pan, #0
    ///   <the atomic, operands mapped, base = sA>         fault site -> PAN stub
    ///   msr  pan, #1
    /// ```
    ///
    /// Commit-after-last-access: before the atomic only scratch is written; the
    /// atomic is the only access and writes its destination (`Rt`, or CAS's `Rs`)
    /// only when it retires; spills follow `msr pan, #1`. An atomic crossing a
    /// 16-byte boundary alignment-faults natively (FEAT_LSE2; `MemSingleGranule()`
    /// is at least 16), so leaving for it is exact or conservative: userspace
    /// re-executes the instruction natively either way.
    fn emit_atomic_window(
        &self,
        rephrased: RephrasedInsn,
        lowering: AtomicLowering,
        out: &mut SharedVec<RephrasedInsn>,
    ) -> SharedResult<(), RegVirtError> {
        let pc = rephrased.ori_pc;
        let (sa, sb) = (lowering.addr, lowering.check);
        let and_15 = |rn: u8| A64Insn::AndLogImmAnd64LogImm {
            // #15: N=1, immr=0, imms=3 (four ones).
            n: 1,
            immr: uimm(0, 6),
            imms: uimm(3, 6),
            rn: x(rn),
            rd: A64Reg::x_sp(sb),
        };
        let cbnz = || A64Insn::CbnzCbnz64Compbranch {
            imm19: scaled_simm(0, 19, 2),
            rt: x(sb),
        };

        if lowering.sp_check {
            for check in [and_15(REG_VIRT_STABLE_MAPPED_SP_PHYS_REG), cbnz()] {
                push_rephrased(out, RephrasedInsn::align_check(pc, check))?;
            }
        }
        if let Some(base) = lowering.copy_base {
            push_rephrased(
                out,
                RephrasedInsn::reg_virt_helper(
                    pc,
                    A64Insn::OrrLogShiftOrr64LogShift {
                        shift: 0,
                        rm: base,
                        imm6: uimm(0, 6),
                        rn: xzr(),
                        rd: x(sa),
                    },
                ),
            )?;
        }
        if lowering.block_check {
            let checks = [
                and_15(sa),
                A64Insn::AddAddsubImmAdd64AddsubImm {
                    sh: 0,
                    imm12: uimm(u32::from(lowering.atomic.size) - 1, 12),
                    rn: A64Reg::x_sp(sb),
                    rd: A64Reg::x_sp(sb),
                },
                // #16: N=1, immr=60, imms=0 (one one, rotated to bit 4).
                A64Insn::AndLogImmAnd64LogImm {
                    n: 1,
                    immr: uimm(60, 6),
                    imms: uimm(0, 6),
                    rn: x(sb),
                    rd: A64Reg::x_sp(sb),
                },
                cbnz(),
            ];
            for check in checks {
                push_rephrased(out, RephrasedInsn::align_check(pc, check))?;
            }
        }

        // ubfx sB, sA, #USER_VA_BITS, #(TOP - USER_VA_BITS + 1) = UBFM immr=lsb, imms=top.
        let range = A64Insn::UbfmUbfm64mBitfield {
            immr: uimm(u32::from(USER_VA_BITS), 6),
            imms: uimm(u32::from(PAN_WINDOW_RANGE_TOP_BIT), 6),
            rn: x(sa),
            rd: x(sb),
        };
        push_rephrased(out, RephrasedInsn::range_check(pc, range))?;
        push_rephrased(out, RephrasedInsn::range_check(pc, cbnz()))?;

        let atomic = self
            .rewrite_insn(rephrased)?
            .set_reg("Rn", A64Reg::x_sp(sa))
            .map_err(|_| RegVirtError::MissingRegisterSetter {
                pc,
                insn: self.insn,
                field: "Rn",
            })?;
        push_rephrased(
            out,
            RephrasedInsn::pan_toggle(pc, A64Insn::MsrImmMsrSiPstate { crm: 0 }),
        )?;
        push_rephrased(out, RephrasedInsn::window_access(pc, atomic))?;
        push_rephrased(
            out,
            RephrasedInsn::pan_toggle(pc, A64Insn::MsrImmMsrSiPstate { crm: 1 }),
        )
    }

    /// The physical register every lowered access addresses from.
    fn access_base(&self, addr: AccessAddr) -> u8 {
        match addr {
            AccessAddr::Base { base, .. } => self.phys(base).enc,
            AccessAddr::BasePlusImm { scratch, .. }
            | AccessAddr::BasePlusIndex { scratch, .. }
            | AccessAddr::Absolute { scratch, .. } => scratch,
        }
    }

    /// Whether a pair's first load may write `rt`'s register directly. Only when that
    /// is invisible until the spill (XZR, or a stack-backed register's scratch) and
    /// does not clobber the base the second access still reads.
    fn can_take_first_load(&self, rt: A64Reg, access_base: u8) -> bool {
        match classify_reg(rt) {
            RegClass::Zero => true,
            RegClass::StackBacked => self
                .stack_mapping(rt.enc)
                .is_some_and(|mapping| mapping.scratch != access_base),
            RegClass::Direct
            | RegClass::RuntimeReserved
            | RegClass::StableMapped
            | RegClass::Sp => false,
        }
    }

    /// `rd = rn + value` with 64-bit `ADD`/`SUB` (imm). Emits nothing for zero (only
    /// a writeback of #0 asks for that, and it is a no-op).
    fn push_add_sub_imm(
        &self,
        out: &mut SharedVec<RephrasedInsn>,
        make: impl Fn(A64Insn) -> RephrasedInsn,
        rd: u8,
        rn: u8,
        value: i64,
    ) -> SharedResult<(), RegVirtError> {
        let (subtract, parts, len) =
            add_sub_imm_parts(value).ok_or(RegVirtError::UnencodableMemOffset {
                pc: self.pc,
                insn: self.insn,
                offset: value,
            })?;
        let mut source = rn;
        for &(sh, imm12) in &parts[..len] {
            let (rd, rn, imm12) = (A64Reg::x_sp(rd), A64Reg::x_sp(source), uimm(imm12, 12));
            let insn = if subtract {
                A64Insn::SubAddsubImmSub64AddsubImm { sh, imm12, rn, rd }
            } else {
                A64Insn::AddAddsubImmAdd64AddsubImm { sh, imm12, rn, rd }
            };
            push_rephrased(out, make(insn))?;
            source = rd.enc;
        }
        Ok(())
    }

    fn phys(&self, reg: A64Reg) -> A64Reg {
        self.physical_reg(reg).unwrap_or(reg)
    }

    /// Emits the lowered accesses of one user load/store, between its fills and
    /// spills. This is where the commit-after-last-access invariant is enforced:
    /// 1. address materialization writes only scratch;
    /// 2. every access but the last loads into scratch (or XZR, or a stack-backed
    ///    register's scratch, which is not user-visible until its spill);
    /// 3. the last access may target its final register;
    /// 4. then the register move, the base writeback, and (in the caller) spills.
    /// So each `LDTR*`/`STTR*` faults with every user-visible location (direct
    /// registers, frame slots, x16/x17) still holding its pre-instruction value.
    ///
    /// Acquire/release forms (A7c; tmp/pipeline.md "Barriers and acquire/release")
    /// become `[alignment check] dmb ish; LDTR*/STTR* [xN, #0]; dmb ish`: no
    /// unprivileged ordered access exists without FEAT_LSUI, and the two full
    /// fences order the access at least as strongly as LDAR/STLR/LDAPR.
    fn emit_mem_lowering(
        &self,
        rephrased: RephrasedInsn,
        mem: MemLowering,
        out: &mut SharedVec<RephrasedInsn>,
    ) -> SharedResult<(), RegVirtError> {
        let pc = rephrased.ori_pc;
        let shape = mem.shape;
        let helper = |insn| RephrasedInsn::reg_virt_helper(pc, insn);

        if let Some(scratch) = mem.sp_align_scratch {
            // `and xS, <mapped SP>, #15` (N=1, immr=0, imms=3: four ones), then
            // `cbnz xS` to this instruction's Mem stub; layout resolves the target.
            // Flags are untouched.
            let sp = A64Reg::x(REG_VIRT_STABLE_MAPPED_SP_PHYS_REG);
            push_rephrased(
                out,
                RephrasedInsn::align_check(
                    pc,
                    A64Insn::AndLogImmAnd64LogImm {
                        n: 1,
                        immr: uimm(0, 6),
                        imms: uimm(3, 6),
                        rn: sp,
                        rd: A64Reg::x_sp(scratch),
                    },
                ),
            )?;
            push_rephrased(
                out,
                RephrasedInsn::align_check(
                    pc,
                    A64Insn::CbnzCbnz64Compbranch {
                        imm19: scaled_simm(0, 19, 2),
                        rt: x(scratch),
                    },
                ),
            )?;
        }
        if let Some(scratch) = mem.block_align_scratch {
            // An unaligned acquire/release access faults (SIGBUS) at EL0 iff it
            // crosses a 16-byte boundary (FEAT_LSE2, SCTLR_EL1.nAA == 0); LDTR*/STTR*
            // never alignment-fault, so leave through the Mem stub when
            // `(addr & 15) + size - 1 >= 16`:
            //   and xS, <base>, #15; add xS, xS, #(size - 1); and xS, xS, #16;
            //   cbnz xS, <Mem stub>
            // Ordered forms address `[base]` (`AccessAddr::Base`), never SP here;
            // flags are untouched.
            let base = self.access_base(mem.addr);
            let s = A64Reg::x_sp(scratch);
            let checks = [
                // #15: N=1, immr=0, imms=3 (four ones).
                A64Insn::AndLogImmAnd64LogImm {
                    n: 1,
                    immr: uimm(0, 6),
                    imms: uimm(3, 6),
                    rn: x(base),
                    rd: s,
                },
                A64Insn::AddAddsubImmAdd64AddsubImm {
                    sh: 0,
                    imm12: uimm(u32::from(shape.op.size()) - 1, 12),
                    rn: s,
                    rd: s,
                },
                // #16: N=1, immr=60, imms=0 (one one, rotated to bit 4).
                A64Insn::AndLogImmAnd64LogImm {
                    n: 1,
                    immr: uimm(60, 6),
                    imms: uimm(0, 6),
                    rn: x(scratch),
                    rd: s,
                },
                A64Insn::CbnzCbnz64Compbranch {
                    imm19: scaled_simm(0, 19, 2),
                    rt: x(scratch),
                },
            ];
            for check in checks {
                push_rephrased(out, RephrasedInsn::align_check(pc, check))?;
            }
        }
        // `DMB ISH` (CRm = 0b1011): every observer of user memory is in the Inner
        // Shareable domain (Linux's smp_mb()).
        let fence = || helper(A64Insn::DmbDmbBoBarriers { crm: 0b1011 });
        if shape.ordered {
            push_rephrased(out, fence())?;
        }

        let first_offset = match mem.addr {
            AccessAddr::Base { offset, .. } => offset,
            AccessAddr::BasePlusImm {
                scratch,
                base,
                offset,
            } => {
                self.push_add_sub_imm(out, helper, scratch, self.phys(base).enc, offset)?;
                0
            }
            AccessAddr::BasePlusIndex {
                scratch,
                base,
                index,
                option,
                shift,
            } => {
                push_rephrased(
                    out,
                    helper(A64Insn::AddAddsubExtAdd64AddsubExt {
                        rm: x(self.phys(index).enc),
                        option,
                        imm3: uimm(u32::from(shift), 3),
                        rn: A64Reg::x_sp(self.phys(base).enc),
                        rd: A64Reg::x_sp(scratch),
                    }),
                )?;
                0
            }
            AccessAddr::Absolute { scratch, address } => {
                push_mov_address(out, pc, scratch, address)?;
                0
            }
        };
        let access_base = self.access_base(mem.addr);
        let op = shape.op;
        let second_offset = first_offset + i64::from(op.size());

        let rt = self.phys(shape.rt);
        match (op.dir(), shape.rt2) {
            (_, None) => {
                push_rephrased(
                    out,
                    RephrasedInsn::user_access(pc, op.insn(rt, access_base, first_offset)),
                )?;
            }
            (MemDir::Load, Some(rt2)) => {
                let first_dest = match mem.first_load_scratch {
                    Some(scratch) => A64Reg::new(scratch, rt.width, A64Reg31Mode::Xzr),
                    None => rt,
                };
                push_rephrased(
                    out,
                    RephrasedInsn::user_access(pc, op.insn(first_dest, access_base, first_offset)),
                )?;
                push_rephrased(
                    out,
                    RephrasedInsn::user_access(
                        pc,
                        op.insn(self.phys(rt2), access_base, second_offset),
                    ),
                )?;
                if let Some(scratch) = mem.first_load_scratch {
                    // Every pair load (LDP W/X, LDPSW) writes the full X register, so a
                    // 64-bit move is exact.
                    push_rephrased(
                        out,
                        RephrasedInsn {
                            insn: A64Insn::OrrLogShiftOrr64LogShift {
                                shift: 0,
                                rm: x(scratch),
                                imm6: uimm(0, 6),
                                rn: xzr(),
                                rd: x(rt.enc),
                            },
                            ..rephrased
                        },
                    )?;
                }
            }
            (MemDir::Store, Some(rt2)) => {
                push_rephrased(
                    out,
                    RephrasedInsn::user_access(pc, op.insn(rt, access_base, first_offset)),
                )?;
                push_rephrased(
                    out,
                    RephrasedInsn::user_access(
                        pc,
                        op.insn(self.phys(rt2), access_base, second_offset),
                    ),
                )?;
            }
        }
        if shape.ordered {
            push_rephrased(out, fence())?;
        }

        if let Some(Writeback { base, amount }) = mem.writeback {
            let base = self.phys(base).enc;
            self.push_add_sub_imm(
                out,
                |insn| RephrasedInsn { insn, ..rephrased },
                base,
                base,
                amount,
            )?;
        }
        Ok(())
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
            RegClass::RuntimeReserved => Ok(()),
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

        let scratch = self.alloc_scratch()?;
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

/// `rd = address`: `MOVZ` of the low halfword, then a `MOVK` for every other
/// non-zero halfword. Writes only `rd` (a scratch register).
fn push_mov_address(
    out: &mut SharedVec<RephrasedInsn>,
    pc: u64,
    rd: u8,
    address: u64,
) -> SharedResult<(), RegVirtError> {
    let halfword = |hw: u8| uimm(((address >> (16 * u32::from(hw))) & 0xFFFF) as u32, 16);
    push_rephrased(
        out,
        RephrasedInsn::reg_virt_helper(
            pc,
            A64Insn::MovzMovz64Movewide {
                hw: 0,
                imm16: halfword(0),
                rd: x(rd),
            },
        ),
    )?;
    for hw in 1..4 {
        if halfword(hw).raw() != 0 {
            push_rephrased(
                out,
                RephrasedInsn::reg_virt_helper(
                    pc,
                    A64Insn::MovkMovk64Movewide {
                        hw,
                        imm16: halfword(hw),
                        rd: x(rd),
                    },
                ),
            )?;
        }
    }
    Ok(())
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

/// Rejects CONSTRAINED UNPREDICTABLE register overlaps. Runs before any mapping, so
/// equality is decided on user (virtual) register numbers. Driven by generated
/// operand roles: a writeback form is a `MemBase` whose field also has a write role.
/// - writeback with base == a transfer register, unless the base is SP (reg 31);
/// - two distinct written fields naming the same register (LDP rt == rt2).
fn reject_constrained_unpredictable(rephrased: RephrasedInsn) -> SharedResult<(), RegVirtError> {
    let insn = rephrased.insn;
    let roles = insn.operand_roles();
    let unpredictable = RegVirtError::UnpredictableMemoryOp {
        pc: rephrased.ori_pc,
        insn: insn.key(),
    };

    for role in roles {
        let A64OperandRole::MemBase { field: base_field } = *role else {
            continue;
        };
        if !field_has_write_role(insn, base_field) {
            continue;
        }
        let base = require_reg(rephrased, base_field)?;
        if base.enc == 31 {
            continue;
        }
        for other in roles {
            let Some((field, _, _)) = access_mode_from_role(*other) else {
                continue;
            };
            if field != base_field && require_reg(rephrased, field)?.enc == base.enc {
                return Err(unpredictable);
            }
        }
    }

    for (index, role) in roles.iter().enumerate() {
        let A64OperandRole::RegWrite { field, .. } = *role else {
            continue;
        };
        let reg = require_reg(rephrased, field)?;
        for later in &roles[index + 1..] {
            let A64OperandRole::RegWrite { field: other, .. } = *later else {
                continue;
            };
            if other != field && require_reg(rephrased, other)?.enc == reg.enc {
                return Err(unpredictable);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::arm64::ergo::{ldst64_offset, ldstpair64_offset, uimm, x, xzr};
    use crate::shared::arm64::{A64Imm, A64Mem, A64Reg31Mode};
    use crate::shared::platform::{SharedVec, GFP_KERNEL};
    use crate::shared::trans::rephrase::{RephrasedBlock, RephrasedInsn};

    fn one_insn(insn: RephrasedInsn) -> RephrasedProgram {
        program_from_insns(&[insn])
    }

    fn program_from_insns(raw: &[RephrasedInsn]) -> RephrasedProgram {
        let mut insns = SharedVec::new();
        for insn in raw {
            insns.push(*insn, GFP_KERNEL).unwrap();
        }
        let first_pc = raw.first().map(|insn| insn.ori_pc).unwrap_or(0);
        let mut program = SharedVec::new();
        program
            .push(
                RephrasedBlock {
                    start_addr: first_pc,
                    end_addr: first_pc + 4,
                    prev: SharedVec::new(),
                    next: SharedVec::new(),
                    insns,
                    cold: SharedVec::new(),
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

    fn pt_regs_slot(reg: u8) -> A64Mem {
        A64Mem::offset(
            x(12),
            A64Imm::scaled_unsigned(((reg as u32) * 8) / 8, 12, 3),
        )
    }

    fn runtime_branch() -> A64Insn {
        A64Insn::BUncondBOnlyBranchImm {
            imm26: A64Imm::scaled_signed(0, 26, 2),
        }
    }

    fn copy_param0_from(reg: A64Reg) -> A64Insn {
        A64Insn::OrrLogShiftOrr64LogShift {
            shift: 0,
            rm: reg,
            imm6: uimm(0, 6),
            rn: xzr(),
            rd: x(RET_PARAM0_REG),
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
        virtualize_registers(program_from_insns(&[
            RephrasedInsn::runtime_exit_payload(0x1000, movz(x(9))),
            RephrasedInsn::runtime_exit_branch(0x1000, runtime_branch()),
        ]))
        .unwrap();
    }

    #[test]
    fn runtime_reserved_user_semantic_registers_remain_direct_until_runtime_exit() {
        let program = validate_one(RephrasedInsn::original(0x1000, movz(x(9)))).unwrap();

        assert_eq!(
            &program[0].insns[..],
            [RephrasedInsn::original(0x1000, movz(x(9)))]
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

    /// Fill of user register `virt` into scratch `scratch`.
    /// The SP alignment check before an SP-based user access, through `scratch`.
    fn sp_align_check(scratch: u8) -> [RephrasedInsn; 2] {
        [
            RephrasedInsn::align_check(
                0x1000,
                A64Insn::AndLogImmAnd64LogImm {
                    n: 1,
                    immr: uimm(0, 6),
                    imms: uimm(3, 6),
                    rn: x(17),
                    rd: A64Reg::x_sp(scratch),
                },
            ),
            RephrasedInsn::align_check(
                0x1000,
                A64Insn::CbnzCbnz64Compbranch {
                    imm19: scaled_simm(0, 19, 2),
                    rt: x(scratch),
                },
            ),
        ]
    }

    fn fill(scratch: u8, virt: u8) -> RephrasedInsn {
        RephrasedInsn::reg_virt_helper(
            0x1000,
            A64Insn::LdrImmGenLdr64LdstPos {
                rt: x(scratch),
                mem: frame_slot(reg_virt_stack_backed_slot_offset(virt).unwrap()),
            },
        )
    }

    /// Spill of user register `virt` from scratch `scratch`.
    fn spill(scratch: u8, virt: u8) -> RephrasedInsn {
        RephrasedInsn::reg_virt_helper(
            0x1000,
            A64Insn::StrImmGenStr64LdstPos {
                rt: x(scratch),
                mem: frame_slot(reg_virt_stack_backed_slot_offset(virt).unwrap()),
            },
        )
    }

    fn unpriv_mem(base: u8, offset: i64) -> A64Mem {
        A64Mem::offset(
            A64Reg::x_sp(base),
            A64Imm::signed((offset as u32) & 0x1FF, 9),
        )
    }

    fn ldtr_x(rt: A64Reg, base: u8, offset: i64) -> RephrasedInsn {
        RephrasedInsn::user_access(
            0x1000,
            A64Insn::LdtrLdtr64LdstUnpriv {
                rt,
                mem: unpriv_mem(base, offset),
            },
        )
    }

    fn sttr_x(rt: A64Reg, base: u8, offset: i64) -> RephrasedInsn {
        RephrasedInsn::user_access(
            0x1000,
            A64Insn::SttrSttr64LdstUnpriv {
                rt,
                mem: unpriv_mem(base, offset),
            },
        )
    }

    fn add_imm(rd: u8, rn: u8, sh: u8, imm: u32) -> A64Insn {
        A64Insn::AddAddsubImmAdd64AddsubImm {
            sh,
            imm12: uimm(imm, 12),
            rn: A64Reg::x_sp(rn),
            rd: A64Reg::x_sp(rd),
        }
    }

    fn sub_imm(rd: u8, rn: u8, imm: u32) -> A64Insn {
        A64Insn::SubAddsubImmSub64AddsubImm {
            sh: 0,
            imm12: uimm(imm, 12),
            rn: A64Reg::x_sp(rn),
            rd: A64Reg::x_sp(rd),
        }
    }

    fn mov(rd: u8, rm: u8) -> A64Insn {
        A64Insn::OrrLogShiftOrr64LogShift {
            shift: 0,
            rm: x(rm),
            imm6: uimm(0, 6),
            rn: xzr(),
            rd: x(rd),
        }
    }

    fn lowered(insn: A64Insn) -> SharedVec<RephrasedInsn> {
        let mut program = validate_one(RephrasedInsn::original(0x1000, insn)).unwrap();
        core::mem::replace(&mut program[0].insns, SharedVec::new())
    }

    #[test]
    fn str_of_stack_backed_register_fills_then_stores_with_sttr() {
        assert_eq!(
            &lowered(A64Insn::StrImmGenStr64LdstPos {
                rt: x(12),
                mem: A64Mem::offset(x(1), A64Imm::scaled_unsigned(0, 12, 3)),
            })[..],
            [fill(12, 12), sttr_x(x(12), 1, 0)]
        );
    }

    #[test]
    fn stp_pre_index_on_sp_stores_through_x17_then_writes_back() {
        assert_eq!(
            &lowered(A64Insn::StpGenStp64LdstpairPre {
                rt2: x(13),
                rt: x(12),
                mem: A64Mem::pre_index(A64Reg::x_sp(31), ldstpair64_offset(-16)),
            })[..],
            [
                fill(12, 12),
                fill(13, 13),
                // A fresh scratch: x12/x13 hold the filled transfer registers.
                sp_align_check(14)[0],
                sp_align_check(14)[1],
                sttr_x(x(12), 17, -16),
                sttr_x(x(13), 17, -8),
                RephrasedInsn::original(0x1000, sub_imm(17, 17, 16)),
            ]
        );
    }

    #[test]
    fn ldp_post_index_into_x29_loads_first_into_scratch() {
        // x29 lives in x16, which is user-visible: the first load may not target it.
        assert_eq!(
            &lowered(A64Insn::LdpGenLdp64LdstpairPost {
                rt2: x(30),
                rt: x(29),
                mem: A64Mem::post_index(A64Reg::x_sp(31), ldstpair64_offset(16)),
            })[..],
            [
                // Shares the first-load scratch: the check runs before any load.
                sp_align_check(12)[0],
                sp_align_check(12)[1],
                ldtr_x(x(12), 17, 0),
                ldtr_x(x(30), 17, 8),
                RephrasedInsn::original(0x1000, mov(16, 12)),
                RephrasedInsn::original(0x1000, add_imm(17, 17, 0, 16)),
            ]
        );
    }

    #[test]
    fn ldp_whose_second_target_is_the_base_loads_it_last() {
        assert_eq!(
            &lowered(A64Insn::LdpGenLdp64LdstpairOff {
                rt2: x(1),
                rt: x(0),
                mem: A64Mem::offset(A64Reg::x_sp(1), ldstpair64_offset(0)),
            })[..],
            [
                ldtr_x(x(12), 1, 0),
                ldtr_x(x(1), 1, 8),
                RephrasedInsn::original(0x1000, mov(0, 12)),
            ]
        );
    }

    #[test]
    fn ldp_into_stack_backed_base_register_keeps_base_until_second_access() {
        // rt == base (x12, in scratch x12): the first load needs its own scratch.
        assert_eq!(
            &lowered(A64Insn::LdpGenLdp64LdstpairOff {
                rt2: x(13),
                rt: x(12),
                mem: A64Mem::offset(A64Reg::x_sp(12), ldstpair64_offset(8)),
            })[..],
            [
                fill(12, 12),
                ldtr_x(x(14), 12, 8),
                ldtr_x(x(13), 12, 16),
                RephrasedInsn::original(0x1000, mov(12, 14)),
                spill(12, 12),
                spill(13, 13),
            ]
        );
    }

    #[test]
    fn ldp_under_full_scratch_pressure_uses_all_four_scratch_registers() {
        // x12/x13 targets, stack-backed base x14, offset out of simm9 range. Scratch
        // follows operand-role order: base x14 -> x12, x12 -> x13, x13 -> x14, then
        // the address -> x15.
        assert_eq!(
            &lowered(A64Insn::LdpGenLdp64LdstpairOff {
                rt2: x(13),
                rt: x(12),
                mem: A64Mem::offset(A64Reg::x_sp(14), ldstpair64_offset(496)),
            })[..],
            [
                fill(12, 14),
                RephrasedInsn::reg_virt_helper(0x1000, add_imm(15, 12, 0, 496)),
                ldtr_x(x(13), 15, 0),
                ldtr_x(x(14), 15, 8),
                spill(13, 12),
                spill(14, 13),
            ]
        );
    }

    #[test]
    fn out_of_range_offsets_materialize_the_address_in_scratch() {
        assert_eq!(
            &lowered(A64Insn::LdrImmGenLdr64LdstPos {
                rt: x(0),
                mem: A64Mem::offset(x(1), ldst64_offset(32760)),
            })[..],
            [
                RephrasedInsn::reg_virt_helper(0x1000, add_imm(12, 1, 1, 7)),
                RephrasedInsn::reg_virt_helper(0x1000, add_imm(12, 12, 0, 0xff8)),
                ldtr_x(x(0), 12, 0),
            ]
        );
        assert_eq!(
            &lowered(A64Insn::StrImmGenStr32LdstPos {
                rt: A64Reg::w(2),
                mem: A64Mem::offset(x(3), A64Imm::scaled_unsigned(16380 / 4, 12, 2)),
            })[..],
            [
                RephrasedInsn::reg_virt_helper(0x1000, add_imm(12, 3, 1, 3)),
                RephrasedInsn::reg_virt_helper(0x1000, add_imm(12, 12, 0, 0xffc)),
                RephrasedInsn::user_access(
                    0x1000,
                    A64Insn::SttrSttr32LdstUnpriv {
                        rt: A64Reg::w(2),
                        mem: unpriv_mem(12, 0),
                    },
                ),
            ]
        );
    }

    #[test]
    fn ldr_post_index_with_stack_backed_base_writes_back_before_spill() {
        assert_eq!(
            &lowered(A64Insn::LdrImmGenLdr64LdstImmpost {
                rt: x(0),
                mem: A64Mem::post_index(A64Reg::x_sp(14), A64Imm::signed(8, 9)),
            })[..],
            [
                fill(12, 14),
                ldtr_x(x(0), 12, 0),
                RephrasedInsn::original(0x1000, add_imm(12, 12, 0, 8)),
                spill(12, 14),
            ]
        );
    }

    #[test]
    fn ldr_w_pre_index_into_stack_backed_loads_w_scratch_and_spills_x() {
        assert_eq!(
            &lowered(A64Insn::LdrImmGenLdr32LdstImmpre {
                rt: A64Reg::w(13),
                mem: A64Mem::pre_index(A64Reg::x_sp(0), A64Imm::signed(signed9(-4), 9)),
            })[..],
            [
                RephrasedInsn::user_access(
                    0x1000,
                    A64Insn::LdtrLdtr32LdstUnpriv {
                        rt: A64Reg::w(12),
                        mem: unpriv_mem(0, -4),
                    },
                ),
                RephrasedInsn::original(0x1000, sub_imm(0, 0, 4)),
                spill(12, 13),
            ]
        );
    }

    fn access(insn: A64Insn) -> RephrasedInsn {
        RephrasedInsn::user_access(0x1000, insn)
    }

    fn helper(insn: A64Insn) -> RephrasedInsn {
        RephrasedInsn::reg_virt_helper(0x1000, insn)
    }

    #[test]
    fn narrow_and_signed_loads_use_the_matching_unprivileged_form() {
        let base = A64Reg::x_sp(1);
        let cases = [
            (
                A64Insn::LdrbImmLdrb32LdstPos {
                    rt: A64Reg::w(0),
                    mem: A64Mem::offset(base, A64Imm::unsigned(3, 12)),
                },
                A64Insn::LdtrbLdtrb32LdstUnpriv {
                    rt: A64Reg::w(0),
                    mem: unpriv_mem(1, 3),
                },
            ),
            (
                A64Insn::LdrshImmLdrsh64LdstPos {
                    rt: x(0),
                    mem: A64Mem::offset(base, A64Imm::scaled_unsigned(2, 12, 1)),
                },
                A64Insn::LdtrshLdtrsh64LdstUnpriv {
                    rt: x(0),
                    mem: unpriv_mem(1, 4),
                },
            ),
            (
                A64Insn::LdursbLdursb32LdstUnscaled {
                    rt: A64Reg::w(0),
                    mem: A64Mem::offset(base, A64Imm::signed(signed9(-1), 9)),
                },
                A64Insn::LdtrsbLdtrsb32LdstUnpriv {
                    rt: A64Reg::w(0),
                    mem: unpriv_mem(1, -1),
                },
            ),
            (
                A64Insn::LdrswImmLdrsw64LdstPos {
                    rt: x(0),
                    mem: A64Mem::offset(base, A64Imm::scaled_unsigned(1, 12, 2)),
                },
                A64Insn::LdtrswLdtrsw64LdstUnpriv {
                    rt: x(0),
                    mem: unpriv_mem(1, 4),
                },
            ),
            (
                A64Insn::SturhSturh32LdstUnscaled {
                    rt: A64Reg::w(0),
                    mem: A64Mem::offset(base, A64Imm::signed(signed9(-3), 9)),
                },
                A64Insn::SttrhSttrh32LdstUnpriv {
                    rt: A64Reg::w(0),
                    mem: unpriv_mem(1, -3),
                },
            ),
            (
                A64Insn::StrbImmStrb32LdstPos {
                    rt: A64Reg::w(31),
                    mem: A64Mem::offset(base, A64Imm::unsigned(255, 12)),
                },
                A64Insn::SttrbSttrb32LdstUnpriv {
                    rt: A64Reg::w(31),
                    mem: unpriv_mem(1, 255),
                },
            ),
        ];
        for (original, expected) in cases {
            assert_eq!(&lowered(original)[..], [access(expected)], "{original:?}");
        }
    }

    #[test]
    fn byte_post_index_store_writes_back_after_its_access() {
        assert_eq!(
            &lowered(A64Insn::StrbImmStrb32LdstImmpost {
                rt: A64Reg::w(2),
                mem: A64Mem::post_index(A64Reg::x_sp(12), A64Imm::signed(1, 9)),
            })[..],
            [
                fill(12, 12),
                access(A64Insn::SttrbSttrb32LdstUnpriv {
                    rt: A64Reg::w(2),
                    mem: unpriv_mem(12, 0),
                }),
                RephrasedInsn::original(0x1000, add_imm(12, 12, 0, 1)),
                spill(12, 12),
            ]
        );
    }

    #[test]
    fn register_offset_computes_the_address_with_add_extended_then_accesses_at_zero() {
        // ldr x12, [x13, w14, sxtw #3]: three stack-backed registers plus the
        // address scratch use the whole pool.
        assert_eq!(
            &lowered(A64Insn::LdrRegGenLdr64LdstRegoff {
                rm: x(14),
                option: 0b110,
                s: 1,
                rn: A64Reg::x_sp(13),
                rt: x(12),
            })[..],
            // Scratch in operand-role order: base x13 -> x12, index x14 -> x13,
            // target x12 -> x14, then the address -> x15.
            [
                fill(12, 13),
                fill(13, 14),
                helper(A64Insn::AddAddsubExtAdd64AddsubExt {
                    rm: x(13),
                    option: 0b110,
                    imm3: uimm(3, 3),
                    rn: A64Reg::x_sp(12),
                    rd: A64Reg::x_sp(15),
                }),
                ldtr_x(x(14), 15, 0),
                spill(14, 12),
            ]
        );
        // ldrh w0, [sp, x29, lsl #1]: SP and x29 through their stable mappings.
        assert_eq!(
            &lowered(A64Insn::LdrhRegLdrh32LdstRegoff {
                rm: x(29),
                option: 0b011,
                s: 1,
                rn: A64Reg::x_sp(31),
                rt: A64Reg::w(0),
            })[..],
            [
                // Shares the address scratch: the check runs before the add.
                sp_align_check(12)[0],
                sp_align_check(12)[1],
                helper(A64Insn::AddAddsubExtAdd64AddsubExt {
                    rm: x(16),
                    option: 0b011,
                    imm3: uimm(1, 3),
                    rn: A64Reg::x_sp(17),
                    rd: A64Reg::x_sp(12),
                }),
                access(A64Insn::LdtrhLdtrh32LdstUnpriv {
                    rt: A64Reg::w(0),
                    mem: unpriv_mem(12, 0),
                }),
            ]
        );
        // The LSL form of LDRSB: S = 1 still means a shift of 0 for bytes; the
        // index XZR stays XZR.
        assert_eq!(
            &lowered(A64Insn::LdrsbRegLdrsb64blLdstRegoff {
                rm: xzr(),
                s: 1,
                rn: A64Reg::x_sp(1),
                rt: x(1),
            })[..],
            [
                helper(A64Insn::AddAddsubExtAdd64AddsubExt {
                    rm: xzr(),
                    option: 0b011,
                    imm3: uimm(0, 3),
                    rn: A64Reg::x_sp(1),
                    rd: A64Reg::x_sp(12),
                }),
                access(A64Insn::LdtrsbLdtrsb64LdstUnpriv {
                    rt: x(1),
                    mem: unpriv_mem(12, 0),
                }),
            ]
        );
    }

    #[test]
    fn literal_load_materializes_the_absolute_address_in_scratch() {
        // At pc 0x1000, imm19 = -2 words: the literal is at 0xff8.
        assert_eq!(
            &lowered(A64Insn::LdrswLitLdrsw64Loadlit {
                imm19: A64Imm::scaled_signed(0x7fffe, 19, 2),
                rt: x(13),
            })[..],
            // Target x13 takes scratch x12; the address takes x13.
            [
                helper(A64Insn::MovzMovz64Movewide {
                    hw: 0,
                    imm16: uimm(0xff8, 16),
                    rd: x(13),
                }),
                access(A64Insn::LdtrswLdtrsw64LdstUnpriv {
                    rt: x(12),
                    mem: unpriv_mem(13, 0),
                }),
                spill(12, 13),
            ]
        );
        // A literal below the PC that wraps: every non-zero halfword is written.
        let program = virtualize_registers(one_insn(RephrasedInsn::original(
            0x0001_0002_0003_0000,
            A64Insn::LdrLitGenLdr64Loadlit {
                imm19: A64Imm::scaled_signed(0x40000, 19, 2),
                rt: x(0),
            },
        )))
        .unwrap();
        let address = 0x0001_0002_0003_0000_u64 - (1 << 20);
        let movs = program[0]
            .insns
            .iter()
            .filter_map(|insn| match insn.insn {
                A64Insn::MovzMovz64Movewide { hw, imm16, .. }
                | A64Insn::MovkMovk64Movewide { hw, imm16, .. } => {
                    Some(u64::from(imm16.raw()) << (16 * u32::from(hw)))
                }
                _ => None,
            })
            .sum::<u64>();
        assert_eq!(movs, address);
    }

    #[test]
    fn narrow_pairs_split_into_two_element_accesses() {
        let base = A64Reg::x_sp(2);
        let pair32 = A64Imm::scaled_signed(signed7(-2), 7, 2);
        assert_eq!(
            &lowered(A64Insn::LdpGenLdp32LdstpairPre {
                rt2: A64Reg::w(1),
                rt: A64Reg::w(0),
                mem: A64Mem::pre_index(base, pair32),
            })[..],
            [
                access(A64Insn::LdtrLdtr32LdstUnpriv {
                    rt: A64Reg::w(12),
                    mem: unpriv_mem(2, -8),
                }),
                access(A64Insn::LdtrLdtr32LdstUnpriv {
                    rt: A64Reg::w(1),
                    mem: unpriv_mem(2, -4),
                }),
                RephrasedInsn::original(0x1000, mov(0, 12)),
                RephrasedInsn::original(0x1000, sub_imm(2, 2, 8)),
            ]
        );
        assert_eq!(
            &lowered(A64Insn::LdpswLdpsw64LdstpairOff {
                rt2: x(13),
                rt: x(12),
                mem: A64Mem::offset(base, A64Imm::scaled_signed(1, 7, 2)),
            })[..],
            [
                access(A64Insn::LdtrswLdtrsw64LdstUnpriv {
                    rt: x(12),
                    mem: unpriv_mem(2, 4),
                }),
                access(A64Insn::LdtrswLdtrsw64LdstUnpriv {
                    rt: x(13),
                    mem: unpriv_mem(2, 8),
                }),
                spill(12, 12),
                spill(13, 13),
            ]
        );
        assert_eq!(
            &lowered(A64Insn::StpGenStp32LdstpairOff {
                rt2: A64Reg::w(31),
                rt: A64Reg::w(31),
                mem: A64Mem::offset(base, A64Imm::scaled_signed(0, 7, 2)),
            })[..],
            [
                access(A64Insn::SttrSttr32LdstUnpriv {
                    rt: A64Reg::w(31),
                    mem: unpriv_mem(2, 0),
                }),
                access(A64Insn::SttrSttr32LdstUnpriv {
                    rt: A64Reg::w(31),
                    mem: unpriv_mem(2, 4),
                }),
            ]
        );
    }

    #[test]
    fn prefetch_becomes_a_nop_without_a_user_access_or_fault_stub() {
        use crate::shared::trans::rephrase::rephrase_insn;
        let prfm = A64Insn::PrfmRegPrfmPLdstRegoff {
            rm: x(1),
            option: 0b011,
            s: 1,
            rn: A64Reg::x_sp(0),
            rt: 0,
        };
        assert!(!prfm.accesses_memory());
        let rephrased = rephrase_insn(IrInsn {
            pc: 0x1000,
            word: prfm.encode().unwrap(),
            inner: prfm,
        })
        .unwrap();
        assert_eq!(
            &rephrased[..],
            [RephrasedInsn::user_synthetic(
                0x1000,
                A64Insn::NopNopHiHints {}
            )]
        );
    }

    fn signed7(value: i64) -> u32 {
        (value as u32) & 0x7F
    }

    fn signed9(value: i64) -> u32 {
        (value as u32) & 0x1FF
    }

    /// Structural check of the commit-after-last-access invariant over every memory
    /// form and a spread of register classes and offsets: nothing before the last
    /// user access writes a register outside the scratch pool or stores to the frame.
    #[test]
    fn every_lowering_commits_only_after_its_last_user_access() {
        let regs = [0u8, 1, 9, 12, 13, 14, 16, 29, 30, 31];
        let mut checked = 0;
        for rt in regs {
            for rt2 in regs {
                for base in regs {
                    for insn in memory_forms(rt, rt2, base) {
                        let Ok(program) =
                            virtualize_registers(one_insn(RephrasedInsn::original(0x1000, insn)))
                        else {
                            continue;
                        };
                        assert_commit_after_last_access(insn, &program[0].insns);
                        checked += 1;
                    }
                }
            }
        }
        assert!(checked > 1000, "only {checked} lowerings checked");
    }

    fn memory_forms(rt: u8, rt2: u8, base: u8) -> Vec<A64Insn> {
        let base = A64Reg::x_sp(base);
        let mut forms = Vec::new();
        for offset in [0i64, 8, 248, 256, 4104, 32760] {
            let pos = A64Mem::offset(base, ldst64_offset(offset as u32));
            forms.push(A64Insn::LdrImmGenLdr64LdstPos {
                rt: x(rt),
                mem: pos,
            });
            forms.push(A64Insn::StrImmGenStr64LdstPos {
                rt: x(rt),
                mem: pos,
            });
            let pos32 = A64Mem::offset(
                base,
                A64Imm::scaled_unsigned((offset / 2) as u32 / 4, 12, 2),
            );
            forms.push(A64Insn::LdrImmGenLdr32LdstPos {
                rt: A64Reg::w(rt),
                mem: pos32,
            });
            forms.push(A64Insn::StrImmGenStr32LdstPos {
                rt: A64Reg::w(rt),
                mem: pos32,
            });
        }
        for offset in [-256i64, -8, 0, 8, 255] {
            let imm = A64Imm::signed(signed9(offset), 9);
            for mem in [A64Mem::pre_index(base, imm), A64Mem::post_index(base, imm)] {
                forms.push(A64Insn::LdrImmGenLdr64LdstImmpre { rt: x(rt), mem });
                forms.push(A64Insn::StrImmGenStr32LdstImmpost {
                    rt: A64Reg::w(rt),
                    mem,
                });
            }
        }
        for offset in [-512i32, -16, 0, 240, 248, 504] {
            let imm = ldstpair64_offset(offset);
            for mem in [
                A64Mem::offset(base, imm),
                A64Mem::pre_index(base, imm),
                A64Mem::post_index(base, imm),
            ] {
                forms.push(A64Insn::LdpGenLdp64LdstpairOff {
                    rt2: x(rt2),
                    rt: x(rt),
                    mem,
                });
                forms.push(A64Insn::StpGenStp64LdstpairPre {
                    rt2: x(rt2),
                    rt: x(rt),
                    mem,
                });
            }
        }
        // A7b forms: narrow/signed single accesses, unscaled, 32-bit pairs, LDPSW,
        // register offset (rt2 doubles as the index register) and literals.
        let w = A64Reg::w;
        for offset in [-256i64, -1, 0, 255] {
            let imm = A64Imm::signed(signed9(offset), 9);
            for mem in [
                A64Mem::offset(base, imm),
                A64Mem::pre_index(base, imm),
                A64Mem::post_index(base, imm),
            ] {
                forms.push(A64Insn::LdrsbImmLdrsb64LdstImmpre { rt: x(rt), mem });
                forms.push(A64Insn::StrhImmStrh32LdstImmpost { rt: w(rt), mem });
                forms.push(A64Insn::LdurswLdursw64LdstUnscaled { rt: x(rt), mem });
                forms.push(A64Insn::SturbSturb32LdstUnscaled { rt: w(rt), mem });
            }
        }
        for raw in [0u32, 1, 4095] {
            let mem = A64Mem::offset(base, A64Imm::scaled_unsigned(raw, 12, 1));
            forms.push(A64Insn::LdrshImmLdrsh32LdstPos { rt: w(rt), mem });
            forms.push(A64Insn::StrhImmStrh32LdstPos { rt: w(rt), mem });
            let mem = A64Mem::offset(base, A64Imm::unsigned(raw, 12));
            forms.push(A64Insn::LdrbImmLdrb32LdstPos { rt: w(rt), mem });
        }
        for raw in [0x40u32, 0x3f, 0] {
            let imm = A64Imm::scaled_signed(raw, 7, 2);
            for mem in [
                A64Mem::offset(base, imm),
                A64Mem::pre_index(base, imm),
                A64Mem::post_index(base, imm),
            ] {
                forms.push(A64Insn::LdpGenLdp32LdstpairPost {
                    rt2: w(rt2),
                    rt: w(rt),
                    mem,
                });
                forms.push(A64Insn::LdpswLdpsw64LdstpairOff {
                    rt2: x(rt2),
                    rt: x(rt),
                    mem,
                });
                forms.push(A64Insn::StpGenStp32LdstpairPre {
                    rt2: w(rt2),
                    rt: w(rt),
                    mem,
                });
            }
        }
        for (option, s) in [(0b010, 1), (0b011, 0), (0b110, 1), (0b111, 1)] {
            forms.push(A64Insn::LdrRegGenLdr64LdstRegoff {
                rm: x(rt2),
                option,
                s,
                rn: base,
                rt: x(rt),
            });
            forms.push(A64Insn::StrhRegStrh32LdstRegoff {
                rm: x(rt2),
                option,
                s,
                rn: base,
                rt: w(rt),
            });
            forms.push(A64Insn::LdrswRegLdrsw64LdstRegoff {
                rm: x(rt2),
                option,
                s,
                rn: base,
                rt: x(rt),
            });
        }
        forms.push(A64Insn::StrbRegStrb32blLdstRegoff {
            rm: x(rt2),
            s: 1,
            rn: base,
            rt: w(rt),
        });
        forms.push(A64Insn::LdrLitGenLdr32Loadlit {
            imm19: A64Imm::scaled_signed(0x40000, 19, 2),
            rt: w(rt),
        });
        forms.push(A64Insn::LdrswLitLdrsw64Loadlit {
            imm19: A64Imm::scaled_signed(0x3ffff, 19, 2),
            rt: x(rt),
        });
        // A7c acquire/release: `[base]` only.
        forms.extend(acquire_release_forms(rt, base));
        forms
    }

    /// Every acquire/release form with transfer register `rt` and base `rn`.
    fn acquire_release_forms(rt: u8, rn: A64Reg) -> [A64Insn; 12] {
        let w = A64Reg::w(rt);
        [
            A64Insn::LdarLdarLr32Ldstord { rn, rt: w },
            A64Insn::LdarLdarLr64Ldstord { rn, rt: x(rt) },
            A64Insn::LdarbLdarbLr32Ldstord { rn, rt: w },
            A64Insn::LdarhLdarhLr32Ldstord { rn, rt: w },
            A64Insn::StlrStlrSl32Ldstord { rn, rt: w },
            A64Insn::StlrStlrSl64Ldstord { rn, rt: x(rt) },
            A64Insn::StlrbStlrbSl32Ldstord { rn, rt: w },
            A64Insn::StlrhStlrhSl32Ldstord { rn, rt: w },
            A64Insn::LdaprLdapr32lMemop { rn, rt: w },
            A64Insn::LdaprLdapr64lMemop { rn, rt: x(rt) },
            A64Insn::LdaprbLdaprb32lMemop { rn, rt: w },
            A64Insn::LdaprhLdaprh32lMemop { rn, rt: w },
        ]
    }

    fn dmb_ish() -> RephrasedInsn {
        helper(A64Insn::DmbDmbBoBarriers { crm: 0b1011 })
    }

    /// The 16-byte-block alignment check of an acquire/release access of `size`
    /// bytes based on physical register `base`, through `scratch`.
    fn block_align_check(scratch: u8, base: u8, size: u32) -> [RephrasedInsn; 4] {
        let s = A64Reg::x_sp(scratch);
        [
            A64Insn::AndLogImmAnd64LogImm {
                n: 1,
                immr: uimm(0, 6),
                imms: uimm(3, 6),
                rn: x(base),
                rd: s,
            },
            add_imm(scratch, scratch, 0, size - 1),
            A64Insn::AndLogImmAnd64LogImm {
                n: 1,
                immr: uimm(60, 6),
                imms: uimm(0, 6),
                rn: x(scratch),
                rd: s,
            },
            A64Insn::CbnzCbnz64Compbranch {
                imm19: scaled_simm(0, 19, 2),
                rt: x(scratch),
            },
        ]
        .map(|insn| RephrasedInsn::align_check(0x1000, insn))
    }

    #[test]
    fn acquire_release_is_a_fenced_unprivileged_access_at_offset_zero() {
        let w = A64Reg::w;
        let ldtr = |op: fn(A64Reg, A64Mem) -> A64Insn, rt, base| {
            access(op(rt, unpriv_mem(base, 0)))
        };
        let seq = |guard: &[RephrasedInsn], body: &[RephrasedInsn]| {
            let mut out = guard.to_vec();
            out.push(dmb_ish());
            out.extend_from_slice(body);
            out.push(dmb_ish());
            out
        };

        // ldar x0, [x1]: guard, fence, ldtr, fence.
        assert_eq!(
            lowered(A64Insn::LdarLdarLr64Ldstord { rn: A64Reg::x_sp(1), rt: x(0) }).to_vec(),
            seq(
                &block_align_check(12, 1, 8),
                &[ldtr(|rt, mem| A64Insn::LdtrLdtr64LdstUnpriv { rt, mem }, x(0), 1)]
            )
        );
        // stlr w12, [x13]: both stack-backed (scratch in role order: base x13 ->
        // x12, rt x12 -> x13); the guard takes the third scratch and reads the
        // base's scratch.
        let mut expected = vec![fill(12, 13), fill(13, 12)];
        expected.extend(seq(
            &block_align_check(14, 12, 4),
            &[ldtr(|rt, mem| A64Insn::SttrSttr32LdstUnpriv { rt, mem }, w(13), 12)],
        ));
        assert_eq!(
            lowered(A64Insn::StlrStlrSl32Ldstord { rn: A64Reg::x_sp(13), rt: w(12) }).to_vec(),
            expected
        );
        // ldarb w12, [x2]: a byte is always aligned, no guard; the load lands in
        // the scratch, then spills.
        let mut expected = seq(
            &[],
            &[ldtr(|rt, mem| A64Insn::LdtrbLdtrb32LdstUnpriv { rt, mem }, w(12), 2)],
        );
        expected.push(spill(12, 12));
        assert_eq!(
            lowered(A64Insn::LdarbLdarbLr32Ldstord { rn: A64Reg::x_sp(2), rt: w(12) }).to_vec(),
            expected
        );
        // ldaprh w3, [sp]: the SP check only (SP 16-byte aligned implies the
        // access is aligned), then through x17.
        assert_eq!(
            lowered(A64Insn::LdaprhLdaprh32lMemop { rn: sp(), rt: w(3) }).to_vec(),
            seq(
                &sp_align_check(12),
                &[ldtr(|rt, mem| A64Insn::LdtrhLdtrh32LdstUnpriv { rt, mem }, w(3), 17)]
            )
        );
        // stlrh / ldapr keep their element size and extension.
        assert_eq!(
            lowered(A64Insn::StlrhStlrhSl32Ldstord { rn: A64Reg::x_sp(4), rt: w(5) }).to_vec(),
            seq(
                &block_align_check(12, 4, 2),
                &[ldtr(|rt, mem| A64Insn::SttrhSttrh32LdstUnpriv { rt, mem }, w(5), 4)]
            )
        );
        assert_eq!(
            lowered(A64Insn::LdaprLdapr32lMemop { rn: A64Reg::x_sp(6), rt: w(6) }).to_vec(),
            seq(
                &block_align_check(12, 6, 4),
                &[ldtr(|rt, mem| A64Insn::LdtrLdtr32LdstUnpriv { rt, mem }, w(6), 6)]
            )
        );
    }

    /// Every acquire/release lowering: exactly one user access, `dmb ish` right
    /// before and right after it, and the alignment guards before the leading fence.
    #[test]
    fn every_acquire_release_lowering_is_fenced_on_both_sides() {
        let regs = [0u8, 1, 9, 12, 13, 16, 29, 30, 31];
        for rt in regs {
            for base in regs {
                for insn in acquire_release_forms(rt, A64Reg::x_sp(base)) {
                    let out = lowered(insn);
                    let at = out
                        .iter()
                        .position(|r| r.kind == RephrasedInsnKind::UserAccess)
                        .unwrap();
                    assert_eq!(out[at - 1], dmb_ish(), "{insn:?}: {out:?}");
                    assert_eq!(out[at + 1], dmb_ish(), "{insn:?}: {out:?}");
                    let fences = out.iter().filter(|r| **r == dmb_ish()).count();
                    assert_eq!(fences, 2, "{insn:?}: {out:?}");
                    assert!(
                        out[at..]
                            .iter()
                            .all(|r| r.kind != RephrasedInsnKind::AlignCheck),
                        "{insn:?}: {out:?}"
                    );
                }
            }
        }
    }

    fn range_check(sa: u8, sb: u8) -> [RephrasedInsn; 2] {
        [
            A64Insn::UbfmUbfm64mBitfield {
                immr: uimm(48, 6),
                imms: uimm(55, 6),
                rn: x(sa),
                rd: x(sb),
            },
            A64Insn::CbnzCbnz64Compbranch {
                imm19: scaled_simm(0, 19, 2),
                rt: x(sb),
            },
        ]
        .map(|insn| RephrasedInsn::range_check(0x1000, insn))
    }

    /// `msr pan, #0; <atomic>; msr pan, #1`.
    fn pan_window(atomic: A64Insn) -> [RephrasedInsn; 3] {
        [
            RephrasedInsn::pan_toggle(0x1000, A64Insn::MsrImmMsrSiPstate { crm: 0 }),
            RephrasedInsn::window_access(0x1000, atomic),
            RephrasedInsn::pan_toggle(0x1000, A64Insn::MsrImmMsrSiPstate { crm: 1 }),
        ]
    }

    /// A8: the exact PAN window (tmp/pipeline.md, "A8 contract").
    #[test]
    fn lse_atomic_lowers_to_the_exact_pan_window() {
        let w = A64Reg::w;
        // ldaddal x0, x1, [x2]: direct base copied into sA = x12; sB = x13 does the
        // block check and the range check.
        let mut expected = vec![helper(mov(12, 2))];
        expected.extend(block_align_check(13, 12, 8));
        expected.extend(range_check(12, 13));
        expected.extend(pan_window(A64Insn::LdaddLdaddal64Memop {
            rs: x(0),
            rn: A64Reg::x_sp(12),
            rt: x(1),
        }));
        assert_eq!(
            lowered(A64Insn::LdaddLdaddal64Memop {
                rs: x(0),
                rn: A64Reg::x_sp(2),
                rt: x(1)
            })
            .to_vec(),
            expected
        );

        // cas x12, x13, [x14]: every operand stack-backed (role order: base x14 ->
        // x12, Rs x12 -> x13, Rt x13 -> x14); the base's fill scratch is sA; the
        // compare register is written by the atomic and spilled after the window.
        let mut expected = vec![fill(12, 14), fill(13, 12), fill(14, 13)];
        expected.extend(block_align_check(15, 12, 8));
        expected.extend(range_check(12, 15));
        expected.extend(pan_window(A64Insn::CasCasC64Comswap {
            rs: x(13),
            rn: A64Reg::x_sp(12),
            rt: x(14),
        }));
        expected.push(spill(13, 12));
        assert_eq!(
            lowered(A64Insn::CasCasC64Comswap {
                rs: x(12),
                rn: A64Reg::x_sp(14),
                rt: x(13)
            })
            .to_vec(),
            expected
        );

        // swpb w0, w16, [sp]: SP check through sB, then sA = x17; a byte needs no
        // block check; the old value lands in the stack-backed x16's scratch.
        let mut expected = sp_align_check(14).to_vec();
        expected.push(helper(mov(13, 17)));
        expected.extend(range_check(13, 14));
        expected.extend(pan_window(A64Insn::SwpbSwpb32Memop {
            rs: w(0),
            rn: A64Reg::x_sp(13),
            rt: w(12),
        }));
        expected.push(spill(12, 16));
        assert_eq!(
            lowered(A64Insn::SwpbSwpb32Memop {
                rs: w(0),
                rn: sp(),
                rt: w(16)
            })
            .to_vec(),
            expected
        );

        // stadd w1, [x29]: x29 lives in x16; Rt = WZR stays.
        let mut expected = vec![helper(mov(12, 16))];
        expected.extend(block_align_check(13, 12, 4));
        expected.extend(range_check(12, 13));
        expected.extend(pan_window(A64Insn::LdaddLdadd32Memop {
            rs: w(1),
            rn: A64Reg::x_sp(12),
            rt: w(31),
        }));
        assert_eq!(
            lowered(A64Insn::LdaddLdadd32Memop {
                rs: w(1),
                rn: A64Reg::x_sp(29),
                rt: w(31)
            })
            .to_vec(),
            expected
        );
    }

    /// Every LSE atomic form with every register class in every operand: admitted
    /// (four scratch registers always suffice), one window, only scratch written
    /// before the atomic, spills only after `msr pan, #1`, and the atomic based on
    /// the range-checked register.
    #[test]
    fn every_atomic_lowering_is_one_window_committing_after_it() {
        use crate::shared::arm64::GENERATED_A64_SUBSET;
        let regs = [0u8, 9, 12, 13, 14, 16, 17, 29, 30, 31];
        let mut checked = 0;
        for spec in GENERATED_A64_SUBSET {
            let base_insn = A64Insn::decode(spec.value).unwrap();
            if base_insn.lse_atomic().is_none() {
                continue;
            }
            for rs in regs {
                for rt in regs {
                    for rn in regs {
                        let insn = base_insn
                            .set_reg("Rs", A64Reg::x(rs))
                            .and_then(|insn| insn.set_reg("Rt", A64Reg::x(rt)))
                            .and_then(|insn| insn.set_reg("Rn", A64Reg::x_sp(rn)))
                            .unwrap();
                        admit_insn(ir(insn)).unwrap_or_else(|err| panic!("{insn:?}: {err:?}"));
                        let out = lowered(insn);
                        let window = out
                            .iter()
                            .position(|r| r.kind == RephrasedInsnKind::WindowAccess)
                            .unwrap();
                        assert_eq!(
                            out.iter()
                                .filter(|r| r.kind == RephrasedInsnKind::WindowAccess)
                                .count(),
                            1
                        );
                        let atomic = out[window].insn;
                        let (ubfx, cbnz) = (out[window - 3], out[window - 2]);
                        assert_eq!(out[window - 1].insn.msr_pan(), Some(false), "{out:?}");
                        assert_eq!(out[window + 1].insn.msr_pan(), Some(true), "{out:?}");
                        let A64Insn::UbfmUbfm64mBitfield { rn: sa, rd: sb, .. } = ubfx.insn else {
                            panic!("{insn:?}: {out:?}");
                        };
                        assert_eq!(ubfx.kind, RephrasedInsnKind::RangeCheck);
                        assert_eq!(cbnz.kind, RephrasedInsnKind::RangeCheck);
                        assert!(
                            matches!(cbnz.insn, A64Insn::CbnzCbnz64Compbranch { rt, .. } if rt.enc == sb.enc)
                        );
                        assert_eq!(atomic.lse_atomic().unwrap().rn.enc, sa.enc, "{out:?}");
                        let scratch = crate::shared::abi::REG_VIRT_SCRATCH_GPR_START
                            ..=crate::shared::abi::REG_VIRT_SCRATCH_GPR_END;
                        assert!(scratch.contains(&sa.enc) && scratch.contains(&sb.enc));
                        for before in &out[..window] {
                            assert!(
                                !matches!(before.insn, A64Insn::StrImmGenStr64LdstPos { .. }),
                                "{insn:?}: spill before the atomic: {out:?}"
                            );
                            for role in before.insn.operand_roles() {
                                if let A64OperandRole::RegWrite { field, .. } = *role {
                                    let reg = before.insn.get_reg(field).unwrap();
                                    assert!(
                                        reg.enc == 31 || scratch.contains(&reg.enc),
                                        "{insn:?}: {out:?}"
                                    );
                                }
                            }
                        }
                        for after in &out[window + 2..] {
                            assert!(
                                matches!(after.insn, A64Insn::StrImmGenStr64LdstPos { .. }),
                                "{insn:?}: only spills follow the window: {out:?}"
                            );
                        }
                        checked += 1;
                    }
                }
            }
        }
        assert_eq!(checked, 160 * 1000);
    }

    #[test]
    fn admission_rejects_user_msr_pan_as_intrinsic() {
        for crm in [0, 1, 7] {
            let inner = A64Insn::MsrImmMsrSiPstate { crm };
            let err = admit_insn(ir(inner)).unwrap_err();
            assert_eq!(
                err,
                RegVirtError::PanUserForm {
                    pc: 0x1000,
                    insn: inner.key(),
                }
            );
            assert!(err.is_instruction_intrinsic());
        }
    }

    fn assert_commit_after_last_access(original: A64Insn, lowered: &[RephrasedInsn]) {
        let last_access = lowered
            .iter()
            .rposition(|insn| insn.kind == RephrasedInsnKind::UserAccess)
            .unwrap_or_else(|| panic!("{original:?} lowered without a user access"));
        let first_access = lowered
            .iter()
            .position(|insn| insn.kind == RephrasedInsnKind::UserAccess)
            .unwrap();
        let accesses = lowered
            .iter()
            .filter(|insn| insn.kind == RephrasedInsnKind::UserAccess)
            .count();
        let expected = if original.get_reg("Rt2").is_some() {
            2
        } else {
            1
        };
        assert_eq!(accesses, expected, "{original:?}: {lowered:?}");
        for insn in lowered {
            if insn.kind != RephrasedInsnKind::UserAccess {
                assert!(
                    !insn.insn.is_unprivileged_access(),
                    "{original:?}: untagged user access"
                );
            }
            if insn.kind == RephrasedInsnKind::UserAccess {
                assert!(insn.insn.is_unprivileged_access());
            } else if insn.insn.accesses_memory() {
                // Runtime accesses: fills/spills, always SP-based frame slots.
                assert_eq!(insn.kind, RephrasedInsnKind::RegVirtHelper);
                assert_eq!(insn.insn.get_reg("Rn").unwrap().enc, 31);
            }
        }
        for (index, insn) in lowered[..last_access].iter().enumerate() {
            if matches!(insn.insn, A64Insn::StrImmGenStr64LdstPos { .. }) {
                panic!("{original:?}: spill before the last user access: {lowered:?}");
            }
            for role in insn.insn.operand_roles() {
                let (A64OperandRole::RegWrite { field, .. }
                | A64OperandRole::RegReadWrite { field, .. }) = *role
                else {
                    continue;
                };
                let reg = insn.insn.get_reg(field).unwrap();
                assert!(
                    reg.enc == 31
                        || (crate::shared::abi::REG_VIRT_SCRATCH_GPR_START
                            ..=crate::shared::abi::REG_VIRT_SCRATCH_GPR_END)
                            .contains(&reg.enc),
                    "{original:?}: {:?} writes x{} before the last user access: {lowered:?}",
                    insn.insn,
                    reg.enc
                );
                // Once the accesses have started, nothing may clobber a later base.
                if index < first_access {
                    continue;
                }
                for later in lowered[index + 1..]
                    .iter()
                    .filter(|later| later.kind == RephrasedInsnKind::UserAccess)
                {
                    assert_ne!(
                        later.insn.get_reg("Rn").unwrap().enc,
                        reg.enc,
                        "{original:?}: base clobbered before a later access: {lowered:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn rejects_constrained_unpredictable_memory_overlaps() {
        assert_eq!(
            validate_one(RephrasedInsn::original(
                0x1000,
                A64Insn::LdrImmGenLdr64LdstImmpost {
                    rt: x(1),
                    mem: A64Mem::post_index(A64Reg::x_sp(1), A64Imm::signed(8, 9)),
                },
            )),
            Err(RegVirtError::UnpredictableMemoryOp {
                pc: 0x1000,
                insn: "LDR_imm_gen.LDR_64_ldst_immpost",
            })
        );
        assert_eq!(
            validate_one(RephrasedInsn::original(
                0x1000,
                A64Insn::LdpGenLdp64LdstpairOff {
                    rt2: x(2),
                    rt: x(2),
                    mem: A64Mem::offset(A64Reg::x_sp(0), ldstpair64_offset(0)),
                },
            )),
            Err(RegVirtError::UnpredictableMemoryOp {
                pc: 0x1000,
                insn: "LDP_gen.LDP_64_ldstpair_off",
            })
        );
        // A7b forms reach the same role-driven rule.
        let unpredictable = [
            A64Insn::LdrbImmLdrb32LdstImmpost {
                rt: A64Reg::w(3),
                mem: A64Mem::post_index(A64Reg::x_sp(3), A64Imm::signed(1, 9)),
            },
            A64Insn::StrhImmStrh32LdstImmpre {
                rt: A64Reg::w(4),
                mem: A64Mem::pre_index(A64Reg::x_sp(4), A64Imm::signed(2, 9)),
            },
            A64Insn::LdrswImmLdrsw64LdstImmpre {
                rt: x(5),
                mem: A64Mem::pre_index(A64Reg::x_sp(5), A64Imm::signed(4, 9)),
            },
            A64Insn::LdpGenLdp32LdstpairOff {
                rt2: A64Reg::w(6),
                rt: A64Reg::w(6),
                mem: A64Mem::offset(A64Reg::x_sp(0), A64Imm::scaled_signed(0, 7, 2)),
            },
            A64Insn::LdpswLdpsw64LdstpairPost {
                rt2: x(7),
                rt: x(8),
                mem: A64Mem::post_index(A64Reg::x_sp(7), A64Imm::scaled_signed(2, 7, 2)),
            },
            A64Insn::StpGenStp32LdstpairPre {
                rt2: A64Reg::w(1),
                rt: A64Reg::w(2),
                mem: A64Mem::pre_index(A64Reg::x_sp(1), A64Imm::scaled_signed(2, 7, 2)),
            },
        ];
        for insn in unpredictable {
            assert_eq!(
                validate_one(RephrasedInsn::original(0x1000, insn)),
                Err(RegVirtError::UnpredictableMemoryOp {
                    pc: 0x1000,
                    insn: insn.key(),
                }),
                "{insn:?}"
            );
        }
        // No writeback, so rt == rn (and rt == rm) is well defined.
        validate_one(RephrasedInsn::original(
            0x1000,
            A64Insn::LdrRegGenLdr64LdstRegoff {
                rm: x(1),
                option: 0b011,
                s: 0,
                rn: A64Reg::x_sp(1),
                rt: x(1),
            },
        ))
        .unwrap();
        // Base SP (reg 31) with transfer XZR (also reg 31) is not an overlap.
        validate_one(RephrasedInsn::original(
            0x1000,
            A64Insn::LdrImmGenLdr64LdstImmpost {
                rt: xzr(),
                mem: A64Mem::post_index(A64Reg::x_sp(31), A64Imm::signed(8, 9)),
            },
        ))
        .unwrap();
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
    fn stack_backed_runtime_exit_source_captures_from_frame_slot() {
        let program = virtualize_registers(program_from_insns(&[
            RephrasedInsn::runtime_exit_payload(
                0x1000,
                A64Insn::OrrLogShiftOrr64LogShift {
                    shift: 0,
                    rm: x(16),
                    imm6: uimm(0, 6),
                    rn: xzr(),
                    rd: x(10),
                },
            ),
            RephrasedInsn::runtime_exit_branch(0x1000, runtime_branch()),
        ]))
        .unwrap();

        assert_eq!(
            &program[0].insns[..],
            [
                RephrasedInsn::reg_virt_helper(
                    0x1000,
                    A64Insn::LdrImmGenLdr64LdstPos {
                        rt: x(12),
                        mem: frame_slot(176),
                    },
                ),
                RephrasedInsn::reg_virt_helper(
                    0x1000,
                    A64Insn::StrImmGenStr64LdstPos {
                        rt: x(9),
                        mem: pt_regs_slot(9),
                    },
                ),
                RephrasedInsn::reg_virt_helper(
                    0x1000,
                    A64Insn::StrImmGenStr64LdstPos {
                        rt: x(10),
                        mem: pt_regs_slot(10),
                    },
                ),
                RephrasedInsn::reg_virt_helper(
                    0x1000,
                    A64Insn::StrImmGenStr64LdstPos {
                        rt: x(11),
                        mem: pt_regs_slot(11),
                    },
                ),
                RephrasedInsn::runtime_exit_payload(
                    0x1000,
                    A64Insn::LdrImmGenLdr64LdstPos {
                        rt: x(10),
                        mem: frame_slot(48),
                    },
                ),
                RephrasedInsn::runtime_exit_branch(0x1000, runtime_branch()),
            ]
        );
    }

    #[test]
    fn br_x9_runtime_exit_preserves_user_regs_and_captures_before_status() {
        let status = movz(x(RET_STATUS_REG));
        let resume = movz(x(RET_PARAM1_REG));
        let program = virtualize_registers(program_from_insns(&[
            RephrasedInsn::runtime_exit_payload(0x1000, status),
            RephrasedInsn::runtime_exit_payload(0x1000, copy_param0_from(x(9))),
            RephrasedInsn::runtime_exit_payload(0x1000, resume),
            RephrasedInsn::runtime_exit_branch(0x1000, runtime_branch()),
        ]))
        .unwrap();

        assert_eq!(
            &program[0].insns[..],
            [
                RephrasedInsn::reg_virt_helper(
                    0x1000,
                    A64Insn::LdrImmGenLdr64LdstPos {
                        rt: x(12),
                        mem: frame_slot(176),
                    },
                ),
                RephrasedInsn::reg_virt_helper(
                    0x1000,
                    A64Insn::StrImmGenStr64LdstPos {
                        rt: x(9),
                        mem: pt_regs_slot(9),
                    },
                ),
                RephrasedInsn::reg_virt_helper(
                    0x1000,
                    A64Insn::StrImmGenStr64LdstPos {
                        rt: x(10),
                        mem: pt_regs_slot(10),
                    },
                ),
                RephrasedInsn::reg_virt_helper(
                    0x1000,
                    A64Insn::StrImmGenStr64LdstPos {
                        rt: x(11),
                        mem: pt_regs_slot(11),
                    },
                ),
                RephrasedInsn::runtime_exit_payload(0x1000, copy_param0_from(x(9))),
                RephrasedInsn::runtime_exit_payload(0x1000, status),
                RephrasedInsn::runtime_exit_payload(0x1000, resume),
                RephrasedInsn::runtime_exit_branch(0x1000, runtime_branch()),
            ]
        );
    }

    #[test]
    fn blr_x30_runtime_exit_captures_old_lr_before_link_update() {
        let link_update = movz(x(30));
        let status = movz(x(RET_STATUS_REG));
        let program = virtualize_registers(program_from_insns(&[
            RephrasedInsn::runtime_exit_payload(0x1000, copy_param0_from(x(30))),
            RephrasedInsn::user_synthetic(0x1000, link_update),
            RephrasedInsn::runtime_exit_payload(0x1000, status),
            RephrasedInsn::runtime_exit_branch(0x1000, runtime_branch()),
        ]))
        .unwrap();

        assert_eq!(
            &program[0].insns[..],
            [
                RephrasedInsn::reg_virt_helper(
                    0x1000,
                    A64Insn::LdrImmGenLdr64LdstPos {
                        rt: x(12),
                        mem: frame_slot(176),
                    },
                ),
                RephrasedInsn::reg_virt_helper(
                    0x1000,
                    A64Insn::StrImmGenStr64LdstPos {
                        rt: x(9),
                        mem: pt_regs_slot(9),
                    },
                ),
                RephrasedInsn::reg_virt_helper(
                    0x1000,
                    A64Insn::StrImmGenStr64LdstPos {
                        rt: x(10),
                        mem: pt_regs_slot(10),
                    },
                ),
                RephrasedInsn::reg_virt_helper(
                    0x1000,
                    A64Insn::StrImmGenStr64LdstPos {
                        rt: x(11),
                        mem: pt_regs_slot(11),
                    },
                ),
                RephrasedInsn::runtime_exit_payload(0x1000, copy_param0_from(x(30))),
                RephrasedInsn::user_synthetic(0x1000, link_update),
                RephrasedInsn::runtime_exit_payload(0x1000, status),
                RephrasedInsn::runtime_exit_branch(0x1000, runtime_branch()),
            ]
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
            Err(RegVirtError::ScratchPoolExhausted {
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

    fn ir(inner: A64Insn) -> IrInsn {
        IrInsn {
            pc: 0x1000,
            word: inner.encode().unwrap(),
            inner,
        }
    }

    #[test]
    fn admission_rejects_what_rewrite_rejects_as_intrinsic() {
        let unpredictable = A64Insn::LdrImmGenLdr64LdstImmpost {
            rt: x(1),
            mem: A64Mem::post_index(A64Reg::x_sp(1), A64Imm::signed(8, 9)),
        };
        let err = admit_insn(ir(unpredictable)).unwrap_err();

        assert_eq!(
            err,
            RegVirtError::UnpredictableMemoryOp {
                pc: 0x1000,
                insn: "LDR_imm_gen.LDR_64_ldst_immpost",
            }
        );
        assert!(err.is_instruction_intrinsic());
        assert_eq!(
            validate_one(RephrasedInsn::original(0x1000, unpredictable)),
            Err(err)
        );
    }

    #[test]
    fn admission_rejects_user_ldtr_sttr_as_intrinsic() {
        for inner in [
            A64Insn::LdtrLdtr64LdstUnpriv {
                rt: x(0),
                mem: A64Mem::offset(A64Reg::x_sp(1), A64Imm::signed(8, 9)),
            },
            A64Insn::LdtrLdtr32LdstUnpriv {
                rt: A64Reg::w(0),
                mem: A64Mem::offset(A64Reg::x_sp(1), A64Imm::signed(0, 9)),
            },
            A64Insn::SttrSttr64LdstUnpriv {
                rt: x(2),
                mem: A64Mem::offset(A64Reg::x_sp(31), A64Imm::signed(0, 9)),
            },
            A64Insn::SttrSttr32LdstUnpriv {
                rt: A64Reg::w(2),
                mem: A64Mem::offset(A64Reg::x_sp(3), A64Imm::signed(0, 9)),
            },
        ] {
            let err = admit_insn(ir(inner)).unwrap_err();
            assert_eq!(
                err,
                RegVirtError::UnprivilegedUserAccess {
                    pc: 0x1000,
                    insn: inner.key(),
                }
            );
            assert!(err.is_instruction_intrinsic());
        }
    }

    #[test]
    fn fault_stub_groups_in_the_cold_region_are_virtualized_like_exit_groups() {
        let mut program = one_insn(RephrasedInsn::original(0x1000, movz(x(0))));
        program[0]
            .cold
            .push(
                RephrasedInsn::runtime_exit_payload(0x1000, movz(x(RET_STATUS_REG))),
                GFP_KERNEL,
            )
            .unwrap();
        program[0]
            .cold
            .push(
                RephrasedInsn::runtime_exit_branch(0x1000, runtime_branch()),
                GFP_KERNEL,
            )
            .unwrap();
        let program = virtualize_registers(program).unwrap();
        // x9-x11 are preserved to pt_regs before the payload, as for any exit.
        assert_eq!(program[0].cold.len(), 6);
        assert_eq!(program[0].cold[0].kind, RephrasedInsnKind::RegVirtHelper);

        // A non-exit instruction in the cold region is malformed.
        let mut program = one_insn(RephrasedInsn::original(0x1000, movz(x(0))));
        program[0]
            .cold
            .push(RephrasedInsn::original(0x1000, movz(x(1))), GFP_KERNEL)
            .unwrap();
        assert_eq!(
            virtualize_registers(program).unwrap_err(),
            RegVirtError::MalformedRuntimeExitGroup { pc: 0x1000 }
        );
    }

    /// The budget check passes through unchanged and stays before the back-edge's
    /// fills, so its scratch use cannot clash with them.
    #[test]
    fn budget_check_precedes_the_back_edge_fills_and_is_not_rewritten() {
        use crate::shared::trans::rephrase::budget_check;

        let cbnz = A64Insn::CbnzCbnz64Compbranch {
            imm19: A64Imm::scaled_signed(0, 19, 2),
            rt: x(12),
        };
        let check = budget_check(0x1000);
        let mut raw = check.to_vec();
        raw.push(RephrasedInsn::original(0x1000, cbnz));
        let program = virtualize_registers(program_from_insns(&raw)).unwrap();

        let insns = &program[0].insns;
        assert_eq!(&insns[..4], &check);
        assert_eq!(insns[4], fill(12, 12));
        assert_eq!(insns[5], RephrasedInsn::original(0x1000, cbnz));
        assert_eq!(insns.len(), 6);

        // Never inside an exit group or the cold region.
        let mut program = one_insn(RephrasedInsn::original(0x1000, movz(x(0))));
        program[0].cold.push(check[0], GFP_KERNEL).unwrap();
        assert_eq!(
            virtualize_registers(program).unwrap_err(),
            RegVirtError::MalformedRuntimeExitGroup { pc: 0x1000 }
        );
    }

    #[test]
    fn admission_accepts_runtime_exits_and_expansions_on_virtualized_registers() {
        for inner in [
            A64Insn::BrBr64BranchReg { rn: x(12) },
            A64Insn::BlrBlr64BranchReg { rn: x(29) },
            A64Insn::RetRet64rBranchReg { rn: x(9) },
            A64Insn::BlBlOnlyBranchImm {
                imm26: A64Imm::scaled_signed(1, 26, 2),
            },
            A64Insn::SvcSvcExException {
                imm16: A64Imm::unsigned(0, 16),
            },
            A64Insn::AdrAdrOnlyPcreladdr {
                immlo: A64Imm::unsigned(0, 2),
                immhi: A64Imm::unsigned(1, 19),
                rd: x(13),
            },
        ] {
            admit_insn(ir(inner)).unwrap();
        }
    }

    #[test]
    fn internal_errors_still_fail_virtualization() {
        let err =
            virtualize_registers(one_insn(RephrasedInsn::reg_virt_helper(0x1000, movz(x(0)))))
                .unwrap_err();

        assert_eq!(err, RegVirtError::UnexpectedRegVirtHelper { pc: 0x1000 });
        assert!(!err.is_instruction_intrinsic());
    }
}
