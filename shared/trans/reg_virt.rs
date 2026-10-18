use crate::shared::abi::{
    pt_regs_x_slot_offset, reg_virt_scratch_gpr, reg_virt_stack_backed_slot_offset,
    reg_virt_is_stack_backed, DISPATCH_TARGET_REG, PAN_WINDOW_RANGE_TOP_BIT,
    REG_VIRT_SCRATCH_GPR_LIMIT, REG_VIRT_SCRATCH_GPR_START, REG_VIRT_STABLE_MAPPED_SP_PHYS_REG,
    REG_VIRT_STABLE_MAPPED_X29_PHYS_REG, REG_VIRT_STABLE_MAPPED_X29_REG, REG_VIRT_STACK_BACKED_REG_START, RET_PARAM0_REG,
    RET_PARAM1_REG, RET_STATUS_REG, RUNTIME_FRAME_PT_REGS_PTR_OFFSET, USER_VA_BITS,
};
use crate::shared::arm64::ergo::{ldst64_offset, mem_off, scaled_simm, simm, sp, uimm, x, xzr};
use crate::shared::arm64::{
    A64Atomic, A64FpSimdIndex, A64FpSimdMem, A64FpSimdWriteback, A64Insn, A64Mem, A64OperandRole,
    A64Reg, A64Reg31Mode, A64RegWidth, IrInsn,
};
use crate::shared::platform::{SharedAllocError, SharedResult, SharedVec, GFP_KERNEL};
use crate::shared::trans::rephrase::{
    is_dispatch_miss_param0_copy, push_mov_imm64, rephrase_insn, RephrasedInsn,
    RephrasedInsnKind, RephrasedProgram,
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
    /// in a fragment it would change the kernel's PSTATE.PAN. A fragment contains no
    /// `msr` (A15: the trampoline alone writes PAN), so it is never translated.
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
/// lowers `insn` into, so admission and rewriting cannot drift. Invariant: whether
/// reg-virt can lower an original instruction, and with which scratch registers,
/// is independent of its neighbours. Only the presence of the SP alignment check
/// depends on them (`SpAlignment`, A20), and it never changes the scratch use.
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
        block.insns = forward_slots(&virtualize_insns(&body, false)?)?;
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

    let mut sp_align = SpAlignment::at_block_start();
    let mut index = 0;
    while index < insns.len() {
        let insn = insns[index];
        let first = rewritten.len();
        if insn.kind.is_runtime_exit_payload() {
            index = virtualize_runtime_exit_group(insns, index, &mut rewritten)?;
        } else if cold {
            return Err(RegVirtError::MalformedRuntimeExitGroup { pc: insn.ori_pc });
        } else {
            virtualize_insn(insn, &mut sp_align, &mut rewritten)?;
            index += 1;
        }
        sp_align.observe_writes(&rewritten[first..]);
    }
    Ok(rewritten)
}

/// The scratch registers a fill/spill pair moves through (x12..x15) and the user-state
/// frame slots they move (x12..x17 and x18).
const SCRATCH_REGS: usize = REG_VIRT_SCRATCH_GPR_LIMIT;
const SLOT_COUNT: usize = 7;

/// One reg-virt fill (`ldr xS, [sp, #slot]`) or spill (`str xS, [sp, #slot]`) of a
/// user-state frame slot. `scratch` is `xS - REG_VIRT_SCRATCH_GPR_START`, `slot` the
/// slot's index (the user register number minus 12, x18 last).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SlotMove {
    fill: bool,
    scratch: usize,
    slot: usize,
}

/// `Some` for exactly the words `emit_fills`/`emit_spills` produce (kind
/// `RegVirtHelper`, 64-bit `ldr`/`str` at `[sp, #slot]` of a stack-backed register's
/// slot, through a scratch register). Every other word, the pt_regs pointer load and
/// the dispatch template's table load included, is not a slot move.
fn slot_move(word: &RephrasedInsn) -> Option<SlotMove> {
    if word.kind != RephrasedInsnKind::RegVirtHelper {
        return None;
    }
    let (fill, rt, mem) = match word.insn {
        A64Insn::LdrImmGenLdr64LdstPos { rt, mem } => (true, rt, mem),
        A64Insn::StrImmGenStr64LdstPos { rt, mem } => (false, rt, mem),
        _ => return None,
    };
    let A64Mem::Offset { base, offset } = mem else {
        return None;
    };
    if classify_reg(base) != RegClass::Sp {
        return None;
    }
    let scratch = usize::from(rt.enc.checked_sub(REG_VIRT_SCRATCH_GPR_START)?);
    if scratch >= SCRATCH_REGS {
        return None;
    }
    let offset = u32::try_from(offset.value()).ok()?;
    let slot = (0..SLOT_COUNT).find(|&slot| {
        let user_reg = REG_VIRT_STACK_BACKED_REG_START + slot as u8;
        reg_virt_stack_backed_slot_offset(user_reg) == Some(offset)
    })?;
    Some(SlotMove {
        fill,
        scratch,
        slot,
    })
}

/// An unconditional `b` or `br`: the word after it is a join point.
fn ends_straight_line(insn: A64Insn) -> bool {
    matches!(
        insn,
        A64Insn::BUncondBOnlyBranchImm { .. } | A64Insn::BrBr64BranchReg { .. }
    )
}

fn is_branch(insn: A64Insn) -> bool {
    insn.operand_roles().iter().any(|role| {
        matches!(
            role,
            A64OperandRole::ControlFlow | A64OperandRole::BranchTarget { .. }
        )
    })
}

/// A21 (docs/pipeline.md, "Hot-path word reduction (A21)"): block-local slot
/// forwarding over one block body, after `virtualize_insns`. It only deletes words.
///
/// Pass 1 deletes a fill of `slot` into `xS` while `xS` is known to hold `slot`'s
/// current value: after a fill of `slot` into `xS` or a spill of `xS` to `slot`;
/// forgotten for `xS` at any write to it (generated operand roles; a role whose
/// register the metadata cannot name counts as a write to every register) and for
/// `slot` at a spill of it from another register; forgotten entirely at a join point
/// and at any memory access that is not a fill/spill or a user/window access. User
/// and window accesses cannot alias the kernel stack (LDTR/STTR run with EL0
/// permissions, window accesses are range-checked to the user VA), so they only
/// forget their destination registers.
///
/// Pass 2 deletes a spill of `slot` that a later spill of the same `slot` overwrites
/// in the same straight-line run. Anything that can observe a slot ends the run: a
/// branch (budget, alignment, range, dispatch and exit branches all lead to a stub
/// or the epilogue, which write the slots back), a link slot (a branch once linked),
/// a user or window access (a fault site), any other memory access, an exit payload,
/// a fill of `slot`, a join point and the block end. Deleted fills of pass 1 are not fills.
///
/// Join points inside a body are its first word and the word after an unconditional
/// `b` or `br` (the dispatch template's victim probe and the exit group behind it):
/// a fragment is entered only at a block start (Entry labels (A20)), and every other
/// label of a body is a branch target in the cold region or the epilogue. The cold
/// region is not processed: its exit groups hold no fill that repeats a load.
fn forward_slots(
    body: &[RephrasedInsn],
) -> SharedResult<SharedVec<RephrasedInsn>, RegVirtError> {
    let mut keep: SharedVec<bool> =
        SharedVec::with_capacity(body.len(), GFP_KERNEL).map_err(RegVirtError::Allocation)?;
    for _ in body {
        keep.push(true, GFP_KERNEL)
            .map_err(RegVirtError::Allocation)?;
    }
    let is_join =
        |index: usize| index == 0 || ends_straight_line(body[index - 1].insn);
    // A word that touches memory the pass cannot name: not a fill/spill, not a
    // user or window access.
    let opaque_memory = |word: &RephrasedInsn| {
        word.insn.accesses_memory()
            && !matches!(
                word.kind,
                RephrasedInsnKind::UserAccess | RephrasedInsnKind::WindowAccess
            )
    };

    // Pass 1: forward fills.
    let mut held: [Option<usize>; SCRATCH_REGS] = [None; SCRATCH_REGS];
    for (index, word) in body.iter().enumerate() {
        if is_join(index) {
            held = [None; SCRATCH_REGS];
        }
        match slot_move(word) {
            Some(SlotMove {
                fill: true,
                scratch,
                slot,
            }) => {
                if held[scratch] == Some(slot) {
                    keep[index] = false;
                }
                held[scratch] = Some(slot);
            }
            Some(SlotMove {
                fill: false,
                scratch,
                slot,
            }) => {
                for other in held.iter_mut().filter(|other| **other == Some(slot)) {
                    *other = None;
                }
                held[scratch] = Some(slot);
            }
            None if opaque_memory(word) => held = [None; SCRATCH_REGS],
            None => {
                for (scratch, fact) in held.iter_mut().enumerate() {
                    let reg = REG_VIRT_SCRATCH_GPR_START + scratch as u8;
                    if writes_physical_reg(word.insn, reg) {
                        *fact = None;
                    }
                }
            }
        }
    }

    // Pass 2: dead spills, scanning backwards. `overwritten[slot]`: a later spill of
    // `slot` follows with nothing in between that can observe it.
    let mut overwritten = [false; SLOT_COUNT];
    for (index, word) in body.iter().enumerate().rev() {
        if !keep[index] {
            continue;
        }
        match slot_move(word) {
            Some(SlotMove {
                fill: true, slot, ..
            }) => overwritten[slot] = false,
            Some(SlotMove {
                fill: false, slot, ..
            }) => {
                if overwritten[slot] {
                    keep[index] = false;
                }
                overwritten[slot] = true;
            }
            None => {
                // A link slot is a `nop` here, but the runtime may patch it into a
                // `b` to another fragment (A16), which then reads the slots.
                let observes = is_branch(word.insn)
                    || word.insn.accesses_memory()
                    || matches!(
                        word.kind,
                        RephrasedInsnKind::RuntimeExitPayload
                            | RephrasedInsnKind::RuntimeExitBranch
                            | RephrasedInsnKind::LinkSlot { .. }
                    );
                if observes {
                    overwritten = [false; SLOT_COUNT];
                }
            }
        }
        if is_join(index) {
            overwritten = [false; SLOT_COUNT];
        }
    }

    let kept = keep.iter().filter(|&&kept| kept).count();
    let mut out =
        SharedVec::with_capacity(kept, GFP_KERNEL).map_err(RegVirtError::Allocation)?;
    for (word, _) in body.iter().zip(keep.iter()).filter(|(_, &kept)| kept) {
        push_rephrased(&mut out, *word)?;
    }
    Ok(out)
}

/// A20 (docs/pipeline.md, "SP alignment check deduplication (A20)"): the one fact
/// reg-virt carries from one original instruction to the next. Per block: it starts
/// unknown (`virtualize_insns` makes a fresh one for every block).
///
/// - Known aligned: after an SP alignment check (its `cbnz` not taken), while physical
///   x17 (user SP) is written only by `add`/`sub x17, x17, #imm` with `imm % 16 == 0`.
/// - Unknown: at the block start and after any other write to x17.
///
/// Every elided check would have passed, so each access that natively faults with
/// SIGBUS still gets its check. Sound because a block is entered only at its start
/// (docs/pipeline.md, "Entry labels (A20)": `ExecutionFragment::entry_labels`), so the fact
/// holds on every path to a word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SpAlignment {
    known_aligned: bool,
}

impl SpAlignment {
    const fn at_block_start() -> Self {
        Self {
            known_aligned: false,
        }
    }

    /// Whether an SP-based access must be preceded by the check.
    const fn needs_check(self) -> bool {
        !self.known_aligned
    }

    /// An SP alignment check was just emitted: past its `cbnz`, SP is aligned.
    fn checked(&mut self) {
        self.known_aligned = true;
    }

    /// Updates the fact for the words one original instruction lowered to (after
    /// `checked`, if it emitted the check, which comes before everything else of the
    /// instruction).
    fn observe_writes(&mut self, lowered: &[RephrasedInsn]) {
        for word in lowered {
            if writes_physical_reg(word.insn, REG_VIRT_STABLE_MAPPED_SP_PHYS_REG)
                && !is_sp_adjust_by_multiple_of_16(word.insn)
            {
                self.known_aligned = false;
            }
        }
    }
}

/// Whether `insn` writes physical register `reg` (an exhaustive read of its operand
/// roles). A role whose register the metadata cannot name counts as a write: the
/// caller gives up its fact.
fn writes_physical_reg(insn: A64Insn, reg: u8) -> bool {
    insn.operand_roles().iter().any(|role| match *role {
        A64OperandRole::RegWrite { field, .. } | A64OperandRole::RegReadWrite { field, .. } => {
            insn.get_reg(field)
                .map_or(true, |written| written.enc == reg)
        }
        A64OperandRole::ImplicitRegWrite { reg: written, .. } => written == reg,
        _ => false,
    })
}

/// `add`/`sub x17, x17, #imm` (optionally `lsl #12`) with an effective `imm % 16 == 0`:
/// the only write to user SP that keeps an aligned SP aligned.
fn is_sp_adjust_by_multiple_of_16(insn: A64Insn) -> bool {
    let sp = REG_VIRT_STABLE_MAPPED_SP_PHYS_REG;
    match insn {
        A64Insn::AddAddsubImmAdd64AddsubImm { sh, imm12, rn, rd }
        | A64Insn::SubAddsubImmSub64AddsubImm { sh, imm12, rn, rd } => {
            rn.enc == sp && rd.enc == sp && (imm12.raw() << (12 * u32::from(sh))) % 16 == 0
        }
        _ => false,
    }
}

fn virtualize_insn(
    rephrased: RephrasedInsn,
    sp_align: &mut SpAlignment,
    out: &mut SharedVec<RephrasedInsn>,
) -> SharedResult<(), RegVirtError> {
    match rephrased.kind {
        kind if kind.is_user_semantic() => rewrite_user_semantic(rephrased, sp_align, out),
        RephrasedInsnKind::RuntimeExitPayload => {
            validate_runtime_exit_payload(rephrased)?;
            push_rephrased(out, rephrased)
        }
        RephrasedInsnKind::RuntimeExitBranch => push_rephrased(out, rephrased),
        // Runtime-owned (`sub x18, x18, #1; cbz x18, <stub>`: physical x18 is the budget
        // counter, user x18 is stack-backed) and placed at an instruction boundary:
        // nothing to map.
        RephrasedInsnKind::BudgetCheck => push_rephrased(out, rephrased),
        // The dispatch template (A11) is runtime-owned scratch code (x12, x13, x14 at an
        // instruction boundary): nothing to map.
        RephrasedInsnKind::DispatchLookup => push_rephrased(out, rephrased),
        RephrasedInsnKind::DispatchTarget => emit_dispatch_target(rephrased, out),
        // A16: a `nop` the runtime may patch (no registers): nothing to map.
        RephrasedInsnKind::LinkSlot { .. } => push_rephrased(out, rephrased),
        // These kinds are reg-virt output; seeing one here is a pipeline bug.
        RephrasedInsnKind::RegVirtHelper
        | RephrasedInsnKind::UserAccess
        | RephrasedInsnKind::AlignCheck
        | RephrasedInsnKind::RangeCheck
        | RephrasedInsnKind::WindowAccess => Err(RegVirtError::UnexpectedRegVirtHelper {
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
        emit_register_capture(
            pc,
            source,
            RET_PARAM0_REG,
            RephrasedInsnKind::RuntimeExitPayload,
            out,
        )?;
    }

    for payload in payloads {
        match payload.kind {
            RephrasedInsnKind::RuntimeExitPayload
                if runtime_param0_capture_source(payload.insn).is_some() => {}
            RephrasedInsnKind::RuntimeExitPayload => {
                validate_runtime_exit_payload(*payload)?;
                push_rephrased(out, *payload)?;
            }
            // A runtime-exit group ends its block: nothing after it uses the fact (its
            // writes reach `virtualize_insns`' `observe_writes` all the same).
            RephrasedInsnKind::UserSynthetic => {
                rewrite_user_semantic(*payload, &mut SpAlignment::at_block_start(), out)?;
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

/// `dest = <user register source>`, for the one physical destination `dest` and
/// output kind `kind` (the exit group's RET_PARAM0 capture, or a dispatch site's
/// target in x13). `source` is a user register, so it is mapped: loaded from its
/// frame slot when stack-backed, read from x16/x17 for user x29/sp, copied as is
/// otherwise.
fn emit_register_capture(
    pc: u64,
    source: A64Reg,
    dest: u8,
    kind: RephrasedInsnKind,
    out: &mut SharedVec<RephrasedInsn>,
) -> SharedResult<(), RegVirtError> {
    let copy = |source: A64Reg, out: &mut SharedVec<RephrasedInsn>| {
        push_rephrased(
            out,
            RephrasedInsn {
                kind,
                ori_pc: pc,
                insn: A64Insn::OrrLogShiftOrr64LogShift {
                    shift: 0,
                    rm: A64Reg::new(source.enc, A64RegWidth::X64, source.reg31),
                    imm6: uimm(0, 6),
                    rn: xzr(),
                    rd: x(dest),
                },
            },
        )
    };
    match classify_reg(source) {
        RegClass::StackBacked => {
            let offset = reg_virt_stack_backed_slot_offset(source.enc).ok_or(
                RegVirtError::StackBackedRewriteNotImplemented {
                    pc,
                    insn: "register_capture",
                    reg: source,
                },
            )?;
            push_rephrased(
                out,
                RephrasedInsn {
                    kind,
                    ori_pc: pc,
                    insn: A64Insn::LdrImmGenLdr64LdstPos {
                        rt: x(dest),
                        mem: mem_off(sp(), ldst64_offset(offset)),
                    },
                },
            )
        }
        RegClass::StableMapped => copy(x(REG_VIRT_STABLE_MAPPED_X29_PHYS_REG), out),
        RegClass::Sp => copy(x(REG_VIRT_STABLE_MAPPED_SP_PHYS_REG), out),
        RegClass::Zero | RegClass::Direct | RegClass::RuntimeReserved => copy(source, out),
    }
}

/// A dispatch site's target move (A11): `movz`/`movk x13, #imm` (BL) pass through;
/// `orr x13, xzr, X<user>` is a capture of a user register.
fn emit_dispatch_target(
    rephrased: RephrasedInsn,
    out: &mut SharedVec<RephrasedInsn>,
) -> SharedResult<(), RegVirtError> {
    let pc = rephrased.ori_pc;
    match rephrased.insn {
        A64Insn::MovzMovz64Movewide { rd, .. } | A64Insn::MovkMovk64Movewide { rd, .. }
            if rd.enc == DISPATCH_TARGET_REG =>
        {
            push_rephrased(out, rephrased)
        }
        A64Insn::OrrLogShiftOrr64LogShift {
            shift: 0,
            rm,
            imm6,
            rn,
            rd,
        } if imm6.raw() == 0 && is_zero_reg(rn) && rd.enc == DISPATCH_TARGET_REG => {
            emit_register_capture(pc, rm, DISPATCH_TARGET_REG, RephrasedInsnKind::DispatchTarget, out)
        }
        _ => Err(RegVirtError::MalformedRuntimeExitGroup { pc }),
    }
}

fn rewrite_user_semantic(
    rephrased: RephrasedInsn,
    sp_align: &mut SpAlignment,
    out: &mut SharedVec<RephrasedInsn>,
) -> SharedResult<(), RegVirtError> {
    let plan = RewritePlan::build(rephrased)?;

    plan.emit_fills(rephrased.ori_pc, out)?;
    match plan.mem {
        Some(MemPlan::Unpriv(mem)) => plan.emit_mem_lowering(rephrased, mem, sp_align, out)?,
        Some(MemPlan::Window(window)) => plan.emit_window(rephrased, window, sp_align, out)?,
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
        // SIMD&FP registers (A9a) are user registers live in hardware while a
        // fragment runs: never virtualized.
        A64OperandRole::ImplicitRegWrite { .. }
        | A64OperandRole::MemOffset { .. }
        | A64OperandRole::BranchTarget { .. }
        | A64OperandRole::FlagsRead
        | A64OperandRole::FlagsWrite
        | A64OperandRole::ControlFlow
        | A64OperandRole::Memory
        | A64OperandRole::VecRead { .. }
        | A64OperandRole::VecWrite { .. } => None,
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

/// The one privileged user access a window access is: an LSE atomic (A8) or an A9a
/// SIMD&FP load/store (docs/pipeline.md, "FP/SIMD in fragments (A9)"). Neither has an
/// unprivileged form, so the fragment runs the user's own access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WindowInsn {
    Atomic(A64Atomic),
    FpSimd(A64FpSimdMem),
}

impl WindowInsn {
    const fn base(self) -> A64Reg {
        match self {
            Self::Atomic(atomic) => atomic.rn,
            Self::FpSimd(mem) => mem.base,
        }
    }

    /// The access address is `base + offset` (an atomic has no offset).
    const fn offset(self) -> i64 {
        match self {
            Self::Atomic(_) => 0,
            Self::FpSimd(mem) => mem.offset,
        }
    }

    /// A18 register-offset SIMD&FP forms: the address is `base + ExtendReg(index)`.
    const fn index(self) -> Option<A64FpSimdIndex> {
        match self {
            Self::Atomic(_) => None,
            Self::FpSimd(mem) => mem.index,
        }
    }
}

/// How one window access (A8, A9a) is lowered (see `emit_window`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WindowLowering {
    insn: WindowInsn,
    /// `sA`: the register holding the access address the window checks and the
    /// access uses as its base. For a base-only access (offset 0, no index; A21) it
    /// is the register the base already lives in (a stack-backed base's fill
    /// scratch, or its physical register), else a fresh scratch loaded from
    /// `addr_base`.
    addr: u8,
    /// `sA = <mapped base> + offset` (`add`/`sub`), or for a register-offset form
    /// `sA = <mapped base> + ExtendReg(<mapped index>)`. `None`: `sA` is the base.
    addr_base: Option<A64Reg>,
    /// `sB`: the range check's result; also the SP / block alignment check's
    /// scratch, which run first.
    check: u8,
    /// SP base: `and sB, x17, #15; cbnz sB, <Mem stub>` (EL0 SP alignment check).
    sp_check: bool,
    /// Atomic wider than a byte, base not SP: the 16-byte block alignment check.
    block_check: bool,
}

/// The memory lowering of one user instruction: `LDTR*`/`STTR*` accesses, or one
/// privileged access (a window access).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemPlan {
    Unpriv(MemLowering),
    Window(WindowLowering),
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
            let window = match (insn.lse_atomic(), insn.fpsimd_mem()) {
                (Some(atomic), _) => Some(WindowInsn::Atomic(atomic)),
                (None, Some(mem)) => Some(WindowInsn::FpSimd(mem)),
                (None, None) => None,
            };
            plan.mem = Some(match window {
                Some(window) => {
                    MemPlan::Window(plan.plan_window(window)?)
                }
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

    /// Scratch for a window access (A8, A9a). Stack-backed operands were mapped first
    /// (role order), so the worst case is three of them plus `sB` (an atomic), or
    /// two plus `sA` and `sB` (an atomic, or LD1/ST1 post-indexed by a register): four.
    fn plan_window(&mut self, insn: WindowInsn) -> SharedResult<WindowLowering, RegVirtError> {
        let base = insn.base();
        let base_class = classify_reg(base);
        let (addr, addr_base) = if insn.offset() == 0 && insn.index().is_none() {
            // A21: the address is the base itself, so `sA` is the register the base
            // lives in and nothing is copied. A stack-backed base is mapped by the
            // `MemBase` role in `build` (missing is a translator bug); every other
            // base is a physical register already (direct, or x16/x17 for x29/SP).
            // The checks only read `sA` and the access reads it before writing its
            // destination, so only scratch is written ahead of the access.
            let register = match base_class {
                RegClass::StackBacked => {
                    self.stack_mapping(base.enc)
                        .ok_or(RegVirtError::StackBackedRewriteNotImplemented {
                            pc: self.pc,
                            insn: self.insn,
                            reg: base,
                        })?
                        .scratch
                }
                RegClass::Direct
                | RegClass::RuntimeReserved
                | RegClass::StableMapped
                | RegClass::Sp => self.phys(base).enc,
                // Encoding 31 of a window base names SP (`Rn|SP`), never XZR; a decoded
                // XZR base would be a metadata error, and native execution is exact.
                RegClass::Zero => {
                    return Err(RegVirtError::UnsupportedSpOperand {
                        pc: self.pc,
                        insn: self.insn,
                        field: "Rn",
                        reg: base,
                    })
                }
            };
            (register, None)
        } else {
            (self.alloc_scratch()?, Some(x(self.phys(base).enc)))
        };
        let check = self.alloc_scratch()?;
        let sp_check = base_class == RegClass::Sp;
        let block_check =
            matches!(insn, WindowInsn::Atomic(atomic) if atomic.size > 1) && !sp_check;
        Ok(WindowLowering {
            insn,
            addr,
            addr_base,
            check,
            sp_check,
            block_check,
        })
    }

    /// Emits one window access (docs/pipeline.md, "LSE atomics through a PAN
    /// window (A8)", "FP/SIMD in fragments (A9)" and "Run-scoped PAN clear (A15)")
    /// between its fills and spills; the run executes with PAN clear, so the access
    /// needs no PSTATE write:
    ///
    /// ```text
    ///   [and sB, x17, #15; cbnz sB, <Mem stub>]         SP base: EL0 SP alignment
    ///   [add/sub sA, <mapped base>, #offset]             SIMD&FP offset/pre-index forms
    ///   [and sB, sA, #15; add sB, sB, #(size - 1);
    ///    and sB, sB, #16; cbnz sB, <Mem stub>]           atomic wider than a byte, base not SP
    ///   ubfx sB, sA, #48, #8                             VA bits [55:48]
    ///   cbnz sB, <Mem stub>                              not a TTBR0 user address
    ///   <the access, base = sA>                          fault site -> Mem stub
    ///   [add/sub <mapped base>, <mapped base>, #amount   SIMD&FP writeback
    ///    | add <mapped base>, <mapped base>, <mapped Xm>]
    /// ```
    ///
    /// The access is the atomic with its operands mapped, or the SIMD&FP load/store
    /// in its base-only encoding (`A64FpSimdMem::access`: same access, `#0`, no
    /// writeback), so the range check covers its start address and the access
    /// (at most 64 bytes) cannot reach the kernel half. Commit-after-last-access:
    /// before the access only scratch is written; the access writes its
    /// destination (`Rt`, CAS's `Rs`, or V registers) only when it retires; the
    /// base writeback and spills follow it. An atomic crossing a
    /// 16-byte boundary alignment-faults natively (FEAT_LSE2; `MemSingleGranule()`
    /// is at least 16), so leaving for it is exact or conservative: userspace
    /// re-executes the instruction natively either way.
    fn emit_window(
        &self,
        rephrased: RephrasedInsn,
        lowering: WindowLowering,
        sp_align: &mut SpAlignment,
        out: &mut SharedVec<RephrasedInsn>,
    ) -> SharedResult<(), RegVirtError> {
        let pc = rephrased.ori_pc;
        let (sa, sb) = (lowering.addr, lowering.check);
        let helper = |insn| RephrasedInsn::reg_virt_helper(pc, insn);
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

        if lowering.sp_check && sp_align.needs_check() {
            for check in [and_15(REG_VIRT_STABLE_MAPPED_SP_PHYS_REG), cbnz()] {
                push_rephrased(out, RephrasedInsn::align_check(pc, check))?;
            }
            sp_align.checked();
        }
        if let Some(base) = lowering.addr_base {
            match (lowering.insn.index(), lowering.insn.offset()) {
                // A18: `add sA, <base>, <index>, <extend> #shift` (ADD extended
                // register, the address arithmetic of the register-offset form).
                (Some(index), _) => push_rephrased(
                    out,
                    helper(A64Insn::AddAddsubExtAdd64AddsubExt {
                        rm: x(self.phys(index.reg).enc),
                        option: index.option,
                        imm3: uimm(u32::from(index.shift), 3),
                        rn: A64Reg::x_sp(base.enc),
                        rd: A64Reg::x_sp(sa),
                    }),
                )?,
                (None, offset) => self.push_add_sub_imm(out, helper, sa, base.enc, offset)?,
            }
        }
        if let (true, WindowInsn::Atomic(atomic)) = (lowering.block_check, lowering.insn) {
            let checks = [
                and_15(sa),
                A64Insn::AddAddsubImmAdd64AddsubImm {
                    sh: 0,
                    imm12: uimm(u32::from(atomic.size) - 1, 12),
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

        let access = match lowering.insn {
            WindowInsn::Atomic(_) => self.rewrite_insn(rephrased)?,
            WindowInsn::FpSimd(mem) => mem.access,
        }
        .set_reg("Rn", A64Reg::x_sp(sa))
        .map_err(|_| RegVirtError::MissingRegisterSetter {
            pc,
            insn: self.insn,
            field: "Rn",
        })?;
        push_rephrased(out, RephrasedInsn::window_access(pc, access))?;

        let WindowInsn::FpSimd(mem) = lowering.insn else {
            return Ok(());
        };
        let base = self.phys(mem.base).enc;
        match mem.writeback {
            None => Ok(()),
            Some(A64FpSimdWriteback::Imm(amount)) => self.push_add_sub_imm(
                out,
                |insn| RephrasedInsn { insn, ..rephrased },
                base,
                base,
                amount,
            ),
            Some(A64FpSimdWriteback::Reg(index)) => push_rephrased(
                out,
                RephrasedInsn {
                    insn: A64Insn::AddAddsubShiftAdd64AddsubShift {
                        shift: 0,
                        rm: x(self.phys(index).enc),
                        imm6: uimm(0, 6),
                        rn: x(base),
                        rd: x(base),
                    },
                    ..rephrased
                },
            ),
        }
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
    /// Acquire/release forms (A7c; docs/pipeline.md "Barriers and acquire/release (A7c)")
    /// become `[alignment check] dmb ish; LDTR*/STTR* [xN, #0]; dmb ish`: no
    /// unprivileged ordered access exists without FEAT_LSUI, and the two full
    /// fences order the access at least as strongly as LDAR/STLR/LDAPR.
    fn emit_mem_lowering(
        &self,
        rephrased: RephrasedInsn,
        mem: MemLowering,
        sp_align: &mut SpAlignment,
        out: &mut SharedVec<RephrasedInsn>,
    ) -> SharedResult<(), RegVirtError> {
        let pc = rephrased.ori_pc;
        let shape = mem.shape;
        let helper = |insn| RephrasedInsn::reg_virt_helper(pc, insn);

        if let Some(scratch) = mem.sp_align_scratch.filter(|_| sp_align.needs_check()) {
            // `and xS, <mapped SP>, #15` (N=1, immr=0, imms=3: four ones), then
            // `cbnz xS` to this instruction's Mem stub; layout resolves the target.
            // Flags are untouched. Elided where SP is known aligned (A20).
            let mapped_sp = A64Reg::x(REG_VIRT_STABLE_MAPPED_SP_PHYS_REG);
            push_rephrased(
                out,
                RephrasedInsn::align_check(
                    pc,
                    A64Insn::AndLogImmAnd64LogImm {
                        n: 1,
                        immr: uimm(0, 6),
                        imms: uimm(3, 6),
                        rn: mapped_sp,
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
            sp_align.checked();
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

/// `rd = address` for a literal load's scratch: rephrase's constant helper, as
/// reg-virt output.
fn push_mov_address(
    out: &mut SharedVec<RephrasedInsn>,
    pc: u64,
    rd: u8,
    address: u64,
) -> SharedResult<(), RegVirtError> {
    push_mov_imm64(out, pc, x(rd), address, RephrasedInsnKind::RegVirtHelper)
        .map_err(RegVirtError::Allocation)
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
                // A dispatch miss's RET_PARAM0 = T reads the physical x13 (A11), the one
                // payload that may read a stack-backed number as a runtime register.
                if reg.enc == DISPATCH_TARGET_REG && is_dispatch_miss_param0_copy(insn) {
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
            | A64OperandRole::Memory
            | A64OperandRole::VecRead { .. }
            | A64OperandRole::VecWrite { .. } => {}
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
    if reg_virt_is_stack_backed(reg.enc) {
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

    // SIMD&FP LDP `t == t2` (A9a): the same rule for the V register file.
    let vec_writes = || {
        roles.iter().filter_map(|role| match *role {
            A64OperandRole::VecWrite { field } => Some(field),
            _ => None,
        })
    };
    for field in vec_writes() {
        let reg = insn.field_value(field);
        for other in vec_writes() {
            if other != field && reg.is_some() && insn.field_value(other) == reg {
                return Err(unpredictable);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::arm64::ergo::{
        ldst64_offset, ldstpair64_offset, mem_post, mem_pre, scaled_uimm, uimm, x, xzr,
    };
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

    /// The window access itself: no PSTATE write around it (A15).
    fn window_access(access: A64Insn) -> [RephrasedInsn; 1] {
        [RephrasedInsn::window_access(0x1000, access)]
    }

    /// A8, A15: the exact window access lowering (docs/pipeline.md, "LSE atomics
    /// through a PAN window (A8)").
    #[test]
    fn lse_atomic_lowers_to_the_exact_window_access() {
        let w = A64Reg::w;
        // ldaddal x0, x1, [x2]: A21: the direct base is sA itself, no copy; sB = x12
        // does the block check and the range check.
        let mut expected = block_align_check(12, 2, 8).to_vec();
        expected.extend(range_check(2, 12));
        expected.extend(window_access(A64Insn::LdaddLdaddal64Memop {
            rs: x(0),
            rn: A64Reg::x_sp(2),
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
        expected.extend(window_access(A64Insn::CasCasC64Comswap {
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

        // swpb w0, w16, [sp]: SP check through sB, sA = x17 itself (A21); a byte needs
        // no block check; the old value lands in the stack-backed x16's scratch.
        let mut expected = sp_align_check(13).to_vec();
        expected.extend(range_check(17, 13));
        expected.extend(window_access(A64Insn::SwpbSwpb32Memop {
            rs: w(0),
            rn: A64Reg::x_sp(17),
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

        // stadd w1, [x29]: x29 lives in x16 and is sA (A21); Rt = WZR stays.
        let mut expected = block_align_check(12, 16, 4).to_vec();
        expected.extend(range_check(16, 12));
        expected.extend(window_access(A64Insn::LdaddLdadd32Memop {
            rs: w(1),
            rn: A64Reg::x_sp(16),
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
    /// before the atomic, spills only after it, and the atomic based on the
    /// range-checked register, right after the range check and with no `msr` anywhere.
    #[test]
    fn every_atomic_lowering_is_one_window_committing_after_it() {
        use crate::shared::arm64::GENERATED_A64_SUBSET;
        let regs = [0u8, 9, 12, 13, 14, 16, 17, 29, 30, 31];
        let mut checked = 0;
        for spec in GENERATED_A64_SUBSET {
            let base_insn = A64Insn::decode(crate::shared::arm64::form_base_word(spec)).unwrap();
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
                        let (ubfx, cbnz) = (out[window - 2], out[window - 1]);
                        assert!(out.iter().all(|r| r.insn.msr_pan().is_none()), "{out:?}");
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
                        assert!(scratch.contains(&sb.enc));
                        // A21: sA is the base's own register when it is not stack-backed
                        // (x29 lives in x16, SP in x17), else its fill scratch.
                        match rn {
                            29 => assert_eq!(sa.enc, 16, "{insn:?}: {out:?}"),
                            31 => assert_eq!(sa.enc, 17, "{insn:?}: {out:?}"),
                            0 | 9 | 30 => assert_eq!(sa.enc, rn, "{insn:?}: {out:?}"),
                            _ => assert!(scratch.contains(&sa.enc), "{insn:?}: {out:?}"),
                        }
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
                        for after in &out[window + 1..] {
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

    fn original(insn: A64Insn) -> RephrasedInsn {
        RephrasedInsn::original(0x1000, insn)
    }

    /// A9a: SIMD&FP loads/stores run their base-only encoding as a window access
    /// (docs/pipeline.md, "FP/SIMD in fragments (A9)"): the access address in sA, the writeback
    /// after the access, V registers untouched by reg-virt.
    #[test]
    fn simd_memory_lowers_to_the_exact_window_access() {
        let q_pos = |rt: u8, base: u8| A64Insn::LdrImmFpsimdLdrQLdstPos {
            rt,
            mem: mem_off(A64Reg::x_sp(base), scaled_uimm(0, 12, 4)),
        };
        // ldr q0, [x1, #32]: sA = x1 + 32, sB = x13.
        let mut expected = vec![helper(add_imm(12, 1, 0, 32))];
        expected.extend(range_check(12, 13));
        expected.extend(window_access(q_pos(0, 12)));
        assert_eq!(
            lowered(A64Insn::LdrImmFpsimdLdrQLdstPos {
                rt: 0,
                mem: mem_off(A64Reg::x_sp(1), scaled_uimm(2, 12, 4)),
            })
            .to_vec(),
            expected
        );

        // ldp q0, q1, [x13], #32: the stack-backed base's fill scratch is sA
        // (offset 0); the writeback follows the window, then the spill.
        let mut expected = vec![fill(12, 13)];
        expected.extend(range_check(12, 13));
        expected.extend(window_access(A64Insn::LdpFpsimdLdpQLdstpairOff {
            rt2: 1,
            rt: 0,
            mem: mem_off(A64Reg::x_sp(12), scaled_simm(0, 7, 4)),
        }));
        expected.push(original(add_imm(12, 12, 0, 32)));
        expected.push(spill(12, 13));
        assert_eq!(
            lowered(A64Insn::LdpFpsimdLdpQLdstpairPost {
                rt2: 1,
                rt: 0,
                mem: mem_post(A64Reg::x_sp(13), scaled_simm(2, 7, 4)),
            })
            .to_vec(),
            expected
        );

        // str q2, [sp, #-16]!: SP check through sB, sA = x17 - 16, SP (x17)
        // written back after the window.
        let mut expected = sp_align_check(13).to_vec();
        expected.push(helper(sub_imm(12, 17, 16)));
        expected.extend(range_check(12, 13));
        expected.extend(window_access(A64Insn::StrImmFpsimdStrQLdstPos {
            rt: 2,
            mem: mem_off(A64Reg::x_sp(12), scaled_uimm(0, 12, 4)),
        }));
        expected.push(original(sub_imm(17, 17, 16)));
        assert_eq!(
            lowered(A64Insn::StrImmFpsimdStrQLdstImmpre {
                rt: 2,
                mem: mem_pre(sp(), simm(0x1f0, 9)),
            })
            .to_vec(),
            expected
        );

        // ld1 {v0.16b, v1.16b}, [x14], x15: base and index stack-backed (x12, x13),
        // sA = the base's scratch, sB = x14; post-index by register after the window.
        let mut expected = vec![fill(12, 14), fill(13, 15)];
        expected.extend(range_check(12, 14));
        expected.extend(window_access(A64Insn::Ld1AdvsimdMultLd1AsisdlseR22v {
            q: 1,
            size: 0,
            rn: A64Reg::x_sp(12),
            rt: 0,
        }));
        expected.push(original(A64Insn::AddAddsubShiftAdd64AddsubShift {
            shift: 0,
            rm: x(13),
            imm6: uimm(0, 6),
            rn: x(12),
            rd: x(12),
        }));
        expected.push(spill(12, 14));
        assert_eq!(
            lowered(A64Insn::Ld1AdvsimdMultLd1AsisdlsepR2R2 {
                q: 1,
                rm: x(15),
                size: 0,
                rn: A64Reg::x_sp(14),
                rt: 0,
            })
            .to_vec(),
            expected
        );

        // ldur d3, [x29, #-8]: x29 lives in x16.
        let mut expected = vec![helper(sub_imm(12, 16, 8))];
        expected.extend(range_check(12, 13));
        expected.extend(window_access(A64Insn::LdrImmFpsimdLdrDLdstPos {
            rt: 3,
            mem: mem_off(A64Reg::x_sp(12), scaled_uimm(0, 12, 3)),
        }));
        assert_eq!(
            lowered(A64Insn::LdurFpsimdLdurDLdstUnscaled {
                rt: 3,
                mem: mem_off(A64Reg::x_sp(29), simm(0x1f8, 9)),
            })
            .to_vec(),
            expected
        );
    }

    /// A18: register-offset SIMD&FP loads/stores run their base-only encoding as a
    /// window access (docs/pipeline.md, "Scalar floating point (A18)"): the address
    /// `base + ExtendReg(index)` in sA by `add sA, <base>, <index>, <extend> #shift`,
    /// then the range check and the base-only access; no writeback.
    #[test]
    fn simd_register_offset_lowers_to_add_range_check_access() {
        let add_ext = |rd: u8, rn: A64Reg, rm: u8, option: u8, shift: u32| {
            helper(A64Insn::AddAddsubExtAdd64AddsubExt {
                rm: x(rm),
                option,
                imm3: uimm(shift, 3),
                rn,
                rd: A64Reg::x_sp(rd),
            })
        };
        let d_pos = |rt: u8, base: u8| A64Insn::LdrImmFpsimdLdrDLdstPos {
            rt,
            mem: mem_off(A64Reg::x_sp(base), scaled_uimm(0, 12, 3)),
        };

        // ldr d0, [x1, x2, lsl #3] (the redis AOF word shape): sA = x12, sB = x13.
        let mut expected = vec![add_ext(12, A64Reg::x_sp(1), 2, 0b011, 3)];
        expected.extend(range_check(12, 13));
        expected.extend(window_access(d_pos(0, 12)));
        assert_eq!(
            lowered(A64Insn::LdrRegFpsimdLdrDLdstRegoff {
                rm: x(2),
                option: 0b011,
                s: 1,
                rn: A64Reg::x_sp(1),
                rt: 0,
            })
            .to_vec(),
            expected
        );

        // str q3, [x13, x14, sxtw #4]: base and index stack-backed (x12, x13), so sA
        // is a third scratch (x14) and sB the fourth (x15): the whole scratch pool.
        let mut expected = vec![fill(12, 13), fill(13, 14)];
        expected.push(add_ext(14, A64Reg::x_sp(12), 13, 0b110, 4));
        expected.extend(range_check(14, 15));
        expected.extend(window_access(A64Insn::StrImmFpsimdStrQLdstPos {
            rt: 3,
            mem: mem_off(A64Reg::x_sp(14), scaled_uimm(0, 12, 4)),
        }));
        assert_eq!(
            lowered(A64Insn::StrRegFpsimdStrQLdstRegoff {
                rm: x(14),
                option: 0b110,
                s: 1,
                rn: A64Reg::x_sp(13),
                rt: 3,
            })
            .to_vec(),
            expected
        );

        // ldr s1, [sp, w2, uxtw #2]: SP check through sB, then sA = x17 + w2 << 2.
        let mut expected = sp_align_check(13).to_vec();
        expected.push(add_ext(12, A64Reg::x_sp(17), 2, 0b010, 2));
        expected.extend(range_check(12, 13));
        expected.extend(window_access(A64Insn::LdrImmFpsimdLdrSLdstPos {
            rt: 1,
            mem: mem_off(A64Reg::x_sp(12), scaled_uimm(0, 12, 2)),
        }));
        assert_eq!(
            lowered(A64Insn::LdrRegFpsimdLdrSLdstRegoff {
                rm: x(2),
                option: 0b010,
                s: 1,
                rn: sp(),
                rt: 1,
            })
            .to_vec(),
            expected
        );

        // ldr b5, [x29, xzr]: user x29 is x16; the zero index stays XZR; the `*BL`
        // byte form (option LSL, S = 0) is the same lowering.
        let mut expected = vec![add_ext(12, A64Reg::x_sp(16), 31, 0b011, 0)];
        expected.extend(range_check(12, 13));
        expected.extend(window_access(A64Insn::LdrImmFpsimdLdrBLdstPos {
            rt: 5,
            mem: mem_off(A64Reg::x_sp(12), uimm(0, 12)),
        }));
        assert_eq!(
            lowered(A64Insn::LdrRegFpsimdLdrBlLdstRegoff {
                rm: xzr(),
                s: 0,
                rn: A64Reg::x_sp(29),
                rt: 5,
            })
            .to_vec(),
            expected
        );
    }

    /// A9a: register-only SIMD&FP forms are emitted unchanged except for their
    /// general-register operands; V registers are never mapped.
    #[test]
    fn simd_register_forms_remap_only_general_registers() {
        let cmeq = A64Insn::CmeqAdvsimdZeroCmeqAsimdmiscZ {
            q: 1,
            size: 0,
            rn: 13,
            rd: 12,
        };
        assert_eq!(lowered(cmeq).to_vec(), vec![original(cmeq)]);

        // dup v0.16b, w13: the stack-backed source is filled into x12.
        assert_eq!(
            lowered(A64Insn::DupAdvsimdGenDupAsimdinsDrR {
                q: 1,
                imm5: uimm(1, 5),
                rn: A64Reg::new(13, A64RegWidth::Unknown, A64Reg31Mode::Xzr),
                rd: 0,
            })
            .to_vec(),
            vec![
                fill(12, 13),
                original(A64Insn::DupAdvsimdGenDupAsimdinsDrR {
                    q: 1,
                    imm5: uimm(1, 5),
                    rn: A64Reg::new(12, A64RegWidth::Unknown, A64Reg31Mode::Xzr),
                    rd: 0,
                }),
            ]
        );

        // umov w14, v1.b[0]: written into scratch, spilled.
        assert_eq!(
            lowered(A64Insn::UmovAdvsimdUmovAsimdinsWW {
                imm5: uimm(1, 5),
                rn: 1,
                rd: A64Reg::w(14),
            })
            .to_vec(),
            vec![
                original(A64Insn::UmovAdvsimdUmovAsimdinsWW {
                    imm5: uimm(1, 5),
                    rn: 1,
                    rd: A64Reg::w(12),
                }),
                spill(12, 14),
            ]
        );

        // fmov x29, d0: user x29 is x16.
        assert_eq!(
            lowered(A64Insn::FmovFloatGenFmov64dFloat2int { rn: 0, rd: x(29) }).to_vec(),
            vec![original(A64Insn::FmovFloatGenFmov64dFloat2int {
                rn: 0,
                rd: x(16),
            })]
        );
    }

    /// A18: scalar floating-point forms are copied as they are; only their general
    /// registers are mapped (a V number equal to a stack-backed register is not).
    #[test]
    fn scalar_fp_forms_remap_only_general_registers() {
        // fadd d14, d12, d13 names V12-V14: untouched, no fills or spills.
        let fadd = A64Insn::FaddFloatFaddDFloatdp2 {
            rm: 13,
            rn: 12,
            rd: 14,
        };
        assert_eq!(lowered(fadd).to_vec(), vec![original(fadd)]);
        // fcmpe d12, #0.0 writes NZCV only.
        let fcmpe = A64Insn::FcmpeFloatFcmpeDzFloatcmp { rn: 12 };
        assert_eq!(lowered(fcmpe).to_vec(), vec![original(fcmpe)]);

        // ucvtf d0, x13 (the redis event loop): the stack-backed source is filled into x12.
        assert_eq!(
            lowered(A64Insn::UcvtfFloatIntUcvtfD64Float2int { rn: x(13), rd: 0 }).to_vec(),
            vec![
                fill(12, 13),
                original(A64Insn::UcvtfFloatIntUcvtfD64Float2int { rn: x(12), rd: 0 }),
            ]
        );
        // fcvtzs w14, d1: written into scratch, spilled.
        assert_eq!(
            lowered(A64Insn::FcvtzsFloatIntFcvtzs32dFloat2int {
                rn: 1,
                rd: A64Reg::w(14),
            })
            .to_vec(),
            vec![
                original(A64Insn::FcvtzsFloatIntFcvtzs32dFloat2int {
                    rn: 1,
                    rd: A64Reg::w(12),
                }),
                spill(12, 14),
            ]
        );
        // fcvtau xzr, s2 and mrs x29, fpcr: XZR stays, user x29 is x16.
        let fcvtau = A64Insn::FcvtauFloatFcvtau64sFloat2int {
            rn: 2,
            rd: A64Reg::new(31, A64RegWidth::X64, A64Reg31Mode::Xzr),
        };
        assert_eq!(lowered(fcvtau).to_vec(), vec![original(fcvtau)]);
        assert_eq!(
            lowered(A64Insn::MrsMrsRsSystemmoveFpcr { rt: x(29) }).to_vec(),
            vec![original(A64Insn::MrsMrsRsSystemmoveFpcr { rt: x(16) })]
        );
    }

    /// A9a: every SIMD&FP load/store form with every register class in its base
    /// (and LD1/ST1 post-index register): admitted, one base-only window access
    /// on the range-checked register, only scratch written
    /// before it, and after it only the base writeback and spills.
    #[test]
    fn every_simd_memory_lowering_is_one_window_committing_after_it() {
        use crate::shared::arm64::GENERATED_A64_SUBSET;
        let regs = [0u8, 9, 12, 13, 14, 16, 17, 29, 30, 31];
        let scratch = crate::shared::abi::REG_VIRT_SCRATCH_GPR_START
            ..=crate::shared::abi::REG_VIRT_SCRATCH_GPR_END;
        let mut checked = 0;
        for spec in GENERATED_A64_SUBSET {
            // Pairs transfer V0 and V1 (`t == t2` is rejected, tested below).
            let word = crate::shared::arm64::form_base_word(spec)
                | spec.field("Rt2").map_or(0, |field| 1 << field.shift());
            let base_insn = A64Insn::decode(word).unwrap();
            if base_insn.fpsimd_mem().is_none() {
                continue;
            }
            // LD1/ST1 post-indexed by a register (writeback), or the A18 register
            // offset (an index, no writeback).
            let has_index = base_insn.get_reg("Rm").is_some();
            let post_index_reg = matches!(
                base_insn.fpsimd_mem().unwrap().writeback,
                Some(crate::shared::arm64::A64FpSimdWriteback::Reg(_))
            );
            for rn in regs {
                for rm in if has_index { &regs[..9] } else { &regs[..1] } {
                    let mut insn = base_insn.set_reg("Rn", A64Reg::x_sp(rn)).unwrap();
                    if has_index {
                        insn = insn.set_reg("Rm", x(*rm)).unwrap();
                    }
                    let admitted = admit_insn(ir(insn));
                    if post_index_reg && *rm == rn && rn != 31 {
                        // Post-index register == base: rejected like any writeback
                        // overlap (conservative: an Unsupported exit is exact).
                        assert!(admitted.is_err(), "{insn:?}");
                        continue;
                    }
                    admitted.unwrap_or_else(|err| panic!("{insn:?}: {err:?}"));
                    let out = lowered(insn);
                    let windows = out
                        .iter()
                        .filter(|r| r.kind == RephrasedInsnKind::WindowAccess)
                        .count();
                    assert_eq!(windows, 1, "{out:?}");
                    let window = out
                        .iter()
                        .position(|r| r.kind == RephrasedInsnKind::WindowAccess)
                        .unwrap();
                    let access = out[window].insn;
                    assert!(access.is_pan_window_access(), "{out:?}");
                    let A64Insn::UbfmUbfm64mBitfield { rn: sa, rd: sb, .. } = out[window - 2].insn
                    else {
                        panic!("{insn:?}: {out:?}");
                    };
                    assert!(out.iter().all(|r| r.insn.msr_pan().is_none()), "{out:?}");
                    assert!(scratch.contains(&sb.enc));
                    // A21: a base-only access is based on the base's own register when
                    // it is not stack-backed; a register-offset form computes sA.
                    match rn {
                        _ if insn.fpsimd_mem().unwrap().index.is_some() => {
                            assert!(scratch.contains(&sa.enc), "{out:?}")
                        }
                        29 => assert_eq!(sa.enc, 16, "{insn:?}: {out:?}"),
                        31 => assert_eq!(sa.enc, 17, "{insn:?}: {out:?}"),
                        0 | 9 | 30 => assert_eq!(sa.enc, rn, "{insn:?}: {out:?}"),
                        _ => assert!(scratch.contains(&sa.enc), "{insn:?}: {out:?}"),
                    }
                    let mem = insn.fpsimd_mem().unwrap();
                    assert_eq!(
                        access,
                        mem.access.set_reg("Rn", A64Reg::x_sp(sa.enc)).unwrap(),
                        "{out:?}"
                    );
                    for before in &out[..window] {
                        assert!(
                            !matches!(before.insn, A64Insn::StrImmGenStr64LdstPos { .. }),
                            "{insn:?}: spill before the access: {out:?}"
                        );
                        for role in before.insn.operand_roles() {
                            if let A64OperandRole::RegWrite { field, .. } = *role {
                                let reg = before.insn.get_reg(field).unwrap();
                                assert!(reg.enc == 31 || scratch.contains(&reg.enc), "{out:?}");
                            }
                        }
                    }
                    let tail = &out[window + 1..];
                    let spills = tail
                        .iter()
                        .filter(|r| matches!(r.insn, A64Insn::StrImmGenStr64LdstPos { .. }))
                        .count();
                    assert!(
                        tail[..tail.len() - spills]
                            .iter()
                            .all(|r| r.kind == RephrasedInsnKind::Original),
                        "{insn:?}: only the writeback, then spills: {out:?}"
                    );
                    // A writeback of #0 (the base word's offset) emits nothing.
                    let writes_back = matches!(
                        mem.writeback,
                        Some(crate::shared::arm64::A64FpSimdWriteback::Reg(_))
                    ) || matches!(
                        mem.writeback,
                        Some(crate::shared::arm64::A64FpSimdWriteback::Imm(amount)) if amount != 0
                    );
                    assert_eq!(writes_back, tail.len() > spills, "{out:?}");
                    checked += 1;
                }
            }
        }
        // 74 forms without an index, 8 LD1/ST1 post-index by register (base != index),
        // 12 register-offset forms (every base and index pair).
        assert_eq!(checked, 74 * 10 + 8 * (10 * 9 - 9) + 12 * 10 * 9);
    }

    /// A9a: SIMD&FP LDP with `t == t2` is CONSTRAINED UNPREDICTABLE: rejected.
    #[test]
    fn simd_ldp_same_destination_is_rejected() {
        let insn = A64Insn::LdpFpsimdLdpQLdstpairOff {
            rt2: 3,
            rt: 3,
            mem: mem_off(A64Reg::x_sp(1), scaled_simm(0, 7, 4)),
        };
        let err = admit_insn(ir(insn)).unwrap_err();
        assert!(
            matches!(err, RegVirtError::UnpredictableMemoryOp { .. }),
            "{err:?}"
        );
        assert!(err.is_instruction_intrinsic());
        // The same register in a store pair, or a writeback base named like a V
        // register, is fine.
        admit_insn(ir(A64Insn::StpFpsimdStpQLdstpairOff {
            rt2: 3,
            rt: 3,
            mem: mem_off(A64Reg::x_sp(1), scaled_simm(0, 7, 4)),
        }))
        .unwrap();
        admit_insn(ir(A64Insn::LdrImmFpsimdLdrQLdstImmpost {
            rt: 1,
            mem: mem_post(A64Reg::x_sp(1), simm(16, 9)),
        }))
        .unwrap();
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
    /// fills. It names only physical x18 (the counter), no scratch register.
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
        assert_eq!(&insns[..2], &check);
        assert_eq!(insns[2], fill(12, 12));
        assert_eq!(insns[3], RephrasedInsn::original(0x1000, cbnz));
        assert_eq!(insns.len(), 4);

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

    /// A12: user x18 is stack-backed like x12..x17, in frame slot 192; physical x18
    /// (the budget counter) is never an operand of a rewritten instruction.
    #[test]
    fn user_x18_is_stack_backed_in_its_own_slot() {
        use crate::shared::abi::RUNTIME_FRAME_USER_X18_OFFSET;

        assert_eq!(reg_virt_stack_backed_slot_offset(18), Some(RUNTIME_FRAME_USER_X18_OFFSET));
        let slot = frame_slot(RUNTIME_FRAME_USER_X18_OFFSET);
        // A write goes through scratch and is spilled to the slot.
        let program = validate_one(RephrasedInsn::original(0x1000, movz(x(18)))).unwrap();
        assert_eq!(
            &program[0].insns[..],
            [
                RephrasedInsn::original(0x1000, movz(x(12))),
                RephrasedInsn::reg_virt_helper(
                    0x1000,
                    A64Insn::StrImmGenStr64LdstPos { rt: x(12), mem: slot },
                ),
            ]
        );
        // A read is a fill from the slot; a 32-bit write spills the zero-extended X.
        let program = validate_one(RephrasedInsn::original(0x1000, orr_mov(0, x(18)))).unwrap();
        assert_eq!(
            &program[0].insns[..],
            [
                RephrasedInsn::reg_virt_helper(
                    0x1000,
                    A64Insn::LdrImmGenLdr64LdstPos { rt: x(12), mem: slot },
                ),
                RephrasedInsn::original(0x1000, orr_mov(0, x(12))),
            ]
        );
        let program = validate_one(RephrasedInsn::original(
            0x1000,
            A64Insn::MovzMovz32Movewide { hw: 0, imm16: uimm(1, 16), rd: A64Reg::w(18) },
        ))
        .unwrap();
        assert_eq!(
            program[0].insns[1],
            RephrasedInsn::reg_virt_helper(
                0x1000,
                A64Insn::StrImmGenStr64LdstPos { rt: x(12), mem: slot },
            )
        );
    }

    /// A12 scratch worst case. The pool is four registers because the most
    /// stack-backed operands one instruction has (plus its address scratch) is four.
    /// Making x18 stack-backed adds a candidate register, not an operand, so putting
    /// x18 into any operand position of the worst-case forms (4-operand `madd`,
    /// register-offset load, pair with writeback, LSE atomic, `ld1` post-indexed by a
    /// register) admits or rejects exactly as the same form on x12..x15 does.
    #[test]
    fn x18_in_any_operand_position_needs_no_more_scratch_than_x12_to_x15() {
        let forms: [(&str, fn([u8; 4]) -> A64Insn); 5] = [
            ("madd", |r| A64Insn::MaddMadd64aDp3src {
                ra: x(r[3]),
                rm: x(r[2]),
                rn: x(r[1]),
                rd: x(r[0]),
            }),
            ("ldr regoffset", |r| A64Insn::LdrRegGenLdr64LdstRegoff {
                rm: x(r[2]),
                option: 0b110,
                s: 1,
                rn: A64Reg::x_sp(r[1]),
                rt: x(r[0]),
            }),
            ("ldp post", |r| A64Insn::LdpGenLdp64LdstpairPost {
                rt2: x(r[2]),
                rt: x(r[0]),
                mem: crate::shared::arm64::ergo::mem_post(
                    A64Reg::x_sp(r[1]),
                    crate::shared::arm64::ergo::ldstpair64_offset(0x1000),
                ),
            }),
            ("cas", |r| A64Insn::CasCasC64Comswap {
                rs: x(r[0]),
                rn: A64Reg::x_sp(r[1]),
                rt: x(r[2]),
            }),
            ("swpb", |r| A64Insn::SwpbSwpb32Memop {
                rs: A64Reg::w(r[0]),
                rn: A64Reg::x_sp(r[1]),
                rt: A64Reg::w(r[2]),
            }),
        ];
        for (name, form) in forms {
            let base = [12, 13, 14, 15];
            let reference = admit_insn(ir(form(base)));
            for position in 0..4 {
                let mut regs = base;
                regs[position] = 18;
                assert_eq!(
                    admit_insn(ir(form(regs))),
                    reference,
                    "{name} with x18 at operand {position}"
                );
            }
        }
    }

    /// A dispatch site's target move (A11): whatever register holds the target, x13
    /// gets its *user* value -- loaded from its frame slot (stack-backed x12..x18),
    /// copied from x16 (user x29), or copied as is -- and nothing but x13 is written
    /// before the template.
    #[test]
    fn dispatch_target_moves_the_users_register_into_x13() {
        use crate::shared::abi::{reg_virt_stack_backed_slot_offset, DISPATCH_TARGET_REG};
        use crate::shared::arm64::IrInsn;

        for reg in 0..=31u8 {
            for insn in [
                A64Insn::BrBr64BranchReg { rn: x(reg) },
                A64Insn::RetRet64rBranchReg { rn: x(reg) },
                A64Insn::BlrBlr64BranchReg { rn: x(reg) },
            ] {
                let lowered = rephrase_insn(IrInsn {
                    pc: 0x1000,
                    word: 0,
                    inner: insn,
                })
                .unwrap();
                let out = virtualize_registers(program_from_insns(&lowered)).unwrap();
                let moves = out[0]
                    .insns
                    .iter()
                    .filter(|insn| insn.kind == RephrasedInsnKind::DispatchTarget)
                    .map(|insn| insn.insn)
                    .collect::<Vec<_>>();
                let expected = match reg {
                    12..=18 => A64Insn::LdrImmGenLdr64LdstPos {
                        rt: x(DISPATCH_TARGET_REG),
                        mem: mem_off(
                            A64Reg::x_sp(31),
                            ldst64_offset(reg_virt_stack_backed_slot_offset(reg).unwrap()),
                        ),
                    },
                    29 => orr_mov(DISPATCH_TARGET_REG, x(REG_VIRT_STABLE_MAPPED_X29_PHYS_REG)),
                    _ => orr_mov(DISPATCH_TARGET_REG, x(reg)),
                };
                assert_eq!(moves, [expected], "{} x{reg}", insn.key());
                // The link write of BLR comes after, and is the only user write before
                // the exit group.
                assert_eq!(
                    out[0]
                        .insns
                        .iter()
                        .take_while(|insn| insn.kind != RephrasedInsnKind::DispatchLookup)
                        .filter(|insn| insn.kind != RephrasedInsnKind::DispatchTarget)
                        .all(|insn| matches!(
                            insn.insn,
                            A64Insn::MovzMovz64Movewide { rd, .. }
                                | A64Insn::MovkMovk64Movewide { rd, .. } if rd.enc == 30
                        )),
                    true,
                    "{} x{reg}",
                    insn.key()
                );
            }
        }
    }

    fn orr_mov(rd: u8, rm: A64Reg) -> A64Insn {
        A64Insn::OrrLogShiftOrr64LogShift {
            shift: 0,
            rm: A64Reg::new(rm.enc, A64RegWidth::X64, rm.reg31),
            imm6: uimm(0, 6),
            rn: xzr(),
            rd: x(rd),
        }
    }

    /// The miss exit group reads the physical x13 for RET_PARAM0, and only that one
    /// word may: any other payload reading a stack-backed number is rejected.
    #[test]
    fn only_the_dispatch_miss_copy_may_read_x13_in_an_exit_group() {
        use crate::shared::trans::rephrase::dispatch_miss_param0_copy;

        let group = |payload: A64Insn| {
            let mut insns = vec![
                RephrasedInsn::runtime_exit_payload(0x1000, movz(x(RET_STATUS_REG))),
                RephrasedInsn::runtime_exit_payload(0x1000, payload),
            ];
            insns.push(RephrasedInsn::runtime_exit_branch(
                0x1000,
                A64Insn::BUncondBOnlyBranchImm {
                    imm26: scaled_simm(0, 26, 2),
                },
            ));
            virtualize_registers(program_from_insns(&insns))
        };
        assert!(group(dispatch_miss_param0_copy()).is_ok());
        let other = A64Insn::AddAddsubImmAdd64AddsubImm {
            sh: 0,
            imm12: uimm(1, 12),
            rn: A64Reg::x_sp(DISPATCH_TARGET_REG),
            rd: A64Reg::x_sp(RET_PARAM0_REG),
        };
        assert!(matches!(
            group(other),
            Err(RegVirtError::UnsupportedRuntimeExitSource { .. })
        ));
    }

    // ---- SP alignment check deduplication (A20) ----

    /// Virtualizes `blocks` (original instructions, one block each, instruction `i` of
    /// block `b` at pc `0x1000 * (b + 1) + 4 * i`) and returns, per block, the indices
    /// of the instructions that carry an SP alignment check (`and xS, x17, #15`).
    fn sp_checked(blocks: &[&[A64Insn]]) -> Vec<Vec<usize>> {
        let mut program = SharedVec::new();
        for (b, insns) in blocks.iter().enumerate() {
            let start = 0x1000 * (b as u64 + 1);
            let mut body = SharedVec::new();
            for (i, insn) in insns.iter().enumerate() {
                body.push(RephrasedInsn::original(start + 4 * i as u64, *insn), GFP_KERNEL)
                    .unwrap();
            }
            program
                .push(
                    RephrasedBlock {
                        start_addr: start,
                        end_addr: start + 4 * insns.len() as u64,
                        prev: SharedVec::new(),
                        next: SharedVec::new(),
                        insns: body,
                        cold: SharedVec::new(),
                    },
                    GFP_KERNEL,
                )
                .unwrap();
        }
        let program = virtualize_registers(program).unwrap();
        program
            .iter()
            .enumerate()
            .map(|(b, block)| {
                let start = 0x1000 * (b as u64 + 1);
                let mut checked = Vec::new();
                for insn in &block.insns {
                    let is_sp_check = insn.kind == RephrasedInsnKind::AlignCheck
                        && matches!(insn.insn, A64Insn::AndLogImmAnd64LogImm { rn, .. } if rn.enc == 17);
                    if is_sp_check {
                        let index = ((insn.ori_pc - start) / 4) as usize;
                        assert!(!checked.contains(&index), "two SP checks for one instruction");
                        checked.push(index);
                    }
                }
                checked
            })
            .collect()
    }

    fn ldr_sp(offset: u32) -> A64Insn {
        A64Insn::LdrImmGenLdr64LdstPos {
            rt: x(0),
            mem: mem_off(sp(), ldst64_offset(offset)),
        }
    }

    /// An SP check is emitted for the first SP-based access of a block only; the
    /// access forms differ, the fact does not.
    #[test]
    fn only_the_first_sp_access_of_a_block_is_checked() {
        let ldp_post = A64Insn::LdpGenLdp64LdstpairPost {
            rt2: x(2),
            rt: x(1),
            mem: mem_post(sp(), ldstpair64_offset(16)),
        };
        let reg_offset = A64Insn::LdrRegGenLdr64LdstRegoff {
            rm: x(3),
            option: 3,
            s: 0,
            rn: sp(),
            rt: x(0),
        };
        let q_load = A64Insn::LdrImmFpsimdLdrQLdstPos {
            rt: 0,
            mem: mem_off(sp(), scaled_uimm(1, 12, 4)),
        };
        // Offsets that need the address scratch (outside simm9) change nothing.
        let far = ldr_sp(0x800);
        assert_eq!(
            sp_checked(&[&[ldr_sp(0), ldr_sp(8), ldp_post, reg_offset, q_load, far, ldr_sp(16)]]),
            [[0]]
        );
        // The first access need not be the block's first instruction, and an access
        // that is not SP-based does not set the fact.
        let other_base = A64Insn::LdrImmGenLdr64LdstPos {
            rt: x(0),
            mem: mem_off(A64Reg::x_sp(1), ldst64_offset(0)),
        };
        assert_eq!(
            sp_checked(&[&[add_imm(3, 4, 0, 1), other_base, ldr_sp(0), other_base, ldr_sp(8)]]),
            [[2]]
        );
    }

    /// The block start resets the fact, whatever the previous block established.
    #[test]
    fn every_block_checks_sp_again() {
        let block: &[A64Insn] = &[ldr_sp(0), ldr_sp(8)];
        assert_eq!(sp_checked(&[block, block, block]), [[0], [0], [0]]);
        let no_access: &[A64Insn] = &[add_imm(3, 4, 0, 1)];
        assert_eq!(sp_checked(&[block, no_access, block]), vec![vec![0], vec![], vec![0]]);
    }

    /// Only `add`/`sub x17, x17, #imm` with `imm % 16 == 0` keep the fact; every other
    /// write to SP drops it, so the next SP access is checked again (and sets the
    /// fact again).
    #[test]
    fn sp_adjusts_by_multiples_of_16_keep_the_fact_and_everything_else_drops_it() {
        let keep = [
            add_imm(31, 31, 0, 16),
            add_imm(31, 31, 0, 32),
            add_imm(31, 31, 0, 0),
            sub_imm(31, 31, 48),
            // imm12 << 12: 4096 and 4096 * 5 are multiples of 16.
            add_imm(31, 31, 1, 1),
            add_imm(31, 31, 1, 5),
            A64Insn::SubAddsubImmSub64AddsubImm {
                sh: 1,
                imm12: uimm(3, 12),
                rn: A64Reg::x_sp(31),
                rd: A64Reg::x_sp(31),
            },
        ];
        for adjust in keep {
            assert_eq!(sp_checked(&[&[ldr_sp(0), adjust, ldr_sp(0)]]), [[0]], "{adjust:?}");
        }
        let drop = [
            add_imm(31, 31, 0, 8),
            add_imm(31, 31, 0, 1),
            sub_imm(31, 31, 8),
            sub_imm(31, 31, 15),
            sub_imm(31, 31, 17),
            // `mov sp, xN`, `add sp, xN, #16` (a different source), SP from a register.
            add_imm(31, 0, 0, 0),
            add_imm(31, 4, 0, 16),
            A64Insn::AddAddsubExtAdd64AddsubExt {
                rm: x(1),
                option: 3,
                imm3: uimm(0, 3),
                rn: A64Reg::x_sp(31),
                rd: A64Reg::x_sp(31),
            },
        ];
        for adjust in drop {
            assert_eq!(
                sp_checked(&[&[ldr_sp(0), adjust, ldr_sp(0), ldr_sp(8)]]),
                [[0, 2]],
                "{adjust:?}"
            );
        }
        // Misaligned by 8, realigned by another 8: the fact stays dropped (the pair of
        // adjusts is not provably aligned), the next access is checked, and then holds.
        assert_eq!(
            sp_checked(&[&[
                ldr_sp(0),
                sub_imm(31, 31, 8),
                add_imm(31, 31, 0, 8),
                ldr_sp(0),
                ldr_sp(8),
            ]]),
            [[0, 3]]
        );
        // A write of another register, or of a user register mapped to a scratch,
        // does not matter.
        assert_eq!(
            sp_checked(&[&[ldr_sp(0), add_imm(0, 0, 0, 1), add_imm(16, 16, 0, 8), ldr_sp(8)]]),
            [[0]]
        );
    }

    /// Pre/post-index writeback of SP is an `add`/`sub x17, x17`: by a multiple of 16 the
    /// fact survives, by 8 it does not.
    #[test]
    fn sp_writeback_by_16_keeps_the_fact_and_by_8_drops_it() {
        let stp_pre = |amount: i32| A64Insn::StpGenStp64LdstpairPre {
            rt2: x(2),
            rt: x(1),
            mem: A64Mem::pre_index(A64Reg::x_sp(31), ldstpair64_offset(amount)),
        };
        let ldr_post = |amount: u32| A64Insn::LdrImmGenLdr64LdstImmpost {
            rt: x(0),
            mem: mem_post(sp(), simm(amount, 9)),
        };
        let str_pre_8 = A64Insn::StrImmGenStr64LdstImmpre {
            rt: x(0),
            mem: mem_pre(sp(), simm((-8i32) as u32 & 0x1ff, 9)),
        };
        // `stp x1, x2, [sp, #-16]!` as the first access: checked before the writeback,
        // and the fact holds afterwards.
        assert_eq!(sp_checked(&[&[stp_pre(-16), ldr_sp(0), stp_pre(-32), ldr_sp(8)]]), [[0]]);
        // By 8: the next access is checked.
        assert_eq!(sp_checked(&[&[str_pre_8, ldr_sp(0), ldr_sp(8)]]), [[0, 1]]);
        assert_eq!(sp_checked(&[&[ldr_post(8), ldr_sp(0), ldr_sp(8)]]), [[0, 1]]);
        // Two 8-byte writebacks: every access is checked (the second sees an SP the first
        // one misaligned, and the third one the second's).
        assert_eq!(sp_checked(&[&[ldr_post(8), ldr_post(8), ldr_sp(0)]]), [[0, 1, 2]]);
        // Register-offset forms never write back.
        let reg_offset = A64Insn::StrRegGenStr64LdstRegoff {
            rm: x(3),
            option: 3,
            s: 0,
            rn: sp(),
            rt: x(0),
        };
        assert_eq!(sp_checked(&[&[reg_offset, reg_offset]]), [[0]]);
    }

    // ---- A21: block-local slot forwarding (`forward_slots`) ----

    fn forwarded(words: &[RephrasedInsn]) -> Vec<RephrasedInsn> {
        forward_slots(words).unwrap().iter().copied().collect()
    }

    fn dp(rd: u8) -> RephrasedInsn {
        original(add_imm(rd, rd, 0, 1))
    }

    fn jump() -> RephrasedInsn {
        original(A64Insn::BUncondBOnlyBranchImm {
            imm26: scaled_simm(0, 26, 2),
        })
    }

    fn cond_branch() -> RephrasedInsn {
        original(A64Insn::CbzCbz64Compbranch {
            imm19: scaled_simm(0, 19, 2),
            rt: x(0),
        })
    }

    /// `ldr x12, [sp, #176]`: the pt_regs pointer load, a reg-virt helper that is not a
    /// user-state slot move.
    fn pt_regs_load() -> RephrasedInsn {
        helper(A64Insn::LdrImmGenLdr64LdstPos {
            rt: x(12),
            mem: frame_slot(176),
        })
    }

    #[test]
    fn a_fill_of_a_register_that_already_holds_the_slot_is_forwarded() {
        // After a fill of the same slot into the same register.
        assert_eq!(
            forwarded(&[fill(12, 16), dp(13), fill(12, 16), dp(12)]),
            [fill(12, 16), dp(13), dp(12)]
        );
        // After a spill of that register to the slot.
        assert_eq!(
            forwarded(&[dp(12), spill(12, 16), dp(13), fill(12, 16), dp(12)]),
            [dp(12), spill(12, 16), dp(13), dp(12)]
        );
        // The same slot into another register is a different fill, and so is another
        // slot into the same one.
        assert_eq!(
            forwarded(&[fill(12, 16), fill(13, 16), fill(12, 15)]),
            [fill(12, 16), fill(13, 16), fill(12, 15)]
        );
        // Facts survive the fall-through of a conditional branch, a user access that
        // writes another register and a window access.
        assert_eq!(
            forwarded(&[
                fill(12, 16),
                cond_branch(),
                ldtr_x(x(0), 17, 0),
                sttr_x(x(12), 17, 8),
                fill(12, 16),
            ]),
            [fill(12, 16), cond_branch(), ldtr_x(x(0), 17, 0), sttr_x(x(12), 17, 8)]
        );
    }

    #[test]
    fn a_fill_is_not_forwarded_past_what_may_change_the_register_or_the_slot() {
        // A write to the register (a data-processing word, a user load into it, a
        // 32-bit write to its W half).
        for write in [
            dp(12),
            ldtr_x(x(12), 17, 0),
            original(A64Insn::MovzMovz32Movewide {
                hw: 0,
                imm16: uimm(1, 16),
                rd: A64Reg::w(12),
            }),
        ] {
            assert_eq!(
                forwarded(&[fill(12, 16), write, fill(12, 16)]),
                [fill(12, 16), write, fill(12, 16)],
                "{write:?}"
            );
        }
        // Another register's spill of the slot: the slot now holds that register.
        assert_eq!(
            forwarded(&[fill(12, 16), spill(13, 16), fill(12, 16), fill(13, 16)]),
            [fill(12, 16), spill(13, 16), fill(12, 16)]
        );
        // A join point: the word after an unconditional branch.
        assert_eq!(
            forwarded(&[fill(12, 16), jump(), fill(12, 16)]),
            [fill(12, 16), jump(), fill(12, 16)]
        );
        // A memory access the pass cannot name (here the pt_regs pointer load) forgets
        // everything, including registers it does not write.
        assert_eq!(
            forwarded(&[fill(13, 16), pt_regs_load(), fill(13, 16)]),
            [fill(13, 16), pt_regs_load(), fill(13, 16)]
        );
    }

    #[test]
    fn a_spill_overwritten_in_the_same_run_is_dead() {
        assert_eq!(
            forwarded(&[spill(12, 16), dp(13), spill(12, 16)]),
            [dp(13), spill(12, 16)]
        );
        // Fills and spills of other slots and registers do not end the run.
        assert_eq!(
            forwarded(&[spill(12, 16), fill(13, 15), spill(14, 14), spill(13, 16)]),
            [fill(13, 15), spill(14, 14), spill(13, 16)]
        );
        // The last spill of a run is kept (the block end), and so is a lone one.
        assert_eq!(forwarded(&[dp(12), spill(12, 16)]), [dp(12), spill(12, 16)]);
        // Three in a row: only the last stays.
        assert_eq!(
            forwarded(&[spill(12, 16), spill(12, 16), spill(12, 16)]),
            [spill(12, 16)]
        );
    }

    #[test]
    fn a_spill_is_kept_when_anything_can_observe_the_slot() {
        let payload = RephrasedInsn::runtime_exit_payload(0x1000, movz(x(9)));
        let window = window_access(A64Insn::LdaddLdaddal64Memop {
            rs: x(0),
            rn: A64Reg::x_sp(1),
            rt: x(2),
        })[0];
        for between in [
            // A branch (budget, alignment, range, dispatch all branch to a stub or
            // leave), conditional or not.
            cond_branch(),
            jump(),
            // A user access and a window access are fault sites.
            ldtr_x(x(0), 17, 0),
            sttr_x(x(0), 17, 0),
            window,
            // Any other memory access.
            pt_regs_load(),
            // A fill of the slot itself.
            fill(13, 16),
            // An exit payload.
            payload,
            // A link slot: a `b` to another fragment once the runtime links it.
            RephrasedInsn::link_slot(0x1000, 0x2000),
        ] {
            let words = [spill(12, 16), between, spill(12, 16)];
            assert_eq!(forwarded(&words), words, "{between:?}");
        }
        // A join point between the two: the later spill is not in the same run.
        let words = [spill(12, 16), jump(), spill(12, 16)];
        assert_eq!(forwarded(&words), words);
    }

    #[test]
    fn a_forwarded_fill_does_not_keep_a_spill_alive_or_dead() {
        // spill; fill (forwarded); spill: the fill is gone, so the first spill is dead.
        assert_eq!(
            forwarded(&[spill(12, 16), fill(12, 16), dp(12), spill(12, 16)]),
            [dp(12), spill(12, 16)]
        );
        // A fill that stays (the register changed) is a read of the slot: the spill
        // before it stays.
        let words = [spill(12, 16), dp(12), fill(12, 16), spill(12, 16)];
        assert_eq!(forwarded(&words), words);
    }

    /// The redis ADRP into a stack-backed register: 11 words became
    /// `movz; movk; movk; str` (docs/pipeline.md, "Hot-path word reduction (A21)").
    #[test]
    fn adrp_into_a_stack_backed_register_builds_in_scratch_and_spills_once() {
        let adrp = rephrase_insn(IrInsn {
            pc: 0x0000_0055_0025_f000,
            word: 0,
            inner: A64Insn::AdrpAdrpOnlyPcreladdr {
                immlo: A64Imm::unsigned(0, 2),
                immhi: A64Imm::unsigned(0, 19),
                rd: x(16),
            },
        })
        .unwrap();
        let mut program = virtualize_registers(program_from_insns(&adrp)).unwrap();
        let words: Vec<_> = core::mem::replace(&mut program[0].insns, SharedVec::new())
            .iter()
            .map(|word| word.insn)
            .collect();
        let movk = |hw, imm: u32| A64Insn::MovkMovk64Movewide {
            hw,
            imm16: uimm(imm, 16),
            rd: x(12),
        };
        assert_eq!(
            words,
            [
                A64Insn::MovzMovz64Movewide {
                    hw: 0,
                    imm16: uimm(0xf000, 16),
                    rd: x(12),
                },
                movk(1, 0x25),
                movk(2, 0x55),
                spill(12, 16).insn,
            ]
        );
    }

    /// Two back-to-back updates of one stack-backed register: the second fill is the
    /// register the first update left, and the first spill is overwritten.
    #[test]
    fn consecutive_instructions_on_one_stack_backed_register_share_the_fill() {
        let bump = |pc| {
            RephrasedInsn::original(
                pc,
                A64Insn::AddAddsubImmAdd64AddsubImm {
                    sh: 0,
                    imm12: uimm(8, 12),
                    rn: A64Reg::x_sp(16),
                    rd: A64Reg::x_sp(16),
                },
            )
        };
        let program = virtualize_registers(program_from_insns(&[bump(0x1000), bump(0x1004)]))
            .unwrap();
        assert_eq!(
            program[0].insns.iter().map(|word| word.insn).collect::<Vec<_>>(),
            [
                fill(12, 16).insn,
                add_imm(12, 12, 0, 8),
                add_imm(12, 12, 0, 8),
                spill(12, 16).insn,
            ]
        );
    }
}
