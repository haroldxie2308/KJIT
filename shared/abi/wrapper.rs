use super::{
    ABI_ENTRY_ARG_REG, ABI_EXTRA_PARAMS_ARG_REG, ABI_LINK_REG, ABI_PT_REGS_ARG_REG,
    DISPATCH_KEY_REG, DISPATCH_SLOT_REG, DISPATCH_TARGET_REG, EXTRA_PARAM_IBTC_TABLE_OFFSET,
    IBTC_BITS, IBTC_INDEX_LSB, IBTC_RECORD_HOST_OFFSET, IBTC_RECORD_PC_OFFSET, IBTC_SLOT_SHIFT,
    KJIT_BACKEDGE_BUDGET, REG_VIRT_SCRATCH_GPR_START, RET_PARAM0_REG, RET_PARAM1_REG,
    RET_STATUS_REG, RUNTIME_FRAME_BUDGET_OFFSET, RUNTIME_FRAME_ENTRY_ADDR_OFFSET,
    RUNTIME_FRAME_IBTC_OFFSET, RUNTIME_FRAME_PT_REGS_PTR_OFFSET, RUNTIME_FRAME_SIZE_BYTES,
};
use crate::shared::arm64::ergo::{
    ldst64_offset, ldstpair64_offset, mem_off, mem_post, mem_pre, scaled_simm, sp, uimm, x, xzr,
};
use crate::shared::arm64::A64Insn;
use crate::shared::platform::{AllocFlags, SharedAllocError, SharedResult, SharedVec};

pub const ABI_INSN_SIZE: usize = 4;
pub const PROLOGUE_LEN_BYTES: usize = KJIT_PROLOGUE.len() * ABI_INSN_SIZE;
pub const EPILOGUE_OFFSET: usize = PROLOGUE_LEN_BYTES;
pub const EPILOGUE_LEN_BYTES: usize = KJIT_EPILOGUE.len() * ABI_INSN_SIZE;

/// Scratch register the prologue's entry `br` goes through. Reg-virt scratch is
/// dead at every instruction boundary, and user x12 already lives in its frame
/// slot when the branch runs.
const PROLOGUE_ENTRY_SCRATCH_REG: u8 = REG_VIRT_SCRATCH_GPR_START;

/// Entered at offset 0 with x0 = pt_regs, x1 = extra params and
/// x2 = `ABI_ENTRY_ARG_REG` (absolute body address to start at). It stores the
/// run's dispatch table (extra params `[2]`) in the frame, resets the budget counter
/// and ends with the prologue's own indirect branch, `br` to that saved entry
/// address.
pub const KJIT_PROLOGUE: &[A64Insn] = &[
    A64Insn::StpGenStp64LdstpairPre {
        rt2: x(30),
        rt: x(29),
        mem: mem_pre(sp(), ldstpair64_offset(-(RUNTIME_FRAME_SIZE_BYTES as i32))),
    },
    A64Insn::AddAddsubImmAdd64AddsubImm {
        sh: 0,
        imm12: uimm(0, 12),
        rn: sp(),
        rd: x(29),
    },
    A64Insn::StrImmGenStr64LdstPos {
        rt: x(18),
        mem: mem_off(sp(), ldst64_offset(88)),
    },
    // Save the entry address before the pt_regs loads below overwrite x2.
    A64Insn::StrImmGenStr64LdstPos {
        rt: x(ABI_ENTRY_ARG_REG),
        mem: mem_off(sp(), ldst64_offset(RUNTIME_FRAME_ENTRY_ADDR_OFFSET)),
    },
    A64Insn::StpGenStp64LdstpairOff {
        rt2: x(20),
        rt: x(19),
        mem: mem_off(sp(), ldstpair64_offset(96)),
    },
    A64Insn::StpGenStp64LdstpairOff {
        rt2: x(22),
        rt: x(21),
        mem: mem_off(sp(), ldstpair64_offset(112)),
    },
    A64Insn::StpGenStp64LdstpairOff {
        rt2: x(24),
        rt: x(23),
        mem: mem_off(sp(), ldstpair64_offset(128)),
    },
    A64Insn::StpGenStp64LdstpairOff {
        rt2: x(26),
        rt: x(25),
        mem: mem_off(sp(), ldstpair64_offset(144)),
    },
    A64Insn::StpGenStp64LdstpairOff {
        rt2: x(28),
        rt: x(27),
        mem: mem_off(sp(), ldstpair64_offset(160)),
    },
    A64Insn::OrrLogShiftOrr64LogShift {
        shift: 0,
        rm: x(ABI_PT_REGS_ARG_REG),
        imm6: uimm(0, 6),
        rn: xzr(),
        rd: x(16),
    },
    A64Insn::OrrLogShiftOrr64LogShift {
        shift: 0,
        rm: x(ABI_EXTRA_PARAMS_ARG_REG),
        imm6: uimm(0, 6),
        rn: xzr(),
        rd: x(17),
    },
    A64Insn::StpGenStp64LdstpairOff {
        rt2: x(17),
        rt: x(16),
        mem: mem_off(
            sp(),
            ldstpair64_offset(RUNTIME_FRAME_PT_REGS_PTR_OFFSET as i32),
        ),
    },
    // The dispatch table of this run (A11), while x1 still holds the extra pointer
    // (the next load overwrites it). x12 is scratch here, see above.
    A64Insn::LdrImmGenLdr64LdstPos {
        rt: x(PROLOGUE_ENTRY_SCRATCH_REG),
        mem: mem_off(
            x(ABI_EXTRA_PARAMS_ARG_REG),
            ldst64_offset(EXTRA_PARAM_IBTC_TABLE_OFFSET),
        ),
    },
    A64Insn::StrImmGenStr64LdstPos {
        rt: x(PROLOGUE_ENTRY_SCRATCH_REG),
        mem: mem_off(sp(), ldst64_offset(RUNTIME_FRAME_IBTC_OFFSET)),
    },
    A64Insn::LdpGenLdp64LdstpairOff {
        rt2: x(1),
        rt: x(0),
        mem: mem_off(x(16), ldstpair64_offset(0)),
    },
    A64Insn::LdpGenLdp64LdstpairOff {
        rt2: x(3),
        rt: x(2),
        mem: mem_off(x(16), ldstpair64_offset(16)),
    },
    A64Insn::LdpGenLdp64LdstpairOff {
        rt2: x(5),
        rt: x(4),
        mem: mem_off(x(16), ldstpair64_offset(32)),
    },
    A64Insn::LdpGenLdp64LdstpairOff {
        rt2: x(7),
        rt: x(6),
        mem: mem_off(x(16), ldstpair64_offset(48)),
    },
    A64Insn::LdpGenLdp64LdstpairOff {
        rt2: x(9),
        rt: x(8),
        mem: mem_off(x(16), ldstpair64_offset(64)),
    },
    A64Insn::LdpGenLdp64LdstpairOff {
        rt2: x(11),
        rt: x(10),
        mem: mem_off(x(16), ldstpair64_offset(80)),
    },
    A64Insn::LdpGenLdp64LdstpairOff {
        rt2: x(13),
        rt: x(12),
        mem: mem_off(x(16), ldstpair64_offset(96)),
    },
    A64Insn::LdpGenLdp64LdstpairOff {
        rt2: x(15),
        rt: x(14),
        mem: mem_off(x(16), ldstpair64_offset(112)),
    },
    A64Insn::LdpGenLdp64LdstpairOff {
        rt2: x(19),
        rt: x(18),
        mem: mem_off(x(16), ldstpair64_offset(144)),
    },
    A64Insn::LdpGenLdp64LdstpairOff {
        rt2: x(21),
        rt: x(20),
        mem: mem_off(x(16), ldstpair64_offset(160)),
    },
    A64Insn::LdpGenLdp64LdstpairOff {
        rt2: x(23),
        rt: x(22),
        mem: mem_off(x(16), ldstpair64_offset(176)),
    },
    A64Insn::LdpGenLdp64LdstpairOff {
        rt2: x(25),
        rt: x(24),
        mem: mem_off(x(16), ldstpair64_offset(192)),
    },
    A64Insn::LdpGenLdp64LdstpairOff {
        rt2: x(27),
        rt: x(26),
        mem: mem_off(x(16), ldstpair64_offset(208)),
    },
    A64Insn::LdrImmGenLdr64LdstPos {
        rt: x(28),
        mem: mem_off(x(16), ldst64_offset(224)),
    },
    A64Insn::LdrImmGenLdr64LdstPos {
        rt: x(30),
        mem: mem_off(x(16), ldst64_offset(240)),
    },
    A64Insn::LdrImmGenLdr64LdstPos {
        rt: x(17),
        mem: mem_off(x(16), ldst64_offset(232)),
    },
    A64Insn::StrImmGenStr64LdstPos {
        rt: x(17),
        mem: mem_off(sp(), ldst64_offset(64)),
    },
    A64Insn::LdrImmGenLdr64LdstPos {
        rt: x(17),
        mem: mem_off(x(16), ldst64_offset(248)),
    },
    A64Insn::StrImmGenStr64LdstPos {
        rt: x(17),
        mem: mem_off(sp(), ldst64_offset(72)),
    },
    A64Insn::LdpGenLdp64LdstpairOff {
        rt2: x(17),
        rt: x(16),
        mem: mem_off(x(16), ldstpair64_offset(128)),
    },
    A64Insn::StpGenStp64LdstpairOff {
        rt2: x(13),
        rt: x(12),
        mem: mem_off(sp(), ldstpair64_offset(16)),
    },
    A64Insn::StpGenStp64LdstpairOff {
        rt2: x(15),
        rt: x(14),
        mem: mem_off(sp(), ldstpair64_offset(32)),
    },
    A64Insn::StpGenStp64LdstpairOff {
        rt2: x(17),
        rt: x(16),
        mem: mem_off(sp(), ldstpair64_offset(48)),
    },
    A64Insn::LdpGenLdp64LdstpairOff {
        rt2: x(17),
        rt: x(16),
        mem: mem_off(sp(), ldstpair64_offset(64)),
    },
    // Every entry starts with a full budget (x12 is scratch here, see above).
    A64Insn::MovzMovz64Movewide {
        hw: 0,
        imm16: uimm(KJIT_BACKEDGE_BUDGET as u32, 16),
        rd: x(PROLOGUE_ENTRY_SCRATCH_REG),
    },
    A64Insn::StrImmGenStr64LdstPos {
        rt: x(PROLOGUE_ENTRY_SCRATCH_REG),
        mem: mem_off(sp(), ldst64_offset(RUNTIME_FRAME_BUDGET_OFFSET)),
    },
    A64Insn::LdrImmGenLdr64LdstPos {
        rt: x(PROLOGUE_ENTRY_SCRATCH_REG),
        mem: mem_off(sp(), ldst64_offset(RUNTIME_FRAME_ENTRY_ADDR_OFFSET)),
    },
    A64Insn::BrBr64BranchReg {
        rn: x(PROLOGUE_ENTRY_SCRATCH_REG),
    },
];

pub const KJIT_EPILOGUE: &[A64Insn] = &[
    A64Insn::StpGenStp64LdstpairOff {
        rt2: x(17),
        rt: x(16),
        mem: mem_off(sp(), ldstpair64_offset(64)),
    },
    A64Insn::LdpGenLdp64LdstpairOff {
        rt2: x(17),
        rt: x(16),
        mem: mem_off(
            sp(),
            ldstpair64_offset(RUNTIME_FRAME_PT_REGS_PTR_OFFSET as i32),
        ),
    },
    A64Insn::StpGenStp64LdstpairOff {
        rt2: x(RET_PARAM1_REG),
        rt: x(RET_PARAM0_REG),
        mem: mem_off(x(17), ldstpair64_offset(0)),
    },
    A64Insn::LdpGenLdp64LdstpairOff {
        rt2: x(15),
        rt: x(14),
        mem: mem_off(sp(), ldstpair64_offset(16)),
    },
    A64Insn::StpGenStp64LdstpairOff {
        rt2: x(15),
        rt: x(14),
        mem: mem_off(x(16), ldstpair64_offset(96)),
    },
    A64Insn::LdpGenLdp64LdstpairOff {
        rt2: x(15),
        rt: x(14),
        mem: mem_off(sp(), ldstpair64_offset(32)),
    },
    A64Insn::StpGenStp64LdstpairOff {
        rt2: x(15),
        rt: x(14),
        mem: mem_off(x(16), ldstpair64_offset(112)),
    },
    A64Insn::LdpGenLdp64LdstpairOff {
        rt2: x(15),
        rt: x(14),
        mem: mem_off(sp(), ldstpair64_offset(48)),
    },
    A64Insn::StpGenStp64LdstpairOff {
        rt2: x(15),
        rt: x(14),
        mem: mem_off(x(16), ldstpair64_offset(128)),
    },
    A64Insn::LdrImmGenLdr64LdstPos {
        rt: x(14),
        mem: mem_off(sp(), ldst64_offset(64)),
    },
    A64Insn::StrImmGenStr64LdstPos {
        rt: x(14),
        mem: mem_off(x(16), ldst64_offset(232)),
    },
    A64Insn::LdrImmGenLdr64LdstPos {
        rt: x(14),
        mem: mem_off(sp(), ldst64_offset(72)),
    },
    A64Insn::StrImmGenStr64LdstPos {
        rt: x(14),
        mem: mem_off(x(16), ldst64_offset(248)),
    },
    A64Insn::StpGenStp64LdstpairOff {
        rt2: x(1),
        rt: x(0),
        mem: mem_off(x(16), ldstpair64_offset(0)),
    },
    A64Insn::StpGenStp64LdstpairOff {
        rt2: x(3),
        rt: x(2),
        mem: mem_off(x(16), ldstpair64_offset(16)),
    },
    A64Insn::StpGenStp64LdstpairOff {
        rt2: x(5),
        rt: x(4),
        mem: mem_off(x(16), ldstpair64_offset(32)),
    },
    A64Insn::StpGenStp64LdstpairOff {
        rt2: x(7),
        rt: x(6),
        mem: mem_off(x(16), ldstpair64_offset(48)),
    },
    A64Insn::StrImmGenStr64LdstPos {
        rt: x(8),
        mem: mem_off(x(16), ldst64_offset(64)),
    },
    A64Insn::StpGenStp64LdstpairOff {
        rt2: x(19),
        rt: x(18),
        mem: mem_off(x(16), ldstpair64_offset(144)),
    },
    A64Insn::StpGenStp64LdstpairOff {
        rt2: x(21),
        rt: x(20),
        mem: mem_off(x(16), ldstpair64_offset(160)),
    },
    A64Insn::StpGenStp64LdstpairOff {
        rt2: x(23),
        rt: x(22),
        mem: mem_off(x(16), ldstpair64_offset(176)),
    },
    A64Insn::StpGenStp64LdstpairOff {
        rt2: x(25),
        rt: x(24),
        mem: mem_off(x(16), ldstpair64_offset(192)),
    },
    A64Insn::StpGenStp64LdstpairOff {
        rt2: x(27),
        rt: x(26),
        mem: mem_off(x(16), ldstpair64_offset(208)),
    },
    A64Insn::StrImmGenStr64LdstPos {
        rt: x(28),
        mem: mem_off(x(16), ldst64_offset(224)),
    },
    A64Insn::StrImmGenStr64LdstPos {
        rt: x(ABI_LINK_REG),
        mem: mem_off(x(16), ldst64_offset(240)),
    },
    A64Insn::OrrLogShiftOrr64LogShift {
        shift: 0,
        rm: x(RET_STATUS_REG),
        imm6: uimm(0, 6),
        rn: xzr(),
        rd: x(ABI_PT_REGS_ARG_REG),
    },
    A64Insn::LdrImmGenLdr64LdstPos {
        rt: x(18),
        mem: mem_off(sp(), ldst64_offset(88)),
    },
    A64Insn::LdpGenLdp64LdstpairOff {
        rt2: x(20),
        rt: x(19),
        mem: mem_off(sp(), ldstpair64_offset(96)),
    },
    A64Insn::LdpGenLdp64LdstpairOff {
        rt2: x(22),
        rt: x(21),
        mem: mem_off(sp(), ldstpair64_offset(112)),
    },
    A64Insn::LdpGenLdp64LdstpairOff {
        rt2: x(24),
        rt: x(23),
        mem: mem_off(sp(), ldstpair64_offset(128)),
    },
    A64Insn::LdpGenLdp64LdstpairOff {
        rt2: x(26),
        rt: x(25),
        mem: mem_off(sp(), ldstpair64_offset(144)),
    },
    A64Insn::LdpGenLdp64LdstpairOff {
        rt2: x(28),
        rt: x(27),
        mem: mem_off(sp(), ldstpair64_offset(160)),
    },
    A64Insn::LdpGenLdp64LdstpairPost {
        rt2: x(ABI_LINK_REG),
        rt: x(29),
        mem: mem_post(sp(), ldstpair64_offset(RUNTIME_FRAME_SIZE_BYTES as i32)),
    },
    A64Insn::RetRet64rBranchReg {
        rn: x(ABI_LINK_REG),
    },
];

pub const DISPATCH_TEMPLATE_LEN: usize = 9;
/// Indices of the template's two miss branches (`cbz` on the slot, `cbnz` on the key
/// compare). Both go to the same forward exit-group start.
pub const DISPATCH_TEMPLATE_MISS_BRANCHES: [usize; 2] = [3, 6];

/// The in-fragment branch dispatch (A11, docs/pipeline.md "In-fragment branch
/// dispatch (A11)", Lowering), emitted after a branch site's budget check and
/// target move (T in `DISPATCH_TARGET_REG`):
///
/// ```text
/// ldr  x12, [sp, #RUNTIME_FRAME_IBTC_OFFSET]     ; the run's table
/// ubfx x14, x13, #IBTC_INDEX_LSB, #IBTC_BITS     ; slot index < 2^IBTC_BITS
/// ldr  x12, [x12, x14, lsl #IBTC_SLOT_SHIFT]     ; slot: 0 or a record
/// cbz  x12, <miss>
/// ldr  x14, [x12, #IBTC_RECORD_PC_OFFSET]        ; the record's pc
/// sub  x14, x14, x13
/// cbnz x14, <miss>
/// ldr  x12, [x12, #IBTC_RECORD_HOST_OFFSET]      ; a verified entry of a live fragment
/// br   x12
/// ```
///
/// The two miss branches carry placeholder offsets (0) until layout resolves them to
/// the exit-group start that directly follows the `br`. Every register, immediate and
/// offset is part of the ABI: the verifier accepts exactly these words
/// (`dispatch_template_matches`), so this is the only way a fragment can branch
/// through a table.
pub const KJIT_DISPATCH_TEMPLATE: [A64Insn; DISPATCH_TEMPLATE_LEN] = [
    A64Insn::LdrImmGenLdr64LdstPos {
        rt: x(DISPATCH_SLOT_REG),
        mem: mem_off(sp(), ldst64_offset(RUNTIME_FRAME_IBTC_OFFSET)),
    },
    A64Insn::UbfmUbfm64mBitfield {
        immr: uimm(IBTC_INDEX_LSB, 6),
        imms: uimm(IBTC_INDEX_LSB + IBTC_BITS - 1, 6),
        rn: x(DISPATCH_TARGET_REG),
        rd: x(DISPATCH_KEY_REG),
    },
    // LDR (register), 64-bit: `lsl #IBTC_SLOT_SHIFT` is option 0b011 (LSL/UXTX), S = 1.
    A64Insn::LdrRegGenLdr64LdstRegoff {
        rm: x(DISPATCH_KEY_REG),
        option: 0b011,
        s: 1,
        rn: x(DISPATCH_SLOT_REG),
        rt: x(DISPATCH_SLOT_REG),
    },
    A64Insn::CbzCbz64Compbranch {
        imm19: scaled_simm(0, 19, 2),
        rt: x(DISPATCH_SLOT_REG),
    },
    A64Insn::LdrImmGenLdr64LdstPos {
        rt: x(DISPATCH_KEY_REG),
        mem: mem_off(x(DISPATCH_SLOT_REG), ldst64_offset(IBTC_RECORD_PC_OFFSET)),
    },
    A64Insn::SubAddsubShiftSub64AddsubShift {
        shift: 0,
        rm: x(DISPATCH_TARGET_REG),
        imm6: uimm(0, 6),
        rn: x(DISPATCH_KEY_REG),
        rd: x(DISPATCH_KEY_REG),
    },
    A64Insn::CbnzCbnz64Compbranch {
        imm19: scaled_simm(0, 19, 2),
        rt: x(DISPATCH_KEY_REG),
    },
    A64Insn::LdrImmGenLdr64LdstPos {
        rt: x(DISPATCH_SLOT_REG),
        mem: mem_off(x(DISPATCH_SLOT_REG), ldst64_offset(IBTC_RECORD_HOST_OFFSET)),
    },
    A64Insn::BrBr64BranchReg {
        rn: x(DISPATCH_SLOT_REG),
    },
];

const _: () = assert!(IBTC_SLOT_SHIFT == 3, "the template's lsl #3 is option 0b011 with S = 1");

/// `imm19` of CBZ/CBNZ (bits 23:5): the only bits of a miss branch that vary.
const MISS_BRANCH_IMM19_MASK: u32 = 0x00ff_ffe0;

/// Whether the encoded `words` are exactly `KJIT_DISPATCH_TEMPLATE`, up to the two
/// miss branches' offsets. Returns those offsets (byte deltas from each branch), which
/// the caller checks (both must name the same forward exit-group start). Compared as
/// words, like the prologue: the encoding is the contract.
pub fn dispatch_template_matches(words: &[u32]) -> Option<[i64; 2]> {
    if words.len() != DISPATCH_TEMPLATE_LEN {
        return None;
    }
    let mut deltas = [0_i64; 2];
    let mut next_miss = 0;
    for (index, (&word, expected)) in words.iter().zip(KJIT_DISPATCH_TEMPLATE.iter()).enumerate() {
        let expected = expected.encode().ok()?;
        if DISPATCH_TEMPLATE_MISS_BRANCHES.contains(&index) {
            if word & !MISS_BRANCH_IMM19_MASK != expected & !MISS_BRANCH_IMM19_MASK {
                return None;
            }
            let imm19 = ((word & MISS_BRANCH_IMM19_MASK) >> 5) as i64;
            deltas[next_miss] = ((imm19 << 45) >> 45) * ABI_INSN_SIZE as i64;
            next_miss += 1;
        } else if word != expected {
            return None;
        }
    }
    Some(deltas)
}

pub fn append_prologue(
    out: &mut SharedVec<A64Insn>,
    flags: AllocFlags,
) -> SharedResult<(), SharedAllocError> {
    append_abi_insns(out, KJIT_PROLOGUE, flags)
}

pub fn append_epilogue(
    out: &mut SharedVec<A64Insn>,
    flags: AllocFlags,
) -> SharedResult<(), SharedAllocError> {
    append_abi_insns(out, KJIT_EPILOGUE, flags)
}

pub fn copy_prologue(flags: AllocFlags) -> SharedResult<SharedVec<A64Insn>, SharedAllocError> {
    copy_abi_insns(KJIT_PROLOGUE, flags)
}

pub fn copy_epilogue(flags: AllocFlags) -> SharedResult<SharedVec<A64Insn>, SharedAllocError> {
    copy_abi_insns(KJIT_EPILOGUE, flags)
}

fn append_abi_insns(
    out: &mut SharedVec<A64Insn>,
    insns: &[A64Insn],
    flags: AllocFlags,
) -> SharedResult<(), SharedAllocError> {
    for insn in insns {
        out.push(*insn, flags)?;
    }
    Ok(())
}

fn copy_abi_insns(
    insns: &[A64Insn],
    flags: AllocFlags,
) -> SharedResult<SharedVec<A64Insn>, SharedAllocError> {
    let mut out = SharedVec::with_capacity(insns.len(), flags)?;
    append_abi_insns(&mut out, insns, flags)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::platform::GFP_KERNEL;

    #[test]
    fn wrapper_lengths_match_contract() {
        assert_eq!(PROLOGUE_LEN_BYTES, 0xa8);
        assert_eq!(EPILOGUE_OFFSET, 0xa8);
        assert_eq!(EPILOGUE_LEN_BYTES, 0x88);
    }

    #[test]
    fn wrapper_sequences_are_encodable() {
        for insn in KJIT_PROLOGUE.iter().chain(KJIT_EPILOGUE.iter()) {
            insn.encode().unwrap();
        }
    }

    /// The run's dispatch table is read from extra params `[2]` while x1 still holds
    /// the extra pointer (the pt_regs load overwrites x1), and stored in the frame
    /// slot the template reads.
    #[test]
    fn prologue_stores_the_dispatch_table_before_x1_is_overwritten() {
        let load = KJIT_PROLOGUE
            .iter()
            .position(|insn| {
                matches!(insn, A64Insn::LdrImmGenLdr64LdstPos { rt, mem }
                    if rt.enc == DISPATCH_SLOT_REG
                        && *mem == mem_off(x(ABI_EXTRA_PARAMS_ARG_REG),
                            ldst64_offset(EXTRA_PARAM_IBTC_TABLE_OFFSET)))
            })
            .expect("the prologue loads extra params [2]");
        assert!(matches!(
            KJIT_PROLOGUE[load + 1],
            A64Insn::StrImmGenStr64LdstPos { rt, mem }
                if rt.enc == DISPATCH_SLOT_REG
                    && mem == mem_off(sp(), ldst64_offset(RUNTIME_FRAME_IBTC_OFFSET))
        ));
        let x1_overwritten = KJIT_PROLOGUE
            .iter()
            .position(|insn| {
                matches!(insn, A64Insn::LdpGenLdp64LdstpairOff { rt, rt2, .. }
                    if rt.enc == ABI_EXTRA_PARAMS_ARG_REG || rt2.enc == ABI_EXTRA_PARAMS_ARG_REG)
            })
            .expect("the prologue loads user x1");
        assert!(load + 1 < x1_overwritten);
    }

    #[test]
    fn dispatch_template_is_the_contract_nine_words() {
        let words = KJIT_DISPATCH_TEMPLATE
            .iter()
            .map(|insn| insn.encode().unwrap())
            .collect::<Vec<_>>();
        // The contract's nine words as `llvm-mc` encodes them (miss offsets 0):
        // ldr x12, [sp, #200]; ubfx x14, x13, #2, #12; ldr x12, [x12, x14, lsl #3];
        // cbz x12; ldr x14, [x12]; sub x14, x14, x13; cbnz x14; ldr x12, [x12, #8];
        // br x12
        assert_eq!(
            words,
            [
                0xf94067ec, 0xd34235ae, 0xf86e798c, 0xb400000c, 0xf940018e, 0xcb0d01ce,
                0xb500000e, 0xf940058c, 0xd61f0180,
            ]
        );
        assert_eq!(words.len(), DISPATCH_TEMPLATE_LEN);
        assert_eq!(dispatch_template_matches(&words), Some([0, 0]));
        // Any other word in a non-miss position, or another register in a miss
        // branch, is not the template; the miss offsets are free.
        for index in 0..DISPATCH_TEMPLATE_LEN {
            let mut altered = words.clone();
            altered[index] ^= 1 << 10;
            let expected = if DISPATCH_TEMPLATE_MISS_BRANCHES.contains(&index) {
                Some(())
            } else {
                None
            };
            assert_eq!(dispatch_template_matches(&altered).map(|_| ()), expected, "word {index}");
        }
        // The two miss offsets are returned as byte deltas, sign-extended.
        let mut moved = words.clone();
        moved[DISPATCH_TEMPLATE_MISS_BRANCHES[0]] |= 6 << 5;
        moved[DISPATCH_TEMPLATE_MISS_BRANCHES[1]] |= 0x7ffff << 5;
        assert_eq!(dispatch_template_matches(&moved), Some([24, -4]));
    }

    #[test]
    fn wrapper_copy_helpers_preserve_sequences() {
        let prologue = copy_prologue(GFP_KERNEL).unwrap();
        let epilogue = copy_epilogue(GFP_KERNEL).unwrap();

        assert_eq!(&*prologue, KJIT_PROLOGUE);
        assert_eq!(&*epilogue, KJIT_EPILOGUE);
    }
}
