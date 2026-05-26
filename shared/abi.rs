use crate::shared::arm64::{A64Imm, A64Insn, A64Mem, A64Reg};
use crate::shared::platform::{AllocFlags, SharedAllocError, SharedResult, SharedVec};

pub const ABI_PT_REGS_ARG_REG: u8 = 0;
pub const ABI_EXTRA_PARAMS_ARG_REG: u8 = 1;
pub const ABI_LINK_REG: u8 = 30;

pub const RET_STATUS_REG: u8 = 9;
pub const RET_PARAM0_REG: u8 = 10;
pub const RET_PARAM1_REG: u8 = 11;

pub const ABI_INSN_SIZE: usize = 4;
pub const PROLOGUE_LEN_BYTES: usize = KJIT_PROLOGUE.len() * ABI_INSN_SIZE;
pub const PROLOGUE_ENTRY_BRANCH_OFFSET: usize = PROLOGUE_LEN_BYTES - ABI_INSN_SIZE;
pub const EPILOGUE_OFFSET: usize = PROLOGUE_LEN_BYTES;
pub const EPILOGUE_LEN_BYTES: usize = KJIT_EPILOGUE.len() * ABI_INSN_SIZE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetStatus {
    Svc,
    Bl,
    Blr,
    Br,
    Ret,
    Mem,
    Debug,
    Invalid(u64),
}

impl RetStatus {
    pub const fn as_reg(self) -> u64 {
        match self {
            Self::Svc => 0,
            Self::Bl => 1,
            Self::Blr => 2,
            Self::Br => 3,
            Self::Ret => 4,
            Self::Mem => 5,
            Self::Debug => 8,
            Self::Invalid(value) => value,
        }
    }

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

pub const KJIT_PROLOGUE: &[A64Insn] = &[
    stp_pre(29, 30, -192),
    mov_from_sp(29),
    str64_off(18, sp(), 88),
    stp_off(19, 20, sp(), 96),
    stp_off(21, 22, sp(), 112),
    stp_off(23, 24, sp(), 128),
    stp_off(25, 26, sp(), 144),
    stp_off(27, 28, sp(), 160),
    mov_x(16, ABI_PT_REGS_ARG_REG),
    mov_x(17, ABI_EXTRA_PARAMS_ARG_REG),
    stp_off(16, 17, sp(), 176),
    ldp_off(0, 1, x(16), 0),
    ldp_off(2, 3, x(16), 16),
    ldp_off(4, 5, x(16), 32),
    ldp_off(6, 7, x(16), 48),
    ldp_off(8, 9, x(16), 64),
    ldp_off(10, 11, x(16), 80),
    ldp_off(12, 13, x(16), 96),
    ldp_off(14, 15, x(16), 112),
    ldp_off(18, 19, x(16), 144),
    ldp_off(20, 21, x(16), 160),
    ldp_off(22, 23, x(16), 176),
    ldp_off(24, 25, x(16), 192),
    ldp_off(26, 27, x(16), 208),
    ldr64_off(28, x(16), 224),
    ldr64_off(30, x(16), 240),
    ldr64_off(17, x(16), 232),
    str64_off(17, sp(), 64),
    ldr64_off(17, x(16), 248),
    str64_off(17, sp(), 72),
    ldp_off(16, 17, x(16), 128),
    stp_off(12, 13, sp(), 16),
    stp_off(14, 15, sp(), 32),
    stp_off(16, 17, sp(), 48),
    ldp_off(16, 17, sp(), 64),
    A64Insn::NopNopHiHints {},
];

pub const KJIT_EPILOGUE: &[A64Insn] = &[
    stp_off(16, 17, sp(), 64),
    ldp_off(16, 17, sp(), 176),
    stp_off(RET_PARAM0_REG, RET_PARAM1_REG, x(17), 0),
    ldp_off(14, 15, sp(), 16),
    stp_off(14, 15, x(16), 96),
    ldp_off(14, 15, sp(), 32),
    stp_off(14, 15, x(16), 112),
    ldp_off(14, 15, sp(), 48),
    stp_off(14, 15, x(16), 128),
    ldr64_off(14, sp(), 64),
    str64_off(14, x(16), 232),
    ldr64_off(14, sp(), 72),
    str64_off(14, x(16), 248),
    stp_off(0, 1, x(16), 0),
    stp_off(2, 3, x(16), 16),
    stp_off(4, 5, x(16), 32),
    stp_off(6, 7, x(16), 48),
    str64_off(8, x(16), 64),
    stp_off(18, 19, x(16), 144),
    stp_off(20, 21, x(16), 160),
    stp_off(22, 23, x(16), 176),
    stp_off(24, 25, x(16), 192),
    stp_off(26, 27, x(16), 208),
    str64_off(28, x(16), 224),
    str64_off(ABI_LINK_REG, x(16), 240),
    mov_x(ABI_PT_REGS_ARG_REG, RET_STATUS_REG),
    ldr64_off(18, sp(), 88),
    ldp_off(19, 20, sp(), 96),
    ldp_off(21, 22, sp(), 112),
    ldp_off(23, 24, sp(), 128),
    ldp_off(25, 26, sp(), 144),
    ldp_off(27, 28, sp(), 160),
    ldp_post(29, ABI_LINK_REG, sp(), 192),
    A64Insn::RetRet64rBranchReg {
        rn: x(ABI_LINK_REG),
    },
];

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

const fn x(reg: u8) -> A64Reg {
    A64Reg::x(reg)
}

const fn sp() -> A64Reg {
    A64Reg::x_sp(31)
}

const fn mov_x(rd: u8, rn: u8) -> A64Insn {
    A64Insn::OrrLogShiftOrr64LogShift {
        shift: 0,
        rm: x(rn),
        imm6: A64Imm::unsigned(0, 6),
        rn: x(31),
        rd: x(rd),
    }
}

const fn mov_from_sp(rd: u8) -> A64Insn {
    A64Insn::AddAddsubImmAdd64AddsubImm {
        sh: 0,
        imm12: A64Imm::unsigned(0, 12),
        rn: sp(),
        rd: x(rd),
    }
}

const fn ldr64_off(rt: u8, base: A64Reg, offset_bytes: u32) -> A64Insn {
    A64Insn::LdrImmGenLdr64LdstPos {
        rt: x(rt),
        mem: A64Mem::offset(base, unsigned_scaled_64(offset_bytes)),
    }
}

const fn str64_off(rt: u8, base: A64Reg, offset_bytes: u32) -> A64Insn {
    A64Insn::StrImmGenStr64LdstPos {
        rt: x(rt),
        mem: A64Mem::offset(base, unsigned_scaled_64(offset_bytes)),
    }
}

const fn ldp_off(rt: u8, rt2: u8, base: A64Reg, offset_bytes: i32) -> A64Insn {
    A64Insn::LdpGenLdp64LdstpairOff {
        rt2: x(rt2),
        rt: x(rt),
        mem: A64Mem::offset(base, signed_scaled_pair(offset_bytes)),
    }
}

const fn ldp_post(rt: u8, rt2: u8, base: A64Reg, offset_bytes: i32) -> A64Insn {
    A64Insn::LdpGenLdp64LdstpairPost {
        rt2: x(rt2),
        rt: x(rt),
        mem: A64Mem::post_index(base, signed_scaled_pair(offset_bytes)),
    }
}

const fn stp_off(rt: u8, rt2: u8, base: A64Reg, offset_bytes: i32) -> A64Insn {
    A64Insn::StpGenStp64LdstpairOff {
        rt2: x(rt2),
        rt: x(rt),
        mem: A64Mem::offset(base, signed_scaled_pair(offset_bytes)),
    }
}

const fn stp_pre(rt: u8, rt2: u8, offset_bytes: i32) -> A64Insn {
    A64Insn::StpGenStp64LdstpairPre {
        rt2: x(rt2),
        rt: x(rt),
        mem: A64Mem::pre_index(sp(), signed_scaled_pair(offset_bytes)),
    }
}

const fn unsigned_scaled_64(offset_bytes: u32) -> A64Imm {
    A64Imm::scaled_unsigned(offset_bytes / 8, 12, 3)
}

const fn signed_scaled_pair(offset_bytes: i32) -> A64Imm {
    let scaled = offset_bytes / 8;
    A64Imm::scaled_signed((scaled as u32) & 0x7F, 7, 3)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::platform::GFP_KERNEL;

    #[test]
    fn wrapper_lengths_match_old_contract() {
        assert_eq!(PROLOGUE_LEN_BYTES, 0x90);
        assert_eq!(PROLOGUE_ENTRY_BRANCH_OFFSET, 0x8c);
        assert_eq!(EPILOGUE_OFFSET, 0x90);
        assert_eq!(EPILOGUE_LEN_BYTES, 0x88);
    }

    #[test]
    fn wrapper_sequences_are_encodable() {
        for insn in KJIT_PROLOGUE.iter().chain(KJIT_EPILOGUE.iter()) {
            insn.encode().unwrap();
        }
    }

    #[test]
    fn wrapper_copy_helpers_preserve_sequences() {
        let prologue = copy_prologue(GFP_KERNEL).unwrap();
        let epilogue = copy_epilogue(GFP_KERNEL).unwrap();

        assert_eq!(&*prologue, KJIT_PROLOGUE);
        assert_eq!(&*epilogue, KJIT_EPILOGUE);
    }
}
