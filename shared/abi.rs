use crate::shared::arm64::ergo::{
    ldst64_offset, ldstpair64_offset, mem_off, mem_post, mem_pre, sp, uimm, x, xzr,
};
use crate::shared::arm64::A64Insn;
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
    A64Insn::StpGenStp64LdstpairPre {
        rt2: x(30),
        rt: x(29),
        mem: mem_pre(sp(), ldstpair64_offset(-192)),
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
        mem: mem_off(sp(), ldstpair64_offset(176)),
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
    A64Insn::NopNopHiHints {},
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
        mem: mem_off(sp(), ldstpair64_offset(176)),
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
        mem: mem_post(sp(), ldstpair64_offset(192)),
    },
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
