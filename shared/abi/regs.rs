pub const ABI_PT_REGS_ARG_REG: u8 = 0;
pub const ABI_EXTRA_PARAMS_ARG_REG: u8 = 1;
pub const ABI_LINK_REG: u8 = 30;

pub const RET_STATUS_REG: u8 = 9;
pub const RET_PARAM0_REG: u8 = 10;
pub const RET_PARAM1_REG: u8 = 11;

pub const REG_VIRT_SCRATCH_GPR_LIMIT: usize = 4;
pub const REG_VIRT_SCRATCH_GPR_START: u8 = 12;
pub const REG_VIRT_SCRATCH_GPR_END: u8 = 15;
pub const REG_VIRT_STACK_BACKED_REG_START: u8 = 12;
pub const REG_VIRT_STACK_BACKED_REG_END: u8 = 17;
pub const REG_VIRT_STABLE_MAPPED_X29_REG: u8 = 29;
pub const REG_VIRT_STABLE_MAPPED_X29_PHYS_REG: u8 = 16;
pub const REG_VIRT_STABLE_MAPPED_SP_PHYS_REG: u8 = 17;

pub const fn reg_virt_scratch_gpr(index: usize) -> Option<u8> {
    if index >= REG_VIRT_SCRATCH_GPR_LIMIT {
        return None;
    }

    Some(REG_VIRT_SCRATCH_GPR_START + index as u8)
}

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
