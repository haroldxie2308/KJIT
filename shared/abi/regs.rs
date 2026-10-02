pub const ABI_PT_REGS_ARG_REG: u8 = 0;
pub const ABI_EXTRA_PARAMS_ARG_REG: u8 = 1;
/// Absolute address of the body instruction the prologue branches to: fragment
/// base + an entry offset the runtime took from `ExecutionFragment` (`entry_offset`
/// or `offset_for_pc`). Never user-controlled.
pub const ABI_ENTRY_ARG_REG: u8 = 2;
pub const ABI_LINK_REG: u8 = 30;

pub const RET_STATUS_REG: u8 = 9;
pub const RET_PARAM0_REG: u8 = 10;
pub const RET_PARAM1_REG: u8 = 11;

/// Dispatch template registers (A11, tmp/pipeline.md "A11 contract"). All three are
/// reg-virt scratch, dead at every original-instruction boundary.
/// `DISPATCH_SLOT_REG` holds kernel values only (table pointer, slot, record, host);
/// `DISPATCH_TARGET_REG` holds the branch target T, a user value, from the site's
/// target move until the template or the site's exit group; `DISPATCH_KEY_REG` holds
/// the slot index, then the record key compare, both user-derived.
pub const DISPATCH_SLOT_REG: u8 = 12;
pub const DISPATCH_TARGET_REG: u8 = 13;
pub const DISPATCH_KEY_REG: u8 = 14;

pub const REG_VIRT_SCRATCH_GPR_LIMIT: usize = 4;
pub const REG_VIRT_SCRATCH_GPR_START: u8 = 12;
pub const REG_VIRT_SCRATCH_GPR_END: u8 = 15;
pub const REG_VIRT_STACK_BACKED_REG_START: u8 = 12;
pub const REG_VIRT_STACK_BACKED_REG_END: u8 = 17;
pub const REG_VIRT_STABLE_MAPPED_X29_REG: u8 = 29;
pub const REG_VIRT_STABLE_MAPPED_X29_PHYS_REG: u8 = 16;
pub const REG_VIRT_STABLE_MAPPED_SP_PHYS_REG: u8 = 17;

const _: () = assert!(DISPATCH_SLOT_REG == REG_VIRT_SCRATCH_GPR_START);
const _: () = assert!(DISPATCH_TARGET_REG > DISPATCH_SLOT_REG && DISPATCH_KEY_REG > DISPATCH_TARGET_REG);
const _: () = assert!(DISPATCH_KEY_REG <= REG_VIRT_SCRATCH_GPR_END);

pub const fn reg_virt_scratch_gpr(index: usize) -> Option<u8> {
    if index >= REG_VIRT_SCRATCH_GPR_LIMIT {
        return None;
    }

    Some(REG_VIRT_SCRATCH_GPR_START + index as u8)
}

/// User VA size the A8 PAN window's range check assumes (tmp/pipeline.md, "A8
/// contract"). Before a privileged LSE atomic the fragment requires VA bits
/// `[PAN_WINDOW_RANGE_TOP_BIT:USER_VA_BITS]` of the address to be zero
/// (`ubfx sB, sA, #48, #8; cbnz sB, <PAN stub>`): bit 55 selects TTBR0 vs TTBR1
/// and the top byte is ignored (TBI0), so the access is a TTBR0 user address below
/// 2^48. The module refuses to load unless `vabits_actual == USER_VA_BITS` (K1 pins
/// `ARM64_VA_BITS_48`).
pub const USER_VA_BITS: u8 = 48;
/// Highest VA bit the range check covers: bit 55, the TTBR select bit under TBI.
pub const PAN_WINDOW_RANGE_TOP_BIT: u8 = 55;

/// RET_PARAM0 of an `Unsupported` exit at a PC whose word could not be read (the
/// translated code ran into the end of the readable text). A real word is always
/// <= `u32::MAX`, so this never collides with one.
pub const UNSUPPORTED_WORD_UNREADABLE: u64 = u64::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetStatus {
    Svc,
    Bl,
    Blr,
    Br,
    Ret,
    Mem,
    /// Undecodable or rejected instruction, or a PC past the readable text;
    /// userspace resumes natively at it. RET_PARAM0 = raw word (zero-extended),
    /// or `UNSUPPORTED_WORD_UNREADABLE` when no word could be read; RET_PARAM1 =
    /// its PC.
    Unsupported,
    /// The back-edge budget ran out before a back-edge branch; userspace resumes
    /// natively at it. RET_PARAM0 = the branch's raw word, RET_PARAM1 = its PC.
    Budget,
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
            Self::Unsupported => 6,
            Self::Budget => 7,
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
            6 => Self::Unsupported,
            7 => Self::Budget,
            8 => Self::Debug,
            other => Self::Invalid(other),
        }
    }
}
