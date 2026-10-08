use core::fmt;

use crate::shared::platform::{SharedAllocError, SharedVec, GFP_KERNEL};
use crate::shared::trans::cfg::RuntimeExitReason;

mod generated;
pub mod ergo;

pub use generated::{
    A64EncodeError, A64Imm, A64Insn, A64Mem, A64OperandRole, A64Reg, A64Reg31Mode, A64RegWidth,
    A64RewriteError, GeneratedFieldSpec, GeneratedInsnSpec, GENERATED_A64_SUBSET,
};

/// A64 condition code (`cond` field), all 16 encodings. `Nv` (0b1111) is kept
/// distinct from `Al` so re-encoding preserves the exact word; both always hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum A64Condition {
    Eq,
    Ne,
    Hs,
    Lo,
    Mi,
    Pl,
    Vs,
    Vc,
    Hi,
    Ls,
    Ge,
    Lt,
    Gt,
    Le,
    Al,
    Nv,
}

impl A64Condition {
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0x0 => Some(Self::Eq),
            0x1 => Some(Self::Ne),
            0x2 => Some(Self::Hs),
            0x3 => Some(Self::Lo),
            0x4 => Some(Self::Mi),
            0x5 => Some(Self::Pl),
            0x6 => Some(Self::Vs),
            0x7 => Some(Self::Vc),
            0x8 => Some(Self::Hi),
            0x9 => Some(Self::Ls),
            0xA => Some(Self::Ge),
            0xB => Some(Self::Lt),
            0xC => Some(Self::Gt),
            0xD => Some(Self::Le),
            0xE => Some(Self::Al),
            0xF => Some(Self::Nv),
            _ => None,
        }
    }

    pub const fn bits(self) -> u8 {
        match self {
            Self::Eq => 0x0,
            Self::Ne => 0x1,
            Self::Hs => 0x2,
            Self::Lo => 0x3,
            Self::Mi => 0x4,
            Self::Pl => 0x5,
            Self::Vs => 0x6,
            Self::Vc => 0x7,
            Self::Hi => 0x8,
            Self::Ls => 0x9,
            Self::Ge => 0xA,
            Self::Lt => 0xB,
            Self::Gt => 0xC,
            Self::Le => 0xD,
            Self::Al => 0xE,
            Self::Nv => 0xF,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IrInsn {
    pub pc: u64,
    pub word: u32,
    pub inner: A64Insn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    UnsupportedWord { pc: u64, word: u32 },
    Alloc(SharedAllocError),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedWord { pc, word } => {
                write!(f, "unsupported instruction word {word:#010x} at pc {pc:#x}")
            }
            Self::Alloc(err) => write!(f, "allocation failed while decoding: {err:?}"),
        }
    }
}

/// The operation of an LSE single-register atomic (A8): `LD<op>` (the old value
/// is returned, `mem = mem <op> Rs`), `SWP` (`mem = Rs`) and `CAS` (`mem = Rt` if
/// `mem == Rs`; `Rs` receives the old value).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum A64AtomicOp {
    Add,
    /// Bit clear: `mem AND NOT(Rs)`.
    Clr,
    Eor,
    /// Bit set: `mem OR Rs`.
    Set,
    Smax,
    Smin,
    Umax,
    Umin,
    Swp,
    Cas,
}

/// An LSE single-register atomic (`LD<op>`, `SWP`, `CAS`, every size and A/L/AL
/// variant; `ST<op>` is `LD<op>` with `Rt` = XZR). `size` is the access size in
/// bytes (1, 2, 4, 8); `rn` is the base (`<Xn|SP>`, no offset, no writeback).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct A64Atomic {
    pub op: A64AtomicOp,
    pub size: u8,
    pub rs: A64Reg,
    pub rt: A64Reg,
    pub rn: A64Reg,
}

impl A64Insn {
    pub fn pc_relative_address(self, pc: u64) -> Option<u64> {
        match self {
            Self::AdrAdrOnlyPcreladdr { immlo, immhi, .. } => {
                let imm = (immhi.raw() << 2) | immlo.raw();
                Some(pc.wrapping_add_signed(sign_extend(imm, 21)))
            }
            Self::AdrpAdrpOnlyPcreladdr { immlo, immhi, .. } => {
                let imm = (immhi.raw() << 2) | immlo.raw();
                let page_pc = pc & !0xFFF;
                Some(page_pc.wrapping_add_signed(sign_extend(imm, 21) << 12))
            }
            _ => None,
        }
    }

    pub const fn condition(self) -> Option<A64Condition> {
        match self {
            Self::BCondBOnlyCondbranch { cond, .. } => A64Condition::from_bits(cond),
            _ => None,
        }
    }

    pub const fn add_sub_imm(sh: u8, imm12: A64Imm) -> Option<u64> {
        match sh {
            0 => Some(imm12.raw() as u64),
            1 => Some((imm12.raw() as u64) << 12),
            _ => None,
        }
    }

    pub const fn move_wide_shift(hw: u8) -> Option<u8> {
        match hw {
            0..=3 => Some(hw * 16),
            _ => None,
        }
    }

    pub fn signed_imm9(imm9: A64Imm) -> i64 {
        imm9.value()
    }

    pub fn direct_branch_target(self, pc: u64) -> Option<u64> {
        match self {
            Self::BUncondBOnlyBranchImm { imm26 } => Some(pc_relative_target(pc, imm26.raw(), 26)),
            _ => None,
        }
    }

    pub fn conditional_targets(self, pc: u64) -> Option<(u64, u64)> {
        let taken = match self {
            Self::BCondBOnlyCondbranch { imm19, .. }
            | Self::CbzCbz32Compbranch { imm19, .. }
            | Self::CbzCbz64Compbranch { imm19, .. }
            | Self::CbnzCbnz32Compbranch { imm19, .. }
            | Self::CbnzCbnz64Compbranch { imm19, .. } => pc_relative_target(pc, imm19.raw(), 19),
            Self::TbzTbzOnlyTestbranch { imm14, .. }
            | Self::TbnzTbnzOnlyTestbranch { imm14, .. } => {
                pc_relative_target(pc, imm14.raw(), 14)
            }
            _ => return None,
        };
        Some((taken, pc.wrapping_add(4)))
    }

    /// The `LDTR`/`STTR` family (`LDTR`, `LDTRB`, `LDTRH`, `LDTRSB`, `LDTRSH`,
    /// `LDTRSW`, `STTR`, `STTRB`, `STTRH`): the only instructions a fragment may use
    /// to touch user memory. Emitted by reg-virt only; never admitted from user code.
    pub const fn is_unprivileged_access(self) -> bool {
        matches!(
            self,
            Self::LdtrLdtr32LdstUnpriv { .. }
                | Self::LdtrLdtr64LdstUnpriv { .. }
                | Self::LdtrbLdtrb32LdstUnpriv { .. }
                | Self::LdtrhLdtrh32LdstUnpriv { .. }
                | Self::LdtrsbLdtrsb32LdstUnpriv { .. }
                | Self::LdtrsbLdtrsb64LdstUnpriv { .. }
                | Self::LdtrshLdtrsh32LdstUnpriv { .. }
                | Self::LdtrshLdtrsh64LdstUnpriv { .. }
                | Self::LdtrswLdtrsw64LdstUnpriv { .. }
                | Self::SttrSttr32LdstUnpriv { .. }
                | Self::SttrSttr64LdstUnpriv { .. }
                | Self::SttrbSttrb32LdstUnpriv { .. }
                | Self::SttrhSttrh32LdstUnpriv { .. }
        )
    }

    /// The LSE single-register atomics (A8): the only forms a fragment runs as a
    /// privileged access to user memory, inside a PAN window (docs/pipeline.md, "LSE
    /// atomics through a PAN window (A8)"). Pinned by a test against the generated mnemonics.
    pub const fn lse_atomic(self) -> Option<A64Atomic> {
        let (op, size, rs, rt, rn) = match self {
            Self::LdaddLdadd32Memop { rs, rn, rt }
            | Self::LdaddLdadda32Memop { rs, rn, rt }
            | Self::LdaddLdaddal32Memop { rs, rn, rt }
            | Self::LdaddLdaddl32Memop { rs, rn, rt } => (A64AtomicOp::Add, 4, rs, rt, rn),
            Self::LdaddLdadd64Memop { rs, rn, rt }
            | Self::LdaddLdadda64Memop { rs, rn, rt }
            | Self::LdaddLdaddal64Memop { rs, rn, rt }
            | Self::LdaddLdaddl64Memop { rs, rn, rt } => (A64AtomicOp::Add, 8, rs, rt, rn),
            Self::LdaddbLdaddb32Memop { rs, rn, rt }
            | Self::LdaddbLdaddab32Memop { rs, rn, rt }
            | Self::LdaddbLdaddalb32Memop { rs, rn, rt }
            | Self::LdaddbLdaddlb32Memop { rs, rn, rt } => (A64AtomicOp::Add, 1, rs, rt, rn),
            Self::LdaddhLdaddh32Memop { rs, rn, rt }
            | Self::LdaddhLdaddah32Memop { rs, rn, rt }
            | Self::LdaddhLdaddalh32Memop { rs, rn, rt }
            | Self::LdaddhLdaddlh32Memop { rs, rn, rt } => (A64AtomicOp::Add, 2, rs, rt, rn),
            Self::LdclrLdclr32Memop { rs, rn, rt }
            | Self::LdclrLdclra32Memop { rs, rn, rt }
            | Self::LdclrLdclral32Memop { rs, rn, rt }
            | Self::LdclrLdclrl32Memop { rs, rn, rt } => (A64AtomicOp::Clr, 4, rs, rt, rn),
            Self::LdclrLdclr64Memop { rs, rn, rt }
            | Self::LdclrLdclra64Memop { rs, rn, rt }
            | Self::LdclrLdclral64Memop { rs, rn, rt }
            | Self::LdclrLdclrl64Memop { rs, rn, rt } => (A64AtomicOp::Clr, 8, rs, rt, rn),
            Self::LdclrbLdclrb32Memop { rs, rn, rt }
            | Self::LdclrbLdclrab32Memop { rs, rn, rt }
            | Self::LdclrbLdclralb32Memop { rs, rn, rt }
            | Self::LdclrbLdclrlb32Memop { rs, rn, rt } => (A64AtomicOp::Clr, 1, rs, rt, rn),
            Self::LdclrhLdclrh32Memop { rs, rn, rt }
            | Self::LdclrhLdclrah32Memop { rs, rn, rt }
            | Self::LdclrhLdclralh32Memop { rs, rn, rt }
            | Self::LdclrhLdclrlh32Memop { rs, rn, rt } => (A64AtomicOp::Clr, 2, rs, rt, rn),
            Self::LdeorLdeor32Memop { rs, rn, rt }
            | Self::LdeorLdeora32Memop { rs, rn, rt }
            | Self::LdeorLdeoral32Memop { rs, rn, rt }
            | Self::LdeorLdeorl32Memop { rs, rn, rt } => (A64AtomicOp::Eor, 4, rs, rt, rn),
            Self::LdeorLdeor64Memop { rs, rn, rt }
            | Self::LdeorLdeora64Memop { rs, rn, rt }
            | Self::LdeorLdeoral64Memop { rs, rn, rt }
            | Self::LdeorLdeorl64Memop { rs, rn, rt } => (A64AtomicOp::Eor, 8, rs, rt, rn),
            Self::LdeorbLdeorb32Memop { rs, rn, rt }
            | Self::LdeorbLdeorab32Memop { rs, rn, rt }
            | Self::LdeorbLdeoralb32Memop { rs, rn, rt }
            | Self::LdeorbLdeorlb32Memop { rs, rn, rt } => (A64AtomicOp::Eor, 1, rs, rt, rn),
            Self::LdeorhLdeorh32Memop { rs, rn, rt }
            | Self::LdeorhLdeorah32Memop { rs, rn, rt }
            | Self::LdeorhLdeoralh32Memop { rs, rn, rt }
            | Self::LdeorhLdeorlh32Memop { rs, rn, rt } => (A64AtomicOp::Eor, 2, rs, rt, rn),
            Self::LdsetLdset32Memop { rs, rn, rt }
            | Self::LdsetLdseta32Memop { rs, rn, rt }
            | Self::LdsetLdsetal32Memop { rs, rn, rt }
            | Self::LdsetLdsetl32Memop { rs, rn, rt } => (A64AtomicOp::Set, 4, rs, rt, rn),
            Self::LdsetLdset64Memop { rs, rn, rt }
            | Self::LdsetLdseta64Memop { rs, rn, rt }
            | Self::LdsetLdsetal64Memop { rs, rn, rt }
            | Self::LdsetLdsetl64Memop { rs, rn, rt } => (A64AtomicOp::Set, 8, rs, rt, rn),
            Self::LdsetbLdsetb32Memop { rs, rn, rt }
            | Self::LdsetbLdsetab32Memop { rs, rn, rt }
            | Self::LdsetbLdsetalb32Memop { rs, rn, rt }
            | Self::LdsetbLdsetlb32Memop { rs, rn, rt } => (A64AtomicOp::Set, 1, rs, rt, rn),
            Self::LdsethLdseth32Memop { rs, rn, rt }
            | Self::LdsethLdsetah32Memop { rs, rn, rt }
            | Self::LdsethLdsetalh32Memop { rs, rn, rt }
            | Self::LdsethLdsetlh32Memop { rs, rn, rt } => (A64AtomicOp::Set, 2, rs, rt, rn),
            Self::LdsmaxLdsmax32Memop { rs, rn, rt }
            | Self::LdsmaxLdsmaxa32Memop { rs, rn, rt }
            | Self::LdsmaxLdsmaxal32Memop { rs, rn, rt }
            | Self::LdsmaxLdsmaxl32Memop { rs, rn, rt } => (A64AtomicOp::Smax, 4, rs, rt, rn),
            Self::LdsmaxLdsmax64Memop { rs, rn, rt }
            | Self::LdsmaxLdsmaxa64Memop { rs, rn, rt }
            | Self::LdsmaxLdsmaxal64Memop { rs, rn, rt }
            | Self::LdsmaxLdsmaxl64Memop { rs, rn, rt } => (A64AtomicOp::Smax, 8, rs, rt, rn),
            Self::LdsmaxbLdsmaxb32Memop { rs, rn, rt }
            | Self::LdsmaxbLdsmaxab32Memop { rs, rn, rt }
            | Self::LdsmaxbLdsmaxalb32Memop { rs, rn, rt }
            | Self::LdsmaxbLdsmaxlb32Memop { rs, rn, rt } => (A64AtomicOp::Smax, 1, rs, rt, rn),
            Self::LdsmaxhLdsmaxh32Memop { rs, rn, rt }
            | Self::LdsmaxhLdsmaxah32Memop { rs, rn, rt }
            | Self::LdsmaxhLdsmaxalh32Memop { rs, rn, rt }
            | Self::LdsmaxhLdsmaxlh32Memop { rs, rn, rt } => (A64AtomicOp::Smax, 2, rs, rt, rn),
            Self::LdsminLdsmin32Memop { rs, rn, rt }
            | Self::LdsminLdsmina32Memop { rs, rn, rt }
            | Self::LdsminLdsminal32Memop { rs, rn, rt }
            | Self::LdsminLdsminl32Memop { rs, rn, rt } => (A64AtomicOp::Smin, 4, rs, rt, rn),
            Self::LdsminLdsmin64Memop { rs, rn, rt }
            | Self::LdsminLdsmina64Memop { rs, rn, rt }
            | Self::LdsminLdsminal64Memop { rs, rn, rt }
            | Self::LdsminLdsminl64Memop { rs, rn, rt } => (A64AtomicOp::Smin, 8, rs, rt, rn),
            Self::LdsminbLdsminb32Memop { rs, rn, rt }
            | Self::LdsminbLdsminab32Memop { rs, rn, rt }
            | Self::LdsminbLdsminalb32Memop { rs, rn, rt }
            | Self::LdsminbLdsminlb32Memop { rs, rn, rt } => (A64AtomicOp::Smin, 1, rs, rt, rn),
            Self::LdsminhLdsminh32Memop { rs, rn, rt }
            | Self::LdsminhLdsminah32Memop { rs, rn, rt }
            | Self::LdsminhLdsminalh32Memop { rs, rn, rt }
            | Self::LdsminhLdsminlh32Memop { rs, rn, rt } => (A64AtomicOp::Smin, 2, rs, rt, rn),
            Self::LdumaxLdumax32Memop { rs, rn, rt }
            | Self::LdumaxLdumaxa32Memop { rs, rn, rt }
            | Self::LdumaxLdumaxal32Memop { rs, rn, rt }
            | Self::LdumaxLdumaxl32Memop { rs, rn, rt } => (A64AtomicOp::Umax, 4, rs, rt, rn),
            Self::LdumaxLdumax64Memop { rs, rn, rt }
            | Self::LdumaxLdumaxa64Memop { rs, rn, rt }
            | Self::LdumaxLdumaxal64Memop { rs, rn, rt }
            | Self::LdumaxLdumaxl64Memop { rs, rn, rt } => (A64AtomicOp::Umax, 8, rs, rt, rn),
            Self::LdumaxbLdumaxb32Memop { rs, rn, rt }
            | Self::LdumaxbLdumaxab32Memop { rs, rn, rt }
            | Self::LdumaxbLdumaxalb32Memop { rs, rn, rt }
            | Self::LdumaxbLdumaxlb32Memop { rs, rn, rt } => (A64AtomicOp::Umax, 1, rs, rt, rn),
            Self::LdumaxhLdumaxh32Memop { rs, rn, rt }
            | Self::LdumaxhLdumaxah32Memop { rs, rn, rt }
            | Self::LdumaxhLdumaxalh32Memop { rs, rn, rt }
            | Self::LdumaxhLdumaxlh32Memop { rs, rn, rt } => (A64AtomicOp::Umax, 2, rs, rt, rn),
            Self::LduminLdumin32Memop { rs, rn, rt }
            | Self::LduminLdumina32Memop { rs, rn, rt }
            | Self::LduminLduminal32Memop { rs, rn, rt }
            | Self::LduminLduminl32Memop { rs, rn, rt } => (A64AtomicOp::Umin, 4, rs, rt, rn),
            Self::LduminLdumin64Memop { rs, rn, rt }
            | Self::LduminLdumina64Memop { rs, rn, rt }
            | Self::LduminLduminal64Memop { rs, rn, rt }
            | Self::LduminLduminl64Memop { rs, rn, rt } => (A64AtomicOp::Umin, 8, rs, rt, rn),
            Self::LduminbLduminb32Memop { rs, rn, rt }
            | Self::LduminbLduminab32Memop { rs, rn, rt }
            | Self::LduminbLduminalb32Memop { rs, rn, rt }
            | Self::LduminbLduminlb32Memop { rs, rn, rt } => (A64AtomicOp::Umin, 1, rs, rt, rn),
            Self::LduminhLduminh32Memop { rs, rn, rt }
            | Self::LduminhLduminah32Memop { rs, rn, rt }
            | Self::LduminhLduminalh32Memop { rs, rn, rt }
            | Self::LduminhLduminlh32Memop { rs, rn, rt } => (A64AtomicOp::Umin, 2, rs, rt, rn),
            Self::SwpSwp32Memop { rs, rn, rt }
            | Self::SwpSwpa32Memop { rs, rn, rt }
            | Self::SwpSwpal32Memop { rs, rn, rt }
            | Self::SwpSwpl32Memop { rs, rn, rt } => (A64AtomicOp::Swp, 4, rs, rt, rn),
            Self::SwpSwp64Memop { rs, rn, rt }
            | Self::SwpSwpa64Memop { rs, rn, rt }
            | Self::SwpSwpal64Memop { rs, rn, rt }
            | Self::SwpSwpl64Memop { rs, rn, rt } => (A64AtomicOp::Swp, 8, rs, rt, rn),
            Self::SwpbSwpb32Memop { rs, rn, rt }
            | Self::SwpbSwpab32Memop { rs, rn, rt }
            | Self::SwpbSwpalb32Memop { rs, rn, rt }
            | Self::SwpbSwplb32Memop { rs, rn, rt } => (A64AtomicOp::Swp, 1, rs, rt, rn),
            Self::SwphSwph32Memop { rs, rn, rt }
            | Self::SwphSwpah32Memop { rs, rn, rt }
            | Self::SwphSwpalh32Memop { rs, rn, rt }
            | Self::SwphSwplh32Memop { rs, rn, rt } => (A64AtomicOp::Swp, 2, rs, rt, rn),
            Self::CasCasC32Comswap { rs, rn, rt }
            | Self::CasCasaC32Comswap { rs, rn, rt }
            | Self::CasCasalC32Comswap { rs, rn, rt }
            | Self::CasCaslC32Comswap { rs, rn, rt } => (A64AtomicOp::Cas, 4, rs, rt, rn),
            Self::CasCasC64Comswap { rs, rn, rt }
            | Self::CasCasaC64Comswap { rs, rn, rt }
            | Self::CasCasalC64Comswap { rs, rn, rt }
            | Self::CasCaslC64Comswap { rs, rn, rt } => (A64AtomicOp::Cas, 8, rs, rt, rn),
            Self::CasbCasbC32Comswap { rs, rn, rt }
            | Self::CasbCasabC32Comswap { rs, rn, rt }
            | Self::CasbCasalbC32Comswap { rs, rn, rt }
            | Self::CasbCaslbC32Comswap { rs, rn, rt } => (A64AtomicOp::Cas, 1, rs, rt, rn),
            Self::CashCashC32Comswap { rs, rn, rt }
            | Self::CashCasahC32Comswap { rs, rn, rt }
            | Self::CashCasalhC32Comswap { rs, rn, rt }
            | Self::CashCaslhC32Comswap { rs, rn, rt } => (A64AtomicOp::Cas, 2, rs, rt, rn),
            _ => return None,
        };
        Some(A64Atomic {
            op,
            size,
            rs,
            rt,
            rn,
        })
    }

    /// `MSR PAN, #imm` (the only decodable MSR): `Some(PSTATE.PAN after it)`, i.e.
    /// `CRm<0>`. Translator-emitted only (the PAN window); user code containing it
    /// is rejected by reg-virt.
    pub const fn msr_pan(self) -> Option<bool> {
        match self {
            Self::MsrImmMsrSiPstate { crm } => Some(crm & 1 == 1),
            _ => None,
        }
    }

    /// The data address of a literal load (`LDR`/`LDRSW` (literal)): `pc + imm19 * 4`.
    pub fn literal_address(self, pc: u64) -> Option<u64> {
        match self {
            Self::LdrLitGenLdr32Loadlit { imm19, .. }
            | Self::LdrLitGenLdr64Loadlit { imm19, .. }
            | Self::LdrswLitLdrsw64Loadlit { imm19, .. } => {
                Some(pc.wrapping_add_signed(imm19.value()))
            }
            _ => None,
        }
    }

    /// `PRFM` (immediate, literal, register): a prefetch hint. It has no
    /// architectural effect and never raises a data abort, so translation drops it.
    pub const fn is_prefetch(self) -> bool {
        matches!(
            self,
            Self::PrfmImmPrfmPLdstPos { .. }
                | Self::PrfmLitPrfmPLoadlit { .. }
                | Self::PrfmRegPrfmPLdstRegoff { .. }
        )
    }

    /// Whether the generated metadata marks this form as accessing memory.
    pub fn accesses_memory(self) -> bool {
        self.operand_roles().contains(&A64OperandRole::Memory)
    }

    pub fn runtime_exit_reason(self, pc: u64) -> Option<RuntimeExitReason> {
        match self {
            Self::BlBlOnlyBranchImm { imm26 } => Some(RuntimeExitReason::Bl {
                target_pc: pc_relative_target(pc, imm26.raw(), 26),
                resume_pc: pc.wrapping_add(4),
            }),
            Self::BlrBlr64BranchReg { rn } => Some(RuntimeExitReason::Blr {
                target_reg: rn.enc(),
                resume_pc: pc.wrapping_add(4),
            }),
            Self::BrBr64BranchReg { rn } => Some(RuntimeExitReason::Br {
                target_reg: rn.enc(),
            }),
            Self::RetRet64rBranchReg { rn } => Some(RuntimeExitReason::Ret { lr_reg: rn.enc() }),
            Self::SvcSvcExException { imm16 } => Some(RuntimeExitReason::Svc {
                imm16: imm16.raw() as u16,
                resume_pc: pc.wrapping_add(4),
            }),
            _ => None,
        }
    }
}

/// Base update of an A9a SIMD&FP load/store with writeback, applied after its
/// access: `base += amount` (pre/post-index immediate; LD1/ST1 post-index by
/// immediate is the transfer size) or `base += Xm` (LD1/ST1 post-index by register).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum A64FpSimdWriteback {
    Imm(i64),
    Reg(A64Reg),
}

/// An A9a SIMD&FP load/store (LDR/STR (immediate), LDUR/STUR, LDP/STP, LD1/ST1
/// (multiple structures)), split the way a fragment performs it (docs/pipeline.md,
/// "FP/SIMD in fragments (A9)"): the address `base + offset`, then `access` -- the same access in
/// its base-only encoding (unsigned-offset LDR/STR or signed-offset LDP/STP with
/// `#0`, LD1/ST1 without post-index; `Rn` still names `base`) -- then `writeback`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct A64FpSimdMem {
    pub access: A64Insn,
    pub base: A64Reg,
    pub offset: i64,
    pub writeback: Option<A64FpSimdWriteback>,
}

impl A64Insn {
    /// Every A9a SIMD&FP load/store (`A64FpSimdMem`); pinned by a test against the
    /// generated forms (a `Memory` role with a `Vec*` role). Translator and harness
    /// helper; the verifier has its own list (`rules::classify`).
    pub fn fpsimd_mem(self) -> Option<A64FpSimdMem> {
        // The base-only addressing: the base with offset #0 in the base-only
        // form's own offset field (`imm12` of LDR/STR (unsigned offset), `imm7` of
        // LDP/STP (signed offset)), as the decoder builds it.
        fn zero(mem: A64Mem, bits: u8) -> A64Mem {
            A64Mem::offset(mem.base(), A64Imm::unsigned(0, bits))
        }
        fn single(
            access: A64Insn,
            mem: A64Mem,
            offset: i64,
            writeback: Option<A64FpSimdWriteback>,
        ) -> Option<A64FpSimdMem> {
            Some(A64FpSimdMem {
                access,
                base: mem.base(),
                offset,
                writeback,
            })
        }
        fn multiple(
            access: A64Insn,
            base: A64Reg,
            writeback: Option<A64FpSimdWriteback>,
        ) -> Option<A64FpSimdMem> {
            Some(A64FpSimdMem {
                access,
                base,
                offset: 0,
                writeback,
            })
        }
        match self {
            Self::LdrImmFpsimdLdrBLdstPos { rt, mem } => single(
                Self::LdrImmFpsimdLdrBLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                None,
            ),
            Self::LdrImmFpsimdLdrBLdstImmpre { rt, mem } => single(
                Self::LdrImmFpsimdLdrBLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::LdrImmFpsimdLdrBLdstImmpost { rt, mem } => single(
                Self::LdrImmFpsimdLdrBLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                0,
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::LdrImmFpsimdLdrHLdstPos { rt, mem } => single(
                Self::LdrImmFpsimdLdrHLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                None,
            ),
            Self::LdrImmFpsimdLdrHLdstImmpre { rt, mem } => single(
                Self::LdrImmFpsimdLdrHLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::LdrImmFpsimdLdrHLdstImmpost { rt, mem } => single(
                Self::LdrImmFpsimdLdrHLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                0,
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::LdrImmFpsimdLdrSLdstPos { rt, mem } => single(
                Self::LdrImmFpsimdLdrSLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                None,
            ),
            Self::LdrImmFpsimdLdrSLdstImmpre { rt, mem } => single(
                Self::LdrImmFpsimdLdrSLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::LdrImmFpsimdLdrSLdstImmpost { rt, mem } => single(
                Self::LdrImmFpsimdLdrSLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                0,
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::LdrImmFpsimdLdrDLdstPos { rt, mem } => single(
                Self::LdrImmFpsimdLdrDLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                None,
            ),
            Self::LdrImmFpsimdLdrDLdstImmpre { rt, mem } => single(
                Self::LdrImmFpsimdLdrDLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::LdrImmFpsimdLdrDLdstImmpost { rt, mem } => single(
                Self::LdrImmFpsimdLdrDLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                0,
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::LdrImmFpsimdLdrQLdstPos { rt, mem } => single(
                Self::LdrImmFpsimdLdrQLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                None,
            ),
            Self::LdrImmFpsimdLdrQLdstImmpre { rt, mem } => single(
                Self::LdrImmFpsimdLdrQLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::LdrImmFpsimdLdrQLdstImmpost { rt, mem } => single(
                Self::LdrImmFpsimdLdrQLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                0,
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::StrImmFpsimdStrBLdstPos { rt, mem } => single(
                Self::StrImmFpsimdStrBLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                None,
            ),
            Self::StrImmFpsimdStrBLdstImmpre { rt, mem } => single(
                Self::StrImmFpsimdStrBLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::StrImmFpsimdStrBLdstImmpost { rt, mem } => single(
                Self::StrImmFpsimdStrBLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                0,
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::StrImmFpsimdStrHLdstPos { rt, mem } => single(
                Self::StrImmFpsimdStrHLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                None,
            ),
            Self::StrImmFpsimdStrHLdstImmpre { rt, mem } => single(
                Self::StrImmFpsimdStrHLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::StrImmFpsimdStrHLdstImmpost { rt, mem } => single(
                Self::StrImmFpsimdStrHLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                0,
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::StrImmFpsimdStrSLdstPos { rt, mem } => single(
                Self::StrImmFpsimdStrSLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                None,
            ),
            Self::StrImmFpsimdStrSLdstImmpre { rt, mem } => single(
                Self::StrImmFpsimdStrSLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::StrImmFpsimdStrSLdstImmpost { rt, mem } => single(
                Self::StrImmFpsimdStrSLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                0,
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::StrImmFpsimdStrDLdstPos { rt, mem } => single(
                Self::StrImmFpsimdStrDLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                None,
            ),
            Self::StrImmFpsimdStrDLdstImmpre { rt, mem } => single(
                Self::StrImmFpsimdStrDLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::StrImmFpsimdStrDLdstImmpost { rt, mem } => single(
                Self::StrImmFpsimdStrDLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                0,
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::StrImmFpsimdStrQLdstPos { rt, mem } => single(
                Self::StrImmFpsimdStrQLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                None,
            ),
            Self::StrImmFpsimdStrQLdstImmpre { rt, mem } => single(
                Self::StrImmFpsimdStrQLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::StrImmFpsimdStrQLdstImmpost { rt, mem } => single(
                Self::StrImmFpsimdStrQLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                0,
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::LdurFpsimdLdurBLdstUnscaled { rt, mem } => single(
                Self::LdrImmFpsimdLdrBLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                None,
            ),
            Self::LdurFpsimdLdurHLdstUnscaled { rt, mem } => single(
                Self::LdrImmFpsimdLdrHLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                None,
            ),
            Self::LdurFpsimdLdurSLdstUnscaled { rt, mem } => single(
                Self::LdrImmFpsimdLdrSLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                None,
            ),
            Self::LdurFpsimdLdurDLdstUnscaled { rt, mem } => single(
                Self::LdrImmFpsimdLdrDLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                None,
            ),
            Self::LdurFpsimdLdurQLdstUnscaled { rt, mem } => single(
                Self::LdrImmFpsimdLdrQLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                None,
            ),
            Self::SturFpsimdSturBLdstUnscaled { rt, mem } => single(
                Self::StrImmFpsimdStrBLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                None,
            ),
            Self::SturFpsimdSturHLdstUnscaled { rt, mem } => single(
                Self::StrImmFpsimdStrHLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                None,
            ),
            Self::SturFpsimdSturSLdstUnscaled { rt, mem } => single(
                Self::StrImmFpsimdStrSLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                None,
            ),
            Self::SturFpsimdSturDLdstUnscaled { rt, mem } => single(
                Self::StrImmFpsimdStrDLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                None,
            ),
            Self::SturFpsimdSturQLdstUnscaled { rt, mem } => single(
                Self::StrImmFpsimdStrQLdstPos {
                    rt,
                    mem: zero(mem, 12),
                },
                mem,
                mem.offset_imm().value(),
                None,
            ),
            Self::LdpFpsimdLdpSLdstpairOff { rt2, rt, mem } => single(
                Self::LdpFpsimdLdpSLdstpairOff {
                    rt2,
                    rt,
                    mem: zero(mem, 7),
                },
                mem,
                mem.offset_imm().value(),
                None,
            ),
            Self::LdpFpsimdLdpSLdstpairPre { rt2, rt, mem } => single(
                Self::LdpFpsimdLdpSLdstpairOff {
                    rt2,
                    rt,
                    mem: zero(mem, 7),
                },
                mem,
                mem.offset_imm().value(),
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::LdpFpsimdLdpSLdstpairPost { rt2, rt, mem } => single(
                Self::LdpFpsimdLdpSLdstpairOff {
                    rt2,
                    rt,
                    mem: zero(mem, 7),
                },
                mem,
                0,
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::LdpFpsimdLdpDLdstpairOff { rt2, rt, mem } => single(
                Self::LdpFpsimdLdpDLdstpairOff {
                    rt2,
                    rt,
                    mem: zero(mem, 7),
                },
                mem,
                mem.offset_imm().value(),
                None,
            ),
            Self::LdpFpsimdLdpDLdstpairPre { rt2, rt, mem } => single(
                Self::LdpFpsimdLdpDLdstpairOff {
                    rt2,
                    rt,
                    mem: zero(mem, 7),
                },
                mem,
                mem.offset_imm().value(),
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::LdpFpsimdLdpDLdstpairPost { rt2, rt, mem } => single(
                Self::LdpFpsimdLdpDLdstpairOff {
                    rt2,
                    rt,
                    mem: zero(mem, 7),
                },
                mem,
                0,
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::LdpFpsimdLdpQLdstpairOff { rt2, rt, mem } => single(
                Self::LdpFpsimdLdpQLdstpairOff {
                    rt2,
                    rt,
                    mem: zero(mem, 7),
                },
                mem,
                mem.offset_imm().value(),
                None,
            ),
            Self::LdpFpsimdLdpQLdstpairPre { rt2, rt, mem } => single(
                Self::LdpFpsimdLdpQLdstpairOff {
                    rt2,
                    rt,
                    mem: zero(mem, 7),
                },
                mem,
                mem.offset_imm().value(),
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::LdpFpsimdLdpQLdstpairPost { rt2, rt, mem } => single(
                Self::LdpFpsimdLdpQLdstpairOff {
                    rt2,
                    rt,
                    mem: zero(mem, 7),
                },
                mem,
                0,
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::StpFpsimdStpSLdstpairOff { rt2, rt, mem } => single(
                Self::StpFpsimdStpSLdstpairOff {
                    rt2,
                    rt,
                    mem: zero(mem, 7),
                },
                mem,
                mem.offset_imm().value(),
                None,
            ),
            Self::StpFpsimdStpSLdstpairPre { rt2, rt, mem } => single(
                Self::StpFpsimdStpSLdstpairOff {
                    rt2,
                    rt,
                    mem: zero(mem, 7),
                },
                mem,
                mem.offset_imm().value(),
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::StpFpsimdStpSLdstpairPost { rt2, rt, mem } => single(
                Self::StpFpsimdStpSLdstpairOff {
                    rt2,
                    rt,
                    mem: zero(mem, 7),
                },
                mem,
                0,
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::StpFpsimdStpDLdstpairOff { rt2, rt, mem } => single(
                Self::StpFpsimdStpDLdstpairOff {
                    rt2,
                    rt,
                    mem: zero(mem, 7),
                },
                mem,
                mem.offset_imm().value(),
                None,
            ),
            Self::StpFpsimdStpDLdstpairPre { rt2, rt, mem } => single(
                Self::StpFpsimdStpDLdstpairOff {
                    rt2,
                    rt,
                    mem: zero(mem, 7),
                },
                mem,
                mem.offset_imm().value(),
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::StpFpsimdStpDLdstpairPost { rt2, rt, mem } => single(
                Self::StpFpsimdStpDLdstpairOff {
                    rt2,
                    rt,
                    mem: zero(mem, 7),
                },
                mem,
                0,
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::StpFpsimdStpQLdstpairOff { rt2, rt, mem } => single(
                Self::StpFpsimdStpQLdstpairOff {
                    rt2,
                    rt,
                    mem: zero(mem, 7),
                },
                mem,
                mem.offset_imm().value(),
                None,
            ),
            Self::StpFpsimdStpQLdstpairPre { rt2, rt, mem } => single(
                Self::StpFpsimdStpQLdstpairOff {
                    rt2,
                    rt,
                    mem: zero(mem, 7),
                },
                mem,
                mem.offset_imm().value(),
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::StpFpsimdStpQLdstpairPost { rt2, rt, mem } => single(
                Self::StpFpsimdStpQLdstpairOff {
                    rt2,
                    rt,
                    mem: zero(mem, 7),
                },
                mem,
                0,
                Some(A64FpSimdWriteback::Imm(mem.offset_imm().value())),
            ),
            Self::Ld1AdvsimdMultLd1AsisdlseR11v { q, size, rn, rt } => multiple(
                Self::Ld1AdvsimdMultLd1AsisdlseR11v { q, size, rn, rt },
                rn,
                None,
            ),
            Self::Ld1AdvsimdMultLd1AsisdlsepI1I1 { q, size, rn, rt } => multiple(
                Self::Ld1AdvsimdMultLd1AsisdlseR11v { q, size, rn, rt },
                rn,
                Some(A64FpSimdWriteback::Imm(1 * (8_i64 << q))),
            ),
            Self::Ld1AdvsimdMultLd1AsisdlsepR1R1 {
                q,
                rm,
                size,
                rn,
                rt,
            } => multiple(
                Self::Ld1AdvsimdMultLd1AsisdlseR11v { q, size, rn, rt },
                rn,
                Some(A64FpSimdWriteback::Reg(rm)),
            ),
            Self::Ld1AdvsimdMultLd1AsisdlseR22v { q, size, rn, rt } => multiple(
                Self::Ld1AdvsimdMultLd1AsisdlseR22v { q, size, rn, rt },
                rn,
                None,
            ),
            Self::Ld1AdvsimdMultLd1AsisdlsepI2I2 { q, size, rn, rt } => multiple(
                Self::Ld1AdvsimdMultLd1AsisdlseR22v { q, size, rn, rt },
                rn,
                Some(A64FpSimdWriteback::Imm(2 * (8_i64 << q))),
            ),
            Self::Ld1AdvsimdMultLd1AsisdlsepR2R2 {
                q,
                rm,
                size,
                rn,
                rt,
            } => multiple(
                Self::Ld1AdvsimdMultLd1AsisdlseR22v { q, size, rn, rt },
                rn,
                Some(A64FpSimdWriteback::Reg(rm)),
            ),
            Self::Ld1AdvsimdMultLd1AsisdlseR33v { q, size, rn, rt } => multiple(
                Self::Ld1AdvsimdMultLd1AsisdlseR33v { q, size, rn, rt },
                rn,
                None,
            ),
            Self::Ld1AdvsimdMultLd1AsisdlsepI3I3 { q, size, rn, rt } => multiple(
                Self::Ld1AdvsimdMultLd1AsisdlseR33v { q, size, rn, rt },
                rn,
                Some(A64FpSimdWriteback::Imm(3 * (8_i64 << q))),
            ),
            Self::Ld1AdvsimdMultLd1AsisdlsepR3R3 {
                q,
                rm,
                size,
                rn,
                rt,
            } => multiple(
                Self::Ld1AdvsimdMultLd1AsisdlseR33v { q, size, rn, rt },
                rn,
                Some(A64FpSimdWriteback::Reg(rm)),
            ),
            Self::Ld1AdvsimdMultLd1AsisdlseR44v { q, size, rn, rt } => multiple(
                Self::Ld1AdvsimdMultLd1AsisdlseR44v { q, size, rn, rt },
                rn,
                None,
            ),
            Self::Ld1AdvsimdMultLd1AsisdlsepI4I4 { q, size, rn, rt } => multiple(
                Self::Ld1AdvsimdMultLd1AsisdlseR44v { q, size, rn, rt },
                rn,
                Some(A64FpSimdWriteback::Imm(4 * (8_i64 << q))),
            ),
            Self::Ld1AdvsimdMultLd1AsisdlsepR4R4 {
                q,
                rm,
                size,
                rn,
                rt,
            } => multiple(
                Self::Ld1AdvsimdMultLd1AsisdlseR44v { q, size, rn, rt },
                rn,
                Some(A64FpSimdWriteback::Reg(rm)),
            ),
            Self::St1AdvsimdMultSt1AsisdlseR11v { q, size, rn, rt } => multiple(
                Self::St1AdvsimdMultSt1AsisdlseR11v { q, size, rn, rt },
                rn,
                None,
            ),
            Self::St1AdvsimdMultSt1AsisdlsepI1I1 { q, size, rn, rt } => multiple(
                Self::St1AdvsimdMultSt1AsisdlseR11v { q, size, rn, rt },
                rn,
                Some(A64FpSimdWriteback::Imm(1 * (8_i64 << q))),
            ),
            Self::St1AdvsimdMultSt1AsisdlsepR1R1 {
                q,
                rm,
                size,
                rn,
                rt,
            } => multiple(
                Self::St1AdvsimdMultSt1AsisdlseR11v { q, size, rn, rt },
                rn,
                Some(A64FpSimdWriteback::Reg(rm)),
            ),
            Self::St1AdvsimdMultSt1AsisdlseR22v { q, size, rn, rt } => multiple(
                Self::St1AdvsimdMultSt1AsisdlseR22v { q, size, rn, rt },
                rn,
                None,
            ),
            Self::St1AdvsimdMultSt1AsisdlsepI2I2 { q, size, rn, rt } => multiple(
                Self::St1AdvsimdMultSt1AsisdlseR22v { q, size, rn, rt },
                rn,
                Some(A64FpSimdWriteback::Imm(2 * (8_i64 << q))),
            ),
            Self::St1AdvsimdMultSt1AsisdlsepR2R2 {
                q,
                rm,
                size,
                rn,
                rt,
            } => multiple(
                Self::St1AdvsimdMultSt1AsisdlseR22v { q, size, rn, rt },
                rn,
                Some(A64FpSimdWriteback::Reg(rm)),
            ),
            Self::St1AdvsimdMultSt1AsisdlseR33v { q, size, rn, rt } => multiple(
                Self::St1AdvsimdMultSt1AsisdlseR33v { q, size, rn, rt },
                rn,
                None,
            ),
            Self::St1AdvsimdMultSt1AsisdlsepI3I3 { q, size, rn, rt } => multiple(
                Self::St1AdvsimdMultSt1AsisdlseR33v { q, size, rn, rt },
                rn,
                Some(A64FpSimdWriteback::Imm(3 * (8_i64 << q))),
            ),
            Self::St1AdvsimdMultSt1AsisdlsepR3R3 {
                q,
                rm,
                size,
                rn,
                rt,
            } => multiple(
                Self::St1AdvsimdMultSt1AsisdlseR33v { q, size, rn, rt },
                rn,
                Some(A64FpSimdWriteback::Reg(rm)),
            ),
            Self::St1AdvsimdMultSt1AsisdlseR44v { q, size, rn, rt } => multiple(
                Self::St1AdvsimdMultSt1AsisdlseR44v { q, size, rn, rt },
                rn,
                None,
            ),
            Self::St1AdvsimdMultSt1AsisdlsepI4I4 { q, size, rn, rt } => multiple(
                Self::St1AdvsimdMultSt1AsisdlseR44v { q, size, rn, rt },
                rn,
                Some(A64FpSimdWriteback::Imm(4 * (8_i64 << q))),
            ),
            Self::St1AdvsimdMultSt1AsisdlsepR4R4 {
                q,
                rm,
                size,
                rn,
                rt,
            } => multiple(
                Self::St1AdvsimdMultSt1AsisdlseR44v { q, size, rn, rt },
                rn,
                Some(A64FpSimdWriteback::Reg(rm)),
            ),
            _ => None,
        }
    }

    /// The raw value of encoding field `name` (e.g. a SIMD&FP register number, which
    /// has no `A64Reg` accessor), read back through the generated field table.
    pub fn field_value(self, name: &str) -> Option<u32> {
        let word = self.encode().ok()?;
        GENERATED_A64_SUBSET
            .iter()
            .find(|spec| spec.key == self.key())?
            .extract_field(word, name)
    }

    /// The instruction a fragment's PAN window may hold (A8, A9a): an LSE atomic, or
    /// an A9a SIMD&FP load/store in its base-only encoding (`A64FpSimdMem::access`
    /// of itself, no offset, no writeback). Translator side (layout's tag check);
    /// the verifier decides this on its own.
    pub fn is_pan_window_access(self) -> bool {
        self.lse_atomic().is_some()
            || self
                .fpsimd_mem()
                .is_some_and(|mem| mem.access == self && mem.offset == 0 && mem.writeback.is_none())
    }
}

/// A word of `spec`'s form: its fixed bits, each `!=` exclusion it would hit
/// escaped by setting the lowest free bit that exclusion covers (A9a: SHRN/USHR/
/// SHL/USHLL's `immh != 0000`). Every other field is zero.
pub fn form_base_word(spec: &GeneratedInsnSpec) -> u32 {
    let mut word = spec.value;
    for &(mask, value) in spec.excludes {
        if word & mask == value {
            let free = mask & !spec.mask;
            word |= free & free.wrapping_neg();
        }
    }
    word
}

pub fn decode_word(word: u32, pc: u64) -> Result<IrInsn, DecodeError> {
    let inner = A64Insn::decode(word)
        .filter(|insn| !insn.is_decode_undefined())
        .ok_or(DecodeError::UnsupportedWord { pc, word })?;
    Ok(IrInsn { pc, word, inner })
}

impl A64Insn {
    /// `true` when the word matches the form's encoding diagram but the form's
    /// decode pseudocode makes it UNDEFINED (`EndOfDecode(Decode_UNDEF)`, or
    /// `DecodeBitMasks` rejecting a logical immediate). The generated mask/value
    /// cannot express these value rules. Such a word must stay undecodable: it takes
    /// the Unsupported exit and userspace gets its SIGILL natively, instead of the
    /// fragment raising an undefined-instruction exception at EL1.
    ///
    /// Exhaustive on purpose: a new form must decide here whether it has such rules.
    pub const fn is_decode_undefined(self) -> bool {
        match self {
            Self::AddAddsubShiftAdd32AddsubShift { shift, imm6, .. }
            | Self::AddsAddsubShiftAdds32AddsubShift { shift, imm6, .. }
            | Self::SubAddsubShiftSub32AddsubShift { shift, imm6, .. }
            | Self::SubsAddsubShiftSubs32AddsubShift { shift, imm6, .. } => {
                shift == 0b11 || imm6.raw() & 0b10_0000 != 0
            }
            Self::AddAddsubShiftAdd64AddsubShift { shift, .. }
            | Self::AddsAddsubShiftAdds64AddsubShift { shift, .. }
            | Self::SubAddsubShiftSub64AddsubShift { shift, .. }
            | Self::SubsAddsubShiftSubs64AddsubShift { shift, .. } => shift == 0b11,

            Self::AddAddsubExtAdd32AddsubExt { imm3, .. }
            | Self::AddAddsubExtAdd64AddsubExt { imm3, .. }
            | Self::AddsAddsubExtAdds32sAddsubExt { imm3, .. }
            | Self::AddsAddsubExtAdds64sAddsubExt { imm3, .. }
            | Self::SubAddsubExtSub32AddsubExt { imm3, .. }
            | Self::SubAddsubExtSub64AddsubExt { imm3, .. }
            | Self::SubsAddsubExtSubs32sAddsubExt { imm3, .. }
            | Self::SubsAddsubExtSubs64sAddsubExt { imm3, .. } => imm3.raw() > 4,

            Self::AndLogShiftAnd32LogShift { imm6, .. }
            | Self::AndsLogShiftAnds32LogShift { imm6, .. }
            | Self::OrrLogShiftOrr32LogShift { imm6, .. }
            | Self::EorLogShiftEor32LogShift { imm6, .. }
            | Self::EonEon32LogShift { imm6, .. }
            | Self::BicLogShiftBic32LogShift { imm6, .. }
            | Self::BicsBics32LogShift { imm6, .. }
            | Self::OrnLogShiftOrn32LogShift { imm6, .. } => imm6.raw() & 0b10_0000 != 0,

            Self::AndLogImmAnd32LogImm { imms, .. }
            | Self::AndsLogImmAnds32sLogImm { imms, .. }
            | Self::OrrLogImmOrr32LogImm { imms, .. }
            | Self::EorLogImmEor32LogImm { imms, .. } => logical_imm_undefined(0, imms),
            Self::AndLogImmAnd64LogImm { n, imms, .. }
            | Self::AndsLogImmAnds64sLogImm { n, imms, .. }
            | Self::OrrLogImmOrr64LogImm { n, imms, .. }
            | Self::EorLogImmEor64LogImm { n, imms, .. } => logical_imm_undefined(n, imms),

            // The 32-bit encodings fix N = 0; immr/imms bit 5 must also be clear.
            Self::SbfmSbfm32mBitfield { immr, imms, .. }
            | Self::UbfmUbfm32mBitfield { immr, imms, .. }
            | Self::BfmBfm32mBitfield { immr, imms, .. } => {
                (immr.raw() | imms.raw()) & 0b10_0000 != 0
            }

            // Register-offset loads/stores: `if option<1> == '0' then
            // EndOfDecode(Decode_UNDEF)` (a sub-word index). The `*BL` byte forms
            // (option = 0b011) and PRFM (register) (option<1> = 1) fix it in their
            // diagrams.
            Self::LdrRegGenLdr32LdstRegoff { option, .. }
            | Self::LdrRegGenLdr64LdstRegoff { option, .. }
            | Self::StrRegGenStr32LdstRegoff { option, .. }
            | Self::StrRegGenStr64LdstRegoff { option, .. }
            | Self::LdrbRegLdrb32bLdstRegoff { option, .. }
            | Self::StrbRegStrb32bLdstRegoff { option, .. }
            | Self::LdrhRegLdrh32LdstRegoff { option, .. }
            | Self::StrhRegStrh32LdstRegoff { option, .. }
            | Self::LdrsbRegLdrsb32bLdstRegoff { option, .. }
            | Self::LdrsbRegLdrsb64bLdstRegoff { option, .. }
            | Self::LdrshRegLdrsh32LdstRegoff { option, .. }
            | Self::LdrshRegLdrsh64LdstRegoff { option, .. }
            | Self::LdrswRegLdrsw64LdstRegoff { option, .. } => option & 0b010 == 0,

            // A9a SIMD&FP (docs/pipeline.md, "FP/SIMD in fragments (A9)"): the value rules of each
            // form's decode pseudocode that its diagram does not fix.
            // DUP/INS/UMOV: `imm5 == 'x0000'` (no element size); DUP (vector) and
            // UMOV (32-bit) also reject a 64-bit element they cannot hold.
            Self::DupAdvsimdEltDupAsisdoneOnly { imm5, .. }
            | Self::InsAdvsimdEltInsAsimdinsIvV { imm5, .. }
            | Self::InsAdvsimdGenInsAsimdinsIrR { imm5, .. } => imm5.raw() & 0b1111 == 0,
            Self::DupAdvsimdEltDupAsimdinsDvV { q, imm5, .. }
            | Self::DupAdvsimdGenDupAsimdinsDrR { q, imm5, .. } => {
                imm5.raw() & 0b1111 == 0 || (imm5.raw() & 0b1111 == 0b1000 && q == 0)
            }
            // `datasize == 32 && esize >= 64`.
            Self::UmovAdvsimdUmovAsimdinsWW { imm5, .. } => {
                matches!(imm5.raw() & 0b1111, 0 | 0b1000)
            }
            // `size:Q == '110'` (a 64-bit vector of 64-bit elements is `1D`, reserved).
            Self::CmeqAdvsimdRegCmeqAsimdsameOnly { q, size, .. }
            | Self::CmeqAdvsimdZeroCmeqAsimdmiscZ { q, size, .. }
            | Self::CmhiAdvsimdCmhiAsimdsameOnly { q, size, .. }
            | Self::CmhsAdvsimdCmhsAsimdsameOnly { q, size, .. }
            | Self::CmgtAdvsimdRegCmgtAsimdsameOnly { q, size, .. }
            | Self::CmgtAdvsimdZeroCmgtAsimdmiscZ { q, size, .. }
            | Self::CmgeAdvsimdRegCmgeAsimdsameOnly { q, size, .. }
            | Self::CmgeAdvsimdZeroCmgeAsimdmiscZ { q, size, .. }
            | Self::CmtstAdvsimdCmtstAsimdsameOnly { q, size, .. }
            | Self::AddAdvsimdAddAsimdsameOnly { q, size, .. }
            | Self::SubAdvsimdSubAsimdsameOnly { q, size, .. }
            | Self::AddpAdvsimdVecAddpAsimdsameOnly { q, size, .. } => size == 0b11 && q == 0,
            // UMAXP/UMINP, XTN: `size == '11'`.
            Self::UmaxpAdvsimdUmaxpAsimdsameOnly { size, .. }
            | Self::UminpAdvsimdUminpAsimdsameOnly { size, .. }
            | Self::XtnAdvsimdXtnAsimdmiscN { size, .. } => size == 0b11,
            // Across-lanes: `size:Q == '100'` or `size == '11'`.
            Self::AddvAdvsimdAddvAsimdallOnly { q, size, .. }
            | Self::UmaxvAdvsimdUmaxvAsimdallOnly { q, size, .. }
            | Self::UminvAdvsimdUminvAsimdallOnly { q, size, .. } => {
                size == 0b11 || (size == 0b10 && q == 0)
            }
            // Narrowing/lengthening shifts: `immh<3> == '1'` (the diagram excludes
            // `immh == 0000`, which is the modified-immediate class).
            Self::ShrnAdvsimdShrnAsimdshfN { immh, .. }
            | Self::UshllAdvsimdUshllAsimdshfL { immh, .. } => immh.raw() & 0b1000 != 0,
            // Vector shifts by immediate: `immh<3>:Q == '10'`.
            Self::UshrAdvsimdUshrAsimdshfR { q, immh, .. }
            | Self::ShlAdvsimdShlAsimdshfR { q, immh, .. } => immh.raw() & 0b1000 != 0 && q == 0,
            // EXT: `Q == '0' && imm4<3> == '1'` (index past a 64-bit vector).
            Self::ExtAdvsimdExtAsimdextOnly { q, imm4, .. } => q == 0 && imm4.raw() & 0b1000 != 0,
            // REV16/32/64: `csize <= esize`.
            Self::Rev16AdvsimdRev16AsimdmiscR { size, .. } => size != 0,
            Self::Rev32AdvsimdRev32AsimdmiscR { size, .. } => size >= 0b10,
            Self::Rev64AdvsimdRev64AsimdmiscR { size, .. } => size == 0b11,
            // CNT: `size != '00'`.
            Self::CntAdvsimdCntAsimdmiscR { size, .. } => size != 0,
            // Every remaining rule of these forms is fixed by the encoding diagram
            // (MOVZ/MOVK/MOVN 32-bit hw<1>, bitfield/EXTR N == sf, EXTR 32-bit
            // imms<5>, REV opc), or the form has no decode-time UNDEFINED case.
            Self::AdrAdrOnlyPcreladdr { .. }
            | Self::AdrpAdrpOnlyPcreladdr { .. }
            | Self::AddAddsubImmAdd32AddsubImm { .. }
            | Self::AddAddsubImmAdd64AddsubImm { .. }
            | Self::SubAddsubImmSub32AddsubImm { .. }
            | Self::SubAddsubImmSub64AddsubImm { .. }
            | Self::SubsAddsubImmSubs32sAddsubImm { .. }
            | Self::SubsAddsubImmSubs64sAddsubImm { .. }
            | Self::AddsAddsubImmAdds32sAddsubImm { .. }
            | Self::AddsAddsubImmAdds64sAddsubImm { .. }
            | Self::BUncondBOnlyBranchImm { .. }
            | Self::BCondBOnlyCondbranch { .. }
            | Self::CbzCbz32Compbranch { .. }
            | Self::CbzCbz64Compbranch { .. }
            | Self::CbnzCbnz32Compbranch { .. }
            | Self::CbnzCbnz64Compbranch { .. }
            | Self::MovzMovz32Movewide { .. }
            | Self::MovzMovz64Movewide { .. }
            | Self::MovkMovk32Movewide { .. }
            | Self::MovkMovk64Movewide { .. }
            | Self::MovnMovn32Movewide { .. }
            | Self::MovnMovn64Movewide { .. }
            | Self::AndLogShiftAnd64LogShift { .. }
            | Self::AndsLogShiftAnds64LogShift { .. }
            | Self::OrrLogShiftOrr64LogShift { .. }
            | Self::EorLogShiftEor64LogShift { .. }
            | Self::EonEon64LogShift { .. }
            | Self::BicLogShiftBic64LogShift { .. }
            | Self::BicsBics64LogShift { .. }
            | Self::OrnLogShiftOrn64LogShift { .. }
            | Self::SbfmSbfm64mBitfield { .. }
            | Self::UbfmUbfm64mBitfield { .. }
            | Self::BfmBfm64mBitfield { .. }
            | Self::ExtrExtr32Extract { .. }
            | Self::ExtrExtr64Extract { .. }
            | Self::CselCsel32Condsel { .. }
            | Self::CselCsel64Condsel { .. }
            | Self::CsincCsinc32Condsel { .. }
            | Self::CsincCsinc64Condsel { .. }
            | Self::CsinvCsinv32Condsel { .. }
            | Self::CsinvCsinv64Condsel { .. }
            | Self::CsnegCsneg32Condsel { .. }
            | Self::CsnegCsneg64Condsel { .. }
            | Self::CcmpImmCcmp32CondcmpImm { .. }
            | Self::CcmpImmCcmp64CondcmpImm { .. }
            | Self::CcmpRegCcmp32CondcmpReg { .. }
            | Self::CcmpRegCcmp64CondcmpReg { .. }
            | Self::CcmnImmCcmn32CondcmpImm { .. }
            | Self::CcmnImmCcmn64CondcmpImm { .. }
            | Self::CcmnRegCcmn32CondcmpReg { .. }
            | Self::CcmnRegCcmn64CondcmpReg { .. }
            | Self::LslvLslv32Dp2src { .. }
            | Self::LslvLslv64Dp2src { .. }
            | Self::LsrvLsrv32Dp2src { .. }
            | Self::LsrvLsrv64Dp2src { .. }
            | Self::AsrvAsrv32Dp2src { .. }
            | Self::AsrvAsrv64Dp2src { .. }
            | Self::RorvRorv32Dp2src { .. }
            | Self::RorvRorv64Dp2src { .. }
            | Self::UdivUdiv32Dp2src { .. }
            | Self::UdivUdiv64Dp2src { .. }
            | Self::SdivSdiv32Dp2src { .. }
            | Self::SdivSdiv64Dp2src { .. }
            | Self::MaddMadd32aDp3src { .. }
            | Self::MaddMadd64aDp3src { .. }
            | Self::MsubMsub32aDp3src { .. }
            | Self::MsubMsub64aDp3src { .. }
            | Self::SmaddlSmaddl64waDp3src { .. }
            | Self::UmaddlUmaddl64waDp3src { .. }
            | Self::SmulhSmulh64Dp3src { .. }
            | Self::UmulhUmulh64Dp3src { .. }
            | Self::ClzIntClz32Dp1src { .. }
            | Self::ClzIntClz64Dp1src { .. }
            | Self::RbitIntRbit32Dp1src { .. }
            | Self::RbitIntRbit64Dp1src { .. }
            | Self::RevRev32Dp1src { .. }
            | Self::RevRev64Dp1src { .. }
            | Self::Rev16IntRev1632Dp1src { .. }
            | Self::Rev16IntRev1664Dp1src { .. }
            | Self::Rev32IntRev3264Dp1src { .. }
            | Self::MrsMrsRsSystemmoveTpidrEl0 { .. }
            | Self::MrsMrsRsSystemmoveCntvctEl0 { .. }
            | Self::MrsMrsRsSystemmoveCntfrqEl0 { .. }
            | Self::TbzTbzOnlyTestbranch { .. }
            | Self::TbnzTbnzOnlyTestbranch { .. }
            | Self::LdrImmGenLdr32LdstImmpost { .. }
            | Self::LdrImmGenLdr64LdstImmpost { .. }
            | Self::LdrImmGenLdr32LdstImmpre { .. }
            | Self::LdrImmGenLdr64LdstImmpre { .. }
            | Self::LdrImmGenLdr32LdstPos { .. }
            | Self::LdrImmGenLdr64LdstPos { .. }
            | Self::StrImmGenStr32LdstImmpost { .. }
            | Self::StrImmGenStr64LdstImmpost { .. }
            | Self::StrImmGenStr32LdstImmpre { .. }
            | Self::StrImmGenStr64LdstImmpre { .. }
            | Self::StrImmGenStr32LdstPos { .. }
            | Self::StrImmGenStr64LdstPos { .. }
            | Self::LdpGenLdp64LdstpairPost { .. }
            | Self::LdpGenLdp64LdstpairPre { .. }
            | Self::LdpGenLdp64LdstpairOff { .. }
            | Self::StpGenStp64LdstpairPost { .. }
            | Self::StpGenStp64LdstpairPre { .. }
            | Self::StpGenStp64LdstpairOff { .. }
            // Memory forms added in A7b. Their decode pseudocode has no UNDEFINED
            // case outside the register-offset rule above; the writeback and LDP
            // `t == t2` overlaps are CONSTRAINED UNPREDICTABLE, which reg-virt rejects
            // from the operand roles (`UnpredictableMemoryOp`).
            | Self::LdpGenLdp32LdstpairPost { .. }
            | Self::LdpGenLdp32LdstpairPre { .. }
            | Self::LdpGenLdp32LdstpairOff { .. }
            | Self::StpGenStp32LdstpairPost { .. }
            | Self::StpGenStp32LdstpairPre { .. }
            | Self::StpGenStp32LdstpairOff { .. }
            | Self::LdpswLdpsw64LdstpairPost { .. }
            | Self::LdpswLdpsw64LdstpairPre { .. }
            | Self::LdpswLdpsw64LdstpairOff { .. }
            | Self::LdrbImmLdrb32LdstImmpost { .. }
            | Self::LdrbImmLdrb32LdstImmpre { .. }
            | Self::LdrbImmLdrb32LdstPos { .. }
            | Self::StrbImmStrb32LdstImmpost { .. }
            | Self::StrbImmStrb32LdstImmpre { .. }
            | Self::StrbImmStrb32LdstPos { .. }
            | Self::LdrhImmLdrh32LdstImmpost { .. }
            | Self::LdrhImmLdrh32LdstImmpre { .. }
            | Self::LdrhImmLdrh32LdstPos { .. }
            | Self::StrhImmStrh32LdstImmpost { .. }
            | Self::StrhImmStrh32LdstImmpre { .. }
            | Self::StrhImmStrh32LdstPos { .. }
            | Self::LdrsbImmLdrsb32LdstImmpost { .. }
            | Self::LdrsbImmLdrsb64LdstImmpost { .. }
            | Self::LdrsbImmLdrsb32LdstImmpre { .. }
            | Self::LdrsbImmLdrsb64LdstImmpre { .. }
            | Self::LdrsbImmLdrsb32LdstPos { .. }
            | Self::LdrsbImmLdrsb64LdstPos { .. }
            | Self::LdrshImmLdrsh32LdstImmpost { .. }
            | Self::LdrshImmLdrsh64LdstImmpost { .. }
            | Self::LdrshImmLdrsh32LdstImmpre { .. }
            | Self::LdrshImmLdrsh64LdstImmpre { .. }
            | Self::LdrshImmLdrsh32LdstPos { .. }
            | Self::LdrshImmLdrsh64LdstPos { .. }
            | Self::LdrswImmLdrsw64LdstImmpost { .. }
            | Self::LdrswImmLdrsw64LdstImmpre { .. }
            | Self::LdrswImmLdrsw64LdstPos { .. }
            | Self::LdurGenLdur32LdstUnscaled { .. }
            | Self::LdurGenLdur64LdstUnscaled { .. }
            | Self::SturGenStur32LdstUnscaled { .. }
            | Self::SturGenStur64LdstUnscaled { .. }
            | Self::LdurbLdurb32LdstUnscaled { .. }
            | Self::SturbSturb32LdstUnscaled { .. }
            | Self::LdurhLdurh32LdstUnscaled { .. }
            | Self::SturhSturh32LdstUnscaled { .. }
            | Self::LdursbLdursb32LdstUnscaled { .. }
            | Self::LdursbLdursb64LdstUnscaled { .. }
            | Self::LdurshLdursh32LdstUnscaled { .. }
            | Self::LdurshLdursh64LdstUnscaled { .. }
            | Self::LdurswLdursw64LdstUnscaled { .. }
            | Self::LdrbRegLdrb32blLdstRegoff { .. }
            | Self::StrbRegStrb32blLdstRegoff { .. }
            | Self::LdrsbRegLdrsb32blLdstRegoff { .. }
            | Self::LdrsbRegLdrsb64blLdstRegoff { .. }
            | Self::LdrLitGenLdr32Loadlit { .. }
            | Self::LdrLitGenLdr64Loadlit { .. }
            | Self::LdrswLitLdrsw64Loadlit { .. }
            | Self::PrfmImmPrfmPLdstPos { .. }
            | Self::PrfmLitPrfmPLoadlit { .. }
            | Self::PrfmRegPrfmPLdstRegoff { .. }
            | Self::LdtrbLdtrb32LdstUnpriv { .. }
            | Self::SttrbSttrb32LdstUnpriv { .. }
            | Self::LdtrhLdtrh32LdstUnpriv { .. }
            | Self::SttrhSttrh32LdstUnpriv { .. }
            | Self::LdtrsbLdtrsb32LdstUnpriv { .. }
            | Self::LdtrsbLdtrsb64LdstUnpriv { .. }
            | Self::LdtrshLdtrsh32LdstUnpriv { .. }
            | Self::LdtrshLdtrsh64LdstUnpriv { .. }
            | Self::LdtrswLdtrsw64LdstUnpriv { .. }
            | Self::LdtrLdtr32LdstUnpriv { .. }
            | Self::LdtrLdtr64LdstUnpriv { .. }
            | Self::SttrSttr32LdstUnpriv { .. }
            | Self::SttrSttr64LdstUnpriv { .. }
            // A7c. Barriers: every CRm value decodes (reserved options behave as
            // SY; DSB CRm 0000/0100 are SSBB/PSSBB). Acquire/release: no value rule
            // (their should-be-one Rs/Rt2 are pinned in subset.toml). LDAPR's only
            // UNDEFINED case is a missing FEAT_LRCPC, a CPU property, not an
            // encoding one (docs/pipeline.md, "Barriers and acquire/release (A7c)").
            | Self::DmbDmbBoBarriers { .. }
            | Self::DsbDsbBoBarriers { .. }
            | Self::IsbIsbBiBarriers { .. }
            | Self::LdarLdarLr32Ldstord { .. }
            | Self::LdarLdarLr64Ldstord { .. }
            | Self::LdarbLdarbLr32Ldstord { .. }
            | Self::LdarhLdarhLr32Ldstord { .. }
            | Self::StlrStlrSl32Ldstord { .. }
            | Self::StlrStlrSl64Ldstord { .. }
            | Self::StlrbStlrbSl32Ldstord { .. }
            | Self::StlrhStlrhSl32Ldstord { .. }
            | Self::LdaprLdapr32lMemop { .. }
            | Self::LdaprLdapr64lMemop { .. }
            | Self::LdaprbLdaprb32lMemop { .. }
            | Self::LdaprhLdaprh32lMemop { .. }
            | Self::NopNopHiHints {}
            // A7d. BTI: without FEAT_BTI its decode is `EndOfDecode(Decode_NOP)`,
            // never UNDEFINED; every `op2` (targets none/c/j/jc) decodes (the diagram
            // fixes CRm = 0100 and op2<0> = 0, so no other hint matches). ADC/ADCS/
            // SBC/SBCS and SMSUBL/UMSUBL: no decode-time rule. CRC32*/CRC32C*: the
            // `sf`/`sz` UNDEFINED combinations are fixed by each form's diagram; the
            // remaining UNDEFINED case is a missing FEAT_CRC32, a CPU property
            // (docs/pipeline.md, "BTI, carry arithmetic, CRC32 (A7d)").
            | Self::BtiBtiHbHints { .. }
            | Self::AdcAdc32AddsubCarry { .. }
            | Self::AdcAdc64AddsubCarry { .. }
            | Self::AdcsAdcs32AddsubCarry { .. }
            | Self::AdcsAdcs64AddsubCarry { .. }
            | Self::SbcSbc32AddsubCarry { .. }
            | Self::SbcSbc64AddsubCarry { .. }
            | Self::SbcsSbcs32AddsubCarry { .. }
            | Self::SbcsSbcs64AddsubCarry { .. }
            | Self::SmsublSmsubl64waDp3src { .. }
            | Self::UmsublUmsubl64waDp3src { .. }
            | Self::Crc32Crc32b32cDp2src { .. }
            | Self::Crc32Crc32h32cDp2src { .. }
            | Self::Crc32Crc32w32cDp2src { .. }
            | Self::Crc32Crc32x64cDp2src { .. }
            | Self::Crc32cCrc32cb32cDp2src { .. }
            | Self::Crc32cCrc32ch32cDp2src { .. }
            | Self::Crc32cCrc32cw32cDp2src { .. }
            | Self::Crc32cCrc32cx64cDp2src { .. }
            | Self::BlBlOnlyBranchImm { .. }
            | Self::BrBr64BranchReg { .. }
            | Self::BlrBlr64BranchReg { .. }
            | Self::RetRet64rBranchReg { .. }
            | Self::SvcSvcExException { .. }
            // A8. LSE atomics: the only UNDEFINED case is a missing FEAT_LSE, a CPU
            // property the module checks at init. MSR (immediate) is constrained to
            // PSTATE.PAN in subset.toml; its remaining UNDEFINED case is a missing
            // FEAT_PAN (K1 requires hardware PAN).
            | Self::MsrImmMsrSiPstate { .. }
            | Self::LdaddLdadd32Memop { .. }
            | Self::LdaddLdadda32Memop { .. }
            | Self::LdaddLdaddal32Memop { .. }
            | Self::LdaddLdaddl32Memop { .. }
            | Self::LdaddLdadd64Memop { .. }
            | Self::LdaddLdadda64Memop { .. }
            | Self::LdaddLdaddal64Memop { .. }
            | Self::LdaddLdaddl64Memop { .. }
            | Self::LdaddbLdaddb32Memop { .. }
            | Self::LdaddbLdaddab32Memop { .. }
            | Self::LdaddbLdaddalb32Memop { .. }
            | Self::LdaddbLdaddlb32Memop { .. }
            | Self::LdaddhLdaddh32Memop { .. }
            | Self::LdaddhLdaddah32Memop { .. }
            | Self::LdaddhLdaddalh32Memop { .. }
            | Self::LdaddhLdaddlh32Memop { .. }
            | Self::LdclrLdclr32Memop { .. }
            | Self::LdclrLdclra32Memop { .. }
            | Self::LdclrLdclral32Memop { .. }
            | Self::LdclrLdclrl32Memop { .. }
            | Self::LdclrLdclr64Memop { .. }
            | Self::LdclrLdclra64Memop { .. }
            | Self::LdclrLdclral64Memop { .. }
            | Self::LdclrLdclrl64Memop { .. }
            | Self::LdclrbLdclrb32Memop { .. }
            | Self::LdclrbLdclrab32Memop { .. }
            | Self::LdclrbLdclralb32Memop { .. }
            | Self::LdclrbLdclrlb32Memop { .. }
            | Self::LdclrhLdclrh32Memop { .. }
            | Self::LdclrhLdclrah32Memop { .. }
            | Self::LdclrhLdclralh32Memop { .. }
            | Self::LdclrhLdclrlh32Memop { .. }
            | Self::LdeorLdeor32Memop { .. }
            | Self::LdeorLdeora32Memop { .. }
            | Self::LdeorLdeoral32Memop { .. }
            | Self::LdeorLdeorl32Memop { .. }
            | Self::LdeorLdeor64Memop { .. }
            | Self::LdeorLdeora64Memop { .. }
            | Self::LdeorLdeoral64Memop { .. }
            | Self::LdeorLdeorl64Memop { .. }
            | Self::LdeorbLdeorb32Memop { .. }
            | Self::LdeorbLdeorab32Memop { .. }
            | Self::LdeorbLdeoralb32Memop { .. }
            | Self::LdeorbLdeorlb32Memop { .. }
            | Self::LdeorhLdeorh32Memop { .. }
            | Self::LdeorhLdeorah32Memop { .. }
            | Self::LdeorhLdeoralh32Memop { .. }
            | Self::LdeorhLdeorlh32Memop { .. }
            | Self::LdsetLdset32Memop { .. }
            | Self::LdsetLdseta32Memop { .. }
            | Self::LdsetLdsetal32Memop { .. }
            | Self::LdsetLdsetl32Memop { .. }
            | Self::LdsetLdset64Memop { .. }
            | Self::LdsetLdseta64Memop { .. }
            | Self::LdsetLdsetal64Memop { .. }
            | Self::LdsetLdsetl64Memop { .. }
            | Self::LdsetbLdsetb32Memop { .. }
            | Self::LdsetbLdsetab32Memop { .. }
            | Self::LdsetbLdsetalb32Memop { .. }
            | Self::LdsetbLdsetlb32Memop { .. }
            | Self::LdsethLdseth32Memop { .. }
            | Self::LdsethLdsetah32Memop { .. }
            | Self::LdsethLdsetalh32Memop { .. }
            | Self::LdsethLdsetlh32Memop { .. }
            | Self::LdsmaxLdsmax32Memop { .. }
            | Self::LdsmaxLdsmaxa32Memop { .. }
            | Self::LdsmaxLdsmaxal32Memop { .. }
            | Self::LdsmaxLdsmaxl32Memop { .. }
            | Self::LdsmaxLdsmax64Memop { .. }
            | Self::LdsmaxLdsmaxa64Memop { .. }
            | Self::LdsmaxLdsmaxal64Memop { .. }
            | Self::LdsmaxLdsmaxl64Memop { .. }
            | Self::LdsmaxbLdsmaxb32Memop { .. }
            | Self::LdsmaxbLdsmaxab32Memop { .. }
            | Self::LdsmaxbLdsmaxalb32Memop { .. }
            | Self::LdsmaxbLdsmaxlb32Memop { .. }
            | Self::LdsmaxhLdsmaxh32Memop { .. }
            | Self::LdsmaxhLdsmaxah32Memop { .. }
            | Self::LdsmaxhLdsmaxalh32Memop { .. }
            | Self::LdsmaxhLdsmaxlh32Memop { .. }
            | Self::LdsminLdsmin32Memop { .. }
            | Self::LdsminLdsmina32Memop { .. }
            | Self::LdsminLdsminal32Memop { .. }
            | Self::LdsminLdsminl32Memop { .. }
            | Self::LdsminLdsmin64Memop { .. }
            | Self::LdsminLdsmina64Memop { .. }
            | Self::LdsminLdsminal64Memop { .. }
            | Self::LdsminLdsminl64Memop { .. }
            | Self::LdsminbLdsminb32Memop { .. }
            | Self::LdsminbLdsminab32Memop { .. }
            | Self::LdsminbLdsminalb32Memop { .. }
            | Self::LdsminbLdsminlb32Memop { .. }
            | Self::LdsminhLdsminh32Memop { .. }
            | Self::LdsminhLdsminah32Memop { .. }
            | Self::LdsminhLdsminalh32Memop { .. }
            | Self::LdsminhLdsminlh32Memop { .. }
            | Self::LdumaxLdumax32Memop { .. }
            | Self::LdumaxLdumaxa32Memop { .. }
            | Self::LdumaxLdumaxal32Memop { .. }
            | Self::LdumaxLdumaxl32Memop { .. }
            | Self::LdumaxLdumax64Memop { .. }
            | Self::LdumaxLdumaxa64Memop { .. }
            | Self::LdumaxLdumaxal64Memop { .. }
            | Self::LdumaxLdumaxl64Memop { .. }
            | Self::LdumaxbLdumaxb32Memop { .. }
            | Self::LdumaxbLdumaxab32Memop { .. }
            | Self::LdumaxbLdumaxalb32Memop { .. }
            | Self::LdumaxbLdumaxlb32Memop { .. }
            | Self::LdumaxhLdumaxh32Memop { .. }
            | Self::LdumaxhLdumaxah32Memop { .. }
            | Self::LdumaxhLdumaxalh32Memop { .. }
            | Self::LdumaxhLdumaxlh32Memop { .. }
            | Self::LduminLdumin32Memop { .. }
            | Self::LduminLdumina32Memop { .. }
            | Self::LduminLduminal32Memop { .. }
            | Self::LduminLduminl32Memop { .. }
            | Self::LduminLdumin64Memop { .. }
            | Self::LduminLdumina64Memop { .. }
            | Self::LduminLduminal64Memop { .. }
            | Self::LduminLduminl64Memop { .. }
            | Self::LduminbLduminb32Memop { .. }
            | Self::LduminbLduminab32Memop { .. }
            | Self::LduminbLduminalb32Memop { .. }
            | Self::LduminbLduminlb32Memop { .. }
            | Self::LduminhLduminh32Memop { .. }
            | Self::LduminhLduminah32Memop { .. }
            | Self::LduminhLduminalh32Memop { .. }
            | Self::LduminhLduminlh32Memop { .. }
            | Self::SwpSwp32Memop { .. }
            | Self::SwpSwpa32Memop { .. }
            | Self::SwpSwpal32Memop { .. }
            | Self::SwpSwpl32Memop { .. }
            | Self::SwpSwp64Memop { .. }
            | Self::SwpSwpa64Memop { .. }
            | Self::SwpSwpal64Memop { .. }
            | Self::SwpSwpl64Memop { .. }
            | Self::SwpbSwpb32Memop { .. }
            | Self::SwpbSwpab32Memop { .. }
            | Self::SwpbSwpalb32Memop { .. }
            | Self::SwpbSwplb32Memop { .. }
            | Self::SwphSwph32Memop { .. }
            | Self::SwphSwpah32Memop { .. }
            | Self::SwphSwpalh32Memop { .. }
            | Self::SwphSwplh32Memop { .. }
            | Self::CasCasC32Comswap { .. }
            | Self::CasCasaC32Comswap { .. }
            | Self::CasCasalC32Comswap { .. }
            | Self::CasCaslC32Comswap { .. }
            | Self::CasCasC64Comswap { .. }
            | Self::CasCasaC64Comswap { .. }
            | Self::CasCasalC64Comswap { .. }
            | Self::CasCaslC64Comswap { .. }
            | Self::CasbCasbC32Comswap { .. }
            | Self::CasbCasabC32Comswap { .. }
            | Self::CasbCasalbC32Comswap { .. }
            | Self::CasbCaslbC32Comswap { .. }
            | Self::CashCashC32Comswap { .. }
            | Self::CashCasahC32Comswap { .. }
            | Self::CashCasalhC32Comswap { .. }
            | Self::CashCaslhC32Comswap { .. }
            // A9a SIMD&FP with no decode-time value rule: loads/stores (the size and
            // opc combinations are fixed per encoding; the only other UNDEFINED
            // case is a missing FEAT_FP/FEAT_AdvSIMD, a CPU property; LDP `t == t2`
            // is CONSTRAINED UNPREDICTABLE, rejected by reg-virt), scalar forms whose
            // diagram fixes `size = 11` / `immh<3> = 1`, bitwise forms, MOVI/MVNI
            // (every listed `cmode`/`op` is defined), FMOV (general, register:
            // single/double only; FP16 forms are not in the subset), UMOV (64-bit:
            // the diagram fixes `imm5<3:0> = 1000`), ADDP (scalar), TBL (one register).
            | Self::LdrImmFpsimdLdrBLdstImmpost { .. }
            | Self::LdrImmFpsimdLdrHLdstImmpost { .. }
            | Self::LdrImmFpsimdLdrSLdstImmpost { .. }
            | Self::LdrImmFpsimdLdrDLdstImmpost { .. }
            | Self::LdrImmFpsimdLdrQLdstImmpost { .. }
            | Self::LdrImmFpsimdLdrBLdstImmpre { .. }
            | Self::LdrImmFpsimdLdrHLdstImmpre { .. }
            | Self::LdrImmFpsimdLdrSLdstImmpre { .. }
            | Self::LdrImmFpsimdLdrDLdstImmpre { .. }
            | Self::LdrImmFpsimdLdrQLdstImmpre { .. }
            | Self::LdrImmFpsimdLdrBLdstPos { .. }
            | Self::LdrImmFpsimdLdrHLdstPos { .. }
            | Self::LdrImmFpsimdLdrSLdstPos { .. }
            | Self::LdrImmFpsimdLdrDLdstPos { .. }
            | Self::LdrImmFpsimdLdrQLdstPos { .. }
            | Self::StrImmFpsimdStrBLdstImmpost { .. }
            | Self::StrImmFpsimdStrHLdstImmpost { .. }
            | Self::StrImmFpsimdStrSLdstImmpost { .. }
            | Self::StrImmFpsimdStrDLdstImmpost { .. }
            | Self::StrImmFpsimdStrQLdstImmpost { .. }
            | Self::StrImmFpsimdStrBLdstImmpre { .. }
            | Self::StrImmFpsimdStrHLdstImmpre { .. }
            | Self::StrImmFpsimdStrSLdstImmpre { .. }
            | Self::StrImmFpsimdStrDLdstImmpre { .. }
            | Self::StrImmFpsimdStrQLdstImmpre { .. }
            | Self::StrImmFpsimdStrBLdstPos { .. }
            | Self::StrImmFpsimdStrHLdstPos { .. }
            | Self::StrImmFpsimdStrSLdstPos { .. }
            | Self::StrImmFpsimdStrDLdstPos { .. }
            | Self::StrImmFpsimdStrQLdstPos { .. }
            | Self::LdurFpsimdLdurBLdstUnscaled { .. }
            | Self::LdurFpsimdLdurHLdstUnscaled { .. }
            | Self::LdurFpsimdLdurSLdstUnscaled { .. }
            | Self::LdurFpsimdLdurDLdstUnscaled { .. }
            | Self::LdurFpsimdLdurQLdstUnscaled { .. }
            | Self::SturFpsimdSturBLdstUnscaled { .. }
            | Self::SturFpsimdSturHLdstUnscaled { .. }
            | Self::SturFpsimdSturSLdstUnscaled { .. }
            | Self::SturFpsimdSturDLdstUnscaled { .. }
            | Self::SturFpsimdSturQLdstUnscaled { .. }
            | Self::LdpFpsimdLdpSLdstpairPost { .. }
            | Self::LdpFpsimdLdpDLdstpairPost { .. }
            | Self::LdpFpsimdLdpQLdstpairPost { .. }
            | Self::LdpFpsimdLdpSLdstpairPre { .. }
            | Self::LdpFpsimdLdpDLdstpairPre { .. }
            | Self::LdpFpsimdLdpQLdstpairPre { .. }
            | Self::LdpFpsimdLdpSLdstpairOff { .. }
            | Self::LdpFpsimdLdpDLdstpairOff { .. }
            | Self::LdpFpsimdLdpQLdstpairOff { .. }
            | Self::StpFpsimdStpSLdstpairPost { .. }
            | Self::StpFpsimdStpDLdstpairPost { .. }
            | Self::StpFpsimdStpQLdstpairPost { .. }
            | Self::StpFpsimdStpSLdstpairPre { .. }
            | Self::StpFpsimdStpDLdstpairPre { .. }
            | Self::StpFpsimdStpQLdstpairPre { .. }
            | Self::StpFpsimdStpSLdstpairOff { .. }
            | Self::StpFpsimdStpDLdstpairOff { .. }
            | Self::StpFpsimdStpQLdstpairOff { .. }
            | Self::Ld1AdvsimdMultLd1AsisdlseR11v { .. }
            | Self::Ld1AdvsimdMultLd1AsisdlseR22v { .. }
            | Self::Ld1AdvsimdMultLd1AsisdlseR33v { .. }
            | Self::Ld1AdvsimdMultLd1AsisdlseR44v { .. }
            | Self::Ld1AdvsimdMultLd1AsisdlsepI1I1 { .. }
            | Self::Ld1AdvsimdMultLd1AsisdlsepR1R1 { .. }
            | Self::Ld1AdvsimdMultLd1AsisdlsepI2I2 { .. }
            | Self::Ld1AdvsimdMultLd1AsisdlsepR2R2 { .. }
            | Self::Ld1AdvsimdMultLd1AsisdlsepI3I3 { .. }
            | Self::Ld1AdvsimdMultLd1AsisdlsepR3R3 { .. }
            | Self::Ld1AdvsimdMultLd1AsisdlsepI4I4 { .. }
            | Self::Ld1AdvsimdMultLd1AsisdlsepR4R4 { .. }
            | Self::St1AdvsimdMultSt1AsisdlseR11v { .. }
            | Self::St1AdvsimdMultSt1AsisdlseR22v { .. }
            | Self::St1AdvsimdMultSt1AsisdlseR33v { .. }
            | Self::St1AdvsimdMultSt1AsisdlseR44v { .. }
            | Self::St1AdvsimdMultSt1AsisdlsepI1I1 { .. }
            | Self::St1AdvsimdMultSt1AsisdlsepR1R1 { .. }
            | Self::St1AdvsimdMultSt1AsisdlsepI2I2 { .. }
            | Self::St1AdvsimdMultSt1AsisdlsepR2R2 { .. }
            | Self::St1AdvsimdMultSt1AsisdlsepI3I3 { .. }
            | Self::St1AdvsimdMultSt1AsisdlsepR3R3 { .. }
            | Self::St1AdvsimdMultSt1AsisdlsepI4I4 { .. }
            | Self::St1AdvsimdMultSt1AsisdlsepR4R4 { .. }
            | Self::UmovAdvsimdUmovAsimdinsXX { .. }
            | Self::MoviAdvsimdMoviAsimdimmNB { .. }
            | Self::MoviAdvsimdMoviAsimdimmLHl { .. }
            | Self::MoviAdvsimdMoviAsimdimmLSl { .. }
            | Self::MoviAdvsimdMoviAsimdimmMSm { .. }
            | Self::MoviAdvsimdMoviAsimdimmDDs { .. }
            | Self::MoviAdvsimdMoviAsimdimmD2D { .. }
            | Self::MvniAdvsimdMvniAsimdimmLHl { .. }
            | Self::MvniAdvsimdMvniAsimdimmLSl { .. }
            | Self::MvniAdvsimdMvniAsimdimmMSm { .. }
            | Self::FmovFloatGenFmovS32Float2int { .. }
            | Self::FmovFloatGenFmov32sFloat2int { .. }
            | Self::FmovFloatGenFmovD64Float2int { .. }
            | Self::FmovFloatGenFmovV64iFloat2int { .. }
            | Self::FmovFloatGenFmov64dFloat2int { .. }
            | Self::FmovFloatGenFmov64vxFloat2int { .. }
            | Self::FmovFloatFmovSFloatdp1 { .. }
            | Self::FmovFloatFmovDFloatdp1 { .. }
            | Self::CmeqAdvsimdRegCmeqAsisdsameOnly { .. }
            | Self::CmeqAdvsimdZeroCmeqAsisdmiscZ { .. }
            | Self::CmhiAdvsimdCmhiAsisdsameOnly { .. }
            | Self::CmhsAdvsimdCmhsAsisdsameOnly { .. }
            | Self::CmgtAdvsimdRegCmgtAsisdsameOnly { .. }
            | Self::CmgtAdvsimdZeroCmgtAsisdmiscZ { .. }
            | Self::CmgeAdvsimdRegCmgeAsisdsameOnly { .. }
            | Self::CmgeAdvsimdZeroCmgeAsisdmiscZ { .. }
            | Self::CmtstAdvsimdCmtstAsisdsameOnly { .. }
            | Self::AndAdvsimdAndAsimdsameOnly { .. }
            | Self::OrrAdvsimdRegOrrAsimdsameOnly { .. }
            | Self::EorAdvsimdEorAsimdsameOnly { .. }
            | Self::BicAdvsimdRegBicAsimdsameOnly { .. }
            | Self::OrnAdvsimdOrnAsimdsameOnly { .. }
            | Self::BitAdvsimdBitAsimdsameOnly { .. }
            | Self::BifAdvsimdBifAsimdsameOnly { .. }
            | Self::BslAdvsimdBslAsimdsameOnly { .. }
            | Self::NotAdvsimdNotAsimdmiscR { .. }
            | Self::AddAdvsimdAddAsisdsameOnly { .. }
            | Self::SubAdvsimdSubAsisdsameOnly { .. }
            | Self::AddpAdvsimdPairAddpAsisdpairOnly { .. }
            | Self::UshrAdvsimdUshrAsisdshfR { .. }
            | Self::ShlAdvsimdShlAsisdshfR { .. }
            | Self::TblAdvsimdTblAsimdtblL11 { .. } => false,
        }
    }
}

/// The UNDEFINED cases of `DecodeBitMasks(N, imms, immr, immediate = TRUE)`:
/// `N:NOT(imms)` has no set bit above bit 0 (element size below 2), or `imms`
/// selects an all-ones element.
const fn logical_imm_undefined(n: u8, imms: A64Imm) -> bool {
    let imms = imms.raw() & 0x3f;
    let n_not_imms = ((n as u32 & 1) << 6) | (!imms & 0x3f);
    if n_not_imms >> 1 == 0 {
        return true;
    }
    let len = 31 - n_not_imms.leading_zeros();
    let levels = (1_u32 << len) - 1;
    imms & levels == levels
}

pub fn decode_program(program: &[u8], base_pc: u64) -> Result<SharedVec<IrInsn>, DecodeError> {
    if program.len() % 4 != 0 {
        return Err(DecodeError::UnsupportedWord {
            pc: base_pc,
            word: 0,
        });
    }

    let mut decoded =
        SharedVec::with_capacity(program.len() / 4, GFP_KERNEL).map_err(DecodeError::Alloc)?;
    for (index, chunk) in program.chunks_exact(4).enumerate() {
        let pc = base_pc + (index as u64) * 4;
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        decoded
            .push(decode_word(word, pc)?, GFP_KERNEL)
            .map_err(DecodeError::Alloc)?;
    }
    Ok(decoded)
}

fn pc_relative_target(pc: u64, encoded: u32, bits: u8) -> u64 {
    pc.wrapping_add_signed(sign_extend(encoded, bits) << 2)
}

fn sign_extend(value: u32, bits: u8) -> i64 {
    let shift = 64 - bits as u32;
    ((value as i64) << shift) >> shift
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Words that match a generated encoding diagram but are UNDEFINED by the
    /// form's decode pseudocode, each next to a defined neighbour.
    #[test]
    fn decode_word_rejects_pseudocode_undefined_encodings() {
        let cases: [(u32, u32, &str); 9] = [
            (0x0b02_0020, 0x0bc2_0020, "add w0, w1, w2 / shift == 0b11"),
            (
                0x0b02_7c20,
                0x0b02_8020,
                "add w0, w1, w2, lsl #31 / imm6 = 32",
            ),
            (
                0x8b22_5020,
                0x8b22_5420,
                "add x0, x1, w2, uxtw #4 / imm3 = 5",
            ),
            (
                0x0a02_7c20,
                0x0a02_8020,
                "and w0, w1, w2, lsl #31 / imm6 = 32",
            ),
            (
                0x1200_7820,
                0x1200_f820,
                "and w0, w1, #0x7fffffff / N:NOT(imms) = 0b000000x",
            ),
            (
                0x9240_f820,
                0x9240_fc20,
                "and x0, x1, #0x7fff.. / N = 1, imms all ones",
            ),
            (
                0x9200_f020,
                0x9200_f420,
                "and x0, x1, #0x5555.. / 2-bit element all ones",
            ),
            (0x131f_7c20, 0x1320_7c20, "asr w0, w1, #31 / immr<5> set"),
            (
                0x1300_7c20,
                0x1300_fc20,
                "sbfm w0, w1, #0, #31 / imms<5> set",
            ),
        ];
        for (defined, undefined, what) in cases {
            assert!(
                decode_word(defined, 0).is_ok(),
                "{what}: {defined:#010x} must decode"
            );
            assert!(
                A64Insn::decode(undefined).is_some(),
                "{what}: {undefined:#010x} must match the encoding diagram"
            );
            assert_eq!(
                decode_word(undefined, 0x40),
                Err(DecodeError::UnsupportedWord {
                    pc: 0x40,
                    word: undefined
                }),
                "{what}"
            );
        }
    }

    /// Register-offset loads/stores with `option<1> == 0` (a sub-word index) are
    /// UNDEFINED; the UXTW neighbour decodes.
    #[test]
    fn register_offset_with_sub_word_index_is_undefined() {
        let cases: [(u32, u32, &str); 3] = [
            (0xf862_4820, 0xf862_0820, "ldr x0, [x1, w2, uxtw] / uxtb"),
            (0xb822_c820, 0xb822_a820, "str w0, [x1, w2, sxtw] / sxth"),
            (0x3862_4820, 0x3862_2820, "ldrb w0, [x1, w2, uxtw] / uxth"),
        ];
        for (defined, undefined, what) in cases {
            assert!(decode_word(defined, 0).is_ok(), "{what}: {defined:#010x}");
            assert!(
                A64Insn::decode(undefined).is_some(),
                "{what}: {undefined:#010x} must match the encoding diagram"
            );
            assert!(
                decode_word(undefined, 0).is_err(),
                "{what}: {undefined:#010x}"
            );
        }
    }

    /// `LDRB_32B_ldst_regoff` carries the diagram constraint `option != 011`; those
    /// words belong to the `LSL` form `LDRB_32BL_ldst_regoff`.
    #[test]
    fn diagram_exclusions_route_words_to_the_right_form() {
        // ldrb w0, [x1, x2, lsl #0]
        assert_eq!(
            A64Insn::decode(0x3862_7820).map(|insn| insn.key()),
            Some("LDRB_reg.LDRB_32BL_ldst_regoff")
        );
        // ldrb w0, [x1, x2, sxtx]
        assert_eq!(
            A64Insn::decode(0x3862_e820).map(|insn| insn.key()),
            Some("LDRB_reg.LDRB_32B_ldst_regoff")
        );
        // RPRFM space (PRFM register with Rt<4:3> == 11) is excluded from PRFM.
        assert!(A64Insn::decode(0xf8a2_4818).is_none());
    }

    /// Every generated form decodes from its own base value to itself, and
    /// `is_unprivileged_access` is exactly the `LDTR*`/`STTR*` family.
    #[test]
    fn unprivileged_family_matches_the_generated_ldtr_sttr_forms() {
        use generated::GENERATED_A64_SUBSET;
        let mut unprivileged = 0;
        for spec in GENERATED_A64_SUBSET {
            let insn = A64Insn::decode(form_base_word(spec))
                .unwrap_or_else(|| panic!("{} does not decode its own value", spec.key));
            assert_eq!(insn.key(), spec.key, "{:#010x}", spec.value);
            let family = spec.mnemonic.starts_with("LDTR") || spec.mnemonic.starts_with("STTR");
            assert_eq!(insn.is_unprivileged_access(), family, "{}", spec.key);
            unprivileged += usize::from(family);
        }
        assert_eq!(unprivileged, 13);
    }

    /// Exclusive, pair-atomic (CASP, FEAT_LSE128) and the FP/SIMD memory forms
    /// outside A9a (register offset, literal, LD2-4, single structure, replicate,
    /// non-temporal), and
    /// the acquire/release forms beyond A7c's base-register ones (FEAT_LRCPC2
    /// unscaled, FEAT_LRCPC3 writeback, non-canonical should-be-one fields), stay
    /// outside the subset: they must not decode, so they take the Unsupported exit.
    #[test]
    fn exclusive_atomic_and_fp_memory_forms_stay_undecodable() {
        let words: [(u32, &str); 26] = [
            (0xc85f_7c20, "ldxr x0, [x1]"),
            (0xc802_7c20, "stxr w2, x0, [x1]"),
            (0x885f_fc20, "ldaxr w0, [x1]"),
            (0x8802_fc20, "stlxr w2, w0, [x1]"),
            (0xc8c0_fc20, "ldar x0, [x1] with Rs = 0"),
            (0x889f_8020, "stlr w0, [x1] with Rt2 = 0"),
            (0xf8a0_c020, "ldapr x0, [x1] with Rs = 0"),
            (0xd9c0_0820, "ldapr x0, [x1], #8 (FEAT_LRCPC3)"),
            (0xd980_0820, "stlr x0, [x1, #-8]! (FEAT_LRCPC3)"),
            (0xd940_8020, "ldapur x0, [x1, #8] (FEAT_LRCPC2)"),
            (0x991f_c020, "stlur w0, [x1, #-4] (FEAT_LRCPC2)"),
            (0xc87f_0440, "ldxp x0, x1, [x2]"),
            (0x4820_7c82, "casp x0, x1, x2, x3, [x4]"),
            (0x0820_7c82, "casp w0, w1, w2, w3, [x4]"),
            (0x1921_1040, "ldclrp x0, x1, [x2] (FEAT_LSE128)"),
            (0x1921_8040, "swpp x0, x1, [x2] (FEAT_LSE128)"),
            (0x1921_3040, "ldsetp x0, x1, [x2] (FEAT_LSE128)"),
            (0xfc22_7820, "str d0, [x1, x2, lsl #3]"),
            (0x3ce2_6820, "str q0, [x1, x2]"),
            (0x4c40_8020, "ld2 {v0.8h, v1.8h}, [x1]"),
            (0x4d40_0020, "ld1 {v0.b}[8], [x1]"),
            (0x4d40_c020, "ld1r {v0.16b}, [x1]"),
            (0x2c40_0420, "ldnp s0, s1, [x1]"),
            (0x9c00_0000, "ldr q0, <literal>"),
            (0xa840_0440, "ldnp x0, x1, [x2]"),
            (0xf880_1000, "prfum pldl1keep, [x0, #1]"),
        ];
        for (word, what) in words {
            assert_eq!(
                decode_word(word, 0x40),
                Err(DecodeError::UnsupportedWord { pc: 0x40, word }),
                "{what}"
            );
        }
    }

    /// A9a: FP arithmetic, conversions and compares, half-precision FMOV, FMOV
    /// (vector, immediate), saturating integer SIMD and multi-register TBL stay
    /// outside the subset (Unsupported exit), next to the forms that joined it.
    #[test]
    fn a9a_subset_boundary() {
        let outside: [(u32, &str); 10] = [
            (0x1e60_2801, "fadd d1, d0, d0"),
            (0x9e63_0020, "ucvtf d0, x1"),
            (0x1e61_2010, "fcmpe d0, d1"),
            (0x9e78_0000, "fcvtzs x0, d0"),
            (0x4f03_f600, "fmov v0.4s, #1.0"),
            (0x1ee6_0020, "fmov w0, h1 (FEAT_FP16)"),
            (0x1ee0_4020, "fmov h0, h1 (FEAT_FP16)"),
            (0x1e22_0020, "scvtf s0, w1"),
            (0x4e22_0c20, "sqadd v0.16b, v1.16b, v2.16b"),
            (0x4e03_2020, "tbl v0.16b, {v1.16b, v2.16b}, v3.16b"),
        ];
        for (word, what) in outside {
            assert!(decode_word(word, 0).is_err(), "{what}");
        }
        let inside: [(u32, &str); 3] = [
            (0x6f00_e400, "MOVI_advsimd.MOVI_asimdimm_D2_d"),
            (0x3dc0_0020, "LDR_imm_fpsimd.LDR_Q_ldst_pos"),
            (0x4e20_9820, "CMEQ_advsimd_zero.CMEQ_asimdmisc_Z"),
        ];
        for (word, key) in inside {
            assert_eq!(decode_word(word, 0).unwrap().inner.key(), key);
        }
    }

    /// A9a: `fpsimd_mem` is exactly the generated SIMD&FP loads/stores (a
    /// `Memory` role and a `Vec*` role), each with its base-only access in the
    /// same XML section family, and `is_pan_window_access` holds for exactly the
    /// base-only encodings and the LSE atomics.
    #[test]
    fn fpsimd_mem_matches_the_generated_simd_memory_forms() {
        use generated::GENERATED_A64_SUBSET;
        let mut memory = 0;
        let mut base_only = 0;
        for spec in GENERATED_A64_SUBSET {
            let insn = A64Insn::decode(form_base_word(spec)).expect("own value decodes");
            let simd_memory = spec.operands.contains(&A64OperandRole::Memory)
                && spec.operands.iter().any(|role| {
                    matches!(
                        role,
                        A64OperandRole::VecRead { .. } | A64OperandRole::VecWrite { .. }
                    )
                });
            assert_eq!(insn.fpsimd_mem().is_some(), simd_memory, "{}", spec.key);
            if let Some(mem) = insn.fpsimd_mem() {
                memory += 1;
                assert!(mem.access.is_pan_window_access(), "{}", spec.key);
                assert_eq!(mem.access.fpsimd_mem().unwrap().access, mem.access);
                if insn.is_pan_window_access() {
                    base_only += 1;
                    assert_eq!(mem.access, insn, "{}", spec.key);
                }
            } else {
                assert_eq!(insn.is_pan_window_access(), insn.lse_atomic().is_some());
            }
        }
        assert_eq!((memory, base_only), (82, 24));
    }

    /// A7c: the barriers and base-register acquire/release forms decode as
    /// themselves.
    #[test]
    fn barriers_and_acquire_release_forms_decode() {
        let words: [(u32, &str); 11] = [
            (0xd503_3bbf, "DMB.DMB_BO_barriers"),
            (0xd503_30bf, "DMB.DMB_BO_barriers"),
            (0xd503_3f9f, "DSB.DSB_BO_barriers"),
            (0xd503_309f, "DSB.DSB_BO_barriers"),
            (0xd503_3fdf, "ISB.ISB_BI_barriers"),
            (0xc8df_fc20, "LDAR.LDAR_LR64_ldstord"),
            (0x889f_fc20, "STLR.STLR_SL32_ldstord"),
            (0x08df_ffe0, "LDARB.LDARB_LR32_ldstord"),
            (0x489f_fc83, "STLRH.STLRH_SL32_ldstord"),
            (0xb8bf_c0c5, "LDAPR.LDAPR_32L_memop"),
            (0x78bf_c107, "LDAPRH.LDAPRH_32L_memop"),
        ];
        for (word, key) in words {
            let insn = decode_word(word, 0x40).unwrap_or_else(|_| panic!("{word:#010x}"));
            assert_eq!(insn.inner.key(), key, "{word:#010x}");
        }
    }

    /// A7d: in the whole HINT space (`hint #0..#127`) exactly NOP and the four BTI
    /// encodings decode. PACIASP/AUTIASP/XPACLRI and every other hint stay
    /// undecodable: pointer authentication must not run at EL1 with the kernel's
    /// keys (K1), so they take the Unsupported exit and run in userspace.
    #[test]
    fn hint_space_decodes_only_nop_and_bti() {
        for imm in 0..128_u32 {
            let word = 0xd503_201f | (imm << 5);
            let key = decode_word(word, 0).ok().map(|insn| insn.inner.key());
            let expected = match imm {
                0 => Some("NOP.NOP_HI_hints"),
                0x20 | 0x22 | 0x24 | 0x26 => Some("BTI.BTI_HB_hints"),
                _ => None,
            };
            assert_eq!(key, expected, "hint #{imm:#x} ({word:#010x})");
        }
    }

    /// A7d: carry arithmetic, multiply-subtract long and CRC32 decode as
    /// themselves (words from llvm-mc); CRC32's `sf`/`sz` UNDEFINED combinations
    /// do not decode.
    #[test]
    fn carry_msubl_and_crc32_forms_decode() {
        let words: [(u32, &str); 13] = [
            (0x1a02_0020, "ADC.ADC_32_addsub_carry"),
            (0x9a02_0020, "ADC.ADC_64_addsub_carry"),
            (0xba05_0083, "ADCS.ADCS_64_addsub_carry"),
            (0x5a02_0020, "SBC.SBC_32_addsub_carry"),
            (0xda01_03e0, "SBC.SBC_64_addsub_carry"),
            (0x7a04_03e3, "SBCS.SBCS_32_addsub_carry"),
            (0xfa02_0020, "SBCS.SBCS_64_addsub_carry"),
            (0x9b22_8c20, "SMSUBL.SMSUBL_64WA_dp_3src"),
            (0x9ba2_fc20, "UMSUBL.UMSUBL_64WA_dp_3src"),
            (0x1ac2_4020, "CRC32.CRC32B_32C_dp_2src"),
            (0x9ac2_4c20, "CRC32.CRC32X_64C_dp_2src"),
            (0x1ac2_5420, "CRC32C.CRC32CH_32C_dp_2src"),
            (0x9ac2_5c20, "CRC32C.CRC32CX_64C_dp_2src"),
        ];
        for (word, key) in words {
            let insn = decode_word(word, 0x40).unwrap_or_else(|_| panic!("{word:#010x}"));
            assert_eq!(insn.inner.key(), key, "{word:#010x}");
        }
        // sf = 1 with sz != 11, sf = 0 with sz == 11 (CRC32 and CRC32C).
        for word in [0x9ac2_4020_u32, 0x9ac2_5820, 0x1ac2_4c20, 0x1ac2_5c20] {
            assert!(decode_word(word, 0).is_err(), "{word:#010x}");
        }
    }

    /// A8: `lse_atomic` is exactly the generated LD<op>/SWP/CAS forms (160), with
    /// the operation and size their mnemonics name; every one decodes from its own
    /// base value.
    #[test]
    fn lse_atomic_matches_the_generated_atomic_forms() {
        use generated::GENERATED_A64_SUBSET;
        let ops: [(&str, A64AtomicOp); 10] = [
            ("LDADD", A64AtomicOp::Add),
            ("LDCLR", A64AtomicOp::Clr),
            ("LDEOR", A64AtomicOp::Eor),
            ("LDSET", A64AtomicOp::Set),
            ("LDSMAX", A64AtomicOp::Smax),
            ("LDSMIN", A64AtomicOp::Smin),
            ("LDUMAX", A64AtomicOp::Umax),
            ("LDUMIN", A64AtomicOp::Umin),
            ("SWP", A64AtomicOp::Swp),
            ("CAS", A64AtomicOp::Cas),
        ];
        let mut atomics = 0;
        for spec in GENERATED_A64_SUBSET {
            let insn = A64Insn::decode(form_base_word(spec)).expect("own value decodes");
            let section = spec.key.split('.').next().unwrap();
            let expected = ops.iter().find_map(|&(prefix, op)| {
                let suffix = section.strip_prefix(prefix)?;
                let size = match suffix {
                    "B" => 1,
                    "H" => 2,
                    "" if spec.key.contains("_64_") || spec.key.contains("_C64_") => 8,
                    "" => 4,
                    _ => return None,
                };
                Some((op, size))
            });
            let got = insn.lse_atomic().map(|atomic| (atomic.op, atomic.size));
            assert_eq!(got, expected, "{}", spec.key);
            atomics += usize::from(expected.is_some());
        }
        assert_eq!(atomics, 160);
    }

    /// A8: LSE atomics decode with their registers (words from llvm-mc; `stadd` is
    /// `ldadd` with Rt = XZR).
    #[test]
    fn lse_atomics_decode_with_their_registers() {
        let cases: [(u32, &str, A64AtomicOp, u8, [u8; 3]); 7] = [
            (0xf8e1_0062, "LDADD.LDADDAL_64_memop", A64AtomicOp::Add, 8, [1, 2, 3]),
            (0xb821_107f, "LDCLR.LDCLR_32_memop", A64AtomicOp::Clr, 4, [1, 31, 3]),
            (0x38a1_83e2, "SWPB.SWPAB_32_memop", A64AtomicOp::Swp, 1, [1, 2, 31]),
            (0x48e1_fc62, "CASH.CASALH_C32_comswap", A64AtomicOp::Cas, 2, [1, 2, 3]),
            (0xc8e1_7c62, "CAS.CASA_C64_comswap", A64AtomicOp::Cas, 8, [1, 2, 3]),
            (0x7861_73e2, "LDUMINH.LDUMINLH_32_memop", A64AtomicOp::Umin, 2, [1, 2, 31]),
            (0xf8a1_4062, "LDSMAX.LDSMAXA_64_memop", A64AtomicOp::Smax, 8, [1, 2, 3]),
        ];
        for (word, key, op, size, [rs, rt, rn]) in cases {
            let insn = decode_word(word, 0).unwrap_or_else(|_| panic!("{word:#010x}"));
            assert_eq!(insn.inner.key(), key, "{word:#010x}");
            let atomic = insn.inner.lse_atomic().expect("an LSE atomic");
            assert_eq!((atomic.op, atomic.size), (op, size), "{key}");
            assert_eq!(
                (atomic.rs.enc(), atomic.rt.enc(), atomic.rn.enc()),
                (rs, rt, rn),
                "{key}"
            );
            assert_eq!(atomic.rn.reg31, A64Reg31Mode::Sp, "{key}: Rn is <Xn|SP>");
        }
    }

    /// A8: of the whole MSR (immediate) space only PSTATE.PAN decodes; every other
    /// PSTATE field (UAO, SPSel, DAIFSet/Clr, DIT, TCO, SSBS, ALLINT, SM/ZA) and the
    /// CFINV/XAFLAG/AXFLAG words stay undecodable.
    #[test]
    fn msr_immediate_decodes_only_pstate_pan() {
        for op1 in 0..8_u32 {
            for op2 in 0..8_u32 {
                for crm in 0..16_u32 {
                    let word = 0xd500_401f | (op1 << 16) | (crm << 8) | (op2 << 5);
                    let insn = decode_word(word, 0).ok().map(|insn| insn.inner);
                    let pan = op1 == 0 && op2 == 4;
                    assert_eq!(insn.is_some(), pan, "op1={op1} op2={op2} crm={crm}");
                    if pan {
                        assert_eq!(
                            insn.and_then(A64Insn::msr_pan),
                            Some(crm & 1 == 1),
                            "crm={crm}"
                        );
                    }
                }
            }
        }
        // msr pan, #0 / #1 (llvm-mc).
        assert_eq!(A64Insn::MsrImmMsrSiPstate { crm: 0 }.encode(), Ok(0xd500_409f));
        assert_eq!(A64Insn::MsrImmMsrSiPstate { crm: 1 }.encode(), Ok(0xd500_419f));
    }
}
