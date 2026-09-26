use core::fmt;

use crate::shared::platform::{SharedAllocError, SharedVec, GFP_KERNEL};
use crate::shared::trans::cfg::RuntimeExitReason;

mod generated;
pub mod ergo;

pub use generated::{
    A64EncodeError, A64Imm, A64Insn, A64Mem, A64OperandRole, A64Reg, A64Reg31Mode, A64RegWidth,
    A64RewriteError,
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
            | Self::MrsMrsRsSystemmove { .. }
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
            | Self::NopNopHiHints {}
            | Self::BlBlOnlyBranchImm { .. }
            | Self::BrBr64BranchReg { .. }
            | Self::BlrBlr64BranchReg { .. }
            | Self::RetRet64rBranchReg { .. }
            | Self::SvcSvcExException { .. } => false,
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
            let insn = A64Insn::decode(spec.value)
                .unwrap_or_else(|| panic!("{} does not decode its own value", spec.key));
            assert_eq!(insn.key(), spec.key, "{:#010x}", spec.value);
            let family = spec.mnemonic.starts_with("LDTR") || spec.mnemonic.starts_with("STTR");
            assert_eq!(insn.is_unprivileged_access(), family, "{}", spec.key);
            unprivileged += usize::from(family);
        }
        assert_eq!(unprivileged, 13);
    }

    /// Exclusive, acquire/release, atomic and FP/SIMD memory forms stay outside the
    /// subset: they must not decode, so they take the Unsupported exit.
    #[test]
    fn exclusive_atomic_and_fp_memory_forms_stay_undecodable() {
        let words: [(u32, &str); 22] = [
            (0xc85f_7c20, "ldxr x0, [x1]"),
            (0xc802_7c20, "stxr w2, x0, [x1]"),
            (0x885f_fc20, "ldaxr w0, [x1]"),
            (0x8802_fc20, "stlxr w2, w0, [x1]"),
            (0xc8df_fc20, "ldar x0, [x1]"),
            (0x889f_fc20, "stlr w0, [x1]"),
            (0xc87f_0440, "ldxp x0, x1, [x2]"),
            (0xc8a0_7c41, "cas x0, x1, [x2]"),
            (0x88e0_fc41, "casal w0, w1, [x2]"),
            (0xf820_0041, "ldadd x0, x1, [x2]"),
            (0xb8e0_0041, "ldaddal w0, w1, [x2]"),
            (0xf820_8041, "swp x0, x1, [x2]"),
            (0xf8bf_c020, "ldapr x0, [x1]"),
            (0x3dc0_0020, "ldr q0, [x1]"),
            (0xfd40_0420, "ldr d0, [x1, #8]"),
            (0xbc40_4420, "ldr s0, [x1], #4"),
            (0xad40_0420, "ldp q0, q1, [x1]"),
            (0xfc22_7820, "str d0, [x1, x2, lsl #3]"),
            (0x3cdf_0020, "ldur q0, [x1, #-16]"),
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
}
