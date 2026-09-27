use crate::arm64::decode_bit_masks;
use crate::shared::arm64::{
    A64Condition, A64FpSimdWriteback, A64Imm, A64Insn, A64Mem, A64Reg, A64Reg31Mode, A64RegWidth,
};
use crate::shared::trans::cfg::RuntimeExitReason;

pub fn pretty_insn(insn: A64Insn, pc: Option<u64>) -> String {
    use A64Insn::*;

    match insn {
        AdrAdrOnlyPcreladdr { rd, .. } => {
            pretty_pc_relative("adr", rd, insn.pc_relative_address(pc.unwrap_or(0)), pc)
        }
        AdrpAdrpOnlyPcreladdr { rd, .. } => {
            pretty_pc_relative("adrp", rd, insn.pc_relative_address(pc.unwrap_or(0)), pc)
        }
        AddAddsubImmAdd32AddsubImm { sh, imm12, rn, rd }
        | AddAddsubImmAdd64AddsubImm { sh, imm12, rn, rd } => {
            pretty_add_sub("add", sh, imm12, rn, rd)
        }
        SubAddsubImmSub32AddsubImm { sh, imm12, rn, rd }
        | SubAddsubImmSub64AddsubImm { sh, imm12, rn, rd } => {
            pretty_add_sub("sub", sh, imm12, rn, rd)
        }
        SubsAddsubImmSubs32sAddsubImm { sh, imm12, rn, rd }
        | SubsAddsubImmSubs64sAddsubImm { sh, imm12, rn, rd } => {
            pretty_add_sub("subs", sh, imm12, rn, rd)
        }
        AddsAddsubImmAdds32sAddsubImm { sh, imm12, rn, rd }
        | AddsAddsubImmAdds64sAddsubImm { sh, imm12, rn, rd } => {
            pretty_add_sub("adds", sh, imm12, rn, rd)
        }
        AddAddsubShiftAdd32AddsubShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        }
        | AddAddsubShiftAdd64AddsubShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => pretty_shifted_reg("add", rd, rn, rm, shift, imm6),
        AddsAddsubShiftAdds32AddsubShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        }
        | AddsAddsubShiftAdds64AddsubShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => pretty_shifted_reg("adds", rd, rn, rm, shift, imm6),
        SubAddsubShiftSub32AddsubShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        }
        | SubAddsubShiftSub64AddsubShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => pretty_shifted_reg("sub", rd, rn, rm, shift, imm6),
        SubsAddsubShiftSubs32AddsubShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        }
        | SubsAddsubShiftSubs64AddsubShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => pretty_shifted_reg("subs", rd, rn, rm, shift, imm6),
        AddAddsubExtAdd32AddsubExt {
            rm,
            option,
            imm3,
            rn,
            rd,
        }
        | AddAddsubExtAdd64AddsubExt {
            rm,
            option,
            imm3,
            rn,
            rd,
        } => pretty_extended_reg("add", rd, rn, rm, option, imm3),
        AddsAddsubExtAdds32sAddsubExt {
            rm,
            option,
            imm3,
            rn,
            rd,
        }
        | AddsAddsubExtAdds64sAddsubExt {
            rm,
            option,
            imm3,
            rn,
            rd,
        } => pretty_extended_reg("adds", rd, rn, rm, option, imm3),
        SubAddsubExtSub32AddsubExt {
            rm,
            option,
            imm3,
            rn,
            rd,
        }
        | SubAddsubExtSub64AddsubExt {
            rm,
            option,
            imm3,
            rn,
            rd,
        } => pretty_extended_reg("sub", rd, rn, rm, option, imm3),
        SubsAddsubExtSubs32sAddsubExt {
            rm,
            option,
            imm3,
            rn,
            rd,
        }
        | SubsAddsubExtSubs64sAddsubExt {
            rm,
            option,
            imm3,
            rn,
            rd,
        } => pretty_extended_reg("subs", rd, rn, rm, option, imm3),
        MovnMovn32Movewide { hw, imm16, rd } | MovnMovn64Movewide { hw, imm16, rd } => {
            pretty_move_wide("movn", rd, imm16, hw)
        }
        AndLogShiftAnd32LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        }
        | AndLogShiftAnd64LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => pretty_shifted_reg("and", rd, rn, rm, shift, imm6),
        AndsLogShiftAnds32LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        }
        | AndsLogShiftAnds64LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => pretty_shifted_reg("ands", rd, rn, rm, shift, imm6),
        OrrLogShiftOrr32LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        }
        | OrrLogShiftOrr64LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => pretty_shifted_reg("orr", rd, rn, rm, shift, imm6),
        EorLogShiftEor32LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        }
        | EorLogShiftEor64LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => pretty_shifted_reg("eor", rd, rn, rm, shift, imm6),
        EonEon32LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        }
        | EonEon64LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => pretty_shifted_reg("eon", rd, rn, rm, shift, imm6),
        BicLogShiftBic32LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        }
        | BicLogShiftBic64LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => pretty_shifted_reg("bic", rd, rn, rm, shift, imm6),
        BicsBics32LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        }
        | BicsBics64LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => pretty_shifted_reg("bics", rd, rn, rm, shift, imm6),
        OrnLogShiftOrn32LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        }
        | OrnLogShiftOrn64LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => pretty_shifted_reg("orn", rd, rn, rm, shift, imm6),
        AndLogImmAnd32LogImm { immr, imms, rn, rd } => {
            pretty_logical_imm("and", rd, rn, 0, immr, imms, 32)
        }
        AndLogImmAnd64LogImm {
            n,
            immr,
            imms,
            rn,
            rd,
        } => pretty_logical_imm("and", rd, rn, n, immr, imms, 64),
        AndsLogImmAnds32sLogImm { immr, imms, rn, rd } => {
            pretty_logical_imm("ands", rd, rn, 0, immr, imms, 32)
        }
        AndsLogImmAnds64sLogImm {
            n,
            immr,
            imms,
            rn,
            rd,
        } => pretty_logical_imm("ands", rd, rn, n, immr, imms, 64),
        OrrLogImmOrr32LogImm { immr, imms, rn, rd } => {
            pretty_logical_imm("orr", rd, rn, 0, immr, imms, 32)
        }
        OrrLogImmOrr64LogImm {
            n,
            immr,
            imms,
            rn,
            rd,
        } => pretty_logical_imm("orr", rd, rn, n, immr, imms, 64),
        EorLogImmEor32LogImm { immr, imms, rn, rd } => {
            pretty_logical_imm("eor", rd, rn, 0, immr, imms, 32)
        }
        EorLogImmEor64LogImm {
            n,
            immr,
            imms,
            rn,
            rd,
        } => pretty_logical_imm("eor", rd, rn, n, immr, imms, 64),
        SbfmSbfm32mBitfield { immr, imms, rn, rd } | SbfmSbfm64mBitfield { immr, imms, rn, rd } => {
            pretty_bitfield("sbfm", rd, rn, immr, imms)
        }
        UbfmUbfm32mBitfield { immr, imms, rn, rd } | UbfmUbfm64mBitfield { immr, imms, rn, rd } => {
            pretty_bitfield("ubfm", rd, rn, immr, imms)
        }
        BfmBfm32mBitfield { immr, imms, rn, rd } | BfmBfm64mBitfield { immr, imms, rn, rd } => {
            pretty_bitfield("bfm", rd, rn, immr, imms)
        }
        ExtrExtr32Extract { rm, imms, rn, rd } | ExtrExtr64Extract { rm, imms, rn, rd } => {
            format!(
                "extr {}, {}, {}, #{}",
                reg_name(rd),
                reg_name(rn),
                reg_name(rm),
                imms.raw()
            )
        }
        CselCsel32Condsel { rm, cond, rn, rd } | CselCsel64Condsel { rm, cond, rn, rd } => {
            pretty_cond_select("csel", rd, rn, rm, cond)
        }
        CsincCsinc32Condsel { rm, cond, rn, rd } | CsincCsinc64Condsel { rm, cond, rn, rd } => {
            pretty_cond_select("csinc", rd, rn, rm, cond)
        }
        CsinvCsinv32Condsel { rm, cond, rn, rd } | CsinvCsinv64Condsel { rm, cond, rn, rd } => {
            pretty_cond_select("csinv", rd, rn, rm, cond)
        }
        CsnegCsneg32Condsel { rm, cond, rn, rd } | CsnegCsneg64Condsel { rm, cond, rn, rd } => {
            pretty_cond_select("csneg", rd, rn, rm, cond)
        }
        CcmpImmCcmp32CondcmpImm {
            imm5,
            cond,
            rn,
            nzcv,
        }
        | CcmpImmCcmp64CondcmpImm {
            imm5,
            cond,
            rn,
            nzcv,
        } => pretty_cond_compare("ccmp", rn, unsigned_imm(imm5.raw() as u64), nzcv, cond),
        CcmpRegCcmp32CondcmpReg { rm, cond, rn, nzcv }
        | CcmpRegCcmp64CondcmpReg { rm, cond, rn, nzcv } => {
            pretty_cond_compare("ccmp", rn, reg_name(rm), nzcv, cond)
        }
        CcmnImmCcmn32CondcmpImm {
            imm5,
            cond,
            rn,
            nzcv,
        }
        | CcmnImmCcmn64CondcmpImm {
            imm5,
            cond,
            rn,
            nzcv,
        } => pretty_cond_compare("ccmn", rn, unsigned_imm(imm5.raw() as u64), nzcv, cond),
        CcmnRegCcmn32CondcmpReg { rm, cond, rn, nzcv }
        | CcmnRegCcmn64CondcmpReg { rm, cond, rn, nzcv } => {
            pretty_cond_compare("ccmn", rn, reg_name(rm), nzcv, cond)
        }
        LslvLslv32Dp2src { rm, rn, rd } | LslvLslv64Dp2src { rm, rn, rd } => {
            pretty_three_reg("lslv", rd, rn, rm)
        }
        LsrvLsrv32Dp2src { rm, rn, rd } | LsrvLsrv64Dp2src { rm, rn, rd } => {
            pretty_three_reg("lsrv", rd, rn, rm)
        }
        AsrvAsrv32Dp2src { rm, rn, rd } | AsrvAsrv64Dp2src { rm, rn, rd } => {
            pretty_three_reg("asrv", rd, rn, rm)
        }
        RorvRorv32Dp2src { rm, rn, rd } | RorvRorv64Dp2src { rm, rn, rd } => {
            pretty_three_reg("rorv", rd, rn, rm)
        }
        UdivUdiv32Dp2src { rm, rn, rd } | UdivUdiv64Dp2src { rm, rn, rd } => {
            pretty_three_reg("udiv", rd, rn, rm)
        }
        SdivSdiv32Dp2src { rm, rn, rd } | SdivSdiv64Dp2src { rm, rn, rd } => {
            pretty_three_reg("sdiv", rd, rn, rm)
        }
        MaddMadd32aDp3src { rm, ra, rn, rd } | MaddMadd64aDp3src { rm, ra, rn, rd } => {
            pretty_four_reg("madd", rd, rn, rm, ra)
        }
        MsubMsub32aDp3src { rm, ra, rn, rd } | MsubMsub64aDp3src { rm, ra, rn, rd } => {
            pretty_four_reg("msub", rd, rn, rm, ra)
        }
        SmaddlSmaddl64waDp3src { rm, ra, rn, rd } => pretty_four_reg("smaddl", rd, rn, rm, ra),
        UmaddlUmaddl64waDp3src { rm, ra, rn, rd } => pretty_four_reg("umaddl", rd, rn, rm, ra),
        SmsublSmsubl64waDp3src { rm, ra, rn, rd } => pretty_four_reg("smsubl", rd, rn, rm, ra),
        UmsublUmsubl64waDp3src { rm, ra, rn, rd } => pretty_four_reg("umsubl", rd, rn, rm, ra),
        SmulhSmulh64Dp3src { rm, rn, rd } => pretty_three_reg("smulh", rd, rn, rm),
        UmulhUmulh64Dp3src { rm, rn, rd } => pretty_three_reg("umulh", rd, rn, rm),
        AdcAdc32AddsubCarry { rm, rn, rd } | AdcAdc64AddsubCarry { rm, rn, rd } => {
            pretty_three_reg("adc", rd, rn, rm)
        }
        AdcsAdcs32AddsubCarry { rm, rn, rd } | AdcsAdcs64AddsubCarry { rm, rn, rd } => {
            pretty_three_reg("adcs", rd, rn, rm)
        }
        SbcSbc32AddsubCarry { rm, rn, rd } | SbcSbc64AddsubCarry { rm, rn, rd } => {
            if rn.enc() == 31 {
                format!("ngc {}, {}", reg_name(rd), reg_name(rm))
            } else {
                pretty_three_reg("sbc", rd, rn, rm)
            }
        }
        SbcsSbcs32AddsubCarry { rm, rn, rd } | SbcsSbcs64AddsubCarry { rm, rn, rd } => {
            if rn.enc() == 31 {
                format!("ngcs {}, {}", reg_name(rd), reg_name(rm))
            } else {
                pretty_three_reg("sbcs", rd, rn, rm)
            }
        }
        Crc32Crc32b32cDp2src { rm, rn, rd } => pretty_three_reg("crc32b", rd, rn, rm),
        Crc32Crc32h32cDp2src { rm, rn, rd } => pretty_three_reg("crc32h", rd, rn, rm),
        Crc32Crc32w32cDp2src { rm, rn, rd } => pretty_three_reg("crc32w", rd, rn, rm),
        Crc32Crc32x64cDp2src { rm, rn, rd } => pretty_three_reg("crc32x", rd, rn, rm),
        Crc32cCrc32cb32cDp2src { rm, rn, rd } => pretty_three_reg("crc32cb", rd, rn, rm),
        Crc32cCrc32ch32cDp2src { rm, rn, rd } => pretty_three_reg("crc32ch", rd, rn, rm),
        Crc32cCrc32cw32cDp2src { rm, rn, rd } => pretty_three_reg("crc32cw", rd, rn, rm),
        Crc32cCrc32cx64cDp2src { rm, rn, rd } => pretty_three_reg("crc32cx", rd, rn, rm),
        ClzIntClz32Dp1src { rn, rd } | ClzIntClz64Dp1src { rn, rd } => {
            format!("clz {}, {}", reg_name(rd), reg_name(rn))
        }
        RbitIntRbit32Dp1src { rn, rd } | RbitIntRbit64Dp1src { rn, rd } => {
            format!("rbit {}, {}", reg_name(rd), reg_name(rn))
        }
        RevRev32Dp1src { rn, rd } | RevRev64Dp1src { rn, rd } => {
            format!("rev {}, {}", reg_name(rd), reg_name(rn))
        }
        Rev16IntRev1632Dp1src { rn, rd } | Rev16IntRev1664Dp1src { rn, rd } => {
            format!("rev16 {}, {}", reg_name(rd), reg_name(rn))
        }
        Rev32IntRev3264Dp1src { rn, rd } => format!("rev32 {}, {}", reg_name(rd), reg_name(rn)),
        MrsMrsRsSystemmove { rt } => format!("mrs {}, tpidr_el0", reg_name(rt)),
        BUncondBOnlyBranchImm { imm26 } => pretty_branch("b", pc, imm26),
        BCondBOnlyCondbranch { imm19, cond } => {
            let mnemonic = format!("b.{}", condition_name(cond));
            pretty_branch(&mnemonic, pc, imm19)
        }
        CbzCbz32Compbranch { imm19, rt } | CbzCbz64Compbranch { imm19, rt } => {
            pretty_compare_branch("cbz", rt, pc, imm19)
        }
        CbnzCbnz32Compbranch { imm19, rt } | CbnzCbnz64Compbranch { imm19, rt } => {
            pretty_compare_branch("cbnz", rt, pc, imm19)
        }
        MovzMovz32Movewide { hw, imm16, rd } | MovzMovz64Movewide { hw, imm16, rd } => {
            pretty_move_wide("movz", rd, imm16, hw)
        }
        MovkMovk32Movewide { hw, imm16, rd } | MovkMovk64Movewide { hw, imm16, rd } => {
            pretty_move_wide("movk", rd, imm16, hw)
        }
        TbzTbzOnlyTestbranch { b5, b40, imm14, rt } => {
            pretty_test_branch("tbz", rt, bit_index(b5, b40), pc, imm14)
        }
        TbnzTbnzOnlyTestbranch { b5, b40, imm14, rt } => {
            pretty_test_branch("tbnz", rt, bit_index(b5, b40), pc, imm14)
        }
        LdrImmGenLdr32LdstImmpost { rt, mem }
        | LdrImmGenLdr32LdstImmpre { rt, mem }
        | LdrImmGenLdr32LdstPos { rt, mem }
        | LdrImmGenLdr64LdstImmpost { rt, mem }
        | LdrImmGenLdr64LdstImmpre { rt, mem }
        | LdrImmGenLdr64LdstPos { rt, mem }
        | StrImmGenStr32LdstImmpost { rt, mem }
        | StrImmGenStr32LdstImmpre { rt, mem }
        | StrImmGenStr32LdstPos { rt, mem }
        | StrImmGenStr64LdstImmpost { rt, mem }
        | StrImmGenStr64LdstImmpre { rt, mem }
        | StrImmGenStr64LdstPos { rt, mem }
        | LdrbImmLdrb32LdstImmpost { rt, mem }
        | LdrbImmLdrb32LdstImmpre { rt, mem }
        | LdrbImmLdrb32LdstPos { rt, mem }
        | StrbImmStrb32LdstImmpost { rt, mem }
        | StrbImmStrb32LdstImmpre { rt, mem }
        | StrbImmStrb32LdstPos { rt, mem }
        | LdrhImmLdrh32LdstImmpost { rt, mem }
        | LdrhImmLdrh32LdstImmpre { rt, mem }
        | LdrhImmLdrh32LdstPos { rt, mem }
        | StrhImmStrh32LdstImmpost { rt, mem }
        | StrhImmStrh32LdstImmpre { rt, mem }
        | StrhImmStrh32LdstPos { rt, mem }
        | LdrsbImmLdrsb32LdstImmpost { rt, mem }
        | LdrsbImmLdrsb32LdstImmpre { rt, mem }
        | LdrsbImmLdrsb32LdstPos { rt, mem }
        | LdrsbImmLdrsb64LdstImmpost { rt, mem }
        | LdrsbImmLdrsb64LdstImmpre { rt, mem }
        | LdrsbImmLdrsb64LdstPos { rt, mem }
        | LdrshImmLdrsh32LdstImmpost { rt, mem }
        | LdrshImmLdrsh32LdstImmpre { rt, mem }
        | LdrshImmLdrsh32LdstPos { rt, mem }
        | LdrshImmLdrsh64LdstImmpost { rt, mem }
        | LdrshImmLdrsh64LdstImmpre { rt, mem }
        | LdrshImmLdrsh64LdstPos { rt, mem }
        | LdrswImmLdrsw64LdstImmpost { rt, mem }
        | LdrswImmLdrsw64LdstImmpre { rt, mem }
        | LdrswImmLdrsw64LdstPos { rt, mem }
        | LdurGenLdur32LdstUnscaled { rt, mem }
        | LdurGenLdur64LdstUnscaled { rt, mem }
        | SturGenStur32LdstUnscaled { rt, mem }
        | SturGenStur64LdstUnscaled { rt, mem }
        | LdurbLdurb32LdstUnscaled { rt, mem }
        | SturbSturb32LdstUnscaled { rt, mem }
        | LdurhLdurh32LdstUnscaled { rt, mem }
        | SturhSturh32LdstUnscaled { rt, mem }
        | LdursbLdursb32LdstUnscaled { rt, mem }
        | LdursbLdursb64LdstUnscaled { rt, mem }
        | LdurshLdursh32LdstUnscaled { rt, mem }
        | LdurshLdursh64LdstUnscaled { rt, mem }
        | LdurswLdursw64LdstUnscaled { rt, mem }
        | LdtrLdtr32LdstUnpriv { rt, mem }
        | LdtrLdtr64LdstUnpriv { rt, mem }
        | SttrSttr32LdstUnpriv { rt, mem }
        | SttrSttr64LdstUnpriv { rt, mem }
        | LdtrbLdtrb32LdstUnpriv { rt, mem }
        | SttrbSttrb32LdstUnpriv { rt, mem }
        | LdtrhLdtrh32LdstUnpriv { rt, mem }
        | SttrhSttrh32LdstUnpriv { rt, mem }
        | LdtrsbLdtrsb32LdstUnpriv { rt, mem }
        | LdtrsbLdtrsb64LdstUnpriv { rt, mem }
        | LdtrshLdtrsh32LdstUnpriv { rt, mem }
        | LdtrshLdtrsh64LdstUnpriv { rt, mem }
        | LdtrswLdtrsw64LdstUnpriv { rt, mem } => {
            format!(
                "{} {}, {}",
                insn.mnemonic().to_lowercase(),
                reg_name(rt),
                mem_operand(mem)
            )
        }
        LdpGenLdp32LdstpairPost { rt2, rt, mem }
        | LdpGenLdp32LdstpairPre { rt2, rt, mem }
        | LdpGenLdp32LdstpairOff { rt2, rt, mem }
        | LdpGenLdp64LdstpairPost { rt2, rt, mem }
        | LdpGenLdp64LdstpairPre { rt2, rt, mem }
        | LdpGenLdp64LdstpairOff { rt2, rt, mem }
        | StpGenStp32LdstpairPost { rt2, rt, mem }
        | StpGenStp32LdstpairPre { rt2, rt, mem }
        | StpGenStp32LdstpairOff { rt2, rt, mem }
        | StpGenStp64LdstpairPost { rt2, rt, mem }
        | StpGenStp64LdstpairPre { rt2, rt, mem }
        | StpGenStp64LdstpairOff { rt2, rt, mem }
        | LdpswLdpsw64LdstpairPost { rt2, rt, mem }
        | LdpswLdpsw64LdstpairPre { rt2, rt, mem }
        | LdpswLdpsw64LdstpairOff { rt2, rt, mem } => {
            format!(
                "{} {}, {}, {}",
                insn.mnemonic().to_lowercase(),
                reg_name(rt),
                reg_name(rt2),
                mem_operand(mem)
            )
        }
        LdrRegGenLdr32LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        }
        | LdrRegGenLdr64LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        }
        | StrRegGenStr32LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        }
        | StrRegGenStr64LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        }
        | LdrbRegLdrb32bLdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        }
        | StrbRegStrb32bLdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        }
        | LdrhRegLdrh32LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        }
        | StrhRegStrh32LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        }
        | LdrsbRegLdrsb32bLdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        }
        | LdrsbRegLdrsb64bLdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        }
        | LdrshRegLdrsh32LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        }
        | LdrshRegLdrsh64LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        }
        | LdrswRegLdrsw64LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => pretty_reg_offset(insn, rt, rn, rm, option, s),
        LdrbRegLdrb32blLdstRegoff { rm, s, rn, rt }
        | StrbRegStrb32blLdstRegoff { rm, s, rn, rt }
        | LdrsbRegLdrsb32blLdstRegoff { rm, s, rn, rt }
        | LdrsbRegLdrsb64blLdstRegoff { rm, s, rn, rt } => {
            pretty_reg_offset(insn, rt, rn, rm, 0b011, s)
        }
        LdrLitGenLdr32Loadlit { rt, .. }
        | LdrLitGenLdr64Loadlit { rt, .. }
        | LdrswLitLdrsw64Loadlit { rt, .. } => pretty_pc_relative(
            &insn.mnemonic().to_lowercase(),
            rt,
            pc.and_then(|pc| insn.literal_address(pc)),
            pc,
        ),
        PrfmImmPrfmPLdstPos { imm12, rn, rt } => {
            format!(
                "prfm #{rt}, [{}, {}]",
                reg_name(rn),
                imm(i64::from(imm12.raw()) * 8)
            )
        }
        PrfmLitPrfmPLoadlit { rt, .. } => format!("prfm #{rt}, <literal>"),
        PrfmRegPrfmPLdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => format!(
            "prfm #{rt}, [{}, {}]",
            reg_name(rn),
            index_operand(rm, option, if s == 1 { 3 } else { 0 })
        ),
        NopNopHiHints {} => "nop".to_string(),
        BtiBtiHbHints { op2 } => match op2 >> 1 {
            0b00 => "bti".to_string(),
            0b01 => "bti c".to_string(),
            0b10 => "bti j".to_string(),
            _ => "bti jc".to_string(),
        },
        DmbDmbBoBarriers { crm } => format!("dmb {}", barrier_option(crm)),
        DsbDsbBoBarriers { crm: 0b0000 } => "ssbb".to_string(),
        DsbDsbBoBarriers { crm: 0b0100 } => "pssbb".to_string(),
        DsbDsbBoBarriers { crm } => format!("dsb {}", barrier_option(crm)),
        IsbIsbBiBarriers { crm: 0b1111 } => "isb".to_string(),
        IsbIsbBiBarriers { crm } => format!("isb #{crm}"),
        LdarLdarLr32Ldstord { rn, rt }
        | LdarLdarLr64Ldstord { rn, rt }
        | LdarbLdarbLr32Ldstord { rn, rt }
        | LdarhLdarhLr32Ldstord { rn, rt }
        | StlrStlrSl32Ldstord { rn, rt }
        | StlrStlrSl64Ldstord { rn, rt }
        | StlrbStlrbSl32Ldstord { rn, rt }
        | StlrhStlrhSl32Ldstord { rn, rt }
        | LdaprLdapr32lMemop { rn, rt }
        | LdaprLdapr64lMemop { rn, rt }
        | LdaprbLdaprb32lMemop { rn, rt }
        | LdaprhLdaprh32lMemop { rn, rt } => format!(
            "{} {}, [{}]",
            insn.mnemonic().to_lowercase(),
            reg_name(rt),
            reg_name(rn)
        ),
        LdaddLdadd32Memop { rs, rn, rt }
        | LdaddLdadda32Memop { rs, rn, rt }
        | LdaddLdaddal32Memop { rs, rn, rt }
        | LdaddLdaddl32Memop { rs, rn, rt }
        | LdaddLdadd64Memop { rs, rn, rt }
        | LdaddLdadda64Memop { rs, rn, rt }
        | LdaddLdaddal64Memop { rs, rn, rt }
        | LdaddLdaddl64Memop { rs, rn, rt }
        | LdaddbLdaddb32Memop { rs, rn, rt }
        | LdaddbLdaddab32Memop { rs, rn, rt }
        | LdaddbLdaddalb32Memop { rs, rn, rt }
        | LdaddbLdaddlb32Memop { rs, rn, rt }
        | LdaddhLdaddh32Memop { rs, rn, rt }
        | LdaddhLdaddah32Memop { rs, rn, rt }
        | LdaddhLdaddalh32Memop { rs, rn, rt }
        | LdaddhLdaddlh32Memop { rs, rn, rt }
        | LdclrLdclr32Memop { rs, rn, rt }
        | LdclrLdclra32Memop { rs, rn, rt }
        | LdclrLdclral32Memop { rs, rn, rt }
        | LdclrLdclrl32Memop { rs, rn, rt }
        | LdclrLdclr64Memop { rs, rn, rt }
        | LdclrLdclra64Memop { rs, rn, rt }
        | LdclrLdclral64Memop { rs, rn, rt }
        | LdclrLdclrl64Memop { rs, rn, rt }
        | LdclrbLdclrb32Memop { rs, rn, rt }
        | LdclrbLdclrab32Memop { rs, rn, rt }
        | LdclrbLdclralb32Memop { rs, rn, rt }
        | LdclrbLdclrlb32Memop { rs, rn, rt }
        | LdclrhLdclrh32Memop { rs, rn, rt }
        | LdclrhLdclrah32Memop { rs, rn, rt }
        | LdclrhLdclralh32Memop { rs, rn, rt }
        | LdclrhLdclrlh32Memop { rs, rn, rt }
        | LdeorLdeor32Memop { rs, rn, rt }
        | LdeorLdeora32Memop { rs, rn, rt }
        | LdeorLdeoral32Memop { rs, rn, rt }
        | LdeorLdeorl32Memop { rs, rn, rt }
        | LdeorLdeor64Memop { rs, rn, rt }
        | LdeorLdeora64Memop { rs, rn, rt }
        | LdeorLdeoral64Memop { rs, rn, rt }
        | LdeorLdeorl64Memop { rs, rn, rt }
        | LdeorbLdeorb32Memop { rs, rn, rt }
        | LdeorbLdeorab32Memop { rs, rn, rt }
        | LdeorbLdeoralb32Memop { rs, rn, rt }
        | LdeorbLdeorlb32Memop { rs, rn, rt }
        | LdeorhLdeorh32Memop { rs, rn, rt }
        | LdeorhLdeorah32Memop { rs, rn, rt }
        | LdeorhLdeoralh32Memop { rs, rn, rt }
        | LdeorhLdeorlh32Memop { rs, rn, rt }
        | LdsetLdset32Memop { rs, rn, rt }
        | LdsetLdseta32Memop { rs, rn, rt }
        | LdsetLdsetal32Memop { rs, rn, rt }
        | LdsetLdsetl32Memop { rs, rn, rt }
        | LdsetLdset64Memop { rs, rn, rt }
        | LdsetLdseta64Memop { rs, rn, rt }
        | LdsetLdsetal64Memop { rs, rn, rt }
        | LdsetLdsetl64Memop { rs, rn, rt }
        | LdsetbLdsetb32Memop { rs, rn, rt }
        | LdsetbLdsetab32Memop { rs, rn, rt }
        | LdsetbLdsetalb32Memop { rs, rn, rt }
        | LdsetbLdsetlb32Memop { rs, rn, rt }
        | LdsethLdseth32Memop { rs, rn, rt }
        | LdsethLdsetah32Memop { rs, rn, rt }
        | LdsethLdsetalh32Memop { rs, rn, rt }
        | LdsethLdsetlh32Memop { rs, rn, rt }
        | LdsmaxLdsmax32Memop { rs, rn, rt }
        | LdsmaxLdsmaxa32Memop { rs, rn, rt }
        | LdsmaxLdsmaxal32Memop { rs, rn, rt }
        | LdsmaxLdsmaxl32Memop { rs, rn, rt }
        | LdsmaxLdsmax64Memop { rs, rn, rt }
        | LdsmaxLdsmaxa64Memop { rs, rn, rt }
        | LdsmaxLdsmaxal64Memop { rs, rn, rt }
        | LdsmaxLdsmaxl64Memop { rs, rn, rt }
        | LdsmaxbLdsmaxb32Memop { rs, rn, rt }
        | LdsmaxbLdsmaxab32Memop { rs, rn, rt }
        | LdsmaxbLdsmaxalb32Memop { rs, rn, rt }
        | LdsmaxbLdsmaxlb32Memop { rs, rn, rt }
        | LdsmaxhLdsmaxh32Memop { rs, rn, rt }
        | LdsmaxhLdsmaxah32Memop { rs, rn, rt }
        | LdsmaxhLdsmaxalh32Memop { rs, rn, rt }
        | LdsmaxhLdsmaxlh32Memop { rs, rn, rt }
        | LdsminLdsmin32Memop { rs, rn, rt }
        | LdsminLdsmina32Memop { rs, rn, rt }
        | LdsminLdsminal32Memop { rs, rn, rt }
        | LdsminLdsminl32Memop { rs, rn, rt }
        | LdsminLdsmin64Memop { rs, rn, rt }
        | LdsminLdsmina64Memop { rs, rn, rt }
        | LdsminLdsminal64Memop { rs, rn, rt }
        | LdsminLdsminl64Memop { rs, rn, rt }
        | LdsminbLdsminb32Memop { rs, rn, rt }
        | LdsminbLdsminab32Memop { rs, rn, rt }
        | LdsminbLdsminalb32Memop { rs, rn, rt }
        | LdsminbLdsminlb32Memop { rs, rn, rt }
        | LdsminhLdsminh32Memop { rs, rn, rt }
        | LdsminhLdsminah32Memop { rs, rn, rt }
        | LdsminhLdsminalh32Memop { rs, rn, rt }
        | LdsminhLdsminlh32Memop { rs, rn, rt }
        | LdumaxLdumax32Memop { rs, rn, rt }
        | LdumaxLdumaxa32Memop { rs, rn, rt }
        | LdumaxLdumaxal32Memop { rs, rn, rt }
        | LdumaxLdumaxl32Memop { rs, rn, rt }
        | LdumaxLdumax64Memop { rs, rn, rt }
        | LdumaxLdumaxa64Memop { rs, rn, rt }
        | LdumaxLdumaxal64Memop { rs, rn, rt }
        | LdumaxLdumaxl64Memop { rs, rn, rt }
        | LdumaxbLdumaxb32Memop { rs, rn, rt }
        | LdumaxbLdumaxab32Memop { rs, rn, rt }
        | LdumaxbLdumaxalb32Memop { rs, rn, rt }
        | LdumaxbLdumaxlb32Memop { rs, rn, rt }
        | LdumaxhLdumaxh32Memop { rs, rn, rt }
        | LdumaxhLdumaxah32Memop { rs, rn, rt }
        | LdumaxhLdumaxalh32Memop { rs, rn, rt }
        | LdumaxhLdumaxlh32Memop { rs, rn, rt }
        | LduminLdumin32Memop { rs, rn, rt }
        | LduminLdumina32Memop { rs, rn, rt }
        | LduminLduminal32Memop { rs, rn, rt }
        | LduminLduminl32Memop { rs, rn, rt }
        | LduminLdumin64Memop { rs, rn, rt }
        | LduminLdumina64Memop { rs, rn, rt }
        | LduminLduminal64Memop { rs, rn, rt }
        | LduminLduminl64Memop { rs, rn, rt }
        | LduminbLduminb32Memop { rs, rn, rt }
        | LduminbLduminab32Memop { rs, rn, rt }
        | LduminbLduminalb32Memop { rs, rn, rt }
        | LduminbLduminlb32Memop { rs, rn, rt }
        | LduminhLduminh32Memop { rs, rn, rt }
        | LduminhLduminah32Memop { rs, rn, rt }
        | LduminhLduminalh32Memop { rs, rn, rt }
        | LduminhLduminlh32Memop { rs, rn, rt }
        | SwpSwp32Memop { rs, rn, rt }
        | SwpSwpa32Memop { rs, rn, rt }
        | SwpSwpal32Memop { rs, rn, rt }
        | SwpSwpl32Memop { rs, rn, rt }
        | SwpSwp64Memop { rs, rn, rt }
        | SwpSwpa64Memop { rs, rn, rt }
        | SwpSwpal64Memop { rs, rn, rt }
        | SwpSwpl64Memop { rs, rn, rt }
        | SwpbSwpb32Memop { rs, rn, rt }
        | SwpbSwpab32Memop { rs, rn, rt }
        | SwpbSwpalb32Memop { rs, rn, rt }
        | SwpbSwplb32Memop { rs, rn, rt }
        | SwphSwph32Memop { rs, rn, rt }
        | SwphSwpah32Memop { rs, rn, rt }
        | SwphSwpalh32Memop { rs, rn, rt }
        | SwphSwplh32Memop { rs, rn, rt }
        | CasCasC32Comswap { rs, rn, rt }
        | CasCasaC32Comswap { rs, rn, rt }
        | CasCasalC32Comswap { rs, rn, rt }
        | CasCaslC32Comswap { rs, rn, rt }
        | CasCasC64Comswap { rs, rn, rt }
        | CasCasaC64Comswap { rs, rn, rt }
        | CasCasalC64Comswap { rs, rn, rt }
        | CasCaslC64Comswap { rs, rn, rt }
        | CasbCasbC32Comswap { rs, rn, rt }
        | CasbCasabC32Comswap { rs, rn, rt }
        | CasbCasalbC32Comswap { rs, rn, rt }
        | CasbCaslbC32Comswap { rs, rn, rt }
        | CashCashC32Comswap { rs, rn, rt }
        | CashCasahC32Comswap { rs, rn, rt }
        | CashCasalhC32Comswap { rs, rn, rt }
        | CashCaslhC32Comswap { rs, rn, rt } => format!(
            "{} {}, {}, [{}]",
            insn.mnemonic().to_lowercase(),
            reg_name(rs),
            reg_name(rt),
            reg_name(rn)
        ),
        // A9a SIMD&FP.
        LdrImmFpsimdLdrBLdstImmpost { .. }
        | LdrImmFpsimdLdrHLdstImmpost { .. }
        | LdrImmFpsimdLdrSLdstImmpost { .. }
        | LdrImmFpsimdLdrDLdstImmpost { .. }
        | LdrImmFpsimdLdrQLdstImmpost { .. }
        | LdrImmFpsimdLdrBLdstImmpre { .. }
        | LdrImmFpsimdLdrHLdstImmpre { .. }
        | LdrImmFpsimdLdrSLdstImmpre { .. }
        | LdrImmFpsimdLdrDLdstImmpre { .. }
        | LdrImmFpsimdLdrQLdstImmpre { .. }
        | LdrImmFpsimdLdrBLdstPos { .. }
        | LdrImmFpsimdLdrHLdstPos { .. }
        | LdrImmFpsimdLdrSLdstPos { .. }
        | LdrImmFpsimdLdrDLdstPos { .. }
        | LdrImmFpsimdLdrQLdstPos { .. }
        | StrImmFpsimdStrBLdstImmpost { .. }
        | StrImmFpsimdStrHLdstImmpost { .. }
        | StrImmFpsimdStrSLdstImmpost { .. }
        | StrImmFpsimdStrDLdstImmpost { .. }
        | StrImmFpsimdStrQLdstImmpost { .. }
        | StrImmFpsimdStrBLdstImmpre { .. }
        | StrImmFpsimdStrHLdstImmpre { .. }
        | StrImmFpsimdStrSLdstImmpre { .. }
        | StrImmFpsimdStrDLdstImmpre { .. }
        | StrImmFpsimdStrQLdstImmpre { .. }
        | StrImmFpsimdStrBLdstPos { .. }
        | StrImmFpsimdStrHLdstPos { .. }
        | StrImmFpsimdStrSLdstPos { .. }
        | StrImmFpsimdStrDLdstPos { .. }
        | StrImmFpsimdStrQLdstPos { .. }
        | LdurFpsimdLdurBLdstUnscaled { .. }
        | LdurFpsimdLdurHLdstUnscaled { .. }
        | LdurFpsimdLdurSLdstUnscaled { .. }
        | LdurFpsimdLdurDLdstUnscaled { .. }
        | LdurFpsimdLdurQLdstUnscaled { .. }
        | SturFpsimdSturBLdstUnscaled { .. }
        | SturFpsimdSturHLdstUnscaled { .. }
        | SturFpsimdSturSLdstUnscaled { .. }
        | SturFpsimdSturDLdstUnscaled { .. }
        | SturFpsimdSturQLdstUnscaled { .. }
        | LdpFpsimdLdpSLdstpairPost { .. }
        | LdpFpsimdLdpDLdstpairPost { .. }
        | LdpFpsimdLdpQLdstpairPost { .. }
        | LdpFpsimdLdpSLdstpairPre { .. }
        | LdpFpsimdLdpDLdstpairPre { .. }
        | LdpFpsimdLdpQLdstpairPre { .. }
        | LdpFpsimdLdpSLdstpairOff { .. }
        | LdpFpsimdLdpDLdstpairOff { .. }
        | LdpFpsimdLdpQLdstpairOff { .. }
        | StpFpsimdStpSLdstpairPost { .. }
        | StpFpsimdStpDLdstpairPost { .. }
        | StpFpsimdStpQLdstpairPost { .. }
        | StpFpsimdStpSLdstpairPre { .. }
        | StpFpsimdStpDLdstpairPre { .. }
        | StpFpsimdStpQLdstpairPre { .. }
        | StpFpsimdStpSLdstpairOff { .. }
        | StpFpsimdStpDLdstpairOff { .. }
        | StpFpsimdStpQLdstpairOff { .. }
        | Ld1AdvsimdMultLd1AsisdlseR11v { .. }
        | Ld1AdvsimdMultLd1AsisdlseR22v { .. }
        | Ld1AdvsimdMultLd1AsisdlseR33v { .. }
        | Ld1AdvsimdMultLd1AsisdlseR44v { .. }
        | Ld1AdvsimdMultLd1AsisdlsepI1I1 { .. }
        | Ld1AdvsimdMultLd1AsisdlsepR1R1 { .. }
        | Ld1AdvsimdMultLd1AsisdlsepI2I2 { .. }
        | Ld1AdvsimdMultLd1AsisdlsepR2R2 { .. }
        | Ld1AdvsimdMultLd1AsisdlsepI3I3 { .. }
        | Ld1AdvsimdMultLd1AsisdlsepR3R3 { .. }
        | Ld1AdvsimdMultLd1AsisdlsepI4I4 { .. }
        | Ld1AdvsimdMultLd1AsisdlsepR4R4 { .. }
        | St1AdvsimdMultSt1AsisdlseR11v { .. }
        | St1AdvsimdMultSt1AsisdlseR22v { .. }
        | St1AdvsimdMultSt1AsisdlseR33v { .. }
        | St1AdvsimdMultSt1AsisdlseR44v { .. }
        | St1AdvsimdMultSt1AsisdlsepI1I1 { .. }
        | St1AdvsimdMultSt1AsisdlsepR1R1 { .. }
        | St1AdvsimdMultSt1AsisdlsepI2I2 { .. }
        | St1AdvsimdMultSt1AsisdlsepR2R2 { .. }
        | St1AdvsimdMultSt1AsisdlsepI3I3 { .. }
        | St1AdvsimdMultSt1AsisdlsepR3R3 { .. }
        | St1AdvsimdMultSt1AsisdlsepI4I4 { .. }
        | St1AdvsimdMultSt1AsisdlsepR4R4 { .. }
        | DupAdvsimdEltDupAsisdoneOnly { .. }
        | DupAdvsimdEltDupAsimdinsDvV { .. }
        | DupAdvsimdGenDupAsimdinsDrR { .. }
        | InsAdvsimdEltInsAsimdinsIvV { .. }
        | InsAdvsimdGenInsAsimdinsIrR { .. }
        | UmovAdvsimdUmovAsimdinsWW { .. }
        | UmovAdvsimdUmovAsimdinsXX { .. }
        | MoviAdvsimdMoviAsimdimmNB { .. }
        | MoviAdvsimdMoviAsimdimmLHl { .. }
        | MoviAdvsimdMoviAsimdimmLSl { .. }
        | MoviAdvsimdMoviAsimdimmMSm { .. }
        | MoviAdvsimdMoviAsimdimmDDs { .. }
        | MoviAdvsimdMoviAsimdimmD2D { .. }
        | MvniAdvsimdMvniAsimdimmLHl { .. }
        | MvniAdvsimdMvniAsimdimmLSl { .. }
        | MvniAdvsimdMvniAsimdimmMSm { .. }
        | FmovFloatGenFmovS32Float2int { .. }
        | FmovFloatGenFmov32sFloat2int { .. }
        | FmovFloatGenFmovD64Float2int { .. }
        | FmovFloatGenFmovV64iFloat2int { .. }
        | FmovFloatGenFmov64dFloat2int { .. }
        | FmovFloatGenFmov64vxFloat2int { .. }
        | FmovFloatFmovSFloatdp1 { .. }
        | FmovFloatFmovDFloatdp1 { .. }
        | CmeqAdvsimdRegCmeqAsisdsameOnly { .. }
        | CmeqAdvsimdRegCmeqAsimdsameOnly { .. }
        | CmeqAdvsimdZeroCmeqAsisdmiscZ { .. }
        | CmeqAdvsimdZeroCmeqAsimdmiscZ { .. }
        | CmhiAdvsimdCmhiAsisdsameOnly { .. }
        | CmhiAdvsimdCmhiAsimdsameOnly { .. }
        | CmhsAdvsimdCmhsAsisdsameOnly { .. }
        | CmhsAdvsimdCmhsAsimdsameOnly { .. }
        | CmgtAdvsimdRegCmgtAsisdsameOnly { .. }
        | CmgtAdvsimdRegCmgtAsimdsameOnly { .. }
        | CmgtAdvsimdZeroCmgtAsisdmiscZ { .. }
        | CmgtAdvsimdZeroCmgtAsimdmiscZ { .. }
        | CmgeAdvsimdRegCmgeAsisdsameOnly { .. }
        | CmgeAdvsimdRegCmgeAsimdsameOnly { .. }
        | CmgeAdvsimdZeroCmgeAsisdmiscZ { .. }
        | CmgeAdvsimdZeroCmgeAsimdmiscZ { .. }
        | CmtstAdvsimdCmtstAsisdsameOnly { .. }
        | CmtstAdvsimdCmtstAsimdsameOnly { .. }
        | AndAdvsimdAndAsimdsameOnly { .. }
        | OrrAdvsimdRegOrrAsimdsameOnly { .. }
        | EorAdvsimdEorAsimdsameOnly { .. }
        | BicAdvsimdRegBicAsimdsameOnly { .. }
        | OrnAdvsimdOrnAsimdsameOnly { .. }
        | BitAdvsimdBitAsimdsameOnly { .. }
        | BifAdvsimdBifAsimdsameOnly { .. }
        | BslAdvsimdBslAsimdsameOnly { .. }
        | NotAdvsimdNotAsimdmiscR { .. }
        | AddAdvsimdAddAsisdsameOnly { .. }
        | AddAdvsimdAddAsimdsameOnly { .. }
        | SubAdvsimdSubAsisdsameOnly { .. }
        | SubAdvsimdSubAsimdsameOnly { .. }
        | AddpAdvsimdVecAddpAsimdsameOnly { .. }
        | AddpAdvsimdPairAddpAsisdpairOnly { .. }
        | UmaxpAdvsimdUmaxpAsimdsameOnly { .. }
        | UminpAdvsimdUminpAsimdsameOnly { .. }
        | AddvAdvsimdAddvAsimdallOnly { .. }
        | UmaxvAdvsimdUmaxvAsimdallOnly { .. }
        | UminvAdvsimdUminvAsimdallOnly { .. }
        | ShrnAdvsimdShrnAsimdshfN { .. }
        | UshrAdvsimdUshrAsisdshfR { .. }
        | UshrAdvsimdUshrAsimdshfR { .. }
        | ShlAdvsimdShlAsisdshfR { .. }
        | ShlAdvsimdShlAsimdshfR { .. }
        | UshllAdvsimdUshllAsimdshfL { .. }
        | XtnAdvsimdXtnAsimdmiscN { .. }
        | ExtAdvsimdExtAsimdextOnly { .. }
        | Rev16AdvsimdRev16AsimdmiscR { .. }
        | Rev32AdvsimdRev32AsimdmiscR { .. }
        | Rev64AdvsimdRev64AsimdmiscR { .. }
        | CntAdvsimdCntAsimdmiscR { .. }
        | TblAdvsimdTblAsimdtblL11 { .. } => pretty_simd(insn),
        MsrImmMsrSiPstate { crm } => format!("msr pan, #{crm}"),
        BlBlOnlyBranchImm { imm26 } => pretty_branch("bl", pc, imm26),
        BrBr64BranchReg { rn } => format!("br {}", reg_name(rn)),
        BlrBlr64BranchReg { rn } => format!("blr {}", reg_name(rn)),
        RetRet64rBranchReg { rn } if rn.enc() == 30 => "ret".to_string(),
        RetRet64rBranchReg { rn } => format!("ret {}", reg_name(rn)),
        SvcSvcExException { imm16 } => format!("svc {}", imm(imm16.value())),
    }
}

/// A9a SIMD&FP forms, in LLVM's syntax (for traces and reproducer comments).
fn pretty_simd(insn: A64Insn) -> String {
    use A64Insn::*;
    let mnemonic = insn.mnemonic().to_lowercase();
    let encoding = insn.key().split('.').nth(1).unwrap_or_default();
    // `LDR_Q_ldst_pos` -> `q`: the scalar register of a load/store.
    let scalar = encoding.split('_').nth(1).unwrap_or("?").to_lowercase();
    let arr = |size: u8, q: u8| {
        ["8b", "16b", "4h", "8h", "2s", "4s", "1d", "2d"][usize::from(size * 2 + q)].to_string()
    };
    let vr = |n: u8, arrangement: &str| format!("v{n}.{arrangement}");
    let imm5_size = |imm5: A64Imm| (imm5.raw() & 0b1111).trailing_zeros().min(3) as u8;
    let elem_letter = |size: u8| ["b", "h", "s", "d"][usize::from(size)];
    let shift_esize = |immh: A64Imm| 8_u32 << (31 - (immh.raw() & 0b1111).leading_zeros());
    match insn {
        LdrImmFpsimdLdrBLdstImmpost { rt, mem }
        | LdrImmFpsimdLdrHLdstImmpost { rt, mem }
        | LdrImmFpsimdLdrSLdstImmpost { rt, mem }
        | LdrImmFpsimdLdrDLdstImmpost { rt, mem }
        | LdrImmFpsimdLdrQLdstImmpost { rt, mem }
        | LdrImmFpsimdLdrBLdstImmpre { rt, mem }
        | LdrImmFpsimdLdrHLdstImmpre { rt, mem }
        | LdrImmFpsimdLdrSLdstImmpre { rt, mem }
        | LdrImmFpsimdLdrDLdstImmpre { rt, mem }
        | LdrImmFpsimdLdrQLdstImmpre { rt, mem }
        | LdrImmFpsimdLdrBLdstPos { rt, mem }
        | LdrImmFpsimdLdrHLdstPos { rt, mem }
        | LdrImmFpsimdLdrSLdstPos { rt, mem }
        | LdrImmFpsimdLdrDLdstPos { rt, mem }
        | LdrImmFpsimdLdrQLdstPos { rt, mem }
        | StrImmFpsimdStrBLdstImmpost { rt, mem }
        | StrImmFpsimdStrHLdstImmpost { rt, mem }
        | StrImmFpsimdStrSLdstImmpost { rt, mem }
        | StrImmFpsimdStrDLdstImmpost { rt, mem }
        | StrImmFpsimdStrQLdstImmpost { rt, mem }
        | StrImmFpsimdStrBLdstImmpre { rt, mem }
        | StrImmFpsimdStrHLdstImmpre { rt, mem }
        | StrImmFpsimdStrSLdstImmpre { rt, mem }
        | StrImmFpsimdStrDLdstImmpre { rt, mem }
        | StrImmFpsimdStrQLdstImmpre { rt, mem }
        | StrImmFpsimdStrBLdstPos { rt, mem }
        | StrImmFpsimdStrHLdstPos { rt, mem }
        | StrImmFpsimdStrSLdstPos { rt, mem }
        | StrImmFpsimdStrDLdstPos { rt, mem }
        | StrImmFpsimdStrQLdstPos { rt, mem }
        | LdurFpsimdLdurBLdstUnscaled { rt, mem }
        | LdurFpsimdLdurHLdstUnscaled { rt, mem }
        | LdurFpsimdLdurSLdstUnscaled { rt, mem }
        | LdurFpsimdLdurDLdstUnscaled { rt, mem }
        | LdurFpsimdLdurQLdstUnscaled { rt, mem }
        | SturFpsimdSturBLdstUnscaled { rt, mem }
        | SturFpsimdSturHLdstUnscaled { rt, mem }
        | SturFpsimdSturSLdstUnscaled { rt, mem }
        | SturFpsimdSturDLdstUnscaled { rt, mem }
        | SturFpsimdSturQLdstUnscaled { rt, mem } => {
            format!("{mnemonic} {scalar}{rt}, {}", mem_operand(mem))
        }
        LdpFpsimdLdpSLdstpairPost { rt2, rt, mem }
        | LdpFpsimdLdpDLdstpairPost { rt2, rt, mem }
        | LdpFpsimdLdpQLdstpairPost { rt2, rt, mem }
        | LdpFpsimdLdpSLdstpairPre { rt2, rt, mem }
        | LdpFpsimdLdpDLdstpairPre { rt2, rt, mem }
        | LdpFpsimdLdpQLdstpairPre { rt2, rt, mem }
        | LdpFpsimdLdpSLdstpairOff { rt2, rt, mem }
        | LdpFpsimdLdpDLdstpairOff { rt2, rt, mem }
        | LdpFpsimdLdpQLdstpairOff { rt2, rt, mem }
        | StpFpsimdStpSLdstpairPost { rt2, rt, mem }
        | StpFpsimdStpDLdstpairPost { rt2, rt, mem }
        | StpFpsimdStpQLdstpairPost { rt2, rt, mem }
        | StpFpsimdStpSLdstpairPre { rt2, rt, mem }
        | StpFpsimdStpDLdstpairPre { rt2, rt, mem }
        | StpFpsimdStpQLdstpairPre { rt2, rt, mem }
        | StpFpsimdStpSLdstpairOff { rt2, rt, mem }
        | StpFpsimdStpDLdstpairOff { rt2, rt, mem }
        | StpFpsimdStpQLdstpairOff { rt2, rt, mem } => {
            format!(
                "{mnemonic} {scalar}{rt}, {scalar}{rt2}, {}",
                mem_operand(mem)
            )
        }
        _ => {
            if let Some(mem) = insn.fpsimd_mem() {
                // LD1/ST1 (multiple structures).
                let word = insn.encode().unwrap_or(0);
                let (q, size, rt) = ((word >> 30) & 1, (word >> 10) & 0b11, word & 0b1_1111);
                let regs = encoding
                    .chars()
                    .rev()
                    .find_map(|ch| ch.to_digit(10))
                    .unwrap_or(1);
                let list = (0..regs)
                    .map(|r| vr(((rt + r) % 32) as u8, &arr(size as u8, q as u8)))
                    .collect::<Vec<_>>()
                    .join(", ");
                let post = match mem.writeback {
                    Some(A64FpSimdWriteback::Imm(amount)) => format!(", #{amount}"),
                    Some(A64FpSimdWriteback::Reg(index)) => format!(", {}", reg_name(index)),
                    None => String::new(),
                };
                return format!("{mnemonic} {{{list}}}, [{}]{post}", reg_name(mem.base));
            }
            pretty_simd_register(
                insn,
                &mnemonic,
                &arr,
                &vr,
                &imm5_size,
                &elem_letter,
                &shift_esize,
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn pretty_simd_register(
    insn: A64Insn,
    mnemonic: &str,
    arr: &dyn Fn(u8, u8) -> String,
    vr: &dyn Fn(u8, &str) -> String,
    imm5_size: &dyn Fn(A64Imm) -> u8,
    elem_letter: &dyn Fn(u8) -> &'static str,
    shift_esize: &dyn Fn(A64Imm) -> u32,
) -> String {
    use A64Insn::*;
    let word = insn.encode().unwrap_or(0);
    match insn {
        DupAdvsimdEltDupAsisdoneOnly { imm5, rn, rd } => {
            let size = imm5_size(imm5);
            let letter = elem_letter(size);
            format!(
                "mov {letter}{rd}, v{rn}.{letter}[{}]",
                imm5.raw() >> (size + 1)
            )
        }
        DupAdvsimdEltDupAsimdinsDvV { q, imm5, rn, rd } => {
            let size = imm5_size(imm5);
            format!(
                "dup {}, v{rn}.{}[{}]",
                vr(rd, &arr(size, q)),
                elem_letter(size),
                imm5.raw() >> (size + 1)
            )
        }
        DupAdvsimdGenDupAsimdinsDrR { q, imm5, rn, rd } => {
            let size = imm5_size(imm5);
            let src = if size == 3 {
                A64Reg::x(rn.enc())
            } else {
                A64Reg::w(rn.enc())
            };
            format!("dup {}, {}", vr(rd, &arr(size, q)), reg_name(src))
        }
        InsAdvsimdEltInsAsimdinsIvV { imm5, imm4, rn, rd } => {
            let size = imm5_size(imm5);
            let letter = elem_letter(size);
            format!(
                "mov v{rd}.{letter}[{}], v{rn}.{letter}[{}]",
                imm5.raw() >> (size + 1),
                imm4.raw() >> size
            )
        }
        InsAdvsimdGenInsAsimdinsIrR { imm5, rn, rd } => {
            let size = imm5_size(imm5);
            let src = if size == 3 {
                A64Reg::x(rn.enc())
            } else {
                A64Reg::w(rn.enc())
            };
            format!(
                "mov v{rd}.{}[{}], {}",
                elem_letter(size),
                imm5.raw() >> (size + 1),
                reg_name(src)
            )
        }
        UmovAdvsimdUmovAsimdinsWW { imm5, rn, rd } | UmovAdvsimdUmovAsimdinsXX { imm5, rn, rd } => {
            let size = imm5_size(imm5);
            format!(
                "umov {}, v{rn}.{}[{}]",
                reg_name(rd),
                elem_letter(size),
                imm5.raw() >> (size + 1)
            )
        }
        MoviAdvsimdMoviAsimdimmNB { rd, .. }
        | MoviAdvsimdMoviAsimdimmLHl { rd, .. }
        | MoviAdvsimdMoviAsimdimmLSl { rd, .. }
        | MoviAdvsimdMoviAsimdimmMSm { rd, .. }
        | MoviAdvsimdMoviAsimdimmDDs { rd, .. }
        | MoviAdvsimdMoviAsimdimmD2D { rd, .. }
        | MvniAdvsimdMvniAsimdimmLHl { rd, .. }
        | MvniAdvsimdMvniAsimdimmLSl { rd, .. }
        | MvniAdvsimdMvniAsimdimmMSm { rd, .. } => {
            let imm8 = ((word >> 16) & 0b111) << 5 | ((word >> 5) & 0b1_1111);
            format!(
                "{mnemonic} v{rd} (q={} op={} cmode={:#06b} imm8={imm8:#04x})",
                (word >> 30) & 1,
                (word >> 29) & 1,
                (word >> 12) & 0b1111
            )
        }
        FmovFloatGenFmovS32Float2int { rn, rd } => format!("fmov s{rd}, {}", reg_name(rn)),
        FmovFloatGenFmovD64Float2int { rn, rd } => format!("fmov d{rd}, {}", reg_name(rn)),
        FmovFloatGenFmovV64iFloat2int { rn, rd } => format!("fmov v{rd}.d[1], {}", reg_name(rn)),
        FmovFloatGenFmov32sFloat2int { rn, rd } => format!("fmov {}, s{rn}", reg_name(rd)),
        FmovFloatGenFmov64dFloat2int { rn, rd } => format!("fmov {}, d{rn}", reg_name(rd)),
        FmovFloatGenFmov64vxFloat2int { rn, rd } => format!("fmov {}, v{rn}.d[1]", reg_name(rd)),
        FmovFloatFmovSFloatdp1 { rn, rd } => format!("fmov s{rd}, s{rn}"),
        FmovFloatFmovDFloatdp1 { rn, rd } => format!("fmov d{rd}, d{rn}"),
        CmeqAdvsimdRegCmeqAsisdsameOnly { rm, rn, rd }
        | CmhiAdvsimdCmhiAsisdsameOnly { rm, rn, rd }
        | CmhsAdvsimdCmhsAsisdsameOnly { rm, rn, rd }
        | CmgtAdvsimdRegCmgtAsisdsameOnly { rm, rn, rd }
        | CmgeAdvsimdRegCmgeAsisdsameOnly { rm, rn, rd }
        | CmtstAdvsimdCmtstAsisdsameOnly { rm, rn, rd }
        | AddAdvsimdAddAsisdsameOnly { rm, rn, rd }
        | SubAdvsimdSubAsisdsameOnly { rm, rn, rd } => format!("{mnemonic} d{rd}, d{rn}, d{rm}"),
        CmeqAdvsimdZeroCmeqAsisdmiscZ { rn, rd }
        | CmgtAdvsimdZeroCmgtAsisdmiscZ { rn, rd }
        | CmgeAdvsimdZeroCmgeAsisdmiscZ { rn, rd } => format!("{mnemonic} d{rd}, d{rn}, #0"),
        CmeqAdvsimdRegCmeqAsimdsameOnly {
            q,
            size,
            rm,
            rn,
            rd,
        }
        | CmhiAdvsimdCmhiAsimdsameOnly {
            q,
            size,
            rm,
            rn,
            rd,
        }
        | CmhsAdvsimdCmhsAsimdsameOnly {
            q,
            size,
            rm,
            rn,
            rd,
        }
        | CmgtAdvsimdRegCmgtAsimdsameOnly {
            q,
            size,
            rm,
            rn,
            rd,
        }
        | CmgeAdvsimdRegCmgeAsimdsameOnly {
            q,
            size,
            rm,
            rn,
            rd,
        }
        | CmtstAdvsimdCmtstAsimdsameOnly {
            q,
            size,
            rm,
            rn,
            rd,
        }
        | AddAdvsimdAddAsimdsameOnly {
            q,
            size,
            rm,
            rn,
            rd,
        }
        | SubAdvsimdSubAsimdsameOnly {
            q,
            size,
            rm,
            rn,
            rd,
        }
        | AddpAdvsimdVecAddpAsimdsameOnly {
            q,
            size,
            rm,
            rn,
            rd,
        }
        | UmaxpAdvsimdUmaxpAsimdsameOnly {
            q,
            size,
            rm,
            rn,
            rd,
        }
        | UminpAdvsimdUminpAsimdsameOnly {
            q,
            size,
            rm,
            rn,
            rd,
        } => {
            let t = arr(size, q);
            format!("{mnemonic} {}, {}, {}", vr(rd, &t), vr(rn, &t), vr(rm, &t))
        }
        CmeqAdvsimdZeroCmeqAsimdmiscZ { q, size, rn, rd }
        | CmgtAdvsimdZeroCmgtAsimdmiscZ { q, size, rn, rd }
        | CmgeAdvsimdZeroCmgeAsimdmiscZ { q, size, rn, rd } => {
            let t = arr(size, q);
            format!("{mnemonic} {}, {}, #0", vr(rd, &t), vr(rn, &t))
        }
        AndAdvsimdAndAsimdsameOnly { q, rm, rn, rd }
        | OrrAdvsimdRegOrrAsimdsameOnly { q, rm, rn, rd }
        | EorAdvsimdEorAsimdsameOnly { q, rm, rn, rd }
        | BicAdvsimdRegBicAsimdsameOnly { q, rm, rn, rd }
        | OrnAdvsimdOrnAsimdsameOnly { q, rm, rn, rd }
        | BitAdvsimdBitAsimdsameOnly { q, rm, rn, rd }
        | BifAdvsimdBifAsimdsameOnly { q, rm, rn, rd }
        | BslAdvsimdBslAsimdsameOnly { q, rm, rn, rd }
        | TblAdvsimdTblAsimdtblL11 { q, rm, rn, rd } => {
            let t = arr(0, q);
            if matches!(insn, TblAdvsimdTblAsimdtblL11 { .. }) {
                return format!("tbl {}, {{v{rn}.16b}}, {}", vr(rd, &t), vr(rm, &t));
            }
            format!("{mnemonic} {}, {}, {}", vr(rd, &t), vr(rn, &t), vr(rm, &t))
        }
        NotAdvsimdNotAsimdmiscR { q, rn, rd } => {
            format!("mvn {}, {}", vr(rd, &arr(0, q)), vr(rn, &arr(0, q)))
        }
        AddpAdvsimdPairAddpAsisdpairOnly { rn, rd } => format!("addp d{rd}, v{rn}.2d"),
        AddvAdvsimdAddvAsimdallOnly { q, size, rn, rd }
        | UmaxvAdvsimdUmaxvAsimdallOnly { q, size, rn, rd }
        | UminvAdvsimdUminvAsimdallOnly { q, size, rn, rd } => {
            format!(
                "{mnemonic} {}{rd}, {}",
                elem_letter(size.min(3)),
                vr(rn, &arr(size, q))
            )
        }
        Rev16AdvsimdRev16AsimdmiscR { q, size, rn, rd }
        | Rev32AdvsimdRev32AsimdmiscR { q, size, rn, rd }
        | Rev64AdvsimdRev64AsimdmiscR { q, size, rn, rd }
        | CntAdvsimdCntAsimdmiscR { q, size, rn, rd } => {
            let t = arr(size, q);
            format!("{mnemonic} {}, {}", vr(rd, &t), vr(rn, &t))
        }
        XtnAdvsimdXtnAsimdmiscN { q, size, rn, rd } => {
            let name = if q == 1 { "xtn2" } else { "xtn" };
            format!(
                "{name} {}, {}",
                vr(rd, &arr(size.min(2), q)),
                vr(rn, &arr((size + 1).min(3), 1))
            )
        }
        ShrnAdvsimdShrnAsimdshfN {
            q,
            immh,
            immb,
            rn,
            rd,
        } => {
            let esize = shift_esize(A64Imm::unsigned(immh.raw() & 0b111, 4));
            let size = esize.trailing_zeros() as u8 - 3;
            let shift = 2 * esize - (immh.raw() << 3 | immb.raw());
            let name = if q == 1 { "shrn2" } else { "shrn" };
            format!(
                "{name} {}, {}, #{shift}",
                vr(rd, &arr(size, q)),
                vr(rn, &arr(size + 1, 1))
            )
        }
        UshllAdvsimdUshllAsimdshfL {
            q,
            immh,
            immb,
            rn,
            rd,
        } => {
            let esize = shift_esize(A64Imm::unsigned(immh.raw() & 0b111, 4));
            let size = esize.trailing_zeros() as u8 - 3;
            let shift = (immh.raw() << 3 | immb.raw()) - esize;
            let name = if q == 1 { "ushll2" } else { "ushll" };
            format!(
                "{name} {}, {}, #{shift}",
                vr(rd, &arr(size + 1, 1)),
                vr(rn, &arr(size, q))
            )
        }
        UshrAdvsimdUshrAsisdshfR { immh, immb, rn, rd } => {
            format!(
                "ushr d{rd}, d{rn}, #{}",
                128 - (immh.raw() << 3 | immb.raw())
            )
        }
        ShlAdvsimdShlAsisdshfR { immh, immb, rn, rd } => {
            format!("shl d{rd}, d{rn}, #{}", (immh.raw() << 3 | immb.raw()) - 64)
        }
        UshrAdvsimdUshrAsimdshfR {
            q,
            immh,
            immb,
            rn,
            rd,
        }
        | ShlAdvsimdShlAsimdshfR {
            q,
            immh,
            immb,
            rn,
            rd,
        } => {
            let esize = shift_esize(immh);
            let size = (esize.trailing_zeros() as u8).saturating_sub(3);
            let raw = immh.raw() << 3 | immb.raw();
            let shift = if matches!(insn, UshrAdvsimdUshrAsimdshfR { .. }) {
                (2 * esize).wrapping_sub(raw)
            } else {
                raw.wrapping_sub(esize)
            };
            let t = arr(size.min(3), q);
            format!("{mnemonic} {}, {}, #{shift}", vr(rd, &t), vr(rn, &t))
        }
        ExtAdvsimdExtAsimdextOnly {
            q,
            rm,
            imm4,
            rn,
            rd,
        } => {
            let t = arr(0, q);
            format!(
                "ext {}, {}, {}, #{}",
                vr(rd, &t),
                vr(rn, &t),
                vr(rm, &t),
                imm4.raw()
            )
        }
        other => other.mnemonic().to_lowercase(),
    }
}

pub fn pretty_runtime_exit(exit: RuntimeExitReason) -> String {
    match exit {
        RuntimeExitReason::Svc { imm16, resume_pc } => {
            format!("runtime_exit=svc imm16={imm16:#x} resume_pc={resume_pc:#x}")
        }
        RuntimeExitReason::Bl {
            target_pc,
            resume_pc,
        } => format!("runtime_exit=bl target={target_pc:#x} resume_pc={resume_pc:#x}"),
        RuntimeExitReason::Blr {
            target_reg,
            resume_pc,
        } => format!(
            "runtime_exit=blr target_reg={} resume_pc={resume_pc:#x}",
            reg_name(A64Reg::x(target_reg))
        ),
        RuntimeExitReason::Br { target_reg } => {
            format!(
                "runtime_exit=br target_reg={}",
                reg_name(A64Reg::x(target_reg))
            )
        }
        RuntimeExitReason::Ret { lr_reg } => {
            format!("runtime_exit=ret lr={}", reg_name(A64Reg::x(lr_reg)))
        }
        RuntimeExitReason::Unsupported {
            pc,
            word: Some(word),
        } => format!("runtime_exit=unsupported pc={pc:#x} word={word:#010x}"),
        RuntimeExitReason::Unsupported { pc, word: None } => {
            format!("runtime_exit=unsupported pc={pc:#x} word=unreadable")
        }
    }
}

fn pretty_pc_relative(mnemonic: &str, rd: A64Reg, target: Option<u64>, pc: Option<u64>) -> String {
    match (target, pc) {
        (Some(target), Some(_)) => format!("{mnemonic} {}, {target:#x}", reg_name(rd)),
        _ => format!("{mnemonic} {}, <pc-relative>", reg_name(rd)),
    }
}

/// `op rt, [rn, index, extend #amount]`; `amount` is `S ? log2(size) : 0`.
fn pretty_reg_offset(
    insn: A64Insn,
    rt: A64Reg,
    rn: A64Reg,
    rm: A64Reg,
    option: u8,
    s: u8,
) -> String {
    let scale = match (insn.mnemonic(), rt.width) {
        ("LDR" | "STR", A64RegWidth::X64) => 3,
        ("LDR" | "STR", _) | ("LDRSW", _) => 2,
        ("LDRH" | "STRH" | "LDRSH", _) => 1,
        _ => 0,
    };
    format!(
        "{} {}, [{}, {}]",
        insn.mnemonic().to_lowercase(),
        reg_name(rt),
        reg_name(rn),
        index_operand(rm, option, if s == 1 { scale } else { 0 })
    )
}

/// The index register of a register-offset address: `w` for UXTW/SXTW.
fn index_operand(rm: A64Reg, option: u8, amount: u8) -> String {
    let width = if option & 1 == 0 {
        A64RegWidth::W32
    } else {
        A64RegWidth::X64
    };
    let index = reg_name(A64Reg::new(rm.enc(), width, A64Reg31Mode::Xzr));
    let extend = match option {
        0b010 => "uxtw",
        0b011 => "lsl",
        0b110 => "sxtw",
        0b111 => "sxtx",
        _ => "extend",
    };
    match (option, amount) {
        (0b011, 0) => index,
        _ => format!("{index}, {extend} #{amount}"),
    }
}

fn pretty_add_sub(mnemonic: &str, sh: u8, imm12: A64Imm, rn: A64Reg, rd: A64Reg) -> String {
    let effective = A64Insn::add_sub_imm(sh, imm12).unwrap_or(imm12.raw() as u64);
    let mut out = format!(
        "{mnemonic} {}, {}, {}",
        reg_name(rd),
        reg_name(rn),
        unsigned_imm(effective)
    );
    if sh != 0 {
        out.push_str(&format!(" ; imm12={}", unsigned_imm(imm12.raw() as u64)));
    }
    out
}

fn pretty_branch(mnemonic: &str, pc: Option<u64>, imm: A64Imm) -> String {
    match pc {
        Some(pc) => format!("{mnemonic} {:#x}", pc.wrapping_add_signed(imm.value())),
        None => format!("{mnemonic} pc{:+#x}", imm.value()),
    }
}

fn pretty_compare_branch(mnemonic: &str, rt: A64Reg, pc: Option<u64>, imm: A64Imm) -> String {
    match pc {
        Some(pc) => format!(
            "{mnemonic} {}, {:#x}",
            reg_name(rt),
            pc.wrapping_add_signed(imm.value())
        ),
        None => format!("{mnemonic} {}, pc{:+#x}", reg_name(rt), imm.value()),
    }
}

fn pretty_test_branch(mnemonic: &str, rt: A64Reg, bit: u8, pc: Option<u64>, imm: A64Imm) -> String {
    match pc {
        Some(pc) => format!(
            "{mnemonic} {}, #{}, {:#x}",
            reg_name(rt),
            bit,
            pc.wrapping_add_signed(imm.value())
        ),
        None => format!(
            "{mnemonic} {}, #{}, pc{:+#x}",
            reg_name(rt),
            bit,
            imm.value()
        ),
    }
}

fn pretty_move_wide(mnemonic: &str, rd: A64Reg, imm16: A64Imm, hw: u8) -> String {
    let shift = u32::from(hw) * 16;
    if shift == 0 {
        format!(
            "{mnemonic} {}, {}",
            reg_name(rd),
            unsigned_imm(imm16.raw() as u64)
        )
    } else {
        format!(
            "{mnemonic} {}, {}, lsl #{}",
            reg_name(rd),
            unsigned_imm(imm16.raw() as u64),
            shift
        )
    }
}

fn pretty_shifted_reg(
    mnemonic: &str,
    rd: A64Reg,
    rn: A64Reg,
    rm: A64Reg,
    shift: u8,
    imm6: A64Imm,
) -> String {
    if imm6.raw() == 0 && shift == 0 {
        format!(
            "{mnemonic} {}, {}, {}",
            reg_name(rd),
            reg_name(rn),
            reg_name(rm)
        )
    } else {
        format!(
            "{mnemonic} {}, {}, {}, {} #{}",
            reg_name(rd),
            reg_name(rn),
            reg_name(rm),
            shift_name(shift),
            imm6.raw()
        )
    }
}

fn pretty_extended_reg(
    mnemonic: &str,
    rd: A64Reg,
    rn: A64Reg,
    rm: A64Reg,
    option: u8,
    imm3: A64Imm,
) -> String {
    let extend = match option {
        0 => "uxtb",
        1 => "uxth",
        2 => "uxtw",
        3 => "uxtx",
        4 => "sxtb",
        5 => "sxth",
        6 => "sxtw",
        7 => "sxtx",
        _ => "extend",
    };
    format!(
        "{mnemonic} {}, {}, {}, {extend} #{}",
        reg_name(rd),
        reg_name(rn),
        reg_name(rm),
        imm3.raw()
    )
}

fn pretty_logical_imm(
    mnemonic: &str,
    rd: A64Reg,
    rn: A64Reg,
    n: u8,
    immr: A64Imm,
    imms: A64Imm,
    bits: u8,
) -> String {
    match decode_bit_masks(n, imms.raw(), immr.raw(), true, bits) {
        Ok((imm, _)) => format!("{mnemonic} {}, {}, #{imm:#x}", reg_name(rd), reg_name(rn)),
        Err(_) => format!(
            "{mnemonic} {}, {}, <reserved N={n} immr={} imms={}>",
            reg_name(rd),
            reg_name(rn),
            immr.raw(),
            imms.raw()
        ),
    }
}

fn pretty_bitfield(mnemonic: &str, rd: A64Reg, rn: A64Reg, immr: A64Imm, imms: A64Imm) -> String {
    format!(
        "{mnemonic} {}, {}, #{}, #{}",
        reg_name(rd),
        reg_name(rn),
        immr.raw(),
        imms.raw()
    )
}

fn pretty_cond_select(mnemonic: &str, rd: A64Reg, rn: A64Reg, rm: A64Reg, cond: u8) -> String {
    format!(
        "{mnemonic} {}, {}, {}, {}",
        reg_name(rd),
        reg_name(rn),
        reg_name(rm),
        condition_name(cond)
    )
}

fn pretty_cond_compare(mnemonic: &str, rn: A64Reg, operand2: String, nzcv: u8, cond: u8) -> String {
    format!(
        "{mnemonic} {}, {operand2}, #{nzcv}, {}",
        reg_name(rn),
        condition_name(cond)
    )
}

fn pretty_three_reg(mnemonic: &str, rd: A64Reg, rn: A64Reg, rm: A64Reg) -> String {
    format!(
        "{mnemonic} {}, {}, {}",
        reg_name(rd),
        reg_name(rn),
        reg_name(rm)
    )
}

fn pretty_four_reg(mnemonic: &str, rd: A64Reg, rn: A64Reg, rm: A64Reg, ra: A64Reg) -> String {
    format!(
        "{mnemonic} {}, {}, {}, {}",
        reg_name(rd),
        reg_name(rn),
        reg_name(rm),
        reg_name(ra)
    )
}

fn reg_name(reg: A64Reg) -> String {
    match (reg.enc(), reg.width, reg.reg31) {
        (31, A64RegWidth::X64, A64Reg31Mode::Xzr) => "xzr".to_string(),
        (31, A64RegWidth::W32, A64Reg31Mode::Xzr) => "wzr".to_string(),
        (31, A64RegWidth::X64, A64Reg31Mode::Sp) => "sp".to_string(),
        (31, A64RegWidth::W32, A64Reg31Mode::Sp) => "wsp".to_string(),
        (_, A64RegWidth::X64, _) => format!("x{}", reg.enc()),
        (_, A64RegWidth::W32, _) => format!("w{}", reg.enc()),
        (_, A64RegWidth::Unknown, _) => format!("r{}", reg.enc()),
    }
}

fn mem_operand(mem: A64Mem) -> String {
    let base = reg_name(mem.base());
    let offset = mem.offset_imm().value();
    match mem {
        A64Mem::Offset { .. } if offset == 0 => format!("[{base}]"),
        A64Mem::Offset { .. } => format!("[{base}, {}]", imm(offset)),
        A64Mem::PreIndex { .. } => format!("[{base}, {}]!", imm(offset)),
        A64Mem::PostIndex { .. } => format!("[{base}], {}", imm(offset)),
    }
}

/// DMB/DSB `<option>` name of a CRm value; reserved values print as `#imm`.
fn barrier_option(crm: u8) -> String {
    let name = match crm {
        0b0001 => "oshld",
        0b0010 => "oshst",
        0b0011 => "osh",
        0b0101 => "nshld",
        0b0110 => "nshst",
        0b0111 => "nsh",
        0b1001 => "ishld",
        0b1010 => "ishst",
        0b1011 => "ish",
        0b1101 => "ld",
        0b1110 => "st",
        0b1111 => "sy",
        _ => return format!("#{crm}"),
    };
    name.to_string()
}

fn bit_index(b5: u8, b40: u8) -> u8 {
    (b5 << 5) | b40
}

fn condition_name(cond: u8) -> &'static str {
    match A64Condition::from_bits(cond) {
        Some(A64Condition::Eq) => "eq",
        Some(A64Condition::Ne) => "ne",
        Some(A64Condition::Hs) => "hs",
        Some(A64Condition::Lo) => "lo",
        Some(A64Condition::Mi) => "mi",
        Some(A64Condition::Pl) => "pl",
        Some(A64Condition::Vs) => "vs",
        Some(A64Condition::Vc) => "vc",
        Some(A64Condition::Hi) => "hi",
        Some(A64Condition::Ls) => "ls",
        Some(A64Condition::Ge) => "ge",
        Some(A64Condition::Lt) => "lt",
        Some(A64Condition::Gt) => "gt",
        Some(A64Condition::Le) => "le",
        Some(A64Condition::Al) => "al",
        Some(A64Condition::Nv) => "nv",
        None => "unknown",
    }
}

fn shift_name(shift: u8) -> &'static str {
    match shift {
        0 => "lsl",
        1 => "lsr",
        2 => "asr",
        3 => "ror",
        _ => "shift",
    }
}

fn unsigned_imm(value: u64) -> String {
    if value < 10 {
        format!("#{value}")
    } else {
        format!("#{value:#x}")
    }
}

fn imm(value: i64) -> String {
    if value < 0 {
        let abs = value.unsigned_abs();
        if abs < 10 {
            format!("#-{abs}")
        } else {
            format!("#-{abs:#x}")
        }
    } else {
        unsigned_imm(value as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_registers_and_immediates_concisely() {
        let insn = A64Insn::MovzMovz64Movewide {
            hw: 0,
            imm16: A64Imm::unsigned(200, 16),
            rd: A64Reg::x(0),
        };
        assert_eq!(pretty_insn(insn, Some(0x4000)), "movz x0, #0xc8");

        let insn = A64Insn::StrImmGenStr64LdstPos {
            rt: A64Reg::x(1),
            mem: A64Mem::offset(A64Reg::x_sp(12), A64Imm::scaled_unsigned(2, 12, 3)),
        };
        assert_eq!(pretty_insn(insn, None), "str x1, [x12, #0x10]");
    }

    #[test]
    fn formats_pc_relative_targets() {
        let insn = A64Insn::CbnzCbnz64Compbranch {
            rt: A64Reg::x(0),
            imm19: A64Imm::scaled_signed(2, 19, 2),
        };
        assert_eq!(pretty_insn(insn, Some(0x403c)), "cbnz x0, 0x4044");
    }
}
