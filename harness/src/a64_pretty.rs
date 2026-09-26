use crate::arm64::decode_bit_masks;
use crate::shared::arm64::{
    A64Condition, A64Imm, A64Insn, A64Mem, A64Reg, A64Reg31Mode, A64RegWidth,
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
        SmulhSmulh64Dp3src { rm, rn, rd } => pretty_three_reg("smulh", rd, rn, rm),
        UmulhUmulh64Dp3src { rm, rn, rd } => pretty_three_reg("umulh", rd, rn, rm),
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
        | LdrImmGenLdr64LdstImmpost { rt, mem }
        | LdrImmGenLdr32LdstImmpre { rt, mem }
        | LdrImmGenLdr64LdstImmpre { rt, mem }
        | LdrImmGenLdr32LdstPos { rt, mem }
        | LdrImmGenLdr64LdstPos { rt, mem } => {
            format!("ldr {}, {}", reg_name(rt), mem_operand(mem))
        }
        StrImmGenStr32LdstImmpost { rt, mem }
        | StrImmGenStr64LdstImmpost { rt, mem }
        | StrImmGenStr32LdstImmpre { rt, mem }
        | StrImmGenStr64LdstImmpre { rt, mem }
        | StrImmGenStr32LdstPos { rt, mem }
        | StrImmGenStr64LdstPos { rt, mem } => {
            format!("str {}, {}", reg_name(rt), mem_operand(mem))
        }
        LdpGenLdp64LdstpairPost { rt2, rt, mem }
        | LdpGenLdp64LdstpairPre { rt2, rt, mem }
        | LdpGenLdp64LdstpairOff { rt2, rt, mem } => {
            format!(
                "ldp {}, {}, {}",
                reg_name(rt),
                reg_name(rt2),
                mem_operand(mem)
            )
        }
        StpGenStp64LdstpairPost { rt2, rt, mem }
        | StpGenStp64LdstpairPre { rt2, rt, mem }
        | StpGenStp64LdstpairOff { rt2, rt, mem } => {
            format!(
                "stp {}, {}, {}",
                reg_name(rt),
                reg_name(rt2),
                mem_operand(mem)
            )
        }
        NopNopHiHints {} => "nop".to_string(),
        BlBlOnlyBranchImm { imm26 } => pretty_branch("bl", pc, imm26),
        BrBr64BranchReg { rn } => format!("br {}", reg_name(rn)),
        BlrBlr64BranchReg { rn } => format!("blr {}", reg_name(rn)),
        RetRet64rBranchReg { rn } if rn.enc() == 30 => "ret".to_string(),
        RetRet64rBranchReg { rn } => format!("ret {}", reg_name(rn)),
        SvcSvcExException { imm16 } => format!("svc {}", imm(imm16.value())),
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
        RuntimeExitReason::Unsupported { pc, word } => {
            format!("runtime_exit=unsupported pc={pc:#x} word={word:#010x}")
        }
    }
}

fn pretty_pc_relative(mnemonic: &str, rd: A64Reg, target: Option<u64>, pc: Option<u64>) -> String {
    match (target, pc) {
        (Some(target), Some(_)) => format!("{mnemonic} {}, {target:#x}", reg_name(rd)),
        _ => format!("{mnemonic} {}, <pc-relative>", reg_name(rd)),
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
