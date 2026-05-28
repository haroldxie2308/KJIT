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
        OrrLogShiftOrr64LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => pretty_shifted_reg("orr", rd, rn, rm, shift, imm6),
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
        RuntimeExitReason::Unsupported => "runtime_exit=unsupported".to_string(),
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
        Some(A64Condition::Ge) => "ge",
        Some(A64Condition::Lt) => "lt",
        Some(A64Condition::Gt) => "gt",
        Some(A64Condition::Le) => "le",
        Some(A64Condition::Al) => "al",
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
