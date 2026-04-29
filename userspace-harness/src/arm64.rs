use crate::model::{ExecutionResult, HaltReason, MachineState};
use crate::shared::trans::arm64::{decode_word, A64Condition, A64Insn};

const MAX_STEPS: usize = 1024;

pub fn execute_program(
    program: &[u8],
    base_pc: u64,
    initial_state: &MachineState,
) -> Result<ExecutionResult, String> {
    if program.len() % 4 != 0 {
        return Err("program length must be a multiple of 4 bytes".to_string());
    }

    let mut state = initial_state.clone();
    let mut pc = base_pc;
    let mut steps = 0;

    loop {
        if steps >= MAX_STEPS {
            return Ok(ExecutionResult {
                state,
                halt_reason: HaltReason::StepLimitExceeded,
                steps,
            });
        }

        if pc < base_pc {
            return Err(format!("pc moved before base address: {pc:#x}"));
        }

        let offset = pc - base_pc;
        if offset % 4 != 0 {
            return Err(format!("pc is not word-aligned: {pc:#x}"));
        }

        let insn_index = (offset / 4) as usize;
        if insn_index >= program.len() / 4 {
            return Ok(ExecutionResult {
                state,
                halt_reason: HaltReason::FellOffEnd,
                steps,
            });
        }

        let chunk = &program[insn_index * 4..insn_index * 4 + 4];
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        let decoded = decode_word(word, pc).map_err(|err| err.to_string())?;
        steps += 1;

        if let Some(reason) = decoded.insn.runtime_exit_reason(pc) {
            return Ok(ExecutionResult {
                state,
                halt_reason: HaltReason::RuntimeExit { reason },
                steps,
            });
        }

        pc = execute_insn(decoded.insn, pc, &mut state)?;
    }
}

fn execute_insn(insn: A64Insn, pc: u64, state: &mut MachineState) -> Result<u64, String> {
    match insn {
        A64Insn::NopNopHiHints {} => Ok(pc + 4),

        A64Insn::AdrAdrOnlyPcreladdr { rd, .. } | A64Insn::AdrpAdrpOnlyPcreladdr { rd, .. } => {
            let value = insn
                .pc_relative_address(pc)
                .ok_or_else(|| format!("missing PC-relative value for {}", insn.key()))?;
            state.write_reg(rd, value);
            Ok(pc + 4)
        }

        A64Insn::MovzMovz32Movewide { hw, imm16, rd } => {
            write_movz(state, 32, rd, imm16, hw)?;
            Ok(pc + 4)
        }
        A64Insn::MovzMovz64Movewide { hw, imm16, rd } => {
            write_movz(state, 64, rd, imm16, hw)?;
            Ok(pc + 4)
        }
        A64Insn::MovkMovk32Movewide { hw, imm16, rd } => {
            write_movk(state, 32, rd, imm16, hw)?;
            Ok(pc + 4)
        }
        A64Insn::MovkMovk64Movewide { hw, imm16, rd } => {
            write_movk(state, 64, rd, imm16, hw)?;
            Ok(pc + 4)
        }

        A64Insn::AddAddsubImmAdd32AddsubImm { sh, imm12, rn, rd } => {
            let result = read_reg_sized(state, rn, 32).wrapping_add(add_sub_imm(sh, imm12, insn)?);
            write_reg_sized(state, rd, result, 32);
            Ok(pc + 4)
        }
        A64Insn::AddAddsubImmAdd64AddsubImm { sh, imm12, rn, rd } => {
            let result = state
                .read_reg(rn)
                .wrapping_add(add_sub_imm(sh, imm12, insn)?);
            state.write_reg(rd, result);
            Ok(pc + 4)
        }
        A64Insn::SubAddsubImmSub32AddsubImm { sh, imm12, rn, rd } => {
            let result = read_reg_sized(state, rn, 32).wrapping_sub(add_sub_imm(sh, imm12, insn)?);
            write_reg_sized(state, rd, result, 32);
            Ok(pc + 4)
        }
        A64Insn::SubAddsubImmSub64AddsubImm { sh, imm12, rn, rd } => {
            let result = state
                .read_reg(rn)
                .wrapping_sub(add_sub_imm(sh, imm12, insn)?);
            state.write_reg(rd, result);
            Ok(pc + 4)
        }
        A64Insn::SubsAddsubImmSubs32sAddsubImm { sh, imm12, rn, rd } => {
            let lhs = read_reg_sized(state, rn, 32);
            let rhs = add_sub_imm(sh, imm12, insn)?;
            let result = lhs.wrapping_sub(rhs);
            update_sub_flags_sized(state, lhs, rhs, result, 32);
            write_reg_sized(state, rd, result, 32);
            Ok(pc + 4)
        }
        A64Insn::SubsAddsubImmSubs64sAddsubImm { sh, imm12, rn, rd } => {
            let lhs = state.read_reg(rn);
            let rhs = add_sub_imm(sh, imm12, insn)?;
            let result = lhs.wrapping_sub(rhs);
            state.update_sub_flags(lhs, rhs, result);
            state.write_reg(rd, result);
            Ok(pc + 4)
        }

        A64Insn::BUncondBOnlyBranchImm { .. } => insn
            .direct_branch_target(pc)
            .ok_or_else(|| format!("missing branch target for {}", insn.key())),
        A64Insn::BCondBOnlyCondbranch { .. } => {
            let (taken, fallthrough) = insn
                .conditional_targets(pc)
                .ok_or_else(|| format!("missing conditional target for {}", insn.key()))?;
            let condition = insn
                .condition()
                .ok_or_else(|| format!("unsupported condition in {}", insn.key()))?;
            Ok(if eval_condition(condition, state) {
                taken
            } else {
                fallthrough
            })
        }
        A64Insn::CbzCbz32Compbranch { rt, .. } => branch_on_zero(insn, pc, state, rt, 32, true),
        A64Insn::CbzCbz64Compbranch { rt, .. } => branch_on_zero(insn, pc, state, rt, 64, true),
        A64Insn::CbnzCbnz32Compbranch { rt, .. } => branch_on_zero(insn, pc, state, rt, 32, false),
        A64Insn::CbnzCbnz64Compbranch { rt, .. } => branch_on_zero(insn, pc, state, rt, 64, false),
        A64Insn::TbzTbzOnlyTestbranch { b5, b40, rt, .. } => {
            branch_on_bit(insn, pc, state, rt, bit_index(b5, b40), false)
        }
        A64Insn::TbnzTbnzOnlyTestbranch { b5, b40, rt, .. } => {
            branch_on_bit(insn, pc, state, rt, bit_index(b5, b40), true)
        }

        A64Insn::LdrImmGenLdr32LdstPos { imm12, rn, rt } => {
            let addr = state.read_reg(rn).wrapping_add((imm12 as u64) << 2);
            state.write_reg(rt, state.read_u32(addr) as u64);
            Ok(pc + 4)
        }
        A64Insn::LdrImmGenLdr64LdstPos { imm12, rn, rt } => {
            let addr = state.read_reg(rn).wrapping_add((imm12 as u64) << 3);
            state.write_reg(rt, state.read_u64(addr));
            Ok(pc + 4)
        }
        A64Insn::StrImmGenStr32LdstPos { imm12, rn, rt } => {
            let addr = state.read_reg(rn).wrapping_add((imm12 as u64) << 2);
            state.write_u32(addr, read_reg_sized(state, rt, 32) as u32);
            Ok(pc + 4)
        }
        A64Insn::StrImmGenStr64LdstPos { imm12, rn, rt } => {
            let addr = state.read_reg(rn).wrapping_add((imm12 as u64) << 3);
            state.write_u64(addr, state.read_reg(rt));
            Ok(pc + 4)
        }

        A64Insn::LdrImmGenLdr32LdstImmpre { imm9, rn, rt } => {
            let addr = add_signed(state.read_reg(rn), A64Insn::signed_imm9(imm9));
            state.write_reg(rn, addr);
            state.write_reg(rt, state.read_u32(addr) as u64);
            Ok(pc + 4)
        }
        A64Insn::LdrImmGenLdr64LdstImmpre { imm9, rn, rt } => {
            let addr = add_signed(state.read_reg(rn), A64Insn::signed_imm9(imm9));
            state.write_reg(rn, addr);
            state.write_reg(rt, state.read_u64(addr));
            Ok(pc + 4)
        }
        A64Insn::StrImmGenStr32LdstImmpre { imm9, rn, rt } => {
            let addr = add_signed(state.read_reg(rn), A64Insn::signed_imm9(imm9));
            state.write_reg(rn, addr);
            state.write_u32(addr, read_reg_sized(state, rt, 32) as u32);
            Ok(pc + 4)
        }
        A64Insn::StrImmGenStr64LdstImmpre { imm9, rn, rt } => {
            let addr = add_signed(state.read_reg(rn), A64Insn::signed_imm9(imm9));
            state.write_reg(rn, addr);
            state.write_u64(addr, state.read_reg(rt));
            Ok(pc + 4)
        }

        A64Insn::LdrImmGenLdr32LdstImmpost { imm9, rn, rt } => {
            let addr = state.read_reg(rn);
            state.write_reg(rt, state.read_u32(addr) as u64);
            state.write_reg(rn, add_signed(addr, A64Insn::signed_imm9(imm9)));
            Ok(pc + 4)
        }
        A64Insn::LdrImmGenLdr64LdstImmpost { imm9, rn, rt } => {
            let addr = state.read_reg(rn);
            state.write_reg(rt, state.read_u64(addr));
            state.write_reg(rn, add_signed(addr, A64Insn::signed_imm9(imm9)));
            Ok(pc + 4)
        }
        A64Insn::StrImmGenStr32LdstImmpost { imm9, rn, rt } => {
            let addr = state.read_reg(rn);
            state.write_u32(addr, read_reg_sized(state, rt, 32) as u32);
            state.write_reg(rn, add_signed(addr, A64Insn::signed_imm9(imm9)));
            Ok(pc + 4)
        }
        A64Insn::StrImmGenStr64LdstImmpost { imm9, rn, rt } => {
            let addr = state.read_reg(rn);
            state.write_u64(addr, state.read_reg(rt));
            state.write_reg(rn, add_signed(addr, A64Insn::signed_imm9(imm9)));
            Ok(pc + 4)
        }

        A64Insn::BlBlOnlyBranchImm { .. }
        | A64Insn::BrBr64BranchReg { .. }
        | A64Insn::BlrBlr64BranchReg { .. }
        | A64Insn::RetRet64rBranchReg { .. }
        | A64Insn::SvcSvcExException { .. } => {
            unreachable!("runtime exits are handled before instruction execution")
        }
    }
}

fn add_sub_imm(sh: u8, imm12: u16, insn: A64Insn) -> Result<u64, String> {
    A64Insn::add_sub_imm(sh, imm12)
        .ok_or_else(|| format!("unsupported add/sub immediate shift in {}", insn.key()))
}

fn write_movz(
    state: &mut MachineState,
    bits: u8,
    rd: u8,
    imm16: u16,
    hw: u8,
) -> Result<(), String> {
    let shift = A64Insn::move_wide_shift(hw)
        .ok_or_else(|| format!("unsupported MOVZ shift field: {hw}"))?;
    write_reg_sized(state, rd, (imm16 as u64) << shift, bits);
    Ok(())
}

fn write_movk(
    state: &mut MachineState,
    bits: u8,
    rd: u8,
    imm16: u16,
    hw: u8,
) -> Result<(), String> {
    let shift = A64Insn::move_wide_shift(hw)
        .ok_or_else(|| format!("unsupported MOVK shift field: {hw}"))?;
    let old = read_reg_sized(state, rd, bits);
    let mask = !(0xFFFF_u64 << shift);
    write_reg_sized(state, rd, (old & mask) | ((imm16 as u64) << shift), bits);
    Ok(())
}

fn branch_on_zero(
    insn: A64Insn,
    pc: u64,
    state: &MachineState,
    rt: u8,
    bits: u8,
    branch_if_zero: bool,
) -> Result<u64, String> {
    let (taken, fallthrough) = insn
        .conditional_targets(pc)
        .ok_or_else(|| format!("missing conditional target for {}", insn.key()))?;
    let is_zero = read_reg_sized(state, rt, bits) == 0;
    Ok(if is_zero == branch_if_zero {
        taken
    } else {
        fallthrough
    })
}

fn branch_on_bit(
    insn: A64Insn,
    pc: u64,
    state: &MachineState,
    rt: u8,
    bit: u8,
    branch_if_set: bool,
) -> Result<u64, String> {
    let (taken, fallthrough) = insn
        .conditional_targets(pc)
        .ok_or_else(|| format!("missing conditional target for {}", insn.key()))?;
    let is_set = ((state.read_reg(rt) >> bit) & 1) != 0;
    Ok(if is_set == branch_if_set {
        taken
    } else {
        fallthrough
    })
}

fn bit_index(b5: u8, b40: u8) -> u8 {
    (b5 << 5) | b40
}

fn eval_condition(condition: A64Condition, state: &MachineState) -> bool {
    let flags = state.flags;
    match condition {
        A64Condition::Eq => flags.z,
        A64Condition::Ne => !flags.z,
        A64Condition::Ge => flags.n == flags.v,
        A64Condition::Lt => flags.n != flags.v,
        A64Condition::Gt => !flags.z && flags.n == flags.v,
        A64Condition::Le => flags.z || flags.n != flags.v,
        A64Condition::Al => true,
    }
}

fn read_reg_sized(state: &MachineState, reg: u8, bits: u8) -> u64 {
    match bits {
        32 => state.read_reg(reg) & 0xFFFF_FFFF,
        64 => state.read_reg(reg),
        _ => unreachable!("unsupported register width"),
    }
}

fn write_reg_sized(state: &mut MachineState, reg: u8, value: u64, bits: u8) {
    match bits {
        32 => state.write_reg(reg, value & 0xFFFF_FFFF),
        64 => state.write_reg(reg, value),
        _ => unreachable!("unsupported register width"),
    }
}

fn update_sub_flags_sized(state: &mut MachineState, lhs: u64, rhs: u64, result: u64, bits: u8) {
    let mask = match bits {
        32 => 0xFFFF_FFFF,
        64 => u64::MAX,
        _ => unreachable!("unsupported flag width"),
    };
    let sign = 1_u64 << (bits - 1);
    let lhs = lhs & mask;
    let rhs = rhs & mask;
    let result = result & mask;

    state.flags.n = (result & sign) != 0;
    state.flags.z = result == 0;
    state.flags.c = lhs >= rhs;
    state.flags.v = ((lhs ^ rhs) & (lhs ^ result) & sign) != 0;
}

fn add_signed(value: u64, offset: i64) -> u64 {
    value.wrapping_add_signed(offset)
}
