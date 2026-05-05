use crate::model::{ExecutionResult, HaltReason, MachineState};
use crate::shared::arm64::{decode_word, A64Condition, A64Insn};

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

        if let Some(reason) = decoded.inner.runtime_exit_reason(pc) {
            return Ok(ExecutionResult {
                state,
                halt_reason: HaltReason::RuntimeExit { reason },
                steps,
            });
        }

        pc = execute_insn(decoded.inner, pc, &mut state)?;
    }
}

pub(crate) fn execute_insn(
    insn: A64Insn,
    pc: u64,
    state: &mut MachineState,
) -> Result<u64, String> {
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
        A64Insn::OrrLogShiftOrr64LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => {
            let shifted = shifted_reg64(state.read_reg(rm), shift, imm6)?;
            state.write_reg(rd, state.read_reg(rn) | shifted);
            Ok(pc + 4)
        }

        A64Insn::AddAddsubImmAdd32AddsubImm { sh, imm12, rn, rd } => {
            let result =
                read_reg_or_sp_sized(state, rn, 32).wrapping_add(add_sub_imm(sh, imm12, insn)?);
            write_reg_or_sp_sized(state, rd, result, 32);
            Ok(pc + 4)
        }
        A64Insn::AddAddsubImmAdd64AddsubImm { sh, imm12, rn, rd } => {
            let result = state
                .read_reg_or_sp(rn)
                .wrapping_add(add_sub_imm(sh, imm12, insn)?);
            state.write_reg_or_sp(rd, result);
            Ok(pc + 4)
        }
        A64Insn::SubAddsubImmSub32AddsubImm { sh, imm12, rn, rd } => {
            let result =
                read_reg_or_sp_sized(state, rn, 32).wrapping_sub(add_sub_imm(sh, imm12, insn)?);
            write_reg_or_sp_sized(state, rd, result, 32);
            Ok(pc + 4)
        }
        A64Insn::SubAddsubImmSub64AddsubImm { sh, imm12, rn, rd } => {
            let result = state
                .read_reg_or_sp(rn)
                .wrapping_sub(add_sub_imm(sh, imm12, insn)?);
            state.write_reg_or_sp(rd, result);
            Ok(pc + 4)
        }
        A64Insn::SubsAddsubImmSubs32sAddsubImm { sh, imm12, rn, rd } => {
            let lhs = read_reg_or_sp_sized(state, rn, 32);
            let rhs = add_sub_imm(sh, imm12, insn)?;
            let result = lhs.wrapping_sub(rhs);
            update_sub_flags_sized(state, lhs, rhs, result, 32);
            write_reg_sized(state, rd, result, 32);
            Ok(pc + 4)
        }
        A64Insn::SubsAddsubImmSubs64sAddsubImm { sh, imm12, rn, rd } => {
            let lhs = state.read_reg_or_sp(rn);
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
            let addr = state.read_reg_or_sp(rn).wrapping_add((imm12 as u64) << 2);
            state.write_reg(rt, state.read_u32(addr) as u64);
            Ok(pc + 4)
        }
        A64Insn::LdrImmGenLdr64LdstPos { imm12, rn, rt } => {
            let addr = state.read_reg_or_sp(rn).wrapping_add((imm12 as u64) << 3);
            state.write_reg(rt, state.read_u64(addr));
            Ok(pc + 4)
        }
        A64Insn::StrImmGenStr32LdstPos { imm12, rn, rt } => {
            let addr = state.read_reg_or_sp(rn).wrapping_add((imm12 as u64) << 2);
            state.write_u32(addr, read_reg_sized(state, rt, 32) as u32);
            Ok(pc + 4)
        }
        A64Insn::StrImmGenStr64LdstPos { imm12, rn, rt } => {
            let addr = state.read_reg_or_sp(rn).wrapping_add((imm12 as u64) << 3);
            state.write_u64(addr, state.read_reg(rt));
            Ok(pc + 4)
        }

        A64Insn::LdrImmGenLdr32LdstImmpre { imm9, rn, rt } => {
            let addr = add_signed(state.read_reg_or_sp(rn), A64Insn::signed_imm9(imm9));
            state.write_reg_or_sp(rn, addr);
            state.write_reg(rt, state.read_u32(addr) as u64);
            Ok(pc + 4)
        }
        A64Insn::LdrImmGenLdr64LdstImmpre { imm9, rn, rt } => {
            let addr = add_signed(state.read_reg_or_sp(rn), A64Insn::signed_imm9(imm9));
            state.write_reg_or_sp(rn, addr);
            state.write_reg(rt, state.read_u64(addr));
            Ok(pc + 4)
        }
        A64Insn::StrImmGenStr32LdstImmpre { imm9, rn, rt } => {
            let addr = add_signed(state.read_reg_or_sp(rn), A64Insn::signed_imm9(imm9));
            state.write_reg_or_sp(rn, addr);
            state.write_u32(addr, read_reg_sized(state, rt, 32) as u32);
            Ok(pc + 4)
        }
        A64Insn::StrImmGenStr64LdstImmpre { imm9, rn, rt } => {
            let addr = add_signed(state.read_reg_or_sp(rn), A64Insn::signed_imm9(imm9));
            state.write_reg_or_sp(rn, addr);
            state.write_u64(addr, state.read_reg(rt));
            Ok(pc + 4)
        }

        A64Insn::LdrImmGenLdr32LdstImmpost { imm9, rn, rt } => {
            let addr = state.read_reg_or_sp(rn);
            state.write_reg(rt, state.read_u32(addr) as u64);
            state.write_reg_or_sp(rn, add_signed(addr, A64Insn::signed_imm9(imm9)));
            Ok(pc + 4)
        }
        A64Insn::LdrImmGenLdr64LdstImmpost { imm9, rn, rt } => {
            let addr = state.read_reg_or_sp(rn);
            state.write_reg(rt, state.read_u64(addr));
            state.write_reg_or_sp(rn, add_signed(addr, A64Insn::signed_imm9(imm9)));
            Ok(pc + 4)
        }
        A64Insn::StrImmGenStr32LdstImmpost { imm9, rn, rt } => {
            let addr = state.read_reg_or_sp(rn);
            state.write_u32(addr, read_reg_sized(state, rt, 32) as u32);
            state.write_reg_or_sp(rn, add_signed(addr, A64Insn::signed_imm9(imm9)));
            Ok(pc + 4)
        }
        A64Insn::StrImmGenStr64LdstImmpost { imm9, rn, rt } => {
            let addr = state.read_reg_or_sp(rn);
            state.write_u64(addr, state.read_reg(rt));
            state.write_reg_or_sp(rn, add_signed(addr, A64Insn::signed_imm9(imm9)));
            Ok(pc + 4)
        }

        A64Insn::LdpGenLdp64LdstpairPost { imm7, rt2, rn, rt } => {
            execute_ldp64(state, rn, rt, rt2, imm7, PairAddressMode::PostIndex)?;
            Ok(pc + 4)
        }
        A64Insn::LdpGenLdp64LdstpairPre { imm7, rt2, rn, rt } => {
            execute_ldp64(state, rn, rt, rt2, imm7, PairAddressMode::PreIndex)?;
            Ok(pc + 4)
        }
        A64Insn::LdpGenLdp64LdstpairOff { imm7, rt2, rn, rt } => {
            execute_ldp64(state, rn, rt, rt2, imm7, PairAddressMode::Offset)?;
            Ok(pc + 4)
        }
        A64Insn::StpGenStp64LdstpairPost { imm7, rt2, rn, rt } => {
            execute_stp64(state, rn, rt, rt2, imm7, PairAddressMode::PostIndex);
            Ok(pc + 4)
        }
        A64Insn::StpGenStp64LdstpairPre { imm7, rt2, rn, rt } => {
            execute_stp64(state, rn, rt, rt2, imm7, PairAddressMode::PreIndex);
            Ok(pc + 4)
        }
        A64Insn::StpGenStp64LdstpairOff { imm7, rt2, rn, rt } => {
            execute_stp64(state, rn, rt, rt2, imm7, PairAddressMode::Offset);
            Ok(pc + 4)
        }

        A64Insn::BlBlOnlyBranchImm { imm26 } => {
            let target = pc_relative_target(pc, imm26, 26);
            state.write_reg(30, pc.wrapping_add(4));
            Ok(target)
        }
        A64Insn::BlrBlr64BranchReg { rn } => {
            state.write_reg(30, pc.wrapping_add(4));
            Ok(state.read_reg(rn))
        }
        A64Insn::BrBr64BranchReg { rn } => Ok(state.read_reg(rn)),
        A64Insn::RetRet64rBranchReg { rn } => Ok(state.read_reg(rn)),
        A64Insn::SvcSvcExException { .. } => {
            Err("raw SVC is not executable inside the userspace runtime fragment".to_string())
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

fn shifted_reg64(value: u64, shift: u8, amount: u8) -> Result<u64, String> {
    match shift {
        0 => Ok(value << amount),
        1 => Ok(value >> amount),
        2 => Ok(((value as i64) >> amount) as u64),
        3 => Ok(value.rotate_right(amount as u32)),
        _ => Err(format!("unsupported shifted-register shift field: {shift}")),
    }
}

#[derive(Clone, Copy)]
enum PairAddressMode {
    Offset,
    PreIndex,
    PostIndex,
}

fn execute_ldp64(
    state: &mut MachineState,
    rn: u8,
    rt: u8,
    rt2: u8,
    imm7: u8,
    mode: PairAddressMode,
) -> Result<(), String> {
    if matches!(mode, PairAddressMode::PreIndex | PairAddressMode::PostIndex)
        && rn != 31
        && (rn == rt || rn == rt2)
    {
        return Err("writeback LDP with base/target overlap is unsupported".to_string());
    }

    let addr = pair_address(state, rn, imm7, mode);
    let first = state.read_u64(addr);
    let second = state.read_u64(addr.wrapping_add(8));
    state.write_reg(rt, first);
    state.write_reg(rt2, second);
    Ok(())
}

fn execute_stp64(
    state: &mut MachineState,
    rn: u8,
    rt: u8,
    rt2: u8,
    imm7: u8,
    mode: PairAddressMode,
) {
    let first = state.read_reg(rt);
    let second = state.read_reg(rt2);
    let addr = pair_address(state, rn, imm7, mode);
    state.write_u64(addr, first);
    state.write_u64(addr.wrapping_add(8), second);
}

fn pair_address(state: &mut MachineState, rn: u8, imm7: u8, mode: PairAddressMode) -> u64 {
    let base = state.read_reg_or_sp(rn);
    let offset = sign_extend(imm7 as u32, 7) << 3;

    match mode {
        PairAddressMode::Offset => add_signed(base, offset),
        PairAddressMode::PreIndex => {
            let addr = add_signed(base, offset);
            state.write_reg_or_sp(rn, addr);
            addr
        }
        PairAddressMode::PostIndex => {
            state.write_reg_or_sp(rn, add_signed(base, offset));
            base
        }
    }
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

fn read_reg_or_sp_sized(state: &MachineState, reg: u8, bits: u8) -> u64 {
    match bits {
        32 => state.read_reg_or_sp(reg) & 0xFFFF_FFFF,
        64 => state.read_reg_or_sp(reg),
        _ => unreachable!("unsupported register width"),
    }
}

fn write_reg_or_sp_sized(state: &mut MachineState, reg: u8, value: u64, bits: u8) {
    match bits {
        32 => state.write_reg_or_sp(reg, value & 0xFFFF_FFFF),
        64 => state.write_reg_or_sp(reg, value),
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

    #[test]
    fn add_sub_immediate_distinguishes_sp_from_xzr() {
        let mut state = MachineState::new();
        state.set_sp(0x1000);

        execute_insn(
            A64Insn::AddAddsubImmAdd64AddsubImm {
                sh: 0,
                imm12: 0x20,
                rn: 31,
                rd: 0,
            },
            0x4000,
            &mut state,
        )
        .unwrap();
        assert_eq!(state.read_reg(0), 0x1020);
        assert_eq!(state.read_reg(31), 0);
        assert_eq!(state.read_reg_or_sp(31), 0x1000);

        execute_insn(
            A64Insn::SubAddsubImmSub64AddsubImm {
                sh: 0,
                imm12: 0x10,
                rn: 31,
                rd: 31,
            },
            0x4004,
            &mut state,
        )
        .unwrap();
        assert_eq!(state.sp(), 0x0ff0);
        assert_eq!(state.read_reg(31), 0);
    }

    #[test]
    fn ldr_str_use_sp_as_memory_base() {
        let mut state = MachineState::new();
        state.set_sp(0x8000);
        state.write_reg(0, 0x1122_3344_5566_7788);

        execute_insn(
            A64Insn::StrImmGenStr64LdstPos {
                imm12: 1,
                rn: 31,
                rt: 0,
            },
            0x4000,
            &mut state,
        )
        .unwrap();
        assert_eq!(state.read_u64(0x8008), 0x1122_3344_5566_7788);

        execute_insn(
            A64Insn::LdrImmGenLdr64LdstPos {
                imm12: 1,
                rn: 31,
                rt: 1,
            },
            0x4004,
            &mut state,
        )
        .unwrap();
        assert_eq!(state.read_reg(1), 0x1122_3344_5566_7788);
    }

    #[test]
    fn ldp_stp_pair_support_sp_pre_and_post_index() {
        let mut state = MachineState::new();
        state.set_sp(0x9000);
        state.write_reg(29, 0x1111_2222_3333_4444);
        state.write_reg(30, 0xAAAA_BBBB_CCCC_DDDD);

        execute_insn(
            A64Insn::StpGenStp64LdstpairPre {
                imm7: signed_field(-2, 7),
                rt2: 30,
                rn: 31,
                rt: 29,
            },
            0x4000,
            &mut state,
        )
        .unwrap();
        assert_eq!(state.sp(), 0x8ff0);
        assert_eq!(state.read_u64(0x8ff0), 0x1111_2222_3333_4444);
        assert_eq!(state.read_u64(0x8ff8), 0xAAAA_BBBB_CCCC_DDDD);

        state.write_reg(29, 0);
        state.write_reg(30, 0);
        execute_insn(
            A64Insn::LdpGenLdp64LdstpairPost {
                imm7: signed_field(2, 7),
                rt2: 30,
                rn: 31,
                rt: 29,
            },
            0x4004,
            &mut state,
        )
        .unwrap();
        assert_eq!(state.read_reg(29), 0x1111_2222_3333_4444);
        assert_eq!(state.read_reg(30), 0xAAAA_BBBB_CCCC_DDDD);
        assert_eq!(state.sp(), 0x9000);
    }

    fn signed_field(value: i64, bits: u8) -> u8 {
        let min = -(1_i64 << (bits - 1));
        let max = (1_i64 << (bits - 1)) - 1;
        assert!((min..=max).contains(&value));
        (value as i128 & ((1_i128 << bits) - 1)) as u8
    }
}
