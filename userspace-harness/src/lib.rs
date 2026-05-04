extern crate alloc;

pub mod arm64;
pub mod model;
pub mod runtime;
pub mod shared;

use crate::shared::trans::input::{
    CodeProvider, CodeReadError, RegisterSnapshot, TranslationRequest, TranslationTrigger,
};
use crate::shared::trans::translate::{translate_request, TranslatedProgram};
use model::{MachineState, NormalizedState};

#[derive(Debug)]
pub struct CaseReport {
    pub name: &'static str,
    pub translated_program: TranslatedProgram,
    pub encoded_program: Vec<u8>,
    pub original_state: NormalizedState,
    pub encoded_state: NormalizedState,
}

pub struct MockCodeProvider {
    base_pc: u64,
    bytes: Vec<u8>,
}

impl MockCodeProvider {
    pub fn new(base_pc: u64, bytes: Vec<u8>) -> Self {
        Self { base_pc, bytes }
    }

    pub fn slice_from(&self, pc: u64) -> Result<&[u8], String> {
        let offset = self.offset(pc, 0).map_err(|err| err.to_string())?;
        Ok(&self.bytes[offset..])
    }

    fn offset(&self, pc: u64, len: usize) -> Result<usize, CodeReadError> {
        let Some(relative) = pc.checked_sub(self.base_pc) else {
            return Err(CodeReadError::Unmapped { pc, len });
        };
        let Ok(offset) = usize::try_from(relative) else {
            return Err(CodeReadError::Unmapped { pc, len });
        };
        let Some(end) = offset.checked_add(len) else {
            return Err(CodeReadError::Unmapped { pc, len });
        };
        if relative % 4 != 0 || end > self.bytes.len() {
            return Err(CodeReadError::Unmapped { pc, len });
        }
        Ok(offset)
    }
}

impl CodeProvider for MockCodeProvider {
    fn entry_addr(&self) -> u64 {
        self.base_pc
    }

    fn read_exact(&self, pc: u64, dst: &mut [u8]) -> Result<(), CodeReadError> {
        let offset = self.offset(pc, dst.len())?;
        dst.copy_from_slice(&self.bytes[offset..offset + dst.len()]);
        Ok(())
    }
}

pub fn run_entry_fixture(
    name: &'static str,
    text_base: u64,
    text_bytes: Vec<u8>,
    entry_pc: u64,
    initial_state: &MachineState,
) -> Result<CaseReport, String> {
    let code = MockCodeProvider::new(text_base, text_bytes);
    let original_program = code.slice_from(entry_pc)?;
    let original = arm64::execute_program(original_program, entry_pc, initial_state)?;

    let request = TranslationRequest {
        entry_pc,
        trigger: TranslationTrigger::HotSvc,
        regs: Some(register_snapshot(initial_state, entry_pc)),
    };
    let translated_program = translate_request(&request, &code).map_err(|err| err.to_string())?;
    let encoded_program = encode_translated_program(&translated_program)?;
    let encoded = arm64::execute_program(&encoded_program, entry_pc, initial_state)?;

    let original_state = NormalizedState::from_execution(&original);
    let encoded_state = NormalizedState::from_execution(&encoded);

    if original_state != encoded_state {
        return Err(format!(
            "original vs encoded mismatch for `{name}`\noriginal: {original_state:#?}\nencoded: {encoded_state:#?}",
        ));
    }

    Ok(CaseReport {
        name,
        translated_program,
        encoded_program,
        original_state,
        encoded_state,
    })
}

fn encode_translated_program(program: &TranslatedProgram) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(program.len() * 4);
    for insn in program {
        let word = insn
            .inner
            .encode()
            .map_err(|err| format!("failed to encode {}: {err:?}", insn.inner.key()))?;
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    Ok(bytes)
}

fn register_snapshot(state: &MachineState, pc: u64) -> RegisterSnapshot {
    let mut x = [0_u64; 31];
    for reg in 0..31 {
        x[reg] = state.read_reg(reg as u8);
    }
    RegisterSnapshot {
        x,
        sp: 0,
        pc,
        pstate: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::arm64::{A64Condition, A64Insn};

    #[test]
    fn generated_arm64_subset_matches_sample_opcodes() {
        let samples = [
            ("ADR.ADR_only_pcreladdr", 0x1000_0000_u32),
            ("ADD_addsub_imm.ADD_64_addsub_imm", 0x9100_1441_u32),
            ("B_uncond.B_only_branch_imm", 0x1400_0000_u32),
            ("B_cond.B_only_condbranch", 0x5400_0000_u32),
            ("CBZ.CBZ_64_compbranch", 0xB400_0003_u32),
            ("CBNZ.CBNZ_64_compbranch", 0xB500_0004_u32),
            ("MOVZ.MOVZ_64_movewide", 0xD2A2_4685_u32),
            ("MOVK.MOVK_64_movewide", 0xF2D5_79A5_u32),
            ("TBZ.TBZ_only_testbranch", 0x3638_0006_u32),
            ("TBNZ.TBNZ_only_testbranch", 0xB708_0007_u32),
            ("LDR_imm_gen.LDR_64_ldst_pos", 0xF940_0928_u32),
            ("STR_imm_gen.STR_64_ldst_pos", 0xF900_0D6A_u32),
        ];

        for (expected_key, opcode) in samples {
            let insn = A64Insn::decode(opcode).unwrap_or_else(|| {
                panic!("no generated instruction matched opcode {opcode:#010x}")
            });
            assert_eq!(
                insn.key(),
                expected_key,
                "unexpected match for opcode {opcode:#010x}"
            );
        }
    }

    #[test]
    fn generated_arm64_subset_extracts_expected_fields() {
        assert_eq!(
            A64Insn::decode(0x9100_1441),
            Some(A64Insn::AddAddsubImmAdd64AddsubImm {
                sh: 0,
                imm12: 5,
                rn: 2,
                rd: 1,
            })
        );
        assert_eq!(
            A64Insn::decode(0xD2A2_4685),
            Some(A64Insn::MovzMovz64Movewide {
                hw: 1,
                imm16: 0x1234,
                rd: 5,
            })
        );
        assert_eq!(
            A64Insn::decode(0xF2D5_79A5),
            Some(A64Insn::MovkMovk64Movewide {
                hw: 2,
                imm16: 0xABCD,
                rd: 5,
            })
        );
        assert_eq!(
            A64Insn::decode(0x3638_0006),
            Some(A64Insn::TbzTbzOnlyTestbranch {
                b5: 0,
                b40: 7,
                imm14: 0,
                rt: 6,
            })
        );
        assert_eq!(
            A64Insn::decode(0xB708_0007),
            Some(A64Insn::TbnzTbnzOnlyTestbranch {
                b5: 1,
                b40: 1,
                imm14: 0,
                rt: 7,
            })
        );
        assert_eq!(
            A64Insn::decode(0xF940_0928),
            Some(A64Insn::LdrImmGenLdr64LdstPos {
                imm12: 2,
                rn: 9,
                rt: 8,
            })
        );
        assert_eq!(
            A64Insn::decode(0xF900_0D6A),
            Some(A64Insn::StrImmGenStr64LdstPos {
                imm12: 3,
                rn: 11,
                rt: 10,
            })
        );
    }

    #[test]
    fn shared_cfg_splits_conditional_branch_into_basic_blocks() {
        use crate::shared::trans::cfg::build_cfg;

        let base_pc = 0x6000;
        let mut program = Vec::new();
        program.extend_from_slice(
            &encode(A64Insn::MovzMovz64Movewide {
                hw: 0,
                imm16: 5,
                rd: 0,
            })
            .to_le_bytes(),
        );
        program.extend_from_slice(
            &encode(A64Insn::SubsAddsubImmSubs64sAddsubImm {
                sh: 0,
                imm12: 5,
                rn: 0,
                rd: 31,
            })
            .to_le_bytes(),
        );
        program.extend_from_slice(
            &encode(A64Insn::BCondBOnlyCondbranch {
                imm19: branch_imm(8, 19),
                cond: A64Condition::Eq.bits(),
            })
            .to_le_bytes(),
        );
        program.extend_from_slice(
            &encode(A64Insn::MovzMovz64Movewide {
                hw: 0,
                imm16: 0x1111,
                rd: 1,
            })
            .to_le_bytes(),
        );
        program.extend_from_slice(
            &encode(A64Insn::MovzMovz64Movewide {
                hw: 0,
                imm16: 0x2222,
                rd: 1,
            })
            .to_le_bytes(),
        );

        let code = MockCodeProvider::new(base_pc, program);
        let request = TranslationRequest {
            entry_pc: base_pc,
            trigger: TranslationTrigger::Manual,
            regs: None,
        };
        let cfg = build_cfg(&request, &code).unwrap();

        assert_eq!(cfg.blocks.len(), 3);

        assert_eq!(cfg.blocks[0].start_addr, base_pc);
        assert_eq!(cfg.blocks[0].end_addr, base_pc + 12);
        assert_eq!(cfg.blocks[0].insns.len(), 3);
        assert_eq!(&*cfg.blocks[0].prev, &[]);
        assert_eq!(
            &*cfg.blocks[0].next,
            &[cfg.blocks[2].start_addr, cfg.blocks[1].start_addr]
        );

        assert_eq!(cfg.blocks[1].start_addr, base_pc + 12);
        assert_eq!(cfg.blocks[1].end_addr, base_pc + 16);
        assert_eq!(cfg.blocks[1].insns.len(), 1);
        assert_eq!(&*cfg.blocks[1].prev, &[cfg.blocks[0].start_addr]);
        assert_eq!(&*cfg.blocks[1].next, &[cfg.blocks[2].start_addr]);

        assert_eq!(cfg.blocks[2].start_addr, base_pc + 16);
        assert_eq!(cfg.blocks[2].end_addr, base_pc + 20);
        assert_eq!(cfg.blocks[2].insns.len(), 1);
        assert_eq!(
            &*cfg.blocks[2].prev,
            &[cfg.blocks[0].start_addr, cfg.blocks[1].start_addr]
        );
        assert_eq!(&*cfg.blocks[2].next, &[]);
    }

    #[test]
    fn shared_cfg_splits_existing_block_when_branch_targets_middle() {
        use crate::shared::trans::cfg::build_cfg;

        let base_pc = 0x9000;
        let mut program = Vec::new();
        program.extend_from_slice(
            &encode(A64Insn::BCondBOnlyCondbranch {
                imm19: branch_imm(12, 19),
                cond: A64Condition::Eq.bits(),
            })
            .to_le_bytes(),
        );
        program.extend_from_slice(&encode(A64Insn::NopNopHiHints {}).to_le_bytes());
        program.extend_from_slice(&encode(A64Insn::NopNopHiHints {}).to_le_bytes());
        program.extend_from_slice(
            &encode(A64Insn::BUncondBOnlyBranchImm {
                imm26: branch_imm(-4, 26),
            })
            .to_le_bytes(),
        );

        let code = MockCodeProvider::new(base_pc, program);
        let request = TranslationRequest {
            entry_pc: base_pc,
            trigger: TranslationTrigger::Manual,
            regs: None,
        };
        let cfg = build_cfg(&request, &code).unwrap();

        assert_eq!(cfg.blocks.len(), 4);
        assert_eq!(cfg.blocks[0].start_addr, base_pc);
        assert_eq!(cfg.blocks[1].start_addr, base_pc + 4);
        assert_eq!(cfg.blocks[2].start_addr, base_pc + 8);
        assert_eq!(cfg.blocks[3].start_addr, base_pc + 12);

        assert_eq!(cfg.blocks[1].end_addr, base_pc + 8);
        assert_eq!(cfg.blocks[1].insns.len(), 1);
        assert_eq!(&*cfg.blocks[1].prev, &[cfg.blocks[0].start_addr]);
        assert_eq!(&*cfg.blocks[1].next, &[base_pc + 8]);

        assert_eq!(cfg.blocks[2].end_addr, base_pc + 12);
        assert_eq!(cfg.blocks[2].insns.len(), 1);
        assert_eq!(
            &*cfg.blocks[2].prev,
            &[cfg.blocks[0].start_addr, base_pc + 4]
        );
        assert_eq!(&*cfg.blocks[2].next, &[base_pc + 12]);

        assert_eq!(&*cfg.blocks[3].prev, &[base_pc + 8]);
        assert_eq!(&*cfg.blocks[3].next, &[base_pc + 8]);
    }

    fn encode(insn: A64Insn) -> u32 {
        insn.encode()
            .unwrap_or_else(|err| panic!("failed to encode {}: {err:?}", insn.key()))
    }

    fn branch_imm(offset_bytes: i64, bits: u8) -> u32 {
        assert_eq!(offset_bytes % 4, 0);
        let value = offset_bytes >> 2;
        let min = -(1_i64 << (bits - 1));
        let max = (1_i64 << (bits - 1)) - 1;
        assert!((min..=max).contains(&value));
        (value as i128 & ((1_i128 << bits) - 1)) as u32
    }
}
