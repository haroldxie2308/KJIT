extern crate alloc;

pub mod arm64;
pub mod model;
#[path = "../../shared/mod.rs"]
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
            .insn
            .encode()
            .map_err(|err| format!("failed to encode {}: {err:?}", insn.insn.key()))?;
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

    mod generated_a64_spec {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../spec/arm64/generated/a64_subset.rs"
        ));
    }

    #[test]
    fn generated_arm64_subset_matches_sample_opcodes() {
        use generated_a64_spec::generated_a64_subset_match;

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
            let spec = generated_a64_subset_match(opcode)
                .unwrap_or_else(|| panic!("no generated spec matched opcode {opcode:#010x}"));
            assert_eq!(
                spec.key, expected_key,
                "unexpected match for opcode {opcode:#010x}"
            );
        }
    }

    #[test]
    fn generated_arm64_subset_extracts_expected_fields() {
        use generated_a64_spec::generated_a64_subset_match;

        let add = generated_a64_subset_match(0x9100_1441).unwrap();
        assert_eq!(add.extract_field(0x9100_1441, "imm12"), Some(5));
        assert_eq!(add.extract_field(0x9100_1441, "Rn"), Some(2));
        assert_eq!(add.extract_field(0x9100_1441, "Rd"), Some(1));

        let movz = generated_a64_subset_match(0xD2A2_4685).unwrap();
        assert_eq!(movz.extract_field(0xD2A2_4685, "hw"), Some(1));
        assert_eq!(movz.extract_field(0xD2A2_4685, "imm16"), Some(0x1234));
        assert_eq!(movz.extract_field(0xD2A2_4685, "Rd"), Some(5));

        let movk = generated_a64_subset_match(0xF2D5_79A5).unwrap();
        assert_eq!(movk.extract_field(0xF2D5_79A5, "hw"), Some(2));
        assert_eq!(movk.extract_field(0xF2D5_79A5, "imm16"), Some(0xABCD));
        assert_eq!(movk.extract_field(0xF2D5_79A5, "Rd"), Some(5));

        let tbz = generated_a64_subset_match(0x3638_0006).unwrap();
        assert_eq!(tbz.extract_field(0x3638_0006, "b5"), Some(0));
        assert_eq!(tbz.extract_field(0x3638_0006, "b40"), Some(7));
        assert_eq!(tbz.extract_field(0x3638_0006, "Rt"), Some(6));

        let tbnz = generated_a64_subset_match(0xB708_0007).unwrap();
        assert_eq!(tbnz.extract_field(0xB708_0007, "b5"), Some(1));
        assert_eq!(tbnz.extract_field(0xB708_0007, "b40"), Some(1));
        assert_eq!(tbnz.extract_field(0xB708_0007, "Rt"), Some(7));

        let ldr = generated_a64_subset_match(0xF940_0928).unwrap();
        assert_eq!(ldr.extract_field(0xF940_0928, "size"), Some(3));
        assert_eq!(ldr.extract_field(0xF940_0928, "imm12"), Some(2));
        assert_eq!(ldr.extract_field(0xF940_0928, "Rn"), Some(9));
        assert_eq!(ldr.extract_field(0xF940_0928, "Rt"), Some(8));

        let str_ = generated_a64_subset_match(0xF900_0D6A).unwrap();
        assert_eq!(str_.extract_field(0xF900_0D6A, "size"), Some(3));
        assert_eq!(str_.extract_field(0xF900_0D6A, "imm12"), Some(3));
        assert_eq!(str_.extract_field(0xF900_0D6A, "Rn"), Some(11));
        assert_eq!(str_.extract_field(0xF900_0D6A, "Rt"), Some(10));
    }

    #[test]
    fn shared_cfg_splits_conditional_branch_into_basic_blocks() {
        use crate::arm64::Condition;
        use crate::shared::trans::cfg::{build_cfg, BlockTerminator};

        let base_pc = 0x6000;
        let mut program = Vec::new();
        program.extend_from_slice(&crate::arm64::encode_movz(0, 5, 0).unwrap().to_le_bytes());
        program.extend_from_slice(&crate::arm64::encode_cmp_imm(0, 5).to_le_bytes());
        program.extend_from_slice(
            &crate::arm64::encode_b_cond(Condition::Eq, 8)
                .unwrap()
                .to_le_bytes(),
        );
        program.extend_from_slice(
            &crate::arm64::encode_movz(1, 0x1111, 0)
                .unwrap()
                .to_le_bytes(),
        );
        program.extend_from_slice(
            &crate::arm64::encode_movz(1, 0x2222, 0)
                .unwrap()
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
        assert_eq!(
            cfg.blocks[0].terminator,
            BlockTerminator::CondBranch {
                taken_pc: cfg.blocks[2].start_addr,
                fallthrough_pc: cfg.blocks[1].start_addr,
            }
        );

        assert_eq!(cfg.blocks[1].start_addr, base_pc + 12);
        assert_eq!(cfg.blocks[1].end_addr, base_pc + 16);
        assert_eq!(cfg.blocks[1].insns.len(), 1);
        assert_eq!(
            cfg.blocks[1].terminator,
            BlockTerminator::Fallthrough {
                next_pc: Some(cfg.blocks[2].start_addr),
            }
        );

        assert_eq!(cfg.blocks[2].start_addr, base_pc + 16);
        assert_eq!(cfg.blocks[2].end_addr, base_pc + 20);
        assert_eq!(cfg.blocks[2].insns.len(), 1);
        assert_eq!(
            cfg.blocks[2].terminator,
            BlockTerminator::Fallthrough { next_pc: None }
        );
    }

    #[test]
    fn shared_cfg_splits_existing_block_when_branch_targets_middle() {
        use crate::arm64::Condition;
        use crate::shared::trans::cfg::{build_cfg, BlockTerminator};

        let base_pc = 0x9000;
        let mut program = Vec::new();
        program.extend_from_slice(
            &crate::arm64::encode_b_cond(Condition::Eq, 12)
                .unwrap()
                .to_le_bytes(),
        );
        program.extend_from_slice(&0xd503_201f_u32.to_le_bytes());
        program.extend_from_slice(&0xd503_201f_u32.to_le_bytes());
        program.extend_from_slice(&crate::arm64::encode_b(-4).unwrap().to_le_bytes());

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
        assert_eq!(
            cfg.blocks[1].terminator,
            BlockTerminator::Fallthrough {
                next_pc: Some(base_pc + 8),
            }
        );

        assert_eq!(cfg.blocks[2].end_addr, base_pc + 12);
        assert_eq!(cfg.blocks[2].insns.len(), 1);
        assert_eq!(
            cfg.blocks[2].terminator,
            BlockTerminator::Fallthrough {
                next_pc: Some(base_pc + 12),
            }
        );

        assert_eq!(
            cfg.blocks[3].terminator,
            BlockTerminator::Branch {
                target_pc: base_pc + 8,
            }
        );
    }
}
