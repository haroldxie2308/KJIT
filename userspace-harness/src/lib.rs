extern crate alloc;

pub mod arm64;
pub mod cases;
pub mod lowered;
pub mod model;
pub mod translate;
#[path = "../../shared/trans_core/mod.rs"]
pub mod trans_core;

use cases::HarnessCase;
use lowered::{encode_program, execute_program as execute_lowered};
use model::NormalizedState;
use translate::translate_program;

#[derive(Debug)]
pub struct CaseReport {
    pub name: &'static str,
    pub lowered_program: Vec<lowered::LoweredInsn>,
    pub encoded_program: Vec<u8>,
    pub original_state: NormalizedState,
    pub lowered_state: NormalizedState,
    pub encoded_state: NormalizedState,
}

pub fn run_case(case: &HarnessCase) -> Result<CaseReport, String> {
    let original =
        arm64::execute_program(&case.original_program, case.base_pc, &case.initial_state)?;
    let lowered_program = translate_program(&case.original_program, case.base_pc)?;
    let lowered = execute_lowered(&lowered_program, &case.initial_state)?;
    let encoded_program = encode_program(&lowered_program)?;
    let encoded = arm64::execute_program(&encoded_program, case.base_pc, &case.initial_state)?;

    let original_state = NormalizedState::from_execution(&original);
    let lowered_state = NormalizedState::from_execution(&lowered);
    let encoded_state = NormalizedState::from_execution(&encoded);

    if original_state != lowered_state {
        return Err(format!(
            "original vs lowered mismatch for `{}`\noriginal: {:#?}\nlowered: {:#?}",
            case.name, original_state, lowered_state
        ));
    }

    if lowered_state != encoded_state {
        return Err(format!(
            "lowered vs encoded mismatch for `{}`\nlowered: {:#?}\nencoded: {:#?}",
            case.name, lowered_state, encoded_state
        ));
    }

    Ok(CaseReport {
        name: case.name,
        lowered_program,
        encoded_program,
        original_state,
        lowered_state,
        encoded_state,
    })
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
    fn built_in_cases_pass() {
        for case in cases::built_in_cases() {
            if let Err(err) = run_case(&case) {
                panic!("case `{}` failed: {err}", case.name);
            }
        }
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
            assert_eq!(spec.key, expected_key, "unexpected match for opcode {opcode:#010x}");
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
    fn shared_typed_decode_maps_sample_opcodes() {
        use crate::trans_core::arm64::{
            decode_word, AddSubOp, DecodedInsnKind, GprWidth, LoadStoreAddressing, LoadStoreOp,
            MoveWideOp, PcRelOp,
        };

        let adrp = decode_word(0xB000_0003, 0x4010).unwrap();
        assert_eq!(
            adrp.kind,
            DecodedInsnKind::PcRelAddress {
                op: PcRelOp::Adrp,
                rd: 3,
                target: 0x5000,
            }
        );

        let cmp = decode_word(0xF100_141F, 0x6004).unwrap();
        assert_eq!(
            cmp.kind,
            DecodedInsnKind::AddSubImm {
                op: AddSubOp::Sub,
                width: GprWidth::X64,
                set_flags: true,
                rd: 31,
                rn: 0,
                imm12: 5,
                shift12: false,
            }
        );

        let movk = decode_word(0xF2D5_79A5, 0x1C).unwrap();
        assert_eq!(
            movk.kind,
            DecodedInsnKind::MoveWide {
                op: MoveWideOp::Keep,
                width: GprWidth::X64,
                rd: 5,
                imm16: 0xABCD,
                shift: 32,
            }
        );

        let ldr = decode_word(0xF940_0928, 0x28).unwrap();
        assert_eq!(
            ldr.kind,
            DecodedInsnKind::LoadStoreImm {
                op: LoadStoreOp::Load,
                width: GprWidth::X64,
                rt: 8,
                rn: 9,
                addressing: LoadStoreAddressing::UnsignedScaledOffset { imm12: 2 },
            }
        );
    }

    #[test]
    fn shared_cfg_splits_conditional_branch_into_basic_blocks() {
        use crate::trans_core::arm64::decode_program;
        use crate::trans_core::cfg::{build_cfg, BlockTerminator};

        let case = crate::cases::find_case("conditional_branch_taken").unwrap();
        let decoded = decode_program(&case.original_program, case.base_pc).unwrap();
        let cfg = build_cfg(&decoded).unwrap();

        assert_eq!(cfg.blocks.len(), 3);

        assert_eq!(cfg.blocks[0].start_index, 0);
        assert_eq!(cfg.blocks[0].end_index, 3);
        assert_eq!(
            cfg.blocks[0].terminator,
            BlockTerminator::CondBranch {
                taken: cfg.blocks[2].id,
                fallthrough: cfg.blocks[1].id,
            }
        );

        assert_eq!(cfg.blocks[1].start_index, 3);
        assert_eq!(cfg.blocks[1].end_index, 4);
        assert_eq!(
            cfg.blocks[1].terminator,
            BlockTerminator::Fallthrough {
                next: Some(cfg.blocks[2].id),
            }
        );

        assert_eq!(cfg.blocks[2].start_index, 4);
        assert_eq!(cfg.blocks[2].end_index, 5);
        assert_eq!(cfg.blocks[2].terminator, BlockTerminator::Fallthrough { next: None });
    }
}
