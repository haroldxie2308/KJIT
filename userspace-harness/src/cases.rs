use crate::arm64::{assemble_program, AsmInsn, Condition};
use crate::model::MachineState;

#[derive(Clone, Debug)]
pub struct HarnessCase {
    pub name: &'static str,
    pub description: &'static str,
    pub base_pc: u64,
    pub initial_state: MachineState,
    pub original_program: Vec<u8>,
}

pub fn built_in_cases() -> Vec<HarnessCase> {
    vec![
        adr_to_load_imm(),
        adrp_to_load_imm(),
        conditional_branch_taken(),
        compare_and_branch_not_zero(),
        memory_roundtrip(),
    ]
}

pub fn find_case(name: &str) -> Option<HarnessCase> {
    built_in_cases().into_iter().find(|case| case.name == name)
}

fn adr_to_load_imm() -> HarnessCase {
    let base_pc = 0x4000;
    let mut initial_state = MachineState::new();
    initial_state.write_reg(2, 0x8000);

    let original_program = assemble_program(
        base_pc,
        &[
            AsmInsn::Adr {
                rd: 0,
                value: base_pc + 12,
            },
            AsmInsn::AddImm {
                rd: 0,
                rn: 0,
                imm12: 0x20,
            },
            AsmInsn::StrImm {
                rt: 0,
                rn: 2,
                offset: 0,
            },
        ],
    )
    .unwrap();

    HarnessCase {
        name: "adr_to_load_imm",
        description: "Lower ADR into an explicit immediate load and preserve side effects.",
        base_pc,
        initial_state,
        original_program,
    }
}

fn adrp_to_load_imm() -> HarnessCase {
    let base_pc = 0x4010;
    let mut initial_state = MachineState::new();
    initial_state.write_reg(4, 0x8100);

    let original_program = assemble_program(
        base_pc,
        &[
            AsmInsn::Adrp {
                rd: 3,
                value: 0x5000,
            },
            AsmInsn::AddImm {
                rd: 3,
                rn: 3,
                imm12: 0x88,
            },
            AsmInsn::StrImm {
                rt: 3,
                rn: 4,
                offset: 8,
            },
        ],
    )
    .unwrap();

    HarnessCase {
        name: "adrp_to_load_imm",
        description: "Lower ADRP into an explicit immediate load while preserving page semantics.",
        base_pc,
        initial_state,
        original_program,
    }
}

fn conditional_branch_taken() -> HarnessCase {
    let base_pc = 0x6000;
    let initial_state = MachineState::new();

    let original_program = assemble_program(
        base_pc,
        &[
            AsmInsn::Movz {
                rd: 0,
                imm16: 5,
                shift: 0,
            },
            AsmInsn::CmpImm { rn: 0, imm12: 5 },
            AsmInsn::BCond {
                cond: Condition::Eq,
                target: 4,
            },
            AsmInsn::Movz {
                rd: 1,
                imm16: 0x1111,
                shift: 0,
            },
            AsmInsn::Movz {
                rd: 1,
                imm16: 0x2222,
                shift: 0,
            },
        ],
    )
    .unwrap();

    HarnessCase {
        name: "conditional_branch_taken",
        description: "Preserve flag behavior and conditional branch resolution.",
        base_pc,
        initial_state,
        original_program,
    }
}

fn compare_and_branch_not_zero() -> HarnessCase {
    let base_pc = 0x7000;
    let initial_state = MachineState::new();

    let original_program = assemble_program(
        base_pc,
        &[
            AsmInsn::Movz {
                rd: 0,
                imm16: 3,
                shift: 0,
            },
            AsmInsn::Cbnz { rt: 0, target: 3 },
            AsmInsn::Movz {
                rd: 1,
                imm16: 1,
                shift: 0,
            },
            AsmInsn::Movz {
                rd: 1,
                imm16: 2,
                shift: 0,
            },
        ],
    )
    .unwrap();

    HarnessCase {
        name: "compare_and_branch_not_zero",
        description: "Preserve compare-and-branch behavior for the non-zero path.",
        base_pc,
        initial_state,
        original_program,
    }
}

fn memory_roundtrip() -> HarnessCase {
    let base_pc = 0x8000;
    let mut initial_state = MachineState::new();
    initial_state.write_reg(2, 0x9000);
    initial_state.seed_memory_u64(0x9008, 0);

    let original_program = assemble_program(
        base_pc,
        &[
            AsmInsn::Movz {
                rd: 0,
                imm16: 0x1234,
                shift: 0,
            },
            AsmInsn::StrImm {
                rt: 0,
                rn: 2,
                offset: 8,
            },
            AsmInsn::LdrImm {
                rt: 1,
                rn: 2,
                offset: 8,
            },
            AsmInsn::SubImm {
                rd: 1,
                rn: 1,
                imm12: 0x34,
            },
        ],
    )
    .unwrap();

    HarnessCase {
        name: "memory_roundtrip",
        description: "Preserve modeled memory effects across store and load operations.",
        base_pc,
        initial_state,
        original_program,
    }
}
