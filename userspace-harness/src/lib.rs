pub mod arm64;
pub mod cases;
pub mod lowered;
pub mod model;
pub mod translate;

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

    #[test]
    fn built_in_cases_pass() {
        for case in cases::built_in_cases() {
            if let Err(err) = run_case(&case) {
                panic!("case `{}` failed: {err}", case.name);
            }
        }
    }
}
