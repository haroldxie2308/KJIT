use crate::shared::platform::SharedResult;
use crate::shared::trans::rephrase::RephrasedProgram;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeRegConvention {
    pub status_reg: u8,
    pub param0_reg: u8,
    pub param1_reg: u8,
}

impl RuntimeRegConvention {
    pub const KJIT_DEFAULT: Self = Self {
        status_reg: 9,
        param0_reg: 10,
        param1_reg: 11,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegVirtConfig {
    pub convention: RuntimeRegConvention,
}

impl RegVirtConfig {
    pub const KJIT_DEFAULT: Self = Self {
        convention: RuntimeRegConvention::KJIT_DEFAULT,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegVirtError {
    UnsupportedOperandRole,
}

pub fn virtualize_registers(
    program: RephrasedProgram,
    _config: &RegVirtConfig,
) -> SharedResult<RephrasedProgram, RegVirtError> {
    Ok(program)
}
