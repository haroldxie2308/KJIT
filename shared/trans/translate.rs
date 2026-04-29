use crate::shared::arm64::DecodedInsn;
use crate::shared::platform::{SharedAllocError, SharedResult, SharedVec, GFP_KERNEL};
use crate::shared::trans::cfg::{build_cfg, CfgError};
use crate::shared::trans::input::{CodeProvider, TranslationRequest};

pub type TranslatedProgram = SharedVec<DecodedInsn>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranslateError {
    Cfg(CfgError),
    Alloc(SharedAllocError),
}

impl From<CfgError> for TranslateError {
    fn from(err: CfgError) -> Self {
        Self::Cfg(err)
    }
}

impl core::fmt::Display for TranslateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cfg(err) => write!(f, "{err}"),
            Self::Alloc(err) => write!(f, "allocation failed while translating: {err:?}"),
        }
    }
}

pub fn translate_request<P: CodeProvider>(
    request: &TranslationRequest,
    code: &P,
) -> SharedResult<TranslatedProgram, TranslateError> {
    let cfg = build_cfg(request, code)?;
    let insn_count = cfg.blocks.iter().map(|block| block.insns.len()).sum();
    let mut program =
        TranslatedProgram::with_capacity(insn_count, GFP_KERNEL).map_err(TranslateError::Alloc)?;

    for block in &cfg.blocks {
        for insn in &block.insns {
            program
                .push(*insn, GFP_KERNEL)
                .map_err(TranslateError::Alloc)?;
        }
    }

    Ok(program)
}
