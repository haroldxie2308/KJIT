use crate::shared::arm64::IrInsn;
use crate::shared::emit::layout::{layout_program, ExecutionFragment, LayoutError};
use crate::shared::platform::{SharedAllocError, SharedResult, SharedVec, GFP_KERNEL};
use crate::shared::trans::cfg::{build_cfg, CfgError};
use crate::shared::trans::input::{CodeProvider, TranslationRequest};
use crate::shared::trans::reg_virt::{virtualize_registers, RegVirtError};
use crate::shared::trans::rephrase::rephrase;

/// Legacy shallow CFG flattening output.
///
/// This is not the executable-fragment compiler path. New userspace validation
/// should use `compile_request`.
pub type LegacyTranslatedProgram = SharedVec<IrInsn>;
pub type TranslatedProgram = LegacyTranslatedProgram;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranslateError {
    Cfg(CfgError),
    Alloc(SharedAllocError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompileError {
    Cfg(CfgError),
    Rephrase(SharedAllocError),
    RegVirt(RegVirtError),
    Layout(LayoutError),
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

impl core::fmt::Display for CompileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cfg(err) => write!(f, "{err}"),
            Self::Rephrase(err) => write!(f, "allocation failed while rephrasing: {err:?}"),
            Self::RegVirt(err) => write!(f, "register virtualization failed: {err:?}"),
            Self::Layout(err) => write!(f, "{err}"),
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

pub fn compile_request<P: CodeProvider>(
    request: &TranslationRequest,
    code: &P,
) -> SharedResult<ExecutionFragment, CompileError> {
    let cfg = build_cfg(request, code).map_err(CompileError::Cfg)?;
    let rephrased = rephrase(cfg).map_err(CompileError::Rephrase)?;
    let virtualized = virtualize_registers(rephrased).map_err(CompileError::RegVirt)?;
    layout_program(virtualized).map_err(CompileError::Layout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::abi::{EPILOGUE_LEN_BYTES, PROLOGUE_LEN_BYTES};
    use crate::shared::arm64::{A64Imm, A64Insn};
    use crate::shared::trans::input::{CodeReadError, TranslationRequest, TranslationTrigger};

    struct TestCode {
        base_pc: u64,
        words: [u32; 2],
    }

    impl CodeProvider for TestCode {
        fn entry_addr(&self) -> u64 {
            self.base_pc
        }

        fn read_exact(&self, pc: u64, dst: &mut [u8]) -> Result<(), CodeReadError> {
            let Some(relative) = pc.checked_sub(self.base_pc) else {
                return Err(CodeReadError::Unmapped { pc, len: dst.len() });
            };
            if relative % 4 != 0 {
                return Err(CodeReadError::Unmapped { pc, len: dst.len() });
            }
            let index = (relative / 4) as usize;
            let Some(word) = self.words.get(index) else {
                return Err(CodeReadError::Unmapped { pc, len: dst.len() });
            };
            if dst.len() != 4 {
                return Err(CodeReadError::Unmapped { pc, len: dst.len() });
            }
            dst.copy_from_slice(&word.to_le_bytes());
            Ok(())
        }
    }

    #[test]
    fn compile_request_returns_encodable_wrapped_fragment() {
        let base_pc = 0x4000;
        let code = TestCode {
            base_pc,
            words: [
                A64Insn::SvcSvcExException {
                    imm16: A64Imm::unsigned(0, 16),
                }
                .encode()
                .unwrap(),
                A64Insn::NopNopHiHints {}.encode().unwrap(),
            ],
        };
        let request = TranslationRequest {
            entry_pc: base_pc,
            trigger: TranslationTrigger::Manual,
            regs: None,
        };

        let fragment = compile_request(&request, &code).unwrap();

        assert!(fragment.insns.len() > (PROLOGUE_LEN_BYTES + EPILOGUE_LEN_BYTES) / 4);
        assert_eq!(
            fragment.entry_offset,
            PROLOGUE_LEN_BYTES + EPILOGUE_LEN_BYTES
        );
        for insn in &fragment.insns {
            insn.encode().unwrap();
        }
    }
}
