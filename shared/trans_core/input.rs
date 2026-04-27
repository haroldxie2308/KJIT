use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranslationTrigger {
    Manual,
    HotSvc,
    BranchDiscovery { source_pc: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterSnapshot {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TranslationRequest {
    pub entry_pc: u64,
    pub trigger: TranslationTrigger,
    pub regs: Option<RegisterSnapshot>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeReadError {
    Unmapped { pc: u64, len: usize },
}

impl fmt::Display for CodeReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unmapped { pc, len } => {
                write!(f, "code read is outside mapped text: pc={pc:#x}, len={len}")
            }
        }
    }
}

pub trait CodeProvider {
    fn read_exact(&self, pc: u64, dst: &mut [u8]) -> Result<(), CodeReadError>;
}
