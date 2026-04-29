use core::fmt;

use crate::shared::platform::{SharedAllocError, SharedVec, GFP_KERNEL};

mod generated;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GprWidth {
    W32,
    X64,
}

impl GprWidth {
    pub const fn bytes(self) -> u16 {
        match self {
            Self::W32 => 4,
            Self::X64 => 8,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BranchCondition {
    Eq,
    Ne,
    Ge,
    Lt,
    Gt,
    Le,
    Al,
}

impl BranchCondition {
    pub fn from_bits(bits: u8) -> Result<Self, DecodeError> {
        match bits {
            0x0 => Ok(Self::Eq),
            0x1 => Ok(Self::Ne),
            0xA => Ok(Self::Ge),
            0xB => Ok(Self::Lt),
            0xC => Ok(Self::Gt),
            0xD => Ok(Self::Le),
            0xE | 0xF => Ok(Self::Al),
            _ => Err(DecodeError::InvalidConditionBits { bits }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MoveWideOp {
    Zero,
    Keep,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcRelOp {
    Adr,
    Adrp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddSubOp {
    Add,
    Sub,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadStoreOp {
    Load,
    Store,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadStoreAddressing {
    UnsignedScaledOffset { imm12: u16 },
    PreIndex { imm9: i16 },
    PostIndex { imm9: i16 },
}

impl LoadStoreAddressing {
    pub fn byte_offset(self, width: GprWidth) -> i32 {
        match self {
            Self::UnsignedScaledOffset { imm12 } => i32::from(imm12) * i32::from(width.bytes()),
            Self::PreIndex { imm9 } | Self::PostIndex { imm9 } => i32::from(imm9),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodedInsnKind {
    Nop,
    MoveWide {
        op: MoveWideOp,
        width: GprWidth,
        rd: u8,
        imm16: u16,
        shift: u8,
    },
    PcRelAddress {
        op: PcRelOp,
        rd: u8,
        target: u64,
    },
    AddSubImm {
        op: AddSubOp,
        width: GprWidth,
        set_flags: bool,
        rd: u8,
        rn: u8,
        imm12: u16,
        shift12: bool,
    },
    Branch {
        target: u64,
    },
    BranchLink {
        target: u64,
    },
    BranchReg {
        rn: u8,
    },
    BranchLinkReg {
        rn: u8,
    },
    Ret {
        rn: u8,
    },
    Svc {
        imm16: u16,
    },
    CondBranch {
        cond: BranchCondition,
        target: u64,
    },
    CompareBranch {
        nonzero: bool,
        width: GprWidth,
        rt: u8,
        target: u64,
    },
    TestBitBranch {
        nonzero: bool,
        width: GprWidth,
        rt: u8,
        bit: u8,
        target: u64,
    },
    LoadStoreImm {
        op: LoadStoreOp,
        width: GprWidth,
        rt: u8,
        rn: u8,
        addressing: LoadStoreAddressing,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedInsn {
    pub pc: u64,
    pub word: u32,
    pub kind: DecodedInsnKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    UnsupportedWord {
        pc: u64,
        word: u32,
    },
    UnsupportedEncoding {
        pc: u64,
        word: u32,
        key: &'static str,
        reason: &'static str,
    },
    MissingField {
        key: &'static str,
        field: &'static str,
    },
    InvalidConditionBits {
        bits: u8,
    },
    Alloc(SharedAllocError),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedWord { pc, word } => {
                write!(f, "unsupported instruction word {word:#010x} at pc {pc:#x}")
            }
            Self::UnsupportedEncoding {
                pc,
                word,
                key,
                reason,
            } => write!(
                f,
                "unsupported generated encoding `{key}` for word {word:#010x} at pc {pc:#x}: {reason}"
            ),
            Self::MissingField { key, field } => {
                write!(f, "generated encoding `{key}` is missing field `{field}`")
            }
            Self::InvalidConditionBits { bits } => {
                write!(f, "unsupported condition bits: {bits:#x}")
            }
            Self::Alloc(err) => write!(f, "allocation failed while decoding: {err:?}"),
        }
    }
}

fn sign_extend(value: u32, bits: u8) -> i64 {
    let shift = 64 - bits as u32;
    ((value as i64) << shift) >> shift
}

fn width_from_encoding(key: &'static str) -> Result<GprWidth, DecodeError> {
    if key.contains("_32_") || key.contains("_32S_") {
        Ok(GprWidth::W32)
    } else if key.contains("_64_") || key.contains("_64S_") {
        Ok(GprWidth::X64)
    } else {
        Err(DecodeError::UnsupportedEncoding {
            pc: 0,
            word: 0,
            key,
            reason: "encoding does not encode operand width",
        })
    }
}

fn field_u32(
    spec: &'static generated::GeneratedInsnSpec,
    word: u32,
    field: &'static str,
) -> Result<u32, DecodeError> {
    spec.extract_field(word, field)
        .ok_or(DecodeError::MissingField {
            key: spec.key,
            field,
        })
}

pub fn decode_word(word: u32, pc: u64) -> Result<DecodedInsn, DecodeError> {
    if word == 0xD503201F {
        return Ok(DecodedInsn {
            pc,
            word,
            kind: DecodedInsnKind::Nop,
        });
    }

    if word & 0xFC00_0000 == 0x9400_0000 {
        let imm26 = word & 0x03FF_FFFF;
        let offset = sign_extend(imm26, 26) << 2;
        return Ok(DecodedInsn {
            pc,
            word,
            kind: DecodedInsnKind::BranchLink {
                target: pc.wrapping_add_signed(offset),
            },
        });
    }

    if word & 0xFFFF_FC1F == 0xD61F_0000 {
        return Ok(DecodedInsn {
            pc,
            word,
            kind: DecodedInsnKind::BranchReg {
                rn: ((word >> 5) & 0x1F) as u8,
            },
        });
    }

    if word & 0xFFFF_FC1F == 0xD63F_0000 {
        return Ok(DecodedInsn {
            pc,
            word,
            kind: DecodedInsnKind::BranchLinkReg {
                rn: ((word >> 5) & 0x1F) as u8,
            },
        });
    }

    if word & 0xFFFF_FC1F == 0xD65F_0000 {
        return Ok(DecodedInsn {
            pc,
            word,
            kind: DecodedInsnKind::Ret {
                rn: ((word >> 5) & 0x1F) as u8,
            },
        });
    }

    if word & 0xFFE0_001F == 0xD400_0001 {
        return Ok(DecodedInsn {
            pc,
            word,
            kind: DecodedInsnKind::Svc {
                imm16: ((word >> 5) & 0xFFFF) as u16,
            },
        });
    }

    let spec = generated::generated_a64_subset_match(word)
        .ok_or(DecodeError::UnsupportedWord { pc, word })?;

    let kind = match spec.key {
        "ADR.ADR_only_pcreladdr" | "ADRP.ADRP_only_pcreladdr" => {
            let rd = field_u32(spec, word, "Rd")? as u8;
            let immhi = field_u32(spec, word, "immhi")?;
            let immlo = field_u32(spec, word, "immlo")?;
            let imm = sign_extend((immhi << 2) | immlo, 21);
            let op = if spec.key.starts_with("ADRP.") || field_u32(spec, word, "op")? != 0 {
                PcRelOp::Adrp
            } else {
                PcRelOp::Adr
            };
            let target = match op {
                PcRelOp::Adr => pc.wrapping_add_signed(imm),
                PcRelOp::Adrp => (pc & !0xFFF).wrapping_add_signed(imm << 12),
            };
            DecodedInsnKind::PcRelAddress { op, rd, target }
        }
        "ADD_addsub_imm.ADD_32_addsub_imm"
        | "ADD_addsub_imm.ADD_64_addsub_imm"
        | "SUB_addsub_imm.SUB_32_addsub_imm"
        | "SUB_addsub_imm.SUB_64_addsub_imm"
        | "SUBS_addsub_imm.SUBS_32S_addsub_imm"
        | "SUBS_addsub_imm.SUBS_64S_addsub_imm" => {
            let width = width_from_encoding(spec.key)?;
            DecodedInsnKind::AddSubImm {
                op: if spec.key.starts_with("ADD_") {
                    AddSubOp::Add
                } else {
                    AddSubOp::Sub
                },
                width,
                set_flags: field_u32(spec, word, "S")? != 0,
                rd: field_u32(spec, word, "Rd")? as u8,
                rn: field_u32(spec, word, "Rn")? as u8,
                imm12: field_u32(spec, word, "imm12")? as u16,
                shift12: field_u32(spec, word, "sh")? != 0,
            }
        }
        "B_uncond.B_only_branch_imm" => {
            let imm26 = field_u32(spec, word, "imm26")?;
            let offset = sign_extend(imm26, 26) << 2;
            DecodedInsnKind::Branch {
                target: pc.wrapping_add_signed(offset),
            }
        }
        "B_cond.B_only_condbranch" => {
            let imm19 = field_u32(spec, word, "imm19")?;
            let offset = sign_extend(imm19, 19) << 2;
            let cond = BranchCondition::from_bits(field_u32(spec, word, "cond")? as u8)?;
            DecodedInsnKind::CondBranch {
                cond,
                target: pc.wrapping_add_signed(offset),
            }
        }
        "CBZ.CBZ_32_compbranch"
        | "CBZ.CBZ_64_compbranch"
        | "CBNZ.CBNZ_32_compbranch"
        | "CBNZ.CBNZ_64_compbranch" => {
            let width = width_from_encoding(spec.key)?;
            let imm19 = field_u32(spec, word, "imm19")?;
            let offset = sign_extend(imm19, 19) << 2;
            DecodedInsnKind::CompareBranch {
                nonzero: spec.key.starts_with("CBNZ."),
                width,
                rt: field_u32(spec, word, "Rt")? as u8,
                target: pc.wrapping_add_signed(offset),
            }
        }
        "MOVZ.MOVZ_32_movewide"
        | "MOVZ.MOVZ_64_movewide"
        | "MOVK.MOVK_32_movewide"
        | "MOVK.MOVK_64_movewide" => {
            let width = width_from_encoding(spec.key)?;
            DecodedInsnKind::MoveWide {
                op: if spec.key.starts_with("MOVK.") {
                    MoveWideOp::Keep
                } else {
                    MoveWideOp::Zero
                },
                width,
                rd: field_u32(spec, word, "Rd")? as u8,
                imm16: field_u32(spec, word, "imm16")? as u16,
                shift: (field_u32(spec, word, "hw")? as u8) * 16,
            }
        }
        "TBZ.TBZ_only_testbranch" | "TBNZ.TBNZ_only_testbranch" => {
            let imm14 = field_u32(spec, word, "imm14")?;
            let offset = sign_extend(imm14, 14) << 2;
            let b5 = field_u32(spec, word, "b5")? as u8;
            let b40 = field_u32(spec, word, "b40")? as u8;
            DecodedInsnKind::TestBitBranch {
                nonzero: spec.key.starts_with("TBNZ."),
                width: if b5 == 0 {
                    GprWidth::W32
                } else {
                    GprWidth::X64
                },
                rt: field_u32(spec, word, "Rt")? as u8,
                bit: (b5 << 5) | b40,
                target: pc.wrapping_add_signed(offset),
            }
        }
        "LDR_imm_gen.LDR_32_ldst_immpost"
        | "LDR_imm_gen.LDR_64_ldst_immpost"
        | "LDR_imm_gen.LDR_32_ldst_immpre"
        | "LDR_imm_gen.LDR_64_ldst_immpre"
        | "LDR_imm_gen.LDR_32_ldst_pos"
        | "LDR_imm_gen.LDR_64_ldst_pos"
        | "STR_imm_gen.STR_32_ldst_immpost"
        | "STR_imm_gen.STR_64_ldst_immpost"
        | "STR_imm_gen.STR_32_ldst_immpre"
        | "STR_imm_gen.STR_64_ldst_immpre"
        | "STR_imm_gen.STR_32_ldst_pos"
        | "STR_imm_gen.STR_64_ldst_pos" => {
            let width = width_from_encoding(spec.key)?;
            let addressing = if spec.key.ends_with("_ldst_pos") {
                LoadStoreAddressing::UnsignedScaledOffset {
                    imm12: field_u32(spec, word, "imm12")? as u16,
                }
            } else if spec.key.ends_with("_ldst_immpre") {
                LoadStoreAddressing::PreIndex {
                    imm9: sign_extend(field_u32(spec, word, "imm9")?, 9) as i16,
                }
            } else {
                LoadStoreAddressing::PostIndex {
                    imm9: sign_extend(field_u32(spec, word, "imm9")?, 9) as i16,
                }
            };
            DecodedInsnKind::LoadStoreImm {
                op: if spec.key.starts_with("LDR_") {
                    LoadStoreOp::Load
                } else {
                    LoadStoreOp::Store
                },
                width,
                rt: field_u32(spec, word, "Rt")? as u8,
                rn: field_u32(spec, word, "Rn")? as u8,
                addressing,
            }
        }
        _ => {
            return Err(DecodeError::UnsupportedEncoding {
                pc,
                word,
                key: spec.key,
                reason: "no typed importer exists for this generated encoding yet",
            });
        }
    };

    Ok(DecodedInsn { pc, word, kind })
}

pub fn decode_program(program: &[u8], base_pc: u64) -> Result<SharedVec<DecodedInsn>, DecodeError> {
    if program.len() % 4 != 0 {
        return Err(DecodeError::UnsupportedEncoding {
            pc: base_pc,
            word: 0,
            key: "program",
            reason: "program length must be a multiple of 4 bytes",
        });
    }

    let mut decoded =
        SharedVec::with_capacity(program.len() / 4, GFP_KERNEL).map_err(DecodeError::Alloc)?;
    for (index, chunk) in program.chunks_exact(4).enumerate() {
        let pc = base_pc + (index as u64) * 4;
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        decoded
            .push(decode_word(word, pc)?, GFP_KERNEL)
            .map_err(DecodeError::Alloc)?;
    }
    Ok(decoded)
}
