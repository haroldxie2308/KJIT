//! A generated program: the fixture layout (hot `svc #0` at the text base,
//! translation from the next word) with program-internal branch targets kept as
//! slot indices, so the minimizer can delete slots and re-encode.

use crate::shared::arm64::{A64Imm, A64Insn};
use crate::FIXTURE_TEXT_BASE;

pub const TEXT_BASE: u64 = FIXTURE_TEXT_BASE;
/// Slot 0's PC: the word after the hot SVC.
pub const ENTRY_PC: u64 = TEXT_BASE + 4;

pub fn hot_svc_word() -> u32 {
    A64Insn::SvcSvcExException {
        imm16: A64Imm::unsigned(0, 16),
    }
    .encode()
    .expect("svc #0 encodes")
}

pub fn nop_word() -> u32 {
    A64Insn::NopNopHiHints {}.encode().expect("nop encodes")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// A fixed word: anything whose meaning does not depend on the slot layout
    /// (BL and ADR/ADRP targets are outside the text, see `Program::validate`).
    Word(u32),
    /// A branch to slot `target`, re-encoded from the layout.
    Branch {
        insn: A64Insn,
        field: &'static str,
        bits: u8,
        scale: u8,
        target: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    pub slots: Vec<Slot>,
}

pub fn slot_pc(index: usize) -> u64 {
    ENTRY_PC + index as u64 * 4
}

impl Program {
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// First PC past the text.
    pub fn end_pc(&self) -> u64 {
        slot_pc(self.slots.len())
    }

    /// Body words, slot 0 first.
    pub fn words(&self) -> Result<Vec<u32>, String> {
        self.slots
            .iter()
            .enumerate()
            .map(|(index, slot)| encode_slot(index, *slot))
            .collect()
    }

    /// The full text: hot SVC, then the body.
    pub fn text_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = hot_svc_word().to_le_bytes().to_vec();
        for word in self.words()? {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        Ok(bytes)
    }

    /// Structural invariants every generated or minimized program keeps:
    /// - every branch target is a slot (translation can't start past the text);
    /// - the last slot is not a conditional branch or SVC, whose fallthrough
    ///   would be past the text (the CFG builder can't read it);
    /// - no ADR/ADRP computes an address inside the body: a register branch to
    ///   it would chain into the fragment, which the original interpreter does
    ///   not model;
    /// - every slot encodes.
    pub fn validate(&self) -> Result<(), String> {
        let Some(last) = self.slots.last() else {
            return Err("empty program".to_string());
        };
        let words = self.words()?;
        for (index, slot) in self.slots.iter().enumerate() {
            if let Slot::Branch { target, .. } = slot {
                if *target >= self.slots.len() {
                    return Err(format!(
                        "slot {index}: branch target {target} past the text"
                    ));
                }
            }
            if let Some(address) = A64Insn::decode(words[index])
                .and_then(|insn| insn.pc_relative_address(slot_pc(index)))
            {
                if (ENTRY_PC..self.end_pc()).contains(&address) {
                    return Err(format!(
                        "slot {index}: ADR/ADRP into the body ({address:#x})"
                    ));
                }
            }
        }
        let last_pc = slot_pc(self.slots.len() - 1);
        let falls_past_end = match *last {
            Slot::Branch { insn, .. } => insn.conditional_targets(last_pc).is_some(),
            Slot::Word(word) => A64Insn::decode(word).is_some_and(|insn| {
                matches!(
                    insn.runtime_exit_reason(last_pc),
                    Some(crate::shared::trans::cfg::RuntimeExitReason::Svc { .. })
                ) || insn.conditional_targets(last_pc).is_some()
            }),
        };
        if falls_past_end {
            return Err("last slot falls through past the text".to_string());
        }
        Ok(())
    }

    /// Removes `range`; branches into it move to the slot that follows it.
    pub fn without(&self, range: std::ops::Range<usize>) -> Program {
        let removed = range.len();
        let slots = self
            .slots
            .iter()
            .enumerate()
            .filter(|(index, _)| !range.contains(index))
            .map(|(_, slot)| match *slot {
                Slot::Branch {
                    insn,
                    field,
                    bits,
                    scale,
                    target,
                } => Slot::Branch {
                    insn,
                    field,
                    bits,
                    scale,
                    target: if target >= range.end {
                        target - removed
                    } else if target >= range.start {
                        range.start
                    } else {
                        target
                    },
                },
                word => word,
            })
            .collect();
        Program { slots }
    }

    /// `words` inserted before slot 0; every branch target shifts with the body.
    pub fn with_prefix(&self, words: &[u32]) -> Program {
        let mut slots: Vec<Slot> = words.iter().map(|&word| Slot::Word(word)).collect();
        slots.extend(self.slots.iter().map(|slot| match *slot {
            Slot::Branch {
                insn,
                field,
                bits,
                scale,
                target,
            } => Slot::Branch {
                insn,
                field,
                bits,
                scale,
                target: target + words.len(),
            },
            word => word,
        }));
        Program { slots }
    }
}

fn encode_slot(index: usize, slot: Slot) -> Result<u32, String> {
    match slot {
        Slot::Word(word) => Ok(word),
        Slot::Branch {
            insn,
            field,
            bits,
            scale,
            target,
        } => {
            let delta_bytes = (target as i64 - index as i64) * 4;
            let encoded = branch_field_value(delta_bytes, bits, scale).ok_or_else(|| {
                format!("slot {index}: branch delta {delta_bytes} does not fit {field}")
            })?;
            insn.set_branch_target_imm(field, encoded)
                .map_err(|err| format!("slot {index}: {err:?}"))?
                .encode()
                .map_err(|err| format!("slot {index}: {err:?}"))
        }
    }
}

/// The raw field value for a PC-relative byte delta, or `None` if it does not fit.
pub fn branch_field_value(delta_bytes: i64, bits: u8, scale: u8) -> Option<u32> {
    if delta_bytes % (1 << scale) != 0 {
        return None;
    }
    let units = delta_bytes >> scale;
    let half = 1_i64 << (bits - 1);
    (-half..half)
        .contains(&units)
        .then(|| (units & ((1_i64 << bits) - 1)) as u32)
}
