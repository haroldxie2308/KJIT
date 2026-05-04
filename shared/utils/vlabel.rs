use crate::shared::platform::SharedVec;
use crate::shared::platform::GFP_KERNEL;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VLabel {
    pub original_pc: u64,
    pub offset: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub struct VLabels {
    entries: SharedVec<VLabel>,
}

impl VLabels {
    pub fn from_entries(entries: SharedVec<VLabel>) -> Self {
        Self { entries }
    }

    pub fn insert(&mut self, original_pc: u64, offset: usize) {
        self.entries.push(VLabel {
            original_pc,
            offset,
        }, GFP_KERNEL).expect("Failed to insert VLabel");
    }

    pub fn offset_for_pc(&self, original_pc: u64) -> Option<usize> {
        self.entries
            .iter()
            .find(|entry| entry.original_pc == original_pc)
            .map(|entry| entry.offset)
    }

    pub fn pc_for_offset(&self, offset: usize) -> Option<u64> {
        self.entries
            .iter()
            .find(|entry| entry.offset == offset)
            .map(|entry| entry.original_pc)
    }

    pub fn entries(&self) -> &[VLabel] {
        &self.entries
    }
}