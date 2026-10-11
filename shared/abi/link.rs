//! Direct BL links (A16, docs/pipeline.md "Direct BL links (A16)"): the one word a
//! link slot is patched to. Pure, called by the kernel runtime (through
//! `kjit_glue.c`) and by the harness code cache, so both write the same bytes.

use crate::shared::arm64::ergo::scaled_simm;
use crate::shared::arm64::A64Insn;

/// `nop`, the word of an unlinked slot (and what a retired link is restored to).
/// `kjit_glue.c` mirrors it (`KJIT_LINK_NOP_WORD`), pinned in `runtime/ffi.rs`; a
/// test pins it to the encoder.
pub const LINK_NOP_WORD: u32 = 0xd503_201f;

/// Reach of `b`: a signed 26-bit word displacement, +-128 MiB.
const LINK_BRANCH_REACH_BYTES: i64 = 1 << 27;

/// `b <host>` encoded for a slot at `slot_addr`, or `None` if the displacement is
/// outside `b`'s range or either address is not word aligned.
pub fn link_branch_word(slot_addr: u64, host: u64) -> Option<u32> {
    if slot_addr % 4 != 0 || host % 4 != 0 {
        return None;
    }
    // Both are kernel addresses of one region: the wrapped difference is the signed
    // distance whenever it is in range.
    let delta = host.wrapping_sub(slot_addr) as i64;
    if !(-LINK_BRANCH_REACH_BYTES..LINK_BRANCH_REACH_BYTES).contains(&delta) {
        return None;
    }
    let raw = ((delta >> 2) as u32) & 0x03ff_ffff;
    A64Insn::BUncondBOnlyBranchImm {
        imm26: scaled_simm(raw, 26, 2),
    }
    .encode()
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_nop_word_is_the_encoders() {
        assert_eq!(A64Insn::NopNopHiHints {}.encode().unwrap(), LINK_NOP_WORD);
    }

    #[test]
    fn branch_words_match_the_architecture() {
        let slot = 0xffff_8000_1234_0000_u64;
        // b .+8 / b .-4 / b . (the encodings llvm-mc gives).
        assert_eq!(link_branch_word(slot, slot + 8), Some(0x1400_0002));
        assert_eq!(link_branch_word(slot, slot - 4), Some(0x17ff_ffff));
        assert_eq!(link_branch_word(slot, slot), Some(0x1400_0000));
    }

    #[test]
    fn the_reach_is_exactly_128_mib() {
        let slot = 0xffff_8000_1000_0000_u64;
        let reach = 1_u64 << 27;
        assert_eq!(link_branch_word(slot, slot + reach - 4), Some(0x15ff_ffff));
        assert_eq!(link_branch_word(slot, slot + reach), None);
        assert_eq!(link_branch_word(slot, slot - reach), Some(0x1600_0000));
        assert_eq!(link_branch_word(slot, slot - reach - 4), None);
    }

    #[test]
    fn unaligned_addresses_are_refused() {
        let slot = 0xffff_8000_1000_0000_u64;
        assert_eq!(link_branch_word(slot + 2, slot + 8), None);
        assert_eq!(link_branch_word(slot, slot + 10), None);
    }

    #[test]
    fn a_distant_address_is_none() {
        assert_eq!(link_branch_word(0xffff_8000_0000_0000, 0x0000_0000_0040_0000), None);
        assert_eq!(link_branch_word(0x0000_0000_0040_0000, 0xffff_8000_0000_0000), None);
    }
}
