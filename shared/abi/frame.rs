use super::{REG_VIRT_STACK_BACKED_REG_END, REG_VIRT_STACK_BACKED_REG_START};

// Runtime frame, sp-relative after the prologue's `stp x29, x30, [sp, #-192]!`:
//   0..16    caller x29, x30
//   16..64   stack-backed user x12..x17
//   64..80   user x29, user sp (loaded into their stable mappings x16/x17)
//   80..88   entry address (ABI_ENTRY_ARG_REG), consumed by the prologue's `br`
//   88..96   caller x18
//   96..176  caller x19..x28
//   176..192 pt_regs pointer, extra-params pointer
pub const RUNTIME_FRAME_SIZE_BYTES: u32 = 192;
pub const RUNTIME_FRAME_ENTRY_ADDR_OFFSET: u32 = 80;
pub const RUNTIME_FRAME_PT_REGS_PTR_OFFSET: u32 = 176;
const REG_VIRT_STACK_BACKED_FRAME_OFFSET_START: u32 = 16;
const REG_VIRT_STACK_BACKED_FRAME_SLOT_SIZE: u32 = 8;
const PT_REGS_GPR_SLOT_SIZE: u32 = 8;

pub const fn reg_virt_stack_backed_slot_offset(reg: u8) -> Option<u32> {
    if reg < REG_VIRT_STACK_BACKED_REG_START || reg > REG_VIRT_STACK_BACKED_REG_END {
        return None;
    }

    Some(
        REG_VIRT_STACK_BACKED_FRAME_OFFSET_START
            + ((reg - REG_VIRT_STACK_BACKED_REG_START) as u32)
                * REG_VIRT_STACK_BACKED_FRAME_SLOT_SIZE,
    )
}

pub const fn pt_regs_x_slot_offset(reg: u8) -> Option<u32> {
    if reg >= 31 {
        return None;
    }

    Some((reg as u32) * PT_REGS_GPR_SLOT_SIZE)
}
