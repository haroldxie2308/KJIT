use super::{REG_VIRT_STACK_BACKED_REG_END, REG_VIRT_STACK_BACKED_REG_START};

pub const REG_VIRT_STACK_BACKED_FRAME_OFFSET_START: u32 = 16;
pub const REG_VIRT_STACK_BACKED_FRAME_SLOT_SIZE: u32 = 8;

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
