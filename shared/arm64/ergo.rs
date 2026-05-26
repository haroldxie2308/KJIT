use super::{A64Imm, A64Mem, A64Reg};

pub const fn x(reg: u8) -> A64Reg {
    A64Reg::x(reg)
}

pub const fn w(reg: u8) -> A64Reg {
    A64Reg::w(reg)
}

pub const fn xzr() -> A64Reg {
    A64Reg::x(31)
}

pub const fn wzr() -> A64Reg {
    A64Reg::w(31)
}

pub const fn sp() -> A64Reg {
    A64Reg::x_sp(31)
}

pub const fn wsp() -> A64Reg {
    A64Reg::w_sp(31)
}

pub const fn uimm(raw: u32, bits: u8) -> A64Imm {
    A64Imm::unsigned(raw, bits)
}

pub const fn simm(raw: u32, bits: u8) -> A64Imm {
    A64Imm::signed(raw, bits)
}

pub const fn scaled_uimm(raw: u32, bits: u8, scale: u8) -> A64Imm {
    A64Imm::scaled_unsigned(raw, bits, scale)
}

pub const fn scaled_simm(raw: u32, bits: u8, scale: u8) -> A64Imm {
    A64Imm::scaled_signed(raw, bits, scale)
}

pub const fn ldst64_offset(offset_bytes: u32) -> A64Imm {
    scaled_uimm(offset_bytes / 8, 12, 3)
}

pub const fn ldstpair64_offset(offset_bytes: i32) -> A64Imm {
    let scaled = offset_bytes / 8;
    scaled_simm((scaled as u32) & 0x7f, 7, 3)
}

pub const fn mem_off(base: A64Reg, offset: A64Imm) -> A64Mem {
    A64Mem::offset(base, offset)
}

pub const fn mem_pre(base: A64Reg, offset: A64Imm) -> A64Mem {
    A64Mem::pre_index(base, offset)
}

pub const fn mem_post(base: A64Reg, offset: A64Imm) -> A64Mem {
    A64Mem::post_index(base, offset)
}
