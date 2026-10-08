//! A9a SIMD&FP semantics of the interpreter (docs/pipeline.md, "Harness memory model
//! (A4)"): exactly the A9a forms, each written from its Arm XML execute
//! pseudocode. A write of `V{datasize}(d)` with `datasize < 128` zero-extends to
//! 128 bits; `Vpart{64}(d, 1)` writes bits 127:64 and keeps the rest. No A9a form
//! reads or writes FPCR/FPSR.

use crate::arm64::{check_accesses, check_window_accesses, untagged, AccessContext, InsnError};
use crate::model::{AccessKind, FaultCause, MachineState, MemAccess, MemFault};
use crate::shared::arm64::{A64FpSimdWriteback, A64Insn, A64Reg31Mode};

/// Executes one A9a SIMD&FP form. Every memory access is checked before any
/// register or byte is written, so an `Err` leaves `state` untouched.
pub(crate) fn execute(
    insn: A64Insn,
    pc: u64,
    state: &mut MachineState,
    ctx: &mut AccessContext<'_>,
) -> Result<u64, InsnError> {
    if insn.fpsimd_mem().is_some() {
        execute_mem(insn, pc, state, ctx)?;
    } else {
        execute_register(insn, state)?;
    }
    Ok(pc + 4)
}

// ---------------------------------------------------------------------------
// Loads and stores
// ---------------------------------------------------------------------------

/// What one SIMD&FP load/store transfers, from its base-only encoding.
#[derive(Clone, Copy, Debug)]
enum Transfer {
    /// LDR/STR/LDUR/STUR: `V{datasize}(t) <-> Mem{datasize}`, `bytes` = datasize / 8.
    Single { rt: u8, bytes: u8 },
    /// LDP/STP: one `Mem{2 * datasize}` access; `V(t)` is its low half.
    Pair { rt: u8, rt2: u8, bytes: u8 },
    /// LD1/ST1 (multiple structures): registers `(t + r) MOD 32` for `r < regs`,
    /// each `64 << q` bits of `esize`-byte elements, one `Mem{esize}` access per
    /// element in register-then-element order.
    Multiple { rt: u8, regs: u8, q: u8, ebytes: u8 },
}

fn transfer(access: A64Insn) -> Result<(Transfer, bool), InsnError> {
    use A64Insn::*;
    let single = |rt, bytes| Transfer::Single { rt, bytes };
    let pair = |rt, rt2, bytes| Transfer::Pair { rt, rt2, bytes };
    let multiple = |rt, regs, q, size: u8| Transfer::Multiple {
        rt,
        regs,
        q,
        ebytes: 1 << size,
    };
    Ok(match access {
        LdrImmFpsimdLdrBLdstPos { rt, .. } => (single(rt, 1), true),
        LdrImmFpsimdLdrHLdstPos { rt, .. } => (single(rt, 2), true),
        LdrImmFpsimdLdrSLdstPos { rt, .. } => (single(rt, 4), true),
        LdrImmFpsimdLdrDLdstPos { rt, .. } => (single(rt, 8), true),
        LdrImmFpsimdLdrQLdstPos { rt, .. } => (single(rt, 16), true),
        StrImmFpsimdStrBLdstPos { rt, .. } => (single(rt, 1), false),
        StrImmFpsimdStrHLdstPos { rt, .. } => (single(rt, 2), false),
        StrImmFpsimdStrSLdstPos { rt, .. } => (single(rt, 4), false),
        StrImmFpsimdStrDLdstPos { rt, .. } => (single(rt, 8), false),
        StrImmFpsimdStrQLdstPos { rt, .. } => (single(rt, 16), false),
        LdpFpsimdLdpSLdstpairOff { rt2, rt, .. } => (pair(rt, rt2, 4), true),
        LdpFpsimdLdpDLdstpairOff { rt2, rt, .. } => (pair(rt, rt2, 8), true),
        LdpFpsimdLdpQLdstpairOff { rt2, rt, .. } => (pair(rt, rt2, 16), true),
        StpFpsimdStpSLdstpairOff { rt2, rt, .. } => (pair(rt, rt2, 4), false),
        StpFpsimdStpDLdstpairOff { rt2, rt, .. } => (pair(rt, rt2, 8), false),
        StpFpsimdStpQLdstpairOff { rt2, rt, .. } => (pair(rt, rt2, 16), false),
        Ld1AdvsimdMultLd1AsisdlseR11v { q, size, rt, .. } => (multiple(rt, 1, q, size), true),
        Ld1AdvsimdMultLd1AsisdlseR22v { q, size, rt, .. } => (multiple(rt, 2, q, size), true),
        Ld1AdvsimdMultLd1AsisdlseR33v { q, size, rt, .. } => (multiple(rt, 3, q, size), true),
        Ld1AdvsimdMultLd1AsisdlseR44v { q, size, rt, .. } => (multiple(rt, 4, q, size), true),
        St1AdvsimdMultSt1AsisdlseR11v { q, size, rt, .. } => (multiple(rt, 1, q, size), false),
        St1AdvsimdMultSt1AsisdlseR22v { q, size, rt, .. } => (multiple(rt, 2, q, size), false),
        St1AdvsimdMultSt1AsisdlseR33v { q, size, rt, .. } => (multiple(rt, 3, q, size), false),
        St1AdvsimdMultSt1AsisdlseR44v { q, size, rt, .. } => (multiple(rt, 4, q, size), false),
        other => {
            return Err(InsnError::Error(format!(
                "{} is not a base-only SIMD&FP load/store",
                other.key()
            )))
        }
    })
}

/// The A9a loads/stores. Original code: EL0 user accesses (with the EL0 SP
/// alignment check). Fragment: a PAN-window access (`check_window_accesses`).
/// Accesses follow the pseudocode: one per LDR/STR/LDP/STP, one per element for
/// LD1/ST1; all are checked before anything is written.
fn execute_mem(
    insn: A64Insn,
    pc: u64,
    state: &mut MachineState,
    ctx: &mut AccessContext<'_>,
) -> Result<(), InsnError> {
    let mem = insn
        .fpsimd_mem()
        .ok_or_else(|| format!("{} is not a SIMD&FP load/store", insn.key()))?;
    let (transfer, load) = transfer(mem.access)?;
    let base = state.read_reg(mem.base);
    let address = base.wrapping_add_signed(mem.offset);
    let kind = if load {
        AccessKind::Read
    } else {
        AccessKind::Write
    };
    let access = |offset: u64, size: u8| MemAccess {
        addr: untagged(address.wrapping_add(offset)),
        size,
        kind,
    };
    let accesses = match transfer {
        Transfer::Single { bytes, .. } => vec![access(0, bytes)],
        Transfer::Pair { bytes, .. } => vec![access(0, 2 * bytes)],
        Transfer::Multiple {
            regs, q, ebytes, ..
        } => {
            let count = u64::from(regs) * (8_u64 << q) / u64::from(ebytes);
            (0..count)
                .map(|index| access(index * u64::from(ebytes), ebytes))
                .collect()
        }
    };

    // EL0 SP alignment check (SCTLR_EL1.SA0): before any access. Original code
    // only; a fragment's window access is based on its scratch register.
    let sp_based = mem.base.enc() == 31 && mem.base.reg31 == A64Reg31Mode::Sp;
    if matches!(ctx, AccessContext::Original { .. }) && sp_based && state.sp() % 16 != 0 {
        return Err(InsnError::Fault(MemFault {
            pc,
            access: accesses[0],
            cause: FaultCause::SpAlignment,
        }));
    }
    match ctx {
        AccessContext::Original { .. } => check_accesses(ctx, state, pc, &accesses, false)?,
        AccessContext::Fragment { .. } => check_window_accesses(ctx, state, pc, &accesses)?,
    }

    if load {
        match transfer {
            Transfer::Single { rt, bytes } => {
                let value = read_bytes(state, accesses[0].addr, bytes);
                set_v(state, rt, value, u32::from(bytes) * 8);
            }
            Transfer::Pair { rt, rt2, bytes } => {
                if rt == rt2 {
                    // CONSTRAINED UNPREDICTABLE; admission never lets it run.
                    return Err(InsnError::Error(format!(
                        "SIMD&FP LDP with t == t2 at pc={pc:#x}"
                    )));
                }
                let addr = accesses[0].addr;
                let low = read_bytes(state, addr, bytes);
                let high = read_bytes(state, addr + u64::from(bytes), bytes);
                set_v(state, rt, low, u32::from(bytes) * 8);
                set_v(state, rt2, high, u32::from(bytes) * 8);
            }
            Transfer::Multiple { rt, q, ebytes, .. } => {
                let per_reg = (8_usize << q) / usize::from(ebytes);
                let esize = u32::from(ebytes) * 8;
                for (index, access) in accesses.iter().enumerate() {
                    let reg = (rt as usize + index / per_reg) % 32;
                    let value = read_bytes(state, access.addr, ebytes) as u64;
                    // `rval = V{datasize}(tt); rval[e] = ...; V{datasize}(tt) = rval`.
                    let old = state.v[reg] & mask(64 << q);
                    let new = with_elem(old, index % per_reg, esize, value);
                    set_v(state, reg as u8, new, 64 << q);
                }
            }
        }
    } else {
        let values: Vec<(u64, u8, u128)> = match transfer {
            Transfer::Single { rt, bytes } => {
                vec![(accesses[0].addr, bytes, state.v[rt as usize])]
            }
            Transfer::Pair { rt, rt2, bytes } => vec![
                (accesses[0].addr, bytes, state.v[rt as usize]),
                (
                    accesses[0].addr + u64::from(bytes),
                    bytes,
                    state.v[rt2 as usize],
                ),
            ],
            Transfer::Multiple { rt, q, ebytes, .. } => {
                let per_reg = (8_usize << q) / usize::from(ebytes);
                let esize = u32::from(ebytes) * 8;
                accesses
                    .iter()
                    .enumerate()
                    .map(|(index, access)| {
                        let reg = (rt as usize + index / per_reg) % 32;
                        let value = elem(state.v[reg], index % per_reg, esize);
                        (access.addr, ebytes, u128::from(value))
                    })
                    .collect()
            }
        };
        for (addr, bytes, value) in values {
            write_bytes(state, addr, bytes, value);
        }
    }

    if let Some(writeback) = mem.writeback {
        let amount = match writeback {
            A64FpSimdWriteback::Imm(amount) => amount as u64,
            A64FpSimdWriteback::Reg(index) => state.read_reg(index),
        };
        state.write_reg(mem.base, base.wrapping_add(amount));
    }
    Ok(())
}

/// Little-endian `bytes` (at most 16) at `addr`, already permission-checked.
fn read_bytes(state: &MachineState, addr: u64, bytes: u8) -> u128 {
    let low = state.read_le(addr, bytes.min(8));
    let high = if bytes > 8 {
        state.read_le(addr + 8, bytes - 8)
    } else {
        0
    };
    u128::from(low) | (u128::from(high) << 64)
}

fn write_bytes(state: &mut MachineState, addr: u64, bytes: u8, value: u128) {
    state.write_le(addr, bytes.min(8), value as u64);
    if bytes > 8 {
        state.write_le(addr + 8, bytes - 8, (value >> 64) as u64);
    }
}

// ---------------------------------------------------------------------------
// Register-only forms
// ---------------------------------------------------------------------------

/// All ones in the low `bits` (1..=128) bits.
fn mask(bits: u32) -> u128 {
    if bits >= 128 {
        u128::MAX
    } else {
        (1_u128 << bits) - 1
    }
}

fn mask64(bits: u32) -> u64 {
    mask(bits) as u64
}

/// `V{bits}(n) = value`: the low `bits` bits, zero-extended to 128.
fn set_v(state: &mut MachineState, n: u8, value: u128, bits: u32) {
    state.v[n as usize] = value & mask(bits);
}

/// `Vpart{64}(n, part) = value`: part 0 zero-extends like `V{64}`; part 1 writes
/// bits 127:64 and keeps bits 63:0.
fn set_vpart(state: &mut MachineState, n: u8, part: u8, value: u64) {
    if part == 0 {
        set_v(state, n, u128::from(value), 64);
    } else {
        let low = state.v[n as usize] & mask(64);
        state.v[n as usize] = low | (u128::from(value) << 64);
    }
}

/// `Vpart{64}(n, part)`.
fn vpart(state: &MachineState, n: u8, part: u8) -> u64 {
    (state.v[n as usize] >> (64 * u32::from(part))) as u64
}

/// `value[e*:esize]`.
fn elem(value: u128, e: usize, esize: u32) -> u64 {
    ((value >> (e as u32 * esize)) & mask(esize)) as u64
}

fn with_elem(value: u128, e: usize, esize: u32, element: u64) -> u128 {
    let shift = e as u32 * esize;
    let field = mask(esize) << shift;
    (value & !field) | ((u128::from(element) & mask(esize)) << shift)
}

fn sint(value: u64, esize: u32) -> i64 {
    let shift = 64 - esize;
    ((value << shift) as i64) >> shift
}

/// `result[e] = f(operand1[e], operand2[e])` over `datasize / esize` elements.
fn elementwise(a: u128, b: u128, datasize: u32, esize: u32, f: impl Fn(u64, u64) -> u64) -> u128 {
    let mut result = 0;
    for e in 0..(datasize / esize) as usize {
        result = with_elem(result, e, esize, f(elem(a, e, esize), elem(b, e, esize)));
    }
    result
}

/// Pairwise over `concat = operand2 :: operand1`: `result[e] = f(concat[2e],
/// concat[2e + 1])`.
fn pairwise(n: u128, m: u128, datasize: u32, esize: u32, f: impl Fn(u64, u64) -> u64) -> u128 {
    let elements = (datasize / esize) as usize;
    let concat = |index: usize| {
        if index < elements {
            elem(n, index, esize)
        } else {
            elem(m, index - elements, esize)
        }
    };
    let mut result = 0;
    for e in 0..elements {
        result = with_elem(result, e, esize, f(concat(2 * e), concat(2 * e + 1)));
    }
    result
}

fn ones_if(condition: bool, esize: u32) -> u64 {
    if condition {
        mask64(esize)
    } else {
        0
    }
}

#[derive(Clone, Copy)]
enum Compare {
    Eq,
    /// Unsigned `>`.
    Hi,
    /// Unsigned `>=`.
    Hs,
    /// Signed `>`.
    Gt,
    /// Signed `>=`.
    Ge,
    /// `(a AND b) != 0`.
    Tst,
}

fn compare(op: Compare, a: u64, b: u64, esize: u32) -> u64 {
    let holds = match op {
        Compare::Eq => a == b,
        Compare::Hi => a > b,
        Compare::Hs => a >= b,
        Compare::Gt => sint(a, esize) > sint(b, esize),
        Compare::Ge => sint(a, esize) >= sint(b, esize),
        Compare::Tst => a & b != 0,
    };
    ones_if(holds, esize)
}

/// `LowestSetBitNZ(imm5<3:0>)`: the element size index of DUP/INS/UMOV.
fn imm5_size(imm5: u32) -> Result<u32, InsnError> {
    let low = imm5 & 0b1111;
    if low == 0 {
        return Err(InsnError::Error(format!(
            "imm5 {imm5:#b} has no element size (UNDEFINED)"
        )));
    }
    Ok(low.trailing_zeros())
}

/// `HighestSetBitNZ(x)`.
fn highest_set_bit(x: u32) -> u32 {
    31 - x.leading_zeros()
}

/// `AdvSIMDExpandImm(op, cmode, imm8)` for the MOVI/MVNI encodings of the subset.
fn expand_imm(op: u32, cmode: u32, imm8: u64) -> Result<u64, InsnError> {
    let replicate = |value: u64, bits: u32| {
        let mut result = 0u64;
        let mut shift = 0;
        while shift < 64 {
            result |= value << shift;
            shift += bits;
        }
        result
    };
    Ok(match cmode >> 1 {
        0b000 => replicate(imm8, 32),
        0b001 => replicate(imm8 << 8, 32),
        0b010 => replicate(imm8 << 16, 32),
        0b011 => replicate(imm8 << 24, 32),
        0b100 => replicate(imm8, 16),
        0b101 => replicate(imm8 << 8, 16),
        0b110 if cmode & 1 == 0 => replicate((imm8 << 8) | 0xff, 32),
        0b110 => replicate((imm8 << 16) | 0xffff, 32),
        0b111 if cmode & 1 == 0 && op == 0 => replicate(imm8, 8),
        0b111 if cmode & 1 == 0 => {
            let mut result = 0u64;
            for bit in 0..8 {
                if imm8 >> bit & 1 == 1 {
                    result |= 0xff << (8 * bit);
                }
            }
            result
        }
        _ => {
            return Err(InsnError::Error(format!(
                "AdvSIMDExpandImm op={op} cmode={cmode:#06b} is not an A9a form"
            )))
        }
    })
}

fn execute_register(insn: A64Insn, state: &mut MachineState) -> Result<(), InsnError> {
    use A64Insn::*;
    let v = |state: &MachineState, n: u8| state.v[n as usize];
    match insn {
        DupAdvsimdEltDupAsisdoneOnly { imm5, rn, rd } => {
            let size = imm5_size(imm5.raw())?;
            let esize = 8 << size;
            let element = elem(v(state, rn), (imm5.raw() >> (size + 1)) as usize, esize);
            set_v(state, rd, u128::from(element), esize);
        }
        DupAdvsimdEltDupAsimdinsDvV { q, imm5, rn, rd } => {
            let size = imm5_size(imm5.raw())?;
            let esize = 8 << size;
            let element = elem(v(state, rn), (imm5.raw() >> (size + 1)) as usize, esize);
            let datasize = 64 << q;
            let result = elementwise(0, 0, datasize, esize, |_, _| element);
            set_v(state, rd, result, datasize);
        }
        DupAdvsimdGenDupAsimdinsDrR { q, imm5, rn, rd } => {
            let esize = 8 << imm5_size(imm5.raw())?;
            let element = state.read_xzr(rn) & mask64(esize);
            let datasize = 64 << q;
            let result = elementwise(0, 0, datasize, esize, |_, _| element);
            set_v(state, rd, result, datasize);
        }
        InsAdvsimdEltInsAsimdinsIvV { imm5, imm4, rn, rd } => {
            let size = imm5_size(imm5.raw())?;
            let esize = 8 << size;
            let element = elem(v(state, rn), (imm4.raw() >> size) as usize, esize);
            let dst = (imm5.raw() >> (size + 1)) as usize;
            state.v[rd as usize] = with_elem(v(state, rd), dst, esize, element);
        }
        InsAdvsimdGenInsAsimdinsIrR { imm5, rn, rd } => {
            let size = imm5_size(imm5.raw())?;
            let esize = 8 << size;
            let element = state.read_xzr(rn) & mask64(esize);
            let dst = (imm5.raw() >> (size + 1)) as usize;
            state.v[rd as usize] = with_elem(v(state, rd), dst, esize, element);
        }
        UmovAdvsimdUmovAsimdinsWW { imm5, rn, rd } | UmovAdvsimdUmovAsimdinsXX { imm5, rn, rd } => {
            let size = imm5_size(imm5.raw())?;
            let esize = 8 << size;
            // `X{datasize}(d) = ZeroExtend(element)`; a W write clears bits 63:32.
            let element = elem(v(state, rn), (imm5.raw() >> (size + 1)) as usize, esize);
            state.write_xzr(rd, element);
        }
        MoviAdvsimdMoviAsimdimmNB { rd, .. }
        | MoviAdvsimdMoviAsimdimmLHl { rd, .. }
        | MoviAdvsimdMoviAsimdimmLSl { rd, .. }
        | MoviAdvsimdMoviAsimdimmMSm { rd, .. }
        | MoviAdvsimdMoviAsimdimmDDs { rd, .. }
        | MoviAdvsimdMoviAsimdimmD2D { rd, .. }
        | MvniAdvsimdMvniAsimdimmLHl { rd, .. }
        | MvniAdvsimdMvniAsimdimmLSl { rd, .. }
        | MvniAdvsimdMvniAsimdimmMSm { rd, .. } => {
            // Q, op and cmode are fixed in some encodings' diagrams: read them
            // from the word.
            let word = insn
                .encode()
                .map_err(|err| format!("{}: {err:?}", insn.key()))?;
            let q = (word >> 30) & 1;
            let op = (word >> 29) & 1;
            let cmode = (word >> 12) & 0b1111;
            let imm8 = u64::from(((word >> 16) & 0b111) << 5 | ((word >> 5) & 0b1_1111));
            let imm64 = expand_imm(op, cmode, imm8)?;
            let datasize = 64 << q;
            let mut imm = u128::from(imm64) | (u128::from(imm64) << 64);
            if matches!(
                insn,
                MvniAdvsimdMvniAsimdimmLHl { .. }
                    | MvniAdvsimdMvniAsimdimmLSl { .. }
                    | MvniAdvsimdMvniAsimdimmMSm { .. }
            ) {
                imm = !imm;
            }
            set_v(state, rd, imm, datasize);
        }
        FmovFloatGenFmovS32Float2int { rn, rd } => {
            set_v(state, rd, u128::from(state.read_xzr(rn)), 32);
        }
        FmovFloatGenFmovD64Float2int { rn, rd } => {
            set_v(state, rd, u128::from(state.read_xzr(rn)), 64);
        }
        FmovFloatGenFmovV64iFloat2int { rn, rd } => {
            set_vpart(state, rd, 1, state.read_xzr(rn));
        }
        FmovFloatGenFmov32sFloat2int { rn, rd } => {
            state.write_xzr(rd, vpart(state, rn, 0) & mask64(32));
        }
        FmovFloatGenFmov64dFloat2int { rn, rd } => {
            state.write_xzr(rd, vpart(state, rn, 0));
        }
        FmovFloatGenFmov64vxFloat2int { rn, rd } => {
            state.write_xzr(rd, vpart(state, rn, 1));
        }
        FmovFloatFmovSFloatdp1 { rn, rd } => set_v(state, rd, v(state, rn), 32),
        FmovFloatFmovDFloatdp1 { rn, rd } => set_v(state, rd, v(state, rn), 64),

        CmeqAdvsimdRegCmeqAsisdsameOnly { rm, rn, rd } => {
            compare_regs(state, Compare::Eq, rd, rn, Some(rm), 64, 64)
        }
        CmhiAdvsimdCmhiAsisdsameOnly { rm, rn, rd } => {
            compare_regs(state, Compare::Hi, rd, rn, Some(rm), 64, 64)
        }
        CmhsAdvsimdCmhsAsisdsameOnly { rm, rn, rd } => {
            compare_regs(state, Compare::Hs, rd, rn, Some(rm), 64, 64)
        }
        CmgtAdvsimdRegCmgtAsisdsameOnly { rm, rn, rd } => {
            compare_regs(state, Compare::Gt, rd, rn, Some(rm), 64, 64)
        }
        CmgeAdvsimdRegCmgeAsisdsameOnly { rm, rn, rd } => {
            compare_regs(state, Compare::Ge, rd, rn, Some(rm), 64, 64)
        }
        CmtstAdvsimdCmtstAsisdsameOnly { rm, rn, rd } => {
            compare_regs(state, Compare::Tst, rd, rn, Some(rm), 64, 64)
        }
        CmeqAdvsimdZeroCmeqAsisdmiscZ { rn, rd } => {
            compare_regs(state, Compare::Eq, rd, rn, None, 64, 64)
        }
        CmgtAdvsimdZeroCmgtAsisdmiscZ { rn, rd } => {
            compare_regs(state, Compare::Gt, rd, rn, None, 64, 64)
        }
        CmgeAdvsimdZeroCmgeAsisdmiscZ { rn, rd } => {
            compare_regs(state, Compare::Ge, rd, rn, None, 64, 64)
        }
        CmeqAdvsimdRegCmeqAsimdsameOnly {
            q,
            size,
            rm,
            rn,
            rd,
        } => compare_regs(state, Compare::Eq, rd, rn, Some(rm), 64 << q, 8 << size),
        CmhiAdvsimdCmhiAsimdsameOnly {
            q,
            size,
            rm,
            rn,
            rd,
        } => compare_regs(state, Compare::Hi, rd, rn, Some(rm), 64 << q, 8 << size),
        CmhsAdvsimdCmhsAsimdsameOnly {
            q,
            size,
            rm,
            rn,
            rd,
        } => compare_regs(state, Compare::Hs, rd, rn, Some(rm), 64 << q, 8 << size),
        CmgtAdvsimdRegCmgtAsimdsameOnly {
            q,
            size,
            rm,
            rn,
            rd,
        } => compare_regs(state, Compare::Gt, rd, rn, Some(rm), 64 << q, 8 << size),
        CmgeAdvsimdRegCmgeAsimdsameOnly {
            q,
            size,
            rm,
            rn,
            rd,
        } => compare_regs(state, Compare::Ge, rd, rn, Some(rm), 64 << q, 8 << size),
        CmtstAdvsimdCmtstAsimdsameOnly {
            q,
            size,
            rm,
            rn,
            rd,
        } => compare_regs(state, Compare::Tst, rd, rn, Some(rm), 64 << q, 8 << size),
        CmeqAdvsimdZeroCmeqAsimdmiscZ { q, size, rn, rd } => {
            compare_regs(state, Compare::Eq, rd, rn, None, 64 << q, 8 << size)
        }
        CmgtAdvsimdZeroCmgtAsimdmiscZ { q, size, rn, rd } => {
            compare_regs(state, Compare::Gt, rd, rn, None, 64 << q, 8 << size)
        }
        CmgeAdvsimdZeroCmgeAsimdmiscZ { q, size, rn, rd } => {
            compare_regs(state, Compare::Ge, rd, rn, None, 64 << q, 8 << size)
        }

        AndAdvsimdAndAsimdsameOnly { q, rm, rn, rd } => {
            set_v(state, rd, v(state, rn) & v(state, rm), 64 << q)
        }
        OrrAdvsimdRegOrrAsimdsameOnly { q, rm, rn, rd } => {
            set_v(state, rd, v(state, rn) | v(state, rm), 64 << q)
        }
        EorAdvsimdEorAsimdsameOnly { q, rm, rn, rd } => {
            set_v(state, rd, v(state, rn) ^ v(state, rm), 64 << q)
        }
        BicAdvsimdRegBicAsimdsameOnly { q, rm, rn, rd } => {
            set_v(state, rd, v(state, rn) & !v(state, rm), 64 << q)
        }
        OrnAdvsimdOrnAsimdsameOnly { q, rm, rn, rd } => {
            set_v(state, rd, v(state, rn) | !v(state, rm), 64 << q)
        }
        // BIT: operand1 = d, operand2 = m, operand3 = n;
        // d = operand1 XOR ((operand1 XOR operand3) AND operand2).
        BitAdvsimdBitAsimdsameOnly { q, rm, rn, rd } => {
            let (d, n, m) = (v(state, rd), v(state, rn), v(state, rm));
            set_v(state, rd, d ^ ((d ^ n) & m), 64 << q)
        }
        // BIF: as BIT with operand2 = NOT(m).
        BifAdvsimdBifAsimdsameOnly { q, rm, rn, rd } => {
            let (d, n, m) = (v(state, rd), v(state, rn), v(state, rm));
            set_v(state, rd, d ^ ((d ^ n) & !m), 64 << q)
        }
        // BSL: operand1 = m, operand2 = d, operand3 = n.
        BslAdvsimdBslAsimdsameOnly { q, rm, rn, rd } => {
            let (d, n, m) = (v(state, rd), v(state, rn), v(state, rm));
            set_v(state, rd, m ^ ((m ^ n) & d), 64 << q)
        }
        NotAdvsimdNotAsimdmiscR { q, rn, rd } => set_v(state, rd, !v(state, rn), 64 << q),

        AddAdvsimdAddAsisdsameOnly { rm, rn, rd } => {
            let result = elementwise(v(state, rn), v(state, rm), 64, 64, u64::wrapping_add);
            set_v(state, rd, result, 64)
        }
        SubAdvsimdSubAsisdsameOnly { rm, rn, rd } => {
            let result = elementwise(v(state, rn), v(state, rm), 64, 64, u64::wrapping_sub);
            set_v(state, rd, result, 64)
        }
        AddAdvsimdAddAsimdsameOnly {
            q,
            size,
            rm,
            rn,
            rd,
        } => {
            let esize = 8 << size;
            let result = elementwise(v(state, rn), v(state, rm), 64 << q, esize, |a, b| {
                a.wrapping_add(b) & mask64(esize)
            });
            set_v(state, rd, result, 64 << q)
        }
        SubAdvsimdSubAsimdsameOnly {
            q,
            size,
            rm,
            rn,
            rd,
        } => {
            let esize = 8 << size;
            let result = elementwise(v(state, rn), v(state, rm), 64 << q, esize, |a, b| {
                a.wrapping_sub(b) & mask64(esize)
            });
            set_v(state, rd, result, 64 << q)
        }
        AddpAdvsimdVecAddpAsimdsameOnly {
            q,
            size,
            rm,
            rn,
            rd,
        } => {
            let esize = 8 << size;
            let result = pairwise(v(state, rn), v(state, rm), 64 << q, esize, |a, b| {
                a.wrapping_add(b) & mask64(esize)
            });
            set_v(state, rd, result, 64 << q)
        }
        UmaxpAdvsimdUmaxpAsimdsameOnly {
            q,
            size,
            rm,
            rn,
            rd,
        } => {
            let result = pairwise(v(state, rn), v(state, rm), 64 << q, 8 << size, u64::max);
            set_v(state, rd, result, 64 << q)
        }
        UminpAdvsimdUminpAsimdsameOnly {
            q,
            size,
            rm,
            rn,
            rd,
        } => {
            let result = pairwise(v(state, rn), v(state, rm), 64 << q, 8 << size, u64::min);
            set_v(state, rd, result, 64 << q)
        }
        // `IntReduce(ReduceOp_ADD)` of the two 64-bit elements.
        AddpAdvsimdPairAddpAsisdpairOnly { rn, rd } => {
            let n = v(state, rn);
            let sum = elem(n, 0, 64).wrapping_add(elem(n, 1, 64));
            set_v(state, rd, u128::from(sum), 64)
        }
        AddvAdvsimdAddvAsimdallOnly { q, size, rn, rd } => {
            reduce(state, rd, rn, 64 << q, 8 << size, u64::wrapping_add)
        }
        UmaxvAdvsimdUmaxvAsimdallOnly { q, size, rn, rd } => {
            reduce(state, rd, rn, 64 << q, 8 << size, u64::max)
        }
        UminvAdvsimdUminvAsimdallOnly { q, size, rn, rd } => {
            reduce(state, rd, rn, 64 << q, 8 << size, u64::min)
        }

        ShrnAdvsimdShrnAsimdshfN {
            q,
            immh,
            immb,
            rn,
            rd,
        } => {
            let esize = 8 << highest_set_bit(immh.raw() & 0b111);
            let shift = 2 * esize - (immh.raw() << 3 | immb.raw());
            let operand = v(state, rn);
            let mut result = 0u128;
            for e in 0..(64 / esize) as usize {
                let element = elem(operand, e, 2 * esize) >> shift;
                result = with_elem(result, e, esize, element);
            }
            set_vpart(state, rd, q, result as u64)
        }
        UshrAdvsimdUshrAsisdshfR { immh, immb, rn, rd } => {
            ushr(state, rd, rn, 64, 64, 128 - (immh.raw() << 3 | immb.raw()))
        }
        UshrAdvsimdUshrAsimdshfR {
            q,
            immh,
            immb,
            rn,
            rd,
        } => {
            let esize = 8 << highest_set_bit(immh.raw());
            let shift = 2 * esize - (immh.raw() << 3 | immb.raw());
            ushr(state, rd, rn, 64 << q, esize, shift)
        }
        ShlAdvsimdShlAsisdshfR { immh, immb, rn, rd } => {
            shl(state, rd, rn, 64, 64, (immh.raw() << 3 | immb.raw()) - 64)
        }
        ShlAdvsimdShlAsimdshfR {
            q,
            immh,
            immb,
            rn,
            rd,
        } => {
            let esize = 8 << highest_set_bit(immh.raw());
            let shift = (immh.raw() << 3 | immb.raw()) - esize;
            shl(state, rd, rn, 64 << q, esize, shift)
        }
        UshllAdvsimdUshllAsimdshfL {
            q,
            immh,
            immb,
            rn,
            rd,
        } => {
            let esize = 8 << highest_set_bit(immh.raw() & 0b111);
            let shift = (immh.raw() << 3 | immb.raw()) - esize;
            let operand = u128::from(vpart(state, rn, q));
            let mut result = 0u128;
            for e in 0..(64 / esize) as usize {
                let element = elem(operand, e, esize) << shift;
                result = with_elem(result, e, 2 * esize, element);
            }
            set_v(state, rd, result, 128)
        }
        XtnAdvsimdXtnAsimdmiscN { q, size, rn, rd } => {
            let esize = 8 << size;
            let operand = v(state, rn);
            let mut result = 0u128;
            for e in 0..(64 / esize) as usize {
                result = with_elem(result, e, esize, elem(operand, e, 2 * esize));
            }
            set_vpart(state, rd, q, result as u64)
        }
        ExtAdvsimdExtAsimdextOnly {
            q,
            rm,
            imm4,
            rn,
            rd,
        } => {
            let datasize = 64 << q;
            let position = 8 * imm4.raw();
            let (lo, hi) = (v(state, rn) & mask(datasize), v(state, rm) & mask(datasize));
            // `(hi :: lo)[position + datasize - 1 : position]`.
            let result = if position == 0 {
                lo
            } else {
                (lo >> position) | (hi << (datasize - position))
            };
            set_v(state, rd, result, datasize)
        }
        Rev16AdvsimdRev16AsimdmiscR { q, size, rn, rd } => {
            rev(state, rd, rn, 64 << q, 16, 8 << size)
        }
        Rev32AdvsimdRev32AsimdmiscR { q, size, rn, rd } => {
            rev(state, rd, rn, 64 << q, 32, 8 << size)
        }
        Rev64AdvsimdRev64AsimdmiscR { q, size, rn, rd } => {
            rev(state, rd, rn, 64 << q, 64, 8 << size)
        }
        CntAdvsimdCntAsimdmiscR { q, rn, rd, .. } => {
            let datasize = 64 << q;
            let result = elementwise(v(state, rn), 0, datasize, 8, |a, _| {
                u64::from(a.count_ones())
            });
            set_v(state, rd, result, datasize)
        }
        TblAdvsimdTblAsimdtblL11 { q, rm, rn, rd } => {
            let datasize = 64 << q;
            let table = v(state, rn);
            // `index < 16 * regs` selects a table byte; any other index gives 0.
            let result = elementwise(v(state, rm), 0, datasize, 8, |index, _| {
                if index < 16 {
                    elem(table, index as usize, 8)
                } else {
                    0
                }
            });
            set_v(state, rd, result, datasize)
        }
        other => {
            return Err(InsnError::Error(format!(
                "{} is not an A9a SIMD&FP register form",
                other.key()
            )))
        }
    }
    Ok(())
}

/// CM<cond> (register, or zero when `rm` is `None`).
fn compare_regs(
    state: &mut MachineState,
    op: Compare,
    rd: u8,
    rn: u8,
    rm: Option<u8>,
    datasize: u32,
    esize: u32,
) {
    let a = state.v[rn as usize];
    let b = rm.map_or(0, |rm| state.v[rm as usize]);
    let result = elementwise(a, b, datasize, esize, |x, y| compare(op, x, y, esize));
    set_v(state, rd, result, datasize);
}

/// Across-lanes reduction into `V{esize}(d)`.
fn reduce(
    state: &mut MachineState,
    rd: u8,
    rn: u8,
    datasize: u32,
    esize: u32,
    f: impl Fn(u64, u64) -> u64,
) {
    let operand = state.v[rn as usize];
    let mut acc = elem(operand, 0, esize);
    for e in 1..(datasize / esize) as usize {
        acc = f(acc, elem(operand, e, esize)) & mask64(esize);
    }
    set_v(state, rd, u128::from(acc), esize);
}

/// `RShr(UInt(element), shift, FALSE)`; `shift` is 1..=esize.
fn ushr(state: &mut MachineState, rd: u8, rn: u8, datasize: u32, esize: u32, shift: u32) {
    let result = elementwise(state.v[rn as usize], 0, datasize, esize, |a, _| {
        a.checked_shr(shift).unwrap_or(0)
    });
    set_v(state, rd, result, datasize);
}

/// `LSL(element, shift)`; `shift` is 0..esize.
fn shl(state: &mut MachineState, rd: u8, rn: u8, datasize: u32, esize: u32, shift: u32) {
    let result = elementwise(state.v[rn as usize], 0, datasize, esize, |a, _| {
        (a << shift) & mask64(esize)
    });
    set_v(state, rd, result, datasize);
}

/// `Reverse{csize}(container, esize)` for every `csize`-bit container.
fn rev(state: &mut MachineState, rd: u8, rn: u8, datasize: u32, csize: u32, esize: u32) {
    let operand = state.v[rn as usize];
    let per = (csize / esize) as usize;
    let mut result = 0u128;
    for e in 0..(datasize / esize) as usize {
        let container = e / per;
        let within = e % per;
        let source = container * per + (per - 1 - within);
        result = with_elem(result, e, esize, elem(operand, source, esize));
    }
    set_v(state, rd, result, datasize);
}
