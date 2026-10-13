//! A18 scalar floating-point semantics of the interpreter (docs/pipeline.md,
//! "Scalar floating point (A18)"): the single- and double-precision data-processing,
//! compare, conversion and move forms of the subset.
//!
//! Every arithmetic, rounding, conversion and compare executes on the host CPU
//! with inline asm: the state's FPCR is written before the operation and FPSR (and
//! NZCV) read back after it, so rounding modes, NaN propagation, flush-to-zero and
//! the cumulative exception flags are the hardware's. Nothing here reimplements
//! IEEE 754. What is not floating-point arithmetic is done on integers: FCSEL (a
//! register select), the FCCMP condition, and FMOV (immediate)'s bit expansion.
//!
//! The host is AArch64 by the project's scope. The host's own FPCR and FPSR are
//! saved and restored around each operation, so the harness itself never runs under
//! a state's rounding mode.

#[cfg(not(target_arch = "aarch64"))]
compile_error!("the A18 interpreter executes scalar floating point on the host CPU: AArch64 only");

use core::arch::asm;

use crate::arm64::{condition_holds, InsnError};
use crate::model::{Flags, MachineState};
use crate::shared::arm64::A64Insn;

/// What the host CPU produced for one operation.
struct Host {
    /// Q0 after the operation (a scalar write zeroes the bits above its size).
    v: u128,
    /// The general register operand `{g}` after the operation (`host_g!` only).
    gpr: u64,
    /// NZCV after the operation (bits 31:28).
    nzcv: u64,
}

/// Runs one instruction on the host with the state's FPCR and FPSR and returns its
/// result. The operands are loaded into v1 (`n`), v2 (`m`) and v3 (`a`); the
/// instruction writes v0 (and NZCV). The state's FPSR becomes the hardware's after
/// the operation. The host's FPCR/FPSR are restored before the asm block ends.
macro_rules! host {
    ($state:expr, $n:expr, $m:expr, $a:expr, $ins:literal) => {{
        let (n, m, a) = (
            $state.v[usize::from($n)],
            $state.v[usize::from($m)],
            $state.v[usize::from($a)],
        );
        let (fpcr, mut fpsr) = ($state.fpcr, $state.fpsr);
        let mut d = 0_u128;
        let nzcv: u64;
        // SAFETY: the asm only touches v0-v3 (declared clobbered), the four 16-byte
        // locals behind the pointers, NZCV, and FPCR/FPSR, which it restores. It
        // does not touch the stack and cannot trap: the state's FPCR has no
        // trap-enable bit (FPCR_USER_BITS), so a floating-point exception only sets
        // a cumulative FPSR flag.
        unsafe {
            asm!(
                "mrs {save_cr}, fpcr",
                "mrs {save_sr}, fpsr",
                "msr fpcr, {cr}",
                "msr fpsr, {sr}",
                "ldr q1, [{pn}]",
                "ldr q2, [{pm}]",
                "ldr q3, [{pa}]",
                $ins,
                "mrs {sr}, fpsr",
                "mrs {nz}, nzcv",
                "msr fpcr, {save_cr}",
                "msr fpsr, {save_sr}",
                "str q0, [{pd}]",
                save_cr = out(reg) _,
                save_sr = out(reg) _,
                cr = in(reg) fpcr,
                sr = inout(reg) fpsr,
                pn = in(reg) &n,
                pm = in(reg) &m,
                pa = in(reg) &a,
                pd = in(reg) &mut d,
                nz = out(reg) nzcv,
                out("v0") _,
                out("v1") _,
                out("v2") _,
                out("v3") _,
                options(nostack),
            );
        }
        $state.fpsr = fpsr;
        Host {
            v: d,
            gpr: 0,
            nzcv,
        }
    }};
}

/// `host!` for the forms with a general register operand `{g}` (SCVTF/UCVTF read
/// it, FCVT* write it): `$g` is its value before, `Host::gpr` after.
macro_rules! host_g {
    ($state:expr, $n:expr, $m:expr, $a:expr, $g:expr, $ins:literal) => {{
        let (n, m, a) = (
            $state.v[usize::from($n)],
            $state.v[usize::from($m)],
            $state.v[usize::from($a)],
        );
        let (fpcr, mut fpsr) = ($state.fpcr, $state.fpsr);
        let mut d = 0_u128;
        let nzcv: u64;
        let mut gpr: u64 = $g;
        // SAFETY: as `host!`; `g` is a general register the instruction reads or
        // writes.
        unsafe {
            asm!(
                "mrs {save_cr}, fpcr",
                "mrs {save_sr}, fpsr",
                "msr fpcr, {cr}",
                "msr fpsr, {sr}",
                "ldr q1, [{pn}]",
                "ldr q2, [{pm}]",
                "ldr q3, [{pa}]",
                $ins,
                "mrs {sr}, fpsr",
                "mrs {nz}, nzcv",
                "msr fpcr, {save_cr}",
                "msr fpsr, {save_sr}",
                "str q0, [{pd}]",
                save_cr = out(reg) _,
                save_sr = out(reg) _,
                cr = in(reg) fpcr,
                sr = inout(reg) fpsr,
                pn = in(reg) &n,
                pm = in(reg) &m,
                pa = in(reg) &a,
                pd = in(reg) &mut d,
                nz = out(reg) nzcv,
                g = inout(reg) gpr,
                out("v0") _,
                out("v1") _,
                out("v2") _,
                out("v3") _,
                options(nostack),
            );
        }
        $state.fpsr = fpsr;
        Host { v: d, gpr, nzcv }
    }};
}

/// Executes one A18 register form (and MRS of FPCR/FPSR). The register-offset
/// SIMD&FP loads/stores are `simd::execute`'s.
pub(crate) fn execute(insn: A64Insn, state: &mut MachineState) -> Result<(), InsnError> {
    use A64Insn::*;
    match insn {
        FaddFloatFaddSFloatdp2 { rm, rn, rd } => {
            let h = host!(state, rn, rm, 0_u8, "fadd s0, s1, s2");
            set_v(state, rd, h.v);
        }
        FaddFloatFaddDFloatdp2 { rm, rn, rd } => {
            let h = host!(state, rn, rm, 0_u8, "fadd d0, d1, d2");
            set_v(state, rd, h.v);
        }
        FsubFloatFsubSFloatdp2 { rm, rn, rd } => {
            let h = host!(state, rn, rm, 0_u8, "fsub s0, s1, s2");
            set_v(state, rd, h.v);
        }
        FsubFloatFsubDFloatdp2 { rm, rn, rd } => {
            let h = host!(state, rn, rm, 0_u8, "fsub d0, d1, d2");
            set_v(state, rd, h.v);
        }
        FmulFloatFmulSFloatdp2 { rm, rn, rd } => {
            let h = host!(state, rn, rm, 0_u8, "fmul s0, s1, s2");
            set_v(state, rd, h.v);
        }
        FmulFloatFmulDFloatdp2 { rm, rn, rd } => {
            let h = host!(state, rn, rm, 0_u8, "fmul d0, d1, d2");
            set_v(state, rd, h.v);
        }
        FnmulFloatFnmulSFloatdp2 { rm, rn, rd } => {
            let h = host!(state, rn, rm, 0_u8, "fnmul s0, s1, s2");
            set_v(state, rd, h.v);
        }
        FnmulFloatFnmulDFloatdp2 { rm, rn, rd } => {
            let h = host!(state, rn, rm, 0_u8, "fnmul d0, d1, d2");
            set_v(state, rd, h.v);
        }
        FdivFloatFdivSFloatdp2 { rm, rn, rd } => {
            let h = host!(state, rn, rm, 0_u8, "fdiv s0, s1, s2");
            set_v(state, rd, h.v);
        }
        FdivFloatFdivDFloatdp2 { rm, rn, rd } => {
            let h = host!(state, rn, rm, 0_u8, "fdiv d0, d1, d2");
            set_v(state, rd, h.v);
        }
        FmaxFloatFmaxSFloatdp2 { rm, rn, rd } => {
            let h = host!(state, rn, rm, 0_u8, "fmax s0, s1, s2");
            set_v(state, rd, h.v);
        }
        FmaxFloatFmaxDFloatdp2 { rm, rn, rd } => {
            let h = host!(state, rn, rm, 0_u8, "fmax d0, d1, d2");
            set_v(state, rd, h.v);
        }
        FminFloatFminSFloatdp2 { rm, rn, rd } => {
            let h = host!(state, rn, rm, 0_u8, "fmin s0, s1, s2");
            set_v(state, rd, h.v);
        }
        FminFloatFminDFloatdp2 { rm, rn, rd } => {
            let h = host!(state, rn, rm, 0_u8, "fmin d0, d1, d2");
            set_v(state, rd, h.v);
        }
        FmaxnmFloatFmaxnmSFloatdp2 { rm, rn, rd } => {
            let h = host!(state, rn, rm, 0_u8, "fmaxnm s0, s1, s2");
            set_v(state, rd, h.v);
        }
        FmaxnmFloatFmaxnmDFloatdp2 { rm, rn, rd } => {
            let h = host!(state, rn, rm, 0_u8, "fmaxnm d0, d1, d2");
            set_v(state, rd, h.v);
        }
        FminnmFloatFminnmSFloatdp2 { rm, rn, rd } => {
            let h = host!(state, rn, rm, 0_u8, "fminnm s0, s1, s2");
            set_v(state, rd, h.v);
        }
        FminnmFloatFminnmDFloatdp2 { rm, rn, rd } => {
            let h = host!(state, rn, rm, 0_u8, "fminnm d0, d1, d2");
            set_v(state, rd, h.v);
        }
        FmaddFloatFmaddSFloatdp3 { rm, ra, rn, rd } => {
            let h = host!(state, rn, rm, ra, "fmadd s0, s1, s2, s3");
            set_v(state, rd, h.v);
        }
        FmaddFloatFmaddDFloatdp3 { rm, ra, rn, rd } => {
            let h = host!(state, rn, rm, ra, "fmadd d0, d1, d2, d3");
            set_v(state, rd, h.v);
        }
        FmsubFloatFmsubSFloatdp3 { rm, ra, rn, rd } => {
            let h = host!(state, rn, rm, ra, "fmsub s0, s1, s2, s3");
            set_v(state, rd, h.v);
        }
        FmsubFloatFmsubDFloatdp3 { rm, ra, rn, rd } => {
            let h = host!(state, rn, rm, ra, "fmsub d0, d1, d2, d3");
            set_v(state, rd, h.v);
        }
        FnmaddFloatFnmaddSFloatdp3 { rm, ra, rn, rd } => {
            let h = host!(state, rn, rm, ra, "fnmadd s0, s1, s2, s3");
            set_v(state, rd, h.v);
        }
        FnmaddFloatFnmaddDFloatdp3 { rm, ra, rn, rd } => {
            let h = host!(state, rn, rm, ra, "fnmadd d0, d1, d2, d3");
            set_v(state, rd, h.v);
        }
        FnmsubFloatFnmsubSFloatdp3 { rm, ra, rn, rd } => {
            let h = host!(state, rn, rm, ra, "fnmsub s0, s1, s2, s3");
            set_v(state, rd, h.v);
        }
        FnmsubFloatFnmsubDFloatdp3 { rm, ra, rn, rd } => {
            let h = host!(state, rn, rm, ra, "fnmsub d0, d1, d2, d3");
            set_v(state, rd, h.v);
        }
        FabsFloatFabsSFloatdp1 { rn, rd } => {
            let h = host!(state, rn, 0_u8, 0_u8, "fabs s0, s1");
            set_v(state, rd, h.v);
        }
        FabsFloatFabsDFloatdp1 { rn, rd } => {
            let h = host!(state, rn, 0_u8, 0_u8, "fabs d0, d1");
            set_v(state, rd, h.v);
        }
        FnegFloatFnegSFloatdp1 { rn, rd } => {
            let h = host!(state, rn, 0_u8, 0_u8, "fneg s0, s1");
            set_v(state, rd, h.v);
        }
        FnegFloatFnegDFloatdp1 { rn, rd } => {
            let h = host!(state, rn, 0_u8, 0_u8, "fneg d0, d1");
            set_v(state, rd, h.v);
        }
        FsqrtFloatFsqrtSFloatdp1 { rn, rd } => {
            let h = host!(state, rn, 0_u8, 0_u8, "fsqrt s0, s1");
            set_v(state, rd, h.v);
        }
        FsqrtFloatFsqrtDFloatdp1 { rn, rd } => {
            let h = host!(state, rn, 0_u8, 0_u8, "fsqrt d0, d1");
            set_v(state, rd, h.v);
        }
        FrintnFloatFrintnSFloatdp1 { rn, rd } => {
            let h = host!(state, rn, 0_u8, 0_u8, "frintn s0, s1");
            set_v(state, rd, h.v);
        }
        FrintnFloatFrintnDFloatdp1 { rn, rd } => {
            let h = host!(state, rn, 0_u8, 0_u8, "frintn d0, d1");
            set_v(state, rd, h.v);
        }
        FrintpFloatFrintpSFloatdp1 { rn, rd } => {
            let h = host!(state, rn, 0_u8, 0_u8, "frintp s0, s1");
            set_v(state, rd, h.v);
        }
        FrintpFloatFrintpDFloatdp1 { rn, rd } => {
            let h = host!(state, rn, 0_u8, 0_u8, "frintp d0, d1");
            set_v(state, rd, h.v);
        }
        FrintmFloatFrintmSFloatdp1 { rn, rd } => {
            let h = host!(state, rn, 0_u8, 0_u8, "frintm s0, s1");
            set_v(state, rd, h.v);
        }
        FrintmFloatFrintmDFloatdp1 { rn, rd } => {
            let h = host!(state, rn, 0_u8, 0_u8, "frintm d0, d1");
            set_v(state, rd, h.v);
        }
        FrintzFloatFrintzSFloatdp1 { rn, rd } => {
            let h = host!(state, rn, 0_u8, 0_u8, "frintz s0, s1");
            set_v(state, rd, h.v);
        }
        FrintzFloatFrintzDFloatdp1 { rn, rd } => {
            let h = host!(state, rn, 0_u8, 0_u8, "frintz d0, d1");
            set_v(state, rd, h.v);
        }
        FrintaFloatFrintaSFloatdp1 { rn, rd } => {
            let h = host!(state, rn, 0_u8, 0_u8, "frinta s0, s1");
            set_v(state, rd, h.v);
        }
        FrintaFloatFrintaDFloatdp1 { rn, rd } => {
            let h = host!(state, rn, 0_u8, 0_u8, "frinta d0, d1");
            set_v(state, rd, h.v);
        }
        FrintxFloatFrintxSFloatdp1 { rn, rd } => {
            let h = host!(state, rn, 0_u8, 0_u8, "frintx s0, s1");
            set_v(state, rd, h.v);
        }
        FrintxFloatFrintxDFloatdp1 { rn, rd } => {
            let h = host!(state, rn, 0_u8, 0_u8, "frintx d0, d1");
            set_v(state, rd, h.v);
        }
        FrintiFloatFrintiSFloatdp1 { rn, rd } => {
            let h = host!(state, rn, 0_u8, 0_u8, "frinti s0, s1");
            set_v(state, rd, h.v);
        }
        FrintiFloatFrintiDFloatdp1 { rn, rd } => {
            let h = host!(state, rn, 0_u8, 0_u8, "frinti d0, d1");
            set_v(state, rd, h.v);
        }
        FcvtFloatFcvtDsFloatdp1 { rn, rd } => {
            let h = host!(state, rn, 0_u8, 0_u8, "fcvt d0, s1");
            set_v(state, rd, h.v);
        }
        FcvtFloatFcvtSdFloatdp1 { rn, rd } => {
            let h = host!(state, rn, 0_u8, 0_u8, "fcvt s0, d1");
            set_v(state, rd, h.v);
        }
        FcmpFloatFcmpSFloatcmp { rm, rn } => {
            let h = host!(state, rn, rm, 0_u8, "fcmp s1, s2");
            set_flags(state, h.nzcv);
        }
        FcmpFloatFcmpSzFloatcmp { rn } => {
            let h = host!(state, rn, 0_u8, 0_u8, "fcmp s1, #0.0");
            set_flags(state, h.nzcv);
        }
        FcmpFloatFcmpDFloatcmp { rm, rn } => {
            let h = host!(state, rn, rm, 0_u8, "fcmp d1, d2");
            set_flags(state, h.nzcv);
        }
        FcmpFloatFcmpDzFloatcmp { rn } => {
            let h = host!(state, rn, 0_u8, 0_u8, "fcmp d1, #0.0");
            set_flags(state, h.nzcv);
        }
        FcmpeFloatFcmpeSFloatcmp { rm, rn } => {
            let h = host!(state, rn, rm, 0_u8, "fcmpe s1, s2");
            set_flags(state, h.nzcv);
        }
        FcmpeFloatFcmpeSzFloatcmp { rn } => {
            let h = host!(state, rn, 0_u8, 0_u8, "fcmpe s1, #0.0");
            set_flags(state, h.nzcv);
        }
        FcmpeFloatFcmpeDFloatcmp { rm, rn } => {
            let h = host!(state, rn, rm, 0_u8, "fcmpe d1, d2");
            set_flags(state, h.nzcv);
        }
        FcmpeFloatFcmpeDzFloatcmp { rn } => {
            let h = host!(state, rn, 0_u8, 0_u8, "fcmpe d1, #0.0");
            set_flags(state, h.nzcv);
        }
        FccmpFloatFccmpSFloatccmp { rm, cond, rn, nzcv } => {
            if condition_holds(cond, state)? {
                let h = host!(state, rn, rm, 0_u8, "fcmp s1, s2");
                set_flags(state, h.nzcv);
            } else {
                set_flags(state, u64::from(nzcv) << 28);
            }
        }
        FccmpFloatFccmpDFloatccmp { rm, cond, rn, nzcv } => {
            if condition_holds(cond, state)? {
                let h = host!(state, rn, rm, 0_u8, "fcmp d1, d2");
                set_flags(state, h.nzcv);
            } else {
                set_flags(state, u64::from(nzcv) << 28);
            }
        }
        FccmpeFloatFccmpeSFloatccmp { rm, cond, rn, nzcv } => {
            if condition_holds(cond, state)? {
                let h = host!(state, rn, rm, 0_u8, "fcmpe s1, s2");
                set_flags(state, h.nzcv);
            } else {
                set_flags(state, u64::from(nzcv) << 28);
            }
        }
        FccmpeFloatFccmpeDFloatccmp { rm, cond, rn, nzcv } => {
            if condition_holds(cond, state)? {
                let h = host!(state, rn, rm, 0_u8, "fcmpe d1, d2");
                set_flags(state, h.nzcv);
            } else {
                set_flags(state, u64::from(nzcv) << 28);
            }
        }
        FcselFloatFcselSFloatsel { rm, cond, rn, rd } => {
            let source = if condition_holds(cond, state)? {
                rn
            } else {
                rm
            };
            // `V[d] = V[source]<31:0>`, the rest of the register zeroed.
            set_v(state, rd, state.v[usize::from(source)] & low_bits(32));
        }
        FcselFloatFcselDFloatsel { rm, cond, rn, rd } => {
            let source = if condition_holds(cond, state)? {
                rn
            } else {
                rm
            };
            // `V[d] = V[source]<63:0>`, the rest of the register zeroed.
            set_v(state, rd, state.v[usize::from(source)] & low_bits(64));
        }
        FmovFloatImmFmovSFloatimm { imm8, rd } => {
            set_v(state, rd, u128::from(expand_imm8(32, imm8.raw() as u8)));
        }
        FmovFloatImmFmovDFloatimm { imm8, rd } => {
            set_v(state, rd, u128::from(expand_imm8(64, imm8.raw() as u8)));
        }
        ScvtfFloatIntScvtfS32Float2int { rn, rd } => {
            let h = host_g!(
                state,
                0_u8,
                0_u8,
                0_u8,
                state.read_xzr(rn),
                "scvtf s0, {g:w}"
            );
            set_v(state, rd, h.v);
        }
        ScvtfFloatIntScvtfD32Float2int { rn, rd } => {
            let h = host_g!(
                state,
                0_u8,
                0_u8,
                0_u8,
                state.read_xzr(rn),
                "scvtf d0, {g:w}"
            );
            set_v(state, rd, h.v);
        }
        ScvtfFloatIntScvtfS64Float2int { rn, rd } => {
            let h = host_g!(
                state,
                0_u8,
                0_u8,
                0_u8,
                state.read_xzr(rn),
                "scvtf s0, {g:x}"
            );
            set_v(state, rd, h.v);
        }
        ScvtfFloatIntScvtfD64Float2int { rn, rd } => {
            let h = host_g!(
                state,
                0_u8,
                0_u8,
                0_u8,
                state.read_xzr(rn),
                "scvtf d0, {g:x}"
            );
            set_v(state, rd, h.v);
        }
        UcvtfFloatIntUcvtfS32Float2int { rn, rd } => {
            let h = host_g!(
                state,
                0_u8,
                0_u8,
                0_u8,
                state.read_xzr(rn),
                "ucvtf s0, {g:w}"
            );
            set_v(state, rd, h.v);
        }
        UcvtfFloatIntUcvtfD32Float2int { rn, rd } => {
            let h = host_g!(
                state,
                0_u8,
                0_u8,
                0_u8,
                state.read_xzr(rn),
                "ucvtf d0, {g:w}"
            );
            set_v(state, rd, h.v);
        }
        UcvtfFloatIntUcvtfS64Float2int { rn, rd } => {
            let h = host_g!(
                state,
                0_u8,
                0_u8,
                0_u8,
                state.read_xzr(rn),
                "ucvtf s0, {g:x}"
            );
            set_v(state, rd, h.v);
        }
        UcvtfFloatIntUcvtfD64Float2int { rn, rd } => {
            let h = host_g!(
                state,
                0_u8,
                0_u8,
                0_u8,
                state.read_xzr(rn),
                "ucvtf d0, {g:x}"
            );
            set_v(state, rd, h.v);
        }
        FcvtzsFloatIntFcvtzs32sFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtzs {g:w}, s1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtzsFloatIntFcvtzs64sFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtzs {g:x}, s1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtzsFloatIntFcvtzs32dFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtzs {g:w}, d1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtzsFloatIntFcvtzs64dFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtzs {g:x}, d1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtzuFloatIntFcvtzu32sFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtzu {g:w}, s1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtzuFloatIntFcvtzu64sFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtzu {g:x}, s1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtzuFloatIntFcvtzu32dFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtzu {g:w}, d1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtzuFloatIntFcvtzu64dFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtzu {g:x}, d1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtnsFloatFcvtns32sFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtns {g:w}, s1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtnsFloatFcvtns64sFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtns {g:x}, s1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtnsFloatFcvtns32dFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtns {g:w}, d1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtnsFloatFcvtns64dFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtns {g:x}, d1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtnuFloatFcvtnu32sFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtnu {g:w}, s1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtnuFloatFcvtnu64sFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtnu {g:x}, s1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtnuFloatFcvtnu32dFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtnu {g:w}, d1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtnuFloatFcvtnu64dFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtnu {g:x}, d1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtmsFloatFcvtms32sFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtms {g:w}, s1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtmsFloatFcvtms64sFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtms {g:x}, s1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtmsFloatFcvtms32dFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtms {g:w}, d1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtmsFloatFcvtms64dFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtms {g:x}, d1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtmuFloatFcvtmu32sFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtmu {g:w}, s1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtmuFloatFcvtmu64sFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtmu {g:x}, s1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtmuFloatFcvtmu32dFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtmu {g:w}, d1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtmuFloatFcvtmu64dFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtmu {g:x}, d1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtpsFloatFcvtps32sFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtps {g:w}, s1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtpsFloatFcvtps64sFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtps {g:x}, s1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtpsFloatFcvtps32dFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtps {g:w}, d1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtpsFloatFcvtps64dFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtps {g:x}, d1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtpuFloatFcvtpu32sFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtpu {g:w}, s1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtpuFloatFcvtpu64sFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtpu {g:x}, s1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtpuFloatFcvtpu32dFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtpu {g:w}, d1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtpuFloatFcvtpu64dFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtpu {g:x}, d1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtasFloatFcvtas32sFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtas {g:w}, s1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtasFloatFcvtas64sFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtas {g:x}, s1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtasFloatFcvtas32dFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtas {g:w}, d1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtasFloatFcvtas64dFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtas {g:x}, d1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtauFloatFcvtau32sFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtau {g:w}, s1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtauFloatFcvtau64sFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtau {g:x}, s1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtauFloatFcvtau32dFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtau {g:w}, d1");
            state.write_xzr(rd, h.gpr);
        }
        FcvtauFloatFcvtau64dFloat2int { rn, rd } => {
            let h = host_g!(state, rn, 0_u8, 0_u8, 0_u64, "fcvtau {g:x}, d1");
            state.write_xzr(rd, h.gpr);
        }
        MrsMrsRsSystemmoveFpcr { rt } => state.write_xzr(rt, state.fpcr),
        MrsMrsRsSystemmoveFpsr { rt } => state.write_xzr(rt, state.fpsr),
        other => {
            return Err(InsnError::Error(format!(
                "{} is not an A18 register form",
                other.key()
            )))
        }
    }
    Ok(())
}

fn set_v(state: &mut MachineState, n: u8, value: u128) {
    state.v[usize::from(n)] = value;
}

/// NZCV from bits 31:28 of `word` (the layout of the NZCV system register).
fn set_flags(state: &mut MachineState, word: u64) {
    state.flags = Flags {
        n: word & (1 << 31) != 0,
        z: word & (1 << 30) != 0,
        c: word & (1 << 29) != 0,
        v: word & (1 << 28) != 0,
    };
}

fn low_bits(bits: u32) -> u128 {
    (1_u128 << bits) - 1
}

/// `VFPExpandImm(imm8, N)`: the FMOV (scalar, immediate) constant as an N-bit
/// pattern, `a:NOT(b):Replicate(b):cd:efgh:Zeros`.
pub(crate) fn expand_imm8(bits: u32, imm8: u8) -> u64 {
    let (sign, b, cd, frac) = (
        u64::from(imm8 >> 7),
        u64::from((imm8 >> 6) & 1),
        u64::from((imm8 >> 4) & 0b11),
        u64::from(imm8 & 0b1111),
    );
    // Exponent width, replicated copies of `b` and fraction padding: 8 bits (5
    // copies) and 19 zeros for N = 32, 11 bits (8 copies) and 48 zeros for N = 64.
    let (exp_bits, replicated, frac_bits) = match bits {
        32 => (8, 5, 19),
        64 => (11, 8, 48),
        _ => unreachable!("FMOV (scalar, immediate) is single or double precision"),
    };
    let exp = ((1 - b) << (exp_bits - 1)) | ((b * ((1 << replicated) - 1)) << 2) | cd;
    (sign << (bits - 1)) | (exp << (bits - 1 - exp_bits)) | (frac << frac_bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FMOV constants against the architecture's table: 1.0 is imm8 0x70, 2.0 is
    /// 0x00, -31.0 is 0xbf, 0.125 is 0x40 (single and double precision alike).
    #[test]
    fn fmov_immediate_expansion_matches_the_documented_constants() {
        for (imm8, value) in [
            (0x70_u8, 1.0_f64),
            (0x00, 2.0),
            (0xbf, -31.0),
            (0x40, 0.125),
        ] {
            assert_eq!(f64::from_bits(expand_imm8(64, imm8)), value, "{imm8:#x}");
            assert_eq!(
                f32::from_bits(expand_imm8(32, imm8) as u32),
                value as f32,
                "{imm8:#x}"
            );
        }
    }
}
