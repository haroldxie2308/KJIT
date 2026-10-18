use super::rules;
use super::*;
use crate::shared::abi::{
    BUDGET_COUNTER_REG, DISPATCH_KEY_REG, KJIT_DISPATCH_TEMPLATE, RUNTIME_FRAME_IBTC_OFFSET,
    RUNTIME_FRAME_PT_REGS_PTR_OFFSET, RUNTIME_FRAME_USER_X18_OFFSET,
};
use crate::shared::arm64::ergo::{
    ldst64_offset, ldstpair64_offset, mem_off, mem_pre, scaled_simm, simm, sp, uimm, x,
};
use crate::shared::arm64::{A64Insn, A64OperandRole, A64Reg};

use alloc::vec::Vec;

const EPI: i64 = EPILOGUE_OFFSET as i64;

/// A hand-built fragment: the ABI wrapper followed by `body`.
struct Frag {
    code: Vec<u8>,
    sites: Vec<FaultSiteEntry>,
    entries: Vec<usize>,
    links: Vec<(usize, u64)>,
}

impl Frag {
    fn new(body: &[A64Insn]) -> Self {
        let mut code = Vec::new();
        for insn in KJIT_PROLOGUE.iter().chain(KJIT_EPILOGUE).chain(body) {
            code.extend_from_slice(&insn.encode().unwrap().to_le_bytes());
        }
        Self {
            code,
            sites: Vec::new(),
            entries: alloc::vec![BODY_OFFSET],
            links: Vec::new(),
        }
    }

    fn site(mut self, access: usize, stub: usize) -> Self {
        self.sites.push(FaultSiteEntry {
            access_offset: at(access),
            stub_offset: at(stub),
        });
        self
    }

    fn entry(mut self, index: usize) -> Self {
        self.entries.push(at(index));
        self
    }

    /// A16: a link-site entry for body word `index`.
    fn link(mut self, index: usize, target_pc: u64) -> Self {
        self.links.push((at(index), target_pc));
        self
    }

    fn verify(&self) -> Result<VerifyOk, VerifyError> {
        verify_fragment(&VerifyInput {
            code: &self.code,
            fault_sites: &self.sites,
            entry_offsets: &self.entries,
            link_sites: &self.links,
        })
    }

    fn rule(&self) -> Option<VerifyRule> {
        self.verify().err().map(|err| err.rule)
    }
}

/// Byte offset of body word `index`.
fn at(index: usize) -> usize {
    BODY_OFFSET + index * 4
}

/// Unconditional branch at body word `from` to fragment byte offset `to`.
fn b(from: usize, to: i64) -> A64Insn {
    A64Insn::BUncondBOnlyBranchImm {
        imm26: branch_imm(to - at(from) as i64, 26),
    }
}

fn b_epi(from: usize) -> A64Insn {
    b(from, EPI)
}

fn branch_imm(delta: i64, bits: u8) -> crate::shared::arm64::A64Imm {
    scaled_simm(((delta >> 2) as u32) & ((1 << bits) - 1), bits, 2)
}

fn movz(rd: u8, imm: u32) -> A64Insn {
    A64Insn::MovzMovz64Movewide {
        hw: 0,
        imm16: uimm(imm, 16),
        rd: x(rd),
    }
}

fn mov(rd: crate::shared::arm64::A64Reg, rn: crate::shared::arm64::A64Reg) -> A64Insn {
    A64Insn::AddAddsubImmAdd64AddsubImm {
        sh: 0,
        imm12: uimm(0, 12),
        rn,
        rd,
    }
}

fn ldtr(rt: u8, rn: u8) -> A64Insn {
    A64Insn::LdtrLdtr64LdstUnpriv {
        rt: x(rt),
        mem: mem_off(crate::shared::arm64::A64Reg::x_sp(rn), simm(0, 9)),
    }
}

fn ldr(rt: u8, base: crate::shared::arm64::A64Reg, offset: u32) -> A64Insn {
    A64Insn::LdrImmGenLdr64LdstPos {
        rt: x(rt),
        mem: mem_off(base, ldst64_offset(offset)),
    }
}

fn str(rt: u8, base: crate::shared::arm64::A64Reg, offset: u32) -> A64Insn {
    A64Insn::StrImmGenStr64LdstPos {
        rt: x(rt),
        mem: mem_off(base, ldst64_offset(offset)),
    }
}

fn xs(reg: u8) -> crate::shared::arm64::A64Reg {
    crate::shared::arm64::A64Reg::x_sp(reg)
}

/// `ldtr x0, [x1]` with its fault stub after the body's final branch.
fn user_access_fragment() -> Frag {
    Frag::new(&[ldtr(0, 1), b_epi(1), movz(9, 5), b_epi(3)]).site(0, 2)
}

#[test]
fn accepts_minimal_body() {
    assert_eq!(Frag::new(&[movz(0, 1), b_epi(1)]).rule(), None);
}

#[test]
fn rejects_length_and_decode_errors() {
    let mut frag = Frag::new(&[b_epi(0)]);
    frag.code.pop();
    assert_eq!(frag.rule(), Some(VerifyRule::Length));
    assert_eq!(Frag::new(&[]).rule(), Some(VerifyRule::Length));

    let mut frag = Frag::new(&[movz(0, 1), b_epi(1)]);
    // `msr tpidr_el0, x0`: outside the generated subset.
    frag.code[BODY_OFFSET..BODY_OFFSET + 4].copy_from_slice(&0xd51b_d040_u32.to_le_bytes());
    assert_eq!(
        frag.verify().unwrap_err(),
        VerifyError {
            offset: BODY_OFFSET,
            rule: VerifyRule::Undecodable { word: 0xd51b_d040 }
        }
    );
}

#[test]
fn rejects_wrapper_mismatch() {
    let mut frag = Frag::new(&[b_epi(0)]);
    frag.code[8] ^= 1;
    assert_eq!(frag.verify().unwrap_err().offset, 8);
    assert_eq!(frag.rule(), Some(VerifyRule::Prologue));

    let mut frag = Frag::new(&[b_epi(0)]);
    frag.code[EPILOGUE_OFFSET + 4] ^= 1;
    assert_eq!(frag.rule(), Some(VerifyRule::Epilogue));
}

#[test]
fn rejects_sp_and_frame_pointer_writes() {
    let cases = [
        (mov(xs(31), xs(0)), VerifyRule::SpWrite),
        (
            A64Insn::AddAddsubImmAdd64AddsubImm {
                sh: 0,
                imm12: uimm(16, 12),
                rn: xs(31),
                rd: xs(31),
            },
            VerifyRule::SpWrite,
        ),
        (movz(29, 0), VerifyRule::FramePointerWrite),
        (mov(xs(29), xs(0)), VerifyRule::FramePointerWrite),
    ];
    for (insn, rule) in cases {
        assert_eq!(Frag::new(&[insn, b_epi(1)]).rule(), Some(rule), "{insn:?}");
    }
    // Writing XZR through an Xzr-mode register field is not an SP write.
    assert_eq!(Frag::new(&[movz(31, 0), b_epi(1)]).rule(), None);
}

#[test]
fn user_access_needs_fault_site_and_exit_group_stub() {
    assert_eq!(user_access_fragment().rule(), None);

    let mut frag = user_access_fragment();
    frag.sites.clear();
    assert_eq!(frag.rule(), Some(VerifyRule::MissingFaultSite));

    // Entry on a non-access word.
    let frag = Frag::new(&[ldtr(0, 1), b_epi(1), movz(9, 5), b_epi(3)]).site(1, 2);
    assert_eq!(frag.rule(), Some(VerifyRule::FaultSiteNotUserAccess));

    // Stub that is not an exit-group start: mid-group, or reachable by fall-through.
    let frag = Frag::new(&[ldtr(0, 1), b_epi(1), movz(9, 5), b_epi(3)]).site(0, 3);
    assert_eq!(frag.rule(), Some(VerifyRule::ExitGroup));
    let frag = Frag::new(&[ldtr(0, 1), movz(9, 5), b_epi(2)]).site(0, 1);
    assert_eq!(frag.rule(), Some(VerifyRule::ExitGroup));
    // Stub that does not end in `b <epilogue>`.
    let frag = Frag::new(&[ldtr(0, 1), b_epi(1), movz(9, 5), b(3, at(0) as i64)]).site(0, 2);
    assert_eq!(frag.rule(), Some(VerifyRule::ExitGroup));
    // Stub outside the fragment.
    let frag = Frag::new(&[ldtr(0, 1), b_epi(1)]).site(0, 7);
    assert_eq!(frag.rule(), Some(VerifyRule::ExitGroup));

    // Unsorted table.
    let frag = Frag::new(&[ldtr(0, 1), ldtr(2, 3), b_epi(2), movz(9, 5), b_epi(4)])
        .site(1, 3)
        .site(0, 3);
    assert_eq!(frag.rule(), Some(VerifyRule::FaultSiteOrder));

    let frag = Frag::new(&[ldtr(0, 31), b_epi(1), movz(9, 5), b_epi(3)]).site(0, 2);
    assert_eq!(frag.rule(), Some(VerifyRule::UserAccessSpBase));
}

/// Every unprivileged form is a user access under the same rules as `LDTR`:
/// fault-site entry required, SP base rejected, and not allowed in an exit group.
#[test]
fn every_unprivileged_form_is_a_fault_site_user_access() {
    let mem = |base| mem_off(xs(base), simm(0x1ff, 9));
    const W0: crate::shared::arm64::A64Reg = crate::shared::arm64::A64Reg::w(0);
    let forms: [fn(crate::shared::arm64::A64Mem) -> A64Insn; 13] = [
        |mem| A64Insn::LdtrLdtr32LdstUnpriv { rt: W0, mem },
        |mem| A64Insn::LdtrLdtr64LdstUnpriv { rt: x(0), mem },
        |mem| A64Insn::LdtrbLdtrb32LdstUnpriv { rt: W0, mem },
        |mem| A64Insn::LdtrhLdtrh32LdstUnpriv { rt: W0, mem },
        |mem| A64Insn::LdtrsbLdtrsb32LdstUnpriv { rt: W0, mem },
        |mem| A64Insn::LdtrsbLdtrsb64LdstUnpriv { rt: x(0), mem },
        |mem| A64Insn::LdtrshLdtrsh32LdstUnpriv { rt: W0, mem },
        |mem| A64Insn::LdtrshLdtrsh64LdstUnpriv { rt: x(0), mem },
        |mem| A64Insn::LdtrswLdtrsw64LdstUnpriv { rt: x(0), mem },
        |mem| A64Insn::SttrSttr32LdstUnpriv { rt: W0, mem },
        |mem| A64Insn::SttrSttr64LdstUnpriv { rt: x(0), mem },
        |mem| A64Insn::SttrbSttrb32LdstUnpriv { rt: W0, mem },
        |mem| A64Insn::SttrhSttrh32LdstUnpriv { rt: W0, mem },
    ];
    for make in forms {
        let access = make(mem(1));
        let ok = Frag::new(&[access, b_epi(1), movz(9, 5), b_epi(3)]).site(0, 2);
        assert_eq!(ok.rule(), None, "{access:?}");
        let no_site = Frag::new(&[access, b_epi(1)]);
        assert_eq!(
            no_site.rule(),
            Some(VerifyRule::MissingFaultSite),
            "{access:?}"
        );
        let sp = make(mem(31));
        let sp_base = Frag::new(&[sp, b_epi(1), movz(9, 5), b_epi(3)]).site(0, 2);
        assert_eq!(sp_base.rule(), Some(VerifyRule::UserAccessSpBase), "{sp:?}");
        // In a fault stub's exit group.
        let in_stub = Frag::new(&[ldtr(0, 1), b_epi(1), access, b_epi(3)])
            .site(0, 2)
            .site(2, 2);
        assert_eq!(in_stub.rule(), Some(VerifyRule::ExitGroup), "{access:?}");
    }
}

/// User-code memory forms are only ever lowered, so the verifier rejects them in a
/// fragment even where a plain runtime `LDR`/`STR` would be allowed (a user-state
/// frame slot).
#[test]
fn user_only_memory_forms_are_rejected_anywhere() {
    let frame = mem_off(sp(), simm(16, 9));
    let frame_pos = |scale| {
        crate::shared::arm64::A64Mem::offset(
            sp(),
            crate::shared::arm64::A64Imm::scaled_unsigned(16_u32 >> scale, 12, scale),
        )
    };
    let pair = crate::shared::arm64::A64Mem::offset(sp(), scaled_simm(4, 7, 2));
    let w0 = crate::shared::arm64::A64Reg::w(0);
    let cases = [
        A64Insn::LdrbImmLdrb32LdstPos {
            rt: w0,
            mem: frame_pos(0),
        },
        A64Insn::StrhImmStrh32LdstPos {
            rt: w0,
            mem: frame_pos(1),
        },
        A64Insn::LdrswImmLdrsw64LdstPos {
            rt: x(0),
            mem: frame_pos(2),
        },
        A64Insn::LdurGenLdur64LdstUnscaled {
            rt: x(0),
            mem: frame,
        },
        A64Insn::SturbSturb32LdstUnscaled { rt: w0, mem: frame },
        A64Insn::LdpGenLdp32LdstpairOff {
            rt2: crate::shared::arm64::A64Reg::w(1),
            rt: w0,
            mem: pair,
        },
        A64Insn::StpGenStp32LdstpairOff {
            rt2: crate::shared::arm64::A64Reg::w(1),
            rt: w0,
            mem: pair,
        },
        A64Insn::LdpswLdpsw64LdstpairOff {
            rt2: x(1),
            rt: x(0),
            mem: pair,
        },
        A64Insn::LdrRegGenLdr64LdstRegoff {
            rm: x(1),
            option: 0b011,
            s: 0,
            rn: sp(),
            rt: x(0),
        },
        A64Insn::StrbRegStrb32blLdstRegoff {
            rm: x(1),
            s: 0,
            rn: xs(2),
            rt: w0,
        },
        A64Insn::LdrLitGenLdr64Loadlit {
            imm19: scaled_simm(1, 19, 2),
            rt: x(0),
        },
        A64Insn::PrfmImmPrfmPLdstPos {
            imm12: uimm(0, 12),
            rn: xs(1),
            rt: 0,
        },
        A64Insn::PrfmLitPrfmPLoadlit {
            imm19: uimm(1, 19),
            rt: 0,
        },
        A64Insn::PrfmRegPrfmPLdstRegoff {
            rm: x(1),
            option: 0b011,
            s: 0,
            rn: xs(2),
            rt: 0,
        },
        // A7c acquire/release: a privileged ordered access, even on the frame.
        A64Insn::LdarLdarLr64Ldstord { rn: sp(), rt: x(0) },
        A64Insn::LdarLdarLr32Ldstord { rn: xs(1), rt: w0 },
        A64Insn::LdarbLdarbLr32Ldstord { rn: xs(1), rt: w0 },
        A64Insn::LdarhLdarhLr32Ldstord { rn: xs(1), rt: w0 },
        A64Insn::StlrStlrSl64Ldstord { rn: sp(), rt: x(0) },
        A64Insn::StlrStlrSl32Ldstord { rn: xs(1), rt: w0 },
        A64Insn::StlrbStlrbSl32Ldstord { rn: xs(1), rt: w0 },
        A64Insn::StlrhStlrhSl32Ldstord { rn: xs(1), rt: w0 },
        A64Insn::LdaprLdapr64lMemop { rn: xs(1), rt: x(0) },
        A64Insn::LdaprLdapr32lMemop { rn: xs(1), rt: w0 },
        A64Insn::LdaprbLdaprb32lMemop { rn: xs(1), rt: w0 },
        A64Insn::LdaprhLdaprh32lMemop { rn: xs(1), rt: w0 },
        // A7d: BTI is rephrased to NOP; the allowlisted hint space is NOP only.
        A64Insn::BtiBtiHbHints { op2: 0b000 },
        A64Insn::BtiBtiHbHints { op2: 0b010 },
        A64Insn::BtiBtiHbHints { op2: 0b100 },
        A64Insn::BtiBtiHbHints { op2: 0b110 },
    ];
    for insn in cases {
        let frag = Frag::new(&[insn, b_epi(1)]);
        assert_eq!(
            frag.verify().unwrap_err(),
            VerifyError {
                offset: at(0),
                rule: VerifyRule::UserOnlyForm
            },
            "{insn:?}"
        );
        // Also with a fault-site entry: that does not make it a user access.
        let frag = Frag::new(&[insn, b_epi(1), movz(9, 5), b_epi(3)]).site(0, 2);
        assert_eq!(
            frag.rule(),
            Some(VerifyRule::FaultSiteNotUserAccess),
            "{insn:?}"
        );
    }
}

/// Rule 5 (A7c): DMB/DSB/ISB are allowlisted with every CRm value, in the body
/// and in an exit group; nothing else of the barrier/hint/system space decodes.
#[test]
fn barriers_are_the_only_allowed_system_instructions_besides_mrs_user_regs() {
    for crm in 0..16 {
        for barrier in [
            A64Insn::DmbDmbBoBarriers { crm },
            A64Insn::DsbDsbBoBarriers { crm },
            A64Insn::IsbIsbBiBarriers { crm },
        ] {
            assert_eq!(
                Frag::new(&[barrier, movz(0, 1), b_epi(2)]).rule(),
                None,
                "{barrier:?}"
            );
            // Around a user access, as the acquire/release lowering emits it, and
            // inside an exit group.
            let fenced = Frag::new(&[barrier, ldtr(0, 1), barrier, b_epi(3), barrier, b_epi(5)])
                .site(1, 4);
            assert_eq!(fenced.rule(), None, "{barrier:?}");
        }
    }

    let words = [
        0xd503_323f_u32, // dsb ishnxs (FEAT_XS): not in the subset
        0xd503_30ff,     // sb
        0xd503_305f,     // clrex
        0xd503_201f | (0b0010 << 5), // hint #2 (wfe)
        0xd503_207f,     // wfi
        0xd503_233f,     // paciasp
        0xd503_23bf,     // autiasp
        0xd503_20ff,     // xpaclri
        0xd503_243f,     // hint #0x21 (BTI's CRm, op2<0> = 1)
        0xd500_40bf,     // msr spsel, #0
        0xd503_41df,     // msr daifset, #1
        0xd508_7500,     // ic ialluis
        0xd50b_7520,     // ic ivau, x0
        0xd50b_7420,     // dc zva, x0
        0xd508_871f,     // tlbi vmalle1is
    ];
    for word in words {
        let mut frag = Frag::new(&[movz(0, 1), b_epi(1)]);
        frag.code[BODY_OFFSET..BODY_OFFSET + 4].copy_from_slice(&word.to_le_bytes());
        assert_eq!(
            frag.rule(),
            Some(VerifyRule::Undecodable { word }),
            "{word:#010x}"
        );
    }
}

/// Rule 5 (A10, A18): MRS is allowlisted for exactly TPIDR_EL0, CNTVCT_EL0,
/// CNTFRQ_EL0, FPCR and FPSR, with any Rt, in the body and in an exit group; every
/// other value of the system-register field (o0:op1:CRn:CRm:op2, all 2^15) is
/// undecodable. Rule 9: their results are user values. FPCR/FPSR need the FP/SIMD
/// bracket (`uses_fpsimd`); the others do not.
#[test]
fn mrs_is_allowed_for_exactly_the_user_readable_registers() {
    const MRS: u32 = 0xd530_0000;
    let sysreg = |op1: u32, crn: u32, crm: u32, op2: u32| {
        (1 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2
    };
    let allowed = [
        sysreg(3, 13, 0, 2), // TPIDR_EL0
        sysreg(3, 14, 0, 2), // CNTVCT_EL0
        sysreg(3, 14, 0, 0), // CNTFRQ_EL0
        sysreg(3, 4, 4, 0),  // FPCR
        sysreg(3, 4, 4, 1),  // FPSR
    ];
    for reg in 0..(1_u32 << 15) {
        for rt in [0, 12, 30, 31] {
            let word = MRS | (reg << 5) | rt;
            // In the body and first in the user access's exit group.
            let body = [movz(1, 1), ldtr(0, 1), b_epi(2), movz(1, 1), movz(9, 5), b_epi(5)];
            let mut frag = Frag::new(&body).site(1, 3);
            for index in [0, 3] {
                let at = BODY_OFFSET + 4 * index;
                frag.code[at..at + 4].copy_from_slice(&word.to_le_bytes());
            }
            let expected = if allowed.contains(&reg) {
                None
            } else {
                Some(VerifyRule::Undecodable { word })
            };
            assert_eq!(frag.rule(), expected, "{word:#010x}");
        }
    }

    // A counter read overwrites a kernel value like any other write.
    let orr = A64Insn::OrrLogShiftOrr64LogShift {
        shift: 0,
        rm: x(12),
        imm6: uimm(0, 6),
        rn: x(31),
        rd: x(0),
    };
    for mrs in [
        A64Insn::MrsMrsRsSystemmoveTpidrEl0 { rt: x(12) },
        A64Insn::MrsMrsRsSystemmoveCntvctEl0 { rt: x(12) },
        A64Insn::MrsMrsRsSystemmoveCntfrqEl0 { rt: x(12) },
        A64Insn::MrsMrsRsSystemmoveFpcr { rt: x(12) },
        A64Insn::MrsMrsRsSystemmoveFpsr { rt: x(12) },
    ] {
        assert_eq!(Frag::new(&[mrs, orr, b_epi(2)]).rule(), None, "{mrs:?}");
    }
    let uses = |insn: A64Insn| Frag::new(&[insn, b_epi(1)]).verify().unwrap().uses_fpsimd;
    assert!(!uses(A64Insn::MrsMrsRsSystemmoveCntvctEl0 { rt: x(0) }));
    assert!(uses(A64Insn::MrsMrsRsSystemmoveFpcr { rt: x(0) }));
    assert!(uses(A64Insn::MrsMrsRsSystemmoveFpsr { rt: x(0) }));
}

#[test]
fn cold_region_is_entered_only_at_exit_group_starts() {
    // Alignment guard: `and x12, x17, #15; cbnz x12, <stub>; sttr x0, [x17]`.
    let guard = A64Insn::AndLogImmAnd64LogImm {
        n: 1,
        immr: uimm(0, 6),
        imms: uimm(3, 6),
        rn: x(17),
        rd: xs(12),
    };
    let cbnz = |to: usize| A64Insn::CbnzCbnz64Compbranch {
        imm19: branch_imm(at(to) as i64 - at(1) as i64, 19),
        rt: x(12),
    };
    let sttr = A64Insn::SttrSttr64LdstUnpriv {
        rt: x(0),
        mem: mem_off(xs(17), simm(0, 9)),
    };
    let body = |to| {
        [
            guard,
            cbnz(to),
            sttr,
            b_epi(3),
            movz(9, 5),
            movz(10, 1),
            b_epi(6),
        ]
    };
    assert_eq!(Frag::new(&body(4)).site(2, 4).rule(), None);
    // Into the middle of the stub.
    assert_eq!(
        Frag::new(&body(5)).site(2, 4).rule(),
        Some(VerifyRule::BranchTarget {
            target: at(5) as i64
        })
    );
    // The entry table never points into the cold region.
    assert_eq!(
        Frag::new(&body(4)).site(2, 4).entry(4).rule(),
        Some(VerifyRule::EntryOffset)
    );
}

#[test]
fn runtime_access_windows() {
    let frame = |insn| Frag::new(&[insn, b_epi(1)]).rule();
    assert_eq!(frame(ldr(0, sp(), 16)), None);
    assert_eq!(frame(str(0, sp(), 72)), None);
    for offset in [0, 8, 80, 88, 168, 184, 200, 208] {
        assert_eq!(
            frame(str(0, sp(), offset)),
            Some(VerifyRule::FrameAccessOutOfRange),
            "str [sp, #{offset}]"
        );
    }
    assert_eq!(
        frame(A64Insn::LdpGenLdp64LdstpairOff {
            rt2: x(1),
            rt: x(0),
            mem: mem_off(sp(), ldstpair64_offset(72)),
        }),
        Some(VerifyRule::FrameAccessOutOfRange)
    );
    // A store to the pt_regs pointer slot would redirect the epilogue's writes.
    assert_eq!(
        frame(str(0, sp(), RUNTIME_FRAME_PT_REGS_PTR_OFFSET)),
        Some(VerifyRule::FrameAccessOutOfRange)
    );
    assert_eq!(
        frame(A64Insn::StrImmGenStr64LdstImmpre {
            rt: x(0),
            mem: mem_pre(sp(), simm(16, 9)),
        }),
        Some(VerifyRule::RuntimeAccessWriteback)
    );
    assert_eq!(frame(ldr(0, xs(1), 0)), Some(VerifyRule::RuntimeAccessBase));
}

#[test]
fn pt_regs_dataflow() {
    let load = ldr(12, sp(), RUNTIME_FRAME_PT_REGS_PTR_OFFSET);
    assert_eq!(
        Frag::new(&[load, str(9, xs(12), 72), str(10, xs(12), 248), b_epi(3)]).rule(),
        None
    );
    // pc / pstate are never fragment-accessible.
    assert_eq!(
        Frag::new(&[load, str(9, xs(12), 256), b_epi(2)]).rule(),
        Some(VerifyRule::PtRegsAccessOutOfRange)
    );
    // Redefinition kills the fact.
    assert_eq!(
        Frag::new(&[load, movz(12, 0), str(9, xs(12), 72), b_epi(3)]).rule(),
        Some(VerifyRule::RuntimeAccessBase)
    );
    // So does a join point: an entry at the store sees x12 = the entry address.
    assert_eq!(
        Frag::new(&[load, str(9, xs(12), 72), b_epi(2)])
            .entry(1)
            .rule(),
        Some(VerifyRule::RuntimeAccessBase)
    );
    // And a branch target.
    assert_eq!(
        Frag::new(&[load, b(1, at(2) as i64), str(9, xs(12), 72), b_epi(3)]).rule(),
        Some(VerifyRule::RuntimeAccessBase)
    );
}

/// The join state is what the prologue leaves behind: x29 (the runtime frame) and
/// the entry scratch (the entry address), nothing else.
#[test]
fn join_state_is_derived_from_the_prologue() {
    let state = taint::Taint::at_entry().unwrap();
    assert_eq!(state.kernel, (1 << 12) | (1 << 29));
    assert_eq!(state.pt_regs, 0);
}

/// Rule 9 lets every exit carry the join state; that is sound only because the
/// epilogue never reads a join-state register before writing it.
#[test]
fn join_state_is_dead_in_the_epilogue() {
    let mut live = 0_u32;
    for insn in KJIT_EPILOGUE.iter().rev() {
        let read = rules::reads(insn).unwrap();
        let base = read
            .base
            .filter(|base| base.enc() < 31)
            .map_or(0, |base| 1 << base.enc());
        live = (live & !rules::writes(insn).unwrap().gprs) | read.gprs | base;
    }
    // Not vacuous: everything the epilogue copies to the user or the runtime. x18 is
    // not live-in: the epilogue loads user x18 from its slot (A12) before writing it back.
    let user = (0..=11).chain(16..=17).chain(19..=28).chain([30]);
    assert_eq!(live, user.fold(0, |mask, reg| mask | (1 << reg)));
    assert_eq!(live & taint::Taint::at_entry().unwrap().kernel, 0);
}

#[test]
fn kernel_values_are_never_read() {
    let rule = |body: &[A64Insn]| Frag::new(body).rule();
    let read = Some(VerifyRule::KernelValueRead);
    let orr = |rd: u8, rm: u8| A64Insn::OrrLogShiftOrr64LogShift {
        shift: 0,
        rm: x(rm),
        imm6: uimm(0, 6),
        rn: x(31),
        rd: x(rd),
    };
    // SP as data (a frame-access base is fine), x29, the entry scratch at entry.
    assert_eq!(rule(&[mov(xs(0), sp()), b_epi(1)]), read);
    assert_eq!(
        rule(&[
            A64Insn::SubsAddsubImmSubs64sAddsubImm {
                sh: 0,
                imm12: uimm(0, 12),
                rn: sp(),
                rd: x(31),
            },
            b_epi(1)
        ]),
        read
    );
    assert_eq!(rule(&[mov(xs(0), xs(29)), b_epi(1)]), read);
    assert_eq!(rule(&[str(29, sp(), 16), b_epi(1)]), read);
    assert_eq!(rule(&[orr(0, 12), b_epi(1)]), read);
    assert_eq!(rule(&[movz(12, 0), orr(0, 12), b_epi(2)]), None);

    // The pt_regs pointer: a base only.
    let load = ldr(12, sp(), RUNTIME_FRAME_PT_REGS_PTR_OFFSET);
    for leak in [
        orr(10, 12),
        str(12, xs(12), 0),
        str(12, sp(), 16),
        A64Insn::CbzCbz64Compbranch {
            imm19: branch_imm(4, 19),
            rt: x(12),
        },
    ] {
        assert_eq!(rule(&[load, leak, b_epi(2)]), read, "{leak:?}");
    }
    // As a user access's base.
    assert_eq!(
        Frag::new(&[load, ldtr(0, 12), b_epi(2), movz(9, 5), b_epi(4)])
            .site(1, 3)
            .rule(),
        read
    );
    // Loaded into anything but scratch, or partly.
    assert_eq!(
        rule(&[ldr(0, sp(), RUNTIME_FRAME_PT_REGS_PTR_OFFSET), b_epi(1)]),
        Some(VerifyRule::FrameAccessOutOfRange)
    );
    assert_eq!(
        rule(&[
            A64Insn::LdrImmGenLdr32LdstPos {
                rt: crate::shared::arm64::ergo::w(12),
                mem: mem_off(sp(), crate::shared::arm64::ergo::scaled_uimm(44, 12, 2)),
            },
            b_epi(1)
        ]),
        Some(VerifyRule::FrameAccessOutOfRange)
    );
}

#[test]
fn kernel_values_do_not_cross_edges() {
    let edge = Some(VerifyRule::KernelValueAtEdge);
    let load13 = ldr(13, sp(), RUNTIME_FRAME_PT_REGS_PTR_OFFSET);
    // A branch into the body, a branch to the epilogue.
    assert_eq!(
        Frag::new(&[load13, b(1, at(2) as i64), b_epi(2)]).rule(),
        edge
    );
    assert_eq!(Frag::new(&[load13, b_epi(1)]).rule(), edge);
    // A fall-through into a join point.
    assert_eq!(
        Frag::new(&[load13, movz(0, 1), b_epi(2)]).entry(1).rule(),
        edge
    );
    // The fault edge of a user access.
    assert_eq!(
        Frag::new(&[load13, ldtr(0, 1), b_epi(2), movz(9, 5), b_epi(4)])
            .site(1, 3)
            .rule(),
        edge
    );
    // Overwritten first: fine. And the entry scratch may hold the pointer at an
    // edge (every join point already assumes it holds a kernel value).
    assert_eq!(Frag::new(&[load13, movz(13, 0), b_epi(2)]).rule(), None);
    let load12 = ldr(12, sp(), RUNTIME_FRAME_PT_REGS_PTR_OFFSET);
    assert_eq!(
        Frag::new(&[load12, str(9, xs(12), 72), b(2, at(3) as i64), b_epi(3)]).rule(),
        None
    );
}

#[test]
fn control_flow_rules() {
    let rule = |insn| Frag::new(&[insn, b_epi(1)]).rule();
    assert_eq!(
        rule(A64Insn::BlBlOnlyBranchImm {
            imm26: branch_imm(4, 26)
        }),
        Some(VerifyRule::Call)
    );
    for insn in [
        A64Insn::BrBr64BranchReg { rn: x(0) },
        A64Insn::BlrBlr64BranchReg { rn: x(0) },
        A64Insn::RetRet64rBranchReg { rn: x(30) },
    ] {
        assert_eq!(rule(insn), Some(VerifyRule::IndirectBranch), "{insn:?}");
    }
    assert_eq!(
        rule(A64Insn::SvcSvcExException { imm16: uimm(0, 16) }),
        Some(VerifyRule::Exception)
    );
    assert_eq!(
        rule(A64Insn::AdrAdrOnlyPcreladdr {
            immlo: uimm(0, 2),
            immhi: uimm(0, 19),
            rd: x(0),
        }),
        Some(VerifyRule::PcRelative)
    );
    for mrs in [
        A64Insn::MrsMrsRsSystemmoveTpidrEl0 { rt: x(0) },
        A64Insn::MrsMrsRsSystemmoveCntvctEl0 { rt: x(0) },
        A64Insn::MrsMrsRsSystemmoveCntfrqEl0 { rt: x(0) },
    ] {
        assert_eq!(rule(mrs), None, "{mrs:?}");
    }
    assert_eq!(rule(A64Insn::NopNopHiHints {}), None);

    for target in [0, 4, EPI + 4, BODY_OFFSET as i64 - 4, at(2) as i64, -4] {
        assert_eq!(
            Frag::new(&[b(0, target), b_epi(1)]).rule(),
            Some(VerifyRule::BranchTarget { target }),
            "target {target:#x}"
        );
    }
    assert_eq!(Frag::new(&[b(0, at(1) as i64), b_epi(1)]).rule(), None);

    assert_eq!(
        Frag::new(&[b_epi(0), movz(0, 0)]).rule(),
        Some(VerifyRule::FallsOffEnd)
    );
    let cond_last = A64Insn::CbzCbz64Compbranch {
        imm19: branch_imm(EPI - at(0) as i64, 19),
        rt: x(0),
    };
    assert_eq!(
        Frag::new(&[cond_last]).rule(),
        Some(VerifyRule::FallsOffEnd)
    );

    let mut frag = Frag::new(&[b_epi(0)]);
    for entry in [0, EPILOGUE_OFFSET, BODY_OFFSET + 2, BODY_OFFSET + 4] {
        frag.entries = alloc::vec![entry];
        assert_eq!(
            frag.rule(),
            Some(VerifyRule::EntryOffset),
            "entry {entry:#x}"
        );
    }
    frag.entries.clear();
    assert_eq!(frag.rule(), Some(VerifyRule::NoEntry));
}

/// Words of a budget check: `sub x18, x18, #1; cbz x18, <stub>`.
const CHECK: usize = 2;

fn budget_sub() -> A64Insn {
    A64Insn::SubAddsubImmSub64AddsubImm {
        sh: 0,
        imm12: uimm(1, 12),
        rn: xs(BUDGET_COUNTER_REG),
        rd: xs(BUDGET_COUNTER_REG),
    }
}

fn budget_cbz(cbz_index: usize, stub_index: usize) -> A64Insn {
    A64Insn::CbzCbz64Compbranch {
        imm19: branch_imm(at(stub_index) as i64 - at(cbz_index) as i64, 19),
        rt: x(BUDGET_COUNTER_REG),
    }
}

fn budget_seq(cbz_index: usize, stub_index: usize) -> [A64Insn; CHECK] {
    [budget_sub(), budget_cbz(cbz_index, stub_index)]
}

/// `loop: nop; <budget check>; <fills>; b loop; stub: movz x9; b <epilogue>`.
/// The check is words 1..=2, the fills 3..3+fills, the back-edge at 3+fills.
fn budget_loop(fills: &[A64Insn]) -> Vec<A64Insn> {
    let branch = 1 + CHECK + fills.len();
    let mut body = alloc::vec![A64Insn::NopNopHiHints {}];
    body.extend_from_slice(&budget_seq(2, branch + 1));
    body.extend_from_slice(fills);
    body.extend_from_slice(&[b(branch, at(0) as i64), movz(9, 7), b_epi(branch + 2)]);
    body
}

fn fill(reg: u8, slot: u32) -> A64Insn {
    ldr(reg, sp(), slot)
}

#[test]
fn budget_rule_accepts_the_check_and_fill_loads() {
    assert_eq!(Frag::new(&budget_loop(&[])).rule(), None);
    let fills = [fill(12, 16), fill(13, 56), fill(15, 32)];
    assert_eq!(Frag::new(&budget_loop(&fills)).rule(), None);
    // The check's first word may be a join point (it is the original PC's label).
    assert_eq!(Frag::new(&budget_loop(&fills)).entry(1).rule(), None);
    // Stack-backed user x18's fill (A12) is a fill like x12..x17's.
    let fills = [fill(14, RUNTIME_FRAME_USER_X18_OFFSET), fill(12, 16)];
    assert_eq!(Frag::new(&budget_loop(&fills)).rule(), None);
}

#[test]
fn budget_rule_rejects_unguarded_or_bypassable_back_edges() {
    let missing = |body: &[A64Insn]| Frag::new(body).rule();

    // No check at all.
    let mut body = budget_loop(&[]);
    body[1..1 + CHECK].copy_from_slice(&[A64Insn::NopNopHiHints {}; CHECK]);
    assert_eq!(
        Frag::new(&body).verify().unwrap_err(),
        VerifyError {
            offset: at(3),
            rule: VerifyRule::MissingBudgetCheck
        }
    );

    // A self-loop is a back-edge too.
    assert_eq!(
        missing(&[A64Insn::NopNopHiHints {}, b(1, at(1) as i64), b_epi(2)]),
        Some(VerifyRule::MissingBudgetCheck)
    );

    // Anything but a fill between the cbz and the back-edge: the check no longer
    // guards the back-edge, so its `sub` is the first rejected word.
    for between in [
        A64Insn::NopNopHiHints {},
        fill(0, 16),
        // The user x29 / sp slots, caller x30, the entry address, the pt_regs pointer
        // and the dispatch table pointer are not stack-backed registers' slots.
        fill(12, 64),
        fill(12, 72),
        fill(12, 8),
        fill(12, 80),
        fill(12, 176),
        fill(12, RUNTIME_FRAME_IBTC_OFFSET),
        A64Insn::LdrImmGenLdr32LdstPos {
            rt: crate::shared::arm64::ergo::w(12),
            mem: mem_off(sp(), crate::shared::arm64::ergo::scaled_uimm(4, 12, 2)),
        },
    ] {
        assert_eq!(
            Frag::new(&budget_loop(&[between])).verify().unwrap_err(),
            VerifyError {
                offset: at(1),
                rule: VerifyRule::BudgetRegisterAccess
            },
            "{between:?}"
        );
    }

    // A join point past the check's first word bypasses the decrement: on the `cbz`,
    // a fill, or the back-edge itself.
    let fills = [fill(12, 16), fill(13, 24)];
    for inner in 2..=5 {
        assert_eq!(
            Frag::new(&budget_loop(&fills)).entry(inner).rule(),
            Some(VerifyRule::MissingBudgetCheck),
            "entry at word {inner}"
        );
    }
}

/// Every word of the check altered or dropped, x18 read or written anywhere else,
/// and the old four-word form (A6) are rejected.
#[test]
fn budget_rule_rejects_altered_checks() {
    let c = BUDGET_COUNTER_REG;
    let sub = |sh, imm, rn, rd| A64Insn::SubAddsubImmSub64AddsubImm {
        sh,
        imm12: uimm(imm, 12),
        rn: xs(rn),
        rd: xs(rd),
    };
    // The `sub` altered: another amount, `lsl #12`, another source or destination.
    for altered in [
        sub(0, 2, c, c),
        sub(0, 0, c, c),
        sub(1, 1, c, c),
        sub(0, 1, 17, c),
        sub(0, 1, c, 17),
        sub(0, 1, 17, 17),
        A64Insn::SubsAddsubImmSubs64sAddsubImm {
            sh: 0,
            imm12: uimm(1, 12),
            rn: xs(c),
            rd: x(c),
        },
        A64Insn::SubAddsubImmSub32AddsubImm {
            sh: 0,
            imm12: uimm(1, 12),
            rn: A64Reg::w_sp(c),
            rd: A64Reg::w_sp(c),
        },
        A64Insn::AddAddsubImmAdd64AddsubImm {
            sh: 0,
            imm12: uimm(1, 12),
            rn: xs(c),
            rd: xs(c),
        },
        A64Insn::NopNopHiHints {},
    ] {
        let mut body = budget_loop(&[]);
        body[1] = altered;
        assert!(Frag::new(&body).rule().is_some(), "{altered:?}");
    }

    // The `cbz` altered: a 32-bit test, `cbnz`, another register, backward, into
    // the middle of the stub, or dropped.
    let stub = at(4);
    let target = branch_imm(stub as i64 - at(2) as i64, 19);
    for altered in [
        A64Insn::CbzCbz32Compbranch {
            imm19: target,
            rt: crate::shared::arm64::ergo::w(c),
        },
        A64Insn::CbnzCbnz64Compbranch { imm19: target, rt: x(c) },
        A64Insn::CbzCbz64Compbranch { imm19: target, rt: x(17) },
        A64Insn::CbzCbz64Compbranch {
            imm19: branch_imm(at(0) as i64 - at(2) as i64, 19),
            rt: x(c),
        },
        A64Insn::CbzCbz64Compbranch {
            imm19: branch_imm(at(5) as i64 - at(2) as i64, 19),
            rt: x(c),
        },
        A64Insn::NopNopHiHints {},
    ] {
        let mut body = budget_loop(&[]);
        body[2] = altered;
        assert!(Frag::new(&body).rule().is_some(), "{altered:?}");
    }
    // Dropped words: the `sub` or the `cbz` alone guard nothing.
    for word in [1, 2] {
        let mut body = budget_loop(&[]);
        body[word] = A64Insn::NopNopHiHints {};
        assert!(Frag::new(&body).rule().is_some(), "word {word} dropped");
    }
    // The check doubled: the first decrement guards nothing.
    let mut body = alloc::vec![A64Insn::NopNopHiHints {}];
    body.extend_from_slice(&budget_seq(2, 6));
    body.extend_from_slice(&budget_seq(4, 6));
    body.extend_from_slice(&[b(5, at(0) as i64), movz(9, 7), b_epi(7)]);
    assert_eq!(Frag::new(&body).rule(), Some(VerifyRule::BudgetRegisterAccess));

    // The old four-word form (A6): `ldr s; sub s; str s; cbz s`, counter in slot 192.
    let old = [
        ldr(12, sp(), RUNTIME_FRAME_USER_X18_OFFSET),
        sub(0, 1, 12, 12),
        str(12, sp(), RUNTIME_FRAME_USER_X18_OFFSET),
        A64Insn::CbzCbz64Compbranch {
            imm19: branch_imm(at(6) as i64 - at(4) as i64, 19),
            rt: x(12),
        },
        b(5, at(0) as i64),
    ];
    let mut body = alloc::vec![A64Insn::NopNopHiHints {}];
    body.extend_from_slice(&old);
    body.extend_from_slice(&[movz(9, 7), b_epi(7)]);
    assert_eq!(Frag::new(&body).rule(), Some(VerifyRule::MissingBudgetCheck));

    // The counter read or written anywhere else, as any operand.
    for insn in [
        movz(c, 5),
        mov(xs(0), xs(c)),
        mov(xs(c), xs(0)),
        sub(0, 1, c, c),
        ldr(0, xs(c), 0),
        str(c, xs(0), 0),
        A64Insn::LdrImmGenLdr64LdstImmpre {
            rt: x(0),
            mem: crate::shared::arm64::A64Mem::PreIndex {
                base: xs(c),
                offset: simm(8, 9),
            },
        },
        A64Insn::CbzCbz64Compbranch {
            imm19: branch_imm(4, 19),
            rt: x(c),
        },
    ] {
        let body = [insn, b_epi(1)];
        assert_eq!(
            Frag::new(&body).rule(),
            Some(VerifyRule::BudgetRegisterAccess),
            "{insn:?}"
        );
    }
    // A well-formed check that guards neither a back-edge nor a template.
    let mut body = budget_loop(&[]);
    body[3] = b_epi(3);
    assert_eq!(Frag::new(&body).rule(), Some(VerifyRule::BudgetRegisterAccess));
}

fn cbnz_to(from: usize, rt: u8, to: usize) -> A64Insn {
    A64Insn::CbnzCbnz64Compbranch {
        imm19: branch_imm(at(to) as i64 - at(from) as i64, 19),
        rt: x(rt),
    }
}

fn cbz_to(from: usize, rt: u8, to: usize) -> A64Insn {
    A64Insn::CbzCbz64Compbranch {
        imm19: branch_imm(at(to) as i64 - at(from) as i64, 19),
        rt: x(rt),
    }
}

/// A22: the check is required exactly on the back-edges whose two ends are in one
/// strongly connected component of the body word graph. Every shape below is a cycle
/// through its back-edge, closed in a different way.
#[test]
fn back_edges_on_a_cycle_need_the_check() {
    let unguarded = |body: &[A64Insn]| Frag::new(body).verify().unwrap_err();
    // A conditional self-loop.
    assert_eq!(
        unguarded(&[cbnz_to(0, 0, 0), b_epi(1)]),
        VerifyError {
            offset: at(0),
            rule: VerifyRule::MissingBudgetCheck
        }
    );
    // A two-word loop closed by a conditional back-edge (the fall-through reaches it).
    assert_eq!(
        unguarded(&[NOP, cbnz_to(1, 0, 0), b_epi(2)]),
        VerifyError {
            offset: at(1),
            rule: VerifyRule::MissingBudgetCheck
        }
    );
    // Closed by an unconditional back-edge, the way into it a conditional fall-through.
    assert_eq!(
        unguarded(&[NOP, cbz_to(1, 0, 3), b(2, at(0) as i64), b_epi(3)]),
        VerifyError {
            offset: at(2),
            rule: VerifyRule::MissingBudgetCheck
        }
    );
    // The way from the target to the branch needs a forward branch and fall-throughs:
    // 0 -> 1 -> 3 (taken) -> 4 -> 0.
    assert_eq!(
        unguarded(&[
            NOP,
            cbnz_to(1, 1, 3),
            b_epi(2),
            NOP,
            cbnz_to(4, 0, 0),
            b_epi(5)
        ]),
        VerifyError {
            offset: at(4),
            rule: VerifyRule::MissingBudgetCheck
        }
    );
    // Two loops sharing a target: each back-edge is on a cycle.
    assert_eq!(
        unguarded(&[NOP, cbnz_to(1, 0, 0), cbnz_to(2, 1, 0), b_epi(3)]).offset,
        at(1)
    );

    // The guarded forms are accepted: the loop of `budget_loop`, and the same with the
    // way back closed through a forward branch.
    assert_eq!(Frag::new(&budget_loop(&[])).rule(), None);
    let guarded = [
        NOP,
        cbnz_to(1, 1, 3),
        b_epi(2),
        budget_sub(),
        budget_cbz(4, 6),
        b(5, at(0) as i64),
        movz(9, 7),
        b_epi(7),
    ];
    assert_eq!(Frag::new(&guarded).rule(), None);
}

/// A22: the cold region is part of the body word graph, so rule 6 does not depend on
/// rules 4 and 7 keeping cycles out of it. Today they do, and reject both shapes
/// below first: a stub that branches back to the loop head (without a check the loop
/// would run on through the counter's wrap-around), and a forward `b` into a cold word
/// that is no stub start, which jumps back.
#[test]
fn a_cycle_through_the_cold_region_needs_the_check() {
    let through_cold = [
        NOP,
        budget_sub(),
        budget_cbz(2, 4),
        b(3, at(0) as i64),
        cbnz_to(4, 0, 0),
        b_epi(5),
    ];
    // Rule 7 rejects it first (a branch inside an exit group); rule 6 would too.
    assert_eq!(Frag::new(&through_cold).rule(), Some(VerifyRule::ExitGroup));
    // The way back from a cold word that is no stub start, reached by a forward `b`:
    // 0 -> 1 -> 9 -> 0. Words 3-5 are a check on an off-cycle back-edge, only there to
    // give the fragment a stub (7) and so a cold region.
    let cold_tail = [
        cbnz_to(0, 0, 3),
        b(1, at(9) as i64),
        b_epi(2),
        budget_sub(),
        budget_cbz(4, 7),
        b(5, at(2) as i64),
        b_epi(6),
        movz(9, 7),
        b_epi(8),
        b(9, at(0) as i64),
    ];
    assert_eq!(
        Frag::new(&cold_tail).rule(),
        Some(VerifyRule::BranchTarget { target: at(9) as i64 })
    );
}

/// A22: a backward branch whose target cannot reach it again runs at most once per
/// pass through its target, so it needs no check. It is still accepted with one.
#[test]
fn back_edges_off_a_cycle_need_no_check() {
    // A jump back to a shared exit block: 0 -> 3 (taken), 3 -> 2, 2 -> epilogue.
    let shared_exit = [cbnz_to(0, 0, 3), NOP, b_epi(2), b(3, at(2) as i64)];
    assert_eq!(Frag::new(&shared_exit).rule(), None);
    // The same with a conditional back-edge.
    let conditional = [
        cbnz_to(0, 0, 3),
        NOP,
        b_epi(2),
        cbz_to(3, 1, 2),
        b_epi(4),
    ];
    assert_eq!(Frag::new(&conditional).rule(), None);
    // An unconditional `B` has no fall-through. Word 2 jumps back to word 0, but only
    // a jump over word 1 would reach it: with the jump it is a cycle, without it not.
    let jump_over = [cbnz_to(0, 0, 2), b_epi(1), b(2, at(0) as i64)];
    assert_eq!(Frag::new(&jump_over).rule(), Some(VerifyRule::MissingBudgetCheck));
    let cut = [NOP, b_epi(1), b(2, at(0) as i64)];
    assert_eq!(Frag::new(&cut).rule(), None);

    // A dispatch site is a sink (its `br` and its exit group leave the fragment), so
    // the return block after it, entered only from outside, jumping back to the word
    // before the site is on no cycle: `0: nop; site; <dead b>; stub`.
    let mut site = dispatch_site_from(1, &[movz(13, 0x4000)]);
    let back = site.len() - 2;
    let stub = back + 2;
    site.insert(back, b(1 + back, at(0) as i64));
    site[1] = budget_cbz(2, stub);
    let last = site.len() - 1;
    site[last] = b_epi(1 + last);
    let mut body = alloc::vec![NOP];
    body.extend(site);
    assert_eq!(Frag::new(&body).entry(1 + back).rule(), None);

    // A check on a back-edge that needs none is allowed (the translator may guard a
    // superset), and is a check like any other: a gap in it is still an x18 access.
    let guarded = [
        cbnz_to(0, 0, 3),
        NOP,
        b_epi(2),
        budget_sub(),
        budget_cbz(4, 6),
        b(5, at(2) as i64),
        movz(9, 7),
        b_epi(7),
    ];
    assert_eq!(Frag::new(&guarded).rule(), None);
    let mut broken = guarded;
    broken[4] = NOP;
    assert_eq!(Frag::new(&broken).rule(), Some(VerifyRule::BudgetRegisterAccess));
}

/// Slot 192 is stack-backed user x18's: an ordinary user-state slot (A12), accessed
/// as a whole 8 bytes by fills and spills; never half of a pair that reaches the
/// pointer slots or the dispatch table pointer.
#[test]
fn slot_192_is_a_user_state_slot() {
    let access = |insn| Frag::new(&[insn, b_epi(1)]).rule();
    for slot in [16, 56, 64, 72, RUNTIME_FRAME_USER_X18_OFFSET] {
        assert_eq!(access(ldr(12, sp(), slot)), None, "ldr slot {slot}");
        assert_eq!(access(str(0, sp(), slot)), None, "str slot {slot}");
    }
    let pair = |slot: u32| A64Insn::LdpGenLdp64LdstpairOff {
        rt2: x(13),
        rt: x(12),
        mem: mem_off(sp(), ldstpair64_offset(slot as i32)),
    };
    assert_eq!(access(pair(RUNTIME_FRAME_USER_X18_OFFSET - 8)), Some(VerifyRule::FrameAccessOutOfRange));
    assert_eq!(access(pair(RUNTIME_FRAME_USER_X18_OFFSET)), Some(VerifyRule::FrameAccessOutOfRange));
    // The slots around it stay kernel state.
    for slot in [80, 88, 176, 184, RUNTIME_FRAME_IBTC_OFFSET] {
        assert_eq!(access(ldr(12, sp(), slot)).is_some(), slot != 176, "ldr slot {slot}");
    }
    // A value loaded from slot 192 is a user value (rule 9): it may be copied out.
    assert_eq!(
        Frag::new(&[ldr(12, sp(), RUNTIME_FRAME_USER_X18_OFFSET), mov(xs(0), xs(12)), b_epi(2)])
            .rule(),
        None
    );
}

/// A8/A15 window access: `ubfx x5, x4, #48, #8; cbnz x5, <S>; ldaddal x0, x1, [x4];
/// b <epilogue>`, then the Mem stub S (exit payload, `b <epilogue>`). The atomic's
/// fault site is S.
/// Indices: 0 ubfx, 1 cbnz, 2 atomic, 3 b, 4 S (movz), 5 b.
fn window_body() -> Vec<A64Insn> {
    alloc::vec![
        ubfx48(4, 5),
        cbnz(1, 5, 4),
        ldaddal(0, 1, 4),
        b_epi(3),
        movz(9, 5),
        b_epi(5),
    ]
}

fn window_fragment(body: &[A64Insn]) -> Frag {
    Frag::new(body).site(2, 4)
}

fn ubfx48(rn: u8, rd: u8) -> A64Insn {
    A64Insn::UbfmUbfm64mBitfield {
        immr: uimm(48, 6),
        imms: uimm(55, 6),
        rn: x(rn),
        rd: x(rd),
    }
}

fn cbnz(from: usize, rt: u8, to: usize) -> A64Insn {
    A64Insn::CbnzCbnz64Compbranch {
        imm19: branch_imm(at(to) as i64 - at(from) as i64, 19),
        rt: x(rt),
    }
}

fn msr_pan(crm: u8) -> A64Insn {
    A64Insn::MsrImmMsrSiPstate { crm }
}

fn ldaddal(rs: u8, rt: u8, rn: u8) -> A64Insn {
    A64Insn::LdaddLdaddal64Memop {
        rs: x(rs),
        rn: xs(rn),
        rt: x(rt),
    }
}

#[test]
fn accepts_the_exact_window_access() {
    assert_eq!(window_fragment(&window_body()).rule(), None);
    // The `ubfx` may be a join point (it recomputes the checked value): branched to,
    // and an entry.
    let mut body = alloc::vec![b(0, at(1) as i64)];
    body.extend(window_body().into_iter().enumerate().map(|(i, insn)| match i {
        1 => cbnz(2, 5, 5),
        3 => b_epi(4),
        5 => b_epi(6),
        _ => insn,
    }));
    assert_eq!(Frag::new(&body).site(3, 5).entry(1).rule(), None);
}

/// Rule 8: a window access needs `ubfx sB, sA, #48, #8; cbnz sB, <exit group>` right
/// before it, based on sA; anything else is `WindowRangeCheck`.
#[test]
fn window_rule_rejects_a_missing_or_wrong_range_check() {
    let rule = |body: &[A64Insn]| window_fragment(body).rule();
    let with = |index: usize, insn: A64Insn| {
        let mut body = window_body();
        body[index] = insn;
        rule(&body)
    };
    let bad = Some(VerifyRule::WindowRangeCheck);
    // `ubfx` of another register than the access base, or into another register
    // than the `cbnz` tests; other lsb / width / 32-bit-clearing forms.
    assert_eq!(with(0, ubfx48(3, 5)), bad);
    assert_eq!(with(0, ubfx48(4, 6)), bad);
    for (immr, imms) in [(47, 55), (48, 54), (48, 63), (56, 63)] {
        let ubfx = A64Insn::UbfmUbfm64mBitfield {
            immr: uimm(immr, 6),
            imms: uimm(imms, 6),
            rn: x(4),
            rd: x(5),
        };
        assert_eq!(with(0, ubfx), bad, "{immr} {imms}");
    }
    // The `ubfx` or the `cbnz` replaced by something else; `cbz` for `cbnz`; the
    // 32-bit `cbnz`.
    assert_eq!(with(0, movz(5, 0)), bad);
    assert_eq!(with(1, movz(2, 0)), bad);
    let cbz = A64Insn::CbzCbz64Compbranch {
        imm19: branch_imm(at(4) as i64 - at(1) as i64, 19),
        rt: x(5),
    };
    assert_eq!(with(1, cbz), bad);
    let cbnz32 = A64Insn::CbnzCbnz32Compbranch {
        imm19: branch_imm(at(4) as i64 - at(1) as i64, 19),
        rt: crate::shared::arm64::A64Reg::w(5),
    };
    assert_eq!(with(1, cbnz32), bad);
    // The `cbnz` tests another register, or targets: a backward word, the access, a
    // body word that is no exit-group start, an offset past the fragment.
    assert_eq!(with(1, cbnz(1, 6, 4)), bad);
    assert_eq!(with(1, cbnz(1, 5, 0)), bad);
    assert_eq!(with(1, cbnz(1, 5, 2)), bad);
    assert_eq!(with(1, cbnz(1, 5, 3)), bad);
    assert_eq!(with(1, cbnz(1, 5, 50)), bad);
    // The access on a base other than the range-checked register.
    assert_eq!(with(2, ldaddal(0, 1, 3)), bad);
    assert_eq!(with(2, ldaddal(0, 1, 5)), bad);
    // No range check at all: first words of the body, or an access whose
    // predecessors are ordinary words, with or without a fault site.
    assert_eq!(Frag::new(&[ldaddal(0, 1, 4), b_epi(1)]).rule(), bad);
    assert_eq!(
        Frag::new(&[movz(5, 0), ldaddal(0, 1, 4), b_epi(2)]).rule(),
        bad
    );
    let body = [
        movz(5, 0),
        movz(6, 0),
        ldaddal(0, 1, 4),
        b_epi(3),
        movz(9, 5),
        b_epi(5),
    ];
    assert_eq!(Frag::new(&body).rule(), bad);
    assert_eq!(Frag::new(&body).site(2, 4).rule(), bad);
}

/// Rule 8: no join point on the `cbnz` or the access, whichever way control arrives.
#[test]
fn window_rule_rejects_a_join_point_on_the_cbnz_or_the_access() {
    let bad = Some(VerifyRule::WindowRangeCheck);
    for index in [1, 2] {
        assert_eq!(
            window_fragment(&window_body()).entry(index).rule(),
            bad,
            "entry at {index}"
        );
    }
    // 0 b/cbz, 1 ubfx, 2 cbnz, 3 atomic, 4 b, 5 S, 6 b.
    let prefixed = |first: A64Insn| {
        let mut body = alloc::vec![first];
        body.extend(window_body().into_iter().enumerate().map(|(i, insn)| match i {
            1 => cbnz(2, 5, 5),
            3 => b_epi(4),
            5 => b_epi(6),
            _ => insn,
        }));
        Frag::new(&body).site(3, 5).rule()
    };
    assert_eq!(prefixed(b(0, at(1) as i64)), None);
    assert_eq!(prefixed(b(0, at(2) as i64)), bad);
    assert_eq!(prefixed(b(0, at(3) as i64)), bad);
    let cbz_to = |to: usize| A64Insn::CbzCbz64Compbranch {
        imm19: branch_imm(at(to) as i64 - at(0) as i64, 19),
        rt: x(0),
    };
    assert_eq!(prefixed(cbz_to(2)), bad);
    assert_eq!(prefixed(cbz_to(3)), bad);
}

/// A window access has a fault-site entry like a user access, naming an exit group.
#[test]
fn window_access_needs_a_fault_site_naming_an_exit_group() {
    assert_eq!(
        Frag::new(&window_body()).rule(),
        Some(VerifyRule::MissingFaultSite)
    );
    // The fault site on a body word that is not an exit-group start.
    assert_eq!(
        Frag::new(&window_body()).site(2, 3).rule(),
        Some(VerifyRule::ExitGroup)
    );
    // A fault site on the `cbnz` is not on an access.
    assert_eq!(
        Frag::new(&window_body()).site(1, 4).site(2, 4).rule(),
        Some(VerifyRule::FaultSiteNotUserAccess)
    );
}

/// A15: a fragment never writes PSTATE.PAN. `msr` is rejected wherever it sits: the
/// body, between the range check and the access, after the access, an exit group.
#[test]
fn any_msr_is_rejected() {
    for crm in [0, 1, 2, 15] {
        assert_eq!(
            Frag::new(&[msr_pan(crm), b_epi(1)]).rule(),
            Some(VerifyRule::Msr),
            "msr #{crm}"
        );
        // After the access.
        let body = [
            ubfx48(4, 5),
            cbnz(1, 5, 5),
            ldaddal(0, 1, 4),
            msr_pan(crm),
            b_epi(4),
            movz(9, 5),
            b_epi(6),
        ];
        assert_eq!(
            Frag::new(&body).site(2, 5).rule(),
            Some(VerifyRule::Msr),
            "after, msr #{crm}"
        );
        // Between the `cbnz` and the access: the access loses its range check.
        let body = [
            ubfx48(4, 5),
            cbnz(1, 5, 5),
            msr_pan(crm),
            ldaddal(0, 1, 4),
            b_epi(4),
            movz(9, 5),
            b_epi(6),
        ];
        assert_eq!(
            Frag::new(&body).site(3, 5).rule(),
            Some(VerifyRule::WindowRangeCheck),
            "between, msr #{crm}"
        );
        // First word of the exit group (the shape of the removed PAN stub).
        let body = [
            ubfx48(4, 5),
            cbnz(1, 5, 4),
            ldaddal(0, 1, 4),
            b_epi(3),
            msr_pan(crm),
            movz(9, 5),
            b_epi(6),
        ];
        assert_eq!(
            Frag::new(&body).site(2, 4).rule(),
            Some(VerifyRule::ExitGroup),
            "stub, msr #{crm}"
        );
    }
}

fn ldr_q(rt: u8, rn: u8, raw_offset: u32) -> A64Insn {
    A64Insn::LdrImmFpsimdLdrQLdstPos {
        rt,
        mem: mem_off(
            xs(rn),
            crate::shared::arm64::ergo::scaled_uimm(raw_offset, 12, 4),
        ),
    }
}

/// A9a: the window access lowering around a base-only SIMD&FP load/store is accepted, and
/// `uses_fpsimd` says whether any SIMD&FP form appears.
#[test]
fn simd_windows_and_uses_fpsimd() {
    let ok = |frag: Frag| frag.verify().unwrap().uses_fpsimd;
    // The LSE window alone: no SIMD&FP.
    assert!(!ok(window_fragment(&window_body())));
    // The same range check around `ldr q0, [x4]`, `ld1 {v0.16b-v3.16b}, [x4]`,
    // `stp q1, q2, [x4]`.
    for access in [
        ldr_q(0, 4, 0),
        A64Insn::Ld1AdvsimdMultLd1AsisdlseR44v {
            q: 1,
            size: 0,
            rn: xs(4),
            rt: 0,
        },
        A64Insn::StpFpsimdStpQLdstpairOff {
            rt2: 2,
            rt: 1,
            mem: mem_off(xs(4), scaled_simm(0, 7, 4)),
        },
    ] {
        let mut body = window_body();
        body[2] = access;
        assert!(ok(window_fragment(&body)), "{access:?}");
    }
    // A register-only SIMD&FP form anywhere.
    let body = [
        A64Insn::CmeqAdvsimdZeroCmeqAsimdmiscZ {
            q: 1,
            size: 0,
            rn: 1,
            rd: 0,
        },
        b_epi(1),
    ];
    assert!(ok(Frag::new(&body)));
    assert!(!ok(Frag::new(&[movz(0, 1), b_epi(1)])));
}

/// A decodable word of `spec`'s form: its fixed bits with the free bits chosen so
/// that no decode-time value rule (`is_decode_undefined`) rejects it.
fn valid_word(spec: &crate::shared::arm64::GeneratedInsnSpec) -> A64Insn {
    let base = crate::shared::arm64::form_base_word(spec);
    let free = !spec.mask;
    // Walk subsets of the low free bits until one decodes as this very form.
    let mut candidate = 0_u32;
    loop {
        if let Some(insn) = A64Insn::decode(base | (candidate & free)) {
            if insn.key() == spec.key && !insn.is_decode_undefined() {
                return insn;
            }
        }
        candidate = candidate.wrapping_add(1);
        assert!(candidate < 1 << 20, "{}: no valid word", spec.key);
    }
}

/// A18: every register-only SIMD&FP form of the subset (A9a data movement and
/// integer SIMD, A18 scalar floating point) is accepted anywhere and makes the
/// fragment `uses_fpsimd`: in the body and first in an exit group.
#[test]
fn every_register_only_simd_form_is_allowed_and_uses_fpsimd() {
    use crate::shared::arm64::GENERATED_A64_SUBSET;
    let mut checked = 0;
    for spec in GENERATED_A64_SUBSET {
        let has_vec = spec.operands.iter().any(|role| {
            matches!(
                role,
                crate::shared::arm64::A64OperandRole::VecRead { .. }
                    | crate::shared::arm64::A64OperandRole::VecWrite { .. }
            )
        });
        if !has_vec || spec.operands.contains(&crate::shared::arm64::A64OperandRole::Memory) {
            continue;
        }
        let insn = valid_word(spec);
        // In the body ...
        let verified = Frag::new(&[insn, b_epi(1)]).verify();
        assert_eq!(verified.map(|ok| ok.uses_fpsimd), Ok(true), "{}", spec.key);
        // ... and in an exit group (after a user access's Mem stub start).
        let body = [movz(1, 1), ldtr(0, 1), b_epi(2), insn, movz(9, 5), b_epi(5)];
        let frag = Frag::new(&body).site(1, 3);
        assert_eq!(frag.verify().map(|ok| ok.uses_fpsimd), Ok(true), "{}", spec.key);
        checked += 1;
    }
    // 75 A9a forms + 112 A18 forms (scalar floating point).
    assert_eq!(checked, 75 + 112);
}

/// A18: the register-offset SIMD&FP loads/stores are never valid in a fragment,
/// window position included -- translation computes the address into sA and runs the
/// base-only encoding -- and that lowering (`add sA, <base>, <index>, <extend>`,
/// range check, access) is accepted. The verifier ties neither the add nor its
/// operands to the access: safety needs only the range check of the register the
/// access uses.
#[test]
fn register_offset_simd_forms_are_user_only_and_their_lowering_is_a_window() {
    use crate::shared::arm64::GENERATED_A64_SUBSET;
    let mut forms = 0;
    for spec in GENERATED_A64_SUBSET {
        if !(spec.key.starts_with("LDR_reg_fpsimd.") || spec.key.starts_with("STR_reg_fpsimd.")) {
            continue;
        }
        let insn = valid_word(spec);
        forms += 1;
        // Anywhere in the body, and in the window's access position.
        assert_eq!(
            Frag::new(&[insn, b_epi(1)]).rule(),
            Some(VerifyRule::UserOnlyForm),
            "{}",
            spec.key
        );
        let mut body = window_body();
        body[2] = insn;
        assert_eq!(window_fragment(&body).rule(), Some(VerifyRule::FaultSiteNotUserAccess));
        assert_eq!(Frag::new(&body).rule(), Some(VerifyRule::UserOnlyForm), "{}", spec.key);
    }
    assert_eq!(forms, 12);

    // add x4, x1, x2, lsl #3; ubfx x5, x4, #48, #8; cbnz x5, <S>; ldr d0, [x4]; ...
    let add = A64Insn::AddAddsubExtAdd64AddsubExt {
        rm: x(2),
        option: 0b011,
        imm3: uimm(3, 3),
        rn: xs(1),
        rd: xs(4),
    };
    let ldr_d = A64Insn::LdrImmFpsimdLdrDLdstPos {
        rt: 0,
        mem: mem_off(xs(4), crate::shared::arm64::ergo::scaled_uimm(0, 12, 3)),
    };
    let body = [add, ubfx48(4, 5), cbnz(2, 5, 5), ldr_d, b_epi(4), movz(9, 5), b_epi(6)];
    let frag = Frag::new(&body).site(3, 5);
    assert_eq!(frag.verify().map(|ok| ok.uses_fpsimd), Ok(true));
    // The same without the add is just as safe (sA is range-checked whatever it
    // holds); without the range check it is rejected.
    let body = [ubfx48(4, 5), cbnz(1, 5, 4), ldr_d, b_epi(3), movz(9, 5), b_epi(5)];
    assert_eq!(Frag::new(&body).site(2, 4).rule(), None);
    let body = [add, ldr_d, b_epi(2), movz(9, 5), b_epi(4)];
    assert_eq!(Frag::new(&body).site(1, 3).rule(), Some(VerifyRule::WindowRangeCheck));
    // The add between the range check and the access: the window is widened.
    let body = [ubfx48(4, 5), cbnz(1, 5, 5), add, ldr_d, b_epi(4), movz(9, 5), b_epi(6)];
    assert_eq!(
        Frag::new(&body).site(3, 5).rule(),
        Some(VerifyRule::WindowRangeCheck)
    );
}

/// A9a: a SIMD&FP load/store is valid only as a window access in its base-only
/// encoding on sA, right after its range check.
#[test]
fn simd_memory_forms_are_window_only() {
    let with = |insn: A64Insn| {
        let mut body = window_body();
        body[2] = insn;
        window_fragment(&body).rule()
    };
    // Another base or SP: a window access, but not on the range-checked register.
    assert_eq!(with(ldr_q(0, 3, 0)), Some(VerifyRule::WindowRangeCheck));
    assert_eq!(with(ldr_q(0, 31, 0)), Some(VerifyRule::WindowRangeCheck));
    // An offset, writeback, unscaled: not a window access at all, so user-only
    // wherever they appear (with a fault site on one, not even a fault site).
    let post = A64Insn::LdrImmFpsimdLdrQLdstImmpost {
        rt: 0,
        mem: crate::shared::arm64::ergo::mem_post(xs(4), simm(16, 9)),
    };
    let ld1_post = A64Insn::Ld1AdvsimdMultLd1AsisdlsepI1I1 {
        q: 1,
        size: 0,
        rn: xs(4),
        rt: 0,
    };
    let ldur = A64Insn::LdurFpsimdLdurQLdstUnscaled {
        rt: 0,
        mem: mem_off(xs(4), simm(0, 9)),
    };
    for insn in [ldr_q(0, 4, 1), post, ld1_post, ldur] {
        assert_eq!(
            with(insn),
            Some(VerifyRule::FaultSiteNotUserAccess),
            "{insn:?}"
        );
        let mut body = window_body();
        body[2] = insn;
        assert_eq!(
            Frag::new(&body).rule(),
            Some(VerifyRule::UserOnlyForm),
            "{insn:?}"
        );
    }
    // Without its range check, even with a fault site.
    let body = [ldr_q(0, 4, 0), b_epi(1), movz(9, 5), b_epi(3)];
    assert_eq!(
        Frag::new(&body).rule(),
        Some(VerifyRule::WindowRangeCheck)
    );
    assert_eq!(
        Frag::new(&body).site(0, 2).rule(),
        Some(VerifyRule::WindowRangeCheck)
    );
    // A SIMD&FP register form writing x29.
    let fmov = A64Insn::FmovFloatGenFmov64dFloat2int { rn: 0, rd: x(29) };
    assert_eq!(
        Frag::new(&[fmov, b_epi(1)]).rule(),
        Some(VerifyRule::FramePointerWrite)
    );
}

/// A9a and rule 9: a SIMD&FP register field is not a general register. Writing
/// V12 does not clear x12's kernel mark and reading V12 is not reading x12; the
/// general operands of SIMD&FP forms (FMOV general, DUP/INS general, UMOV) are
/// read and written like any other, so a kernel value never reaches a V register.
#[test]
fn simd_registers_are_not_general_registers_for_rule_9() {
    let rule = |body: &[A64Insn]| Frag::new(body).rule();
    let read = Some(VerifyRule::KernelValueRead);
    let orr = |rd: u8, rm: u8| A64Insn::OrrLogShiftOrr64LogShift {
        shift: 0,
        rm: x(rm),
        imm6: uimm(0, 6),
        rn: x(31),
        rd: x(rd),
    };
    let load12 = ldr(12, sp(), RUNTIME_FRAME_PT_REGS_PTR_OFFSET);
    let load13 = ldr(13, sp(), RUNTIME_FRAME_PT_REGS_PTR_OFFSET);
    let fmov_d_x = |d: u8, n: u8| A64Insn::FmovFloatGenFmovD64Float2int { rn: x(n), rd: d };
    let umov_x = |d: u8, n: u8| A64Insn::UmovAdvsimdUmovAsimdinsXX {
        imm5: uimm(0b01000, 5),
        rn: n,
        rd: x(d),
    };
    // `fmov d12, x0` does not overwrite x12: the pt_regs pointer still leaks.
    assert_eq!(rule(&[load12, fmov_d_x(12, 0), orr(0, 12), b_epi(3)]), read);
    // A clean general register into a V register, and V registers read freely
    // (x12 is kernel-valued at entry; V12 is not).
    assert_eq!(rule(&[fmov_d_x(0, 0), b_epi(1)]), None);
    let cmeq = A64Insn::CmeqAdvsimdZeroCmeqAsimdmiscZ {
        q: 1,
        size: 0,
        rn: 12,
        rd: 0,
    };
    assert_eq!(rule(&[cmeq, umov_x(0, 12), b_epi(2)]), None);
    // General operands of SIMD&FP forms are general registers: a kernel value
    // never goes into a V register ...
    let dup = |n: u8| A64Insn::DupAdvsimdGenDupAsimdinsDrR {
        q: 1,
        imm5: uimm(0b01000, 5),
        rn: x(n),
        rd: 0,
    };
    let ins = |n: u8| A64Insn::InsAdvsimdGenInsAsimdinsIrR {
        imm5: uimm(0b11000, 5),
        rn: x(n),
        rd: 0,
    };
    assert_eq!(rule(&[dup(12), b_epi(1)]), read);
    assert_eq!(rule(&[load13, ins(13), b_epi(2)]), read);
    assert_eq!(rule(&[fmov_d_x(0, 29), b_epi(1)]), read);
    assert_eq!(rule(&[load13, fmov_d_x(3, 13), b_epi(2)]), read);
    // ... and a V-to-general move overwrites a kernel mark.
    assert_eq!(rule(&[load13, umov_x(13, 0), orr(0, 13), b_epi(3)]), None);
    // A window around a SIMD&FP access based on the pt_regs pointer: its range
    // check already reads a kernel value.
    let body = [
        load13,
        ubfx48(13, 5),
        cbnz(2, 5, 5),
        ldr_q(0, 13, 0),
        b_epi(4),
        movz(9, 5),
        b_epi(6),
    ];
    assert_eq!(Frag::new(&body).site(3, 5).rule(), read);
}

/// Cross-check of the hand classification against the generated metadata on
/// random words: an `Alu` word has no memory, branch or control-flow role and is
/// not SVC; every memory form is a user or runtime access; every control-flow
/// form is a branch, call or indirect branch.
#[test]
fn classification_agrees_with_generated_roles() {
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    let mut decoded = 0;
    for _ in 0..400_000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let word = (state >> 16) as u32;
        let Some(insn) = A64Insn::decode(word) else {
            continue;
        };
        decoded += 1;
        let roles = insn.operand_roles();
        let memory = roles.contains(&A64OperandRole::Memory);
        let control = roles.iter().any(|role| {
            matches!(
                role,
                A64OperandRole::ControlFlow | A64OperandRole::BranchTarget { .. }
            )
        });
        match rules::classify(insn) {
            rules::Form::Alu
            | rules::Form::Nop
            | rules::Form::Barrier
            | rules::Form::MrsUserReg => {
                assert!(!memory && !control, "{}", insn.key());
                assert!(!insn.key().starts_with("SVC"), "{}", insn.key());
                // A9a: a form naming a V register is `Simd`, never `Alu`.
                assert!(
                    !roles.iter().any(|role| matches!(
                        role,
                        A64OperandRole::VecRead { .. } | A64OperandRole::VecWrite { .. }
                    )),
                    "{}",
                    insn.key()
                );
            }
            rules::Form::UserAccess { .. } | rules::Form::RuntimeAccess { .. } => {
                assert!(memory && !control, "{}", insn.key())
            }
            rules::Form::Branch { .. } | rules::Form::Call | rules::Form::IndirectBranch => {
                assert!(control && !memory, "{}", insn.key())
            }
            rules::Form::Exception | rules::Form::PcRelative => {
                assert!(!memory && !control, "{}", insn.key())
            }
            // A8/A9a: the window accesses access memory; MSR (PSTATE.PAN) has no role.
            rules::Form::WindowAccess { .. } => assert!(memory && !control, "{}", insn.key()),
            // A9a, A18: SIMD&FP register-only forms name a V register (MRS of
            // FPCR/FPSR reads the floating-point control registers instead), never
            // memory or control flow. The A18 compares and conditional selects read
            // or write NZCV.
            rules::Form::Simd => {
                assert!(!memory && !control, "{}", insn.key());
                assert!(
                    insn.key().starts_with("MRS.")
                        || roles.iter().any(|role| matches!(
                            role,
                            A64OperandRole::VecRead { .. } | A64OperandRole::VecWrite { .. }
                        )),
                    "{}",
                    insn.key()
                );
            }
            rules::Form::Msr => {
                assert!(!memory && !control && roles.is_empty(), "{}", insn.key())
            }
            // Every user-only form is a load/store, except PRFM and BTI (hints, no
            // access).
            rules::Form::UserOnly => {
                assert!(!control, "{}", insn.key());
                let hint = insn.key().starts_with("PRFM") || insn.key().starts_with("BTI");
                assert_eq!(memory, !hint, "{}", insn.key());
            }
        }
    }
    assert!(decoded > 1000, "only {decoded} random words decoded");
}

/// Independence rule: the verifier imports only `shared::{abi, arm64, platform}`.
#[test]
fn verifier_does_not_import_the_translator() {
    let sources = [
        ("mod.rs", include_str!("mod.rs")),
        ("rules.rs", include_str!("rules.rs")),
        ("taint.rs", include_str!("taint.rs")),
        ("tests.rs", include_str!("tests.rs")),
    ];
    let shared_path = concat!("crate", "::", "shared", "::");
    let allowed = ["abi", "arm64", "platform"];
    for (name, source) in sources {
        for (index, _) in source.match_indices(shared_path) {
            let rest = &source[index + shared_path.len()..];
            assert!(
                allowed.iter().any(|module| rest.starts_with(module)),
                "{name}: forbidden import `{}`",
                rest.lines().next().unwrap_or("")
            );
        }
        for forbidden in [
            concat!("trans", "::"),
            concat!("emit", "::"),
            concat!("super", "::", "super"),
        ] {
            assert!(!source.contains(forbidden), "{name} mentions `{forbidden}`");
        }
    }
}

// ---- Dispatch templates (A11, A11c) ----

/// `miss` (a miss branch of the template, `cbz x12` / `cbnz x14`) with its offset set
/// to reach body word `to` from body word `from`.
fn miss_branch_to(miss: A64Insn, from: usize, to: usize) -> A64Insn {
    let imm19 = branch_imm(at(to) as i64 - at(from) as i64, 19);
    match miss {
        A64Insn::CbzCbz64Compbranch { rt, .. } => A64Insn::CbzCbz64Compbranch { imm19, rt },
        A64Insn::CbnzCbnz64Compbranch { rt, .. } => A64Insn::CbnzCbnz64Compbranch { imm19, rt },
        other => panic!("{other:?} is not a miss branch"),
    }
}

/// A dispatch site whose first word is body word `base`: `<budget check>; <gap>;
/// <template>; <exit group>; <budget stub>`. The check's `cbz` is aimed at the stub;
/// the main probe's miss branches target the victim probe's first word, the victim
/// probe's the exit group that follows the template's final `br`.
fn dispatch_site_from(base: usize, gap: &[A64Insn]) -> Vec<A64Insn> {
    let template = base + CHECK + gap.len();
    let group = template + DISPATCH_TEMPLATE_LEN;
    let stub = group + 2;
    let mut body = budget_seq(base + CHECK - 1, stub).to_vec();
    body.extend_from_slice(gap);
    for (position, insn) in KJIT_DISPATCH_TEMPLATE.iter().enumerate() {
        let from = template + position;
        body.push(match DISPATCH_TEMPLATE_MISS_BRANCHES
            .iter()
            .position(|&branch| branch == position)
        {
            Some(miss) => {
                miss_branch_to(*insn, from, template + DISPATCH_TEMPLATE_MISS_TARGETS[miss])
            }
            None => *insn,
        });
    }
    body.extend_from_slice(&[movz(9, 1), b_epi(group + 1), movz(9, 7), b_epi(stub + 1)]);
    body
}

fn dispatch_site(gap: &[A64Insn]) -> Vec<A64Insn> {
    dispatch_site_from(0, gap)
}

fn site_with(position: usize, insn: A64Insn) -> Frag {
    let mut body = dispatch_site(&[movz(13, 0x4000)]);
    body[CHECK + 1 + position] = insn;
    Frag::new(&body)
}

#[test]
fn accepts_the_exact_dispatch_template_behind_its_budget_check() {
    let ok = Frag::new(&dispatch_site(&[movz(13, 0x4000)])).verify().unwrap();
    assert!(!ok.uses_fpsimd);
    // No gap at all (a target already in x13), or a fill and a link write in it.
    assert_eq!(Frag::new(&dispatch_site(&[])).rule(), None);
    assert_eq!(
        Frag::new(&dispatch_site(&[fill(13, 56), movz(30, 0x1004)])).rule(),
        None
    );
    // The check's first word may be a join point (the site's original PC label);
    // so may the exit group (the miss target) and the budget stub.
    assert_eq!(Frag::new(&dispatch_site(&[movz(13, 1)])).entry(0).rule(), None);
}

#[test]
fn dispatch_template_words_are_byte_exact() {
    let site = |position, insn| site_with(position, insn).rule();
    let nop = A64Insn::NopNopHiHints {};
    // Every word dropped (replaced by a nop) is rejected as a broken template.
    for position in 0..DISPATCH_TEMPLATE_LEN {
        assert_eq!(site(position, nop), Some(VerifyRule::DispatchTemplate), "word {position}");
    }
    // Every word altered by a flipped bit that still decodes: registers, immediates
    // and shift amounts are the contract. Only the offsets of the miss branches are free.
    for position in 0..DISPATCH_TEMPLATE_LEN {
        let word = KJIT_DISPATCH_TEMPLATE[position].encode().unwrap();
        let is_miss = DISPATCH_TEMPLATE_MISS_BRANCHES.contains(&position);
        for bit in 0..32 {
            if is_miss && (5..24).contains(&bit) {
                continue;
            }
            let Some(altered) =
                A64Insn::decode(word ^ (1 << bit)).filter(|insn| !insn.is_decode_undefined())
            else {
                continue;
            };
            assert!(site(position, altered).is_some(), "word {position} bit {bit}");
        }
    }
    // The ways the contract lists, by name, in both probes (words 0..9 and 9..20).
    for base in [0, DISPATCH_TEMPLATE_VICTIM_PROBE] {
        assert_eq!(site(base, ldr(12, sp(), 192)), Some(VerifyRule::DispatchTemplate));
        assert_eq!(
            site(base, ldr(13, sp(), RUNTIME_FRAME_IBTC_OFFSET)),
            Some(VerifyRule::DispatchTemplate)
        );
        assert_eq!(site(base + 4, ldr(14, xs(12), 8)), Some(VerifyRule::DispatchTemplate));
        assert_eq!(site(base + 7, ldr(12, xs(12), 16)), Some(VerifyRule::DispatchTemplate));
        // The key compare dropped: the `sub`, the `cbnz`.
        assert_eq!(site(base + 5, nop), Some(VerifyRule::DispatchTemplate));
        assert_eq!(site(base + 6, nop), Some(VerifyRule::DispatchTemplate));
    }
    // A wider main index (13 bits) reaches past the 4096-slot main part.
    assert_eq!(
        site(
            1,
            A64Insn::UbfmUbfm64mBitfield {
                immr: uimm(2, 6),
                imms: uimm(14, 6),
                rn: x(13),
                rd: x(14),
            }
        ),
        Some(VerifyRule::DispatchTemplate),
        "a 13-bit index reaches past the 4096-slot main part"
    );
    // The victim index: a wider ubfx, a changed fold shift, a changed part offset.
    let victim_index = |lsb: u32, width: u32| A64Insn::UbfmUbfm64mBitfield {
        immr: uimm(lsb, 6),
        imms: uimm(lsb + width - 1, 6),
        rn: x(14),
        rd: x(14),
    };
    assert_eq!(site(11, victim_index(2, 8)), None, "the template's own word");
    assert_eq!(site(11, victim_index(2, 9)), Some(VerifyRule::DispatchTemplate));
    assert_eq!(site(11, victim_index(3, 8)), Some(VerifyRule::DispatchTemplate));
    for shift in [0, 11, 13] {
        assert_eq!(
            site(
                10,
                A64Insn::EorLogShiftEor64LogShift {
                    shift: 1,
                    rm: x(13),
                    imm6: uimm(shift, 6),
                    rn: x(13),
                    rd: x(14),
                }
            ),
            Some(VerifyRule::DispatchTemplate),
            "fold shift {shift}"
        );
    }
    for imm in [0, 4, 7, 9, 16] {
        assert_eq!(
            site(
                12,
                A64Insn::AddAddsubImmAdd64AddsubImm {
                    sh: 1,
                    imm12: uimm(imm, 12),
                    rn: A64Reg::x_sp(12),
                    rd: A64Reg::x_sp(12),
                }
            ),
            Some(VerifyRule::DispatchTemplate),
            "victim part offset {imm} << 12"
        );
    }
    // Without a probe's `br x12` the words are plain, and the check guards nothing:
    // rejected (which of the rules fires first is not the point).
    for position in [8, 19] {
        assert!(site(position, A64Insn::BrBr64BranchReg { rn: x(13) }).is_some());
        assert!(site(position, A64Insn::BrBr64BranchReg { rn: x(14) }).is_some());
    }
}

#[test]
fn every_other_indirect_branch_stays_rejected() {
    for insn in [
        A64Insn::BrBr64BranchReg { rn: x(0) },
        A64Insn::BrBr64BranchReg { rn: x(14) },
        A64Insn::BlrBlr64BranchReg { rn: x(12) },
        A64Insn::RetRet64rBranchReg { rn: x(30) },
        A64Insn::RetRet64rBranchReg { rn: x(12) },
    ] {
        assert_eq!(
            Frag::new(&[insn, b_epi(1)]).rule(),
            Some(VerifyRule::IndirectBranch),
            "{insn:?}"
        );
    }
    // `br x12` outside a complete template.
    assert_eq!(
        Frag::new(&[A64Insn::BrBr64BranchReg { rn: x(12) }, b_epi(1)]).rule(),
        Some(VerifyRule::DispatchTemplate)
    );
}

#[test]
fn dispatch_templates_need_a_budget_check_and_have_no_join_points() {
    let site = dispatch_site(&[movz(13, 0x4000)]);
    // No budget check: its words replaced.
    let mut body = site.clone();
    body[..CHECK].fill(A64Insn::NopNopHiHints {});
    assert_eq!(Frag::new(&body).rule(), Some(VerifyRule::MissingBudgetCheck));
    let mut body = site.clone();
    body[..CHECK].fill(movz(14, 0));
    assert_eq!(Frag::new(&body).rule(), Some(VerifyRule::MissingBudgetCheck));
    // Something a gap may not hold between the check and the template (a `nop` it
    // may: a BL's link slot, A16).
    for insn in [
        str(0, sp(), 16),
        ldr(0, sp(), 16),
        b(CHECK, at(CHECK + 1) as i64),
    ] {
        let mut body = site.clone();
        body[CHECK] = insn;
        assert_eq!(Frag::new(&body).rule(), Some(VerifyRule::MissingBudgetCheck), "{insn:?}");
    }
    // A join point between the check's `sub` and the template, or inside it
    // (the victim probe's first word included: only the main probe's own miss
    // branches may reach it).
    for index in 1..=CHECK {
        assert_eq!(
            Frag::new(&site).entry(index).rule(),
            Some(VerifyRule::MissingBudgetCheck),
            "entry at {index}"
        );
    }
    for index in CHECK + 1..CHECK + 1 + DISPATCH_TEMPLATE_LEN {
        assert_eq!(
            Frag::new(&site).entry(index).rule(),
            Some(VerifyRule::DispatchTemplate),
            "entry at {index}"
        );
    }
    // A branch into the template, at each of its words (the victim probe's first
    // word, template word 9, included).
    for inner in 0..DISPATCH_TEMPLATE_LEN {
        let mut body = alloc::vec![b(0, at(1 + CHECK + 1 + inner) as i64)];
        body.extend(dispatch_site_from(1, &[movz(13, 0x4000)]));
        assert_eq!(Frag::new(&body).rule(), Some(VerifyRule::DispatchTemplate), "word {inner}");
    }
}

#[test]
fn dispatch_miss_branches_name_the_victim_probe_or_one_forward_exit_group() {
    let site = dispatch_site(&[movz(13, 0x4000)]);
    let template = CHECK + 1;
    let group = template + DISPATCH_TEMPLATE_LEN;
    let retarget = |miss: usize, to: usize| {
        let mut body = site.clone();
        let from = template + DISPATCH_TEMPLATE_MISS_BRANCHES[miss];
        body[from] = miss_branch_to(body[from], from, to);
        Frag::new(&body).rule()
    };
    // The victim probe's pair (misses 2 and 3): the same forward exit group.
    assert_eq!(retarget(2, group), None);
    // Different targets, backward, into the template, into the middle of the group.
    assert_eq!(retarget(2, group + 1), Some(VerifyRule::DispatchTemplate));
    assert_eq!(retarget(3, group + 1), Some(VerifyRule::DispatchTemplate));
    assert_eq!(retarget(2, template), Some(VerifyRule::DispatchTemplate));
    assert_eq!(retarget(3, template + 8), Some(VerifyRule::DispatchTemplate));
    assert_eq!(retarget(2, template + DISPATCH_TEMPLATE_VICTIM_PROBE), Some(VerifyRule::DispatchTemplate));
    // Both moved to the middle of the group: the exit-group check.
    let mut body = site.clone();
    for miss in [2, 3] {
        let from = template + DISPATCH_TEMPLATE_MISS_BRANCHES[miss];
        body[from] = miss_branch_to(body[from], from, group + 1);
    }
    assert_eq!(Frag::new(&body).rule(), Some(VerifyRule::ExitGroup));
    // The main probe's pair (misses 0 and 1) must name word 9 exactly: not the word
    // before or after it, not the exit group, not anything else of the template.
    for miss in [0, 1] {
        for to in [
            template + DISPATCH_TEMPLATE_VICTIM_PROBE - 1,
            template + DISPATCH_TEMPLATE_VICTIM_PROBE + 1,
            template,
            group,
            group + 1,
            template + DISPATCH_TEMPLATE_LEN - 1,
        ] {
            assert_eq!(retarget(miss, to), Some(VerifyRule::DispatchTemplate), "miss {miss} -> {to}");
        }
    }
}

#[test]
fn slot_200_is_readable_only_by_a_templates_table_loads() {
    let outside = |insn| Frag::new(&[insn, b_epi(1)]).rule();
    assert_eq!(
        outside(ldr(12, sp(), RUNTIME_FRAME_IBTC_OFFSET)),
        Some(VerifyRule::FrameAccessOutOfRange)
    );
    assert_eq!(
        outside(ldr(0, sp(), RUNTIME_FRAME_IBTC_OFFSET)),
        Some(VerifyRule::FrameAccessOutOfRange)
    );
    assert_eq!(
        outside(str(12, sp(), RUNTIME_FRAME_IBTC_OFFSET)),
        Some(VerifyRule::FrameAccessOutOfRange)
    );
}

#[test]
fn kernel_values_never_reach_a_dispatch_template() {
    // x13 holds a kernel value where the template reads it as T.
    for insn in [mov(xs(13), xs(29)), mov(xs(13), sp())] {
        let body = dispatch_site(&[insn]);
        assert_eq!(Frag::new(&body).rule(), Some(VerifyRule::KernelValueRead), "{insn:?}");
    }
    // Another kernel value (the pt_regs pointer) live across the template's edges.
    let mut body = alloc::vec![ldr(15, sp(), RUNTIME_FRAME_PT_REGS_PTR_OFFSET)];
    body.extend(dispatch_site_from(1, &[movz(13, 0x4000)]));
    assert_eq!(Frag::new(&body).rule(), Some(VerifyRule::KernelValueAtEdge));
}

/// The verifier's template transfer function (`step_dispatch_template`) assumes, of
/// the exact template words: x12 is the only register that ever holds a kernel value
/// in a template; the other words (x14 as index, key and compare, x13 never written)
/// read only T, x14 and, for the two key loads, x12 as the record base; x14 is written
/// before it is read on every path, including a miss branch to the victim probe.
/// Checked here on the words, from the generated operand metadata.
#[test]
fn template_register_discipline_holds() {
    const SLOT: u32 = 1 << DISPATCH_SLOT_REG;
    const TARGET: u32 = 1 << DISPATCH_TARGET_REG;
    const KEY: u32 = 1 << DISPATCH_KEY_REG;
    for (position, insn) in KJIT_DISPATCH_TEMPLATE.iter().enumerate() {
        let read = rules::reads(insn).unwrap();
        let written = rules::writes(insn).unwrap();
        let is_edge = DISPATCH_TEMPLATE_MISS_BRANCHES.contains(&position)
            || matches!(insn, A64Insn::BrBr64BranchReg { .. });
        if is_edge {
            assert_eq!(written.gprs, 0, "word {position}");
            assert!(read.gprs & !(SLOT | KEY) == 0, "word {position}");
            continue;
        }
        assert!(!written.sp, "word {position}");
        // Words read x12..x14 only (and sp for the table load); never x15, never a
        // user register.
        assert_eq!(read.gprs & !(SLOT | TARGET | KEY), 0, "word {position}");
        // T is never written; the only registers written are x12 and x14.
        assert_eq!(written.gprs & TARGET, 0, "word {position}");
        if written.gprs & SLOT != 0 {
            // A kernel value (table, slot, record, host) is never computed from T.
            assert_eq!(written.gprs, SLOT, "word {position}");
            assert_eq!(read.gprs & (TARGET | KEY), read.gprs & KEY, "word {position}");
        } else {
            assert_eq!(written.gprs, KEY, "word {position}");
            // x14 is derived from T and the record's pc, never from the kernel value
            // x12 -- except the key load, whose source is the record (user data).
            let key_load = matches!(insn, A64Insn::LdrImmGenLdr64LdstPos { rt, mem }
                if rt.enc() == DISPATCH_KEY_REG && mem.base().enc() == DISPATCH_SLOT_REG);
            assert!(key_load || read.gprs & SLOT == 0, "word {position}");
        }
    }
    // x14 defined before read, on the fall-through path and on the path a main-probe
    // miss branch takes into the victim probe (the miss branches read x12 / x14 as
    // tests, whose values the previous words defined).
    let mut defined = 0u32;
    for (position, insn) in KJIT_DISPATCH_TEMPLATE.iter().enumerate() {
        if position == DISPATCH_TEMPLATE_VICTIM_PROBE {
            // Entered by a miss edge or the fall-after-br: x14 is not relied on.
            defined = 0;
        }
        let read = rules::reads(insn).unwrap().gprs & KEY;
        assert_eq!(read & !defined, 0, "word {position} reads x14 before it is written");
        defined |= rules::writes(insn).unwrap().gprs & KEY;
    }
}

// ---- Link slots (A16, rule 10) ----

fn movk(rd: u8, hw: u8, imm: u32) -> A64Insn {
    A64Insn::MovkMovk64Movewide {
        hw,
        imm16: uimm(imm, 16),
        rd: x(rd),
    }
}

fn movz_hw(rd: u8, hw: u8, imm: u32) -> A64Insn {
    A64Insn::MovzMovz64Movewide {
        hw,
        imm16: uimm(imm, 16),
        rd: x(rd),
    }
}

/// `movz` + three `movk`s: the lowering of a 64-bit constant into `rd`.
fn mov_imm64(rd: u8, value: u64) -> Vec<A64Insn> {
    alloc::vec![
        movz_hw(rd, 3, (value >> 48) as u32 & 0xffff),
        movk(rd, 2, (value >> 32) as u32 & 0xffff),
        movk(rd, 1, (value >> 16) as u32 & 0xffff),
        movk(rd, 0, value as u32 & 0xffff),
    ]
}

const NOP: A64Insn = A64Insn::NopNopHiHints {};

fn mov_x(rd: u8, rm: u8) -> A64Insn {
    mov(x(rd), x(rm))
}

fn add(rd: u8, rn: u8, imm: u32) -> A64Insn {
    A64Insn::AddAddsubImmAdd64AddsubImm {
        sh: 0,
        imm12: uimm(imm, 12),
        rn: A64Reg::x_sp(rn),
        rd: A64Reg::x_sp(rd),
    }
}

/// A BL site as rephrase lowers it (A20 order): `<check>; x30 <- resume; nop;
/// x13 <- target; <template>; <exit group>; <stub>`. Returns the body and the slot's
/// body index.
fn bl_site_with(target_move: &[A64Insn]) -> (Vec<A64Insn>, usize) {
    let mut gap = mov_imm64(30, 0x1004);
    gap.push(NOP);
    let slot = CHECK + gap.len() - 1;
    gap.extend_from_slice(target_move);
    (dispatch_site(&gap), slot)
}

fn bl_site(target: u64) -> (Vec<A64Insn>, usize) {
    bl_site_with(&mov_imm64(13, target))
}

#[test]
fn accepts_a_link_slot_whose_template_target_is_the_listed_pc() {
    for target in [0x40_05a0_u64, 0, 0x1_2345_6789_abcc, u64::MAX & !3] {
        let (body, slot) = bl_site(target);
        let ok = Frag::new(&body).link(slot, target).verify();
        assert_eq!(ok.map(|ok| ok.uses_fpsimd), Ok(false), "target {target:#x}");
    }
    // A shorter constant move: a movz and one movk.
    let (body, slot) = bl_site_with(&[movz_hw(13, 1, 0x40), movk(13, 0, 0x5a0)]);
    assert_eq!(Frag::new(&body).link(slot, 0x40_05a0).rule(), None);
    // Halfwords in any order.
    let (body, slot) = bl_site_with(&[movz_hw(13, 0, 0x5a0), movk(13, 1, 0x40)]);
    assert_eq!(Frag::new(&body).link(slot, 0x40_05a0).rule(), None);
    // A listed slot of the second of two sites.
    let mut body = alloc::vec![NOP, b(1, at(2) as i64)];
    let (site, slot) = {
        let mut gap = mov_imm64(30, 0x1004);
        gap.push(NOP);
        let slot = 2 + CHECK + gap.len() - 1;
        gap.extend(mov_imm64(13, 0x7000));
        (dispatch_site_from(2, &gap), slot)
    };
    body.extend(site);
    assert_eq!(Frag::new(&body).link(slot, 0x7000).rule(), None);
    // Unlisted, the same nop is just a nop in the gap.
    let (body, _) = bl_site(0x4000);
    assert_eq!(Frag::new(&body).rule(), None);
}

#[test]
fn a_link_slot_must_be_a_nop_before_the_target_move() {
    let target = 0x40_05a0_u64;
    let (body, slot) = bl_site(target);
    let rule = |body: &[A64Insn], slot: usize| Frag::new(body).link(slot, target).rule();

    // Not a nop: any other word, data processing included.
    for insn in [movz(9, 0), mov_x(13, 13), fill(12, 16)] {
        let mut body = body.clone();
        body[slot] = insn;
        assert_eq!(rule(&body, slot), Some(VerifyRule::LinkSite), "{insn:?}");
    }
    // Listed on another word: before the slot (the link write), on a target move, on the
    // template, on its last word, past the fragment, in the epilogue, unaligned.
    let template = slot + 5;
    for offset in [
        at(slot - 1),
        at(slot + 1),
        at(slot + 4),
        at(template),
        at(template + DISPATCH_TEMPLATE_LEN - 1),
        at(body.len()),
        at(body.len() + 8),
        EPILOGUE_OFFSET,
        at(slot) + 2,
        0,
    ] {
        let mut frag = Frag::new(&body);
        frag.links.push((offset, target));
        assert_eq!(frag.rule(), Some(VerifyRule::LinkSite), "listed at {offset:#x}");
    }
    // A nop that no template follows (it is followed by the exit group).
    let mut with_stray = body.clone();
    let group = template + DISPATCH_TEMPLATE_LEN;
    with_stray[group] = NOP;
    let mut frag = Frag::new(&with_stray);
    frag.links.push((at(group), target));
    assert_eq!(frag.rule(), Some(VerifyRule::LinkSite));
    // A nop in front of the template's second word is not in front of the template.
    let mut frag = Frag::new(&body);
    frag.links.push((at(template + 1), target));
    assert_eq!(frag.rule(), Some(VerifyRule::LinkSite));
}

#[test]
fn a_link_slot_names_the_templates_target_exactly() {
    let target = 0x40_05a0_u64;
    let (body, slot) = bl_site(target);
    // Another PC listed, down to one bit of each halfword.
    for bit in [0, 2, 4, 15, 16, 22, 31, 32, 40, 47, 48, 63] {
        assert_eq!(
            Frag::new(&body).link(slot, target ^ (1 << bit)).rule(),
            Some(VerifyRule::LinkSite),
            "bit {bit}"
        );
    }
    // The move altered instead: each halfword.
    for hw in 0..4 {
        let mut altered = body.clone();
        altered[slot + 1 + hw] = if hw == 0 {
            movz_hw(13, 3, 1)
        } else {
            movk(13, 3 - hw as u8, 1)
        };
        assert_eq!(
            Frag::new(&altered).link(slot, target).rule(),
            Some(VerifyRule::LinkSite),
            "word {hw}"
        );
    }
}

#[test]
fn a_link_slot_needs_x13_set_once_by_a_movz_and_movks() {
    let target = 0x40_05a0_u64;
    let reject = |target_move: &[A64Insn]| {
        let (body, slot) = bl_site_with(target_move);
        Frag::new(&body).link(slot, target).rule()
    };
    let exact = [movz_hw(13, 1, 0x40), movk(13, 0, 0x5a0)];
    assert_eq!(reject(&exact), None);
    // Nothing sets x13 / only a movk / a movk before the movz.
    assert_eq!(reject(&[]), Some(VerifyRule::LinkSite));
    assert_eq!(reject(&[movk(13, 0, 0x5a0)]), Some(VerifyRule::LinkSite));
    assert_eq!(reject(&[movk(13, 1, 0x40), movz_hw(13, 0, 0x5a0)]), Some(VerifyRule::LinkSite));
    // Set twice: a second movz, a movk of a halfword already set, either order.
    assert_eq!(
        reject(&[movz_hw(13, 1, 0x40), movk(13, 0, 0x5a0), movz_hw(13, 1, 0x40), movk(13, 0, 0x5a0)]),
        Some(VerifyRule::LinkSite)
    );
    assert_eq!(
        reject(&[movz_hw(13, 0, 0x5a0), movk(13, 0, 0x5a0), movk(13, 1, 0x40)]),
        Some(VerifyRule::LinkSite)
    );
    // Five moves cannot set each halfword once.
    assert_eq!(
        reject(&[
            movz_hw(13, 1, 0x40),
            movk(13, 0, 0x5a0),
            movk(13, 2, 0),
            movk(13, 3, 0),
            movk(13, 0, 0x5a0),
        ]),
        Some(VerifyRule::LinkSite)
    );
    // x13 written another way, before or after the move: a copy, arithmetic, a fill,
    // a 32-bit movz, a load. Anything between the slot and the template that is not
    // part of the move run is rejected, so is anything between the slot and the run.
    for insn in [
        mov_x(13, 30),
        add(13, 13, 0),
        fill(13, 56),
        A64Insn::MovzMovz32Movewide { hw: 0, imm16: uimm(0x5a0, 16), rd: A64Reg::w(13) },
        NOP,
        movz(9, 5),
        fill(14, 32),
        mov_x(15, 13),
    ] {
        let mut before = alloc::vec![insn];
        before.extend_from_slice(&exact);
        let mut after = exact.to_vec();
        after.push(insn);
        let inside = alloc::vec![exact[0], insn, exact[1]];
        assert_eq!(reject(&before), Some(VerifyRule::LinkSite), "{insn:?} between slot and moves");
        assert_eq!(reject(&after), Some(VerifyRule::LinkSite), "{insn:?} between moves and template");
        assert_eq!(reject(&inside), Some(VerifyRule::LinkSite), "{insn:?} inside the moves");
    }
    // A write of x13 before the slot (in the link write's part of the guarded run) does
    // not matter: the moves after the slot overwrite it, and a linked transfer leaves x13
    // dead.
    let (mut body, slot) = bl_site_with(&exact);
    body[slot - 1] = movz(13, 0x1234);
    assert_eq!(Frag::new(&body).link(slot, target).rule(), None);
}

/// The A20 order: the slot comes first, then the moves. A slot after the moves (the
/// pre-A20 order), or moves on both sides, is not a link site.
#[test]
fn a_link_slot_after_its_moves_is_rejected() {
    let target = 0x40_05a0_u64;
    // Pre-A20: x13 <- target; x30 <- resume; nop; <template>.
    let mut gap = mov_imm64(13, target);
    gap.extend(mov_imm64(30, 0x1004));
    gap.push(NOP);
    let slot = CHECK + gap.len() - 1;
    let body = dispatch_site(&gap);
    assert_eq!(Frag::new(&body).link(slot, target).rule(), Some(VerifyRule::LinkSite));
    // The moves directly before the slot, nothing after it.
    let mut gap = mov_imm64(30, 0x1004);
    gap.extend(mov_imm64(13, target));
    gap.push(NOP);
    let slot = CHECK + gap.len() - 1;
    let body = dispatch_site(&gap);
    assert_eq!(Frag::new(&body).link(slot, target).rule(), Some(VerifyRule::LinkSite));
    // Moves on both sides of the slot: the run after it alone must give the target.
    let mut gap = mov_imm64(13, target);
    gap.push(NOP);
    let slot = CHECK + gap.len() - 1;
    gap.extend(mov_imm64(13, 0x9000));
    let body = dispatch_site(&gap);
    assert_eq!(Frag::new(&body).link(slot, target).rule(), Some(VerifyRule::LinkSite));
    assert_eq!(Frag::new(&body).link(slot, 0x9000).rule(), None);
}

#[test]
fn a_link_slot_is_listed_once_and_is_no_join_point() {
    let target = 0x40_05a0_u64;
    let (body, slot) = bl_site(target);
    let mut twice = Frag::new(&body).link(slot, target);
    twice.links.push((at(slot), target));
    assert_eq!(twice.rule(), Some(VerifyRule::LinkSite));
    // Twice with two targets, one of them the template's.
    let mut twice = Frag::new(&body).link(slot, target);
    twice.links.push((at(slot), 0x1000));
    assert_eq!(twice.rule(), Some(VerifyRule::LinkSite));
    // A join point on the slot or on any of the target moves: an entry.
    for index in slot..slot + 5 {
        assert_eq!(
            Frag::new(&body).entry(index).link(slot, target).rule(),
            Some(VerifyRule::LinkSite),
            "entry on word {}",
            index - slot
        );
    }
    // A join point on the slot or on a move: a branch to it.
    let mut gap = mov_imm64(30, 0x1004);
    gap.push(NOP);
    let slot_in_gap = gap.len() - 1;
    gap.extend(mov_imm64(13, target));
    let slot = 1 + CHECK + slot_in_gap;
    for word in slot_in_gap..slot_in_gap + 5 {
        let mut with_branch = alloc::vec![b(0, at(1 + CHECK + word) as i64)];
        with_branch.extend(dispatch_site_from(1, &gap));
        assert_eq!(
            Frag::new(&with_branch).link(slot, target).rule(),
            Some(VerifyRule::LinkSite),
            "branch to word {}",
            word - slot_in_gap
        );
        // Not listed, the same branch is the generic rule-6 join point.
        assert_eq!(Frag::new(&with_branch).rule(), Some(VerifyRule::MissingBudgetCheck));
    }
}
