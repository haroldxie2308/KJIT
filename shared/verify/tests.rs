use super::rules::{self, BUDGET_SCRATCH_REG, BUDGET_SLOT_OFFSET};
use super::*;
use crate::shared::abi::{
    DISPATCH_KEY_REG, KJIT_DISPATCH_TEMPLATE, RUNTIME_FRAME_IBTC_OFFSET,
    RUNTIME_FRAME_PT_REGS_PTR_OFFSET,
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

    fn verify(&self) -> Result<VerifyOk, VerifyError> {
        verify_fragment(&VerifyInput {
            code: &self.code,
            fault_sites: &self.sites,
            entry_offsets: &self.entries,
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

/// Rule 5 (A10): MRS is allowlisted for exactly TPIDR_EL0, CNTVCT_EL0 and
/// CNTFRQ_EL0, with any Rt, in the body and in an exit group; every other value of
/// the system-register field (o0:op1:CRn:CRm:op2, all 2^15) is undecodable. Rule 9:
/// their results are user values.
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
    ] {
        assert_eq!(Frag::new(&[mrs, orr, b_epi(2)]).rule(), None, "{mrs:?}");
    }
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
    // Not vacuous: everything the epilogue copies to the user or the runtime.
    let user = (0..=11).chain(16..=28).chain([30]);
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

fn budget_seq(cbz_index: usize, stub_index: usize) -> [A64Insn; 4] {
    let s = BUDGET_SCRATCH_REG;
    [
        ldr(s, sp(), BUDGET_SLOT_OFFSET),
        A64Insn::SubAddsubImmSub64AddsubImm {
            sh: 0,
            imm12: uimm(1, 12),
            rn: xs(s),
            rd: xs(s),
        },
        str(s, sp(), BUDGET_SLOT_OFFSET),
        A64Insn::CbzCbz64Compbranch {
            imm19: branch_imm(at(stub_index) as i64 - at(cbz_index) as i64, 19),
            rt: x(s),
        },
    ]
}

/// `loop: nop; <budget check>; <fills>; b loop; stub: movz x9; b <epilogue>`.
/// The check is words 1..=4, the fills 5..5+fills, the back-edge at 5+fills.
fn budget_loop(fills: &[A64Insn]) -> Vec<A64Insn> {
    let branch = 5 + fills.len();
    let mut body = alloc::vec![A64Insn::NopNopHiHints {}];
    body.extend_from_slice(&budget_seq(4, branch + 1));
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
}

#[test]
fn budget_rule_rejects_unguarded_or_bypassable_back_edges() {
    let missing = |body: &[A64Insn]| Frag::new(body).rule();

    // No check at all.
    let mut body = budget_loop(&[]);
    body[1..5].copy_from_slice(&[A64Insn::NopNopHiHints {}; 4]);
    assert_eq!(
        Frag::new(&body).verify().unwrap_err(),
        VerifyError {
            offset: at(5),
            rule: VerifyRule::MissingBudgetCheck
        }
    );

    // A self-loop is a back-edge too.
    assert_eq!(
        missing(&[A64Insn::NopNopHiHints {}, b(1, at(1) as i64), b_epi(2)]),
        Some(VerifyRule::MissingBudgetCheck)
    );

    // Anything but a fill between the cbz and the back-edge: the check no longer
    // guards the back-edge, so its counter load is the first rejected word.
    for between in [
        A64Insn::NopNopHiHints {},
        fill(0, 16),
        fill(12, 64),
        fill(12, 8),
        A64Insn::LdrImmGenLdr32LdstPos {
            rt: crate::shared::arm64::ergo::w(12),
            mem: mem_off(sp(), crate::shared::arm64::ergo::scaled_uimm(4, 12, 2)),
        },
    ] {
        assert_eq!(
            Frag::new(&budget_loop(&[between])).verify().unwrap_err(),
            VerifyError {
                offset: at(1),
                rule: VerifyRule::BudgetSlotAccess
            },
            "{between:?}"
        );
    }

    // A join point past the check's first word bypasses the decrement. On the
    // `sub`, `str` or `cbz`, the check's scratch still holds the entry address
    // there (rule 9 rejects the read first).
    let fills = [fill(12, 16), fill(13, 24)];
    for inner in 2..=7 {
        let rule = if inner <= 4 {
            VerifyRule::KernelValueRead
        } else {
            VerifyRule::MissingBudgetCheck
        };
        assert_eq!(
            Frag::new(&budget_loop(&fills)).entry(inner).rule(),
            Some(rule),
            "entry at word {inner}"
        );
    }
}

#[test]
fn budget_rule_rejects_altered_checks() {
    let s = BUDGET_SCRATCH_REG;
    // `sub s, s, #2`: the load no longer belongs to a check.
    let mut body = budget_loop(&[]);
    body[2] = A64Insn::SubAddsubImmSub64AddsubImm {
        sh: 0,
        imm12: uimm(2, 12),
        rn: xs(s),
        rd: xs(s),
    };
    assert_eq!(Frag::new(&body).rule(), Some(VerifyRule::BudgetSlotAccess));

    // `cbz` backward, or into the middle of the stub.
    for target in [0, 7] {
        let mut body = budget_loop(&[]);
        body[4] = A64Insn::CbzCbz64Compbranch {
            imm19: branch_imm(at(target) as i64 - at(4) as i64, 19),
            rt: x(s),
        };
        assert!(Frag::new(&body).rule().is_some(), "cbz -> word {target}");
    }

    // A check that guards no back-edge.
    let mut body = budget_loop(&[]);
    body[5] = b_epi(5);
    assert_eq!(Frag::new(&body).rule(), Some(VerifyRule::BudgetSlotAccess));

    // The counter written anywhere else.
    for insn in [
        str(0, sp(), BUDGET_SLOT_OFFSET),
        str(s, sp(), BUDGET_SLOT_OFFSET),
        ldr(s, sp(), BUDGET_SLOT_OFFSET),
    ] {
        let body = [insn, b_epi(1)];
        assert_eq!(
            Frag::new(&body).rule(),
            Some(VerifyRule::BudgetSlotAccess),
            "{insn:?}"
        );
    }
}

/// A8 PAN window: `ubfx x5, x4, #48, #8; cbnz x5, <S>; msr pan, #0;
/// ldaddal x0, x1, [x4]; msr pan, #1; b <epilogue>`, then the PAN stub S (`msr
/// pan, #1`, exit payload, `b <epilogue>`). The atomic's fault site is S.
/// Indices: 0 ubfx, 1 cbnz, 2 msr#0, 3 atomic, 4 msr#1, 5 b, 6 S, 7 movz, 8 b.
fn pan_window_body() -> Vec<A64Insn> {
    alloc::vec![
        ubfx48(4, 5),
        cbnz(1, 5, 6),
        msr_pan(0),
        ldaddal(0, 1, 4),
        msr_pan(1),
        b_epi(5),
        msr_pan(1),
        movz(9, 5),
        b_epi(8),
    ]
}

fn pan_window_fragment(body: &[A64Insn]) -> Frag {
    Frag::new(body).site(3, 6)
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
fn accepts_the_exact_pan_window() {
    assert_eq!(pan_window_fragment(&pan_window_body()).rule(), None);
    // The `ubfx` may be a join point (it recomputes the checked value).
    assert_eq!(
        pan_window_fragment(&pan_window_body()).entry(0).rule(),
        None
    );
}

#[test]
fn pan_window_rule_rejects_every_deviation() {
    let rule = |body: &[A64Insn]| pan_window_fragment(body).rule();
    let with = |index: usize, insn: A64Insn| {
        let mut body = pan_window_body();
        body[index] = insn;
        rule(&body)
    };
    // Range check: other register, shift, width, 32-bit form; cbnz on another
    // register, to a non-PAN-stub word, 32-bit form.
    assert_eq!(with(0, ubfx48(3, 5)), Some(VerifyRule::PanWindow));
    assert_eq!(with(0, ubfx48(4, 6)), Some(VerifyRule::PanWindow));
    for (immr, imms) in [(47, 55), (48, 54), (48, 63), (56, 63)] {
        let ubfx = A64Insn::UbfmUbfm64mBitfield {
            immr: uimm(immr, 6),
            imms: uimm(imms, 6),
            rn: x(4),
            rd: x(5),
        };
        assert_eq!(with(0, ubfx), Some(VerifyRule::PanWindow), "{immr} {imms}");
    }
    assert_eq!(with(1, cbnz(1, 6, 6)), Some(VerifyRule::PanWindow));
    assert_eq!(with(1, cbnz(1, 5, 7)), Some(VerifyRule::PanWindow));
    let cbnz32 = A64Insn::CbnzCbnz32Compbranch {
        imm19: branch_imm(at(6) as i64 - at(1) as i64, 19),
        rt: crate::shared::arm64::A64Reg::w(5),
    };
    assert_eq!(with(1, cbnz32), Some(VerifyRule::PanWindow));
    // The atomic on another base, or not an atomic.
    assert_eq!(with(3, ldaddal(0, 1, 3)), Some(VerifyRule::PanWindow));
    assert_eq!(with(3, ldtr(0, 4)), Some(VerifyRule::PanWindow));
    assert_eq!(with(3, movz(0, 1)), Some(VerifyRule::PanWindow));
    // Missing window end; `msr pan, #1` / `#0` anywhere else; other CRm.
    assert_eq!(with(4, movz(2, 0)), Some(VerifyRule::PanWindow));
    assert_eq!(with(2, movz(2, 0)), Some(VerifyRule::AtomicOutsideWindow));
    assert_eq!(with(0, msr_pan(1)), Some(VerifyRule::PanWindow));
    assert_eq!(
        Frag::new(&[msr_pan(2), b_epi(1)]).rule(),
        Some(VerifyRule::Msr)
    );
    assert_eq!(
        Frag::new(&[msr_pan(15), b_epi(1)]).rule(),
        Some(VerifyRule::Msr)
    );
    let body = [msr_pan(1), movz(0, 1), b_epi(2)];
    assert_eq!(
        Frag::new(&body).rule(),
        Some(VerifyRule::PanSetOutsideWindow)
    );
    let body = [movz(0, 1), msr_pan(0), b_epi(2)];
    assert_eq!(Frag::new(&body).rule(), Some(VerifyRule::PanWindow));
    // The PAN stub without its leading msr.
    assert_eq!(with(6, movz(8, 0)), Some(VerifyRule::PanWindow));
    // No join point on the cbnz, either MSR or the atomic.
    for index in 1..=4 {
        assert_eq!(
            pan_window_fragment(&pan_window_body()).entry(index).rule(),
            Some(VerifyRule::PanWindow),
            "entry at {index}"
        );
    }
}

#[test]
fn pan_stub_is_only_a_window_target() {
    // The atomic's fault site at a plain stub, or missing.
    let mut body = pan_window_body();
    body.extend([movz(9, 5), b_epi(10)]);
    assert_eq!(
        Frag::new(&body).site(3, 9).rule(),
        Some(VerifyRule::PanStubTarget)
    );
    assert_eq!(
        Frag::new(&pan_window_body()).rule(),
        Some(VerifyRule::MissingFaultSite)
    );
    // An LDTR whose fault site is the PAN stub.
    let body = [
        ubfx48(4, 5),
        cbnz(1, 5, 7),
        msr_pan(0),
        ldaddal(0, 1, 4),
        msr_pan(1),
        ldtr(2, 3),
        b_epi(6),
        msr_pan(1),
        movz(9, 5),
        b_epi(9),
    ];
    assert_eq!(
        Frag::new(&body).site(3, 7).rule(),
        Some(VerifyRule::MissingFaultSite)
    );
    let frag = Frag::new(&body).site(3, 7).site(5, 7);
    assert_eq!(frag.rule(), Some(VerifyRule::PanStubTarget));
    // Any other branch into the PAN stub.
    let mut body = pan_window_body();
    body[5] = b(5, at(6) as i64);
    assert_eq!(
        pan_window_fragment(&body).rule(),
        Some(VerifyRule::PanStubTarget)
    );
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

/// A9a: the A8 window around a base-only SIMD&FP load/store is accepted, and
/// `uses_fpsimd` says whether any SIMD&FP form appears.
#[test]
fn simd_windows_and_uses_fpsimd() {
    let ok = |frag: Frag| frag.verify().unwrap().uses_fpsimd;
    // The LSE window alone: no SIMD&FP.
    assert!(!ok(pan_window_fragment(&pan_window_body())));
    // The same window around `ldr q0, [x4]`, `ld1 {v0.16b-v3.16b}, [x4]`,
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
        let mut body = pan_window_body();
        body[3] = access;
        assert!(ok(pan_window_fragment(&body)), "{access:?}");
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

/// A9a: a SIMD&FP load/store is valid only as a window's base-only access on sA,
/// with its fault site at the window's PAN stub.
#[test]
fn simd_memory_forms_are_window_only() {
    let with = |insn: A64Insn| {
        let mut body = pan_window_body();
        body[3] = insn;
        pan_window_fragment(&body).rule()
    };
    // Another base, SP, an offset, writeback, unscaled: not a window access, so
    // the window is malformed (and each form is user-only elsewhere).
    assert_eq!(with(ldr_q(0, 3, 0)), Some(VerifyRule::PanWindow));
    assert_eq!(with(ldr_q(0, 31, 0)), Some(VerifyRule::PanWindow));
    assert_eq!(with(ldr_q(0, 4, 1)), Some(VerifyRule::PanWindow));
    assert_eq!(
        Frag::new(&[ldr_q(0, 4, 1), b_epi(1)]).rule(),
        Some(VerifyRule::UserOnlyForm)
    );
    let post = A64Insn::LdrImmFpsimdLdrQLdstImmpost {
        rt: 0,
        mem: crate::shared::arm64::ergo::mem_post(xs(4), simm(16, 9)),
    };
    assert_eq!(with(post), Some(VerifyRule::PanWindow));
    let ld1_post = A64Insn::Ld1AdvsimdMultLd1AsisdlsepI1I1 {
        q: 1,
        size: 0,
        rn: xs(4),
        rt: 0,
    };
    assert_eq!(with(ld1_post), Some(VerifyRule::PanWindow));
    let ldur = A64Insn::LdurFpsimdLdurQLdstUnscaled {
        rt: 0,
        mem: mem_off(xs(4), simm(0, 9)),
    };
    assert_eq!(with(ldur), Some(VerifyRule::PanWindow));
    for insn in [post, ld1_post, ldur] {
        assert_eq!(
            Frag::new(&[insn, b_epi(1)]).rule(),
            Some(VerifyRule::UserOnlyForm),
            "{insn:?}"
        );
    }
    // Outside a window, even with a fault site.
    let body = [ldr_q(0, 4, 0), b_epi(1), movz(9, 5), b_epi(3)];
    assert_eq!(
        Frag::new(&body).rule(),
        Some(VerifyRule::AtomicOutsideWindow)
    );
    assert_eq!(
        Frag::new(&body).site(0, 2).rule(),
        Some(VerifyRule::AtomicOutsideWindow)
    );
    // In a window whose access's fault site is a plain stub.
    let mut body = pan_window_body();
    body[3] = ldr_q(0, 4, 0);
    body.extend([movz(9, 5), b_epi(10)]);
    assert_eq!(
        Frag::new(&body).site(3, 9).rule(),
        Some(VerifyRule::PanStubTarget)
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
        cbnz(2, 5, 7),
        msr_pan(0),
        ldr_q(0, 13, 0),
        msr_pan(1),
        b_epi(6),
        msr_pan(1),
        movz(9, 5),
        b_epi(9),
    ];
    assert_eq!(Frag::new(&body).site(4, 7).rule(), read);
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
            // A9a: SIMD&FP register-only forms name a V register, never memory,
            // flags or control flow.
            rules::Form::Simd => {
                assert!(!memory && !control, "{}", insn.key());
                assert!(
                    roles.iter().any(|role| matches!(
                        role,
                        A64OperandRole::VecRead { .. } | A64OperandRole::VecWrite { .. }
                    )),
                    "{}",
                    insn.key()
                );
                assert!(
                    !roles.iter().any(|role| matches!(
                        role,
                        A64OperandRole::FlagsRead | A64OperandRole::FlagsWrite
                    )),
                    "{}",
                    insn.key()
                );
            }
            rules::Form::PanClear | rules::Form::PanSet | rules::Form::MsrOther => {
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
    let template = base + 4 + gap.len();
    let group = template + DISPATCH_TEMPLATE_LEN;
    let stub = group + 2;
    let mut body = budget_seq(base + 3, stub).to_vec();
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
    body[5 + position] = insn;
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
    body[..4].fill(A64Insn::NopNopHiHints {});
    assert_eq!(Frag::new(&body).rule(), Some(VerifyRule::MissingBudgetCheck));
    let mut body = site.clone();
    body[..4].fill(movz(14, 0));
    assert_eq!(Frag::new(&body).rule(), Some(VerifyRule::MissingBudgetCheck));
    // Something a gap may not hold between the check and the template.
    for insn in [
        A64Insn::NopNopHiHints {},
        str(0, sp(), 16),
        ldr(0, sp(), 16),
        b(4, at(5) as i64),
    ] {
        let mut body = site.clone();
        body[4] = insn;
        assert_eq!(Frag::new(&body).rule(), Some(VerifyRule::MissingBudgetCheck), "{insn:?}");
    }
    // A join point between the check's `sub` and the template, or inside it
    // (the victim probe's first word included: only the main probe's own miss
    // branches may reach it).
    for index in 1..=4 {
        assert_eq!(
            Frag::new(&site).entry(index).rule(),
            Some(VerifyRule::MissingBudgetCheck),
            "entry at {index}"
        );
    }
    for index in 5..5 + DISPATCH_TEMPLATE_LEN {
        assert_eq!(
            Frag::new(&site).entry(index).rule(),
            Some(VerifyRule::DispatchTemplate),
            "entry at {index}"
        );
    }
    // A branch into the template, at each of its words (the victim probe's first
    // word, template word 9, included).
    for inner in 0..DISPATCH_TEMPLATE_LEN {
        let mut body = alloc::vec![b(0, at(1 + 5 + inner) as i64)];
        body.extend(dispatch_site_from(1, &[movz(13, 0x4000)]));
        assert_eq!(Frag::new(&body).rule(), Some(VerifyRule::DispatchTemplate), "word {inner}");
    }
}

#[test]
fn dispatch_miss_branches_name_the_victim_probe_or_one_forward_exit_group() {
    let site = dispatch_site(&[movz(13, 0x4000)]);
    let template = 5;
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
