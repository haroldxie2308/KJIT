use super::rules::{self, BUDGET_SCRATCH_REG, BUDGET_SLOT_OFFSET};
use super::*;
use crate::shared::abi::RUNTIME_FRAME_PT_REGS_PTR_OFFSET;
use crate::shared::arm64::ergo::{
    ldst64_offset, ldstpair64_offset, mem_off, mem_pre, scaled_simm, simm, sp, uimm, x,
};
use crate::shared::arm64::{A64Insn, A64OperandRole};

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

    fn verify(&self) -> Result<(), VerifyError> {
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
fn barriers_are_the_only_allowed_system_instructions_besides_mrs_tpidr() {
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
    // So does a join point: an entry at the store sees a user-controlled x12.
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
    assert_eq!(rule(A64Insn::MrsMrsRsSystemmove { rt: x(0) }), None);
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

    // A join point past the check's first word bypasses the decrement.
    let fills = [fill(12, 16), fill(13, 24)];
    for inner in 2..=7 {
        assert_eq!(
            Frag::new(&budget_loop(&fills)).entry(inner).rule(),
            Some(VerifyRule::MissingBudgetCheck),
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
            | rules::Form::MrsTpidrEl0 => {
                assert!(!memory && !control, "{}", insn.key());
                assert!(!insn.key().starts_with("SVC"), "{}", insn.key());
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
