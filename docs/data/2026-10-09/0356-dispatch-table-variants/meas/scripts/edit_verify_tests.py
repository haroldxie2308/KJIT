p='/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/agent-a4b243dcf4b342be4/shared/verify/tests.rs'
s=open(p).read()

def rep(old, new):
    global s
    assert s.count(old) == 1, ("count", s.count(old), old[:70])
    s = s.replace(old, new)

rep('''use crate::shared::abi::{
    KJIT_DISPATCH_TEMPLATE, RUNTIME_FRAME_IBTC_OFFSET, RUNTIME_FRAME_PT_REGS_PTR_OFFSET,
};''','''use crate::shared::abi::{
    dispatch_template, ibtc_variant_by_id, ibtc_variant_id, template_for, DISPATCH_INDEX_REG,
    DISPATCH_KEY_REG, IBTC_VARIANT_COUNT, RUNTIME_FRAME_IBTC_OFFSET,
    RUNTIME_FRAME_PT_REGS_PTR_OFFSET,
};''')

a=s.index("// ---- Dispatch templates (A11) ----")
new='''// ---- Dispatch templates (A11) ----

/// A dispatch site whose first word is body word `base`: `<budget check>; <gap>;
/// <template>; <exit group>; <budget stub>`. The check's `cbz` is aimed at the stub;
/// the template's miss branches go where the selected variant says: the next probe's
/// first word, or the exit group that follows the template's final `br`.
fn dispatch_site_from(base: usize, gap: &[A64Insn]) -> Vec<A64Insn> {
    let template = dispatch_template();
    let start = base + 4 + gap.len();
    let group = start + template.len();
    let stub = group + 2;
    let mut body = budget_seq(base + 3, stub).to_vec();
    body.extend_from_slice(gap);
    for (position, insn) in template.words.iter().enumerate() {
        let from = start + position;
        let to = template.miss_at(position).map(|miss| start + miss.to);
        body.push(match insn {
            A64Insn::CbzCbz64Compbranch { rt, .. } => A64Insn::CbzCbz64Compbranch {
                imm19: branch_imm(at(to.unwrap()) as i64 - at(from) as i64, 19),
                rt: *rt,
            },
            A64Insn::CbnzCbnz64Compbranch { rt, .. } => A64Insn::CbnzCbnz64Compbranch {
                imm19: branch_imm(at(to.unwrap()) as i64 - at(from) as i64, 19),
                rt: *rt,
            },
            other => *other,
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

/// Every word of the selected template altered or dropped is rejected; the V0
/// words are also altered one by one in the ways the A11 contract lists.
#[test]
fn dispatch_template_words_are_byte_exact() {
    let site = |position, insn| site_with(position, insn).rule();
    let template = dispatch_template();
    let nop = A64Insn::NopNopHiHints {};
    for position in 0..template.len() {
        let rule = site(position, nop);
        if template.is_br(position) && position + 1 == template.len() {
            // Without its final `br x12` the template is plain words, and the check
            // guards nothing: rejected (which of the rules fires first is not the point).
            assert!(rule.is_some(), "word {position} dropped");
        } else {
            assert_eq!(rule, Some(VerifyRule::DispatchTemplate), "word {position} dropped");
        }
        // A single register-field bit flipped in every word (rd/rt, rn, rm).
        for bit in [0, 1, 5, 6, 16, 17] {
            let word = template.words[position].encode().unwrap() ^ (1 << bit);
            let Some(altered) = A64Insn::decode(word).filter(|insn| !insn.is_decode_undefined())
            else {
                continue;
            };
            if altered == template.words[position] || template.miss_at(position).is_some() && bit >= 5 && bit < 24
            {
                continue;
            }
            assert!(site(position, altered).is_some(), "word {position} bit {bit}");
        }
    }
    if ibtc_variant_id() != 0 {
        return;
    }
    assert_eq!(site(0, ldr(12, sp(), 192)), Some(VerifyRule::DispatchTemplate));
    assert_eq!(site(0, ldr(13, sp(), RUNTIME_FRAME_IBTC_OFFSET)), Some(VerifyRule::DispatchTemplate));
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
        "a 13-bit index reaches past the 4096-slot table"
    );
    assert_eq!(site(4, ldr(14, xs(12), 8)), Some(VerifyRule::DispatchTemplate));
    assert_eq!(site(7, ldr(12, xs(12), 16)), Some(VerifyRule::DispatchTemplate));
    assert!(site(8, A64Insn::BrBr64BranchReg { rn: x(13) }).is_some());
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
    // (including the first word of a later probe, which only the template's own miss
    // branches may reach).
    for index in 1..=4 {
        assert_eq!(
            Frag::new(&site).entry(index).rule(),
            Some(VerifyRule::MissingBudgetCheck),
            "entry at {index}"
        );
    }
    for index in 5..5 + dispatch_template().len() {
        assert_eq!(
            Frag::new(&site).entry(index).rule(),
            Some(VerifyRule::DispatchTemplate),
            "entry at {index}"
        );
    }
    // A branch into the template, at each of its words.
    for inner in 0..dispatch_template().len() {
        let mut body = alloc::vec![b(0, at(1 + 5 + inner) as i64)];
        body.extend(dispatch_site_from(1, &[movz(13, 0x4000)]));
        assert_eq!(Frag::new(&body).rule(), Some(VerifyRule::DispatchTemplate), "word {inner}");
    }
}

#[test]
fn dispatch_miss_branches_name_the_next_probe_or_one_forward_exit_group() {
    let site = dispatch_site(&[movz(13, 0x4000)]);
    let template = dispatch_template();
    let start = 5;
    let group = start + template.len();
    // The miss branches that go to the exit group: the last probe's.
    let exits = template
        .misses
        .iter()
        .filter(|miss| miss.to == template.len())
        .map(|miss| miss.at)
        .collect::<Vec<_>>();
    assert_eq!(exits.len(), 2);
    let retarget = |first: usize, second: usize| {
        let mut body = site.clone();
        for (&position, target) in exits.iter().zip([first, second]) {
            let from = start + position;
            body[from] = match body[from] {
                A64Insn::CbzCbz64Compbranch { rt, .. } => A64Insn::CbzCbz64Compbranch {
                    imm19: branch_imm(at(target) as i64 - at(from) as i64, 19),
                    rt,
                },
                A64Insn::CbnzCbnz64Compbranch { rt, .. } => A64Insn::CbnzCbnz64Compbranch {
                    imm19: branch_imm(at(target) as i64 - at(from) as i64, 19),
                    rt,
                },
                other => panic!("{other:?} is not a miss branch"),
            };
        }
        Frag::new(&body).rule()
    };
    assert_eq!(retarget(group, group), None);
    // Different targets, backward, into the template, into the middle of the group.
    assert_eq!(retarget(group, group + 1), Some(VerifyRule::DispatchTemplate));
    assert_eq!(retarget(start, start), Some(VerifyRule::DispatchTemplate));
    assert_eq!(retarget(group - 1, group - 1), Some(VerifyRule::DispatchTemplate));
    assert_eq!(retarget(group + 1, group + 1), Some(VerifyRule::ExitGroup));
    // A probe-to-probe miss branch must name the next probe's first word exactly.
    for miss in template.misses.iter().filter(|miss| miss.to < template.len()) {
        for to in [miss.to - 1, miss.to + 1, group] {
            let mut body = site.clone();
            let from = start + miss.at;
            body[from] = match body[from] {
                A64Insn::CbzCbz64Compbranch { rt, .. } => A64Insn::CbzCbz64Compbranch {
                    imm19: branch_imm(at(start + to) as i64 - at(from) as i64, 19),
                    rt,
                },
                A64Insn::CbnzCbnz64Compbranch { rt, .. } => A64Insn::CbnzCbnz64Compbranch {
                    imm19: branch_imm(at(start + to) as i64 - at(from) as i64, 19),
                    rt,
                },
                other => panic!("{other:?} is not a miss branch"),
            };
            assert_eq!(
                Frag::new(&body).rule(),
                Some(VerifyRule::DispatchTemplate),
                "miss at {} -> {to}",
                miss.at
            );
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
    let mut body = alloc::vec![ldr(1, sp(), RUNTIME_FRAME_PT_REGS_PTR_OFFSET)];
    body.extend(dispatch_site_from(1, &[movz(13, 0x4000)]));
    assert_eq!(Frag::new(&body).rule(), Some(VerifyRule::KernelValueAtEdge));
}

/// The verifier's template transfer function assumes, for every variant: x12 is the
/// only register that ever holds a kernel value in a template; every other word's
/// result is derived from T, the record's pc and the template's own earlier results;
/// no word but the key load reads x12 while writing another register; and x14/x15 are
/// written before they are read on every path (a miss branch taken or not). Checked
/// here on the words, per variant, from the generated operand metadata.
#[test]
fn template_register_discipline_holds_for_every_variant() {
    const SLOT: u32 = 1 << DISPATCH_SLOT_REG;
    const TARGET: u32 = 1 << DISPATCH_TARGET_REG;
    const KEY: u32 = 1 << DISPATCH_KEY_REG;
    const INDEX: u32 = 1 << DISPATCH_INDEX_REG;
    for id in 0..IBTC_VARIANT_COUNT {
        let variant = ibtc_variant_by_id(id).unwrap();
        let template = template_for(variant);
        for (position, insn) in template.words.iter().enumerate() {
            let read = rules::reads(insn).unwrap();
            let written = rules::writes(insn).unwrap();
            let is_edge = template.miss_at(position).is_some() || template.is_br(position);
            if is_edge {
                assert_eq!(written.gprs, 0);
                continue;
            }
            // Template words read only x12..x15 (and sp, for the table load).
            let allowed = SLOT | TARGET | KEY | INDEX;
            assert_eq!(read.gprs & !allowed, 0, "variant {id} word {position}");
            if written.gprs & SLOT != 0 {
                assert_eq!(written.gprs, SLOT, "variant {id} word {position}");
                // Never T into x12.
                assert_eq!(read.gprs & TARGET, 0, "variant {id} word {position}");
            } else {
                assert!(
                    written.gprs == KEY || written.gprs == INDEX,
                    "variant {id} word {position} writes {:#x}",
                    written.gprs
                );
                assert!(!written.sp && !read.sp, "variant {id} word {position}");
                // The key load is the one word that reads x12 (as the record base);
                // no other writer of x14/x15 uses a kernel value.
                let key_load = matches!(insn, A64Insn::LdrImmGenLdr64LdstPos { rt, mem }
                    if rt.enc() == DISPATCH_KEY_REG && mem.base().enc() == DISPATCH_SLOT_REG);
                assert!(key_load || read.gprs & SLOT == 0, "variant {id} word {position}");
            }
        }
        // Defined-before-read of x14/x15 on every path.
        fn walk(
            template: &crate::shared::abi::DispatchTemplate,
            position: usize,
            mut defined: u32,
            id: u8,
        ) {
            for position in position..template.len() {
                let insn = &template.words[position];
                let read = rules::reads(insn).unwrap().gprs & (KEY | INDEX);
                assert_eq!(read & !defined, 0, "variant {id} word {position} reads an undefined register");
                defined |= rules::writes(insn).unwrap().gprs & (KEY | INDEX);
                if let Some(miss) = template.miss_at(position) {
                    if miss.to < template.len() {
                        walk(template, miss.to, defined, id);
                    }
                }
                if template.is_br(position) {
                    return;
                }
            }
        }
        walk(template, 0, 0, id);
    }
}
'''
s=s[:a]+new
open(p,'w').write(s)
