p='/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/agent-a4b243dcf4b342be4/shared/abi/dispatch.rs'
s=open(p).read()

def rep(old, new):
    global s
    assert s.count(old) == 1, ("count", s.count(old), old[:70])
    s = s.replace(old, new)

rep('''pub fn ibtc_variant() -> IbtcVariant {
    VARIANTS[ibtc_variant_id() as usize]
}''','''pub fn ibtc_variant() -> IbtcVariant {
    VARIANTS[ibtc_variant_id() as usize]
}

/// The variant with this id, for code that handles every variant (tests).
pub fn ibtc_variant_by_id(id: u8) -> Option<IbtcVariant> {
    VARIANTS.get(id as usize).copied()
}''')

rep('''/// Words in one dispatch table (all ways and the victim table included).
pub fn ibtc_table_words() -> usize {
    match ibtc_variant() {
        IbtcVariant::Direct''','''/// Words in one dispatch table (all ways and the victim table included).
pub fn ibtc_table_words() -> usize {
    table_words(ibtc_variant())
}

pub fn table_words(variant: IbtcVariant) -> usize {
    match variant {
        IbtcVariant::Direct''')

rep('''pub fn ibtc_lookup_slots(pc: u64) -> ([usize; IBTC_MAX_PROBES], usize) {
    match ibtc_variant() {''','''pub fn ibtc_lookup_slots(pc: u64) -> ([usize; IBTC_MAX_PROBES], usize) {
    lookup_slots(ibtc_variant(), pc)
}

pub fn lookup_slots(variant: IbtcVariant, pc: u64) -> ([usize; IBTC_MAX_PROBES], usize) {
    match variant {''')

rep('''pub fn ibtc_plan_publish(pc: u64, resident: &dyn Fn(usize) -> Option<u64>) -> IbtcPlan {
    let (slots, probes) = ibtc_lookup_slots(pc);
    if slots[..probes].iter().any(|&slot| resident(slot) == Some(pc)) {
        return IbtcPlan::NONE;
    }
    match ibtc_variant() {''','''pub fn ibtc_plan_publish(pc: u64, resident: &dyn Fn(usize) -> Option<u64>) -> IbtcPlan {
    plan_publish(ibtc_variant(), pc, resident)
}

pub fn plan_publish(
    variant: IbtcVariant,
    pc: u64,
    resident: &dyn Fn(usize) -> Option<u64>,
) -> IbtcPlan {
    let (slots, probes) = lookup_slots(variant, pc);
    if slots[..probes].iter().any(|&slot| resident(slot) == Some(pc)) {
        return IbtcPlan::NONE;
    }
    match variant {''')
rep('''                let (old_slots, _) = ibtc_lookup_slots(old_pc);''','''                let (old_slots, _) = lookup_slots(variant, old_pc);''')

rep('''pub fn dispatch_template() -> &'static DispatchTemplate {
    match ibtc_variant() {''','''pub fn dispatch_template() -> &'static DispatchTemplate {
    template_for(ibtc_variant())
}

pub fn template_for(variant: IbtcVariant) -> &'static DispatchTemplate {
    match variant {''')

rep('''pub fn dispatch_template_matches(words: &[u32]) -> Option<MissDeltas> {
    let template = dispatch_template();
    if words.len()''','''pub fn dispatch_template_matches(words: &[u32]) -> Option<MissDeltas> {
    template_matches(dispatch_template(), words)
}

pub fn template_matches(template: &DispatchTemplate, words: &[u32]) -> Option<MissDeltas> {
    if words.len()''')

# tests: remove with_variant and use pure functions
a=s.index("    fn with_variant(id: u8, check: impl Fn()) {")
b=s.index("    #[test]\n    fn every_template_is_well_formed()")
s=s[:a]+s[b:]
a=s.index("    #[test]\n    fn every_template_is_well_formed()")
new_tests='''    fn all_variants() -> impl Iterator<Item = (u8, IbtcVariant)> {
        (0..IBTC_VARIANT_COUNT).map(|id| (id, ibtc_variant_by_id(id).unwrap()))
    }

    #[test]
    fn every_template_is_well_formed() {
        for (id, variant) in all_variants() {
            let template = template_for(variant);
            // Ends in a `br x12`; every `br` is `br x12`; the miss branches are
            // exactly the cbz x12 / cbnz x14 words, forward, to a probe start or
            // the exit group; probe starts follow a `br`.
            let len = template.len();
            assert!(template.is_br(len - 1), "variant {id}");
            for position in 0..len {
                let insn = template.words[position];
                match insn {
                    A64Insn::BrBr64BranchReg { rn } => assert_eq!(rn.enc(), SLOT),
                    A64Insn::CbzCbz64Compbranch { rt, .. } => {
                        assert_eq!(rt.enc(), SLOT);
                        assert!(template.miss_at(position).is_some());
                    }
                    A64Insn::CbnzCbnz64Compbranch { rt, .. } => {
                        assert_eq!(rt.enc(), KEY);
                        assert!(template.miss_at(position).is_some());
                    }
                    _ => assert!(template.miss_at(position).is_none()),
                }
            }
            for miss in template.misses {
                assert!(miss.to > miss.at && miss.to <= len);
                assert!(miss.to == len || template.is_br(miss.to - 1));
            }
            assert_eq!(template.misses.len() % 2, 0);
            assert!(template.misses.len() <= MAX_MISS_BRANCHES);
            assert!(len <= 24, "the verifier's MAX_TEMPLATE_WORDS");
            // One probe per looked-up slot.
            assert_eq!(
                (0..len).filter(|&position| template.is_br(position)).count(),
                lookup_slots(variant, 0x1000).1
            );
        }
    }

    #[test]
    fn lookup_slots_are_bounded_and_victim_indices_differ_for_aliasing_pcs() {
        for (id, variant) in all_variants() {
            let words = table_words(variant);
            for pc in [0u64, 4, 0x1000, 0x4000, 0xffff_ffff_fffc, 0xaaaa_bbbb_cccc, u64::MAX & !3] {
                let (slots, n) = lookup_slots(variant, pc);
                assert!((1..=IBTC_MAX_PROBES).contains(&n));
                for &slot in &slots[..n] {
                    assert!(slot < words, "variant {id}, pc {pc:#x}");
                }
            }
        }
        // Variants 1, 4 and 5 separate pcs that share pc[13:2] (a main-table alias)
        // and differ by a small number of 16 KiB units.
        let slot = |id: u8, pc: u64, probe: usize| {
            lookup_slots(ibtc_variant_by_id(id).unwrap(), pc).0[probe]
        };
        assert_eq!(slot(0, 0x10000, 0), slot(0, 0x14000, 0));
        assert_ne!(slot(1, 0x10000, 0), slot(1, 0x14000, 0));
        for id in [4, 5] {
            assert_eq!(slot(id, 0x10000, 0), slot(id, 0x14000, 0));
            assert_ne!(slot(id, 0x10000, 1), slot(id, 0x14000, 1));
        }
    }

    #[test]
    fn publish_plans_follow_the_policy() {
        let table = std::cell::RefCell::new(std::collections::BTreeMap::<usize, u64>::new());
        let resident = |slot: usize| table.borrow().get(&slot).copied();
        let publish = |variant: IbtcVariant, pc: u64| {
            let plan = plan_publish(variant, pc, &resident);
            for store in plan.stores() {
                let value = match store.src {
                    IbtcSource::New => pc,
                    IbtcSource::Slot(slot) => table.borrow()[&slot],
                };
                table.borrow_mut().insert(store.dst, value);
            }
            plan.len
        };
        let by_id = |id| ibtc_variant_by_id(id).unwrap();
        let (a, b, c) = (0x10000u64, 0x14000u64, 0x18000u64);

        let direct = by_id(0);
        table.borrow_mut().clear();
        assert_eq!(publish(direct, a), 1);
        assert_eq!(publish(direct, a), 0, "same pc kept");
        publish(direct, b);
        assert_eq!(table.borrow()[&lookup_slots(direct, a).0[0]], b, "last writer wins");

        let two_way = by_id(2);
        table.borrow_mut().clear();
        let (slots, _) = lookup_slots(two_way, a);
        publish(two_way, a);
        publish(two_way, b);
        assert_eq!((table.borrow()[&slots[0]], table.borrow()[&slots[1]]), (a, b));
        assert_eq!(publish(two_way, b), 0);
        // Both full: way 0 moves to way 1, the new record is way 0.
        publish(two_way, c);
        assert_eq!((table.borrow()[&slots[0]], table.borrow()[&slots[1]]), (c, a));

        let victim = by_id(4);
        table.borrow_mut().clear();
        let main = lookup_slots(victim, a).0[0];
        publish(victim, a);
        publish(victim, b);
        assert_eq!(table.borrow()[&main], b);
        assert_eq!(table.borrow()[&lookup_slots(victim, a).0[1]], a, "evicted into the victim");
        assert_eq!(publish(victim, a), 0, "a is live in the victim table");
    }
}
'''
s=s[:a]+new_tests
open(p,'w').write(s)

# mod.rs exports
p2='/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/agent-a4b243dcf4b342be4/shared/abi/mod.rs'
m=open(p2).read()
m=m.replace('''    dispatch_template, dispatch_template_matches, ibtc_lookup_slots, ibtc_plan_publish,
    ibtc_table_bytes, ibtc_table_words, ibtc_variant, ibtc_variant_id, select_ibtc_variant,''','''    dispatch_template, dispatch_template_matches, ibtc_lookup_slots, ibtc_plan_publish,
    ibtc_table_bytes, ibtc_table_words, ibtc_variant, ibtc_variant_by_id, ibtc_variant_id,
    lookup_slots, plan_publish, select_ibtc_variant, table_words, template_for,
    template_matches,''')
open(p2,'w').write(m)
