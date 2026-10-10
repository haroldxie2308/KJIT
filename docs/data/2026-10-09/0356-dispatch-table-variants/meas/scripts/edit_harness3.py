base='/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/agent-a4b243dcf4b342be4/harness/src/'
def edit(path, pairs):
    s=open(base+path).read()
    for old,new in pairs:
        assert s.count(old)>=1, (path, s.count(old), old[:80])
        s=s.replace(old,new)
    open(base+path,'w').write(s)
edit('dispatch_tests.rs', [
('''use crate::shared::abi::RetStatus;''','''use crate::shared::abi::{ibtc_variant, IbtcVariant, RetStatus};'''),
('''/// Two callees 16 KiB apart share a table slot: every call finds the other
/// callee's record, so it misses and the runtime's resolution replaces the slot.
/// The warm run misses just the same.
#[test]
fn aliasing_targets_replace_each_others_slot_and_keep_missing() {
    let (_, cold, warm, _, cache) = cold_and_warm("dispatch_alias", "alias_blr_mark");
    // 8 iterations x 2 calls, each a replace after the first of each callee.
    assert!(cache.stats.ibtc_replace >= 14, "{:?}", cache.stats);
    assert!(cold.runtime_entries >= 14, "{}", cold.runtime_entries);
    assert!(
        warm.runtime_entries >= 14,
        "the warm run still ping-pongs: {} runtime entries",
        warm.runtime_entries
    );
    cache.check_invariants().unwrap();
}''','''/// Two callees 16 KiB apart share a main-table slot (and a two-way set). Direct
/// mapped, every call finds the other callee's record, so it misses and the
/// runtime's resolution replaces the slot; the warm run misses just the same. The
/// hash variant puts them in different slots, the two-way variants in the two ways
/// of the set, the victim variants keep the replaced one in the victim table: after
/// the cold run's two resolutions every call of the warm run hits.
#[test]
fn aliasing_targets_ping_pong_only_when_direct_mapped() {
    let (_, cold, warm, _, cache) = cold_and_warm("dispatch_alias", "alias_blr_mark");
    if ibtc_variant() == IbtcVariant::Direct {
        // 8 iterations x 2 calls, each a replace after the first of each callee.
        assert!(cache.stats.ibtc_replace >= 14, "{:?}", cache.stats);
        assert!(cold.runtime_entries >= 14, "{}", cold.runtime_entries);
        assert!(
            warm.runtime_entries >= 14,
            "the warm run still ping-pongs: {} runtime entries",
            warm.runtime_entries
        );
    } else {
        assert!(
            cold.runtime_entries < 14,
            "{:?}: cold run took {} runtime entries",
            ibtc_variant(),
            cold.runtime_entries
        );
        assert_eq!(warm.runtime_entries, 0, "{:?}", ibtc_variant());
    }
    cache.check_invariants().unwrap();
}'''),
('''    assert_eq!(cache.slot_target(true, entry).map(|(frag, _)| frag), Some(fp));
    assert_eq!(cache.slot_target(false, entry), None);''','''    assert_eq!(cache.lookup(true, entry), Some(fp));
    assert_eq!(cache.lookup(false, entry), None);'''),
('''    assert!(cache.slot_target(false, func_f).is_some(), "func_f was published");''','''    assert!(cache.lookup(false, func_f).is_some(), "func_f was published");'''),
('''    assert!(cache.slot_target(true, func_f).is_none());
    assert!(cache.slot_target(false, func_f).is_none());''','''    assert!(cache.lookup(true, func_f).is_none());
    assert!(cache.lookup(false, func_f).is_none());'''),
('''    assert!(cache.slot_target(false, func_f).is_some(), "and is published again");''','''    assert!(cache.lookup(false, func_f).is_some(), "and is published again");'''),
])
