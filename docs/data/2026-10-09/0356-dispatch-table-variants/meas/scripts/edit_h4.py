base='/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/agent-a4b243dcf4b342be4/harness/src/'
def edit(path, pairs):
    s=open(base+path).read()
    for old,new in pairs:
        assert s.count(old)==1, (path, s.count(old), old[:80])
        s=s.replace(old,new)
    open(base+path,'w').write(s)

edit('golden.rs', [('''    #[test]
    fn kernel_golden_matches_harness_output() {
        let fragment''','''    #[test]
    fn kernel_golden_matches_harness_output() {
        // The reference embeds dispatch variant 0's template (the kernel module
        // skips the byte comparison for other variants, rust_kjit.rs).
        if crate::shared::abi::ibtc_variant_id() != 0 {
            println!(
                "kernel golden skipped: dispatch variant {} (the reference is variant 0)",
                crate::shared::abi::ibtc_variant_id()
            );
            return;
        }
        let fragment''')])

edit('verify_mutation_tests.rs', [
('''    in_bounds_runtime_access: usize,
    escapes: Vec<String>,
}''','''    in_bounds_runtime_access: usize,
    /// An unprivileged load/store replacing a word at a fault-site entry: a user
    /// access with its fault edge, which rule 3 only asks to exist.
    user_access_at_fault_site: usize,
    escapes: Vec<String>,
}'''),
('''            } else if insn.is_some_and(is_offset_runtime_access) {
                self.random.in_bounds_runtime_access += 1;
            } else if self.random.escapes.len() < 10 {''','''            } else if insn.is_some_and(is_offset_runtime_access) {
                self.random.in_bounds_runtime_access += 1;
            } else if insn.is_some_and(|insn| insn.is_unprivileged_access())
                && fixture
                    .tables
                    .fault_sites
                    .iter()
                    .any(|site| site.access_offset == index * 4)
            {
                self.random.user_access_at_fault_site += 1;
            } else if self.random.escapes.len() < 10 {'''),
('''        "| random body word | rejected {} / benign ALU {} / in-fragment branch {} / in-bounds runtime access {} / other accepted {} of {} | |",
        random.rejected,
        random.benign_alu,
        random.in_fragment_branch,
        random.in_bounds_runtime_access,''','''        "| random body word | rejected {} / benign ALU {} / in-fragment branch {} / in-bounds runtime access {} / user access at a fault site {} / other accepted {} of {} | |",
        random.rejected,
        random.benign_alu,
        random.in_fragment_branch,
        random.in_bounds_runtime_access,
        random.user_access_at_fault_site,'''),
])
