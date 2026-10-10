base='/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/agent-a4b243dcf4b342be4/'
def edit(path, pairs):
    s=open(base+path).read()
    for old,new in pairs:
        assert s.count(old)==1, (path, s.count(old), old[:80])
        s=s.replace(old,new)
    open(base+path,'w').write(s)

edit('runtime/mod.rs', [('''/// Registers the syscall hook and creates `/sys/kernel/debug/kjit/`.
pub(crate) fn init() -> Result {''','''/// Selects the dispatch variant from the `ibtc_variant` module parameter
/// (`kjit_glue.c`). Must run before the first translation, verification or table:
/// the template, the verifier's accepted words and the table layout all follow it.
pub(crate) fn select_ibtc_variant() -> Result {
    // SAFETY: a plain read of a module parameter.
    let id = unsafe { ffi::kjit_glue_ibtc_variant() };
    match u8::try_from(id) {
        Ok(id) if crate::shared::abi::select_ibtc_variant(id) => {
            pr_info!("kjit: dispatch variant {id}\\n");
            Ok(())
        }
        _ => {
            pr_err!(
                "kjit: ibtc_variant={id} is not a variant (0..={})\\n",
                crate::shared::abi::IBTC_VARIANT_COUNT - 1
            );
            Err(EINVAL)
        }
    }
}

/// Registers the syscall hook and creates `/sys/kernel/debug/kjit/`.
pub(crate) fn init() -> Result {''')])

edit('rust_kjit.rs', [('''    let expected = &golden::GOLDEN_FRAGMENT_BYTES;
    let mut offset = 0usize;''','''    // The golden bytes embed variant 0's dispatch template. For another variant the
    // fragment is still translated and encoded (above and below), but the bytes
    // cannot equal the reference: the comparison is skipped, and the verifier's
    // acceptance of the variant's own template is what the guest tests exercise.
    if shared::abi::ibtc_variant_id() != 0 {
        for insn in fragment.insns.iter() {
            if let Err(err) = insn.encode() {
                pr_err!("golden {name}:{symbol} FAIL: encode: {err:?}\\n");
                return Err(EINVAL);
            }
        }
        pr_info!(
            "golden {name}:{symbol} translated for dispatch variant {}; byte comparison skipped (reference is variant 0)\\n",
            shared::abi::ibtc_variant_id()
        );
        return Ok(());
    }
    let expected = &golden::GOLDEN_FRAGMENT_BYTES;
    let mut offset = 0usize;'''),
('''        pr_info!("######## Rust KJIT inits ########\\n");
        check_golden()?;''','''        pr_info!("######## Rust KJIT inits ########\\n");
        runtime::select_ibtc_variant()?;
        check_golden()?;''')])
