base='/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/agent-a4b243dcf4b342be4/harness/src/'
def edit(path, pairs):
    s=open(base+path).read()
    for old,new in pairs:
        assert s.count(old)>=1, (path, s.count(old), old[:80])
        s=s.replace(old,new)
    open(base+path,'w').write(s)

edit('runtime.rs', [
('''    EXTRA_PARAMS_BYTES, EXTRA_PARAM_IBTC_TABLE_OFFSET, IBTC_TABLE_BYTES, PROLOGUE_LEN_BYTES,''','''    ibtc_table_bytes, EXTRA_PARAMS_BYTES, EXTRA_PARAM_IBTC_TABLE_OFFSET, PROLOGUE_LEN_BYTES,'''),
('''/// The dispatch tables and records (A11), in runtime-owned memory below the extra
/// params page and above the code space (`DEFAULT_BASE_PC` up).
pub const DEFAULT_CACHE_LAYOUT: CacheLayout = CacheLayout {
    table_all: 0x600000,
    table_nofp: 0x600000 + IBTC_TABLE_BYTES as u64,
    records: 0x600000 + 2 * IBTC_TABLE_BYTES as u64,
    records_len: 0x40000,
};''','''/// The dispatch tables and records (A11), in runtime-owned memory below the extra
/// params page and above the code space (`DEFAULT_BASE_PC` up). The tables' size
/// depends on the selected dispatch variant.
pub fn default_cache_layout() -> CacheLayout {
    let table_bytes = ibtc_table_bytes() as u64;
    CacheLayout {
        table_all: 0x600000,
        table_nofp: 0x600000 + table_bytes,
        records: 0x600000 + 2 * table_bytes,
        records_len: 0x40000,
    }
}'''),
('''            DEFAULT_CACHE_LAYOUT,
            None,''','''            default_cache_layout(),
            None,'''),
])
edit('cached_run.rs', [
('''    URuntime, URuntimeConfig, URuntimeHalt, URuntimeReport, DEFAULT_BASE_PC, DEFAULT_CACHE_LAYOUT,
};''','''    default_cache_layout, URuntime, URuntimeConfig, URuntimeHalt, URuntimeReport, DEFAULT_BASE_PC,
};'''),
('''        DEFAULT_CACHE_LAYOUT,
        Some(MockCodeProvider''','''        default_cache_layout(),
        Some(MockCodeProvider'''),
])
edit('native.rs', [
('''    pt_regs_x_slot_offset, EXTRA_PARAMS_WORDS, EXTRA_PARAM_IBTC_TABLE_INDEX, IBTC_SLOTS,
    IBTC_TABLE_BYTES,''','''    ibtc_table_bytes, ibtc_table_words, pt_regs_x_slot_offset, EXTRA_PARAMS_WORDS,
    EXTRA_PARAM_IBTC_TABLE_INDEX,'''),
('''    let empty_table = vec![0u64; IBTC_SLOTS];''','''    let empty_table = vec![0u64; ibtc_table_words()];'''),
('''            2 * IBTC_TABLE_BYTES + NATIVE_RECORDS_BYTES,''','''            2 * ibtc_table_bytes() + NATIVE_RECORDS_BYTES,'''),
('''            table_nofp: memory.base() + IBTC_TABLE_BYTES as u64,
            records: memory.base() + 2 * IBTC_TABLE_BYTES as u64,''','''            table_nofp: memory.base() + ibtc_table_bytes() as u64,
            records: memory.base() + 2 * ibtc_table_bytes() as u64,'''),
])
