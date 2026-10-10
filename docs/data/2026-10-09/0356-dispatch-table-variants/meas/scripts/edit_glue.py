p='/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/agent-a4b243dcf4b342be4/kjit_glue.c'
s=open(p).read()
def rep(old,new):
    global s
    assert s.count(old)==1, (s.count(old), old[:80])
    s=s.replace(old,new)

rep('''size_t kjit_rs_ibtc_slots_show(char *buf, size_t len);
void kjit_rs_ibtc_slots_reset(void);''','''size_t kjit_rs_ibtc_slots_show(char *buf, size_t len);
void kjit_rs_ibtc_slots_reset(void);

/*
 * Dispatch-table layout and publish policy of the selected variant
 * (runtime/ibtc.rs over shared::abi): table size, the slots a pc may sit in,
 * and the stores that publish a record. struct kjit_ibtc_store mirrors
 * IbtcStoreC.
 */
struct kjit_ibtc_store {
	u32 dst;	/* table word to store into */
	u32 src;	/* KJIT_IBTC_SRC_NEW, or the table word whose record moves */
};
#define KJIT_IBTC_SRC_NEW U32_MAX
size_t kjit_rs_ibtc_table_bytes(void);
u32 kjit_rs_ibtc_plan_publish(const u64 *table, u64 pc, struct kjit_ibtc_store *out);
u32 kjit_rs_ibtc_lookup_slots(u64 pc, u32 *out);''')

rep('''/*
 * Dispatch tables (IBTC): per kjit_mm, direct mapped, 2^KJIT_IBTC_BITS slots
 * indexed by pc[13:2]; a slot is 0 or a record of a live fragment of that mm.
 * Same constants as the dispatch template (shared/abi), pinned by an assertion
 * in runtime/ffi.rs.
 */
#define KJIT_IBTC_BITS 12
#define KJIT_IBTC_SLOTS (1U << KJIT_IBTC_BITS)

static inline u32 kjit_ibtc_index(u64 pc)
{
	return (pc >> 2) & (KJIT_IBTC_SLOTS - 1);
}
''','''/*
 * Dispatch tables (IBTC): per kjit_mm, kjit_rs_ibtc_table_bytes() bytes of
 * 8-byte slots; a slot is 0 or a record of a live fragment of that mm. Which
 * slots a pc may sit in, the table size and the publish policy are the selected
 * dispatch variant's (shared/abi dispatch, reached through kjit_rs_ibtc_*); the
 * record layout is pinned by an assertion in runtime/ffi.rs.
 *
 * The variant is a module parameter, fixed at build time per module binary for
 * the guest tests (-DKJIT_IBTC_DEFAULT=n via KCFLAGS) and read-only at run time:
 * the tables of an mm cannot change layout once allocated.
 */
#ifndef KJIT_IBTC_DEFAULT
#define KJIT_IBTC_DEFAULT 0
#endif
static unsigned int kjit_ibtc_variant = KJIT_IBTC_DEFAULT;
module_param_named(ibtc_variant, kjit_ibtc_variant, uint, 0444);
MODULE_PARM_DESC(ibtc_variant, "Dispatch variant: 0 direct, 1 hash, 2 two-way 2048 sets, 3 two-way 4096 sets, 4 victim 256, 5 victim 512");

u32 kjit_glue_ibtc_variant(void)
{
	return kjit_ibtc_variant;
}
''')

rep('''	for (i = 0; i < f->n_labels; i++) {
		struct kjit_label *label = &f->labels[i];
		u32 idx = kjit_ibtc_index(label->pc);

		if (kmm->table_all[idx] == label) {
			WRITE_ONCE(kmm->table_all[idx], NULL);
			cleared++;
		}
		if (kmm->table_nofp[idx] == label) {
			WRITE_ONCE(kmm->table_nofp[idx], NULL);
			cleared++;
		}
	}''','''	for (i = 0; i < f->n_labels; i++) {
		struct kjit_label *label = &f->labels[i];
		u32 slots[2], n, j;

		/* Every slot the variant may have put a record of this pc in. */
		n = kjit_rs_ibtc_lookup_slots(label->pc, slots);
		for (j = 0; j < n; j++) {
			if (kmm->table_all[slots[j]] == label) {
				WRITE_ONCE(kmm->table_all[slots[j]], NULL);
				cleared++;
			}
			if (kmm->table_nofp[slots[j]] == label) {
				WRITE_ONCE(kmm->table_nofp[slots[j]], NULL);
				cleared++;
			}
		}
	}''')

a=s.index("/* Stores @label into @table's slot @idx under kmm->lock; counts insert and replace. */")
b=s.index("/*\n * A branch exit's target @pc resolved to @f, the fragment the run is in:")
new='''/*
 * Publishes @label into @table under kmm->lock with the variant's publish
 * policy (kjit_rs_ibtc_plan_publish): up to two slot stores, performed in the
 * planned order (a record that moves is stored at its new slot before its old
 * slot is overwritten, so a concurrent probe of its pc finds it in one of the
 * two). Counts insert (a slot store) and replace (a store over another record).
 */
static void kjit_ibtc_store_locked(struct kjit_label **table, struct kjit_label *label)
{
	struct kjit_ibtc_store stores[2];
	u32 n = kjit_rs_ibtc_plan_publish((const u64 *)table, label->pc, stores);
	u32 i;

	/*
	 * An empty plan: any live record for the same pc is equivalent (every
	 * fragment's label for a pc enters a translation of the same text, and a
	 * retired one is no longer in a slot). Replacing it would only make two
	 * fragments sharing a pc take turns in the slot, one lock round trip per
	 * resolution.
	 */
	for (i = 0; i < n; i++) {
		struct kjit_label *old = table[stores[i].dst];
		struct kjit_label *value = stores[i].src == KJIT_IBTC_SRC_NEW ?
					   label : table[stores[i].src];

		/*
		 * Fragment code reads slot -> record -> fields through address
		 * dependencies, no barrier of its own; the release orders the
		 * store after everything that made the record valid.
		 */
		smp_store_release(&table[stores[i].dst], value);
		kjit_rs_note(KJIT_NOTE_IBTC_INSERT, 1);
		if (old)
			kjit_rs_note(KJIT_NOTE_IBTC_REPLACE, 1);
	}
}

/*
 * A branch exit's target resolved to @label of @f: publishes it in the
 * dispatch tables it belongs to (always table_all, table_nofp unless @f uses
 * FP/SIMD), so the next transfer to its pc from a run of that class hits
 * inside fragment code. The variant decides where (kjit_ibtc_store_locked()).
 * Nothing is published for a retired fragment.
 *
 * Must run in the hook call that found @f (it keeps @f allocated).
 */
static void kjit_ibtc_publish(struct kjit_frag *f, struct kjit_label *label)
{
	struct kjit_mm *kmm = f->kmm;
	struct kjit_ibtc_store scratch[2];

	/*
	 * Each table it belongs in already has a record for this pc (an empty
	 * plan, see kjit_ibtc_store_locked()): nothing to store, so no lock.
	 * Dereferencing a slot's record is safe here: it is retired at the
	 * earliest now, and freed only after this hook call. A retire racing with
	 * this clears the slot under the lock; seeing it set here changes no
	 * state.
	 */
	if (!kjit_rs_ibtc_plan_publish((const u64 *)kmm->table_all, label->pc, scratch) &&
	    (f->uses_fpsimd ||
	     !kjit_rs_ibtc_plan_publish((const u64 *)kmm->table_nofp, label->pc, scratch)))
		return;
	spin_lock(&kmm->lock);
	if (!f->retired) {
		kjit_ibtc_store_locked(kmm->table_all, label);
		if (!f->uses_fpsimd)
			kjit_ibtc_store_locked(kmm->table_nofp, label);
	}
	spin_unlock(&kmm->lock);
}

'''
s=s[:a]+new+s[b:]

rep('''	if (!READ_ONCE(kmm->table_all)) {
		new_all = kvzalloc(KJIT_IBTC_SLOTS * sizeof(*new_all), GFP_KERNEL);
		new_nofp = kvzalloc(KJIT_IBTC_SLOTS * sizeof(*new_nofp), GFP_KERNEL);''','''	if (!READ_ONCE(kmm->table_all)) {
		new_all = kvzalloc(kjit_rs_ibtc_table_bytes(), GFP_KERNEL);
		new_nofp = kvzalloc(kjit_rs_ibtc_table_bytes(), GFP_KERNEL);''')
open(p,'w').write(s)
