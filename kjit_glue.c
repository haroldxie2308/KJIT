// SPDX-License-Identifier: GPL-2.0
/*
 * KJIT K2 runtime: kernel-object glue for rust_kjit.rs.
 *
 * Rust owns translation, verification, the image contents, the exit decision
 * table and the statistics (runtime/). This file owns what has no Rust binding
 * and what must interoperate with C-side lifetimes: the hook registration
 * (kernel-patches/0001, 0002), the per-mm code cache and its mmu_notifier,
 * fragment memory (the packed image arena, the arm64 exception table), reading
 * the target's user text, the call trampoline, the auto-mode profiler and its
 * task_work requests (kernel-patches/0004), the FP/SIMD bracket around
 * fragments that use the user's FP/SIMD registers (kernel-patches/0005), and
 * the debugfs files.
 * Design notes: docs/pipeline.md, "Kernel runtime (K2)", "Automatic hot-path
 * detection (K3)", "FP/SIMD in fragments (A9)" and "In-fragment branch dispatch
 * (A11)".
 *
 * Lifetimes and locking
 *
 *   kjit_mm   One per mm with at least one translation request, or (auto mode)
 *             one eligible syscall; embeds the mmu_notifier
 *             (mmu_notifier_get/put), the mm's profile table and, from its
 *             first install on, the two dispatch tables (A11). Found from the
 *             syscall path
 *             through kjit_mm_hash (RCU). The hash membership owns exactly
 *             one notifier reference; whoever unhashes it (mm release or
 *             module exit, under kjit_mm_lock) drops it. Freed by
 *             free_notifier after the notifier SRCU grace period, then (when
 *             it has tables) after a hook-SRCU grace period, which covers the
 *             runs that read them, then kvfree_rcu for the hash readers.
 *   kjit_frag One installed translation. Retired (under kjit_mm.lock) when it
 *             is removed from its kjit_mm: out of the table and the dispatch
 *             tables, then freed after a grace period of the hook's SRCU
 *             (kernel-patches/0007). Every execution of a fragment, chained
 *             or dispatched into, is inside one hook call, which is inside
 *             that SRCU's read section, so nothing else protects a run. The
 *             SRCU callback takes it off kjit_all_frags (the extable search
 *             list, RCU), so a fragment removed while it runs still has its
 *             fault fixups, and queues the image's free (an RCU work item:
 *             the slot is filled with BRK and released in process context).
 *   Image arena (A17): a fragment's image is a slot (code, then its extable)
 *             of one shared arena of 2 MiB ROX chunks, first fit under
 *             kjit_arena_lock (a mutex over the chunk list and the bitmaps;
 *             never held together with kjit_mm.lock or kjit_frags_lock). A
 *             chunk is filled with BRK and made ROX once; slots are written
 *             with aarch64_insn_copy() (kernel-patches/0009) at install and
 *             filled with BRK by aarch64_insn_set() when the free work
 *             releases them. Both flush the I-cache and IPI every CPU, so
 *             slots are only written from process context, no spinlock held,
 *             interrupts on. A slot is invisible until kjit_install()
 *             publishes the fragment under kjit_mm.lock; after that its words
 *             change only by link patches (A16), until the retired fragment's
 *             free work, which runs after a hook-SRCU grace period.
 *   Direct BL links (A16): a static BL site's `nop` slot is patched to a `b`
 *             into another fragment (or its own) of the same kjit_mm, and back,
 *             under kjit_mm.lock only (struct kjit_link, kjit_link_*()). A run
 *             that took the `b` is inside the hook SRCU like any other, so the
 *             target is freed only after the restore that retire does first.
 *   kjit_request  One queued auto-mode translation (task_work). Holds no
 *             reference: it names its kjit_mm by (mm, id) and finds it again
 *             under RCU, and it runs through the kernel's
 *             kjit_queue_task_work(), which frees it instead of calling in
 *             here once this module is unregistered.
 *   Lock order: kjit_mm.lock -> kjit_frags_lock. kjit_mm_lock and
 *             kjit_arena_lock are never held together with either. None of the
 *             spinlocks is held across an allocation (they are taken inside
 *             mmu_notifier invalidation).
 */
#include <linux/atomic.h>
#include <linux/bitfield.h>
#include <linux/bitmap.h>
#include <linux/bottom_half.h>
#include <linux/cacheflush.h>
#include <linux/compat.h>
#include <linux/cpuhotplug.h>
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/execmem.h>
#include <linux/extable.h>
#include <linux/hash.h>
#include <linux/hashtable.h>
#include <linux/highmem.h>
#include <linux/hrtimer.h>
#include <linux/kjit.h>
#include <linux/math64.h>
#include <linux/mm.h>
#include <linux/mmu_notifier.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/pid.h>
#include <linux/rculist.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/set_memory.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

#include <asm/arch_timer.h>
#include <asm/asm-extable.h>
#include <asm/cpufeature.h>
#include <asm/fpsimd.h>
#include <asm/insn.h>
#include <asm/neon.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/simd.h>
#include <asm/sysreg.h>
#include <asm/text-patching.h>

#include <clocksource/arm_arch_timer.h>

#include <linux/irq-entry-common.h>

/* shared/abi and runtime/exec.rs read pt_regs through these offsets. */
static_assert(offsetof(struct pt_regs, regs) == 0);
static_assert(offsetof(struct pt_regs, sp) == 248);
static_assert(offsetof(struct pt_regs, pc) == 256);
static_assert(offsetof(struct pt_regs, pstate) == 264);
static_assert(sizeof(struct exception_table_entry) == 12);

/*
 * The FP/SIMD bracket (kjit_call_fragment_fpsimd) is a task-level
 * kernel_neon_begin() section that is preempted and migrated like any task.
 * A softirq kernel-mode NEON section that interrupts it nests into the task's
 * with a buffer of its own; on PREEMPT_RT kernel_neon_begin() BUGs on that
 * (the nested path asserts !PREEMPT_RT).
 */
#ifdef CONFIG_PREEMPT_RT
#error "kjit: the FP/SIMD fragment bracket assumes !PREEMPT_RT"
#endif

/* ------------------------------------------------------------------------- */
/* Rust side (runtime/)                                                        */

struct kjit_mm;
long kjit_rs_after_syscall(struct pt_regs *regs);
int kjit_rs_translate(struct kjit_mm *kmm, u64 pc, bool verbose, u32 *entry_word);
size_t kjit_rs_stats_show(char *buf, size_t len);
size_t kjit_rs_unsupported_show(char *buf, size_t len);
size_t kjit_rs_ibtc_slots_show(char *buf, size_t len);
void kjit_rs_ibtc_slots_reset(void);

/*
 * Dispatch-table slot planning (shared/abi dispatch.rs, reached through
 * runtime/ibtc.rs): the slots a pc may sit in (main, then victim) and the
 * stores that publish a record. struct kjit_ibtc_store mirrors IbtcStoreC.
 */
struct kjit_ibtc_store {
	u32 dst;	/* table word to store into */
	u32 src;	/* KJIT_IBTC_SRC_NEW, or the table word whose record moves */
};
#define KJIT_IBTC_SRC_NEW U32_MAX
u32 kjit_rs_ibtc_plan_publish(const u64 *table, u64 pc, struct kjit_ibtc_store *out);
void kjit_rs_ibtc_lookup_slots(u64 pc, u32 *out);
void kjit_rs_note_entry_stop(u32 word);
/* shared/abi link.rs (runtime/link.rs): `b <host>` for a slot at @slot_addr, or false if out of range. */
bool kjit_rs_link_branch_word(u64 slot_addr, u64 host, u32 *word);

/* Counters this file bumps: runtime/stats.rs, enum Note (same values). */
enum kjit_note {
	KJIT_NOTE_INVALIDATED = 0,	/* fragments removed by an invalidation */
	KJIT_NOTE_RELEASED = 1,		/* fragments removed at mm/module teardown */
	KJIT_NOTE_SVC_SITES = 2,	/* SVC words found by translate_svc_sites */
	KJIT_NOTE_MM_CREATED = 3,	/* kjit_mm set up by the auto profiler */
	KJIT_NOTE_MM_SETUP_FAILED = 4,	/* ... and failed (retried next syscall) */
	KJIT_NOTE_PROF_FULL = 5,	/* hit dropped: no free profile slot */
	KJIT_NOTE_HOT_NEGATIVE = 6,	/* hot PC in the negative cache */
	KJIT_NOTE_HOT_CAPPED = 7,	/* hot PC, but a fragment cap is reached */
	KJIT_NOTE_HOT_QUEUE_FULL = 8,	/* hot PC, but the mm has too many requests */
	KJIT_NOTE_REQ_SVC_RESUME = 9,	/* request queued for a syscall resume PC */
	KJIT_NOTE_REQ_EXIT_TARGET = 10,	/* request queued for a branch-exit target */
	KJIT_NOTE_REQ_DROPPED = 11,	/* request not queued (no memory, exiting) */
	KJIT_NOTE_REQ_STALE = 12,	/* request ran after exec/exit/auto off */
	KJIT_NOTE_NEG_ADDED = 13,	/* PC added to the negative cache */
	KJIT_NOTE_NEG_EVICTED = 14,	/* ... evicting an older one */
	KJIT_NOTE_TRANSLATE_NS = 15,	/* time spent in auto-mode translations */
	KJIT_NOTE_FPSIMD_PREEMPTED = 16,	/* FP/SIMD brackets the task was switched out in */
	KJIT_NOTE_IBTC_INSERT = 17,	/* dispatch-table slot stores */
	KJIT_NOTE_IBTC_REPLACE = 18,	/* ... that replaced another record */
	KJIT_NOTE_IBTC_CLEAR = 19,	/* slots cleared by a fragment's retirement */
	KJIT_NOTE_LINK_MADE = 20,	/* link slots patched nop -> b */
	KJIT_NOTE_LINK_RESTORED = 21,	/* ... and b -> nop by a retirement */
	KJIT_NOTE_LINK_OUT_OF_RANGE = 22,	/* link attempts no in-range label took */
	KJIT_NOTE_LINK_CLASS_REFUSED = 23,	/* link attempts only an FP/SIMD label could take */
};
void kjit_rs_note(u32 note, u64 n);

/* ------------------------------------------------------------------------- */
/* Types and functions shared with runtime/ffi.rs (keep in sync).              */

struct kjit_frag;
struct kjit_site;
struct kjit_entry;
struct kjit_link_site;
int kjit_glue_init(void);
void kjit_glue_exit(void);
u64 kjit_mm_seq(struct kjit_mm *kmm);
int kjit_read_text_page(struct kjit_mm *kmm, u64 addr, u8 *buf);
int kjit_install(struct kjit_mm *kmm, u64 seq, u64 entry_pc,
		 const u8 *code, u32 code_len, u32 entry_offset,
		 const struct kjit_site *sites, u32 n_sites,
		 const struct kjit_entry *entries, u32 n_entries,
		 const struct kjit_link_site *links, u32 n_links,
		 u64 src_start, u64 src_end, bool uses_fpsimd);
bool kjit_fpsimd_supported(void);
bool kjit_can_run(const struct pt_regs *regs);
struct kjit_frag *kjit_lookup(u64 pc, bool link, u64 *entry);
u64 kjit_frag_base(const struct kjit_frag *f);
u64 kjit_frag_link(struct kjit_frag *f, u64 pc);
u64 kjit_frag_table(const struct kjit_frag *f);
bool kjit_frag_uses_fpsimd(const struct kjit_frag *f);
void kjit_bad_status(u64 status, u64 pc);
u64 kjit_call_fragment(struct pt_regs *regs, u64 *extra, u64 entry, u64 base);
bool kjit_call_fragment_fpsimd(struct pt_regs *regs, u64 *extra, u64 entry, u64 base,
			       u64 *status);
u64 kjit_fpsimd_run_max_ns(void);
void kjit_profile(u64 pc, u32 kind);
u64 kjit_hook_calls(void);
u32 kjit_chain_budget(void);

/* kjit_profile()'s @kind: where the profiled PC came from. */
enum kjit_hot_kind {
	KJIT_HOT_SVC_RESUME = 0,	/* regs->pc after a syscall */
	KJIT_HOT_EXIT_TARGET = 1,	/* target of a Bl/Blr/Br/Ret exit */
};

/* One fault site: a user access at code offset @access resumes at @stub. */
struct kjit_site {
	u32 access;
	u32 stub;
};

/* A verified entry as the runtime passes it to kjit_install(). Sorted by @pc. */
struct kjit_entry {
	u64 pc;
	u32 offset;
	u32 pad;
};

/* A static BL site's link slot (A16): the `nop` at code offset @slot, for a BL to @target_pc. */
struct kjit_link_site {
	u32 slot;
	u32 pad;
	u64 target_pc;
};

/*
 * A verified entry of an installed fragment: the user PC and the absolute
 * address of its code (image + a verified entry offset). Immutable after
 * install and sorted by @pc in kjit_frag.labels. It is also the record the
 * dispatch tables point to, which fragment code reads (docs/pipeline.md,
 * "In-fragment branch dispatch (A11)"): the layout is part of the dispatch template, so @pc is
 * first and @host second. @by_pc and @frag serve the link bookkeeping (A16).
 */
struct kjit_label {
	u64 pc;
	u64 host;
	/* Not read by fragment code: */
	struct hlist_node by_pc;	/* kjit_mm.links->labels, under kjit_mm.lock */
	struct kjit_frag *frag;		/* the fragment this label belongs to */
};
static_assert(offsetof(struct kjit_label, pc) == 0);
static_assert(offsetof(struct kjit_label, host) == 8);

/*
 * Dispatch tables (IBTC): per kjit_mm one array of 8-byte slots, a
 * direct-mapped main part of 2^KJIT_IBTC_BITS slots followed by a victim part
 * of 2^KJIT_IBTC_VICTIM_BITS slots; a slot is 0 or a record of a live fragment
 * of that mm. Which slots a pc may sit in and which stores publish a record
 * are the shared planning's (kjit_rs_ibtc_*). Same constants as the dispatch
 * template (shared/abi), pinned by an assertion in runtime/ffi.rs.
 */
#define KJIT_IBTC_BITS 12
#define KJIT_IBTC_VICTIM_BITS 8
#define KJIT_IBTC_TABLE_SLOTS ((1U << KJIT_IBTC_BITS) + (1U << KJIT_IBTC_VICTIM_BITS))

/*
 * Fragment image placement (docs/pipeline.md, "Image placement (A17, packed
 * arena)"): an image is a slot of a shared arena of KJIT_ARENA_CHUNK-byte
 * chunks, first fit at KJIT_ARENA_GRANULE bytes, so the hot code of all
 * fragments is dense. At most KJIT_ARENA_MAX_CHUNKS chunks exist.
 */
#define KJIT_ARENA_CHUNK SZ_2M
#define KJIT_ARENA_GRANULE 16
#define KJIT_ARENA_GRANULES (KJIT_ARENA_CHUNK / KJIT_ARENA_GRANULE)
#define KJIT_ARENA_MAX_CHUNKS 64
static_assert(KJIT_ARENA_CHUNK % PAGE_SIZE == 0);
static_assert(KJIT_ARENA_GRANULE % sizeof(u32) == 0);

/*
 * Direct BL links (docs/pipeline.md, "Direct BL links (A16, kernel side)"):
 * one record per link slot of a fragment, allocated with it. The slot is
 * either linked (@to is the label whose host the `b` in the slot targets, the
 * record is on @to->frag's incoming list) or a `nop` and pending (@to is NULL,
 * the record is on the mm's pending hash, keyed by @target_pc). Everything
 * under kjit_mm.lock.
 */
struct kjit_link {
	struct hlist_node node;		/* pending hash, or target fragment's incoming list */
	struct kjit_frag *frag;		/* the fragment holding the slot */
	struct kjit_label *to;		/* NULL: pending */
	u64 target_pc;
	u32 slot;			/* code offset of the slot, from frag->image */
};

/*
 * The `nop` word of an unlinked slot. runtime/ffi.rs asserts it equals
 * shared::abi LINK_NOP_WORD; kjit_glue_init() checks it against the kernel's
 * own encoder.
 */
#define KJIT_LINK_NOP_WORD 0xd503201fU

#define KJIT_LINK_LABEL_BITS 11
#define KJIT_LINK_PENDING_BITS 8

/* Per kjit_mm, allocated with the dispatch tables. */
struct kjit_link_index {
	/* Every label of every fragment of the mm, by pc: the targets a site may link to. */
	struct hlist_head labels[1 << KJIT_LINK_LABEL_BITS];
	/* Sites that are `nop`, by target pc. */
	struct hlist_head pending[1 << KJIT_LINK_PENDING_BITS];
};

struct kjit_frag {
	struct hlist_node table_node;	/* kjit_mm.table, under kjit_mm.lock */
	struct list_head all_node;	/* kjit_all_frags, under kjit_frags_lock */
	struct kjit_mm *kmm;		/* valid while the fragment is reachable */
	struct rcu_head retire;		/* hook-SRCU callback: kjit_frag_retired_cb() */
	struct rcu_work free_work;
	/* Removed from kmm: no record of it may be published. Under kmm->lock. */
	bool retired;
	u64 entry_pc;
	u64 src_start, src_end;		/* user text the translation read */
	void *image;			/* the arena slot: code, then the extable */
	u32 code_len;
	struct kjit_label *entry_label;	/* the label of entry_pc, in labels[] */
	/*
	 * verify_fragment's uses_fpsimd: the code reads or writes the user's
	 * V0-V31/FPCR/FPSR, so every run goes through kjit_call_fragment_fpsimd().
	 */
	bool uses_fpsimd;
	const struct exception_table_entry *extable;
	u32 n_extable;
	struct hlist_head incoming;	/* links patched to one of our labels, under kmm->lock */
	struct kjit_link *links;	/* the fragment's link slots, kvcalloc'd */
	u32 n_links;
	u32 n_labels;
	struct kjit_label labels[] __counted_by(n_labels);	/* sorted by pc */
};

#define KJIT_TABLE_BITS 6

/*
 * Auto-mode profile table (docs/pipeline.md, "Profiler"): open addressing over
 * KJIT_PROF_SLOTS, a PC may sit in any of the KJIT_PROF_PROBE slots after its
 * hash slot. Lookups scan all of them (no early stop at a free slot), so
 * freeing a slot needs no tombstone.
 */
#define KJIT_PROF_BITS 8
#define KJIT_PROF_SLOTS (1U << KJIT_PROF_BITS)
#define KJIT_PROF_PROBE 8
/*
 * Negative cache: PCs whose translation failed for good; FIFO replacement.
 * Tagged words (KJIT_WORD_TAG | word) record an untranslatable entry
 * instruction, 0 any other failure.
 */
#define KJIT_NEG_SLOTS 64
#define KJIT_WORD_TAG BIT_ULL(63)
/* Requests (queued task_work) per mm at a time. */
#define KJIT_MAX_QUEUED_PER_MM 8

struct kjit_prof_slot {
	u64 pc;				/* 0: free (never a user text address) */
	u64 start;			/* arch counter at the window start */
	u32 hits;			/* in the window */
	bool queued;			/* a request for pc is queued: keep the slot */
	/*
	 * Tagged entry word if pc is in the negative cache because its entry
	 * instruction is untranslatable: every later hit is a path stop at that
	 * word (unsupported_top's entry_stops), not a count.
	 */
	u64 stop_word;
};

struct kjit_mm {
	struct mmu_notifier mn;
	struct hlist_node hash_node;	/* kjit_mm_hash, under kjit_mm_lock */
	bool hashed;			/* under kjit_mm_lock */
	struct rcu_head rcu;
	u64 id;				/* unique per kjit_mm, for requests */
	spinlock_t lock;		/* everything below */
	DECLARE_HASHTABLE(table, KJIT_TABLE_BITS);
	/*
	 * Dispatch tables (docs/pipeline.md, "Dispatch tables (A11, kernel side)"): both are allocated
	 * together at the first install and never replaced, so they are valid
	 * for every fragment of this kjit_mm. Slots are written under @lock
	 * (smp_store_release / WRITE_ONCE); fragment code reads them without
	 * it. Invariant: a non-zero slot (main or victim part) points at a label
	 * of a non-retired fragment of this kjit_mm, stored at that label's pc's
	 * main or victim index, and a table_nofp slot only at a fragment with
	 * !uses_fpsimd.
	 */
	struct kjit_label **table_all;
	struct kjit_label **table_nofp;
	/* A16: the link bookkeeping, allocated with the tables, under @lock. */
	struct kjit_link_index *links;
	u64 seq;			/* invalidations started */
	unsigned int invalidating;	/* invalidations in progress */
	bool dead;			/* mm released or module exiting */
	bool disabled;			/* runtime bug seen for this mm */
	unsigned int n_frags;		/* installed fragments ... */
	unsigned long code_bytes;	/* ... and their code bytes */
	unsigned int queued;		/* requests queued */
	unsigned int neg_next;		/* next negative-cache slot to fill */
	u64 neg[KJIT_NEG_SLOTS];
	u64 neg_word[KJIT_NEG_SLOTS];	/* tagged entry word, or 0 */
	struct kjit_prof_slot prof[KJIT_PROF_SLOTS];
};

static DEFINE_HASHTABLE(kjit_mm_hash, 6);
static DEFINE_SPINLOCK(kjit_mm_lock);
static LIST_HEAD(kjit_all_frags);
static DEFINE_SPINLOCK(kjit_frags_lock);
static struct workqueue_struct *kjit_wq;
static struct dentry *kjit_debugfs;
static bool kjit_enabled = true;
static atomic64_t kjit_mm_ids = ATOMIC64_INIT(0);
static DEFINE_PER_CPU(u64, kjit_hook_calls_pcpu);

/*
 * Auto mode (P3) and its limits. Module parameters (writable in
 * /sys/module/kjit/parameters/); auto, hot_threshold and hot_window_ms are
 * also in debugfs. Defaults: docs/pipeline.md, "Profiler".
 */
static bool kjit_auto;
/*
 * <linux/compiler_types.h> defines `auto` as `__auto_type` (C23 spelling), and
 * module_param_named() expands its name argument, which would name the
 * parameter "__auto_type". Undefine it for these two lines only.
 */
#pragma push_macro("auto")
#undef auto
module_param_named(auto, kjit_auto, bool, 0644);
MODULE_PARM_DESC(auto, "Translate hot syscall resume PCs and exit targets automatically (default off)");
#pragma pop_macro("auto")
static u32 kjit_hot_threshold = 64;
module_param_named(hot_threshold, kjit_hot_threshold, uint, 0644);
MODULE_PARM_DESC(hot_threshold, "Hits of one PC within hot_window_ms that request its translation (default 64)");
static u32 kjit_hot_window_ms = 100;
module_param_named(hot_window_ms, kjit_hot_window_ms, uint, 0644);
MODULE_PARM_DESC(hot_window_ms, "Profile window in ms (default 100)");
static unsigned int kjit_max_frags_per_mm = 512;
module_param_named(max_frags_per_mm, kjit_max_frags_per_mm, uint, 0644);
static unsigned long kjit_max_code_per_mm = 2UL << 20;
module_param_named(max_code_per_mm, kjit_max_code_per_mm, ulong, 0644);
static unsigned long kjit_max_frags_total = 8192;
module_param_named(max_frags_total, kjit_max_frags_total, ulong, 0644);
static unsigned long kjit_max_code_total = 64UL << 20;
module_param_named(max_code_total, kjit_max_code_total, ulong, 0644);
/*
 * Chaining (docs/pipeline.md, "Chaining rules"): at most chain_budget
 * fragment entries per hook call (after-syscall return path), the first one
 * included; 1 disables chaining. Module parameter and debugfs, both range
 * checked. The maximum keeps runtime/stats.rs's chain histogram exact.
 */
#define KJIT_CHAIN_BUDGET_MAX	65536
static unsigned int kjit_chain_budget_val = 1024;

static int kjit_chain_budget_param_set(const char *val, const struct kernel_param *kp)
{
	return param_set_uint_minmax(val, kp, 1, KJIT_CHAIN_BUDGET_MAX);
}

static const struct kernel_param_ops kjit_chain_budget_param_ops = {
	.set = kjit_chain_budget_param_set,
	.get = param_get_uint,
};
module_param_cb(chain_budget, &kjit_chain_budget_param_ops, &kjit_chain_budget_val, 0644);
MODULE_PARM_DESC(chain_budget, "Fragment entries per syscall-return hook call, chained ones included (1..65536, default 1024)");

u32 kjit_chain_budget(void)
{
	return READ_ONCE(kjit_chain_budget_val);
}

static int kjit_chain_budget_debugfs_get(void *data, u64 *val)
{
	*val = READ_ONCE(kjit_chain_budget_val);
	return 0;
}

static int kjit_chain_budget_debugfs_set(void *data, u64 val)
{
	if (val < 1 || val > KJIT_CHAIN_BUDGET_MAX)
		return -EINVAL;
	WRITE_ONCE(kjit_chain_budget_val, val);
	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(kjit_chain_budget_fops, kjit_chain_budget_debugfs_get,
			 kjit_chain_budget_debugfs_set, "%llu\n");

/* Installed fragments of every mm; see kjit_caps_allow(). */
static atomic_long_t kjit_total_frags = ATOMIC_LONG_INIT(0);
static atomic_long_t kjit_total_code = ATOMIC_LONG_INIT(0);
/*
 * Requests queued, and requests whose task_work ran: the difference at unload
 * is left to the kernel (0004) to free.
 */
static atomic64_t kjit_req_queued = ATOMIC64_INIT(0);
static atomic64_t kjit_req_ran = ATOMIC64_INIT(0);

/* ------------------------------------------------------------------------- */
/* Image arena (A17)                                                           */

/*
 * docs/pipeline.md, "Image placement (A17, packed arena)". Everything here
 * runs in process context with no spinlock held and interrupts on: a chunk is
 * allocated and made ROX, and slots are written and filled with BRK through
 * the text patcher, whose icache flush IPIs every CPU.
 */

/* The slots of one execmem allocation. @used, @map: kjit_arena_lock. */
struct kjit_arena_chunk {
	struct list_head node;		/* kjit_arena_chunks */
	void *base;			/* ROX from creation to execmem_free() */
	unsigned int used;		/* granules in use */
	unsigned long map[BITS_TO_LONGS(KJIT_ARENA_GRANULES)];	/* 1 = in use */
};

static DEFINE_MUTEX(kjit_arena_lock);
/* New chunks at the tail, so the first fit fills the oldest chunk first. */
static LIST_HEAD(kjit_arena_chunks);
/* Gauges (stats file), written under kjit_arena_lock: chunks, and bytes in live slots. */
static atomic_long_t kjit_arena_nchunks = ATOMIC_LONG_INIT(0);
static atomic_long_t kjit_arena_nbytes = ATOMIC_LONG_INIT(0);

/*
 * The bytes an image of @code_len bytes of code and @n_sites extable entries
 * takes in the arena: the code, then the entries (at offset @code_len, which
 * is a multiple of 4), rounded to a granule.
 */
static size_t kjit_image_size(u32 code_len, u32 n_sites)
{
	return ALIGN((size_t)code_len + (size_t)n_sites * sizeof(struct exception_table_entry),
		     KJIT_ARENA_GRANULE);
}

/*
 * A new chunk, full of BRK and ROX; its pages are never writable through this
 * mapping again. The BRK fill gets the same icache flush as every later write,
 * so a branch into a slot that was never written traps instead of running a
 * stale line of whatever the pages held before.
 */
static struct kjit_arena_chunk *kjit_arena_chunk_new(void)
{
	struct kjit_arena_chunk *c = kvzalloc(sizeof(*c), GFP_KERNEL);
	int ret;

	if (!c)
		return ERR_PTR(-ENOMEM);
	c->base = execmem_alloc(EXECMEM_BPF, KJIT_ARENA_CHUNK);
	if (!c->base) {
		kvfree(c);
		return ERR_PTR(-ENOMEM);
	}
	memset32(c->base, AARCH64_BREAK_FAULT, KJIT_ARENA_CHUNK / sizeof(u32));
	flush_icache_range((unsigned long)c->base, (unsigned long)c->base + KJIT_ARENA_CHUNK);
	ret = set_memory_rox((unsigned long)c->base, KJIT_ARENA_CHUNK >> PAGE_SHIFT);
	if (ret) {
		execmem_free(c->base);
		kvfree(c);
		return ERR_PTR(ret);
	}
	return c;
}

/*
 * A free slot of @size bytes (a multiple of KJIT_ARENA_GRANULE), first fit
 * over the chunks, in a new chunk if none has room. Returns the slot, whose
 * contents are BRK, or an ERR_PTR: -ENOSPC (@size exceeds a chunk, or the
 * chunk cap is reached), -ENOMEM, or the set_memory_rox() error.
 */
static void *kjit_arena_alloc(size_t size)
{
	unsigned int granules = size / KJIT_ARENA_GRANULE, start;
	struct kjit_arena_chunk *c;
	void *slot;

	if (size > KJIT_ARENA_CHUNK)
		return ERR_PTR(-ENOSPC);
	mutex_lock(&kjit_arena_lock);
	list_for_each_entry(c, &kjit_arena_chunks, node) {
		/* A miss returns an index past the end of the bitmap. */
		start = bitmap_find_next_zero_area(c->map, KJIT_ARENA_GRANULES, 0, granules, 0);
		if (start + granules <= KJIT_ARENA_GRANULES)
			goto found;
	}
	if (atomic_long_read(&kjit_arena_nchunks) >= KJIT_ARENA_MAX_CHUNKS) {
		slot = ERR_PTR(-ENOSPC);
		goto out;
	}
	c = kjit_arena_chunk_new();
	if (IS_ERR(c)) {
		slot = ERR_CAST(c);
		goto out;
	}
	list_add_tail(&c->node, &kjit_arena_chunks);
	atomic_long_inc(&kjit_arena_nchunks);
	start = 0;
found:
	bitmap_set(c->map, start, granules);
	c->used += granules;
	atomic_long_add(size, &kjit_arena_nbytes);
	slot = c->base + (size_t)start * KJIT_ARENA_GRANULE;
out:
	mutex_unlock(&kjit_arena_lock);
	return slot;
}

/*
 * Fills the slot with BRK, then releases it; a chunk with no slot left is
 * freed. The caller guarantees nothing can run or read the slot: it was never
 * published, or a hook-SRCU grace period has passed since its fragment was
 * retired.
 */
static void kjit_arena_free(void *slot, size_t size)
{
	struct kjit_arena_chunk *c, *empty = NULL;
	unsigned int granules = size / KJIT_ARENA_GRANULE;

	/*
	 * Not recoverable and not possible for a slot this file handed out
	 * (chunk base + a multiple of 16): the patcher refuses a misaligned
	 * address. The slot stays allocated: it is never reused, so no code
	 * ever runs from it, and arena_bytes shows the leak (WARN at unload).
	 */
	if (WARN_ON_ONCE(!aarch64_insn_set(slot, AARCH64_BREAK_FAULT, size)))
		return;
	mutex_lock(&kjit_arena_lock);
	list_for_each_entry(c, &kjit_arena_chunks, node) {
		if (slot >= c->base && slot < c->base + KJIT_ARENA_CHUNK) {
			bitmap_clear(c->map, (slot - c->base) / KJIT_ARENA_GRANULE, granules);
			c->used -= granules;
			atomic_long_sub(size, &kjit_arena_nbytes);
			if (!c->used) {
				list_del(&c->node);
				atomic_long_dec(&kjit_arena_nchunks);
				empty = c;
			}
			break;
		}
	}
	/* The slot is in no chunk: a slot freed twice, or not ours. */
	WARN_ON_ONCE(list_entry_is_head(c, &kjit_arena_chunks, node));
	mutex_unlock(&kjit_arena_lock);
	if (empty) {
		/* VM_FLUSH_RESET_PERMS (execmem) restores the linear map on vfree. */
		execmem_free(empty->base);
		kvfree(empty);
	}
}

/* ------------------------------------------------------------------------- */
/* Fragments                                                                   */

static void kjit_frag_free_work(struct work_struct *work)
{
	struct kjit_frag *f = container_of(to_rcu_work(work), struct kjit_frag, free_work);

	kjit_arena_free(f->image, kjit_image_size(f->code_len, f->n_extable));
	kvfree(f->links);
	kfree(f);
}

/*
 * Takes the fragment off the extable list and frees it after an RCU grace
 * period (extable searchers are RCU readers). Callable in atomic context. The
 * caller guarantees that no run can still be inside the fragment: a hook-SRCU
 * grace period has passed since it was retired.
 */
static void kjit_frag_unlist_and_free(struct kjit_frag *f)
{
	spin_lock(&kjit_frags_lock);
	list_del_rcu(&f->all_node);
	spin_unlock(&kjit_frags_lock);
	INIT_RCU_WORK(&f->free_work, kjit_frag_free_work);
	queue_rcu_work(kjit_wq, &f->free_work);
}

/*
 * Hook-SRCU callback of kjit_frag_retire_locked(): every hook call that could
 * have been running the fragment has returned, so its fault fixups are no
 * longer needed and its image can go (queued, not freed here: the slot's fill
 * needs process context). Runs in a workqueue context with BHs disabled;
 * kjit_frags_lock is never taken from a context it can interrupt.
 */
static void kjit_frag_retired_cb(struct rcu_head *head)
{
	kjit_frag_unlist_and_free(container_of(head, struct kjit_frag, retire));
}

/* ------------------------------------------------------------------------- */
/* Direct BL links (A16)                                                       */

/*
 * docs/pipeline.md, "Direct BL links (A16, kernel side)". Everything below runs
 * under kmm->lock and allocates nothing (the records came with the fragment,
 * the hashes with the tables).
 */

/* Sites currently `b` and currently `nop`, over all mms: the stats file shows them. */
static atomic_long_t kjit_links_linked = ATOMIC_LONG_INIT(0);
static atomic_long_t kjit_links_pending = ATOMIC_LONG_INIT(0);

static struct hlist_head *kjit_link_label_bucket(struct kjit_link_index *idx, u64 pc)
{
	return &idx->labels[hash_64(pc >> 2, KJIT_LINK_LABEL_BITS)];
}

static struct hlist_head *kjit_link_pending_bucket(struct kjit_link_index *idx, u64 pc)
{
	return &idx->pending[hash_64(pc >> 2, KJIT_LINK_PENDING_BITS)];
}

/*
 * Writes @word into @l's slot with the arm64 text patcher (fixmap alias of the
 * ROX page, data cache clean and instruction cache invalidate included). Only
 * nop <-> b is ever written: both are in the architecture's list of
 * instructions that may be modified while another CPU executes them, so a CPU
 * fetching the slot runs either the old or the new word. Returns the patcher's
 * error (a fault writing the alias: not expected for a mapped page).
 */
static int kjit_link_patch(const struct kjit_link *l, u32 word)
{
	if (WARN_ON_ONCE(word != KJIT_LINK_NOP_WORD && !aarch64_insn_is_b(word)))
		return -EINVAL;
	return aarch64_insn_patch_text_nosync(l->frag->image + l->slot, word);
}

enum kjit_link_result {
	KJIT_LINK_MADE,
	KJIT_LINK_CLASS,	/* a non-FP/SIMD site, an FP/SIMD label */
	KJIT_LINK_RANGE,	/* the label is out of `b`'s +-128 MiB */
	KJIT_LINK_FAILED,	/* the patcher failed; the site stays pending */
};

/*
 * Links the pending site @l to @label (of a non-retired fragment, translated
 * for @l->target_pc) if the link condition holds: the class rule (a run
 * outside the FP/SIMD bracket never reaches FP/SIMD code, as for table_nofp)
 * and `b`'s range.
 */
static enum kjit_link_result kjit_link_to_locked(struct kjit_link *l, struct kjit_label *label)
{
	struct kjit_frag *g = label->frag;
	u32 word;

	lockdep_assert_held(&l->frag->kmm->lock);
	WARN_ON_ONCE(l->to || g->retired || label->pc != l->target_pc);
	if (!l->frag->uses_fpsimd && g->uses_fpsimd)
		return KJIT_LINK_CLASS;
	if (!kjit_rs_link_branch_word((u64)l->frag->image + l->slot, label->host, &word))
		return KJIT_LINK_RANGE;
	if (kjit_link_patch(l, word))
		return KJIT_LINK_FAILED;
	hlist_del(&l->node);
	l->to = label;
	hlist_add_head(&l->node, &g->incoming);
	atomic_long_dec(&kjit_links_pending);
	atomic_long_inc(&kjit_links_linked);
	kjit_rs_note(KJIT_NOTE_LINK_MADE, 1);
	return KJIT_LINK_MADE;
}

static void kjit_link_note_refusal(enum kjit_link_result res)
{
	if (res == KJIT_LINK_CLASS)
		kjit_rs_note(KJIT_NOTE_LINK_CLASS_REFUSED, 1);
	else if (res == KJIT_LINK_RANGE)
		kjit_rs_note(KJIT_NOTE_LINK_OUT_OF_RANGE, 1);
}

/*
 * A pending site against every label of its target pc in the mm: links to the
 * first that satisfies the condition. With none, counts once each reason the
 * labels were refused.
 */
static void kjit_link_site_locked(struct kjit_mm *kmm, struct kjit_link *l)
{
	struct kjit_label *label;
	bool class_refused = false, out_of_range = false;

	hlist_for_each_entry(label, kjit_link_label_bucket(kmm->links, l->target_pc), by_pc) {
		if (label->pc != l->target_pc)
			continue;
		switch (kjit_link_to_locked(l, label)) {
		case KJIT_LINK_MADE:
		case KJIT_LINK_FAILED:
			return;
		case KJIT_LINK_CLASS:
			class_refused = true;
			break;
		case KJIT_LINK_RANGE:
			out_of_range = true;
			break;
		}
	}
	if (class_refused)
		kjit_link_note_refusal(KJIT_LINK_CLASS);
	if (out_of_range)
		kjit_link_note_refusal(KJIT_LINK_RANGE);
}

/*
 * Install of @f, which has just become visible: its labels become link
 * targets; each of its sites is put on pending and linked now if a label
 * (its own included) satisfies the condition; then every other pending site
 * that one of its labels satisfies is linked.
 */
static void kjit_link_install_locked(struct kjit_mm *kmm, struct kjit_frag *f)
{
	struct kjit_link_index *idx = kmm->links;
	u32 i;

	lockdep_assert_held(&kmm->lock);
	for (i = 0; i < f->n_labels; i++)
		hlist_add_head(&f->labels[i].by_pc, kjit_link_label_bucket(idx, f->labels[i].pc));
	for (i = 0; i < f->n_links; i++) {
		struct kjit_link *l = &f->links[i];

		hlist_add_head(&l->node, kjit_link_pending_bucket(idx, l->target_pc));
		atomic_long_inc(&kjit_links_pending);
		kjit_link_site_locked(kmm, l);
	}
	for (i = 0; i < f->n_labels; i++) {
		struct kjit_label *label = &f->labels[i];
		struct hlist_node *tmp;
		struct kjit_link *l;

		hlist_for_each_entry_safe(l, tmp, kjit_link_pending_bucket(idx, label->pc), node) {
			/* @f's own sites were tried against all of its labels above. */
			if (l->target_pc != label->pc || l->frag == f)
				continue;
			kjit_link_note_refusal(kjit_link_to_locked(l, label));
		}
	}
}

/*
 * Retire of @f (before its retirement callback is queued): its labels are no
 * longer link targets; every site linked into it is restored to `nop` and goes
 * back to pending; its own sites leave pending and their targets' incoming
 * lists.
 */
static void kjit_link_retire_locked(struct kjit_mm *kmm, struct kjit_frag *f)
{
	struct hlist_node *tmp;
	struct kjit_link *l;
	u32 i;

	lockdep_assert_held(&kmm->lock);
	for (i = 0; i < f->n_labels; i++)
		hlist_del(&f->labels[i].by_pc);
	hlist_for_each_entry_safe(l, tmp, &f->incoming, node) {
		/*
		 * Not allowed to fail: a slot left as `b` would branch into code
		 * that is freed after the grace period of this retirement. The
		 * patcher faults only if the alias of a mapped page cannot be
		 * written, which arm64's own text patching treats as fatal too
		 * (patch_map() BUG_ON).
		 */
		BUG_ON(kjit_link_patch(l, KJIT_LINK_NOP_WORD));
		hlist_del(&l->node);
		l->to = NULL;
		hlist_add_head(&l->node, kjit_link_pending_bucket(kmm->links, l->target_pc));
		atomic_long_dec(&kjit_links_linked);
		atomic_long_inc(&kjit_links_pending);
		kjit_rs_note(KJIT_NOTE_LINK_RESTORED, 1);
	}
	for (i = 0; i < f->n_links; i++) {
		l = &f->links[i];
		hlist_del(&l->node);
		atomic_long_dec(l->to ? &kjit_links_linked : &kjit_links_pending);
		l->to = NULL;
	}
}

/*
 * Retires @f, which the caller has already removed from its kjit_mm's table
 * and accounting: no new run can look it up, no table slot may point into it
 * (a slot is cleared if it holds one of its labels), and no record of it can
 * be published any more. A run that loaded a slot or looked the fragment up
 * before this may enter it and run until its next dispatch or exit; it is
 * inside a hook call, so the fragment stays allocated until the hook-SRCU
 * grace period that starts here has ended. Caller holds kmm->lock; callable in
 * atomic context.
 */
static void kjit_frag_retire_locked(struct kjit_mm *kmm, struct kjit_frag *f)
{
	u64 cleared = 0;
	u32 i;

	lockdep_assert_held(&kmm->lock);
	/* Links first: no site may still branch into @f once its tables are cleared. */
	kjit_link_retire_locked(kmm, f);
	f->retired = true;
	for (i = 0; i < f->n_labels; i++) {
		struct kjit_label *label = &f->labels[i];
		u32 slots[2], j;

		/* The label's main and victim slot, where they still point at it. */
		kjit_rs_ibtc_lookup_slots(label->pc, slots);
		for (j = 0; j < 2; j++) {
			if (kmm->table_all[slots[j]] == label) {
				WRITE_ONCE(kmm->table_all[slots[j]], NULL);
				cleared++;
			}
			if (kmm->table_nofp[slots[j]] == label) {
				WRITE_ONCE(kmm->table_nofp[slots[j]], NULL);
				cleared++;
			}
		}
	}
	if (cleared)
		kjit_rs_note(KJIT_NOTE_IBTC_CLEAR, cleared);
	kjit_hook_call_srcu(&f->retire, kjit_frag_retired_cb);
}

u64 kjit_frag_base(const struct kjit_frag *f)
{
	return (u64)f->image;
}

bool kjit_frag_uses_fpsimd(const struct kjit_frag *f)
{
	return f->uses_fpsimd;
}

/*
 * The dispatch table every run of @f passes as extra[2] (docs/pipeline.md,
 * "Dispatch tables (A11, kernel side)"): a run inside the FP/SIMD bracket may continue into any
 * fragment, any other run only into fragments without FP/SIMD. Both tables
 * exist before the first fragment of the mm does (kjit_install()).
 */
u64 kjit_frag_table(const struct kjit_frag *f)
{
	return (u64)(f->uses_fpsimd ? f->kmm->table_all : f->kmm->table_nofp);
}

/*
 * The label of the verified entry for @pc in @f, or NULL. Every label host is
 * image + an entry offset of verify_fragment's input.
 */
static struct kjit_label *kjit_frag_find_label(struct kjit_frag *f, u64 pc)
{
	u32 lo = 0, hi = f->n_labels;

	while (lo < hi) {
		u32 mid = lo + (hi - lo) / 2;

		if (f->labels[mid].pc == pc)
			return &f->labels[mid];
		if (f->labels[mid].pc < pc)
			lo = mid + 1;
		else
			hi = mid;
	}
	return NULL;
}

/*
 * Publishes @label into @table under kmm->lock with the shared plan
 * (kjit_rs_ibtc_plan_publish): up to two slot stores, performed in the planned
 * order. A conflicting publish first stores the record that is in the main
 * slot into its own victim slot, then @label into the main slot, so every slot
 * always holds 0 or a live record and a concurrent probe of the moved record's
 * pc finds it in one of the two. Counts insert (a slot store) and replace (a
 * store over another record).
 */
static void kjit_ibtc_store_locked(struct kjit_label **table, struct kjit_label *label)
{
	struct kjit_ibtc_store stores[2];
	u32 n = kjit_rs_ibtc_plan_publish((const u64 *)table, label->pc, stores);
	u32 i;

	/*
	 * An empty plan: any live record for the same pc, in its main or victim
	 * slot, is equivalent (every fragment's label for a pc enters a
	 * translation of the same text, and a retired one is no longer in a
	 * slot). Replacing it would only make two fragments sharing a pc take
	 * turns in the slot, one lock round trip per resolution.
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
 * inside fragment code. A record for another pc in the main slot moves to its
 * victim slot, one for the same pc (main or victim slot) is kept. Nothing is
 * published for a retired fragment.
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

/*
 * A branch exit's target @pc resolved to @f, the fragment the run is in:
 * publishes the label of @pc and returns its host (the address to continue
 * at), or 0 if @f has no entry for @pc.
 */
u64 kjit_frag_link(struct kjit_frag *f, u64 pc)
{
	struct kjit_label *label = kjit_frag_find_label(f, pc);

	if (!label)
		return 0;
	kjit_ibtc_publish(f, label);
	return label->host;
}

/* Removes every fragment of @kmm from its table. Caller holds kmm->lock. */
static u64 kjit_mm_flush_locked(struct kjit_mm *kmm, unsigned long start, unsigned long end)
{
	struct kjit_frag *f;
	struct hlist_node *tmp;
	unsigned int bkt;
	u64 n = 0;

	lockdep_assert_held(&kmm->lock);
	hash_for_each_safe(kmm->table, bkt, tmp, f, table_node) {
		if (f->src_start < end && start < f->src_end) {
			hash_del_rcu(&f->table_node);
			kmm->n_frags--;
			kmm->code_bytes -= f->code_len;
			atomic_long_dec(&kjit_total_frags);
			atomic_long_sub(f->code_len, &kjit_total_code);
			kjit_frag_retire_locked(kmm, f);
			n++;
		}
	}
	return n;
}

/*
 * Whether @kmm may install @code_len more bytes of code. The per-mm limits are
 * exact under kmm->lock; the global ones are checked racily against other
 * mms, so concurrent installs can overshoot them by one fragment each. The
 * extable entries and the granule rounding of the arena slot are not code; the
 * arena's own cap is KJIT_ARENA_MAX_CHUNKS.
 */
static bool kjit_caps_allow(const struct kjit_mm *kmm, unsigned long code_len)
{
	return kmm->n_frags < READ_ONCE(kjit_max_frags_per_mm) &&
	       kmm->code_bytes + code_len <= READ_ONCE(kjit_max_code_per_mm) &&
	       atomic_long_read(&kjit_total_frags) < READ_ONCE(kjit_max_frags_total) &&
	       atomic_long_read(&kjit_total_code) + code_len <= READ_ONCE(kjit_max_code_total);
}

/* ------------------------------------------------------------------------- */
/* Per-mm state and the mmu_notifier                                           */

static struct kjit_mm *kjit_mm_find_rcu(struct mm_struct *mm)
{
	struct kjit_mm *kmm;

	hash_for_each_possible_rcu(kjit_mm_hash, kmm, hash_node, (unsigned long)mm)
		if (kmm->mn.mm == mm)
			return kmm;
	return NULL;
}

/* Empties kmm and refuses further installs. */
static void kjit_mm_kill(struct kjit_mm *kmm)
{
	u64 n;

	spin_lock(&kmm->lock);
	kmm->dead = true;
	n = kjit_mm_flush_locked(kmm, 0, ULONG_MAX);
	spin_unlock(&kmm->lock);
	kjit_rs_note(KJIT_NOTE_RELEASED, n);
}

/*
 * mm release: empty kmm, take it off the syscall path and drop the hash
 * reference, unless module exit already claimed it. kmm stays valid for the
 * whole callback (notifier SRCU).
 */
static void kjit_mm_retire(struct kjit_mm *kmm)
{
	bool put = false;

	kjit_mm_kill(kmm);
	spin_lock(&kjit_mm_lock);
	if (kmm->hashed) {
		hash_del_rcu(&kmm->hash_node);
		kmm->hashed = false;
		put = true;
	}
	spin_unlock(&kjit_mm_lock);
	if (put)
		mmu_notifier_put(&kmm->mn);
}

static int kjit_mn_invalidate_range_start(struct mmu_notifier *mn,
					  const struct mmu_notifier_range *range)
{
	struct kjit_mm *kmm = container_of(mn, struct kjit_mm, mn);
	u64 n;

	/*
	 * Every event, not only unmaps: a protection change can make the text
	 * writable, and migration/CoW replace pages. Dropping a translation is
	 * always correct; keeping a stale one is not. Never sleeps, so the
	 * non-blockable case needs no special handling.
	 */
	spin_lock(&kmm->lock);
	kmm->seq++;
	kmm->invalidating++;
	n = kjit_mm_flush_locked(kmm, range->start, range->end);
	spin_unlock(&kmm->lock);
	if (n)
		kjit_rs_note(KJIT_NOTE_INVALIDATED, n);
	return 0;
}

static void kjit_mn_invalidate_range_end(struct mmu_notifier *mn,
					 const struct mmu_notifier_range *range)
{
	struct kjit_mm *kmm = container_of(mn, struct kjit_mm, mn);

	spin_lock(&kmm->lock);
	kmm->invalidating--;
	spin_unlock(&kmm->lock);
}

/* exit_mmap(): the address space is going away. */
static void kjit_mn_release(struct mmu_notifier *mn, struct mm_struct *mm)
{
	kjit_mm_retire(container_of(mn, struct kjit_mm, mn));
}

static struct mmu_notifier *kjit_mn_alloc(struct mm_struct *mm)
{
	/* About 10 KiB with the profile table: no need for contiguous pages. */
	struct kjit_mm *kmm = kvzalloc(sizeof(*kmm), GFP_KERNEL);

	if (!kmm)
		return ERR_PTR(-ENOMEM);
	kmm->id = atomic64_inc_return(&kjit_mm_ids);
	spin_lock_init(&kmm->lock);
	hash_init(kmm->table);
	return &kmm->mn;
}

/*
 * Hook-SRCU callback: every hook call that could be running a fragment of this
 * kjit_mm, and so reading its dispatch tables, has returned.
 */
static void kjit_mm_free_cb(struct rcu_head *head)
{
	struct kjit_mm *kmm = container_of(head, struct kjit_mm, rcu);

	kvfree(kmm->table_all);
	kvfree(kmm->table_nofp);
	kvfree(kmm->links);
	/* Syscall-path readers found it under RCU, not the notifier SRCU. */
	kvfree_rcu(kmm, rcu);
}

static void kjit_mn_free(struct mmu_notifier *mn)
{
	struct kjit_mm *kmm = container_of(mn, struct kjit_mm, mn);

	/*
	 * Nothing installed, so no run ever read a table: the hook-SRCU grace
	 * period would wait for nothing. Most kjit_mms of the auto mode are such
	 * (a process that never got a translation).
	 */
	if (!kmm->table_all) {
		kvfree_rcu(kmm, rcu);
		return;
	}
	kjit_hook_call_srcu(&kmm->rcu, kjit_mm_free_cb);
}

static const struct mmu_notifier_ops kjit_mn_ops = {
	.release = kjit_mn_release,
	.invalidate_range_start = kjit_mn_invalidate_range_start,
	.invalidate_range_end = kjit_mn_invalidate_range_end,
	.alloc_notifier = kjit_mn_alloc,
	.free_notifier = kjit_mn_free,
};

/*
 * The kjit_mm of @mm, created and hashed on first use. Returns with one
 * notifier reference the caller drops with kjit_mm_put(). @mm must have
 * mm_users held.
 */
static struct kjit_mm *kjit_mm_get(struct mm_struct *mm)
{
	struct mmu_notifier *mn = mmu_notifier_get(&kjit_mn_ops, mm);
	struct kjit_mm *kmm;
	bool extra = false;

	if (IS_ERR(mn))
		return ERR_CAST(mn);
	kmm = container_of(mn, struct kjit_mm, mn);

	spin_lock(&kjit_mm_lock);
	if (!kmm->hashed && !READ_ONCE(kmm->dead)) {
		hash_add_rcu(kjit_mm_hash, &kmm->hash_node, (unsigned long)mm);
		kmm->hashed = true;
		extra = true;
	}
	spin_unlock(&kjit_mm_lock);
	/* The hash owns one reference; give the caller its own. */
	if (extra)
		mmu_notifier_get(&kjit_mn_ops, mm);
	return kmm;
}

static void kjit_mm_put(struct kjit_mm *kmm)
{
	mmu_notifier_put(&kmm->mn);
}

u64 kjit_mm_seq(struct kjit_mm *kmm)
{
	u64 seq;

	spin_lock(&kmm->lock);
	seq = kmm->seq;
	spin_unlock(&kmm->lock);
	return seq;
}

/* ------------------------------------------------------------------------- */
/* User text                                                                   */

/*
 * Copies the page at @addr (page aligned) of @kmm's mm into @buf, but only
 * from a VMA that is executable and not writable. Returns 0, -EACCES for any
 * other VMA, -EFAULT if there is none, or the gup error.
 */
int kjit_read_text_page(struct kjit_mm *kmm, u64 addr, u8 *buf)
{
	struct mm_struct *mm = kmm->mn.mm;
	struct vm_area_struct *vma;
	struct page *page;
	long got;
	int ret;

	if (addr & ~PAGE_MASK)
		return -EINVAL;
	ret = mmap_read_lock_killable(mm);
	if (ret)
		return ret;
	vma = vma_lookup(mm, addr);
	if (!vma) {
		ret = -EFAULT;
		goto out;
	}
	if (!(vma->vm_flags & VM_EXEC) || (vma->vm_flags & VM_WRITE)) {
		ret = -EACCES;
		goto out;
	}
	/* FOLL_FORCE without FOLL_WRITE only lets us read exec-only text. */
	got = get_user_pages_remote(mm, addr, 1, FOLL_FORCE, &page, NULL);
	if (got != 1) {
		ret = got < 0 ? got : -EFAULT;
		goto out;
	}
	memcpy_from_page(buf, page, 0, PAGE_SIZE);
	put_page(page);
	ret = 0;
out:
	mmap_read_unlock(mm);
	return ret;
}

/* ------------------------------------------------------------------------- */
/* Install                                                                     */

/*
 * Installs a verified fragment for @entry_pc in @kmm: a slot of the image arena
 * (A17) holding @code and, after it, one exception_table_entry per fault site
 * (self-relative, so it must be the same slot). The image is built in a buffer
 * and written to the slot with aarch64_insn_copy(); labels and extable entries
 * are relative to the slot start; the caps count @code_len. Process context,
 * no spinlock held, interrupts on (the write IPIs every CPU).
 * Installs only if no invalidation started since @seq
 * (kjit_mm_seq() before the text was read) and none is in progress, so a
 * translation of text that changed while it was read never becomes visible.
 *
 * @uses_fpsimd is verify_fragment's verdict on @code: every run of the fragment
 * then goes through the FP/SIMD bracket (kjit_call_fragment_fpsimd()).
 *
 * @links are the fragment's link slots (A16): verified by verify_fragment (rule
 * 10), so each is a `nop` right before a dispatch template, for a BL to @target_pc.
 * The install links them, and every pending site its labels satisfy, before it
 * returns (kjit_link_install_locked()).
 *
 * The first install of a kjit_mm also allocates its two dispatch tables (32 KiB
 * each) and the link bookkeeping; a failure to do so fails that install with
 * -ENOMEM.
 *
 * Returns 0, -EEXIST (@entry_pc already has a fragment), -EAGAIN (raced with
 * an invalidation), -ESRCH (mm gone), -ENOSPC (a fragment cap is reached,
 * kjit_caps_allow(); or the arena's: the image exceeds a chunk, or
 * KJIT_ARENA_MAX_CHUNKS chunks exist and none has room), -ENOMEM, -EINVAL
 * (malformed tables, which the Rust side never passes; or the text patcher
 * refused the slot), -EIO (the slot does not read back as written), or the
 * set_memory_rox() error of a new chunk. A failure after the write releases
 * the slot at once: the fragment was never visible.
 */
int kjit_install(struct kjit_mm *kmm, u64 seq, u64 entry_pc,
		 const u8 *code, u32 code_len, u32 entry_offset,
		 const struct kjit_site *sites, u32 n_sites,
		 const struct kjit_entry *entries, u32 n_entries,
		 const struct kjit_link_site *links, u32 n_links,
		 u64 src_start, u64 src_end, bool uses_fpsimd)
{
	struct kjit_label **new_all = NULL, **new_nofp = NULL;
	struct kjit_link_index *new_links = NULL;
	struct exception_table_entry *ex, *ex_slot;
	struct kjit_frag *f, *old;
	bool has_entry = false;
	size_t len, size;
	void *buf, *slot;
	int ret;
	u32 i;

	if (!code_len || code_len % 4 || entry_offset >= code_len || entry_offset % 4)
		return -EINVAL;
	for (i = 0; i < n_sites; i++)
		if (sites[i].access >= code_len || sites[i].stub >= code_len ||
		    (i && sites[i].access <= sites[i - 1].access))
			return -EINVAL;
	for (i = 0; i < n_entries; i++) {
		if (entries[i].offset >= code_len || (i && entries[i].pc <= entries[i - 1].pc))
			return -EINVAL;
		/* kjit_lookup() enters at the label of entry_pc: it must be entry_offset. */
		if (entries[i].pc == entry_pc)
			has_entry = entries[i].offset == entry_offset;
	}
	if (!has_entry)
		return -EINVAL;
	/* Rule 10 of the verifier says each slot is a nop; the patcher relies on it. */
	for (i = 0; i < n_links; i++)
		if (links[i].slot >= code_len || links[i].slot % 4 ||
		    le32_to_cpup((const __le32 *)(code + links[i].slot)) != KJIT_LINK_NOP_WORD)
			return -EINVAL;

	/*
	 * Allocated outside kmm->lock, only by installs that find none; the
	 * loser of a race frees its copy below.
	 */
	if (!READ_ONCE(kmm->table_all)) {
		new_all = kvzalloc(KJIT_IBTC_TABLE_SLOTS * sizeof(*new_all), GFP_KERNEL);
		new_nofp = kvzalloc(KJIT_IBTC_TABLE_SLOTS * sizeof(*new_nofp), GFP_KERNEL);
		new_links = kvzalloc(sizeof(*new_links), GFP_KERNEL);
		if (!new_all || !new_nofp || !new_links) {
			ret = -ENOMEM;
			goto out_tables;
		}
	}

	f = kzalloc(struct_size(f, labels, n_entries), GFP_KERNEL);
	if (!f) {
		ret = -ENOMEM;
		goto out_tables;
	}
	f->kmm = kmm;
	f->n_labels = n_entries;
	f->n_links = n_links;
	f->links = kvcalloc(n_links, sizeof(*f->links), GFP_KERNEL);
	if (n_links && !f->links) {
		kfree(f);
		ret = -ENOMEM;
		goto out_tables;
	}
	for (i = 0; i < n_links; i++) {
		f->links[i].frag = f;
		f->links[i].target_pc = links[i].target_pc;
		f->links[i].slot = links[i].slot;
	}

	/*
	 * The extable entries start at offset code_len (a multiple of 4, checked
	 * above); @len is what is written, @size the slot (the tail stays BRK).
	 */
	len = code_len + (size_t)n_sites * sizeof(*ex);
	size = kjit_image_size(code_len, n_sites);
	buf = kvmalloc(len, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto out_frag;
	}
	slot = kjit_arena_alloc(size);
	if (IS_ERR(slot)) {
		ret = PTR_ERR(slot);
		kvfree(buf);
		goto out_frag;
	}
	f->image = slot;
	for (i = 0; i < n_entries; i++) {
		f->labels[i].pc = entries[i].pc;
		f->labels[i].host = (u64)slot + entries[i].offset;
		f->labels[i].frag = f;
		if (entries[i].pc == entry_pc)
			f->entry_label = &f->labels[i];
	}
	f->code_len = code_len;
	f->entry_pc = entry_pc;
	f->src_start = src_start;
	f->src_end = src_end;
	f->n_extable = n_sites;
	f->uses_fpsimd = uses_fpsimd;

	memcpy(buf, code, code_len);
	ex = buf + code_len;
	ex_slot = slot + code_len;
	for (i = 0; i < n_sites; i++) {
		/* Self-relative, so computed for the slot's final address. */
		ex[i].insn = (long)(slot + sites[i].access) - (long)&ex_slot[i].insn;
		ex[i].fixup = (long)(slot + sites[i].stub) - (long)&ex_slot[i].fixup;
		ex[i].type = EX_TYPE_UACCESS_ERR_ZERO;
		/* xzr for both: the handler only sets pc to the fixup. */
		ex[i].data = FIELD_PREP(EX_DATA_REG_ERR, 31) | FIELD_PREP(EX_DATA_REG_ZERO, 31);
	}
	f->extable = ex_slot;

	/* NULL only for a misaligned slot, which the arena never hands out. */
	if (WARN_ON_ONCE(!aarch64_insn_copy(slot, buf, len))) {
		ret = -EINVAL;
		goto out_buf;
	}
	/*
	 * The patcher's faulting copy reports nothing: what the verifier
	 * accepted is what must be in the slot before anything can run it.
	 */
	if (WARN_ON_ONCE(memcmp(slot, buf, len))) {
		ret = -EIO;
		goto out_buf;
	}
	kvfree(buf);

	spin_lock(&kmm->lock);
	if (kmm->dead || kmm->disabled) {
		ret = -ESRCH;
	} else if (kmm->seq != seq || kmm->invalidating) {
		ret = -EAGAIN;
	} else {
		ret = 0;
		hash_for_each_possible(kmm->table, old, table_node, entry_pc)
			if (old->entry_pc == entry_pc)
				ret = -EEXIST;
		if (!ret && !kjit_caps_allow(kmm, code_len))
			ret = -ENOSPC;
		if (!ret) {
			/*
			 * Before the fragment is visible: whoever finds it (table or
			 * dispatch) finds tables too.
			 */
			if (!kmm->table_all) {
				WRITE_ONCE(kmm->table_all, new_all);
				WRITE_ONCE(kmm->table_nofp, new_nofp);
				kmm->links = new_links;
				new_all = new_nofp = NULL;
				new_links = NULL;
			}
			/* On the extable list before anything can run it. */
			spin_lock(&kjit_frags_lock);
			list_add_rcu(&f->all_node, &kjit_all_frags);
			spin_unlock(&kjit_frags_lock);
			hash_add_rcu(kmm->table, &f->table_node, entry_pc);
			kmm->n_frags++;
			kmm->code_bytes += code_len;
			atomic_long_inc(&kjit_total_frags);
			atomic_long_add(code_len, &kjit_total_code);
			kjit_link_install_locked(kmm, f);
		}
	}
	spin_unlock(&kmm->lock);
	if (!ret)
		goto out_tables;
	/* Never published, so nothing can be running or reading it. */
	goto out_slot;
out_buf:
	kvfree(buf);
out_slot:
	kjit_arena_free(slot, size);
out_frag:
	kvfree(f->links);
	kfree(f);
out_tables:
	/* Tables another install published first, or that this one did not need. */
	kvfree(new_all);
	kvfree(new_nofp);
	kvfree(new_links);
	return ret;
}

/* ------------------------------------------------------------------------- */
/* Syscall path                                                                */

/*
 * Exit-to-user work (signals, rescheduling, task_work/rseq/notify-resume,
 * uprobes, livepatch, MTE async faults), syscall work (ptrace syscall stops,
 * audit, seccomp, syscall tracepoints) and single-step all need the normal
 * return to userspace. TIF_FOREIGN_FPSTATE only asks for an FP register reload
 * before userspace runs: a fragment without FP/SIMD never touches those
 * registers, and one with FP/SIMD loads the user state from memory itself inside
 * its bracket (kjit_call_fragment_fpsimd()).
 */
#define KJIT_BAIL_FLAGS \
	((EXIT_TO_USER_MODE_WORK & ~_TIF_FOREIGN_FPSTATE) | _TIF_SYSCALL_WORK | _TIF_SINGLESTEP)

/*
 * The K2 run conditions on the current task (docs/pipeline.md, "Run conditions
 * (kjit_can_run)"), checked before every fragment entry and before every
 * in-kernel syscall. A traced task is declined as a whole: a tracer may
 * single-step, set watchpoints or read registers at any instruction.
 */
bool kjit_can_run(const struct pt_regs *regs)
{
	unsigned long x0 = regs->regs[0];

	/* debugfs enable=N stops fragment runs and chains at the next check. */
	if (!READ_ONCE(kjit_enabled) || is_compat_task() || current->ptrace)
		return false;
	if (read_thread_flags() & KJIT_BAIL_FLAGS)
		return false;
	/* -ERESTARTSYS..-ERESTART_RESTARTBLOCK: the signal code must see it. */
	if (x0 >= (unsigned long)-ERESTART_RESTARTBLOCK && x0 <= (unsigned long)-ERESTARTSYS)
		return false;
	return true;
}

/*
 * Returns the installed fragment for (current->mm, @pc) and its entry address
 * in @entry, or NULL; with @link (a branch exit's target resolved to it) it
 * also publishes the entry in the dispatch tables (kjit_ibtc_publish()). No
 * reference is taken: the caller is inside a hook call
 * (kjit_hook_srcu read section), and a fragment found in one is not freed
 * before that call returns, even if it is retired meanwhile (the hook-SRCU
 * grace period of kjit_frag_retire_locked() waits for it). Not for use outside
 * the hook (the debugfs paths hold a kjit_mm reference instead).
 */
struct kjit_frag *kjit_lookup(u64 pc, bool link, u64 *entry)
{
	struct mm_struct *mm = current->mm;
	struct kjit_frag *f, *found = NULL;
	struct kjit_mm *kmm;

	if (!mm)
		return NULL;
	rcu_read_lock();
	kmm = kjit_mm_find_rcu(mm);
	if (kmm && !READ_ONCE(kmm->disabled)) {
		hash_for_each_possible_rcu(kmm->table, f, table_node, pc) {
			if (f->entry_pc == pc) {
				found = f;
				break;
			}
		}
	}
	rcu_read_unlock();
	if (found) {
		if (link)
			kjit_ibtc_publish(found, found->entry_label);
		*entry = found->entry_label->host;
	}
	return found;
}

/* A fragment returned a status the runtime does not know: a kernel bug. */
void kjit_bad_status(u64 status, u64 pc)
{
	struct kjit_mm *kmm;
	u64 n = 0;

	WARN_ONCE(1, "kjit: fragment for pc %#llx returned unknown status %#llx; KJIT disabled for pid %d\n",
		  pc, status, task_pid_nr(current));
	rcu_read_lock();
	kmm = kjit_mm_find_rcu(current->mm);
	if (kmm) {
		spin_lock(&kmm->lock);
		kmm->disabled = true;
		n = kjit_mm_flush_locked(kmm, 0, ULONG_MAX);
		spin_unlock(&kmm->lock);
	}
	rcu_read_unlock();
	kjit_rs_note(KJIT_NOTE_RELEASED, n);
}

/*
 * u64 kjit_call_fragment(struct pt_regs *regs, u64 extra[3], u64 entry, u64 base)
 *
 * The ABI call (docs/pipeline.md, "ABI: fragment entry"; mirrors
 * harness/src/native.rs): x0 = regs, x1 = extra params, x2 = entry address,
 * call the fragment at its base. The fragment runs user code, so the user's
 * NZCV (regs->pstate) is live in PSTATE while it runs and is written back
 * afterwards; x19..x29, x30 and sp come back through the fragment epilogue.
 * Returns x0 = RetStatus; extra[0], extra[1] = x10, x11 (out), extra[2] = the
 * run's dispatch table (in, kjit_frag_table()).
 *
 * PSTATE.PAN is clear for exactly the fragment run (A15, docs/pipeline.md,
 * "Run-scoped PAN clear (A15)"): `msr pan, #0` right before the blr and
 * `msr pan, #1` right after it returns, the only PAN writes of the module.
 * The window accesses (LSE atomics, SIMD&FP loads/stores) are privileged
 * accesses to user memory behind a range check; nothing in a fragment writes
 * PAN (the verifier rejects any msr). SCTLR_EL1.SPAN == 0 (checked at init)
 * makes every exception taken inside the run set PAN, so interrupts and
 * preemption run kernel code with PAN set.
 */
asm(
"	.pushsection .text, \"ax\"\n"
"	.p2align 2\n"
"	.globl	kjit_call_fragment\n"
"	.type	kjit_call_fragment, %function\n"
"kjit_call_fragment:\n"
"	stp	x29, x30, [sp, #-32]!\n"
"	mov	x29, sp\n"
"	str	x0, [sp, #16]\n"
"	ldr	x9, [x0, #264]\n"
"	and	x9, x9, #0xf0000000\n"
"	msr	nzcv, x9\n"
	SET_PSTATE_PAN(0)
"	blr	x3\n"
	SET_PSTATE_PAN(1)
"	mrs	x9, nzcv\n"
"	ldr	x1, [sp, #16]\n"
"	ldr	x10, [x1, #264]\n"
"	bic	x10, x10, #0xf0000000\n"
"	orr	x10, x10, x9\n"
"	str	x10, [x1, #264]\n"
"	ldp	x29, x30, [sp], #32\n"
"	ret\n"
"	.size	kjit_call_fragment, . - kjit_call_fragment\n"
"	.popsection\n");

/*
 * Longest FP/SIMD bracket per CPU, in arch counter ticks (stats:
 * fpsimd_run_max_ns). Written with preemption off, on the CPU the bracket ends
 * on; the stats file reads it racily.
 */
static DEFINE_PER_CPU(u64, kjit_fpsimd_max_ticks);

/*
 * FPCR's trap-enable bits: IOE, DZE, OFE, UFE, IXE (bits 8-12) and IDE (bit 15).
 * A bit set on a CPU that implements trapped floating-point exceptions makes a
 * floating-point instruction that raises that exception take an FP exception
 * (synchronous, to the current EL) instead of setting a FPSR flag. CPUs without
 * trapping support read them as zero.
 */
#define KJIT_FPCR_TRAP_ENABLES (GENMASK(12, 8) | BIT(15))

/*
 * kjit_call_fragment() for a fragment that uses FP/SIMD: its code reads and
 * writes V0-V31, FPCR and FPSR as the user's own registers (docs/pipeline.md,
 * "FP/SIMD in fragments (A9)", Kernel). One bracket per runtime entry (chained
 * entries included; a bracketed run continues across fragments inside it),
 * from task context on the syscall return path with interrupts enabled. It is
 * preemptible and migratable: a task-level kernel-mode NEON section
 * (TIF_KERNEL_FPSTATE) makes the context switch save the registers into @kbuf
 * and reload them on whichever CPU the task resumes on.
 *
 * - kernel_neon_begin(): saves the user state to thread.uw if it is live in
 *   the registers, takes the registers, flushes this CPU's binding.
 * - FPCR trap enables (A18): the user's FPCR is read from thread.uw, which
 *   kernel_neon_begin() has just brought up to date. If any trap-enable bit is
 *   set the run is declined: the fragment would execute floating-point
 *   instructions at EL1 with that FPCR, and one that raises an enabled exception
 *   would take an FP exception in the kernel instead of the user's SIGFPE.
 *   Nothing was loaded or written, so the bracket just closes
 *   (kernel_neon_end(): the user state stays in thread.uw with
 *   TIF_FOREIGN_FPSTATE set, as after any kernel-mode NEON section that did not
 *   touch it) and userspace executes natively from the entry pc.
 * - fpsimd_load_state(): the user state (thread.uw, authoritative now: no SVE
 *   or SME, kjit_fpsimd_supported()) into the registers.
 * - pagefault_disable(): a user-access fault must not sleep or run a
 *   filesystem's NEON-accelerated read path, which would nest a second
 *   task-level kernel_neon_begin() (a BUG). With page faults disabled,
 *   do_page_fault() goes straight to no_context, the fragment's exception table
 *   (kernel-patches/0002) sends the access to its Mem stub, and the Mem
 *   exit makes userspace re-execute the instruction natively, where the fault is
 *   handled as usual (demand paging, CoW, SIGSEGV). Correct, occasionally slower.
 * - fpsimd_save_state(): the registers back into thread.uw.
 * - thread.fpsimd_cpu = NR_CPUS: thread.uw was written behind the kernel's
 *   back, so no CPU's registers hold a current copy of it, whatever its
 *   binding (fpsimd_last_state) says. Without this a CPU this task last loaded
 *   its state on (thread.fpsimd_cpu) could still be bound to it, and the next
 *   fpsimd_thread_switch() there would take the stale registers for current
 *   and clear TIF_FOREIGN_FPSTATE. Same as fpsimd_flush_task_state() after the
 *   kernel edits a user state (sigreturn, ptrace). Written while
 *   TIF_KERNEL_FPSTATE is still set, so no switch-in evaluates the binding in
 *   between (that path reloads from @kbuf and does not look at it).
 * - kernel_neon_end(): TIF_FOREIGN_FPSTATE stays set, so the exit to userspace
 *   (or the next bracket) loads thread.uw.
 *
 * A softirq that uses kernel-mode NEON while the bracket is open (at irq exit,
 * or when it is switched in) takes the nested path: it saves the registers in
 * its own buffer and restores them at its kernel_neon_end(). Hardirqs never use
 * NEON (may_use_simd()). kernel_neon_begin() BUGs unless may_use_simd(): this
 * is called from the syscall hook, in task context with no NEON section open,
 * and no bracket is entered from inside another run.
 *
 * Bracket length stats: the bracket is measured from the return of
 * kernel_neon_begin() to just before kernel_neon_end(), in wall clock, so time
 * switched out counts. The tail runs with preemption off, so the end time and
 * the per-CPU maximum are on the CPU the bracket ends on. A bracket is
 * "preempted" when the task's context-switch counters changed inside it.
 */
bool kjit_call_fragment_fpsimd(struct pt_regs *regs, u64 *extra, u64 entry, u64 base,
			       u64 *status)
{
	struct user_fpsimd_state kbuf;
	struct user_fpsimd_state *uw = &current->thread.uw.fpsimd_state;
	unsigned long switches;
	u64 t0, ticks;

	kernel_neon_begin(&kbuf);
	if (uw->fpcr & KJIT_FPCR_TRAP_ENABLES) {
		kernel_neon_end(&kbuf);
		return false;
	}
	switches = current->nvcsw + current->nivcsw;
	t0 = arch_timer_read_counter();
	fpsimd_load_state(uw);
	pagefault_disable();
	*status = kjit_call_fragment(regs, extra, entry, base);
	pagefault_enable();

	preempt_disable();
	fpsimd_save_state(uw);
	current->thread.fpsimd_cpu = NR_CPUS;
	barrier();
	ticks = arch_timer_read_counter() - t0;
	if (ticks > __this_cpu_read(kjit_fpsimd_max_ticks))
		__this_cpu_write(kjit_fpsimd_max_ticks, ticks);
	switches = current->nvcsw + current->nivcsw - switches;
	kernel_neon_end(&kbuf);
	preempt_enable();

	if (switches)
		kjit_rs_note(KJIT_NOTE_FPSIMD_PREEMPTED, 1);
	return true;
}

/* The longest FP/SIMD bracket on any CPU so far, in ns. */
u64 kjit_fpsimd_run_max_ns(void)
{
	u64 max = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		max = max_t(u64, max, READ_ONCE(per_cpu(kjit_fpsimd_max_ticks, cpu)));
	return mul_u64_u32_div(max, NSEC_PER_SEC, arch_timer_get_cntfrq());
}

/*
 * Whether fragments that use FP/SIMD may be installed on this system. SVE and
 * SME change what the user's FP/SIMD state is (Z/P registers whose low bits
 * are the V registers, the SVE discard at syscall entry, streaming mode, ZA);
 * none of it is modelled, so such fragments are refused (docs/pipeline.md, "FP/SIMD
 * in fragments (A9)"). Without FP/SIMD at all (arm64.nofpsimd) the fragment's FP/SIMD
 * instructions would trap at EL1.
 */
bool kjit_fpsimd_supported(void)
{
	return system_supports_fpsimd() && !system_supports_sve() && !system_supports_sme();
}

/*
 * Softirq kernel-mode NEON noise (debugfs neon_noise_us), for the FP/SIMD
 * bracket's stress test (tests/guest/fp_preempt.c, fp_stress.sh). The guest
 * kernel has no NEON user on any path a test reaches, so nothing would
 * otherwise exercise "a softirq takes the registers while a bracket is open".
 * A pinned soft hrtimer per CPU fires every N microseconds and, in softirq
 * context, does a kernel_neon_begin() / clobber V0-V31 / kernel_neon_end()
 * round: exactly what a crypto softirq does, and the kernel's own protocol for
 * it, so it is correct whatever the interrupted task is doing. Rounds are
 * counted by what they interrupted: a task inside a task-level kernel-mode NEON
 * section (the bracket), a task whose user state is live in the registers, or
 * a task with no live state.
 */
static DEFINE_PER_CPU(struct hrtimer, kjit_neon_timer);
static u32 kjit_neon_period_us;
static atomic64_t kjit_neon_hits_kernel = ATOMIC64_INIT(0);
static atomic64_t kjit_neon_hits_live = ATOMIC64_INIT(0);
static atomic64_t kjit_neon_hits_other = ATOMIC64_INIT(0);

static enum hrtimer_restart kjit_neon_timer_fn(struct hrtimer *t)
{
	u32 period = READ_ONCE(kjit_neon_period_us);
	struct user_fpsimd_state st;

	if (!period)
		return HRTIMER_NORESTART;
	if (may_use_simd()) {
		if (test_thread_flag(TIF_KERNEL_FPSTATE))
			atomic64_inc(&kjit_neon_hits_kernel);
		else if (!test_thread_flag(TIF_FOREIGN_FPSTATE))
			atomic64_inc(&kjit_neon_hits_live);
		else
			atomic64_inc(&kjit_neon_hits_other);
		kernel_neon_begin(&st);
		asm volatile(".arch_extension simd\n"
			     ".irp n, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31\n"
			     "movi v\\n\\().16b, #0xa5\n"
			     ".endr\n");
		kernel_neon_end(&st);
	}
	hrtimer_forward_now(t, ns_to_ktime((u64)period * NSEC_PER_USEC));
	return HRTIMER_RESTART;
}

static void kjit_neon_start_cpu(void *unused)
{
	hrtimer_start(this_cpu_ptr(&kjit_neon_timer),
		      ns_to_ktime((u64)READ_ONCE(kjit_neon_period_us) * NSEC_PER_USEC),
		      HRTIMER_MODE_REL_PINNED_SOFT);
}

static int kjit_neon_noise_get(void *data, u64 *val)
{
	*val = READ_ONCE(kjit_neon_period_us);
	return 0;
}

/* 0 = off; else the period in microseconds, 5..1000000. */
static int kjit_neon_noise_set(void *data, u64 val)
{
	if (val > 1000000 || (val && val < 5) || !kjit_fpsimd_supported())
		return -EINVAL;
	WRITE_ONCE(kjit_neon_period_us, val);
	if (val)
		on_each_cpu(kjit_neon_start_cpu, NULL, 1);
	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(kjit_neon_noise_fops, kjit_neon_noise_get, kjit_neon_noise_set, "%llu\n");

static ssize_t kjit_neon_hits_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
	char buf[128];
	int n = scnprintf(buf, sizeof(buf), "kernel_section %lld live_user %lld other %lld\n",
			  atomic64_read(&kjit_neon_hits_kernel), atomic64_read(&kjit_neon_hits_live),
			  atomic64_read(&kjit_neon_hits_other));

	return simple_read_from_buffer(ubuf, count, ppos, buf, n);
}

static const struct file_operations kjit_neon_hits_fops = {
	.read = kjit_neon_hits_read,
	.llseek = default_llseek,
};

static void kjit_neon_noise_stop(void)
{
	int cpu;

	WRITE_ONCE(kjit_neon_period_us, 0);
	for_each_possible_cpu(cpu)
		hrtimer_cancel(per_cpu_ptr(&kjit_neon_timer, cpu));
}

static long kjit_after_syscall(struct pt_regs *regs)
{
	if (!READ_ONCE(kjit_enabled))
		return -1;
	this_cpu_inc(kjit_hook_calls_pcpu);
	return kjit_rs_after_syscall(regs);
}

/*
 * Hook calls while enabled: every syscall without syscall work, in-kernel ones
 * included.
 */
u64 kjit_hook_calls(void)
{
	u64 sum = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		sum += per_cpu(kjit_hook_calls_pcpu, cpu);
	return sum;
}

/*
 * Fault fixups of running fragments. Only reached for addresses no other
 * exception table claims. The entry stays valid while the caller runs: only
 * the task running a fragment faults in it, inside a hook call, and a retired
 * fragment stays on the list until a hook-SRCU grace period after its
 * retirement.
 */
static const struct exception_table_entry *kjit_search_extable(unsigned long addr)
{
	const struct exception_table_entry *found = NULL;
	struct kjit_frag *f;

	rcu_read_lock();
	list_for_each_entry_rcu(f, &kjit_all_frags, all_node) {
		unsigned long base = (unsigned long)f->image;
		u32 lo = 0, hi = f->n_extable;

		if (addr - base >= f->code_len)
			continue;
		while (lo < hi) {
			u32 mid = lo + (hi - lo) / 2;
			const struct exception_table_entry *e = &f->extable[mid];
			unsigned long insn = (unsigned long)&e->insn + e->insn;

			if (insn == addr) {
				found = e;
				break;
			}
			if (insn < addr)
				lo = mid + 1;
			else
				hi = mid;
		}
		break;
	}
	rcu_read_unlock();
	return found;
}

/* ------------------------------------------------------------------------- */
/* Auto mode (P3): profiler and task_work translation requests                 */

/*
 * One queued translation of @pc. Holds no reference: @mm is only compared,
 * never dereferenced, and the kjit_mm is found again by (@mm, @kmm_id) under
 * RCU, so neither a dying mm nor module unload waits for it.
 */
struct kjit_request {
	struct kjit_task_work tw;	/* first: the kernel kfree()s an orphaned request */
	struct mm_struct *mm;
	u64 kmm_id;
	u64 pc;
};

static u64 kjit_window_ticks(void)
{
	return (u64)READ_ONCE(kjit_hot_window_ms) * arch_timer_get_cntfrq() / MSEC_PER_SEC;
}

/* The negative-cache index of @pc, or -1. */
static int kjit_neg_find_locked(const struct kjit_mm *kmm, u64 pc)
{
	unsigned int i;

	for (i = 0; i < KJIT_NEG_SLOTS; i++)
		if (kmm->neg[i] == pc)
			return i;
	return -1;
}

static void kjit_neg_add_locked(struct kjit_mm *kmm, u64 pc, u64 word)
{
	unsigned int i = kmm->neg_next++ % KJIT_NEG_SLOTS;

	if (kmm->neg[i])
		kjit_rs_note(KJIT_NOTE_NEG_EVICTED, 1);
	kmm->neg[i] = pc;
	kmm->neg_word[i] = word;
	kjit_rs_note(KJIT_NOTE_NEG_ADDED, 1);
}

/*
 * Counts one hit of @pc at arch counter @now. Returns true if @pc just became
 * hot and a request must be queued; the slot is then marked queued (and
 * counted in kmm->queued) until kjit_request_done(). A hit of a PC known to
 * start with an untranslatable word sets *@stop to that tagged word instead.
 */
static bool kjit_prof_hit_locked(struct kjit_mm *kmm, u64 pc, u64 now, u64 *stop)
{
	u32 h = hash_64(pc, KJIT_PROF_BITS), threshold = READ_ONCE(kjit_hot_threshold);
	struct kjit_prof_slot *s = NULL, *victim = NULL;
	u64 window = kjit_window_ticks();
	unsigned int i;
	int neg;

	lockdep_assert_held(&kmm->lock);
	for (i = 0; i < KJIT_PROF_PROBE; i++) {
		struct kjit_prof_slot *c = &kmm->prof[(h + i) & (KJIT_PROF_SLOTS - 1)];

		if (c->pc == pc) {
			s = c;
			break;
		}
		/* A free slot, or one whose window is over (it was not hot). */
		if (!victim && !c->queued && (!c->pc || now - c->start > window))
			victim = c;
	}
	if (!s) {
		if (!victim) {
			kjit_rs_note(KJIT_NOTE_PROF_FULL, 1);
			return false;
		}
		s = victim;
		s->pc = pc;
		s->start = now;
		s->hits = 0;
		s->stop_word = 0;
	}
	if (s->queued)
		return false;
	if (s->stop_word) {
		/* Keep the slot fresh (not a victim) while the stops go on. */
		s->start = now;
		*stop = s->stop_word;
		return false;
	}
	if (now - s->start > window) {
		s->start = now;
		s->hits = 0;
	}
	if (++s->hits < threshold)
		return false;

	/* Hot. Whatever happens next, the next request needs a fresh window. */
	s->start = now;
	s->hits = 0;
	neg = kjit_neg_find_locked(kmm, pc);
	if (neg >= 0) {
		kjit_rs_note(KJIT_NOTE_HOT_NEGATIVE, 1);
		s->stop_word = kmm->neg_word[neg];
		return false;
	}
	/* Pre-check only; kjit_install() enforces the caps. */
	if (!kjit_caps_allow(kmm, 0)) {
		kjit_rs_note(KJIT_NOTE_HOT_CAPPED, 1);
		return false;
	}
	if (kmm->queued >= KJIT_MAX_QUEUED_PER_MM) {
		kjit_rs_note(KJIT_NOTE_HOT_QUEUE_FULL, 1);
		return false;
	}
	s->queued = true;
	kmm->queued++;
	return true;
}

/*
 * Whether a failed translation of a PC would fail again on the same text:
 * compile, encode or verifier failure (-EINVAL, -EPERM), text outside an
 * executable non-writable mapping or unmapped (-EACCES, -EFAULT), over the
 * text budget (-E2BIG), or FP/SIMD code on a CPU with SVE/SME (-ENODEV).
 * Races, memory, a fatal signal, a dying mm and the caps
 * are transient: the PC is profiled again.
 */
static bool kjit_failure_is_final(int ret)
{
	switch (ret) {
	case -EAGAIN:
	case -ENOMEM:
	case -EINTR:
	case -ESRCH:
	case -ENOSPC:
		return false;
	default:
		return true;
	}
}

/*
 * The request for @pc of (@mm, @id) is finished with @ret (0 or -EEXIST:
 * installed); @word is the tagged entry word for -ENOEXEC. Frees its profile
 * slot and records a final failure in the negative cache. The kjit_mm may be
 * gone (mm exited): then nothing is left to update.
 */
static void kjit_request_done(struct mm_struct *mm, u64 id, u64 pc, int ret, u64 word)
{
	bool final = ret && ret != -EEXIST && kjit_failure_is_final(ret);
	u32 h = hash_64(pc, KJIT_PROF_BITS);
	struct kjit_mm *kmm;
	unsigned int i;

	rcu_read_lock();
	kmm = kjit_mm_find_rcu(mm);
	if (kmm && kmm->id == id) {
		spin_lock(&kmm->lock);
		for (i = 0; i < KJIT_PROF_PROBE; i++) {
			struct kjit_prof_slot *s = &kmm->prof[(h + i) & (KJIT_PROF_SLOTS - 1)];

			if (s->pc == pc && s->queued) {
				kmm->queued--;
				memset(s, 0, sizeof(*s));
				/* Count the stops at this word from now on. */
				if (final && word) {
					s->pc = pc;
					s->start = arch_timer_read_counter();
					s->stop_word = word;
				}
				break;
			}
		}
		if (final)
			kjit_neg_add_locked(kmm, pc, word);
		spin_unlock(&kmm->lock);
	}
	rcu_read_unlock();
}

/* Queues the translation of @pc in current's context. */
static void kjit_request(struct mm_struct *mm, u64 id, u64 pc, u32 kind)
{
	struct kjit_request *req = kmalloc(sizeof(*req), GFP_KERNEL);
	int ret = -ENOMEM;

	if (req) {
		req->mm = mm;
		req->kmm_id = id;
		req->pc = pc;
		ret = kjit_queue_task_work(&req->tw);
		if (!ret) {
			atomic64_inc(&kjit_req_queued);
			kjit_rs_note(kind == KJIT_HOT_EXIT_TARGET ? KJIT_NOTE_REQ_EXIT_TARGET :
				     KJIT_NOTE_REQ_SVC_RESUME, 1);
			return;
		}
		/* -ESRCH: current is exiting; nothing will run the request. */
		kfree(req);
	}
	kjit_rs_note(KJIT_NOTE_REQ_DROPPED, 1);
	/* Both errors are transient: the slot is freed, the PC profiled again. */
	kjit_request_done(mm, id, pc, ret, 0);
}

/*
 * The runtime's ops->task_work (kernel-patches/0004): translate the request's
 * PC in the requesting task's own context, which is the context the manual
 * trigger emulates with a remote mm. The request is stale if the task has
 * exec'd (another mm), is exiting (no mm), or auto mode was switched off.
 */
static void kjit_task_work(struct kjit_task_work *tw)
{
	struct kjit_request *req = container_of(tw, struct kjit_request, tw);
	struct mm_struct *mm = current->mm;
	struct kjit_mm *kmm;
	int ret = -ESRCH;
	u32 word = 0;

	if (mm && mm == req->mm && !(current->flags & PF_EXITING) &&
	    READ_ONCE(kjit_auto) && READ_ONCE(kjit_enabled)) {
		/* current->mm: mm_users is held. */
		kmm = kjit_mm_get(mm);
		if (!IS_ERR(kmm)) {
			if (kmm->id == req->kmm_id) {
				u64 t0 = ktime_get_ns();

				ret = kjit_rs_translate(kmm, req->pc, false, &word);
				kjit_rs_note(KJIT_NOTE_TRANSLATE_NS, ktime_get_ns() - t0);
			}
			kjit_mm_put(kmm);
		}
	} else {
		kjit_rs_note(KJIT_NOTE_REQ_STALE, 1);
	}
	kjit_request_done(req->mm, req->kmm_id, req->pc, ret,
			  ret == -ENOEXEC ? KJIT_WORD_TAG | word : 0);
	kfree(req);
	atomic64_inc(&kjit_req_ran);
}

/*
 * Auto mode, from the syscall path: one more hit of @pc, a PC current's mm has
 * no fragment for and at which userspace is about to resume. The first hit of
 * an mm sets up its kjit_mm (mmu_notifier registration, may sleep) and is not
 * counted. After that, a hit costs a hash lookup, a spinlock and an arch
 * counter read, and allocates nothing; a PC that becomes hot allocates its
 * request.
 */
void kjit_profile(u64 pc, u32 kind)
{
	struct mm_struct *mm = current->mm;
	struct kjit_mm *kmm;
	bool queue = false;
	u64 id = 0, stop = 0;

	if (!READ_ONCE(kjit_auto) || !mm || !pc)
		return;
	rcu_read_lock();
	kmm = kjit_mm_find_rcu(mm);
	if (kmm) {
		u64 now = arch_timer_read_counter();

		spin_lock(&kmm->lock);
		if (!kmm->dead && !kmm->disabled)
			queue = kjit_prof_hit_locked(kmm, pc, now, &stop);
		id = kmm->id;
		spin_unlock(&kmm->lock);
	}
	rcu_read_unlock();
	if (stop)
		kjit_rs_note_entry_stop((u32)stop);

	if (queue) {
		kjit_request(mm, id, pc, kind);
	} else if (!kmm) {
		/* current->mm: mm_users is held. The hash keeps the kjit_mm. */
		kmm = kjit_mm_get(mm);
		if (IS_ERR(kmm)) {
			/*
			 * Fallback: -ENOMEM, or -EINTR from mm_take_all_locks()
			 * with a signal pending. Profiling only starts later; the
			 * next hit retries.
			 */
			kjit_rs_note(KJIT_NOTE_MM_SETUP_FAILED, 1);
			return;
		}
		kjit_mm_put(kmm);
		kjit_rs_note(KJIT_NOTE_MM_CREATED, 1);
	}
}

static const struct kjit_hook_ops kjit_hook_ops = {
	.after_syscall = kjit_after_syscall,
	.search_extable = kjit_search_extable,
	.task_work = kjit_task_work,
};

/* ------------------------------------------------------------------------- */
/* debugfs: /sys/kernel/debug/kjit/                                            */

static struct mm_struct *kjit_get_pid_mm(pid_t pid)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *p;

	p = find_get_pid(pid);
	if (!p)
		return ERR_PTR(-ESRCH);
	task = get_pid_task(p, PIDTYPE_PID);
	put_pid(p);
	if (!task)
		return ERR_PTR(-ESRCH);
	mm = get_task_mm(task);
	put_task_struct(task);
	return mm ? mm : ERR_PTR(-EINVAL);
}

static int kjit_copy_cmd(char *buf, size_t size, const char __user *ubuf, size_t count)
{
	if (!count || count >= size)
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';
	return 0;
}

/* "<pid> <pc>": translate one entry PC of that process. */
static ssize_t kjit_translate_write(struct file *file, const char __user *ubuf,
				    size_t count, loff_t *ppos)
{
	struct mm_struct *mm;
	struct kjit_mm *kmm;
	char buf[64];
	u64 pc;
	int pid, ret;

	ret = kjit_copy_cmd(buf, sizeof(buf), ubuf, count);
	if (ret)
		return ret;
	if (sscanf(buf, "%d %lli", &pid, &pc) != 2)
		return -EINVAL;
	mm = kjit_get_pid_mm(pid);
	if (IS_ERR(mm))
		return PTR_ERR(mm);
	kmm = kjit_mm_get(mm);
	if (IS_ERR(kmm)) {
		ret = PTR_ERR(kmm);
	} else {
		ret = kjit_rs_translate(kmm, pc, true, NULL);
		kjit_mm_put(kmm);
	}
	mmput(mm);
	return ret ? ret : count;
}

struct kjit_range {
	unsigned long start, end;
};

#define KJIT_MAX_TEXT_RANGES 256

/*
 * "<pid>": translate the resume PC (svc + 4) of every aligned SVC word in the
 * process's executable, non-writable mappings. Failures of single sites are
 * counted in stats; the write fails only if the scan itself fails.
 */
static ssize_t kjit_svc_sites_write(struct file *file, const char __user *ubuf,
				    size_t count, loff_t *ppos)
{
	struct kjit_range *ranges;
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	struct kjit_mm *kmm;
	unsigned int n = 0, i;
	u64 sites = 0;
	char buf[32];
	u8 *page;
	int pid, ret;

	ret = kjit_copy_cmd(buf, sizeof(buf), ubuf, count);
	if (ret)
		return ret;
	if (kstrtoint(strim(buf), 0, &pid))
		return -EINVAL;
	mm = kjit_get_pid_mm(pid);
	if (IS_ERR(mm))
		return PTR_ERR(mm);

	ranges = kcalloc(KJIT_MAX_TEXT_RANGES, sizeof(*ranges), GFP_KERNEL);
	page = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!ranges || !page) {
		ret = -ENOMEM;
		goto out_mm;
	}
	kmm = kjit_mm_get(mm);
	if (IS_ERR(kmm)) {
		ret = PTR_ERR(kmm);
		goto out_mm;
	}

	ret = mmap_read_lock_killable(mm);
	if (ret)
		goto out_kmm;
	{
		VMA_ITERATOR(vmi, mm, 0);

		for_each_vma(vmi, vma) {
			if (!(vma->vm_flags & VM_EXEC) || (vma->vm_flags & VM_WRITE))
				continue;
			if (n == KJIT_MAX_TEXT_RANGES) {
				ret = -E2BIG;
				break;
			}
			ranges[n].start = vma->vm_start;
			ranges[n].end = vma->vm_end;
			n++;
		}
	}
	mmap_read_unlock(mm);
	if (ret)
		goto out_kmm;

	for (i = 0; i < n; i++) {
		unsigned long addr;

		for (addr = ranges[i].start; addr < ranges[i].end; addr += PAGE_SIZE) {
			unsigned int w;

			ret = kjit_read_text_page(kmm, addr, page);
			/* The mapping changed under the scan: skip what is gone. */
			if (ret == -EFAULT || ret == -EACCES)
				continue;
			if (ret)
				goto out_kmm;
			for (w = 0; w < PAGE_SIZE / 4; w++) {
				u32 word = le32_to_cpu(((__le32 *)page)[w]);

				/* SVC #imm16 */
				if ((word & 0xffe0001f) != 0xd4000001)
					continue;
				sites++;
				/* Per-site results are counted in stats. */
				kjit_rs_translate(kmm, addr + w * 4 + 4, false, NULL);
				cond_resched();
				if (fatal_signal_pending(current)) {
					ret = -EINTR;
					goto out_kmm;
				}
			}
		}
	}
	kjit_rs_note(KJIT_NOTE_SVC_SITES, sites);
	pr_info("kjit: translate_svc_sites pid %d: %u text ranges, %llu svc sites\n", pid, n, sites);
	ret = 0;
out_kmm:
	kjit_mm_put(kmm);
out_mm:
	kfree(page);
	kfree(ranges);
	mmput(mm);
	return ret ? ret : count;
}

static ssize_t kjit_stats_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
	size_t size = 2 * PAGE_SIZE;
	char *buf = kmalloc(size, GFP_KERNEL);
	ssize_t ret;
	size_t len;

	if (!buf)
		return -ENOMEM;
	len = kjit_rs_stats_show(buf, size);
	/* Gauges (A16): link slots patched to a `b` / waiting as a `nop`, over all mms. */
	len += scnprintf(buf + len, size - len, "link_sites_linked %ld\nlink_sites_pending %ld\n",
			 atomic_long_read(&kjit_links_linked),
			 atomic_long_read(&kjit_links_pending));
	/* Gauges (A17): arena chunks, and bytes in live slots. */
	len += scnprintf(buf + len, size - len, "arena_chunks %ld\narena_bytes %ld\n",
			 atomic_long_read(&kjit_arena_nchunks),
			 atomic_long_read(&kjit_arena_nbytes));
	ret = simple_read_from_buffer(ubuf, count, ppos, buf, len);
	kfree(buf);
	return ret;
}

/* The Unsupported words seen at runtime, most frequent first (runtime/stats.rs). */
static ssize_t kjit_unsupported_read(struct file *file, char __user *ubuf, size_t count,
				     loff_t *ppos)
{
	size_t size = 4 * PAGE_SIZE;
	char *buf = kmalloc(size, GFP_KERNEL);
	ssize_t ret;

	if (!buf)
		return -ENOMEM;
	ret = simple_read_from_buffer(ubuf, count, ppos, buf, kjit_rs_unsupported_show(buf, size));
	kfree(buf);
	return ret;
}

/*
 * Dispatch-table conflict diagnostics (runtime/ibtc.rs): the slots with most
 * conflict misses, per table. Writing "reset" zeroes them.
 */
static ssize_t kjit_ibtc_slots_read(struct file *file, char __user *ubuf, size_t count,
				    loff_t *ppos)
{
	size_t size = 2 * PAGE_SIZE;
	char *buf = kmalloc(size, GFP_KERNEL);
	ssize_t ret;

	if (!buf)
		return -ENOMEM;
	ret = simple_read_from_buffer(ubuf, count, ppos, buf, kjit_rs_ibtc_slots_show(buf, size));
	kfree(buf);
	return ret;
}

static ssize_t kjit_ibtc_slots_write(struct file *file, const char __user *ubuf,
				     size_t count, loff_t *ppos)
{
	char buf[16];
	int ret = kjit_copy_cmd(buf, sizeof(buf), ubuf, count);

	if (ret)
		return ret;
	if (strcmp(strim(buf), "reset"))
		return -EINVAL;
	kjit_rs_ibtc_slots_reset();
	return count;
}

static const struct file_operations kjit_translate_fops = {
	.owner = THIS_MODULE,
	.write = kjit_translate_write,
};

static const struct file_operations kjit_svc_sites_fops = {
	.owner = THIS_MODULE,
	.write = kjit_svc_sites_write,
};

static const struct file_operations kjit_stats_fops = {
	.owner = THIS_MODULE,
	.read = kjit_stats_read,
};

static const struct file_operations kjit_unsupported_fops = {
	.owner = THIS_MODULE,
	.read = kjit_unsupported_read,
};

static const struct file_operations kjit_ibtc_slots_fops = {
	.owner = THIS_MODULE,
	.read = kjit_ibtc_slots_read,
	.write = kjit_ibtc_slots_write,
};

/* ------------------------------------------------------------------------- */
/* Module init/exit (called from rust_kjit.rs)                                 */

/*
 * CPU features the translator's output relies on (docs/pipeline.md, "Kernel
 * runtime (K2)", Preconditions). Sanitised ID registers: the value every CPU
 * supports. Returns 0 or -ENODEV, naming the missing feature.
 */
static int kjit_check_cpu(void)
{
	u64 mmfr2 = read_sanitised_ftr_reg(SYS_ID_AA64MMFR2_EL1);
	u64 isar0 = read_sanitised_ftr_reg(SYS_ID_AA64ISAR0_EL1);
	u64 isar1 = read_sanitised_ftr_reg(SYS_ID_AA64ISAR1_EL1);

	/*
	 * FEAT_LSE2: a misaligned LDAR/STLR/LDAPR inside a 16-byte block must
	 * not fault natively, since the fragment's LDTR/STTR-family access for
	 * it does not.
	 */
	if (!cpuid_feature_extract_unsigned_field(mmfr2, ID_AA64MMFR2_EL1_AT_SHIFT)) {
		pr_err("kjit: CPU lacks FEAT_LSE2 (ID_AA64MMFR2_EL1.AT == 0): fragments would not fault on misaligned acquire/release accesses that fault natively; refusing to load\n");
		return -ENODEV;
	}
	/* ...and with SCTLR_EL1.nAA clear (Linux never sets it). */
	if (read_sysreg(sctlr_el1) & SCTLR_EL1_nAA) {
		pr_err("kjit: SCTLR_EL1.nAA is set: misaligned acquire/release accesses fault natively; refusing to load\n");
		return -ENODEV;
	}
	/* FEAT_LRCPC: else user LDAPR is UNDEFINED natively but would run in a fragment. */
	if (!cpuid_feature_extract_unsigned_field(isar1, ID_AA64ISAR1_EL1_LRCPC_SHIFT)) {
		pr_err("kjit: CPU lacks FEAT_LRCPC (ID_AA64ISAR1_EL1.LRCPC == 0): user LDAPR is UNDEFINED natively but would run in a fragment; refusing to load\n");
		return -ENODEV;
	}
	/*
	 * FEAT_CRC32: else user CRC32* / CRC32C* are UNDEFINED natively, and in a
	 * fragment they would be an undefined instruction at EL1.
	 */
	if (!cpuid_feature_extract_unsigned_field(isar0, ID_AA64ISAR0_EL1_CRC32_SHIFT)) {
		pr_err("kjit: CPU lacks FEAT_CRC32 (ID_AA64ISAR0_EL1.CRC32 == 0): user CRC32 is UNDEFINED natively but would run in a fragment; refusing to load\n");
		return -ENODEV;
	}
	/*
	 * A8 window accesses (docs/pipeline.md, "LSE atomics through a PAN window
	 * (A8)"): user LSE atomics run as privileged accesses, in a run that
	 * executes with PAN clear (A15).
	 * FEAT_LSE: else user LD<op>/SWP/CAS are UNDEFINED natively but would
	 * run in a fragment.
	 */
	if (cpuid_feature_extract_unsigned_field(isar0, ID_AA64ISAR0_EL1_ATOMIC_SHIFT) <
	    ID_AA64ISAR0_EL1_ATOMIC_IMP) {
		pr_err("kjit: CPU lacks FEAT_LSE (ID_AA64ISAR0_EL1.Atomic < 2): user LSE atomics are UNDEFINED natively but would run in a fragment; refusing to load\n");
		return -ENODEV;
	}
	/*
	 * The window's range check admits VA bits [55:48] == 0 only: a TTBR0
	 * address below 2^48. That is all of user space only with 48-bit VAs
	 * (K1 pins ARM64_VA_BITS_48).
	 */
	if (vabits_actual != 48) {
		pr_err("kjit: vabits_actual is %llu, not 48: a window access's range check assumes 48-bit user VAs; refusing to load\n",
		       (unsigned long long)vabits_actual);
		return -ENODEV;
	}
	/*
	 * A privileged access does not honour the user's tag-check mode the way
	 * LDTR/STTR do (TCF0), so a window atomic would skip MTE tag checks.
	 */
	if (system_supports_mte()) {
		pr_err("kjit: MTE is in use: a window atomic is a privileged access that skips the user's tag checks; refusing to load\n");
		return -ENODEV;
	}
	/*
	 * A15: a run executes with PAN clear and relies on an exception taken
	 * inside it setting PAN (SCTLR_EL1.SPAN == 0, which cpu_enable_pan()
	 * establishes); with SPAN set, an interrupt handler would run with PAN
	 * clear.
	 */
	if (read_sysreg(sctlr_el1) & SCTLR_EL1_SPAN) {
		pr_err("kjit: SCTLR_EL1.SPAN is set: an exception inside a fragment run would keep PAN clear; refusing to load\n");
		return -ENODEV;
	}
	return 0;
}

/*
 * A10: a fragment executes the user's `mrs Xt, cntvct_el0` and
 * `mrs Xt, cntfrq_el0` at EL1. EL1 reads the same virtual count (CNTPCT -
 * CNTVOFF at EL0 and EL1 alike) and frequency, so that is exact while EL0
 * reads them from the hardware too: CNTKCTL_EL1.EL0VCTEN set (which also
 * makes CNTFRQ_EL0 readable at EL0), and no out-of-line timer erratum
 * workaround for CNTVCT (arch_counter_set_user_access() clears EL0VCTEN on
 * such a CPU, so EL0 reads trap and the kernel emulates them with the
 * workaround's stable read). Both are per CPU and established when the CPU
 * starts (CPUHP_AP_ARM_ARCH_TIMER_STARTING, before this ONLINE_DYN state), so
 * this runs on every online CPU at load (a failure fails the load) and on every
 * CPU that comes online while kjit is loaded (a failure fails its onlining).
 * EL0VCTEN changes after that only for compat tasks (ARM64_ERRATUM_1418040),
 * which never run fragments.
 */
static enum cpuhp_state kjit_counter_cpuhp;

static int kjit_counter_cpu_online(unsigned int cpu)
{
	if (!(read_sysreg(cntkctl_el1) & ARCH_TIMER_USR_VCT_ACCESS_EN)) {
		pr_err("kjit: CPU%u: CNTKCTL_EL1.EL0VCTEN is clear: EL0 counter reads trap, a fragment's would not; refusing\n",
		       cpu);
		return -ENODEV;
	}
	/* Runs in this CPU's hotplug thread, so the per-CPU read is stable. */
	if (has_erratum_handler(read_cntvct_el0)) {
		pr_err("kjit: CPU%u: a timer erratum workaround emulates EL0 CNTVCT_EL0 reads; refusing\n",
		       cpu);
		return -ENODEV;
	}
	return 0;
}

int kjit_glue_init(void)
{
	int ret, cpu;

	ret = kjit_check_cpu();
	if (ret)
		return ret;
	/* The mirrored link slot word is the kernel's nop (A16). */
	if (WARN_ON(aarch64_insn_gen_nop() != KJIT_LINK_NOP_WORD))
		return -EINVAL;
	if (!kjit_fpsimd_supported())
		pr_info("kjit: SVE/SME present or no FP/SIMD: fragments that use FP/SIMD will not be installed\n");
	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "kjit/counter:online",
				kjit_counter_cpu_online, NULL);
	if (ret < 0)
		return ret;
	kjit_counter_cpuhp = ret;

	for_each_possible_cpu(cpu)
		hrtimer_setup(per_cpu_ptr(&kjit_neon_timer, cpu), kjit_neon_timer_fn,
			      CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED_SOFT);
	kjit_wq = alloc_workqueue("kjit", WQ_UNBOUND, 0);
	if (!kjit_wq) {
		cpuhp_remove_state_nocalls(kjit_counter_cpuhp);
		return -ENOMEM;
	}
	kjit_debugfs = debugfs_create_dir("kjit", NULL);
	debugfs_create_file("translate", 0200, kjit_debugfs, NULL, &kjit_translate_fops);
	debugfs_create_file("translate_svc_sites", 0200, kjit_debugfs, NULL, &kjit_svc_sites_fops);
	debugfs_create_file("stats", 0400, kjit_debugfs, NULL, &kjit_stats_fops);
	debugfs_create_bool("enable", 0600, kjit_debugfs, &kjit_enabled);
	debugfs_create_bool("auto", 0600, kjit_debugfs, &kjit_auto);
	debugfs_create_u32("hot_threshold", 0600, kjit_debugfs, &kjit_hot_threshold);
	debugfs_create_u32("hot_window_ms", 0600, kjit_debugfs, &kjit_hot_window_ms);
	debugfs_create_file_unsafe("chain_budget", 0600, kjit_debugfs, NULL, &kjit_chain_budget_fops);
	debugfs_create_file("unsupported_top", 0400, kjit_debugfs, NULL, &kjit_unsupported_fops);
	debugfs_create_file("ibtc_slots", 0600, kjit_debugfs, NULL, &kjit_ibtc_slots_fops);
	debugfs_create_file_unsafe("neon_noise_us", 0600, kjit_debugfs, NULL, &kjit_neon_noise_fops);
	debugfs_create_file("neon_noise_hits", 0400, kjit_debugfs, NULL, &kjit_neon_hits_fops);

	ret = kjit_register_hook(&kjit_hook_ops);
	if (ret) {
		debugfs_remove(kjit_debugfs);
		destroy_workqueue(kjit_wq);
		cpuhp_remove_state_nocalls(kjit_counter_cpuhp);
	}
	return ret;
}

void kjit_glue_exit(void)
{
	struct kjit_mm *kmm;
	unsigned int bkt;

	/* No new translations (waits for writers in flight). */
	debugfs_remove(kjit_debugfs);
	kjit_neon_noise_stop();
	/*
	 * No hook calls, extable lookups or task_work requests in here after
	 * this; requests still queued are freed by the kernel (0004). Fragments
	 * running in hook calls in flight keep their fault fixups until those
	 * calls have returned (0006).
	 */
	kjit_unregister_hook(&kjit_hook_ops);
	pr_info("kjit: %lld of %lld translation requests still queued at unload (freed by the kernel)\n",
		atomic64_read(&kjit_req_queued) - atomic64_read(&kjit_req_ran),
		atomic64_read(&kjit_req_queued));

	for (;;) {
		struct kjit_mm *victim = NULL;

		/*
		 * Claim the hash reference under the lock, so a concurrent mm
		 * release cannot drop it (and free the kmm) under us.
		 */
		spin_lock(&kjit_mm_lock);
		hash_for_each(kjit_mm_hash, bkt, kmm, hash_node) {
			victim = kmm;
			break;
		}
		if (victim) {
			hash_del_rcu(&victim->hash_node);
			victim->hashed = false;
		}
		spin_unlock(&kjit_mm_lock);
		if (!victim)
			break;
		kjit_mm_kill(victim);
		mmu_notifier_put(&victim->mn);
	}
	/* free_notifier callbacks (module code) have run after this. */
	mmu_notifier_synchronize();
	/*
	 * Fragment retirements and kjit_mm frees are hook-SRCU callbacks (module
	 * code); all of them have run after this, and what they queue is queued...
	 */
	kjit_hook_srcu_barrier();
	/* ...kvfree_rcu and the rcu_work frees are queued after this... */
	rcu_barrier();
	/* ...and the image frees have run after this. */
	destroy_workqueue(kjit_wq);
	WARN_ON(!list_empty(&kjit_all_frags));
	/* Every fragment is retired: no link record is left linked or pending (A16). */
	WARN_ON(atomic_long_read(&kjit_links_linked) || atomic_long_read(&kjit_links_pending));
	/* ...and every slot is released and every chunk freed (A17). */
	WARN_ON(atomic_long_read(&kjit_arena_nchunks) || atomic_long_read(&kjit_arena_nbytes) ||
		!list_empty(&kjit_arena_chunks));
	cpuhp_remove_state_nocalls(kjit_counter_cpuhp);
}
