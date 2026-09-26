// SPDX-License-Identifier: GPL-2.0
/*
 * KJIT K2 runtime: kernel-object glue for rust_kjit.rs.
 *
 * Rust owns translation, verification, the image contents, the exit decision
 * table and the statistics (runtime/). This file owns what has no Rust binding
 * and what must interoperate with C-side lifetimes: the hook registration
 * (kernel-patches/0001, 0002), the per-mm code cache and its mmu_notifier,
 * fragment memory (execmem, ROX, I-cache, the arm64 exception table), reading
 * the target's user text, the call trampoline and the debugfs files.
 * Design notes: tmp/pipeline.md, "K2 implementation".
 *
 * Lifetimes and locking
 *
 *   kjit_mm   One per mm with at least one translation request; embeds the
 *             mmu_notifier (mmu_notifier_get/put). Found from the syscall path
 *             through kjit_mm_hash (RCU). The hash membership owns exactly
 *             one notifier reference; whoever unhashes it (mm release or
 *             module exit, under kjit_mm_lock) drops it. Freed by
 *             free_notifier after the notifier SRCU grace period, then
 *             kfree_rcu for the hash readers.
 *   kjit_frag One installed translation. refcount: one reference held by its
 *             kjit_mm's table while it is installed, one per running call.
 *             It stays on kjit_all_frags (the extable search list, RCU) until
 *             its last reference is gone, so a fragment removed from its table
 *             while it runs still has its fault fixups. The image is freed
 *             by a work item after an RCU grace period.
 *   Lock order: kjit_mm.lock -> kjit_frags_lock. kjit_mm_lock is never held
 *             together with either. None of them is held across an allocation
 *             (they are taken inside mmu_notifier invalidation).
 */
#include <linux/bitfield.h>
#include <linux/cacheflush.h>
#include <linux/compat.h>
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/execmem.h>
#include <linux/extable.h>
#include <linux/hashtable.h>
#include <linux/highmem.h>
#include <linux/kjit.h>
#include <linux/mm.h>
#include <linux/mmu_notifier.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/rculist.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/set_memory.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

#include <asm/asm-extable.h>
#include <asm/ptrace.h>

#include <linux/irq-entry-common.h>

/* shared/abi and runtime/exec.rs read pt_regs through these offsets. */
static_assert(offsetof(struct pt_regs, regs) == 0);
static_assert(offsetof(struct pt_regs, sp) == 248);
static_assert(offsetof(struct pt_regs, pc) == 256);
static_assert(offsetof(struct pt_regs, pstate) == 264);
static_assert(sizeof(struct exception_table_entry) == 12);

/* ------------------------------------------------------------------------- */
/* Rust side (runtime/)                                                        */

struct kjit_mm;
long kjit_rs_after_syscall(struct pt_regs *regs);
int kjit_rs_translate(struct kjit_mm *kmm, u64 pc, bool verbose);
size_t kjit_rs_stats_show(char *buf, size_t len);
void kjit_rs_note_invalidated(u64 fragments);
void kjit_rs_note_released(u64 fragments);
void kjit_rs_note_svc_scan(u64 sites);

/* ------------------------------------------------------------------------- */
/* Types and functions shared with runtime/ffi.rs (keep in sync).              */

struct kjit_frag;
struct kjit_site;
struct kjit_label;
int kjit_glue_init(void);
void kjit_glue_exit(void);
u64 kjit_mm_seq(struct kjit_mm *kmm);
int kjit_read_text_page(struct kjit_mm *kmm, u64 addr, u8 *buf);
int kjit_install(struct kjit_mm *kmm, u64 seq, u64 entry_pc,
		 const u8 *code, u32 code_len, u32 entry_offset,
		 const struct kjit_site *sites, u32 n_sites,
		 const struct kjit_label *labels, u32 n_labels,
		 u64 src_start, u64 src_end);
bool kjit_can_run(const struct pt_regs *regs);
struct kjit_frag *kjit_lookup(u64 pc, u64 *entry);
void kjit_frag_put(struct kjit_frag *f);
u64 kjit_frag_base(const struct kjit_frag *f);
s64 kjit_frag_offset_for_pc(const struct kjit_frag *f, u64 pc);
void kjit_bad_status(u64 status, u64 pc);
u64 kjit_call_fragment(struct pt_regs *regs, u64 *extra, u64 entry, u64 base);

/* One fault site: a user access at code offset @access resumes at @stub. */
struct kjit_site {
	u32 access;
	u32 stub;
};

/* One verified entry: original PC -> code offset. Sorted by @pc. */
struct kjit_label {
	u64 pc;
	u32 offset;
	u32 pad;
};

struct kjit_frag {
	refcount_t ref;
	struct hlist_node table_node;	/* kjit_mm.table, under kjit_mm.lock */
	struct list_head all_node;	/* kjit_all_frags, under kjit_frags_lock */
	struct rcu_work free_work;
	u64 entry_pc;
	u64 src_start, src_end;		/* user text the translation read */
	void *image;			/* execmem: code, then the extable */
	size_t image_size;
	u32 code_len;
	u32 entry_offset;
	const struct exception_table_entry *extable;
	u32 n_extable;
	u32 n_labels;
	struct kjit_label labels[] __counted_by(n_labels);
};

#define KJIT_TABLE_BITS 6

struct kjit_mm {
	struct mmu_notifier mn;
	struct hlist_node hash_node;	/* kjit_mm_hash, under kjit_mm_lock */
	bool hashed;			/* under kjit_mm_lock */
	struct rcu_head rcu;
	spinlock_t lock;		/* everything below */
	DECLARE_HASHTABLE(table, KJIT_TABLE_BITS);
	u64 seq;			/* invalidations started */
	unsigned int invalidating;	/* invalidations in progress */
	bool dead;			/* mm released or module exiting */
	bool disabled;			/* runtime bug seen for this mm */
};

static DEFINE_HASHTABLE(kjit_mm_hash, 6);
static DEFINE_SPINLOCK(kjit_mm_lock);
static LIST_HEAD(kjit_all_frags);
static DEFINE_SPINLOCK(kjit_frags_lock);
static struct workqueue_struct *kjit_wq;
static struct dentry *kjit_debugfs;
static bool kjit_enabled = true;

/* ------------------------------------------------------------------------- */
/* Fragments                                                                   */

static void kjit_frag_free_work(struct work_struct *work)
{
	struct kjit_frag *f = container_of(to_rcu_work(work), struct kjit_frag, free_work);

	/* VM_FLUSH_RESET_PERMS (execmem) restores the linear map on vfree. */
	execmem_free(f->image);
	kfree(f);
}

/*
 * Drops a reference. The last one takes the fragment off the extable list and
 * frees it after an RCU grace period (extable searchers and hot-path lookups
 * are RCU readers). Callable in atomic context.
 */
void kjit_frag_put(struct kjit_frag *f)
{
	if (!refcount_dec_and_test(&f->ref))
		return;
	spin_lock(&kjit_frags_lock);
	list_del_rcu(&f->all_node);
	spin_unlock(&kjit_frags_lock);
	INIT_RCU_WORK(&f->free_work, kjit_frag_free_work);
	queue_rcu_work(kjit_wq, &f->free_work);
}

u64 kjit_frag_base(const struct kjit_frag *f)
{
	return (u64)f->image;
}

/*
 * Offset of the verified entry for @pc in @f, or -1. Every label offset was an
 * entry offset of verify_fragment's input.
 */
s64 kjit_frag_offset_for_pc(const struct kjit_frag *f, u64 pc)
{
	u32 lo = 0, hi = f->n_labels;

	while (lo < hi) {
		u32 mid = lo + (hi - lo) / 2;

		if (f->labels[mid].pc == pc)
			return f->labels[mid].offset;
		if (f->labels[mid].pc < pc)
			lo = mid + 1;
		else
			hi = mid;
	}
	return -1;
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
			kjit_frag_put(f);
			n++;
		}
	}
	return n;
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
	kjit_rs_note_released(n);
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
		kjit_rs_note_invalidated(n);
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
	struct kjit_mm *kmm = kzalloc(sizeof(*kmm), GFP_KERNEL);

	if (!kmm)
		return ERR_PTR(-ENOMEM);
	spin_lock_init(&kmm->lock);
	hash_init(kmm->table);
	return &kmm->mn;
}

static void kjit_mn_free(struct mmu_notifier *mn)
{
	struct kjit_mm *kmm = container_of(mn, struct kjit_mm, mn);

	/* Syscall-path readers found it under RCU, not the notifier SRCU. */
	kfree_rcu(kmm, rcu);
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
 * Installs a verified fragment for @entry_pc in @kmm: one execmem allocation
 * holding @code and, after it, one exception_table_entry per fault site
 * (self-relative, so it must be the same allocation), made ROX. Installs only
 * if no invalidation started since @seq (kjit_mm_seq() before the text was
 * read) and none is in progress, so a translation of text that changed while
 * it was read never becomes visible.
 *
 * Returns 0, -EEXIST (@entry_pc already has a fragment), -EAGAIN (raced with
 * an invalidation), -ESRCH (mm gone), -ENOMEM, -EINVAL (malformed tables; the
 * Rust side never passes them), or the set_memory_rox() error.
 */
int kjit_install(struct kjit_mm *kmm, u64 seq, u64 entry_pc,
		 const u8 *code, u32 code_len, u32 entry_offset,
		 const struct kjit_site *sites, u32 n_sites,
		 const struct kjit_label *labels, u32 n_labels,
		 u64 src_start, u64 src_end)
{
	struct exception_table_entry *ex;
	struct kjit_frag *f, *old;
	size_t ex_off, size;
	int ret;
	u32 i;

	if (!code_len || code_len % 4 || entry_offset >= code_len || entry_offset % 4)
		return -EINVAL;
	for (i = 0; i < n_sites; i++)
		if (sites[i].access >= code_len || sites[i].stub >= code_len ||
		    (i && sites[i].access <= sites[i - 1].access))
			return -EINVAL;
	for (i = 0; i < n_labels; i++)
		if (labels[i].offset >= code_len || (i && labels[i].pc <= labels[i - 1].pc))
			return -EINVAL;

	f = kzalloc(struct_size(f, labels, n_labels), GFP_KERNEL);
	if (!f)
		return -ENOMEM;
	f->n_labels = n_labels;
	memcpy(f->labels, labels, flex_array_size(f, labels, n_labels));

	ex_off = ALIGN(code_len, 4);
	size = ex_off + (size_t)n_sites * sizeof(*ex);
	f->image = execmem_alloc(EXECMEM_BPF, size);
	if (!f->image) {
		kfree(f);
		return -ENOMEM;
	}
	f->image_size = PAGE_ALIGN(size);
	f->code_len = code_len;
	f->entry_offset = entry_offset;
	f->entry_pc = entry_pc;
	f->src_start = src_start;
	f->src_end = src_end;
	f->n_extable = n_sites;

	memcpy(f->image, code, code_len);
	ex = f->image + ex_off;
	for (i = 0; i < n_sites; i++) {
		ex[i].insn = (long)(f->image + sites[i].access) - (long)&ex[i].insn;
		ex[i].fixup = (long)(f->image + sites[i].stub) - (long)&ex[i].fixup;
		ex[i].type = EX_TYPE_UACCESS_ERR_ZERO;
		/* xzr for both: the handler only sets pc to the fixup. */
		ex[i].data = FIELD_PREP(EX_DATA_REG_ERR, 31) | FIELD_PREP(EX_DATA_REG_ZERO, 31);
	}
	f->extable = ex;

	flush_icache_range((unsigned long)f->image, (unsigned long)f->image + code_len);
	ret = set_memory_rox((unsigned long)f->image, f->image_size >> PAGE_SHIFT);
	if (ret) {
		execmem_free(f->image);
		kfree(f);
		return ret;
	}
	refcount_set(&f->ref, 1);

	/* On the extable list before anything can run it. */
	spin_lock(&kjit_frags_lock);
	list_add_rcu(&f->all_node, &kjit_all_frags);
	spin_unlock(&kjit_frags_lock);

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
		if (!ret)
			hash_add_rcu(kmm->table, &f->table_node, entry_pc);
	}
	spin_unlock(&kmm->lock);
	if (ret)
		kjit_frag_put(f);
	return ret;
}

/* ------------------------------------------------------------------------- */
/* Syscall path                                                                */

/*
 * Exit-to-user work (signals, rescheduling, task_work/rseq/notify-resume,
 * uprobes, livepatch, MTE async faults), syscall work (ptrace syscall stops,
 * audit, seccomp, syscall tracepoints) and single-step all need the normal
 * return to userspace. TIF_FOREIGN_FPSTATE only asks for an FP register reload
 * before userspace runs; fragments never touch FP/SIMD.
 */
#define KJIT_BAIL_FLAGS \
	((EXIT_TO_USER_MODE_WORK & ~_TIF_FOREIGN_FPSTATE) | _TIF_SYSCALL_WORK | _TIF_SINGLESTEP)

/*
 * The K2 run conditions on the current task (tmp/pipeline.md, "K2 contract",
 * decision table), checked before every fragment entry and before every
 * in-kernel syscall. A traced task is declined as a whole: a tracer may
 * single-step, set watchpoints or read registers at any instruction.
 */
bool kjit_can_run(const struct pt_regs *regs)
{
	unsigned long x0 = regs->regs[0];

	if (is_compat_task() || current->ptrace)
		return false;
	if (read_thread_flags() & KJIT_BAIL_FLAGS)
		return false;
	/* -ERESTARTSYS..-ERESTART_RESTARTBLOCK: the signal code must see it. */
	if (x0 >= (unsigned long)-ERESTART_RESTARTBLOCK && x0 <= (unsigned long)-ERESTARTSYS)
		return false;
	return true;
}

/*
 * Returns the installed fragment for (current->mm, @pc) with a reference, and
 * its entry address in @entry, or NULL.
 */
struct kjit_frag *kjit_lookup(u64 pc, u64 *entry)
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
			if (f->entry_pc == pc && refcount_inc_not_zero(&f->ref)) {
				found = f;
				break;
			}
		}
	}
	rcu_read_unlock();
	if (found)
		*entry = (u64)found->image + found->entry_offset;
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
	kjit_rs_note_released(n);
}

/*
 * u64 kjit_call_fragment(struct pt_regs *regs, u64 extra[2], u64 entry, u64 base)
 *
 * The ABI call (tmp/pipeline.md, "ABI: fragment entry"; mirrors
 * harness/src/native.rs): x0 = regs, x1 = extra params, x2 = entry address,
 * call the fragment at its base. The fragment runs user code, so the user's
 * NZCV (regs->pstate) is live in PSTATE while it runs and is written back
 * afterwards; x19..x29, x30 and sp come back through the fragment epilogue.
 * Returns x0 = RetStatus; extra[0], extra[1] = x10, x11.
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
"	blr	x3\n"
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

static long kjit_after_syscall(struct pt_regs *regs)
{
	if (!READ_ONCE(kjit_enabled))
		return -1;
	return kjit_rs_after_syscall(regs);
}

/*
 * Fault fixups of running fragments. Only reached for addresses no other
 * exception table claims. The entry stays valid while the caller runs: only
 * the task running a fragment faults in it, and it holds a reference.
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

static const struct kjit_hook_ops kjit_hook_ops = {
	.after_syscall = kjit_after_syscall,
	.search_extable = kjit_search_extable,
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
		ret = kjit_rs_translate(kmm, pc, true);
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
				kjit_rs_translate(kmm, addr + w * 4 + 4, false);
				cond_resched();
				if (fatal_signal_pending(current)) {
					ret = -EINTR;
					goto out_kmm;
				}
			}
		}
	}
	kjit_rs_note_svc_scan(sites);
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
	char *buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	ssize_t ret;

	if (!buf)
		return -ENOMEM;
	ret = simple_read_from_buffer(ubuf, count, ppos, buf,
				      kjit_rs_stats_show(buf, PAGE_SIZE));
	kfree(buf);
	return ret;
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

/* ------------------------------------------------------------------------- */
/* Module init/exit (called from rust_kjit.rs)                                 */

int kjit_glue_init(void)
{
	int ret;

	kjit_wq = alloc_workqueue("kjit", WQ_UNBOUND, 0);
	if (!kjit_wq)
		return -ENOMEM;
	kjit_debugfs = debugfs_create_dir("kjit", NULL);
	debugfs_create_file("translate", 0200, kjit_debugfs, NULL, &kjit_translate_fops);
	debugfs_create_file("translate_svc_sites", 0200, kjit_debugfs, NULL, &kjit_svc_sites_fops);
	debugfs_create_file("stats", 0400, kjit_debugfs, NULL, &kjit_stats_fops);
	debugfs_create_bool("enable", 0600, kjit_debugfs, &kjit_enabled);

	ret = kjit_register_hook(&kjit_hook_ops);
	if (ret) {
		debugfs_remove(kjit_debugfs);
		destroy_workqueue(kjit_wq);
	}
	return ret;
}

void kjit_glue_exit(void)
{
	struct kjit_mm *kmm;
	unsigned int bkt;

	/* No new translations (waits for writers in flight). */
	debugfs_remove(kjit_debugfs);
	/* No fragment runs or extable lookups after this. */
	kjit_unregister_hook(&kjit_hook_ops);

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
	/* kfree_rcu and the rcu_work frees are queued after this... */
	rcu_barrier();
	/* ...and the image frees have run after this. */
	destroy_workqueue(kjit_wq);
	WARN_ON(!list_empty(&kjit_all_frags));
}
