//! Independent fragment verifier (V3): the security boundary between the
//! translator and EL1 execution.
//!
//! Input is only what the kernel holds: the encoded fragment bytes, its fault-site
//! table and its entry-offset table, all offset-relative. The verifier re-derives
//! every fact it checks from the generated A64 decoder and `shared::abi`; it never
//! imports the translator (`shared::trans`, `shared::emit`), so a translator bug
//! cannot also be a verifier bug. The rules are listed in docs/pipeline.md,
//! "Verifier (V3)".
//!
//! Cost: one decode pass and one check pass over the words, one pass over each
//! table, and each exit group walked once: O(words + fault sites + entries) time,
//! O(words) memory.

mod rules;
mod scc;
mod taint;

use crate::shared::abi::{
    dispatch_template_matches, ABI_INSN_SIZE, BUDGET_COUNTER_REG, DISPATCH_SLOT_REG, DISPATCH_TARGET_REG,
    DISPATCH_TEMPLATE_LEN, DISPATCH_TEMPLATE_MISS_BRANCHES, DISPATCH_TEMPLATE_MISS_TARGETS,
    DISPATCH_TEMPLATE_VICTIM_PROBE, EPILOGUE_LEN_BYTES, EPILOGUE_OFFSET, KJIT_DISPATCH_TEMPLATE,
    KJIT_EPILOGUE, KJIT_PROLOGUE, PROLOGUE_LEN_BYTES,
};
use crate::shared::arm64::{A64Insn, A64Mem};
use crate::shared::platform::{SharedVec, GFP_KERNEL};

use rules::{classify, reads, writes, Form};
use taint::Taint;

/// First body byte: layout order is prologue, epilogue, body, cold region.
pub const BODY_OFFSET: usize = PROLOGUE_LEN_BYTES + EPILOGUE_LEN_BYTES;

/// One fault-site entry as the kernel's extable holds it: a user-access fault at
/// `access_offset` resumes at `stub_offset`. (The original PC is not needed: the
/// stub itself loads the resume PC.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultSiteEntry {
    pub access_offset: usize,
    pub stub_offset: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct VerifyInput<'a> {
    pub code: &'a [u8],
    /// Sorted by `access_offset`, strictly increasing.
    pub fault_sites: &'a [FaultSiteEntry],
    /// Every offset the runtime may pass as the entry address.
    pub entry_offsets: &'a [usize],
    /// A16 link slots: (byte offset of the slot, user PC the runtime may link it to),
    /// in any order. Rule 10.
    pub link_sites: &'a [(usize, u64)],
}

/// What an accepted fragment is, derived from its bytes alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyOk {
    /// Some word is an A9a SIMD&FP form (register-only, or a window load/store):
    /// the fragment reads or writes the user's V registers, which the kernel must
    /// hold live while it runs (docs/pipeline.md, "FP/SIMD in fragments (A9)", Kernel).
    pub uses_fpsimd: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyError {
    /// Fragment byte offset of the offending word (for an entry-table error, the
    /// rejected entry offset).
    pub offset: usize,
    pub rule: VerifyRule,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyRule {
    /// Length not a whole number of words, or no body word.
    Length,
    Alloc,
    /// 1: the word matches no generated form, or the form makes it UNDEFINED.
    Undecodable {
        word: u32,
    },
    /// 2: prologue/epilogue word differs from `shared::abi`.
    Prologue,
    Epilogue,
    /// 2: the body writes SP (destination, or base writeback).
    SpWrite,
    /// 2: the body writes x29, the kernel frame pointer.
    FramePointerWrite,
    /// Generated operand metadata names a field the form does not have.
    OperandMetadata,
    /// 3: a user access based on SP (the runtime frame is never user memory).
    UserAccessSpBase,
    /// 3: a user access with no fault-site entry.
    MissingFaultSite,
    /// 3: fault table not strictly increasing.
    FaultSiteOrder,
    /// 3: a fault-site entry that is not on a user access.
    FaultSiteNotUserAccess,
    /// 3: a user-code load/store/prefetch form (byte/half/signed, unscaled,
    /// register offset, literal, 32-bit pair, PRFM, acquire/release), or BTI:
    /// translation lowers these, so one in a fragment is neither a user nor a
    /// runtime access (nor an allowlisted system instruction).
    UserOnlyForm,
    /// 3: a runtime access with base writeback.
    RuntimeAccessWriteback,
    /// 3: a runtime access whose base is neither SP nor a proven pt_regs pointer.
    RuntimeAccessBase,
    /// 3: an SP access outside the user-state frame slots.
    FrameAccessOutOfRange,
    /// 3: a pt_regs access outside `regs[]` + `sp`.
    PtRegsAccessOutOfRange,
    /// 2/6 (A12): physical x18 (`BUDGET_COUNTER_REG`) read or written by any word but
    /// a budget check's `sub x18, x18, #1` and `cbz x18` (or a check that guards
    /// neither a back-edge nor a dispatch template).
    BudgetRegisterAccess,
    /// 4: a direct branch target outside the fragment, into the prologue, into
    /// the epilogue other than its first word, or into the cold region other than
    /// an exit-group start.
    BranchTarget {
        target: i64,
    },
    /// 4: `BL`.
    Call,
    /// 4: `BR`/`BLR`/`RET` outside the prologue/epilogue and the dispatch template's
    /// two `br x12` words.
    IndirectBranch,
    /// 4/6/9 (A11, A11c): a `br x12` that is not word 8 or word 19 of the exact
    /// dispatch template, a template whose main-probe miss branches do not name its
    /// word 9 or whose victim-probe miss branches are not the same forward body word
    /// that is an exit-group start, a join point inside the template (an edge into
    /// word 9 from outside it included), or two overlapping templates.
    DispatchTemplate,
    /// 10 (A16, A20): a link-site entry whose slot is not a body `nop` inside a
    /// dispatch template's guarded run, that is listed twice or is a join point, or
    /// whose following words up to the template's first word are not exactly one
    /// `movz` and up to three `movk`s of x13 (each halfword set once) giving the
    /// entry's target PC, or that contain a join point.
    LinkSite,
    /// 4: the last word can fall through past the fragment.
    FallsOffEnd,
    /// 4: an entry offset outside the body, in the cold region, or unaligned.
    EntryOffset,
    /// 4: empty entry table.
    NoEntry,
    /// 5: `SVC` (and any exception-generating form).
    Exception,
    /// 5: `ADR`/`ADRP` (kernel address into a user register).
    PcRelative,
    /// 6: a back-edge on a cycle (A22) not preceded by the budget check (plus only
    /// reg-virt fill loads), or a dispatch template (A11) not preceded by it (plus only
    /// data-processing words and fills), or a join point inside that run.
    MissingBudgetCheck,
    /// 7: a fault/budget stub that does not start an exit group, or an exit group
    /// that does not end in `b <epilogue>`.
    ExitGroup,
    /// 8 (A8, A9a, A15): a window access (LSE atomic, base-only SIMD&FP load/store)
    /// not preceded by `ubfx sB, sA, #48, #8; cbnz sB, <S>` with the access based
    /// on sA and S a forward exit-group start, or with a join point on the `cbnz`
    /// or the access.
    WindowRangeCheck,
    /// 8 (A15): any `MSR` (PSTATE.PAN). A fragment never writes PAN; the trampoline
    /// clears it around the run.
    Msr,
    /// 9: a kernel value (SP, x29, the pt_regs pointer, the entry address) read
    /// other than as the base of an allowed runtime access: as data, a branch
    /// operand, or the base of a user access.
    KernelValueRead,
    /// 9: a kernel value live across a control edge (branch, fall-through into a
    /// join point, fault edge of a user access) other than one every join point
    /// already assumes.
    KernelValueAtEdge,
}

const fn err(offset: usize, rule: VerifyRule) -> VerifyError {
    VerifyError { offset, rule }
}

pub fn verify_fragment(input: &VerifyInput<'_>) -> Result<VerifyOk, VerifyError> {
    let code = input.code;
    if code.len() % ABI_INSN_SIZE != 0 || code.len() <= BODY_OFFSET {
        return Err(err(code.len(), VerifyRule::Length));
    }

    check_wrapper(code, 0, KJIT_PROLOGUE, VerifyRule::Prologue)?;
    check_wrapper(code, EPILOGUE_OFFSET, KJIT_EPILOGUE, VerifyRule::Epilogue)?;

    let body = decode_body(code)?;
    // Dispatch templates (A11): every `br x12` is a probe's end of the exact template. Found before
    // the other tables because every later check treats their words specially.
    let templates = find_dispatch_templates(code, &body)?;
    let frag = Fragment {
        body: &body,
        len: code.len(),
        templates: &templates,
    };

    // Join points: every place control can arrive other than by falling through.
    // The taint dataflow (rules 3 and 9) restarts at each of them.
    let mut join = alloc_bools(body.len())?;

    // Fault table: sorted, every entry on a user access, every stub an exit group.
    let mut exit_group_checked = alloc_bools(body.len())?;
    let mut cold_start = body.len();
    let mut previous = None;
    for site in input.fault_sites {
        if previous.is_some_and(|prev| site.access_offset <= prev) {
            return Err(err(site.access_offset, VerifyRule::FaultSiteOrder));
        }
        previous = Some(site.access_offset);
        let access = frag
            .body_index(site.access_offset)
            .ok_or(err(site.access_offset, VerifyRule::FaultSiteNotUserAccess))?;
        let stub = frag
            .body_index(site.stub_offset)
            .ok_or(err(site.stub_offset, VerifyRule::ExitGroup))?;
        if !matches!(
            classify(body[access]),
            Form::UserAccess { .. } | Form::WindowAccess { .. }
        ) {
            return Err(err(site.access_offset, VerifyRule::FaultSiteNotUserAccess));
        }
        check_exit_group(&frag, stub, &mut exit_group_checked)?;
        join[stub] = true;
        cold_start = cold_start.min(stub);
    }

    // Budget stubs are exit groups too, and join points. A back-edge on a cycle
    // without its check is rejected in the main pass.
    for index in 0..body.len() {
        if !frag.is_back_edge(index) {
            continue;
        }
        if let Some((_, stub)) = frag.budget_guard(index) {
            check_exit_group(&frag, stub, &mut exit_group_checked)?;
            join[stub] = true;
            cold_start = cold_start.min(stub);
        }
    }

    // A window access's range check leaves through a forward exit group (rule 8),
    // which belongs to the cold region like any stub.
    for index in 0..body.len() {
        if matches!(classify(body[index]), Form::WindowAccess { .. }) {
            let stub = window_range_check(&frag, index)?;
            check_exit_group(&frag, stub, &mut exit_group_checked)
                .map_err(|_| err(frag.offset(index), VerifyRule::WindowRangeCheck))?;
            join[stub] = true;
            cold_start = cold_start.min(stub);
        }
    }

    // A dispatch template's budget check has a Budget stub like a back-edge's (an
    // exit group, a join point); its miss target is the site's exit group. A
    // template without its check is rejected here.
    for index in 0..body.len() {
        if templates.position[index] != Some(0) {
            continue;
        }
        let (_, stub) = frag
            .template_guard(index)
            .ok_or(err(frag.offset(index), VerifyRule::MissingBudgetCheck))?;
        check_exit_group(&frag, stub, &mut exit_group_checked)?;
        join[stub] = true;
        cold_start = cold_start.min(stub);
        let miss = templates.miss[index].ok_or(err(frag.offset(index), VerifyRule::DispatchTemplate))?;
        check_exit_group(&frag, miss, &mut exit_group_checked)?;
        join[miss] = true;
    }

    // Cold region: from the first stub on, the fragment is exit groups only (layout
    // order). It is entered by fault fixup or by a branch to an exit-group start,
    // never through the entry table.
    if input.entry_offsets.is_empty() {
        return Err(err(0, VerifyRule::NoEntry));
    }
    for &entry in input.entry_offsets {
        let index = frag
            .body_index(entry)
            .filter(|&index| index < cold_start)
            .ok_or(err(entry, VerifyRule::EntryOffset))?;
        join[index] = true;
    }
    for (index, insn) in body.iter().enumerate() {
        if let Form::Branch { delta, .. } = classify(*insn) {
            let offset = frag.offset(index);
            let target = offset as i64 + delta;
            let target_error = err(offset, VerifyRule::BranchTarget { target });
            if !frag.is_branch_target(target) {
                return Err(target_error);
            }
            if let Some(target_index) = frag.body_index(target as usize) {
                // The main probe's miss branches name the victim probe's first word
                // (checked exact by `find_dispatch_templates`): the one edge into a
                // template's inside, and not a join point -- the dataflow carries the
                // state across it (the join state, as after the main probe's `br`).
                // Any other edge into the template makes a join point there.
                if let Some(position) = templates.position[index] {
                    if DISPATCH_TEMPLATE_MISS_BRANCHES[..2].contains(&(position as usize))
                        && target_index + position as usize
                            == index + DISPATCH_TEMPLATE_VICTIM_PROBE
                    {
                        continue;
                    }
                }
                if target_index >= cold_start
                    && check_exit_group(&frag, target_index, &mut exit_group_checked).is_err()
                {
                    return Err(target_error);
                }
                join[target_index] = true;
            }
        }
    }

    // Rule 10 (A16, A20): every link slot is a `nop` inside a template's guarded run,
    // followed by exactly the `movz`/`movk`s of x13 that set the slot's target PC, then
    // the template. Before the generic join check below, so a join point on a slot or
    // a move is reported as the link-site error it is.
    let mut slot_listed = alloc_bools(body.len())?;
    for &(slot_offset, target_pc) in input.link_sites {
        let reject = err(slot_offset, VerifyRule::LinkSite);
        let slot = frag.body_index(slot_offset).ok_or(reject)?;
        if slot_listed[slot] || !matches!(body[slot], A64Insn::NopNopHiHints {}) {
            return Err(reject);
        }
        slot_listed[slot] = true;
        let moves = slot + 1;
        let template = moves
            + body[moves.min(body.len())..]
                .iter()
                .take_while(|insn| is_x13_wide_move(insn))
                .count();
        if templates.position.get(template) != Some(&Some(0)) {
            return Err(reject);
        }
        let (guard, _) = frag.template_guard(template).ok_or(reject)?;
        if guard + BUDGET_CHECK_WORDS > slot
            || (slot..template).any(|inner| join[inner])
            || link_target_of(&body[moves..template]) != Some(target_pc)
        {
            return Err(reject);
        }
    }

    // Rules 4/6 (A11): nothing arrives inside a dispatch template, or between its
    // budget check's `sub` and the template, by any edge: every path to the `br`
    // runs the whole check and the whole template.
    for index in 0..body.len() {
        if templates.position[index] != Some(0) {
            continue;
        }
        let (guard, _) = frag
            .template_guard(index)
            .ok_or(err(frag.offset(index), VerifyRule::MissingBudgetCheck))?;
        if (index..index + DISPATCH_TEMPLATE_LEN).any(|inner| join[inner]) {
            return Err(err(frag.offset(index), VerifyRule::DispatchTemplate));
        }
        if (guard + 1..index).any(|inner| join[inner]) {
            return Err(err(frag.offset(index), VerifyRule::MissingBudgetCheck));
        }
    }

    // Rule 8: nothing jumps into a window access past its range check (the `ubfx`
    // may be a join point: it recomputes the checked value).
    for index in 0..body.len() {
        if matches!(classify(body[index]), Form::WindowAccess { .. })
            && (join[index - 1] || join[index])
        {
            return Err(err(frag.offset(index), VerifyRule::WindowRangeCheck));
        }
    }

    // Main pass, with the taint dataflow (rules 3 and 9, `taint.rs`): `state`
    // holds, for every path that reaches this word without crossing a join point,
    // the registers holding kernel values and those proven to hold the pt_regs
    // pointer. Every join point starts from the entry state; every edge into one
    // (and every exit) must carry no kernel value beyond it, so that start is
    // sound.
    let join_state = Taint::at_entry().ok_or(err(0, VerifyRule::Prologue))?;
    let component =
        scc::components(body.len(), |word, slot| frag.successor(word, slot, body.len()))
            .map_err(|_| err(0, VerifyRule::Alloc))?;
    let mut state = join_state;
    let mut sites = input.fault_sites.iter();
    let mut uses_fpsimd = false;
    for (index, insn) in body.iter().enumerate() {
        let offset = frag.offset(index);
        if join[index] {
            // Falling through into a join point is an edge too.
            check_edge(state, join_state, offset)?;
            state = join_state;
        }
        if let Some(position) = templates.position[index] {
            state = step_dispatch_template(position, state, join_state, offset)?;
            continue;
        }
        let form = classify(*insn);
        check_budget_register(&frag, index, insn)?;
        match form {
            Form::Alu | Form::Nop | Form::Barrier | Form::MrsUserReg => {}
            Form::Simd => uses_fpsimd = true,
            Form::PcRelative => return Err(err(offset, VerifyRule::PcRelative)),
            Form::UserOnly => return Err(err(offset, VerifyRule::UserOnlyForm)),
            Form::Call => return Err(err(offset, VerifyRule::Call)),
            Form::IndirectBranch => return Err(err(offset, VerifyRule::IndirectBranch)),
            Form::Exception => return Err(err(offset, VerifyRule::Exception)),
            Form::Branch { .. } => {
                if frag.is_back_edge_on_cycle(&component, index) {
                    check_budget_before(&frag, &join, index)?;
                }
                // Into the body or the epilogue: the epilogue reads no register
                // of the join state (`join_state_is_dead_in_the_epilogue`).
                check_edge(state, join_state, offset)?;
            }
            Form::UserAccess { mem } => {
                if rules::is_sp(mem.base()) {
                    return Err(err(offset, VerifyRule::UserAccessSpBase));
                }
                // The fault edge to the stub.
                check_edge(state, join_state, offset)?;
                // The table is sorted and every entry is on a user access (checked
                // above), so the next entry must be this one.
                match sites.next() {
                    Some(site) if site.access_offset == offset => {}
                    _ => return Err(err(offset, VerifyRule::MissingFaultSite)),
                }
            }
            Form::WindowAccess { fpsimd, .. } => {
                uses_fpsimd |= fpsimd;
                check_edge(state, join_state, offset)?;
                match sites.next() {
                    Some(site) if site.access_offset == offset => {}
                    _ => return Err(err(offset, VerifyRule::MissingFaultSite)),
                }
            }
            Form::Msr => return Err(err(offset, VerifyRule::Msr)),
            Form::RuntimeAccess { mem, bytes, .. } => {
                check_runtime_access(&frag, index, *insn, mem, bytes, state)?;
            }
        }

        let written = writes(insn).ok_or(err(offset, VerifyRule::OperandMetadata))?;
        if written.sp {
            return Err(err(offset, VerifyRule::SpWrite));
        }
        if written.gprs & (1 << rules::KERNEL_FP_REG) != 0 {
            return Err(err(offset, VerifyRule::FramePointerWrite));
        }

        // Rule 9: a kernel value is never read as data, and is a base only of a
        // runtime access (SP: a frame access; the pt_regs pointer: checked above).
        let read = reads(insn).ok_or(err(offset, VerifyRule::OperandMetadata))?;
        let user_base = match form {
            Form::UserAccess { .. } | Form::WindowAccess { .. } => read.base,
            _ => None,
        };
        if read.sp
            || read.gprs & state.kernel != 0
            || user_base.is_some_and(|base| state.is_kernel(base.enc()))
        {
            return Err(err(offset, VerifyRule::KernelValueRead));
        }

        state = taint::step(insn, form, state).ok_or(err(offset, VerifyRule::OperandMetadata))?;
        if matches!(
            form,
            Form::Branch {
                conditional: false,
                ..
            }
        ) {
            // Only a join point can reach the next word.
            state = join_state;
        }
    }

    let last = body.len() - 1;
    if !matches!(
        classify(body[last]),
        Form::Branch {
            conditional: false,
            ..
        }
    ) {
        return Err(err(frag.offset(last), VerifyRule::FallsOffEnd));
    }
    Ok(VerifyOk { uses_fpsimd })
}

struct Fragment<'a> {
    /// Decoded words from `BODY_OFFSET` on.
    body: &'a [A64Insn],
    len: usize,
    templates: &'a DispatchTemplates,
}

/// Words of a budget check: `sub x18, x18, #1; cbz x18, <stub>`.
const BUDGET_CHECK_WORDS: usize = 2;

/// Most words (target move, link write, link slot, fills) the budget check's `cbz` may
/// be away from its dispatch template: BL's 4-word link write, link slot and 4-word
/// target move are the longest site (9). Bounded so each template's walk back is O(1).
const DISPATCH_GUARD_MAX_GAP: usize = 16;

impl Fragment<'_> {
    fn offset(&self, index: usize) -> usize {
        BODY_OFFSET + index * ABI_INSN_SIZE
    }

    /// Index of an aligned in-body offset.
    fn body_index(&self, offset: usize) -> Option<usize> {
        if offset < BODY_OFFSET || offset >= self.len || offset % ABI_INSN_SIZE != 0 {
            return None;
        }
        Some((offset - BODY_OFFSET) / ABI_INSN_SIZE)
    }

    /// A direct branch may go to the epilogue's first word (a runtime exit) or to
    /// any body word; never into the prologue or the rest of the epilogue.
    fn is_branch_target(&self, target: i64) -> bool {
        target == EPILOGUE_OFFSET as i64
            || usize::try_from(target).is_ok_and(|target| self.body_index(target).is_some())
    }

    /// A direct branch to a body word at or before itself (layout order is offset
    /// order). Branches to the epilogue are exits, not back-edges. Whether it needs
    /// a budget check is `is_back_edge_on_cycle`; a check on any back-edge is allowed.
    fn is_back_edge(&self, index: usize) -> bool {
        let Form::Branch { delta, .. } = classify(self.body[index]) else {
            return false;
        };
        let offset = self.offset(index) as i64;
        let target = offset + delta;
        target <= offset && target >= BODY_OFFSET as i64
    }

    /// Slot `slot` (0 or 1) of word `index`'s successors in the body word graph of
    /// rule 6 (A22), over the words before `nodes`: every word after the epilogue,
    /// the cold region included, so that no cycle can hide in it whatever the other
    /// rules allow there. The next word unless the word is an unconditional `B` or an
    /// indirect branch, and the target of a direct branch after the epilogue. A
    /// branch to the epilogue and a template's `br` add no edge.
    fn successor(&self, index: usize, slot: usize, nodes: usize) -> Option<usize> {
        let (target, falls_through) = match classify(self.body[index]) {
            Form::Branch { delta, conditional } => {
                let target = usize::try_from(self.offset(index) as i64 + delta)
                    .ok()
                    .and_then(|target| self.body_index(target));
                (target, conditional)
            }
            Form::IndirectBranch => (None, false),
            _ => (None, true),
        };
        [falls_through.then_some(index + 1), target]
            .into_iter()
            .flatten()
            .filter(|&successor| successor < nodes)
            .nth(slot)
    }

    /// Whether the branch at `index` is a back-edge on a cycle (A22): a back-edge
    /// whose target shares its component of the body word graph (`component`, over
    /// every word after the epilogue), so that the budget check is required.
    fn is_back_edge_on_cycle(&self, component: &[usize], index: usize) -> bool {
        let Form::Branch { delta, .. } = classify(self.body[index]) else {
            return false;
        };
        let target = usize::try_from(self.offset(index) as i64 + delta)
            .ok()
            .and_then(|target| self.body_index(target));
        self.is_back_edge(index)
            && target.is_some_and(|target| {
                index < component.len() && component[index] == component[target]
            })
    }

    /// The budget check guarding the branch at `index`: the two-word sequence,
    /// then only fill loads up to the branch. Returns the sequence's first index
    /// and its `cbz` target, which must be a forward body word.
    fn budget_guard(&self, index: usize) -> Option<(usize, usize)> {
        let mut end = index;
        while end > 0 && rules::is_budget_fill(&self.body[end - 1]) {
            end -= 1;
        }
        let start = end.checked_sub(BUDGET_CHECK_WORDS)?;
        let delta = rules::budget_sequence(&self.body[start..end])?;
        let cbz = self.offset(end - 1) as i64;
        let target = cbz + delta;
        if target <= cbz {
            return None;
        }
        Some((start, self.body_index(usize::try_from(target).ok()?)?))
    }

    /// The budget check guarding the dispatch template whose first word is at
    /// `template` (A11): the two-word sequence, then only data-processing words and
    /// fill loads (target move, link write) up to the template. Returns the
    /// sequence's first index and its `cbz` target, which must be a forward body word.
    fn template_guard(&self, template: usize) -> Option<(usize, usize)> {
        let mut end = template;
        while end > 0
            && template - end < DISPATCH_GUARD_MAX_GAP
            && rules::is_dispatch_gap_word(&self.body[end - 1])
        {
            end -= 1;
        }
        let start = end.checked_sub(BUDGET_CHECK_WORDS)?;
        let delta = rules::budget_sequence(&self.body[start..end])?;
        let cbz = self.offset(end - 1) as i64;
        let target = cbz + delta;
        if target <= cbz {
            return None;
        }
        Some((start, self.body_index(usize::try_from(target).ok()?)?))
    }

    /// Whether a budget sequence starting at `start` is the guard of a dispatch
    /// template.
    fn guards_template(&self, start: usize) -> bool {
        let mut index = start + BUDGET_CHECK_WORDS;
        while index < self.body.len()
            && index - (start + BUDGET_CHECK_WORDS) <= DISPATCH_GUARD_MAX_GAP
            && rules::is_dispatch_gap_word(&self.body[index])
        {
            index += 1;
        }
        index < self.body.len()
            && self.templates.position[index] == Some(0)
            && self
                .template_guard(index)
                .is_some_and(|(guard, _)| guard == start)
    }

    /// Whether a budget sequence starting at `start` is the guard of a back-edge.
    fn guards_back_edge(&self, start: usize) -> bool {
        let mut branch = start + BUDGET_CHECK_WORDS;
        while branch < self.body.len() && rules::is_budget_fill(&self.body[branch]) {
            branch += 1;
        }
        branch < self.body.len()
            && self.is_back_edge(branch)
            && self
                .budget_guard(branch)
                .is_some_and(|(guard, _)| guard == start)
    }
}

/// Rule 4/6/9 (A11) facts: which body words belong to a dispatch template.
struct DispatchTemplates {
    /// `Some(p)`: word `p` (0..`DISPATCH_TEMPLATE_LEN`) of a template.
    position: SharedVec<Option<u8>>,
    /// Template's first word -> the body index its miss branches target.
    miss: SharedVec<Option<usize>>,
}

/// Every `br x12` must be word 8 (the main probe's) or word 19 (the victim probe's) of
/// the exact dispatch template (`dispatch_template_matches`: registers, `#200`, the
/// `ubfx` lsb/width, the fold, `#8, lsl #12`, the key compares). Its main-probe miss
/// branches must name the template's word 9, its victim-probe ones the same forward
/// body word after word 19 (`DISPATCH_TEMPLATE_MISS_TARGETS`). A `br x12` found
/// first is taken as the main probe's end, which fixes the template's start; the
/// second is then already inside it. Any other `br` is `Form::IndirectBranch`,
/// rejected by the main pass. Two templates never share a word.
fn find_dispatch_templates(
    code: &[u8],
    body: &[A64Insn],
) -> Result<DispatchTemplates, VerifyError> {
    let offset = |index: usize| BODY_OFFSET + index * ABI_INSN_SIZE;
    let mut templates = DispatchTemplates {
        position: alloc_positions(body.len())?,
        miss: alloc_none(body.len())?,
    };
    for (index, insn) in body.iter().enumerate() {
        let A64Insn::BrBr64BranchReg { rn } = insn else {
            continue;
        };
        if rn.enc() != DISPATCH_SLOT_REG || templates.position[index].is_some() {
            continue;
        }
        let reject = err(offset(index), VerifyRule::DispatchTemplate);
        let start = (index + 1)
            .checked_sub(DISPATCH_TEMPLATE_VICTIM_PROBE)
            .ok_or(reject)?;
        let mut words = [0_u32; DISPATCH_TEMPLATE_LEN];
        for (position, word) in words.iter_mut().enumerate() {
            *word = read_word(code, offset(start + position)).ok_or(reject)?;
        }
        let deltas = dispatch_template_matches(&words).ok_or(reject)?;
        let mut exit: Option<i64> = None;
        for ((&branch, &to), &delta) in DISPATCH_TEMPLATE_MISS_BRANCHES
            .iter()
            .zip(&DISPATCH_TEMPLATE_MISS_TARGETS)
            .zip(&deltas)
        {
            let target = offset(start + branch) as i64 + delta;
            if to < DISPATCH_TEMPLATE_LEN {
                if target != offset(start + to) as i64 {
                    return Err(reject);
                }
            } else if exit.is_some_and(|exit| exit != target) {
                return Err(reject);
            } else {
                exit = Some(target);
            }
        }
        // Forward past the final `br`, in the body.
        let miss = exit
            .filter(|&target| target > offset(start + DISPATCH_TEMPLATE_LEN - 1) as i64)
            .and_then(|target| usize::try_from(target).ok())
            .filter(|&target| target >= BODY_OFFSET && (target - BODY_OFFSET) % ABI_INSN_SIZE == 0)
            .map(|target| (target - BODY_OFFSET) / ABI_INSN_SIZE)
            .filter(|&target| target < body.len())
            .ok_or(reject)?;
        if templates.position[start..start + DISPATCH_TEMPLATE_LEN]
            .iter()
            .any(Option::is_some)
        {
            return Err(reject);
        }
        for (position, slot) in templates.position[start..start + DISPATCH_TEMPLATE_LEN]
            .iter_mut()
            .enumerate()
        {
            *slot = Some(position as u8);
        }
        templates.miss[start] = Some(miss);
    }
    Ok(templates)
}

/// Whether `insn` is a 64-bit `movz`/`movk` of `DISPATCH_TARGET_REG`.
fn is_x13_wide_move(insn: &A64Insn) -> bool {
    matches!(
        insn,
        A64Insn::MovzMovz64Movewide { rd, .. } | A64Insn::MovkMovk64Movewide { rd, .. }
            if rd.enc() == DISPATCH_TARGET_REG
    )
}

/// Rule 10: the value the `movz`/`movk` run `moves` (every word already checked by
/// `is_x13_wide_move`, between a link slot and its dispatch template) leaves in
/// `DISPATCH_TARGET_REG`: one `movz` first, then up to three `movk`s, each halfword set
/// once. `None` if the run starts with a `movk` or sets a halfword twice.
fn link_target_of(moves: &[A64Insn]) -> Option<u64> {
    let mut value: Option<u64> = None;
    let mut set_halfwords = 0_u8;
    for insn in moves {
        match insn {
            A64Insn::MovzMovz64Movewide { hw, imm16, .. } => {
                if value.is_some() {
                    return None;
                }
                set_halfwords |= 1 << hw;
                value = Some((imm16.raw() as u64) << (16 * u32::from(*hw)));
            }
            A64Insn::MovkMovk64Movewide { hw, imm16, .. } => {
                let current = value?;
                let shift = 16 * u32::from(*hw);
                if set_halfwords & (1 << hw) != 0 {
                    return None;
                }
                set_halfwords |= 1 << hw;
                value = Some((current & !(0xffff_u64 << shift)) | (imm16.raw() as u64) << shift);
            }
            // Not reachable (the caller passes `is_x13_wide_move` words only); the verifier
            // rejects rather than panics.
            _ => return None,
        }
    }
    value
}

fn alloc_positions(len: usize) -> Result<SharedVec<Option<u8>>, VerifyError> {
    let mut out =
        SharedVec::with_capacity(len, GFP_KERNEL).map_err(|_| err(0, VerifyRule::Alloc))?;
    for _ in 0..len {
        out.push(None, GFP_KERNEL)
            .map_err(|_| err(0, VerifyRule::Alloc))?;
    }
    Ok(out)
}

/// Rules 3 and 9 for one word of a dispatch template, whose bytes
/// `find_dispatch_templates` already proved exact (so nothing else about the word
/// is checked here: its accesses are the template's). The only kernel-valued register
/// of a template is `DISPATCH_SLOT_REG` (x12: the table, the victim part's base, a
/// slot, a record's host): a word that writes x12 makes it a kernel value; any other
/// word writes a value derived from T and the record's pc (the key load reads the
/// record's pc, a user PC the runtime copied from a user branch target: not a
/// source). `template_register_discipline_holds` checks on the words that no other
/// word writes or reads x12 as data. T (x13) must hold no kernel value where a word
/// reads it. A miss branch (`cbz x12` / `cbnz x14`) and a `br x12` are control edges
/// carrying exactly the join state ({x12, x29}): x12 may be read by `cbz` and `br`
/// (the one kernel register operand a branch may have), nothing else is
/// kernel-valued. After a `br` only a join point or the main probe's miss edge can
/// reach the next word, and both carry the join state, so the walk continues from it.
fn step_dispatch_template(
    position: u8,
    state: Taint,
    join_state: Taint,
    offset: usize,
) -> Result<Taint, VerifyError> {
    const SLOT: u32 = 1 << DISPATCH_SLOT_REG;
    const TARGET: u32 = 1 << DISPATCH_TARGET_REG;
    let position = position as usize;
    let insn = KJIT_DISPATCH_TEMPLATE
        .get(position)
        .ok_or(err(offset, VerifyRule::DispatchTemplate))?;
    // Control edges: the miss branches and the `br x12` that ends a probe.
    let is_br = matches!(insn, A64Insn::BrBr64BranchReg { .. });
    if DISPATCH_TEMPLATE_MISS_BRANCHES.contains(&position) || is_br {
        check_edge(state, join_state, offset)?;
        return Ok(if is_br { join_state } else { state });
    }
    let read = reads(insn).ok_or(err(offset, VerifyRule::OperandMetadata))?;
    if read.gprs & TARGET & state.kernel != 0 {
        return Err(err(offset, VerifyRule::KernelValueRead));
    }
    let written = writes(insn).ok_or(err(offset, VerifyRule::OperandMetadata))?;
    let mut next = state;
    next.pt_regs &= !written.gprs;
    next.kernel = if written.gprs & SLOT != 0 {
        (next.kernel & !written.gprs) | SLOT
    } else {
        next.kernel & !written.gprs
    };
    Ok(next)
}

fn check_wrapper(
    code: &[u8],
    start: usize,
    expected: &[A64Insn],
    rule: VerifyRule,
) -> Result<(), VerifyError> {
    for (index, insn) in expected.iter().enumerate() {
        let offset = start + index * ABI_INSN_SIZE;
        let word = insn.encode().map_err(|_| err(offset, rule))?;
        if read_word(code, offset) != Some(word) {
            return Err(err(offset, rule));
        }
    }
    Ok(())
}

fn read_word(code: &[u8], offset: usize) -> Option<u32> {
    let bytes = code.get(offset..offset.checked_add(ABI_INSN_SIZE)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn decode_body(code: &[u8]) -> Result<SharedVec<A64Insn>, VerifyError> {
    let count = (code.len() - BODY_OFFSET) / ABI_INSN_SIZE;
    let mut body = SharedVec::with_capacity(count, GFP_KERNEL)
        .map_err(|_| err(BODY_OFFSET, VerifyRule::Alloc))?;
    for index in 0..count {
        let offset = BODY_OFFSET + index * ABI_INSN_SIZE;
        let word = read_word(code, offset).ok_or(err(offset, VerifyRule::Length))?;
        let insn = A64Insn::decode(word)
            .filter(|insn| !insn.is_decode_undefined())
            .ok_or(err(offset, VerifyRule::Undecodable { word }))?;
        body.push(insn, GFP_KERNEL)
            .map_err(|_| err(offset, VerifyRule::Alloc))?;
    }
    Ok(body)
}

fn alloc_bools(len: usize) -> Result<SharedVec<bool>, VerifyError> {
    let mut out =
        SharedVec::with_capacity(len, GFP_KERNEL).map_err(|_| err(0, VerifyRule::Alloc))?;
    for _ in 0..len {
        out.push(false, GFP_KERNEL)
            .map_err(|_| err(0, VerifyRule::Alloc))?;
    }
    Ok(out)
}

/// Rule 7. `stub` must start an exit group: the word before it cannot fall
/// through (an unconditional `B`), and the straight-line run from it ends in
/// `b <epilogue>` without a user access. Each group is walked once.
fn check_exit_group(
    frag: &Fragment<'_>,
    stub: usize,
    checked: &mut SharedVec<bool>,
) -> Result<(), VerifyError> {
    if checked[stub] {
        return Ok(());
    }
    let reject = |index: usize| err(frag.offset(index), VerifyRule::ExitGroup);
    // The word before cannot fall through: an unconditional `B`, or (A11) the `br x12`
    // that ends a dispatch template, whose miss branches target the group after it.
    let starts_group = stub > 0
        && (matches!(
            classify(frag.body[stub - 1]),
            Form::Branch {
                conditional: false,
                ..
            }
        ) || frag.templates.position[stub - 1] == Some((DISPATCH_TEMPLATE_LEN - 1) as u8));
    if !starts_group {
        return Err(reject(stub));
    }
    for index in stub..frag.body.len() {
        match classify(frag.body[index]) {
            Form::Branch {
                delta,
                conditional: false,
            } if frag.offset(index) as i64 + delta == EPILOGUE_OFFSET as i64 => {
                checked[stub] = true;
                return Ok(());
            }
            Form::Branch { .. }
            | Form::Call
            | Form::IndirectBranch
            | Form::Exception
            | Form::UserAccess { .. }
            | Form::UserOnly
            | Form::WindowAccess { .. }
            | Form::Msr => return Err(reject(index)),
            Form::Alu
            | Form::Simd
            | Form::Nop
            | Form::Barrier
            | Form::MrsUserReg
            | Form::PcRelative
            | Form::RuntimeAccess { .. } => {}
        }
    }
    Err(reject(frag.body.len() - 1))
}

/// Rule 8 (A8, A9a, A15): the window access at `index` is preceded by
///
/// ```text
/// index-2  ubfx sB, sA, #48, #8    (64-bit UBFM immr=48 imms=55, sA/sB < 31)
/// index-1  cbnz sB, <S>            (forward; S starts an exit group)
/// index    <window access, base sA>   (LSE atomic, or base-only SIMD&FP load/store)
/// ```
///
/// Returns S's body index. `S` being an exit group start and the absence of join
/// points on the `cbnz` and the access are checked by the caller; the access's fault
/// site is rule 3's.
fn window_range_check(frag: &Fragment<'_>, index: usize) -> Result<usize, VerifyError> {
    let reject = err(frag.offset(index), VerifyRule::WindowRangeCheck);
    let Form::WindowAccess { rn, .. } = classify(frag.body[index]) else {
        return Err(reject);
    };
    if index < 2 {
        return Err(reject);
    }
    let (sa, sb) = rules::range_check(&frag.body[index - 2]).ok_or(reject)?;
    let (tested, delta) = rules::cbnz64(&frag.body[index - 1]).ok_or(reject)?;
    if tested != sb || rn.enc() != sa || delta <= 0 {
        return Err(reject);
    }
    let target = frag.offset(index - 1) as i64 + delta;
    usize::try_from(target)
        .ok()
        .and_then(|target| frag.body_index(target))
        .ok_or(reject)
}

fn alloc_none(len: usize) -> Result<SharedVec<Option<usize>>, VerifyError> {
    let mut out =
        SharedVec::with_capacity(len, GFP_KERNEL).map_err(|_| err(0, VerifyRule::Alloc))?;
    for _ in 0..len {
        out.push(None, GFP_KERNEL)
            .map_err(|_| err(0, VerifyRule::Alloc))?;
    }
    Ok(out)
}

/// Rule 6: the back-edge at `index` is guarded by the budget check, and nothing
/// jumps past the check's first word (onto the `cbz`, a fill, or the back-edge
/// itself), so every path to the back-edge decrements the budget.
fn check_budget_before(
    frag: &Fragment<'_>,
    join: &SharedVec<bool>,
    index: usize,
) -> Result<(), VerifyError> {
    let missing = err(frag.offset(index), VerifyRule::MissingBudgetCheck);
    let (start, _) = frag.budget_guard(index).ok_or(missing)?;
    if (start + 1..=index).any(|inner| join[inner]) {
        return Err(missing);
    }
    Ok(())
}

/// Rule 2 (A12): physical x18 is the budget counter. The only body words that read or
/// write it are a budget check's `sub x18, x18, #1` and `cbz x18`, and a check must
/// guard a back-edge or a dispatch template (`guards_back_edge`/`guards_template`:
/// the exact shape, the fills and gap words between, and the guarded word). Every
/// other operand naming x18 -- any role, a memory base or its writeback included --
/// is `BudgetRegisterAccess`. Words of a dispatch template never name x18 (they are
/// byte-exact).
fn check_budget_register(
    frag: &Fragment<'_>,
    index: usize,
    insn: &A64Insn,
) -> Result<(), VerifyError> {
    let offset = frag.offset(index);
    let read = reads(insn).ok_or(err(offset, VerifyRule::OperandMetadata))?;
    let written = writes(insn).ok_or(err(offset, VerifyRule::OperandMetadata))?;
    let counter = 1_u32 << BUDGET_COUNTER_REG;
    let names_counter = (read.gprs | written.gprs) & counter != 0
        || read.base.is_some_and(|base| base.enc() == BUDGET_COUNTER_REG);
    if !names_counter {
        return Ok(());
    }
    let check_start = if rules::is_budget_sub(insn) {
        index
    } else if index > 0 && matches!(insn, A64Insn::CbzCbz64Compbranch { .. }) {
        index - 1
    } else {
        return Err(err(offset, VerifyRule::BudgetRegisterAccess));
    };
    let is_check = frag
        .body
        .get(check_start..check_start + BUDGET_CHECK_WORDS)
        .and_then(rules::budget_sequence)
        .is_some();
    if is_check && (frag.guards_back_edge(check_start) || frag.guards_template(check_start)) {
        Ok(())
    } else {
        Err(err(offset, VerifyRule::BudgetRegisterAccess))
    }
}

/// Rule 9: at a control edge, no register holds a kernel value the join state
/// does not already assume.
fn check_edge(state: Taint, join_state: Taint, offset: usize) -> Result<(), VerifyError> {
    if state.kernel & !join_state.kernel != 0 {
        return Err(err(offset, VerifyRule::KernelValueAtEdge));
    }
    Ok(())
}

/// Rule 3 for a plain load/store.
fn check_runtime_access(
    frag: &Fragment<'_>,
    index: usize,
    insn: A64Insn,
    mem: A64Mem,
    bytes: u32,
    state: Taint,
) -> Result<(), VerifyError> {
    let offset = frag.offset(index);
    let A64Mem::Offset { base, offset: imm } = mem else {
        return Err(err(offset, VerifyRule::RuntimeAccessWriteback));
    };
    let start = imm.value();
    let end = start + bytes as i64;
    let within = |lo: u32, hi: u32| start >= lo as i64 && end <= hi as i64;

    if rules::is_sp(base) {
        if rules::is_user_state_slot(start, bytes) || rules::pt_regs_pointer_load(&insn).is_some()
        {
            return Ok(());
        }
        return Err(err(offset, VerifyRule::FrameAccessOutOfRange));
    }

    if state.is_pt_regs(base.enc()) {
        if within(0, rules::PT_REGS_USER_STATE_END) {
            return Ok(());
        }
        return Err(err(offset, VerifyRule::PtRegsAccessOutOfRange));
    }
    Err(err(offset, VerifyRule::RuntimeAccessBase))
}

#[cfg(test)]
mod tests;
