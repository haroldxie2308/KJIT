//! Independent fragment verifier (V3): the security boundary between the
//! translator and EL1 execution.
//!
//! Input is only what the kernel holds: the encoded fragment bytes, its fault-site
//! table and its entry-offset table, all offset-relative. The verifier re-derives
//! every fact it checks from the generated A64 decoder and `shared::abi`; it never
//! imports the translator (`shared::trans`, `shared::emit`), so a translator bug
//! cannot also be a verifier bug. The rules are listed in tmp/pipeline.md,
//! "Verifier (V3)".
//!
//! Cost: one decode pass and one check pass over the words, one pass over each
//! table, and each exit group walked once: O(words + fault sites + entries) time,
//! O(words) memory.

mod rules;
mod taint;

use crate::shared::abi::{
    ABI_INSN_SIZE, EPILOGUE_LEN_BYTES, EPILOGUE_OFFSET, KJIT_EPILOGUE, KJIT_PROLOGUE,
    PROLOGUE_LEN_BYTES,
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
}

/// What an accepted fragment is, derived from its bytes alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyOk {
    /// Some word is an A9a SIMD&FP form (register-only, or a window load/store):
    /// the fragment reads or writes the user's V registers, which the kernel must
    /// hold live while it runs (tmp/pipeline.md, "A9 contract", Kernel).
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
    /// 3/6: a budget-slot access that is not part of a budget sequence.
    BudgetSlotAccess,
    /// 4: a direct branch target outside the fragment, into the prologue, into
    /// the epilogue other than its first word, or into the cold region other than
    /// an exit-group start.
    BranchTarget {
        target: i64,
    },
    /// 4: `BL`.
    Call,
    /// 4: `BR`/`BLR`/`RET` outside the prologue/epilogue.
    IndirectBranch,
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
    /// 6: a back-edge not preceded by the budget sequence (plus only reg-virt fill
    /// loads), or a join point inside that run.
    MissingBudgetCheck,
    /// 7: a fault/budget stub that does not start an exit group, or an exit group
    /// that does not end in `b <epilogue>`.
    ExitGroup,
    /// 8 (A8, A9a): a `msr pan, #0` that is not the start of an exact PAN window:
    /// `ubfx sB, sA, #48, #8; cbnz sB, <S>; msr pan, #0; <window access, base sA,
    /// fault site -> S>; msr pan, #1`, with S a PAN stub and the window access an
    /// LSE atomic or a base-only SIMD&FP load/store, or a join point on the
    /// `cbnz`, either MSR or the access.
    PanWindow,
    /// 8: a window access (LSE atomic, base-only SIMD&FP load/store) outside a PAN
    /// window.
    AtomicOutsideWindow,
    /// 8: a `msr pan, #1` that is neither a window's end nor a PAN stub's first word.
    PanSetOutsideWindow,
    /// 8: a PAN stub targeted by anything but a window `cbnz` or the fault site of
    /// that window's access, or a window access whose fault site is not its
    /// window's PAN stub.
    PanStubTarget,
    /// 8: any other `MSR` (PSTATE.PAN with an immediate other than 0/1).
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
    let frag = Fragment {
        body: &body,
        len: code.len(),
    };

    // PAN windows (rule 8): every `msr pan, #0` must start an exact window. Records
    // each window's words and its PAN stub before any table is read.
    let windows = find_pan_windows(&frag)?;

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
        match classify(body[access]) {
            // A PAN stub restores PAN for a window access only.
            Form::UserAccess { .. } if windows.pan_stub[stub] => {
                return Err(err(site.access_offset, VerifyRule::PanStubTarget));
            }
            Form::UserAccess { .. } => {}
            // The window access's fault site is its window's PAN stub.
            Form::WindowAccess { .. } => match windows.access_stub[access] {
                Some(pan_stub) if pan_stub == stub => {}
                Some(_) => return Err(err(site.access_offset, VerifyRule::PanStubTarget)),
                None => return Err(err(site.access_offset, VerifyRule::AtomicOutsideWindow)),
            },
            _ => return Err(err(site.access_offset, VerifyRule::FaultSiteNotUserAccess)),
        }
        check_exit_group(&frag, stub, &mut exit_group_checked)?;
        join[stub] = true;
        cold_start = cold_start.min(stub);
    }

    // Budget stubs are exit groups too, and join points. A back-edge without its
    // check is rejected in the main pass.
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
                // A PAN stub is the target of its windows' range-check `cbnz` only.
                if windows.pan_stub[target_index] && windows.cbnz_stub[index] != Some(target_index)
                {
                    return Err(err(offset, VerifyRule::PanStubTarget));
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

    // Rule 8: nothing jumps into a window past its range check (the `ubfx` may be a
    // join point: it recomputes the checked value).
    for (index, is_start) in windows.clear.iter().enumerate() {
        if *is_start && (index - 1..=index + 2).any(|inner| join[inner]) {
            return Err(err(frag.offset(index), VerifyRule::PanWindow));
        }
    }

    // Main pass, with the taint dataflow (rules 3 and 9, `taint.rs`): `state`
    // holds, for every path that reaches this word without crossing a join point,
    // the registers holding kernel values and those proven to hold the pt_regs
    // pointer. Every join point starts from the entry state; every edge into one
    // (and every exit) must carry no kernel value beyond it, so that start is
    // sound.
    let join_state = Taint::at_entry().ok_or(err(0, VerifyRule::Prologue))?;
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
        let form = classify(*insn);
        match form {
            Form::Alu | Form::Nop | Form::Barrier | Form::MrsUserReg => {}
            Form::Simd => uses_fpsimd = true,
            Form::PcRelative => return Err(err(offset, VerifyRule::PcRelative)),
            Form::UserOnly => return Err(err(offset, VerifyRule::UserOnlyForm)),
            Form::Call => return Err(err(offset, VerifyRule::Call)),
            Form::IndirectBranch => return Err(err(offset, VerifyRule::IndirectBranch)),
            Form::Exception => return Err(err(offset, VerifyRule::Exception)),
            Form::Branch { .. } => {
                if frag.is_back_edge(index) {
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
                if windows.access_stub[index].is_none() {
                    return Err(err(offset, VerifyRule::AtomicOutsideWindow));
                }
                check_edge(state, join_state, offset)?;
                match sites.next() {
                    Some(site) if site.access_offset == offset => {}
                    _ => return Err(err(offset, VerifyRule::MissingFaultSite)),
                }
            }
            // Every `msr pan, #0` was matched to its window by `find_pan_windows`.
            Form::PanClear => {}
            Form::PanSet => {
                if !windows.end[index] && !windows.pan_stub[index] {
                    return Err(err(offset, VerifyRule::PanSetOutsideWindow));
                }
            }
            Form::MsrOther => return Err(err(offset, VerifyRule::Msr)),
            Form::RuntimeAccess { mem, bytes, store } => {
                check_runtime_access(&frag, index, *insn, mem, bytes, store, state)?;
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
}

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
    /// order). Branches to the epilogue are exits, not back-edges.
    fn is_back_edge(&self, index: usize) -> bool {
        let Form::Branch { delta, .. } = classify(self.body[index]) else {
            return false;
        };
        let offset = self.offset(index) as i64;
        let target = offset + delta;
        target <= offset && target >= BODY_OFFSET as i64
    }

    /// The budget check guarding the branch at `index`: the four-word sequence,
    /// then only fill loads up to the branch. Returns the sequence's first index
    /// and its `cbz` target, which must be a forward body word.
    fn budget_guard(&self, index: usize) -> Option<(usize, usize)> {
        let mut end = index;
        while end > 0 && rules::is_budget_fill(&self.body[end - 1]) {
            end -= 1;
        }
        let start = end.checked_sub(4)?;
        let delta = rules::budget_sequence(&self.body[start..end])?;
        let cbz = self.offset(end - 1) as i64;
        let target = cbz + delta;
        if target <= cbz {
            return None;
        }
        Some((start, self.body_index(usize::try_from(target).ok()?)?))
    }

    /// Whether a budget sequence starting at `start` is the guard of a back-edge.
    fn guards_back_edge(&self, start: usize) -> bool {
        let mut branch = start + 4;
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
    let starts_group = stub > 0
        && matches!(
            classify(frag.body[stub - 1]),
            Form::Branch {
                conditional: false,
                ..
            }
        );
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
            // A PAN stub (A8) restores PAN as its first word.
            Form::PanSet if index == stub => {}
            Form::Branch { .. }
            | Form::Call
            | Form::IndirectBranch
            | Form::Exception
            | Form::UserAccess { .. }
            | Form::UserOnly
            | Form::WindowAccess { .. }
            | Form::PanClear
            | Form::PanSet
            | Form::MsrOther => return Err(reject(index)),
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

/// Rule 8 (A8) facts, per body word.
struct PanWindows {
    /// `msr pan, #0` of a window.
    clear: SharedVec<bool>,
    /// `msr pan, #1` ending a window.
    end: SharedVec<bool>,
    /// First word (`msr pan, #1`) of a PAN stub some window's `cbnz` targets.
    pan_stub: SharedVec<bool>,
    /// Window access -> its window's PAN stub.
    access_stub: SharedVec<Option<usize>>,
    /// Window range-check `cbnz` -> its PAN stub.
    cbnz_stub: SharedVec<Option<usize>>,
}

/// Rule 8: every `msr pan, #0` at index i starts the exact window
///
/// ```text
/// i-2  ubfx sB, sA, #48, #8        (64-bit UBFM immr=48 imms=55, sA/sB < 31)
/// i-1  cbnz sB, <S>                (forward; S's first word is msr pan, #1)
/// i    msr  pan, #0
/// i+1  <window access, base sA>  (LSE atomic, or base-only SIMD&FP load/store)
/// i+2  msr  pan, #1
/// ```
///
/// The access's fault site, the PAN stub's exit-group shape and the absence of
/// join points are checked by the callers once the tables and joins are known.
fn find_pan_windows(frag: &Fragment<'_>) -> Result<PanWindows, VerifyError> {
    let len = frag.body.len();
    let mut windows = PanWindows {
        clear: alloc_bools(len)?,
        end: alloc_bools(len)?,
        pan_stub: alloc_bools(len)?,
        access_stub: alloc_none(len)?,
        cbnz_stub: alloc_none(len)?,
    };
    for index in 0..len {
        if classify(frag.body[index]) != Form::PanClear {
            continue;
        }
        let reject = err(frag.offset(index), VerifyRule::PanWindow);
        if index < 2 || index + 2 >= len {
            return Err(reject);
        }
        let (sa, sb) = rules::range_check(&frag.body[index - 2]).ok_or(reject)?;
        let (tested, delta) = rules::cbnz64(&frag.body[index - 1]).ok_or(reject)?;
        let target = frag.offset(index - 1) as i64 + delta;
        let stub = usize::try_from(target)
            .ok()
            .and_then(|target| frag.body_index(target))
            .filter(|&stub| stub > index + 2 && classify(frag.body[stub]) == Form::PanSet)
            .ok_or(reject)?;
        let based_on_sa = matches!(
            classify(frag.body[index + 1]),
            Form::WindowAccess { rn, .. } if rn.enc() == sa
        );
        if tested != sb || !based_on_sa || classify(frag.body[index + 2]) != Form::PanSet {
            return Err(reject);
        }
        windows.clear[index] = true;
        windows.end[index + 2] = true;
        windows.pan_stub[stub] = true;
        windows.access_stub[index + 1] = Some(stub);
        windows.cbnz_stub[index - 1] = Some(stub);
    }
    Ok(windows)
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
/// jumps past the check's first word (onto the `sub`, `str`, `cbz`, a fill, or the
/// back-edge itself), so every path to the back-edge decrements the budget.
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

/// Rule 9: at a control edge, no register holds a kernel value the join state
/// does not already assume.
fn check_edge(state: Taint, join_state: Taint, offset: usize) -> Result<(), VerifyError> {
    if state.kernel & !join_state.kernel != 0 {
        return Err(err(offset, VerifyRule::KernelValueAtEdge));
    }
    Ok(())
}

/// Rule 3 for a plain load/store.
#[allow(clippy::too_many_arguments)]
fn check_runtime_access(
    frag: &Fragment<'_>,
    index: usize,
    insn: A64Insn,
    mem: A64Mem,
    bytes: u32,
    store: bool,
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
        if within(rules::FRAME_USER_START, rules::FRAME_USER_END)
            || rules::pt_regs_pointer_load(&insn).is_some()
        {
            return Ok(());
        }
        if start == rules::BUDGET_SLOT_OFFSET as i64 && bytes == 8 {
            // Only the budget check's own load and store touch the counter.
            let seq_start = if store {
                index.checked_sub(2)
            } else {
                Some(index)
            };
            if seq_start.is_some_and(|start| frag.guards_back_edge(start)) {
                return Ok(());
            }
            return Err(err(offset, VerifyRule::BudgetSlotAccess));
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
