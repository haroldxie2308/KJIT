p='/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/agent-a4b243dcf4b342be4/shared/verify/mod.rs'
s=open(p).read()

def rep(old, new, count=1):
    global s
    assert s.count(old) >= 1, old[:80]
    if count == 1:
        assert s.count(old) == 1, ("ambiguous", old[:80])
    s = s.replace(old, new)

rep("""use crate::shared::abi::{
    dispatch_template_matches, ABI_INSN_SIZE, DISPATCH_KEY_REG, DISPATCH_SLOT_REG,
    DISPATCH_TARGET_REG, DISPATCH_TEMPLATE_LEN, DISPATCH_TEMPLATE_MISS_BRANCHES, EPILOGUE_LEN_BYTES,
    EPILOGUE_OFFSET, KJIT_EPILOGUE, KJIT_PROLOGUE, PROLOGUE_LEN_BYTES,
};""","""use crate::shared::abi::{
    dispatch_template, dispatch_template_matches, DispatchTemplate, ABI_INSN_SIZE,
    DISPATCH_SLOT_REG, DISPATCH_TARGET_REG, EPILOGUE_LEN_BYTES, EPILOGUE_OFFSET, KJIT_EPILOGUE,
    KJIT_PROLOGUE, PROLOGUE_LEN_BYTES,
};""")

# branch loop: template-internal edges
rep("""    for (index, insn) in body.iter().enumerate() {
        if let Form::Branch { delta, .. } = classify(*insn) {
            let offset = frag.offset(index);
            let target = offset as i64 + delta;
            let target_error = err(offset, VerifyRule::BranchTarget { target });
            if !frag.is_branch_target(target) {
                return Err(target_error);
            }
            if let Some(target_index) = frag.body_index(target as usize) {""","""    for (index, insn) in body.iter().enumerate() {
        if let Form::Branch { delta, .. } = classify(*insn) {
            let offset = frag.offset(index);
            let target = offset as i64 + delta;
            let target_error = err(offset, VerifyRule::BranchTarget { target });
            if !frag.is_branch_target(target) {
                return Err(target_error);
            }
            if let Some(target_index) = frag.body_index(target as usize) {
                // A miss branch of a template to a later probe of the same template
                // (found exact by `find_dispatch_templates`) is not a join point:
                // every other edge into a template is, and is rejected below.
                if templates.position[index].is_some() && templates.position[target_index].is_some()
                {
                    continue;
                }""")

rep("""    // Rules 4/6 (A11): nothing arrives inside a dispatch template, or between its
    // budget check's `sub` and the template, by any edge: every path to the `br`
    // runs the whole check and the whole template.
    for index in 0..body.len() {
        if templates.position[index] != Some(0) {
            continue;
        }
        let (guard, _) = frag
            .template_guard(index)
            .ok_or(err(frag.offset(index), VerifyRule::MissingBudgetCheck))?;
        if (index..index + DISPATCH_TEMPLATE_LEN).any(|inner| join[inner]) {""","""    // Rules 4/6 (A11): nothing arrives inside a dispatch template, or between its
    // budget check's `sub` and the template, by any edge but the template's own
    // miss branches to its later probes: every path to a `br` runs the whole check
    // and the probes before it.
    for index in 0..body.len() {
        if templates.position[index] != Some(0) {
            continue;
        }
        let (guard, _) = frag
            .template_guard(index)
            .ok_or(err(frag.offset(index), VerifyRule::MissingBudgetCheck))?;
        if (index..index + dispatch_template().len()).any(|inner| join[inner]) {""")

rep("""        if let Some(position) = templates.position[index] {
            state = step_dispatch_template(position, state, join_state, offset)?;
            continue;
        }""","""        if let Some(position) = templates.position[index] {
            state = step_dispatch_template(position, insn, state, join_state, offset)?;
            continue;
        }""")

rep("""    /// `Some(p)`: word `p` (0..`DISPATCH_TEMPLATE_LEN`) of a template.""","""    /// `Some(p)`: word `p` (0..`dispatch_template().len()`) of a template.""")

a = s.index("/// Every `br x12` must be the last word of the exact dispatch template")
b = s.index("fn alloc_positions(")
new_find = '''/// Every `br x12` must be a `br` word of the exact dispatch template of the selected
/// variant (`dispatch_template_matches`: registers, `#200`, `ubfx` widths, array
/// offsets, the key compares). Its miss branches must go where the template says: to
/// the first word of the next probe, or, for the last probe, all to the same forward
/// body word after the template's final `br`. Any other `br` is `Form::IndirectBranch`,
/// rejected by the main pass. Two templates never share a word.
fn find_dispatch_templates(
    code: &[u8],
    body: &[A64Insn],
) -> Result<DispatchTemplates, VerifyError> {
    let offset = |index: usize| BODY_OFFSET + index * ABI_INSN_SIZE;
    let template = dispatch_template();
    let len = template.len();
    let mut templates = DispatchTemplates {
        position: alloc_positions(body.len())?,
        miss: alloc_none(body.len())?,
    };
    for (index, insn) in body.iter().enumerate() {
        let A64Insn::BrBr64BranchReg { rn } = insn else {
            continue;
        };
        if rn.enc() != DISPATCH_SLOT_REG {
            continue;
        }
        // An inner `br` of a template matched from its first `br`.
        if templates.position[index].is_some() {
            continue;
        }
        let reject = err(offset(index), VerifyRule::DispatchTemplate);
        // This is the first `br` of its template, so its position is the first `br`
        // word's; try every `br` position anyway, the exact words decide.
        let mut found = None;
        for position in (0..len).filter(|&position| template.is_br(position)) {
            let Some(start) = index.checked_sub(position) else {
                continue;
            };
            if start + len > body.len() {
                continue;
            }
            let mut words = [0_u32; MAX_TEMPLATE_WORDS];
            for (word_index, word) in words[..len].iter_mut().enumerate() {
                *word = read_word(code, offset(start + word_index)).ok_or(reject)?;
            }
            if let Some(deltas) = dispatch_template_matches(&words[..len]) {
                found = Some((start, deltas));
                break;
            }
        }
        let (start, deltas) = found.ok_or(reject)?;
        let mut exit: Option<i64> = None;
        for (miss, &delta) in template.misses.iter().zip(deltas.iter()) {
            let target = offset(start + miss.at) as i64 + delta;
            if miss.to < len {
                if target != offset(start + miss.to) as i64 {
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
            .filter(|&target| target > offset(start + len - 1) as i64)
            .and_then(|target| usize::try_from(target).ok())
            .filter(|&target| target >= BODY_OFFSET && (target - BODY_OFFSET) % ABI_INSN_SIZE == 0)
            .map(|target| (target - BODY_OFFSET) / ABI_INSN_SIZE)
            .filter(|&target| target < body.len())
            .ok_or(reject)?;
        if templates.position[start..start + len].iter().any(Option::is_some) {
            return Err(reject);
        }
        for (position, slot) in templates.position[start..start + len].iter_mut().enumerate() {
            *slot = Some(position as u8);
        }
        templates.miss[start] = Some(miss);
    }
    Ok(templates)
}

/// Longest template (`shared::abi`), so a template's words fit one stack array.
const MAX_TEMPLATE_WORDS: usize = 24;

'''
s = s[:a] + new_find + s[b:]

a = s.index("/// Rules 3 and 9 for one word of a dispatch template, whose bytes")
b = s.index("fn check_wrapper(")
new_step = '''/// Rules 3 and 9 for one word of a dispatch template, whose bytes
/// `find_dispatch_templates` already proved exact (so nothing else about the word
/// is checked here: its accesses are the template's). The only kernel-valued register
/// of a template is `DISPATCH_SLOT_REG` (x12: the table, an array base, a slot, a
/// record's host): a word that writes x12 makes it a kernel value, any other word
/// writes a value derived from T and the record's pc (the key load reads the
/// record's pc, a user PC the runtime copied from a user branch target: not a
/// source). `shared::verify::tests` checks, for every variant's template, that no
/// other word reads x12 and that x14/x15 are written before they are read on every
/// path. T (x13) must hold no kernel value where a word reads it. A miss branch
/// (`cbz x12` / `cbnz x14`) and the `br x12` are control edges carrying exactly the
/// join state ({x12, x29}): x12 may be read by `cbz` and `br` (the one kernel
/// register operand a branch may have), nothing else is kernel-valued. After a `br`
/// only a join point or a later probe's miss edge can reach the next word.
fn step_dispatch_template(
    position: u8,
    insn: &A64Insn,
    state: Taint,
    join_state: Taint,
    offset: usize,
) -> Result<Taint, VerifyError> {
    const SLOT: u32 = 1 << DISPATCH_SLOT_REG;
    const TARGET: u32 = 1 << DISPATCH_TARGET_REG;
    let template: &DispatchTemplate = dispatch_template();
    let position = position as usize;
    if position >= template.len() {
        return Err(err(offset, VerifyRule::DispatchTemplate));
    }
    // Control edges: miss branches and the `br x12` of a hit.
    if template.miss_at(position).is_some() || template.is_br(position) {
        check_edge(state, join_state, offset)?;
        return Ok(if template.is_br(position) { join_state } else { state });
    }
    let read = reads(insn).ok_or(err(offset, VerifyRule::OperandMetadata))?;
    if read.gprs & TARGET & state.kernel != 0 {
        return Err(err(offset, VerifyRule::KernelValueRead));
    }
    let written = writes(insn).ok_or(err(offset, VerifyRule::OperandMetadata))?;
    let mut next = state;
    next.pt_regs &= !written.gprs;
    if written.gprs & SLOT != 0 {
        next.kernel = (next.kernel & !written.gprs) | SLOT;
    } else {
        next.kernel &= !written.gprs;
    }
    Ok(next)
}

'''
s = s[:a] + new_step + s[b:]

rep("""        ) || frag.templates.position[stub - 1] == Some((DISPATCH_TEMPLATE_LEN - 1) as u8));""","""        ) || frag.templates.position[stub - 1] == Some((dispatch_template().len() - 1) as u8));""")
open(p,'w').write(s)
