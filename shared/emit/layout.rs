use crate::shared::abi::{
    append_epilogue, append_prologue, DISPATCH_TEMPLATE_LEN, DISPATCH_TEMPLATE_MISS_BRANCHES,
    DISPATCH_TEMPLATE_MISS_TARGETS, DISPATCH_TEMPLATE_VICTIM_PROBE, EPILOGUE_LEN_BYTES,
    EPILOGUE_OFFSET, PROLOGUE_LEN_BYTES,
};
use crate::shared::arm64::{A64Insn, A64OperandRole, A64RewriteError};
use crate::shared::platform::{SharedAllocError, SharedResult, SharedVec, GFP_KERNEL};
use crate::shared::trans::cfg::layout_block_order;
use crate::shared::trans::rephrase::{RephrasedInsnKind, RephrasedProgram};

pub type LayoutVLabels = SharedVec<(u64, usize)>;

/// One user access (`LDTR`/`STTR`, or a PAN window's LSE atomic) of the fragment. A
/// fault on the instruction at `access_offset` resumes at `stub_offset`: the
/// out-of-line `RetStatus::Mem` exit group of the original memory instruction at
/// `ori_pc` (for a window atomic, its PAN stub, which restores PAN first).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultSite {
    pub access_offset: usize,
    pub stub_offset: usize,
    pub ori_pc: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ExecutionFragment {
    pub insns: SharedVec<A64Insn>,
    pub entry_offset: usize,
    /// Body-entry map keyed by original PC. Never points into the cold region.
    pub vlabels: LayoutVLabels,
    /// Every user access, sorted by `access_offset` (strictly increasing).
    pub fault_sites: SharedVec<FaultSite>,
}

impl ExecutionFragment {
    pub fn len_bytes(&self) -> usize {
        self.insns.len() * 4
    }

    pub fn offset_for_pc(&self, original_pc: u64) -> Option<usize> {
        find_vlabel(&self.vlabels, original_pc)
    }

    pub fn fault_site(&self, access_offset: usize) -> Option<FaultSite> {
        self.fault_sites
            .binary_search_by_key(&access_offset, |site| site.access_offset)
            .ok()
            .map(|index| self.fault_sites[index])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutError {
    Alloc(SharedAllocError),
    EmptyProgram,
    MissingLabel {
        target_original_pc: u64,
    },
    BranchOutOfRange {
        insn_index: usize,
        target_original_pc: u64,
    },
    UnalignedBranchTarget {
        insn_index: usize,
        target_original_pc: u64,
    },
    UnsupportedBranchField {
        insn_index: usize,
        field: &'static str,
    },
    /// A user access whose original instruction has no fault stub.
    MissingFaultStub {
        insn_index: usize,
        ori_pc: u64,
    },
    /// `UserAccess` kind and `LDTR`/`STTR` instruction disagree: a user access the
    /// fault table would miss, or a fault site that is not a user access.
    UntaggedUserAccess {
        insn_index: usize,
    },
    /// Two cold exit groups (fault or budget stubs) for the same original
    /// instruction (A8: two plain groups, or two PAN stubs).
    DuplicateFaultStub {
        ori_pc: u64,
    },
    /// A8: a `WindowAccess`/`PanToggle`/`PanRestore` tag and the instruction (LSE
    /// atomic or A9a base-only SIMD&FP load/store, `msr pan`) disagree, or an LSE
    /// atomic, SIMD&FP load/store or `msr pan` outside those kinds.
    UntaggedPanWindow {
        insn_index: usize,
    },
    /// A8: a window atomic or range check whose original instruction has no PAN
    /// stub.
    MissingPanStub {
        insn_index: usize,
        ori_pc: u64,
    },
    /// A budget check whose original instruction has no `Budget` stub.
    MissingBudgetStub {
        insn_index: usize,
        ori_pc: u64,
    },
    /// A user branch to a target at or before it in layout order without a budget
    /// check in its original instruction's sequence: rephrase and layout disagree on
    /// the layout order, and the loop would run unbounded.
    UnguardedBackEdge {
        insn_index: usize,
        target_original_pc: u64,
    },
    /// A dispatch template (A11) that is not exactly `DISPATCH_TEMPLATE_LEN` words of
    /// `DispatchLookup` ending in its `br`, whose miss branch positions are not a
    /// `cbz`/`cbnz`, or that no exit group follows.
    MalformedDispatchTemplate {
        insn_index: usize,
    },
    /// A block whose successor starts at its end (it falls through) is not
    /// followed by that successor in layout order: its lowering would run into
    /// the wrong block.
    FallthroughNotAdjacent {
        block_start: u64,
        end_addr: u64,
    },
}

impl From<SharedAllocError> for LayoutError {
    fn from(err: SharedAllocError) -> Self {
        Self::Alloc(err)
    }
}

impl core::fmt::Display for LayoutError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Alloc(err) => write!(f, "allocation failed during layout: {err:?}"),
            Self::EmptyProgram => write!(f, "cannot layout an empty rephrased program"),
            Self::MissingLabel { target_original_pc } => {
                write!(
                    f,
                    "missing layout label for original pc {target_original_pc:#x}"
                )
            }
            Self::BranchOutOfRange {
                insn_index,
                target_original_pc,
            } => write!(
                f,
                "branch at instruction {insn_index} cannot reach target {target_original_pc:#x}"
            ),
            Self::UnalignedBranchTarget {
                insn_index,
                target_original_pc,
            } => write!(
                f,
                "branch at instruction {insn_index} has unaligned target {target_original_pc:#x}"
            ),
            Self::UnsupportedBranchField { insn_index, field } => write!(
                f,
                "unsupported branch field `{field}` at instruction {insn_index}"
            ),
            Self::MissingFaultStub { insn_index, ori_pc } => write!(
                f,
                "user access at instruction {insn_index} has no fault stub for pc {ori_pc:#x}"
            ),
            Self::UntaggedUserAccess { insn_index } => write!(
                f,
                "instruction {insn_index}: user-access tag and LDTR/STTR form disagree"
            ),
            Self::DuplicateFaultStub { ori_pc } => {
                write!(f, "duplicate fault stub for pc {ori_pc:#x}")
            }
            Self::UntaggedPanWindow { insn_index } => write!(
                f,
                "instruction {insn_index}: PAN-window tag and LSE atomic / msr pan form disagree"
            ),
            Self::MissingPanStub { insn_index, ori_pc } => write!(
                f,
                "PAN window at instruction {insn_index} has no PAN stub for pc {ori_pc:#x}"
            ),
            Self::MissingBudgetStub { insn_index, ori_pc } => write!(
                f,
                "budget check at instruction {insn_index} has no budget stub for pc {ori_pc:#x}"
            ),
            Self::UnguardedBackEdge {
                insn_index,
                target_original_pc,
            } => write!(
                f,
                "back-edge at instruction {insn_index} to {target_original_pc:#x} has no budget check"
            ),
            Self::MalformedDispatchTemplate { insn_index } => {
                write!(f, "malformed dispatch template at instruction {insn_index}")
            }
            Self::FallthroughNotAdjacent {
                block_start,
                end_addr,
            } => write!(
                f,
                "block {block_start:#x} falls through to {end_addr:#x}, which is not laid out next"
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct BranchReloc {
    pub(crate) insn_index: usize,
    pub(crate) target_original_pc: u64,
    pub(crate) kind: BranchRelocKind,
    /// A budget check precedes the branch within its original instruction's
    /// sequence. Required when the branch resolves backward.
    pub(crate) budget_checked: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum BranchRelocKind {
    B,
    BCond,
    Bl,
    Cbz,
    Cbnz,
    Tbz,
    Tbnz,
}

/// Layout order: prologue, epilogue, every block body in `layout_block_order`, then
/// the cold region (every block's `cold` exit groups -- fault and budget stubs -- in
/// the same order). The entry block is `program[0]` (CFG order). Each cold group
/// ends in its runtime-exit branch, so nothing falls through into or out of the
/// region. A dispatch template's miss branches (A11, A11c) resolve per
/// `DISPATCH_TEMPLATE_MISS_TARGETS`: the main probe's to the victim probe's first word,
/// the victim probe's to the word right after the template's final `br`, where the
/// site's exit group starts. A budget check's
/// `CBZ` and an alignment check's `CBNZ` resolve to the
/// plain stub of their `ori_pc`; a PAN window's range-check `CBNZ` and its atomic's
/// fault site resolve to the PAN stub (A8). A user branch that resolves backward
/// must be budget-checked.
pub fn layout_program(program: RephrasedProgram) -> SharedResult<ExecutionFragment, LayoutError> {
    let insn_count = program
        .iter()
        .map(|block| block.insns.len() + block.cold.len())
        .sum::<usize>();
    let entry_pc = program.first().ok_or(LayoutError::EmptyProgram)?.start_addr;
    let order = layout_block_order(program.iter().map(|block| block.start_addr))?;
    check_fallthrough_adjacency(&program, &order)?;
    let mut fragment = ExecutionFragment {
        insns: SharedVec::with_capacity(
            insn_count + (PROLOGUE_LEN_BYTES + EPILOGUE_LEN_BYTES) / 4,
            GFP_KERNEL,
        )?,
        entry_offset: 0,
        vlabels: SharedVec::with_capacity(insn_count, GFP_KERNEL)?,
        fault_sites: SharedVec::new(),
    };
    let mut relocs = SharedVec::with_capacity(insn_count, GFP_KERNEL)?;
    let mut runtime_exit_branches = SharedVec::with_capacity(insn_count, GFP_KERNEL)?;
    // Stub labels: original PC -> offset of its cold `Mem` or `Budget` exit group
    // (at most one per PC). Their own label kind, never merged into `vlabels`.
    let mut stub_labels: LayoutVLabels = SharedVec::new();
    // PAN stub labels (A8): original PC -> offset of its PAN stub (`msr pan, #1`
    // then its `Mem` exit group). At most one per PC.
    let mut pan_stub_labels: LayoutVLabels = SharedVec::new();
    // Range-check `CBNZ`s: (instruction index, original PC of the atomic).
    let mut range_branches: SharedVec<(usize, u64)> = SharedVec::new();
    // Budget-check `CBZ`s: (instruction index, original PC of the back-edge).
    let mut budget_branches: SharedVec<(usize, u64)> = SharedVec::new();
    // Alignment check `CBNZ`s: (instruction index, original PC of the access).
    let mut align_branches: SharedVec<(usize, u64)> = SharedVec::new();
    // Dispatch templates (A11): first word of the template being laid out, and the
    // (miss branch index, exit-group index, original PC) of every finished one.
    let mut dispatch_start: Option<usize> = None;
    let mut dispatch_misses: SharedVec<(usize, usize, u64)> = SharedVec::new();
    // Original PC whose budget check has been emitted in the current run of
    // instructions with that PC.
    let mut budget_checked_pc = None;

    append_prologue(&mut fragment.insns, GFP_KERNEL)?;
    append_epilogue(&mut fragment.insns, GFP_KERNEL)?;

    for block in order.iter().map(|&index| &program[index]) {
        for rephrased in &block.insns {
            let insn_index = fragment.insns.len();
            let output_offset = insn_index * 4;
            insert_vlabel_once(&mut fragment.vlabels, rephrased.ori_pc, output_offset)?;
            if budget_checked_pc != Some(rephrased.ori_pc) {
                budget_checked_pc = None;
            }

            if rephrased.kind != RephrasedInsnKind::DispatchLookup && dispatch_start.is_some() {
                return Err(LayoutError::MalformedDispatchTemplate { insn_index });
            }
            let user_access = rephrased.kind == RephrasedInsnKind::UserAccess;
            if user_access != rephrased.insn.is_unprivileged_access() {
                return Err(LayoutError::UntaggedUserAccess { insn_index });
            }
            let window_access = rephrased.kind == RephrasedInsnKind::WindowAccess;
            let pan_toggle = rephrased.kind == RephrasedInsnKind::PanToggle;
            // A9a: a SIMD&FP load/store appears only as a window's base-only access.
            if window_access != rephrased.insn.is_pan_window_access()
                || (!window_access && rephrased.insn.fpsimd_mem().is_some())
                || pan_toggle != rephrased.insn.msr_pan().is_some()
            {
                return Err(LayoutError::UntaggedPanWindow { insn_index });
            }
            if user_access || window_access {
                // Stub offset resolved once the cold region is placed.
                fragment.fault_sites.push(
                    FaultSite {
                        access_offset: output_offset,
                        stub_offset: 0,
                        ori_pc: rephrased.ori_pc,
                    },
                    GFP_KERNEL,
                )?;
            } else if rephrased.kind == RephrasedInsnKind::AlignCheck {
                if branch_target_role(rephrased.insn).is_some() {
                    align_branches.push((insn_index, rephrased.ori_pc), GFP_KERNEL)?;
                }
            } else if rephrased.kind == RephrasedInsnKind::RangeCheck {
                if branch_target_role(rephrased.insn).is_some() {
                    range_branches.push((insn_index, rephrased.ori_pc), GFP_KERNEL)?;
                }
            } else if rephrased.kind == RephrasedInsnKind::BudgetCheck {
                if branch_target_role(rephrased.insn).is_some() {
                    budget_branches.push((insn_index, rephrased.ori_pc), GFP_KERNEL)?;
                    budget_checked_pc = Some(rephrased.ori_pc);
                }
            } else if rephrased.kind == RephrasedInsnKind::DispatchLookup {
                let start = *dispatch_start.get_or_insert(insn_index);
                let position = insn_index - start;
                let miss = DISPATCH_TEMPLATE_MISS_BRANCHES
                    .iter()
                    .position(|&branch| branch == position);
                let is_last = position + 1 == DISPATCH_TEMPLATE_LEN;
                let is_br = is_last || position + 1 == DISPATCH_TEMPLATE_VICTIM_PROBE;
                let well_formed = position < DISPATCH_TEMPLATE_LEN
                    && miss.is_some()
                        == matches!(
                            rephrased.insn,
                            A64Insn::CbzCbz64Compbranch { .. }
                                | A64Insn::CbnzCbnz64Compbranch { .. }
                        )
                    && is_br == matches!(rephrased.insn, A64Insn::BrBr64BranchReg { .. });
                if !well_formed {
                    return Err(LayoutError::MalformedDispatchTemplate { insn_index });
                }
                if let Some(miss) = miss {
                    // The main probe's misses go to the victim probe's first word, the
                    // victim probe's to the exit group, which starts right after the
                    // template's final `br`.
                    dispatch_misses.push(
                        (
                            insn_index,
                            start + DISPATCH_TEMPLATE_MISS_TARGETS[miss],
                            rephrased.ori_pc,
                        ),
                        GFP_KERNEL,
                    )?;
                }
                if is_last {
                    dispatch_start = None;
                }
            } else if rephrased.kind.is_user_semantic() {
                if let Some(reloc) = branch_reloc_for(
                    rephrased.insn,
                    rephrased.ori_pc,
                    insn_index,
                    budget_checked_pc == Some(rephrased.ori_pc),
                )? {
                    relocs.push(reloc, GFP_KERNEL)?;
                }
            } else if rephrased.kind.is_runtime_exit_branch() {
                runtime_exit_branches.push(insn_index, GFP_KERNEL)?;
            }

            fragment.insns.push(rephrased.insn, GFP_KERNEL)?;
        }
    }

    if dispatch_start.is_some() {
        return Err(LayoutError::MalformedDispatchTemplate {
            insn_index: fragment.insns.len(),
        });
    }

    // Reg-virt guarantees each cold group is one PC and ends in its exit branch; a
    // PAN stub is a group whose first instruction is `PanRestore`.
    let mut group_start = true;
    for rephrased in order.iter().flat_map(|&index| program[index].cold.iter()) {
        let insn_index = fragment.insns.len();
        let pan_restore = rephrased.kind == RephrasedInsnKind::PanRestore;
        if pan_restore != (group_start && rephrased.insn.msr_pan() == Some(true))
            || (!pan_restore && rephrased.insn.msr_pan().is_some())
            || rephrased.insn.lse_atomic().is_some()
            || rephrased.insn.fpsimd_mem().is_some()
        {
            return Err(LayoutError::UntaggedPanWindow { insn_index });
        }
        if group_start {
            let labels = if pan_restore {
                &mut pan_stub_labels
            } else {
                &mut stub_labels
            };
            if find_vlabel(labels, rephrased.ori_pc).is_some() {
                return Err(LayoutError::DuplicateFaultStub {
                    ori_pc: rephrased.ori_pc,
                });
            }
            labels.push((rephrased.ori_pc, insn_index * 4), GFP_KERNEL)?;
        }
        if rephrased.insn.is_unprivileged_access() {
            return Err(LayoutError::UntaggedUserAccess { insn_index });
        }
        group_start = rephrased.kind.is_runtime_exit_branch();
        if group_start {
            runtime_exit_branches.push(insn_index, GFP_KERNEL)?;
        }
        fragment.insns.push(rephrased.insn, GFP_KERNEL)?;
    }

    for site in fragment.fault_sites.iter_mut() {
        let insn_index = site.access_offset / 4;
        site.stub_offset = if fragment.insns[insn_index].is_pan_window_access() {
            find_vlabel(&pan_stub_labels, site.ori_pc).ok_or(LayoutError::MissingPanStub {
                insn_index,
                ori_pc: site.ori_pc,
            })?
        } else {
            find_vlabel(&stub_labels, site.ori_pc).ok_or(LayoutError::MissingFaultStub {
                insn_index,
                ori_pc: site.ori_pc,
            })?
        };
    }

    for &(insn_index, ori_pc) in &range_branches {
        let stub_offset = find_vlabel(&pan_stub_labels, ori_pc)
            .ok_or(LayoutError::MissingPanStub { insn_index, ori_pc })?;
        rewrite_branch_to_offset(&mut fragment, insn_index, stub_offset, ori_pc)?;
    }

    for &(insn_index, ori_pc) in &align_branches {
        let stub_offset = find_vlabel(&stub_labels, ori_pc)
            .ok_or(LayoutError::MissingFaultStub { insn_index, ori_pc })?;
        rewrite_branch_to_offset(&mut fragment, insn_index, stub_offset, ori_pc)?;
    }

    for &(insn_index, exit_index, ori_pc) in &dispatch_misses {
        // The exit group is the rest of the site's body, so a word follows the `br`.
        if exit_index >= fragment.insns.len() {
            return Err(LayoutError::MalformedDispatchTemplate { insn_index });
        }
        rewrite_branch_to_offset(&mut fragment, insn_index, exit_index * 4, ori_pc)?;
    }

    for &(insn_index, ori_pc) in &budget_branches {
        let stub_offset = find_vlabel(&stub_labels, ori_pc)
            .ok_or(LayoutError::MissingBudgetStub { insn_index, ori_pc })?;
        rewrite_branch_to_offset(&mut fragment, insn_index, stub_offset, ori_pc)?;
    }

    fragment.entry_offset =
        find_vlabel(&fragment.vlabels, entry_pc).ok_or(LayoutError::MissingLabel {
            target_original_pc: entry_pc,
        })?;

    resolve_runtime_exit_branches(&mut fragment, &runtime_exit_branches)?;
    resolve_branch_relocs(&mut fragment, &relocs)?;
    Ok(fragment)
}

/// Lowering relies on physical fall-through: a block with a successor at its own
/// end (a conditional branch's not-taken path, a split at a branch target) emits
/// no branch to it. So that successor must be the next block in layout order.
fn check_fallthrough_adjacency(
    program: &RephrasedProgram,
    order: &[usize],
) -> SharedResult<(), LayoutError> {
    for (position, &index) in order.iter().enumerate() {
        let block = &program[index];
        if !block.next.contains(&block.end_addr) {
            continue;
        }
        let next_start = order
            .get(position + 1)
            .map(|&next| program[next].start_addr);
        if next_start != Some(block.end_addr) {
            return Err(LayoutError::FallthroughNotAdjacent {
                block_start: block.start_addr,
                end_addr: block.end_addr,
            });
        }
    }
    Ok(())
}

fn insert_vlabel_once(
    vlabels: &mut LayoutVLabels,
    original_pc: u64,
    output_offset: usize,
) -> SharedResult<(), LayoutError> {
    if find_vlabel(vlabels, original_pc).is_none() {
        vlabels.push((original_pc, output_offset), GFP_KERNEL)?;
    }
    Ok(())
}

fn find_vlabel(vlabels: &LayoutVLabels, original_pc: u64) -> Option<usize> {
    vlabels
        .iter()
        .find(|(pc, _)| *pc == original_pc)
        .map(|(_, offset)| *offset)
}

fn branch_reloc_for(
    insn: A64Insn,
    original_pc: u64,
    insn_index: usize,
    budget_checked: bool,
) -> SharedResult<Option<BranchReloc>, LayoutError> {
    let Some((field, scale, bits)) = branch_target_role(insn) else {
        return Ok(None);
    };
    let Some(encoded) = insn.branch_target_imm(field) else {
        return Err(LayoutError::UnsupportedBranchField { insn_index, field });
    };
    let Some(kind) = BranchRelocKind::from_insn(insn) else {
        return Ok(None);
    };

    Ok(Some(BranchReloc {
        insn_index,
        target_original_pc: pc_relative_target(original_pc, encoded, bits, scale),
        kind,
        budget_checked,
    }))
}

fn branch_target_role(insn: A64Insn) -> Option<(&'static str, u8, u8)> {
    for role in insn.operand_roles() {
        if let A64OperandRole::BranchTarget { field, scale, bits } = *role {
            return Some((field, scale, bits));
        }
    }
    None
}

fn resolve_branch_relocs(
    fragment: &mut ExecutionFragment,
    relocs: &SharedVec<BranchReloc>,
) -> SharedResult<(), LayoutError> {
    for reloc in relocs {
        let target_offset = find_vlabel(&fragment.vlabels, reloc.target_original_pc).ok_or(
            LayoutError::MissingLabel {
                target_original_pc: reloc.target_original_pc,
            },
        )?;
        if target_offset <= reloc.insn_index * 4 && !reloc.budget_checked {
            return Err(LayoutError::UnguardedBackEdge {
                insn_index: reloc.insn_index,
                target_original_pc: reloc.target_original_pc,
            });
        }
        rewrite_branch_to_offset(
            fragment,
            reloc.insn_index,
            target_offset,
            reloc.target_original_pc,
        )?;
    }
    Ok(())
}

fn resolve_runtime_exit_branches(
    fragment: &mut ExecutionFragment,
    branches: &SharedVec<usize>,
) -> SharedResult<(), LayoutError> {
    for insn_index in branches {
        rewrite_branch_to_offset(fragment, *insn_index, EPILOGUE_OFFSET, u64::MAX)?;
    }
    Ok(())
}

fn rewrite_branch_to_offset(
    fragment: &mut ExecutionFragment,
    insn_index: usize,
    target_offset: usize,
    target_original_pc: u64,
) -> SharedResult<(), LayoutError> {
    let Some(insn) = fragment.insns.get_mut(insn_index) else {
        return Err(LayoutError::BranchOutOfRange {
            insn_index,
            target_original_pc,
        });
    };
    let Some((field, scale, bits)) = branch_target_role(*insn) else {
        return Err(LayoutError::UnsupportedBranchField {
            insn_index,
            field: "",
        });
    };
    let encoded = encode_branch_delta(
        insn_index * 4,
        target_offset,
        scale,
        bits,
        insn_index,
        target_original_pc,
    )?;

    *insn = insn
        .set_branch_target_imm(field, encoded)
        .map_err(|err| match err {
            A64RewriteError::UnsupportedField { field, .. } => {
                LayoutError::UnsupportedBranchField { insn_index, field }
            }
            A64RewriteError::FieldOutOfRange { .. } => LayoutError::BranchOutOfRange {
                insn_index,
                target_original_pc,
            },
        })?;
    Ok(())
}

fn encode_branch_delta(
    source_offset: usize,
    target_offset: usize,
    scale: u8,
    bits: u8,
    insn_index: usize,
    target_original_pc: u64,
) -> SharedResult<u32, LayoutError> {
    if bits == 0 || bits >= 32 || scale >= 32 {
        return Err(LayoutError::BranchOutOfRange {
            insn_index,
            target_original_pc,
        });
    }

    // No i128 here: the kernel has no 128-bit division builtins (__divti3).
    // Both offsets are non-negative once in i64, so the subtraction cannot overflow.
    let (Ok(source), Ok(target)) = (i64::try_from(source_offset), i64::try_from(target_offset))
    else {
        return Err(LayoutError::BranchOutOfRange {
            insn_index,
            target_original_pc,
        });
    };
    let align = 1_i64 << scale;
    let delta = target - source;
    if delta % align != 0 {
        return Err(LayoutError::UnalignedBranchTarget {
            insn_index,
            target_original_pc,
        });
    }

    let scaled = delta / align;
    let min = -(1_i64 << (bits - 1));
    let max = (1_i64 << (bits - 1)) - 1;
    if scaled < min || scaled > max {
        return Err(LayoutError::BranchOutOfRange {
            insn_index,
            target_original_pc,
        });
    }

    Ok((scaled & ((1_i64 << bits) - 1)) as u32)
}

fn pc_relative_target(pc: u64, encoded: u32, bits: u8, scale: u8) -> u64 {
    pc.wrapping_add_signed(sign_extend(encoded, bits) << scale)
}

fn sign_extend(value: u32, bits: u8) -> i64 {
    let shift = 64 - bits;
    ((value as i64) << shift) >> shift
}

impl BranchRelocKind {
    fn from_insn(insn: A64Insn) -> Option<Self> {
        match insn {
            A64Insn::BUncondBOnlyBranchImm { .. } => Some(Self::B),
            A64Insn::BCondBOnlyCondbranch { .. } => Some(Self::BCond),
            A64Insn::BlBlOnlyBranchImm { .. } => Some(Self::Bl),
            A64Insn::CbzCbz32Compbranch { .. } | A64Insn::CbzCbz64Compbranch { .. } => {
                Some(Self::Cbz)
            }
            A64Insn::CbnzCbnz32Compbranch { .. } | A64Insn::CbnzCbnz64Compbranch { .. } => {
                Some(Self::Cbnz)
            }
            A64Insn::TbzTbzOnlyTestbranch { .. } => Some(Self::Tbz),
            A64Insn::TbnzTbnzOnlyTestbranch { .. } => Some(Self::Tbnz),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::arm64::{A64Imm, A64Reg};
    use crate::shared::trans::rephrase::{RephrasedBlock, RephrasedInsn};

    fn one_block(insns: SharedVec<RephrasedInsn>) -> RephrasedProgram {
        let mut program = SharedVec::new();
        program
            .push(
                RephrasedBlock {
                    start_addr: 0x1000,
                    end_addr: 0x100c,
                    prev: SharedVec::new(),
                    next: SharedVec::new(),
                    insns,
                    cold: SharedVec::new(),
                },
                GFP_KERNEL,
            )
            .unwrap();
        program
    }

    fn body_start_offset() -> usize {
        PROLOGUE_LEN_BYTES + EPILOGUE_LEN_BYTES
    }

    /// A11, A11c: the main probe's miss branches resolve to the victim probe's first
    /// word, the victim probe's to the word right after the final `br` (the site's exit
    /// group); a template that is cut short (also right after the main probe), or whose
    /// final `br` nothing follows, is a layout error.
    #[test]
    fn dispatch_template_miss_branches_resolve_to_the_next_probe_or_the_exit_group() {
        use crate::shared::abi::KJIT_DISPATCH_TEMPLATE;

        let template = |count: usize, followed: bool| {
            let mut insns = SharedVec::new();
            for insn in KJIT_DISPATCH_TEMPLATE.iter().take(count) {
                insns
                    .push(RephrasedInsn::dispatch_lookup(0x1000, *insn), GFP_KERNEL)
                    .unwrap();
            }
            if followed {
                insns
                    .push(RephrasedInsn::synthetic(0x1000, A64Insn::NopNopHiHints {}), GFP_KERNEL)
                    .unwrap();
            }
            insns
        };

        let layout = layout_program(one_block(template(DISPATCH_TEMPLATE_LEN, true))).unwrap();
        let start = body_start_offset() / 4;
        let exit_group = start + DISPATCH_TEMPLATE_LEN;
        for (position, target) in DISPATCH_TEMPLATE_MISS_BRANCHES
            .into_iter()
            .zip(DISPATCH_TEMPLATE_MISS_TARGETS)
        {
            assert_eq!(
                layout.insns[start + position]
                    .conditional_targets(((start + position) * 4) as u64)
                    .map(|(taken, _)| taken),
                Some(((start + target) * 4) as u64),
                "miss branch {position}"
            );
        }
        // The `br` is the template's last word; the exit group starts after it.
        assert!(matches!(
            layout.insns[exit_group - 1],
            A64Insn::BrBr64BranchReg { .. }
        ));

        for count in [DISPATCH_TEMPLATE_LEN - 1, DISPATCH_TEMPLATE_VICTIM_PROBE, 3] {
            assert!(matches!(
                layout_program(one_block(template(count, true))),
                Err(LayoutError::MalformedDispatchTemplate { .. })
            ));
        }
        // A `br` with no word after it has no exit group to miss to.
        assert!(matches!(
            layout_program(one_block(template(DISPATCH_TEMPLATE_LEN, false))),
            Err(LayoutError::MalformedDispatchTemplate { .. })
        ));
    }

    #[test]
    fn rewrites_forward_branch_to_layout_offset() {
        let mut insns = SharedVec::new();
        insns
            .push(
                RephrasedInsn::original(
                    0x1000,
                    A64Insn::BUncondBOnlyBranchImm {
                        imm26: A64Imm::scaled_signed(2, 26, 2),
                    },
                ),
                GFP_KERNEL,
            )
            .unwrap();
        insns
            .push(
                RephrasedInsn::synthetic(0x1004, A64Insn::NopNopHiHints {}),
                GFP_KERNEL,
            )
            .unwrap();
        insns
            .push(
                RephrasedInsn::synthetic(0x1004, A64Insn::NopNopHiHints {}),
                GFP_KERNEL,
            )
            .unwrap();
        insns
            .push(
                RephrasedInsn::original(0x1008, A64Insn::NopNopHiHints {}),
                GFP_KERNEL,
            )
            .unwrap();

        let layout = layout_program(one_block(insns)).unwrap();
        let body_index = body_start_offset() / 4;

        assert_eq!(layout.entry_offset, body_start_offset());
        assert_eq!(layout.vlabels[2], (0x1008, body_start_offset() + 12));
        assert_eq!(layout.insns[body_index].branch_target_imm("imm26"), Some(3));
        assert_eq!(
            layout.insns[body_index].direct_branch_target(body_start_offset() as u64),
            Some((body_start_offset() + 12) as u64)
        );
    }

    /// nop @0x1000; two synthetic nops @0x1004; `cbnz x0, 0x1000` @0x1008, with the
    /// back-edge's budget check before the CBNZ when `checked`.
    fn backward_cbnz_block(checked: bool) -> SharedVec<RephrasedInsn> {
        let nop = A64Insn::NopNopHiHints {};
        let mut insns = vec_of(&[
            RephrasedInsn::original(0x1000, nop),
            RephrasedInsn::synthetic(0x1004, nop),
            RephrasedInsn::synthetic(0x1004, nop),
        ]);
        if checked {
            for check in crate::shared::trans::rephrase::budget_check(0x1008) {
                insns.push(check, GFP_KERNEL).unwrap();
            }
        }
        insns
            .push(
                RephrasedInsn::original(
                    0x1008,
                    A64Insn::CbnzCbnz64Compbranch {
                        imm19: A64Imm::scaled_signed(524286, 19, 2),
                        rt: A64Reg::x(0),
                    },
                ),
                GFP_KERNEL,
            )
            .unwrap();
        insns
    }

    #[test]
    fn rewrites_backward_cond_branch_to_layout_offset() {
        let mut program = one_block(backward_cbnz_block(true));
        program[0].cold = vec_of(&[
            RephrasedInsn::runtime_exit_payload(0x1008, A64Insn::NopNopHiHints {}),
            exit_branch(0x1008),
        ]);

        let layout = layout_program(program).unwrap();
        let body_index = body_start_offset() / 4;
        let cold_index = body_index + 8;

        // The CBNZ follows its 4-instruction budget check and goes back 7.
        assert_eq!(
            layout.insns[body_index + 7].branch_target_imm("imm19"),
            Some(524288 - 7)
        );
        // The check's CBZ goes to the Budget stub in the cold region.
        assert_eq!(
            layout.insns[body_index + 6].direct_branch_target(0),
            None,
            "CBZ is conditional"
        );
        assert_eq!(
            layout.insns[body_index + 6]
                .conditional_targets(((body_index + 6) * 4) as u64)
                .map(|(taken, _)| taken),
            Some((cold_index * 4) as u64)
        );
    }

    /// A block whose successor starts at its end must be followed by it: here the
    /// successor at 0x100c is missing, so the next laid-out block starts at 0x1010.
    #[test]
    fn rejects_a_fallthrough_successor_that_is_not_laid_out_next() {
        let nop = A64Insn::NopNopHiHints {};
        let mut program = one_block(vec_of(&[RephrasedInsn::original(0x1000, nop)]));
        program[0].next.push(0x100c, GFP_KERNEL).unwrap();
        program
            .push(
                RephrasedBlock {
                    start_addr: 0x1010,
                    end_addr: 0x1014,
                    prev: SharedVec::new(),
                    next: SharedVec::new(),
                    insns: vec_of(&[RephrasedInsn::original(0x1010, nop)]),
                    cold: SharedVec::new(),
                },
                GFP_KERNEL,
            )
            .unwrap();

        assert_eq!(
            layout_program(program),
            Err(LayoutError::FallthroughNotAdjacent {
                block_start: 0x1000,
                end_addr: 0x100c,
            })
        );
    }

    /// Bodies go out in `layout_block_order` (ascending start), not program order;
    /// the entry is still `program[0]`.
    #[test]
    fn emits_blocks_in_layout_order_and_enters_at_the_first_program_block() {
        let nop = A64Insn::NopNopHiHints {};
        let mut program = one_block(vec_of(&[RephrasedInsn::original(0x1008, nop)]));
        program[0].start_addr = 0x1008;
        program
            .push(
                RephrasedBlock {
                    start_addr: 0x1000,
                    end_addr: 0x1008,
                    prev: SharedVec::new(),
                    next: SharedVec::new(),
                    insns: vec_of(&[
                        RephrasedInsn::original(0x1000, nop),
                        RephrasedInsn::original(0x1004, nop),
                    ]),
                    cold: SharedVec::new(),
                },
                GFP_KERNEL,
            )
            .unwrap();

        let layout = layout_program(program).unwrap();
        let body = body_start_offset();
        assert_eq!(
            &layout.vlabels[..],
            [(0x1000, body), (0x1004, body + 4), (0x1008, body + 8)]
        );
        assert_eq!(layout.entry_offset, body + 8);
    }

    #[test]
    fn rejects_backward_branch_without_budget_check() {
        assert_eq!(
            layout_program(one_block(backward_cbnz_block(false))),
            Err(LayoutError::UnguardedBackEdge {
                insn_index: body_start_offset() / 4 + 3,
                target_original_pc: 0x1000,
            })
        );
    }

    #[test]
    fn rejects_budget_check_without_budget_stub() {
        assert_eq!(
            layout_program(one_block(backward_cbnz_block(true))),
            Err(LayoutError::MissingBudgetStub {
                insn_index: body_start_offset() / 4 + 6,
                ori_pc: 0x1008,
            })
        );
    }

    #[test]
    fn rewrites_user_synthetic_branch_to_layout_offset() {
        let mut insns = SharedVec::new();
        insns
            .push(
                RephrasedInsn::user_synthetic(
                    0x1000,
                    A64Insn::BUncondBOnlyBranchImm {
                        imm26: A64Imm::scaled_signed(2, 26, 2),
                    },
                ),
                GFP_KERNEL,
            )
            .unwrap();
        insns
            .push(
                RephrasedInsn::original(0x1004, A64Insn::NopNopHiHints {}),
                GFP_KERNEL,
            )
            .unwrap();
        insns
            .push(
                RephrasedInsn::original(0x1008, A64Insn::NopNopHiHints {}),
                GFP_KERNEL,
            )
            .unwrap();

        let layout = layout_program(one_block(insns)).unwrap();
        let body_index = body_start_offset() / 4;

        assert_eq!(layout.insns[body_index].branch_target_imm("imm26"), Some(2));
        assert_eq!(
            layout.insns[body_index].direct_branch_target(body_start_offset() as u64),
            Some((body_start_offset() + 8) as u64)
        );
    }

    #[test]
    fn wraps_body_with_prologue_and_epilogue() {
        let mut insns = SharedVec::new();
        insns
            .push(
                RephrasedInsn::original(0x1000, A64Insn::NopNopHiHints {}),
                GFP_KERNEL,
            )
            .unwrap();

        let layout = layout_program(one_block(insns)).unwrap();

        assert_eq!(layout.insns.len(), (body_start_offset() / 4) + 1);
        assert_eq!(layout.entry_offset, body_start_offset());
        assert_eq!(layout.vlabels[0], (0x1000, body_start_offset()));
    }

    #[test]
    fn resolves_runtime_exit_branch_to_epilogue() {
        let mut insns = SharedVec::new();
        insns
            .push(
                RephrasedInsn::runtime_exit_branch(
                    0x1000,
                    A64Insn::BUncondBOnlyBranchImm {
                        imm26: A64Imm::scaled_signed(0, 26, 2),
                    },
                ),
                GFP_KERNEL,
            )
            .unwrap();

        let layout = layout_program(one_block(insns)).unwrap();
        let runtime_branch_index = body_start_offset() / 4;

        assert_eq!(
            layout.insns[runtime_branch_index].direct_branch_target(body_start_offset() as u64),
            Some(EPILOGUE_OFFSET as u64)
        );
    }

    fn exit_branch(pc: u64) -> RephrasedInsn {
        RephrasedInsn::runtime_exit_branch(
            pc,
            A64Insn::BUncondBOnlyBranchImm {
                imm26: A64Imm::scaled_signed(0, 26, 2),
            },
        )
    }

    fn ldtr(pc: u64) -> RephrasedInsn {
        RephrasedInsn::user_access(
            pc,
            A64Insn::LdtrLdtr64LdstUnpriv {
                rt: A64Reg::x(0),
                mem: crate::shared::arm64::A64Mem::offset(A64Reg::x_sp(1), A64Imm::signed(0, 9)),
            },
        )
    }

    fn vec_of(insns: &[RephrasedInsn]) -> SharedVec<RephrasedInsn> {
        let mut out = SharedVec::new();
        for insn in insns {
            out.push(*insn, GFP_KERNEL).unwrap();
        }
        out
    }

    #[test]
    fn places_fault_stubs_after_the_body_and_records_sorted_fault_sites() {
        let nop = A64Insn::NopNopHiHints {};
        let mut program = one_block(vec_of(&[
            ldtr(0x1000),
            ldtr(0x1000),
            RephrasedInsn::original(0x1004, nop),
            ldtr(0x1008),
        ]));
        program[0].cold = vec_of(&[
            RephrasedInsn::runtime_exit_payload(0x1000, nop),
            exit_branch(0x1000),
            RephrasedInsn::runtime_exit_payload(0x1008, nop),
            exit_branch(0x1008),
        ]);

        let layout = layout_program(program).unwrap();
        let body = body_start_offset();
        let cold = body + 16;

        // vlabels map only body entries.
        assert_eq!(
            &layout.vlabels[..],
            [(0x1000, body), (0x1004, body + 8), (0x1008, body + 12)]
        );
        assert_eq!(
            &layout.fault_sites[..],
            [
                FaultSite {
                    access_offset: body,
                    stub_offset: cold,
                    ori_pc: 0x1000,
                },
                FaultSite {
                    access_offset: body + 4,
                    stub_offset: cold,
                    ori_pc: 0x1000,
                },
                FaultSite {
                    access_offset: body + 12,
                    stub_offset: cold + 8,
                    ori_pc: 0x1008,
                },
            ]
        );
        assert_eq!(layout.fault_site(body + 12).unwrap().stub_offset, cold + 8);
        assert_eq!(layout.fault_site(body + 8), None);
        // Stub exit branches go to the epilogue like every other exit.
        assert_eq!(
            layout.insns[(cold + 4) / 4].direct_branch_target((cold + 4) as u64),
            Some(EPILOGUE_OFFSET as u64)
        );
    }

    #[test]
    fn rejects_user_accesses_without_stub_or_tag() {
        assert_eq!(
            layout_program(one_block(vec_of(&[ldtr(0x1000)]))),
            Err(LayoutError::MissingFaultStub {
                insn_index: body_start_offset() / 4,
                ori_pc: 0x1000,
            })
        );
        let untagged = RephrasedInsn {
            kind: RephrasedInsnKind::Original,
            ..ldtr(0x1000)
        };
        assert_eq!(
            layout_program(one_block(vec_of(&[untagged]))),
            Err(LayoutError::UntaggedUserAccess {
                insn_index: body_start_offset() / 4,
            })
        );
    }
}
