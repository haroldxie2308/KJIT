use crate::arm64::{execute_insn, AccessContext, InsnError, LoggedAccess, UserAccessCounter};
use crate::code_cache::{synthetic_loader, CacheAction, CacheLayout, CodeCache};
use crate::model::{MachineState, PAGE_SIZE};
use crate::shared::abi::{
    RetStatus, ABI_ENTRY_ARG_REG, ABI_EXTRA_PARAMS_ARG_REG, ABI_LINK_REG, ABI_PT_REGS_ARG_REG,
    EXTRA_PARAMS_BYTES, EXTRA_PARAM_IBTC_TABLE_OFFSET, IBTC_TABLE_BYTES, PROLOGUE_LEN_BYTES,
    RET_PARAM0_REG, RET_PARAM1_REG, RET_STATUS_REG, RUNTIME_FRAME_SIZE_BYTES,
};
use crate::shared::arm64::A64OperandRole;
use crate::shared::emit::layout::ExecutionFragment;

pub const DEFAULT_BASE_PC: u64 = 0x400000;
pub const DEFAULT_PT_REGS_ADDR: u64 = 0x7fe000;
pub const DEFAULT_EXTRA_PARAMS_ADDR: u64 = 0x7ff000;
pub const DEFAULT_RETURN_PC: u64 = 0x123456;
pub const DEFAULT_STACK_TOP: u64 = 0x800000;
/// The dispatch tables and records (A11), in runtime-owned memory below the extra
/// params page and above the code space (`DEFAULT_BASE_PC` up).
pub const DEFAULT_CACHE_LAYOUT: CacheLayout = CacheLayout {
    table_all: 0x600000,
    table_nofp: 0x600000 + IBTC_TABLE_BYTES as u64,
    records: 0x600000 + 2 * IBTC_TABLE_BYTES as u64,
    records_len: 0x40000,
};

pub(crate) const PT_REGS_BYTES: u64 = 256;
pub(crate) const PT_REGS_SP_OFFSET: u64 = 31 * 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct URuntimeConfig {
    pub base_pc: u64,
    pub pt_regs_addr: u64,
    pub extra_params_addr: u64,
    pub return_pc: u64,
    pub stack_top: u64,
}

impl Default for URuntimeConfig {
    fn default() -> Self {
        Self {
            base_pc: DEFAULT_BASE_PC,
            pt_regs_addr: DEFAULT_PT_REGS_ADDR,
            extra_params_addr: DEFAULT_EXTRA_PARAMS_ADDR,
            return_pc: DEFAULT_RETURN_PC,
            stack_top: DEFAULT_STACK_TOP,
        }
    }
}

#[derive(Debug)]
pub struct URuntime {
    pub state: MachineState,
    pub config: URuntimeConfig,
    /// Every fragment the run can execute, with the dispatch tables. A run of one
    /// fragment (`URuntime::new`) has a cache of one fragment and never publishes: its
    /// tables stay empty, so every branch exit misses and takes the runtime path.
    cache: CodeCache,
    /// The fragment of the current entry: its table is the run's (`extra params[2]`).
    entered: usize,
    /// `with_cache` runs resolve exits through the cache (publish, translate on a
    /// miss, `CodeCache::decide`); a single-fragment run uses
    /// `decide_runtime_return`.
    resolving: bool,
    /// Numbers the fragment's user accesses (`LDTR`/`STTR`) across the whole run,
    /// runtime-loop continuations included; optionally fails one.
    user_accesses: UserAccessCounter,
    access_log: Option<Vec<LoggedAccess>>,
    /// PSTATE.PAN while the fragment runs (A8). The kernel calls a fragment with
    /// PAN set; only a PAN window clears it, and every return to the runtime must
    /// find it set again (checked in `apply_runtime_return`).
    pan: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct URuntimeReport {
    pub state: MachineState,
    pub halt: URuntimeHalt,
    pub steps: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum URuntimeHalt {
    FellOffFragment {
        pc: u64,
    },
    NeedsTranslation {
        status: RetStatus,
        target_pc: u64,
        resume_offset: Option<usize>,
    },
    ReturnedToUserspace {
        status: RetStatus,
        target_pc: u64,
    },
    InvalidReturnStatus {
        raw: u64,
    },
    UnsupportedRuntimeExit {
        status: RetStatus,
    },
    ExecutionError {
        pc: u64,
        message: String,
    },
    /// A bounded run (`run_differential` with `StepLimits`) executed its
    /// budget of fragment instructions or runtime continuations without halting.
    StepLimit {
        pc: u64,
        steps: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct URuntimeStep {
    /// The fragment `offset`, `insn_index` and `next_offset` are relative to.
    pub fragment: usize,
    pub offset: Option<usize>,
    pub insn_index: Option<usize>,
    pub next_offset: Option<usize>,
    pub executed: bool,
    pub runtime_transition: Option<URuntimeTransition>,
    pub halt: Option<URuntimeHalt>,
    pub state: MachineState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum URuntimeTransition {
    Continued {
        fragment: usize,
        offset: usize,
    },
    /// A user access at `access_offset` faulted; execution resumes at its fault
    /// stub, as the kernel's exception fixup does.
    FaultRedirect {
        access_offset: usize,
        stub_offset: usize,
    },
}

impl URuntime {
    pub fn new(fragment: ExecutionFragment, initial_state: MachineState) -> Self {
        Self::with_config(fragment, initial_state, URuntimeConfig::default())
    }

    pub fn with_config(
        fragment: ExecutionFragment,
        initial_state: MachineState,
        config: URuntimeConfig,
    ) -> Self {
        let entry_pc = fragment
            .vlabels
            .iter()
            .find(|&&(_, offset)| offset == fragment.entry_offset)
            .map(|&(pc, _)| pc)
            .expect("a compiled fragment's entry offset is one of its labels");
        // The translator's view of FP/SIMD use: this fragment was not verified here.
        let uses_fpsimd = fragment.insns.iter().any(|insn| {
            insn.operand_roles().iter().any(|role| {
                matches!(
                    role,
                    A64OperandRole::VecRead { .. } | A64OperandRole::VecWrite { .. }
                )
            })
        });
        let mut cache = CodeCache::new(
            DEFAULT_CACHE_LAYOUT,
            None,
            synthetic_loader(config.base_pc),
        );
        cache
            .install(entry_pc, fragment, Vec::new(), uses_fpsimd)
            .expect("one fragment fits an empty cache");
        Self::start(cache, 0, initial_state, config, false)
    }

    /// A run over a code cache (`entry` is the fragment to enter first). Branch exits
    /// resolve through the cache: they publish, and a miss translates its target.
    /// The cache's memory (tables, records) is part of the run's runtime-owned memory.
    /// The fragments' addresses are the cache loader's (`config.base_pc` is only the
    /// first fragment's base for a single-fragment `URuntime::new`).
    pub fn with_cache(
        cache: CodeCache,
        entry: usize,
        initial_state: MachineState,
        config: URuntimeConfig,
    ) -> Self {
        Self::start(cache, entry, initial_state, config, true)
    }

    fn start(
        mut cache: CodeCache,
        entry: usize,
        mut initial_state: MachineState,
        config: URuntimeConfig,
        resolving: bool,
    ) -> Self {
        seed_pt_regs(&mut initial_state, &config);
        cache.begin_run();
        for (addr, value) in cache.image() {
            initial_state.write_u64(addr, value);
        }
        initial_state.write_x(ABI_PT_REGS_ARG_REG, config.pt_regs_addr);
        initial_state.write_x(ABI_EXTRA_PARAMS_ARG_REG, config.extra_params_addr);
        initial_state.write_x(ABI_LINK_REG, config.return_pc);
        initial_state.set_sp(config.stack_top);
        Self {
            state: initial_state,
            config,
            cache,
            entered: entry,
            resolving,
            user_accesses: UserAccessCounter::default(),
            access_log: None,
            pan: true,
        }
    }

    /// The fragment this runtime was created with (its first fragment).
    pub fn fragment(&self) -> &ExecutionFragment {
        &self.cache.fragments[0].fragment
    }

    pub fn cache(&self) -> &CodeCache {
        &self.cache
    }

    pub fn into_cache(self) -> CodeCache {
        self.cache
    }

    /// Fails the `k`-th dynamic user access (`LDTR`/`STTR`) of the run (1-based)
    /// regardless of permissions.
    pub fn fail_user_access(mut self, k: u64) -> Self {
        self.user_accesses = UserAccessCounter::failing_at(k);
        self
    }

    /// Records every attempted fragment access (user and runtime) of the run.
    pub fn record_accesses(mut self) -> Self {
        self.access_log = Some(Vec::new());
        self
    }

    pub fn access_log(&self) -> Option<&[LoggedAccess]> {
        self.access_log.as_deref()
    }

    /// User accesses performed (or attempted, for a faulting one) so far.
    pub fn user_accesses(&self) -> u64 {
        self.user_accesses.seen()
    }

    pub fn run(&mut self) -> URuntimeReport {
        match URuntimeCursor::new(self) {
            Ok(mut cursor) => run_cursor_to_halt(self, &mut cursor),
            Err(message) => self.report(
                URuntimeHalt::ExecutionError {
                    pc: self.config.base_pc,
                    message,
                },
                0,
            ),
        }
    }

    /// The runtime's decision for the exit the fragment just returned with. A cache
    /// run applies the memory writes of any publish or install to the machine.
    fn handle_runtime_return(&mut self) -> Result<CacheAction, String> {
        let status = self.state.read_x(RET_STATUS_REG);
        let param0 = self.state.read_x(RET_PARAM0_REG);
        let param1 = self.state.read_x(RET_PARAM1_REG);
        if !self.resolving {
            return Ok(
                match decide_runtime_return(&self.cache.fragments[0].fragment, status, param0, param1)
                {
                    RuntimeAction::ContinueAt(offset) => CacheAction::ContinueAt {
                        fragment: 0,
                        offset,
                    },
                    RuntimeAction::Stop(halt) => CacheAction::Stop(halt),
                },
            );
        }
        let run_fpsimd = self.cache.fragments[self.entered].uses_fpsimd;
        let action = self.cache.decide(run_fpsimd, status, param0, param1)?;
        for (addr, value) in self.cache.drain_writes() {
            self.state.write_u64(addr, value);
        }
        Ok(action)
    }

    /// Sets up the ABI call: the fragment is always called at its base (the
    /// prologue) and the prologue branches to `ABI_ENTRY_ARG_REG`. Extra params
    /// `[2]` is the dispatch table of this run, chosen by the fragment entered.
    fn prepare_entry_at(&mut self, fragment: usize, offset: usize) -> Result<(), String> {
        let frag = &self.cache.fragments[fragment];
        validate_entry_offset(&frag.fragment, offset)?;
        let (base, table) = (frag.base, self.cache.table_for(frag.uses_fpsimd));
        self.entered = fragment;
        self.state
            .write_x(ABI_PT_REGS_ARG_REG, self.config.pt_regs_addr);
        self.state
            .write_x(ABI_EXTRA_PARAMS_ARG_REG, self.config.extra_params_addr);
        self.state.write_u64(
            self.config.extra_params_addr + u64::from(EXTRA_PARAM_IBTC_TABLE_OFFSET),
            table,
        );
        self.state
            .write_x(ABI_ENTRY_ARG_REG, base + offset as u64);
        self.state.write_x(ABI_LINK_REG, self.config.return_pc);
        self.state.set_sp(self.config.stack_top);
        self.pan = true;
        Ok(())
    }

    /// The fragment holding emitted address `pc`, and the offset in it.
    fn locate(&self, pc: u64) -> Option<(usize, usize)> {
        let (fragment, offset) = self.cache.locate(pc)?;
        (offset % 4 == 0).then_some((fragment, offset))
    }

    fn report(&self, halt: URuntimeHalt, steps: usize) -> URuntimeReport {
        URuntimeReport {
            state: self.user_state_from_pt_regs(),
            halt,
            steps,
        }
    }

    pub(crate) fn user_state_from_pt_regs(&self) -> MachineState {
        let ranges = self.runtime_owned_ranges();
        let mut state = self.state.without_memory_ranges(&ranges);
        for reg in 0..31 {
            state.write_x(
                reg,
                self.state
                    .read_u64(self.config.pt_regs_addr + (reg as u64) * 8),
            );
        }
        state.set_sp(
            self.state
                .read_u64(self.config.pt_regs_addr + PT_REGS_SP_OFFSET),
        );
        state.flags = self.state.flags;
        state
    }

    pub(crate) fn physical_user_state(&self) -> MachineState {
        self.state
            .without_memory_ranges(&self.runtime_owned_ranges())
    }

    /// Runtime-owned memory is never user-accessible: no page it touches may
    /// be in the user page map.
    fn check_runtime_memory_not_user_mapped(&self) -> Result<(), String> {
        for (start, end) in self.runtime_owned_ranges() {
            let first_page = start - start % PAGE_SIZE;
            for page in (first_page..end).step_by(PAGE_SIZE as usize) {
                if self.state.user_page_perm(page).is_some() {
                    return Err(format!(
                        "runtime-owned range {start:#x}..{end:#x} overlaps user-mapped page \
                         {page:#x}; runtime memory is never user-accessible"
                    ));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn runtime_owned_ranges(&self) -> Vec<(u64, u64)> {
        let mut ranges = vec![
            (
                self.config.pt_regs_addr,
                self.config.pt_regs_addr + PT_REGS_BYTES,
            ),
            (
                self.config.extra_params_addr,
                self.config.extra_params_addr + EXTRA_PARAMS_BYTES as u64,
            ),
            (
                self.config
                    .stack_top
                    .saturating_sub(RUNTIME_FRAME_SIZE_BYTES as u64),
                self.config.stack_top,
            ),
        ];
        ranges.extend(self.cache.layout().ranges());
        ranges
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct URuntimeCursor {
    pc: u64,
    steps: usize,
    stopped: bool,
}

impl URuntimeCursor {
    fn new(runtime: &mut URuntime) -> Result<Self, String> {
        runtime.check_runtime_memory_not_user_mapped()?;
        let entry = runtime.entered;
        let frag = &runtime.cache.fragments[entry];
        if frag.fragment.len_bytes() <= PROLOGUE_LEN_BYTES {
            return Err("fragment is missing the ABI prologue".to_string());
        }
        let (base, entry_offset) = (frag.base, frag.fragment.entry_offset);
        runtime.prepare_entry_at(entry, entry_offset)?;

        Ok(Self {
            pc: base,
            steps: 0,
            stopped: false,
        })
    }

    fn pc(&self) -> u64 {
        self.pc
    }

    fn current_offset(&self, runtime: &URuntime) -> Option<usize> {
        runtime.locate(self.pc).map(|(_, offset)| offset)
    }


    fn steps(&self) -> usize {
        self.steps
    }

    fn step(&mut self, runtime: &mut URuntime) -> Result<Option<URuntimeStep>, String> {
        Ok(self
            .advance(runtime)?
            .map(|advanced| advanced.into_step(runtime)))
    }

    /// One step without its state snapshot, which costs a full memory copy;
    /// `run_cursor_to_halt` only needs the final report.
    fn advance(&mut self, runtime: &mut URuntime) -> Result<Option<Advanced>, String> {
        if self.stopped {
            return Ok(None);
        }

        if self.pc == runtime.config.return_pc {
            return Ok(Some(
                self.apply_runtime_return(runtime, None, None, None, None, false)?,
            ));
        }

        let Some((fragment, offset)) = runtime.locate(self.pc) else {
            self.stopped = true;
            let halt = URuntimeHalt::FellOffFragment { pc: self.pc };
            return Ok(Some(Advanced {
                fragment: runtime.entered,
                offset: None,
                insn_index: None,
                next_offset: None,
                executed: false,
                runtime_transition: None,
                halt: Some(halt),
                snapshot: Snapshot::Physical,
            }));
        };
        let Some(&insn) = runtime.cache.fragments[fragment]
            .fragment
            .insns
            .get(offset / 4)
        else {
            unreachable!("`locate` returns offsets inside the fragment");
        };
        let index = offset / 4;
        let insn_pc = self.pc;
        self.steps += 1;

        let runtime_ranges = runtime.runtime_owned_ranges();
        let mut ctx = AccessContext::Fragment {
            runtime_ranges: &runtime_ranges,
            counter: &mut runtime.user_accesses,
            log: runtime.access_log.as_mut(),
            pan: &mut runtime.pan,
        };
        let next_pc = match execute_insn(insn, insn_pc, &mut runtime.state, &mut ctx) {
            Ok(next_pc) => next_pc,
            Err(err) => {
                let message = match err {
                    // The faulting access did not retire. Like the kernel's fixup,
                    // only the PC changes: to the site's Mem stub.
                    InsnError::Fault(fault) => match runtime.cache.fragments[fragment]
                        .fragment
                        .fault_site(offset)
                    {
                        Some(site) => {
                            self.pc = runtime.cache.fragments[fragment].base + site.stub_offset as u64;
                            return Ok(Some(Advanced {
                                fragment,
                                offset: Some(offset),
                                insn_index: Some(index),
                                next_offset: Some(site.stub_offset),
                                executed: false,
                                runtime_transition: Some(URuntimeTransition::FaultRedirect {
                                    access_offset: offset,
                                    stub_offset: site.stub_offset,
                                }),
                                halt: None,
                                snapshot: Snapshot::Physical,
                            }));
                        }
                        None => format!(
                            "{fault} at fragment offset {offset:#x}, which has no fault-site entry"
                        ),
                    },
                    InsnError::Error(message) => message,
                };
                self.stopped = true;
                let halt = URuntimeHalt::ExecutionError {
                    pc: insn_pc,
                    message,
                };
                return Ok(Some(Advanced {
                    fragment,
                    offset: Some(offset),
                    insn_index: Some(index),
                    next_offset: None,
                    executed: true,
                    runtime_transition: None,
                    halt: Some(halt),
                    snapshot: Snapshot::Physical,
                }));
            }
        };

        self.pc = next_pc;
        if self.pc == runtime.config.return_pc {
            return Ok(Some(self.apply_runtime_return(
                runtime,
                Some(fragment),
                Some(offset),
                Some(index),
                runtime.locate(next_pc).map(|(_, offset)| offset),
                true,
            )?));
        }

        Ok(Some(Advanced {
            fragment,
            offset: Some(offset),
            insn_index: Some(index),
            next_offset: runtime.locate(self.pc).map(|(_, offset)| offset),
            executed: true,
            runtime_transition: None,
            halt: None,
            snapshot: Snapshot::Physical,
        }))
    }

    fn apply_runtime_return(
        &mut self,
        runtime: &mut URuntime,
        fragment: Option<usize>,
        offset: Option<usize>,
        insn_index: Option<usize>,
        next_offset: Option<usize>,
        executed: bool,
    ) -> Result<Advanced, String> {
        // A8: the fragment must hand PSTATE back with PAN set, at every exit (a
        // PAN stub restores it before its exit group).
        if !runtime.pan {
            return Err(format!(
                "fragment returned to the runtime with PSTATE.PAN clear (status {:#x})",
                runtime.state.read_x(RET_STATUS_REG)
            ));
        }
        let fragment = fragment.unwrap_or(runtime.entered);
        match runtime.handle_runtime_return()? {
            CacheAction::ContinueAt {
                fragment: fragment_to_enter,
                offset: offset_to_enter,
            } => {
                runtime.prepare_entry_at(fragment_to_enter, offset_to_enter)?;
                self.pc = runtime.cache.fragments[fragment_to_enter].base;
                Ok(Advanced {
                    fragment,
                    offset,
                    insn_index,
                    next_offset,
                    executed,
                    runtime_transition: Some(URuntimeTransition::Continued {
                        fragment: fragment_to_enter,
                        offset: offset_to_enter,
                    }),
                    halt: None,
                    snapshot: Snapshot::UserFromPtRegs,
                })
            }
            CacheAction::Stop(halt) => {
                self.stopped = true;
                Ok(Advanced {
                    fragment,
                    offset,
                    insn_index,
                    next_offset,
                    executed,
                    runtime_transition: None,
                    halt: Some(halt),
                    snapshot: Snapshot::UserFromPtRegs,
                })
            }
        }
    }
}

/// Which user state a step reports; see `URuntimeCursor::advance`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Snapshot {
    /// The machine state minus runtime-owned memory (mid-fragment).
    Physical,
    /// Registers from `pt_regs` (at a runtime boundary).
    UserFromPtRegs,
}

/// A `URuntimeStep` whose state has not been captured yet.
pub(crate) struct Advanced {
    /// The fragment `offset` is relative to: the one that ran the step.
    pub(crate) fragment: usize,
    pub(crate) offset: Option<usize>,
    insn_index: Option<usize>,
    next_offset: Option<usize>,
    pub(crate) executed: bool,
    pub(crate) runtime_transition: Option<URuntimeTransition>,
    pub(crate) halt: Option<URuntimeHalt>,
    snapshot: Snapshot,
}

impl Advanced {
    fn into_step(self, runtime: &URuntime) -> URuntimeStep {
        URuntimeStep {
            fragment: self.fragment,
            offset: self.offset,
            insn_index: self.insn_index,
            next_offset: self.next_offset,
            executed: self.executed,
            runtime_transition: self.runtime_transition,
            halt: self.halt,
            state: match self.snapshot {
                Snapshot::Physical => runtime.physical_user_state(),
                Snapshot::UserFromPtRegs => runtime.user_state_from_pt_regs(),
            },
        }
    }
}

pub struct URuntimeStepper<'a> {
    runtime: &'a mut URuntime,
    cursor: URuntimeCursor,
}

impl<'a> URuntimeStepper<'a> {
    pub fn new(runtime: &'a mut URuntime) -> Result<Self, String> {
        let cursor = URuntimeCursor::new(runtime)?;
        Ok(Self { runtime, cursor })
    }

    pub fn pc(&self) -> u64 {
        self.cursor.pc()
    }

    pub fn current_offset(&self) -> Option<usize> {
        self.cursor.current_offset(self.runtime)
    }

    pub fn steps(&self) -> usize {
        self.cursor.steps()
    }

    pub fn report_for_halt(&self, halt: URuntimeHalt) -> URuntimeReport {
        self.runtime.report(halt, self.cursor.steps())
    }

    pub fn step(&mut self) -> Result<Option<URuntimeStep>, String> {
        self.cursor.step(self.runtime)
    }

    /// `step` without the user-state snapshot (a full memory copy), for callers
    /// that only need the final report.
    pub(crate) fn advance(&mut self) -> Result<Option<Advanced>, String> {
        self.cursor.advance(self.runtime)
    }

    pub fn run_to_halt(&mut self) -> URuntimeReport {
        run_cursor_to_halt(self.runtime, &mut self.cursor)
    }
}

#[derive(Debug)]
pub struct OwnedURuntimeStepper {
    runtime: URuntime,
    cursor: URuntimeCursor,
}

impl OwnedURuntimeStepper {
    pub fn new(mut runtime: URuntime) -> Result<Self, String> {
        let cursor = URuntimeCursor::new(&mut runtime)?;
        Ok(Self { runtime, cursor })
    }

    pub fn pc(&self) -> u64 {
        self.cursor.pc()
    }

    pub fn current_offset(&self) -> Option<usize> {
        self.cursor.current_offset(&self.runtime)
    }

    pub fn steps(&self) -> usize {
        self.cursor.steps()
    }

    pub fn current_state(&self) -> MachineState {
        self.runtime.physical_user_state()
    }

    pub fn runtime_owned_ranges(&self) -> Vec<(u64, u64)> {
        self.runtime.runtime_owned_ranges()
    }

    pub fn report_for_halt(&self, halt: URuntimeHalt) -> URuntimeReport {
        self.runtime.report(halt, self.cursor.steps())
    }

    pub fn step(&mut self) -> Result<Option<URuntimeStep>, String> {
        self.cursor.step(&mut self.runtime)
    }

    pub fn run_to_halt(&mut self) -> URuntimeReport {
        run_cursor_to_halt(&mut self.runtime, &mut self.cursor)
    }
}

fn run_cursor_to_halt(runtime: &mut URuntime, cursor: &mut URuntimeCursor) -> URuntimeReport {
    loop {
        match cursor.advance(runtime) {
            Ok(Some(step)) => {
                if let Some(halt) = step.halt {
                    return runtime.report(halt, cursor.steps());
                }
            }
            Ok(None) => {
                return runtime.report(
                    URuntimeHalt::ExecutionError {
                        pc: cursor.pc(),
                        message: "runtime stepper stopped without a halt reason".to_string(),
                    },
                    cursor.steps(),
                );
            }
            Err(message) => {
                return runtime.report(
                    URuntimeHalt::ExecutionError {
                        pc: cursor.pc(),
                        message,
                    },
                    cursor.steps(),
                );
            }
        }
    }
}

/// What the runtime does when a fragment returns through the epilogue.
pub(crate) enum RuntimeAction {
    /// Call the fragment again, entering the body at this offset.
    ContinueAt(usize),
    Stop(URuntimeHalt),
}

/// The runtime's continue/stop decision for one fragment return. Shared by
/// `URuntime` and the native runner so both drive a fragment identically; the
/// caller reads `raw_status`/`param0`/`param1` from wherever its ABI boundary
/// delivers them.
pub(crate) fn decide_runtime_return(
    fragment: &ExecutionFragment,
    raw_status: u64,
    param0: u64,
    param1: u64,
) -> RuntimeAction {
    let status = RetStatus::from_reg(raw_status);
    let resume_pc = param1;
    let resume_offset = fragment.offset_for_pc(resume_pc);
    let continue_or_request_translation = |target_pc: u64| {
        if let Some(offset) = fragment.offset_for_pc(target_pc) {
            RuntimeAction::ContinueAt(offset)
        } else {
            RuntimeAction::Stop(URuntimeHalt::NeedsTranslation {
                status,
                target_pc,
                resume_offset,
            })
        }
    };

    match status {
        RetStatus::Svc => {
            if let Some(offset) = resume_offset {
                RuntimeAction::ContinueAt(offset)
            } else {
                RuntimeAction::Stop(URuntimeHalt::ReturnedToUserspace {
                    status,
                    target_pc: resume_pc,
                })
            }
        }
        RetStatus::Bl | RetStatus::Blr | RetStatus::Br => continue_or_request_translation(param0),
        RetStatus::Ret => {
            if let Some(offset) = fragment.offset_for_pc(param0) {
                RuntimeAction::ContinueAt(offset)
            } else {
                RuntimeAction::Stop(URuntimeHalt::ReturnedToUserspace {
                    status,
                    target_pc: param0,
                })
            }
        }
        // Never continue inside the fragment: resuming at this PC would re-enter
        // the same exit. Userspace executes the instruction natively: for
        // Unsupported that runs it, for Mem it re-executes the faulting memory
        // instruction and takes the fault (and any signal) itself, for Budget it
        // runs the back-edge branch (the kernel's return to userspace is where
        // signals and rescheduling happen).
        RetStatus::Unsupported | RetStatus::Mem | RetStatus::Budget => {
            RuntimeAction::Stop(URuntimeHalt::ReturnedToUserspace {
                status,
                target_pc: param1,
            })
        }
        RetStatus::Invalid(_) => {
            RuntimeAction::Stop(URuntimeHalt::InvalidReturnStatus { raw: raw_status })
        }
        RetStatus::Debug => RuntimeAction::Stop(URuntimeHalt::UnsupportedRuntimeExit { status }),
    }
}

/// The ABI entry invariant: the prologue's `br` only ever targets a body label
/// of this fragment (`entry_offset` is one; `offset_for_pc` returns them).
pub(crate) fn validate_entry_offset(
    fragment: &ExecutionFragment,
    offset: usize,
) -> Result<(), String> {
    if !fragment.vlabels.iter().any(|(_, label)| *label == offset) {
        return Err(format!(
            "runtime entry offset {offset:#x} is not a fragment label"
        ));
    }
    Ok(())
}

fn seed_pt_regs(state: &mut MachineState, config: &URuntimeConfig) {
    for reg in 0..31 {
        state.write_u64(config.pt_regs_addr + (reg as u64) * 8, state.read_x(reg));
    }
    state.write_u64(config.pt_regs_addr + PT_REGS_SP_OFFSET, state.sp());
    for word in 0..crate::shared::abi::EXTRA_PARAMS_WORDS as u64 {
        state.write_u64(config.extra_params_addr + word * 8, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arm64::OriginalStepper;
    use crate::model::{AccessKind, HaltReason, PagePerm};
    use crate::shared::abi::PROLOGUE_LEN_BYTES;
    use crate::shared::arm64::ergo::{uimm, x};
    use crate::shared::arm64::{A64Imm, A64Insn, A64Mem, A64Reg};
    use crate::shared::platform::SharedVec;
    use crate::shared::trans::input::{TranslationRequest, TranslationTrigger};
    use crate::shared::trans::translate::compile_request;
    use crate::MockCodeProvider;

    fn compile_insns(base_pc: u64, insns: &[A64Insn]) -> ExecutionFragment {
        let mut bytes = Vec::with_capacity(insns.len() * 4);
        for insn in insns {
            bytes.extend_from_slice(&insn.encode().unwrap().to_le_bytes());
        }
        let code = MockCodeProvider::new(base_pc, bytes);
        let request = TranslationRequest {
            entry_pc: base_pc,
            trigger: TranslationTrigger::Manual,
            regs: None,
        };
        let fragment = compile_request(&request, &code).unwrap();
        let encoded = crate::encode_fragment(&fragment).unwrap();
        crate::verify_encoded_fragment(&fragment, &encoded).unwrap();
        fragment
    }

    #[test]
    fn runtime_stepper_executes_prologue_before_body() {
        let base_pc = 0x3000;
        let fragment = compile_insns(
            base_pc,
            &[
                A64Insn::MovzMovz64Movewide {
                    hw: 0,
                    imm16: uimm(2, 16),
                    rd: x(2),
                },
                A64Insn::RetRet64rBranchReg { rn: x(30) },
            ],
        );
        let entry_offset = fragment.entry_offset;
        let mut runtime = URuntime::new(fragment, MachineState::new());
        let mut stepper = URuntimeStepper::new(&mut runtime).unwrap();

        let first = stepper.step().unwrap().unwrap();
        assert_eq!(first.offset, Some(0));

        let mut branch = first;
        for _ in 1..PROLOGUE_LEN_BYTES / 4 {
            branch = stepper.step().unwrap().unwrap();
        }

        // The prologue's last instruction is the real `br` to ABI_ENTRY_ARG_REG.
        assert_eq!(branch.offset, Some(PROLOGUE_LEN_BYTES - 4));
        assert_eq!(stepper.current_offset(), Some(entry_offset));

        let body = stepper.step().unwrap().unwrap();
        assert_eq!(body.offset, Some(entry_offset));
        assert_eq!(body.state.read_x(2), 2);
    }

    #[test]
    fn bl_runtime_exit_writes_user_lr_before_epilogue() {
        let base_pc = 0x3000;
        let fragment = compile_insns(
            base_pc,
            &[
                A64Insn::BlBlOnlyBranchImm {
                    imm26: A64Imm::scaled_signed(2, 26, 2),
                },
                A64Insn::NopNopHiHints {},
                A64Insn::NopNopHiHints {},
            ],
        );
        let mut runtime = URuntime::new(fragment, MachineState::new());
        let report = runtime.run();

        assert_eq!(report.state.read_x(30), base_pc + 4);
        assert_eq!(
            report.halt,
            URuntimeHalt::NeedsTranslation {
                status: RetStatus::Bl,
                target_pc: base_pc + 8,
                resume_offset: None,
            }
        );
    }

    #[test]
    fn runtime_stepper_runtime_return_preserves_run_behavior() {
        let base_pc = 0x4000;
        let insns = [
            A64Insn::MovzMovz64Movewide {
                hw: 0,
                imm16: uimm(172, 16),
                rd: x(8),
            },
            A64Insn::SvcSvcExException {
                imm16: A64Imm::unsigned(0, 16),
            },
            A64Insn::MovzMovz64Movewide {
                hw: 0,
                imm16: uimm(2, 16),
                rd: x(2),
            },
            A64Insn::RetRet64rBranchReg { rn: x(30) },
        ];
        let fragment = compile_insns(base_pc, &insns);
        let resume_offset = fragment.offset_for_pc(base_pc + 8).unwrap();
        let mut initial_state = MachineState::new();
        initial_state.write_x(30, 0xfeed_0000);

        let mut stepped_runtime = URuntime::new(fragment, initial_state.clone());
        let stepped_report = {
            let mut stepper = URuntimeStepper::new(&mut stepped_runtime).unwrap();
            let mut saw_svc_continue = false;
            loop {
                let step = stepper.step().unwrap().unwrap();
                if step.runtime_transition
                    == Some(URuntimeTransition::Continued {
                        fragment: 0,
                        offset: resume_offset,
                    })
                {
                    saw_svc_continue = true;
                }
                if let Some(halt) = step.halt {
                    assert!(saw_svc_continue);
                    break stepper.report_for_halt(halt);
                }
            }
        };

        let mut direct_runtime = URuntime::new(compile_insns(base_pc, &insns), initial_state);
        let direct_report = direct_runtime.run();

        assert_eq!(stepped_report.state, direct_report.state);
        assert_eq!(stepped_report.halt, direct_report.halt);
    }

    #[test]
    fn svc_runtime_exit_continues_at_original_resume_pc() {
        let base_pc = 0x4000;
        let fragment = compile_insns(
            base_pc,
            &[
                A64Insn::MovzMovz64Movewide {
                    hw: 0,
                    imm16: uimm(172, 16),
                    rd: x(8),
                },
                A64Insn::SvcSvcExException {
                    imm16: A64Imm::unsigned(0, 16),
                },
                A64Insn::MovzMovz64Movewide {
                    hw: 0,
                    imm16: uimm(2, 16),
                    rd: x(2),
                },
                A64Insn::RetRet64rBranchReg { rn: x(30) },
            ],
        );
        let mut initial_state = MachineState::new();
        initial_state.write_x(30, 0xfeed_0000);

        let mut runtime = URuntime::new(fragment, initial_state);
        let report = runtime.run();

        assert_eq!(report.state.read_x(2), 2);
        assert_eq!(
            report.halt,
            URuntimeHalt::ReturnedToUserspace {
                status: RetStatus::Ret,
                target_pc: 0xfeed_0000
            }
        );
    }

    #[test]
    fn ret_to_unknown_original_pc_returns_to_userspace() {
        let base_pc = 0x5000;
        let fragment = compile_insns(base_pc, &[A64Insn::RetRet64rBranchReg { rn: x(30) }]);
        let mut initial_state = MachineState::new();
        initial_state.write_x(30, 0x7777_0000);

        let mut runtime = URuntime::new(fragment, initial_state);
        let report = runtime.run();

        assert_eq!(
            report.halt,
            URuntimeHalt::ReturnedToUserspace {
                status: RetStatus::Ret,
                target_pc: 0x7777_0000
            }
        );
    }

    fn ldr_x0_from_x1() -> A64Insn {
        A64Insn::LdrImmGenLdr64LdstPos {
            rt: x(0),
            mem: A64Mem::offset(A64Reg::x_sp(1), A64Imm::scaled_unsigned(0, 12, 3)),
        }
    }

    #[test]
    fn runtime_owned_memory_is_never_user_accessible() {
        // A user access to runtime-owned memory faults: it is never user-mapped.
        let program = ldr_x0_from_x1().encode().unwrap().to_le_bytes();
        let mut state = MachineState::new();
        state.write_x(1, DEFAULT_PT_REGS_ADDR);
        let mut stepper = OriginalStepper::new(&program, 0x4000, 0x4000, &state).unwrap();
        let step = stepper.step().unwrap().unwrap();
        match step.halt_reason {
            Some(HaltReason::Fault(fault)) => {
                assert_eq!(fault.access.addr, DEFAULT_PT_REGS_ADDR);
                assert_eq!(fault.access.kind, AccessKind::Read);
            }
            other => panic!("expected a fault, got {other:?}"),
        }

        // And a runtime refuses a user page map that covers runtime-owned memory.
        state
            .map_user_range(
                DEFAULT_PT_REGS_ADDR,
                DEFAULT_PT_REGS_ADDR + PAGE_SIZE,
                PagePerm::ReadOnly,
            )
            .unwrap();
        let fragment = compile_insns(0x4000, &[A64Insn::RetRet64rBranchReg { rn: x(30) }]);
        let report = URuntime::new(fragment, state).run();
        match report.halt {
            URuntimeHalt::ExecutionError { message, .. } => {
                assert!(message.contains("never user-accessible"), "{message}");
            }
            other => panic!("expected an execution error, got {other:?}"),
        }
    }

    fn encode(insns: &[A64Insn]) -> Vec<u8> {
        insns
            .iter()
            .flat_map(|insn| insn.encode().unwrap().to_le_bytes())
            .collect()
    }

    #[test]
    fn user_access_fault_inside_fragment_exits_through_its_mem_stub() {
        let insns = [
            A64Insn::MovzMovz64Movewide {
                hw: 0,
                imm16: uimm(7, 16),
                rd: x(2),
            },
            ldr_x0_from_x1(),
            A64Insn::RetRet64rBranchReg { rn: x(30) },
        ];
        let mut state = MachineState::new();
        state.write_x(0, 0x55);
        state.write_x(1, 0x9000); // unmapped
        let mut runtime = URuntime::new(compile_insns(0x4000, &insns), state.clone());
        let report = runtime.run();

        assert_eq!(
            report.halt,
            URuntimeHalt::ReturnedToUserspace {
                status: RetStatus::Mem,
                target_pc: 0x4004,
            }
        );
        // The state userspace resumes with is the state before the faulting LDR.
        let mut expected = state;
        expected.write_x(2, 7);
        assert_eq!(report.state, expected);
        assert_eq!(runtime.user_accesses(), 1);
    }

    #[test]
    fn store_to_read_only_page_matches_the_original_fault_end_to_end() {
        let insns = [
            A64Insn::StrImmGenStr64LdstPos {
                rt: x(0),
                mem: A64Mem::offset(A64Reg::x_sp(1), A64Imm::scaled_unsigned(1, 12, 3)),
            },
            A64Insn::RetRet64rBranchReg { rn: x(30) },
        ];
        let mut state = MachineState::new();
        state
            .map_user_range(0x9000, 0xa000, PagePerm::ReadOnly)
            .unwrap();
        state.seed_memory_u64(0x9008, 0x1122);
        state.write_x(0, 0x3344);
        state.write_x(1, 0x9000);

        // Compares state and halt against the original interpreter, which faults.
        let report =
            crate::run_entry_fixture("ro-store", 0x4000, encode(&insns), 0x4000, &state).unwrap();
        assert!(matches!(report.original.halt_reason, HaltReason::Fault(_)));
        assert_eq!(
            report.fragment_halt,
            URuntimeHalt::ReturnedToUserspace {
                status: RetStatus::Mem,
                target_pc: 0x4000,
            }
        );
        assert_eq!(report.fragment_state.read_u64(0x9008), 0x1122);
    }

    /// A8: a faulting window atomic resumes at its PAN stub, which restores PAN
    /// before the Mem exit; a stub without its `msr pan, #1` hands PSTATE back to
    /// the runtime with PAN clear, which is a hard error.
    #[test]
    fn window_atomic_fault_exits_through_the_pan_stub_with_pan_restored() {
        let insns = [
            A64Insn::LdaddLdaddal64Memop {
                rs: x(0),
                rn: A64Reg::x_sp(1),
                rt: x(2),
            },
            A64Insn::RetRet64rBranchReg { rn: x(30) },
        ];
        let mut state = MachineState::new();
        state.write_x(0, 1);
        state.write_x(1, 0x9000); // unmapped
        state.write_x(2, 0x22);
        let fragment = compile_insns(0x4000, &insns);
        let mut runtime = URuntime::new(fragment, state.clone());
        let report = runtime.run();
        assert_eq!(
            report.halt,
            URuntimeHalt::ReturnedToUserspace {
                status: RetStatus::Mem,
                target_pc: 0x4000,
            }
        );
        assert_eq!(report.state, state);
        assert_eq!(runtime.user_accesses(), 1);

        let mut fragment = compile_insns(0x4000, &insns);
        let stub = fragment.fault_sites[0].stub_offset / 4;
        assert_eq!(fragment.insns[stub].msr_pan(), Some(true));
        fragment.insns[stub] = A64Insn::NopNopHiHints {};
        let report = URuntime::new(fragment, state).run();
        assert!(
            matches!(&report.halt, URuntimeHalt::ExecutionError { message, .. }
                if message.contains("PSTATE.PAN clear")),
            "{:?}",
            report.halt
        );
    }

    #[test]
    fn user_access_fault_without_fault_site_is_a_hard_error() {
        let mut fragment = compile_insns(
            0x4000,
            &[ldr_x0_from_x1(), A64Insn::RetRet64rBranchReg { rn: x(30) }],
        );
        fragment.fault_sites = SharedVec::new();
        let mut state = MachineState::new();
        state.write_x(1, 0x9000);
        let report = URuntime::new(fragment, state).run();
        match report.halt {
            URuntimeHalt::ExecutionError { message, .. } => {
                assert!(message.contains("user read fault"), "{message}");
                assert!(message.contains("no fault-site entry"), "{message}");
            }
            other => panic!("expected an execution error, got {other:?}"),
        }
    }

    /// Privilege follows the instruction, not the address: a plain LDR from a
    /// readable user page is still a runtime access, so it is a PAN violation.
    #[test]
    fn plain_load_of_user_memory_in_a_fragment_is_a_pan_violation() {
        let mut fragment = compile_insns(
            0x4000,
            &[ldr_x0_from_x1(), A64Insn::RetRet64rBranchReg { rn: x(30) }],
        );
        let site = fragment.fault_sites[0];
        let A64Insn::LdtrLdtr64LdstUnpriv { rt, mem } = fragment.insns[site.access_offset / 4]
        else {
            panic!("fault site is not an LDTR");
        };
        fragment.insns[site.access_offset / 4] = A64Insn::LdrImmGenLdr64LdstPos {
            rt,
            mem: A64Mem::offset(mem.base(), A64Imm::scaled_unsigned(0, 12, 3)),
        };
        let mut state = MachineState::new();
        state
            .map_user_range(0x9000, 0xa000, PagePerm::ReadWrite)
            .unwrap();
        state.write_x(1, 0x9000);
        let report = URuntime::new(fragment, state).run();
        match report.halt {
            URuntimeHalt::ExecutionError { message, .. } => {
                assert!(message.contains("PAN violation"), "{message}");
            }
            other => panic!("expected an execution error, got {other:?}"),
        }
    }

    // ---- Execution budget (A6) ----

    fn movz_x(rd: u8, value: u32) -> A64Insn {
        A64Insn::MovzMovz64Movewide {
            hw: 0,
            imm16: uimm(value, 16),
            rd: x(rd),
        }
    }

    /// `movz x0, #n; L: sub x0, x0, #1; cbnz x0, L; ret` at 0x4000.
    fn countdown(n: u32) -> [A64Insn; 4] {
        [
            movz_x(0, n),
            A64Insn::SubAddsubImmSub64AddsubImm {
                sh: 0,
                imm12: uimm(1, 12),
                rn: A64Reg::x_sp(0),
                rd: A64Reg::x_sp(0),
            },
            A64Insn::CbnzCbnz64Compbranch {
                imm19: A64Imm::scaled_signed((1 << 19) - 1, 19, 2),
                rt: x(0),
            },
            A64Insn::RetRet64rBranchReg { rn: x(30) },
        ]
    }

    fn run_counting(insns: &[A64Insn]) -> (URuntimeReport, Option<crate::InstanceCap>) {
        let mut runtime = URuntime::new(compile_insns(0x4000, insns), MachineState::new());
        crate::run_fragment_counting_instances(&mut runtime, None).unwrap()
    }

    #[test]
    fn self_branch_exits_budget_on_its_budget_th_execution() {
        use crate::shared::abi::KJIT_BACKEDGE_BUDGET;

        let (report, cap) = run_counting(&[
            movz_x(0, 0x1234),
            A64Insn::BUncondBOnlyBranchImm {
                imm26: A64Imm::scaled_signed(0, 26, 2),
            },
        ]);
        assert_eq!(
            report.halt,
            URuntimeHalt::ReturnedToUserspace {
                status: RetStatus::Budget,
                target_pc: 0x4004,
            }
        );
        assert_eq!(
            cap,
            Some(crate::InstanceCap {
                pc: 0x4004,
                instance: KJIT_BACKEDGE_BUDGET,
            })
        );
        assert_eq!(report.state.read_x(0), 0x1234);
    }

    /// The N-th budget unit of one entry exits (N = the budget), before the branch
    /// runs; N - 1 units complete. A back-edge execution is one unit and, since A11,
    /// so is a dispatch attempt: the `ret` that ends `countdown` takes one more than
    /// its loop does.
    #[test]
    fn budget_exits_exactly_on_the_budget_th_unit() {
        use crate::shared::abi::KJIT_BACKEDGE_BUDGET;
        let budget = KJIT_BACKEDGE_BUDGET as u32;

        // n back-edge executions + the `ret`'s dispatch = N - 1 units: all complete.
        let (report, cap) = run_counting(&countdown(budget - 2));
        assert_eq!(
            report.halt,
            URuntimeHalt::ReturnedToUserspace {
                status: RetStatus::Ret,
                // User x30 of `MachineState::new()`.
                target_pc: 0,
            }
        );
        assert_eq!(cap, None);
        assert_eq!(report.state.read_x(0), 0);

        // N - 1 back-edge executions + the `ret` = N units: the `ret` is the N-th.
        let (report, cap) = run_counting(&countdown(budget - 1));
        assert_eq!(
            report.halt,
            URuntimeHalt::ReturnedToUserspace {
                status: RetStatus::Budget,
                target_pc: 0x400c,
            }
        );
        assert_eq!(
            cap,
            Some(crate::InstanceCap {
                pc: 0x400c,
                instance: 1,
            })
        );
        assert_eq!(report.state.read_x(0), 0);

        // N back-edge executions: the N-th one exits.
        let (report, cap) = run_counting(&countdown(budget));
        assert_eq!(
            report.halt,
            URuntimeHalt::ReturnedToUserspace {
                status: RetStatus::Budget,
                target_pc: 0x4008,
            }
        );
        assert_eq!(
            cap,
            Some(crate::InstanceCap {
                pc: 0x4008,
                instance: KJIT_BACKEDGE_BUDGET,
            })
        );
        // The last `sub` ran; the cbnz that would have fallen through did not.
        assert_eq!(report.state.read_x(0), 0);
    }

    /// Every entry through the prologue restarts the budget: an SVC in the loop
    /// body leaves and re-enters the fragment.
    #[test]
    fn budget_restarts_on_every_fragment_entry() {
        use crate::shared::abi::KJIT_BACKEDGE_BUDGET;

        // movz x0, #3 * budget / 2; L: svc; sub x0, x0, #1; cbnz x0, L; ret
        let iterations = 3 * KJIT_BACKEDGE_BUDGET as u32 / 2;
        let insns = [
            movz_x(0, iterations),
            A64Insn::SvcSvcExException {
                imm16: A64Imm::unsigned(0, 16),
            },
            A64Insn::SubAddsubImmSub64AddsubImm {
                sh: 0,
                imm12: uimm(1, 12),
                rn: A64Reg::x_sp(0),
                rd: A64Reg::x_sp(0),
            },
            A64Insn::CbnzCbnz64Compbranch {
                imm19: A64Imm::scaled_signed((1 << 19) - 2, 19, 2),
                rt: x(0),
            },
            A64Insn::RetRet64rBranchReg { rn: x(30) },
        ];
        let (report, cap) = run_counting(&insns);
        assert_eq!(
            report.halt,
            URuntimeHalt::ReturnedToUserspace {
                status: RetStatus::Ret,
                // User x30 of `MachineState::new()`.
                target_pc: 0,
            }
        );
        assert_eq!(cap, None);
        assert_eq!(report.state.read_x(0), 0);
    }
}
