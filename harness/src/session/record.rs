//! The recorder: drives the two worlds and writes down what happens.
//!
//! - Reference world: the original program alone, `OriginalStepper` following
//!   branches with the `SVC` mocked.
//! - KJIT world: user code runs natively on a second `OriginalStepper`. After every
//!   `SVC` the recorder plays the kernel's syscall-return hook (runtime/exec.rs,
//!   `kjit_rs_after_syscall`): look up a fragment translated for the resume pc; on a
//!   hit run a chain over the code cache (`URuntime` + `CodeCache` with
//!   `MissPolicy::ReturnToUser`), on a miss profile the pc. A chain that returns to
//!   userspace at a branch target the cache could not resolve profiles that target
//!   (exit-target learning). A pc that turns hot is translated before userspace
//!   resumes, as the kernel's task_work does.
//! - The worlds are compared at every `SVC` (both stop there, whichever of
//!   userspace or a fragment executes it) and at the end.

use std::collections::{BTreeMap, BTreeSet};

use crate::arm64::OriginalStepper;
use crate::code_cache::{synthetic_loader, CacheEvent, CodeCache, MissPolicy};
use crate::model::{ExecutionResult, HaltReason, MachineState};
use crate::runtime::{
    URuntime, URuntimeConfig, URuntimeHalt, URuntimeStepper, URuntimeTransition, DEFAULT_BASE_PC,
    DEFAULT_CACHE_LAYOUT,
};
use crate::shared::abi::RetStatus;
use crate::shared::arm64::A64Insn;
use crate::shared::trans::cfg::RuntimeExitReason;
use crate::shared::trans::rephrase::RephrasedInsnKind;
use crate::{faulting_footprint, undo_footprint, MockCodeProvider};

use super::steps::{reg_diff, RegFile, StepAt, StepLog, StepMemWrite};
use super::translation::{self, Rejection, Trigger};
use super::{
    Divergence, DivergenceKind, Event, EventKind, LinkTarget, Loc, MemDiff, Outcome, RegDiff,
    Session, SessionConfig, SessionError, StateDiff, SyncPoint, SyscallRecord, TransferVia,
    SESSION_EXIT_PC,
};

pub(super) fn record(config: SessionConfig) -> Result<Session, SessionError> {
    record_with(config, |_| {})
}

/// Test hook (`session::tests`): corrupts the KJIT world at a syscall, before the
/// worlds are compared, to prove the comparison catches a broken model.
#[cfg(test)]
pub(super) type TamperFn = Box<dyn FnMut(u64, &mut MachineState)>;

#[cfg(test)]
pub(super) fn record_tampered(
    config: SessionConfig,
    tamper: TamperFn,
) -> Result<Session, SessionError> {
    record_with(config, |recorder| recorder.tamper = Some(tamper))
}

fn record_with(
    config: SessionConfig,
    setup: impl FnOnce(&mut Recorder<'_>),
) -> Result<Session, SessionError> {
    validate(&config)?;
    let finished = {
        let mut recorder = Recorder::new(&config)?;
        setup(&mut recorder);
        let outcome = recorder.run()?;
        recorder
            .cache()
            .check_invariants()
            .map_err(SessionError::Runtime)?;
        recorder.finish(outcome)
    };
    Ok(Session {
        config,
        translations: finished.translations,
        events: finished.events,
        steps: finished.steps,
        checkpoints: finished.checkpoints,
        syscalls: finished.syscalls,
        outcome: finished.outcome,
        cache: finished.cache,
        fragment_translation: finished.fragment_translation,
        final_state: finished.final_state,
    })
}

fn validate(config: &SessionConfig) -> Result<(), SessionError> {
    let invalid = |message: &str| Err(SessionError::InvalidConfig(message.to_string()));
    if config.policy.hot_threshold == 0 {
        return invalid("hot_threshold must be at least 1");
    }
    if config.policy.chain_budget == 0 {
        return invalid("chain_budget must be at least 1");
    }
    if config.limits.max_steps == 0 {
        return invalid("max_steps must be at least 1");
    }
    if config.limits.checkpoint_every == 0 {
        return invalid("checkpoint_every must be at least 1");
    }
    if config.text.len() % 4 != 0 {
        return invalid("the text is not a whole number of A64 words");
    }
    let code = MockCodeProvider::new(config.text_base, config.text.as_slice());
    if crate::shared::trans::input::CodeProvider::read_exact(&code, config.entry_pc, &mut [0; 4])
        .is_err()
    {
        return Err(SessionError::EntryUnreadable {
            entry_pc: config.entry_pc,
        });
    }
    Ok(())
}

/// The recording, without the config it borrowed.
struct Finished {
    translations: Vec<translation::TranslationRecord>,
    events: Vec<Event>,
    steps: StepLog,
    checkpoints: Vec<MachineState>,
    syscalls: Vec<SyscallRecord>,
    outcome: Outcome,
    cache: CodeCache,
    fragment_translation: BTreeMap<usize, usize>,
    final_state: MachineState,
}

/// Why user mode stopped.
enum UserStop {
    Svc { pc: u64, resume: u64 },
    Exit,
    Halt(HaltReason),
    Limit,
}

/// Why a chain stopped.
enum ChainStop {
    /// The fragment executed an `SVC` at `pc`; its syscall comes next.
    Svc { pc: u64, resume: u64 },
    /// Userspace resumes at `pc`.
    ToUser { pc: u64 },
    /// The session ends.
    Outcome(Outcome),
}

/// How the stepping loop of a chain ended.
enum ChainEnd {
    /// The cache returned the run to userspace, or the run failed.
    Halt(URuntimeHalt),
    /// `max_steps` ticks were executed mid-run.
    Limit,
}

/// A world's stop, or the reference failing to stop.
enum Reached {
    Point(SyncPoint),
    Runaway { steps: u64 },
}

struct Recorder<'a> {
    config: &'a SessionConfig,
    code: MockCodeProvider<Vec<u8>>,
    reference: OriginalStepper<'a>,
    /// Where the reference resumes after the `SVC` it last stopped at.
    reference_resume: u64,
    user: OriginalStepper<'a>,
    /// Out while a chain holds it.
    cache: Option<CodeCache>,
    t: u64,
    k: u64,
    events: Vec<Event>,
    /// Index in `events` of the open `UserSpan`.
    span: Option<usize>,
    translations: Vec<translation::TranslationRecord>,
    fragment_translation: BTreeMap<usize, usize>,
    steps: StepLog,
    checkpoints: Vec<MachineState>,
    syscalls: Vec<SyscallRecord>,
    /// The registers after the last tick: the next tick's diff is against them.
    shadow: RegFile,
    /// Hits of each pc without a fragment since it last turned hot.
    hits: BTreeMap<u64, u32>,
    /// Pcs whose translation failed for good: never requested again (section 9,
    /// "Negative cache").
    negative: BTreeSet<u64>,
    /// The state the recording ended in, when the user stepper does not hold it: the
    /// recording stopped inside a chain (`max_steps`).
    final_state: Option<MachineState>,
    #[cfg(test)]
    tamper: Option<TamperFn>,
}

impl<'a> Recorder<'a> {
    fn new(config: &'a SessionConfig) -> Result<Self, SessionError> {
        let mut initial = config.initial_state.clone();
        initial.write_x(30, SESSION_EXIT_PC);
        initial.stop_write_journal();
        let stepper = || {
            OriginalStepper::new(&config.text, config.text_base, config.entry_pc, &initial)
                .map(OriginalStepper::follow_branches)
                .map_err(SessionError::Interpreter)
        };
        let reference = stepper()?;
        let mut user = stepper()?;
        user.state_mut().start_write_journal();

        let mut cache = CodeCache::new(
            DEFAULT_CACHE_LAYOUT,
            Some(MockCodeProvider::new(config.text_base, config.text.clone())),
            synthetic_loader(DEFAULT_BASE_PC),
        )
        .with_chain_budget(config.policy.chain_budget)
        .with_miss_policy(MissPolicy::ReturnToUser);
        if !config.policy.links {
            cache = cache.without_links();
        }
        let cache = cache.with_event_log();

        Ok(Self {
            config,
            code: MockCodeProvider::new(config.text_base, config.text.clone()),
            reference,
            reference_resume: config.entry_pc,
            user,
            cache: Some(cache),
            t: 0,
            k: 0,
            events: Vec::new(),
            span: None,
            translations: Vec::new(),
            fragment_translation: BTreeMap::new(),
            steps: StepLog::default(),
            checkpoints: vec![initial.clone()],
            syscalls: Vec::new(),
            shadow: RegFile::of(&initial),
            hits: BTreeMap::new(),
            negative: BTreeSet::new(),
            final_state: None,
            #[cfg(test)]
            tamper: None,
        })
    }

    fn finish(mut self, outcome: Outcome) -> Finished {
        let mut final_state = match self.final_state.take() {
            Some(state) => state,
            None => self.user.state().clone(),
        };
        final_state.stop_write_journal();
        Finished {
            translations: self.translations,
            events: self.events,
            steps: self.steps,
            checkpoints: self.checkpoints,
            syscalls: self.syscalls,
            outcome,
            cache: self.cache.expect("the cache is back after the last chain"),
            fragment_translation: self.fragment_translation,
            final_state,
        }
    }

    fn cache(&mut self) -> &mut CodeCache {
        self.cache.as_mut().expect("no chain is running")
    }

    fn push(&mut self, kind: EventKind) {
        self.events.push(Event { t: self.t, kind });
    }

    fn close_span(&mut self) {
        self.span = None;
    }

    // ---- the run ----------------------------------------------------------------

    fn run(&mut self) -> Result<Outcome, SessionError> {
        loop {
            match self.run_user()? {
                UserStop::Svc { pc, resume } => {
                    if let Some(outcome) = self.syscall(pc)? {
                        return Ok(outcome);
                    }
                    if let Some(outcome) = self.hook(resume)? {
                        return Ok(outcome);
                    }
                }
                UserStop::Exit => return self.end(SyncPoint::Exit),
                UserStop::Halt(halt) => return self.end(SyncPoint::Halt(halt)),
                UserStop::Limit => return Ok(Outcome::StepLimit),
            }
        }
    }

    /// The syscall-return hook at `resume` (`kjit_rs_after_syscall`), looping while
    /// chains end in an `SVC` (each one is a new hook call after its syscall).
    fn hook(&mut self, mut resume: u64) -> Result<Option<Outcome>, SessionError> {
        loop {
            // kjit_can_run, before the lookup and the profile (A22: the run conditions
            // the harness models are user SP 16-byte aligned): userspace continues.
            if self.user.state().sp() % 16 != 0 {
                self.user.resume_at(resume);
                return Ok(None);
            }
            // kjit_lookup(pc, link = false): the fragment translated for exactly `resume`.
            let Some(fragment) = self.cache().fragment_for_entry(resume) else {
                self.profile(resume, Trigger::SvcResume, resume.wrapping_sub(4))?;
                self.user.resume_at(resume);
                return Ok(None);
            };
            match self.run_chain(fragment)? {
                ChainStop::Outcome(outcome) => return Ok(Some(outcome)),
                ChainStop::ToUser { pc } => {
                    self.user.resume_at(pc);
                    return Ok(None);
                }
                ChainStop::Svc { pc, resume: next } => {
                    if let Some(outcome) = self.syscall(pc)? {
                        return Ok(Some(outcome));
                    }
                    resume = next;
                }
            }
        }
    }

    // ---- userspace -----------------------------------------------------------------

    fn text_word(&self, pc: u64) -> Option<u32> {
        let offset = usize::try_from(pc.checked_sub(self.config.text_base)?).ok()?;
        let bytes = self.config.text.get(offset..offset.checked_add(4)?)?;
        Some(u32::from_le_bytes(bytes.try_into().expect("4 bytes")))
    }

    fn run_user(&mut self) -> Result<UserStop, SessionError> {
        loop {
            let pc = self.user.pc();
            if pc == SESSION_EXIT_PC {
                return Ok(UserStop::Exit);
            }
            if self.t >= self.config.limits.max_steps {
                return Ok(UserStop::Limit);
            }
            let word = self.text_word(pc);
            let advance = self
                .user
                .advance()
                .map_err(SessionError::Interpreter)?
                .ok_or_else(|| {
                    SessionError::Interpreter("the user stepper stopped without a halt".into())
                })?;
            let resume = match advance.halt_reason {
                Some(HaltReason::RuntimeExit {
                    reason: RuntimeExitReason::Svc { resume_pc, .. },
                }) => Some(resume_pc),
                _ => None,
            };
            if advance.executed {
                let word = word.expect("an executed instruction was read from the text");
                let next = advance.next_pc.or(resume).expect("an executed step has a successor");
                self.user_tick(pc, word, next);
            }
            match advance.halt_reason {
                None => {}
                Some(HaltReason::RuntimeExit {
                    reason: RuntimeExitReason::Svc { resume_pc, .. },
                }) => {
                    return Ok(UserStop::Svc {
                        pc: advance.pc,
                        resume: resume_pc,
                    })
                }
                Some(halt) => return Ok(UserStop::Halt(halt)),
            }
        }
    }

    /// Records an instruction of original code that executed; the user stepper's state
    /// is already after it.
    fn user_tick(&mut self, pc: u64, word: u32, next_pc: u64) {
        self.t += 1;
        match self.span {
            Some(index) => {
                let EventKind::UserSpan { to_pc, steps, .. } = &mut self.events[index].kind else {
                    unreachable!("span indexes a UserSpan");
                };
                *to_pc = next_pc;
                *steps += 1;
            }
            None => {
                self.span = Some(self.events.len());
                self.events.push(Event {
                    t: self.t - 1,
                    kind: EventKind::UserSpan {
                        from_pc: pc,
                        to_pc: next_pc,
                        steps: 1,
                    },
                });
            }
        }
        let after = RegFile::of(self.user.state());
        let writes = self
            .user
            .state_mut()
            .take_write_journal()
            .into_iter()
            .map(|write| StepMemWrite {
                addr: write.addr,
                size: write.size,
                old: write.old,
                new: write.new,
                runtime_owned: false,
            })
            .collect::<Vec<_>>();
        self.push_step(StepAt::User { pc }, word, after, writes);
        if self.t % self.config.limits.checkpoint_every == 0 {
            let mut state = self.user.state().clone();
            state.stop_write_journal();
            self.checkpoints.push(state);
        }
    }

    fn push_step(&mut self, at: StepAt, word: u32, after: RegFile, mems: Vec<StepMemWrite>) {
        let writes = self.shadow.diff(&after);
        self.steps
            .push(at, word, self.shadow.flags, after.flags, writes, mems);
        self.shadow = after;
        debug_assert_eq!(self.steps.len(), self.t);
    }

    // ---- chains ----------------------------------------------------------------------

    /// One hook call that found `fragment`: runs the chain until it returns to userspace.
    fn run_chain(&mut self, fragment: usize) -> Result<ChainStop, SessionError> {
        self.close_span();
        let cache = self.cache.take().expect("no chain is running");
        let entry_pc = cache.fragments[fragment].entry_pc;
        let state = std::mem::take(self.user.state_mut());
        let mut runtime =
            URuntime::with_cache(cache, fragment, state, URuntimeConfig::default());
        runtime.state.start_write_journal();
        let ranges = runtime.runtime_owned_ranges();
        self.push(EventKind::RunBegin { fragment, entry_pc });

        let mut entries = 1u32;
        // Whether the last tick ended in the runtime, where the observable registers
        // are the user's (`Advanced::is_runtime_return`).
        let mut at_boundary = true;
        let mut last_exit = None;
        // The last exit group branch executed: where the fragment left for the runtime.
        let mut exit_site = None;
        let end: ChainEnd;
        let report_state;
        {
            let mut stepper = match URuntimeStepper::new(&mut runtime) {
                Ok(stepper) => stepper,
                Err(message) => {
                    self.cache = Some(runtime.into_cache());
                    return Err(SessionError::Runtime(message));
                }
            };
            // Setting up the run (pt_regs, the extra params, the entry) is not a tick.
            stepper.runtime_mut().state.take_write_journal();
            end = loop {
                if self.t >= self.config.limits.max_steps {
                    break ChainEnd::Limit;
                }
                let here = stepper.location();
                let before = here.map(|(f, o)| {
                    let frag = &stepper.runtime().cache().fragments[f];
                    let word = u32::from_le_bytes(
                        frag.encoded[o..o + 4].try_into().expect("4 bytes"),
                    );
                    (word, frag.fragment.insns[o / 4])
                });
                let advance = match stepper.advance() {
                    Ok(Some(advance)) => advance,
                    Ok(None) => {
                        break ChainEnd::Halt(URuntimeHalt::ExecutionError {
                            pc: stepper.pc(),
                            message: "runtime stepper stopped without a halt reason".into(),
                        })
                    }
                    Err(message) => {
                        break ChainEnd::Halt(URuntimeHalt::ExecutionError {
                            pc: stepper.pc(),
                            message,
                        })
                    }
                };
                let boundary = advance.is_runtime_return();
                if advance.executed {
                    let (fragment, offset) = here.expect("an executed step was in a fragment");
                    let (word, _) = before.expect("an executed step was in a fragment");
                    self.t += 1;
                    let after = if boundary {
                        RegFile::of(&advance.state_after(stepper.runtime()))
                    } else {
                        RegFile::of(&stepper.runtime().state)
                    };
                    let writes = stepper
                        .runtime_mut()
                        .state
                        .take_write_journal()
                        .into_iter()
                        .map(|write| StepMemWrite {
                            addr: write.addr,
                            size: write.size,
                            old: write.old,
                            new: write.new,
                            runtime_owned: ranges
                                .iter()
                                .any(|&(start, end)| start <= write.addr && write.addr < end),
                        })
                        .collect::<Vec<_>>();
                    self.push_step(StepAt::Fragment { fragment, offset }, word, after, writes);
                    if self.t % self.config.limits.checkpoint_every == 0 {
                        let mut state = advance.state_after(stepper.runtime());
                        state.stop_write_journal();
                        self.checkpoints.push(state);
                    }
                    at_boundary = boundary;
                    if self.word_kind(fragment, offset) == Some(RephrasedInsnKind::RuntimeExitBranch)
                    {
                        exit_site = Some((fragment, offset));
                    }
                }
                match advance.runtime_transition {
                    Some(URuntimeTransition::FaultRedirect {
                        access_offset,
                        stub_offset,
                    }) => self.push(EventKind::FaultRedirect {
                        fragment: advance.fragment,
                        access_offset,
                        stub_offset,
                    }),
                    _ => {}
                }
                // A transfer inside the run: a dispatch hit or a patched link slot.
                if !boundary && advance.runtime_transition.is_none() && advance.halt.is_none() {
                    if let (Some((fragment, offset)), Some((_, insn)), Some((to_fragment, to_offset))) =
                        (here, before, stepper.location())
                    {
                        if let Some(via) = self.transfer_via(fragment, offset, insn) {
                            self.push(EventKind::Transfer {
                                from: Loc { fragment, offset },
                                to: Loc {
                                    fragment: to_fragment,
                                    offset: to_offset,
                                },
                                via,
                            });
                        }
                    }
                }
                if let Some(exit) = advance.exit {
                    last_exit = Some(exit);
                    // Every return to the runtime leaves through the branch that ends an
                    // exit group (layout, `RuntimeExitBranch`).
                    let Some((fragment, offset)) = exit_site.take() else {
                        break ChainEnd::Halt(URuntimeHalt::ExecutionError {
                            pc: stepper.pc(),
                            message: "a fragment returned without an exit group branch".into(),
                        });
                    };
                    self.push(EventKind::Exit {
                        fragment,
                        offset,
                        status: exit.status,
                        param0: exit.param0,
                        param1: exit.param1,
                    });
                    let events = stepper.runtime_mut().cache_mut().drain_events();
                    self.cache_events(events);
                    if let Some(URuntimeTransition::Continued {
                        fragment: to_fragment,
                        offset: to_offset,
                    }) = advance.runtime_transition
                    {
                        entries += 1;
                        self.push(EventKind::Transfer {
                            from: Loc { fragment, offset },
                            to: Loc {
                                fragment: to_fragment,
                                offset: to_offset,
                            },
                            via: TransferVia::Runtime,
                        });
                    }
                }
                if let Some(halt) = advance.halt {
                    break ChainEnd::Halt(halt);
                }
            };
            report_state = match &end {
                // Its journal is empty: every tick took what it wrote.
                ChainEnd::Halt(halt) => stepper.report_for_halt(halt.clone()).state,
                // Out of ticks mid-run: the state the last tick left.
                ChainEnd::Limit => {
                    if at_boundary {
                        stepper.runtime().user_state_from_pt_regs()
                    } else {
                        stepper.runtime().physical_user_state()
                    }
                }
            };
        }
        let chain_capped = runtime.cache().chain_capped();
        self.cache = Some(runtime.into_cache());

        let halt = match end {
            ChainEnd::Halt(halt) => halt,
            ChainEnd::Limit => {
                self.final_state = Some(report_state);
                return Ok(ChainStop::Outcome(Outcome::StepLimit));
            }
        };
        *self.user.state_mut() = report_state;
        let URuntimeHalt::ReturnedToUserspace { status, target_pc } = halt else {
            let kjit = self.user.state().clone();
            let reference = self.reference.state().clone();
            let outcome = self.diverge(
                DivergenceKind::RuntimeHalt(halt),
                self.syscalls.last().map(|syscall| syscall.k),
                reference,
                kjit,
            );
            return Ok(ChainStop::Outcome(outcome));
        };
        self.push(EventKind::RunEnd {
            user_pc: target_pc,
            entries,
            chain_capped,
        });
        match status {
            RetStatus::Svc => Ok(ChainStop::Svc {
                pc: target_pc.wrapping_sub(4),
                resume: target_pc,
            }),
            RetStatus::Bl | RetStatus::Blr | RetStatus::Br | RetStatus::Ret => {
                // An exit-target miss: the target is profiled, unless the chain budget
                // (not a miss) stopped it. The branch is the word before the resume pc
                // (x11) the fragment returned.
                if !chain_capped {
                    let exit = last_exit.expect("a branch stop follows a runtime return");
                    self.profile(target_pc, Trigger::ExitTarget, exit.param1.wrapping_sub(4))?;
                }
                Ok(ChainStop::ToUser { pc: target_pc })
            }
            // Userspace executes the instruction itself.
            RetStatus::Unsupported | RetStatus::Mem | RetStatus::Budget => {
                Ok(ChainStop::ToUser { pc: target_pc })
            }
            RetStatus::Invalid(_) | RetStatus::Debug => {
                unreachable!("the cache turns these into other halts")
            }
        }
    }

    /// The kind of the fragment word at `offset`; `None` for the prologue and epilogue.
    fn word_kind(&self, fragment: usize, offset: usize) -> Option<RephrasedInsnKind> {
        let translation = self.fragment_translation.get(&fragment)?;
        self.translations[*translation].word_at(offset)?.kind
    }

    /// How control passed from the executed fragment word `insn` at `offset`, if it
    /// is a transfer between fragment locations without the runtime.
    fn transfer_via(&self, fragment: usize, offset: usize, insn: A64Insn) -> Option<TransferVia> {
        match (self.word_kind(fragment, offset)?, insn) {
            (RephrasedInsnKind::DispatchLookup, A64Insn::BrBr64BranchReg { .. }) => {
                Some(TransferVia::Dispatch)
            }
            // A link slot is a `nop` until it is patched to a `b`.
            (RephrasedInsnKind::LinkSlot { .. }, A64Insn::BUncondBOnlyBranchImm { .. }) => {
                Some(TransferVia::Link)
            }
            _ => None,
        }
    }

    fn cache_events(&mut self, events: Vec<CacheEvent>) {
        for event in events {
            let kind = match event {
                CacheEvent::Installed { fragment, .. } => EventKind::Installed {
                    fragment,
                    translation: self.fragment_translation[&fragment],
                },
                CacheEvent::Published {
                    table,
                    slot,
                    pc,
                    fragment,
                    replaced,
                } => EventKind::Published {
                    table,
                    slot,
                    pc,
                    fragment,
                    replaced,
                },
                CacheEvent::Linked {
                    fragment,
                    slot_offset,
                    target_fragment,
                    target_pc,
                } => EventKind::Linked {
                    fragment,
                    slot_offset,
                    target: LinkTarget {
                        fragment: target_fragment,
                        pc: target_pc,
                    },
                },
                CacheEvent::Restored {
                    fragment,
                    slot_offset,
                    target_fragment,
                    target_pc,
                } => EventKind::Restored {
                    fragment,
                    slot_offset,
                    target: LinkTarget {
                        fragment: target_fragment,
                        pc: target_pc,
                    },
                },
                CacheEvent::Retired { fragment } => EventKind::Retired { fragment },
            };
            self.push(kind);
        }
    }

    // ---- profiler and translation requests ---------------------------------------------

    /// One more hit of `pc`, where userspace resumes and no fragment is translated for
    /// it (`kjit_profile`). At `hot_threshold` hits the request runs at once: the
    /// kernel runs it in task_work before the task returns to user mode.
    fn profile(&mut self, pc: u64, kind: Trigger, source_pc: u64) -> Result<(), SessionError> {
        if self.negative.contains(&pc) {
            return Ok(());
        }
        let count = {
            let hits = self.hits.entry(pc).or_insert(0);
            *hits += 1;
            *hits
        };
        self.push(EventKind::ProfileHit { pc, kind, count });
        if count < self.config.policy.hot_threshold {
            return Ok(());
        }
        self.hits.remove(&pc);
        self.push(EventKind::Hot { pc });
        self.request(pc, kind, source_pc)
    }

    fn request(&mut self, pc: u64, trigger: Trigger, source_pc: u64) -> Result<(), SessionError> {
        let index = self.translations.len();
        let mut record = translation::translate(index, self.t, pc, trigger, source_pc, &self.code);
        let drift = |message: String| SessionError::TranslationDrift {
            translation: index,
            message,
        };
        self.push(EventKind::Translated { translation: index });
        let installed = match &record.rejection {
            // Refused before translating, as the kernel does.
            Some(Rejection::EntryUnsupported(_)) => None,
            rejection => {
                let result = self.cache().translate(pc, source_pc);
                match (rejection, result) {
                    (None, Ok(Some(fragment))) => {
                        translation::check_installed(
                            &record,
                            &self.cache().fragments[fragment],
                        )
                        .map_err(drift)?;
                        Some(fragment)
                    }
                    (None, Ok(None)) => {
                        return Err(drift("the cache found no text the record translated".into()))
                    }
                    (None, Err(message)) => {
                        return Err(drift(format!("the cache failed, the record did not: {message}")))
                    }
                    (Some(rejection), Ok(Some(_))) => {
                        return Err(drift(format!(
                            "the cache installed a fragment the record rejected: {rejection:?}"
                        )))
                    }
                    (Some(_), Ok(None) | Err(_)) => None,
                }
            }
        };
        record.installed = installed;
        if let Some(fragment) = installed {
            self.fragment_translation.insert(fragment, index);
        } else {
            self.negative.insert(pc);
        }
        self.translations.push(record);
        let events = self.cache().drain_events();
        self.cache_events(events);
        Ok(())
    }

    // ---- the comparison -------------------------------------------------------------------

    /// The `SVC` at `pc` executed in the KJIT world (user code or fragment); the user
    /// stepper holds its state. Compares the worlds.
    fn syscall(&mut self, pc: u64) -> Result<Option<Outcome>, SessionError> {
        self.close_span();
        self.k += 1;
        let k = self.k;
        self.push(EventKind::Syscall { k, pc });
        self.syscalls.push(SyscallRecord { k, pc, t: self.t });
        #[cfg(test)]
        if let Some(tamper) = self.tamper.as_mut() {
            tamper(k, self.user.state_mut());
        }
        let reference = self.advance_reference()?;
        self.compare(reference, SyncPoint::Svc { pc }, Some(k))
    }

    /// The end of the KJIT world's run: userspace at `SESSION_EXIT_PC` or halted.
    fn end(&mut self, kjit: SyncPoint) -> Result<Outcome, SessionError> {
        self.close_span();
        let reference = self.advance_reference()?;
        Ok(match self.compare(reference, kjit, None)? {
            Some(outcome) => outcome,
            None => match kjit {
                SyncPoint::Exit => Outcome::Exited,
                SyncPoint::Halt(halt) => Outcome::Halted(halt),
                SyncPoint::Svc { .. } => unreachable!("the end is not a syscall"),
            },
        })
    }

    /// Runs the reference to its next sync point: an `SVC`, `SESSION_EXIT_PC` or a halt.
    fn advance_reference(&mut self) -> Result<Reached, SessionError> {
        let mut steps = 0u64;
        loop {
            if self.reference.pc() == SESSION_EXIT_PC {
                return Ok(Reached::Point(SyncPoint::Exit));
            }
            if steps >= self.config.limits.max_steps {
                return Ok(Reached::Runaway { steps });
            }
            let advance = self
                .reference
                .advance()
                .map_err(SessionError::Interpreter)?
                .ok_or_else(|| {
                    SessionError::Interpreter("the reference stepper stopped without a halt".into())
                })?;
            steps += u64::from(advance.executed);
            match advance.halt_reason {
                None => {}
                Some(HaltReason::RuntimeExit {
                    reason: RuntimeExitReason::Svc { resume_pc, .. },
                }) => {
                    self.reference_resume = resume_pc;
                    return Ok(Reached::Point(SyncPoint::Svc { pc: advance.pc }));
                }
                Some(halt) => return Ok(Reached::Point(SyncPoint::Halt(halt))),
            }
        }
    }

    /// `None`: the worlds agree (the reference is resumed after its `SVC`).
    fn compare(
        &mut self,
        reference: Reached,
        kjit: SyncPoint,
        syscall: Option<u64>,
    ) -> Result<Option<Outcome>, SessionError> {
        let kind = match reference {
            Reached::Runaway { steps } => Some(DivergenceKind::ReferenceRunaway { steps }),
            Reached::Point(point) if point != kjit => Some(DivergenceKind::SyncPoint {
                reference: point,
                kjit,
            }),
            Reached::Point(point) if !self.states_agree(point)? => Some(DivergenceKind::State),
            Reached::Point(_) => None,
        };
        if let Some(kind) = kind {
            let (reference, kjit) = (self.reference.state().clone(), self.user.state().clone());
            return Ok(Some(self.diverge(kind, syscall, reference, kjit)));
        }
        if let SyncPoint::Svc { .. } = kjit {
            self.reference.resume_at(self.reference_resume);
        }
        Ok(None)
    }

    /// Equal states; at a fault, up to the footprint of the faulting store, which the
    /// fragment may have written before userspace re-executed the instruction (the
    /// differential oracle's rule, docs/pipeline.md "Fault sites (A5)").
    fn states_agree(&self, point: SyncPoint) -> Result<bool, SessionError> {
        let (reference, kjit) = (self.reference.state(), self.user.state());
        let SyncPoint::Halt(halt @ HaltReason::Fault(_)) = point else {
            return Ok(reference == kjit);
        };
        let result = ExecutionResult {
            state: reference.clone(),
            halt_reason: halt,
            steps: 0,
        };
        let footprint = faulting_footprint(&self.config.text, self.config.text_base, &result)
            .map_err(SessionError::Interpreter)?;
        Ok(undo_footprint(reference, &footprint, kjit) == *reference)
    }

    fn diverge(
        &mut self,
        kind: DivergenceKind,
        syscall: Option<u64>,
        mut reference: MachineState,
        mut kjit: MachineState,
    ) -> Outcome {
        reference.stop_write_journal();
        kjit.stop_write_journal();
        self.push(EventKind::Divergence);
        Outcome::Divergence(Box::new(Divergence {
            t: self.t,
            syscall,
            kind,
            diff: state_diff(&reference, &kjit),
            reference,
            kjit,
        }))
    }
}

fn state_diff(reference: &MachineState, kjit: &MachineState) -> StateDiff {
    let mut diff = StateDiff::default();
    for (reg, reference, kjit) in reg_diff(reference, kjit) {
        diff.regs.push(RegDiff {
            reg,
            reference,
            kjit,
        });
    }
    if reference.flags != kjit.flags {
        diff.flags = Some((reference.flags, kjit.flags));
    }
    let addrs = reference
        .memory()
        .keys()
        .chain(kjit.memory().keys())
        .copied()
        .collect::<BTreeSet<_>>();
    for addr in addrs {
        // The model elides stored zero bytes (`MachineState::read_le`): absent is 0.
        let (r, k) = (
            reference.memory().get(&addr).copied().unwrap_or(0),
            kjit.memory().get(&addr).copied().unwrap_or(0),
        );
        if r != k {
            diff.mem.push(MemDiff {
                addr,
                reference: r,
                kjit: k,
            });
        }
    }
    if reference.tpidr_el0 != kjit.tpidr_el0 {
        diff.other.push(format!(
            "tpidr_el0: reference {:#x}, kjit {:#x}",
            reference.tpidr_el0, kjit.tpidr_el0
        ));
    }
    if (reference.cntvct_el0, reference.cntfrq_el0) != (kjit.cntvct_el0, kjit.cntfrq_el0) {
        diff.other.push("the counter registers differ".to_string());
    }
    if reference.user_pages().ne(kjit.user_pages()) {
        diff.other.push("the user page maps differ".to_string());
    }
    diff
}
