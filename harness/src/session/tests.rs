//! Tests of the session recorder, over the three session programs of
//! `tests/arm64/session_*.s`. They check the recorder's claims: the worlds agree, the
//! profiler translates exactly at the threshold, a warm chain makes no runtime round
//! trip, `state_at` and `cache_at` are what a fresh run and the real cache have, and a
//! broken model is caught.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::arm64::OriginalStepper;
use crate::asm_fixture::compile_case;
use crate::model::{HaltReason, MachineState};
use crate::shared::abi::{RetStatus, IBTC_TABLE_WORDS, LINK_NOP_WORD};
use crate::shared::trans::cfg::RuntimeExitReason;
use crate::shared::trans::rephrase::RephrasedInsnKind;

use super::record::record_tampered;
use super::{
    DivergenceKind, EventKind, Outcome, RegId, Rejection, Session, SessionConfig, SessionError,
    StepAt, TransferVia, Trigger, SESSION_EXIT_PC,
};

const PROGRAMS: [&str; 3] = [
    "session_svc_loop",
    "session_call_loop",
    "session_indirect_loop",
];
/// Every program makes one `SVC` before its loop and 300 inside it.
const SYSCALLS: u64 = 301;

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("harness manifest dir has a parent")
}

/// Assembles `fixture`; the session starts at its `symbol`, the instruction before
/// the `_mark` SVC (`symbol` and `symbol_mark` are 4 bytes apart in the programs).
fn config_for(fixture: &Path, symbol: &str) -> SessionConfig {
    // One directory per call: tests run in parallel threads.
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let out = root().join("tmp").join(format!(
        "session-tests.{}.{symbol}.{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let case = compile_case(root(), fixture, symbol, &out)
        .unwrap_or_else(|err| panic!("assembling {}: {err}", fixture.display()));
    std::fs::remove_dir_all(&out).expect("remove the assembly output");
    // `compile_case` resolves `symbol + 4`, the first instruction after an SVC mark.
    SessionConfig::fixture(case.text_base, case.text_bytes, case.entry_pc - 4)
        .expect("fixture state")
}

/// `tests/arm64/<name>.s`, started at its `<name>` symbol.
fn config(name: &str) -> SessionConfig {
    config_for(&root().join(format!("tests/arm64/{name}.s")), name)
}

pub(crate) fn session(name: &str) -> Session {
    Session::record(config(name)).unwrap_or_else(|err| panic!("recording {name}: {err}"))
}

/// The fragment runs of a session: the events from each `RunBegin` to its `RunEnd`.
fn chains(session: &Session) -> Vec<&[super::Event]> {
    let events = session.events();
    let mut chains = Vec::new();
    let mut begin = None;
    for (index, event) in events.iter().enumerate() {
        match event.kind {
            EventKind::RunBegin { .. } => begin = Some(index),
            EventKind::RunEnd { .. } => {
                let begin = begin.take().expect("a RunEnd follows a RunBegin");
                chains.push(&events[begin..=index]);
            }
            _ => {}
        }
    }
    assert!(begin.is_none(), "every run ended");
    chains
}

#[test]
fn every_program_exits_with_the_worlds_in_agreement() {
    for name in PROGRAMS {
        let session = session(name);
        assert_eq!(session.outcome(), &Outcome::Exited, "{name}");
        assert_eq!(session.syscalls().len() as u64, SYSCALLS, "{name}");
        assert!(
            !session
                .events()
                .iter()
                .any(|event| event.kind == EventKind::Divergence),
            "{name}"
        );
        // The program stores its checksum to the data window and returns to the exit pc.
        let end = session.final_state();
        assert_ne!(end.read_u64(crate::FIXTURE_DATA_BASE + 0x10), 0, "{name}");
        assert_eq!(end.read_x(30), SESSION_EXIT_PC, "{name}");
        // The final state is also what replaying the steps gives.
        assert_eq!(&session.state_at(session.ticks()).unwrap(), end, "{name}");
    }
}

#[test]
fn a_pc_is_translated_exactly_when_its_hits_reach_the_threshold() {
    for name in PROGRAMS {
        for threshold in [1, 7, 64] {
            let mut config = config(name);
            config.policy.hot_threshold = threshold;
            let session = Session::record(config).unwrap();
            assert_eq!(session.outcome(), &Outcome::Exited, "{name}/{threshold}");

            let mut hits: BTreeMap<u64, u32> = BTreeMap::new();
            let mut hot = None;
            let mut translated = 0;
            for event in session.events() {
                match event.kind {
                    EventKind::ProfileHit { pc, count, .. } => {
                        assert!(hot.is_none(), "a hit between Hot and Translated");
                        let seen = hits.entry(pc).or_insert(0);
                        *seen += 1;
                        assert_eq!(count, *seen, "{name}: hit counts go up one by one");
                        assert!(count <= threshold, "{name}: past the threshold untranslated");
                    }
                    EventKind::Hot { pc } => {
                        assert_eq!(
                            hits.remove(&pc),
                            Some(threshold),
                            "{name}: {pc:#x} turned hot below the threshold"
                        );
                        hot = Some(pc);
                    }
                    EventKind::Translated { translation } => {
                        let pc = hot.take().expect("Translated follows Hot");
                        assert_eq!(session.translations()[translation].entry_pc, pc);
                        assert_eq!(session.translations()[translation].t, event.t);
                        translated += 1;
                    }
                    _ => {}
                }
            }
            assert_eq!(translated, session.translations().len());
            // Whatever has not reached the threshold is still counting.
            assert!(hits.values().all(|&count| count < threshold));
            assert!(translated > 0, "{name}/{threshold}: nothing turned hot");
        }
    }
}

#[test]
fn the_warm_path_of_a_chain_makes_no_runtime_round_trip() {
    for (name, expect_link) in [
        ("session_svc_loop", false),
        ("session_call_loop", true),
        ("session_indirect_loop", false),
    ] {
        let session = session(name);
        let chains = chains(&session);
        // The last chain ends the program through `ret`; the 20 before it are warm.
        let warm = &chains[chains.len() - 21..chains.len() - 1];
        let transfers = |via: TransferVia| {
            warm.iter()
                .flat_map(|chain| chain.iter())
                .filter(|event| matches!(event.kind, EventKind::Transfer { via: v, .. } if v == via))
                .count()
        };
        assert_eq!(transfers(TransferVia::Runtime), 0, "{name}");
        assert_eq!(
            transfers(TransferVia::Link) > 0,
            expect_link,
            "{name}: direct BL link"
        );
        if name != "session_svc_loop" {
            assert!(transfers(TransferVia::Dispatch) > 0, "{name}: dispatch hits");
        }
        for chain in warm {
            // One fragment entry per hook call, ended by the SVC of the iteration.
            assert!(matches!(
                chain.last().unwrap().kind,
                EventKind::RunEnd {
                    entries: 1,
                    chain_capped: false,
                    ..
                }
            ));
            assert!(chain.iter().any(|event| matches!(
                event.kind,
                EventKind::Exit {
                    status: RetStatus::Svc,
                    ..
                }
            )));
        }
    }
}

#[test]
fn cold_chains_continue_through_the_runtime_and_learn_the_callee() {
    let session = session("session_call_loop");
    // The callee and the return point are learned by exit-target misses.
    let learned = session
        .translations()
        .iter()
        .filter(|record| record.trigger == Trigger::ExitTarget)
        .count();
    assert_eq!(learned, 2);
    assert_eq!(session.translations()[0].trigger, Trigger::SvcResume);
    assert!(session.events().iter().any(|event| matches!(
        event.kind,
        EventKind::Transfer {
            via: TransferVia::Runtime,
            ..
        }
    )));
}

#[test]
fn without_links_nothing_is_linked() {
    let linked = |session: &Session| {
        session
            .events()
            .iter()
            .filter(|event| matches!(event.kind, EventKind::Linked { .. }))
            .count()
    };
    let with = session("session_call_loop");
    assert!(linked(&with) > 0);

    let mut config = config("session_call_loop");
    config.policy.links = false;
    let without = Session::record(config).unwrap();
    assert_eq!(without.outcome(), &Outcome::Exited);
    assert_eq!(linked(&without), 0);
    assert!(without
        .events()
        .iter()
        .all(|event| !matches!(event.kind, EventKind::Linked { .. } | EventKind::Restored { .. })));
    assert!(!without.events().iter().any(|event| matches!(
        event.kind,
        EventKind::Transfer {
            via: TransferVia::Link,
            ..
        }
    )));
}

#[test]
fn cache_at_the_last_tick_is_the_final_cache() {
    for name in PROGRAMS {
        let session = session(name);
        let view = session.cache_at(session.ticks()).unwrap();
        let cache = session.final_cache();
        assert_eq!(view.fragments.len(), cache.fragments.len(), "{name}");
        for (fragment, shown) in cache.fragments.iter().zip(&view.fragments) {
            assert_eq!(shown.entry_pc, fragment.entry_pc);
            assert_eq!(shown.retired, fragment.retired);
            assert_eq!(Some(shown.translation), session.translation_of(shown.fragment));
        }
        for (all, table) in [(true, &view.table_all), (false, &view.table_nofp)] {
            for slot in 0..IBTC_TABLE_WORDS {
                let occupant = table.get(&slot);
                assert_eq!(
                    cache.resident_pc(all, slot),
                    occupant.map(|occupant| occupant.pc),
                    "{name}: table slot {slot}"
                );
                if let Some(occupant) = occupant {
                    assert_eq!(cache.lookup(all, occupant.pc), Some(occupant.fragment));
                }
            }
        }
        let mut sites = 0;
        for (index, fragment) in cache.fragments.iter().enumerate() {
            for site in &fragment.links {
                sites += 1;
                let shown = view
                    .links
                    .iter()
                    .find(|link| link.fragment == index && link.slot_offset == site.slot)
                    .expect("every link site is listed");
                assert_eq!(shown.target_pc, site.target_pc);
                assert_eq!(
                    shown.linked_to.map(|target| (target.fragment, target.pc)),
                    site.linked_to.map(|(target, label)| (target, fragment_label_pc(cache, target, label)))
                );
                // The word in the slot is what the cache's own code holds there.
                let held = &fragment.encoded[site.slot..site.slot + 4];
                assert_eq!(held, shown.word.to_le_bytes(), "{name}");
                assert_eq!(shown.linked_to.is_none(), shown.word == LINK_NOP_WORD);
            }
        }
        assert_eq!(view.links.len(), sites);
    }
}

fn fragment_label_pc(cache: &crate::code_cache::CodeCache, fragment: usize, label: usize) -> u64 {
    cache.fragments[fragment].labels[label].pc
}

#[test]
fn the_cache_grows_as_the_events_say() {
    let session = session("session_call_loop");
    let installs = session
        .events()
        .iter()
        .filter(|event| matches!(event.kind, EventKind::Installed { .. }))
        .collect::<Vec<_>>();
    assert_eq!(installs.len(), 3);
    assert_eq!(session.cache_at(0).unwrap().fragments.len(), 0);
    for (count, install) in installs.iter().enumerate() {
        // At the tick of the install the fragment is there, one tick earlier it is not
        // (unless an earlier install shares the tick: they are in separate requests).
        let after = session.cache_at(install.t).unwrap();
        assert!(after.fragments.len() > count);
        if install.t > 0 {
            let before = session.cache_at(install.t - 1).unwrap();
            assert!(before.fragments.len() <= count);
        }
    }
    // The first link appears with the callee's install.
    let first_link = session
        .events()
        .iter()
        .find(|event| matches!(event.kind, EventKind::Linked { .. }))
        .unwrap();
    let linked = |t: u64| {
        session
            .cache_at(t)
            .unwrap()
            .links
            .iter()
            .filter(|link| link.linked_to.is_some())
            .count()
    };
    assert_eq!(linked(first_link.t), 1);
    assert_eq!(linked(first_link.t - 1), 0);
}

fn initial_state(config: &SessionConfig) -> MachineState {
    let mut state = config.initial_state.clone();
    state.write_x(30, SESSION_EXIT_PC);
    state
}

#[test]
fn state_at_is_the_state_of_a_fresh_run_stopped_there() {
    for (name, every) in [
        ("session_call_loop", 4096),
        ("session_call_loop", 100),
        ("session_indirect_loop", 997),
    ] {
        let mut full = config(name);
        full.limits.checkpoint_every = every;
        let session = Session::record(full.clone()).unwrap();
        assert_eq!(session.state_at(0).unwrap(), initial_state(&full));
        let ticks = session.ticks();
        // Around checkpoint boundaries, run-internal points and the ends.
        let mut sampled = vec![1, 2, 57, 98, 99, 100, 101, every - 1, every, every + 1];
        sampled.extend([2 * every - 1, 2 * every, 2 * every + 1, 8000, 16137, 16138, 20001]);
        sampled.extend([ticks - 2, ticks - 1]);
        sampled.retain(|&t| 0 < t && t < ticks);
        for t in sampled {
            let mut limited = full.clone();
            limited.limits.max_steps = t;
            let fresh = Session::record(limited).unwrap();
            assert_eq!(fresh.outcome(), &Outcome::StepLimit, "{name} t={t}");
            assert_eq!(fresh.ticks(), t);
            assert_eq!(
                &session.state_at(t).unwrap(),
                fresh.final_state(),
                "{name} every={every} t={t}"
            );
        }
        assert_eq!(&session.state_at(ticks).unwrap(), session.final_state());
        assert!(session.state_at(ticks + 1).is_err());
    }
}

/// With a checkpoint at every tick, each is the machine as captured directly; every
/// step must take the checkpoint before it to the one after it. The exhaustive check
/// of what a step records (registers, flags, stores), across user ticks, fragment
/// ticks, runtime boundaries and link patches.
#[test]
fn every_step_takes_the_previous_state_to_the_next() {
    for name in PROGRAMS {
        let mut config = config(name);
        config.limits.checkpoint_every = 1;
        let session = Session::record(config).unwrap();
        assert_eq!(session.checkpoints.len() as u64, session.ticks() + 1);
        for step in session.steps() {
            let mut state = session.checkpoints[step.tick as usize - 1].clone();
            super::steps::apply_step(&mut state, &step);
            assert_eq!(state, session.checkpoints[step.tick as usize], "{name} tick {}", step.tick);
        }
    }
}

#[test]
fn steps_are_the_instructions_that_executed() {
    let session = session("session_call_loop");
    let cache = session.final_cache();
    let config = session.config();
    let (mut user, mut fragment_ticks, mut link_slots) = (0u64, 0u64, 0u64);
    for step in session.steps() {
        match step.at {
            StepAt::User { pc } => {
                user += 1;
                let offset = (pc - config.text_base) as usize;
                let word = u32::from_le_bytes(config.text[offset..offset + 4].try_into().unwrap());
                assert_eq!(step.word, word, "tick {}", step.tick);
            }
            StepAt::Fragment { fragment, offset } => {
                fragment_ticks += 1;
                let code = &cache.fragments[fragment];
                let held = u32::from_le_bytes(code.encoded[offset..offset + 4].try_into().unwrap());
                let origin = session.origin(fragment, offset).unwrap();
                let translated =
                    session.translations()[origin.translation].layout[origin.layout_index].word;
                if let Some(RephrasedInsnKind::LinkSlot { .. }) = origin.kind {
                    // The slot is `nop` until the cache patches it: the word executed
                    // is the one the cache held at that tick.
                    let link = session
                        .cache_at(step.tick - 1)
                        .unwrap()
                        .links
                        .into_iter()
                        .find(|link| link.fragment == fragment && link.slot_offset == offset)
                        .unwrap();
                    assert_eq!(step.word, link.word, "tick {}", step.tick);
                    link_slots += 1;
                } else {
                    assert_eq!(step.word, translated, "tick {}", step.tick);
                    assert_eq!(step.word, held, "tick {}", step.tick);
                }
            }
        }
    }
    assert!(link_slots > 0);
    assert_eq!(user + fragment_ticks, session.ticks());
    let span_steps: u64 = session
        .events()
        .iter()
        .map(|event| match event.kind {
            EventKind::UserSpan { steps, .. } => steps,
            _ => 0,
        })
        .sum();
    assert_eq!(span_steps, user);
}

#[test]
fn reference_at_syscall_is_what_an_independent_reference_run_has() {
    let session = session("session_indirect_loop");
    let config = session.config();
    let mut initial = config.initial_state.clone();
    initial.write_x(30, SESSION_EXIT_PC);
    let mut reference =
        OriginalStepper::new(&config.text, config.text_base, config.entry_pc, &initial)
            .unwrap()
            .follow_branches();
    let mut k = 0;
    while k < SYSCALLS {
        let advance = reference.advance().unwrap().unwrap();
        if let Some(HaltReason::RuntimeExit {
            reason: RuntimeExitReason::Svc { resume_pc, .. },
        }) = advance.halt_reason
        {
            k += 1;
            if [1, 2, 66, 67, 129, 130, 200, 301].contains(&k) {
                assert_eq!(
                    session.reference_at_syscall(k).unwrap(),
                    *reference.state(),
                    "syscall {k}"
                );
                assert_eq!(session.syscalls()[k as usize - 1].pc, advance.pc);
            }
            reference.resume_at(resume_pc);
        }
    }
    assert!(session.reference_at_syscall(0).is_err());
    assert!(session.reference_at_syscall(SYSCALLS + 1).is_err());
}

#[test]
fn a_translation_record_is_the_fragment_the_cache_installed() {
    for name in PROGRAMS {
        let session = session(name);
        let cache = session.final_cache();
        assert_eq!(cache.fragments.len(), session.translations().len());
        for record in session.translations() {
            let fragment = record.installed.expect("every request of the programs installs");
            let installed = &cache.fragments[fragment];
            assert_eq!(session.translation_of(fragment), Some(record.index));
            assert_eq!(record.layout.len(), installed.fragment.insns.len());
            for word in &record.layout {
                let code = installed.encoded[word.offset..word.offset + 4].to_vec();
                let is_slot = record.link_sites.iter().any(|&(slot, _)| slot == word.offset);
                if is_slot {
                    assert_eq!(word.word, LINK_NOP_WORD);
                } else {
                    assert_eq!(code, word.word.to_le_bytes(), "{name} {:#x}", word.offset);
                }
                // origin() and words_for() are inverse and agree with the passes.
                let origin = session.origin(fragment, word.offset).unwrap();
                assert_eq!(origin.ori_pc, word.ori_pc);
                assert_eq!(origin.kind, word.kind);
                if let Some(pc) = word.ori_pc {
                    assert!(session.words_for(fragment, pc).contains(&word.offset));
                    assert!(record.vlabels.iter().all(|&(label_pc, offset)| {
                        offset != word.offset || label_pc == pc
                    }));
                    let position = origin.lineage.virtualized.expect("a body word has a source");
                    let block = &record.virtualized[position.block];
                    let insn = if position.cold {
                        block.cold[position.index]
                    } else {
                        block.insns[position.index]
                    };
                    // Layout resolves branch offsets: the pass's instruction is the
                    // word's up to those.
                    assert_eq!((insn.ori_pc, insn.kind), (pc, word.kind.unwrap()));
                    assert_eq!(insn.insn.key(), word.insn.key());
                    assert!(!origin.lineage.rephrased.is_empty(), "{name} {pc:#x}");
                    assert!(origin.lineage.cfg_block.is_some());
                } else {
                    assert!(origin.lineage.virtualized.is_none());
                }
            }
            assert!(session.origin(fragment, record.layout.len() * 4).is_none());
            assert!(session.words_for(fragment, 0xdead_0000).is_empty());
        }
        assert!(session.origin(cache.fragments.len(), 0).is_none());
    }
}

#[test]
fn events_are_ordered_by_tick_and_events_between_is_half_open() {
    let session = session("session_call_loop");
    let events = session.events();
    assert!(events.windows(2).all(|pair| pair[0].t <= pair[1].t));
    assert!(events.iter().all(|event| event.t <= session.ticks()));
    assert_eq!(session.events_between(0, session.ticks() + 1), events);
    assert!(session.events_between(5, 5).is_empty());
    let some = events[events.len() / 2].t;
    let window = session.events_between(some, some + 1);
    assert!(!window.is_empty());
    assert!(window.iter().all(|event| event.t == some));
    assert_eq!(
        session.events_between(0, some).len() + session.events_between(some, session.ticks() + 1).len(),
        events.len()
    );
}

#[test]
fn a_broken_model_diverges_at_the_syscall_it_breaks() {
    let session = record_tampered(
        config("session_call_loop"),
        Box::new(|k, state| {
            // Syscall 100 is the exit of a fragment run.
            if k == 100 {
                state.write_x(20, state.read_x(20) ^ 1);
            }
        }),
    )
    .unwrap();
    let Outcome::Divergence(divergence) = session.outcome() else {
        panic!("expected a divergence, got {:?}", session.outcome());
    };
    assert_eq!(divergence.syscall, Some(100));
    assert_eq!(divergence.kind, DivergenceKind::State);
    assert_eq!(divergence.t, session.ticks());
    assert_eq!(divergence.diff.regs.len(), 1);
    assert_eq!(divergence.diff.regs[0].reg, RegId::X(20));
    assert_eq!(
        divergence.diff.regs[0].reference ^ divergence.diff.regs[0].kjit,
        1
    );
    assert_eq!(session.syscalls().len(), 100);
    assert_eq!(session.events().last().unwrap().kind, EventKind::Divergence);
    assert_eq!(session.reference_at_syscall(100).unwrap(), divergence.reference);
    // The corruption is in the KJIT world only.
    assert_ne!(divergence.reference, divergence.kjit);
}

#[test]
fn a_corrupted_memory_word_diverges_too() {
    let session = record_tampered(
        config("session_svc_loop"),
        Box::new(|k, state| {
            if k == 10 {
                state.write_u64(crate::FIXTURE_DATA_BASE + 0x40, 7);
            }
        }),
    )
    .unwrap();
    let Outcome::Divergence(divergence) = session.outcome() else {
        panic!("expected a divergence");
    };
    assert_eq!(divergence.syscall, Some(10));
    assert_eq!(divergence.diff.mem.len(), 1);
    assert_eq!(divergence.diff.mem[0].addr, crate::FIXTURE_DATA_BASE + 0x40);
}

#[test]
fn the_step_limit_ends_the_recording() {
    let mut config = config("session_svc_loop");
    config.limits.max_steps = 1000;
    let session = Session::record(config).unwrap();
    assert_eq!(session.outcome(), &Outcome::StepLimit);
    assert_eq!(session.ticks(), 1000);
    assert_eq!(&session.state_at(1000).unwrap(), session.final_state());
}

#[test]
fn a_hot_unreadable_pc_is_refused_and_never_requested_again() {
    // With a threshold of 1 the return to the exit pc is hot at its first hit. It is no
    // text: the request is refused (the kernel's -ENOEXEC for an entry it cannot run).
    let mut config = config("session_svc_loop");
    config.policy.hot_threshold = 1;
    let session = Session::record(config).unwrap();
    assert_eq!(session.outcome(), &Outcome::Exited);
    let last = session.translations().last().unwrap();
    assert_eq!(last.entry_pc, SESSION_EXIT_PC);
    assert_eq!(last.installed, None);
    assert!(matches!(last.rejection, Some(Rejection::EntryUnsupported(_))));
    assert!(last.layout.is_empty());
}

#[test]
fn bad_configs_are_errors() {
    let valid = config("session_svc_loop");
    let mut zero = valid.clone();
    zero.policy.hot_threshold = 0;
    assert!(matches!(Session::record(zero), Err(SessionError::InvalidConfig(_))));
    let mut zero = valid.clone();
    zero.limits.max_steps = 0;
    assert!(matches!(Session::record(zero), Err(SessionError::InvalidConfig(_))));
    let mut zero = valid.clone();
    zero.limits.checkpoint_every = 0;
    assert!(matches!(Session::record(zero), Err(SessionError::InvalidConfig(_))));
    let mut unreadable = valid;
    unreadable.entry_pc = 0x8;
    assert!(matches!(
        Session::record(unreadable),
        Err(SessionError::EntryUnreadable { entry_pc: 0x8 })
    ));
}

/// A loop of SVCs translated at its second hit, then a store to a read-only page: the
/// fragment redirects the fault to its `Mem` stub, userspace takes the fault itself and
/// both worlds halt at it.
#[test]
fn a_fault_in_a_fragment_halts_both_worlds() {
    let source = root().join("tmp").join(format!("session-tests.{}.fault.s", std::process::id()));
    std::fs::write(
        &source,
        ".text\n.global fault_loop\nfault_loop:\n movz x8, #172\nsvc #0\n movz x19, #5\n\
         1: movz x8, #172\n svc #0\n subs x19, x19, #1\n b.ne 1b\n movz x0, #0x1234\n\
         stp x0, x1, [x12, #16]\n str x0, [x12, #0x4000]\n ret\n",
    )
    .unwrap();
    // The fault_loop symbol is the movz; `config_for` expects an SVC at +4 as the mark.
    let mut config = config_for(&source, "fault_loop");
    std::fs::remove_file(&source).unwrap();
    config.policy.hot_threshold = 2;
    let session = Session::record(config).unwrap();
    let Outcome::Halted(HaltReason::Fault(fault)) = session.outcome() else {
        panic!("expected a halt on the fault, got {:?}", session.outcome());
    };
    assert_eq!(fault.access.addr, crate::FIXTURE_RO_BASE);
    // The store pair before it completed in both worlds.
    assert_eq!(session.final_state().read_u64(crate::FIXTURE_DATA_BASE + 16), 0x1234);
    let events = session.events();
    assert!(events.iter().any(|event| matches!(event.kind, EventKind::FaultRedirect { .. })));
    assert!(events.iter().any(|event| matches!(
        event.kind,
        EventKind::Exit {
            status: RetStatus::Mem,
            ..
        }
    )));
}

/// A word outside the subset: the fragment exits `Unsupported`, userspace executes it
/// natively, where the model halts, in both worlds.
#[test]
fn an_unsupported_word_halts_both_worlds() {
    let mut config = config_for(&root().join("tests/arm64/unsupported_exit.s"), "hot_svc_mark");
    config.policy.hot_threshold = 2;
    let session = Session::record(config).unwrap();
    assert!(matches!(
        session.outcome(),
        Outcome::Halted(HaltReason::RuntimeExit {
            reason: RuntimeExitReason::Unsupported { .. }
        })
    ));
    assert!(session.events().iter().any(|event| matches!(
        event.kind,
        EventKind::Exit {
            status: RetStatus::Unsupported,
            ..
        }
    )));
}
