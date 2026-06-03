use crate::a64_pretty::pretty_insn;
use crate::arm64::OriginalStepper;
use crate::model::{HaltReason, MachineState};
use crate::runtime::{URuntime, URuntimeHalt, URuntimeStepper, URuntimeTransition};
use crate::shared::arm64::{decode_word, A64Insn};
use crate::shared::emit::layout::ExecutionFragment;
use crate::shared::platform::{SharedVec, GFP_KERNEL};
use crate::shared::trans::cfg::{build_cfg, Cfg, RuntimeExitReason};
use crate::shared::trans::input::{RegisterSnapshot, TranslationRequest};
use crate::shared::trans::reg_virt::{virtualize_registers, RegVirtConfig};
use crate::shared::trans::rephrase::{
    rephrase, RephrasedBlock, RephrasedInsnKind, RephrasedProgram,
};
use crate::MockCodeProvider;

#[derive(Debug)]
pub struct PipelineTrace {
    pub input: TraceInput,
    pub raw: Vec<TraceInsn>,
    pub cfg: TraceCfg,
    pub translated: Vec<TraceInsn>,
    pub rephrased: Vec<TraceRephrasedBlock>,
    pub virtualized: Vec<TraceRephrasedBlock>,
    pub fragment: TraceFragment,
    pub execution_fragment: ExecutionFragment,
    pub pc_index: Vec<PcIndexEntry>,
    pub runtime_index: Vec<RuntimeIndexEntry>,
    pub run: Option<TraceRun>,
    pub execution: Option<TraceExecution>,
}

#[derive(Debug)]
pub struct TraceInput {
    pub text_base: u64,
    pub entry_pc: u64,
    pub text_len: usize,
}

#[derive(Clone, Debug)]
pub struct TraceInsn {
    pub pc: u64,
    pub text_offset: usize,
    pub word: u32,
    pub key: &'static str,
    pub mnemonic: &'static str,
    pub pretty: String,
    pub debug: String,
    pub direct_branch_target: Option<u64>,
    pub conditional_targets: Option<(u64, u64)>,
    pub runtime_exit: Option<RuntimeExitReason>,
}

#[derive(Debug)]
pub struct TraceCfg {
    pub entry_pc: u64,
    pub blocks: Vec<TraceCfgBlock>,
}

#[derive(Debug)]
pub struct TraceCfgBlock {
    pub index: usize,
    pub start_pc: u64,
    pub end_pc: u64,
    pub prev: Vec<u64>,
    pub next: Vec<u64>,
    pub insn_pcs: Vec<u64>,
}

#[derive(Debug)]
pub struct TraceRephrasedBlock {
    pub index: usize,
    pub start_pc: u64,
    pub end_pc: u64,
    pub prev: Vec<u64>,
    pub next: Vec<u64>,
    pub insns: Vec<TraceRephrasedInsn>,
}

#[derive(Debug)]
pub struct TraceRephrasedInsn {
    pub block_index: usize,
    pub index_in_block: usize,
    pub ori_pc: u64,
    pub kind: RephrasedInsnKind,
    pub key: &'static str,
    pub mnemonic: &'static str,
    pub pretty: String,
    pub debug: String,
}

#[derive(Debug)]
pub struct TraceFragment {
    pub entry_offset: usize,
    pub len_bytes: usize,
    pub vlabels: Vec<(u64, usize)>,
    pub insns: Vec<TraceLayoutInsn>,
}

#[derive(Clone, Debug)]
pub struct TraceLayoutInsn {
    pub index: usize,
    pub offset: usize,
    pub ori_pc: Option<u64>,
    pub region: LayoutRegion,
    pub key: &'static str,
    pub mnemonic: &'static str,
    pub pretty: String,
    pub debug: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutRegion {
    Prologue,
    Epilogue,
    Body,
}

#[derive(Debug)]
pub struct PcIndexEntry {
    pub pc: u64,
    pub raw_index: Option<usize>,
    pub cfg_block: Option<usize>,
    pub rephrased_block: Option<usize>,
    pub layout_offsets: Vec<usize>,
}

#[derive(Debug)]
pub struct RuntimeIndexEntry {
    pub offset: usize,
    pub runtime_pc: u64,
    pub insn_index: usize,
    pub ori_pc: Option<u64>,
    pub region: LayoutRegion,
}

#[derive(Debug)]
pub struct TraceRun {
    pub steps: usize,
    pub halt: URuntimeHalt,
    pub final_state: MachineState,
}

#[derive(Debug)]
pub struct TraceExecution {
    pub original_steps: Vec<TraceOriginalStep>,
    pub translated_steps: Vec<TraceTranslatedStep>,
    pub groups: Vec<TraceStepGroup>,
}

#[derive(Clone, Debug)]
pub struct TraceOriginalStep {
    pub pc: u64,
    pub runtime_exit: Option<RuntimeExitReason>,
    pub halt_reason: Option<HaltReason>,
    pub state: MachineState,
}

#[derive(Clone, Debug)]
pub struct TraceTranslatedStep {
    pub offset: Option<usize>,
    pub insn_index: Option<usize>,
    pub ori_pc: Option<u64>,
    pub runtime_transition: Option<URuntimeTransition>,
    pub halt: Option<URuntimeHalt>,
    pub state: MachineState,
}

#[derive(Clone, Debug)]
pub struct TraceStepGroup {
    pub ori_pc: Option<u64>,
    pub original_step: Option<usize>,
    pub translated_steps: Vec<usize>,
    pub states_match: Option<bool>,
}

impl PipelineTrace {
    pub fn build(
        text_base: u64,
        text_bytes: Vec<u8>,
        request: TranslationRequest,
        initial_state: &MachineState,
        run_runtime: bool,
    ) -> Result<Self, String> {
        let code = MockCodeProvider::new(text_base, text_bytes.clone());
        let raw = decode_raw(&text_bytes, text_base)?;
        let cfg = build_cfg(&request, &code).map_err(|err| err.to_string())?;
        let translated = trace_translated(&cfg);
        let cfg_trace = trace_cfg(&cfg);

        let rephrased_program = rephrase(cfg).map_err(|err| format!("{err:?}"))?;
        let rephrased = trace_rephrased(&rephrased_program);
        let virtualized_program = virtualize_registers(
            copy_rephrased_program(&rephrased_program)?,
            &RegVirtConfig::KJIT_DEFAULT,
        )
        .map_err(|err| format!("{err:?}"))?;
        let virtualized = trace_rephrased(&virtualized_program);
        let layout_origins = layout_original_pcs(&virtualized_program);
        let fragment = crate::shared::emit::layout::layout_program(virtualized_program)
            .map_err(|err| err.to_string())?;
        let fragment_trace = trace_fragment(&fragment, &layout_origins);

        let (run, execution) = if run_runtime {
            let original_steps =
                trace_original_execution(&text_bytes, text_base, request.entry_pc, initial_state)?;
            let mut runtime = URuntime::new(copy_fragment(&fragment)?, initial_state.clone());
            let (translated_steps, report) =
                trace_translated_execution(&mut runtime, &fragment_trace)?;
            let groups = build_step_groups(&original_steps, &translated_steps);
            let run = TraceRun {
                steps: report.steps,
                halt: report.halt,
                final_state: report.state,
            };
            (
                Some(run),
                Some(TraceExecution {
                    original_steps,
                    translated_steps,
                    groups,
                }),
            )
        } else {
            (None, None)
        };

        let pc_index = build_pc_index(&raw, &cfg_trace, &rephrased, &fragment_trace);
        let runtime_index = build_runtime_index(&fragment_trace);

        Ok(Self {
            input: TraceInput {
                text_base,
                entry_pc: request.entry_pc,
                text_len: text_bytes.len(),
            },
            raw,
            cfg: cfg_trace,
            translated,
            rephrased,
            virtualized,
            fragment: fragment_trace,
            execution_fragment: fragment,
            pc_index,
            runtime_index,
            run,
            execution,
        })
    }

    pub fn selected_pc(&self, pc: u64) -> Option<&PcIndexEntry> {
        self.pc_index.iter().find(|entry| entry.pc == pc)
    }

    pub fn selected_offset(&self, offset: usize) -> Option<&RuntimeIndexEntry> {
        self.runtime_index
            .iter()
            .find(|entry| entry.offset == offset)
    }

    pub fn cfg_block_for_pc(&self, pc: u64) -> Option<&TraceCfgBlock> {
        self.cfg
            .blocks
            .iter()
            .find(|block| block.start_pc <= pc && pc < block.end_pc)
    }
}

pub fn request_for_trace(
    entry_pc: u64,
    trigger: crate::shared::trans::input::TranslationTrigger,
    state: &MachineState,
) -> TranslationRequest {
    TranslationRequest {
        entry_pc,
        trigger,
        regs: Some(register_snapshot(state, entry_pc)),
    }
}

fn decode_raw(bytes: &[u8], text_base: u64) -> Result<Vec<TraceInsn>, String> {
    if bytes.len() % 4 != 0 {
        return Err("raw text length must be a multiple of 4 bytes".to_string());
    }

    let mut raw = Vec::with_capacity(bytes.len() / 4);
    for (index, chunk) in bytes.chunks_exact(4).enumerate() {
        let pc = text_base + (index as u64) * 4;
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        let decoded = decode_word(word, pc).map_err(|err| err.to_string())?;
        raw.push(trace_insn(pc, index * 4, word, decoded.inner));
    }
    Ok(raw)
}

fn trace_insn(pc: u64, text_offset: usize, word: u32, insn: A64Insn) -> TraceInsn {
    TraceInsn {
        pc,
        text_offset,
        word,
        key: insn.key(),
        mnemonic: insn.mnemonic(),
        pretty: pretty_insn(insn, Some(pc)),
        debug: format!("{insn:?}"),
        direct_branch_target: insn.direct_branch_target(pc),
        conditional_targets: insn.conditional_targets(pc),
        runtime_exit: insn.runtime_exit_reason(pc),
    }
}

fn trace_translated(cfg: &Cfg) -> Vec<TraceInsn> {
    let count = cfg.blocks.iter().map(|block| block.insns.len()).sum();
    let mut out = Vec::with_capacity(count);
    for block in &cfg.blocks {
        for insn in &block.insns {
            out.push(trace_insn(insn.pc, 0, insn.word, insn.inner));
        }
    }
    out
}

fn trace_cfg(cfg: &Cfg) -> TraceCfg {
    TraceCfg {
        entry_pc: cfg.entry_pc,
        blocks: cfg
            .blocks
            .iter()
            .enumerate()
            .map(|(index, block)| TraceCfgBlock {
                index,
                start_pc: block.start_addr,
                end_pc: block.end_addr,
                prev: block.prev.iter().copied().collect(),
                next: block.next.iter().copied().collect(),
                insn_pcs: block.insns.iter().map(|insn| insn.pc).collect(),
            })
            .collect(),
    }
}

fn trace_rephrased(program: &RephrasedProgram) -> Vec<TraceRephrasedBlock> {
    program
        .iter()
        .enumerate()
        .map(|(block_index, block)| TraceRephrasedBlock {
            index: block_index,
            start_pc: block.start_addr,
            end_pc: block.end_addr,
            prev: block.prev.iter().copied().collect(),
            next: block.next.iter().copied().collect(),
            insns: block
                .insns
                .iter()
                .enumerate()
                .map(|(index_in_block, insn)| TraceRephrasedInsn {
                    block_index,
                    index_in_block,
                    ori_pc: insn.ori_pc,
                    kind: insn.kind,
                    key: insn.insn.key(),
                    mnemonic: insn.insn.mnemonic(),
                    pretty: pretty_insn(
                        insn.insn,
                        insn.kind.is_user_semantic().then_some(insn.ori_pc),
                    ),
                    debug: format!("{:?}", insn.insn),
                })
                .collect(),
        })
        .collect()
}

fn trace_fragment(
    fragment: &ExecutionFragment,
    layout_original_pcs: &[Option<u64>],
) -> TraceFragment {
    let insns = fragment
        .insns
        .iter()
        .enumerate()
        .map(|(index, insn)| {
            let offset = index * 4;
            let runtime_pc = crate::runtime::DEFAULT_BASE_PC + offset as u64;
            TraceLayoutInsn {
                index,
                offset,
                ori_pc: layout_original_pcs
                    .get(index)
                    .copied()
                    .flatten()
                    .or_else(|| original_pc_for_offset(&fragment.vlabels, offset)),
                region: layout_region(offset),
                key: insn.key(),
                mnemonic: insn.mnemonic(),
                pretty: pretty_insn(*insn, Some(runtime_pc)),
                debug: format!("{insn:?}"),
            }
        })
        .collect();

    TraceFragment {
        entry_offset: fragment.entry_offset,
        len_bytes: fragment.len_bytes(),
        vlabels: fragment.vlabels.iter().copied().collect(),
        insns,
    }
}

fn layout_original_pcs(program: &RephrasedProgram) -> Vec<Option<u64>> {
    use crate::shared::abi::{EPILOGUE_LEN_BYTES, PROLOGUE_LEN_BYTES};

    let wrapper_insns = (PROLOGUE_LEN_BYTES + EPILOGUE_LEN_BYTES) / 4;
    let body_insns = program.iter().map(|block| block.insns.len()).sum::<usize>();
    let mut origins = Vec::with_capacity(wrapper_insns + body_insns);

    for _ in 0..wrapper_insns {
        origins.push(None);
    }
    for block in program {
        for insn in &block.insns {
            origins.push(Some(insn.ori_pc));
        }
    }
    origins
}

fn build_pc_index(
    raw: &[TraceInsn],
    cfg: &TraceCfg,
    rephrased: &[TraceRephrasedBlock],
    fragment: &TraceFragment,
) -> Vec<PcIndexEntry> {
    let mut pcs = Vec::new();
    push_unique_pcs(&mut pcs, raw.iter().map(|insn| insn.pc));
    push_unique_pcs(
        &mut pcs,
        cfg.blocks
            .iter()
            .flat_map(|block| block.insn_pcs.iter().copied()),
    );
    push_unique_pcs(
        &mut pcs,
        rephrased
            .iter()
            .flat_map(|block| block.insns.iter().map(|insn| insn.ori_pc)),
    );
    push_unique_pcs(
        &mut pcs,
        fragment.insns.iter().filter_map(|insn| insn.ori_pc),
    );
    pcs.sort_unstable();

    pcs.into_iter()
        .map(|pc| PcIndexEntry {
            pc,
            raw_index: raw.iter().position(|insn| insn.pc == pc),
            cfg_block: cfg
                .blocks
                .iter()
                .find(|block| block.start_pc <= pc && pc < block.end_pc)
                .map(|block| block.index),
            rephrased_block: rephrased
                .iter()
                .find(|block| block.start_pc <= pc && pc < block.end_pc)
                .map(|block| block.index),
            layout_offsets: fragment
                .insns
                .iter()
                .filter_map(|insn| (insn.ori_pc == Some(pc)).then_some(insn.offset))
                .collect(),
        })
        .collect()
}

fn build_runtime_index(fragment: &TraceFragment) -> Vec<RuntimeIndexEntry> {
    fragment
        .insns
        .iter()
        .map(|insn| RuntimeIndexEntry {
            offset: insn.offset,
            runtime_pc: crate::runtime::DEFAULT_BASE_PC + insn.offset as u64,
            insn_index: insn.index,
            ori_pc: insn.ori_pc,
            region: insn.region,
        })
        .collect()
}

fn trace_original_execution(
    bytes: &[u8],
    text_base: u64,
    entry_pc: u64,
    initial_state: &MachineState,
) -> Result<Vec<TraceOriginalStep>, String> {
    const MAX_ORIGINAL_STEPS: usize = 100_000;

    let mut stepper = OriginalStepper::new(bytes, text_base, entry_pc, initial_state)?;
    let mut steps = Vec::new();

    for _ in 0..MAX_ORIGINAL_STEPS {
        let Some(step) = stepper.step()? else {
            break;
        };
        let runtime_exit = step.runtime_exit;
        let halt_reason = step.halt_reason;
        let resume_pc = match runtime_exit {
            Some(RuntimeExitReason::Svc { resume_pc, .. }) => Some(resume_pc),
            _ => None,
        };
        steps.push(TraceOriginalStep {
            pc: step.pc,
            runtime_exit,
            halt_reason,
            state: step.state,
        });

        if let Some(resume_pc) = resume_pc {
            stepper.resume_at(resume_pc);
        } else if halt_reason.is_some() {
            return Ok(steps);
        }
    }

    Err("original step trace exceeded step limit".to_string())
}

fn trace_translated_execution(
    runtime: &mut URuntime,
    fragment: &TraceFragment,
) -> Result<(Vec<TraceTranslatedStep>, crate::runtime::URuntimeReport), String> {
    const MAX_TRANSLATED_STEPS: usize = 200_000;

    let mut stepper = URuntimeStepper::new(runtime)?;
    let mut steps = Vec::new();

    for _ in 0..MAX_TRANSLATED_STEPS {
        let Some(step) = stepper.step()? else {
            break;
        };
        let ori_pc = step
            .offset
            .and_then(|offset| fragment.insns.iter().find(|insn| insn.offset == offset))
            .and_then(|insn| insn.ori_pc);
        let halt = step.halt.clone();
        steps.push(TraceTranslatedStep {
            offset: step.offset,
            insn_index: step.insn_index,
            ori_pc,
            runtime_transition: step.runtime_transition,
            halt: step.halt,
            state: step.state,
        });

        if let Some(halt) = halt {
            let report = stepper.report_for_halt(halt);
            return Ok((steps, report));
        }
    }

    Err("translated step trace exceeded step limit".to_string())
}

fn build_step_groups(
    original_steps: &[TraceOriginalStep],
    translated_steps: &[TraceTranslatedStep],
) -> Vec<TraceStepGroup> {
    let mut groups = Vec::new();
    let mut original_cursor = 0usize;
    let mut translated_cursor = 0usize;

    while translated_cursor < translated_steps.len() {
        let ori_pc = translated_steps[translated_cursor].ori_pc;
        let mut translated_group = Vec::new();
        while translated_cursor < translated_steps.len()
            && translated_steps[translated_cursor].ori_pc == ori_pc
        {
            translated_group.push(translated_cursor);
            translated_cursor += 1;
        }

        let original_step = ori_pc.and_then(|pc| {
            let found = original_steps[original_cursor..]
                .iter()
                .position(|step| step.pc == pc)
                .map(|relative| original_cursor + relative);
            if let Some(index) = found {
                original_cursor = index + 1;
            }
            found
        });

        let states_match = original_step.map(|original_index| {
            let translated_index = *translated_group
                .last()
                .expect("translated groups are never empty");
            original_steps[original_index].state == translated_steps[translated_index].state
        });

        groups.push(TraceStepGroup {
            ori_pc,
            original_step,
            translated_steps: translated_group,
            states_match,
        });
    }

    groups
}

fn push_unique_pcs<I>(pcs: &mut Vec<u64>, iter: I)
where
    I: Iterator<Item = u64>,
{
    for pc in iter {
        if !pcs.contains(&pc) {
            pcs.push(pc);
        }
    }
}

fn original_pc_for_offset(vlabels: &[(u64, usize)], offset: usize) -> Option<u64> {
    vlabels
        .iter()
        .find_map(|(pc, label_offset)| (*label_offset == offset).then_some(*pc))
}

fn layout_region(offset: usize) -> LayoutRegion {
    use crate::shared::abi::{EPILOGUE_LEN_BYTES, EPILOGUE_OFFSET, PROLOGUE_LEN_BYTES};

    if offset < PROLOGUE_LEN_BYTES {
        LayoutRegion::Prologue
    } else if offset < EPILOGUE_OFFSET + EPILOGUE_LEN_BYTES {
        LayoutRegion::Epilogue
    } else {
        LayoutRegion::Body
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run_entry_fixture;
    use crate::shared::arm64::ergo::{uimm, x};
    use crate::shared::arm64::{A64Imm, A64Insn, A64Mem, A64Reg};
    use crate::shared::trans::input::TranslationTrigger;
    use crate::shared::trans::rephrase::RephrasedInsn;

    fn encode_insns(insns: &[A64Insn]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(insns.len() * 4);
        for insn in insns {
            bytes.extend_from_slice(&insn.encode().unwrap().to_le_bytes());
        }
        bytes
    }

    #[test]
    fn trace_fragment_keeps_origin_for_every_expanded_body_instruction() {
        let original_pc = 0x1000;
        let mut insns = SharedVec::new();
        insns
            .push(
                RephrasedInsn::synthetic(original_pc, A64Insn::NopNopHiHints {}),
                GFP_KERNEL,
            )
            .unwrap();
        insns
            .push(
                RephrasedInsn::synthetic(original_pc, A64Insn::NopNopHiHints {}),
                GFP_KERNEL,
            )
            .unwrap();

        let mut program = SharedVec::new();
        program
            .push(
                RephrasedBlock {
                    start_addr: original_pc,
                    end_addr: original_pc + 4,
                    prev: SharedVec::new(),
                    next: SharedVec::new(),
                    insns,
                },
                GFP_KERNEL,
            )
            .unwrap();

        let layout_origins = layout_original_pcs(&program);
        let fragment = crate::shared::emit::layout::layout_program(program).unwrap();
        let trace = trace_fragment(&fragment, &layout_origins);
        let offsets = trace
            .insns
            .iter()
            .filter_map(|insn| (insn.ori_pc == Some(original_pc)).then_some(insn.offset))
            .collect::<Vec<_>>();

        assert_eq!(offsets.len(), 2);
        assert_eq!(offsets[0], fragment.vlabels[0].1);
        assert_eq!(offsets[1], fragment.vlabels[0].1 + 4);
    }

    #[test]
    fn step_trace_exposes_wrapper_only_and_origin_groups() {
        let text_base = 0x4000;
        let entry_pc = text_base;
        let bytes = encode_insns(&[
            A64Insn::MovzMovz64Movewide {
                hw: 0,
                imm16: uimm(5, 16),
                rd: x(0),
            },
            A64Insn::RetRet64rBranchReg { rn: x(30) },
        ]);
        let mut state = MachineState::new();
        state.write_x(30, 0xfeed_0000);
        let request = request_for_trace(entry_pc, TranslationTrigger::Manual, &state);

        let trace = PipelineTrace::build(text_base, bytes, request, &state, true).unwrap();
        let execution = trace.execution.as_ref().unwrap();

        assert_eq!(execution.translated_steps.first().unwrap().ori_pc, None);
        assert_eq!(execution.groups.first().unwrap().ori_pc, None);
        assert!(execution.groups.iter().any(|group| {
            group.ori_pc == Some(entry_pc)
                && group.original_step.is_some()
                && !group.translated_steps.is_empty()
        }));
    }

    #[test]
    fn step_trace_final_state_matches_fixture_and_keeps_user_memory() {
        let text_base = 0x5000;
        let entry_pc = text_base;
        let bytes = encode_insns(&[
            A64Insn::MovzMovz64Movewide {
                hw: 0,
                imm16: uimm(5, 16),
                rd: x(0),
            },
            A64Insn::StrImmGenStr64LdstPos {
                rt: x(0),
                mem: A64Mem::offset(A64Reg::x(12), A64Imm::scaled_unsigned(2, 12, 3)),
            },
            A64Insn::LdrImmGenLdr64LdstPos {
                rt: x(3),
                mem: A64Mem::offset(A64Reg::x(12), A64Imm::scaled_unsigned(2, 12, 3)),
            },
            A64Insn::RetRet64rBranchReg { rn: x(30) },
        ]);
        let mut state = MachineState::new();
        state.write_x(12, 0x9000);
        state.write_x(30, 0xfeed_0000);
        let request = request_for_trace(entry_pc, TranslationTrigger::Manual, &state);

        let trace = PipelineTrace::build(text_base, bytes.clone(), request, &state, true).unwrap();
        let report =
            run_entry_fixture("step-trace-memory", text_base, bytes, entry_pc, &state).unwrap();
        let run = trace.run.as_ref().unwrap();

        assert_eq!(run.final_state, report.fragment_state);
        assert_eq!(run.final_state.read_u64(0x9010), 5);
        assert_eq!(run.final_state.read_x(3), 5);
    }
}

fn copy_rephrased_program(program: &RephrasedProgram) -> Result<RephrasedProgram, String> {
    let mut out =
        SharedVec::with_capacity(program.len(), GFP_KERNEL).map_err(|err| format!("{err:?}"))?;
    for block in program {
        let mut insns = SharedVec::with_capacity(block.insns.len(), GFP_KERNEL)
            .map_err(|err| format!("{err:?}"))?;
        for insn in &block.insns {
            insns
                .push(*insn, GFP_KERNEL)
                .map_err(|err| format!("{err:?}"))?;
        }
        out.push(
            RephrasedBlock {
                start_addr: block.start_addr,
                end_addr: block.end_addr,
                prev: copy_u64_vec(&block.prev)?,
                next: copy_u64_vec(&block.next)?,
                insns,
            },
            GFP_KERNEL,
        )
        .map_err(|err| format!("{err:?}"))?;
    }
    Ok(out)
}

fn copy_u64_vec(values: &SharedVec<u64>) -> Result<SharedVec<u64>, String> {
    let mut out =
        SharedVec::with_capacity(values.len(), GFP_KERNEL).map_err(|err| format!("{err:?}"))?;
    for value in values {
        out.push(*value, GFP_KERNEL)
            .map_err(|err| format!("{err:?}"))?;
    }
    Ok(out)
}

fn copy_fragment(fragment: &ExecutionFragment) -> Result<ExecutionFragment, String> {
    let mut insns = SharedVec::with_capacity(fragment.insns.len(), GFP_KERNEL)
        .map_err(|err| format!("{err:?}"))?;
    for insn in &fragment.insns {
        insns
            .push(*insn, GFP_KERNEL)
            .map_err(|err| format!("{err:?}"))?;
    }
    let mut vlabels = SharedVec::with_capacity(fragment.vlabels.len(), GFP_KERNEL)
        .map_err(|err| format!("{err:?}"))?;
    for label in &fragment.vlabels {
        vlabels
            .push(*label, GFP_KERNEL)
            .map_err(|err| format!("{err:?}"))?;
    }
    Ok(ExecutionFragment {
        insns,
        entry_offset: fragment.entry_offset,
        vlabels,
    })
}

fn register_snapshot(state: &MachineState, pc: u64) -> RegisterSnapshot {
    let mut x = [0_u64; 31];
    for reg in 0..31 {
        x[reg] = state.read_x(reg as u8);
    }
    RegisterSnapshot {
        x,
        sp: state.sp(),
        pc,
        pstate: 0,
    }
}
