//! Random program and initial-state generation over the catalog.
//!
//! Shape: 1..=max_len slots after the hot SVC. Plain slots are instances of
//! any catalog form (operands from the form's free-field metadata); bounded
//! loops are `movz xC, #n; head: <body not writing xC>; sub[s] xC, xC, #1;
//! cbnz xC, head | b.ne head`; forward branches never enter a loop from
//! outside or skip a loop's decrement; a few percent of branches go backward
//! unstructured and rely on the back-edge budget. Branches may target the first
//! PC past the text. The last slot is a register exit (mostly `ret x30`), BL out
//! of the text, an undecodable word, or nothing (fall off the end).

use super::forms::{BranchField, Catalog, FieldKind, Form, FormClass};
use super::program::{branch_field_value, slot_pc, Program, Slot, TEXT_BASE};
use super::rng::Rng;
use crate::model::{Flags, MachineState, PAGE_SIZE};
use crate::shared::arm64::{A64Imm, A64Insn, A64Mem, A64Reg, A64Reg31Mode};
use crate::shared::trans::cfg::admit_word;
use crate::{default_fixture_state, FIXTURE_DATA_BASE, FIXTURE_DATA_LEN, FIXTURE_RO_BASE};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenConfig {
    pub max_len: usize,
    /// Chance, per mille and per memory instruction, that its base is the
    /// fault pointer (a register aimed at a read-only or unmapped page).
    pub fault_per_mille: u32,
    /// Keep SP 16-byte aligned: no ALU writes to SP and SP writeback only by
    /// multiples of 16. Linux enables SP alignment checking at EL0, which the
    /// interpreter does not model and the translated code (SP lives in x17)
    /// cannot reproduce, so a native run faults where neither side does.
    pub sp_aligned: bool,
}

impl Default for GenConfig {
    fn default() -> Self {
        Self {
            max_len: 64,
            fault_per_mille: 10,
            sp_aligned: false,
        }
    }
}

pub struct Generated {
    pub program: Program,
    pub state: MachineState,
}

const RESERVED: [u8; 3] = [9, 10, 11];
const STACK_BACKED: [u8; 6] = [12, 13, 14, 15, 16, 17];
const FRAME: [u8; 2] = [29, 30];

const LOOP_PER_MILLE: u32 = 80;
const BACKWARD_PER_MILLE: u32 = 30;
/// Share of plain slots that may hold a word `admit_word` rejects.
const REJECTED_PER_MILLE: u32 = 30;
/// Slot-class weights for plain slots.
const CLASS_WEIGHTS: [(Choice, u64); 8] = [
    (Choice::Class(FormClass::Straight), 40),
    (Choice::Class(FormClass::Memory), 35),
    (Choice::Class(FormClass::CondBranch), 12),
    (Choice::Class(FormClass::Jump), 3),
    (Choice::Class(FormClass::Svc), 4),
    (Choice::Class(FormClass::ExitReg), 1),
    (Choice::Class(FormClass::ExitImm), 1),
    (Choice::Undecodable, 1),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Choice {
    Class(FormClass),
    Undecodable,
}

enum Pending {
    Word(u32),
    Branch {
        insn: A64Insn,
        field: BranchField,
        target: Option<usize>,
    },
}

struct LoopSpan {
    head: usize,
    dec: usize,
    back: usize,
}

struct Gen<'a> {
    rng: &'a mut Rng,
    catalog: &'a Catalog,
    config: GenConfig,
    /// Registers (never 31) holding in-window pointers; SP is one too.
    pointers: Vec<u8>,
    /// Register aimed at a read-only or unmapped page.
    fault_reg: u8,
    /// Registers (never 31) holding small non-negative values: register-offset
    /// memory forms read them as their index, keeping the address in the window.
    index_regs: Vec<u8>,
    slots: Vec<Pending>,
    /// Loop owning each slot.
    owner: Vec<Option<usize>>,
    loops: Vec<LoopSpan>,
}

pub fn generate(catalog: &Catalog, rng: &mut Rng, config: GenConfig) -> Generated {
    assert!(config.max_len >= 1, "max_len must be at least 1");
    let mut gen = Gen {
        rng,
        catalog,
        config,
        pointers: Vec::new(),
        index_regs: Vec::new(),
        fault_reg: 0,
        slots: Vec::new(),
        owner: Vec::new(),
        loops: Vec::new(),
    };
    gen.pick_pointer_regs();
    let state = gen.initial_state();

    let len = gen.rng.range(1, config.max_len as u64) as usize;
    while gen.slots.len() + 1 < len {
        let remaining = len - 1 - gen.slots.len();
        if remaining >= 4 && gen.rng.chance(LOOP_PER_MILLE) {
            gen.push_loop(remaining);
        } else {
            let slot = gen.plain(gen.slots.len(), &[]);
            gen.push(slot, None);
        }
    }
    gen.push_terminal();
    gen.resolve_targets();

    let program = Program {
        slots: gen
            .slots
            .into_iter()
            .map(|slot| match slot {
                Pending::Word(word) => Slot::Word(word),
                Pending::Branch {
                    insn,
                    field,
                    target,
                } => Slot::Branch {
                    insn,
                    field: field.name,
                    bits: field.bits,
                    scale: field.scale,
                    target: target.expect("every branch target is resolved"),
                },
            })
            .collect(),
    };
    if let Err(err) = program.validate() {
        panic!("generator produced an invalid program ({err}): {program:#?}");
    }
    Generated { program, state }
}

impl Gen<'_> {
    fn push(&mut self, slot: Pending, owner: Option<usize>) {
        self.slots.push(slot);
        self.owner.push(owner);
    }

    fn pick_reg(&mut self) -> u8 {
        match self.rng.below(100) {
            0..=21 => self.rng.pick(&RESERVED),
            22..=43 => self.rng.pick(&STACK_BACKED),
            44..=53 => self.rng.pick(&FRAME),
            54..=61 => 31,
            _ => self.rng.below(31) as u8,
        }
    }

    fn pick_pointer_regs(&mut self) {
        let count = self.rng.range(2, 3);
        while (self.pointers.len() as u64) < count {
            let reg = self.pick_reg();
            if reg != 31 && !self.pointers.contains(&reg) {
                self.pointers.push(reg);
            }
        }
        self.fault_reg = loop {
            let reg = self.pick_reg();
            if reg != 31 && !self.pointers.contains(&reg) {
                break reg;
            }
        };
        while self.index_regs.len() < 2 {
            let reg = self.pick_reg();
            if reg != 31 && !self.is_address_reg(reg) {
                self.index_regs.push(reg);
            }
        }
    }

    /// Pointer, fault or index register: generated writes mostly avoid them so
    /// later memory accesses keep hitting their intended pages.
    fn is_address_reg(&self, reg: u8) -> bool {
        self.pointers.contains(&reg) || reg == self.fault_reg || self.index_regs.contains(&reg)
    }

    /// A pointer with room for the generated offsets (at most ~200 bytes
    /// either way) inside the read-write window; 10% are not 8-aligned.
    fn window_pointer(&mut self) -> u64 {
        let low = FIXTURE_DATA_BASE + 0x100;
        let slots = (FIXTURE_DATA_LEN - 0x200) / 8;
        let aligned = low + 8 * self.rng.below(slots);
        if self.rng.chance(100) {
            aligned + self.rng.pick(&[1, 2, 4])
        } else {
            aligned
        }
    }

    fn fault_pointer(&mut self) -> u64 {
        let window_end = FIXTURE_DATA_BASE + FIXTURE_DATA_LEN;
        match self.rng.below(5) {
            // Read-only page: loads succeed, stores fault.
            0 | 1 => FIXTURE_RO_BASE + 8 * self.rng.below(PAGE_SIZE / 8 - 32),
            // Straddles read-write into read-only.
            2 => window_end - 4,
            // Just below the window: unmapped.
            3 => FIXTURE_DATA_BASE - 8 * self.rng.range(1, 8),
            // Past the read-only page: unmapped.
            _ => FIXTURE_RO_BASE + PAGE_SIZE + 8 * self.rng.below(32),
        }
    }

    fn random_value(&mut self) -> u64 {
        match self.rng.below(10) {
            0 => 0,
            1 | 2 => self.rng.below(16),
            3 => self.window_pointer(),
            4 => self.rng.pick(&[
                1 << 63,
                u64::MAX,
                0xffff_ffff,
                0x8000_0000,
                0x7fff_ffff_ffff_ffff,
            ]),
            _ => self.rng.next_u64(),
        }
    }

    fn initial_state(&mut self) -> MachineState {
        // The fixture state: data window read-write, `FIXTURE_RO_BASE` read-only.
        let mut state = default_fixture_state();
        for reg in 0..31 {
            let value = self.random_value();
            state.write_x(reg, value);
        }
        for index in 0..self.pointers.len() {
            let value = self.window_pointer();
            state.write_x(self.pointers[index], value);
        }
        let fault = self.fault_pointer();
        state.write_x(self.fault_reg, fault);
        for index in 0..self.index_regs.len() {
            let value = self.rng.below(17);
            state.write_x(self.index_regs[index], value);
        }
        let sp = self.window_pointer() & !0xf;
        state.set_sp(sp);
        state.flags = Flags {
            n: self.rng.chance(500),
            z: self.rng.chance(500),
            c: self.rng.chance(500),
            v: self.rng.chance(500),
        };

        // Data around every pointer, a few words elsewhere in the window and
        // some in the read-only page.
        let mut around = self
            .pointers
            .iter()
            .map(|&reg| state.read_x(reg))
            .collect::<Vec<_>>();
        around.push(sp);
        for base in around {
            for index in 0..8u64 {
                let value = self.rng.next_u64();
                state.write_u64((base & !7) - 32 + index * 8, value);
            }
        }
        for _ in 0..16 {
            let addr = FIXTURE_DATA_BASE + 8 * self.rng.below(FIXTURE_DATA_LEN / 8);
            let value = self.rng.next_u64();
            state.write_u64(addr, value);
        }
        for _ in 0..8 {
            let addr = FIXTURE_RO_BASE + 8 * self.rng.below(PAGE_SIZE / 8);
            let value = self.rng.next_u64();
            state.write_u64(addr, value);
        }
        state
    }

    fn choose_class(&mut self) -> Choice {
        let total: u64 = CLASS_WEIGHTS.iter().map(|(_, weight)| weight).sum();
        let mut pick = self.rng.below(total);
        for (choice, weight) in CLASS_WEIGHTS {
            if pick < weight {
                return choice;
            }
            pick -= weight;
        }
        unreachable!("weights cover the range")
    }

    /// One plain slot at `index`; `forbid` lists registers it must not write.
    fn plain(&mut self, index: usize, forbid: &[u8]) -> Pending {
        // Mostly words translation admits: a rejected word (reserved encoding,
        // constrained-unpredictable register overlap, user LDTR/STTR) ends the
        // program at an Unsupported exit. A few exercise that exit.
        let admitted_only = !self.rng.chance(REJECTED_PER_MILLE);
        loop {
            let class = match self.choose_class() {
                Choice::Undecodable => return Pending::Word(self.undecodable_word()),
                Choice::Class(class) => class,
            };
            let forms = self.catalog.of_class(class);
            if forms.is_empty() {
                continue;
            }
            let form = self.rng.pick(&forms);
            // A form translation never admits is re-picked.
            if let Some(slot) = self.instance_slot(form, index, forbid, admitted_only) {
                return slot;
            }
        }
    }

    fn instance_slot(
        &mut self,
        form: &Form,
        index: usize,
        forbid: &[u8],
        admitted_only: bool,
    ) -> Option<Pending> {
        let word = self.instance(form, index, forbid, admitted_only)?;
        Some(match form.class {
            FormClass::CondBranch | FormClass::Jump => Pending::Branch {
                insn: form.decode(word).expect("instance decodes as its form"),
                field: form.branch_field().expect("branch form has a target field"),
                target: None,
            },
            FormClass::ExitImm => Pending::Word(self.outside_target(form, word, index)),
            _ => Pending::Word(word),
        })
    }

    /// Random operands for `form` at slot `index`, round-tripped through the
    /// generated decoder and encoder. With `admitted_only`, only words
    /// `admit_word` translates; `None` if none turned up.
    fn instance(
        &mut self,
        form: &Form,
        index: usize,
        forbid: &[u8],
        admitted_only: bool,
    ) -> Option<u32> {
        const ATTEMPTS: usize = 256;
        for _ in 0..ATTEMPTS {
            let mut word = form.spec.value;
            for field in &form.fields {
                let raw = match field.kind {
                    FieldKind::BranchTarget(_) => 0,
                    FieldKind::MemBase { reg31, .. } => self.base_reg(reg31) as u32,
                    FieldKind::MemOffset { signed, .. } => self.offset_raw(field.width(), signed),
                    FieldKind::LiteralOffset => self.literal_raw(field.width(), index),
                    // A read operand of a memory form may be its index register.
                    FieldKind::Reg { written: false, .. }
                        if form.class == FormClass::Memory && self.rng.chance(850) =>
                    {
                        self.rng.pick(&self.index_regs.clone()) as u32
                    }
                    FieldKind::Reg { reg31, written } => {
                        if written && reg31 == A64Reg31Mode::Sp && self.config.sp_aligned {
                            self.operand_reg(written, &with_sp(forbid)) as u32
                        } else {
                            self.operand_reg(written, forbid) as u32
                        }
                    }
                    FieldKind::Imm => self.imm_raw(field.width()),
                };
                word = field.set(word, raw);
            }
            let Some(insn) = form.decode(word) else {
                continue;
            };
            assert_eq!(
                insn.encode().ok(),
                Some(word),
                "{}: {word:#010x} does not round-trip through decode/encode",
                form.key()
            );
            if matches!(form.class, FormClass::Straight | FormClass::Memory)
                && form.implicit_writes.iter().any(|reg| forbid.contains(reg))
            {
                continue;
            }
            if self.config.sp_aligned
                && insn.mem_operand().is_some_and(|mem| {
                    mem.base().enc() == 31
                        && !matches!(mem, A64Mem::Offset { .. })
                        && mem.offset_imm().value() % 16 != 0
                })
            {
                continue;
            }
            if admitted_only && matches!(admit_word(word, slot_pc(index)), Ok(Err(_))) {
                continue;
            }
            // ADR/ADRP may not point into the text: see `Program::validate`.
            let text_limit = TEXT_BASE + 4 * (self.config.max_len as u64 + 2);
            if insn
                .pc_relative_address(slot_pc(index))
                .is_some_and(|address| (TEXT_BASE..text_limit).contains(&address))
            {
                continue;
            }
            return Some(word);
        }
        assert!(
            admitted_only,
            "{}: no valid instance in {ATTEMPTS} attempts",
            form.key()
        );
        None
    }

    fn base_reg(&mut self, reg31: A64Reg31Mode) -> u8 {
        if self.rng.chance(self.config.fault_per_mille) {
            return self.fault_reg;
        }
        if reg31 == A64Reg31Mode::Sp && self.rng.chance(250) {
            return 31;
        }
        self.rng.pick(&self.pointers.clone())
    }

    fn operand_reg(&mut self, written: bool, forbid: &[u8]) -> u8 {
        loop {
            let reg = self.pick_reg();
            if written {
                if forbid.contains(&reg) {
                    continue;
                }
                // Keep most address registers intact so later memory ops stay
                // in bounds.
                if self.is_address_reg(reg) && !self.rng.chance(150) {
                    continue;
                }
            }
            return reg;
        }
    }

    /// A literal-load offset (word units from the slot's PC) to a data-window
    /// address. The text itself is not user-readable in the harness page map.
    fn literal_raw(&mut self, width: u8, index: usize) -> u32 {
        let target = self.window_pointer() & !3;
        let units = (target as i64 - slot_pc(index) as i64) >> 2;
        (units as u32) & field_mask(width)
    }

    fn offset_raw(&mut self, width: u8, signed: bool) -> u32 {
        let units = if signed {
            self.rng.range_i64(-12, 12)
        } else {
            self.rng.range(0, 24) as i64
        };
        (units as u32) & field_mask(width)
    }

    fn imm_raw(&mut self, width: u8) -> u32 {
        let mask = field_mask(width);
        let raw = match self.rng.below(10) {
            0..=2 => 0,
            3 | 4 => self.rng.below(8) as u32,
            5 => mask,
            6 => 1,
            _ => self.rng.next_u64() as u32,
        };
        raw & mask
    }

    fn undecodable_word(&mut self) -> u32 {
        loop {
            let word = self.rng.next_u64() as u32;
            if A64Insn::decode(word).is_none() {
                return word;
            }
        }
    }

    /// `word` (an immediate-target exit) retargeted 64 KiB..320 KiB away.
    fn outside_target(&mut self, form: &Form, word: u32, index: usize) -> u32 {
        let field = form
            .branch_field()
            .expect("exit-imm form has a target field");
        let magnitude = 0x10000 + 4 * self.rng.below(0x10000) as i64;
        let backward = self.rng.chance(500) && slot_pc(index) as i64 > magnitude;
        let delta = if backward { -magnitude } else { magnitude };
        let encoded = branch_field_value(delta, field.bits, field.scale)
            .expect("out-of-text delta fits the BL immediate");
        encode(
            form.decode(word)
                .expect("instance decodes as its form")
                .set_branch_target_imm(field.name, encoded)
                .expect("exit-imm target field accepts the delta"),
        )
    }

    fn push_loop(&mut self, remaining: usize) {
        let counter = loop {
            let reg = self.pick_reg();
            if reg != 31 && !self.is_address_reg(reg) {
                break reg;
            }
        };
        let iterations = self.rng.range(1, 5) as u32;
        self.push(
            Pending::Word(encode(A64Insn::MovzMovz64Movewide {
                hw: 0,
                imm16: A64Imm::unsigned(iterations, 16),
                rd: A64Reg::x(counter),
            })),
            None,
        );

        let loop_id = self.loops.len();
        let head = self.slots.len();
        let body_len = self.rng.below((remaining - 3).min(8) as u64 + 1) as usize;
        for _ in 0..body_len {
            let slot = self.plain(self.slots.len(), &[counter]);
            self.push(slot, Some(loop_id));
        }

        let one = A64Imm::unsigned(1, 12);
        let (dec, back) = if self.rng.chance(500) {
            (
                A64Insn::SubAddsubImmSub64AddsubImm {
                    sh: 0,
                    imm12: one,
                    rn: A64Reg::x_sp(counter),
                    rd: A64Reg::x_sp(counter),
                },
                A64Insn::CbnzCbnz64Compbranch {
                    imm19: A64Imm::scaled_signed(0, 19, 2),
                    rt: A64Reg::x(counter),
                },
            )
        } else {
            (
                A64Insn::SubsAddsubImmSubs64sAddsubImm {
                    sh: 0,
                    imm12: one,
                    rn: A64Reg::x_sp(counter),
                    rd: A64Reg::x(counter),
                },
                A64Insn::BCondBOnlyCondbranch {
                    imm19: A64Imm::scaled_signed(0, 19, 2),
                    cond: 0b0001, // NE
                },
            )
        };
        let dec_index = self.slots.len();
        self.push(Pending::Word(encode(dec)), Some(loop_id));
        let back_field = self
            .catalog
            .by_key(back.key())
            .and_then(Form::branch_field)
            .expect("loop back-edge form is in the catalog");
        let back_index = self.slots.len();
        self.push(
            Pending::Branch {
                insn: back,
                field: back_field,
                target: Some(head),
            },
            Some(loop_id),
        );
        self.loops.push(LoopSpan {
            head,
            dec: dec_index,
            back: back_index,
        });
    }

    fn push_terminal(&mut self) {
        let index = self.slots.len();
        let pick = self.rng.below(100);
        let slot = if pick < 15 {
            let forms = self.catalog.of_class(FormClass::ExitImm);
            let form = self.rng.pick(&forms);
            self.instance_slot(form, index, &[], true)
                .expect("exit-imm forms are admitted")
        } else if pick < 27 {
            Pending::Word(self.undecodable_word())
        } else if pick < 37 && index > 0 {
            return; // fall off the end
        } else {
            let forms = self.catalog.of_class(FormClass::ExitReg);
            let form = self.rng.pick(&forms);
            let mut word = self
                .instance(form, index, &[], true)
                .expect("register exit forms are admitted");
            if self.rng.chance(700) {
                // Mostly the plain `ret`/`br x30`/`blr x30` shape.
                let insn = form.decode(word).expect("instance decodes as its form");
                let field = form
                    .fields
                    .iter()
                    .find(|field| matches!(field.kind, FieldKind::Reg { .. }))
                    .expect("register exit has a register field");
                word = encode(
                    insn.set_reg(field.spec.name, A64Reg::x(30))
                        .expect("register exit field accepts x30"),
                );
            }
            Pending::Word(word)
        };
        self.push(slot, None);
    }

    fn in_any_loop(&self, index: usize) -> bool {
        self.loops
            .iter()
            .any(|span| span.head <= index && index <= span.back)
    }

    /// Forward targets never enter a loop from outside (the counter would be
    /// uninitialized) and never skip a loop's decrement from inside it.
    fn forward_allowed(&self, from: usize, to: usize) -> bool {
        match self.owner[from] {
            Some(loop_id) => {
                let span = &self.loops[loop_id];
                to <= span.dec || (to > span.back && !self.in_any_loop(to))
            }
            None => !self.in_any_loop(to),
        }
    }

    fn resolve_targets(&mut self) {
        let len = self.slots.len();
        for index in 0..len {
            let Pending::Branch { target: None, .. } = self.slots[index] else {
                continue;
            };
            let target = if self.rng.chance(BACKWARD_PER_MILLE) {
                self.rng.below(index as u64 + 1) as usize
            } else {
                // `len` is the first PC past the text: an `Unreadable` exit.
                let candidates = (index + 1..=len)
                    .filter(|&to| self.forward_allowed(index, to))
                    .collect::<Vec<_>>();
                assert!(
                    !candidates.is_empty(),
                    "branch at slot {index} has no forward target"
                );
                // Biased toward near targets.
                let pick = self
                    .rng
                    .below(candidates.len() as u64)
                    .min(self.rng.below(candidates.len() as u64));
                candidates[pick as usize]
            };
            if let Pending::Branch { target: slot, .. } = &mut self.slots[index] {
                *slot = Some(target);
            }
        }
    }
}

fn with_sp(forbid: &[u8]) -> Vec<u8> {
    let mut regs = forbid.to_vec();
    regs.push(31);
    regs
}

fn field_mask(width: u8) -> u32 {
    if width >= 32 {
        u32::MAX
    } else {
        (1 << width) - 1
    }
}

fn encode(insn: A64Insn) -> u32 {
    insn.encode()
        .unwrap_or_else(|err| panic!("{} does not encode: {err:?}", insn.key()))
}
