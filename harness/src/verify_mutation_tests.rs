//! Mutation suite for the independent verifier (V3).
//!
//! Every fixture fragment is first accepted as the translator emitted it; then each
//! deterministic mutation class below is applied at every applicable site and must
//! be rejected (the G1 gate: 100%). A random-word class replaces random body words
//! with random 32-bit values: each result must be rejected, or be provably benign
//! (a pure register ALU word, or a direct branch the verifier's own target rule
//! admits); anything else fails the test.

use std::collections::BTreeMap;

use crate::asm_fixture::CompiledCase;
use crate::asm_fixture_tests::run_every_case;
use crate::shared::abi::{
    EPILOGUE_OFFSET, PROLOGUE_LEN_BYTES, REG_VIRT_SCRATCH_GPR_START, RUNTIME_FRAME_BUDGET_OFFSET,
    RUNTIME_FRAME_PT_REGS_PTR_OFFSET, RUNTIME_FRAME_SIZE_BYTES,
};
use crate::shared::arm64::ergo::{
    ldst64_offset, ldstpair64_offset, mem_off, mem_post, mem_pre, scaled_simm, scaled_uimm, simm,
    sp, uimm, w, x,
};
use crate::shared::arm64::{A64Insn, A64Mem, A64OperandRole, A64Reg, A64Reg31Mode};
use crate::shared::verify::{verify_fragment, VerifyRule, BODY_OFFSET};
use crate::{compile_fixture_fragment, encode_fragment, fixture_state, FragmentTables};

/// The budget check's scratch register (the prologue's budget init uses it too).
const BUDGET_REG: u8 = REG_VIRT_SCRATCH_GPR_START;

/// Words outside the generated subset (test-only raw encodings).
const FOREIGN_WORDS: &[(&str, u32)] = &[
    ("msr tpidr_el0, x0", 0xd51b_d040),
    ("msr daifset, #0xf", 0xd503_43ff),
    ("hvc #0", 0xd400_0002),
    ("smc #0", 0xd400_0003),
    ("brk #0", 0xd420_0000),
    ("hlt #0", 0xd440_0000),
    ("eret", 0xd69f_03e0),
    ("dc civac, x0", 0xd50b_7e20),
    ("ic ivau, x0", 0xd50b_7520),
    ("ldxr x0, [x1]", 0xc85f_7c20),
    ("stxr w2, x0, [x1]", 0xc802_7c20),
    ("ldaxr w0, [x1]", 0x885f_fc20),
    ("stlxr w2, w0, [x1]", 0x8802_fc20),
    ("casp x0, x1, x2, x3, [x4]", 0x4820_7c82),
    ("swpp x0, x1, [x2] (LSE128)", 0x1921_8040),
    ("msr uao, #1", 0xd500_417f),
    ("msr spsel, #0", 0xd500_40bf),
    ("msr daifclr, #2", 0xd503_42ff),
    ("ldapr x0, [x1], #8 (LRCPC3)", 0xd9c0_0820),
    ("stlr x0, [x1, #-8]! (LRCPC3)", 0xd980_0820),
    ("ldapur x0, [x1, #8] (LRCPC2)", 0xd940_8020),
    ("ldr q0, [x1]", 0x3dc0_0020),
    ("ldr d0, [x1, #8]", 0xfd40_0420),
    ("ldr q0, <literal>", 0x9c00_0000),
    ("ldnp x0, x1, [x2]", 0xa840_0440),
    ("prfum pldl1keep, [x0, #1]", 0xf880_1000),
    ("rprfm pldkeep, x22, [x30]", 0xf8b6_4bd8),
    // Register offset with a sub-word index: matches the diagram, UNDEFINED.
    ("ldr x0, [x1, w2, uxtb]", 0xf862_0820),
];

/// Barrier-like and hint/system words next to the allowlisted DMB/DSB/ISB (A7c):
/// none of them is in the subset.
const BARRIER_LIKE_WORDS: &[(&str, u32)] = &[
    ("dsb ishnxs", 0xd503_3a3f),
    ("sb", 0xd503_30ff),
    ("clrex", 0xd503_3f5f),
    ("wfe", 0xd503_205f),
    ("wfi", 0xd503_207f),
    ("yield", 0xd503_203f),
    ("esb", 0xd503_221f),
];

/// Hint-space words next to BTI (A7d): pointer authentication must never run at
/// EL1 with the kernel's keys, and the other hints are not in the subset. None of
/// them decodes (the BTI form fixes CRm = 0100 and op2<0> = 0).
const HINT_WORDS: &[(&str, u32)] = &[
    ("paciasp", 0xd503_233f),
    ("autiasp", 0xd503_23bf),
    ("pacibsp", 0xd503_237f),
    ("autibsp", 0xd503_23ff),
    ("paciaz", 0xd503_231f),
    ("xpaclri", 0xd503_20ff),
    ("sev", 0xd503_209f),
    ("csdb", 0xd503_229f),
    ("hint #0x21", 0xd503_243f),
    ("hint #0x27", 0xd503_24ff),
    ("chkfeat x16", 0xd503_251f),
];

/// BTI, every target (A7d). Translation rephrases it to `NOP`, so it is a
/// user-only form: rejected anywhere in a fragment.
const BTI_WORDS: &[(&str, u32)] = &[
    ("bti", 0xd503_241f),
    ("bti c", 0xd503_245f),
    ("bti j", 0xd503_249f),
    ("bti jc", 0xd503_24df),
];

/// Acquire/release user forms of the subset (A7c). Translation lowers them to
/// fenced `LDTR*`/`STTR*`, so each is rejected anywhere in a fragment.
const ACQ_REL_WORDS: &[(&str, u32)] = &[
    ("ldar x0, [x1]", 0xc8df_fc20),
    ("stlr w0, [x1]", 0x889f_fc20),
    ("ldarb w0, [sp]", 0x08df_ffe0),
    ("stlrh w3, [x4]", 0x489f_fc83),
    ("ldapr w5, [x6]", 0xb8bf_c0c5),
    ("ldaprh w7, [x8]", 0x78bf_c107),
];

/// User-code memory forms of the subset (A7b). Translation only lowers them, so
/// each is rejected anywhere in a fragment, even on runtime memory.
const USER_ONLY_WORDS: &[(&str, u32)] = &[
    ("prfm pldl1keep, [x1]", 0xf980_0020),
    ("prfm pldl1keep, <literal>", 0xd800_0020),
    ("prfm pldl2strm, [x0, x1, lsl #3]", 0xf8a1_7803),
    ("ldur x0, [x1, #-8]", 0xf85f_8020),
    ("sturb w0, [sp, #16]", 0x3801_03e0),
    ("ldr x0, [x1, x2]", 0xf862_6820),
    ("str x0, [sp, x1, lsl #3]", 0xf821_7be0),
    ("ldrb w0, [x1, x2, lsl #0]", 0x3862_7820),
    ("ldr x0, <literal>", 0x5800_0000),
    ("ldrsw x0, <literal>", 0x9800_0000),
    ("ldrb w0, [sp, #16]", 0x3940_43e0),
    ("ldrsh x0, [x1, #2]", 0x7980_0420),
    ("ldrsw x0, [sp, #16]", 0xb980_13e0),
    ("strh w0, [x1], #2", 0x7800_2420),
    ("ldp w0, w1, [sp, #16]", 0x2942_07e0),
    ("stp wzr, wzr, [sp, #16]", 0x2902_7fff),
    ("ldpsw x0, x1, [x2]", 0x6940_0440),
];

/// LSE atomics of the subset (A8): allowed only as the atomic of an exact PAN
/// window, so each is rejected anywhere else (its window's own atomic position is
/// skipped: another atomic on the same base there is not a violation).
const ATOMIC_WORDS: &[(&str, u32)] = &[
    ("ldadd x0, x1, [x2]", 0xf820_0041),
    ("ldaddal x1, x2, [x3]", 0xf8e1_0062),
    ("stclr w1, [x3]", 0xb821_107f),
    ("swpab w1, w2, [sp]", 0x38a1_83e2),
    ("casalh w1, w2, [x3]", 0x48e1_fc62),
    ("casa x1, x2, [x3]", 0xc8e1_7c62),
    ("ldsmaxa x1, x2, [x12]", 0xf8a1_4182),
];

/// `MSR (immediate)` of PSTATE.PAN (A8): `#0` only as a window start, `#1` only as
/// a window end or a PAN stub's first word, any other immediate never.
const MSR_PAN_WORDS: &[(&str, u32)] = &[
    ("msr pan, #0", 0xd500_409f),
    ("msr pan, #1", 0xd500_419f),
    ("msr pan, #2", 0xd500_429f),
    ("msr pan, #15", 0xd500_4f9f),
];

/// Unprivileged forms beyond `LDTR`/`STTR` (A7b), for insertion without a
/// fault-site entry.
const UNPRIVILEGED_WORDS: &[(&str, u32)] = &[
    ("ldtrb w0, [x1]", 0x3840_0820),
    ("ldtrsh x0, [x1, #-2]", 0x789f_e820),
    ("ldtrsw x0, [x1, #4]", 0xb880_4820),
    ("sttrh w0, [x1]", 0x7800_0820),
];

#[derive(Default)]
struct ClassResult {
    total: usize,
    rejected: usize,
    rules: BTreeMap<String, usize>,
    /// First few accepted mutations, for the failure message.
    escapes: Vec<String>,
}

#[derive(Default)]
struct RandomResult {
    total: usize,
    rejected: usize,
    benign_alu: usize,
    in_fragment_branch: usize,
    /// An offset-form runtime load/store the verifier admitted: rule 3 proved it
    /// stays in the frame's user-state slots or `pt_regs` `regs[]`/`sp`.
    in_bounds_runtime_access: usize,
    escapes: Vec<String>,
}

struct Fixture {
    name: String,
    words: Vec<u32>,
    tables: FragmentTables,
}

impl Fixture {
    fn body(&self) -> std::ops::Range<usize> {
        BODY_OFFSET / 4..self.words.len()
    }

    fn decoded(&self, index: usize) -> Option<A64Insn> {
        decode(self.words[index])
    }
}

fn decode(word: u32) -> Option<A64Insn> {
    A64Insn::decode(word).filter(|insn| !insn.is_decode_undefined())
}

fn enc(insn: A64Insn) -> u32 {
    insn.encode()
        .unwrap_or_else(|err| panic!("encode {}: {err:?}", insn.key()))
}

fn bytes(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn verify(words: &[u32], tables: &FragmentTables) -> Result<(), VerifyRule> {
    let code = bytes(words);
    verify_fragment(&tables.input(&code)).map_err(|err| err.rule)
}

fn rule_name(rule: VerifyRule) -> String {
    let debug = format!("{rule:?}");
    debug
        .split([' ', '{'])
        .next()
        .unwrap_or_default()
        .to_string()
}

struct Suite {
    classes: BTreeMap<&'static str, ClassResult>,
    random: RandomResult,
    fragments: usize,
    body_words: usize,
}

impl Suite {
    fn expect_reject(
        &mut self,
        class: &'static str,
        fixture: &Fixture,
        what: String,
        words: &[u32],
        tables: &FragmentTables,
    ) {
        let result = self.classes.entry(class).or_default();
        result.total += 1;
        match verify(words, tables) {
            Err(rule) => {
                result.rejected += 1;
                *result.rules.entry(rule_name(rule)).or_default() += 1;
            }
            Ok(()) if result.escapes.len() < 5 => {
                result.escapes.push(format!("{}: {what}", fixture.name))
            }
            Ok(()) => {}
        }
    }

    /// Replaces body word `index` with `word`.
    fn replace(
        &mut self,
        class: &'static str,
        fixture: &Fixture,
        index: usize,
        word: u32,
        what: &str,
    ) {
        let mut words = fixture.words.clone();
        words[index] = word;
        self.expect_reject(
            class,
            fixture,
            format!("{what} at {:#x}", index * 4),
            &words,
            &fixture.tables,
        );
    }

    fn replace_everywhere(
        &mut self,
        class: &'static str,
        fixture: &Fixture,
        word: u32,
        what: &str,
    ) {
        for index in fixture.body() {
            self.replace(class, fixture, index, word, what);
        }
    }

    fn run(&mut self, fixture: &Fixture) {
        assert_eq!(
            verify(&fixture.words, &fixture.tables),
            Ok(()),
            "{}: translator output rejected",
            fixture.name
        );
        self.fragments += 1;
        self.body_words += fixture.body().len();

        self.unprivileged_to_plain(fixture);
        self.branches_out(fixture);
        self.branches_into_stubs(fixture);
        self.inserted_words(fixture);
        self.wrapper_corruption(fixture);
        self.fault_table(fixture);
        self.sp_and_fp_writes(fixture);
        self.runtime_accesses(fixture);
        self.end_and_entries(fixture);
        self.budget_checks(fixture);
        self.pan_windows_checks(fixture);
        self.random_words(fixture);
    }

    /// Every `LDTR*`/`STTR*` turned into the plain user form of the same size and
    /// extension (`LDTRB` -> `LDRB`, ...): the scaled immediate form (offset 0 when
    /// the unscaled offset has no scaled form) and the unscaled `LDUR*`/`STUR*` form
    /// with the identical offset. Table intact, and with the site dropped.
    fn unprivileged_to_plain(&mut self, fixture: &Fixture) {
        for index in fixture.body() {
            let Some(insn) = fixture.decoded(index) else {
                continue;
            };
            let Some((class, plain, unscaled)) = plain_forms(insn) else {
                continue;
            };
            for (class, plain) in [(class, plain), ("LDTR*/STTR* -> LDUR*/STUR*", unscaled)] {
                let word = enc(plain);
                self.replace(class, fixture, index, word, plain.key());

                let mut words = fixture.words.clone();
                words[index] = word;
                let mut tables = clone_tables(&fixture.tables);
                tables
                    .fault_sites
                    .retain(|site| site.access_offset != index * 4);
                self.expect_reject(
                    "LDTR*/STTR* -> plain form, site dropped",
                    fixture,
                    format!("{} at {:#x}", plain.key(), index * 4),
                    &words,
                    &tables,
                );
            }
        }
    }

    /// Every direct branch retargeted outside the fragment, into the prologue, or
    /// into the epilogue past its first word.
    fn branches_out(&mut self, fixture: &Fixture) {
        let len = (fixture.words.len() * 4) as i64;
        let targets = [
            -8,
            0,
            4,
            (PROLOGUE_LEN_BYTES - 4) as i64,
            EPILOGUE_OFFSET as i64 + 4,
            BODY_OFFSET as i64 - 4,
            len,
            len + 0x1000,
        ];
        for index in fixture.body() {
            let Some(insn) = fixture.decoded(index) else {
                continue;
            };
            let Some((field, scale, bits)) = branch_role(insn) else {
                continue;
            };
            if matches!(insn, A64Insn::BlBlOnlyBranchImm { .. }) {
                continue;
            }
            for target in targets {
                let delta = target - (index * 4) as i64;
                let encoded = ((delta >> scale) as u32) & ((1 << bits) - 1);
                let Ok(moved) = insn.set_branch_target_imm(field, encoded) else {
                    continue;
                };
                let class = if (0..len).contains(&target) {
                    "branch -> prologue / epilogue middle"
                } else {
                    "branch -> outside fragment"
                };
                self.replace(
                    class,
                    fixture,
                    index,
                    enc(moved),
                    &format!("{} -> {target:#x}", insn.key()),
                );
            }
        }
    }

    /// Every direct branch retargeted to the second word of each fault stub (inside
    /// an exit group, in the cold region).
    fn branches_into_stubs(&mut self, fixture: &Fixture) {
        let mut stubs: Vec<usize> = fixture
            .tables
            .fault_sites
            .iter()
            .map(|site| site.stub_offset)
            .collect();
        stubs.sort_unstable();
        stubs.dedup();
        for index in fixture.body() {
            let Some(insn) = fixture.decoded(index) else {
                continue;
            };
            let Some((field, scale, bits)) = branch_role(insn) else {
                continue;
            };
            for stub in &stubs {
                let target = (stub + 4) as i64;
                let delta = target - (index * 4) as i64;
                let encoded = ((delta >> scale) as u32) & ((1 << bits) - 1);
                let Ok(moved) = insn.set_branch_target_imm(field, encoded) else {
                    continue;
                };
                self.replace(
                    "branch -> middle of an exit group",
                    fixture,
                    index,
                    enc(moved),
                    &format!("{} -> {target:#x}", insn.key()),
                );
            }
        }
    }

    fn inserted_words(&mut self, fixture: &Fixture) {
        let control = [
            (
                "bl",
                A64Insn::BlBlOnlyBranchImm {
                    imm26: scaled_simm(1, 26, 2),
                },
            ),
            ("blr x0", A64Insn::BlrBlr64BranchReg { rn: x(0) }),
            ("br x0", A64Insn::BrBr64BranchReg { rn: x(0) }),
            ("ret", A64Insn::RetRet64rBranchReg { rn: x(30) }),
        ];
        for (what, insn) in control {
            self.replace_everywhere("insert BL/BLR/BR/RET", fixture, enc(insn), what);
        }
        self.replace_everywhere(
            "insert SVC",
            fixture,
            enc(A64Insn::SvcSvcExException { imm16: uimm(0, 16) }),
            "svc #0",
        );
        for (what, word) in FOREIGN_WORDS {
            self.replace_everywhere(
                "insert system / exclusive / SIMD / other non-subset",
                fixture,
                *word,
                what,
            );
        }
        for (what, word) in BARRIER_LIKE_WORDS {
            self.replace_everywhere(
                "insert non-allowlisted barrier-like system op (A7c)",
                fixture,
                *word,
                what,
            );
        }
        for (what, word) in HINT_WORDS {
            self.replace_everywhere("insert non-subset hint / PAC (A7d)", fixture, *word, what);
        }
        for (what, word) in USER_ONLY_WORDS {
            self.replace_everywhere("insert user-only memory form (A7b)", fixture, *word, what);
        }
        for (what, word) in BTI_WORDS {
            self.replace_everywhere("insert BTI (A7d)", fixture, *word, what);
        }
        for (what, word) in ACQ_REL_WORDS {
            self.replace_everywhere("insert acquire/release user form (A7c)", fixture, *word, what);
        }
        // A user access where the table has no entry. (Swapping one user access for
        // another at a fault site is not a violation, so those words are skipped.)
        for (what, word) in UNPRIVILEGED_WORDS {
            for index in fixture.body() {
                if fixture
                    .tables
                    .fault_sites
                    .iter()
                    .any(|site| site.access_offset == index * 4)
                {
                    continue;
                }
                self.replace(
                    "insert LDTR*/STTR* without a fault site",
                    fixture,
                    index,
                    *word,
                    what,
                );
            }
        }
        for insn in [
            A64Insn::AdrAdrOnlyPcreladdr {
                immlo: uimm(0, 2),
                immhi: uimm(0, 19),
                rd: x(0),
            },
            A64Insn::AdrpAdrpOnlyPcreladdr {
                immlo: uimm(0, 2),
                immhi: uimm(0, 19),
                rd: x(0),
            },
        ] {
            self.replace_everywhere("insert ADR/ADRP", fixture, enc(insn), insn.key());
        }
    }

    fn wrapper_corruption(&mut self, fixture: &Fixture) {
        for index in 0..BODY_OFFSET / 4 {
            for bit in [0, 5, 12, 22] {
                let mut words = fixture.words.clone();
                words[index] ^= 1 << bit;
                self.expect_reject(
                    "prologue/epilogue word corrupted",
                    fixture,
                    format!("bit {bit} of word {:#x}", index * 4),
                    &words,
                    &fixture.tables,
                );
            }
        }
    }

    fn fault_table(&mut self, fixture: &Fixture) {
        let len = fixture.words.len() * 4;
        for (position, site) in fixture.tables.fault_sites.iter().enumerate() {
            let mut tables = clone_tables(&fixture.tables);
            tables.fault_sites.remove(position);
            self.expect_reject(
                "fault site dropped",
                fixture,
                format!("site {:#x}", site.access_offset),
                &fixture.words,
                &tables,
            );

            for stub in [
                site.access_offset,
                site.stub_offset + 4,
                0,
                EPILOGUE_OFFSET,
                BODY_OFFSET,
                len,
                site.stub_offset + 2,
            ] {
                let mut tables = clone_tables(&fixture.tables);
                tables.fault_sites[position].stub_offset = stub;
                self.expect_reject(
                    "fault site -> non-stub",
                    fixture,
                    format!("site {:#x} stub {stub:#x}", site.access_offset),
                    &fixture.words,
                    &tables,
                );
            }

            for access in [
                site.access_offset + 4,
                site.access_offset - 4,
                site.stub_offset,
            ] {
                let mut tables = clone_tables(&fixture.tables);
                tables.fault_sites[position].access_offset = access;
                self.expect_reject(
                    "fault site -> non-access",
                    fixture,
                    format!("site {:#x} moved to {access:#x}", site.access_offset),
                    &fixture.words,
                    &tables,
                );
            }
        }
    }

    fn sp_and_fp_writes(&mut self, fixture: &Fixture) {
        let sp_writes = [
            (
                "mov sp, x0",
                A64Insn::AddAddsubImmAdd64AddsubImm {
                    sh: 0,
                    imm12: uimm(0, 12),
                    rn: A64Reg::x_sp(0),
                    rd: sp(),
                },
            ),
            (
                "add sp, sp, #16",
                A64Insn::AddAddsubImmAdd64AddsubImm {
                    sh: 0,
                    imm12: uimm(16, 12),
                    rn: sp(),
                    rd: sp(),
                },
            ),
            (
                "and sp, x0, #0xfffffffffffffff0",
                A64Insn::AndLogImmAnd64LogImm {
                    n: 1,
                    immr: uimm(60, 6),
                    imms: uimm(59, 6),
                    rn: x(0),
                    rd: sp(),
                },
            ),
            (
                "str x0, [sp, #-16]!",
                A64Insn::StrImmGenStr64LdstImmpre {
                    rt: x(0),
                    mem: mem_pre(sp(), simm(0x1f0, 9)),
                },
            ),
            (
                "ldp x0, x1, [sp], #16",
                A64Insn::LdpGenLdp64LdstpairPost {
                    rt2: x(1),
                    rt: x(0),
                    mem: mem_post(sp(), ldstpair64_offset(16)),
                },
            ),
        ];
        for (what, insn) in sp_writes {
            self.replace_everywhere("SP write", fixture, enc(insn), what);
        }
        let fp_writes = [
            (
                "mov x29, x0",
                A64Insn::OrrLogShiftOrr64LogShift {
                    shift: 0,
                    rm: x(0),
                    imm6: uimm(0, 6),
                    rn: x(31),
                    rd: x(29),
                },
            ),
            (
                "movz w29, #0",
                A64Insn::MovzMovz32Movewide {
                    hw: 0,
                    imm16: uimm(0, 16),
                    rd: w(29),
                },
            ),
        ];
        for (what, insn) in fp_writes {
            self.replace_everywhere("x29 write", fixture, enc(insn), what);
        }
    }

    fn runtime_accesses(&mut self, fixture: &Fixture) {
        let plain = [
            ("ldr x0, [x5]", ldr64(0, A64Reg::x_sp(5), 0)),
            ("str x0, [x6, #8]", str64(0, A64Reg::x_sp(6), 8)),
            (
                "str w0, [x7]",
                A64Insn::StrImmGenStr32LdstPos {
                    rt: w(0),
                    mem: mem_off(A64Reg::x_sp(7), scaled_uimm(0, 12, 2)),
                },
            ),
            (
                "ldp x0, x1, [x8]",
                A64Insn::LdpGenLdp64LdstpairOff {
                    rt2: x(1),
                    rt: x(0),
                    mem: mem_off(A64Reg::x_sp(8), ldstpair64_offset(0)),
                },
            ),
        ];
        for (what, insn) in plain {
            self.replace_everywhere("plain LDR/STR, non-frame base", fixture, enc(insn), what);
        }

        let frame = [
            ("ldr x0, [sp] (caller x29)", ldr64(0, sp(), 0)),
            ("str x0, [sp, #8] (return address)", str64(0, sp(), 8)),
            ("str x0, [sp, #80] (entry address)", str64(0, sp(), 80)),
            ("ldr x0, [sp, #88] (caller x18)", ldr64(0, sp(), 88)),
            ("str x0, [sp, #168] (caller x28)", str64(0, sp(), 168)),
            (
                "str x0, [sp, #176] (pt_regs pointer)",
                str64(0, sp(), RUNTIME_FRAME_PT_REGS_PTR_OFFSET),
            ),
            (
                "ldr x0, [sp, #184] (extra-params pointer)",
                ldr64(0, sp(), 184),
            ),
            ("str x0, [sp, #200] (padding)", str64(0, sp(), 200)),
            (
                "str x0, [sp, #208] (caller frame)",
                str64(0, sp(), RUNTIME_FRAME_SIZE_BYTES),
            ),
            (
                "ldp x0, x1, [sp, #72] (straddles entry slot)",
                A64Insn::LdpGenLdp64LdstpairOff {
                    rt2: x(1),
                    rt: x(0),
                    mem: mem_off(sp(), ldstpair64_offset(72)),
                },
            ),
            (
                "ldp x0, x1, [sp, #-16]",
                A64Insn::LdpGenLdp64LdstpairOff {
                    rt2: x(1),
                    rt: x(0),
                    mem: mem_off(sp(), ldstpair64_offset(-16)),
                },
            ),
        ];
        for (what, insn) in frame {
            self.replace_everywhere("frame access out of range", fixture, enc(insn), what);
        }

        // `ldr x12, [sp, #PT_REGS_PTR]` then an access past regs[] + sp.
        let load = enc(ldr64(12, sp(), RUNTIME_FRAME_PT_REGS_PTR_OFFSET));
        let beyond = [
            ("str x0, [x12, #256] (pc)", str64(0, A64Reg::x_sp(12), 256)),
            (
                "str x0, [x12, #264] (pstate)",
                str64(0, A64Reg::x_sp(12), 264),
            ),
            ("ldr x0, [x12, #272]", ldr64(0, A64Reg::x_sp(12), 272)),
        ];
        for (what, insn) in beyond {
            for index in fixture.body().skip(1) {
                let mut words = fixture.words.clone();
                words[index - 1] = load;
                words[index] = enc(insn);
                self.expect_reject(
                    "pt_regs access out of range",
                    fixture,
                    format!("{what} at {:#x}", index * 4),
                    &words,
                    &fixture.tables,
                );
            }
        }
    }

    /// Budget checks found on the bytes: `(check start, back-edge index)`. The
    /// check is `ldr x12, [sp, #192]` + 3 words, then scratch fill loads, then the
    /// back-edge.
    fn budget_guards(fixture: &Fixture) -> Vec<(usize, usize)> {
        let counter_load = enc(ldr64(BUDGET_REG, sp(), RUNTIME_FRAME_BUDGET_OFFSET));
        let mut guards = Vec::new();
        for start in fixture.body() {
            if fixture.words[start] != counter_load {
                continue;
            }
            let mut branch = start + 4;
            while fixture.decoded(branch).is_some_and(|insn| {
                matches!(insn, A64Insn::LdrImmGenLdr64LdstPos { rt, mem: A64Mem::Offset { base, .. } }
                    if (12..=15).contains(&rt.enc()) && base.enc() == 31)
            }) {
                branch += 1;
            }
            guards.push((start, branch));
        }
        guards
    }

    fn budget_checks(&mut self, fixture: &Fixture) {
        let guards = Self::budget_guards(fixture);
        let nop = enc(A64Insn::NopNopHiHints {});
        for &(start, branch) in &guards {
            // Dropped: the whole check, or any one of its words.
            let mut words = fixture.words.clone();
            words[start..start + 4].fill(nop);
            self.expect_reject(
                "budget check dropped",
                fixture,
                format!("check at {:#x}", start * 4),
                &words,
                &fixture.tables,
            );
            for word in start..start + 4 {
                self.replace(
                    "budget check dropped",
                    fixture,
                    word,
                    nop,
                    "nop over one word",
                );
            }

            // `cbz` retargeted: backward, onto the back-edge, into the stub, to the
            // epilogue, outside the fragment.
            let cbz = start + 3;
            let Some(A64Insn::CbzCbz64Compbranch { imm19, rt }) = fixture.decoded(cbz) else {
                panic!(
                    "{}: budget check at {:#x} has no cbz",
                    fixture.name,
                    start * 4
                );
            };
            let stub = (cbz * 4) as i64 + imm19.value();
            let len = (fixture.words.len() * 4) as i64;
            for target in [
                BODY_OFFSET as i64,
                (start * 4) as i64,
                (branch * 4) as i64,
                stub + 4,
                EPILOGUE_OFFSET as i64,
                len,
            ] {
                let delta = target - (cbz * 4) as i64;
                let moved = A64Insn::CbzCbz64Compbranch {
                    imm19: scaled_simm(((delta >> 2) as u32) & 0x7ffff, 19, 2),
                    rt,
                };
                self.replace(
                    "budget cbz retargeted",
                    fixture,
                    cbz,
                    enc(moved),
                    &format!("-> {target:#x}"),
                );
            }

            // Decrement altered: #0 (no progress), #2, #4095, `#1, lsl #12`, `add`.
            let s = A64Reg::x_sp(BUDGET_REG);
            let subs = [
                A64Insn::SubAddsubImmSub64AddsubImm {
                    sh: 0,
                    imm12: uimm(0, 12),
                    rn: s,
                    rd: s,
                },
                A64Insn::SubAddsubImmSub64AddsubImm {
                    sh: 0,
                    imm12: uimm(2, 12),
                    rn: s,
                    rd: s,
                },
                A64Insn::SubAddsubImmSub64AddsubImm {
                    sh: 0,
                    imm12: uimm(4095, 12),
                    rn: s,
                    rd: s,
                },
                A64Insn::SubAddsubImmSub64AddsubImm {
                    sh: 1,
                    imm12: uimm(1, 12),
                    rn: s,
                    rd: s,
                },
                A64Insn::AddAddsubImmAdd64AddsubImm {
                    sh: 0,
                    imm12: uimm(1, 12),
                    rn: s,
                    rd: s,
                },
                A64Insn::SubAddsubImmSub64AddsubImm {
                    sh: 0,
                    imm12: uimm(1, 12),
                    rn: s,
                    rd: A64Reg::x_sp(BUDGET_REG + 1),
                },
            ];
            for sub in subs {
                self.replace(
                    "budget sub amount altered",
                    fixture,
                    start + 1,
                    enc(sub),
                    &format!("{sub:?}"),
                );
            }

            // Bypass: an entry past the check's first word.
            for inner in start + 1..=branch {
                let mut tables = clone_tables(&fixture.tables);
                tables.entry_offsets.push(inner * 4);
                self.expect_reject(
                    "budget check bypassed by an entry",
                    fixture,
                    format!("entry {:#x}", inner * 4),
                    &fixture.words,
                    &tables,
                );
            }
        }

        // The counter written anywhere but the check's own store.
        let own_stores: Vec<usize> = guards.iter().map(|&(start, _)| start + 2).collect();
        let writes = [
            (
                "str x12, [sp, #192]",
                str64(BUDGET_REG, sp(), RUNTIME_FRAME_BUDGET_OFFSET),
            ),
            (
                "str xzr, [sp, #192]",
                str64(31, sp(), RUNTIME_FRAME_BUDGET_OFFSET),
            ),
            (
                "str w12, [sp, #192]",
                A64Insn::StrImmGenStr32LdstPos {
                    rt: w(BUDGET_REG),
                    mem: mem_off(sp(), scaled_uimm(RUNTIME_FRAME_BUDGET_OFFSET / 4, 12, 2)),
                },
            ),
            (
                "stp x12, x13, [sp, #192]",
                A64Insn::StpGenStp64LdstpairOff {
                    rt2: x(BUDGET_REG + 1),
                    rt: x(BUDGET_REG),
                    mem: mem_off(sp(), ldstpair64_offset(RUNTIME_FRAME_BUDGET_OFFSET as i32)),
                },
            ),
            (
                "stp x0, x1, [sp, #184]",
                A64Insn::StpGenStp64LdstpairOff {
                    rt2: x(1),
                    rt: x(0),
                    mem: mem_off(sp(), ldstpair64_offset(184)),
                },
            ),
        ];
        for (what, insn) in writes {
            for index in fixture.body().filter(|index| !own_stores.contains(index)) {
                self.replace(
                    "budget slot written elsewhere",
                    fixture,
                    index,
                    enc(insn),
                    what,
                );
            }
        }
    }

    /// PAN windows found on the bytes (A8): the index of each `msr pan, #0`, which
    /// the translator only emits as `ubfx; cbnz <S>; msr pan, #0; <atomic>; msr pan,
    /// #1`, and its PAN stub S.
    fn pan_windows(fixture: &Fixture) -> Vec<(usize, usize)> {
        fixture
            .body()
            .filter(|&index| fixture.words[index] == enc(msr_pan(0)))
            .map(|clear| {
                let Some(A64Insn::CbnzCbnz64Compbranch { imm19, .. }) = fixture.decoded(clear - 1)
                else {
                    panic!("{}: window at {:#x} has no cbnz", fixture.name, clear * 4);
                };
                let stub = ((clear - 1) as i64 * 4 + imm19.value()) as usize / 4;
                (clear, stub)
            })
            .collect()
    }

    /// Every A8 mutation class, at every window of the fragment, plus the
    /// everywhere-else insertions of atomics and `msr pan`.
    fn pan_windows_checks(&mut self, fixture: &Fixture) {
        let windows = Self::pan_windows(fixture);
        let nop = enc(A64Insn::NopNopHiHints {});
        let window_atomics: Vec<usize> = windows.iter().map(|&(clear, _)| clear + 1).collect();
        let pan_stubs: Vec<usize> = windows.iter().map(|&(_, stub)| stub).collect();
        let plain_stubs: Vec<usize> = fixture
            .tables
            .fault_sites
            .iter()
            .map(|site| site.stub_offset / 4)
            .filter(|stub| !pan_stubs.contains(stub))
            .collect();

        for &(clear, stub) in &windows {
            let (ubfx, cbnz, atomic, set) = (clear - 2, clear - 1, clear + 1, clear + 2);
            let Some(A64Insn::UbfmUbfm64mBitfield { rn: sa, rd: sb, .. }) = fixture.decoded(ubfx)
            else {
                panic!("{}: window at {:#x} has no ubfx", fixture.name, clear * 4);
            };
            let at = |index: usize| format!("window at {:#x}, word {:#x}", clear * 4, index * 4);

            // Dropped: either MSR, or the PAN stub's leading MSR.
            for (index, class) in [
                (clear, "PAN window msr pan, #0 dropped"),
                (set, "PAN window msr pan, #1 dropped"),
                (stub, "PAN stub msr pan, #1 dropped"),
            ] {
                self.replace(class, fixture, index, nop, &at(index));
            }

            // Moved: each MSR swapped with a neighbour.
            for (a, b) in [
                (clear, clear - 1),
                (clear, clear + 1),
                (clear, clear - 3),
                (set, set - 1),
                (set, set + 1),
            ] {
                let mut words = fixture.words.clone();
                words.swap(a, b);
                self.expect_reject(
                    "PAN window msr moved",
                    fixture,
                    at(a),
                    &words,
                    &fixture.tables,
                );
            }

            // Widened: one word inserted into each gap of the window. The words
            // before the gap move one word earlier (over the word before the
            // `ubfx`), with the `cbnz` still aimed at S and the atomic's fault site
            // following the atomic, so only the window shape changes.
            let inserts = [
                ("nop", A64Insn::NopNopHiHints {}),
                ("mov sA, x0", mov_reg(sa.enc(), 0)),
                ("add sA, sA, #1", add_imm(sa.enc(), sa.enc(), 1)),
                (
                    "movz sB, #0",
                    A64Insn::MovzMovz64Movewide {
                        hw: 0,
                        imm16: uimm(0, 16),
                        rd: x(sb.enc()),
                    },
                ),
            ];
            for gap in ubfx + 1..=set {
                for (what, insn) in inserts {
                    let mut words = fixture.words.clone();
                    let mut tables = clone_tables(&fixture.tables);
                    for index in ubfx - 1..gap - 1 {
                        words[index] = fixture.words[index + 1];
                    }
                    words[gap - 1] = enc(insn);
                    // The cbnz moved: re-aim it at S.
                    let new_cbnz = if gap > cbnz { cbnz - 1 } else { cbnz };
                    words[new_cbnz] = enc(cbnz_to(new_cbnz, stub, sb.enc()));
                    if gap > atomic {
                        for site in &mut tables.fault_sites {
                            if site.access_offset == atomic * 4 {
                                site.access_offset -= 4;
                            }
                        }
                    }
                    self.expect_reject(
                        "PAN window widened (word inserted)",
                        fixture,
                        format!("{what} before word {:#x}, {}", gap * 4, at(clear)),
                        &words,
                        &tables,
                    );
                }
            }

            // Range check altered: other source / destination register, shift,
            // width, or not a UBFM.
            let other = |reg: u8| if reg == 0 { 1 } else { reg - 1 };
            let checks = [
                (
                    "ubfx from another register",
                    ubfx_insn(other(sa.enc()), sb.enc(), 48, 55),
                ),
                (
                    "ubfx into another register",
                    ubfx_insn(sa.enc(), other(sb.enc()), 48, 55),
                ),
                ("ubfx #47, #8", ubfx_insn(sa.enc(), sb.enc(), 47, 54)),
                ("ubfx #49, #7", ubfx_insn(sa.enc(), sb.enc(), 49, 55)),
                ("ubfx #48, #7", ubfx_insn(sa.enc(), sb.enc(), 48, 54)),
                (
                    "ubfx #48, #16 (lsr #48)",
                    ubfx_insn(sa.enc(), sb.enc(), 48, 63),
                ),
                ("ubfx #56, #8", ubfx_insn(sa.enc(), sb.enc(), 56, 63)),
                ("mov sB, xzr", mov_reg(sb.enc(), 31)),
                (
                    "and sB, sA, #0xff000000000000",
                    A64Insn::AndLogImmAnd64LogImm {
                        n: 1,
                        immr: uimm(16, 6),
                        imms: uimm(7, 6),
                        rn: x(sa.enc()),
                        rd: A64Reg::x_sp(sb.enc()),
                    },
                ),
            ];
            for (what, insn) in checks {
                self.replace("PAN range check altered", fixture, ubfx, enc(insn), what);
            }

            // cbnz retargeted, inverted, on another register.
            let len = fixture.words.len();
            let mut targets = vec![clear, set + 1, stub + 1, BODY_OFFSET / 4, len - 1];
            targets.extend(plain_stubs.iter().copied());
            targets.extend(pan_stubs.iter().copied().filter(|&other| other != stub));
            for target in targets {
                self.replace(
                    "PAN range check cbnz retargeted",
                    fixture,
                    cbnz,
                    enc(cbnz_to(cbnz, target, sb.enc())),
                    &format!("-> {:#x}", target * 4),
                );
            }
            let delta = ((stub as i64 - cbnz as i64) as u32) & 0x7ffff;
            let branches = [
                (
                    "cbz sB (inverted)",
                    A64Insn::CbzCbz64Compbranch {
                        imm19: scaled_simm(delta, 19, 2),
                        rt: x(sb.enc()),
                    },
                ),
                (
                    "cbnz on another register",
                    cbnz_to(cbnz, stub, other(sb.enc())),
                ),
                (
                    "cbnz w (32-bit)",
                    A64Insn::CbnzCbnz32Compbranch {
                        imm19: scaled_simm(delta, 19, 2),
                        rt: w(sb.enc()),
                    },
                ),
                (
                    "tbnz sB, #0",
                    A64Insn::TbnzTbnzOnlyTestbranch {
                        b5: 0,
                        b40: 0,
                        imm14: scaled_simm(delta & 0x3fff, 14, 2),
                        rt: x(sb.enc()),
                    },
                ),
            ];
            for (what, insn) in branches {
                self.replace(
                    "PAN range check cbnz altered",
                    fixture,
                    cbnz,
                    enc(insn),
                    what,
                );
            }

            // Window around something other than an LSE atomic on sA.
            let base = A64Reg::x_sp(sa.enc());
            let others = [
                ("ldr x0, [sA]", ldr64(0, base, 0)),
                ("str x0, [sA]", str64(0, base, 0)),
                (
                    "ldtr x0, [sA]",
                    A64Insn::LdtrLdtr64LdstUnpriv {
                        rt: x(0),
                        mem: mem_off(base, simm(0, 9)),
                    },
                ),
                (
                    "sttr w0, [sA]",
                    A64Insn::SttrSttr32LdstUnpriv {
                        rt: w(0),
                        mem: mem_off(base, simm(0, 9)),
                    },
                ),
                (
                    "ldar x0, [sA]",
                    A64Insn::LdarLdarLr64Ldstord { rn: base, rt: x(0) },
                ),
                ("mov x0, sA", mov_reg(0, sa.enc())),
                ("nop", A64Insn::NopNopHiHints {}),
                (
                    "ldadd x0, x1, [another register]",
                    A64Insn::LdaddLdadd64Memop {
                        rs: x(0),
                        rn: A64Reg::x_sp(other(sa.enc())),
                        rt: x(1),
                    },
                ),
                (
                    "ldadd x0, x1, [sp]",
                    A64Insn::LdaddLdadd64Memop {
                        rs: x(0),
                        rn: sp(),
                        rt: x(1),
                    },
                ),
            ];
            for (what, insn) in others {
                self.replace(
                    "PAN window around a non-atomic / plain access",
                    fixture,
                    atomic,
                    enc(insn),
                    what,
                );
            }

            // The atomic's fault site at a non-PAN stub, at another window's PAN
            // stub, or dropped.
            let position = fixture
                .tables
                .fault_sites
                .iter()
                .position(|site| site.access_offset == atomic * 4)
                .unwrap_or_else(|| panic!("{}: window atomic without a site", fixture.name));
            let mut stubs = plain_stubs.clone();
            stubs.extend(pan_stubs.iter().copied().filter(|&other| other != stub));
            for other in stubs {
                let mut tables = clone_tables(&fixture.tables);
                tables.fault_sites[position].stub_offset = other * 4;
                self.expect_reject(
                    "window fault site -> other stub",
                    fixture,
                    format!("{} -> {:#x}", at(atomic), other * 4),
                    &fixture.words,
                    &tables,
                );
            }

            // Bypass: an entry on the cbnz, either MSR or the atomic.
            for inner in cbnz..=set {
                let mut tables = clone_tables(&fixture.tables);
                tables.entry_offsets.push(inner * 4);
                self.expect_reject(
                    "PAN window entered past its range check",
                    fixture,
                    format!("entry {:#x}", inner * 4),
                    &fixture.words,
                    &tables,
                );
            }
        }

        // Any other LDTR/STTR's fault site pointed at a PAN stub.
        for (position, site) in fixture.tables.fault_sites.iter().enumerate() {
            if window_atomics.contains(&(site.access_offset / 4)) {
                continue;
            }
            for &stub in &pan_stubs {
                let mut tables = clone_tables(&fixture.tables);
                tables.fault_sites[position].stub_offset = stub * 4;
                self.expect_reject(
                    "LDTR/STTR fault site -> PAN stub",
                    fixture,
                    format!("site {:#x} -> {:#x}", site.access_offset, stub * 4),
                    &fixture.words,
                    &tables,
                );
            }
        }

        // Any other direct branch retargeted to a PAN stub.
        for index in fixture.body() {
            if windows.iter().any(|&(clear, _)| index == clear - 1) {
                continue;
            }
            let Some(insn) = fixture.decoded(index) else {
                continue;
            };
            let Some((field, scale, bits)) = branch_role(insn) else {
                continue;
            };
            for &stub in &pan_stubs {
                let delta = (stub as i64 - index as i64) * 4;
                let encoded = ((delta >> scale) as u32) & ((1 << bits) - 1);
                let Ok(moved) = insn.set_branch_target_imm(field, encoded) else {
                    continue;
                };
                self.replace(
                    "branch -> PAN stub",
                    fixture,
                    index,
                    enc(moved),
                    &format!("{} -> {:#x}", insn.key(), stub * 4),
                );
            }
        }

        // `msr pan` and LSE atomics anywhere else.
        for (what, word) in MSR_PAN_WORDS {
            for index in fixture.body() {
                if fixture.words[index] == *word {
                    continue;
                }
                self.replace("insert msr pan elsewhere", fixture, index, *word, what);
            }
        }
        for (what, word) in ATOMIC_WORDS {
            for index in fixture.body() {
                if window_atomics.contains(&index) {
                    continue;
                }
                self.replace(
                    "insert LSE atomic outside a window",
                    fixture,
                    index,
                    *word,
                    what,
                );
            }
        }
    }

    fn end_and_entries(&mut self, fixture: &Fixture) {
        let last = fixture.words.len() - 1;
        let nop = enc(A64Insn::NopNopHiHints {});
        self.replace("falls off the end", fixture, last, nop, "nop");
        let cond = A64Insn::BCondBOnlyCondbranch {
            imm19: scaled_simm(
                (((EPILOGUE_OFFSET as i64 - (last * 4) as i64) >> 2) as u32) & 0x7ffff,
                19,
                2,
            ),
            cond: 0,
        };
        self.replace(
            "falls off the end",
            fixture,
            last,
            enc(cond),
            "b.eq <epilogue>",
        );

        let len = fixture.words.len() * 4;
        let stubs = fixture
            .tables
            .fault_sites
            .iter()
            .map(|site| site.stub_offset);
        for entry in [0, 4, EPILOGUE_OFFSET, BODY_OFFSET - 4, BODY_OFFSET + 2, len]
            .into_iter()
            .chain(stubs)
        {
            let mut tables = clone_tables(&fixture.tables);
            tables.entry_offsets.push(entry);
            self.expect_reject(
                "entry offset outside body / into cold region",
                fixture,
                format!("entry {entry:#x}"),
                &fixture.words,
                &tables,
            );
        }
    }

    fn random_words(&mut self, fixture: &Fixture) {
        const PER_FRAGMENT: usize = 400;
        let body = fixture.body();
        let mut rng = XorShift(0x9e37_79b9_7f4a_7c15 ^ fixture.words.len() as u64);
        for _ in 0..PER_FRAGMENT {
            let index = body.start + (rng.next() as usize) % body.len();
            let word = rng.next() as u32;
            let mut words = fixture.words.clone();
            words[index] = word;
            self.random.total += 1;
            if verify(&words, &fixture.tables).is_err() {
                self.random.rejected += 1;
                continue;
            }
            let insn = decode(word);
            if insn.is_some_and(is_benign_alu) {
                self.random.benign_alu += 1;
            } else if insn.is_some_and(|insn| is_admitted_branch(insn, index, words.len())) {
                self.random.in_fragment_branch += 1;
            } else if insn.is_some_and(is_offset_runtime_access) {
                self.random.in_bounds_runtime_access += 1;
            } else if self.random.escapes.len() < 10 {
                self.random.escapes.push(format!(
                    "{}: {word:#010x} at {:#x} ({:?})",
                    fixture.name,
                    index * 4,
                    insn.map(|insn| insn.key())
                ));
            }
        }
    }
}

/// Benign by the generated metadata alone: no memory, branch or control-flow role,
/// not SVC / ADR / ADRP, and no write to SP or x29.
fn is_benign_alu(insn: A64Insn) -> bool {
    let key = insn.key();
    if key.starts_with("SVC") || key.starts_with("ADR") {
        return false;
    }
    insn.operand_roles().iter().all(|role| match *role {
        A64OperandRole::Memory
        | A64OperandRole::ControlFlow
        | A64OperandRole::BranchTarget { .. }
        | A64OperandRole::MemBase { .. }
        | A64OperandRole::MemOffset { .. } => false,
        A64OperandRole::RegWrite { field, .. } | A64OperandRole::RegReadWrite { field, .. } => {
            insn.get_reg(field).is_some_and(|reg| {
                reg.enc() != 29 && (reg.enc() != 31 || reg.reg31 == A64Reg31Mode::Xzr)
            })
        }
        A64OperandRole::ImplicitRegWrite { reg, .. } => reg != 29 && reg != 31,
        A64OperandRole::RegRead { .. } | A64OperandRole::FlagsRead | A64OperandRole::FlagsWrite => {
            true
        }
    })
}

/// A plain load/store with offset addressing (no writeback) that is neither a
/// user access nor a window atomic: if the verifier admits one, its rule 3
/// placed it in the frame's user-state slots or `pt_regs` user state.
fn is_offset_runtime_access(insn: A64Insn) -> bool {
    insn.accesses_memory()
        && !insn.is_unprivileged_access()
        && insn.lse_atomic().is_none()
        && matches!(insn.mem_operand(), Some(A64Mem::Offset { .. }))
}

/// A non-linking direct branch whose target is the epilogue's first word or a body
/// word: safe by rule 4 even though it is not an ALU op.
fn is_admitted_branch(insn: A64Insn, index: usize, words: usize) -> bool {
    if matches!(insn, A64Insn::BlBlOnlyBranchImm { .. }) {
        return false;
    }
    let Some((field, scale, bits)) = branch_role(insn) else {
        return false;
    };
    let Some(encoded) = insn.branch_target_imm(field) else {
        return false;
    };
    let shift = 64 - bits as u32;
    let delta = (((encoded as i64) << shift) >> shift) << scale;
    let target = (index * 4) as i64 + delta;
    target == EPILOGUE_OFFSET as i64
        || (target >= BODY_OFFSET as i64 && target < (words * 4) as i64)
}

fn branch_role(insn: A64Insn) -> Option<(&'static str, u8, u8)> {
    insn.operand_roles().iter().find_map(|role| match *role {
        A64OperandRole::BranchTarget { field, scale, bits } => Some((field, scale, bits)),
        _ => None,
    })
}

/// For an unprivileged access: (class, scaled plain form, unscaled plain form).
fn plain_forms(insn: A64Insn) -> Option<(&'static str, A64Insn, A64Insn)> {
    use A64Insn as I;
    Some(match insn {
        I::LdtrLdtr64LdstUnpriv { rt, mem } => (
            "LDTR -> LDR",
            I::LdrImmGenLdr64LdstPos {
                rt,
                mem: scaled_offset(mem, 3),
            },
            I::LdurGenLdur64LdstUnscaled { rt, mem },
        ),
        I::LdtrLdtr32LdstUnpriv { rt, mem } => (
            "LDTR -> LDR",
            I::LdrImmGenLdr32LdstPos {
                rt,
                mem: scaled_offset(mem, 2),
            },
            I::LdurGenLdur32LdstUnscaled { rt, mem },
        ),
        I::SttrSttr64LdstUnpriv { rt, mem } => (
            "STTR -> STR",
            I::StrImmGenStr64LdstPos {
                rt,
                mem: scaled_offset(mem, 3),
            },
            I::SturGenStur64LdstUnscaled { rt, mem },
        ),
        I::SttrSttr32LdstUnpriv { rt, mem } => (
            "STTR -> STR",
            I::StrImmGenStr32LdstPos {
                rt,
                mem: scaled_offset(mem, 2),
            },
            I::SturGenStur32LdstUnscaled { rt, mem },
        ),
        I::LdtrbLdtrb32LdstUnpriv { rt, mem } => (
            "LDTRB/H/SB/SH/SW -> LDRB/H/SB/SH/SW",
            I::LdrbImmLdrb32LdstPos {
                rt,
                mem: scaled_offset(mem, 0),
            },
            I::LdurbLdurb32LdstUnscaled { rt, mem },
        ),
        I::LdtrhLdtrh32LdstUnpriv { rt, mem } => (
            "LDTRB/H/SB/SH/SW -> LDRB/H/SB/SH/SW",
            I::LdrhImmLdrh32LdstPos {
                rt,
                mem: scaled_offset(mem, 1),
            },
            I::LdurhLdurh32LdstUnscaled { rt, mem },
        ),
        I::LdtrsbLdtrsb32LdstUnpriv { rt, mem } => (
            "LDTRB/H/SB/SH/SW -> LDRB/H/SB/SH/SW",
            I::LdrsbImmLdrsb32LdstPos {
                rt,
                mem: scaled_offset(mem, 0),
            },
            I::LdursbLdursb32LdstUnscaled { rt, mem },
        ),
        I::LdtrsbLdtrsb64LdstUnpriv { rt, mem } => (
            "LDTRB/H/SB/SH/SW -> LDRB/H/SB/SH/SW",
            I::LdrsbImmLdrsb64LdstPos {
                rt,
                mem: scaled_offset(mem, 0),
            },
            I::LdursbLdursb64LdstUnscaled { rt, mem },
        ),
        I::LdtrshLdtrsh32LdstUnpriv { rt, mem } => (
            "LDTRB/H/SB/SH/SW -> LDRB/H/SB/SH/SW",
            I::LdrshImmLdrsh32LdstPos {
                rt,
                mem: scaled_offset(mem, 1),
            },
            I::LdurshLdursh32LdstUnscaled { rt, mem },
        ),
        I::LdtrshLdtrsh64LdstUnpriv { rt, mem } => (
            "LDTRB/H/SB/SH/SW -> LDRB/H/SB/SH/SW",
            I::LdrshImmLdrsh64LdstPos {
                rt,
                mem: scaled_offset(mem, 1),
            },
            I::LdurshLdursh64LdstUnscaled { rt, mem },
        ),
        I::LdtrswLdtrsw64LdstUnpriv { rt, mem } => (
            "LDTRB/H/SB/SH/SW -> LDRB/H/SB/SH/SW",
            I::LdrswImmLdrsw64LdstPos {
                rt,
                mem: scaled_offset(mem, 2),
            },
            I::LdurswLdursw64LdstUnscaled { rt, mem },
        ),
        I::SttrbSttrb32LdstUnpriv { rt, mem } => (
            "STTRB/H -> STRB/H",
            I::StrbImmStrb32LdstPos {
                rt,
                mem: scaled_offset(mem, 0),
            },
            I::SturbSturb32LdstUnscaled { rt, mem },
        ),
        I::SttrhSttrh32LdstUnpriv { rt, mem } => (
            "STTRB/H -> STRB/H",
            I::StrhImmStrh32LdstPos {
                rt,
                mem: scaled_offset(mem, 1),
            },
            I::SturhSturh32LdstUnscaled { rt, mem },
        ),
        _ => return None,
    })
}

fn scaled_offset(mem: A64Mem, log2: u8) -> A64Mem {
    let value = mem.offset_imm().value();
    let size = 1_i64 << log2;
    let raw = if value >= 0 && value % size == 0 && value / size < 4096 {
        (value / size) as u32
    } else {
        0
    };
    A64Mem::offset(mem.base(), scaled_uimm(raw, 12, log2))
}

fn msr_pan(crm: u8) -> A64Insn {
    A64Insn::MsrImmMsrSiPstate { crm }
}

fn ubfx_insn(rn: u8, rd: u8, immr: u32, imms: u32) -> A64Insn {
    A64Insn::UbfmUbfm64mBitfield {
        immr: uimm(immr, 6),
        imms: uimm(imms, 6),
        rn: x(rn),
        rd: x(rd),
    }
}

/// `cbnz x<rt>` at body word `from` aimed at word `to`.
fn cbnz_to(from: usize, to: usize, rt: u8) -> A64Insn {
    let delta = ((to as i64 - from as i64) as u32) & 0x7ffff;
    A64Insn::CbnzCbnz64Compbranch {
        imm19: scaled_simm(delta, 19, 2),
        rt: x(rt),
    }
}

fn mov_reg(rd: u8, rm: u8) -> A64Insn {
    A64Insn::OrrLogShiftOrr64LogShift {
        shift: 0,
        rm: x(rm),
        imm6: uimm(0, 6),
        rn: x(31),
        rd: x(rd),
    }
}

fn add_imm(rd: u8, rn: u8, imm: u32) -> A64Insn {
    A64Insn::AddAddsubImmAdd64AddsubImm {
        sh: 0,
        imm12: uimm(imm, 12),
        rn: A64Reg::x_sp(rn),
        rd: A64Reg::x_sp(rd),
    }
}

fn ldr64(rt: u8, base: A64Reg, offset: u32) -> A64Insn {
    A64Insn::LdrImmGenLdr64LdstPos {
        rt: x(rt),
        mem: mem_off(base, ldst64_offset(offset)),
    }
}

fn str64(rt: u8, base: A64Reg, offset: u32) -> A64Insn {
    A64Insn::StrImmGenStr64LdstPos {
        rt: x(rt),
        mem: mem_off(base, ldst64_offset(offset)),
    }
}

fn clone_tables(tables: &FragmentTables) -> FragmentTables {
    FragmentTables {
        fault_sites: tables.fault_sites.clone(),
        entry_offsets: tables.entry_offsets.clone(),
    }
}

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn verifier_rejects_every_mutation_of_every_fixture_fragment() {
    let mut suite = Suite {
        classes: BTreeMap::new(),
        random: RandomResult::default(),
        fragments: 0,
        body_words: 0,
    };
    let mut fixtures = Vec::new();
    run_every_case("verify-mutation", &mut |case: &CompiledCase| {
        let fragment = compile_fixture_fragment(
            case.text_base,
            case.text_bytes.clone(),
            case.entry_pc,
            &fixture_state(case.text_base, &case.text_bytes)?,
        )?;
        let code = encode_fragment(&fragment)?;
        fixtures.push(Fixture {
            name: format!("entry {:#x} ({} words)", case.entry_pc, code.len() / 4),
            words: code
                .chunks_exact(4)
                .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
                .collect(),
            tables: FragmentTables::of(&fragment),
        });
        Ok(String::new())
    });
    for fixture in &fixtures {
        suite.run(fixture);
    }

    println!(
        "verifier mutation suite: {} fragments, {} body words",
        suite.fragments, suite.body_words
    );
    println!("| mutation class | rejected | rules |");
    println!("|---|---|---|");
    let mut failures = Vec::new();
    for (class, result) in &suite.classes {
        let rules = result
            .rules
            .iter()
            .map(|(rule, count)| format!("{rule} {count}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "| {class} | {} of {} | {rules} |",
            result.rejected, result.total
        );
        if result.rejected != result.total || result.total == 0 {
            failures.push(format!("{class}: {:?}", result.escapes));
        }
    }
    let random = &suite.random;
    println!(
        "| random body word | rejected {} / benign ALU {} / in-fragment branch {} / in-bounds runtime access {} / other accepted {} of {} | |",
        random.rejected,
        random.benign_alu,
        random.in_fragment_branch,
        random.in_bounds_runtime_access,
        random.escapes.len(),
        random.total
    );
    if !random.escapes.is_empty() {
        failures.push(format!("random words accepted: {:?}", random.escapes));
    }
    assert!(
        failures.is_empty(),
        "verifier escapes:\n{}",
        failures.join("\n")
    );
}

/// The word lists mean what their names say: foreign words do not decode, the
/// user-only and unprivileged words do (so their classes test the classification,
/// not the decoder).
#[test]
fn mutation_word_lists_are_classified_as_named() {
    for (what, word) in FOREIGN_WORDS
        .iter()
        .chain(BARRIER_LIKE_WORDS)
        .chain(HINT_WORDS)
    {
        assert!(decode(*word).is_none(), "{what} decodes");
    }
    for (what, word) in USER_ONLY_WORDS.iter().chain(ACQ_REL_WORDS).chain(BTI_WORDS) {
        let insn = decode(*word).unwrap_or_else(|| panic!("{what} does not decode"));
        assert!(!insn.is_unprivileged_access(), "{what}");
    }
    for (what, word) in ATOMIC_WORDS {
        let insn = decode(*word).unwrap_or_else(|| panic!("{what} does not decode"));
        assert!(insn.lse_atomic().is_some(), "{what}");
    }
    for (what, word) in MSR_PAN_WORDS {
        let insn = decode(*word).unwrap_or_else(|| panic!("{what} does not decode"));
        assert!(insn.msr_pan().is_some(), "{what}");
    }
    for (what, word) in UNPRIVILEGED_WORDS {
        let insn = decode(*word).unwrap_or_else(|| panic!("{what} does not decode"));
        assert!(insn.is_unprivileged_access(), "{what}");
    }
}
