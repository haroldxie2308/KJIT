p='/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/agent-a4b243dcf4b342be4/harness/src/verify_mutation_tests.rs'
s=open(p).read()

def rep(old, new):
    global s
    assert s.count(old) == 1, ("count", s.count(old), old[:90])
    s = s.replace(old, new)

rep('''    dispatch_template_matches, DISPATCH_TEMPLATE_LEN, EPILOGUE_OFFSET, PROLOGUE_LEN_BYTES,''','''    dispatch_template, dispatch_template_matches, ibtc_variant_id, EPILOGUE_OFFSET,
    PROLOGUE_LEN_BYTES,''')

rep('''    /// Start index of every dispatch template (A11) of the fragment, found on the
    /// bytes: nine words that are `KJIT_DISPATCH_TEMPLATE` up to the miss offsets.
    fn find_dispatch_templates(fixture: &Fixture) -> Vec<usize> {
        fixture
            .body()
            .filter(|&start| {
                start + DISPATCH_TEMPLATE_LEN <= fixture.words.len()
                    && dispatch_template_matches(&fixture.words[start..start + DISPATCH_TEMPLATE_LEN])
                        .is_some()
            })
            .collect()
    }''','''    /// Start index of every dispatch template (A11) of the fragment, found on the
    /// bytes: the selected variant's words, up to the miss offsets.
    fn find_dispatch_templates(fixture: &Fixture) -> Vec<usize> {
        let len = dispatch_template().len();
        fixture
            .body()
            .filter(|&start| {
                start + len <= fixture.words.len()
                    && dispatch_template_matches(&fixture.words[start..start + len]).is_some()
            })
            .collect()
    }''')

rep('''            // The miss exit group is the word right after the template's `br`.
            let group = start + DISPATCH_TEMPLATE_LEN;

            // Every word altered: register, #200, ubfx lsb/width, #8, the shift, the
            // compare, the branch kinds.
            let by_position: Vec<(usize, Vec<(&str, A64Insn)>)> = vec![''','''            let template = dispatch_template();
            let template_len = template.len();
            // The miss exit group is the word right after the template's final `br`.
            let group = start + template_len;
            self.generic_template_mutations(fixture, start);

            // Every word altered, in the ways the A11 contract lists for the nine
            // words of variant 0: register, #200, ubfx lsb/width, #8, the shift, the
            // compare, the branch kinds. (The other variants' words are covered by
            // `generic_template_mutations`, which needs no per-word list.)
            if ibtc_variant_id() == 0 {
            let by_position: Vec<(usize, Vec<(&str, A64Insn)>)> = vec![''')

rep('''                // Dropped.
                self.replace(
                    "dispatch template word altered (A11)",
                    fixture,
                    word_at(position),
                    nop,
                    &format!("nop, {}", at(position)),
                );
            }

            // Key compare dropped: the `sub`, the `cbnz`, both, or the whole record
            // check (load, sub, cbnz).
            for (what, range) in [
                ("sub", 5..6),
                ("cbnz", 6..7),
                ("sub + cbnz", 5..7),
                ("ldr key + sub + cbnz", 4..7),
            ] {
                let mut words = fixture.words.clone();
                for position in range {
                    words[word_at(position)] = nop;
                }
                self.expect_reject(
                    "dispatch key compare dropped (A11)",
                    fixture,
                    format!("{what}, {}", at(0)),
                    &words,
                    &fixture.tables,
                );
            }

            // Join points inside the template or between its budget check and it.
            let guard = start.saturating_sub(1);
            for inner in start..=start + 8 {''','''                // Dropped.
                self.replace(
                    "dispatch template word altered (A11)",
                    fixture,
                    word_at(position),
                    nop,
                    &format!("nop, {}", at(position)),
                );
            }
            }

            // Key compare dropped, in every probe: the `sub`, the `cbnz`, both, or the
            // whole record check (load, sub, cbnz). The `cbnz` is the miss branch on
            // the key register; the `sub` and the key load are the two words before it.
            for miss in template.misses {
                if !matches!(template.words[miss.at], A64Insn::CbnzCbnz64Compbranch { .. }) {
                    continue;
                }
                let cbnz = miss.at;
                for (what, range) in [
                    ("sub", cbnz - 1..cbnz),
                    ("cbnz", cbnz..cbnz + 1),
                    ("sub + cbnz", cbnz - 1..cbnz + 1),
                    ("ldr key + sub + cbnz", cbnz - 2..cbnz + 1),
                ] {
                    let mut words = fixture.words.clone();
                    for position in range {
                        words[word_at(position)] = nop;
                    }
                    self.expect_reject(
                        "dispatch key compare dropped (A11)",
                        fixture,
                        format!("{what} of the probe ending at word {cbnz}, {}", at(0)),
                        &words,
                        &fixture.tables,
                    );
                }
            }

            // Join points inside the template or between its budget check and it.
            let guard = start.saturating_sub(1);
            for inner in start..start + template_len {''')

rep('''            for index in fixture.body() {
                if (start..=start + 8).contains(&index) {
                    continue;
                }''','''            for index in fixture.body() {
                if (start..start + template_len).contains(&index) {
                    continue;
                }''')

rep('''                for inner in [start, start + 1, start + 4, start + 8] {
                    let delta = (inner as i64 - index as i64) * 4;''','''                let mut inners = vec![start, start + 1, start + 4, start + template_len - 1];
                inners.extend(template.misses.iter().map(|miss| start + miss.to));
                inners.retain(|&inner| inner < start + template_len);
                for inner in inners {
                    let delta = (inner as i64 - index as i64) * 4;''')

a=s.index("            // Both miss branches to another word each, or only one moved.")
b=s.index("    fn end_and_entries(&mut self, fixture: &Fixture) {")
new_tail='''            // Every miss branch to another word each: the exit-bound ones to a word of
            // the group or the `br`, the probe-to-probe ones to anywhere but the next
            // probe's first word. (Only one branch moved: the pair then disagrees.)
            for miss in template.misses {
                let mut targets = vec![group + 1, group + 2, word_at(template_len - 1)];
                if miss.to < template_len {
                    targets.extend([word_at(miss.to) - 1, word_at(miss.to) + 1, group]);
                }
                for target in targets {
                    let mut words = fixture.words.clone();
                    let insn = if matches!(template.words[miss.at], A64Insn::CbzCbz64Compbranch { .. }) {
                        cbz_to(word_at(miss.at), target, 12)
                    } else {
                        cbnz_to(word_at(miss.at), target, 14)
                    };
                    words[word_at(miss.at)] = enc(insn);
                    self.expect_reject(
                        "dispatch miss branches disagree (A11)",
                        fixture,
                        format!("miss branch {} -> {:#x}, {}", miss.at, target * 4, at(0)),
                        &words,
                        &fixture.tables,
                    );
                }
            }
        }
    }

    /// The template-word classes that need no per-variant list: for the template at
    /// `start`, every word replaced by a nop, by a `mov` of the target register
    /// (index and fold words: the bounds removed), and every single-bit flip of every
    /// word that still decodes. Each must be rejected: the verifier accepts only the
    /// selected variant's exact words.
    fn generic_template_mutations(&mut self, fixture: &Fixture, start: usize) {
        let template = dispatch_template();
        let nop = enc(A64Insn::NopNopHiHints {});
        for (position, &insn) in template.words.iter().enumerate() {
            let index = start + position;
            let at = format!("template at {:#x}, word {position}", start * 4);
            self.replace(
                "dispatch template word altered (A11)",
                fixture,
                index,
                nop,
                &format!("nop, {at}"),
            );
            // Bounds removed: the masking `ubfx` / fold replaced by an unmasked move
            // of T (or of the key register) into the same destination.
            if let A64Insn::UbfmUbfm64mBitfield { rd, rn, .. }
            | A64Insn::EorLogShiftEor64LogShift { rd, rn, .. } = insn
            {
                self.replace(
                    "dispatch index bounds removed (A11)",
                    fixture,
                    index,
                    enc(mov_reg(rd.enc(), rn.enc())),
                    &format!("mov x{}, x{}, {at}", rd.enc(), rn.enc()),
                );
                // The width widened by one bit (an index reaching past its array).
                if let A64Insn::UbfmUbfm64mBitfield { immr, imms, rn, rd } = insn {
                    let widened = A64Insn::UbfmUbfm64mBitfield {
                        immr,
                        imms: uimm(imms.value() as u32 + 1, 6),
                        rn,
                        rd,
                    };
                    self.replace(
                        "dispatch index bounds removed (A11)",
                        fixture,
                        index,
                        enc(widened),
                        &format!("ubfx widened by one bit, {at}"),
                    );
                }
            }
            for bit in 0..32 {
                let word = fixture.words[index] ^ (1 << bit);
                self.replace(
                    "dispatch template word altered (A11)",
                    fixture,
                    index,
                    word,
                    &format!("bit {bit} flipped, {at}"),
                );
            }
        }
    }

'''
s=s[:a]+new_tail+s[b:]
open(p,'w').write(s)
