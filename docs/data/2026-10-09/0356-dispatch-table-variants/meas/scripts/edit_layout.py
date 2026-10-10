p='/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/agent-a4b243dcf4b342be4/shared/emit/layout.rs'
s=open(p).read()
s=s.replace("""    append_epilogue, append_prologue, DISPATCH_TEMPLATE_LEN, DISPATCH_TEMPLATE_MISS_BRANCHES,
    EPILOGUE_LEN_BYTES, EPILOGUE_OFFSET, PROLOGUE_LEN_BYTES,""","""    append_epilogue, append_prologue, dispatch_template, EPILOGUE_LEN_BYTES, EPILOGUE_OFFSET,
    PROLOGUE_LEN_BYTES,""")
old=s[s.index("                let start = *dispatch_start.get_or_insert(insn_index);"):s.index("            } else if rephrased.kind.is_user_semantic() {")]
new='''                let template = dispatch_template();
                let start = *dispatch_start.get_or_insert(insn_index);
                let position = insn_index - start;
                let is_last = position + 1 == template.len();
                let miss = if position < template.len() {
                    template.miss_at(position)
                } else {
                    None
                };
                let well_formed = position < template.len()
                    && miss.is_some()
                        == matches!(
                            rephrased.insn,
                            A64Insn::CbzCbz64Compbranch { .. }
                                | A64Insn::CbnzCbnz64Compbranch { .. }
                        )
                    && template.is_br(position)
                        == matches!(rephrased.insn, A64Insn::BrBr64BranchReg { .. });
                if !well_formed {
                    return Err(LayoutError::MalformedDispatchTemplate { insn_index });
                }
                if let Some(miss) = miss {
                    // A probe's miss goes to the next probe's first word, the last
                    // probe's to the exit group, which starts right after the
                    // template's final `br`.
                    dispatch_misses.push((insn_index, start + miss.to, rephrased.ori_pc), GFP_KERNEL)?;
                }
                if is_last {
                    dispatch_start = None;
                }
'''
s=s.replace(old,new)
s=s.replace("/// A dispatch template (A11) that is not exactly `DISPATCH_TEMPLATE_LEN` words of","/// A dispatch template (A11) that is not exactly `dispatch_template().len()` words of")
s=s.replace("/// region. A dispatch template's two miss branches (A11) resolve to the word right\n/// after the template's `br`, where the site's exit group starts.","/// region. A dispatch template's miss branches (A11) resolve to the next probe's first\n/// word, or, for the last probe, to the word right after the template's final `br`,\n/// where the site's exit group starts.")
a=s.index("    /// A11: both miss branches of a dispatch template resolve to the word right")
b=s.index("    #[test]\n    fn rewrites_forward_branch_to_layout_offset()")
newtest='''    /// A11: a dispatch template's miss branches resolve to the next probe's first word
    /// or to the word right after its final `br` (the site's exit group); a template
    /// that is cut short, or whose `br` nothing follows, is a layout error.
    #[test]
    fn dispatch_template_miss_branches_resolve_to_the_exit_group() {
        use crate::shared::abi::dispatch_template;
        let template_len = dispatch_template().len();

        let template = |count: usize, followed: bool| {
            let mut insns = SharedVec::new();
            for insn in dispatch_template().words.iter().take(count) {
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

        let layout = layout_program(one_block(template(template_len, true))).unwrap();
        let start = body_start_offset() / 4;
        let exit_group = start + template_len;
        for miss in dispatch_template().misses {
            assert_eq!(
                layout.insns[start + miss.at]
                    .conditional_targets(((start + miss.at) * 4) as u64)
                    .map(|(taken, _)| taken),
                Some(((start + miss.to) * 4) as u64),
                "miss branch {}",
                miss.at
            );
        }
        // The `br` is the template's last word; the exit group starts after it.
        assert!(matches!(
            layout.insns[exit_group - 1],
            A64Insn::BrBr64BranchReg { .. }
        ));

        for count in [template_len - 1, 3] {
            assert!(matches!(
                layout_program(one_block(template(count, true))),
                Err(LayoutError::MalformedDispatchTemplate { .. })
            ));
        }
        // A `br` with no word after it has no exit group to miss to.
        assert!(matches!(
            layout_program(one_block(template(template_len, false))),
            Err(LayoutError::MalformedDispatchTemplate { .. })
        ));
    }

'''
s=s[:a]+newtest+s[b:]
open(p,'w').write(s)
