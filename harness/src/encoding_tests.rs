use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::shared::arm64::{
    A64Condition, A64Imm, A64Insn, A64Mem, A64Reg, A64Reg31Mode, A64RegWidth, A64RewriteError,
};

const SUBSET_TOML: &str = include_str!("../../spec/arm64/subset.toml");

struct EncodingCase {
    form: &'static str,
    asm: String,
    expected: A64Insn,
}

#[test]
#[ignore = "requires llvm-mc and llvm-objcopy in PATH"]
fn encoding_matches_llvm_for_handwritten_cases() {
    let mut cases = encoding_cases();
    cases.extend(alu_encoding_cases());
    cases.extend(condition_code_cases());
    cases.extend(mem_encoding_cases());
    cases.extend(barrier_acqrel_encoding_cases());
    cases.extend(bti_carry_crc_encoding_cases());
    cases.extend(lse_msr_encoding_cases());
    cases.extend(simd_encoding_cases());
    let decode_forms = decode_forms_from_subset_toml(SUBSET_TOML);
    let decode_form_set = decode_forms.iter().cloned().collect::<BTreeSet<_>>();
    let covered_forms = cases.iter().map(|case| case.form).collect::<BTreeSet<_>>();

    for case in &cases {
        assert!(
            decode_form_set.contains(case.form),
            "encoding test case references form not in subset.toml: {}",
            case.form
        );
        assert_case_matches_llvm(case);
    }

    let mut uncovered_simd = Vec::new();
    for form in decode_forms {
        if !covered_forms.contains(form.as_str()) {
            println!("WARN: decode form has no encoding test: {form}");
            // A9a: every SIMD&FP form has a case.
            let simd = crate::shared::arm64::GENERATED_A64_SUBSET
                .iter()
                .any(|spec| {
                    spec.key == form
                        && spec.operands.iter().any(|role| {
                            matches!(
                                role,
                                crate::shared::arm64::A64OperandRole::VecRead { .. }
                                    | crate::shared::arm64::A64OperandRole::VecWrite { .. }
                            )
                        })
                });
            if simd {
                uncovered_simd.push(form);
            }
        }
    }
    assert!(
        uncovered_simd.is_empty(),
        "SIMD&FP forms without an encoding case: {uncovered_simd:?}"
    );
}

/// A9a decode admission against LLVM's disassembler: 300 random words per
/// SIMD&FP form (fixed bits kept, free bits random, `!=` exclusions skipped). A
/// word the generated decoder admits (`decode` and not `is_decode_undefined`)
/// must disassemble, and one it refuses must not. (The CONSTRAINED UNPREDICTABLE
/// LDP `t == t2` is admitted here and by LLVM; reg-virt rejects it.)
#[test]
#[ignore = "requires llvm-mc in PATH"]
fn a9a_decode_admission_agrees_with_llvm_disassembler() {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut words = Vec::new();
    for spec in crate::shared::arm64::GENERATED_A64_SUBSET
        .iter()
        .filter(|spec| {
            spec.operands.iter().any(|role| {
                matches!(
                    role,
                    crate::shared::arm64::A64OperandRole::VecRead { .. }
                        | crate::shared::arm64::A64OperandRole::VecWrite { .. }
                )
            })
        })
    {
        for _ in 0..300 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let word = spec.value | ((state >> 11) as u32 & !spec.mask);
            // A word a `!=` exclusion removes belongs to another encoding (SHL's
            // `immh == 0000` is the modified-immediate class).
            if spec.matches(word) {
                words.push((spec.key, word));
            }
        }
    }
    let texts =
        crate::a64_forms::disassemble(&words.iter().map(|&(_, word)| word).collect::<Vec<_>>())
            .expect("llvm-mc runs");
    let mut disagreements = Vec::new();
    let mut undefined = 0;
    for (&(key, word), text) in words.iter().zip(texts) {
        let ours = A64Insn::decode(word).filter(|insn| !insn.is_decode_undefined());
        undefined += usize::from(ours.is_none());
        match (&ours, &text) {
            (Some(_), Some(_)) | (None, None) => {}
            _ => disagreements.push(format!(
                "{key}: {word:#010x} ours={:?} llvm={text:?}",
                ours.map(|insn| insn.key())
            )),
        }
    }
    println!(
        "a9a decode vs llvm-mc: {} words ({undefined} decode-undefined), {} disagreements",
        words.len(),
        disagreements.len()
    );
    assert!(
        disagreements.is_empty(),
        "{}",
        disagreements[..disagreements.len().min(20)].join("\n")
    );
}

#[test]
fn reg_accessors_get_and_set_top_level_fields() {
    let insn = A64Insn::OrrLogShiftOrr64LogShift {
        shift: 0,
        rm: A64Reg::x(2),
        imm6: A64Imm::unsigned(0, 6),
        rn: A64Reg::x(3),
        rd: A64Reg::x(4),
    };

    assert_eq!(insn.get_reg("Rm"), Some(A64Reg::x(2)));
    assert_eq!(insn.get_reg("Rn"), Some(A64Reg::x(3)));
    assert_eq!(insn.get_reg("Rd"), Some(A64Reg::x(4)));

    let rewritten = insn.set_reg("Rm", A64Reg::w_sp(9)).unwrap();
    assert_eq!(rewritten.get_reg("Rm"), Some(A64Reg::x(9)));
    assert_eq!(rewritten.get_reg("Rn"), Some(A64Reg::x(3)));
    assert_eq!(rewritten.get_reg("Rd"), Some(A64Reg::x(4)));
}

#[test]
fn reg_accessors_get_and_set_memory_base_preserving_mode_and_offset() {
    let post_offset = A64Imm::signed(4, 9);
    let post = A64Insn::LdrImmGenLdr64LdstImmpost {
        rt: A64Reg::x(1),
        mem: A64Mem::post_index(A64Reg::x_sp(31), post_offset),
    };
    assert_eq!(post.get_reg("Rn"), Some(A64Reg::x_sp(31)));
    assert_eq!(
        post.set_reg("Rn", A64Reg::w(8)).unwrap(),
        A64Insn::LdrImmGenLdr64LdstImmpost {
            rt: A64Reg::x(1),
            mem: A64Mem::post_index(A64Reg::x_sp(8), post_offset),
        }
    );

    let pre_offset = A64Imm::signed(signed_field(-8, 9), 9);
    let pre = A64Insn::StrImmGenStr64LdstImmpre {
        rt: A64Reg::x(2),
        mem: A64Mem::pre_index(A64Reg::x_sp(31), pre_offset),
    };
    assert_eq!(
        pre.set_reg("Rn", A64Reg::unknown(7)).unwrap(),
        A64Insn::StrImmGenStr64LdstImmpre {
            rt: A64Reg::x(2),
            mem: A64Mem::pre_index(A64Reg::x_sp(7), pre_offset),
        }
    );

    let scaled_offset = A64Imm::scaled_unsigned(3, 12, 3);
    let offset = A64Insn::LdrImmGenLdr64LdstPos {
        rt: A64Reg::x(3),
        mem: A64Mem::offset(A64Reg::x_sp(31), scaled_offset),
    };
    assert_eq!(
        offset.set_reg("Rn", A64Reg::w_sp(6)).unwrap(),
        A64Insn::LdrImmGenLdr64LdstPos {
            rt: A64Reg::x(3),
            mem: A64Mem::offset(A64Reg::x_sp(6), scaled_offset),
        }
    );
}

#[test]
fn set_reg_rejects_unsupported_field() {
    let insn = A64Insn::AddAddsubImmAdd32AddsubImm {
        sh: 0,
        imm12: A64Imm::unsigned(1, 12),
        rn: A64Reg::w_sp(1),
        rd: A64Reg::w_sp(2),
    };

    assert_eq!(insn.get_reg("Rm"), None);
    assert_eq!(
        insn.set_reg("Rm", A64Reg::w(3)),
        Err(A64RewriteError::UnsupportedField {
            insn: "ADD_addsub_imm.ADD_32_addsub_imm",
            field: "Rm",
        })
    );
}

#[test]
fn set_reg_rejects_invalid_register_encoding() {
    let insn = A64Insn::MovzMovz32Movewide {
        hw: 0,
        imm16: A64Imm::unsigned(0, 16),
        rd: A64Reg::w(0),
    };

    assert_eq!(
        insn.set_reg("Rd", A64Reg::new(32, A64RegWidth::X64, A64Reg31Mode::Sp)),
        Err(A64RewriteError::FieldOutOfRange {
            insn: "MOVZ.MOVZ_32_movewide",
            field: "Rd",
            value: 32,
            width: 5,
        })
    );
}

#[test]
fn set_reg_canonicalizes_target_width_and_reg31_mode() {
    let add = A64Insn::AddAddsubImmAdd64AddsubImm {
        sh: 0,
        imm12: A64Imm::unsigned(16, 12),
        rn: A64Reg::x_sp(31),
        rd: A64Reg::x_sp(0),
    };
    let rewritten_add = add.set_reg("Rd", A64Reg::w(31)).unwrap();
    assert_eq!(rewritten_add.get_reg("Rd"), Some(A64Reg::x_sp(31)));

    let movz = A64Insn::MovzMovz32Movewide {
        hw: 0,
        imm16: A64Imm::unsigned(0, 16),
        rd: A64Reg::w(0),
    };
    let rewritten_movz = movz.set_reg("Rd", A64Reg::x_sp(31)).unwrap();
    assert_eq!(rewritten_movz.get_reg("Rd"), Some(A64Reg::w(31)));
}

#[test]
fn reg_accessors_do_not_expose_implicit_bl_link_register() {
    let insn = A64Insn::BlBlOnlyBranchImm {
        imm26: A64Imm::scaled_signed(branch_imm(4, 26), 26, 2),
    };

    assert_eq!(insn.get_reg("x30"), None);
    assert_eq!(
        insn.set_reg("x30", A64Reg::x(0)),
        Err(A64RewriteError::UnsupportedField {
            insn: "BL.BL_only_branch_imm",
            field: "x30",
        })
    );
}

fn assert_case_matches_llvm(case: &EncodingCase) {
    let llvm_bytes = assemble_with_llvm(case);
    let kjit_word = case
        .expected
        .encode()
        .unwrap_or_else(|err| panic!("{}: encode failed: {err:?}", case.form));
    let kjit_bytes = kjit_word.to_le_bytes();

    assert_eq!(
        llvm_bytes,
        kjit_bytes,
        "{}\nasm:\n{}\nLLVM bytes: {}\nKJIT bytes: {}",
        case.form,
        case.asm,
        bytes_hex(&llvm_bytes),
        bytes_hex(&kjit_bytes)
    );

    let decoded = A64Insn::decode(u32::from_le_bytes(llvm_bytes))
        .unwrap_or_else(|| panic!("{}: LLVM bytes did not decode", case.form));
    assert_eq!(
        decoded, case.expected,
        "{}\nasm:\n{}\ndecoded LLVM instruction mismatch",
        case.form, case.asm
    );
}

fn assemble_with_llvm(case: &EncodingCase) -> [u8; 4] {
    let llvm_mc = std::env::var("LLVM_MC").unwrap_or_else(|_| "llvm-mc".to_string());
    let llvm_objcopy = std::env::var("LLVM_OBJCOPY").unwrap_or_else(|_| "llvm-objcopy".to_string());
    let dir = TempDir::new("kjit-encoding-test");
    let asm_path = dir.path().join("case.s");
    let obj_path = dir.path().join("case.o");
    let bin_path = dir.path().join("case.text.bin");

    fs::write(&asm_path, asm_source(&case.asm))
        .unwrap_or_else(|err| panic!("{}: failed to write assembly: {err}", case.form));

    let mc_output = Command::new(&llvm_mc)
        .arg("-triple=aarch64")
        .arg("-filetype=obj")
        .arg(&asm_path)
        .arg("-o")
        .arg(&obj_path)
        .output()
        .unwrap_or_else(|err| {
            panic!(
                "{}: failed to execute {llvm_mc}: {err}\nset LLVM_MC to the llvm-mc binary",
                case.form
            )
        });
    assert!(
        mc_output.status.success(),
        "{}: llvm-mc failed\nasm:\n{}\nstdout:\n{}\nstderr:\n{}",
        case.form,
        case.asm,
        String::from_utf8_lossy(&mc_output.stdout),
        String::from_utf8_lossy(&mc_output.stderr)
    );

    let objcopy_output = Command::new(&llvm_objcopy)
        .arg("--only-section=.text")
        .arg("-O")
        .arg("binary")
        .arg(&obj_path)
        .arg(&bin_path)
        .output()
        .unwrap_or_else(|err| {
            panic!(
                "{}: failed to execute {llvm_objcopy}: {err}\nset LLVM_OBJCOPY to the llvm-objcopy binary",
                case.form
            )
        });
    assert!(
        objcopy_output.status.success(),
        "{}: llvm-objcopy failed\nstdout:\n{}\nstderr:\n{}",
        case.form,
        String::from_utf8_lossy(&objcopy_output.stdout),
        String::from_utf8_lossy(&objcopy_output.stderr)
    );

    let bytes = fs::read(&bin_path)
        .unwrap_or_else(|err| panic!("{}: failed to read .text binary: {err}", case.form));
    assert_eq!(
        bytes.len(),
        4,
        "{}: expected exactly one instruction, got {} bytes: {}",
        case.form,
        bytes.len(),
        bytes_hex(&bytes)
    );
    bytes.try_into().unwrap()
}

fn asm_source(body: &str) -> String {
    format!(".text\n.globl _start\n_start:\n{body}\n")
}

fn encoding_cases() -> Vec<EncodingCase> {
    vec![
        case(
            "ADR.ADR_only_pcreladdr",
            "    adr x3, .Ltarget\n.Ltarget:",
            A64Insn::AdrAdrOnlyPcreladdr {
                immlo: A64Imm::unsigned(0, 2),
                immhi: A64Imm::unsigned(1, 19),
                rd: A64Reg::x(3),
            },
        ),
        case(
            "ADRP.ADRP_only_pcreladdr",
            "    adrp x4, .Ltarget\n.Ltarget:",
            A64Insn::AdrpAdrpOnlyPcreladdr {
                immlo: A64Imm::unsigned(0, 2),
                immhi: A64Imm::unsigned(0, 19),
                rd: A64Reg::x(4),
            },
        ),
        case(
            "ADD_addsub_imm.ADD_32_addsub_imm",
            "    add w1, w2, #5",
            A64Insn::AddAddsubImmAdd32AddsubImm {
                sh: 0,
                imm12: A64Imm::unsigned(5, 12),
                rn: A64Reg::w_sp(2),
                rd: A64Reg::w_sp(1),
            },
        ),
        case(
            "ADD_addsub_imm.ADD_64_addsub_imm",
            "    add x1, sp, #16",
            A64Insn::AddAddsubImmAdd64AddsubImm {
                sh: 0,
                imm12: A64Imm::unsigned(16, 12),
                rn: A64Reg::x_sp(31),
                rd: A64Reg::x_sp(1),
            },
        ),
        case(
            "SUB_addsub_imm.SUB_32_addsub_imm",
            "    sub w3, w4, #7",
            A64Insn::SubAddsubImmSub32AddsubImm {
                sh: 0,
                imm12: A64Imm::unsigned(7, 12),
                rn: A64Reg::w_sp(4),
                rd: A64Reg::w_sp(3),
            },
        ),
        case(
            "SUB_addsub_imm.SUB_64_addsub_imm",
            "    sub sp, sp, #32",
            A64Insn::SubAddsubImmSub64AddsubImm {
                sh: 0,
                imm12: A64Imm::unsigned(32, 12),
                rn: A64Reg::x_sp(31),
                rd: A64Reg::x_sp(31),
            },
        ),
        case(
            "SUBS_addsub_imm.SUBS_32S_addsub_imm",
            "    subs w5, w6, #9",
            A64Insn::SubsAddsubImmSubs32sAddsubImm {
                sh: 0,
                imm12: A64Imm::unsigned(9, 12),
                rn: A64Reg::w_sp(6),
                rd: A64Reg::w(5),
            },
        ),
        case(
            "SUBS_addsub_imm.SUBS_64S_addsub_imm",
            "    subs xzr, x7, #11",
            A64Insn::SubsAddsubImmSubs64sAddsubImm {
                sh: 0,
                imm12: A64Imm::unsigned(11, 12),
                rn: A64Reg::x_sp(7),
                rd: A64Reg::x(31),
            },
        ),
        case(
            "B_uncond.B_only_branch_imm",
            "    b .Ltarget\n.Ltarget:",
            A64Insn::BUncondBOnlyBranchImm {
                imm26: A64Imm::scaled_signed(branch_imm(4, 26), 26, 2),
            },
        ),
        case(
            "B_cond.B_only_condbranch",
            "    b.eq .Ltarget\n.Ltarget:",
            A64Insn::BCondBOnlyCondbranch {
                imm19: A64Imm::scaled_signed(branch_imm(4, 19), 19, 2),
                cond: A64Condition::Eq.bits(),
            },
        ),
        case(
            "CBZ.CBZ_32_compbranch",
            "    cbz w8, .Ltarget\n.Ltarget:",
            A64Insn::CbzCbz32Compbranch {
                imm19: A64Imm::scaled_signed(branch_imm(4, 19), 19, 2),
                rt: A64Reg::w(8),
            },
        ),
        case(
            "CBZ.CBZ_64_compbranch",
            "    cbz x9, .Ltarget\n.Ltarget:",
            A64Insn::CbzCbz64Compbranch {
                imm19: A64Imm::scaled_signed(branch_imm(4, 19), 19, 2),
                rt: A64Reg::x(9),
            },
        ),
        case(
            "CBNZ.CBNZ_32_compbranch",
            "    cbnz w10, .Ltarget\n.Ltarget:",
            A64Insn::CbnzCbnz32Compbranch {
                imm19: A64Imm::scaled_signed(branch_imm(4, 19), 19, 2),
                rt: A64Reg::w(10),
            },
        ),
        case(
            "CBNZ.CBNZ_64_compbranch",
            "    cbnz x11, .Ltarget\n.Ltarget:",
            A64Insn::CbnzCbnz64Compbranch {
                imm19: A64Imm::scaled_signed(branch_imm(4, 19), 19, 2),
                rt: A64Reg::x(11),
            },
        ),
        case(
            "MOVZ.MOVZ_32_movewide",
            "    movz w12, #0x1234",
            A64Insn::MovzMovz32Movewide {
                hw: 0,
                imm16: A64Imm::unsigned(0x1234, 16),
                rd: A64Reg::w(12),
            },
        ),
        case(
            "MOVZ.MOVZ_64_movewide",
            "    movz x13, #0x1234, lsl #16",
            A64Insn::MovzMovz64Movewide {
                hw: 1,
                imm16: A64Imm::unsigned(0x1234, 16),
                rd: A64Reg::x(13),
            },
        ),
        case(
            "MOVK.MOVK_32_movewide",
            "    movk w14, #0xabcd",
            A64Insn::MovkMovk32Movewide {
                hw: 0,
                imm16: A64Imm::unsigned(0xabcd, 16),
                rd: A64Reg::w(14),
            },
        ),
        case(
            "MOVK.MOVK_64_movewide",
            "    movk x15, #0xabcd, lsl #32",
            A64Insn::MovkMovk64Movewide {
                hw: 2,
                imm16: A64Imm::unsigned(0xabcd, 16),
                rd: A64Reg::x(15),
            },
        ),
        case(
            "ORR_log_shift.ORR_64_log_shift",
            "    orr x16, x17, x18, lsl #4",
            A64Insn::OrrLogShiftOrr64LogShift {
                shift: 0,
                rm: A64Reg::x(18),
                imm6: A64Imm::unsigned(4, 6),
                rn: A64Reg::x(17),
                rd: A64Reg::x(16),
            },
        ),
        case(
            "TBZ.TBZ_only_testbranch",
            "    tbz w19, #7, .Ltarget\n.Ltarget:",
            A64Insn::TbzTbzOnlyTestbranch {
                b5: 0,
                b40: 7,
                imm14: A64Imm::scaled_signed(branch_imm(4, 14), 14, 2),
                rt: A64Reg::new(19, A64RegWidth::Unknown, A64Reg31Mode::Xzr),
            },
        ),
        case(
            "TBNZ.TBNZ_only_testbranch",
            "    tbnz x20, #33, .Ltarget\n.Ltarget:",
            A64Insn::TbnzTbnzOnlyTestbranch {
                b5: 1,
                b40: 1,
                imm14: A64Imm::scaled_signed(branch_imm(4, 14), 14, 2),
                rt: A64Reg::new(20, A64RegWidth::Unknown, A64Reg31Mode::Xzr),
            },
        ),
        case(
            "LDR_imm_gen.LDR_32_ldst_immpost",
            "    ldr w1, [sp], #4",
            A64Insn::LdrImmGenLdr32LdstImmpost {
                rt: A64Reg::w(1),
                mem: A64Mem::post_index(A64Reg::x_sp(31), A64Imm::signed(4, 9)),
            },
        ),
        case(
            "LDR_imm_gen.LDR_64_ldst_immpost",
            "    ldr x2, [sp], #8",
            A64Insn::LdrImmGenLdr64LdstImmpost {
                rt: A64Reg::x(2),
                mem: A64Mem::post_index(A64Reg::x_sp(31), A64Imm::signed(8, 9)),
            },
        ),
        case(
            "LDR_imm_gen.LDR_32_ldst_immpre",
            "    ldr w3, [sp, #-4]!",
            A64Insn::LdrImmGenLdr32LdstImmpre {
                rt: A64Reg::w(3),
                mem: A64Mem::pre_index(A64Reg::x_sp(31), A64Imm::signed(signed_field(-4, 9), 9)),
            },
        ),
        case(
            "LDR_imm_gen.LDR_64_ldst_immpre",
            "    ldr x4, [sp, #-8]!",
            A64Insn::LdrImmGenLdr64LdstImmpre {
                rt: A64Reg::x(4),
                mem: A64Mem::pre_index(A64Reg::x_sp(31), A64Imm::signed(signed_field(-8, 9), 9)),
            },
        ),
        case(
            "LDR_imm_gen.LDR_32_ldst_pos",
            "    ldr w5, [sp, #12]",
            A64Insn::LdrImmGenLdr32LdstPos {
                rt: A64Reg::w(5),
                mem: A64Mem::offset(A64Reg::x_sp(31), A64Imm::scaled_unsigned(3, 12, 2)),
            },
        ),
        case(
            "LDR_imm_gen.LDR_64_ldst_pos",
            "    ldr x6, [sp, #16]",
            A64Insn::LdrImmGenLdr64LdstPos {
                rt: A64Reg::x(6),
                mem: A64Mem::offset(A64Reg::x_sp(31), A64Imm::scaled_unsigned(2, 12, 3)),
            },
        ),
        case(
            "STR_imm_gen.STR_32_ldst_immpost",
            "    str w7, [sp], #4",
            A64Insn::StrImmGenStr32LdstImmpost {
                rt: A64Reg::w(7),
                mem: A64Mem::post_index(A64Reg::x_sp(31), A64Imm::signed(4, 9)),
            },
        ),
        case(
            "STR_imm_gen.STR_64_ldst_immpost",
            "    str x8, [sp], #8",
            A64Insn::StrImmGenStr64LdstImmpost {
                rt: A64Reg::x(8),
                mem: A64Mem::post_index(A64Reg::x_sp(31), A64Imm::signed(8, 9)),
            },
        ),
        case(
            "STR_imm_gen.STR_32_ldst_immpre",
            "    str w9, [sp, #-4]!",
            A64Insn::StrImmGenStr32LdstImmpre {
                rt: A64Reg::w(9),
                mem: A64Mem::pre_index(A64Reg::x_sp(31), A64Imm::signed(signed_field(-4, 9), 9)),
            },
        ),
        case(
            "STR_imm_gen.STR_64_ldst_immpre",
            "    str x10, [sp, #-8]!",
            A64Insn::StrImmGenStr64LdstImmpre {
                rt: A64Reg::x(10),
                mem: A64Mem::pre_index(A64Reg::x_sp(31), A64Imm::signed(signed_field(-8, 9), 9)),
            },
        ),
        case(
            "STR_imm_gen.STR_32_ldst_pos",
            "    str w11, [sp, #12]",
            A64Insn::StrImmGenStr32LdstPos {
                rt: A64Reg::w(11),
                mem: A64Mem::offset(A64Reg::x_sp(31), A64Imm::scaled_unsigned(3, 12, 2)),
            },
        ),
        case(
            "STR_imm_gen.STR_64_ldst_pos",
            "    str x12, [sp, #16]",
            A64Insn::StrImmGenStr64LdstPos {
                rt: A64Reg::x(12),
                mem: A64Mem::offset(A64Reg::x_sp(31), A64Imm::scaled_unsigned(2, 12, 3)),
            },
        ),
        case(
            "LDP_gen.LDP_64_ldstpair_post",
            "    ldp x13, x14, [sp], #16",
            A64Insn::LdpGenLdp64LdstpairPost {
                rt2: A64Reg::x(14),
                rt: A64Reg::x(13),
                mem: A64Mem::post_index(A64Reg::x_sp(31), A64Imm::scaled_signed(2, 7, 3)),
            },
        ),
        case(
            "LDP_gen.LDP_64_ldstpair_pre",
            "    ldp x15, x16, [sp, #-16]!",
            A64Insn::LdpGenLdp64LdstpairPre {
                rt2: A64Reg::x(16),
                rt: A64Reg::x(15),
                mem: A64Mem::pre_index(
                    A64Reg::x_sp(31),
                    A64Imm::scaled_signed(signed_field(-2, 7), 7, 3),
                ),
            },
        ),
        case(
            "LDP_gen.LDP_64_ldstpair_off",
            "    ldp x17, x18, [sp, #24]",
            A64Insn::LdpGenLdp64LdstpairOff {
                rt2: A64Reg::x(18),
                rt: A64Reg::x(17),
                mem: A64Mem::offset(A64Reg::x_sp(31), A64Imm::scaled_signed(3, 7, 3)),
            },
        ),
        case(
            "STP_gen.STP_64_ldstpair_post",
            "    stp x19, x20, [sp], #16",
            A64Insn::StpGenStp64LdstpairPost {
                rt2: A64Reg::x(20),
                rt: A64Reg::x(19),
                mem: A64Mem::post_index(A64Reg::x_sp(31), A64Imm::scaled_signed(2, 7, 3)),
            },
        ),
        case(
            "STP_gen.STP_64_ldstpair_pre",
            "    stp x21, x22, [sp, #-16]!",
            A64Insn::StpGenStp64LdstpairPre {
                rt2: A64Reg::x(22),
                rt: A64Reg::x(21),
                mem: A64Mem::pre_index(
                    A64Reg::x_sp(31),
                    A64Imm::scaled_signed(signed_field(-2, 7), 7, 3),
                ),
            },
        ),
        case(
            "STP_gen.STP_64_ldstpair_off",
            "    stp x23, x24, [sp, #24]",
            A64Insn::StpGenStp64LdstpairOff {
                rt2: A64Reg::x(24),
                rt: A64Reg::x(23),
                mem: A64Mem::offset(A64Reg::x_sp(31), A64Imm::scaled_signed(3, 7, 3)),
            },
        ),
        case(
            "LDTR.LDTR_32_ldst_unpriv",
            "    ldtr w3, [x4, #-256]",
            A64Insn::LdtrLdtr32LdstUnpriv {
                rt: A64Reg::w(3),
                mem: A64Mem::offset(A64Reg::x_sp(4), A64Imm::signed(signed_field(-256, 9), 9)),
            },
        ),
        case(
            "LDTR.LDTR_64_ldst_unpriv",
            "    ldtr x12, [sp, #255]",
            A64Insn::LdtrLdtr64LdstUnpriv {
                rt: A64Reg::x(12),
                mem: A64Mem::offset(A64Reg::x_sp(31), A64Imm::signed(255, 9)),
            },
        ),
        case(
            "LDTR.LDTR_64_ldst_unpriv",
            "    ldtr x0, [x17]",
            A64Insn::LdtrLdtr64LdstUnpriv {
                rt: A64Reg::x(0),
                mem: A64Mem::offset(A64Reg::x_sp(17), A64Imm::signed(0, 9)),
            },
        ),
        case(
            "STTR.STTR_32_ldst_unpriv",
            "    sttr wzr, [x5, #3]",
            A64Insn::SttrSttr32LdstUnpriv {
                rt: A64Reg::w(31),
                mem: A64Mem::offset(A64Reg::x_sp(5), A64Imm::signed(3, 9)),
            },
        ),
        case(
            "STTR.STTR_64_ldst_unpriv",
            "    sttr x30, [x16, #-8]",
            A64Insn::SttrSttr64LdstUnpriv {
                rt: A64Reg::x(30),
                mem: A64Mem::offset(A64Reg::x_sp(16), A64Imm::signed(signed_field(-8, 9), 9)),
            },
        ),
        case("NOP.NOP_HI_hints", "    nop", A64Insn::NopNopHiHints {}),
        case(
            "BL.BL_only_branch_imm",
            "    bl .Ltarget\n.Ltarget:",
            A64Insn::BlBlOnlyBranchImm {
                imm26: A64Imm::scaled_signed(branch_imm(4, 26), 26, 2),
            },
        ),
        case(
            "BR.BR_64_branch_reg",
            "    br x25",
            A64Insn::BrBr64BranchReg { rn: A64Reg::x(25) },
        ),
        case(
            "BLR.BLR_64_branch_reg",
            "    blr x26",
            A64Insn::BlrBlr64BranchReg { rn: A64Reg::x(26) },
        ),
        case(
            "RET.RET_64R_branch_reg",
            "    ret x27",
            A64Insn::RetRet64rBranchReg { rn: A64Reg::x(27) },
        ),
        case(
            "SVC.SVC_EX_exception",
            "    svc #0x80",
            A64Insn::SvcSvcExException {
                imm16: A64Imm::unsigned(0x80, 16),
            },
        ),
    ]
}

fn case(form: &'static str, asm: impl Into<String>, expected: A64Insn) -> EncodingCase {
    EncodingCase {
        form,
        asm: asm.into(),
        expected,
    }
}
/// Register constructors matching the generated register-31 mode of each field.
fn w(enc: u8) -> A64Reg {
    A64Reg::w(enc)
}

fn x(enc: u8) -> A64Reg {
    A64Reg::x(enc)
}

fn wsp(enc: u8) -> A64Reg {
    A64Reg::w_sp(enc)
}

fn xsp(enc: u8) -> A64Reg {
    A64Reg::x_sp(enc)
}

fn uimm(raw: u32, bits: u8) -> A64Imm {
    A64Imm::unsigned(raw, bits)
}

const CONDITION_NAMES: [&str; 16] = [
    "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
];

/// `b.<cond>` for all 16 condition codes. `A64Condition` round-trips every value,
/// including NV (0b1111), which must not be re-encoded as AL.
fn condition_code_cases() -> Vec<EncodingCase> {
    CONDITION_NAMES
        .iter()
        .enumerate()
        .map(|(bits, name)| {
            let bits = bits as u8;
            let condition = A64Condition::from_bits(bits).expect("4-bit condition");
            assert_eq!(condition.bits(), bits);
            case(
                "B_cond.B_only_condbranch",
                format!("    b.{name} .Ltarget\n.Ltarget:"),
                A64Insn::BCondBOnlyCondbranch {
                    imm19: A64Imm::scaled_signed(branch_imm(4, 19), 19, 2),
                    cond: condition.bits(),
                },
            )
        })
        .collect()
}

fn alu_encoding_cases() -> Vec<EncodingCase> {
    vec![
        // ADDS (immediate): cmn is ADDS with Rd = ZR; Rn may be SP.
        case(
            "ADDS_addsub_imm.ADDS_32S_addsub_imm",
            "    adds w0, w1, #4095",
            A64Insn::AddsAddsubImmAdds32sAddsubImm {
                sh: 0,
                imm12: uimm(4095, 12),
                rn: wsp(1),
                rd: w(0),
            },
        ),
        case(
            "ADDS_addsub_imm.ADDS_32S_addsub_imm",
            "    cmn wsp, #4095",
            A64Insn::AddsAddsubImmAdds32sAddsubImm {
                sh: 0,
                imm12: uimm(4095, 12),
                rn: wsp(31),
                rd: w(31),
            },
        ),
        case(
            "ADDS_addsub_imm.ADDS_64S_addsub_imm",
            "    cmn x0, #1, lsl #12",
            A64Insn::AddsAddsubImmAdds64sAddsubImm {
                sh: 1,
                imm12: uimm(1, 12),
                rn: xsp(0),
                rd: x(31),
            },
        ),
        case(
            "ADDS_addsub_imm.ADDS_64S_addsub_imm",
            "    adds x2, sp, #8",
            A64Insn::AddsAddsubImmAdds64sAddsubImm {
                sh: 0,
                imm12: uimm(8, 12),
                rn: xsp(31),
                rd: x(2),
            },
        ),
        case(
            "SUBS_addsub_imm.SUBS_64S_addsub_imm",
            "    cmp x0, #4095",
            A64Insn::SubsAddsubImmSubs64sAddsubImm {
                sh: 0,
                imm12: uimm(4095, 12),
                rn: xsp(0),
                rd: x(31),
            },
        ),
        case(
            "SUB_addsub_imm.SUB_64_addsub_imm",
            "    sub sp, sp, #4095, lsl #12",
            A64Insn::SubAddsubImmSub64AddsubImm {
                sh: 1,
                imm12: uimm(4095, 12),
                rn: xsp(31),
                rd: xsp(31),
            },
        ),
        case(
            "ADD_addsub_imm.ADD_64_addsub_imm",
            "    mov x29, sp",
            A64Insn::AddAddsubImmAdd64AddsubImm {
                sh: 0,
                imm12: uimm(0, 12),
                rn: xsp(31),
                rd: xsp(29),
            },
        ),
        // ADD/ADDS/SUB/SUBS (shifted register): register 31 is ZR everywhere.
        case(
            "ADD_addsub_shift.ADD_32_addsub_shift",
            "    add w0, w1, w2, lsl #31",
            A64Insn::AddAddsubShiftAdd32AddsubShift {
                shift: 0,
                rm: w(2),
                imm6: uimm(31, 6),
                rn: w(1),
                rd: w(0),
            },
        ),
        case(
            "ADD_addsub_shift.ADD_64_addsub_shift",
            "    add x0, xzr, x2, asr #63",
            A64Insn::AddAddsubShiftAdd64AddsubShift {
                shift: 2,
                rm: x(2),
                imm6: uimm(63, 6),
                rn: x(31),
                rd: x(0),
            },
        ),
        case(
            "ADD_addsub_shift.ADD_64_addsub_shift",
            "    add x3, x4, x5",
            A64Insn::AddAddsubShiftAdd64AddsubShift {
                shift: 0,
                rm: x(5),
                imm6: uimm(0, 6),
                rn: x(4),
                rd: x(3),
            },
        ),
        case(
            "ADDS_addsub_shift.ADDS_32_addsub_shift",
            "    adds w3, w4, w5, lsr #7",
            A64Insn::AddsAddsubShiftAdds32AddsubShift {
                shift: 1,
                rm: w(5),
                imm6: uimm(7, 6),
                rn: w(4),
                rd: w(3),
            },
        ),
        case(
            "ADDS_addsub_shift.ADDS_64_addsub_shift",
            "    cmn x6, x7, lsl #2",
            A64Insn::AddsAddsubShiftAdds64AddsubShift {
                shift: 0,
                rm: x(7),
                imm6: uimm(2, 6),
                rn: x(6),
                rd: x(31),
            },
        ),
        case(
            "SUB_addsub_shift.SUB_32_addsub_shift",
            "    neg w0, w1",
            A64Insn::SubAddsubShiftSub32AddsubShift {
                shift: 0,
                rm: w(1),
                imm6: uimm(0, 6),
                rn: w(31),
                rd: w(0),
            },
        ),
        case(
            "SUB_addsub_shift.SUB_64_addsub_shift",
            "    sub x8, x9, x10, asr #63",
            A64Insn::SubAddsubShiftSub64AddsubShift {
                shift: 2,
                rm: x(10),
                imm6: uimm(63, 6),
                rn: x(9),
                rd: x(8),
            },
        ),
        case(
            "SUBS_addsub_shift.SUBS_32_addsub_shift",
            "    cmp w1, w2",
            A64Insn::SubsAddsubShiftSubs32AddsubShift {
                shift: 0,
                rm: w(2),
                imm6: uimm(0, 6),
                rn: w(1),
                rd: w(31),
            },
        ),
        case(
            "SUBS_addsub_shift.SUBS_64_addsub_shift",
            "    subs x11, x12, x13, lsl #63",
            A64Insn::SubsAddsubShiftSubs64AddsubShift {
                shift: 0,
                rm: x(13),
                imm6: uimm(63, 6),
                rn: x(12),
                rd: x(11),
            },
        ),
        case(
            "SUBS_addsub_shift.SUBS_64_addsub_shift",
            "    negs x0, x1",
            A64Insn::SubsAddsubShiftSubs64AddsubShift {
                shift: 0,
                rm: x(1),
                imm6: uimm(0, 6),
                rn: x(31),
                rd: x(0),
            },
        ),
        // ADD/ADDS/SUB/SUBS (extended register): Rn is SP-capable; Rd is SP-capable
        // only for the non-flag-setting forms; Rm is always ZR.
        case(
            "ADD_addsub_ext.ADD_32_addsub_ext",
            "    add w0, wsp, w1, uxtb #4",
            A64Insn::AddAddsubExtAdd32AddsubExt {
                rm: w(1),
                option: 0,
                imm3: uimm(4, 3),
                rn: wsp(31),
                rd: wsp(0),
            },
        ),
        case(
            "ADD_addsub_ext.ADD_64_addsub_ext",
            "    add x0, sp, w1, uxtw",
            A64Insn::AddAddsubExtAdd64AddsubExt {
                rm: x(1),
                option: 2,
                imm3: uimm(0, 3),
                rn: xsp(31),
                rd: xsp(0),
            },
        ),
        case(
            "ADD_addsub_ext.ADD_64_addsub_ext",
            "    add sp, x1, xzr, sxtx #3",
            A64Insn::AddAddsubExtAdd64AddsubExt {
                rm: x(31),
                option: 7,
                imm3: uimm(3, 3),
                rn: xsp(1),
                rd: xsp(31),
            },
        ),
        case(
            "ADD_addsub_ext.ADD_64_addsub_ext",
            "    add x2, x3, w4, sxtw #2",
            A64Insn::AddAddsubExtAdd64AddsubExt {
                rm: x(4),
                option: 6,
                imm3: uimm(2, 3),
                rn: xsp(3),
                rd: xsp(2),
            },
        ),
        case(
            "ADDS_addsub_ext.ADDS_32S_addsub_ext",
            "    adds w3, w4, w5, sxth #2",
            A64Insn::AddsAddsubExtAdds32sAddsubExt {
                rm: w(5),
                option: 5,
                imm3: uimm(2, 3),
                rn: wsp(4),
                rd: w(3),
            },
        ),
        case(
            "ADDS_addsub_ext.ADDS_64S_addsub_ext",
            "    cmn sp, w6, sxtw",
            A64Insn::AddsAddsubExtAdds64sAddsubExt {
                rm: x(6),
                option: 6,
                imm3: uimm(0, 3),
                rn: xsp(31),
                rd: x(31),
            },
        ),
        case(
            "SUB_addsub_ext.SUB_32_addsub_ext",
            "    sub wsp, wsp, w7, uxth",
            A64Insn::SubAddsubExtSub32AddsubExt {
                rm: w(7),
                option: 1,
                imm3: uimm(0, 3),
                rn: wsp(31),
                rd: wsp(31),
            },
        ),
        case(
            "SUB_addsub_ext.SUB_64_addsub_ext",
            "    sub x8, sp, x9, uxtx #1",
            A64Insn::SubAddsubExtSub64AddsubExt {
                rm: x(9),
                option: 3,
                imm3: uimm(1, 3),
                rn: xsp(31),
                rd: xsp(8),
            },
        ),
        case(
            "SUBS_addsub_ext.SUBS_32S_addsub_ext",
            "    cmp wsp, w10, uxtw #1",
            A64Insn::SubsAddsubExtSubs32sAddsubExt {
                rm: w(10),
                option: 2,
                imm3: uimm(1, 3),
                rn: wsp(31),
                rd: w(31),
            },
        ),
        case(
            "SUBS_addsub_ext.SUBS_64S_addsub_ext",
            "    subs x11, x12, w13, sxtb #4",
            A64Insn::SubsAddsubExtSubs64sAddsubExt {
                rm: x(13),
                option: 4,
                imm3: uimm(4, 3),
                rn: xsp(12),
                rd: x(11),
            },
        ),
        // MOVN
        case(
            "MOVN.MOVN_32_movewide",
            "    movn w0, #0xffff, lsl #16",
            A64Insn::MovnMovn32Movewide {
                hw: 1,
                imm16: uimm(0xffff, 16),
                rd: w(0),
            },
        ),
        case(
            "MOVN.MOVN_64_movewide",
            "    movn x1, #0x1234, lsl #48",
            A64Insn::MovnMovn64Movewide {
                hw: 3,
                imm16: uimm(0x1234, 16),
                rd: x(1),
            },
        ),
        case(
            "MOVN.MOVN_64_movewide",
            "    mov xzr, #-1",
            A64Insn::MovnMovn64Movewide {
                hw: 0,
                imm16: uimm(0, 16),
                rd: x(31),
            },
        ),
        // Logical (shifted register): ROR is a valid shift here.
        case(
            "AND_log_shift.AND_32_log_shift",
            "    and w0, w1, w2, ror #31",
            A64Insn::AndLogShiftAnd32LogShift {
                shift: 3,
                rm: w(2),
                imm6: uimm(31, 6),
                rn: w(1),
                rd: w(0),
            },
        ),
        case(
            "AND_log_shift.AND_64_log_shift",
            "    and x0, x1, x2, asr #63",
            A64Insn::AndLogShiftAnd64LogShift {
                shift: 2,
                rm: x(2),
                imm6: uimm(63, 6),
                rn: x(1),
                rd: x(0),
            },
        ),
        case(
            "ANDS_log_shift.ANDS_32_log_shift",
            "    tst w3, w4",
            A64Insn::AndsLogShiftAnds32LogShift {
                shift: 0,
                rm: w(4),
                imm6: uimm(0, 6),
                rn: w(3),
                rd: w(31),
            },
        ),
        case(
            "ANDS_log_shift.ANDS_64_log_shift",
            "    ands x5, x6, x7, lsr #1",
            A64Insn::AndsLogShiftAnds64LogShift {
                shift: 1,
                rm: x(7),
                imm6: uimm(1, 6),
                rn: x(6),
                rd: x(5),
            },
        ),
        case(
            "ORR_log_shift.ORR_32_log_shift",
            "    mov w0, w19",
            A64Insn::OrrLogShiftOrr32LogShift {
                shift: 0,
                rm: w(19),
                imm6: uimm(0, 6),
                rn: w(31),
                rd: w(0),
            },
        ),
        case(
            "ORR_log_shift.ORR_64_log_shift",
            "    orr xzr, xzr, xzr, ror #63",
            A64Insn::OrrLogShiftOrr64LogShift {
                shift: 3,
                rm: x(31),
                imm6: uimm(63, 6),
                rn: x(31),
                rd: x(31),
            },
        ),
        case(
            "EOR_log_shift.EOR_32_log_shift",
            "    eor w8, w9, w10, lsl #5",
            A64Insn::EorLogShiftEor32LogShift {
                shift: 0,
                rm: w(10),
                imm6: uimm(5, 6),
                rn: w(9),
                rd: w(8),
            },
        ),
        case(
            "EOR_log_shift.EOR_64_log_shift",
            "    eor x8, x9, x10, lsr #33",
            A64Insn::EorLogShiftEor64LogShift {
                shift: 1,
                rm: x(10),
                imm6: uimm(33, 6),
                rn: x(9),
                rd: x(8),
            },
        ),
        case(
            "EON.EON_32_log_shift",
            "    eon w11, w12, w13",
            A64Insn::EonEon32LogShift {
                shift: 0,
                rm: w(13),
                imm6: uimm(0, 6),
                rn: w(12),
                rd: w(11),
            },
        ),
        case(
            "EON.EON_64_log_shift",
            "    eon x11, x12, x13, asr #2",
            A64Insn::EonEon64LogShift {
                shift: 2,
                rm: x(13),
                imm6: uimm(2, 6),
                rn: x(12),
                rd: x(11),
            },
        ),
        case(
            "BIC_log_shift.BIC_32_log_shift",
            "    bic w14, w15, w16, ror #1",
            A64Insn::BicLogShiftBic32LogShift {
                shift: 3,
                rm: w(16),
                imm6: uimm(1, 6),
                rn: w(15),
                rd: w(14),
            },
        ),
        case(
            "BIC_log_shift.BIC_64_log_shift",
            "    bic x14, x15, x16",
            A64Insn::BicLogShiftBic64LogShift {
                shift: 0,
                rm: x(16),
                imm6: uimm(0, 6),
                rn: x(15),
                rd: x(14),
            },
        ),
        case(
            "BICS.BICS_32_log_shift",
            "    bics w17, w18, w19, lsl #31",
            A64Insn::BicsBics32LogShift {
                shift: 0,
                rm: w(19),
                imm6: uimm(31, 6),
                rn: w(18),
                rd: w(17),
            },
        ),
        case(
            "BICS.BICS_64_log_shift",
            "    bics xzr, x18, x19",
            A64Insn::BicsBics64LogShift {
                shift: 0,
                rm: x(19),
                imm6: uimm(0, 6),
                rn: x(18),
                rd: x(31),
            },
        ),
        case(
            "ORN_log_shift.ORN_32_log_shift",
            "    mvn w0, w1",
            A64Insn::OrnLogShiftOrn32LogShift {
                shift: 0,
                rm: w(1),
                imm6: uimm(0, 6),
                rn: w(31),
                rd: w(0),
            },
        ),
        case(
            "ORN_log_shift.ORN_64_log_shift",
            "    orn x20, x21, x22, lsr #63",
            A64Insn::OrnLogShiftOrn64LogShift {
                shift: 1,
                rm: x(22),
                imm6: uimm(63, 6),
                rn: x(21),
                rd: x(20),
            },
        ),
        // Logical (immediate): Rd is SP-capable except for ANDS; Rn is always ZR.
        case(
            "AND_log_imm.AND_32_log_imm",
            "    and w0, w1, #0xff",
            A64Insn::AndLogImmAnd32LogImm {
                immr: uimm(0, 6),
                imms: uimm(7, 6),
                rn: w(1),
                rd: wsp(0),
            },
        ),
        case(
            "AND_log_imm.AND_64_log_imm",
            "    and sp, x1, #0xfffffffffffffff0",
            A64Insn::AndLogImmAnd64LogImm {
                n: 1,
                immr: uimm(60, 6),
                imms: uimm(59, 6),
                rn: x(1),
                rd: xsp(31),
            },
        ),
        case(
            "ANDS_log_imm.ANDS_32S_log_imm",
            "    tst w0, #0x80000000",
            A64Insn::AndsLogImmAnds32sLogImm {
                immr: uimm(1, 6),
                imms: uimm(0, 6),
                rn: w(0),
                rd: w(31),
            },
        ),
        case(
            "ANDS_log_imm.ANDS_64S_log_imm",
            "    ands x1, x2, #0x5555555555555555",
            A64Insn::AndsLogImmAnds64sLogImm {
                n: 0,
                immr: uimm(0, 6),
                imms: uimm(0b111100, 6),
                rn: x(2),
                rd: x(1),
            },
        ),
        case(
            "ORR_log_imm.ORR_32_log_imm",
            "    orr wsp, w1, #0x3",
            A64Insn::OrrLogImmOrr32LogImm {
                immr: uimm(0, 6),
                imms: uimm(1, 6),
                rn: w(1),
                rd: wsp(31),
            },
        ),
        case(
            "ORR_log_imm.ORR_64_log_imm",
            "    orr x0, xzr, #0x00ff00ff00ff00ff",
            A64Insn::OrrLogImmOrr64LogImm {
                n: 0,
                immr: uimm(0, 6),
                imms: uimm(0b100111, 6),
                rn: x(31),
                rd: xsp(0),
            },
        ),
        case(
            "EOR_log_imm.EOR_32_log_imm",
            "    eor w0, w1, #0xfffffffe",
            A64Insn::EorLogImmEor32LogImm {
                immr: uimm(31, 6),
                imms: uimm(30, 6),
                rn: w(1),
                rd: wsp(0),
            },
        ),
        case(
            "EOR_log_imm.EOR_64_log_imm",
            "    eor x0, x1, #0x8000000000000000",
            A64Insn::EorLogImmEor64LogImm {
                n: 1,
                immr: uimm(1, 6),
                imms: uimm(0, 6),
                rn: x(1),
                rd: xsp(0),
            },
        ),
        // Bitfield moves: immr/imms edge values and the common aliases.
        case(
            "SBFM.SBFM_32M_bitfield",
            "    asr w0, w1, #31",
            A64Insn::SbfmSbfm32mBitfield {
                immr: uimm(31, 6),
                imms: uimm(31, 6),
                rn: w(1),
                rd: w(0),
            },
        ),
        case(
            "SBFM.SBFM_32M_bitfield",
            "    sxtb w2, w3",
            A64Insn::SbfmSbfm32mBitfield {
                immr: uimm(0, 6),
                imms: uimm(7, 6),
                rn: w(3),
                rd: w(2),
            },
        ),
        case(
            "SBFM.SBFM_64M_bitfield",
            "    sxtw x0, w1",
            A64Insn::SbfmSbfm64mBitfield {
                immr: uimm(0, 6),
                imms: uimm(31, 6),
                rn: x(1),
                rd: x(0),
            },
        ),
        case(
            "SBFM.SBFM_64M_bitfield",
            "    sbfm x2, x3, #63, #63",
            A64Insn::SbfmSbfm64mBitfield {
                immr: uimm(63, 6),
                imms: uimm(63, 6),
                rn: x(3),
                rd: x(2),
            },
        ),
        case(
            "UBFM.UBFM_32M_bitfield",
            "    lsl w0, w1, #1",
            A64Insn::UbfmUbfm32mBitfield {
                immr: uimm(31, 6),
                imms: uimm(30, 6),
                rn: w(1),
                rd: w(0),
            },
        ),
        case(
            "UBFM.UBFM_32M_bitfield",
            "    uxtb w2, w3",
            A64Insn::UbfmUbfm32mBitfield {
                immr: uimm(0, 6),
                imms: uimm(7, 6),
                rn: w(3),
                rd: w(2),
            },
        ),
        case(
            "UBFM.UBFM_64M_bitfield",
            "    lsl x0, x1, #63",
            A64Insn::UbfmUbfm64mBitfield {
                immr: uimm(1, 6),
                imms: uimm(0, 6),
                rn: x(1),
                rd: x(0),
            },
        ),
        case(
            "UBFM.UBFM_64M_bitfield",
            "    lsr x2, x3, #63",
            A64Insn::UbfmUbfm64mBitfield {
                immr: uimm(63, 6),
                imms: uimm(63, 6),
                rn: x(3),
                rd: x(2),
            },
        ),
        case(
            "UBFM.UBFM_64M_bitfield",
            "    ubfx x4, x5, #4, #8",
            A64Insn::UbfmUbfm64mBitfield {
                immr: uimm(4, 6),
                imms: uimm(11, 6),
                rn: x(5),
                rd: x(4),
            },
        ),
        case(
            "BFM.BFM_32M_bitfield",
            "    bfi w0, w1, #3, #4",
            A64Insn::BfmBfm32mBitfield {
                immr: uimm(29, 6),
                imms: uimm(3, 6),
                rn: w(1),
                rd: w(0),
            },
        ),
        case(
            "BFM.BFM_64M_bitfield",
            "    bfm x0, x1, #63, #0",
            A64Insn::BfmBfm64mBitfield {
                immr: uimm(63, 6),
                imms: uimm(0, 6),
                rn: x(1),
                rd: x(0),
            },
        ),
        case(
            "BFM.BFM_64M_bitfield",
            "    bfxil x2, x3, #8, #56",
            A64Insn::BfmBfm64mBitfield {
                immr: uimm(8, 6),
                imms: uimm(63, 6),
                rn: x(3),
                rd: x(2),
            },
        ),
        // EXTR (ror immediate is EXTR with Rn == Rm)
        case(
            "EXTR.EXTR_32_extract",
            "    extr w0, w1, w2, #31",
            A64Insn::ExtrExtr32Extract {
                rm: w(2),
                imms: uimm(31, 6),
                rn: w(1),
                rd: w(0),
            },
        ),
        case(
            "EXTR.EXTR_64_extract",
            "    ror x0, x1, #63",
            A64Insn::ExtrExtr64Extract {
                rm: x(1),
                imms: uimm(63, 6),
                rn: x(1),
                rd: x(0),
            },
        ),
        case(
            "EXTR.EXTR_64_extract",
            "    extr x3, x4, x5, #0",
            A64Insn::ExtrExtr64Extract {
                rm: x(5),
                imms: uimm(0, 6),
                rn: x(4),
                rd: x(3),
            },
        ),
        // Conditional select and its aliases (cset/csetm/cinc/cneg invert cond).
        case(
            "CSEL.CSEL_32_condsel",
            "    csel w0, w1, w2, eq",
            A64Insn::CselCsel32Condsel {
                rm: w(2),
                cond: 0x0,
                rn: w(1),
                rd: w(0),
            },
        ),
        case(
            "CSEL.CSEL_64_condsel",
            "    csel x0, x1, xzr, nv",
            A64Insn::CselCsel64Condsel {
                rm: x(31),
                cond: 0xf,
                rn: x(1),
                rd: x(0),
            },
        ),
        case(
            "CSINC.CSINC_32_condsel",
            "    cset w0, hi",
            A64Insn::CsincCsinc32Condsel {
                rm: w(31),
                cond: 0x9,
                rn: w(31),
                rd: w(0),
            },
        ),
        case(
            "CSINC.CSINC_64_condsel",
            "    cinc x0, x1, lo",
            A64Insn::CsincCsinc64Condsel {
                rm: x(1),
                cond: 0x2,
                rn: x(1),
                rd: x(0),
            },
        ),
        case(
            "CSINV.CSINV_32_condsel",
            "    csinv w3, w4, w5, vs",
            A64Insn::CsinvCsinv32Condsel {
                rm: w(5),
                cond: 0x6,
                rn: w(4),
                rd: w(3),
            },
        ),
        case(
            "CSINV.CSINV_64_condsel",
            "    csetm x0, ne",
            A64Insn::CsinvCsinv64Condsel {
                rm: x(31),
                cond: 0x0,
                rn: x(31),
                rd: x(0),
            },
        ),
        case(
            "CSNEG.CSNEG_32_condsel",
            "    cneg w0, w1, mi",
            A64Insn::CsnegCsneg32Condsel {
                rm: w(1),
                cond: 0x5,
                rn: w(1),
                rd: w(0),
            },
        ),
        case(
            "CSNEG.CSNEG_64_condsel",
            "    csneg x6, x7, x8, le",
            A64Insn::CsnegCsneg64Condsel {
                rm: x(8),
                cond: 0xd,
                rn: x(7),
                rd: x(6),
            },
        ),
        // Conditional compare
        case(
            "CCMP_imm.CCMP_32_condcmp_imm",
            "    ccmp w0, #31, #15, hs",
            A64Insn::CcmpImmCcmp32CondcmpImm {
                imm5: uimm(31, 5),
                cond: 0x2,
                rn: w(0),
                nzcv: 0xf,
            },
        ),
        case(
            "CCMP_imm.CCMP_64_condcmp_imm",
            "    ccmp x1, #0, #0, vc",
            A64Insn::CcmpImmCcmp64CondcmpImm {
                imm5: uimm(0, 5),
                cond: 0x7,
                rn: x(1),
                nzcv: 0x0,
            },
        ),
        case(
            "CCMP_reg.CCMP_32_condcmp_reg",
            "    ccmp w2, w3, #4, gt",
            A64Insn::CcmpRegCcmp32CondcmpReg {
                rm: w(3),
                cond: 0xc,
                rn: w(2),
                nzcv: 0x4,
            },
        ),
        case(
            "CCMP_reg.CCMP_64_condcmp_reg",
            "    ccmp x4, xzr, #8, ls",
            A64Insn::CcmpRegCcmp64CondcmpReg {
                rm: x(31),
                cond: 0x9,
                rn: x(4),
                nzcv: 0x8,
            },
        ),
        case(
            "CCMN_imm.CCMN_32_condcmp_imm",
            "    ccmn w5, #1, #2, pl",
            A64Insn::CcmnImmCcmn32CondcmpImm {
                imm5: uimm(1, 5),
                cond: 0x5,
                rn: w(5),
                nzcv: 0x2,
            },
        ),
        case(
            "CCMN_imm.CCMN_64_condcmp_imm",
            "    ccmn xzr, #16, #1, al",
            A64Insn::CcmnImmCcmn64CondcmpImm {
                imm5: uimm(16, 5),
                cond: 0xe,
                rn: x(31),
                nzcv: 0x1,
            },
        ),
        case(
            "CCMN_reg.CCMN_32_condcmp_reg",
            "    ccmn w6, w7, #9, lt",
            A64Insn::CcmnRegCcmn32CondcmpReg {
                rm: w(7),
                cond: 0xb,
                rn: w(6),
                nzcv: 0x9,
            },
        ),
        case(
            "CCMN_reg.CCMN_64_condcmp_reg",
            "    ccmn x8, x9, #6, ge",
            A64Insn::CcmnRegCcmn64CondcmpReg {
                rm: x(9),
                cond: 0xa,
                rn: x(8),
                nzcv: 0x6,
            },
        ),
        // Data-processing (2 source)
        case(
            "LSLV.LSLV_32_dp_2src",
            "    lsl w0, w1, w2",
            A64Insn::LslvLslv32Dp2src {
                rm: w(2),
                rn: w(1),
                rd: w(0),
            },
        ),
        case(
            "LSLV.LSLV_64_dp_2src",
            "    lslv x0, x1, xzr",
            A64Insn::LslvLslv64Dp2src {
                rm: x(31),
                rn: x(1),
                rd: x(0),
            },
        ),
        case(
            "LSRV.LSRV_32_dp_2src",
            "    lsrv w3, w4, w5",
            A64Insn::LsrvLsrv32Dp2src {
                rm: w(5),
                rn: w(4),
                rd: w(3),
            },
        ),
        case(
            "LSRV.LSRV_64_dp_2src",
            "    lsr x3, x4, x5",
            A64Insn::LsrvLsrv64Dp2src {
                rm: x(5),
                rn: x(4),
                rd: x(3),
            },
        ),
        case(
            "ASRV.ASRV_32_dp_2src",
            "    asr w6, w7, w8",
            A64Insn::AsrvAsrv32Dp2src {
                rm: w(8),
                rn: w(7),
                rd: w(6),
            },
        ),
        case(
            "ASRV.ASRV_64_dp_2src",
            "    asrv x6, x7, x8",
            A64Insn::AsrvAsrv64Dp2src {
                rm: x(8),
                rn: x(7),
                rd: x(6),
            },
        ),
        case(
            "RORV.RORV_32_dp_2src",
            "    ror w9, w10, w11",
            A64Insn::RorvRorv32Dp2src {
                rm: w(11),
                rn: w(10),
                rd: w(9),
            },
        ),
        case(
            "RORV.RORV_64_dp_2src",
            "    rorv x9, x10, x11",
            A64Insn::RorvRorv64Dp2src {
                rm: x(11),
                rn: x(10),
                rd: x(9),
            },
        ),
        case(
            "UDIV.UDIV_32_dp_2src",
            "    udiv w12, w13, w14",
            A64Insn::UdivUdiv32Dp2src {
                rm: w(14),
                rn: w(13),
                rd: w(12),
            },
        ),
        case(
            "UDIV.UDIV_64_dp_2src",
            "    udiv x12, x13, x14",
            A64Insn::UdivUdiv64Dp2src {
                rm: x(14),
                rn: x(13),
                rd: x(12),
            },
        ),
        case(
            "SDIV.SDIV_32_dp_2src",
            "    sdiv w15, w16, w17",
            A64Insn::SdivSdiv32Dp2src {
                rm: w(17),
                rn: w(16),
                rd: w(15),
            },
        ),
        case(
            "SDIV.SDIV_64_dp_2src",
            "    sdiv x15, x16, x17",
            A64Insn::SdivSdiv64Dp2src {
                rm: x(17),
                rn: x(16),
                rd: x(15),
            },
        ),
        // Data-processing (3 source)
        case(
            "MADD.MADD_32A_dp_3src",
            "    mul w0, w1, w2",
            A64Insn::MaddMadd32aDp3src {
                rm: w(2),
                ra: w(31),
                rn: w(1),
                rd: w(0),
            },
        ),
        case(
            "MADD.MADD_64A_dp_3src",
            "    madd x0, x1, x2, x3",
            A64Insn::MaddMadd64aDp3src {
                rm: x(2),
                ra: x(3),
                rn: x(1),
                rd: x(0),
            },
        ),
        case(
            "MSUB.MSUB_32A_dp_3src",
            "    mneg w4, w5, w6",
            A64Insn::MsubMsub32aDp3src {
                rm: w(6),
                ra: w(31),
                rn: w(5),
                rd: w(4),
            },
        ),
        case(
            "MSUB.MSUB_64A_dp_3src",
            "    msub x4, x5, x6, x7",
            A64Insn::MsubMsub64aDp3src {
                rm: x(6),
                ra: x(7),
                rn: x(5),
                rd: x(4),
            },
        ),
        case(
            "SMADDL.SMADDL_64WA_dp_3src",
            "    smull x8, w9, w10",
            A64Insn::SmaddlSmaddl64waDp3src {
                rm: w(10),
                ra: x(31),
                rn: w(9),
                rd: x(8),
            },
        ),
        case(
            "UMADDL.UMADDL_64WA_dp_3src",
            "    umaddl x8, w9, w10, x11",
            A64Insn::UmaddlUmaddl64waDp3src {
                rm: w(10),
                ra: x(11),
                rn: w(9),
                rd: x(8),
            },
        ),
        case(
            "SMULH.SMULH_64_dp_3src",
            "    smulh x12, x13, x14",
            A64Insn::SmulhSmulh64Dp3src {
                rm: x(14),
                rn: x(13),
                rd: x(12),
            },
        ),
        case(
            "UMULH.UMULH_64_dp_3src",
            "    umulh x12, x13, x14",
            A64Insn::UmulhUmulh64Dp3src {
                rm: x(14),
                rn: x(13),
                rd: x(12),
            },
        ),
        // Data-processing (1 source)
        case(
            "CLZ_int.CLZ_32_dp_1src",
            "    clz w0, w1",
            A64Insn::ClzIntClz32Dp1src { rn: w(1), rd: w(0) },
        ),
        case(
            "CLZ_int.CLZ_64_dp_1src",
            "    clz x0, x1",
            A64Insn::ClzIntClz64Dp1src { rn: x(1), rd: x(0) },
        ),
        case(
            "RBIT_int.RBIT_32_dp_1src",
            "    rbit w2, w3",
            A64Insn::RbitIntRbit32Dp1src { rn: w(3), rd: w(2) },
        ),
        case(
            "RBIT_int.RBIT_64_dp_1src",
            "    rbit x2, x3",
            A64Insn::RbitIntRbit64Dp1src { rn: x(3), rd: x(2) },
        ),
        case(
            "REV.REV_32_dp_1src",
            "    rev w4, w5",
            A64Insn::RevRev32Dp1src { rn: w(5), rd: w(4) },
        ),
        case(
            "REV.REV_64_dp_1src",
            "    rev x4, x5",
            A64Insn::RevRev64Dp1src { rn: x(5), rd: x(4) },
        ),
        case(
            "REV16_int.REV16_32_dp_1src",
            "    rev16 w6, w7",
            A64Insn::Rev16IntRev1632Dp1src { rn: w(7), rd: w(6) },
        ),
        case(
            "REV16_int.REV16_64_dp_1src",
            "    rev16 x6, x7",
            A64Insn::Rev16IntRev1664Dp1src { rn: x(7), rd: x(6) },
        ),
        case(
            "REV32_int.REV32_64_dp_1src",
            "    rev32 x8, x9",
            A64Insn::Rev32IntRev3264Dp1src { rn: x(9), rd: x(8) },
        ),
        // MRS: TPIDR_EL0 only.
        case(
            "MRS.MRS_RS_systemmove",
            "    mrs x1, tpidr_el0",
            A64Insn::MrsMrsRsSystemmove { rt: x(1) },
        ),
        case(
            "MRS.MRS_RS_systemmove",
            "    mrs xzr, tpidr_el0",
            A64Insn::MrsMrsRsSystemmove { rt: x(31) },
        ),
    ]
}

/// A7b memory forms: every addressing mode, SP bases, XZR/WZR transfers, and the
/// ends of every offset range.
fn mem_encoding_cases() -> Vec<EncodingCase> {
    vec![
        case(
            "LDRB_imm.LDRB_32_ldst_pos",
            "    ldrb w1, [x2, #4095]",
            A64Insn::LdrbImmLdrb32LdstPos {
                rt: w(1),
                mem: A64Mem::offset(xsp(2), A64Imm::scaled_unsigned(4095, 12, 0)),
            },
        ),
        case(
            "LDRB_imm.LDRB_32_ldst_immpre",
            "    ldrb w3, [sp, #-256]!",
            A64Insn::LdrbImmLdrb32LdstImmpre {
                rt: w(3),
                mem: A64Mem::pre_index(xsp(31), simm9(-256)),
            },
        ),
        case(
            "LDRB_imm.LDRB_32_ldst_immpost",
            "    ldrb wzr, [x4], #255",
            A64Insn::LdrbImmLdrb32LdstImmpost {
                rt: w(31),
                mem: A64Mem::post_index(xsp(4), simm9(255)),
            },
        ),
        case(
            "STRB_imm.STRB_32_ldst_pos",
            "    strb w5, [sp, #1]",
            A64Insn::StrbImmStrb32LdstPos {
                rt: w(5),
                mem: A64Mem::offset(xsp(31), A64Imm::scaled_unsigned(1, 12, 0)),
            },
        ),
        case(
            "STRB_imm.STRB_32_ldst_immpre",
            "    strb w6, [x7, #255]!",
            A64Insn::StrbImmStrb32LdstImmpre {
                rt: w(6),
                mem: A64Mem::pre_index(xsp(7), simm9(255)),
            },
        ),
        case(
            "STRB_imm.STRB_32_ldst_immpost",
            "    strb wzr, [x8], #-1",
            A64Insn::StrbImmStrb32LdstImmpost {
                rt: w(31),
                mem: A64Mem::post_index(xsp(8), simm9(-1)),
            },
        ),
        case(
            "LDRH_imm.LDRH_32_ldst_pos",
            "    ldrh w9, [x10, #8190]",
            A64Insn::LdrhImmLdrh32LdstPos {
                rt: w(9),
                mem: A64Mem::offset(xsp(10), A64Imm::scaled_unsigned(4095, 12, 1)),
            },
        ),
        case(
            "LDRH_imm.LDRH_32_ldst_immpre",
            "    ldrh w11, [x12, #-2]!",
            A64Insn::LdrhImmLdrh32LdstImmpre {
                rt: w(11),
                mem: A64Mem::pre_index(xsp(12), simm9(-2)),
            },
        ),
        case(
            "LDRH_imm.LDRH_32_ldst_immpost",
            "    ldrh w13, [sp], #2",
            A64Insn::LdrhImmLdrh32LdstImmpost {
                rt: w(13),
                mem: A64Mem::post_index(xsp(31), simm9(2)),
            },
        ),
        case(
            "STRH_imm.STRH_32_ldst_pos",
            "    strh wzr, [x14, #2]",
            A64Insn::StrhImmStrh32LdstPos {
                rt: w(31),
                mem: A64Mem::offset(xsp(14), A64Imm::scaled_unsigned(1, 12, 1)),
            },
        ),
        case(
            "STRH_imm.STRH_32_ldst_immpre",
            "    strh w15, [x16, #-256]!",
            A64Insn::StrhImmStrh32LdstImmpre {
                rt: w(15),
                mem: A64Mem::pre_index(xsp(16), simm9(-256)),
            },
        ),
        case(
            "STRH_imm.STRH_32_ldst_immpost",
            "    strh w17, [x18], #254",
            A64Insn::StrhImmStrh32LdstImmpost {
                rt: w(17),
                mem: A64Mem::post_index(xsp(18), simm9(254)),
            },
        ),
        case(
            "LDRSB_imm.LDRSB_32_ldst_pos",
            "    ldrsb w0, [x1, #0]",
            A64Insn::LdrsbImmLdrsb32LdstPos {
                rt: w(0),
                mem: A64Mem::offset(xsp(1), A64Imm::scaled_unsigned(0, 12, 0)),
            },
        ),
        case(
            "LDRSB_imm.LDRSB_32_ldst_immpre",
            "    ldrsb w2, [x3, #-1]!",
            A64Insn::LdrsbImmLdrsb32LdstImmpre {
                rt: w(2),
                mem: A64Mem::pre_index(xsp(3), simm9(-1)),
            },
        ),
        case(
            "LDRSB_imm.LDRSB_32_ldst_immpost",
            "    ldrsb w4, [sp], #1",
            A64Insn::LdrsbImmLdrsb32LdstImmpost {
                rt: w(4),
                mem: A64Mem::post_index(xsp(31), simm9(1)),
            },
        ),
        case(
            "LDRSB_imm.LDRSB_64_ldst_pos",
            "    ldrsb x5, [x6, #4095]",
            A64Insn::LdrsbImmLdrsb64LdstPos {
                rt: x(5),
                mem: A64Mem::offset(xsp(6), A64Imm::scaled_unsigned(4095, 12, 0)),
            },
        ),
        case(
            "LDRSB_imm.LDRSB_64_ldst_immpre",
            "    ldrsb xzr, [x7, #-256]!",
            A64Insn::LdrsbImmLdrsb64LdstImmpre {
                rt: x(31),
                mem: A64Mem::pre_index(xsp(7), simm9(-256)),
            },
        ),
        case(
            "LDRSB_imm.LDRSB_64_ldst_immpost",
            "    ldrsb x8, [x9], #255",
            A64Insn::LdrsbImmLdrsb64LdstImmpost {
                rt: x(8),
                mem: A64Mem::post_index(xsp(9), simm9(255)),
            },
        ),
        case(
            "LDRSH_imm.LDRSH_32_ldst_pos",
            "    ldrsh w10, [x11, #8190]",
            A64Insn::LdrshImmLdrsh32LdstPos {
                rt: w(10),
                mem: A64Mem::offset(xsp(11), A64Imm::scaled_unsigned(4095, 12, 1)),
            },
        ),
        case(
            "LDRSH_imm.LDRSH_32_ldst_immpre",
            "    ldrsh w12, [x13, #-2]!",
            A64Insn::LdrshImmLdrsh32LdstImmpre {
                rt: w(12),
                mem: A64Mem::pre_index(xsp(13), simm9(-2)),
            },
        ),
        case(
            "LDRSH_imm.LDRSH_32_ldst_immpost",
            "    ldrsh w14, [x15], #2",
            A64Insn::LdrshImmLdrsh32LdstImmpost {
                rt: w(14),
                mem: A64Mem::post_index(xsp(15), simm9(2)),
            },
        ),
        case(
            "LDRSH_imm.LDRSH_64_ldst_pos",
            "    ldrsh x16, [sp, #2]",
            A64Insn::LdrshImmLdrsh64LdstPos {
                rt: x(16),
                mem: A64Mem::offset(xsp(31), A64Imm::scaled_unsigned(1, 12, 1)),
            },
        ),
        case(
            "LDRSH_imm.LDRSH_64_ldst_immpre",
            "    ldrsh x17, [x18, #254]!",
            A64Insn::LdrshImmLdrsh64LdstImmpre {
                rt: x(17),
                mem: A64Mem::pre_index(xsp(18), simm9(254)),
            },
        ),
        case(
            "LDRSH_imm.LDRSH_64_ldst_immpost",
            "    ldrsh xzr, [x19], #-256",
            A64Insn::LdrshImmLdrsh64LdstImmpost {
                rt: x(31),
                mem: A64Mem::post_index(xsp(19), simm9(-256)),
            },
        ),
        case(
            "LDRSW_imm.LDRSW_64_ldst_pos",
            "    ldrsw x0, [x1, #16380]",
            A64Insn::LdrswImmLdrsw64LdstPos {
                rt: x(0),
                mem: A64Mem::offset(xsp(1), A64Imm::scaled_unsigned(4095, 12, 2)),
            },
        ),
        case(
            "LDRSW_imm.LDRSW_64_ldst_immpre",
            "    ldrsw x2, [x3, #-256]!",
            A64Insn::LdrswImmLdrsw64LdstImmpre {
                rt: x(2),
                mem: A64Mem::pre_index(xsp(3), simm9(-256)),
            },
        ),
        case(
            "LDRSW_imm.LDRSW_64_ldst_immpost",
            "    ldrsw xzr, [sp], #255",
            A64Insn::LdrswImmLdrsw64LdstImmpost {
                rt: x(31),
                mem: A64Mem::post_index(xsp(31), simm9(255)),
            },
        ),
        case(
            "LDUR_gen.LDUR_32_ldst_unscaled",
            "    ldur w0, [x1, #-256]",
            A64Insn::LdurGenLdur32LdstUnscaled {
                rt: w(0),
                mem: A64Mem::offset(xsp(1), simm9(-256)),
            },
        ),
        case(
            "LDUR_gen.LDUR_64_ldst_unscaled",
            "    ldur x2, [sp, #255]",
            A64Insn::LdurGenLdur64LdstUnscaled {
                rt: x(2),
                mem: A64Mem::offset(xsp(31), simm9(255)),
            },
        ),
        case(
            "STUR_gen.STUR_32_ldst_unscaled",
            "    stur wzr, [x3, #-1]",
            A64Insn::SturGenStur32LdstUnscaled {
                rt: w(31),
                mem: A64Mem::offset(xsp(3), simm9(-1)),
            },
        ),
        case(
            "STUR_gen.STUR_64_ldst_unscaled",
            "    stur x4, [x5, #3]",
            A64Insn::SturGenStur64LdstUnscaled {
                rt: x(4),
                mem: A64Mem::offset(xsp(5), simm9(3)),
            },
        ),
        case(
            "LDURB.LDURB_32_ldst_unscaled",
            "    ldurb w6, [x7, #-7]",
            A64Insn::LdurbLdurb32LdstUnscaled {
                rt: w(6),
                mem: A64Mem::offset(xsp(7), simm9(-7)),
            },
        ),
        case(
            "STURB.STURB_32_ldst_unscaled",
            "    sturb w8, [sp]",
            A64Insn::SturbSturb32LdstUnscaled {
                rt: w(8),
                mem: A64Mem::offset(xsp(31), simm9(0)),
            },
        ),
        case(
            "LDURH.LDURH_32_ldst_unscaled",
            "    ldurh w9, [x10, #1]",
            A64Insn::LdurhLdurh32LdstUnscaled {
                rt: w(9),
                mem: A64Mem::offset(xsp(10), simm9(1)),
            },
        ),
        case(
            "STURH.STURH_32_ldst_unscaled",
            "    sturh w11, [x12, #-255]",
            A64Insn::SturhSturh32LdstUnscaled {
                rt: w(11),
                mem: A64Mem::offset(xsp(12), simm9(-255)),
            },
        ),
        case(
            "LDURSB.LDURSB_32_ldst_unscaled",
            "    ldursb w13, [x14, #5]",
            A64Insn::LdursbLdursb32LdstUnscaled {
                rt: w(13),
                mem: A64Mem::offset(xsp(14), simm9(5)),
            },
        ),
        case(
            "LDURSB.LDURSB_64_ldst_unscaled",
            "    ldursb x15, [x16, #-5]",
            A64Insn::LdursbLdursb64LdstUnscaled {
                rt: x(15),
                mem: A64Mem::offset(xsp(16), simm9(-5)),
            },
        ),
        case(
            "LDURSH.LDURSH_32_ldst_unscaled",
            "    ldursh w17, [x18, #9]",
            A64Insn::LdurshLdursh32LdstUnscaled {
                rt: w(17),
                mem: A64Mem::offset(xsp(18), simm9(9)),
            },
        ),
        case(
            "LDURSH.LDURSH_64_ldst_unscaled",
            "    ldursh xzr, [x19, #-9]",
            A64Insn::LdurshLdursh64LdstUnscaled {
                rt: x(31),
                mem: A64Mem::offset(xsp(19), simm9(-9)),
            },
        ),
        case(
            "LDURSW.LDURSW_64_ldst_unscaled",
            "    ldursw x20, [x21, #-256]",
            A64Insn::LdurswLdursw64LdstUnscaled {
                rt: x(20),
                mem: A64Mem::offset(xsp(21), simm9(-256)),
            },
        ),
        case(
            "LDTRB.LDTRB_32_ldst_unpriv",
            "    ldtrb w0, [x1, #-256]",
            A64Insn::LdtrbLdtrb32LdstUnpriv {
                rt: w(0),
                mem: A64Mem::offset(xsp(1), simm9(-256)),
            },
        ),
        case(
            "STTRB.STTRB_32_ldst_unpriv",
            "    sttrb wzr, [sp, #255]",
            A64Insn::SttrbSttrb32LdstUnpriv {
                rt: w(31),
                mem: A64Mem::offset(xsp(31), simm9(255)),
            },
        ),
        case(
            "LDTRH.LDTRH_32_ldst_unpriv",
            "    ldtrh w2, [x3]",
            A64Insn::LdtrhLdtrh32LdstUnpriv {
                rt: w(2),
                mem: A64Mem::offset(xsp(3), simm9(0)),
            },
        ),
        case(
            "STTRH.STTRH_32_ldst_unpriv",
            "    sttrh w4, [x5, #-1]",
            A64Insn::SttrhSttrh32LdstUnpriv {
                rt: w(4),
                mem: A64Mem::offset(xsp(5), simm9(-1)),
            },
        ),
        case(
            "LDTRSB.LDTRSB_32_ldst_unpriv",
            "    ldtrsb w6, [x7, #1]",
            A64Insn::LdtrsbLdtrsb32LdstUnpriv {
                rt: w(6),
                mem: A64Mem::offset(xsp(7), simm9(1)),
            },
        ),
        case(
            "LDTRSB.LDTRSB_64_ldst_unpriv",
            "    ldtrsb x8, [sp]",
            A64Insn::LdtrsbLdtrsb64LdstUnpriv {
                rt: x(8),
                mem: A64Mem::offset(xsp(31), simm9(0)),
            },
        ),
        case(
            "LDTRSH.LDTRSH_32_ldst_unpriv",
            "    ldtrsh w9, [x10, #-2]",
            A64Insn::LdtrshLdtrsh32LdstUnpriv {
                rt: w(9),
                mem: A64Mem::offset(xsp(10), simm9(-2)),
            },
        ),
        case(
            "LDTRSH.LDTRSH_64_ldst_unpriv",
            "    ldtrsh x11, [x12, #2]",
            A64Insn::LdtrshLdtrsh64LdstUnpriv {
                rt: x(11),
                mem: A64Mem::offset(xsp(12), simm9(2)),
            },
        ),
        case(
            "LDTRSW.LDTRSW_64_ldst_unpriv",
            "    ldtrsw x13, [x14, #-4]",
            A64Insn::LdtrswLdtrsw64LdstUnpriv {
                rt: x(13),
                mem: A64Mem::offset(xsp(14), simm9(-4)),
            },
        ),
        case(
            "LDP_gen.LDP_32_ldstpair_post",
            "    ldp w0, w1, [x2], #-256",
            A64Insn::LdpGenLdp32LdstpairPost {
                rt2: w(1),
                rt: w(0),
                mem: A64Mem::post_index(xsp(2), pair_imm(-256, 2)),
            },
        ),
        case(
            "LDP_gen.LDP_32_ldstpair_pre",
            "    ldp w3, w4, [sp, #252]!",
            A64Insn::LdpGenLdp32LdstpairPre {
                rt2: w(4),
                rt: w(3),
                mem: A64Mem::pre_index(xsp(31), pair_imm(252, 2)),
            },
        ),
        case(
            "LDP_gen.LDP_32_ldstpair_off",
            "    ldp wzr, w5, [x6]",
            A64Insn::LdpGenLdp32LdstpairOff {
                rt2: w(5),
                rt: w(31),
                mem: A64Mem::offset(xsp(6), pair_imm(0, 2)),
            },
        ),
        case(
            "STP_gen.STP_32_ldstpair_post",
            "    stp w8, w9, [x10], #4",
            A64Insn::StpGenStp32LdstpairPost {
                rt2: w(9),
                rt: w(8),
                mem: A64Mem::post_index(xsp(10), pair_imm(4, 2)),
            },
        ),
        case(
            "STP_gen.STP_32_ldstpair_pre",
            "    stp w7, wzr, [sp, #-4]!",
            A64Insn::StpGenStp32LdstpairPre {
                rt2: w(31),
                rt: w(7),
                mem: A64Mem::pre_index(xsp(31), pair_imm(-4, 2)),
            },
        ),
        case(
            "STP_gen.STP_32_ldstpair_off",
            "    stp wzr, wzr, [x11, #8]",
            A64Insn::StpGenStp32LdstpairOff {
                rt2: w(31),
                rt: w(31),
                mem: A64Mem::offset(xsp(11), pair_imm(8, 2)),
            },
        ),
        case(
            "LDPSW.LDPSW_64_ldstpair_post",
            "    ldpsw x3, x4, [sp], #252",
            A64Insn::LdpswLdpsw64LdstpairPost {
                rt2: x(4),
                rt: x(3),
                mem: A64Mem::post_index(xsp(31), pair_imm(252, 2)),
            },
        ),
        case(
            "LDPSW.LDPSW_64_ldstpair_pre",
            "    ldpsw x0, x1, [x2, #-256]!",
            A64Insn::LdpswLdpsw64LdstpairPre {
                rt2: x(1),
                rt: x(0),
                mem: A64Mem::pre_index(xsp(2), pair_imm(-256, 2)),
            },
        ),
        case(
            "LDPSW.LDPSW_64_ldstpair_off",
            "    ldpsw x5, x6, [x7, #4]",
            A64Insn::LdpswLdpsw64LdstpairOff {
                rt2: x(6),
                rt: x(5),
                mem: A64Mem::offset(xsp(7), pair_imm(4, 2)),
            },
        ),
        case(
            "LDR_reg_gen.LDR_64_ldst_regoff",
            "    ldr x0, [x1, x2, lsl #3]",
            A64Insn::LdrRegGenLdr64LdstRegoff {
                rm: x(2),
                option: 0b011,
                s: 1,
                rn: xsp(1),
                rt: x(0),
            },
        ),
        case(
            "LDR_reg_gen.LDR_64_ldst_regoff",
            "    ldr x3, [sp, w4, sxtw]",
            A64Insn::LdrRegGenLdr64LdstRegoff {
                rm: x(4),
                option: 0b110,
                s: 0,
                rn: xsp(31),
                rt: x(3),
            },
        ),
        case(
            "LDR_reg_gen.LDR_64_ldst_regoff",
            "    ldr xzr, [x5, w6, uxtw #3]",
            A64Insn::LdrRegGenLdr64LdstRegoff {
                rm: x(6),
                option: 0b010,
                s: 1,
                rn: xsp(5),
                rt: x(31),
            },
        ),
        case(
            "LDR_reg_gen.LDR_64_ldst_regoff",
            "    ldr x7, [x8, x9, sxtx #3]",
            A64Insn::LdrRegGenLdr64LdstRegoff {
                rm: x(9),
                option: 0b111,
                s: 1,
                rn: xsp(8),
                rt: x(7),
            },
        ),
        case(
            "LDR_reg_gen.LDR_64_ldst_regoff",
            "    ldr x10, [x11, xzr]",
            A64Insn::LdrRegGenLdr64LdstRegoff {
                rm: x(31),
                option: 0b011,
                s: 0,
                rn: xsp(11),
                rt: x(10),
            },
        ),
        case(
            "LDR_reg_gen.LDR_32_ldst_regoff",
            "    ldr w0, [x1, w2, uxtw #2]",
            A64Insn::LdrRegGenLdr32LdstRegoff {
                rm: x(2),
                option: 0b010,
                s: 1,
                rn: xsp(1),
                rt: w(0),
            },
        ),
        case(
            "LDR_reg_gen.LDR_32_ldst_regoff",
            "    ldr w3, [x4, x5, sxtx]",
            A64Insn::LdrRegGenLdr32LdstRegoff {
                rm: x(5),
                option: 0b111,
                s: 0,
                rn: xsp(4),
                rt: w(3),
            },
        ),
        case(
            "STR_reg_gen.STR_64_ldst_regoff",
            "    str x0, [sp, x1, lsl #3]",
            A64Insn::StrRegGenStr64LdstRegoff {
                rm: x(1),
                option: 0b011,
                s: 1,
                rn: xsp(31),
                rt: x(0),
            },
        ),
        case(
            "STR_reg_gen.STR_32_ldst_regoff",
            "    str wzr, [x1, w2, sxtw #2]",
            A64Insn::StrRegGenStr32LdstRegoff {
                rm: x(2),
                option: 0b110,
                s: 1,
                rn: xsp(1),
                rt: w(31),
            },
        ),
        case(
            "LDRB_reg.LDRB_32B_ldst_regoff",
            "    ldrb w0, [x1, w2, uxtw]",
            A64Insn::LdrbRegLdrb32bLdstRegoff {
                rm: x(2),
                option: 0b010,
                s: 0,
                rn: xsp(1),
                rt: w(0),
            },
        ),
        case(
            "LDRB_reg.LDRB_32B_ldst_regoff",
            "    ldrb w3, [x4, w5, sxtw #0]",
            A64Insn::LdrbRegLdrb32bLdstRegoff {
                rm: x(5),
                option: 0b110,
                s: 1,
                rn: xsp(4),
                rt: w(3),
            },
        ),
        case(
            "LDRB_reg.LDRB_32B_ldst_regoff",
            "    ldrb w6, [x7, x8, sxtx]",
            A64Insn::LdrbRegLdrb32bLdstRegoff {
                rm: x(8),
                option: 0b111,
                s: 0,
                rn: xsp(7),
                rt: w(6),
            },
        ),
        case(
            "LDRB_reg.LDRB_32BL_ldst_regoff",
            "    ldrb w0, [x1, x2]",
            A64Insn::LdrbRegLdrb32blLdstRegoff {
                rm: x(2),
                s: 0,
                rn: xsp(1),
                rt: w(0),
            },
        ),
        case(
            "LDRB_reg.LDRB_32BL_ldst_regoff",
            "    ldrb w3, [x4, x5, lsl #0]",
            A64Insn::LdrbRegLdrb32blLdstRegoff {
                rm: x(5),
                s: 1,
                rn: xsp(4),
                rt: w(3),
            },
        ),
        case(
            "STRB_reg.STRB_32B_ldst_regoff",
            "    strb w0, [x1, w2, sxtw]",
            A64Insn::StrbRegStrb32bLdstRegoff {
                rm: x(2),
                option: 0b110,
                s: 0,
                rn: xsp(1),
                rt: w(0),
            },
        ),
        case(
            "STRB_reg.STRB_32BL_ldst_regoff",
            "    strb wzr, [sp, x3]",
            A64Insn::StrbRegStrb32blLdstRegoff {
                rm: x(3),
                s: 0,
                rn: xsp(31),
                rt: w(31),
            },
        ),
        case(
            "LDRH_reg.LDRH_32_ldst_regoff",
            "    ldrh w0, [x1, x2, lsl #1]",
            A64Insn::LdrhRegLdrh32LdstRegoff {
                rm: x(2),
                option: 0b011,
                s: 1,
                rn: xsp(1),
                rt: w(0),
            },
        ),
        case(
            "LDRH_reg.LDRH_32_ldst_regoff",
            "    ldrh w3, [x4, w5, sxtw]",
            A64Insn::LdrhRegLdrh32LdstRegoff {
                rm: x(5),
                option: 0b110,
                s: 0,
                rn: xsp(4),
                rt: w(3),
            },
        ),
        case(
            "STRH_reg.STRH_32_ldst_regoff",
            "    strh w0, [x1, w2, uxtw #1]",
            A64Insn::StrhRegStrh32LdstRegoff {
                rm: x(2),
                option: 0b010,
                s: 1,
                rn: xsp(1),
                rt: w(0),
            },
        ),
        case(
            "LDRSB_reg.LDRSB_32B_ldst_regoff",
            "    ldrsb w0, [x1, w2, uxtw #0]",
            A64Insn::LdrsbRegLdrsb32bLdstRegoff {
                rm: x(2),
                option: 0b010,
                s: 1,
                rn: xsp(1),
                rt: w(0),
            },
        ),
        case(
            "LDRSB_reg.LDRSB_32BL_ldst_regoff",
            "    ldrsb w3, [x4, x5]",
            A64Insn::LdrsbRegLdrsb32blLdstRegoff {
                rm: x(5),
                s: 0,
                rn: xsp(4),
                rt: w(3),
            },
        ),
        case(
            "LDRSB_reg.LDRSB_64B_ldst_regoff",
            "    ldrsb x6, [x7, w8, sxtw]",
            A64Insn::LdrsbRegLdrsb64bLdstRegoff {
                rm: x(8),
                option: 0b110,
                s: 0,
                rn: xsp(7),
                rt: x(6),
            },
        ),
        case(
            "LDRSB_reg.LDRSB_64BL_ldst_regoff",
            "    ldrsb x0, [x1, xzr, lsl #0]",
            A64Insn::LdrsbRegLdrsb64blLdstRegoff {
                rm: x(31),
                s: 1,
                rn: xsp(1),
                rt: x(0),
            },
        ),
        case(
            "LDRSH_reg.LDRSH_32_ldst_regoff",
            "    ldrsh w0, [x1, w2, sxtw #1]",
            A64Insn::LdrshRegLdrsh32LdstRegoff {
                rm: x(2),
                option: 0b110,
                s: 1,
                rn: xsp(1),
                rt: w(0),
            },
        ),
        case(
            "LDRSH_reg.LDRSH_64_ldst_regoff",
            "    ldrsh x3, [x4, x5, lsl #1]",
            A64Insn::LdrshRegLdrsh64LdstRegoff {
                rm: x(5),
                option: 0b011,
                s: 1,
                rn: xsp(4),
                rt: x(3),
            },
        ),
        case(
            "LDRSW_reg.LDRSW_64_ldst_regoff",
            "    ldrsw x0, [x1, w2, sxtw #2]",
            A64Insn::LdrswRegLdrsw64LdstRegoff {
                rm: x(2),
                option: 0b110,
                s: 1,
                rn: xsp(1),
                rt: x(0),
            },
        ),
        case(
            "LDRSW_reg.LDRSW_64_ldst_regoff",
            "    ldrsw x3, [sp, x4]",
            A64Insn::LdrswRegLdrsw64LdstRegoff {
                rm: x(4),
                option: 0b011,
                s: 0,
                rn: xsp(31),
                rt: x(3),
            },
        ),
        case(
            "LDR_lit_gen.LDR_32_loadlit",
            "    ldr w0, .Ltarget\n.Ltarget:",
            A64Insn::LdrLitGenLdr32Loadlit {
                imm19: literal_imm(1),
                rt: w(0),
            },
        ),
        case(
            "LDR_lit_gen.LDR_32_loadlit",
            "    ldr w1, . + 0xffffc",
            A64Insn::LdrLitGenLdr32Loadlit {
                imm19: literal_imm(262143),
                rt: w(1),
            },
        ),
        case(
            "LDR_lit_gen.LDR_64_loadlit",
            ".Ltarget:\n    ldr xzr, .Ltarget",
            A64Insn::LdrLitGenLdr64Loadlit {
                imm19: literal_imm(0),
                rt: x(31),
            },
        ),
        case(
            "LDR_lit_gen.LDR_64_loadlit",
            "    ldr x2, . - 0x100000",
            A64Insn::LdrLitGenLdr64Loadlit {
                imm19: literal_imm(-262144),
                rt: x(2),
            },
        ),
        case(
            "LDRSW_lit.LDRSW_64_loadlit",
            "    ldrsw x3, . - 4",
            A64Insn::LdrswLitLdrsw64Loadlit {
                imm19: literal_imm(-1),
                rt: x(3),
            },
        ),
        case(
            "PRFM_imm.PRFM_P_ldst_pos",
            "    prfm pldl1keep, [x0, #32760]",
            A64Insn::PrfmImmPrfmPLdstPos {
                imm12: uimm(4095, 12),
                rn: xsp(0),
                rt: 0,
            },
        ),
        case(
            "PRFM_imm.PRFM_P_ldst_pos",
            "    prfm pstl3strm, [sp]",
            A64Insn::PrfmImmPrfmPLdstPos {
                imm12: uimm(0, 12),
                rn: xsp(31),
                rt: 0b10101,
            },
        ),
        case(
            "PRFM_imm.PRFM_P_ldst_pos",
            "    prfm #31, [x1, #8]",
            A64Insn::PrfmImmPrfmPLdstPos {
                imm12: uimm(1, 12),
                rn: xsp(1),
                rt: 31,
            },
        ),
        case(
            "PRFM_lit.PRFM_P_loadlit",
            "    prfm pldl1keep, .Ltarget\n.Ltarget:",
            A64Insn::PrfmLitPrfmPLoadlit {
                imm19: uimm(1, 19),
                rt: 0,
            },
        ),
        case(
            "PRFM_reg.PRFM_P_ldst_regoff",
            "    prfm pldl2strm, [x0, x1, lsl #3]",
            A64Insn::PrfmRegPrfmPLdstRegoff {
                rm: x(1),
                option: 0b011,
                s: 1,
                rn: xsp(0),
                rt: 3,
            },
        ),
        case(
            "PRFM_reg.PRFM_P_ldst_regoff",
            "    prfm plil1keep, [sp, w2, sxtw]",
            A64Insn::PrfmRegPrfmPLdstRegoff {
                rm: x(2),
                option: 0b110,
                s: 0,
                rn: xsp(31),
                rt: 8,
            },
        ),
    ]
}

/// A7c: every CRm value of DMB/DSB/ISB (named options and the reserved `#imm`
/// ones; DSB 0000/0100 are SSBB/PSSBB) and every acquire/release form.
fn barrier_acqrel_encoding_cases() -> Vec<EncodingCase> {
    const OPTIONS: [&str; 16] = [
        "#0", "oshld", "oshst", "osh", "#4", "nshld", "nshst", "nsh", "#8", "ishld", "ishst",
        "ish", "#12", "ld", "st", "sy",
    ];
    let mut cases = Vec::new();
    for (crm, option) in OPTIONS.iter().enumerate() {
        let crm = crm as u8;
        cases.push(case(
            "DMB.DMB_BO_barriers",
            format!("    dmb {option}"),
            A64Insn::DmbDmbBoBarriers { crm },
        ));
        let dsb = match crm {
            0b0000 => "    ssbb".to_string(),
            0b0100 => "    pssbb".to_string(),
            _ => format!("    dsb {option}"),
        };
        cases.push(case(
            "DSB.DSB_BO_barriers",
            dsb,
            A64Insn::DsbDsbBoBarriers { crm },
        ));
        let isb = if crm == 0b1111 {
            "    isb".to_string()
        } else {
            format!("    isb #{crm}")
        };
        cases.push(case(
            "ISB.ISB_BI_barriers",
            isb,
            A64Insn::IsbIsbBiBarriers { crm },
        ));
    }
    cases.extend([
        case("DSB.DSB_BO_barriers", "    dsb ish", A64Insn::DsbDsbBoBarriers { crm: 0b1011 }),
        case("DSB.DSB_BO_barriers", "    dsb sy", A64Insn::DsbDsbBoBarriers { crm: 0b1111 }),
        case("ISB.ISB_BI_barriers", "    isb sy", A64Insn::IsbIsbBiBarriers { crm: 0b1111 }),
        case(
            "LDAR.LDAR_LR32_ldstord",
            "    ldar w0, [x1]",
            A64Insn::LdarLdarLr32Ldstord { rn: xsp(1), rt: w(0) },
        ),
        case(
            "LDAR.LDAR_LR64_ldstord",
            "    ldar x30, [sp, #0]",
            A64Insn::LdarLdarLr64Ldstord { rn: xsp(31), rt: x(30) },
        ),
        case(
            "LDAR.LDAR_LR64_ldstord",
            "    ldar xzr, [x17]",
            A64Insn::LdarLdarLr64Ldstord { rn: xsp(17), rt: x(31) },
        ),
        case(
            "LDARB.LDARB_LR32_ldstord",
            "    ldarb w2, [x3]",
            A64Insn::LdarbLdarbLr32Ldstord { rn: xsp(3), rt: w(2) },
        ),
        case(
            "LDARH.LDARH_LR32_ldstord",
            "    ldarh w4, [sp]",
            A64Insn::LdarhLdarhLr32Ldstord { rn: xsp(31), rt: w(4) },
        ),
        case(
            "STLR.STLR_SL32_ldstord",
            "    stlr wzr, [x5]",
            A64Insn::StlrStlrSl32Ldstord { rn: xsp(5), rt: w(31) },
        ),
        case(
            "STLR.STLR_SL64_ldstord",
            "    stlr x6, [sp]",
            A64Insn::StlrStlrSl64Ldstord { rn: xsp(31), rt: x(6) },
        ),
        case(
            "STLRB.STLRB_SL32_ldstord",
            "    stlrb w7, [x8]",
            A64Insn::StlrbStlrbSl32Ldstord { rn: xsp(8), rt: w(7) },
        ),
        case(
            "STLRH.STLRH_SL32_ldstord",
            "    stlrh w9, [x10]",
            A64Insn::StlrhStlrhSl32Ldstord { rn: xsp(10), rt: w(9) },
        ),
        case(
            "LDAPR.LDAPR_32L_memop",
            "    .arch_extension rcpc\n    ldapr w11, [x12]",
            A64Insn::LdaprLdapr32lMemop { rn: xsp(12), rt: w(11) },
        ),
        case(
            "LDAPR.LDAPR_64L_memop",
            "    .arch_extension rcpc\n    ldapr x13, [sp]",
            A64Insn::LdaprLdapr64lMemop { rn: xsp(31), rt: x(13) },
        ),
        case(
            "LDAPRB.LDAPRB_32L_memop",
            "    .arch_extension rcpc\n    ldaprb w14, [x15]",
            A64Insn::LdaprbLdaprb32lMemop { rn: xsp(15), rt: w(14) },
        ),
        case(
            "LDAPRH.LDAPRH_32L_memop",
            "    .arch_extension rcpc\n    ldaprh wzr, [x16, #0]",
            A64Insn::LdaprhLdaprh32lMemop { rn: xsp(16), rt: w(31) },
        ),
    ]);
    cases
}

/// A7d: BTI (every target), ADC/ADCS/SBC/SBCS (+ NGC/NGCS), SMSUBL/UMSUBL
/// (+ SMNEGL/UMNEGL), CRC32*/CRC32C*.
fn bti_carry_crc_encoding_cases() -> Vec<EncodingCase> {
    let mut cases = Vec::new();
    for (op2, targets) in [(0b000, ""), (0b010, " c"), (0b100, " j"), (0b110, " jc")] {
        cases.push(case(
            "BTI.BTI_HB_hints",
            // BTI is in the HINT space: llvm-mc accepts it without an extension.
            format!("    bti{targets}"),
            A64Insn::BtiBtiHbHints { op2 },
        ));
    }
    cases.extend([
        case(
            "ADC.ADC_32_addsub_carry",
            "    adc w0, w1, wzr",
            A64Insn::AdcAdc32AddsubCarry {
                rm: w(31),
                rn: w(1),
                rd: w(0),
            },
        ),
        case(
            "ADC.ADC_64_addsub_carry",
            "    adc x30, xzr, x2",
            A64Insn::AdcAdc64AddsubCarry {
                rm: x(2),
                rn: x(31),
                rd: x(30),
            },
        ),
        case(
            "ADCS.ADCS_32_addsub_carry",
            "    adcs w3, w4, w5",
            A64Insn::AdcsAdcs32AddsubCarry {
                rm: w(5),
                rn: w(4),
                rd: w(3),
            },
        ),
        case(
            "ADCS.ADCS_64_addsub_carry",
            "    adcs xzr, x17, x18",
            A64Insn::AdcsAdcs64AddsubCarry {
                rm: x(18),
                rn: x(17),
                rd: x(31),
            },
        ),
        case(
            "SBC.SBC_32_addsub_carry",
            "    sbc w6, w7, w8",
            A64Insn::SbcSbc32AddsubCarry {
                rm: w(8),
                rn: w(7),
                rd: w(6),
            },
        ),
        case(
            "SBC.SBC_64_addsub_carry",
            "    ngc x9, x10",
            A64Insn::SbcSbc64AddsubCarry {
                rm: x(10),
                rn: x(31),
                rd: x(9),
            },
        ),
        case(
            "SBCS.SBCS_32_addsub_carry",
            "    ngcs w11, w12",
            A64Insn::SbcsSbcs32AddsubCarry {
                rm: w(12),
                rn: w(31),
                rd: w(11),
            },
        ),
        case(
            "SBCS.SBCS_64_addsub_carry",
            "    sbcs x13, x14, x15",
            A64Insn::SbcsSbcs64AddsubCarry {
                rm: x(15),
                rn: x(14),
                rd: x(13),
            },
        ),
        case(
            "SMSUBL.SMSUBL_64WA_dp_3src",
            "    smsubl x0, w1, w2, x3",
            A64Insn::SmsublSmsubl64waDp3src {
                rm: w(2),
                ra: x(3),
                rn: w(1),
                rd: x(0),
            },
        ),
        case(
            "SMSUBL.SMSUBL_64WA_dp_3src",
            "    smnegl x4, w5, w6",
            A64Insn::SmsublSmsubl64waDp3src {
                rm: w(6),
                ra: x(31),
                rn: w(5),
                rd: x(4),
            },
        ),
        case(
            "UMSUBL.UMSUBL_64WA_dp_3src",
            "    umsubl x7, w8, w9, x10",
            A64Insn::UmsublUmsubl64waDp3src {
                rm: w(9),
                ra: x(10),
                rn: w(8),
                rd: x(7),
            },
        ),
        case(
            "UMSUBL.UMSUBL_64WA_dp_3src",
            "    umnegl x11, wzr, w12",
            A64Insn::UmsublUmsubl64waDp3src {
                rm: w(12),
                ra: x(31),
                rn: w(31),
                rd: x(11),
            },
        ),
    ]);
    type Crc = fn(A64Reg, A64Reg, A64Reg) -> A64Insn;
    let crc: [(&'static str, &str, bool, Crc); 8] = [
        ("CRC32.CRC32B_32C_dp_2src", "crc32b", false, |rm, rn, rd| {
            A64Insn::Crc32Crc32b32cDp2src { rm, rn, rd }
        }),
        ("CRC32.CRC32H_32C_dp_2src", "crc32h", false, |rm, rn, rd| {
            A64Insn::Crc32Crc32h32cDp2src { rm, rn, rd }
        }),
        ("CRC32.CRC32W_32C_dp_2src", "crc32w", false, |rm, rn, rd| {
            A64Insn::Crc32Crc32w32cDp2src { rm, rn, rd }
        }),
        ("CRC32.CRC32X_64C_dp_2src", "crc32x", true, |rm, rn, rd| {
            A64Insn::Crc32Crc32x64cDp2src { rm, rn, rd }
        }),
        (
            "CRC32C.CRC32CB_32C_dp_2src",
            "crc32cb",
            false,
            |rm, rn, rd| A64Insn::Crc32cCrc32cb32cDp2src { rm, rn, rd },
        ),
        (
            "CRC32C.CRC32CH_32C_dp_2src",
            "crc32ch",
            false,
            |rm, rn, rd| A64Insn::Crc32cCrc32ch32cDp2src { rm, rn, rd },
        ),
        (
            "CRC32C.CRC32CW_32C_dp_2src",
            "crc32cw",
            false,
            |rm, rn, rd| A64Insn::Crc32cCrc32cw32cDp2src { rm, rn, rd },
        ),
        (
            "CRC32C.CRC32CX_64C_dp_2src",
            "crc32cx",
            true,
            |rm, rn, rd| A64Insn::Crc32cCrc32cx64cDp2src { rm, rn, rd },
        ),
    ];
    for (form, mnemonic, x_data, insn) in crc {
        let (rm, rm_name) = if x_data {
            (x(18), "x18")
        } else {
            (w(18), "w18")
        };
        cases.push(case(
            form,
            format!("    .arch_extension crc\n    {mnemonic} w16, wzr, {rm_name}"),
            insn(rm, w(31), w(16)),
        ));
    }
    cases
}

/// A8: every LSE atomic form (LD<op>, SWP, CAS; all sizes and A/L/AL), generated
/// from the subset metadata: the mnemonic, W or X registers by access size, the
/// base cycling through x0..x30 and SP, Rt = XZR on some (the ST<op> alias
/// shape). The expected instruction is built from the form's own base word and
/// register fields, never from `encode`. Plus `msr pan, #imm` for every CRm.
fn lse_msr_encoding_cases() -> Vec<EncodingCase> {
    let mut cases = Vec::new();
    for (index, spec) in crate::shared::arm64::GENERATED_A64_SUBSET
        .iter()
        .enumerate()
    {
        let Some(atomic) = A64Insn::decode(spec.value).and_then(A64Insn::lse_atomic) else {
            continue;
        };
        let rs = (index % 29) as u32;
        let rt = if index % 5 == 0 {
            31
        } else {
            ((index + 7) % 31) as u32
        };
        let rn = (index % 32) as u32;
        let field = |name: &str, value: u32| {
            let field = spec
                .field(name)
                .unwrap_or_else(|| panic!("{}: no {name}", spec.key));
            value << field.shift()
        };
        let word = spec.value | field("Rs", rs) | field("Rt", rt) | field("Rn", rn);
        let expected = A64Insn::decode(word).unwrap();
        assert_eq!(expected.key(), spec.key);
        let prefix = if atomic.size == 8 { "x" } else { "w" };
        let reg = |enc: u32| match enc {
            31 => format!("{prefix}zr"),
            _ => format!("{prefix}{enc}"),
        };
        let base = match rn {
            31 => "sp".to_string(),
            _ => format!("x{rn}"),
        };
        let asm = format!(
            "    .arch_extension lse\n    {} {}, {}, [{base}]",
            spec.mnemonic.to_lowercase(),
            reg(rs),
            reg(rt)
        );
        cases.push(case(spec.key, asm, expected));
    }
    assert_eq!(cases.len(), 160);
    for crm in 0..16_u8 {
        cases.push(case(
            "MSR_imm.MSR_SI_pstate",
            format!("    .arch_extension pan\n    msr pan, #{crm}"),
            A64Insn::MsrImmMsrSiPstate { crm },
        ));
    }
    cases
}

/// A9a SIMD&FP forms (tmp/pipeline.md, "A9 contract"): at least one case per
/// form, built from the generated field table (`(field, raw value)`; `imm8` stands
/// for MOVI/MVNI's `a:b:c:d:e:f:g:h`) and compared with LLVM's encoding of `asm`.
fn simd_encoding_cases() -> Vec<EncodingCase> {
    const CASES: &[(&str, &[(&str, u32)], &str)] = &[
        (
            "LDR_imm_fpsimd.LDR_B_ldst_immpost",
            &[("imm9", 1), ("Rn", 1), ("Rt", 0)],
            "ldr b0, [x1], #1",
        ),
        (
            "LDR_imm_fpsimd.LDR_H_ldst_immpost",
            &[("imm9", 0x1fe), ("Rn", 31), ("Rt", 2)],
            "ldr h2, [sp], #-2",
        ),
        (
            "LDR_imm_fpsimd.LDR_S_ldst_immpost",
            &[("imm9", 4), ("Rn", 3), ("Rt", 31)],
            "ldr s31, [x3], #4",
        ),
        (
            "LDR_imm_fpsimd.LDR_D_ldst_immpost",
            &[("imm9", 8), ("Rn", 4), ("Rt", 5)],
            "ldr d5, [x4], #8",
        ),
        (
            "LDR_imm_fpsimd.LDR_Q_ldst_immpost",
            &[("imm9", 16), ("Rn", 6), ("Rt", 7)],
            "ldr q7, [x6], #16",
        ),
        (
            "LDR_imm_fpsimd.LDR_B_ldst_immpre",
            &[("imm9", 0x100), ("Rn", 1), ("Rt", 0)],
            "ldr b0, [x1, #-256]!",
        ),
        (
            "LDR_imm_fpsimd.LDR_H_ldst_immpre",
            &[("imm9", 2), ("Rn", 2), ("Rt", 1)],
            "ldr h1, [x2, #2]!",
        ),
        (
            "LDR_imm_fpsimd.LDR_S_ldst_immpre",
            &[("imm9", 0x1fc), ("Rn", 31), ("Rt", 3)],
            "ldr s3, [sp, #-4]!",
        ),
        (
            "LDR_imm_fpsimd.LDR_D_ldst_immpre",
            &[("imm9", 255), ("Rn", 5), ("Rt", 4)],
            "ldr d4, [x5, #255]!",
        ),
        (
            "LDR_imm_fpsimd.LDR_Q_ldst_immpre",
            &[("imm9", 0x1f0), ("Rn", 7), ("Rt", 6)],
            "ldr q6, [x7, #-16]!",
        ),
        (
            "LDR_imm_fpsimd.LDR_B_ldst_pos",
            &[("imm12", 4095), ("Rn", 1), ("Rt", 0)],
            "ldr b0, [x1, #4095]",
        ),
        (
            "LDR_imm_fpsimd.LDR_H_ldst_pos",
            &[("imm12", 1), ("Rn", 2), ("Rt", 1)],
            "ldr h1, [x2, #2]",
        ),
        (
            "LDR_imm_fpsimd.LDR_S_ldst_pos",
            &[("imm12", 2), ("Rn", 31), ("Rt", 2)],
            "ldr s2, [sp, #8]",
        ),
        (
            "LDR_imm_fpsimd.LDR_D_ldst_pos",
            &[("imm12", 0), ("Rn", 4), ("Rt", 3)],
            "ldr d3, [x4]",
        ),
        (
            "LDR_imm_fpsimd.LDR_Q_ldst_pos",
            &[("imm12", 4095), ("Rn", 5), ("Rt", 4)],
            "ldr q4, [x5, #65520]",
        ),
        (
            "STR_imm_fpsimd.STR_B_ldst_immpost",
            &[("imm9", 1), ("Rn", 1), ("Rt", 0)],
            "str b0, [x1], #1",
        ),
        (
            "STR_imm_fpsimd.STR_H_ldst_immpost",
            &[("imm9", 0x1fe), ("Rn", 2), ("Rt", 1)],
            "str h1, [x2], #-2",
        ),
        (
            "STR_imm_fpsimd.STR_S_ldst_immpost",
            &[("imm9", 4), ("Rn", 31), ("Rt", 2)],
            "str s2, [sp], #4",
        ),
        (
            "STR_imm_fpsimd.STR_D_ldst_immpost",
            &[("imm9", 8), ("Rn", 4), ("Rt", 3)],
            "str d3, [x4], #8",
        ),
        (
            "STR_imm_fpsimd.STR_Q_ldst_immpost",
            &[("imm9", 0x1f0), ("Rn", 5), ("Rt", 4)],
            "str q4, [x5], #-16",
        ),
        (
            "STR_imm_fpsimd.STR_B_ldst_immpre",
            &[("imm9", 3), ("Rn", 1), ("Rt", 0)],
            "str b0, [x1, #3]!",
        ),
        (
            "STR_imm_fpsimd.STR_H_ldst_immpre",
            &[("imm9", 6), ("Rn", 2), ("Rt", 1)],
            "str h1, [x2, #6]!",
        ),
        (
            "STR_imm_fpsimd.STR_S_ldst_immpre",
            &[("imm9", 0x1f8), ("Rn", 3), ("Rt", 2)],
            "str s2, [x3, #-8]!",
        ),
        (
            "STR_imm_fpsimd.STR_D_ldst_immpre",
            &[("imm9", 0x1f0), ("Rn", 31), ("Rt", 3)],
            "str d3, [sp, #-16]!",
        ),
        (
            "STR_imm_fpsimd.STR_Q_ldst_immpre",
            &[("imm9", 32), ("Rn", 5), ("Rt", 4)],
            "str q4, [x5, #32]!",
        ),
        (
            "STR_imm_fpsimd.STR_B_ldst_pos",
            &[("imm12", 7), ("Rn", 1), ("Rt", 0)],
            "str b0, [x1, #7]",
        ),
        (
            "STR_imm_fpsimd.STR_H_ldst_pos",
            &[("imm12", 4), ("Rn", 2), ("Rt", 1)],
            "str h1, [x2, #8]",
        ),
        (
            "STR_imm_fpsimd.STR_S_ldst_pos",
            &[("imm12", 0), ("Rn", 3), ("Rt", 2)],
            "str s2, [x3]",
        ),
        (
            "STR_imm_fpsimd.STR_D_ldst_pos",
            &[("imm12", 1), ("Rn", 4), ("Rt", 3)],
            "str d3, [x4, #8]",
        ),
        (
            "STR_imm_fpsimd.STR_Q_ldst_pos",
            &[("imm12", 3), ("Rn", 31), ("Rt", 4)],
            "str q4, [sp, #48]",
        ),
        (
            "LDUR_fpsimd.LDUR_B_ldst_unscaled",
            &[("imm9", 0x1ff), ("Rn", 1), ("Rt", 0)],
            "ldur b0, [x1, #-1]",
        ),
        (
            "LDUR_fpsimd.LDUR_H_ldst_unscaled",
            &[("imm9", 1), ("Rn", 2), ("Rt", 1)],
            "ldur h1, [x2, #1]",
        ),
        (
            "LDUR_fpsimd.LDUR_S_ldst_unscaled",
            &[("imm9", 3), ("Rn", 3), ("Rt", 2)],
            "ldur s2, [x3, #3]",
        ),
        (
            "LDUR_fpsimd.LDUR_D_ldst_unscaled",
            &[("imm9", 0x1f9), ("Rn", 31), ("Rt", 3)],
            "ldur d3, [sp, #-7]",
        ),
        (
            "LDUR_fpsimd.LDUR_Q_ldst_unscaled",
            &[("imm9", 0x1f0), ("Rn", 5), ("Rt", 4)],
            "ldur q4, [x5, #-16]",
        ),
        (
            "STUR_fpsimd.STUR_B_ldst_unscaled",
            &[("imm9", 5), ("Rn", 1), ("Rt", 0)],
            "stur b0, [x1, #5]",
        ),
        (
            "STUR_fpsimd.STUR_H_ldst_unscaled",
            &[("imm9", 0x1ff), ("Rn", 2), ("Rt", 1)],
            "stur h1, [x2, #-1]",
        ),
        (
            "STUR_fpsimd.STUR_S_ldst_unscaled",
            &[("imm9", 255), ("Rn", 3), ("Rt", 2)],
            "stur s2, [x3, #255]",
        ),
        (
            "STUR_fpsimd.STUR_D_ldst_unscaled",
            &[("imm9", 0x100), ("Rn", 4), ("Rt", 3)],
            "stur d3, [x4, #-256]",
        ),
        (
            "STUR_fpsimd.STUR_Q_ldst_unscaled",
            &[("imm9", 0x1f1), ("Rn", 31), ("Rt", 4)],
            "stur q4, [sp, #-15]",
        ),
        (
            "LDP_fpsimd.LDP_S_ldstpair_post",
            &[("imm7", 2), ("Rt2", 1), ("Rn", 2), ("Rt", 0)],
            "ldp s0, s1, [x2], #8",
        ),
        (
            "LDP_fpsimd.LDP_D_ldstpair_post",
            &[("imm7", 0x7e), ("Rt2", 3), ("Rn", 31), ("Rt", 2)],
            "ldp d2, d3, [sp], #-16",
        ),
        (
            "LDP_fpsimd.LDP_Q_ldstpair_post",
            &[("imm7", 2), ("Rt2", 5), ("Rn", 6), ("Rt", 4)],
            "ldp q4, q5, [x6], #32",
        ),
        (
            "LDP_fpsimd.LDP_S_ldstpair_pre",
            &[("imm7", 0x7f), ("Rt2", 1), ("Rn", 2), ("Rt", 0)],
            "ldp s0, s1, [x2, #-4]!",
        ),
        (
            "LDP_fpsimd.LDP_D_ldstpair_pre",
            &[("imm7", 1), ("Rt2", 3), ("Rn", 4), ("Rt", 2)],
            "ldp d2, d3, [x4, #8]!",
        ),
        (
            "LDP_fpsimd.LDP_Q_ldstpair_pre",
            &[("imm7", 0x7e), ("Rt2", 5), ("Rn", 31), ("Rt", 4)],
            "ldp q4, q5, [sp, #-32]!",
        ),
        (
            "LDP_fpsimd.LDP_S_ldstpair_off",
            &[("imm7", 63), ("Rt2", 1), ("Rn", 2), ("Rt", 0)],
            "ldp s0, s1, [x2, #252]",
        ),
        (
            "LDP_fpsimd.LDP_D_ldstpair_off",
            &[("imm7", 0x40), ("Rt2", 31), ("Rn", 4), ("Rt", 30)],
            "ldp d30, d31, [x4, #-512]",
        ),
        (
            "LDP_fpsimd.LDP_Q_ldstpair_off",
            &[("imm7", 0), ("Rt2", 0), ("Rn", 6), ("Rt", 31)],
            "ldp q31, q0, [x6]",
        ),
        (
            "STP_fpsimd.STP_S_ldstpair_post",
            &[("imm7", 2), ("Rt2", 1), ("Rn", 2), ("Rt", 0)],
            "stp s0, s1, [x2], #8",
        ),
        (
            "STP_fpsimd.STP_D_ldstpair_post",
            &[("imm7", 0x7e), ("Rt2", 3), ("Rn", 4), ("Rt", 2)],
            "stp d2, d3, [x4], #-16",
        ),
        (
            "STP_fpsimd.STP_Q_ldstpair_post",
            &[("imm7", 2), ("Rt2", 4), ("Rn", 31), ("Rt", 4)],
            "stp q4, q4, [sp], #32",
        ),
        (
            "STP_fpsimd.STP_S_ldstpair_pre",
            &[("imm7", 0x7e), ("Rt2", 1), ("Rn", 2), ("Rt", 0)],
            "stp s0, s1, [x2, #-8]!",
        ),
        (
            "STP_fpsimd.STP_D_ldstpair_pre",
            &[("imm7", 0x7e), ("Rt2", 3), ("Rn", 31), ("Rt", 2)],
            "stp d2, d3, [sp, #-16]!",
        ),
        (
            "STP_fpsimd.STP_Q_ldstpair_pre",
            &[("imm7", 1), ("Rt2", 5), ("Rn", 6), ("Rt", 4)],
            "stp q4, q5, [x6, #16]!",
        ),
        (
            "STP_fpsimd.STP_S_ldstpair_off",
            &[("imm7", 0x40), ("Rt2", 1), ("Rn", 2), ("Rt", 0)],
            "stp s0, s1, [x2, #-256]",
        ),
        (
            "STP_fpsimd.STP_D_ldstpair_off",
            &[("imm7", 0), ("Rt2", 3), ("Rn", 4), ("Rt", 2)],
            "stp d2, d3, [x4]",
        ),
        (
            "STP_fpsimd.STP_Q_ldstpair_off",
            &[("imm7", 63), ("Rt2", 5), ("Rn", 6), ("Rt", 4)],
            "stp q4, q5, [x6, #1008]",
        ),
        (
            "LD1_advsimd_mult.LD1_asisdlse_R1_1v",
            &[("Q", 1), ("size", 0), ("Rn", 1), ("Rt", 0)],
            "ld1 {v0.16b}, [x1]",
        ),
        (
            "LD1_advsimd_mult.LD1_asisdlse_R2_2v",
            &[("Q", 0), ("size", 3), ("Rn", 31), ("Rt", 31)],
            "ld1 {v31.1d, v0.1d}, [sp]",
        ),
        (
            "LD1_advsimd_mult.LD1_asisdlse_R3_3v",
            &[("Q", 1), ("size", 1), ("Rn", 2), ("Rt", 30)],
            "ld1 {v30.8h, v31.8h, v0.8h}, [x2]",
        ),
        (
            "LD1_advsimd_mult.LD1_asisdlse_R4_4v",
            &[("Q", 0), ("size", 2), ("Rn", 3), ("Rt", 4)],
            "ld1 {v4.2s, v5.2s, v6.2s, v7.2s}, [x3]",
        ),
        (
            "LD1_advsimd_mult.LD1_asisdlsep_I1_i1",
            &[("Q", 0), ("size", 0), ("Rn", 1), ("Rt", 0)],
            "ld1 {v0.8b}, [x1], #8",
        ),
        (
            "LD1_advsimd_mult.LD1_asisdlsep_R1_r1",
            &[("Q", 1), ("Rm", 2), ("size", 3), ("Rn", 1), ("Rt", 0)],
            "ld1 {v0.2d}, [x1], x2",
        ),
        (
            "LD1_advsimd_mult.LD1_asisdlsep_I2_i2",
            &[("Q", 1), ("size", 0), ("Rn", 31), ("Rt", 2)],
            "ld1 {v2.16b, v3.16b}, [sp], #32",
        ),
        (
            "LD1_advsimd_mult.LD1_asisdlsep_R2_r2",
            &[("Q", 0), ("Rm", 30), ("size", 1), ("Rn", 4), ("Rt", 31)],
            "ld1 {v31.4h, v0.4h}, [x4], x30",
        ),
        (
            "LD1_advsimd_mult.LD1_asisdlsep_I3_i3",
            &[("Q", 0), ("size", 2), ("Rn", 5), ("Rt", 6)],
            "ld1 {v6.2s, v7.2s, v8.2s}, [x5], #24",
        ),
        (
            "LD1_advsimd_mult.LD1_asisdlsep_R3_r3",
            &[("Q", 1), ("Rm", 0), ("size", 2), ("Rn", 5), ("Rt", 6)],
            "ld1 {v6.4s, v7.4s, v8.4s}, [x5], x0",
        ),
        (
            "LD1_advsimd_mult.LD1_asisdlsep_I4_i4",
            &[("Q", 1), ("size", 0), ("Rn", 7), ("Rt", 0)],
            "ld1 {v0.16b, v1.16b, v2.16b, v3.16b}, [x7], #64",
        ),
        (
            "LD1_advsimd_mult.LD1_asisdlsep_R4_r4",
            &[("Q", 0), ("Rm", 9), ("size", 3), ("Rn", 8), ("Rt", 29)],
            "ld1 {v29.1d, v30.1d, v31.1d, v0.1d}, [x8], x9",
        ),
        (
            "ST1_advsimd_mult.ST1_asisdlse_R1_1v",
            &[("Q", 0), ("size", 1), ("Rn", 1), ("Rt", 0)],
            "st1 {v0.4h}, [x1]",
        ),
        (
            "ST1_advsimd_mult.ST1_asisdlse_R2_2v",
            &[("Q", 1), ("size", 2), ("Rn", 2), ("Rt", 1)],
            "st1 {v1.4s, v2.4s}, [x2]",
        ),
        (
            "ST1_advsimd_mult.ST1_asisdlse_R3_3v",
            &[("Q", 0), ("size", 0), ("Rn", 31), ("Rt", 2)],
            "st1 {v2.8b, v3.8b, v4.8b}, [sp]",
        ),
        (
            "ST1_advsimd_mult.ST1_asisdlse_R4_4v",
            &[("Q", 1), ("size", 3), ("Rn", 4), ("Rt", 31)],
            "st1 {v31.2d, v0.2d, v1.2d, v2.2d}, [x4]",
        ),
        (
            "ST1_advsimd_mult.ST1_asisdlsep_I1_i1",
            &[("Q", 1), ("size", 0), ("Rn", 1), ("Rt", 0)],
            "st1 {v0.16b}, [x1], #16",
        ),
        (
            "ST1_advsimd_mult.ST1_asisdlsep_R1_r1",
            &[("Q", 0), ("Rm", 3), ("size", 2), ("Rn", 1), ("Rt", 0)],
            "st1 {v0.2s}, [x1], x3",
        ),
        (
            "ST1_advsimd_mult.ST1_asisdlsep_I2_i2",
            &[("Q", 0), ("size", 3), ("Rn", 2), ("Rt", 1)],
            "st1 {v1.1d, v2.1d}, [x2], #16",
        ),
        (
            "ST1_advsimd_mult.ST1_asisdlsep_R2_r2",
            &[("Q", 1), ("Rm", 4), ("size", 1), ("Rn", 31), ("Rt", 1)],
            "st1 {v1.8h, v2.8h}, [sp], x4",
        ),
        (
            "ST1_advsimd_mult.ST1_asisdlsep_I3_i3",
            &[("Q", 1), ("size", 2), ("Rn", 3), ("Rt", 5)],
            "st1 {v5.4s, v6.4s, v7.4s}, [x3], #48",
        ),
        (
            "ST1_advsimd_mult.ST1_asisdlsep_R3_r3",
            &[("Q", 0), ("Rm", 6), ("size", 0), ("Rn", 3), ("Rt", 5)],
            "st1 {v5.8b, v6.8b, v7.8b}, [x3], x6",
        ),
        (
            "ST1_advsimd_mult.ST1_asisdlsep_I4_i4",
            &[("Q", 0), ("size", 1), ("Rn", 4), ("Rt", 28)],
            "st1 {v28.4h, v29.4h, v30.4h, v31.4h}, [x4], #32",
        ),
        (
            "ST1_advsimd_mult.ST1_asisdlsep_R4_r4",
            &[("Q", 1), ("Rm", 7), ("size", 2), ("Rn", 4), ("Rt", 0)],
            "st1 {v0.4s, v1.4s, v2.4s, v3.4s}, [x4], x7",
        ),
        (
            "DUP_advsimd_elt.DUP_asisdone_only",
            &[("imm5", 0b10111), ("Rn", 1), ("Rd", 0)],
            "dup b0, v1.b[11]",
        ),
        (
            "DUP_advsimd_elt.DUP_asisdone_only",
            &[("imm5", 0b11000), ("Rn", 3), ("Rd", 2)],
            "dup d2, v3.d[1]",
        ),
        (
            "DUP_advsimd_elt.DUP_asimdins_DV_v",
            &[("Q", 1), ("imm5", 0b11111), ("Rn", 1), ("Rd", 0)],
            "dup v0.16b, v1.b[15]",
        ),
        (
            "DUP_advsimd_elt.DUP_asimdins_DV_v",
            &[("Q", 0), ("imm5", 0b01100), ("Rn", 3), ("Rd", 2)],
            "dup v2.2s, v3.s[1]",
        ),
        (
            "DUP_advsimd_elt.DUP_asimdins_DV_v",
            &[("Q", 1), ("imm5", 0b11000), ("Rn", 5), ("Rd", 4)],
            "dup v4.2d, v5.d[1]",
        ),
        (
            "DUP_advsimd_gen.DUP_asimdins_DR_r",
            &[("Q", 1), ("imm5", 0b00001), ("Rn", 1), ("Rd", 0)],
            "dup v0.16b, w1",
        ),
        (
            "DUP_advsimd_gen.DUP_asimdins_DR_r",
            &[("Q", 0), ("imm5", 0b00010), ("Rn", 31), ("Rd", 2)],
            "dup v2.4h, wzr",
        ),
        (
            "DUP_advsimd_gen.DUP_asimdins_DR_r",
            &[("Q", 1), ("imm5", 0b01000), ("Rn", 3), ("Rd", 4)],
            "dup v4.2d, x3",
        ),
        (
            "INS_advsimd_elt.INS_asimdins_IV_v",
            &[("imm5", 0b01100), ("imm4", 0b1100), ("Rn", 1), ("Rd", 0)],
            "mov v0.s[1], v1.s[3]",
        ),
        (
            "INS_advsimd_elt.INS_asimdins_IV_v",
            &[("imm5", 0b11111), ("imm4", 0b0000), ("Rn", 3), ("Rd", 2)],
            "mov v2.b[15], v3.b[0]",
        ),
        (
            "INS_advsimd_gen.INS_asimdins_IR_r",
            &[("imm5", 0b11000), ("Rn", 1), ("Rd", 0)],
            "mov v0.d[1], x1",
        ),
        (
            "INS_advsimd_gen.INS_asimdins_IR_r",
            &[("imm5", 0b00110), ("Rn", 3), ("Rd", 2)],
            "mov v2.h[1], w3",
        ),
        (
            "UMOV_advsimd.UMOV_asimdins_W_w",
            &[("imm5", 0b01111), ("Rn", 1), ("Rd", 0)],
            "umov w0, v1.b[7]",
        ),
        (
            "UMOV_advsimd.UMOV_asimdins_W_w",
            &[("imm5", 0b11100), ("Rn", 3), ("Rd", 2)],
            "mov w2, v3.s[3]",
        ),
        (
            "UMOV_advsimd.UMOV_asimdins_X_x",
            &[("imm5", 0b11000), ("Rn", 5), ("Rd", 4)],
            "mov x4, v5.d[1]",
        ),
        (
            "MOVI_advsimd.MOVI_asimdimm_N_b",
            &[("Q", 1), ("imm8", 0xff), ("Rd", 0)],
            "movi v0.16b, #0xff",
        ),
        (
            "MOVI_advsimd.MOVI_asimdimm_N_b",
            &[("Q", 0), ("imm8", 0x21), ("Rd", 1)],
            "movi v1.8b, #0x21",
        ),
        (
            "MOVI_advsimd.MOVI_asimdimm_L_hl",
            &[("Q", 0), ("cmode", 0b1010), ("imm8", 0x12), ("Rd", 2)],
            "movi v2.4h, #0x12, lsl #8",
        ),
        (
            "MOVI_advsimd.MOVI_asimdimm_L_hl",
            &[("Q", 1), ("cmode", 0b1000), ("imm8", 0x80), ("Rd", 3)],
            "movi v3.8h, #0x80",
        ),
        (
            "MOVI_advsimd.MOVI_asimdimm_L_sl",
            &[("Q", 1), ("cmode", 0b0110), ("imm8", 0x34), ("Rd", 4)],
            "movi v4.4s, #0x34, lsl #24",
        ),
        (
            "MOVI_advsimd.MOVI_asimdimm_L_sl",
            &[("Q", 0), ("cmode", 0b0010), ("imm8", 0x01), ("Rd", 5)],
            "movi v5.2s, #0x1, lsl #8",
        ),
        (
            "MOVI_advsimd.MOVI_asimdimm_M_sm",
            &[("Q", 0), ("cmode", 0b1101), ("imm8", 0x56), ("Rd", 6)],
            "movi v6.2s, #0x56, msl #16",
        ),
        (
            "MOVI_advsimd.MOVI_asimdimm_M_sm",
            &[("Q", 1), ("cmode", 0b1100), ("imm8", 0x7f), ("Rd", 7)],
            "movi v7.4s, #0x7f, msl #8",
        ),
        (
            "MOVI_advsimd.MOVI_asimdimm_D_ds",
            &[("imm8", 0b10101010), ("Rd", 8)],
            "movi d8, #0xff00ff00ff00ff00",
        ),
        (
            "MOVI_advsimd.MOVI_asimdimm_D2_d",
            &[("imm8", 0), ("Rd", 9)],
            "movi v9.2d, #0000000000000000",
        ),
        (
            "MOVI_advsimd.MOVI_asimdimm_D2_d",
            &[("imm8", 0b11111110), ("Rd", 31)],
            "movi v31.2d, #0xffffffffffffff00",
        ),
        (
            "MVNI_advsimd.MVNI_asimdimm_L_hl",
            &[("Q", 1), ("cmode", 0b1010), ("imm8", 0x12), ("Rd", 0)],
            "mvni v0.8h, #0x12, lsl #8",
        ),
        (
            "MVNI_advsimd.MVNI_asimdimm_L_sl",
            &[("Q", 1), ("cmode", 0b0000), ("imm8", 0x01), ("Rd", 1)],
            "mvni v1.4s, #0x1",
        ),
        (
            "MVNI_advsimd.MVNI_asimdimm_L_sl",
            &[("Q", 0), ("cmode", 0b0100), ("imm8", 0xab), ("Rd", 2)],
            "mvni v2.2s, #0xab, lsl #16",
        ),
        (
            "MVNI_advsimd.MVNI_asimdimm_M_sm",
            &[("Q", 1), ("cmode", 0b1100), ("imm8", 0x12), ("Rd", 3)],
            "mvni v3.4s, #0x12, msl #8",
        ),
        (
            "FMOV_float_gen.FMOV_S32_float2int",
            &[("Rn", 1), ("Rd", 0)],
            "fmov s0, w1",
        ),
        (
            "FMOV_float_gen.FMOV_32S_float2int",
            &[("Rn", 1), ("Rd", 0)],
            "fmov w0, s1",
        ),
        (
            "FMOV_float_gen.FMOV_D64_float2int",
            &[("Rn", 31), ("Rd", 2)],
            "fmov d2, xzr",
        ),
        (
            "FMOV_float_gen.FMOV_64D_float2int",
            &[("Rn", 3), ("Rd", 30)],
            "fmov x30, d3",
        ),
        (
            "FMOV_float_gen.FMOV_V64I_float2int",
            &[("Rn", 5), ("Rd", 4)],
            "fmov v4.d[1], x5",
        ),
        (
            "FMOV_float_gen.FMOV_64VX_float2int",
            &[("Rn", 7), ("Rd", 6)],
            "fmov x6, v7.d[1]",
        ),
        (
            "FMOV_float.FMOV_S_floatdp1",
            &[("Rn", 1), ("Rd", 0)],
            "fmov s0, s1",
        ),
        (
            "FMOV_float.FMOV_D_floatdp1",
            &[("Rn", 31), ("Rd", 30)],
            "fmov d30, d31",
        ),
        (
            "CMEQ_advsimd_reg.CMEQ_asisdsame_only",
            &[("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "cmeq d0, d1, d2",
        ),
        (
            "CMEQ_advsimd_reg.CMEQ_asimdsame_only",
            &[("Q", 1), ("size", 0), ("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "cmeq v0.16b, v1.16b, v2.16b",
        ),
        (
            "CMEQ_advsimd_reg.CMEQ_asimdsame_only",
            &[("Q", 1), ("size", 3), ("Rm", 5), ("Rn", 4), ("Rd", 3)],
            "cmeq v3.2d, v4.2d, v5.2d",
        ),
        (
            "CMEQ_advsimd_zero.CMEQ_asisdmisc_Z",
            &[("Rn", 1), ("Rd", 0)],
            "cmeq d0, d1, #0",
        ),
        (
            "CMEQ_advsimd_zero.CMEQ_asimdmisc_Z",
            &[("Q", 0), ("size", 1), ("Rn", 1), ("Rd", 0)],
            "cmeq v0.4h, v1.4h, #0",
        ),
        (
            "CMHI_advsimd.CMHI_asisdsame_only",
            &[("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "cmhi d0, d1, d2",
        ),
        (
            "CMHI_advsimd.CMHI_asimdsame_only",
            &[("Q", 0), ("size", 2), ("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "cmhi v0.2s, v1.2s, v2.2s",
        ),
        (
            "CMHS_advsimd.CMHS_asisdsame_only",
            &[("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "cmhs d0, d1, d2",
        ),
        (
            "CMHS_advsimd.CMHS_asimdsame_only",
            &[("Q", 1), ("size", 1), ("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "cmhs v0.8h, v1.8h, v2.8h",
        ),
        (
            "CMGT_advsimd_reg.CMGT_asisdsame_only",
            &[("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "cmgt d0, d1, d2",
        ),
        (
            "CMGT_advsimd_reg.CMGT_asimdsame_only",
            &[("Q", 1), ("size", 2), ("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "cmgt v0.4s, v1.4s, v2.4s",
        ),
        (
            "CMGT_advsimd_zero.CMGT_asisdmisc_Z",
            &[("Rn", 1), ("Rd", 0)],
            "cmgt d0, d1, #0",
        ),
        (
            "CMGT_advsimd_zero.CMGT_asimdmisc_Z",
            &[("Q", 0), ("size", 0), ("Rn", 1), ("Rd", 0)],
            "cmgt v0.8b, v1.8b, #0",
        ),
        (
            "CMGE_advsimd_reg.CMGE_asisdsame_only",
            &[("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "cmge d0, d1, d2",
        ),
        (
            "CMGE_advsimd_reg.CMGE_asimdsame_only",
            &[("Q", 0), ("size", 1), ("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "cmge v0.4h, v1.4h, v2.4h",
        ),
        (
            "CMGE_advsimd_zero.CMGE_asisdmisc_Z",
            &[("Rn", 1), ("Rd", 0)],
            "cmge d0, d1, #0",
        ),
        (
            "CMGE_advsimd_zero.CMGE_asimdmisc_Z",
            &[("Q", 1), ("size", 3), ("Rn", 1), ("Rd", 0)],
            "cmge v0.2d, v1.2d, #0",
        ),
        (
            "CMTST_advsimd.CMTST_asisdsame_only",
            &[("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "cmtst d0, d1, d2",
        ),
        (
            "CMTST_advsimd.CMTST_asimdsame_only",
            &[("Q", 1), ("size", 0), ("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "cmtst v0.16b, v1.16b, v2.16b",
        ),
        (
            "AND_advsimd.AND_asimdsame_only",
            &[("Q", 1), ("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "and v0.16b, v1.16b, v2.16b",
        ),
        (
            "AND_advsimd.AND_asimdsame_only",
            &[("Q", 0), ("Rm", 5), ("Rn", 4), ("Rd", 3)],
            "and v3.8b, v4.8b, v5.8b",
        ),
        (
            "ORR_advsimd_reg.ORR_asimdsame_only",
            &[("Q", 1), ("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "orr v0.16b, v1.16b, v2.16b",
        ),
        (
            "ORR_advsimd_reg.ORR_asimdsame_only",
            &[("Q", 1), ("Rm", 1), ("Rn", 1), ("Rd", 0)],
            "mov v0.16b, v1.16b",
        ),
        (
            "EOR_advsimd.EOR_asimdsame_only",
            &[("Q", 0), ("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "eor v0.8b, v1.8b, v2.8b",
        ),
        (
            "BIC_advsimd_reg.BIC_asimdsame_only",
            &[("Q", 1), ("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "bic v0.16b, v1.16b, v2.16b",
        ),
        (
            "ORN_advsimd.ORN_asimdsame_only",
            &[("Q", 1), ("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "orn v0.16b, v1.16b, v2.16b",
        ),
        (
            "BIT_advsimd.BIT_asimdsame_only",
            &[("Q", 1), ("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "bit v0.16b, v1.16b, v2.16b",
        ),
        (
            "BIF_advsimd.BIF_asimdsame_only",
            &[("Q", 0), ("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "bif v0.8b, v1.8b, v2.8b",
        ),
        (
            "BSL_advsimd.BSL_asimdsame_only",
            &[("Q", 1), ("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "bsl v0.16b, v1.16b, v2.16b",
        ),
        (
            "NOT_advsimd.NOT_asimdmisc_R",
            &[("Q", 1), ("Rn", 1), ("Rd", 0)],
            "not v0.16b, v1.16b",
        ),
        (
            "NOT_advsimd.NOT_asimdmisc_R",
            &[("Q", 0), ("Rn", 3), ("Rd", 2)],
            "mvn v2.8b, v3.8b",
        ),
        (
            "ADD_advsimd.ADD_asisdsame_only",
            &[("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "add d0, d1, d2",
        ),
        (
            "ADD_advsimd.ADD_asimdsame_only",
            &[("Q", 1), ("size", 2), ("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "add v0.4s, v1.4s, v2.4s",
        ),
        (
            "ADD_advsimd.ADD_asimdsame_only",
            &[("Q", 0), ("size", 0), ("Rm", 5), ("Rn", 4), ("Rd", 3)],
            "add v3.8b, v4.8b, v5.8b",
        ),
        (
            "SUB_advsimd.SUB_asisdsame_only",
            &[("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "sub d0, d1, d2",
        ),
        (
            "SUB_advsimd.SUB_asimdsame_only",
            &[("Q", 1), ("size", 3), ("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "sub v0.2d, v1.2d, v2.2d",
        ),
        (
            "ADDP_advsimd_vec.ADDP_asimdsame_only",
            &[("Q", 1), ("size", 1), ("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "addp v0.8h, v1.8h, v2.8h",
        ),
        (
            "ADDP_advsimd_vec.ADDP_asimdsame_only",
            &[("Q", 0), ("size", 0), ("Rm", 5), ("Rn", 4), ("Rd", 3)],
            "addp v3.8b, v4.8b, v5.8b",
        ),
        (
            "ADDP_advsimd_pair.ADDP_asisdpair_only",
            &[("Rn", 1), ("Rd", 0)],
            "addp d0, v1.2d",
        ),
        (
            "UMAXP_advsimd.UMAXP_asimdsame_only",
            &[("Q", 1), ("size", 0), ("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "umaxp v0.16b, v1.16b, v2.16b",
        ),
        (
            "UMAXP_advsimd.UMAXP_asimdsame_only",
            &[("Q", 0), ("size", 2), ("Rm", 5), ("Rn", 4), ("Rd", 3)],
            "umaxp v3.2s, v4.2s, v5.2s",
        ),
        (
            "UMINP_advsimd.UMINP_asimdsame_only",
            &[("Q", 1), ("size", 1), ("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "uminp v0.8h, v1.8h, v2.8h",
        ),
        (
            "ADDV_advsimd.ADDV_asimdall_only",
            &[("Q", 1), ("size", 0), ("Rn", 1), ("Rd", 0)],
            "addv b0, v1.16b",
        ),
        (
            "ADDV_advsimd.ADDV_asimdall_only",
            &[("Q", 0), ("size", 1), ("Rn", 3), ("Rd", 2)],
            "addv h2, v3.4h",
        ),
        (
            "UMAXV_advsimd.UMAXV_asimdall_only",
            &[("Q", 1), ("size", 2), ("Rn", 1), ("Rd", 0)],
            "umaxv s0, v1.4s",
        ),
        (
            "UMAXV_advsimd.UMAXV_asimdall_only",
            &[("Q", 0), ("size", 0), ("Rn", 3), ("Rd", 2)],
            "umaxv b2, v3.8b",
        ),
        (
            "UMINV_advsimd.UMINV_asimdall_only",
            &[("Q", 1), ("size", 1), ("Rn", 1), ("Rd", 0)],
            "uminv h0, v1.8h",
        ),
        (
            "SHRN_advsimd.SHRN_asimdshf_N",
            &[
                ("Q", 0),
                ("immh", 0b0001),
                ("immb", 0b100),
                ("Rn", 1),
                ("Rd", 0),
            ],
            "shrn v0.8b, v1.8h, #4",
        ),
        (
            "SHRN_advsimd.SHRN_asimdshf_N",
            &[
                ("Q", 1),
                ("immh", 0b0001),
                ("immb", 0b000),
                ("Rn", 3),
                ("Rd", 2),
            ],
            "shrn2 v2.16b, v3.8h, #8",
        ),
        (
            "SHRN_advsimd.SHRN_asimdshf_N",
            &[
                ("Q", 0),
                ("immh", 0b0100),
                ("immb", 0b000),
                ("Rn", 5),
                ("Rd", 4),
            ],
            "shrn v4.2s, v5.2d, #32",
        ),
        (
            "USHR_advsimd.USHR_asisdshf_R",
            &[("immh", 0b1000), ("immb", 0b000), ("Rn", 1), ("Rd", 0)],
            "ushr d0, d1, #64",
        ),
        (
            "USHR_advsimd.USHR_asisdshf_R",
            &[("immh", 0b1111), ("immb", 0b111), ("Rn", 3), ("Rd", 2)],
            "ushr d2, d3, #1",
        ),
        (
            "USHR_advsimd.USHR_asimdshf_R",
            &[
                ("Q", 1),
                ("immh", 0b0001),
                ("immb", 0b101),
                ("Rn", 1),
                ("Rd", 0),
            ],
            "ushr v0.16b, v1.16b, #3",
        ),
        (
            "USHR_advsimd.USHR_asimdshf_R",
            &[
                ("Q", 1),
                ("immh", 0b1000),
                ("immb", 0b000),
                ("Rn", 3),
                ("Rd", 2),
            ],
            "ushr v2.2d, v3.2d, #64",
        ),
        (
            "SHL_advsimd.SHL_asisdshf_R",
            &[("immh", 0b1111), ("immb", 0b111), ("Rn", 1), ("Rd", 0)],
            "shl d0, d1, #63",
        ),
        (
            "SHL_advsimd.SHL_asimdshf_R",
            &[
                ("Q", 1),
                ("immh", 0b0111),
                ("immb", 0b111),
                ("Rn", 1),
                ("Rd", 0),
            ],
            "shl v0.4s, v1.4s, #31",
        ),
        (
            "SHL_advsimd.SHL_asimdshf_R",
            &[
                ("Q", 0),
                ("immh", 0b0001),
                ("immb", 0b000),
                ("Rn", 3),
                ("Rd", 2),
            ],
            "shl v2.8b, v3.8b, #0",
        ),
        (
            "USHLL_advsimd.USHLL_asimdshf_L",
            &[
                ("Q", 0),
                ("immh", 0b0001),
                ("immb", 0b000),
                ("Rn", 1),
                ("Rd", 0),
            ],
            "ushll v0.8h, v1.8b, #0",
        ),
        (
            "USHLL_advsimd.USHLL_asimdshf_L",
            &[
                ("Q", 1),
                ("immh", 0b0010),
                ("immb", 0b011),
                ("Rn", 3),
                ("Rd", 2),
            ],
            "ushll2 v2.4s, v3.8h, #3",
        ),
        (
            "USHLL_advsimd.USHLL_asimdshf_L",
            &[
                ("Q", 0),
                ("immh", 0b0111),
                ("immb", 0b111),
                ("Rn", 5),
                ("Rd", 4),
            ],
            "ushll v4.2d, v5.2s, #31",
        ),
        (
            "XTN_advsimd.XTN_asimdmisc_N",
            &[("Q", 0), ("size", 0), ("Rn", 1), ("Rd", 0)],
            "xtn v0.8b, v1.8h",
        ),
        (
            "XTN_advsimd.XTN_asimdmisc_N",
            &[("Q", 1), ("size", 2), ("Rn", 3), ("Rd", 2)],
            "xtn2 v2.4s, v3.2d",
        ),
        (
            "EXT_advsimd.EXT_asimdext_only",
            &[("Q", 1), ("Rm", 2), ("imm4", 15), ("Rn", 1), ("Rd", 0)],
            "ext v0.16b, v1.16b, v2.16b, #15",
        ),
        (
            "EXT_advsimd.EXT_asimdext_only",
            &[("Q", 0), ("Rm", 5), ("imm4", 7), ("Rn", 4), ("Rd", 3)],
            "ext v3.8b, v4.8b, v5.8b, #7",
        ),
        (
            "REV16_advsimd.REV16_asimdmisc_R",
            &[("Q", 1), ("size", 0), ("Rn", 1), ("Rd", 0)],
            "rev16 v0.16b, v1.16b",
        ),
        (
            "REV32_advsimd.REV32_asimdmisc_R",
            &[("Q", 1), ("size", 1), ("Rn", 1), ("Rd", 0)],
            "rev32 v0.8h, v1.8h",
        ),
        (
            "REV32_advsimd.REV32_asimdmisc_R",
            &[("Q", 0), ("size", 0), ("Rn", 3), ("Rd", 2)],
            "rev32 v2.8b, v3.8b",
        ),
        (
            "REV64_advsimd.REV64_asimdmisc_R",
            &[("Q", 1), ("size", 2), ("Rn", 1), ("Rd", 0)],
            "rev64 v0.4s, v1.4s",
        ),
        (
            "REV64_advsimd.REV64_asimdmisc_R",
            &[("Q", 0), ("size", 0), ("Rn", 3), ("Rd", 2)],
            "rev64 v2.8b, v3.8b",
        ),
        (
            "CNT_advsimd.CNT_asimdmisc_R",
            &[("Q", 1), ("size", 0), ("Rn", 1), ("Rd", 0)],
            "cnt v0.16b, v1.16b",
        ),
        (
            "CNT_advsimd.CNT_asimdmisc_R",
            &[("Q", 0), ("size", 0), ("Rn", 3), ("Rd", 2)],
            "cnt v2.8b, v3.8b",
        ),
        (
            "TBL_advsimd.TBL_asimdtbl_L1_1",
            &[("Q", 1), ("Rm", 2), ("Rn", 1), ("Rd", 0)],
            "tbl v0.16b, {v1.16b}, v2.16b",
        ),
        (
            "TBL_advsimd.TBL_asimdtbl_L1_1",
            &[("Q", 0), ("Rm", 5), ("Rn", 31), ("Rd", 3)],
            "tbl v3.8b, {v31.16b}, v5.8b",
        ),
    ];
    CASES
        .iter()
        .map(|&(form, fields, asm)| {
            let spec = crate::shared::arm64::GENERATED_A64_SUBSET
                .iter()
                .find(|spec| spec.key == form)
                .unwrap_or_else(|| panic!("{form}: not generated"));
            let mut word = spec.value;
            let mut set = |name: &str, value: u32| {
                let field = spec
                    .field(name)
                    .unwrap_or_else(|| panic!("{form}: no field {name}"));
                let bits = value << field.shift();
                assert_eq!(
                    bits & !field.mask,
                    0,
                    "{form}: {name} = {value:#x} does not fit"
                );
                // A partly fixed field (UMOV (64-bit) `imm5<3:0> = 1000`) must agree
                // with the diagram.
                assert_eq!(
                    bits & spec.mask,
                    spec.value & field.mask,
                    "{form}: {name} = {value:#x} changes a fixed bit"
                );
                word = (word & !field.mask) | bits;
            };
            for &(name, value) in fields {
                if name == "imm8" {
                    for (bit, name) in ["h", "g", "f", "e", "d", "c", "b", "a"].iter().enumerate() {
                        set(name, (value >> bit) & 1);
                    }
                } else {
                    set(name, value);
                }
            }
            let expected = A64Insn::decode(word)
                .unwrap_or_else(|| panic!("{form}: {word:#010x} does not decode"));
            assert_eq!(expected.key(), form, "{asm}: decodes as another form");
            assert!(!expected.is_decode_undefined(), "{asm}: decode-undefined");
            case(form, format!("    {asm}"), expected)
        })
        .collect()
}

fn simm9(value: i64) -> A64Imm {
    A64Imm::signed(signed_field(value, 9), 9)
}

fn pair_imm(bytes: i64, scale: u8) -> A64Imm {
    A64Imm::scaled_signed(signed_field(bytes >> scale, 7), 7, scale)
}

fn literal_imm(words: i64) -> A64Imm {
    A64Imm::scaled_signed(signed_field(words, 19), 19, 2)
}

fn decode_forms_from_subset_toml(toml: &str) -> Vec<String> {
    let mut forms = Vec::new();
    let mut in_decode = false;
    let mut in_forms = false;

    for line in toml.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            in_decode = line == "[decode]";
            in_forms = false;
            continue;
        }
        if !in_decode {
            continue;
        }
        if line.starts_with("forms") {
            in_forms = line.contains('[') && !line.contains(']');
            forms.extend(quoted_strings(line));
            continue;
        }
        if in_forms {
            forms.extend(quoted_strings(line));
            if line.contains(']') {
                in_forms = false;
            }
        }
    }

    forms
}

fn quoted_strings(line: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut rest = line;
    while let Some(start) = rest.find('"') {
        rest = &rest[start + 1..];
        let Some(end) = rest.find('"') else {
            break;
        };
        values.push(rest[..end].to_string());
        rest = &rest[end + 1..];
    }
    values
}

fn branch_imm(offset_bytes: i64, bits: u8) -> u32 {
    assert_eq!(offset_bytes % 4, 0);
    let value = offset_bytes >> 2;
    signed_field(value, bits)
}

fn signed_field(value: i64, bits: u8) -> u32 {
    let min = -(1_i64 << (bits - 1));
    let max = (1_i64 << (bits - 1)) - 1;
    assert!((min..=max).contains(&value));
    (value as i128 & ((1_i128 << bits) - 1)) as u32
}

fn bytes_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is before UNIX_EPOCH")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).unwrap_or_else(|err| {
            panic!(
                "failed to create temporary directory {}: {err}",
                path.display()
            )
        });
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
