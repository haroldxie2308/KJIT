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

    for form in decode_forms {
        if !covered_forms.contains(form.as_str()) {
            println!("WARN: decode form has no encoding test: {form}");
        }
    }
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
