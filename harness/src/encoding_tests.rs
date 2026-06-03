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
    asm: &'static str,
    expected: A64Insn,
}

#[test]
#[ignore = "requires llvm-mc and llvm-objcopy in PATH"]
fn encoding_matches_llvm_for_handwritten_cases() {
    let cases = encoding_cases();
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

    fs::write(&asm_path, asm_source(case.asm))
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

fn case(form: &'static str, asm: &'static str, expected: A64Insn) -> EncodingCase {
    EncodingCase {
        form,
        asm,
        expected,
    }
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
