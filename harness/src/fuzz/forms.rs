//! The fuzzer's view of the supported subset, derived entirely from the
//! generated form table (`GENERATED_A64_SUBSET`) and the generated `A64Insn`
//! API: which bits of each form are free, what each free field is (register
//! with its SP/ZR mode and whether it is written, memory base, memory offset
//! with signedness and scale, branch target with width, plain immediate), and
//! what kind of control flow the form is. A form added to
//! `spec/arm64/subset.toml` is fuzzed without touching this file.

use crate::shared::arm64::{
    form_base_word, A64Insn, A64OperandRole, A64Reg31Mode, GeneratedFieldSpec, GeneratedInsnSpec,
    GENERATED_A64_SUBSET,
};
use crate::shared::trans::cfg::RuntimeExitReason;

/// Any PC works for classifying a form; branch targets are PC-relative.
const PROBE_PC: u64 = 0x10000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormClass {
    /// Falls through: ALU, moves, NOP, ADR/ADRP.
    Straight,
    /// Loads and stores.
    Memory,
    /// Two-way branch to a program-internal target.
    CondBranch,
    /// Unconditional branch to a program-internal target.
    Jump,
    /// Immediate-target runtime exit (BL); its target is placed outside the text.
    ExitImm,
    /// Register-target runtime exit (BR, BLR, RET).
    ExitReg,
    /// SVC: a runtime exit that resumes at the next instruction.
    Svc,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BranchField {
    pub name: &'static str,
    pub bits: u8,
    pub scale: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKind {
    Reg {
        reg31: A64Reg31Mode,
        written: bool,
    },
    MemBase {
        reg31: A64Reg31Mode,
        written: bool,
    },
    /// Byte offset = sign-or-zero-extended raw value << `scale`.
    MemOffset {
        signed: bool,
        scale: u8,
    },
    /// PC-relative literal-load offset; the address is `A64Insn::literal_address`.
    LiteralOffset,
    BranchTarget(BranchField),
    Imm,
}

#[derive(Clone, Copy, Debug)]
pub struct FreeField {
    pub spec: &'static GeneratedFieldSpec,
    /// Word bits of this field the form's fixed mask leaves free.
    pub free_mask: u32,
    pub kind: FieldKind,
}

impl FreeField {
    /// `word` with this field's free bits replaced by `raw`.
    pub fn set(&self, word: u32, raw: u32) -> u32 {
        (word & !self.free_mask) | ((raw << self.spec.lo) & self.free_mask)
    }

    pub fn width(&self) -> u8 {
        self.spec.width
    }
}

#[derive(Debug)]
pub struct Form {
    pub spec: &'static GeneratedInsnSpec,
    pub class: FormClass,
    pub fields: Vec<FreeField>,
    pub implicit_writes: Vec<u8>,
}

impl Form {
    pub fn key(&self) -> &'static str {
        self.spec.key
    }

    pub fn branch_field(&self) -> Option<BranchField> {
        self.fields.iter().find_map(|field| match field.kind {
            FieldKind::BranchTarget(branch) => Some(branch),
            _ => None,
        })
    }

    /// Decodes `word` and requires it to be this form.
    pub fn decode(&self, word: u32) -> Option<A64Insn> {
        A64Insn::decode(word).filter(|insn| insn.key() == self.spec.key)
    }
}

#[derive(Debug)]
pub struct Catalog {
    pub forms: Vec<Form>,
}

impl Catalog {
    /// Panics if the generated metadata is inconsistent with the generated
    /// decoder: that is a specgen bug, not something to fuzz around.
    pub fn from_generated() -> Self {
        Self {
            forms: GENERATED_A64_SUBSET.iter().map(derive_form).collect(),
        }
    }

    pub fn by_key(&self, key: &str) -> Option<&Form> {
        self.forms.iter().find(|form| form.key() == key)
    }

    pub fn form_for_word(&self, word: u32) -> Option<&Form> {
        A64Insn::decode(word).and_then(|insn| self.by_key(insn.key()))
    }

    pub fn of_class(&self, class: FormClass) -> Vec<&Form> {
        self.forms
            .iter()
            .filter(|form| form.class == class)
            .collect()
    }

    /// The forms of `class` grouped by XML instruction section (the key before
    /// its `.`), in first-seen order. Picking a section first keeps a section
    /// with many encodings (A8's LSE atomics: 160 forms in 30 sections) from
    /// crowding out the rest of its class.
    pub fn sections_of_class(&self, class: FormClass) -> Vec<Vec<&Form>> {
        let mut sections: Vec<Vec<&Form>> = Vec::new();
        for form in self.of_class(class) {
            let section = |form: &Form| form.key().split('.').next().unwrap_or_default();
            match sections
                .iter_mut()
                .find(|forms| section(forms[0]) == section(form))
            {
                Some(forms) => forms.push(form),
                None => sections.push(vec![form]),
            }
        }
        sections
    }
}

fn derive_form(spec: &'static GeneratedInsnSpec) -> Form {
    let probe = decode_as(spec, form_base_word(spec));
    let roles = spec.operands;
    let written = |name: &str| {
        roles.iter().any(|role| {
            matches!(role, A64OperandRole::RegWrite { field, .. }
                | A64OperandRole::RegReadWrite { field, .. } if *field == name)
        })
    };

    let mut fields = Vec::new();
    for field in spec.fields {
        let free_mask = field.mask & !spec.mask;
        if free_mask == 0 {
            continue;
        }
        let name = field.name;
        let kind = if let Some(branch) = roles.iter().find_map(|role| match role {
            A64OperandRole::BranchTarget { field, bits, scale } if *field == name => {
                Some(BranchField {
                    name: field,
                    bits: *bits,
                    scale: *scale,
                })
            }
            _ => None,
        }) {
            FieldKind::BranchTarget(branch)
        } else if roles
            .iter()
            .any(|role| matches!(role, A64OperandRole::MemBase { field } if *field == name))
        {
            // Immediate-offset forms fold the base into their memory operand;
            // register-offset forms keep it as a plain register field.
            let base = probe
                .mem_operand()
                .map(|mem| mem.base())
                .or_else(|| probe.get_reg(name))
                .unwrap_or_else(|| {
                    panic!("form {}: MemBase field {name} is no register", spec.key)
                });
            FieldKind::MemBase {
                reg31: base.reg31,
                written: written(name),
            }
        } else if roles
            .iter()
            .any(|role| matches!(role, A64OperandRole::MemOffset { field } if *field == name))
        {
            if probe.literal_address(PROBE_PC).is_some() {
                FieldKind::LiteralOffset
            } else if probe.mem_operand().is_some() {
                probe_mem_offset(spec, field, free_mask)
            } else {
                // No address semantics (PRFM: a hint that never accesses memory).
                FieldKind::Imm
            }
        } else if let Some(reg) = probe.get_reg(name) {
            FieldKind::Reg {
                reg31: reg.reg31,
                written: written(name),
            }
        } else {
            FieldKind::Imm
        };
        fields.push(FreeField {
            spec: field,
            free_mask,
            kind,
        });
    }

    let implicit_writes = roles
        .iter()
        .filter_map(|role| match role {
            A64OperandRole::ImplicitRegWrite { reg, .. } => Some(*reg),
            _ => None,
        })
        .collect();

    let has_branch_target = fields
        .iter()
        .any(|field| matches!(field.kind, FieldKind::BranchTarget(_)));
    let exit = probe.runtime_exit_reason(PROBE_PC);
    let class = if has_branch_target {
        if exit.is_some() {
            FormClass::ExitImm
        } else if probe.direct_branch_target(PROBE_PC).is_some() {
            FormClass::Jump
        } else if probe.conditional_targets(PROBE_PC).is_some() {
            FormClass::CondBranch
        } else {
            panic!(
                "form {}: branch-target field but no branch semantics",
                spec.key
            )
        }
    } else {
        match exit {
            Some(RuntimeExitReason::Svc { .. }) => FormClass::Svc,
            Some(_) => FormClass::ExitReg,
            None if roles
                .iter()
                .any(|role| matches!(role, A64OperandRole::Memory)) =>
            {
                FormClass::Memory
            }
            None => FormClass::Straight,
        }
    };

    Form {
        spec,
        class,
        fields,
        implicit_writes,
    }
}

fn decode_as(spec: &GeneratedInsnSpec, word: u32) -> A64Insn {
    let insn = A64Insn::decode(word)
        .unwrap_or_else(|| panic!("form {}: {word:#010x} does not decode", spec.key));
    assert_eq!(
        insn.key(),
        spec.key,
        "form {}: {word:#010x} decodes as another form",
        spec.key
    );
    insn
}

/// Signedness and scale of a memory offset field, read back from the
/// generated decoder: all-ones raw decodes negative iff signed, raw 1 decodes
/// to the scale.
fn probe_mem_offset(
    spec: &'static GeneratedInsnSpec,
    field: &'static GeneratedFieldSpec,
    free_mask: u32,
) -> FieldKind {
    let offset_of = |word: u32| {
        decode_as(spec, word)
            .mem_operand()
            .unwrap_or_else(|| panic!("form {}: MemOffset role but no memory operand", spec.key))
            .offset_imm()
            .value()
    };
    let unit = offset_of((spec.value & !free_mask) | (1 << field.lo));
    assert!(
        unit > 0 && (unit as u64).is_power_of_two(),
        "form {}: offset unit {unit} is not a power of two",
        spec.key
    );
    FieldKind::MemOffset {
        signed: offset_of(spec.value | free_mask) < 0,
        scale: unit.trailing_zeros() as u8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_classifies_every_generated_form() {
        let catalog = Catalog::from_generated();
        assert_eq!(catalog.forms.len(), GENERATED_A64_SUBSET.len());
        let class = |key: &str| catalog.by_key(key).unwrap().class;
        assert_eq!(class("B_cond.B_only_condbranch"), FormClass::CondBranch);
        assert_eq!(class("B_uncond.B_only_branch_imm"), FormClass::Jump);
        assert_eq!(class("BL.BL_only_branch_imm"), FormClass::ExitImm);
        assert_eq!(class("RET.RET_64R_branch_reg"), FormClass::ExitReg);
        assert_eq!(class("SVC.SVC_EX_exception"), FormClass::Svc);
        assert_eq!(class("LDP_gen.LDP_64_ldstpair_pre"), FormClass::Memory);
        assert_eq!(class("MOVK.MOVK_64_movewide"), FormClass::Straight);
        // A10: each MRS instance is its own form, generated like any other.
        for sysreg in ["TPIDR_EL0", "CNTVCT_EL0", "CNTFRQ_EL0"] {
            let key = format!("MRS.MRS_RS_systemmove@{sysreg}");
            assert_eq!(class(&key), FormClass::Straight, "{key}");
        }

        let offset = |key: &str| {
            catalog
                .by_key(key)
                .unwrap()
                .fields
                .iter()
                .find_map(|field| match field.kind {
                    FieldKind::MemOffset { signed, scale } => Some((signed, scale)),
                    _ => None,
                })
                .unwrap()
        };
        assert_eq!(offset("LDR_imm_gen.LDR_64_ldst_pos"), (false, 3));
        assert_eq!(offset("STR_imm_gen.STR_32_ldst_pos"), (false, 2));
        assert_eq!(offset("LDR_imm_gen.LDR_64_ldst_immpost"), (true, 0));
        assert_eq!(offset("STP_gen.STP_64_ldstpair_off"), (true, 3));
    }
}
