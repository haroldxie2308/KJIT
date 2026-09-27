use indexmap::IndexMap;
use serde::Serialize;

#[derive(Clone, Debug)]
pub struct FieldSlice {
    pub name: String,
    pub hi: u8,
    pub width: u8,
    pub variable: bool,
}

impl FieldSlice {
    pub fn lo(&self) -> u8 {
        self.hi + 1 - self.width
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AsmOperand {
    pub text: String,
    pub link: String,
    pub hover: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct FieldSpec {
    pub name: String,
    pub hi: u8,
    pub lo: u8,
    pub width: u8,
    pub shift: u8,
    pub mask: String,
    pub variable: bool,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct OperandRoleSpec {
    pub kind: String,
    pub field: String,
    pub width: String,
}

/// A bit pattern the variant's words must not match (a `!=` constraint in the
/// encoding diagram).
#[derive(Clone, Debug, Serialize)]
pub struct ExcludeSpec {
    pub mask: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct VariantSpec {
    pub section_id: String,
    pub heading: String,
    pub title: String,
    pub iclass: String,
    pub encoding_name: String,
    pub encoding_label: String,
    pub mnemonic: String,
    pub docvars: IndexMap<String, String>,
    pub asm_operands: Vec<AsmOperand>,
    pub mask: String,
    pub value: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub excludes: Vec<ExcludeSpec>,
    pub fields: Vec<FieldSpec>,
    pub operand_roles: Vec<OperandRoleSpec>,
    pub asm: String,
    /// Set for one exact instance of an encoding (`decode.field_instances`):
    /// the encoding with some non-operand fields pinned, generated as its own
    /// variant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
}

impl VariantSpec {
    /// The XML form key `<section>.<encoding>`.
    pub fn form_key(&self) -> String {
        format!("{}.{}", self.section_id, self.encoding_name)
    }

    /// The generated form key: the XML form key, plus `@<instance>` for an
    /// instance.
    pub fn key(&self) -> String {
        match &self.instance {
            Some(instance) => format!("{}@{instance}", self.form_key()),
            None => self.form_key(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct InstructionSpec {
    pub source_file: String,
    pub section_id: String,
    pub heading: String,
    pub title: String,
    pub docvars: IndexMap<String, String>,
    pub variants: Vec<VariantSpec>,
}
