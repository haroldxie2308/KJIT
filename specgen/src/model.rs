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
    pub fields: Vec<FieldSpec>,
    pub operand_roles: Vec<OperandRoleSpec>,
    pub asm: String,
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
