use crate::model::{AsmOperand, FieldSlice, OperandRoleSpec};
use indexmap::IndexMap;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};

type RoleTuple = (String, String, String);

pub fn infer_operand_roles(
    docvars: &IndexMap<String, String>,
    fields: &[FieldSlice],
    operands: &[AsmOperand],
    decode_text: &str,
    execute_text: &str,
) -> Vec<OperandRoleSpec> {
    let field_names = fields
        .iter()
        .filter(|field| field.variable)
        .map(|field| field.name.clone())
        .collect::<BTreeSet<_>>();
    let var_map = decode_var_map(decode_text);
    let mut roles = BTreeSet::new();

    roles.extend(infer_roles_from_docvars_and_asm(
        docvars,
        operands,
        &field_names,
    ));
    roles.extend(infer_roles_from_pseudocode(
        &field_names,
        &var_map,
        docvars,
        execute_text,
    ));

    simplify_roles(roles)
        .into_iter()
        .map(|(kind, field, width)| OperandRoleSpec { kind, field, width })
        .collect()
}

fn decode_var_map(decode_text: &str) -> BTreeMap<String, String> {
    let mut ret = BTreeMap::new();
    let let_re = Regex::new(r"\blet\s+(\w+)\b[^=]*=\s*UInt\((\w+)\)").unwrap();
    let var_re = Regex::new(r"\bvar\s+(\w+)\b[^=]*=\s*UInt\((\w+)\)").unwrap();

    for captures in let_re.captures_iter(decode_text) {
        ret.insert(captures[1].to_string(), captures[2].to_string());
    }
    for captures in var_re.captures_iter(decode_text) {
        ret.insert(captures[1].to_string(), captures[2].to_string());
    }
    ret
}

fn normalize_role_field(value: &str, fields: &BTreeSet<String>) -> String {
    if matches!(value, "30" | "x30") {
        return "x30".to_string();
    }

    fields
        .iter()
        .find(|field| field.eq_ignore_ascii_case(value))
        .cloned()
        .unwrap_or_else(|| value.to_string())
}

fn operand_width(docvars: &IndexMap<String, String>, operand: Option<&AsmOperand>) -> String {
    let datatype = docvars.get("datatype").map(String::as_str);
    let reg_type = docvars.get("reg-type").map(String::as_str).unwrap_or("");
    let hover = operand
        .map(|operand| operand.hover.to_lowercase())
        .unwrap_or_default();
    let text = operand.map(|operand| operand.text.as_str()).unwrap_or("");

    if datatype == Some("32")
        || reg_type.starts_with("32-")
        || hover.contains("32-bit")
        || text.starts_with("<W")
    {
        return "W32".to_string();
    }
    if datatype == Some("64")
        || reg_type.starts_with("64-")
        || hover.contains("64-bit")
        || text.starts_with("<X")
    {
        return "X64".to_string();
    }
    "Unknown".to_string()
}

fn role_tuple(kind: &str, field: &str, width: &str) -> RoleTuple {
    (kind.to_string(), field.to_string(), width.to_string())
}

fn infer_roles_from_pseudocode(
    fields: &BTreeSet<String>,
    var_map: &BTreeMap<String, String>,
    docvars: &IndexMap<String, String>,
    execute_text: &str,
) -> BTreeSet<RoleTuple> {
    let mut roles = BTreeSet::new();
    let reg_accessors = Regex::new(r"\b(?:X|W|SP)\s*(?:\{[^}]*\})?\((\w+)\)").unwrap();
    let assignment_after = Regex::new(r"^\s*=").unwrap();

    for captures in reg_accessors.captures_iter(execute_text) {
        let captured = captures.get(1).unwrap().as_str();
        let field = normalize_role_field(
            var_map.get(captured).map_or(captured, String::as_str),
            fields,
        );
        if !fields.contains(&field) && field != "x30" {
            continue;
        }

        let after_start = captures.get(0).unwrap().end();
        let after_end = (after_start + 8).min(execute_text.len());
        let kind = if assignment_after.is_match(&execute_text[after_start..after_end]) {
            "RegWrite"
        } else {
            "RegRead"
        };
        roles.insert(role_tuple(kind, &field, &operand_width(docvars, None)));
    }

    let bracket_accessors = Regex::new(r"\b(?:X|W|SP)\[([^\],\]]+)(?:,[^\]]*)?\]").unwrap();
    for captures in bracket_accessors.captures_iter(execute_text) {
        let captured = captures.get(1).unwrap().as_str().trim();
        let field = normalize_role_field(
            var_map.get(captured).map_or(captured, String::as_str),
            fields,
        );
        if !fields.contains(&field) && field != "x30" {
            continue;
        }

        let after_start = captures.get(0).unwrap().end();
        let after_end = (after_start + 8).min(execute_text.len());
        let kind = if assignment_after.is_match(&execute_text[after_start..after_end]) {
            "RegWrite"
        } else {
            "RegRead"
        };
        roles.insert(role_tuple(kind, &field, &operand_width(docvars, None)));
    }

    if execute_text.contains("ConditionHolds") {
        roles.insert(role_tuple("FlagsRead", "", "Unknown"));
    }
    if execute_text.contains("PSTATE.NZCV")
        || (execute_text.contains("AddWithCarry") && execute_text.contains("nzcv"))
    {
        roles.insert(role_tuple("FlagsWrite", "", "Unknown"));
    }
    if execute_text.contains("BranchTo") || execute_text.contains("BranchNotTaken") {
        roles.insert(role_tuple("ControlFlow", "", "Unknown"));
    }
    if execute_text.contains("Mem") {
        roles.insert(role_tuple("Memory", "", "Unknown"));
    }

    roles
}

fn infer_roles_from_docvars_and_asm(
    docvars: &IndexMap<String, String>,
    operands: &[AsmOperand],
    fields: &BTreeSet<String>,
) -> BTreeSet<RoleTuple> {
    let mut roles = BTreeSet::new();
    let mnemonic = docvars.get("mnemonic").map(String::as_str).unwrap_or("");
    let address_form = docvars
        .get("address-form")
        .map(String::as_str)
        .unwrap_or("");

    if docvars.contains_key("branch-offset") {
        for field in fields {
            if field.to_lowercase().starts_with("imm") {
                roles.insert(role_tuple("BranchTarget", field, "Unknown"));
            }
        }
    }

    if matches!(mnemonic, "B" | "BL") {
        for field in fields {
            if field.to_lowercase().starts_with("imm") {
                roles.insert(role_tuple("BranchTarget", field, "Unknown"));
            }
        }
        if mnemonic == "BL" {
            roles.insert(role_tuple("ImplicitRegWrite", "x30", "X64"));
        }
    }

    if matches!(mnemonic, "BR" | "BLR" | "RET") && fields.contains("Rn") {
        roles.insert(role_tuple("RegRead", "Rn", "X64"));
        if mnemonic == "BLR" {
            roles.insert(role_tuple("ImplicitRegWrite", "x30", "X64"));
        }
    }

    if matches!(mnemonic, "CBZ" | "CBNZ" | "TBZ" | "TBNZ") && fields.contains("Rt") {
        roles.insert(role_tuple("RegRead", "Rt", &operand_width(docvars, None)));
        for field in fields {
            if field.to_lowercase().starts_with("imm") {
                roles.insert(role_tuple("BranchTarget", field, "Unknown"));
            }
        }
    }

    if matches!(mnemonic, "LDR" | "STR") {
        if fields.contains("Rn") {
            if matches!(address_form, "pre-indexed" | "post-indexed") {
                roles.insert(role_tuple("RegReadWrite", "Rn", "X64"));
            } else {
                roles.insert(role_tuple("RegRead", "Rn", "X64"));
            }
            roles.insert(role_tuple("MemBase", "Rn", "X64"));
        }
        if fields.contains("Rt") {
            let kind = if mnemonic == "LDR" {
                "RegWrite"
            } else {
                "RegRead"
            };
            roles.insert(role_tuple(kind, "Rt", &operand_width(docvars, None)));
        }
        for field in fields {
            if field.to_lowercase().starts_with("imm") {
                roles.insert(role_tuple("MemOffset", field, "Unknown"));
            }
        }
    }

    let encoded_re = Regex::new(r#"encoded (?:as|in) (?:the )?"([^"]+)" field"#).unwrap();
    for operand in operands {
        let hover = operand.hover.to_lowercase();
        let Some(captures) = encoded_re.captures(&hover) else {
            continue;
        };
        let field = normalize_role_field(captures.get(1).unwrap().as_str(), fields);
        let width = operand_width(docvars, Some(operand));

        if hover.contains("base register") {
            roles.insert(role_tuple("MemBase", &field, "X64"));
            roles.insert(role_tuple("RegRead", &field, "X64"));
        }
        if hover.contains("destination register") || hover.contains("written") {
            roles.insert(role_tuple("RegWrite", &field, &width));
        }
        if hover.contains("source register")
            || hover.contains("first operand register")
            || hover.contains("second operand register")
            || hover.contains("register to be tested")
        {
            roles.insert(role_tuple("RegRead", &field, &width));
        }
        if hover.contains("register to be transferred") {
            let kind = if mnemonic == "LDR" {
                "RegWrite"
            } else {
                "RegRead"
            };
            roles.insert(role_tuple(kind, &field, &width));
        }
        if hover.contains("program label") || operand.text.contains("<label>") {
            roles.insert(role_tuple("BranchTarget", &field, "Unknown"));
        }
    }

    roles
}

fn simplify_roles(roles: BTreeSet<RoleTuple>) -> BTreeSet<RoleTuple> {
    let mut simplified = roles.clone();

    for (kind, field, width) in simplified.clone() {
        if kind == "RegWrite" && field == "x30" {
            simplified.remove(&(kind, field, width));
            simplified.insert(role_tuple("ImplicitRegWrite", "x30", "X64"));
        }
    }

    for (kind, field, width) in &roles {
        if width != "Unknown" {
            simplified.remove(&(kind.clone(), field.clone(), "Unknown".to_string()));
        }
    }

    let read_write_fields = simplified
        .iter()
        .filter(|(kind, _, _)| kind == "RegReadWrite")
        .map(|(_, field, width)| (field.clone(), width.clone()))
        .collect::<Vec<_>>();
    for (field, width) in read_write_fields {
        simplified.remove(&role_tuple("RegRead", &field, &width));
        simplified.remove(&role_tuple("RegWrite", &field, &width));
    }

    simplified
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_implicit_lr_write() {
        let mut roles = BTreeSet::new();
        roles.insert(role_tuple("RegWrite", "x30", "Unknown"));

        let simplified = simplify_roles(roles);

        assert!(simplified.contains(&role_tuple("ImplicitRegWrite", "x30", "X64")));
        assert!(!simplified.contains(&role_tuple("RegWrite", "x30", "Unknown")));
    }
}
