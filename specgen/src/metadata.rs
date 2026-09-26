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
    postdecode_text: &str,
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
    roles.extend(infer_load_store_roles(
        docvars,
        operands,
        &field_names,
        &bound_fields(&format!("{decode_text} {postdecode_text}")),
        execute_text,
    ));
    // A general-purpose load/store's register roles come from
    // `infer_load_store_roles` alone. Its execute pseudocode is shared by every
    // encoding of the section (STLR's ldstord form shares the FEAT_LRCPC3
    // writeback form's `X{64}(n) = address`), so a register access there does not
    // hold for each form.
    let load_store = gpr_mem_op(execute_text).is_some();
    roles.extend(
        infer_roles_from_pseudocode(&field_names, &var_map, docvars, operands, execute_text)
            .into_iter()
            .filter(|(kind, _, _)| {
                !(load_store && matches!(kind.as_str(), "RegRead" | "RegWrite" | "RegReadWrite"))
            }),
    );

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

/// Encoding fields the decode/postdecode pseudocode reads as a register number
/// (`UInt(Rt2)`).
fn bound_fields(decode_text: &str) -> BTreeSet<String> {
    Regex::new(r"\bUInt\((\w+)\)")
        .unwrap()
        .captures_iter(decode_text)
        .map(|captures| captures[1].to_string())
        .collect()
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

    // An operand's own `<W..>`/`<X..>` wins over the form's datatype: CRC32X is a
    // 64-bit datatype form whose accumulator and result are `<Wn>`/`<Wd>`.
    if text.starts_with("<W") {
        return "W32".to_string();
    }
    if text.starts_with("<X") {
        return "X64".to_string();
    }
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
    operands: &[AsmOperand],
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
        let width = operand_width(docvars, encoding_operand(operands, &field));
        roles.insert(role_tuple(kind, &field, &width));
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
        let width = operand_width(docvars, encoding_operand(operands, &field));
        roles.insert(role_tuple(kind, &field, &width));
    }

    if execute_text.contains("ConditionHolds") || reads_single_flag(execute_text) {
        roles.insert(role_tuple("FlagsRead", "", "Unknown"));
    }
    // Every flag-setting form assigns all four flags, e.g. `PSTATE.[N,Z,C,V] = nzcv;`
    // (ADDS/SUBS), `= result[..]::IsZeroBit(..)::'00';` (ANDS/BICS), `= flags;` (CCMP).
    let flags_write = Regex::new(r"PSTATE\.(?:NZCV|\[N,\s*Z,\s*C,\s*V\])\s*=").unwrap();
    if flags_write.is_match(execute_text) {
        roles.insert(role_tuple("FlagsWrite", "", "Unknown"));
    }
    if execute_text.contains("BranchTo") || execute_text.contains("BranchNotTaken") {
        roles.insert(role_tuple("ControlFlow", "", "Unknown"));
    }
    // An architectural memory access (`Mem{size}(address, accdesc)`). PRFM only
    // builds a `MemOp_PREFETCH` descriptor and calls `Prefetch`: no access, no role.
    if Regex::new(r"\bMem\s*\{").unwrap().is_match(execute_text) {
        roles.insert(role_tuple("Memory", "", "Unknown"));
    }

    roles
}

/// A read of one flag, e.g. ADC/SBC's carry in `AddWithCarry(x, y, PSTATE.C)`. An
/// assignment to it (`PSTATE.C = ...`, not `==`) is a write, not a read. The
/// flattened XML text may split a linked `PSTATE` from `.C` with a space.
fn reads_single_flag(execute_text: &str) -> bool {
    let flag = Regex::new(r"PSTATE\s*\.[NZCV]\b").unwrap();
    let assignment = Regex::new(r"^\s*=([^=]|$)").unwrap();
    let read = flag
        .find_iter(execute_text)
        .any(|found| !assignment.is_match(&execute_text[found.end()..]));
    read
}

fn infer_roles_from_docvars_and_asm(
    docvars: &IndexMap<String, String>,
    operands: &[AsmOperand],
    fields: &BTreeSet<String>,
) -> BTreeSet<RoleTuple> {
    let mut roles = BTreeSet::new();
    let mnemonic = docvars.get("mnemonic").map(String::as_str).unwrap_or("");
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

    let encoded_re = Regex::new(r#"encoded (?:as|in) (?:the )?"([^"]+)" field"#).unwrap();
    for operand in operands {
        let hover = operand.hover.to_lowercase();
        let Some(captures) = encoded_re.captures(&hover) else {
            continue;
        };
        let field = normalize_role_field(captures.get(1).unwrap().as_str(), fields);
        let width = operand_width(docvars, Some(operand));

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
        if hover.contains("program label") || operand.text.contains("<label>") {
            roles.insert(role_tuple("BranchTarget", &field, "Unknown"));
        }
    }

    roles
}

/// Direction of a general-purpose load/store, read from the access descriptor its
/// execute pseudocode builds: `CreateAccDescGPR(MemOp_LOAD | MemOp_STORE |
/// MemOp_PREFETCH, ...)`, the ordered `CreateAccDescAcqRel(MemOp_LOAD |
/// MemOp_STORE, ...)` (LDAR/STLR), or `CreateAccDescLDAcqPC(...)`, which is
/// load-only (LDAPR). Exclusive and atomic descriptors are not matched. `None` for
/// anything else, or if the text names more than one direction.
fn gpr_mem_op(execute_text: &str) -> Option<String> {
    let re = Regex::new(
        r"CreateAccDesc(?:GPR|AcqRel)\s*\(\s*MemOp_(LOAD|STORE|PREFETCH)\b|CreateAccDesc(LDAcqPC)\s*\(",
    )
    .unwrap();
    let ops = re
        .captures_iter(execute_text)
        .map(|captures| match captures.get(1) {
            Some(op) => op.as_str().to_string(),
            None => "LOAD".to_string(),
        })
        .collect::<BTreeSet<_>>();
    if ops.len() == 1 {
        ops.into_iter().next()
    } else {
        None
    }
}

/// Register and addressing roles of every general-purpose load/store form, derived
/// from the XML rather than mnemonic lists:
/// - `Rn` is the base (`MemBase`), read-write when `address-form` is pre/post-indexed;
/// - `Rt`/`Rt2` are written by a load and read by a store (a prefetch's `Rt` is its
///   operation code, not a register);
/// - `Rm` is the register-offset index, read as a 64-bit register that `ExtendReg`
///   then narrows (as for ADD/SUB extended register);
/// - every `imm*` field is the address offset (`MemOffset`); with no `Rn` the offset
///   is from the PC (literal loads).
///
/// A register field (`R*`) is an operand only if the decode or postdecode
/// pseudocode binds it (`let t2 = UInt(Rt2)`): LDAR/STLR carry `Rs`/`Rt2` as
/// should-be-one fields their decode never reads.
fn infer_load_store_roles(
    docvars: &IndexMap<String, String>,
    operands: &[AsmOperand],
    diagram_fields: &BTreeSet<String>,
    bound: &BTreeSet<String>,
    execute_text: &str,
) -> BTreeSet<RoleTuple> {
    let mut roles = BTreeSet::new();
    let Some(mem_op) = gpr_mem_op(execute_text) else {
        return roles;
    };
    let fields = diagram_fields
        .iter()
        .filter(|field| !field.starts_with('R') || bound.contains(*field))
        .cloned()
        .collect::<BTreeSet<_>>();
    let writeback = matches!(
        docvars.get("address-form").map(String::as_str),
        Some("pre-indexed" | "post-indexed")
    );

    if fields.contains("Rn") {
        let kind = if writeback { "RegReadWrite" } else { "RegRead" };
        roles.insert(role_tuple(kind, "Rn", "X64"));
        roles.insert(role_tuple("MemBase", "Rn", "X64"));
    }
    if fields.contains("Rm") {
        roles.insert(role_tuple("RegRead", "Rm", "X64"));
    }
    let transfer_kind = match mem_op.as_str() {
        "LOAD" => Some("RegWrite"),
        "STORE" => Some("RegRead"),
        _ => None,
    };
    if let Some(kind) = transfer_kind {
        for field in ["Rt", "Rt2"] {
            if fields.contains(field) {
                let width = operand_width(docvars, encoding_operand(operands, field));
                roles.insert(role_tuple(kind, field, &width));
            }
        }
    }
    for field in &fields {
        if field.to_lowercase().starts_with("imm") {
            roles.insert(role_tuple("MemOffset", field, "Unknown"));
        }
    }
    roles
}

/// The assembler operand whose hover says it is encoded in `field`.
fn encoding_operand<'a>(operands: &'a [AsmOperand], field: &str) -> Option<&'a AsmOperand> {
    let encoded = format!("\"{field}\" field");
    operands
        .iter()
        .find(|operand| operand.hover.contains(&encoded))
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
    fn flags_write_is_inferred_from_nzcv_assignment_only() {
        let fields = BTreeSet::new();
        let vars = BTreeMap::new();
        let docvars = IndexMap::new();
        let writes =
            |text: &str| {
                infer_roles_from_pseudocode(&fields, &vars, &docvars, &[], text)
                    .contains(&role_tuple("FlagsWrite", "", "Unknown"))
            };

        assert!(writes(
            "(result, nzcv) = AddWithCarry(a, b, '1'); PSTATE.[N,Z,C,V] = nzcv;"
        ));
        assert!(writes(
            "PSTATE.[N,Z,C,V] = result[31]::IsZeroBit(result)::'00';"
        ));
        assert!(writes("if ConditionHolds(c) then (-, flags) = AddWithCarry(a, b, '0'); end; PSTATE.[N,Z,C,V] = flags;"));
        assert!(!writes(
            "(result, -) = AddWithCarry(a, b, '0'); X(d) = result;"
        ));
        assert!(!writes("if ConditionHolds(c) then result = X(n); end;"));
    }

    #[test]
    fn flags_read_is_inferred_from_condition_or_single_flag_read() {
        let fields = BTreeSet::new();
        let vars = BTreeMap::new();
        let docvars = IndexMap::new();
        let reads =
            |text: &str| {
                infer_roles_from_pseudocode(&fields, &vars, &docvars, &[], text)
                    .contains(&role_tuple("FlagsRead", "", "Unknown"))
            };

        assert!(reads(
            "(result, -) = AddWithCarry{datasize}(operand1, operand2, PSTATE.C);"
        ));
        assert!(reads("if PSTATE.C == '1' then X(d) = a; end;"));
        assert!(reads(
            "AddWithCarry {datasize} (operand1, operand2, PSTATE .C);"
        ));
        assert!(reads("if ConditionHolds(cond) then result = X(n); end;"));
        assert!(!reads(
            "(result, nzcv) = AddWithCarry(a, b, '0'); PSTATE.[N,Z,C,V] = nzcv;"
        ));
        assert!(!reads("PSTATE.C = '1';"));
    }

    #[test]
    fn operand_text_width_wins_over_datatype() {
        let mut docvars = IndexMap::new();
        docvars.insert("datatype".to_string(), "64".to_string());
        let operand = |text: &str| AsmOperand {
            text: text.to_string(),
            link: String::new(),
            hover: String::new(),
        };
        // CRC32X: 64-bit datatype, `<Wd>, <Wn>, <Xm>`.
        assert_eq!(operand_width(&docvars, Some(&operand("<Wd>"))), "W32");
        assert_eq!(operand_width(&docvars, Some(&operand("<Xm>"))), "X64");
        assert_eq!(operand_width(&docvars, None), "X64");
    }

    #[test]
    fn load_store_direction_comes_from_the_access_descriptor() {
        let load = "let accdesc = CreateAccDescGPR(MemOp_LOAD, nontemporal, privileged, t);";
        let store = "let accdesc = CreateAccDescGPR ( MemOp_STORE , nontemporal );";
        let prefetch = "CreateAccDescGPR(MemOp_PREFETCH, nontemporal); Prefetch(address, t);";
        assert_eq!(gpr_mem_op(load).as_deref(), Some("LOAD"));
        assert_eq!(gpr_mem_op(store).as_deref(), Some("STORE"));
        assert_eq!(gpr_mem_op(prefetch).as_deref(), Some("PREFETCH"));
        assert_eq!(gpr_mem_op(&format!("{load} {store}")), None);
        let acquire = "let accdesc = CreateAccDescAcqRel(MemOp_LOAD, tagchecked, acquire, t);";
        let release = "let accdesc = CreateAccDescAcqRel(MemOp_STORE, tagchecked, acquire, t);";
        let acquire_pc = "let accdesc = CreateAccDescLDAcqPC(tagchecked, acquirepc, t);";
        let exclusive = "let accdesc = CreateAccDescExLDST(MemOp_LOAD, acquire, tagchecked, t);";
        assert_eq!(gpr_mem_op(acquire).as_deref(), Some("LOAD"));
        assert_eq!(gpr_mem_op(release).as_deref(), Some("STORE"));
        assert_eq!(gpr_mem_op(acquire_pc).as_deref(), Some("LOAD"));
        assert_eq!(gpr_mem_op(exclusive), None);
        assert_eq!(gpr_mem_op("X(d) = result;"), None);
    }

    #[test]
    fn normalizes_implicit_lr_write() {
        let mut roles = BTreeSet::new();
        roles.insert(role_tuple("RegWrite", "x30", "Unknown"));

        let simplified = simplify_roles(roles);

        assert!(simplified.contains(&role_tuple("ImplicitRegWrite", "x30", "X64")));
        assert!(!simplified.contains(&role_tuple("RegWrite", "x30", "Unknown")));
    }
}
