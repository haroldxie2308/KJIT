#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import textwrap
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path


DEFAULT_SUBSET_CONFIG = "./spec/arm64/subset.toml"


@dataclass
class FieldSlice:
    name: str
    hi: int
    width: int
    variable: bool

    @property
    def lo(self) -> int:
        return self.hi - self.width + 1


def flatten_text(elem: ET.Element) -> str:
    parts: list[str] = []
    for chunk in elem.itertext():
        text = chunk.strip()
        if text:
            parts.append(text)
    return " ".join(parts)


def bit_positions(hibit: int, width: int) -> list[int]:
    return list(range(hibit, hibit - width, -1))


def parse_box(box: ET.Element) -> tuple[int, int, list[FieldSlice]]:
    hibit = int(box.attrib["hibit"])
    width = int(box.attrib.get("width", "1"))
    name = box.attrib.get("name")
    positions = bit_positions(hibit, width)
    cells = box.findall("c")

    mask = 0
    value = 0
    used = 0

    for cell in cells:
        span = int(cell.attrib.get("colspan", "1"))
        text = (cell.text or "").strip()
        cell_positions = positions[used:used + span]
        used += span
        if len(text) == span and all(ch in "01" for ch in text):
            for bit, ch in zip(cell_positions, text):
                mask |= 1 << bit
                if ch == "1":
                    value |= 1 << bit
        elif len(text) == 1 and text in "01" and span == 1:
            bit = cell_positions[0]
            mask |= 1 << bit
            if text == "1":
                value |= 1 << bit

    fields: list[FieldSlice] = []
    if name:
        field_mask = ((1 << width) - 1) << (hibit - width + 1)
        fields.append(
            FieldSlice(
                name=name,
                hi=hibit,
                width=width,
                variable=(mask & field_mask) != field_mask,
            )
        )

    return mask, value, fields


def parse_regdiagram(regdiagram: ET.Element | None) -> tuple[int, int, list[FieldSlice]]:
    if regdiagram is None:
        return 0, 0, []

    mask = 0
    value = 0
    fields: list[FieldSlice] = []
    for box in regdiagram.findall("box"):
        box_mask, box_value, box_fields = parse_box(box)
        mask |= box_mask
        value |= box_value
        fields.extend(box_fields)
    return mask, value, fields


def parse_docvars(node: ET.Element) -> dict[str, str]:
    docvars = node.find("docvars")
    if docvars is None:
        return {}
    return {
        docvar.attrib["key"]: docvar.attrib["value"]
        for docvar in docvars.findall("docvar")
    }


def parse_asm_operands(encoding: ET.Element) -> list[dict[str, str]]:
    asm = encoding.find("asmtemplate")
    if asm is None:
        return []
    return [
        {
            "text": flatten_text(anchor),
            "link": anchor.attrib.get("link", ""),
            "hover": anchor.attrib.get("hover", ""),
        }
        for anchor in asm.findall("a")
    ]


def parse_ps_texts(root: ET.Element, iclass: ET.Element) -> tuple[str, str]:
    decode = " ".join(
        flatten_text(node)
        for node in iclass.findall(".//pstext")
        if node.attrib.get("rep_section") == "decode"
    )
    execute = " ".join(
        flatten_text(node)
        for node in root.findall("./ps_section//pstext")
        if node.attrib.get("rep_section") == "execute"
    )
    return decode, execute


def decode_var_map(decode_text: str) -> dict[str, str]:
    ret: dict[str, str] = {}
    for var, field in re.findall(r"\blet\s+(\w+)\b[^=]*=\s*UInt\((\w+)\)", decode_text):
        ret[var] = field
    for var, field in re.findall(r"\bvar\s+(\w+)\b[^=]*=\s*UInt\((\w+)\)", decode_text):
        ret[var] = field
    return ret


def normalize_role_field(value: str, fields: set[str]) -> str:
    by_lower = {field.lower(): field for field in fields}
    if value in {"30", "x30"}:
        return "x30"
    return by_lower.get(value.lower(), value)


def operand_width(docvars: dict[str, str], operand: dict[str, str] | None = None) -> str:
    datatype = docvars.get("datatype")
    reg_type = docvars.get("reg-type", "")
    hover = (operand or {}).get("hover", "").lower()
    text = (operand or {}).get("text", "")
    if datatype == "32" or reg_type.startswith("32-") or "32-bit" in hover or text.startswith("<W"):
        return "W32"
    if datatype == "64" or reg_type.startswith("64-") or "64-bit" in hover or text.startswith("<X"):
        return "X64"
    return "Unknown"


def role_tuple(kind: str, field: str = "", width: str = "Unknown") -> tuple[str, str, str]:
    return kind, field, width


def infer_roles_from_pseudocode(
    fields: set[str],
    var_map: dict[str, str],
    docvars: dict[str, str],
    execute_text: str,
) -> set[tuple[str, str, str]]:
    roles: set[tuple[str, str, str]] = set()
    reg_accessors = r"\b(?:X|W|SP)\s*(?:\{[^}]*\})?\((\w+)\)"
    for match in re.finditer(reg_accessors, execute_text):
        field = normalize_role_field(var_map.get(match.group(1), match.group(1)), fields)
        if field not in fields and field != "x30":
            continue
        after = execute_text[match.end() : match.end() + 8]
        kind = "RegWrite" if re.match(r"\s*=", after) else "RegRead"
        roles.add(role_tuple(kind, field, operand_width(docvars)))

    bracket_accessors = r"\b(?:X|W|SP)\[([^\],\]]+)(?:,[^\]]*)?\]"
    for match in re.finditer(bracket_accessors, execute_text):
        field = normalize_role_field(var_map.get(match.group(1).strip(), match.group(1).strip()), fields)
        if field not in fields and field != "x30":
            continue
        after = execute_text[match.end() : match.end() + 8]
        kind = "RegWrite" if re.match(r"\s*=", after) else "RegRead"
        roles.add(role_tuple(kind, field, operand_width(docvars)))

    if "ConditionHolds" in execute_text:
        roles.add(role_tuple("FlagsRead"))
    if "PSTATE.NZCV" in execute_text or ("AddWithCarry" in execute_text and "nzcv" in execute_text):
        roles.add(role_tuple("FlagsWrite"))
    if "BranchTo" in execute_text or "BranchNotTaken" in execute_text:
        roles.add(role_tuple("ControlFlow"))
    if "Mem" in execute_text:
        roles.add(role_tuple("Memory"))
    return roles


def infer_roles_from_docvars_and_asm(
    docvars: dict[str, str],
    operands: list[dict[str, str]],
    fields: set[str],
) -> set[tuple[str, str, str]]:
    roles: set[tuple[str, str, str]] = set()
    mnemonic = docvars.get("mnemonic", "")
    address_form = docvars.get("address-form", "")

    if "branch-offset" in docvars:
        for field in fields:
            if field.lower().startswith("imm"):
                roles.add(role_tuple("BranchTarget", field))

    if mnemonic in {"B", "BL"}:
        for field in fields:
            if field.lower().startswith("imm"):
                roles.add(role_tuple("BranchTarget", field))
        if mnemonic == "BL":
            roles.add(role_tuple("ImplicitRegWrite", "x30", "X64"))

    if mnemonic in {"BR", "BLR", "RET"} and "Rn" in fields:
        roles.add(role_tuple("RegRead", "Rn", "X64"))
        if mnemonic == "BLR":
            roles.add(role_tuple("ImplicitRegWrite", "x30", "X64"))

    if mnemonic in {"CBZ", "CBNZ", "TBZ", "TBNZ"} and "Rt" in fields:
        roles.add(role_tuple("RegRead", "Rt", operand_width(docvars)))
        for field in fields:
            if field.lower().startswith("imm"):
                roles.add(role_tuple("BranchTarget", field))

    if mnemonic in {"LDR", "STR"}:
        if "Rn" in fields:
            if address_form in {"pre-indexed", "post-indexed"}:
                roles.add(role_tuple("RegReadWrite", "Rn", "X64"))
            else:
                roles.add(role_tuple("RegRead", "Rn", "X64"))
            roles.add(role_tuple("MemBase", "Rn", "X64"))
        if "Rt" in fields:
            kind = "RegWrite" if mnemonic == "LDR" else "RegRead"
            roles.add(role_tuple(kind, "Rt", operand_width(docvars)))
        for field in fields:
            if field.lower().startswith("imm"):
                roles.add(role_tuple("MemOffset", field))

    for operand in operands:
        hover = operand["hover"].lower()
        text = operand["text"]
        encoded = re.search(r'encoded (?:as|in) (?:the )?"([^"]+)" field', hover)
        if not encoded:
            continue
        field = normalize_role_field(encoded.group(1), fields)
        width = operand_width(docvars, operand)
        if "base register" in hover:
            roles.add(role_tuple("MemBase", field, "X64"))
            roles.add(role_tuple("RegRead", field, "X64"))
        if "destination register" in hover or "written" in hover:
            roles.add(role_tuple("RegWrite", field, width))
        if "source register" in hover:
            roles.add(role_tuple("RegRead", field, width))
        if "first operand register" in hover or "second operand register" in hover:
            roles.add(role_tuple("RegRead", field, width))
        if "register to be tested" in hover:
            roles.add(role_tuple("RegRead", field, width))
        if "register to be transferred" in hover:
            kind = "RegWrite" if mnemonic == "LDR" else "RegRead"
            roles.add(role_tuple(kind, field, width))
        if "program label" in hover or "<label>" in text:
            roles.add(role_tuple("BranchTarget", field))

    return roles


def role_sort_key(role: tuple[str, str, str]) -> tuple[str, str, str]:
    return role


def simplify_roles(roles: set[tuple[str, str, str]]) -> set[tuple[str, str, str]]:
    simplified = set(roles)
    for kind, field, width in list(simplified):
        if kind == "RegWrite" and field == "x30":
            simplified.discard((kind, field, width))
            simplified.add(("ImplicitRegWrite", "x30", "X64"))

    for kind, field, width in list(roles):
        if width != "Unknown":
            simplified.discard((kind, field, "Unknown"))

    read_write_fields = {
        (field, width)
        for kind, field, width in simplified
        if kind == "RegReadWrite"
    }
    for field, width in read_write_fields:
        simplified.discard(("RegRead", field, width))
        simplified.discard(("RegWrite", field, width))
    return simplified


def infer_operand_roles(
    docvars: dict[str, str],
    fields: list[FieldSlice],
    operands: list[dict[str, str]],
    decode_text: str,
    execute_text: str,
) -> list[dict[str, str]]:
    field_names = {field.name for field in fields if field.variable}
    var_map = decode_var_map(decode_text)
    roles = set()
    roles |= infer_roles_from_docvars_and_asm(docvars, operands, field_names)
    roles |= infer_roles_from_pseudocode(field_names, var_map, docvars, execute_text)
    roles = simplify_roles(roles)
    return [
        {"kind": kind, "field": field, "width": width}
        for kind, field, width in sorted(roles, key=role_sort_key)
    ]


def parse_instruction(path: Path) -> dict:
    root = ET.parse(path).getroot()
    section_id = root.attrib["id"]
    heading = (root.findtext("heading") or "").strip()
    title = root.attrib.get("title", "")
    section_docvars = parse_docvars(root)

    variants: list[dict] = []
    for iclass in root.findall("./classes/iclass"):
        iclass_name = iclass.attrib.get("name", "")
        base_mask, base_value, fields = parse_regdiagram(iclass.find("regdiagram"))
        iclass_docvars = parse_docvars(iclass)
        decode_text, execute_text = parse_ps_texts(root, iclass)
        for encoding in iclass.findall("encoding"):
            enc_mask, enc_value, _ = parse_regdiagram(encoding)
            combined_mask = base_mask | enc_mask
            combined_value = base_value | enc_value
            variant_docvars = {**section_docvars, **iclass_docvars, **parse_docvars(encoding)}
            asm = flatten_text(encoding.find("asmtemplate")) if encoding.find("asmtemplate") is not None else ""
            asm_operands = parse_asm_operands(encoding)
            variants.append(
                {
                    "section_id": section_id,
                    "heading": heading,
                    "title": title,
                    "iclass": iclass_name,
                    "encoding_name": encoding.attrib["name"],
                    "encoding_label": encoding.attrib.get("label", ""),
                    "mnemonic": variant_docvars.get("mnemonic", heading.split()[0] if heading else section_id),
                    "docvars": variant_docvars,
                    "asm_operands": asm_operands,
                    "mask": f"0x{combined_mask:08x}",
                    "value": f"0x{combined_value:08x}",
                    "fields": [
                        {
                            "name": field.name,
                            "hi": field.hi,
                            "lo": field.lo,
                            "width": field.width,
                            "shift": field.lo,
                            "mask": f"0x{(((1 << field.width) - 1) << field.lo):08x}",
                            "variable": (
                                combined_mask
                                & (((1 << field.width) - 1) << field.lo)
                            )
                            != (((1 << field.width) - 1) << field.lo),
                        }
                        for field in fields
                    ],
                    "operand_roles": infer_operand_roles(
                        variant_docvars,
                        fields,
                        asm_operands,
                        decode_text,
                        execute_text,
                    ),
                    "asm": asm,
                }
            )

    return {
        "source_file": path.name,
        "section_id": section_id,
        "heading": heading,
        "title": title,
        "docvars": section_docvars,
        "variants": variants,
    }


def form_source_file(form_key: str) -> str:
    section_id, separator, _ = form_key.partition(".")
    if separator != "." or not section_id:
        raise ValueError(f"invalid form key `{form_key}`; expected `<section>.<encoding>`")
    return f"{section_id.lower()}.xml"


def load_decode_forms(path: Path) -> list[str]:
    config = tomllib.loads(path.read_text(encoding="utf-8"))
    forms = config.get("decode", {}).get("forms")
    if not isinstance(forms, list) or not all(isinstance(form, str) for form in forms):
        raise ValueError(f"{path} must define decode.forms as a string array")
    return forms


def filter_specs_by_forms(specs: list[dict], forms: list[str]) -> list[dict]:
    wanted = set(forms)
    found: set[str] = set()
    filtered: list[dict] = []

    for spec in specs:
        variants = []
        for variant in spec["variants"]:
            key = f'{variant["section_id"]}.{variant["encoding_name"]}'
            if key in wanted:
                variants.append(variant)
                found.add(key)

        if variants:
            spec = {**spec, "variants": variants}
            filtered.append(spec)

    missing = [form for form in forms if form not in found]
    if missing:
        missing_list = "\n".join(f"  - {form}" for form in missing)
        raise ValueError(f"configured generated forms were not found in XML:\n{missing_list}")

    return filtered


def rust_ident(text: str) -> str:
    chars: list[str] = []
    for ch in text:
        if ch.isalnum():
            chars.append(ch.upper())
        else:
            chars.append("_")
    ident = "".join(chars).strip("_")
    while "__" in ident:
        ident = ident.replace("__", "_")
    if ident and ident[0].isdigit():
        ident = f"V_{ident}"
    return ident or "UNNAMED"


def rust_variant_ident(text: str) -> str:
    ident = rust_ident(text)
    parts = [part for part in ident.split("_") if part]
    variant = "".join(part[0] + part[1:].lower() for part in parts)
    if variant and variant[0].isdigit():
        variant = f"V{variant}"
    return variant or "Unnamed"


def rust_field_ident(text: str) -> str:
    chars: list[str] = []
    prev_lower_or_digit = False
    for ch in text:
        if ch.isalnum():
            if ch.isupper() and prev_lower_or_digit:
                chars.append("_")
            chars.append(ch.lower())
            prev_lower_or_digit = ch.islower() or ch.isdigit()
        else:
            chars.append("_")
            prev_lower_or_digit = False

    ident = "".join(chars).strip("_")
    while "__" in ident:
        ident = ident.replace("__", "_")
    if not ident:
        ident = "field"
    if ident[0].isdigit():
        ident = f"field_{ident}"
    if ident in {"as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where", "while"}:
        ident = f"{ident}_field"
    return ident


def rust_field_type(width: int) -> str:
    if width <= 8:
        return "u8"
    if width <= 16:
        return "u16"
    return "u32"


def rust_operand_width(width: str) -> str:
    match width:
        case "W32":
            return "A64RegWidth::W32"
        case "X64":
            return "A64RegWidth::X64"
        case _:
            return "A64RegWidth::Unknown"


def branch_role_bits(field_name: str, fields: list[dict]) -> int:
    for field in fields:
        if field["name"] == field_name:
            return int(field["width"])
    return 0


def render_operand_role(role: dict[str, str], fields: list[dict]) -> str:
    kind = role["kind"]
    field = role["field"]
    width = rust_operand_width(role["width"])
    match kind:
        case "RegRead":
            return f'A64OperandRole::RegRead {{ field: "{field}", width: {width} }}'
        case "RegWrite":
            return f'A64OperandRole::RegWrite {{ field: "{field}", width: {width} }}'
        case "RegReadWrite":
            return f'A64OperandRole::RegReadWrite {{ field: "{field}", width: {width} }}'
        case "ImplicitRegWrite":
            reg = 30 if field == "x30" else int(field.removeprefix("x"))
            return f"A64OperandRole::ImplicitRegWrite {{ reg: {reg}, width: {width} }}"
        case "BranchTarget":
            bits = branch_role_bits(field, fields)
            return f'A64OperandRole::BranchTarget {{ field: "{field}", scale: 2, bits: {bits} }}'
        case "MemBase":
            return f'A64OperandRole::MemBase {{ field: "{field}" }}'
        case "MemOffset":
            return f'A64OperandRole::MemOffset {{ field: "{field}" }}'
        case "FlagsRead":
            return "A64OperandRole::FlagsRead"
        case "FlagsWrite":
            return "A64OperandRole::FlagsWrite"
        case "ControlFlow":
            return "A64OperandRole::ControlFlow"
        case "Memory":
            return "A64OperandRole::Memory"
        case _:
            raise ValueError(f"unsupported operand role: {role}")


def branch_target_roles(variant: dict) -> list[dict[str, str]]:
    return [
        role
        for role in variant.get("operand_roles", [])
        if role["kind"] == "BranchTarget"
    ]


def field_by_name(fields: list[dict], name: str) -> dict:
    for field in fields:
        if field["name"] == name:
            return field
    raise ValueError(f"missing generated field metadata for branch target field `{name}`")


def render_a64_insn(specs: list[dict]) -> list[str]:
    variants: list[dict] = []
    for spec in specs:
        for variant in spec["variants"]:
            key = f'{variant["section_id"]}.{variant["encoding_name"]}'
            fields = [
                {
                    **field,
                    "rust_name": rust_field_ident(field["name"]),
                    "rust_type": rust_field_type(field["width"]),
                }
                for field in variant["fields"]
                if field["variable"]
            ]
            variants.append(
                {
                    **variant,
                    "key": key,
                    "variant_name": rust_variant_ident(key),
                    "fields": fields,
                    "operand_array_name": f'OPERANDS_{rust_ident(key)}',
                }
            )

    lines = [
        "#[allow(dead_code)]",
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
        "pub enum A64Insn {",
    ]
    for variant in variants:
        lines.append(f"    {variant['variant_name']} {{")
        for field in variant["fields"]:
            lines.append(f"        {field['rust_name']}: {field['rust_type']},")
        lines.append("    },")
    lines.append("}")
    lines.append("")
    lines.extend(
        [
            "#[allow(dead_code)]",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub enum A64EncodeError {",
            "    FieldOutOfRange {",
            "        insn: &'static str,",
            "        field: &'static str,",
            "        value: u32,",
            "        width: u8,",
            "    },",
            "}",
            "",
            "#[allow(dead_code)]",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
            "pub enum A64RewriteError {",
            "    UnsupportedField {",
            "        insn: &'static str,",
            "        field: &'static str,",
            "    },",
            "    FieldOutOfRange {",
            "        insn: &'static str,",
            "        field: &'static str,",
            "        value: u32,",
            "        width: u8,",
            "    },",
            "}",
            "",
            "fn encode_a64_field(",
            "    insn: &'static str,",
            "    field: &'static str,",
            "    value: u32,",
            "    width: u8,",
            "    shift: u8,",
            ") -> Result<u32, A64EncodeError> {",
            "    if width < 32 && value >= (1_u32 << width) {",
            "        return Err(A64EncodeError::FieldOutOfRange {",
            "            insn,",
            "            field,",
            "            value,",
            "            width,",
            "        });",
            "    }",
            "    Ok(value << shift)",
            "}",
            "",
            "fn validate_a64_rewrite_field(",
            "    insn: &'static str,",
            "    field: &'static str,",
            "    value: u32,",
            "    width: u8,",
            ") -> Result<(), A64RewriteError> {",
            "    if width < 32 && value >= (1_u32 << width) {",
            "        return Err(A64RewriteError::FieldOutOfRange {",
            "            insn,",
            "            field,",
            "            value,",
            "            width,",
            "        });",
            "    }",
            "    Ok(())",
            "}",
            "",
            "#[allow(dead_code)]",
            "impl A64Insn {",
            "    pub const fn key(&self) -> &'static str {",
            "        match self {",
        ]
    )
    for variant in variants:
        lines.append(f"            Self::{variant['variant_name']} {{ .. }} => \"{variant['key']}\",")
    lines.extend(
        [
            "        }",
            "    }",
            "",
            "    pub const fn mnemonic(&self) -> &'static str {",
            "        match self {",
        ]
    )
    for variant in variants:
        lines.append(f"            Self::{variant['variant_name']} {{ .. }} => \"{variant['mnemonic']}\",")
    lines.extend(
        [
            "        }",
            "    }",
            "",
            "    pub const fn asm_template(&self) -> &'static str {",
            "        match self {",
        ]
    )
    for variant in variants:
        lines.append(
            f"            Self::{variant['variant_name']} {{ .. }} => {json.dumps(variant['asm'])},"
        )
    lines.extend(
        [
            "        }",
            "    }",
            "",
            "    pub fn decode(word: u32) -> Option<Self> {",
            "        decode_a64_insn(word)",
            "    }",
            "",
            "    pub fn encode(self) -> Result<u32, A64EncodeError> {",
            "        match self {",
        ]
    )
    for variant in variants:
        if variant["fields"]:
            field_list = ", ".join(field["rust_name"] for field in variant["fields"])
            lines.append(f"            Self::{variant['variant_name']} {{ {field_list} }} => {{")
        else:
            lines.append(f"            Self::{variant['variant_name']} {{ }} => {{")
        if variant["fields"]:
            lines.append(f"                let mut word = {variant['value']};")
        else:
            lines.append(f"                let word = {variant['value']};")
        for field in variant["fields"]:
            lines.append(
                "                word |= encode_a64_field("
                f"\"{variant['key']}\", "
                f"\"{field['name']}\", "
                f"{field['rust_name']} as u32, "
                f"{field['width']}, "
                f"{field['shift']}"
                ")?;"
            )
        lines.append("                Ok(word)")
        lines.append("            }")
    lines.extend(
        [
            "        }",
            "    }",
            "",
            "    pub fn branch_target_imm(&self, field: &'static str) -> Option<u32> {",
            "        match self {",
        ]
    )
    for variant in variants:
        for role in branch_target_roles(variant):
            target_field = field_by_name(variant["fields"], role["field"])
            if variant["fields"]:
                lines.append(
                    f"            Self::{variant['variant_name']} {{ {target_field['rust_name']}, .. }} "
                    f"if field == \"{target_field['name']}\" => Some(*{target_field['rust_name']} as u32),"
                )
            else:
                raise ValueError(f"branch target role without fields in {variant['key']}")
    lines.extend(
        [
            "            _ => None,",
            "        }",
            "    }",
            "",
            "    pub fn set_branch_target_imm(",
            "        self,",
            "        field: &'static str,",
            "        encoded: u32,",
            "    ) -> Result<Self, A64RewriteError> {",
            "        let insn_key = self.key();",
            "        match self {",
        ]
    )
    for variant in variants:
        for role in branch_target_roles(variant):
            target_field = field_by_name(variant["fields"], role["field"])
            pattern_fields = []
            result_fields = []
            for field in variant["fields"]:
                if field["name"] == target_field["name"]:
                    result_fields.append(f"{field['rust_name']}: encoded as {field['rust_type']}")
                else:
                    pattern_fields.append(field["rust_name"])
                    result_fields.append(field["rust_name"])

            pattern = ", ".join(pattern_fields)
            if pattern:
                pattern = f"{pattern}, .."
            else:
                pattern = ".."
            result = ", ".join(result_fields)
            lines.append(
                f"            Self::{variant['variant_name']} {{ {pattern} }} "
                f"if field == \"{target_field['name']}\" => {{"
            )
            lines.append(
                "                validate_a64_rewrite_field("
                f"\"{variant['key']}\", "
                f"\"{target_field['name']}\", "
                "encoded, "
                f"{target_field['width']}"
                ")?;"
            )
            lines.append(f"                Ok(Self::{variant['variant_name']} {{ {result} }})")
            lines.append("            }")
    lines.extend(
        [
            "            _ => Err(A64RewriteError::UnsupportedField {",
            "                insn: insn_key,",
            "                field,",
            "            }),",
            "        }",
            "    }",
            "",
            "    pub const fn operand_roles(&self) -> &'static [A64OperandRole] {",
            "        match self {",
        ]
    )
    for variant in variants:
        lines.append(
            f"            Self::{variant['variant_name']} {{ .. }} => {variant['operand_array_name']},"
        )
    lines.extend(
        [
            "        }",
            "    }",
            "}",
            "",
            "#[allow(dead_code)]",
            "pub fn decode_a64_insn(word: u32) -> Option<A64Insn> {",
        ]
    )
    for variant in variants:
        lines.append(f"    if (word & {variant['mask']}) == {variant['value']} {{")
        if variant["fields"]:
            lines.append(f"        return Some(A64Insn::{variant['variant_name']} {{")
            for field in variant["fields"]:
                lines.append(
                    f"            {field['rust_name']}: ((word & {field['mask']}) >> {field['shift']}) as {field['rust_type']},"
                )
            lines.append("        });")
        else:
            lines.append(f"        return Some(A64Insn::{variant['variant_name']} {{ }});")
        lines.append("    }")
    lines.extend(
        [
            "    None",
            "}",
            "",
        ]
    )
    return lines


def render_rust(specs: list[dict]) -> str:
    lines = [
        "// Generated by scripts/gen-arm64-spec.py from Arm ISA XML.",
        "#[allow(dead_code)]",
        "#[derive(Clone, Copy, Debug)]",
        "pub struct GeneratedFieldSpec {",
        "    pub name: &'static str,",
        "    pub hi: u8,",
        "    pub lo: u8,",
        "    pub width: u8,",
        "    pub mask: u32,",
        "}",
        "",
        "#[allow(dead_code)]",
        "impl GeneratedFieldSpec {",
        "    pub const fn shift(&self) -> u8 {",
        "        self.lo",
        "    }",
        "",
        "    pub const fn extract(&self, word: u32) -> u32 {",
        "        (word & self.mask) >> self.lo",
        "    }",
        "}",
        "",
        "#[allow(dead_code)]",
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
        "pub enum A64RegWidth {",
        "    W32,",
        "    X64,",
        "    Unknown,",
        "}",
        "",
        "#[allow(dead_code)]",
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
        "pub enum A64OperandRole {",
        "    RegRead { field: &'static str, width: A64RegWidth },",
        "    RegWrite { field: &'static str, width: A64RegWidth },",
        "    RegReadWrite { field: &'static str, width: A64RegWidth },",
        "    ImplicitRegWrite { reg: u8, width: A64RegWidth },",
        "    BranchTarget { field: &'static str, scale: u8, bits: u8 },",
        "    MemBase { field: &'static str },",
        "    MemOffset { field: &'static str },",
        "    FlagsRead,",
        "    FlagsWrite,",
        "    ControlFlow,",
        "    Memory,",
        "}",
        "",
        "#[allow(dead_code)]",
        "#[derive(Clone, Copy, Debug)]",
        "pub struct GeneratedInsnSpec {",
        "    pub key: &'static str,",
        "    pub mnemonic: &'static str,",
        "    pub heading: &'static str,",
        "    pub title: &'static str,",
        "    pub encoding_label: &'static str,",
        "    pub mask: u32,",
        "    pub value: u32,",
        "    pub fields: &'static [GeneratedFieldSpec],",
        "    pub operands: &'static [A64OperandRole],",
        "    pub asm: &'static str,",
        "}",
        "",
        "#[allow(dead_code)]",
        "impl GeneratedInsnSpec {",
        "    pub const fn matches(&self, word: u32) -> bool {",
        "        (word & self.mask) == self.value",
        "    }",
        "",
        "    pub fn field(&self, name: &str) -> Option<&'static GeneratedFieldSpec> {",
        "        let mut index = 0;",
        "        while index < self.fields.len() {",
        "            let field = &self.fields[index];",
        "            if field.name == name {",
        "                return Some(field);",
        "            }",
        "            index += 1;",
        "        }",
        "        None",
        "    }",
        "",
        "    pub fn extract_field(&self, word: u32, name: &str) -> Option<u32> {",
        "        self.field(name).map(|field| field.extract(word))",
        "    }",
        "}",
        "",
    ]
    lines.extend(render_a64_insn(specs))

    all_entries: list[str] = []
    for spec in specs:
        for variant in spec["variants"]:
            key = f'{variant["section_id"]}.{variant["encoding_name"]}'
            array_name = f'FIELDS_{rust_ident(key)}'
            operand_array_name = f'OPERANDS_{rust_ident(key)}'
            lines.append("#[allow(dead_code)]")
            lines.append(f"pub const {array_name}: &[GeneratedFieldSpec] = &[")
            for field in variant["fields"]:
                lines.append(
                    "    GeneratedFieldSpec { "
                    f'name: "{field["name"]}", hi: {field["hi"]}, lo: {field["lo"]}, '
                    f'width: {field["width"]}, mask: {field["mask"]} '
                    "},"
                )
            lines.append("];")
            lines.append("")
            lines.append("#[allow(dead_code)]")
            lines.append(f"pub const {operand_array_name}: &[A64OperandRole] = &[")
            for role in variant["operand_roles"]:
                lines.append(f"    {render_operand_role(role, variant['fields'])},")
            lines.append("];")
            lines.append("")
            all_entries.append(
                textwrap.dedent(
                    f"""\
                    GeneratedInsnSpec {{
                        key: "{key}",
                        mnemonic: "{variant["mnemonic"]}",
                        heading: "{variant["heading"]}",
                        title: "{variant["title"]}",
                        encoding_label: "{variant["encoding_label"]}",
                        mask: {variant["mask"]},
                        value: {variant["value"]},
                        fields: {array_name},
                        operands: {operand_array_name},
                        asm: {json.dumps(variant["asm"])},
                    }},"""
                ).rstrip()
            )

    lines.append("#[allow(dead_code)]")
    lines.append("pub const GENERATED_A64_SUBSET: &[GeneratedInsnSpec] = &[")
    for entry in all_entries:
        for line in entry.splitlines():
            lines.append(f"    {line}")
    lines.append("];")
    lines.append("")
    lines.append("#[allow(dead_code)]")
    lines.append("pub fn generated_a64_subset_match(word: u32) -> Option<&'static GeneratedInsnSpec> {")
    lines.append("    let mut index = 0;")
    lines.append("    while index < GENERATED_A64_SUBSET.len() {")
    lines.append("        let spec = &GENERATED_A64_SUBSET[index];")
    lines.append("        if spec.matches(word) {")
    lines.append("            return Some(spec);")
    lines.append("        }")
    lines.append("        index += 1;")
    lines.append("    }")
    lines.append("    None")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a narrow A64 spec subset from Arm ISA XML.")
    parser.add_argument(
        "--xml-dir",
        default="./tmp/isa_a64_2026_03/ISA_A64_xml_A_profile-2026-03",
        help="Directory containing the Arm ISA XML bundle.",
    )
    parser.add_argument(
        "--instructions",
        nargs="*",
        default=None,
        help="Instruction XML filenames to parse. Overrides --subset-config and emits all variants in those files.",
    )
    parser.add_argument(
        "--subset-config",
        default=DEFAULT_SUBSET_CONFIG,
        help="TOML subset config containing decode.forms.",
    )
    parser.add_argument(
        "--json-out",
        default="./spec/arm64/generated/a64_subset.json",
        help="Output JSON summary path.",
    )
    parser.add_argument(
        "--rust-out",
        default="./spec/arm64/generated/a64_subset.rs",
        help="Output Rust table path.",
    )
    args = parser.parse_args()

    xml_dir = Path(args.xml_dir)
    if args.instructions is None:
        decode_forms = load_decode_forms(Path(args.subset_config))
        instructions = list(dict.fromkeys(form_source_file(form) for form in decode_forms))
        specs = [parse_instruction(xml_dir / filename) for filename in instructions]
        specs = filter_specs_by_forms(specs, decode_forms)
    else:
        specs = [parse_instruction(xml_dir / filename) for filename in args.instructions]

    json_out = Path(args.json_out)
    json_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(specs, indent=2) + "\n", encoding="utf-8")

    rust_out = Path(args.rust_out)
    rust_out.parent.mkdir(parents=True, exist_ok=True)
    rust_out.write_text(render_rust(specs) + "\n", encoding="utf-8")

    variant_count = sum(len(spec["variants"]) for spec in specs)
    print(f"parsed {len(specs)} instruction files -> {variant_count} encoding variants")
    print(f"json: {json_out}")
    print(f"rust: {rust_out}")


if __name__ == "__main__":
    main()
