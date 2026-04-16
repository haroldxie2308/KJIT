#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import textwrap
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path


DEFAULT_SUBSET = [
    "adr.xml",
    "adrp.xml",
    "add_addsub_imm.xml",
    "sub_addsub_imm.xml",
    "subs_addsub_imm.xml",
    "b_uncond.xml",
    "b_cond.xml",
    "cbz.xml",
    "cbnz.xml",
    "movz.xml",
    "movk.xml",
    "tbz.xml",
    "tbnz.xml",
    "ldr_imm_gen.xml",
    "str_imm_gen.xml",
]


@dataclass
class FieldSlice:
    name: str
    hi: int
    width: int

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
        fields.append(FieldSlice(name=name, hi=hibit, width=width))

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
        for encoding in iclass.findall("encoding"):
            enc_mask, enc_value, _ = parse_regdiagram(encoding)
            variant_docvars = {**section_docvars, **iclass_docvars, **parse_docvars(encoding)}
            asm = flatten_text(encoding.find("asmtemplate")) if encoding.find("asmtemplate") is not None else ""
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
                    "mask": f"0x{(base_mask | enc_mask):08x}",
                    "value": f"0x{(base_value | enc_value):08x}",
                    "fields": [
                        {
                            "name": field.name,
                            "hi": field.hi,
                            "lo": field.lo,
                            "width": field.width,
                            "shift": field.lo,
                            "mask": f"0x{(((1 << field.width) - 1) << field.lo):08x}",
                        }
                        for field in fields
                    ],
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

    all_entries: list[str] = []
    for spec in specs:
        for variant in spec["variants"]:
            key = f'{variant["section_id"]}.{variant["encoding_name"]}'
            array_name = f'FIELDS_{rust_ident(key)}'
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
                        asm: {json.dumps(variant["asm"])},
                    }},"""
                ).rstrip()
            )

    lines.append("pub const GENERATED_A64_SUBSET: &[GeneratedInsnSpec] = &[")
    for entry in all_entries:
        for line in entry.splitlines():
            lines.append(f"    {line}")
    lines.append("];")
    lines.append("")
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
        default=DEFAULT_SUBSET,
        help="Instruction XML filenames to parse.",
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
