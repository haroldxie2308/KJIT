use crate::metadata::infer_operand_roles;
use crate::model::{AsmOperand, ExcludeSpec, FieldSlice, FieldSpec, InstructionSpec, VariantSpec};
use anyhow::{bail, Context, Result};
use indexmap::IndexMap;
use roxmltree::{Document, Node};
use std::fs;
use std::path::Path;

pub fn parse_instruction(path: &Path) -> Result<InstructionSpec> {
    let xml = fs::read_to_string(path)
        .with_context(|| format!("failed to read XML instruction file {}", path.display()))?;
    let xml = strip_doctype(&xml);
    let doc = Document::parse(&xml)
        .with_context(|| format!("failed to parse XML instruction file {}", path.display()))?;
    let root = doc.root_element();

    let section_id = attr(root, "id")?.to_string();
    let heading = child_text(root, "heading").unwrap_or_default();
    let title = root.attribute("title").unwrap_or("").to_string();
    let section_docvars = parse_docvars(root);

    let mut variants = Vec::new();
    for classes in children(root, "classes") {
        for iclass in children(classes, "iclass") {
            let iclass_name = iclass.attribute("name").unwrap_or("").to_string();
            let (base_mask, base_value, fields, base_excludes) =
                parse_regdiagram(child(iclass, "regdiagram"))?;
            let iclass_docvars = parse_docvars(iclass);
            let (decode_text, postdecode_text, execute_text) = parse_ps_texts(root, iclass);

            for encoding in children(iclass, "encoding") {
                let (enc_mask, enc_value, _, enc_excludes) = parse_regdiagram(Some(encoding))?;
                let combined_mask = base_mask | enc_mask;
                let combined_value = base_value | enc_value;
                let excludes = base_excludes
                    .iter()
                    .chain(&enc_excludes)
                    .map(|&(mask, value)| ExcludeSpec {
                        mask: format!("0x{mask:08x}"),
                        value: format!("0x{value:08x}"),
                    })
                    .collect();
                let mut variant_docvars = section_docvars.clone();
                variant_docvars.extend(iclass_docvars.clone());
                variant_docvars.extend(parse_docvars(encoding));

                let asm = child(encoding, "asmtemplate")
                    .map(flatten_text)
                    .unwrap_or_default();
                let asm_operands = parse_asm_operands(encoding);

                variants.push(VariantSpec {
                    section_id: section_id.clone(),
                    heading: heading.clone(),
                    title: title.clone(),
                    iclass: iclass_name.clone(),
                    encoding_name: attr(encoding, "name")?.to_string(),
                    encoding_label: encoding.attribute("label").unwrap_or("").to_string(),
                    mnemonic: variant_docvars
                        .get("mnemonic")
                        .cloned()
                        .unwrap_or_else(|| fallback_mnemonic(&heading, &section_id)),
                    docvars: variant_docvars.clone(),
                    asm_operands,
                    mask: format!("0x{combined_mask:08x}"),
                    value: format!("0x{combined_value:08x}"),
                    excludes,
                    fields: render_fields(&fields, combined_mask),
                    operand_roles: infer_operand_roles(
                        &variant_docvars,
                        &fields,
                        &parse_asm_operands(encoding),
                        &decode_text,
                        &postdecode_text,
                        &execute_text,
                    ),
                    asm,
                });
            }
        }
    }

    Ok(InstructionSpec {
        source_file: path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string(),
        section_id,
        heading,
        title,
        docvars: section_docvars,
        variants,
    })
}

fn attr<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Result<&'a str> {
    node.attribute(name)
        .with_context(|| format!("missing required XML attribute `{name}`"))
}

fn child<'a, 'input>(node: Node<'a, 'input>, tag: &str) -> Option<Node<'a, 'input>> {
    node.children().find(|child| child.has_tag_name(tag))
}

fn children<'a, 'input>(
    node: Node<'a, 'input>,
    tag: &'static str,
) -> impl Iterator<Item = Node<'a, 'input>> {
    node.children().filter(move |child| child.has_tag_name(tag))
}

fn child_text(node: Node<'_, '_>, tag: &str) -> Option<String> {
    child(node, tag).map(flatten_text)
}

fn flatten_text(node: Node<'_, '_>) -> String {
    node.descendants()
        .filter(|node| node.is_text())
        .filter_map(|node| node.text())
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn bit_positions(hibit: u8, width: u8) -> Vec<u8> {
    (0..width).map(|offset| hibit - offset).collect()
}

/// A `(mask, value)` bit pattern a word must NOT match: the diagram's `!= pattern`
/// constraints.
type Exclude = (u32, u32);

fn parse_regdiagram(
    regdiagram: Option<Node<'_, '_>>,
) -> Result<(u32, u32, Vec<FieldSlice>, Vec<Exclude>)> {
    let Some(regdiagram) = regdiagram else {
        return Ok((0, 0, Vec::new(), Vec::new()));
    };

    let mut mask = 0;
    let mut value = 0;
    let mut fields = Vec::new();
    let mut excludes = Vec::new();
    for box_node in children(regdiagram, "box") {
        let (box_mask, box_value, box_fields, box_exclude) = parse_box(box_node)?;
        mask |= box_mask;
        value |= box_value;
        fields.extend(box_fields);
        excludes.extend(box_exclude);
    }
    Ok((mask, value, fields, excludes))
}

/// One box of a register diagram: its fixed bits, its field, and its `!=`
/// constraint if it has one. The XML writes that constraint two ways: a cell whose
/// text is `!= <pattern>` (`x` = don't care), or per-bit `Z`/`N` cells (the
/// excluded pattern has a 0/1 there), as in `LDRB_32B_ldst_regoff`'s
/// `option != 011`.
fn parse_box(box_node: Node<'_, '_>) -> Result<(u32, u32, Vec<FieldSlice>, Option<Exclude>)> {
    let hibit = attr(box_node, "hibit")?.parse::<u8>()?;
    let width = box_node.attribute("width").unwrap_or("1").parse::<u8>()?;
    let name = box_node.attribute("name").map(str::to_string);
    let positions = bit_positions(hibit, width);

    let mut mask = 0_u32;
    let mut value = 0_u32;
    let mut exclude: Option<Exclude> = None;
    let mut used = 0_usize;

    for cell in children(box_node, "c") {
        let span = cell.attribute("colspan").unwrap_or("1").parse::<usize>()?;
        let text = cell.text().unwrap_or("").trim();
        let cell_positions = &positions[used..used + span];
        used += span;

        if text.len() == span && text.chars().all(|ch| matches!(ch, '0' | '1')) {
            for (bit, ch) in cell_positions.iter().zip(text.chars()) {
                mask |= 1_u32 << bit;
                if ch == '1' {
                    value |= 1_u32 << bit;
                }
            }
        } else if text.len() == 1 && matches!(text, "0" | "1") && span == 1 {
            let bit = cell_positions[0];
            mask |= 1_u32 << bit;
            if text == "1" {
                value |= 1_u32 << bit;
            }
        } else if let Some(pattern) = text.strip_prefix("!=") {
            let pattern = pattern.trim();
            if pattern.len() != span || !pattern.chars().all(|ch| matches!(ch, '0' | '1' | 'x')) {
                bail!("unsupported `!=` constraint cell `{text}` spanning {span} bits");
            }
            let (ex_mask, ex_value) = exclude.get_or_insert((0, 0));
            for (bit, ch) in cell_positions.iter().zip(pattern.chars()) {
                if ch != 'x' {
                    *ex_mask |= 1_u32 << bit;
                    if ch == '1' {
                        *ex_value |= 1_u32 << bit;
                    }
                }
            }
        } else if span == 1 && matches!(text, "Z" | "N") {
            let bit = cell_positions[0];
            let (ex_mask, ex_value) = exclude.get_or_insert((0, 0));
            *ex_mask |= 1_u32 << bit;
            if text == "N" {
                *ex_value |= 1_u32 << bit;
            }
        }
    }

    let fields = name
        .map(|name| {
            let field_mask = bit_mask(width) << (hibit + 1 - width);
            FieldSlice {
                name,
                hi: hibit,
                width,
                variable: (mask & field_mask) != field_mask,
            }
        })
        .into_iter()
        .collect();

    Ok((mask, value, fields, exclude))
}

fn parse_docvars(node: Node<'_, '_>) -> IndexMap<String, String> {
    let mut ret = IndexMap::new();
    let Some(docvars) = child(node, "docvars") else {
        return ret;
    };

    for docvar in children(docvars, "docvar") {
        if let (Some(key), Some(value)) = (docvar.attribute("key"), docvar.attribute("value")) {
            ret.insert(key.to_string(), value.to_string());
        }
    }
    ret
}

fn parse_asm_operands(encoding: Node<'_, '_>) -> Vec<AsmOperand> {
    let Some(asm) = child(encoding, "asmtemplate") else {
        return Vec::new();
    };

    children(asm, "a")
        .map(|anchor| AsmOperand {
            text: flatten_text(anchor),
            link: anchor.attribute("link").unwrap_or("").to_string(),
            hover: anchor.attribute("hover").unwrap_or("").to_string(),
        })
        .collect()
}

/// `(decode, postdecode, execute)` pseudocode. `decode` is the iclass's own;
/// `postdecode` and `execute` are shared by the whole instruction section.
fn parse_ps_texts(root: Node<'_, '_>, iclass: Node<'_, '_>) -> (String, String, String) {
    let decode = iclass
        .descendants()
        .filter(|node| node.has_tag_name("pstext"))
        .filter(|node| node.attribute("rep_section") == Some("decode"))
        .map(flatten_text)
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join(" ");

    let postdecode = children(root, "ps_section")
        .flat_map(|section| section.descendants())
        .filter(|node| node.has_tag_name("pstext"))
        .filter(|node| node.attribute("rep_section") == Some("postdecode"))
        .map(flatten_text)
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join(" ");

    let execute = children(root, "ps_section")
        .flat_map(|section| section.descendants())
        .filter(|node| node.has_tag_name("pstext"))
        .filter(|node| node.attribute("rep_section") == Some("execute"))
        .map(flatten_text)
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join(" ");

    (decode, postdecode, execute)
}

fn render_fields(fields: &[FieldSlice], combined_mask: u32) -> Vec<FieldSpec> {
    fields
        .iter()
        .map(|field| {
            let lo = field.lo();
            let mask = bit_mask(field.width) << lo;
            FieldSpec {
                name: field.name.clone(),
                hi: field.hi,
                lo,
                width: field.width,
                shift: lo,
                mask: format!("0x{mask:08x}"),
                variable: (combined_mask & mask) != mask,
            }
        })
        .collect()
}

fn bit_mask(width: u8) -> u32 {
    if width == 32 {
        u32::MAX
    } else {
        (1_u32 << width) - 1
    }
}

fn fallback_mnemonic(heading: &str, section_id: &str) -> String {
    heading
        .split_whitespace()
        .next()
        .unwrap_or(section_id)
        .to_string()
}

fn strip_doctype(xml: &str) -> String {
    let Some(start) = xml.find("<!DOCTYPE") else {
        return xml.to_string();
    };
    let Some(end) = xml[start..].find('>') else {
        return xml.to_string();
    };

    let mut ret = String::with_capacity(xml.len());
    ret.push_str(&xml[..start]);
    ret.push_str(&xml[start + end + 1..]);
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_one_box(xml: &str) -> (u32, u32, Option<Exclude>) {
        let doc = Document::parse(xml).unwrap();
        let (mask, value, _, exclude) = parse_box(doc.root_element()).unwrap();
        (mask, value, exclude)
    }

    #[test]
    fn not_equal_constraints_become_exclusions() {
        // `LDRB_32B_ldst_regoff`: option (bits 15:13) != 011, as Z/N cells.
        let zn = r#"<box hibit="15" width="3" name="option"><c>Z</c><c>N</c><c>N</c></box>"#;
        assert_eq!(parse_one_box(zn), (0, 0, Some((0xe000, 0x6000))));
        // Text form with a don't-care bit: opc (bits 24:22) != 11x.
        let text = r#"<box hibit="24" width="3" name="opc"><c colspan="3">!= 11x</c></box>"#;
        assert_eq!(
            parse_one_box(text),
            (0, 0, Some((0x0180_0000, 0x0180_0000)))
        );
        // Fixed bits and free fields carry no exclusion.
        let fixed = r#"<box hibit="11" width="2"><c>1</c><c>0</c></box>"#;
        assert_eq!(parse_one_box(fixed), (0xc00, 0x800, None));
        let free = r#"<box hibit="4" width="5" name="Rt"><c colspan="5"/></box>"#;
        assert_eq!(parse_one_box(free), (0, 0, None));
    }
}
