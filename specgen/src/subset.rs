use crate::model::{InstructionSpec, VariantSpec};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct SubsetConfig {
    decode: DecodeConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecodeConfig {
    pub forms: Vec<String>,
    /// Per-form fixed field values: `form key -> field name -> value`. A constrained
    /// field stops being an operand; its bits join the form's mask/value, so only
    /// words with exactly these values decode. An absent table means no form is
    /// constrained.
    #[serde(default)]
    pub field_constraints: BTreeMap<String, BTreeMap<String, u32>>,
    /// Per-form exact instances: `form key -> instance name -> field name ->
    /// value`. The form is replaced by one generated variant per instance, each
    /// pinned like a field constraint (key `<form>@<instance>`), so only words
    /// matching one instance decode, and every consumer's exhaustive match
    /// decides each instance on its own.
    #[serde(default)]
    pub field_instances: BTreeMap<String, BTreeMap<String, BTreeMap<String, u32>>>,
}

pub fn load_decode_config(path: &Path) -> Result<DecodeConfig> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read subset config {}", path.display()))?;
    let config = toml::from_str::<SubsetConfig>(&text)
        .with_context(|| format!("failed to parse subset config {}", path.display()))?;
    Ok(config.decode)
}

/// Pins the configured fields of each constrained form to fixed values. Fails if a
/// constraint names an unconfigured form, a missing or already fixed field, a field
/// that carries an operand role, or a value wider than the field.
pub fn apply_field_constraints(specs: &mut [InstructionSpec], config: &DecodeConfig) -> Result<()> {
    let forms = config.forms.iter().collect::<BTreeSet<_>>();
    let mut applied = BTreeSet::new();

    for variant in specs.iter_mut().flat_map(|spec| spec.variants.iter_mut()) {
        let key = variant.form_key();
        let Some(constraints) = config.field_constraints.get(&key) else {
            continue;
        };
        if !forms.contains(&key) {
            bail!("field constraint for `{key}`, which is not in decode.forms");
        }
        pin_fields(variant, &key, constraints)?;
        applied.insert(key);
    }

    let missing = config
        .field_constraints
        .keys()
        .filter(|key| !applied.contains(*key))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        bail!("field constraints for forms not found in XML: {missing:?}");
    }
    Ok(())
}

/// Replaces each form of `decode.field_instances` by its instances, in instance
/// name order. Each instance is pinned with the field-constraint rules. Fails
/// additionally if the form also has a field constraint, has no instance, an
/// instance name is not `[A-Z0-9_]+`, or two instances decode the same words.
pub fn apply_field_instances(specs: &mut [InstructionSpec], config: &DecodeConfig) -> Result<()> {
    let forms = config.forms.iter().collect::<BTreeSet<_>>();
    let mut applied = BTreeSet::new();

    for spec in specs.iter_mut() {
        let mut variants = Vec::with_capacity(spec.variants.len());
        for variant in spec.variants.drain(..) {
            let key = variant.form_key();
            let Some(instances) = config.field_instances.get(&key) else {
                variants.push(variant);
                continue;
            };
            if !forms.contains(&key) {
                bail!("field instances for `{key}`, which is not in decode.forms");
            }
            if config.field_constraints.contains_key(&key) {
                bail!("`{key}` has both field constraints and field instances");
            }
            if instances.is_empty() {
                bail!("field instances for `{key}`: no instance");
            }
            let mut patterns = BTreeSet::new();
            for (name, constraints) in instances {
                if name.is_empty()
                    || !name
                        .chars()
                        .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
                {
                    bail!("field instance `{key}@{name}`: name must be [A-Z0-9_]+");
                }
                let mut instance = variant.clone();
                instance.instance = Some(name.clone());
                let instance_key = instance.key();
                pin_fields(&mut instance, &instance_key, constraints)?;
                if !patterns.insert((instance.mask.clone(), instance.value.clone())) {
                    bail!("field instance `{key}@{name}` decodes the same words as another instance");
                }
                variants.push(instance);
            }
            applied.insert(key);
        }
        spec.variants = variants;
    }

    let missing = config
        .field_instances
        .keys()
        .filter(|key| !applied.contains(*key))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        bail!("field instances for forms not found in XML: {missing:?}");
    }
    Ok(())
}

/// Fixes each constrained field of `variant` (`key` names it in errors): its
/// bits join mask/value and it stops being variable.
fn pin_fields(variant: &mut VariantSpec, key: &str, constraints: &BTreeMap<String, u32>) -> Result<()> {
    let mut mask = parse_hex_word(&variant.mask).with_context(|| format!("bad mask for `{key}`"))?;
    let mut value =
        parse_hex_word(&variant.value).with_context(|| format!("bad value for `{key}`"))?;
    for (field_name, fixed) in constraints {
        let Some(field) = variant.fields.iter_mut().find(|f| &f.name == field_name) else {
            bail!("field constraint `{key}.{field_name}`: no such field");
        };
        if !field.variable {
            bail!("field constraint `{key}.{field_name}`: field is already fixed");
        }
        if variant
            .operand_roles
            .iter()
            .any(|role| &role.field == field_name)
        {
            bail!("field constraint `{key}.{field_name}`: field carries an operand role");
        }
        if field.width < 32 && *fixed >= (1_u32 << field.width) {
            bail!(
                "field constraint `{key}.{field_name}` = {fixed} does not fit {} bits",
                field.width
            );
        }
        let field_mask = parse_hex_word(&field.mask)
            .with_context(|| format!("bad field mask for `{key}.{field_name}`"))?;
        mask |= field_mask;
        value = (value & !field_mask) | (fixed << field.lo);
        field.variable = false;
    }
    variant.mask = format!("0x{mask:08x}");
    variant.value = format!("0x{value:08x}");
    Ok(())
}

fn parse_hex_word(text: &str) -> Result<u32> {
    let digits = text
        .strip_prefix("0x")
        .with_context(|| format!("expected 0x-prefixed hex word, got `{text}`"))?;
    u32::from_str_radix(digits, 16).with_context(|| format!("invalid hex word `{text}`"))
}

pub fn form_source_file(form_key: &str) -> Result<String> {
    let Some((section_id, _)) = form_key.split_once('.') else {
        bail!("invalid form key `{form_key}`; expected `<section>.<encoding>`");
    };
    if section_id.is_empty() {
        bail!("invalid form key `{form_key}`; expected `<section>.<encoding>`");
    }
    Ok(format!("{}.xml", section_id.to_lowercase()))
}

pub fn filter_specs_by_forms(
    specs: Vec<InstructionSpec>,
    forms: &[String],
) -> Result<Vec<InstructionSpec>> {
    let wanted = forms.iter().cloned().collect::<BTreeSet<_>>();
    let mut found = BTreeSet::new();
    let mut filtered = Vec::new();

    for mut spec in specs {
        spec.variants.retain(|variant| {
            let key = variant.form_key();
            if wanted.contains(&key) {
                found.insert(key);
                true
            } else {
                false
            }
        });

        if !spec.variants.is_empty() {
            filtered.push(spec);
        }
    }

    let missing = forms
        .iter()
        .filter(|form| !found.contains(*form))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        let missing_list = missing
            .iter()
            .map(|form| format!("  - {form}"))
            .collect::<Vec<_>>()
            .join("\n");
        bail!("configured generated forms were not found in XML:\n{missing_list}");
    }

    Ok(filtered)
}

pub fn unique_instruction_files(forms: &[String]) -> Result<Vec<String>> {
    let mut seen = BTreeSet::new();
    let mut files = Vec::new();
    for form in forms {
        let file = form_source_file(form)?;
        if seen.insert(file.clone()) {
            files.push(file);
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FieldSpec, OperandRoleSpec, VariantSpec};
    use indexmap::IndexMap;

    fn field(name: &str, hi: u8, width: u8) -> FieldSpec {
        let lo = hi + 1 - width;
        FieldSpec {
            name: name.to_string(),
            hi,
            lo,
            width,
            shift: lo,
            mask: format!("0x{:08x}", ((1_u32 << width) - 1) << lo),
            variable: true,
        }
    }

    fn mrs_like_spec() -> InstructionSpec {
        let variant = VariantSpec {
            section_id: "MRS".to_string(),
            heading: String::new(),
            title: String::new(),
            iclass: String::new(),
            encoding_name: "MRS_RS_systemmove".to_string(),
            encoding_label: String::new(),
            mnemonic: "MRS".to_string(),
            docvars: IndexMap::new(),
            asm_operands: Vec::new(),
            mask: "0xfff00000".to_string(),
            value: "0xd5300000".to_string(),
            excludes: Vec::new(),
            fields: vec![field("op1", 18, 3), field("op2", 7, 3), field("Rt", 4, 5)],
            operand_roles: vec![OperandRoleSpec {
                kind: "RegWrite".to_string(),
                field: "Rt".to_string(),
                width: "X64".to_string(),
            }],
            asm: String::new(),
            instance: None,
        };
        InstructionSpec {
            source_file: "mrs.xml".to_string(),
            section_id: "MRS".to_string(),
            heading: String::new(),
            title: String::new(),
            docvars: IndexMap::new(),
            variants: vec![variant],
        }
    }

    fn config(field: &str, value: u32) -> DecodeConfig {
        let key = "MRS.MRS_RS_systemmove".to_string();
        DecodeConfig {
            forms: vec![key.clone()],
            field_constraints: BTreeMap::from([(
                key,
                BTreeMap::from([(field.to_string(), value)]),
            )]),
            field_instances: BTreeMap::new(),
        }
    }

    fn instances(list: &[(&str, &[(&str, u32)])]) -> DecodeConfig {
        let key = "MRS.MRS_RS_systemmove".to_string();
        DecodeConfig {
            forms: vec![key.clone()],
            field_constraints: BTreeMap::new(),
            field_instances: BTreeMap::from([(
                key,
                list.iter()
                    .map(|(name, fields)| {
                        (
                            name.to_string(),
                            fields
                                .iter()
                                .map(|(field, value)| (field.to_string(), *value))
                                .collect(),
                        )
                    })
                    .collect(),
            )]),
        }
    }

    #[test]
    fn field_instances_replace_the_form_by_pinned_variants() {
        let mut specs = vec![mrs_like_spec()];
        let config = instances(&[("B", &[("op2", 2)]), ("A", &[("op1", 3), ("op2", 0)])]);
        apply_field_instances(&mut specs, &config).unwrap();

        let variants = &specs[0].variants;
        let keys = variants.iter().map(VariantSpec::key).collect::<Vec<_>>();
        assert_eq!(
            keys,
            ["MRS.MRS_RS_systemmove@A", "MRS.MRS_RS_systemmove@B"]
        );
        assert_eq!(variants[0].mask, "0xfff700e0");
        assert_eq!(variants[0].value, "0xd5330000");
        assert_eq!(variants[1].mask, "0xfff000e0");
        assert_eq!(variants[1].value, "0xd5300040");
        assert!(variants.iter().all(|v| v.form_key() == "MRS.MRS_RS_systemmove"));
    }

    #[test]
    fn field_instances_reject_bad_configs() {
        let bad: [&[(&str, &[(&str, u32)])]; 5] = [
            &[],
            &[("lower", &[("op2", 2)])],
            &[("A", &[("op2", 2)]), ("B", &[("op2", 2)])],
            &[("A", &[("Rt", 0)])],
            &[("A", &[("CRn", 0)])],
        ];
        for list in bad {
            let mut specs = vec![mrs_like_spec()];
            assert!(
                apply_field_instances(&mut specs, &instances(list)).is_err(),
                "{list:?} must be rejected"
            );
        }

        let mut both = instances(&[("A", &[("op2", 2)])]);
        both.field_constraints = config("op1", 3).field_constraints;
        assert!(apply_field_instances(&mut vec![mrs_like_spec()], &both).is_err());

        let mut unknown_form = instances(&[("A", &[("op2", 2)])]);
        unknown_form.forms.clear();
        assert!(apply_field_instances(&mut vec![mrs_like_spec()], &unknown_form).is_err());
    }

    #[test]
    fn field_constraint_fixes_bits_and_removes_operand() {
        let mut specs = vec![mrs_like_spec()];
        apply_field_constraints(&mut specs, &config("op2", 2)).unwrap();

        let variant = &specs[0].variants[0];
        assert_eq!(variant.mask, "0xfff000e0");
        assert_eq!(variant.value, "0xd5300040");
        assert!(
            !variant
                .fields
                .iter()
                .find(|f| f.name == "op2")
                .unwrap()
                .variable
        );
        assert!(
            variant
                .fields
                .iter()
                .find(|f| f.name == "op1")
                .unwrap()
                .variable
        );
    }

    #[test]
    fn field_constraint_rejects_bad_targets() {
        for (field, value) in [("op2", 8), ("Rt", 0), ("CRn", 0)] {
            let mut specs = vec![mrs_like_spec()];
            assert!(
                apply_field_constraints(&mut specs, &config(field, value)).is_err(),
                "{field} = {value} must be rejected"
            );
        }

        let mut unknown_form = config("op2", 2);
        unknown_form.forms.clear();
        assert!(apply_field_constraints(&mut vec![mrs_like_spec()], &unknown_form).is_err());
    }

    #[test]
    fn form_source_file_uses_section_prefix() {
        assert_eq!(
            form_source_file("CBNZ.CBNZ_64_compbranch").unwrap(),
            "cbnz.xml"
        );
    }

    #[test]
    fn form_source_file_rejects_malformed_keys() {
        assert!(form_source_file("CBNZ").is_err());
        assert!(form_source_file(".CBNZ_64_compbranch").is_err());
    }
}
