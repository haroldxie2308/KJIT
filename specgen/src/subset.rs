use crate::model::InstructionSpec;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct SubsetConfig {
    decode: DecodeConfig,
}

#[derive(Debug, Deserialize)]
struct DecodeConfig {
    forms: Vec<String>,
}

pub fn load_decode_forms(path: &Path) -> Result<Vec<String>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read subset config {}", path.display()))?;
    let config = toml::from_str::<SubsetConfig>(&text)
        .with_context(|| format!("failed to parse subset config {}", path.display()))?;
    Ok(config.decode.forms)
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
            let key = format!("{}.{}", variant.section_id, variant.encoding_name);
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
