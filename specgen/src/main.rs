mod metadata;
mod model;
mod render;
mod subset;
mod xml;

use anyhow::{Context, Result};
use clap::Parser;
use std::fs;
use std::path::PathBuf;

const DEFAULT_XML_DIR: &str = "./tmp/isa_a64_2026_03/ISA_A64_xml_A_profile-2026-03";
const DEFAULT_SUBSET_CONFIG: &str = "./spec/arm64/subset.toml";
const DEFAULT_JSON_OUT: &str = "./spec/arm64/generated/a64_subset.json";
const DEFAULT_RUST_OUT: &str = "./spec/arm64/generated/a64_subset.rs";

#[derive(Debug, Parser)]
#[command(about = "Generate a narrow A64 spec subset from Arm ISA XML.")]
struct Args {
    #[arg(long, default_value = DEFAULT_XML_DIR)]
    xml_dir: PathBuf,

    #[arg(long, num_args = 1..)]
    instructions: Option<Vec<String>>,

    #[arg(long, default_value = DEFAULT_SUBSET_CONFIG)]
    subset_config: PathBuf,

    #[arg(long, default_value = DEFAULT_JSON_OUT)]
    json_out: PathBuf,

    #[arg(long, default_value = DEFAULT_RUST_OUT)]
    rust_out: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let specs = if let Some(instructions) = &args.instructions {
        parse_instructions(&args.xml_dir, instructions)?
    } else {
        let decode_forms = subset::load_decode_forms(&args.subset_config)?;
        let instructions = subset::unique_instruction_files(&decode_forms)?;
        let specs = parse_instructions(&args.xml_dir, &instructions)?;
        subset::filter_specs_by_forms(specs, &decode_forms)?
    };

    write_output(&args.json_out, serde_json::to_string_pretty(&specs)? + "\n")?;
    write_output(&args.rust_out, render::render_rust(&specs)? + "\n")?;

    let variant_count = specs.iter().map(|spec| spec.variants.len()).sum::<usize>();
    println!(
        "parsed {} instruction files -> {} encoding variants",
        specs.len(),
        variant_count
    );
    println!("json: {}", args.json_out.display());
    println!("rust: {}", args.rust_out.display());
    Ok(())
}

fn parse_instructions(
    xml_dir: &std::path::Path,
    instructions: &[String],
) -> Result<Vec<model::InstructionSpec>> {
    instructions
        .iter()
        .map(|filename| xml::parse_instruction(&xml_dir.join(filename)))
        .collect()
}

fn write_output(path: &std::path::Path, content: String) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("output path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))
}
