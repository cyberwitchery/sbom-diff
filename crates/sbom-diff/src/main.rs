use anyhow::{anyhow, Context};
use clap::{Parser, ValueEnum};
use sbom_diff::{
    renderer::{JsonRenderer, MarkdownRenderer, Renderer, TextRenderer},
    Differ,
};
use sbom_model::Sbom;
use sbom_model_cyclonedx::CycloneDxReader;
use sbom_model_spdx::SpdxReader;
use std::fs::File;
use std::io::{self, Read};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// old sbom file (use - for stdin)
    old: String,

    /// new sbom file (use - for stdin)
    new: String,

    /// input format
    #[arg(short, long, value_enum, default_value_t = Format::Auto)]
    format: Format,

    /// output format
    #[arg(short, long, value_enum, default_value_t = Output::Text)]
    output: Output,

    /// deny these licenses (repeatable)
    #[arg(long)]
    deny_license: Vec<String>,

    /// allow only these licenses (repeatable)
    #[arg(long)]
    allow_license: Vec<String>,

    /// only report changes in these fields
    #[arg(long, value_enum, value_delimiter = ',')]
    only: Vec<Field>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum Field {
    Version,
    License,
    Supplier,
    Purl,
    Hashes,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Format {
    Auto,
    Cyclonedx,
    Spdx,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Output {
    Text,
    Markdown,
    Json,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let old_sbom = load_sbom(&args.old, args.format).context("failed to load old sbom")?;
    let new_sbom = load_sbom(&args.new, args.format).context("failed to load new sbom")?;

    let only_fields: Vec<sbom_diff::Field> = args
        .only
        .iter()
        .map(|f| match f {
            Field::Version => sbom_diff::Field::Version,
            Field::License => sbom_diff::Field::License,
            Field::Supplier => sbom_diff::Field::Supplier,
            Field::Purl => sbom_diff::Field::Purl,
            Field::Hashes => sbom_diff::Field::Hashes,
        })
        .collect();

    let diff = Differ::diff(
        &old_sbom,
        &new_sbom,
        if only_fields.is_empty() {
            None
        } else {
            Some(&only_fields)
        },
    );

    let license_violation = check_licenses(&new_sbom, &args.deny_license, &args.allow_license);

    let stdout = io::stdout();
    let mut handle = stdout.lock();

    match args.output {
        Output::Text => TextRenderer.render(&diff, &mut handle)?,
        Output::Markdown => MarkdownRenderer.render(&diff, &mut handle)?,
        Output::Json => JsonRenderer.render(&diff, &mut handle)?,
    }

    if license_violation {
        std::process::exit(2);
    }

    Ok(())
}

fn check_licenses(sbom: &Sbom, deny: &[String], allow: &[String]) -> bool {
    let mut violation = false;
    for comp in sbom.components.values() {
        for license in &comp.licenses {
            if !deny.is_empty() && deny.contains(license) {
                eprintln!(
                    "error: license {} is denied (component {})",
                    license, comp.id
                );
                violation = true;
            }
            if !allow.is_empty() && !allow.contains(license) {
                eprintln!(
                    "error: license {} is not allowed (component {})",
                    license, comp.id
                );
                violation = true;
            }
        }
    }
    violation
}

fn load_sbom(path: &str, format: Format) -> anyhow::Result<Sbom> {
    let mut content = Vec::new();
    if path == "-" {
        io::stdin().read_to_end(&mut content)?;
    } else {
        let mut file = File::open(path).context(format!("could not open file: {}", path))?;
        file.read_to_end(&mut content)?;
    }

    match format {
        Format::Cyclonedx => {
            CycloneDxReader::read_json(&content[..]).map_err(|e| anyhow!("cyclonedx error: {}", e))
        }
        Format::Spdx => {
            SpdxReader::read_json(&content[..]).map_err(|e| anyhow!("spdx error: {}", e))
        }
        Format::Auto => {
            if let Ok(sbom) = CycloneDxReader::read_json(&content[..]) {
                return Ok(sbom);
            }
            if let Ok(sbom) = SpdxReader::read_json(&content[..]) {
                return Ok(sbom);
            }
            Err(anyhow!("could not detect sbom format automatically"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbom_model::Component;

    #[test]
    fn test_check_licenses() {
        let mut sbom = Sbom::default();
        let mut c = Component::new("a".into(), Some("1".into()));
        c.licenses.push("gpl-3.0".into());
        sbom.components.insert(c.id.clone(), c);

        assert!(check_licenses(&sbom, &["gpl-3.0".into()], &[]));
        assert!(!check_licenses(&sbom, &["mit".into()], &[]));
        assert!(check_licenses(&sbom, &[], &["mit".into()]));
        assert!(!check_licenses(&sbom, &[], &["gpl-3.0".into()]));
    }

    #[test]

    fn test_load_sbom_auto_cyclonedx() {
        // use existing fixture

        let path = "../../tests/fixtures/old.json";

        let sbom = load_sbom(path, Format::Auto).unwrap();

        assert!(!sbom.components.is_empty());
    }

    #[test]

    fn test_load_sbom_auto_spdx() {
        // use existing fixture

        let path = "../../tests/fixtures/old.spdx.json";

        let sbom = load_sbom(path, Format::Auto).unwrap();

        assert!(!sbom.components.is_empty());
    }
}
