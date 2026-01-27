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

    /// fail on specific conditions (repeatable)
    #[arg(long, value_enum)]
    fail_on: Vec<FailOn>,

    /// print only summary counts (no component details)
    #[arg(long)]
    summary: bool,

    /// suppress all output except errors
    #[arg(short, long)]
    quiet: bool,
}

/// Conditions that trigger a non-zero exit code.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum FailOn {
    /// Fail if any added component lacks checksums.
    MissingHashes,
    /// Fail if any components were added.
    AddedComponents,
    /// Fail if any dependency edges changed.
    Deps,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum Field {
    Version,
    License,
    Supplier,
    Purl,
    Hashes,
    Deps,
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
            Field::Deps => sbom_diff::Field::Deps,
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
    let fail_on_violation = check_fail_on(&diff, &args.fail_on);

    if !args.quiet {
        let stdout = io::stdout();
        let mut handle = stdout.lock();

        if args.summary {
            render_summary(&diff, &mut handle)?;
        } else {
            match args.output {
                Output::Text => TextRenderer.render(&diff, &mut handle)?,
                Output::Markdown => MarkdownRenderer.render(&diff, &mut handle)?,
                Output::Json => JsonRenderer.render(&diff, &mut handle)?,
            }
        }
    }

    if license_violation {
        std::process::exit(2);
    }

    if fail_on_violation {
        std::process::exit(3);
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

fn render_summary(diff: &sbom_diff::Diff, out: &mut impl io::Write) -> io::Result<()> {
    writeln!(out, "Added:   {}", diff.added.len())?;
    writeln!(out, "Removed: {}", diff.removed.len())?;
    writeln!(out, "Changed: {}", diff.changed.len())?;
    Ok(())
}

fn check_fail_on(diff: &sbom_diff::Diff, fail_on: &[FailOn]) -> bool {
    let mut violation = false;

    for condition in fail_on {
        match condition {
            FailOn::AddedComponents => {
                if !diff.added.is_empty() {
                    for comp in &diff.added {
                        eprintln!(
                            "error: added component {} (--fail-on added-components)",
                            comp.id
                        );
                    }
                    violation = true;
                }
            }
            FailOn::MissingHashes => {
                for comp in &diff.added {
                    if comp.hashes.is_empty() {
                        eprintln!(
                            "error: added component {} has no hashes (--fail-on missing-hashes)",
                            comp.id
                        );
                        violation = true;
                    }
                }
            }
            FailOn::Deps => {
                if !diff.edge_diffs.is_empty() {
                    for edge in &diff.edge_diffs {
                        for added in &edge.added {
                            eprintln!(
                                "error: added dependency edge {} -> {} (--fail-on deps)",
                                edge.parent, added
                            );
                        }
                        for removed in &edge.removed {
                            eprintln!(
                                "error: removed dependency edge {} -> {} (--fail-on deps)",
                                edge.parent, removed
                            );
                        }
                    }
                    violation = true;
                }
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
        c.licenses.insert("GPL-3.0-only".into());
        sbom.components.insert(c.id.clone(), c);

        // Exact match
        assert!(check_licenses(&sbom, &["GPL-3.0-only".into()], &[]));
        // No match
        assert!(!check_licenses(&sbom, &["MIT".into()], &[]));
        // Not in allow list
        assert!(check_licenses(&sbom, &[], &["MIT".into()]));
        // In allow list
        assert!(!check_licenses(&sbom, &[], &["GPL-3.0-only".into()]));
    }

    #[test]
    fn test_check_licenses_multiple() {
        let mut sbom = Sbom::default();
        let mut c = Component::new("a".into(), Some("1".into()));
        // Two separate licenses in the set
        c.licenses.insert("MIT".into());
        c.licenses.insert("Apache-2.0".into());
        sbom.components.insert(c.id.clone(), c);

        // Either license triggers deny
        assert!(check_licenses(&sbom, &["MIT".into()], &[]));
        assert!(check_licenses(&sbom, &["Apache-2.0".into()], &[]));
        // Both must be in allow list
        assert!(check_licenses(&sbom, &[], &["MIT".into()])); // Apache-2.0 not allowed
        assert!(!check_licenses(
            &sbom,
            &[],
            &["MIT".into(), "Apache-2.0".into()]
        ));
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
        let path = "../../tests/fixtures/old.spdx.json";
        let sbom = load_sbom(path, Format::Auto).unwrap();
        assert!(!sbom.components.is_empty());
    }

    #[test]
    fn test_check_fail_on_added_components() {
        use sbom_diff::Diff;

        let mut diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            metadata_changed: false,
        };

        // No added components - no violation
        assert!(!check_fail_on(&diff, &[FailOn::AddedComponents]));

        // With added component - violation
        diff.added
            .push(Component::new("new-pkg".into(), Some("1.0".into())));
        assert!(check_fail_on(&diff, &[FailOn::AddedComponents]));
    }

    #[test]
    fn test_check_fail_on_missing_hashes() {
        use sbom_diff::Diff;

        let mut diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            metadata_changed: false,
        };

        // No added components - no violation
        assert!(!check_fail_on(&diff, &[FailOn::MissingHashes]));

        // Added component without hashes - violation
        diff.added
            .push(Component::new("new-pkg".into(), Some("1.0".into())));
        assert!(check_fail_on(&diff, &[FailOn::MissingHashes]));

        // Added component with hashes - no violation
        diff.added[0].hashes.insert("sha256".into(), "abc".into());
        assert!(!check_fail_on(&diff, &[FailOn::MissingHashes]));
    }

    #[test]
    fn test_check_fail_on_deps() {
        use sbom_diff::{Diff, EdgeDiff};
        use sbom_model::ComponentId;
        use std::collections::BTreeSet;

        let mut diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            metadata_changed: false,
        };

        // No edge changes - no violation
        assert!(!check_fail_on(&diff, &[FailOn::Deps]));

        // With edge changes - violation
        diff.edge_diffs.push(EdgeDiff {
            parent: ComponentId::new(None, &[("name", "parent")]),
            added: BTreeSet::from([ComponentId::new(None, &[("name", "child")])]),
            removed: BTreeSet::new(),
        });
        assert!(check_fail_on(&diff, &[FailOn::Deps]));
    }
}
