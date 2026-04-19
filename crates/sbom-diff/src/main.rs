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
    /// Fail if any components were removed.
    RemovedComponents,
    /// Fail if any components changed.
    ChangedComponents,
    /// Fail if any dependency edges changed.
    Deps,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum Field {
    Version,
    License,
    Supplier,
    Purl,
    Description,
    Hashes,
    Deps,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Format {
    Auto,
    Cyclonedx,
    CyclonedxXml,
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
            Field::Description => sbom_diff::Field::Description,
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
    // SPDX license IDs are case-insensitive per spec (Annex E / clause 10.1).
    // Normalize to lowercase for matching so that e.g. --deny-license GPL-3.0-only
    // catches components whose SBOM uses gpl-3.0-only.
    let deny_lower: Vec<String> = deny.iter().map(|s| s.to_ascii_lowercase()).collect();
    let allow_lower: Vec<String> = allow.iter().map(|s| s.to_ascii_lowercase()).collect();

    let mut violation = false;
    for comp in sbom.components.values() {
        // A component with no license information cannot satisfy an allow-list.
        if !allow.is_empty() && comp.licenses.is_empty() {
            eprintln!(
                "error: component {} has no license information (--allow-license requires it)",
                comp.id
            );
            violation = true;
            continue;
        }
        for license in &comp.licenses {
            let license_lower = license.to_ascii_lowercase();
            if !deny_lower.is_empty() && deny_lower.contains(&license_lower) {
                eprintln!(
                    "error: license {} is denied (component {})",
                    license, comp.id
                );
                violation = true;
            }
            if !allow_lower.is_empty() && !allow_lower.contains(&license_lower) {
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
    writeln!(out, "Added:        {}", diff.added.len())?;
    writeln!(out, "Removed:      {}", diff.removed.len())?;
    writeln!(out, "Changed:      {}", diff.changed.len())?;
    writeln!(out, "Edge changes: {}", diff.edge_diffs.len())?;
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
            FailOn::RemovedComponents => {
                if !diff.removed.is_empty() {
                    for comp in &diff.removed {
                        eprintln!(
                            "error: removed component {} (--fail-on removed-components)",
                            comp.id
                        );
                    }
                    violation = true;
                }
            }
            FailOn::ChangedComponents => {
                if !diff.changed.is_empty() {
                    for change in &diff.changed {
                        eprintln!(
                            "error: changed component {} (--fail-on changed-components)",
                            change.id
                        );
                    }
                    violation = true;
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
        Format::CyclonedxXml => CycloneDxReader::read_xml(&content[..])
            .map_err(|e| anyhow!("cyclonedx xml error: {}", e)),
        Format::Spdx => {
            SpdxReader::read_json(&content[..]).map_err(|e| anyhow!("spdx error: {}", e))
        }
        Format::Auto => {
            if let Ok(sbom) = CycloneDxReader::read_json(&content[..]) {
                return Ok(sbom);
            }
            if let Ok(sbom) = CycloneDxReader::read_xml(&content[..]) {
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
    fn test_load_sbom_auto_cyclonedx_xml() {
        let path = "../../tests/fixtures/golden-old.cdx.xml";
        let sbom = load_sbom(path, Format::Auto).unwrap();
        assert!(!sbom.components.is_empty());
    }

    #[test]
    fn test_load_sbom_explicit_cyclonedx_xml() {
        let path = "../../tests/fixtures/golden-old.cdx.xml";
        let sbom = load_sbom(path, Format::CyclonedxXml).unwrap();
        assert!(!sbom.components.is_empty());
    }

    #[test]
    fn test_load_sbom_explicit_cyclonedx_json() {
        let path = "../../tests/fixtures/old.json";
        let sbom = load_sbom(path, Format::Cyclonedx).unwrap();
        assert!(!sbom.components.is_empty());
    }

    #[test]
    fn test_load_sbom_explicit_spdx() {
        let path = "../../tests/fixtures/old.spdx.json";
        let sbom = load_sbom(path, Format::Spdx).unwrap();
        assert!(!sbom.components.is_empty());
    }

    #[test]
    fn test_load_sbom_auto_detection_failure() {
        // A file that isn't valid in any format should fail
        let result = load_sbom("Cargo.toml", Format::Auto);
        assert!(result.is_err());
    }

    #[test]
    fn test_render_summary() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![
                Component::new("a".into(), Some("1".into())),
                Component::new("b".into(), Some("1".into())),
            ],
            removed: vec![Component::new("c".into(), Some("1".into()))],
            changed: vec![],
            edge_diffs: vec![],
            metadata_changed: false,
        };

        let mut buf = Vec::new();
        render_summary(&diff, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("Added:        2"));
        assert!(out.contains("Removed:      1"));
        assert!(out.contains("Changed:      0"));
        assert!(out.contains("Edge changes: 0"));
    }

    #[test]
    fn test_render_summary_with_edge_diffs() {
        use sbom_diff::{Diff, EdgeDiff};
        use sbom_model::ComponentId;
        use std::collections::BTreeSet;

        let diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![
                EdgeDiff {
                    parent: ComponentId::new(None, &[("name", "pkg-a")]),
                    added: BTreeSet::from([ComponentId::new(None, &[("name", "pkg-b")])]),
                    removed: BTreeSet::new(),
                },
                EdgeDiff {
                    parent: ComponentId::new(None, &[("name", "pkg-c")]),
                    added: BTreeSet::new(),
                    removed: BTreeSet::from([ComponentId::new(None, &[("name", "pkg-d")])]),
                },
            ],
            metadata_changed: false,
        };

        let mut buf = Vec::new();
        render_summary(&diff, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("Edge changes: 2"));
    }

    #[test]
    fn test_check_fail_on_deps_with_removed_edges() {
        use sbom_diff::{Diff, EdgeDiff};
        use sbom_model::ComponentId;
        use std::collections::BTreeSet;

        let diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![EdgeDiff {
                parent: ComponentId::new(None, &[("name", "parent")]),
                added: BTreeSet::new(),
                removed: BTreeSet::from([ComponentId::new(None, &[("name", "child")])]),
            }],
            metadata_changed: false,
        };

        assert!(check_fail_on(&diff, &[FailOn::Deps]));
    }

    #[test]
    fn test_check_fail_on_multiple_conditions() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![Component::new("new".into(), Some("1".into()))],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            metadata_changed: false,
        };

        // Both conditions checked
        assert!(check_fail_on(
            &diff,
            &[FailOn::AddedComponents, FailOn::MissingHashes]
        ));
    }

    #[test]
    fn test_check_licenses_empty_lists() {
        let sbom = Sbom::default();
        // No components, no violations
        assert!(!check_licenses(&sbom, &[], &[]));
    }

    #[test]
    fn test_check_licenses_unlicensed_component_with_allowlist() {
        let mut sbom = Sbom::default();
        // Component with no license information
        let c = Component::new("unlicensed-pkg".into(), Some("1.0".into()));
        // licenses is empty by default
        sbom.components.insert(c.id.clone(), c);

        // No allow-list: unlicensed component is not a violation
        assert!(!check_licenses(&sbom, &[], &[]));

        // With allow-list: unlicensed component cannot satisfy it → violation
        assert!(check_licenses(&sbom, &[], &["MIT".into()]));

        // With deny-list only: unlicensed component is not a violation (nothing to deny)
        assert!(!check_licenses(&sbom, &["GPL-3.0-only".into()], &[]));
    }

    #[test]
    fn test_check_licenses_case_insensitive() {
        let mut sbom = Sbom::default();
        let mut c = Component::new("a".into(), Some("1".into()));
        c.licenses.insert("GPL-3.0-only".into());
        sbom.components.insert(c.id.clone(), c);

        // Deny: different casing still matches
        assert!(check_licenses(&sbom, &["gpl-3.0-only".into()], &[]));
        assert!(check_licenses(&sbom, &["Gpl-3.0-Only".into()], &[]));

        // Allow: different casing is still accepted
        assert!(!check_licenses(&sbom, &[], &["gpl-3.0-only".into()]));
        assert!(!check_licenses(&sbom, &[], &["GPL-3.0-ONLY".into()]));

        // Allow: wrong license is still rejected regardless of case
        assert!(check_licenses(&sbom, &[], &["mit".into()]));
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

    #[test]
    fn test_check_fail_on_removed_components() {
        use sbom_diff::Diff;

        let mut diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            metadata_changed: false,
        };

        // No removed components - no violation
        assert!(!check_fail_on(&diff, &[FailOn::RemovedComponents]));

        // With removed component - violation
        diff.removed
            .push(Component::new("old-pkg".into(), Some("1.0".into())));
        assert!(check_fail_on(&diff, &[FailOn::RemovedComponents]));
    }

    #[test]
    fn test_check_fail_on_changed_components() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let mut diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            metadata_changed: false,
        };

        // No changed components - no violation
        assert!(!check_fail_on(&diff, &[FailOn::ChangedComponents]));

        // With changed component - violation
        let old = Component::new("pkg".into(), Some("1.0".into()));
        let new = Component::new("pkg".into(), Some("2.0".into()));
        diff.changed.push(ComponentChange {
            id: old.id.clone(),
            old: old.clone(),
            new,
            changes: vec![FieldChange::Version("1.0".into(), "2.0".into())],
        });
        assert!(check_fail_on(&diff, &[FailOn::ChangedComponents]));
    }

    #[test]
    fn test_description_only_changes_do_not_trigger_gates() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let old = Component::new("pkg".into(), Some("1.0".into()));
        let mut new = old.clone();
        new.description = Some("updated description".into());

        let diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old,
                new,
                changes: vec![FieldChange::Description(
                    None,
                    Some("updated description".into()),
                )],
            }],
            edge_diffs: vec![],
            metadata_changed: false,
        };

        assert!(!check_fail_on(
            &diff,
            &[
                FailOn::AddedComponents,
                FailOn::RemovedComponents,
                FailOn::MissingHashes,
                FailOn::Deps,
            ]
        ));
        // But ChangedComponents *should* trigger on description changes
        assert!(check_fail_on(&diff, &[FailOn::ChangedComponents]));
    }
}
