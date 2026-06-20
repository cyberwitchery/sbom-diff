mod format;

use anyhow::Context;
use clap::{Parser, ValueEnum};
use format::{load_sbom, Format};
use sbom_diff::{
    renderer::{
        format_option, format_set, CsvRenderer, JsonRenderer, MarkdownRenderer, RenderOptions,
        Renderer, SarifRenderer, SummaryRenderer, TextRenderer,
    },
    Differ, Field,
};
use sbom_model::is_hash_algorithm_downgrade;
use sbom_model::versions::is_version_downgrade;
use sbom_model::Sbom;
use std::collections::HashSet;
use std::io;

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

    /// only show changes for these ecosystems (repeatable)
    #[arg(long)]
    include_ecosystem: Vec<String>,

    /// exclude changes for these ecosystems (repeatable)
    #[arg(long)]
    exclude_ecosystem: Vec<String>,

    /// break down counts by package ecosystem (npm, cargo, pypi, etc)
    #[arg(long)]
    group_by_ecosystem: bool,

    /// print only summary counts (no component details)
    #[arg(long)]
    summary: bool,

    /// suppress all output except errors
    #[arg(short, long)]
    quiet: bool,

    /// include parser warnings in rendered output
    #[arg(long)]
    show_warnings: bool,
}

/// conditions that trigger a non-zero exit code.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum FailOn {
    /// fail if any added component lacks checksums or a changed component dropped all its checksums.
    MissingHashes,
    /// fail if any components were added.
    AddedComponents,
    /// fail if any components were removed.
    RemovedComponents,
    /// fail if any components changed.
    ChangedComponents,
    /// fail if any dependency edges changed.
    Deps,
    /// fail if any changed component's license changed or any added component introduces licenses.
    LicenseChanged,
    /// fail if document metadata changed (timestamp, tools, or authors).
    MetadataChanged,
    /// fail if any changed component's version went from a higher to a lower value.
    VersionDowngrade,
    /// fail if any changed component's supplier changed or any added component has a supplier.
    SupplierChanged,
    /// fail if any changed component's strongest hash algorithm is weaker than before.
    HashAlgorithmDowngrade,
    /// fail if the new SBOM's dependency graph contains cycles.
    CyclicDependency,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Output {
    Text,
    Markdown,
    Json,
    Sarif,
    Csv,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let old_sbom = load_sbom(&args.old, args.format).context("failed to load old sbom")?;
    let new_sbom = load_sbom(&args.new, args.format).context("failed to load new sbom")?;

    for w in old_sbom.warnings.iter().chain(new_sbom.warnings.iter()) {
        eprintln!("warning: {}", w);
    }

    // build render options and run license checks before diff_owned consumes
    // the SBOMs — this avoids cloning both SBOMs inside the differ.
    let render_opts = RenderOptions {
        group_by_ecosystem: args.group_by_ecosystem,
        show_warnings: args.show_warnings,
        old_warnings: old_sbom.warnings.clone(),
        new_warnings: new_sbom.warnings.clone(),
    };

    let license_violation = check_licenses(&new_sbom, &args.deny_license, &args.allow_license);
    let cycle_violation = check_cyclic_dependencies(&new_sbom, &args.fail_on);

    // build ecosystem filter and pre-count filtered totals before diff_owned
    // consumes the SBOMs.
    let eco_include: HashSet<String> = args
        .include_ecosystem
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();
    let eco_exclude: HashSet<String> = args
        .exclude_ecosystem
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();
    let eco_filter_active = !eco_include.is_empty() || !eco_exclude.is_empty();

    let eco_matches = |eco: Option<&str>| -> bool {
        let eco_lower = eco.unwrap_or("unknown").to_ascii_lowercase();
        if !eco_include.is_empty() && !eco_include.contains(&eco_lower) {
            return false;
        }
        if eco_exclude.contains(&eco_lower) {
            return false;
        }
        true
    };

    let (filtered_old_total, filtered_new_total, component_ecosystems) = if eco_filter_active {
        // build ecosystem map from both SBOMs before diff_owned consumes them
        let mut eco_map = std::collections::BTreeMap::new();
        for (id, comp) in old_sbom.components.iter() {
            eco_map.insert(id.clone(), comp.ecosystem.clone());
        }
        for (id, comp) in new_sbom.components.iter() {
            eco_map.insert(id.clone(), comp.ecosystem.clone());
        }
        (
            old_sbom
                .components
                .values()
                .filter(|c| eco_matches(c.ecosystem.as_deref()))
                .count(),
            new_sbom
                .components
                .values()
                .filter(|c| eco_matches(c.ecosystem.as_deref()))
                .count(),
            eco_map,
        )
    } else {
        (0, 0, std::collections::BTreeMap::new())
    };

    let mut diff = Differ::diff_owned(
        old_sbom,
        new_sbom,
        if args.only.is_empty() {
            None
        } else {
            Some(&args.only)
        },
    );

    if eco_filter_active {
        diff.filter_by_ecosystem(
            &eco_matches,
            filtered_old_total,
            filtered_new_total,
            &component_ecosystems,
        );
    }

    let fail_on_violation = check_fail_on(&diff, &args.fail_on);

    if !args.quiet {
        let stdout = io::stdout();
        let mut handle = stdout.lock();

        if args.summary {
            match args.output {
                Output::Text => TextRenderer.render_summary(&diff, &render_opts, &mut handle)?,
                Output::Markdown => {
                    MarkdownRenderer.render_summary(&diff, &render_opts, &mut handle)?
                }
                Output::Json => JsonRenderer.render_summary(&diff, &render_opts, &mut handle)?,
                Output::Sarif => SarifRenderer.render_summary(&diff, &render_opts, &mut handle)?,
                Output::Csv => CsvRenderer.render_summary(&diff, &render_opts, &mut handle)?,
            }
        } else {
            match args.output {
                Output::Text => TextRenderer.render(&diff, &render_opts, &mut handle)?,
                Output::Markdown => MarkdownRenderer.render(&diff, &render_opts, &mut handle)?,
                Output::Json => JsonRenderer.render(&diff, &render_opts, &mut handle)?,
                Output::Sarif => SarifRenderer.render(&diff, &render_opts, &mut handle)?,
                Output::Csv => CsvRenderer.render(&diff, &render_opts, &mut handle)?,
            }
        }
    }

    if license_violation {
        std::process::exit(2);
    }

    if fail_on_violation || cycle_violation {
        std::process::exit(3);
    }

    Ok(())
}

fn check_licenses(sbom: &Sbom, deny: &[String], allow: &[String]) -> bool {
    // SPDX license IDs are case-insensitive per spec (Annex E / clause 10.1).
    // normalize to lowercase for matching so that e.g. --deny-license GPL-3.0-only
    // catches components whose SBOM uses gpl-3.0-only.
    let deny_lower: HashSet<String> = deny.iter().map(|s| s.to_ascii_lowercase()).collect();
    let allow_lower: HashSet<String> = allow.iter().map(|s| s.to_ascii_lowercase()).collect();

    let mut violation = false;
    for comp in sbom.components.values() {
        // a component with no license information cannot satisfy an allow-list.
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

fn check_cyclic_dependencies(sbom: &Sbom, fail_on: &[FailOn]) -> bool {
    if !fail_on.contains(&FailOn::CyclicDependency) {
        return false;
    }

    let cycles = sbom.detect_cycles();
    if cycles.is_empty() {
        return false;
    }

    for cycle in &cycles {
        let names: Vec<_> = cycle.iter().map(|id| id.to_string()).collect();
        eprintln!(
            "error: dependency cycle detected: {} (--fail-on cyclic-dependency)",
            names.join(" -> ")
        );
    }
    true
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
                for change in &diff.changed {
                    if !change.old.hashes.is_empty() && change.new.hashes.is_empty() {
                        eprintln!(
                            "error: changed component {} dropped all hashes (--fail-on missing-hashes)",
                            change.id
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
                        for added in edge.added.keys() {
                            eprintln!(
                                "error: added dependency edge {} -> {} (--fail-on deps)",
                                edge.parent, added
                            );
                        }
                        for removed in edge.removed.keys() {
                            eprintln!(
                                "error: removed dependency edge {} -> {} (--fail-on deps)",
                                edge.parent, removed
                            );
                        }
                        for (child, (old_kind, new_kind)) in &edge.kind_changed {
                            eprintln!(
                                "error: dependency edge {} -> {} changed kind: {} -> {} (--fail-on deps)",
                                edge.parent, child, old_kind, new_kind
                            );
                        }
                    }
                    violation = true;
                }
            }
            FailOn::LicenseChanged => {
                for change in &diff.changed {
                    for fc in &change.changes {
                        if let sbom_diff::FieldChange::License(old, new) = fc {
                            eprintln!(
                                "error: license changed on component {}: {} -> {} (--fail-on license-changed)",
                                change.id, format_set(old), format_set(new)
                            );
                            violation = true;
                        }
                    }
                }
                for comp in &diff.added {
                    if !comp.licenses.is_empty() {
                        let licenses: Vec<_> = comp.licenses.iter().cloned().collect();
                        eprintln!(
                            "error: added component {} introduces license(s): {} (--fail-on license-changed)",
                            comp.id, licenses.join(", ")
                        );
                        violation = true;
                    }
                }
            }
            FailOn::MetadataChanged => {
                if let Some(mc) = &diff.metadata_changed {
                    if mc.timestamp.is_some() {
                        eprintln!(
                            "error: document metadata timestamp changed (--fail-on metadata-changed)"
                        );
                    }
                    if mc.tools.is_some() {
                        eprintln!(
                            "error: document metadata tools changed (--fail-on metadata-changed)"
                        );
                    }
                    if mc.authors.is_some() {
                        eprintln!(
                            "error: document metadata authors changed (--fail-on metadata-changed)"
                        );
                    }
                    violation = true;
                }
            }
            FailOn::VersionDowngrade => {
                for change in &diff.changed {
                    for fc in &change.changes {
                        if let sbom_diff::FieldChange::Version(Some(old_ver), Some(new_ver)) = fc {
                            if is_version_downgrade(old_ver, new_ver) {
                                eprintln!(
                                    "error: version downgrade on component {}: {} -> {} (--fail-on version-downgrade)",
                                    change.id, old_ver, new_ver
                                );
                                violation = true;
                            }
                        }
                    }
                }
            }
            FailOn::SupplierChanged => {
                for change in &diff.changed {
                    for fc in &change.changes {
                        if let sbom_diff::FieldChange::Supplier(old_sup, new_sup) = fc {
                            eprintln!(
                                "error: supplier changed on component {}: {} -> {} (--fail-on supplier-changed)",
                                change.id, format_option(old_sup), format_option(new_sup)
                            );
                            violation = true;
                        }
                    }
                }
                for comp in &diff.added {
                    if comp.supplier.is_some() {
                        eprintln!(
                            "error: added component {} has supplier: {} (--fail-on supplier-changed)",
                            comp.id,
                            comp.supplier.as_deref().unwrap_or("<none>")
                        );
                        violation = true;
                    }
                }
            }
            FailOn::HashAlgorithmDowngrade => {
                for change in &diff.changed {
                    for fc in &change.changes {
                        if let sbom_diff::FieldChange::Hashes(old_hashes, new_hashes) = fc {
                            if is_hash_algorithm_downgrade(old_hashes, new_hashes) {
                                let old_algos: Vec<_> = old_hashes.keys().cloned().collect();
                                let new_algos: Vec<_> = new_hashes.keys().cloned().collect();
                                eprintln!(
                                    "error: hash algorithm downgrade on component {}: [{}] -> [{}] (--fail-on hash-algorithm-downgrade)",
                                    change.id,
                                    old_algos.join(", "),
                                    new_algos.join(", "),
                                );
                                violation = true;
                            }
                        }
                    }
                }
            }
            // handled separately in check_cyclic_dependencies before diff
            FailOn::CyclicDependency => {}
        }
    }

    violation
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

        assert!(check_licenses(&sbom, &["GPL-3.0-only".into()], &[]));
        assert!(!check_licenses(&sbom, &["MIT".into()], &[]));
        assert!(check_licenses(&sbom, &[], &["MIT".into()]));
        assert!(!check_licenses(&sbom, &[], &["GPL-3.0-only".into()]));
    }

    #[test]
    fn test_check_licenses_multiple() {
        let mut sbom = Sbom::default();
        let mut c = Component::new("a".into(), Some("1".into()));
        // two separate licenses in the set
        c.licenses.insert("MIT".into());
        c.licenses.insert("Apache-2.0".into());
        sbom.components.insert(c.id.clone(), c);

        // either license triggers deny
        assert!(check_licenses(&sbom, &["MIT".into()], &[]));
        assert!(check_licenses(&sbom, &["Apache-2.0".into()], &[]));
        // both must be in allow list
        assert!(check_licenses(&sbom, &[], &["MIT".into()])); // Apache-2.0 not allowed
        assert!(!check_licenses(
            &sbom,
            &[],
            &["MIT".into(), "Apache-2.0".into()]
        ));
    }

    #[test]
    fn test_check_licenses_licenseref() {
        let mut sbom = Sbom::default();
        let mut c = Component::new("a".into(), Some("1".into()));
        // simulate a component whose license expression was
        // "LicenseRef-proprietary AND Apache-2.0" — after parsing, both
        // individual terms should be in the licenses set.
        c.licenses.insert("LicenseRef-proprietary".into());
        c.licenses.insert("Apache-2.0".into());
        sbom.components.insert(c.id.clone(), c);

        // denying the LicenseRef term should trigger a violation
        assert!(check_licenses(
            &sbom,
            &["LicenseRef-proprietary".into()],
            &[]
        ));
        // denying the SPDX term should also trigger
        assert!(check_licenses(&sbom, &["Apache-2.0".into()], &[]));
        // allow-list must include both
        assert!(check_licenses(&sbom, &[], &["Apache-2.0".into()]));
        assert!(!check_licenses(
            &sbom,
            &[],
            &["Apache-2.0".into(), "LicenseRef-proprietary".into()]
        ));
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
            ..Diff::default()
        };

        let mut buf = Vec::new();
        TextRenderer
            .render_summary(&diff, &RenderOptions::default(), &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("Added:            2"));
        assert!(out.contains("Removed:          1"));
        assert!(out.contains("Changed:          0"));
        assert!(out.contains("Edge changes:     0"));
    }

    #[test]
    fn test_render_summary_with_edge_diffs() {
        use sbom_diff::{Diff, EdgeDiff};
        use sbom_model::{ComponentId, DependencyKind};
        use std::collections::BTreeMap;

        let diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![
                EdgeDiff {
                    parent: ComponentId::new(None, &[("name", "pkg-a")]),
                    added: BTreeMap::from([(
                        ComponentId::new(None, &[("name", "pkg-b")]),
                        DependencyKind::Runtime,
                    )]),
                    removed: BTreeMap::new(),
                    kind_changed: BTreeMap::new(),
                },
                EdgeDiff {
                    parent: ComponentId::new(None, &[("name", "pkg-c")]),
                    added: BTreeMap::new(),
                    removed: BTreeMap::from([(
                        ComponentId::new(None, &[("name", "pkg-d")]),
                        DependencyKind::Runtime,
                    )]),
                    kind_changed: BTreeMap::new(),
                },
            ],
            ..Diff::default()
        };

        let mut buf = Vec::new();
        TextRenderer
            .render_summary(&diff, &RenderOptions::default(), &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("Edge changes:     2"));
    }

    #[test]
    fn test_check_fail_on_deps_with_removed_edges() {
        use sbom_diff::{Diff, EdgeDiff};
        use sbom_model::{ComponentId, DependencyKind};
        use std::collections::BTreeMap;

        let diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![EdgeDiff {
                parent: ComponentId::new(None, &[("name", "parent")]),
                added: BTreeMap::new(),
                removed: BTreeMap::from([(
                    ComponentId::new(None, &[("name", "child")]),
                    DependencyKind::Runtime,
                )]),
                kind_changed: BTreeMap::new(),
            }],
            ..Diff::default()
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
            ..Diff::default()
        };

        assert!(check_fail_on(
            &diff,
            &[FailOn::AddedComponents, FailOn::MissingHashes]
        ));
    }

    #[test]
    fn test_check_licenses_empty_lists() {
        let sbom = Sbom::default();
        // no components, no violations
        assert!(!check_licenses(&sbom, &[], &[]));
    }

    #[test]
    fn test_check_licenses_unlicensed_component_with_allowlist() {
        let mut sbom = Sbom::default();
        // component with no license information
        let c = Component::new("unlicensed-pkg".into(), Some("1.0".into()));
        // licenses is empty by default
        sbom.components.insert(c.id.clone(), c);

        // no allow-list: unlicensed component is not a violation
        assert!(!check_licenses(&sbom, &[], &[]));

        // with allow-list: unlicensed component cannot satisfy it → violation
        assert!(check_licenses(&sbom, &[], &["MIT".into()]));

        // with deny-list only: unlicensed component is not a violation (nothing to deny)
        assert!(!check_licenses(&sbom, &["GPL-3.0-only".into()], &[]));
    }

    #[test]
    fn test_check_licenses_case_insensitive() {
        let mut sbom = Sbom::default();
        let mut c = Component::new("a".into(), Some("1".into()));
        c.licenses.insert("GPL-3.0-only".into());
        sbom.components.insert(c.id.clone(), c);

        // deny: different casing still matches
        assert!(check_licenses(&sbom, &["gpl-3.0-only".into()], &[]));
        assert!(check_licenses(&sbom, &["Gpl-3.0-Only".into()], &[]));

        // allow: different casing is still accepted
        assert!(!check_licenses(&sbom, &[], &["gpl-3.0-only".into()]));
        assert!(!check_licenses(&sbom, &[], &["GPL-3.0-ONLY".into()]));

        // allow: wrong license is still rejected regardless of case
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
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::AddedComponents]));

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
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::MissingHashes]));

        diff.added
            .push(Component::new("new-pkg".into(), Some("1.0".into())));
        assert!(check_fail_on(&diff, &[FailOn::MissingHashes]));

        diff.added[0].hashes.insert("sha256".into(), "abc".into());
        assert!(!check_fail_on(&diff, &[FailOn::MissingHashes]));
    }

    #[test]
    fn test_check_fail_on_missing_hashes_changed_component_dropped() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};
        use std::collections::BTreeMap;

        let mut old = Component::new("pkg".into(), Some("1.0".into()));
        old.hashes.insert("sha256".into(), "abc".into());
        let new = Component::new("pkg".into(), Some("1.1".into()));
        // new has no hashes — regression

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![
                    FieldChange::Version(Some("1.0".into()), Some("1.1".into())),
                    FieldChange::Hashes(old.hashes.clone(), BTreeMap::new()),
                ],
            }],
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::MissingHashes]));
    }

    #[test]
    fn test_check_fail_on_missing_hashes_changed_component_kept() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let mut old = Component::new("pkg".into(), Some("1.0".into()));
        old.hashes.insert("sha256".into(), "abc".into());
        let mut new = Component::new("pkg".into(), Some("1.1".into()));
        new.hashes.insert("sha256".into(), "def".into());
        // new still has hashes — not a regression

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![
                    FieldChange::Version(Some("1.0".into()), Some("1.1".into())),
                    FieldChange::Hashes(old.hashes.clone(), new.hashes.clone()),
                ],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::MissingHashes]));
    }

    #[test]
    fn test_check_fail_on_missing_hashes_changed_component_both_empty() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let old = Component::new("pkg".into(), Some("1.0".into()));
        let new = Component::new("pkg".into(), Some("1.1".into()));
        // both have no hashes — not a regression, was already missing

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Version(Some("1.0".into()), Some("1.1".into()))],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::MissingHashes]));
    }

    #[test]
    fn test_check_fail_on_deps() {
        use sbom_diff::{Diff, EdgeDiff};
        use sbom_model::{ComponentId, DependencyKind};
        use std::collections::BTreeMap;

        let mut diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::Deps]));

        diff.edge_diffs.push(EdgeDiff {
            parent: ComponentId::new(None, &[("name", "parent")]),
            added: BTreeMap::from([(
                ComponentId::new(None, &[("name", "child")]),
                DependencyKind::Runtime,
            )]),
            removed: BTreeMap::new(),
            kind_changed: BTreeMap::new(),
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
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::RemovedComponents]));

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
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::ChangedComponents]));

        let old = Component::new("pkg".into(), Some("1.0".into()));
        let new = Component::new("pkg".into(), Some("2.0".into()));
        diff.changed.push(ComponentChange {
            id: old.id.clone(),
            old: old.clone(),
            new,
            changes: vec![FieldChange::Version(Some("1.0".into()), Some("2.0".into()))],
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
            ..Diff::default()
        };

        assert!(!check_fail_on(
            &diff,
            &[
                FailOn::AddedComponents,
                FailOn::RemovedComponents,
                FailOn::MissingHashes,
                FailOn::Deps,
                FailOn::LicenseChanged,
            ]
        ));
        // but ChangedComponents *should* trigger on description changes
        assert!(check_fail_on(&diff, &[FailOn::ChangedComponents]));
    }

    #[test]
    fn test_render_summary_markdown() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![
                Component::new("a".into(), Some("1".into())),
                Component::new("b".into(), Some("1".into())),
            ],
            removed: vec![Component::new("c".into(), Some("1".into()))],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let mut buf = Vec::new();
        MarkdownRenderer
            .render_summary(&diff, &RenderOptions::default(), &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("### SBOM Diff Summary"));
        assert!(out.contains("| Metric | Count |"));
        assert!(out.contains("| Old total | 0 |"));
        assert!(out.contains("| New total | 0 |"));
        assert!(out.contains("| Unchanged | 0 |"));
        assert!(out.contains("| Added | 2 |"));
        assert!(out.contains("| Removed | 1 |"));
        assert!(out.contains("| Changed | 0 |"));
        assert!(out.contains("| Edge changes | 0 |"));
        // should NOT contain component details
        assert!(!out.contains("<details>"));
    }

    #[test]
    fn test_render_summary_markdown_with_ecosystems() {
        use sbom_diff::Diff;

        let mut added_npm = Component::new("express".into(), Some("4.18.0".into()));
        added_npm.ecosystem = Some("npm".into());
        let mut added_cargo = Component::new("serde".into(), Some("1.0.0".into()));
        added_cargo.ecosystem = Some("cargo".into());
        let mut removed = Component::new("lodash".into(), Some("4.17.21".into()));
        removed.ecosystem = Some("npm".into());

        let diff = Diff {
            added: vec![added_npm, added_cargo],
            removed: vec![removed],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let opts = RenderOptions {
            group_by_ecosystem: true,
            ..Default::default()
        };

        let mut buf = Vec::new();
        MarkdownRenderer
            .render_summary(&diff, &opts, &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("#### By Ecosystem"));
        assert!(out.contains("| Ecosystem | Added | Removed | Changed |"));
        assert!(out.contains("| cargo | 1 | 0 | 0 |"));
        assert!(out.contains("| npm | 1 | 1 | 0 |"));
    }

    #[test]
    fn test_render_summary_markdown_empty() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let mut buf = Vec::new();
        MarkdownRenderer
            .render_summary(&diff, &RenderOptions::default(), &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("| Added | 0 |"));
        assert!(out.contains("| Removed | 0 |"));
        assert!(out.contains("| Changed | 0 |"));
        assert!(out.contains("| Edge changes | 0 |"));
    }

    #[test]
    fn test_render_summary_json() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![
                Component::new("a".into(), Some("1".into())),
                Component::new("b".into(), Some("1".into())),
            ],
            removed: vec![Component::new("c".into(), Some("1".into()))],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let mut buf = Vec::new();
        JsonRenderer
            .render_summary(&diff, &RenderOptions::default(), &mut buf)
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

        assert_eq!(val["added"], 2);
        assert_eq!(val["removed"], 1);
        assert_eq!(val["changed"], 0);
        assert_eq!(val["edge_changes"], 0);
        assert!(val.get("ecosystem_breakdown").is_none());
    }

    #[test]
    fn test_render_summary_json_with_ecosystems() {
        use sbom_diff::Diff;

        let mut added_npm = Component::new("express".into(), Some("4.18.0".into()));
        added_npm.ecosystem = Some("npm".into());

        let diff = Diff {
            added: vec![added_npm],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let opts = RenderOptions {
            group_by_ecosystem: true,
            ..Default::default()
        };

        let mut buf = Vec::new();
        JsonRenderer.render_summary(&diff, &opts, &mut buf).unwrap();
        let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

        assert_eq!(val["added"], 1);
        let breakdown = &val["ecosystem_breakdown"];
        assert!(breakdown.is_object());
        assert_eq!(breakdown["npm"]["added"], 1);
    }

    #[test]
    fn test_render_summary_text_with_warnings() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![Component::new("a".into(), Some("1".into()))],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let opts = RenderOptions {
            show_warnings: true,
            old_warnings: vec!["old sbom missing supplier".into()],
            new_warnings: vec!["new sbom missing license".into()],
            ..Default::default()
        };

        let mut buf = Vec::new();
        TextRenderer.render_summary(&diff, &opts, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("Warnings:     2"));
        assert!(out.contains("[old] old sbom missing supplier"));
        assert!(out.contains("[new] new sbom missing license"));
        assert!(out.contains("Added:            1"));
    }

    #[test]
    fn test_render_summary_markdown_with_warnings() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![Component::new("a".into(), Some("1".into()))],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let opts = RenderOptions {
            show_warnings: true,
            old_warnings: vec!["old sbom missing supplier".into()],
            new_warnings: vec!["new sbom missing license".into()],
            ..Default::default()
        };

        let mut buf = Vec::new();
        MarkdownRenderer
            .render_summary(&diff, &opts, &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("<details><summary><b>Warnings (2)</b></summary>"));
        assert!(out.contains("- **old:** old sbom missing supplier"));
        assert!(out.contains("- **new:** new sbom missing license"));
        assert!(out.contains("</details>"));
        assert!(out.contains("### SBOM Diff Summary"));
        assert!(out.contains("| Added | 1 |"));
    }

    #[test]
    fn test_render_summary_markdown_no_warnings_without_flag() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let opts = RenderOptions {
            show_warnings: false,
            old_warnings: vec!["some warning".into()],
            ..Default::default()
        };

        let mut buf = Vec::new();
        MarkdownRenderer
            .render_summary(&diff, &opts, &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(!out.contains("Warnings"));
        assert!(!out.contains("<details>"));
    }

    #[test]
    fn test_render_summary_json_with_warnings() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![Component::new("a".into(), Some("1".into()))],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let opts = RenderOptions {
            show_warnings: true,
            old_warnings: vec!["old sbom missing supplier".into()],
            new_warnings: vec!["new sbom missing license".into()],
            ..Default::default()
        };

        let mut buf = Vec::new();
        JsonRenderer.render_summary(&diff, &opts, &mut buf).unwrap();
        let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

        assert_eq!(val["added"], 1);
        let warnings = &val["warnings"];
        assert!(warnings.is_object());
        assert_eq!(warnings["old"][0], "old sbom missing supplier");
        assert_eq!(warnings["new"][0], "new sbom missing license");
    }

    #[test]
    fn test_render_summary_json_no_warnings_without_flag() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let opts = RenderOptions {
            show_warnings: false,
            old_warnings: vec!["some warning".into()],
            ..Default::default()
        };

        let mut buf = Vec::new();
        JsonRenderer.render_summary(&diff, &opts, &mut buf).unwrap();
        let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

        assert!(val.get("warnings").is_none());
    }

    #[test]
    fn test_check_fail_on_license_changed_on_changed_component() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};
        use std::collections::BTreeSet;

        let mut old = Component::new("pkg".into(), Some("1.0".into()));
        old.licenses.insert("MIT".into());
        let mut new = Component::new("pkg".into(), Some("1.0".into()));
        new.licenses.insert("GPL-3.0-only".into());

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::License(
                    BTreeSet::from(["MIT".into()]),
                    BTreeSet::from(["GPL-3.0-only".into()]),
                )],
            }],
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::LicenseChanged]));
    }

    #[test]
    fn test_check_fail_on_license_changed_no_license_change() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let old = Component::new("pkg".into(), Some("1.0".into()));
        let new = Component::new("pkg".into(), Some("2.0".into()));

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old,
                new,
                changes: vec![FieldChange::Version(Some("1.0".into()), Some("2.0".into()))],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::LicenseChanged]));
    }

    #[test]
    fn test_check_fail_on_license_changed_added_component_with_license() {
        use sbom_diff::Diff;

        let mut added = Component::new("new-pkg".into(), Some("1.0".into()));
        added.licenses.insert("AGPL-3.0-only".into());

        let diff = Diff {
            added: vec![added],
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::LicenseChanged]));
    }

    #[test]
    fn test_check_fail_on_license_changed_added_component_without_license() {
        use sbom_diff::Diff;

        let added = Component::new("new-pkg".into(), Some("1.0".into()));

        let diff = Diff {
            added: vec![added],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::LicenseChanged]));
    }

    #[test]
    fn test_check_fail_on_license_changed_empty_diff() {
        use sbom_diff::Diff;

        let diff = Diff::default();
        assert!(!check_fail_on(&diff, &[FailOn::LicenseChanged]));
    }

    #[test]
    fn test_check_fail_on_license_changed_license_dropped() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};
        use std::collections::BTreeSet;

        let mut old = Component::new("pkg".into(), Some("1.0".into()));
        old.licenses.insert("MIT".into());
        let new = Component::new("pkg".into(), Some("1.0".into()));

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::License(
                    BTreeSet::from(["MIT".into()]),
                    BTreeSet::new(),
                )],
            }],
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::LicenseChanged]));
    }

    #[test]
    fn test_check_fail_on_license_changed_combined_with_other_conditions() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};
        use std::collections::BTreeSet;

        let mut old = Component::new("pkg".into(), Some("1.0".into()));
        old.licenses.insert("MIT".into());
        let mut new = Component::new("pkg".into(), Some("1.0".into()));
        new.licenses.insert("GPL-3.0-only".into());

        let diff = Diff {
            added: vec![Component::new("new-pkg".into(), Some("1.0".into()))],
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::License(
                    BTreeSet::from(["MIT".into()]),
                    BTreeSet::from(["GPL-3.0-only".into()]),
                )],
            }],
            ..Diff::default()
        };

        assert!(check_fail_on(
            &diff,
            &[FailOn::AddedComponents, FailOn::LicenseChanged]
        ));
        // LicenseChanged alone should fire (changed license)
        assert!(check_fail_on(&diff, &[FailOn::LicenseChanged]));
        // AddedComponents alone should fire (new-pkg)
        assert!(check_fail_on(&diff, &[FailOn::AddedComponents]));
    }

    #[test]
    fn test_check_fail_on_metadata_changed() {
        use sbom_diff::{Diff, MetadataChange};

        let diff = Diff {
            metadata_changed: Some(MetadataChange {
                timestamp: Some((Some("2024-01-01".into()), Some("2024-01-02".into()))),
                tools: None,
                authors: None,
            }),
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::MetadataChanged]));
    }

    #[test]
    fn test_check_fail_on_metadata_changed_no_change() {
        use sbom_diff::Diff;

        let diff = Diff::default();
        assert!(!check_fail_on(&diff, &[FailOn::MetadataChanged]));
    }

    #[test]
    fn test_check_fail_on_metadata_changed_tools_only() {
        use sbom_diff::{Diff, MetadataChange};

        let diff = Diff {
            metadata_changed: Some(MetadataChange {
                timestamp: None,
                tools: Some((vec!["syft".into()], vec!["trivy".into()])),
                authors: None,
            }),
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::MetadataChanged]));
    }

    #[test]
    fn test_check_fail_on_metadata_changed_does_not_trigger_other_gates() {
        use sbom_diff::{Diff, MetadataChange};

        let diff = Diff {
            metadata_changed: Some(MetadataChange {
                timestamp: Some((Some("2024-01-01".into()), Some("2024-01-02".into()))),
                tools: Some((vec!["syft".into()], vec!["trivy".into()])),
                authors: Some((vec!["alice".into()], vec!["bob".into()])),
            }),
            ..Diff::default()
        };

        // only MetadataChanged should trigger, not other gates
        assert!(!check_fail_on(&diff, &[FailOn::AddedComponents]));
        assert!(!check_fail_on(&diff, &[FailOn::RemovedComponents]));
        assert!(!check_fail_on(&diff, &[FailOn::ChangedComponents]));
        assert!(!check_fail_on(&diff, &[FailOn::Deps]));
        assert!(!check_fail_on(&diff, &[FailOn::LicenseChanged]));
        assert!(!check_fail_on(&diff, &[FailOn::MissingHashes]));
        assert!(check_fail_on(&diff, &[FailOn::MetadataChanged]));
    }

    #[test]
    fn test_check_fail_on_metadata_changed_combined() {
        use sbom_diff::{Diff, MetadataChange};

        let diff = Diff {
            added: vec![Component::new("new-pkg".into(), Some("1.0".into()))],
            metadata_changed: Some(MetadataChange {
                timestamp: Some((Some("2024-01-01".into()), Some("2024-01-02".into()))),
                tools: None,
                authors: None,
            }),
            ..Diff::default()
        };

        assert!(check_fail_on(
            &diff,
            &[FailOn::AddedComponents, FailOn::MetadataChanged]
        ));
    }

    #[test]
    fn test_check_fail_on_version_downgrade() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let old = Component::new("pkg".into(), Some("2.0.0".into()));
        let new = Component::new("pkg".into(), Some("1.5.0".into()));

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Version(
                    Some("2.0.0".into()),
                    Some("1.5.0".into()),
                )],
            }],
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::VersionDowngrade]));
    }

    #[test]
    fn test_check_fail_on_version_downgrade_upgrade_no_violation() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let old = Component::new("pkg".into(), Some("1.0.0".into()));
        let new = Component::new("pkg".into(), Some("2.0.0".into()));

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Version(
                    Some("1.0.0".into()),
                    Some("2.0.0".into()),
                )],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::VersionDowngrade]));
    }

    #[test]
    fn test_check_fail_on_version_downgrade_empty_diff() {
        use sbom_diff::Diff;

        let diff = Diff::default();
        assert!(!check_fail_on(&diff, &[FailOn::VersionDowngrade]));
    }

    #[test]
    fn test_check_fail_on_version_downgrade_no_version_change() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        // only license changed, no version change
        let old = Component::new("pkg".into(), Some("1.0.0".into()));
        let new = Component::new("pkg".into(), Some("1.0.0".into()));

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Supplier(
                    Some("Old Corp".into()),
                    Some("New Corp".into()),
                )],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::VersionDowngrade]));
    }

    #[test]
    fn test_check_fail_on_version_downgrade_version_added() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        // version went from None to Some — not a downgrade
        let old = Component::new("pkg".into(), None);
        let new = Component::new("pkg".into(), Some("1.0.0".into()));

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old,
                new,
                changes: vec![FieldChange::Version(None, Some("1.0.0".into()))],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::VersionDowngrade]));
    }

    #[test]
    fn test_check_fail_on_version_downgrade_does_not_trigger_other_gates() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let old = Component::new("pkg".into(), Some("2.0.0".into()));
        let new = Component::new("pkg".into(), Some("1.0.0".into()));

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Version(
                    Some("2.0.0".into()),
                    Some("1.0.0".into()),
                )],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::AddedComponents]));
        assert!(!check_fail_on(&diff, &[FailOn::RemovedComponents]));
        assert!(!check_fail_on(&diff, &[FailOn::MissingHashes]));
        assert!(!check_fail_on(&diff, &[FailOn::Deps]));
        assert!(!check_fail_on(&diff, &[FailOn::LicenseChanged]));
        assert!(!check_fail_on(&diff, &[FailOn::MetadataChanged]));
        // ChangedComponents should still fire
        assert!(check_fail_on(&diff, &[FailOn::ChangedComponents]));
        // VersionDowngrade should fire
        assert!(check_fail_on(&diff, &[FailOn::VersionDowngrade]));
    }

    #[test]
    fn test_check_fail_on_supplier_changed() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let mut old = Component::new("pkg".into(), Some("1.0.0".into()));
        old.supplier = Some("Acme Corp".into());
        let mut new = Component::new("pkg".into(), Some("1.0.0".into()));
        new.supplier = Some("Evil Corp".into());

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Supplier(
                    Some("Acme Corp".into()),
                    Some("Evil Corp".into()),
                )],
            }],
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::SupplierChanged]));
    }

    #[test]
    fn test_check_fail_on_supplier_changed_no_change() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let old = Component::new("pkg".into(), Some("1.0.0".into()));
        let new = Component::new("pkg".into(), Some("2.0.0".into()));

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old,
                new,
                changes: vec![FieldChange::Version(
                    Some("1.0.0".into()),
                    Some("2.0.0".into()),
                )],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::SupplierChanged]));
    }

    #[test]
    fn test_check_fail_on_supplier_changed_empty_diff() {
        use sbom_diff::Diff;

        let diff = Diff::default();
        assert!(!check_fail_on(&diff, &[FailOn::SupplierChanged]));
    }

    #[test]
    fn test_check_fail_on_supplier_changed_supplier_added() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let old = Component::new("pkg".into(), Some("1.0.0".into()));
        let mut new = Component::new("pkg".into(), Some("1.0.0".into()));
        new.supplier = Some("New Corp".into());

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Supplier(None, Some("New Corp".into()))],
            }],
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::SupplierChanged]));
    }

    #[test]
    fn test_check_fail_on_supplier_changed_supplier_removed() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let mut old = Component::new("pkg".into(), Some("1.0.0".into()));
        old.supplier = Some("Old Corp".into());
        let new = Component::new("pkg".into(), Some("1.0.0".into()));

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Supplier(Some("Old Corp".into()), None)],
            }],
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::SupplierChanged]));
    }

    #[test]
    fn test_check_fail_on_supplier_changed_added_component_with_supplier() {
        use sbom_diff::Diff;

        let mut added = Component::new("new-pkg".into(), Some("1.0.0".into()));
        added.supplier = Some("Some Corp".into());

        let diff = Diff {
            added: vec![added],
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::SupplierChanged]));
    }

    #[test]
    fn test_check_fail_on_supplier_changed_added_component_without_supplier() {
        use sbom_diff::Diff;

        let added = Component::new("new-pkg".into(), Some("1.0.0".into()));

        let diff = Diff {
            added: vec![added],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::SupplierChanged]));
    }

    #[test]
    fn test_check_fail_on_supplier_changed_does_not_trigger_other_gates() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let mut old = Component::new("pkg".into(), Some("1.0.0".into()));
        old.supplier = Some("Acme Corp".into());
        let mut new = Component::new("pkg".into(), Some("1.0.0".into()));
        new.supplier = Some("Evil Corp".into());

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Supplier(
                    Some("Acme Corp".into()),
                    Some("Evil Corp".into()),
                )],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::AddedComponents]));
        assert!(!check_fail_on(&diff, &[FailOn::RemovedComponents]));
        assert!(!check_fail_on(&diff, &[FailOn::MissingHashes]));
        assert!(!check_fail_on(&diff, &[FailOn::Deps]));
        assert!(!check_fail_on(&diff, &[FailOn::LicenseChanged]));
        assert!(!check_fail_on(&diff, &[FailOn::MetadataChanged]));
        assert!(!check_fail_on(&diff, &[FailOn::VersionDowngrade]));
        // ChangedComponents should still fire
        assert!(check_fail_on(&diff, &[FailOn::ChangedComponents]));
        // SupplierChanged should fire
        assert!(check_fail_on(&diff, &[FailOn::SupplierChanged]));
    }

    #[test]
    fn test_check_fail_on_hash_algorithm_downgrade() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let mut old = Component::new("pkg".into(), Some("1.0.0".into()));
        old.hashes.insert("sha-256".into(), "abc".into());
        let mut new = Component::new("pkg".into(), Some("1.0.0".into()));
        new.hashes.insert("md5".into(), "def".into());

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Hashes(old.hashes.clone(), new.hashes.clone())],
            }],
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::HashAlgorithmDowngrade]));
    }

    #[test]
    fn test_check_fail_on_hash_algorithm_downgrade_upgrade_no_violation() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let mut old = Component::new("pkg".into(), Some("1.0.0".into()));
        old.hashes.insert("sha-1".into(), "abc".into());
        let mut new = Component::new("pkg".into(), Some("1.0.0".into()));
        new.hashes.insert("sha-256".into(), "def".into());

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Hashes(old.hashes.clone(), new.hashes.clone())],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::HashAlgorithmDowngrade]));
    }

    #[test]
    fn test_check_fail_on_hash_algorithm_downgrade_same_algorithm() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let mut old = Component::new("pkg".into(), Some("1.0.0".into()));
        old.hashes.insert("sha-256".into(), "abc".into());
        let mut new = Component::new("pkg".into(), Some("1.0.0".into()));
        new.hashes.insert("sha-256".into(), "def".into());

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Hashes(old.hashes.clone(), new.hashes.clone())],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::HashAlgorithmDowngrade]));
    }

    #[test]
    fn test_check_fail_on_hash_algorithm_downgrade_empty_diff() {
        use sbom_diff::Diff;

        let diff = Diff::default();
        assert!(!check_fail_on(&diff, &[FailOn::HashAlgorithmDowngrade]));
    }

    #[test]
    fn test_check_fail_on_hash_algorithm_downgrade_no_hash_change() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        // only version changed, no hash change
        let old = Component::new("pkg".into(), Some("1.0.0".into()));
        let new = Component::new("pkg".into(), Some("2.0.0".into()));

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old,
                new,
                changes: vec![FieldChange::Version(
                    Some("1.0.0".into()),
                    Some("2.0.0".into()),
                )],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::HashAlgorithmDowngrade]));
    }

    #[test]
    fn test_check_fail_on_hash_algorithm_downgrade_dropped_strongest() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        // old has SHA-256 + MD5, new has only MD5
        let mut old = Component::new("pkg".into(), Some("1.0.0".into()));
        old.hashes.insert("sha-256".into(), "abc".into());
        old.hashes.insert("md5".into(), "xyz".into());
        let mut new = Component::new("pkg".into(), Some("1.0.0".into()));
        new.hashes.insert("md5".into(), "def".into());

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Hashes(old.hashes.clone(), new.hashes.clone())],
            }],
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::HashAlgorithmDowngrade]));
    }

    #[test]
    fn test_check_fail_on_hash_algorithm_downgrade_hashes_dropped_entirely() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};
        use std::collections::BTreeMap;

        // old has SHA-256, new has no hashes — should NOT trigger
        // (missing-hashes gate handles this)
        let mut old = Component::new("pkg".into(), Some("1.0.0".into()));
        old.hashes.insert("sha-256".into(), "abc".into());
        let new = Component::new("pkg".into(), Some("1.0.0".into()));

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Hashes(old.hashes.clone(), BTreeMap::new())],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::HashAlgorithmDowngrade]));
    }

    #[test]
    fn test_check_fail_on_hash_algorithm_downgrade_does_not_trigger_other_gates() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let mut old = Component::new("pkg".into(), Some("1.0.0".into()));
        old.hashes.insert("sha-256".into(), "abc".into());
        let mut new = Component::new("pkg".into(), Some("1.0.0".into()));
        new.hashes.insert("md5".into(), "def".into());

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Hashes(old.hashes.clone(), new.hashes.clone())],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::AddedComponents]));
        assert!(!check_fail_on(&diff, &[FailOn::RemovedComponents]));
        assert!(!check_fail_on(&diff, &[FailOn::MissingHashes]));
        assert!(!check_fail_on(&diff, &[FailOn::Deps]));
        assert!(!check_fail_on(&diff, &[FailOn::LicenseChanged]));
        assert!(!check_fail_on(&diff, &[FailOn::MetadataChanged]));
        assert!(!check_fail_on(&diff, &[FailOn::VersionDowngrade]));
        assert!(!check_fail_on(&diff, &[FailOn::SupplierChanged]));
        // ChangedComponents should still fire
        assert!(check_fail_on(&diff, &[FailOn::ChangedComponents]));
        // HashAlgorithmDowngrade should fire
        assert!(check_fail_on(&diff, &[FailOn::HashAlgorithmDowngrade]));
    }

    #[test]
    fn test_check_cyclic_dependencies_with_cycle() {
        use sbom_model::DependencyKind;

        let mut sbom = Sbom::default();
        let c1 = Component::new("a".into(), Some("1".into()));
        let c2 = Component::new("b".into(), Some("1".into()));
        let id1 = c1.id.clone();
        let id2 = c2.id.clone();
        sbom.components.insert(id1.clone(), c1);
        sbom.components.insert(id2.clone(), c2);

        // a -> b -> a
        sbom.dependencies
            .entry(id1.clone())
            .or_default()
            .insert(id2.clone(), DependencyKind::Runtime);
        sbom.dependencies
            .entry(id2.clone())
            .or_default()
            .insert(id1.clone(), DependencyKind::Runtime);

        assert!(check_cyclic_dependencies(
            &sbom,
            &[FailOn::CyclicDependency]
        ));
    }

    #[test]
    fn test_check_cyclic_dependencies_no_cycle() {
        use sbom_model::DependencyKind;

        let mut sbom = Sbom::default();
        let c1 = Component::new("a".into(), Some("1".into()));
        let c2 = Component::new("b".into(), Some("1".into()));
        let id1 = c1.id.clone();
        let id2 = c2.id.clone();
        sbom.components.insert(id1.clone(), c1);
        sbom.components.insert(id2.clone(), c2);

        // a -> b (no cycle)
        sbom.dependencies
            .entry(id1.clone())
            .or_default()
            .insert(id2.clone(), DependencyKind::Runtime);

        assert!(!check_cyclic_dependencies(
            &sbom,
            &[FailOn::CyclicDependency]
        ));
    }

    #[test]
    fn test_check_cyclic_dependencies_not_requested() {
        use sbom_model::DependencyKind;

        let mut sbom = Sbom::default();
        let c1 = Component::new("a".into(), Some("1".into()));
        let c2 = Component::new("b".into(), Some("1".into()));
        let id1 = c1.id.clone();
        let id2 = c2.id.clone();
        sbom.components.insert(id1.clone(), c1);
        sbom.components.insert(id2.clone(), c2);

        // a -> b -> a (cycle exists but gate not requested)
        sbom.dependencies
            .entry(id1.clone())
            .or_default()
            .insert(id2.clone(), DependencyKind::Runtime);
        sbom.dependencies
            .entry(id2.clone())
            .or_default()
            .insert(id1.clone(), DependencyKind::Runtime);

        // not in fail_on list — should return false
        assert!(!check_cyclic_dependencies(
            &sbom,
            &[FailOn::AddedComponents]
        ));
    }

    #[test]
    fn test_check_cyclic_dependencies_does_not_trigger_other_gates() {
        use sbom_diff::Diff;

        // cyclic-dependency is checked on the SBOM, not the diff,
        // so it should never trigger via check_fail_on
        let diff = Diff::default();
        assert!(!check_fail_on(&diff, &[FailOn::CyclicDependency]));
    }
}
