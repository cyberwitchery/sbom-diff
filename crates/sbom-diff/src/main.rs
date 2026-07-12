mod format;

use anyhow::Context;
use clap::{Parser, ValueEnum};
use format::{load_sbom, Format};
use sbom_diff::{
    renderer::{
        format_option, format_set, CsvRenderer, JsonRenderer, MarkdownRenderer, RenderOptions,
        Renderer, SarifRenderer, SummaryRenderer, TextRenderer,
    },
    Differ, Field, FieldChange,
};
use sbom_model::versions::is_version_downgrade;
use sbom_model::{copyleft_introduced, is_copyleft_license, is_hash_algorithm_downgrade};
use sbom_model::{ComponentId, DependencyKind, Sbom};
use std::collections::{BTreeSet, HashSet};
use std::fmt;
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
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, ValueEnum, Debug)]
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
    /// fail if a changed or added component introduces a copyleft license (e.g. GPL, AGPL) not present before.
    CopyleftAdded,
    /// fail if the new SBOM's dependency graph contains cycles.
    CyclicDependency,
    /// fail if any changed component's package URL (purl) changed.
    PurlChanged,
    /// fail if any changed component's ecosystem changed.
    EcosystemChanged,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Output {
    Text,
    Markdown,
    Json,
    Sarif,
    Csv,
}

/// a single policy violation detected by `--fail-on`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Violation {
    AddedComponent {
        id: ComponentId,
    },
    RemovedComponent {
        id: ComponentId,
    },
    ChangedComponent {
        id: ComponentId,
    },
    MissingHashesAdded {
        id: ComponentId,
    },
    MissingHashesDropped {
        id: ComponentId,
    },
    LicenseChanged {
        id: ComponentId,
        old: BTreeSet<String>,
        new: BTreeSet<String>,
    },
    LicenseIntroduced {
        id: ComponentId,
        licenses: Vec<String>,
    },
    CopyleftAdded {
        id: ComponentId,
        licenses: Vec<String>,
    },
    VersionDowngrade {
        id: ComponentId,
        old: String,
        new: String,
    },
    SupplierChanged {
        id: ComponentId,
        old: Option<String>,
        new: Option<String>,
    },
    SupplierIntroduced {
        id: ComponentId,
        supplier: String,
    },
    PurlChanged {
        id: ComponentId,
        old: Option<String>,
        new: Option<String>,
    },
    EcosystemChanged {
        id: ComponentId,
        old: Option<String>,
        new: Option<String>,
    },
    HashAlgorithmDowngrade {
        id: ComponentId,
        old_algos: Vec<String>,
        new_algos: Vec<String>,
    },
    DepsAdded {
        parent: ComponentId,
        child: ComponentId,
    },
    DepsRemoved {
        parent: ComponentId,
        child: ComponentId,
    },
    DepsKindChanged {
        parent: ComponentId,
        child: ComponentId,
        old_kind: DependencyKind,
        new_kind: DependencyKind,
    },
    MetadataTimestampChanged,
    MetadataToolsChanged,
    MetadataAuthorsChanged,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Violation::AddedComponent { id } => {
                write!(f, "added component {} (--fail-on added-components)", id)
            }
            Violation::RemovedComponent { id } => {
                write!(f, "removed component {} (--fail-on removed-components)", id)
            }
            Violation::ChangedComponent { id } => {
                write!(f, "changed component {} (--fail-on changed-components)", id)
            }
            Violation::MissingHashesAdded { id } => {
                write!(
                    f,
                    "added component {} has no hashes (--fail-on missing-hashes)",
                    id
                )
            }
            Violation::MissingHashesDropped { id } => {
                write!(
                    f,
                    "changed component {} dropped all hashes (--fail-on missing-hashes)",
                    id
                )
            }
            Violation::LicenseChanged { id, old, new } => {
                write!(
                    f,
                    "license changed on component {}: {} -> {} (--fail-on license-changed)",
                    id,
                    format_set(old),
                    format_set(new)
                )
            }
            Violation::LicenseIntroduced { id, licenses } => {
                write!(
                    f,
                    "added component {} introduces license(s): {} (--fail-on license-changed)",
                    id,
                    licenses.join(", ")
                )
            }
            Violation::CopyleftAdded { id, licenses } => {
                write!(
                    f,
                    "copyleft license introduced on component {}: {} (--fail-on copyleft-added)",
                    id,
                    licenses.join(", ")
                )
            }
            Violation::VersionDowngrade { id, old, new } => {
                write!(
                    f,
                    "version downgrade on component {}: {} -> {} (--fail-on version-downgrade)",
                    id, old, new
                )
            }
            Violation::SupplierChanged { id, old, new } => {
                write!(
                    f,
                    "supplier changed on component {}: {} -> {} (--fail-on supplier-changed)",
                    id,
                    format_option(old),
                    format_option(new)
                )
            }
            Violation::SupplierIntroduced { id, supplier } => {
                write!(
                    f,
                    "added component {} has supplier: {} (--fail-on supplier-changed)",
                    id, supplier
                )
            }
            Violation::PurlChanged { id, old, new } => {
                write!(
                    f,
                    "purl changed on component {}: {} -> {} (--fail-on purl-changed)",
                    id,
                    format_option(old),
                    format_option(new)
                )
            }
            Violation::EcosystemChanged { id, old, new } => {
                write!(
                    f,
                    "ecosystem changed on component {}: {} -> {} (--fail-on ecosystem-changed)",
                    id,
                    format_option(old),
                    format_option(new)
                )
            }
            Violation::HashAlgorithmDowngrade {
                id,
                old_algos,
                new_algos,
            } => {
                write!(
                    f,
                    "hash algorithm downgrade on component {}: [{}] -> [{}] (--fail-on hash-algorithm-downgrade)",
                    id,
                    old_algos.join(", "),
                    new_algos.join(", "),
                )
            }
            Violation::DepsAdded { parent, child } => {
                write!(
                    f,
                    "added dependency edge {} -> {} (--fail-on deps)",
                    parent, child
                )
            }
            Violation::DepsRemoved { parent, child } => {
                write!(
                    f,
                    "removed dependency edge {} -> {} (--fail-on deps)",
                    parent, child
                )
            }
            Violation::DepsKindChanged {
                parent,
                child,
                old_kind,
                new_kind,
            } => {
                write!(
                    f,
                    "dependency edge {} -> {} changed kind: {} -> {} (--fail-on deps)",
                    parent, child, old_kind, new_kind
                )
            }
            Violation::MetadataTimestampChanged => {
                write!(
                    f,
                    "document metadata timestamp changed (--fail-on metadata-changed)"
                )
            }
            Violation::MetadataToolsChanged => {
                write!(
                    f,
                    "document metadata tools changed (--fail-on metadata-changed)"
                )
            }
            Violation::MetadataAuthorsChanged => {
                write!(
                    f,
                    "document metadata authors changed (--fail-on metadata-changed)"
                )
            }
        }
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    for w in only_masked_gate_warnings(&args.only, &args.fail_on) {
        eprintln!("warning: {w}");
    }

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

    let violations = collect_violations(&diff, &args.fail_on);
    for v in &violations {
        eprintln!("error: {v}");
    }

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

    if !violations.is_empty() || cycle_violation {
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

/// collects all policy violations from a diff in a single pass per collection.
///
/// instead of iterating `diff.changed` once per condition, builds a set of
/// active conditions and checks all of them in one traversal. returns
/// structured violations the caller can inspect, format, or count.
fn collect_violations(diff: &sbom_diff::Diff, fail_on: &[FailOn]) -> Vec<Violation> {
    let active: HashSet<FailOn> = fail_on.iter().copied().collect();
    if active.is_empty() {
        return Vec::new();
    }

    let mut violations = Vec::new();

    let check_added = active.contains(&FailOn::AddedComponents);
    let check_missing_hashes = active.contains(&FailOn::MissingHashes);
    let check_license_changed = active.contains(&FailOn::LicenseChanged);
    let check_copyleft_added = active.contains(&FailOn::CopyleftAdded);
    let check_supplier_changed = active.contains(&FailOn::SupplierChanged);
    let check_purl_changed = active.contains(&FailOn::PurlChanged);
    let check_ecosystem_changed = active.contains(&FailOn::EcosystemChanged);

    for comp in &diff.added {
        if check_added {
            violations.push(Violation::AddedComponent {
                id: comp.id.clone(),
            });
        }
        if check_missing_hashes && comp.hashes.is_empty() {
            violations.push(Violation::MissingHashesAdded {
                id: comp.id.clone(),
            });
        }
        if check_license_changed && !comp.licenses.is_empty() {
            violations.push(Violation::LicenseIntroduced {
                id: comp.id.clone(),
                licenses: comp.licenses.iter().cloned().collect(),
            });
        }
        if check_copyleft_added {
            // an added component has no prior licenses, so every copyleft id it
            // carries is newly introduced.
            let introduced: Vec<String> = comp
                .licenses
                .iter()
                .filter(|&l| is_copyleft_license(l))
                .cloned()
                .collect();
            if !introduced.is_empty() {
                violations.push(Violation::CopyleftAdded {
                    id: comp.id.clone(),
                    licenses: introduced,
                });
            }
        }
        if check_supplier_changed && comp.supplier.is_some() {
            violations.push(Violation::SupplierIntroduced {
                id: comp.id.clone(),
                supplier: comp.supplier.clone().unwrap(),
            });
        }
    }

    if active.contains(&FailOn::RemovedComponents) {
        for comp in &diff.removed {
            violations.push(Violation::RemovedComponent {
                id: comp.id.clone(),
            });
        }
    }

    let check_changed = active.contains(&FailOn::ChangedComponents);
    let check_version_downgrade = active.contains(&FailOn::VersionDowngrade);
    let check_hash_downgrade = active.contains(&FailOn::HashAlgorithmDowngrade);
    let any_field_check = check_missing_hashes
        || check_license_changed
        || check_copyleft_added
        || check_version_downgrade
        || check_supplier_changed
        || check_hash_downgrade
        || check_purl_changed
        || check_ecosystem_changed;

    for change in &diff.changed {
        if check_changed {
            violations.push(Violation::ChangedComponent {
                id: change.id.clone(),
            });
        }
        if check_missing_hashes && !change.old.hashes.is_empty() && change.new.hashes.is_empty() {
            violations.push(Violation::MissingHashesDropped {
                id: change.id.clone(),
            });
        }
        if any_field_check {
            for fc in &change.changes {
                match fc {
                    FieldChange::License(old, new)
                        if check_license_changed || check_copyleft_added =>
                    {
                        if check_license_changed {
                            violations.push(Violation::LicenseChanged {
                                id: change.id.clone(),
                                old: old.clone(),
                                new: new.clone(),
                            });
                        }
                        if check_copyleft_added && copyleft_introduced(old, new) {
                            let introduced: Vec<String> = new
                                .iter()
                                .filter(|&l| is_copyleft_license(l) && !old.contains(l))
                                .cloned()
                                .collect();
                            violations.push(Violation::CopyleftAdded {
                                id: change.id.clone(),
                                licenses: introduced,
                            });
                        }
                    }
                    FieldChange::Version(Some(old_ver), Some(new_ver))
                        if check_version_downgrade && is_version_downgrade(old_ver, new_ver) =>
                    {
                        violations.push(Violation::VersionDowngrade {
                            id: change.id.clone(),
                            old: old_ver.clone(),
                            new: new_ver.clone(),
                        });
                    }
                    FieldChange::Supplier(old_sup, new_sup) if check_supplier_changed => {
                        violations.push(Violation::SupplierChanged {
                            id: change.id.clone(),
                            old: old_sup.clone(),
                            new: new_sup.clone(),
                        });
                    }
                    FieldChange::Purl(old_purl, new_purl) if check_purl_changed => {
                        violations.push(Violation::PurlChanged {
                            id: change.id.clone(),
                            old: old_purl.clone(),
                            new: new_purl.clone(),
                        });
                    }
                    FieldChange::Ecosystem(old_eco, new_eco) if check_ecosystem_changed => {
                        violations.push(Violation::EcosystemChanged {
                            id: change.id.clone(),
                            old: old_eco.clone(),
                            new: new_eco.clone(),
                        });
                    }
                    FieldChange::Hashes(old_hashes, new_hashes)
                        if check_hash_downgrade
                            && is_hash_algorithm_downgrade(old_hashes, new_hashes) =>
                    {
                        violations.push(Violation::HashAlgorithmDowngrade {
                            id: change.id.clone(),
                            old_algos: old_hashes.keys().cloned().collect(),
                            new_algos: new_hashes.keys().cloned().collect(),
                        });
                    }
                    _ => {}
                }
            }
        }
    }

    if active.contains(&FailOn::Deps) {
        for edge in &diff.edge_diffs {
            for child in edge.added.keys() {
                violations.push(Violation::DepsAdded {
                    parent: edge.parent.clone(),
                    child: child.clone(),
                });
            }
            for child in edge.removed.keys() {
                violations.push(Violation::DepsRemoved {
                    parent: edge.parent.clone(),
                    child: child.clone(),
                });
            }
            for (child, (old_kind, new_kind)) in &edge.kind_changed {
                violations.push(Violation::DepsKindChanged {
                    parent: edge.parent.clone(),
                    child: child.clone(),
                    old_kind: *old_kind,
                    new_kind: *new_kind,
                });
            }
        }
    }

    if active.contains(&FailOn::MetadataChanged) {
        if let Some(mc) = &diff.metadata_changed {
            if mc.timestamp.is_some() {
                violations.push(Violation::MetadataTimestampChanged);
            }
            if mc.tools.is_some() {
                violations.push(Violation::MetadataToolsChanged);
            }
            if mc.authors.is_some() {
                violations.push(Violation::MetadataAuthorsChanged);
            }
        }
    }

    // CyclicDependency is handled separately before diffing
    violations
}

/// the CLI value name of a `clap` enum variant (e.g. `Field::Version` -> "version").
fn value_name<T: ValueEnum>(value: &T) -> String {
    value
        .to_possible_value()
        .map(|pv| pv.get_name().to_owned())
        .unwrap_or_default()
}

/// the diff fields a `--fail-on` gate must observe to fire. `--only` filters the
/// fields the diff computes, so excluding one of these leaves the gate reading a
/// diff with its evidence removed. gates that read structural collections
/// (added/removed components, metadata, cycles) are unaffected and map to `&[]`.
fn gate_field_dependencies(gate: FailOn) -> &'static [Field] {
    match gate {
        FailOn::VersionDowngrade => &[Field::Version],
        FailOn::LicenseChanged => &[Field::License],
        FailOn::CopyleftAdded => &[Field::License],
        FailOn::SupplierChanged => &[Field::Supplier],
        FailOn::PurlChanged => &[Field::Purl],
        FailOn::EcosystemChanged => &[Field::Ecosystem],
        FailOn::HashAlgorithmDowngrade | FailOn::MissingHashes => &[Field::Hashes],
        FailOn::Deps => &[Field::Deps],
        // a component only counts as "changed" when one of its compared fields
        // differs, so any excluded field can hide a change from this gate.
        FailOn::ChangedComponents => &[
            Field::Version,
            Field::License,
            Field::Supplier,
            Field::Purl,
            Field::Description,
            Field::Hashes,
            Field::Ecosystem,
        ],
        FailOn::AddedComponents
        | FailOn::RemovedComponents
        | FailOn::MetadataChanged
        | FailOn::CyclicDependency => &[],
    }
}

/// warns when an active `--only` filter excludes a field that an active
/// `--fail-on` gate depends on. `--only` is documented as an output filter, but
/// it also narrows what the diff computes, so a gate whose field is excluded
/// reads a diff with no evidence and exits 0 — a silent CI/supply-chain bypass.
/// returns one line per affected gate (empty when `--only` is unused or nothing
/// conflicts); ordering is deterministic and gates are de-duplicated.
fn only_masked_gate_warnings(only: &[Field], fail_on: &[FailOn]) -> Vec<String> {
    if only.is_empty() {
        return Vec::new();
    }

    // `only` holds at most one entry per field, so a linear membership check is
    // cheaper than building a set (and `Field` is not `Hash`).
    let active: BTreeSet<FailOn> = fail_on.iter().copied().collect();

    let mut warnings = Vec::new();
    for gate in active {
        let excluded: Vec<Field> = gate_field_dependencies(gate)
            .iter()
            .copied()
            .filter(|f| !only.contains(f))
            .collect();
        if excluded.is_empty() {
            continue;
        }
        let noun = if excluded.len() == 1 {
            "field"
        } else {
            "fields"
        };
        let names = excluded
            .iter()
            .map(value_name)
            .collect::<Vec<_>>()
            .join(", ");
        warnings.push(format!(
            "--fail-on {} depends on the {} {} that --only excludes; the gate may silently pass",
            value_name(&gate),
            names,
            noun,
        ));
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbom_model::Component;

    #[test]
    fn gate_field_dependencies_maps_every_variant() {
        // field-dependent gates map to the field whose exclusion neuters them
        assert_eq!(
            gate_field_dependencies(FailOn::VersionDowngrade),
            &[Field::Version]
        );
        assert_eq!(
            gate_field_dependencies(FailOn::LicenseChanged),
            &[Field::License]
        );
        assert_eq!(
            gate_field_dependencies(FailOn::CopyleftAdded),
            &[Field::License]
        );
        assert_eq!(
            gate_field_dependencies(FailOn::SupplierChanged),
            &[Field::Supplier]
        );
        assert_eq!(gate_field_dependencies(FailOn::PurlChanged), &[Field::Purl]);
        assert_eq!(
            gate_field_dependencies(FailOn::EcosystemChanged),
            &[Field::Ecosystem]
        );
        assert_eq!(
            gate_field_dependencies(FailOn::HashAlgorithmDowngrade),
            &[Field::Hashes]
        );
        assert_eq!(
            gate_field_dependencies(FailOn::MissingHashes),
            &[Field::Hashes]
        );
        assert_eq!(gate_field_dependencies(FailOn::Deps), &[Field::Deps]);
        assert_eq!(gate_field_dependencies(FailOn::ChangedComponents).len(), 7);
        // structural gates read added/removed/metadata/cycles, not filtered fields
        assert!(gate_field_dependencies(FailOn::AddedComponents).is_empty());
        assert!(gate_field_dependencies(FailOn::RemovedComponents).is_empty());
        assert!(gate_field_dependencies(FailOn::MetadataChanged).is_empty());
        assert!(gate_field_dependencies(FailOn::CyclicDependency).is_empty());
    }

    #[test]
    fn no_only_filter_never_warns() {
        assert!(only_masked_gate_warnings(&[], &[FailOn::VersionDowngrade]).is_empty());
    }

    #[test]
    fn only_excluding_gate_field_warns() {
        let w = only_masked_gate_warnings(&[Field::License], &[FailOn::VersionDowngrade]);
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("--fail-on version-downgrade"));
        assert!(w[0].contains("version"));
        assert!(w[0].contains("--only"));
        assert!(w[0].contains("silently pass"));
    }

    #[test]
    fn only_including_gate_field_does_not_warn() {
        assert!(
            only_masked_gate_warnings(&[Field::Version], &[FailOn::VersionDowngrade]).is_empty()
        );
    }

    #[test]
    fn structural_gates_never_warn() {
        let gates = [
            FailOn::AddedComponents,
            FailOn::RemovedComponents,
            FailOn::MetadataChanged,
            FailOn::CyclicDependency,
        ];
        assert!(only_masked_gate_warnings(&[Field::License], &gates).is_empty());
    }

    #[test]
    fn deps_gate_warns_when_deps_excluded() {
        let w = only_masked_gate_warnings(&[Field::License], &[FailOn::Deps]);
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("--fail-on deps"));
        assert!(w[0].contains("silently pass"));
    }

    #[test]
    fn missing_hashes_warns_when_hashes_excluded_but_not_when_included() {
        let excluded = only_masked_gate_warnings(&[Field::Version], &[FailOn::MissingHashes]);
        assert_eq!(excluded.len(), 1);
        assert!(excluded[0].contains("missing-hashes"));
        assert!(excluded[0].contains("hashes"));
        assert!(only_masked_gate_warnings(&[Field::Hashes], &[FailOn::MissingHashes]).is_empty());
    }

    #[test]
    fn changed_components_lists_excluded_fields_only() {
        let w = only_masked_gate_warnings(&[Field::License], &[FailOn::ChangedComponents]);
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("changed-components"));
        assert!(w[0].contains("fields")); // plural: several fields excluded
        assert!(w[0].contains("version"));
        // license is included, so it must not appear in the excluded list
        assert!(!w[0].contains("license"));
    }

    #[test]
    fn multiple_gates_warn_deduplicated_and_ordered() {
        // a duplicate gate collapses to one warning; output is enum-order stable
        let w = only_masked_gate_warnings(
            &[Field::License],
            &[
                FailOn::VersionDowngrade,
                FailOn::Deps,
                FailOn::VersionDowngrade,
            ],
        );
        assert_eq!(w.len(), 2);
        assert!(w[0].contains("--fail-on deps"));
        assert!(w[1].contains("--fail-on version-downgrade"));
    }

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
    fn test_collect_violations_deps_with_removed_edges() {
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

        let vs = collect_violations(&diff, &[FailOn::Deps]);
        assert!(!vs.is_empty());
        assert!(vs
            .iter()
            .any(|v| matches!(v, Violation::DepsRemoved { .. })));
    }

    #[test]
    fn test_collect_violations_multiple_conditions() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![Component::new("new".into(), Some("1".into()))],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let vs = collect_violations(&diff, &[FailOn::AddedComponents, FailOn::MissingHashes]);
        assert!(!vs.is_empty());
        assert!(vs
            .iter()
            .any(|v| matches!(v, Violation::AddedComponent { .. })));
        assert!(vs
            .iter()
            .any(|v| matches!(v, Violation::MissingHashesAdded { .. })));
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
    fn test_collect_violations_added_components() {
        use sbom_diff::Diff;

        let mut diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::AddedComponents]).is_empty());

        diff.added
            .push(Component::new("new-pkg".into(), Some("1.0".into())));
        assert!(!collect_violations(&diff, &[FailOn::AddedComponents]).is_empty());
    }

    #[test]
    fn test_collect_violations_missing_hashes() {
        use sbom_diff::Diff;

        let mut diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::MissingHashes]).is_empty());

        diff.added
            .push(Component::new("new-pkg".into(), Some("1.0".into())));
        assert!(!collect_violations(&diff, &[FailOn::MissingHashes]).is_empty());

        diff.added[0].hashes.insert("sha256".into(), "abc".into());
        assert!(collect_violations(&diff, &[FailOn::MissingHashes]).is_empty());
    }

    #[test]
    fn test_collect_violations_missing_hashes_changed_component_dropped() {
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(!collect_violations(&diff, &[FailOn::MissingHashes]).is_empty());
    }

    #[test]
    fn test_collect_violations_missing_hashes_changed_component_kept() {
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::MissingHashes]).is_empty());
    }

    #[test]
    fn test_collect_violations_missing_hashes_changed_component_both_empty() {
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::MissingHashes]).is_empty());
    }

    #[test]
    fn test_collect_violations_deps() {
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

        assert!(collect_violations(&diff, &[FailOn::Deps]).is_empty());

        diff.edge_diffs.push(EdgeDiff {
            parent: ComponentId::new(None, &[("name", "parent")]),
            added: BTreeMap::from([(
                ComponentId::new(None, &[("name", "child")]),
                DependencyKind::Runtime,
            )]),
            removed: BTreeMap::new(),
            kind_changed: BTreeMap::new(),
        });
        assert!(!collect_violations(&diff, &[FailOn::Deps]).is_empty());
    }

    #[test]
    fn test_collect_violations_removed_components() {
        use sbom_diff::Diff;

        let mut diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::RemovedComponents]).is_empty());

        diff.removed
            .push(Component::new("old-pkg".into(), Some("1.0".into())));
        assert!(!collect_violations(&diff, &[FailOn::RemovedComponents]).is_empty());
    }

    #[test]
    fn test_collect_violations_changed_components() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let mut diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::ChangedComponents]).is_empty());

        let old = Component::new("pkg".into(), Some("1.0".into()));
        let new = Component::new("pkg".into(), Some("2.0".into()));
        diff.changed.push(ComponentChange {
            id: old.id.clone(),
            old: old.clone(),
            new,
            changes: vec![FieldChange::Version(Some("1.0".into()), Some("2.0".into()))],
            is_downgrade: false,
        });
        assert!(!collect_violations(&diff, &[FailOn::ChangedComponents]).is_empty());
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
                is_downgrade: false,
            }],
            edge_diffs: vec![],
            ..Diff::default()
        };

        assert!(collect_violations(
            &diff,
            &[
                FailOn::AddedComponents,
                FailOn::RemovedComponents,
                FailOn::MissingHashes,
                FailOn::Deps,
                FailOn::LicenseChanged,
            ]
        )
        .is_empty());
        // but ChangedComponents *should* trigger on description changes
        assert!(!collect_violations(&diff, &[FailOn::ChangedComponents]).is_empty());
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
    fn test_collect_violations_license_changed_on_changed_component() {
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(!collect_violations(&diff, &[FailOn::LicenseChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_license_changed_no_license_change() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let old = Component::new("pkg".into(), Some("1.0".into()));
        let new = Component::new("pkg".into(), Some("2.0".into()));

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old,
                new,
                changes: vec![FieldChange::Version(Some("1.0".into()), Some("2.0".into()))],
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::LicenseChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_license_changed_added_component_with_license() {
        use sbom_diff::Diff;

        let mut added = Component::new("new-pkg".into(), Some("1.0".into()));
        added.licenses.insert("AGPL-3.0-only".into());

        let diff = Diff {
            added: vec![added],
            ..Diff::default()
        };

        assert!(!collect_violations(&diff, &[FailOn::LicenseChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_license_changed_added_component_without_license() {
        use sbom_diff::Diff;

        let added = Component::new("new-pkg".into(), Some("1.0".into()));

        let diff = Diff {
            added: vec![added],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::LicenseChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_license_changed_empty_diff() {
        use sbom_diff::Diff;

        let diff = Diff::default();
        assert!(collect_violations(&diff, &[FailOn::LicenseChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_license_changed_license_dropped() {
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(!collect_violations(&diff, &[FailOn::LicenseChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_license_changed_combined_with_other_conditions() {
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(
            !collect_violations(&diff, &[FailOn::AddedComponents, FailOn::LicenseChanged])
                .is_empty()
        );
        // LicenseChanged alone should fire (changed license)
        assert!(!collect_violations(&diff, &[FailOn::LicenseChanged]).is_empty());
        // AddedComponents alone should fire (new-pkg)
        assert!(!collect_violations(&diff, &[FailOn::AddedComponents]).is_empty());
    }

    #[test]
    fn test_collect_violations_copyleft_added_changed_component() {
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        let vs = collect_violations(&diff, &[FailOn::CopyleftAdded]);
        assert!(vs.iter().any(|v| matches!(
            v,
            Violation::CopyleftAdded { licenses, .. } if licenses == &["GPL-3.0-only".to_string()]
        )));
    }

    #[test]
    fn test_collect_violations_copyleft_added_permissive_change_no_violation() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};
        use std::collections::BTreeSet;

        // a genuine license change that stays permissive must not fire
        let mut old = Component::new("pkg".into(), Some("1.0".into()));
        old.licenses.insert("MIT".into());
        let mut new = Component::new("pkg".into(), Some("1.0".into()));
        new.licenses.insert("Apache-2.0".into());

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::License(
                    BTreeSet::from(["MIT".into()]),
                    BTreeSet::from(["Apache-2.0".into()]),
                )],
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::CopyleftAdded]).is_empty());
    }

    #[test]
    fn test_collect_violations_copyleft_added_carried_over_no_violation() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};
        use std::collections::BTreeSet;

        // copyleft license present on both sides is not a new introduction
        let mut old = Component::new("pkg".into(), Some("1.0".into()));
        old.licenses.insert("MIT".into());
        old.licenses.insert("GPL-3.0-only".into());
        let mut new = Component::new("pkg".into(), Some("1.0".into()));
        new.licenses.insert("GPL-3.0-only".into());

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::License(
                    BTreeSet::from(["GPL-3.0-only".into(), "MIT".into()]),
                    BTreeSet::from(["GPL-3.0-only".into()]),
                )],
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::CopyleftAdded]).is_empty());
    }

    #[test]
    fn test_collect_violations_copyleft_added_on_added_component() {
        use sbom_diff::Diff;

        let mut permissive = Component::new("perm-pkg".into(), Some("1.0".into()));
        permissive.licenses.insert("MIT".into());
        let mut copyleft = Component::new("copyleft-pkg".into(), Some("1.0".into()));
        copyleft.licenses.insert("AGPL-3.0-only".into());

        let diff = Diff {
            added: vec![permissive, copyleft.clone()],
            ..Diff::default()
        };

        let vs = collect_violations(&diff, &[FailOn::CopyleftAdded]);
        // only the copyleft component fires
        assert_eq!(vs.len(), 1);
        assert!(matches!(
            &vs[0],
            Violation::CopyleftAdded { id, licenses }
                if id == &copyleft.id && licenses == &["AGPL-3.0-only".to_string()]
        ));
    }

    #[test]
    fn test_collect_violations_copyleft_added_and_license_changed_both_fire() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};
        use std::collections::BTreeSet;

        // both gates read FieldChange::License; with both active, each must fire
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        let vs = collect_violations(&diff, &[FailOn::LicenseChanged, FailOn::CopyleftAdded]);
        assert!(vs
            .iter()
            .any(|v| matches!(v, Violation::LicenseChanged { .. })));
        assert!(vs
            .iter()
            .any(|v| matches!(v, Violation::CopyleftAdded { .. })));
    }

    #[test]
    fn test_collect_violations_copyleft_added_does_not_trigger_other_gates() {
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::VersionDowngrade]).is_empty());
        assert!(collect_violations(&diff, &[FailOn::SupplierChanged]).is_empty());
        assert!(collect_violations(&diff, &[FailOn::HashAlgorithmDowngrade]).is_empty());
        // ChangedComponents still fires on any change
        assert!(!collect_violations(&diff, &[FailOn::ChangedComponents]).is_empty());
        // CopyleftAdded fires
        assert!(!collect_violations(&diff, &[FailOn::CopyleftAdded]).is_empty());
    }

    #[test]
    fn test_collect_violations_metadata_changed() {
        use sbom_diff::{Diff, MetadataChange};

        let diff = Diff {
            metadata_changed: Some(MetadataChange {
                timestamp: Some((Some("2024-01-01".into()), Some("2024-01-02".into()))),
                tools: None,
                authors: None,
            }),
            ..Diff::default()
        };

        assert!(!collect_violations(&diff, &[FailOn::MetadataChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_metadata_changed_no_change() {
        use sbom_diff::Diff;

        let diff = Diff::default();
        assert!(collect_violations(&diff, &[FailOn::MetadataChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_metadata_changed_tools_only() {
        use sbom_diff::{Diff, MetadataChange};

        let diff = Diff {
            metadata_changed: Some(MetadataChange {
                timestamp: None,
                tools: Some((vec!["syft".into()], vec!["trivy".into()])),
                authors: None,
            }),
            ..Diff::default()
        };

        assert!(!collect_violations(&diff, &[FailOn::MetadataChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_metadata_changed_does_not_trigger_other_gates() {
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
        assert!(collect_violations(&diff, &[FailOn::AddedComponents]).is_empty());
        assert!(collect_violations(&diff, &[FailOn::RemovedComponents]).is_empty());
        assert!(collect_violations(&diff, &[FailOn::ChangedComponents]).is_empty());
        assert!(collect_violations(&diff, &[FailOn::Deps]).is_empty());
        assert!(collect_violations(&diff, &[FailOn::LicenseChanged]).is_empty());
        assert!(collect_violations(&diff, &[FailOn::MissingHashes]).is_empty());
        assert!(!collect_violations(&diff, &[FailOn::MetadataChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_metadata_changed_combined() {
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

        assert!(
            !collect_violations(&diff, &[FailOn::AddedComponents, FailOn::MetadataChanged])
                .is_empty()
        );
    }

    #[test]
    fn test_collect_violations_version_downgrade() {
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(!collect_violations(&diff, &[FailOn::VersionDowngrade]).is_empty());
    }

    #[test]
    fn test_collect_violations_version_downgrade_upgrade_no_violation() {
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::VersionDowngrade]).is_empty());
    }

    #[test]
    fn test_collect_violations_version_downgrade_empty_diff() {
        use sbom_diff::Diff;

        let diff = Diff::default();
        assert!(collect_violations(&diff, &[FailOn::VersionDowngrade]).is_empty());
    }

    #[test]
    fn test_collect_violations_version_downgrade_no_version_change() {
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::VersionDowngrade]).is_empty());
    }

    #[test]
    fn test_collect_violations_version_downgrade_version_added() {
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::VersionDowngrade]).is_empty());
    }

    #[test]
    fn test_collect_violations_version_downgrade_does_not_trigger_other_gates() {
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::AddedComponents]).is_empty());
        assert!(collect_violations(&diff, &[FailOn::RemovedComponents]).is_empty());
        assert!(collect_violations(&diff, &[FailOn::MissingHashes]).is_empty());
        assert!(collect_violations(&diff, &[FailOn::Deps]).is_empty());
        assert!(collect_violations(&diff, &[FailOn::LicenseChanged]).is_empty());
        assert!(collect_violations(&diff, &[FailOn::MetadataChanged]).is_empty());
        // ChangedComponents should still fire
        assert!(!collect_violations(&diff, &[FailOn::ChangedComponents]).is_empty());
        // VersionDowngrade should fire
        assert!(!collect_violations(&diff, &[FailOn::VersionDowngrade]).is_empty());
    }

    #[test]
    fn test_collect_violations_supplier_changed() {
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(!collect_violations(&diff, &[FailOn::SupplierChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_supplier_changed_no_change() {
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::SupplierChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_supplier_changed_empty_diff() {
        use sbom_diff::Diff;

        let diff = Diff::default();
        assert!(collect_violations(&diff, &[FailOn::SupplierChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_supplier_changed_supplier_added() {
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(!collect_violations(&diff, &[FailOn::SupplierChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_supplier_changed_supplier_removed() {
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(!collect_violations(&diff, &[FailOn::SupplierChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_supplier_changed_added_component_with_supplier() {
        use sbom_diff::Diff;

        let mut added = Component::new("new-pkg".into(), Some("1.0.0".into()));
        added.supplier = Some("Some Corp".into());

        let diff = Diff {
            added: vec![added],
            ..Diff::default()
        };

        assert!(!collect_violations(&diff, &[FailOn::SupplierChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_supplier_changed_added_component_without_supplier() {
        use sbom_diff::Diff;

        let added = Component::new("new-pkg".into(), Some("1.0.0".into()));

        let diff = Diff {
            added: vec![added],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::SupplierChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_supplier_changed_does_not_trigger_other_gates() {
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::AddedComponents]).is_empty());
        assert!(collect_violations(&diff, &[FailOn::RemovedComponents]).is_empty());
        assert!(collect_violations(&diff, &[FailOn::MissingHashes]).is_empty());
        assert!(collect_violations(&diff, &[FailOn::Deps]).is_empty());
        assert!(collect_violations(&diff, &[FailOn::LicenseChanged]).is_empty());
        assert!(collect_violations(&diff, &[FailOn::MetadataChanged]).is_empty());
        assert!(collect_violations(&diff, &[FailOn::VersionDowngrade]).is_empty());
        // ChangedComponents should still fire
        assert!(!collect_violations(&diff, &[FailOn::ChangedComponents]).is_empty());
        // SupplierChanged should fire
        assert!(!collect_violations(&diff, &[FailOn::SupplierChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_purl_changed() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let mut old = Component::new("pkg".into(), Some("1.0.0".into()));
        old.purl = Some("pkg:npm/pkg@1.0.0".into());
        let mut new = Component::new("pkg".into(), Some("1.0.0".into()));
        new.purl = Some("pkg:npm/pkg-typo@1.0.0".into());

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Purl(
                    Some("pkg:npm/pkg@1.0.0".into()),
                    Some("pkg:npm/pkg-typo@1.0.0".into()),
                )],
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        let violations = collect_violations(&diff, &[FailOn::PurlChanged]);
        assert_eq!(violations.len(), 1);
        assert!(matches!(violations[0], Violation::PurlChanged { .. }));
    }

    #[test]
    fn test_collect_violations_purl_changed_no_change() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        // only the version changed — the purl gate must not fire
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::PurlChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_ecosystem_changed() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let mut old = Component::new("pkg".into(), Some("1.0.0".into()));
        old.ecosystem = Some("npm".into());
        let mut new = Component::new("pkg".into(), Some("1.0.0".into()));
        new.ecosystem = Some("cargo".into());

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Ecosystem(
                    Some("npm".into()),
                    Some("cargo".into()),
                )],
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        let violations = collect_violations(&diff, &[FailOn::EcosystemChanged]);
        assert_eq!(violations.len(), 1);
        assert!(matches!(violations[0], Violation::EcosystemChanged { .. }));
    }

    #[test]
    fn test_collect_violations_ecosystem_changed_no_change() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        // only the version changed — the ecosystem gate must not fire
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::EcosystemChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_hash_algorithm_downgrade() {
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(!collect_violations(&diff, &[FailOn::HashAlgorithmDowngrade]).is_empty());
    }

    #[test]
    fn test_collect_violations_hash_algorithm_downgrade_upgrade_no_violation() {
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::HashAlgorithmDowngrade]).is_empty());
    }

    #[test]
    fn test_collect_violations_hash_algorithm_downgrade_same_algorithm() {
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::HashAlgorithmDowngrade]).is_empty());
    }

    #[test]
    fn test_collect_violations_hash_algorithm_downgrade_empty_diff() {
        use sbom_diff::Diff;

        let diff = Diff::default();
        assert!(collect_violations(&diff, &[FailOn::HashAlgorithmDowngrade]).is_empty());
    }

    #[test]
    fn test_collect_violations_hash_algorithm_downgrade_no_hash_change() {
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::HashAlgorithmDowngrade]).is_empty());
    }

    #[test]
    fn test_collect_violations_hash_algorithm_downgrade_dropped_strongest() {
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(!collect_violations(&diff, &[FailOn::HashAlgorithmDowngrade]).is_empty());
    }

    #[test]
    fn test_collect_violations_hash_algorithm_downgrade_hashes_dropped_entirely() {
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::HashAlgorithmDowngrade]).is_empty());
    }

    #[test]
    fn test_collect_violations_hash_algorithm_downgrade_does_not_trigger_other_gates() {
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
                is_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::AddedComponents]).is_empty());
        assert!(collect_violations(&diff, &[FailOn::RemovedComponents]).is_empty());
        assert!(collect_violations(&diff, &[FailOn::MissingHashes]).is_empty());
        assert!(collect_violations(&diff, &[FailOn::Deps]).is_empty());
        assert!(collect_violations(&diff, &[FailOn::LicenseChanged]).is_empty());
        assert!(collect_violations(&diff, &[FailOn::MetadataChanged]).is_empty());
        assert!(collect_violations(&diff, &[FailOn::VersionDowngrade]).is_empty());
        assert!(collect_violations(&diff, &[FailOn::SupplierChanged]).is_empty());
        // ChangedComponents should still fire
        assert!(!collect_violations(&diff, &[FailOn::ChangedComponents]).is_empty());
        // HashAlgorithmDowngrade should fire
        assert!(!collect_violations(&diff, &[FailOn::HashAlgorithmDowngrade]).is_empty());
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
        // so it should never trigger via collect_violations
        let diff = Diff::default();
        assert!(collect_violations(&diff, &[FailOn::CyclicDependency]).is_empty());
    }
}
