//! the gates a diff is checked against: the `--fail-on` conditions and the license policy.

use crate::renderer::{format_option, format_set, Labels};
use crate::{ComponentChange, Diff, DiffOptions, Differ, FieldChange};
use sbom_model::{changed_checksums, copyleft_obligations_added, is_spdx_expression};
use sbom_model::{DependencyKind, LicenseRequirement, Licensing, Sbom};
use std::collections::{BTreeSet, HashSet};
use std::fmt;

/// conditions that trigger a non-zero exit code.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, clap::ValueEnum, Debug)]
pub enum FailOn {
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
    /// fail if any changed component's package URL (purl) changed other than in its version; a purl namespace swap is a removed and an added component instead.
    PurlChanged,
    /// fail if any changed component's ecosystem changed.
    EcosystemChanged,
    /// fail if a changed component's checksum differs under an algorithm both sides carry while its version is unchanged.
    ChecksumChanged,
}

/// a single policy violation, from a `--fail-on` gate or the license policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    AddedComponent {
        name: String,
    },
    RemovedComponent {
        name: String,
    },
    ChangedComponent {
        name: String,
    },
    MissingHashesAdded {
        name: String,
    },
    MissingHashesDropped {
        name: String,
    },
    LicenseChanged {
        name: String,
        old: BTreeSet<String>,
        new: BTreeSet<String>,
    },
    LicenseExpressionChanged {
        name: String,
        old: Option<String>,
        new: Option<String>,
    },
    LicenseIntroduced {
        name: String,
        licenses: Vec<String>,
    },
    CopyleftAdded {
        name: String,
        licenses: Vec<String>,
    },
    VersionDowngrade {
        name: String,
        old: String,
        new: String,
    },
    SupplierChanged {
        name: String,
        old: Option<String>,
        new: Option<String>,
    },
    SupplierIntroduced {
        name: String,
        supplier: String,
    },
    PurlChanged {
        name: String,
        old: Option<String>,
        new: Option<String>,
    },
    EcosystemChanged {
        name: String,
        old: Option<String>,
        new: Option<String>,
    },
    HashAlgorithmDowngrade {
        name: String,
        old_algos: Vec<String>,
        new_algos: Vec<String>,
    },
    ChecksumChanged {
        name: String,
        algorithm: String,
        old: String,
        new: String,
    },
    DepsAdded {
        parent: String,
        child: String,
    },
    DepsRemoved {
        parent: String,
        child: String,
    },
    DepsKindChanged {
        parent: String,
        child: String,
        old_kind: DependencyKind,
        new_kind: DependencyKind,
    },
    MetadataTimestampChanged,
    MetadataToolsChanged,
    MetadataAuthorsChanged,
    DependencyCycle {
        path: Vec<String>,
    },
    LicenseDenied {
        name: String,
        licenses: Vec<String>,
    },
    LicenseNotAllowed {
        name: String,
        licenses: Vec<String>,
    },
    NoLicenseInfo {
        name: String,
    },
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Violation::AddedComponent { name } => {
                write!(f, "added component {} (--fail-on added-components)", name)
            }
            Violation::RemovedComponent { name } => {
                write!(
                    f,
                    "removed component {} (--fail-on removed-components)",
                    name
                )
            }
            Violation::ChangedComponent { name } => {
                write!(
                    f,
                    "changed component {} (--fail-on changed-components)",
                    name
                )
            }
            Violation::MissingHashesAdded { name } => {
                write!(
                    f,
                    "added component {} has no hashes (--fail-on missing-hashes)",
                    name
                )
            }
            Violation::MissingHashesDropped { name } => {
                write!(
                    f,
                    "changed component {} dropped all hashes (--fail-on missing-hashes)",
                    name
                )
            }
            Violation::LicenseChanged { name, old, new } => {
                write!(
                    f,
                    "license changed on component {}: {} -> {} (--fail-on license-changed)",
                    name,
                    format_set(old),
                    format_set(new)
                )
            }
            Violation::LicenseExpressionChanged { name, old, new } => {
                write!(
                    f,
                    "license expression changed on component {}: {} -> {} (--fail-on license-changed)",
                    name,
                    format_option(old),
                    format_option(new)
                )
            }
            Violation::LicenseIntroduced { name, licenses } => {
                write!(
                    f,
                    "added component {} introduces license(s): {} (--fail-on license-changed)",
                    name,
                    licenses.join(", ")
                )
            }
            Violation::CopyleftAdded { name, licenses } => {
                write!(
                    f,
                    "copyleft license introduced on component {}: {} (--fail-on copyleft-added)",
                    name,
                    licenses.join(", ")
                )
            }
            Violation::VersionDowngrade { name, old, new } => {
                write!(
                    f,
                    "version downgrade on component {}: {} -> {} (--fail-on version-downgrade)",
                    name, old, new
                )
            }
            Violation::SupplierChanged { name, old, new } => {
                write!(
                    f,
                    "supplier changed on component {}: {} -> {} (--fail-on supplier-changed)",
                    name,
                    format_option(old),
                    format_option(new)
                )
            }
            Violation::SupplierIntroduced { name, supplier } => {
                write!(
                    f,
                    "added component {} has supplier: {} (--fail-on supplier-changed)",
                    name, supplier
                )
            }
            Violation::PurlChanged { name, old, new } => {
                write!(
                    f,
                    "purl changed on component {}: {} -> {} (--fail-on purl-changed)",
                    name,
                    format_option(old),
                    format_option(new)
                )
            }
            Violation::EcosystemChanged { name, old, new } => {
                write!(
                    f,
                    "ecosystem changed on component {}: {} -> {} (--fail-on ecosystem-changed)",
                    name,
                    format_option(old),
                    format_option(new)
                )
            }
            Violation::HashAlgorithmDowngrade {
                name,
                old_algos,
                new_algos,
            } => {
                write!(
                    f,
                    "hash algorithm downgrade on component {}: [{}] -> [{}] (--fail-on hash-algorithm-downgrade)",
                    name,
                    old_algos.join(", "),
                    new_algos.join(", "),
                )
            }
            Violation::ChecksumChanged {
                name,
                algorithm,
                old,
                new,
            } => {
                write!(
                    f,
                    "checksum changed on component {} without a version change: {} {} -> {} (--fail-on checksum-changed)",
                    name, algorithm, old, new
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
            Violation::DependencyCycle { path } => {
                write!(
                    f,
                    "dependency cycle detected: {} (--fail-on cyclic-dependency)",
                    path.join(" -> ")
                )
            }
            Violation::LicenseDenied { name, licenses } => {
                write!(
                    f,
                    "license {} is denied (component {})",
                    licenses.join(", "),
                    name
                )
            }
            Violation::LicenseNotAllowed { name, licenses } => {
                write!(
                    f,
                    "license {} is not allowed (component {})",
                    licenses.join(", "),
                    name
                )
            }
            Violation::NoLicenseInfo { name } => {
                write!(
                    f,
                    "component {} has no license information (--allow-license requires it)",
                    name
                )
            }
        }
    }
}

impl Violation {
    /// whether `--deny-license` or `--allow-license` raised it, rather than a `--fail-on` gate.
    pub fn is_license_policy(&self) -> bool {
        matches!(
            self,
            Violation::LicenseDenied { .. }
                | Violation::LicenseNotAllowed { .. }
                | Violation::NoLicenseInfo { .. }
        )
    }

    /// the component it is about, as reports name it: an edge's parent for a dependency change.
    pub fn component(&self) -> Option<&str> {
        match self {
            Violation::AddedComponent { name }
            | Violation::RemovedComponent { name }
            | Violation::ChangedComponent { name }
            | Violation::MissingHashesAdded { name }
            | Violation::MissingHashesDropped { name }
            | Violation::LicenseChanged { name, .. }
            | Violation::LicenseExpressionChanged { name, .. }
            | Violation::LicenseIntroduced { name, .. }
            | Violation::CopyleftAdded { name, .. }
            | Violation::VersionDowngrade { name, .. }
            | Violation::SupplierChanged { name, .. }
            | Violation::SupplierIntroduced { name, .. }
            | Violation::PurlChanged { name, .. }
            | Violation::EcosystemChanged { name, .. }
            | Violation::HashAlgorithmDowngrade { name, .. }
            | Violation::ChecksumChanged { name, .. }
            | Violation::LicenseDenied { name, .. }
            | Violation::LicenseNotAllowed { name, .. }
            | Violation::NoLicenseInfo { name } => Some(name),
            Violation::DepsAdded { parent, .. }
            | Violation::DepsRemoved { parent, .. }
            | Violation::DepsKindChanged { parent, .. } => Some(parent),
            Violation::MetadataTimestampChanged
            | Violation::MetadataToolsChanged
            | Violation::MetadataAuthorsChanged
            | Violation::DependencyCycle { .. } => None,
        }
    }
}

/// a `--deny-license` or `--allow-license` entry that cannot match as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyEntryIssue {
    /// the entry names more than one license, so it can never match.
    MultipleLicenses { flag: String, entry: String },
    /// the entry is not an SPDX license id, so it can only match a free-text license name.
    NotSpdx { flag: String, entry: String },
}

impl PolicyEntryIssue {
    /// whether the entry is unusable, rather than only suspect.
    pub fn is_error(&self) -> bool {
        matches!(self, PolicyEntryIssue::MultipleLicenses { .. })
    }
}

impl fmt::Display for PolicyEntryIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyEntryIssue::MultipleLicenses { flag, entry } => write!(
                f,
                "{flag} {entry:?} names more than one license and can never match; repeat {flag} once per license"
            ),
            PolicyEntryIssue::NotSpdx { flag, entry } => write!(
                f,
                "{flag} {entry:?} is not an SPDX license id; it can only match a free-text license name"
            ),
        }
    }
}

/// the gates to check a diff against.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    /// the `--fail-on` conditions.
    pub fail_on: Vec<FailOn>,
    /// `--deny-license`: licenses no component may require.
    pub deny_licenses: Vec<String>,
    /// `--allow-license`: the only licenses components may require.
    pub allow_licenses: Vec<String>,
}

impl Policy {
    /// the problems with the deny entries, then with the allow entries, in the order given.
    pub fn entry_issues(&self) -> Vec<PolicyEntryIssue> {
        let mut issues = check_policy_entries("--deny-license", &self.deny_licenses);
        issues.extend(check_policy_entries(
            "--allow-license",
            &self.allow_licenses,
        ));
        issues
    }

    /// diffs `old` against `new` under `options` and checks the result against the policy.
    ///
    /// call [`Policy::entry_issues`] first and don't check while any issue
    /// [`is_error`](PolicyEntryIssue::is_error): such an entry never matches a license.
    ///
    /// the gates see every field whatever `options.only` leaves in the returned diff, and the
    /// license and cycle gates read the components of `new` the diff covers. violations come
    /// in order: license policy, dependency cycles, then the gates on the diff.
    pub fn check(&self, old: Sbom, new: Sbom, options: &DiffOptions) -> (Diff, Vec<Violation>) {
        let filter = &options.ecosystems;
        let sbom_gates = |sbom: &Sbom| {
            let mut violations = check_licenses(sbom, &self.deny_licenses, &self.allow_licenses);
            violations.extend(check_cyclic_dependencies(sbom, &self.fail_on));
            violations
        };
        let sbom_gates_active = !self.deny_licenses.is_empty()
            || !self.allow_licenses.is_empty()
            || self.fail_on.contains(&FailOn::CyclicDependency);
        let (mut diff, mut violations) = if sbom_gates_active && !filter.is_empty() {
            let (diff, scope) = Differ::diff_with_scope(old, new, filter);
            (diff, sbom_gates(&scope))
        } else {
            let violations = sbom_gates(&new);
            let unreduced = DiffOptions {
                only: Vec::new(),
                ecosystems: filter.clone(),
            };
            (Differ::diff(old, new, &unreduced), violations)
        };
        violations.extend(collect_violations(&diff, &self.fail_on));
        if !options.only.is_empty() {
            diff.retain_fields(&options.only);
        }
        (diff, violations)
    }
}

/// reports whether a policy list names this requirement.
///
/// an entry can be the bare identifier, its `+` form, or the full
/// `<id> WITH <exception>` spelling; an exception is only nameable through the
/// latter, so allowing a license never implies allowing the exception alone.
fn requirement_listed(req: &LicenseRequirement, list: &HashSet<String>) -> bool {
    if list.contains(&req.license.to_ascii_lowercase()) {
        return true;
    }
    if req.or_later && list.contains(&format!("{}+", req.license.to_ascii_lowercase())) {
        return true;
    }
    req.exception.is_some() && list.contains(&req.to_string().to_ascii_lowercase())
}

/// lowercases a policy entry as the license gates read it: `GPL-3.0+` lists `gpl-3.0-or-later`.
fn policy_spelling(entry: &str) -> String {
    let ids = BTreeSet::from([entry.to_string()]);
    let reqs = Licensing {
        expression: Some(entry),
        ids: &ids,
    }
    .requirements();
    match reqs.first() {
        Some(req) if reqs.len() == 1 => req.to_string().to_ascii_lowercase(),
        _ => entry.to_ascii_lowercase(),
    }
}

/// the entries of `flag` no license can match, and those only a license name can.
pub fn check_policy_entries(flag: &str, entries: &[String]) -> Vec<PolicyEntryIssue> {
    let mut issues = Vec::new();
    for entry in entries {
        let ids = BTreeSet::from([entry.clone()]);
        let licensing = Licensing {
            expression: Some(entry),
            ids: &ids,
        };
        let (flag, entry) = (flag.to_owned(), entry.clone());
        if licensing.requirements().len() > 1 {
            issues.push(PolicyEntryIssue::MultipleLicenses { flag, entry });
        } else if !is_spdx_expression(&entry) {
            issues.push(PolicyEntryIssue::NotSpdx { flag, entry });
        }
    }
    issues
}

/// names the requirements that made a policy gate fire, for the diagnostic.
fn offending_requirements(
    licensing: Licensing<'_>,
    keep: impl Fn(&LicenseRequirement) -> bool,
) -> Vec<String> {
    licensing
        .requirements()
        .iter()
        .filter(|req| keep(req))
        .map(|req| req.to_string())
        .collect()
}

/// the components of `sbom` the `deny` and `allow` lists reject.
pub fn check_licenses(sbom: &Sbom, deny: &[String], allow: &[String]) -> Vec<Violation> {
    let mut violations = Vec::new();
    if deny.is_empty() && allow.is_empty() {
        return violations;
    }
    let labels = Labels::for_sbom(sbom);
    // SPDX license IDs are case-insensitive per spec (Annex E / clause 10.1).
    let deny_lower: HashSet<String> = deny.iter().map(|s| policy_spelling(s)).collect();
    let allow_lower: HashSet<String> = allow.iter().map(|s| policy_spelling(s)).collect();

    for comp in sbom.components.values() {
        // a component with no license information cannot satisfy an allow-list.
        if !allow.is_empty() && comp.licenses.is_empty() {
            violations.push(Violation::NoLicenseInfo {
                name: labels.component(comp).to_owned(),
            });
            continue;
        }

        let licensing = comp.licensing();

        if !deny_lower.is_empty()
            && !licensing.satisfiable(|req| !requirement_listed(req, &deny_lower))
        {
            violations.push(Violation::LicenseDenied {
                name: labels.component(comp).to_owned(),
                licenses: offending_requirements(licensing, |req| {
                    requirement_listed(req, &deny_lower)
                }),
            });
        }

        if !allow_lower.is_empty()
            && !licensing.satisfiable(|req| requirement_listed(req, &allow_lower))
        {
            violations.push(Violation::LicenseNotAllowed {
                name: labels.component(comp).to_owned(),
                licenses: offending_requirements(licensing, |req| {
                    !requirement_listed(req, &allow_lower)
                }),
            });
        }
    }
    violations
}

/// the dependency cycles in `sbom`, when `fail_on` asks for them.
pub fn check_cyclic_dependencies(sbom: &Sbom, fail_on: &[FailOn]) -> Vec<Violation> {
    if !fail_on.contains(&FailOn::CyclicDependency) {
        return Vec::new();
    }

    let cycles = sbom.detect_cycles();
    let labels = Labels::for_sbom(sbom);
    cycles
        .iter()
        .map(|cycle| Violation::DependencyCycle {
            path: cycle.iter().map(|id| labels.id(id).to_owned()).collect(),
        })
        .collect()
}

/// builds the `copyleft-added` violation for a changed component, if the new
/// licensing imposes a copyleft obligation the old one did not.
fn copyleft_violation(change: &ComponentChange, name: &str, active: bool) -> Option<Violation> {
    if !active {
        return None;
    }
    let introduced = copyleft_obligations_added(change.old.licensing(), change.new.licensing());
    if introduced.is_empty() {
        return None;
    }
    Some(Violation::CopyleftAdded {
        name: name.to_owned(),
        licenses: introduced.into_iter().collect(),
    })
}

/// collects all policy violations from a diff in a single pass per collection.
///
/// instead of iterating `diff.changed` once per condition, builds a set of
/// active conditions and checks all of them in one traversal. returns
/// structured violations the caller can inspect, format, or count.
/// [`FailOn::CyclicDependency`] reads the sbom, see [`check_cyclic_dependencies`].
pub fn collect_violations(diff: &Diff, fail_on: &[FailOn]) -> Vec<Violation> {
    let active: HashSet<FailOn> = fail_on.iter().copied().collect();
    if active.is_empty() {
        return Vec::new();
    }

    let labels = Labels::new(diff);
    let mut violations = Vec::new();

    let check_added = active.contains(&FailOn::AddedComponents);
    let check_missing_hashes = active.contains(&FailOn::MissingHashes);
    let check_license_changed = active.contains(&FailOn::LicenseChanged);
    let check_copyleft_added = active.contains(&FailOn::CopyleftAdded);
    let check_supplier_changed = active.contains(&FailOn::SupplierChanged);
    let check_purl_changed = active.contains(&FailOn::PurlChanged);
    let check_ecosystem_changed = active.contains(&FailOn::EcosystemChanged);

    for comp in &diff.added {
        let name = labels.component(comp);
        if check_added {
            violations.push(Violation::AddedComponent {
                name: name.to_owned(),
            });
        }
        if check_missing_hashes && comp.hashes.is_empty() {
            violations.push(Violation::MissingHashesAdded {
                name: name.to_owned(),
            });
        }
        if check_license_changed && !comp.licenses.is_empty() {
            violations.push(Violation::LicenseIntroduced {
                name: name.to_owned(),
                licenses: comp.licenses.iter().cloned().collect(),
            });
        }
        if check_copyleft_added {
            let none = BTreeSet::new();
            let introduced =
                copyleft_obligations_added(Licensing::from_ids(&none), comp.licensing());
            if !introduced.is_empty() {
                violations.push(Violation::CopyleftAdded {
                    name: name.to_owned(),
                    licenses: introduced.into_iter().collect(),
                });
            }
        }
        if check_supplier_changed && comp.supplier.is_some() {
            violations.push(Violation::SupplierIntroduced {
                name: name.to_owned(),
                supplier: comp.supplier.clone().unwrap(),
            });
        }
    }

    if active.contains(&FailOn::RemovedComponents) {
        for comp in &diff.removed {
            violations.push(Violation::RemovedComponent {
                name: labels.component(comp).to_owned(),
            });
        }
    }

    let check_changed = active.contains(&FailOn::ChangedComponents);
    let check_version_downgrade = active.contains(&FailOn::VersionDowngrade);
    let check_hash_downgrade = active.contains(&FailOn::HashAlgorithmDowngrade);
    let check_checksum_changed = active.contains(&FailOn::ChecksumChanged);
    let any_field_check = check_missing_hashes
        || check_license_changed
        || check_copyleft_added
        || check_version_downgrade
        || check_supplier_changed
        || check_hash_downgrade
        || check_purl_changed
        || check_ecosystem_changed
        || check_checksum_changed;

    for change in &diff.changed {
        let name = labels.component(&change.new);
        if check_changed {
            violations.push(Violation::ChangedComponent {
                name: name.to_owned(),
            });
        }
        if check_missing_hashes && !change.old.hashes.is_empty() && change.new.hashes.is_empty() {
            violations.push(Violation::MissingHashesDropped {
                name: name.to_owned(),
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
                                name: name.to_owned(),
                                old: old.clone(),
                                new: new.clone(),
                            });
                        }
                        violations.extend(copyleft_violation(change, name, check_copyleft_added));
                    }
                    FieldChange::LicenseExpression(old, new)
                        if check_license_changed || check_copyleft_added =>
                    {
                        if check_license_changed {
                            violations.push(Violation::LicenseExpressionChanged {
                                name: name.to_owned(),
                                old: old.clone(),
                                new: new.clone(),
                            });
                        }
                        violations.extend(copyleft_violation(change, name, check_copyleft_added));
                    }
                    FieldChange::Version(Some(old_ver), Some(new_ver))
                        if check_version_downgrade && change.is_downgrade =>
                    {
                        violations.push(Violation::VersionDowngrade {
                            name: name.to_owned(),
                            old: old_ver.clone(),
                            new: new_ver.clone(),
                        });
                    }
                    FieldChange::Supplier(old_sup, new_sup) if check_supplier_changed => {
                        violations.push(Violation::SupplierChanged {
                            name: name.to_owned(),
                            old: old_sup.clone(),
                            new: new_sup.clone(),
                        });
                    }
                    FieldChange::Purl(old_purl, new_purl)
                        if check_purl_changed
                            && purl_coordinates_changed(
                                old_purl.as_deref(),
                                new_purl.as_deref(),
                            ) =>
                    {
                        violations.push(Violation::PurlChanged {
                            name: name.to_owned(),
                            old: old_purl.clone(),
                            new: new_purl.clone(),
                        });
                    }
                    FieldChange::Ecosystem(old_eco, new_eco) if check_ecosystem_changed => {
                        violations.push(Violation::EcosystemChanged {
                            name: name.to_owned(),
                            old: old_eco.clone(),
                            new: new_eco.clone(),
                        });
                    }
                    FieldChange::Hashes(old_hashes, new_hashes)
                        if check_hash_downgrade || check_checksum_changed =>
                    {
                        if check_hash_downgrade && change.is_hash_algorithm_downgrade {
                            violations.push(Violation::HashAlgorithmDowngrade {
                                name: name.to_owned(),
                                old_algos: old_hashes.keys().cloned().collect(),
                                new_algos: new_hashes.keys().cloned().collect(),
                            });
                        }
                        if check_checksum_changed && change.old.version == change.new.version {
                            for (algorithm, old, new) in changed_checksums(old_hashes, new_hashes) {
                                violations.push(Violation::ChecksumChanged {
                                    name: name.to_owned(),
                                    algorithm,
                                    old,
                                    new,
                                });
                            }
                        }
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
                    parent: labels.id(&edge.parent).to_owned(),
                    child: labels.id(child).to_owned(),
                });
            }
            for child in edge.removed.keys() {
                violations.push(Violation::DepsRemoved {
                    parent: labels.id(&edge.parent).to_owned(),
                    child: labels.id(child).to_owned(),
                });
            }
            for (child, (old_kind, new_kind)) in &edge.kind_changed {
                violations.push(Violation::DepsKindChanged {
                    parent: labels.id(&edge.parent).to_owned(),
                    child: labels.id(child).to_owned(),
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

    violations
}

/// whether two purls differ in anything but their version; an unparseable purl compares as a string.
fn purl_coordinates_changed(old: Option<&str>, new: Option<&str>) -> bool {
    let coordinates = |purl: &str| {
        sbom_model::parse_purl(purl).map(|mut parsed| {
            parsed.without_version();
            parsed
        })
    };
    match (old.map(coordinates), new.map(coordinates)) {
        (Some(Some(a)), Some(Some(b))) => a != b,
        _ => old != new,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EcosystemFilter, Field};
    use sbom_model::{Component, ComponentId};

    #[test]
    fn test_check_licenses() {
        let mut sbom = Sbom::default();
        let mut c = Component::new("a".into(), Some("1".into()));
        c.licenses.insert("GPL-3.0-only".into());
        sbom.components.insert(c.id.clone(), c);

        assert!(!check_licenses(&sbom, &["GPL-3.0-only".into()], &[]).is_empty());
        assert!(check_licenses(&sbom, &["MIT".into()], &[]).is_empty());
        assert!(!check_licenses(&sbom, &[], &["MIT".into()]).is_empty());
        assert!(check_licenses(&sbom, &[], &["GPL-3.0-only".into()]).is_empty());
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
        assert!(!check_licenses(&sbom, &["MIT".into()], &[]).is_empty());
        assert!(!check_licenses(&sbom, &["Apache-2.0".into()], &[]).is_empty());
        // both must be in allow list
        assert!(!check_licenses(&sbom, &[], &["MIT".into()]).is_empty()); // Apache-2.0 not allowed
        assert!(check_licenses(&sbom, &[], &["MIT".into(), "Apache-2.0".into()]).is_empty());
    }

    #[test]
    fn test_collect_violations_deps_with_removed_edges() {
        use crate::{Diff, EdgeDiff};
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
        use crate::Diff;

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
    fn test_check_licenses_unlicensed_component_with_allowlist() {
        let mut sbom = Sbom::default();
        // component with no license information
        let c = Component::new("unlicensed-pkg".into(), Some("1.0".into()));
        // licenses is empty by default
        sbom.components.insert(c.id.clone(), c);

        // no allow-list: unlicensed component is not a violation
        assert!(check_licenses(&sbom, &[], &[]).is_empty());

        // with allow-list: unlicensed component cannot satisfy it → violation
        assert!(!check_licenses(&sbom, &[], &["MIT".into()]).is_empty());

        // with deny-list only: unlicensed component is not a violation (nothing to deny)
        assert!(check_licenses(&sbom, &["GPL-3.0-only".into()], &[]).is_empty());
    }

    #[test]
    fn test_check_licenses_case_insensitive() {
        let mut sbom = Sbom::default();
        let mut c = Component::new("a".into(), Some("1".into()));
        c.licenses.insert("GPL-3.0-only".into());
        sbom.components.insert(c.id.clone(), c);

        // deny: different casing still matches
        assert!(!check_licenses(&sbom, &["gpl-3.0-only".into()], &[]).is_empty());
        assert!(!check_licenses(&sbom, &["Gpl-3.0-Only".into()], &[]).is_empty());

        // allow: different casing is still accepted
        assert!(check_licenses(&sbom, &[], &["gpl-3.0-only".into()]).is_empty());
        assert!(check_licenses(&sbom, &[], &["GPL-3.0-ONLY".into()]).is_empty());

        // allow: wrong license is still rejected regardless of case
        assert!(!check_licenses(&sbom, &[], &["mit".into()]).is_empty());
    }

    #[test]
    fn test_collect_violations_added_components() {
        use crate::Diff;

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
        use crate::Diff;

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
        use crate::{ComponentChange, Diff, FieldChange};
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
                is_hash_algorithm_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(!collect_violations(&diff, &[FailOn::MissingHashes]).is_empty());
    }

    #[test]
    fn test_collect_violations_missing_hashes_changed_component_kept() {
        use crate::{ComponentChange, Diff, FieldChange};

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
                is_hash_algorithm_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::MissingHashes]).is_empty());
    }

    #[test]
    fn test_collect_violations_missing_hashes_changed_component_both_empty() {
        use crate::{ComponentChange, Diff, FieldChange};

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
                is_hash_algorithm_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::MissingHashes]).is_empty());
    }

    #[test]
    fn test_collect_violations_deps() {
        use crate::{Diff, EdgeDiff};
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
        use crate::Diff;

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
        use crate::{ComponentChange, Diff, FieldChange};

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
            is_hash_algorithm_downgrade: false,
        });
        assert!(!collect_violations(&diff, &[FailOn::ChangedComponents]).is_empty());
    }

    #[test]
    fn test_description_only_changes_do_not_trigger_gates() {
        use crate::{ComponentChange, Diff, FieldChange};

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
                is_hash_algorithm_downgrade: false,
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
    fn test_collect_violations_license_changed_on_changed_component() {
        use crate::{ComponentChange, Diff, FieldChange};
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
                is_hash_algorithm_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(!collect_violations(&diff, &[FailOn::LicenseChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_license_changed_no_license_change() {
        use crate::{ComponentChange, Diff, FieldChange};

        let old = Component::new("pkg".into(), Some("1.0".into()));
        let new = Component::new("pkg".into(), Some("2.0".into()));

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old,
                new,
                changes: vec![FieldChange::Version(Some("1.0".into()), Some("2.0".into()))],
                is_downgrade: false,
                is_hash_algorithm_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::LicenseChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_license_changed_added_component_with_license() {
        use crate::Diff;

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
        use crate::Diff;

        let added = Component::new("new-pkg".into(), Some("1.0".into()));

        let diff = Diff {
            added: vec![added],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::LicenseChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_license_changed_license_dropped() {
        use crate::{ComponentChange, Diff, FieldChange};
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
                is_hash_algorithm_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(!collect_violations(&diff, &[FailOn::LicenseChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_copyleft_added_changed_component() {
        use crate::{ComponentChange, Diff, FieldChange};
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
                is_hash_algorithm_downgrade: false,
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
        use crate::{ComponentChange, Diff, FieldChange};
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
                is_hash_algorithm_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::CopyleftAdded]).is_empty());
    }

    #[test]
    fn test_collect_violations_copyleft_added_carried_over_no_violation() {
        use crate::{ComponentChange, Diff, FieldChange};
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
                is_hash_algorithm_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::CopyleftAdded]).is_empty());
    }

    #[test]
    fn test_collect_violations_copyleft_added_on_added_component() {
        use crate::Diff;

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
            Violation::CopyleftAdded { name, licenses }
                if name == "copyleft-pkg@1.0" && licenses == &["AGPL-3.0-only".to_string()]
        ));
    }

    #[test]
    fn test_collect_violations_copyleft_added_and_license_changed_both_fire() {
        use crate::{ComponentChange, Diff, FieldChange};
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
                is_hash_algorithm_downgrade: false,
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
        use crate::{ComponentChange, Diff, FieldChange};
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
                is_hash_algorithm_downgrade: false,
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
        use crate::{Diff, MetadataChange};

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
    fn test_collect_violations_metadata_changed_tools_only() {
        use crate::{Diff, MetadataChange};

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
        use crate::{Diff, MetadataChange};

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
    fn test_collect_violations_version_downgrade() {
        use crate::{ComponentChange, Diff, FieldChange};

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
                is_downgrade: true,
                is_hash_algorithm_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(!collect_violations(&diff, &[FailOn::VersionDowngrade]).is_empty());
    }

    #[test]
    fn test_collect_violations_version_downgrade_upgrade_no_violation() {
        use crate::{ComponentChange, Diff, FieldChange};

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
                is_hash_algorithm_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::VersionDowngrade]).is_empty());
    }

    #[test]
    fn test_collect_violations_version_downgrade_no_version_change() {
        use crate::{ComponentChange, Diff, FieldChange};

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
                is_hash_algorithm_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::VersionDowngrade]).is_empty());
    }

    #[test]
    fn test_collect_violations_version_downgrade_version_added() {
        use crate::{ComponentChange, Diff, FieldChange};

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
                is_hash_algorithm_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::VersionDowngrade]).is_empty());
    }

    #[test]
    fn test_collect_violations_version_downgrade_does_not_trigger_other_gates() {
        use crate::{ComponentChange, Diff, FieldChange};

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
                is_downgrade: true,
                is_hash_algorithm_downgrade: false,
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
        use crate::{ComponentChange, Diff, FieldChange};

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
                is_hash_algorithm_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(!collect_violations(&diff, &[FailOn::SupplierChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_supplier_changed_no_change() {
        use crate::{ComponentChange, Diff, FieldChange};

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
                is_hash_algorithm_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::SupplierChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_supplier_changed_supplier_added() {
        use crate::{ComponentChange, Diff, FieldChange};

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
                is_hash_algorithm_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(!collect_violations(&diff, &[FailOn::SupplierChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_supplier_changed_supplier_removed() {
        use crate::{ComponentChange, Diff, FieldChange};

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
                is_hash_algorithm_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(!collect_violations(&diff, &[FailOn::SupplierChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_supplier_changed_added_component_with_supplier() {
        use crate::Diff;

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
        use crate::Diff;

        let added = Component::new("new-pkg".into(), Some("1.0.0".into()));

        let diff = Diff {
            added: vec![added],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::SupplierChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_supplier_changed_does_not_trigger_other_gates() {
        use crate::{ComponentChange, Diff, FieldChange};

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
                is_hash_algorithm_downgrade: false,
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
        use crate::{ComponentChange, Diff, FieldChange};

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
                is_hash_algorithm_downgrade: false,
            }],
            ..Diff::default()
        };

        let violations = collect_violations(&diff, &[FailOn::PurlChanged]);
        assert_eq!(violations.len(), 1);
        assert!(matches!(violations[0], Violation::PurlChanged { .. }));
    }

    #[test]
    fn test_collect_violations_purl_changed_no_change() {
        // only the version changed — the purl gate must not fire
        let mut old = Sbom::default();
        let mut new = Sbom::default();
        for (sbom, version) in [(&mut old, "1.0.0"), (&mut new, "2.0.0")] {
            let mut comp = Component::new("pkg".into(), Some(version.into()));
            comp.purl = Some(format!("pkg:npm/pkg@{version}"));
            comp.id = ComponentId::new(comp.purl.as_deref(), &[]);
            sbom.components.insert(comp.id.clone(), comp);
        }

        let diff = Differ::diff(old.clone(), new.clone(), &DiffOptions::default());
        assert!(diff.changed[0]
            .changes
            .iter()
            .any(|c| matches!(c, FieldChange::Purl(..))));
        assert!(collect_violations(&diff, &[FailOn::PurlChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_purl_changed_on_qualifier_change() {
        use crate::{ComponentChange, Diff, FieldChange};

        let old_purl = "pkg:maven/org.example/lib@1.0.0?repository_url=https://repo.example.com";
        let new_purl = "pkg:maven/org.example/lib@1.0.0?repository_url=https://evil.example.com";
        let mut old = Component::new("lib".into(), Some("1.0.0".into()));
        old.purl = Some(old_purl.into());
        let mut new = Component::new("lib".into(), Some("1.0.0".into()));
        new.purl = Some(new_purl.into());

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old,
                new,
                changes: vec![FieldChange::Purl(
                    Some(old_purl.into()),
                    Some(new_purl.into()),
                )],
                is_downgrade: false,
                is_hash_algorithm_downgrade: false,
            }],
            ..Diff::default()
        };

        let violations = collect_violations(&diff, &[FailOn::PurlChanged]);
        assert_eq!(violations.len(), 1);
        assert!(matches!(violations[0], Violation::PurlChanged { .. }));
    }

    #[test]
    fn test_purl_coordinates_changed_ignores_version() {
        assert!(!purl_coordinates_changed(
            Some("pkg:npm/left-pad@1.0.0"),
            Some("pkg:npm/left-pad@1.1.0")
        ));
        assert!(!purl_coordinates_changed(
            Some("pkg:npm/left-pad@1.0.0"),
            Some("pkg:npm/left-pad")
        ));
    }

    #[test]
    fn test_purl_coordinates_changed_ignores_equivalent_spellings() {
        assert!(!purl_coordinates_changed(
            Some("pkg:maven/org.example/lib@1.0.0?type=jar&repository_url=https://repo.example.com"),
            Some("pkg:maven/org.example/lib@1.1.0?Repository_URL=https%3A%2F%2Frepo.example.com&type=jar")
        ));
        assert!(!purl_coordinates_changed(
            Some("pkg:NPM/left-pad@1.0.0?classifier="),
            Some("pkg:npm/left-pad@1.1.0")
        ));
    }

    #[test]
    fn test_purl_coordinates_changed_on_renamed_purl() {
        assert!(purl_coordinates_changed(
            Some("pkg:npm/left-pad@1.0.0"),
            Some("pkg:npm/left-pad-fork@1.0.0")
        ));
        assert!(purl_coordinates_changed(
            Some("pkg:npm/left-pad@1.0.0"),
            Some("pkg:npm/left-pad-fork@1.1.0")
        ));
    }

    #[test]
    fn test_purl_coordinates_changed_on_qualifier_or_subpath_change() {
        let old = Some("pkg:maven/org.example/lib@1.0.0?repository_url=https://repo.example.com");
        assert!(purl_coordinates_changed(
            old,
            Some("pkg:maven/org.example/lib@1.1.0?repository_url=https://evil.example.com")
        ));
        assert!(purl_coordinates_changed(
            old,
            Some("pkg:maven/org.example/lib@1.1.0")
        ));
        assert!(purl_coordinates_changed(
            Some("pkg:golang/github.com/example/mod@v1.0.0#cmd/a"),
            Some("pkg:golang/github.com/example/mod@v1.1.0#cmd/b")
        ));
    }

    #[test]
    fn test_purl_coordinates_changed_on_purl_present_on_one_side() {
        assert!(purl_coordinates_changed(
            Some("pkg:npm/left-pad@1.0.0"),
            None
        ));
        assert!(purl_coordinates_changed(
            None,
            Some("pkg:npm/left-pad@1.1.0")
        ));
    }

    #[test]
    fn test_purl_coordinates_changed_compares_unparseable_purls_as_strings() {
        assert!(purl_coordinates_changed(
            Some("pkg:swift/Alamofire@5.0.0"),
            Some("pkg:swift/Alamofire@5.1.0")
        ));
        assert!(purl_coordinates_changed(
            Some("pkg:npm/left-pad@1.0.0"),
            Some("not a purl")
        ));
    }

    #[test]
    fn test_collect_violations_ecosystem_changed() {
        use crate::{ComponentChange, Diff, FieldChange};

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
                is_hash_algorithm_downgrade: false,
            }],
            ..Diff::default()
        };

        let violations = collect_violations(&diff, &[FailOn::EcosystemChanged]);
        assert_eq!(violations.len(), 1);
        assert!(matches!(violations[0], Violation::EcosystemChanged { .. }));
    }

    #[test]
    fn test_collect_violations_ecosystem_changed_no_change() {
        use crate::{ComponentChange, Diff, FieldChange};

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
                is_hash_algorithm_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::EcosystemChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_hash_algorithm_downgrade() {
        use crate::{ComponentChange, Diff, FieldChange};

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
                is_hash_algorithm_downgrade: true,
            }],
            ..Diff::default()
        };

        assert!(!collect_violations(&diff, &[FailOn::HashAlgorithmDowngrade]).is_empty());
    }

    #[test]
    fn test_collect_violations_hash_algorithm_downgrade_upgrade_no_violation() {
        use crate::{ComponentChange, Diff, FieldChange};

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
                is_hash_algorithm_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::HashAlgorithmDowngrade]).is_empty());
    }

    #[test]
    fn test_collect_violations_hash_algorithm_downgrade_same_algorithm() {
        use crate::{ComponentChange, Diff, FieldChange};

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
                is_hash_algorithm_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::HashAlgorithmDowngrade]).is_empty());
    }

    #[test]
    fn test_collect_violations_hash_algorithm_downgrade_no_hash_change() {
        use crate::{ComponentChange, Diff, FieldChange};

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
                is_hash_algorithm_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::HashAlgorithmDowngrade]).is_empty());
    }

    #[test]
    fn test_collect_violations_hash_algorithm_downgrade_dropped_strongest() {
        use crate::{ComponentChange, Diff, FieldChange};

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
                is_hash_algorithm_downgrade: true,
            }],
            ..Diff::default()
        };

        assert!(!collect_violations(&diff, &[FailOn::HashAlgorithmDowngrade]).is_empty());
    }

    #[test]
    fn test_collect_violations_hash_algorithm_downgrade_hashes_dropped_entirely() {
        use crate::{ComponentChange, Diff, FieldChange};
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
                is_hash_algorithm_downgrade: false,
            }],
            ..Diff::default()
        };

        assert!(collect_violations(&diff, &[FailOn::HashAlgorithmDowngrade]).is_empty());
    }

    #[test]
    fn test_collect_violations_hash_algorithm_downgrade_does_not_trigger_other_gates() {
        use crate::{ComponentChange, Diff, FieldChange};

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
                is_hash_algorithm_downgrade: true,
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
        assert!(collect_violations(&diff, &[FailOn::ChecksumChanged]).is_empty());
        // ChangedComponents should still fire
        assert!(!collect_violations(&diff, &[FailOn::ChangedComponents]).is_empty());
        // HashAlgorithmDowngrade should fire
        assert!(!collect_violations(&diff, &[FailOn::HashAlgorithmDowngrade]).is_empty());
    }

    fn hash_change_diff(
        old_version: &str,
        new_version: &str,
        old_hashes: &[(&str, &str)],
        new_hashes: &[(&str, &str)],
    ) -> crate::Diff {
        use crate::{ComponentChange, Diff, FieldChange};

        let mut old = Component::new("pkg".into(), Some(old_version.into()));
        old.hashes = old_hashes
            .iter()
            .map(|(a, v)| ((*a).to_string(), (*v).to_string()))
            .collect();
        let mut new = Component::new("pkg".into(), Some(new_version.into()));
        new.hashes = new_hashes
            .iter()
            .map(|(a, v)| ((*a).to_string(), (*v).to_string()))
            .collect();

        let mut changes = Vec::new();
        if old_version != new_version {
            changes.push(FieldChange::Version(
                Some(old_version.into()),
                Some(new_version.into()),
            ));
        }
        changes.push(FieldChange::Hashes(old.hashes.clone(), new.hashes.clone()));
        let hash_downgrade = sbom_model::is_hash_algorithm_downgrade(&old.hashes, &new.hashes);

        Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old,
                new,
                changes,
                is_downgrade: false,
                is_hash_algorithm_downgrade: hash_downgrade,
            }],
            ..Diff::default()
        }
    }

    #[test]
    fn test_collect_violations_checksum_changed_same_version() {
        let diff = hash_change_diff(
            "1.0.0",
            "1.0.0",
            &[("sha-256", "abc")],
            &[("sha-256", "def")],
        );

        let violations = collect_violations(&diff, &[FailOn::ChecksumChanged]);
        assert_eq!(violations.len(), 1);
        let rendered = violations[0].to_string();
        assert!(
            rendered.contains("SHA-256") && rendered.contains("abc") && rendered.contains("def"),
            "violation should name the algorithm and both digests, got: {rendered}"
        );

        assert!(collect_violations(&diff, &[FailOn::MissingHashes]).is_empty());
        assert!(collect_violations(&diff, &[FailOn::HashAlgorithmDowngrade]).is_empty());
    }

    #[test]
    fn test_collect_violations_checksum_changed_version_changed_no_violation() {
        let diff = hash_change_diff(
            "1.0.0",
            "1.1.0",
            &[("sha-256", "abc")],
            &[("sha-256", "def")],
        );

        assert!(collect_violations(&diff, &[FailOn::ChecksumChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_checksum_changed_case_only_no_violation() {
        let diff = hash_change_diff(
            "1.0.0",
            "1.0.0",
            &[("sha-256", "ABC")],
            &[("sha-256", "abc")],
        );

        assert!(collect_violations(&diff, &[FailOn::ChecksumChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_checksum_changed_disjoint_algorithms_no_violation() {
        let diff = hash_change_diff(
            "1.0.0",
            "1.0.0",
            &[("sha-256", "abc")],
            &[("sha-512", "def")],
        );

        assert!(collect_violations(&diff, &[FailOn::ChecksumChanged]).is_empty());
    }

    #[test]
    fn test_collect_violations_checksum_changed_alongside_algorithm_downgrade() {
        let diff = hash_change_diff(
            "1.0.0",
            "1.0.0",
            &[("sha-256", "abc"), ("sha-512", "xyz")],
            &[("sha-256", "def")],
        );

        let violations = collect_violations(
            &diff,
            &[FailOn::ChecksumChanged, FailOn::HashAlgorithmDowngrade],
        );
        assert_eq!(
            violations.len(),
            2,
            "both gates should fire: {violations:?}"
        );
    }

    #[test]
    fn policy_check_gates_the_whole_diff_of_the_filtered_ecosystems() {
        let component = |name: &str, version: &str, ecosystem: &str, license: &str| {
            let mut c = Component::new(name.into(), Some(version.into()));
            c.ecosystem = Some(ecosystem.into());
            c.licenses.insert(license.into());
            c
        };
        let sbom = |components: Vec<Component>| {
            let mut sbom = Sbom::default();
            for c in components {
                sbom.components.insert(c.id.clone(), c);
            }
            sbom
        };
        let old = sbom(vec![
            component("a", "2.0.0", "npm", "MIT"),
            component("b", "1.0.0", "cargo", "GPL-3.0-only"),
        ]);
        let new = sbom(vec![
            component("a", "1.0.0", "npm", "MIT"),
            component("b", "1.0.0", "cargo", "GPL-3.0-only"),
        ]);
        let policy = Policy {
            fail_on: vec![FailOn::VersionDowngrade],
            deny_licenses: vec!["GPL-3.0-only".into()],
            ..Policy::default()
        };
        let downgrade = Violation::VersionDowngrade {
            name: "a@1.0.0".into(),
            old: "2.0.0".into(),
            new: "1.0.0".into(),
        };
        let denied = Violation::LicenseDenied {
            name: "b@1.0.0".into(),
            licenses: vec!["GPL-3.0-only".into()],
        };

        let only_license = DiffOptions {
            only: vec![Field::License],
            ..DiffOptions::default()
        };
        let (diff, violations) = policy.check(old.clone(), new.clone(), &only_license);
        assert!(diff.changed.is_empty());
        assert_eq!(violations, vec![denied, downgrade.clone()]);

        let npm = DiffOptions {
            ecosystems: EcosystemFilter::new(["npm"], []),
            ..only_license
        };
        let (_, violations) = policy.check(old, new, &npm);
        assert_eq!(violations, vec![downgrade]);
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

        assert!(!check_cyclic_dependencies(&sbom, &[FailOn::CyclicDependency]).is_empty());
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

        assert!(check_cyclic_dependencies(&sbom, &[FailOn::CyclicDependency]).is_empty());
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
        assert!(check_cyclic_dependencies(&sbom, &[FailOn::AddedComponents]).is_empty());
    }
}
