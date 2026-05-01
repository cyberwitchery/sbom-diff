#![doc = include_str!("../readme.md")]

use sbom_model::{Component, ComponentId, Sbom};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};

pub mod renderer;

/// Per-ecosystem counts of added, removed, and changed components.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EcosystemCounts {
    pub added: usize,
    pub removed: usize,
    pub changed: usize,
}

/// The result of comparing two SBOMs.
///
/// Contains lists of added, removed, and changed components,
/// as well as dependency edge changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diff {
    /// Components present in the new SBOM but not the old.
    pub added: Vec<Component>,
    /// Components present in the old SBOM but not the new.
    pub removed: Vec<Component>,
    /// Components present in both with field-level changes.
    pub changed: Vec<ComponentChange>,
    /// Dependency edge changes between components.
    pub edge_diffs: Vec<EdgeDiff>,
    /// Whether document metadata differs (usually ignored).
    pub metadata_changed: bool,
}

impl Diff {
    /// Returns `true` if the diff contains no changes of any kind.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.changed.is_empty()
            && self.edge_diffs.is_empty()
            && !self.metadata_changed
    }

    /// Groups added/removed/changed counts by package ecosystem.
    ///
    /// Components without an ecosystem are grouped under `"unknown"`.
    pub fn ecosystem_breakdown(&self) -> BTreeMap<String, EcosystemCounts> {
        let mut breakdown: BTreeMap<String, EcosystemCounts> = BTreeMap::new();

        for comp in &self.added {
            let eco = comp.ecosystem.as_deref().unwrap_or("unknown").to_string();
            breakdown.entry(eco).or_default().added += 1;
        }

        for comp in &self.removed {
            let eco = comp.ecosystem.as_deref().unwrap_or("unknown").to_string();
            breakdown.entry(eco).or_default().removed += 1;
        }

        for change in &self.changed {
            let eco = change
                .new
                .ecosystem
                .as_deref()
                .unwrap_or("unknown")
                .to_string();
            breakdown.entry(eco).or_default().changed += 1;
        }

        breakdown
    }

    /// Groups the full diff by ecosystem, returning per-ecosystem slices.
    ///
    /// Components without an ecosystem are grouped under `"unknown"`.
    pub fn group_by_ecosystem(&self) -> GroupedDiff {
        let mut ecosystems: BTreeMap<String, EcosystemDiff> = BTreeMap::new();

        for c in &self.added {
            let eco = c.ecosystem.as_deref().unwrap_or("unknown").to_string();
            ecosystems.entry(eco).or_default().added.push(c.clone());
        }
        for c in &self.removed {
            let eco = c.ecosystem.as_deref().unwrap_or("unknown").to_string();
            ecosystems.entry(eco).or_default().removed.push(c.clone());
        }
        for c in &self.changed {
            let eco = c.new.ecosystem.as_deref().unwrap_or("unknown").to_string();
            ecosystems.entry(eco).or_default().changed.push(c.clone());
        }

        GroupedDiff {
            by_ecosystem: ecosystems,
            edge_diffs: self.edge_diffs.clone(),
            metadata_changed: self.metadata_changed,
        }
    }
}

/// Diff grouped by package ecosystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupedDiff {
    pub by_ecosystem: BTreeMap<String, EcosystemDiff>,
    pub edge_diffs: Vec<EdgeDiff>,
    pub metadata_changed: bool,
}

impl GroupedDiff {
    /// Derives per-ecosystem counts from the already-grouped data.
    ///
    /// This avoids a redundant traversal when both grouped components and
    /// counts are needed — call [`Diff::group_by_ecosystem`] once, then
    /// derive counts from the result.
    pub fn ecosystem_breakdown(&self) -> BTreeMap<String, EcosystemCounts> {
        self.by_ecosystem
            .iter()
            .map(|(eco, eco_diff)| {
                (
                    eco.clone(),
                    EcosystemCounts {
                        added: eco_diff.added.len(),
                        removed: eco_diff.removed.len(),
                        changed: eco_diff.changed.len(),
                    },
                )
            })
            .collect()
    }
}

/// Per-ecosystem slice of added, removed, and changed components.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EcosystemDiff {
    pub added: Vec<Component>,
    pub removed: Vec<Component>,
    pub changed: Vec<ComponentChange>,
}

/// A component that exists in both SBOMs with detected changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentChange {
    /// The component identifier (from the new SBOM).
    pub id: ComponentId,
    /// The component as it appeared in the old SBOM.
    pub old: Component,
    /// The component as it appears in the new SBOM.
    pub new: Component,
    /// List of specific field changes detected.
    pub changes: Vec<FieldChange>,
}

/// A dependency edge change for a single parent component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeDiff {
    /// The parent component whose dependencies changed.
    pub parent: ComponentId,
    /// Dependencies added in the new SBOM.
    pub added: BTreeSet<ComponentId>,
    /// Dependencies removed from the old SBOM.
    pub removed: BTreeSet<ComponentId>,
}

/// A specific field that changed between two versions of a component.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FieldChange {
    /// Version changed: (old, new).
    Version(String, String),
    /// Licenses changed: (old, new).
    License(BTreeSet<String>, BTreeSet<String>),
    /// Supplier changed: (old, new).
    Supplier(Option<String>, Option<String>),
    /// Package URL changed: (old, new).
    Purl(Option<String>, Option<String>),
    /// Description changed: (old, new).
    Description(Option<String>, Option<String>),
    /// Hashes changed: (old, new).
    Hashes(BTreeMap<String, String>, BTreeMap<String, String>),
}

/// Fields that can be compared and filtered.
///
/// Use with [`Differ::diff`] to limit comparison to specific fields.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Field {
    /// Package version.
    Version,
    /// License identifiers.
    License,
    /// Supplier/publisher.
    Supplier,
    /// Package URL.
    Purl,
    /// Human-readable description.
    Description,
    /// Checksums.
    Hashes,
    /// Dependency edges.
    Deps,
}

/// SBOM comparison engine.
///
/// Compares two SBOMs and produces a [`Diff`] describing the changes.
/// Components are matched first by ID (purl), then by identity (name + ecosystem).
pub struct Differ;

impl Differ {
    /// Compares two SBOMs and returns the differences.
    ///
    /// Both SBOMs are normalized before comparison to ignore irrelevant differences
    /// like ordering or metadata timestamps.
    ///
    /// # Arguments
    ///
    /// * `old` - The baseline SBOM
    /// * `new` - The SBOM to compare against the baseline
    /// * `only` - Optional filter to limit comparison to specific fields
    ///
    /// # Example
    ///
    /// ```
    /// use sbom_diff::{Differ, Field};
    /// use sbom_model::Sbom;
    ///
    /// let old = Sbom::default();
    /// let new = Sbom::default();
    ///
    /// // Compare all fields
    /// let diff = Differ::diff(&old, &new, None);
    ///
    /// // Compare only version and license changes
    /// let diff = Differ::diff(&old, &new, Some(&[Field::Version, Field::License]));
    /// ```
    pub fn diff(old: &Sbom, new: &Sbom, only: Option<&[Field]>) -> Diff {
        let mut old = old.clone();
        let mut new = new.clone();

        // Compare metadata before normalize() strips volatile fields
        let metadata_changed = old.metadata != new.metadata;

        old.normalize();
        new.normalize();

        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut changed = Vec::new();

        let mut processed_old = HashSet::new();
        let mut processed_new = HashSet::new();

        // Track old_id -> new_id mappings for edge reconciliation
        let mut id_mapping: BTreeMap<ComponentId, ComponentId> = BTreeMap::new();

        // 1. Match by ID
        for (id, new_comp) in &new.components {
            if let Some(old_comp) = old.components.get(id) {
                processed_old.insert(id.clone());
                processed_new.insert(id.clone());
                id_mapping.insert(id.clone(), id.clone());

                if let Some(change) = Self::compute_change(old_comp, new_comp, only) {
                    changed.push(change);
                }
            }
        }

        // 2. Reconciliation: Match by "Identity" (Name + Ecosystem)
        // When purls are absent or change, we match by (ecosystem, name).
        // If either ecosystem is None, we treat it as a wildcard and match by name alone.
        let mut old_identity_map: BTreeMap<(Option<String>, String), Vec<ComponentId>> =
            BTreeMap::new();
        for (id, comp) in &old.components {
            if !processed_old.contains(id) {
                let identity = (comp.ecosystem.clone(), comp.name.clone());
                old_identity_map
                    .entry(identity)
                    .or_default()
                    .push(id.clone());
            }
        }

        for (id, new_comp) in &new.components {
            if processed_new.contains(id) {
                continue;
            }

            let identity = (new_comp.ecosystem.clone(), new_comp.name.clone());

            // Try to find a matching old component:
            // 1. Exact match on (ecosystem, name)
            // 2. If new has ecosystem but no exact match, try old with None ecosystem (same name)
            // 3. If new has no ecosystem, try any old with same name
            let matched_old_id = old_identity_map
                .get_mut(&identity)
                .and_then(|ids| ids.pop())
                .or_else(|| {
                    if new_comp.ecosystem.is_some() {
                        // New has ecosystem, try matching old with None ecosystem
                        old_identity_map
                            .get_mut(&(None, new_comp.name.clone()))
                            .and_then(|ids| ids.pop())
                    } else {
                        // New has no ecosystem, try matching any old with same name
                        old_identity_map
                            .iter_mut()
                            .find(|((_, name), ids)| name == &new_comp.name && !ids.is_empty())
                            .and_then(|(_, ids)| ids.pop())
                    }
                });

            if let Some(old_id) = matched_old_id {
                if let Some(old_comp) = old.components.get(&old_id) {
                    processed_old.insert(old_id.clone());
                    processed_new.insert(id.clone());
                    id_mapping.insert(old_id.clone(), id.clone());

                    if let Some(change) = Self::compute_change(old_comp, new_comp, only) {
                        changed.push(change);
                    }
                    continue;
                }
            }

            added.push(new_comp.clone());
            processed_new.insert(id.clone());
        }

        for (id, old_comp) in &old.components {
            if !processed_old.contains(id) {
                removed.push(old_comp.clone());
            }
        }

        // 3. Compute edge diffs (dependency graph changes)
        let should_include_deps = only.is_none_or(|fields| fields.contains(&Field::Deps));
        let edge_diffs = if should_include_deps {
            Self::compute_edge_diffs(&old, &new, &id_mapping)
        } else {
            Vec::new()
        };

        Diff {
            added,
            removed,
            changed,
            edge_diffs,
            metadata_changed,
        }
    }

    /// Computes dependency edge differences between two SBOMs.
    ///
    /// Uses the id_mapping to translate old component IDs to new IDs when
    /// components were matched by identity rather than exact ID match.
    fn compute_edge_diffs(
        old: &Sbom,
        new: &Sbom,
        id_mapping: &BTreeMap<ComponentId, ComponentId>,
    ) -> Vec<EdgeDiff> {
        let mut edge_diffs = Vec::new();

        // Build reverse mapping (new_id -> old_id) once upfront for O(1) lookups.
        // The forward id_mapping is old_id -> new_id; we need the inverse for
        // translating new parent IDs back to old parent IDs.
        let reverse_mapping: BTreeMap<ComponentId, ComponentId> = id_mapping
            .iter()
            .map(|(old_id, new_id)| (new_id.clone(), old_id.clone()))
            .collect();

        // Helper to translate old ID to new ID (if mapped) or keep as-is
        let translate_id = |old_id: &ComponentId| -> ComponentId {
            id_mapping
                .get(old_id)
                .cloned()
                .unwrap_or_else(|| old_id.clone())
        };

        // Collect all parent IDs from new SBOM's perspective
        // We use new IDs as the canonical reference
        let mut all_parents: BTreeSet<ComponentId> = new.dependencies.keys().cloned().collect();

        // Also include old parents (translated to new IDs)
        for old_parent in old.dependencies.keys() {
            all_parents.insert(translate_id(old_parent));
        }

        for parent_id in all_parents {
            // Get new dependencies for this parent
            let new_children: BTreeSet<ComponentId> = new
                .dependencies
                .get(&parent_id)
                .cloned()
                .unwrap_or_default();

            // Get old dependencies, translating both parent and child IDs
            // Look up the old parent ID via the reverse map
            let old_parent_id = reverse_mapping
                .get(&parent_id)
                .cloned()
                .unwrap_or_else(|| parent_id.clone());

            let old_children: BTreeSet<ComponentId> = old
                .dependencies
                .get(&old_parent_id)
                .map(|children| children.iter().map(&translate_id).collect())
                .unwrap_or_default();

            // Compute added and removed edges
            let added: BTreeSet<ComponentId> =
                new_children.difference(&old_children).cloned().collect();
            let removed: BTreeSet<ComponentId> =
                old_children.difference(&new_children).cloned().collect();

            if !added.is_empty() || !removed.is_empty() {
                edge_diffs.push(EdgeDiff {
                    parent: parent_id,
                    added,
                    removed,
                });
            }
        }

        edge_diffs
    }

    fn compute_change(
        old: &Component,
        new: &Component,
        only: Option<&[Field]>,
    ) -> Option<ComponentChange> {
        let mut changes = Vec::new();

        let should_include = |f: Field| only.is_none_or(|fields| fields.contains(&f));

        if should_include(Field::Version) && old.version != new.version {
            changes.push(FieldChange::Version(
                old.version.clone().unwrap_or_default(),
                new.version.clone().unwrap_or_default(),
            ));
        }

        if should_include(Field::License) && old.licenses != new.licenses {
            changes.push(FieldChange::License(
                old.licenses.clone(),
                new.licenses.clone(),
            ));
        }

        if should_include(Field::Supplier) && old.supplier != new.supplier {
            changes.push(FieldChange::Supplier(
                old.supplier.clone(),
                new.supplier.clone(),
            ));
        }

        if should_include(Field::Purl) && old.purl != new.purl {
            changes.push(FieldChange::Purl(old.purl.clone(), new.purl.clone()));
        }

        if should_include(Field::Description) && old.description != new.description {
            changes.push(FieldChange::Description(
                old.description.clone(),
                new.description.clone(),
            ));
        }

        if should_include(Field::Hashes) && old.hashes != new.hashes {
            changes.push(FieldChange::Hashes(old.hashes.clone(), new.hashes.clone()));
        }

        if changes.is_empty() {
            None
        } else {
            Some(ComponentChange {
                id: new.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_added_removed() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let c1 = Component::new("pkg-a".to_string(), Some("1.0".to_string()));
        let c2 = Component::new("pkg-b".to_string(), Some("1.0".to_string()));

        old.components.insert(c1.id.clone(), c1);
        new.components.insert(c2.id.clone(), c2);

        let diff = Differ::diff(&old, &new, None);
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.changed.len(), 0);
    }

    #[test]
    fn test_diff_changed() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let c1 = Component::new("pkg-a".to_string(), Some("1.0".to_string()));
        let mut c2 = c1.clone();
        c2.version = Some("1.1".to_string());

        old.components.insert(c1.id.clone(), c1);
        new.components.insert(c2.id.clone(), c2);

        let diff = Differ::diff(&old, &new, None);
        assert_eq!(diff.added.len(), 0);
        assert_eq!(diff.removed.len(), 0);
        assert_eq!(diff.changed.len(), 1);
        assert!(matches!(
            diff.changed[0].changes[0],
            FieldChange::Version(_, _)
        ));
    }

    #[test]
    fn test_diff_identity_reconciliation() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let c1 = Component::new("pkg-a".to_string(), Some("1.0".to_string()));
        let c2 = Component::new("pkg-a".to_string(), Some("1.1".to_string()));

        old.components.insert(c1.id.clone(), c1);
        new.components.insert(c2.id.clone(), c2);

        let diff = Differ::diff(&old, &new, None);
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.added.len(), 0);
    }

    #[test]
    fn test_diff_license_change() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let mut c1 = Component::new("pkg-a".to_string(), Some("1.0".to_string()));
        c1.licenses.insert("MIT".into());
        let mut c2 = c1.clone();
        c2.licenses = BTreeSet::from(["Apache-2.0".into()]);

        old.components.insert(c1.id.clone(), c1);
        new.components.insert(c2.id.clone(), c2);

        let diff = Differ::diff(&old, &new, None);
        assert_eq!(diff.changed.len(), 1);
        assert!(diff.changed[0]
            .changes
            .iter()
            .any(|c| matches!(c, FieldChange::License(_, _))));
    }

    #[test]
    fn test_diff_supplier_change() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let mut c1 = Component::new("pkg-a".to_string(), Some("1.0".to_string()));
        c1.supplier = Some("Acme Corp".into());
        let mut c2 = c1.clone();
        c2.supplier = Some("New Corp".into());

        old.components.insert(c1.id.clone(), c1);
        new.components.insert(c2.id.clone(), c2);

        let diff = Differ::diff(&old, &new, None);
        assert_eq!(diff.changed.len(), 1);
        assert!(diff.changed[0]
            .changes
            .iter()
            .any(|c| matches!(c, FieldChange::Supplier(_, _))));
    }

    #[test]
    fn test_diff_hashes_change() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let mut c1 = Component::new("pkg-a".to_string(), Some("1.0".to_string()));
        c1.hashes.insert("sha256".into(), "aaa".into());
        let mut c2 = c1.clone();
        c2.hashes.insert("sha256".into(), "bbb".into());

        old.components.insert(c1.id.clone(), c1);
        new.components.insert(c2.id.clone(), c2);

        let diff = Differ::diff(&old, &new, None);
        assert_eq!(diff.changed.len(), 1);
        assert!(diff.changed[0]
            .changes
            .iter()
            .any(|c| matches!(c, FieldChange::Hashes(_, _))));
    }

    #[test]
    fn test_diff_description_change() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let mut c1 = Component::new("pkg-a".to_string(), Some("1.0".to_string()));
        c1.description = Some("Old description".into());
        let mut c2 = c1.clone();
        c2.description = Some("New description".into());

        old.components.insert(c1.id.clone(), c1);
        new.components.insert(c2.id.clone(), c2);

        let diff = Differ::diff(&old, &new, None);
        assert_eq!(diff.changed.len(), 1);
        assert!(diff.changed[0]
            .changes
            .iter()
            .any(|c| matches!(c, FieldChange::Description(_, _))));
    }

    #[test]
    fn test_diff_description_added() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let c1 = Component::new("pkg-a".to_string(), Some("1.0".to_string()));
        let mut c2 = c1.clone();
        c2.description = Some("A new description".into());

        old.components.insert(c1.id.clone(), c1);
        new.components.insert(c2.id.clone(), c2);

        let diff = Differ::diff(&old, &new, None);
        assert_eq!(diff.changed.len(), 1);
        assert!(diff.changed[0]
            .changes
            .iter()
            .any(|c| matches!(c, FieldChange::Description(None, Some(_)))));
    }

    #[test]
    fn test_diff_description_removed() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let mut c1 = Component::new("pkg-a".to_string(), Some("1.0".to_string()));
        c1.description = Some("Had a description".into());
        let mut c2 = c1.clone();
        c2.description = None;

        old.components.insert(c1.id.clone(), c1);
        new.components.insert(c2.id.clone(), c2);

        let diff = Differ::diff(&old, &new, None);
        assert_eq!(diff.changed.len(), 1);
        assert!(diff.changed[0]
            .changes
            .iter()
            .any(|c| matches!(c, FieldChange::Description(Some(_), None))));
    }

    #[test]
    fn test_diff_description_unchanged() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let mut c1 = Component::new("pkg-a".to_string(), Some("1.0".to_string()));
        c1.description = Some("Same description".into());
        let c2 = c1.clone();

        old.components.insert(c1.id.clone(), c1);
        new.components.insert(c2.id.clone(), c2);

        let diff = Differ::diff(&old, &new, None);
        assert!(diff.changed.is_empty());
    }

    #[test]
    fn test_diff_description_filtering() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let mut c1 = Component::new("pkg-a".to_string(), Some("1.0".to_string()));
        c1.description = Some("Old".into());
        let mut c2 = c1.clone();
        c2.version = Some("2.0".into());
        c2.description = Some("New".into());

        old.components.insert(c1.id.clone(), c1);
        new.components.insert(c2.id.clone(), c2);

        // Only description: should see description change but not version
        let diff = Differ::diff(&old, &new, Some(&[Field::Description]));
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].changes.len(), 1);
        assert!(matches!(
            diff.changed[0].changes[0],
            FieldChange::Description(_, _)
        ));

        // Only version: should see version change but not description
        let diff = Differ::diff(&old, &new, Some(&[Field::Version]));
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].changes.len(), 1);
        assert!(matches!(
            diff.changed[0].changes[0],
            FieldChange::Version(_, _)
        ));
    }

    #[test]
    fn test_diff_multiple_field_changes() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let mut c1 = Component::new("pkg-a".to_string(), Some("1.0".to_string()));
        c1.licenses.insert("MIT".into());
        c1.supplier = Some("Old Corp".into());
        c1.hashes.insert("sha256".into(), "aaa".into());

        let mut c2 = c1.clone();
        c2.version = Some("2.0".into());
        c2.licenses = BTreeSet::from(["Apache-2.0".into()]);
        c2.supplier = Some("New Corp".into());
        c2.hashes.insert("sha256".into(), "bbb".into());

        old.components.insert(c1.id.clone(), c1);
        new.components.insert(c2.id.clone(), c2);

        let diff = Differ::diff(&old, &new, None);
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].changes.len(), 4);
    }

    #[test]
    fn test_diff_no_changes() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let c = Component::new("pkg-a".to_string(), Some("1.0".to_string()));
        old.components.insert(c.id.clone(), c.clone());
        new.components.insert(c.id.clone(), c);

        let diff = Differ::diff(&old, &new, None);
        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert!(diff.changed.is_empty());
        assert!(diff.edge_diffs.is_empty());
    }

    #[test]
    fn test_diff_metadata_changed_timestamp() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        old.metadata.timestamp = Some("2024-01-01".into());
        new.metadata.timestamp = Some("2024-01-02".into());

        let diff = Differ::diff(&old, &new, None);
        assert!(diff.metadata_changed);
        assert!(!diff.is_empty());
    }

    #[test]
    fn test_diff_metadata_changed_tools() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        old.metadata.tools = vec!["syft".into()];
        new.metadata.tools = vec!["trivy".into()];

        let diff = Differ::diff(&old, &new, None);
        assert!(diff.metadata_changed);
    }

    #[test]
    fn test_diff_metadata_changed_authors() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        old.metadata.authors = vec!["alice".into()];
        new.metadata.authors = vec!["bob".into()];

        let diff = Differ::diff(&old, &new, None);
        assert!(diff.metadata_changed);
    }

    #[test]
    fn test_diff_metadata_unchanged() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        old.metadata.timestamp = Some("2024-01-01".into());
        new.metadata.timestamp = Some("2024-01-01".into());
        old.metadata.tools = vec!["syft".into()];
        new.metadata.tools = vec!["syft".into()];

        let diff = Differ::diff(&old, &new, None);
        assert!(!diff.metadata_changed);
    }

    #[test]
    fn test_diff_filtering() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let mut c1 = Component::new("pkg-a".to_string(), Some("1.0".to_string()));
        c1.licenses.insert("MIT".into());

        let mut c2 = c1.clone();
        c2.version = Some("1.1".to_string());
        c2.licenses = BTreeSet::from(["Apache-2.0".into()]);

        old.components.insert(c1.id.clone(), c1);
        new.components.insert(c2.id.clone(), c2);

        let diff = Differ::diff(&old, &new, Some(&[Field::Version]));
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].changes.len(), 1);
        assert!(matches!(
            diff.changed[0].changes[0],
            FieldChange::Version(_, _)
        ));
    }

    #[test]
    fn test_purl_change_same_ecosystem_name_is_change_not_add_remove() {
        // Component with purl in old, different purl in new (same ecosystem+name)
        // Should be treated as a CHANGE with Purl field change, not add/remove
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        // Old: lodash with one purl
        let mut c_old = Component::new("lodash".to_string(), Some("4.17.20".to_string()));
        c_old.purl = Some("pkg:npm/lodash@4.17.20".to_string());
        c_old.ecosystem = Some("npm".to_string());
        c_old.id = ComponentId::new(c_old.purl.as_deref(), &[]);

        // New: lodash with updated purl (version bump)
        let mut c_new = Component::new("lodash".to_string(), Some("4.17.21".to_string()));
        c_new.purl = Some("pkg:npm/lodash@4.17.21".to_string());
        c_new.ecosystem = Some("npm".to_string());
        c_new.id = ComponentId::new(c_new.purl.as_deref(), &[]);

        old.components.insert(c_old.id.clone(), c_old);
        new.components.insert(c_new.id.clone(), c_new);

        let diff = Differ::diff(&old, &new, None);

        // Should NOT be add/remove
        assert_eq!(diff.added.len(), 0, "Should not have added components");
        assert_eq!(diff.removed.len(), 0, "Should not have removed components");

        // Should be a change
        assert_eq!(diff.changed.len(), 1, "Should have one changed component");

        // Should include both Version and Purl changes
        let changes = &diff.changed[0].changes;
        assert!(changes
            .iter()
            .any(|c| matches!(c, FieldChange::Version(_, _))));
        assert!(changes.iter().any(|c| matches!(c, FieldChange::Purl(_, _))));
    }

    #[test]
    fn test_purl_removed_is_change() {
        // Component with purl in old, no purl in new (same name)
        // This is realistic: old SBOM from tool that adds purls, new from tool that doesn't
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let mut c_old = Component::new("lodash".to_string(), Some("4.17.21".to_string()));
        c_old.purl = Some("pkg:npm/lodash@4.17.21".to_string());
        c_old.ecosystem = Some("npm".to_string()); // Extracted from purl
        c_old.id = ComponentId::new(c_old.purl.as_deref(), &[]);

        // New component without purl - ecosystem is None (realistic!)
        let mut c_new = Component::new("lodash".to_string(), Some("4.17.21".to_string()));
        c_new.purl = None;
        c_new.ecosystem = None; // No purl means no ecosystem extraction
                                // ID will be hash-based since no purl
        c_new.id = ComponentId::new(None, &[("name", "lodash"), ("version", "4.17.21")]);

        old.components.insert(c_old.id.clone(), c_old);
        new.components.insert(c_new.id.clone(), c_new);

        let diff = Differ::diff(&old, &new, None);

        assert_eq!(diff.added.len(), 0, "Should not have added components");
        assert_eq!(diff.removed.len(), 0, "Should not have removed components");
        assert_eq!(diff.changed.len(), 1, "Should have one changed component");

        // Should have Purl change
        assert!(diff.changed[0]
            .changes
            .iter()
            .any(|c| matches!(c, FieldChange::Purl(_, _))));
    }

    #[test]
    fn test_purl_added_is_change() {
        // Component with no purl in old, purl in new
        // This is realistic: old SBOM without purls, new from better tooling
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let mut c_old = Component::new("lodash".to_string(), Some("4.17.21".to_string()));
        c_old.purl = None;
        c_old.ecosystem = None; // No purl means no ecosystem (realistic!)
        c_old.id = ComponentId::new(None, &[("name", "lodash"), ("version", "4.17.21")]);

        let mut c_new = Component::new("lodash".to_string(), Some("4.17.21".to_string()));
        c_new.purl = Some("pkg:npm/lodash@4.17.21".to_string());
        c_new.ecosystem = Some("npm".to_string()); // Extracted from purl
        c_new.id = ComponentId::new(c_new.purl.as_deref(), &[]);

        old.components.insert(c_old.id.clone(), c_old);
        new.components.insert(c_new.id.clone(), c_new);

        let diff = Differ::diff(&old, &new, None);

        assert_eq!(diff.added.len(), 0, "Should not have added components");
        assert_eq!(diff.removed.len(), 0, "Should not have removed components");
        assert_eq!(diff.changed.len(), 1, "Should have one changed component");
    }

    #[test]
    fn test_same_name_different_ecosystems_not_matched() {
        // Two components with same name but different ecosystems should NOT match
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        // Old: "utils" from npm
        let mut c_old = Component::new("utils".to_string(), Some("1.0.0".to_string()));
        c_old.purl = Some("pkg:npm/utils@1.0.0".to_string());
        c_old.ecosystem = Some("npm".to_string());
        c_old.id = ComponentId::new(c_old.purl.as_deref(), &[]);

        // New: "utils" from pypi (different ecosystem!)
        let mut c_new = Component::new("utils".to_string(), Some("1.0.0".to_string()));
        c_new.purl = Some("pkg:pypi/utils@1.0.0".to_string());
        c_new.ecosystem = Some("pypi".to_string());
        c_new.id = ComponentId::new(c_new.purl.as_deref(), &[]);

        old.components.insert(c_old.id.clone(), c_old);
        new.components.insert(c_new.id.clone(), c_new);

        let diff = Differ::diff(&old, &new, None);

        // Should be separate add/remove, NOT a change
        assert_eq!(diff.added.len(), 1, "pypi/utils should be added");
        assert_eq!(diff.removed.len(), 1, "npm/utils should be removed");
        assert_eq!(
            diff.changed.len(),
            0,
            "Should not match different ecosystems"
        );
    }

    #[test]
    fn test_same_name_both_no_ecosystem_matched() {
        // Components with same name and both having None ecosystem should match
        // (backwards compatibility for SBOMs without purls)
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let mut c_old = Component::new("mystery-pkg".to_string(), Some("1.0.0".to_string()));
        c_old.ecosystem = None;

        let mut c_new = Component::new("mystery-pkg".to_string(), Some("2.0.0".to_string()));
        c_new.ecosystem = None;

        old.components.insert(c_old.id.clone(), c_old);
        new.components.insert(c_new.id.clone(), c_new);

        let diff = Differ::diff(&old, &new, None);

        assert_eq!(diff.added.len(), 0);
        assert_eq!(diff.removed.len(), 0);
        assert_eq!(
            diff.changed.len(),
            1,
            "Same name with None ecosystems should match"
        );
    }

    #[test]
    fn test_edge_diff_added_removed() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let c1 = Component::new("parent".to_string(), Some("1.0".to_string()));
        let c2 = Component::new("child-a".to_string(), Some("1.0".to_string()));
        let c3 = Component::new("child-b".to_string(), Some("1.0".to_string()));

        let parent_id = c1.id.clone();
        let child_a_id = c2.id.clone();
        let child_b_id = c3.id.clone();

        // Add all components to both SBOMs
        old.components.insert(c1.id.clone(), c1.clone());
        old.components.insert(c2.id.clone(), c2.clone());
        old.components.insert(c3.id.clone(), c3.clone());

        new.components.insert(c1.id.clone(), c1);
        new.components.insert(c2.id.clone(), c2);
        new.components.insert(c3.id.clone(), c3);

        // Old: parent -> child-a
        old.dependencies
            .entry(parent_id.clone())
            .or_default()
            .insert(child_a_id.clone());

        // New: parent -> child-b (removed child-a, added child-b)
        new.dependencies
            .entry(parent_id.clone())
            .or_default()
            .insert(child_b_id.clone());

        let diff = Differ::diff(&old, &new, None);

        assert_eq!(diff.edge_diffs.len(), 1);
        assert_eq!(diff.edge_diffs[0].parent, parent_id);
        assert!(diff.edge_diffs[0].added.contains(&child_b_id));
        assert!(diff.edge_diffs[0].removed.contains(&child_a_id));
    }

    #[test]
    fn test_edge_diff_with_identity_reconciliation() {
        // Test that edge diffs work when components are matched by identity
        // (different IDs but same name/ecosystem)
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        // Parent with purl in old
        let mut parent_old = Component::new("parent".to_string(), Some("1.0".to_string()));
        parent_old.purl = Some("pkg:npm/parent@1.0".to_string());
        parent_old.ecosystem = Some("npm".to_string());
        parent_old.id = ComponentId::new(parent_old.purl.as_deref(), &[]);

        // Parent with different purl in new (same name/ecosystem)
        let mut parent_new = Component::new("parent".to_string(), Some("1.1".to_string()));
        parent_new.purl = Some("pkg:npm/parent@1.1".to_string());
        parent_new.ecosystem = Some("npm".to_string());
        parent_new.id = ComponentId::new(parent_new.purl.as_deref(), &[]);

        // Child component (same in both)
        let child = Component::new("child".to_string(), Some("1.0".to_string()));

        old.components
            .insert(parent_old.id.clone(), parent_old.clone());
        old.components.insert(child.id.clone(), child.clone());

        new.components
            .insert(parent_new.id.clone(), parent_new.clone());
        new.components.insert(child.id.clone(), child.clone());

        // Old: parent -> child
        old.dependencies
            .entry(parent_old.id.clone())
            .or_default()
            .insert(child.id.clone());

        // New: parent -> child (same edge, but parent has different ID)
        new.dependencies
            .entry(parent_new.id.clone())
            .or_default()
            .insert(child.id.clone());

        let diff = Differ::diff(&old, &new, None);

        // Components should be matched by identity, so no spurious edge changes
        // (the edge parent->child exists in both, just under different parent IDs)
        assert_eq!(
            diff.edge_diffs.len(),
            0,
            "No edge changes expected when parent is reconciled by identity"
        );
    }

    #[test]
    fn test_edge_diff_filtering() {
        // Test that --only filtering excludes edge diffs when deps not included
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let c1 = Component::new("parent".to_string(), Some("1.0".to_string()));
        let c2 = Component::new("child".to_string(), Some("1.0".to_string()));

        let parent_id = c1.id.clone();
        let child_id = c2.id.clone();

        old.components.insert(c1.id.clone(), c1.clone());
        old.components.insert(c2.id.clone(), c2.clone());

        new.components.insert(c1.id.clone(), c1);
        new.components.insert(c2.id.clone(), c2);

        // New has an edge that old doesn't
        new.dependencies
            .entry(parent_id.clone())
            .or_default()
            .insert(child_id);

        // Without filtering - should have edge diff
        let diff = Differ::diff(&old, &new, None);
        assert_eq!(diff.edge_diffs.len(), 1);

        // With filtering to only Version - should NOT have edge diff
        let diff_filtered = Differ::diff(&old, &new, Some(&[Field::Version]));
        assert_eq!(diff_filtered.edge_diffs.len(), 0);

        // With filtering to include Deps - should have edge diff
        let diff_with_deps = Differ::diff(&old, &new, Some(&[Field::Deps]));
        assert_eq!(diff_with_deps.edge_diffs.len(), 1);
    }

    #[test]
    fn test_ecosystem_breakdown() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        // npm component in old only (removed)
        let mut c1 = Component::new("lodash".into(), Some("4.17.21".into()));
        c1.ecosystem = Some("npm".into());
        old.components.insert(c1.id.clone(), c1);

        // npm component in new only (added)
        let mut c2 = Component::new("express".into(), Some("4.18.0".into()));
        c2.ecosystem = Some("npm".into());
        new.components.insert(c2.id.clone(), c2);

        // cargo component in new only (added)
        let mut c3 = Component::new("serde".into(), Some("1.0.0".into()));
        c3.ecosystem = Some("cargo".into());
        new.components.insert(c3.id.clone(), c3);

        // npm component changed (present in both, different version)
        let mut c4_old = Component::new("react".into(), Some("17.0.0".into()));
        c4_old.ecosystem = Some("npm".into());
        let mut c4_new = Component::new("react".into(), Some("18.0.0".into()));
        c4_new.ecosystem = Some("npm".into());
        old.components.insert(c4_old.id.clone(), c4_old);
        new.components.insert(c4_new.id.clone(), c4_new);

        // component with no ecosystem (added)
        let c5 = Component::new("mystery".into(), Some("1.0".into()));
        new.components.insert(c5.id.clone(), c5);

        let diff = Differ::diff(&old, &new, None);
        let breakdown = diff.ecosystem_breakdown();

        let npm = breakdown.get("npm").unwrap();
        assert_eq!(npm.added, 1);
        assert_eq!(npm.removed, 1);
        assert_eq!(npm.changed, 1);

        let cargo = breakdown.get("cargo").unwrap();
        assert_eq!(cargo.added, 1);
        assert_eq!(cargo.removed, 0);
        assert_eq!(cargo.changed, 0);

        let unknown = breakdown.get("unknown").unwrap();
        assert_eq!(unknown.added, 1);
        assert_eq!(unknown.removed, 0);
        assert_eq!(unknown.changed, 0);
    }

    #[test]
    fn test_ecosystem_breakdown_empty_diff() {
        let old = Sbom::default();
        let new = Sbom::default();

        let diff = Differ::diff(&old, &new, None);
        assert!(diff.is_empty());
        assert!(diff.ecosystem_breakdown().is_empty());
    }

    #[test]
    fn test_group_by_ecosystem_empty_diff() {
        let old = Sbom::default();
        let new = Sbom::default();

        let diff = Differ::diff(&old, &new, None);
        let grouped = diff.group_by_ecosystem();
        assert!(grouped.by_ecosystem.is_empty());
        assert!(grouped.edge_diffs.is_empty());
        assert!(!grouped.metadata_changed);
        assert!(grouped.ecosystem_breakdown().is_empty());
    }

    #[test]
    fn test_group_by_ecosystem_groups_correctly() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        // npm removed
        let mut c1 = Component::new("lodash".into(), Some("4.17.21".into()));
        c1.ecosystem = Some("npm".into());
        old.components.insert(c1.id.clone(), c1);

        // npm added
        let mut c2 = Component::new("express".into(), Some("4.18.0".into()));
        c2.ecosystem = Some("npm".into());
        new.components.insert(c2.id.clone(), c2);

        // cargo added
        let mut c3 = Component::new("serde".into(), Some("1.0.0".into()));
        c3.ecosystem = Some("cargo".into());
        new.components.insert(c3.id.clone(), c3);

        // npm changed
        let mut c4_old = Component::new("react".into(), Some("17.0.0".into()));
        c4_old.ecosystem = Some("npm".into());
        let mut c4_new = Component::new("react".into(), Some("18.0.0".into()));
        c4_new.ecosystem = Some("npm".into());
        old.components.insert(c4_old.id.clone(), c4_old);
        new.components.insert(c4_new.id.clone(), c4_new);

        // unknown added
        let c5 = Component::new("mystery".into(), Some("1.0".into()));
        new.components.insert(c5.id.clone(), c5);

        let diff = Differ::diff(&old, &new, None);
        let grouped = diff.group_by_ecosystem();

        let npm = grouped.by_ecosystem.get("npm").unwrap();
        assert_eq!(npm.added.len(), 1);
        assert_eq!(npm.removed.len(), 1);
        assert_eq!(npm.changed.len(), 1);

        let cargo = grouped.by_ecosystem.get("cargo").unwrap();
        assert_eq!(cargo.added.len(), 1);
        assert_eq!(cargo.removed.len(), 0);
        assert_eq!(cargo.changed.len(), 0);

        let unknown = grouped.by_ecosystem.get("unknown").unwrap();
        assert_eq!(unknown.added.len(), 1);
        assert_eq!(unknown.removed.len(), 0);
        assert_eq!(unknown.changed.len(), 0);

        // Derived breakdown should match direct breakdown
        let grouped_counts = grouped.ecosystem_breakdown();
        let direct_counts = diff.ecosystem_breakdown();
        assert_eq!(grouped_counts, direct_counts);
    }
}
