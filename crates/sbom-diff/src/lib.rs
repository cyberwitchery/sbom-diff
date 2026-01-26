#![doc = include_str!("../readme.md")]

use sbom_model::{Component, ComponentId, Sbom};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

pub mod renderer;

/// The result of comparing two SBOMs.
///
/// Contains lists of added, removed, and changed components.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diff {
    /// Components present in the new SBOM but not the old.
    pub added: Vec<Component>,
    /// Components present in the old SBOM but not the new.
    pub removed: Vec<Component>,
    /// Components present in both with field-level changes.
    pub changed: Vec<ComponentChange>,
    /// Whether document metadata differs (usually ignored).
    pub metadata_changed: bool,
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

/// A specific field that changed between two versions of a component.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FieldChange {
    /// Version changed: (old, new).
    Version(String, String),
    /// Licenses changed: (old, new).
    License(Vec<String>, Vec<String>),
    /// Supplier changed: (old, new).
    Supplier(Option<String>, Option<String>),
    /// Package URL changed: (old, new).
    Purl(Option<String>, Option<String>),
    /// Hashes changed (details not tracked).
    Hashes,
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
    /// Checksums.
    Hashes,
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

        old.normalize();
        new.normalize();

        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut changed = Vec::new();

        let mut processed_old = HashSet::new();
        let mut processed_new = HashSet::new();

        // 1. Match by ID
        for (id, new_comp) in &new.components {
            if let Some(old_comp) = old.components.get(id) {
                processed_old.insert(id.clone());
                processed_new.insert(id.clone());

                if let Some(change) = Self::compute_change(old_comp, new_comp, only) {
                    changed.push(change);
                }
            }
        }

        // 2. Reconciliation: Match by "Identity" (Name + Ecosystem)
        let mut old_identity_map = BTreeMap::new();
        for (id, comp) in &old.components {
            if !processed_old.contains(id) {
                let identity = (comp.ecosystem.clone(), comp.name.clone());
                old_identity_map
                    .entry(identity)
                    .or_insert_with(Vec::new)
                    .push(id.clone());
            }
        }

        for (id, new_comp) in &new.components {
            if processed_new.contains(id) {
                continue;
            }

            let identity = (new_comp.ecosystem.clone(), new_comp.name.clone());
            if let Some(old_ids) = old_identity_map.get_mut(&identity) {
                if let Some(old_id) = old_ids.pop() {
                    if let Some(old_comp) = old.components.get(&old_id) {
                        processed_old.insert(old_id.clone());
                        processed_new.insert(id.clone());

                        if let Some(change) = Self::compute_change(old_comp, new_comp, only) {
                            changed.push(change);
                        }
                        continue;
                    }
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

        Diff {
            added,
            removed,
            changed,
            metadata_changed: old.metadata != new.metadata,
        }
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

        if should_include(Field::Hashes) && old.hashes != new.hashes {
            changes.push(FieldChange::Hashes);
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
    fn test_diff_filtering() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let mut c1 = Component::new("pkg-a".to_string(), Some("1.0".to_string()));
        c1.licenses.push("MIT".into());

        let mut c2 = c1.clone();
        c2.version = Some("1.1".to_string());
        c2.licenses = vec!["Apache-2.0".into()];

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
}
