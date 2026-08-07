#![doc = include_str!("../readme.md")]

use sbom_model::versions::{is_version_downgrade, Version};
use sbom_model::{Component, ComponentId, DependencyKind, Sbom};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashSet};

pub mod renderer;

/// structured tracking of document metadata changes between two SBOMs.
///
/// instead of a simple boolean, this captures exactly which metadata fields
/// differ, making it possible to render meaningful output and gate CI on
/// specific metadata changes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetadataChange {
    /// timestamp changed: (old, new).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<(Option<String>, Option<String>)>,
    /// tools changed: (old, new).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<(Vec<String>, Vec<String>)>,
    /// authors changed: (old, new).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authors: Option<(Vec<String>, Vec<String>)>,
}

impl MetadataChange {
    /// returns true if no metadata fields actually differ.
    pub fn is_empty(&self) -> bool {
        self.timestamp.is_none() && self.tools.is_none() && self.authors.is_none()
    }
}

/// per-ecosystem counts of added, removed, and changed components.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EcosystemCounts {
    pub added: usize,
    pub removed: usize,
    pub changed: usize,
}

/// the result of comparing two SBOMs.
///
/// contains lists of added, removed, and changed components,
/// as well as dependency edge changes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Diff {
    /// components present in the new SBOM but not the old.
    pub added: Vec<Component>,
    /// components present in the old SBOM but not the new.
    pub removed: Vec<Component>,
    /// components present in both with field-level changes.
    pub changed: Vec<ComponentChange>,
    /// dependency edge changes between components.
    pub edge_diffs: Vec<EdgeDiff>,
    /// structured metadata change details, or `None` if metadata is unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_changed: Option<MetadataChange>,
    /// total number of components in the old SBOM.
    pub old_total: usize,
    /// total number of components in the new SBOM.
    pub new_total: usize,
    /// number of components present in both SBOMs with no changes.
    pub unchanged: usize,
    /// human-readable display names for component IDs that appear in edge diffs.
    ///
    /// maps hash-based IDs (`h:...`) to `name@version` or `name` so that edge
    /// diff output is readable without cross-referencing the full component list.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub component_names: BTreeMap<ComponentId, String>,
}

impl Diff {
    /// returns `true` if the diff contains no changes of any kind.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.changed.is_empty()
            && self.edge_diffs.is_empty()
            && self.metadata_changed.is_none()
    }

    /// returns a human-readable display name for a component ID.
    ///
    /// looks up the ID in `component_names`; falls back to the raw ID string.
    pub fn display_name<'a>(&'a self, id: &'a ComponentId) -> &'a str {
        self.component_names
            .get(id)
            .map(String::as_str)
            .unwrap_or_else(|| id.as_str())
    }

    /// groups added/removed/changed counts by package ecosystem.
    ///
    /// components without an ecosystem are grouped under `"unknown"`.
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

    /// groups the full diff by ecosystem, returning per-ecosystem slices.
    ///
    /// components without an ecosystem are grouped under `"unknown"`.
    /// this clones components out of the diff; use
    /// [`into_group_by_ecosystem`](Self::into_group_by_ecosystem) to move
    /// them instead when you own the diff.
    pub fn group_by_ecosystem(&self) -> GroupedDiff {
        group_components_by_ecosystem(
            self.added.iter().cloned(),
            self.removed.iter().cloned(),
            self.changed.iter().cloned(),
            self.edge_diffs.clone(),
            self.metadata_changed.clone(),
        )
    }

    /// consuming variant of [`group_by_ecosystem`](Self::group_by_ecosystem)
    /// that moves components instead of cloning them.
    pub fn into_group_by_ecosystem(self) -> GroupedDiff {
        group_components_by_ecosystem(
            self.added,
            self.removed,
            self.changed,
            self.edge_diffs,
            self.metadata_changed,
        )
    }

    /// filters the diff to only include components whose ecosystem matches
    /// the given predicate. adjusts `old_total`, `new_total`, and `unchanged`
    /// to reflect the filtered view.
    ///
    /// `filtered_old_total` and `filtered_new_total` are the pre-counted
    /// number of components in each SBOM that pass the predicate. these must
    /// be computed before [`Differ::diff_owned`] consumes the SBOMs.
    ///
    /// `component_ecosystems` maps component IDs to their ecosystem, built
    /// from both SBOMs before they are consumed. this is used to filter
    /// edge diffs by the parent component's ecosystem.
    pub fn filter_by_ecosystem<F: Fn(Option<&str>) -> bool>(
        &mut self,
        matches: &F,
        filtered_old_total: usize,
        filtered_new_total: usize,
        component_ecosystems: &BTreeMap<ComponentId, Option<String>>,
    ) {
        self.added.retain(|c| matches(c.ecosystem.as_deref()));
        self.removed.retain(|c| matches(c.ecosystem.as_deref()));
        self.changed.retain(|c| matches(c.new.ecosystem.as_deref()));

        // filter edge diffs by parent ecosystem; keep edges whose parent is
        // unknown (not in the map) as a conservative default.
        self.edge_diffs.retain(|edge| {
            component_ecosystems
                .get(&edge.parent)
                .map(|eco| matches(eco.as_deref()))
                .unwrap_or(true)
        });

        // prune component_names to only IDs still referenced in edge diffs
        let mut referenced_ids = BTreeSet::new();
        for edge in &self.edge_diffs {
            referenced_ids.insert(&edge.parent);
            referenced_ids.extend(edge.added.keys());
            referenced_ids.extend(edge.removed.keys());
            referenced_ids.extend(edge.kind_changed.keys());
        }
        self.component_names
            .retain(|id, _| referenced_ids.contains(id));

        self.old_total = filtered_old_total;
        self.new_total = filtered_new_total;
        // derive unchanged from the NEW side, consistent with added/changed
        // (both retained by new-side ecosystem). deriving from the old side
        // over-counts a matched pair whose ecosystem changes across the filter
        // boundary, which can push unchanged above new_total.
        self.unchanged = filtered_new_total
            .saturating_sub(self.added.len())
            .saturating_sub(self.changed.len());
    }
}

/// shared implementation for [`Diff::group_by_ecosystem`] and
/// [`Diff::into_group_by_ecosystem`]. accepts owned iterators so both the
/// cloning and consuming callers can share the same loop logic.
fn group_components_by_ecosystem(
    added: impl IntoIterator<Item = Component>,
    removed: impl IntoIterator<Item = Component>,
    changed: impl IntoIterator<Item = ComponentChange>,
    edge_diffs: Vec<EdgeDiff>,
    metadata_changed: Option<MetadataChange>,
) -> GroupedDiff {
    let mut ecosystems: BTreeMap<String, EcosystemDiff> = BTreeMap::new();

    for c in added {
        let eco = c.ecosystem.as_deref().unwrap_or("unknown").to_string();
        ecosystems.entry(eco).or_default().added.push(c);
    }
    for c in removed {
        let eco = c.ecosystem.as_deref().unwrap_or("unknown").to_string();
        ecosystems.entry(eco).or_default().removed.push(c);
    }
    for c in changed {
        let eco = c.new.ecosystem.as_deref().unwrap_or("unknown").to_string();
        ecosystems.entry(eco).or_default().changed.push(c);
    }

    GroupedDiff {
        by_ecosystem: ecosystems,
        edge_diffs,
        metadata_changed,
    }
}

/// diff grouped by package ecosystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupedDiff {
    pub by_ecosystem: BTreeMap<String, EcosystemDiff>,
    pub edge_diffs: Vec<EdgeDiff>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_changed: Option<MetadataChange>,
}

impl GroupedDiff {
    /// derives per-ecosystem counts from the already-grouped data.
    ///
    /// this avoids a redundant traversal when both grouped components and
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

/// per-ecosystem slice of added, removed, and changed components.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EcosystemDiff {
    pub added: Vec<Component>,
    pub removed: Vec<Component>,
    pub changed: Vec<ComponentChange>,
}

/// a component that exists in both SBOMs with detected changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentChange {
    /// the component identifier (from the new SBOM).
    pub id: ComponentId,
    /// the component as it appeared in the old SBOM.
    pub old: Component,
    /// the component as it appears in the new SBOM.
    pub new: Component,
    /// list of specific field changes detected.
    pub changes: Vec<FieldChange>,
    /// true when the version change is a downgrade (higher to lower).
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_downgrade: bool,
}

fn is_false(b: &bool) -> bool {
    !b
}

/// a dependency edge change for a single parent component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeDiff {
    /// the parent component whose dependencies changed.
    pub parent: ComponentId,
    /// dependencies added in the new SBOM, with their dependency kind.
    pub added: BTreeMap<ComponentId, DependencyKind>,
    /// dependencies removed from the old SBOM, with their dependency kind.
    pub removed: BTreeMap<ComponentId, DependencyKind>,
    /// dependencies whose kind changed between old and new (old_kind, new_kind).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub kind_changed: BTreeMap<ComponentId, (DependencyKind, DependencyKind)>,
}

/// a specific field that changed between two versions of a component.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FieldChange {
    /// version changed: (old, new).
    Version(Option<String>, Option<String>),
    /// licenses changed: (old, new).
    License(BTreeSet<String>, BTreeSet<String>),
    /// supplier changed: (old, new).
    Supplier(Option<String>, Option<String>),
    /// package URL changed: (old, new).
    Purl(Option<String>, Option<String>),
    /// description changed: (old, new).
    Description(Option<String>, Option<String>),
    /// hashes changed: (old, new).
    Hashes(BTreeMap<String, String>, BTreeMap<String, String>),
    /// ecosystem changed: (old, new).
    Ecosystem(Option<String>, Option<String>),
}

/// fields that can be compared and filtered.
///
/// use with [`Differ::diff`] to limit comparison to specific fields.
#[derive(Debug, Copy, Clone, PartialEq, Eq, clap::ValueEnum)]
pub enum Field {
    /// package version.
    Version,
    /// license identifiers.
    License,
    /// supplier/publisher.
    Supplier,
    /// package URL.
    Purl,
    /// human-readable description.
    Description,
    /// checksums.
    Hashes,
    /// package ecosystem.
    Ecosystem,
    /// dependency edges.
    Deps,
}

/// how many same-identity candidates a reconciliation bucket may hold before
/// the version alignment gives up and pairs them by id.
const MAX_ALIGNED_CANDIDATES: usize = 256;

/// SBOM comparison engine.
///
/// compares two SBOMs and produces a [`Diff`] describing the changes.
/// components are matched first by ID (purl), then by identity (name + ecosystem).
pub struct Differ;

impl Differ {
    /// compares two SBOMs and returns the differences.
    ///
    /// both SBOMs are normalized before comparison to ignore irrelevant differences
    /// like ordering or metadata timestamps. this method clones both SBOMs
    /// internally; use [`diff_owned`](Self::diff_owned) to avoid cloning when
    /// you already own the SBOMs.
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
    /// // compare only version and license changes
    /// let diff = Differ::diff(&old, &new, Some(&[Field::Version, Field::License]));
    /// ```
    pub fn diff(old: &Sbom, new: &Sbom, only: Option<&[Field]>) -> Diff {
        Self::diff_owned(old.clone(), new.clone(), only)
    }

    /// consuming variant of [`diff`](Self::diff) that normalizes in place,
    /// avoiding two full SBOM clones.
    pub fn diff_owned(mut old: Sbom, mut new: Sbom, only: Option<&[Field]>) -> Diff {
        // compare metadata before normalize() strips volatile fields
        let metadata_changed = {
            let mut mc = MetadataChange {
                timestamp: None,
                tools: None,
                authors: None,
            };
            if old.metadata.timestamp != new.metadata.timestamp {
                mc.timestamp = Some((
                    old.metadata.timestamp.clone(),
                    new.metadata.timestamp.clone(),
                ));
            }
            if old.metadata.tools != new.metadata.tools {
                mc.tools = Some((old.metadata.tools.clone(), new.metadata.tools.clone()));
            }
            if old.metadata.authors != new.metadata.authors {
                mc.authors = Some((old.metadata.authors.clone(), new.metadata.authors.clone()));
            }
            if mc.is_empty() {
                None
            } else {
                Some(mc)
            }
        };

        old.normalize();
        new.normalize();

        // phase 1: collect match decisions using only borrows — no component
        // clones. we record (old_id, new_id, field_changes) triples for pairs
        // that actually differ and track all matched IDs for later draining.
        let mut changed_pairs: Vec<(ComponentId, ComponentId, Vec<FieldChange>)> = Vec::new();
        let mut matched_old: HashSet<ComponentId> = HashSet::new();
        let mut matched_new: HashSet<ComponentId> = HashSet::new();

        // track old_id -> new_id mappings for edge reconciliation
        let mut id_mapping: BTreeMap<ComponentId, ComponentId> = BTreeMap::new();

        // 1. match by ID
        for (id, new_comp) in &new.components {
            if let Some(old_comp) = old.components.get(id) {
                matched_old.insert(id.clone());
                matched_new.insert(id.clone());
                id_mapping.insert(id.clone(), id.clone());

                let fields = Self::compute_fields(old_comp, new_comp, only);
                if !fields.is_empty() {
                    changed_pairs.push((id.clone(), id.clone(), fields));
                }
            }
        }

        // 2. reconciliation: match by "identity" (name + ecosystem)
        // when purls are absent or change, we match by (ecosystem, name).
        // if either ecosystem is None, we treat it as a wildcard and match by name alone.
        //
        // the map is keyed by name, then by ecosystem, so the wildcard lookup
        // (new has no ecosystem → match any old with the same name) is O(k)
        // where k is the number of distinct ecosystems sharing that name,
        // rather than a linear scan of the entire map.
        let mut old_identity_map: BTreeMap<String, BTreeMap<Option<String>, Vec<ComponentId>>> =
            BTreeMap::new();
        for (id, comp) in &old.components {
            if !matched_old.contains(id) {
                old_identity_map
                    .entry(comp.name.clone())
                    .or_default()
                    .entry(comp.ecosystem.clone())
                    .or_default()
                    .push(id.clone());
            }
        }
        let mut new_identity_map: BTreeMap<String, BTreeMap<Option<String>, Vec<ComponentId>>> =
            BTreeMap::new();
        for (id, comp) in &new.components {
            if !matched_new.contains(id) {
                new_identity_map
                    .entry(comp.name.clone())
                    .or_default()
                    .entry(comp.ecosystem.clone())
                    .or_default()
                    .push(id.clone());
            }
        }

        // 2a. exact (ecosystem, name) matches are resolved a whole bucket at a
        // time, so several versions of one package pair up in version order.
        let mut identity_pairs: Vec<(ComponentId, ComponentId)> = Vec::new();
        for (name, new_eco_map) in &new_identity_map {
            let Some(old_eco_map) = old_identity_map.get_mut(name) else {
                continue;
            };
            for (ecosystem, new_ids) in new_eco_map {
                let Some(old_ids) = old_eco_map.get_mut(ecosystem) else {
                    continue;
                };
                let pairs = Self::align_by_version(old_ids, new_ids, &old, &new);
                let consumed: HashSet<ComponentId> =
                    pairs.iter().map(|(old_id, _)| old_id.clone()).collect();
                old_ids.retain(|id| !consumed.contains(id));
                identity_pairs.extend(pairs);
            }
        }
        for (_, new_id) in &identity_pairs {
            matched_new.insert(new_id.clone());
        }

        // 2b. what is left falls through to the wildcard cases, aligned by
        // version as well; an ecosystem-less new component pools every old
        // ecosystem of that name, so the version-nearest candidate wins over
        // the alphabetically first.
        for (name, new_eco_map) in &new_identity_map {
            let Some(old_eco_map) = old_identity_map.get_mut(name) else {
                continue;
            };
            for (ecosystem, new_ids) in new_eco_map {
                let new_ids: Vec<ComponentId> = new_ids
                    .iter()
                    .filter(|id| !matched_new.contains(*id))
                    .cloned()
                    .collect();
                if new_ids.is_empty() {
                    continue;
                }
                let old_ids: Vec<ComponentId> = if ecosystem.is_some() {
                    old_eco_map.get(&None).cloned().unwrap_or_default()
                } else {
                    old_eco_map.values().flatten().cloned().collect()
                };
                let pairs = Self::align_by_version(&old_ids, &new_ids, &old, &new);
                let consumed: HashSet<ComponentId> =
                    pairs.iter().map(|(old_id, _)| old_id.clone()).collect();
                for ids in old_eco_map.values_mut() {
                    ids.retain(|id| !consumed.contains(id));
                }
                for (_, new_id) in &pairs {
                    matched_new.insert(new_id.clone());
                }
                identity_pairs.extend(pairs);
            }
        }

        identity_pairs.sort_by(|a, b| a.1.cmp(&b.1));
        for (old_id, new_id) in identity_pairs {
            let (Some(old_comp), Some(new_comp)) =
                (old.components.get(&old_id), new.components.get(&new_id))
            else {
                continue;
            };
            matched_old.insert(old_id.clone());
            matched_new.insert(new_id.clone());
            id_mapping.insert(old_id.clone(), new_id.clone());

            let fields = Self::compute_fields(old_comp, new_comp, only);
            if !fields.is_empty() {
                changed_pairs.push((old_id, new_id, fields));
            }
        }

        // 3. compute totals (must happen before draining the maps)
        let old_total = old.components.len();
        let new_total = new.components.len();
        let matched = matched_old.len();
        let unchanged = matched - changed_pairs.len();

        // 4. compute edge diffs (needs dependencies, not component values)
        let should_include_deps = only.is_none_or(|fields| fields.contains(&Field::Deps));
        let edge_diffs = if should_include_deps {
            Self::compute_edge_diffs(&old, &new, &id_mapping)
        } else {
            Vec::new()
        };

        // 5. build human-readable name map (needs component maps intact)
        let component_names = Self::build_component_names(&old, &new, &edge_diffs);

        // phase 2: drain components by moving them out of the maps, avoiding
        // all Component::clone() calls.

        // 6. drain changed pairs — swap_remove moves values out of the IndexMap
        let mut changed = Vec::with_capacity(changed_pairs.len());
        for (old_id, new_id, fields) in changed_pairs {
            let old_comp = old.components.swap_remove(&old_id).unwrap();
            let new_comp = new.components.swap_remove(&new_id).unwrap();
            let downgrade = fields.iter().any(|f| match f {
                FieldChange::Version(Some(old_ver), Some(new_ver)) => {
                    is_version_downgrade(old_ver, new_ver)
                }
                _ => false,
            });
            changed.push(ComponentChange {
                id: new_comp.id.clone(),
                old: old_comp,
                new: new_comp,
                changes: fields,
                is_downgrade: downgrade,
            });
        }

        // 7. remove unchanged matched components (already drained changed ones
        //    above, so swap_remove returns None for those — that's fine)
        for id in &matched_old {
            old.components.swap_remove(id);
        }
        for id in &matched_new {
            new.components.swap_remove(id);
        }

        // 8. drain remaining: everything left is unmatched
        let added: Vec<Component> = new.components.into_values().collect();
        let removed: Vec<Component> = old.components.into_values().collect();

        Diff {
            added,
            removed,
            changed,
            edge_diffs,
            metadata_changed,
            old_total,
            new_total,
            unchanged,
            component_names,
        }
    }

    /// pairs same-identity candidates by aligning them in version order, so that
    /// pairings never cross; unequal counts and ties resolve to the smallest
    /// total distance in the merged version order, then to the fewest downgrades.
    ///
    /// candidates whose versions admit no total order — absent, opaque, or of
    /// mixed [`Version`] variants — are paired by id instead, as are buckets
    /// above [`MAX_ALIGNED_CANDIDATES`].
    fn align_by_version(
        old_ids: &[ComponentId],
        new_ids: &[ComponentId],
        old: &Sbom,
        new: &Sbom,
    ) -> Vec<(ComponentId, ComponentId)> {
        let by_id = || -> Vec<(ComponentId, ComponentId)> {
            new_ids
                .iter()
                .zip(old_ids.iter().rev())
                .map(|(new_id, old_id)| (old_id.clone(), new_id.clone()))
                .collect()
        };

        if old_ids.is_empty() || new_ids.is_empty() {
            return Vec::new();
        }
        if old_ids.len() > MAX_ALIGNED_CANDIDATES || new_ids.len() > MAX_ALIGNED_CANDIDATES {
            return by_id();
        }

        let mut merged: Vec<(Version, u8, &ComponentId)> =
            Vec::with_capacity(old_ids.len() + new_ids.len());
        for (side, ids, sbom) in [(0u8, old_ids, old), (1u8, new_ids, new)] {
            for id in ids {
                let Some(version) = sbom.components.get(id).and_then(|c| c.version.as_deref())
                else {
                    return by_id();
                };
                merged.push((Version::parse_lenient(version), side, id));
            }
        }
        // `sort_by` needs a strict weak ordering; comparability is an equivalence, so
        // one class check against the first element rules out a mixed-class bucket.
        let first = &merged[0].0;
        if first.partial_cmp_lenient(first).is_none()
            || merged
                .iter()
                .any(|(version, ..)| first.partial_cmp_lenient(version).is_none())
        {
            return by_id();
        }
        // comparability is not enough: `Semver` against `Numeric` drops the pre-release,
        // so `Equal` stops being transitive once a bucket holds both.
        let (mut numeric, mut prerelease) = (false, false);
        for (version, ..) in &merged {
            match version {
                Version::Numeric(_) => numeric = true,
                Version::Semver(v) => prerelease |= !v.pre.is_empty(),
                _ => {}
            }
        }
        if numeric && prerelease {
            return by_id();
        }
        merged.sort_by(|a, b| {
            a.0.partial_cmp_lenient(&b.0)
                .unwrap_or(Ordering::Equal)
                .then_with(|| a.1.cmp(&b.1))
                .then_with(|| a.2.cmp(b.2))
        });

        let (mut old_ranked, mut new_ranked) = (Vec::new(), Vec::new());
        for (rank, (version, side, id)) in merged.iter().enumerate() {
            if *side == 0 {
                old_ranked.push((rank, *id, version));
            } else {
                new_ranked.push((rank, *id, version));
            }
        }

        let (n, m) = (old_ranked.len(), new_ranked.len());
        let cost = |i: usize, j: usize| {
            (
                old_ranked[i].0.abs_diff(new_ranked[j].0),
                usize::from(old_ranked[i].2.is_downgrade(new_ranked[j].2)),
            )
        };
        let better = |a: (usize, usize, usize), b: (usize, usize, usize)| {
            a.0 > b.0 || (a.0 == b.0 && (a.1, a.2) < (b.1, b.2))
        };
        let paired_with = |(pairs, distance, downgrades): (usize, usize, usize), i, j| {
            let (extra_distance, extra_downgrade) = cost(i, j);
            (
                pairs + 1,
                distance + extra_distance,
                downgrades + extra_downgrade,
            )
        };

        // score[i][j]: best (pairs, total distance, downgrades) from candidates i and j on
        let mut score = vec![vec![(0usize, 0usize, 0usize); m + 1]; n + 1];
        for i in (0..n).rev() {
            for j in (0..m).rev() {
                let mut best = paired_with(score[i + 1][j + 1], i, j);
                if better(score[i + 1][j], best) {
                    best = score[i + 1][j];
                }
                if better(score[i][j + 1], best) {
                    best = score[i][j + 1];
                }
                score[i][j] = best;
            }
        }

        let mut pairs = Vec::with_capacity(n.min(m));
        let (mut i, mut j) = (0, 0);
        while i < n && j < m {
            let take = paired_with(score[i + 1][j + 1], i, j);
            if !better(score[i + 1][j], take) && !better(score[i][j + 1], take) {
                pairs.push((old_ranked[i].1.clone(), new_ranked[j].1.clone()));
                i += 1;
                j += 1;
            } else if better(score[i + 1][j], score[i][j + 1]) {
                i += 1;
            } else {
                j += 1;
            }
        }
        pairs
    }

    /// computes dependency edge differences between two SBOMs.
    ///
    /// uses the id_mapping to translate old component IDs to new IDs when
    /// components were matched by identity rather than exact ID match.
    /// tracks dependency kind for added/removed edges and detects kind changes
    /// (e.g. a dependency moving from dev to runtime).
    fn compute_edge_diffs(
        old: &Sbom,
        new: &Sbom,
        id_mapping: &BTreeMap<ComponentId, ComponentId>,
    ) -> Vec<EdgeDiff> {
        let mut edge_diffs = Vec::new();

        // borrow references instead of cloning every ID pair
        let reverse_mapping: BTreeMap<&ComponentId, &ComponentId> = id_mapping
            .iter()
            .map(|(old_id, new_id)| (new_id, old_id))
            .collect();

        // collect parent IDs as references — avoids cloning every key
        let mut all_parents: BTreeSet<&ComponentId> = new.dependencies.keys().collect();
        for old_parent in old.dependencies.keys() {
            all_parents.insert(id_mapping.get(old_parent).unwrap_or(old_parent));
        }

        let empty_deps = BTreeMap::new();

        for parent_id in all_parents {
            // borrow the new dependency map instead of cloning it
            let new_children = new.dependencies.get(parent_id).unwrap_or(&empty_deps);

            let old_parent_id = reverse_mapping.get(parent_id).copied().unwrap_or(parent_id);

            // old children needs translated keys, but use reference keys
            let old_children: BTreeMap<&ComponentId, DependencyKind> = old
                .dependencies
                .get(old_parent_id)
                .map(|children| {
                    children
                        .iter()
                        .map(|(id, &kind)| (id_mapping.get(id).unwrap_or(id), kind))
                        .collect()
                })
                .unwrap_or_default();

            let new_keys: BTreeSet<&ComponentId> = new_children.keys().collect();
            let old_keys: BTreeSet<&ComponentId> = old_children.keys().copied().collect();

            // clone IDs only for entries that actually differ
            let added: BTreeMap<ComponentId, DependencyKind> = new_keys
                .difference(&old_keys)
                .map(|&id| (id.clone(), new_children[id]))
                .collect();
            let removed: BTreeMap<ComponentId, DependencyKind> = old_keys
                .difference(&new_keys)
                .map(|&id| (id.clone(), old_children[id]))
                .collect();

            let kind_changed: BTreeMap<ComponentId, (DependencyKind, DependencyKind)> = new_keys
                .intersection(&old_keys)
                .filter_map(|&id| {
                    let old_kind = old_children[id];
                    let new_kind = new_children[id];
                    if old_kind != new_kind {
                        Some((id.clone(), (old_kind, new_kind)))
                    } else {
                        None
                    }
                })
                .collect();

            if !added.is_empty() || !removed.is_empty() || !kind_changed.is_empty() {
                edge_diffs.push(EdgeDiff {
                    parent: parent_id.clone(),
                    added,
                    removed,
                    kind_changed,
                });
            }
        }

        edge_diffs
    }

    /// builds a human-readable display name map for component IDs in edge diffs.
    ///
    /// only includes entries for hash-based IDs (`h:...`) since purl-based IDs
    /// are already human-readable. looks up component names from both SBOMs.
    fn build_component_names(
        old: &Sbom,
        new: &Sbom,
        edge_diffs: &[EdgeDiff],
    ) -> BTreeMap<ComponentId, String> {
        let mut names = BTreeMap::new();

        // collect all IDs that appear in edge diffs
        let mut ids = BTreeSet::new();
        for edge in edge_diffs {
            ids.insert(&edge.parent);
            ids.extend(edge.added.keys());
            ids.extend(edge.removed.keys());
            ids.extend(edge.kind_changed.keys());
        }

        // only resolve hash-based IDs — purls are already readable
        for id in ids {
            if !id.as_str().starts_with("h:") {
                continue;
            }

            // try new SBOM first (edge diffs use new-SBOM IDs), then old
            let comp = new.components.get(id).or_else(|| old.components.get(id));
            if let Some(comp) = comp {
                let display = match &comp.version {
                    Some(v) => format!("{}@{}", comp.name, v),
                    None => comp.name.clone(),
                };
                names.insert(id.clone(), display);
            }
        }

        names
    }

    /// compares two components field-by-field, returning the list of
    /// [`FieldChange`]s. an empty vector means the components are identical
    /// (modulo fields excluded by `only`).
    ///
    /// this is a pure comparison — it does not construct a [`ComponentChange`]
    /// or clone either component. the caller is responsible for building the
    /// final struct from owned values.
    fn compute_fields(
        old: &Component,
        new: &Component,
        only: Option<&[Field]>,
    ) -> Vec<FieldChange> {
        let mut changes = Vec::new();

        let should_include = |f: Field| only.is_none_or(|fields| fields.contains(&f));

        if should_include(Field::Version) && old.version != new.version {
            changes.push(FieldChange::Version(
                old.version.clone(),
                new.version.clone(),
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

        if should_include(Field::Ecosystem) && old.ecosystem != new.ecosystem {
            changes.push(FieldChange::Ecosystem(
                old.ecosystem.clone(),
                new.ecosystem.clone(),
            ));
        }

        changes
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

        // only description: should see description change but not version
        let diff = Differ::diff(&old, &new, Some(&[Field::Description]));
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].changes.len(), 1);
        assert!(matches!(
            diff.changed[0].changes[0],
            FieldChange::Description(_, _)
        ));

        // only version: should see version change but not description
        let diff = Differ::diff(&old, &new, Some(&[Field::Version]));
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].changes.len(), 1);
        assert!(matches!(
            diff.changed[0].changes[0],
            FieldChange::Version(_, _)
        ));
    }

    #[test]
    fn test_diff_ecosystem_change() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let mut c1 = Component::new("pkg-a".to_string(), Some("1.0".to_string()));
        c1.ecosystem = Some("npm".to_string());
        let mut c2 = c1.clone();
        c2.ecosystem = Some("cargo".to_string());

        old.components.insert(c1.id.clone(), c1);
        new.components.insert(c2.id.clone(), c2);

        let diff = Differ::diff(&old, &new, None);
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].changes.len(), 1);
        assert!(matches!(
            diff.changed[0].changes[0],
            FieldChange::Ecosystem(_, _)
        ));

        if let FieldChange::Ecosystem(ref o, ref n) = diff.changed[0].changes[0] {
            assert_eq!(o.as_deref(), Some("npm"));
            assert_eq!(n.as_deref(), Some("cargo"));
        }
    }

    #[test]
    fn test_diff_ecosystem_change_from_none() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let c1 = Component::new("pkg-a".to_string(), Some("1.0".to_string()));
        let mut c2 = c1.clone();
        c2.ecosystem = Some("npm".to_string());

        old.components.insert(c1.id.clone(), c1);
        new.components.insert(c2.id.clone(), c2);

        let diff = Differ::diff(&old, &new, None);
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].changes.len(), 1);
        assert!(matches!(
            diff.changed[0].changes[0],
            FieldChange::Ecosystem(None, Some(_))
        ));
    }

    #[test]
    fn test_diff_ecosystem_filtering() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let mut c1 = Component::new("pkg-a".to_string(), Some("1.0".to_string()));
        c1.ecosystem = Some("npm".to_string());
        let mut c2 = c1.clone();
        c2.version = Some("2.0".into());
        c2.ecosystem = Some("cargo".to_string());

        old.components.insert(c1.id.clone(), c1);
        new.components.insert(c2.id.clone(), c2);

        // only ecosystem: should see ecosystem change but not version
        let diff = Differ::diff(&old, &new, Some(&[Field::Ecosystem]));
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].changes.len(), 1);
        assert!(matches!(
            diff.changed[0].changes[0],
            FieldChange::Ecosystem(_, _)
        ));

        // only version: should see version change but not ecosystem
        let diff = Differ::diff(&old, &new, Some(&[Field::Version]));
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].changes.len(), 1);
        assert!(matches!(
            diff.changed[0].changes[0],
            FieldChange::Version(_, _)
        ));
    }

    #[test]
    fn test_diff_ecosystem_no_change() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let mut c1 = Component::new("pkg-a".to_string(), Some("1.0".to_string()));
        c1.ecosystem = Some("npm".to_string());
        let c2 = c1.clone();

        old.components.insert(c1.id.clone(), c1);
        new.components.insert(c2.id.clone(), c2);

        let diff = Differ::diff(&old, &new, None);
        assert!(diff.changed.is_empty());
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
        let mc = diff.metadata_changed.as_ref().unwrap();
        assert_eq!(
            mc.timestamp,
            Some((Some("2024-01-01".into()), Some("2024-01-02".into())))
        );
        assert!(mc.tools.is_none());
        assert!(mc.authors.is_none());
        assert!(!diff.is_empty());
    }

    #[test]
    fn test_diff_metadata_changed_tools() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        old.metadata.tools = vec!["syft".into()];
        new.metadata.tools = vec!["trivy".into()];

        let diff = Differ::diff(&old, &new, None);
        let mc = diff.metadata_changed.as_ref().unwrap();
        assert!(mc.timestamp.is_none());
        assert_eq!(mc.tools, Some((vec!["syft".into()], vec!["trivy".into()])));
        assert!(mc.authors.is_none());
    }

    #[test]
    fn test_diff_metadata_changed_authors() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        old.metadata.authors = vec!["alice".into()];
        new.metadata.authors = vec!["bob".into()];

        let diff = Differ::diff(&old, &new, None);
        let mc = diff.metadata_changed.as_ref().unwrap();
        assert!(mc.timestamp.is_none());
        assert!(mc.tools.is_none());
        assert_eq!(mc.authors, Some((vec!["alice".into()], vec!["bob".into()])));
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
        assert!(diff.metadata_changed.is_none());
    }

    #[test]
    fn test_diff_metadata_changed_multiple_fields() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        old.metadata.timestamp = Some("2024-01-01".into());
        new.metadata.timestamp = Some("2024-01-02".into());
        old.metadata.tools = vec!["syft".into()];
        new.metadata.tools = vec!["trivy".into()];
        old.metadata.authors = vec!["alice".into()];
        new.metadata.authors = vec!["bob".into()];

        let diff = Differ::diff(&old, &new, None);
        let mc = diff.metadata_changed.as_ref().unwrap();
        assert!(mc.timestamp.is_some());
        assert!(mc.tools.is_some());
        assert!(mc.authors.is_some());
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
        // component with purl in old, different purl in new (same ecosystem+name)
        // should be treated as a CHANGE with Purl field change, not add/remove
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        // old: lodash with one purl
        let mut c_old = Component::new("lodash".to_string(), Some("4.17.20".to_string()));
        c_old.purl = Some("pkg:npm/lodash@4.17.20".to_string());
        c_old.ecosystem = Some("npm".to_string());
        c_old.id = ComponentId::new(c_old.purl.as_deref(), &[]);

        // new: lodash with updated purl (version bump)
        let mut c_new = Component::new("lodash".to_string(), Some("4.17.21".to_string()));
        c_new.purl = Some("pkg:npm/lodash@4.17.21".to_string());
        c_new.ecosystem = Some("npm".to_string());
        c_new.id = ComponentId::new(c_new.purl.as_deref(), &[]);

        old.components.insert(c_old.id.clone(), c_old);
        new.components.insert(c_new.id.clone(), c_new);

        let diff = Differ::diff(&old, &new, None);

        assert_eq!(diff.added.len(), 0, "Should not have added components");
        assert_eq!(diff.removed.len(), 0, "Should not have removed components");

        assert_eq!(diff.changed.len(), 1, "Should have one changed component");

        let changes = &diff.changed[0].changes;
        assert!(changes
            .iter()
            .any(|c| matches!(c, FieldChange::Version(_, _))));
        assert!(changes.iter().any(|c| matches!(c, FieldChange::Purl(_, _))));
    }

    #[test]
    fn test_purl_removed_is_change() {
        // component with purl in old, no purl in new (same name)
        // this is realistic: old SBOM from tool that adds purls, new from tool that doesn't
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let mut c_old = Component::new("lodash".to_string(), Some("4.17.21".to_string()));
        c_old.purl = Some("pkg:npm/lodash@4.17.21".to_string());
        c_old.ecosystem = Some("npm".to_string()); // Extracted from purl
        c_old.id = ComponentId::new(c_old.purl.as_deref(), &[]);

        // new component without purl - ecosystem is None (realistic!)
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

        assert!(diff.changed[0]
            .changes
            .iter()
            .any(|c| matches!(c, FieldChange::Purl(_, _))));
    }

    #[test]
    fn test_purl_added_is_change() {
        // component with no purl in old, purl in new
        // this is realistic: old SBOM without purls, new from better tooling
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
        // two components with same name but different ecosystems should NOT match
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        // old: "utils" from npm
        let mut c_old = Component::new("utils".to_string(), Some("1.0.0".to_string()));
        c_old.purl = Some("pkg:npm/utils@1.0.0".to_string());
        c_old.ecosystem = Some("npm".to_string());
        c_old.id = ComponentId::new(c_old.purl.as_deref(), &[]);

        // new: "utils" from pypi (different ecosystem!)
        let mut c_new = Component::new("utils".to_string(), Some("1.0.0".to_string()));
        c_new.purl = Some("pkg:pypi/utils@1.0.0".to_string());
        c_new.ecosystem = Some("pypi".to_string());
        c_new.id = ComponentId::new(c_new.purl.as_deref(), &[]);

        old.components.insert(c_old.id.clone(), c_old);
        new.components.insert(c_new.id.clone(), c_new);

        let diff = Differ::diff(&old, &new, None);

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
        // components with same name and both having None ecosystem should match
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

        // add all components to both SBOMs
        old.components.insert(c1.id.clone(), c1.clone());
        old.components.insert(c2.id.clone(), c2.clone());
        old.components.insert(c3.id.clone(), c3.clone());

        new.components.insert(c1.id.clone(), c1);
        new.components.insert(c2.id.clone(), c2);
        new.components.insert(c3.id.clone(), c3);

        // old: parent -> child-a
        old.dependencies
            .entry(parent_id.clone())
            .or_default()
            .insert(child_a_id.clone(), DependencyKind::Runtime);

        // new: parent -> child-b (removed child-a, added child-b)
        new.dependencies
            .entry(parent_id.clone())
            .or_default()
            .insert(child_b_id.clone(), DependencyKind::Runtime);

        let diff = Differ::diff(&old, &new, None);

        assert_eq!(diff.edge_diffs.len(), 1);
        assert_eq!(diff.edge_diffs[0].parent, parent_id);
        assert!(diff.edge_diffs[0].added.contains_key(&child_b_id));
        assert!(diff.edge_diffs[0].removed.contains_key(&child_a_id));
    }

    #[test]
    fn test_edge_diff_with_identity_reconciliation() {
        // test that edge diffs work when components are matched by identity
        // (different IDs but same name/ecosystem)
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        // parent with purl in old
        let mut parent_old = Component::new("parent".to_string(), Some("1.0".to_string()));
        parent_old.purl = Some("pkg:npm/parent@1.0".to_string());
        parent_old.ecosystem = Some("npm".to_string());
        parent_old.id = ComponentId::new(parent_old.purl.as_deref(), &[]);

        // parent with different purl in new (same name/ecosystem)
        let mut parent_new = Component::new("parent".to_string(), Some("1.1".to_string()));
        parent_new.purl = Some("pkg:npm/parent@1.1".to_string());
        parent_new.ecosystem = Some("npm".to_string());
        parent_new.id = ComponentId::new(parent_new.purl.as_deref(), &[]);

        // child component (same in both)
        let child = Component::new("child".to_string(), Some("1.0".to_string()));

        old.components
            .insert(parent_old.id.clone(), parent_old.clone());
        old.components.insert(child.id.clone(), child.clone());

        new.components
            .insert(parent_new.id.clone(), parent_new.clone());
        new.components.insert(child.id.clone(), child.clone());

        // old: parent -> child
        old.dependencies
            .entry(parent_old.id.clone())
            .or_default()
            .insert(child.id.clone(), DependencyKind::Runtime);

        // new: parent -> child (same edge, but parent has different ID)
        new.dependencies
            .entry(parent_new.id.clone())
            .or_default()
            .insert(child.id.clone(), DependencyKind::Runtime);

        let diff = Differ::diff(&old, &new, None);

        // components should be matched by identity, so no spurious edge changes
        // (the edge parent->child exists in both, just under different parent IDs)
        assert_eq!(
            diff.edge_diffs.len(),
            0,
            "No edge changes expected when parent is reconciled by identity"
        );
    }

    #[test]
    fn test_edge_diff_filtering() {
        // test that --only filtering excludes edge diffs when deps not included
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

        // new has an edge that old doesn't
        new.dependencies
            .entry(parent_id.clone())
            .or_default()
            .insert(child_id, DependencyKind::Runtime);

        // without filtering - should have edge diff
        let diff = Differ::diff(&old, &new, None);
        assert_eq!(diff.edge_diffs.len(), 1);

        // with filtering to only Version - should NOT have edge diff
        let diff_filtered = Differ::diff(&old, &new, Some(&[Field::Version]));
        assert_eq!(diff_filtered.edge_diffs.len(), 0);

        // with filtering to include Deps - should have edge diff
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
        assert!(grouped.metadata_changed.is_none());
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

        // derived breakdown should match direct breakdown
        let grouped_counts = grouped.ecosystem_breakdown();
        let direct_counts = diff.ecosystem_breakdown();
        assert_eq!(grouped_counts, direct_counts);
    }

    #[test]
    fn test_totals_no_changes() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let c1 = Component::new("pkg-a".to_string(), Some("1.0".to_string()));
        let c2 = Component::new("pkg-b".to_string(), Some("2.0".to_string()));

        old.components.insert(c1.id.clone(), c1.clone());
        old.components.insert(c2.id.clone(), c2.clone());
        new.components.insert(c1.id.clone(), c1);
        new.components.insert(c2.id.clone(), c2);

        let diff = Differ::diff(&old, &new, None);
        assert_eq!(diff.old_total, 2);
        assert_eq!(diff.new_total, 2);
        assert_eq!(diff.unchanged, 2);
    }

    #[test]
    fn test_totals_with_changes() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let c1 = Component::new("pkg-a".to_string(), Some("1.0".to_string()));
        let mut c1_updated = c1.clone();
        c1_updated.version = Some("1.1".to_string());
        let c2 = Component::new("pkg-b".to_string(), Some("2.0".to_string()));
        let c3 = Component::new("pkg-c".to_string(), Some("3.0".to_string()));
        let c4 = Component::new("pkg-d".to_string(), Some("4.0".to_string()));

        old.components.insert(c1.id.clone(), c1);
        old.components.insert(c2.id.clone(), c2.clone());
        old.components.insert(c3.id.clone(), c3);
        new.components.insert(c1_updated.id.clone(), c1_updated);
        new.components.insert(c2.id.clone(), c2);
        new.components.insert(c4.id.clone(), c4);

        let diff = Differ::diff(&old, &new, None);
        assert_eq!(diff.old_total, 3);
        assert_eq!(diff.new_total, 3);
        assert_eq!(diff.added.len(), 1); // c4
        assert_eq!(diff.removed.len(), 1); // c3
        assert_eq!(diff.changed.len(), 1); // c1
        assert_eq!(diff.unchanged, 1); // c2
    }

    #[test]
    fn test_component_names_for_hash_ids_in_edge_diffs() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        // components without purls → hash-based IDs
        let parent = Component::new("my-app".to_string(), Some("1.0".to_string()));
        let child_a = Component::new("dep-old".to_string(), Some("0.1".to_string()));
        let child_b = Component::new("dep-new".to_string(), Some("0.2".to_string()));

        old.components.insert(parent.id.clone(), parent.clone());
        old.components.insert(child_a.id.clone(), child_a.clone());
        new.components.insert(parent.id.clone(), parent.clone());
        new.components.insert(child_b.id.clone(), child_b.clone());

        // set up edges: old parent -> child_a, new parent -> child_b
        old.dependencies.insert(
            parent.id.clone(),
            BTreeMap::from([(child_a.id.clone(), DependencyKind::Runtime)]),
        );
        new.dependencies.insert(
            parent.id.clone(),
            BTreeMap::from([(child_b.id.clone(), DependencyKind::Runtime)]),
        );

        let diff = Differ::diff(&old, &new, None);

        // all IDs in edge diffs should be hash-based (no purls)
        assert!(diff.edge_diffs[0].parent.as_str().starts_with("h:"));

        // component_names should resolve all hash IDs to readable names
        assert_eq!(diff.display_name(&diff.edge_diffs[0].parent), "my-app@1.0");
        for added in diff.edge_diffs[0].added.keys() {
            assert!(!diff.display_name(added).starts_with("h:"));
        }
        for removed in diff.edge_diffs[0].removed.keys() {
            assert!(!diff.display_name(removed).starts_with("h:"));
        }
    }

    #[test]
    fn test_component_names_skips_purl_ids() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let mut parent = Component::new("parent".to_string(), Some("1.0".to_string()));
        parent.purl = Some("pkg:npm/parent@1.0".to_string());
        parent.id = ComponentId::new(parent.purl.as_deref(), &[]);

        let mut child_a = Component::new("child-a".to_string(), Some("1.0".to_string()));
        child_a.purl = Some("pkg:npm/child-a@1.0".to_string());
        child_a.id = ComponentId::new(child_a.purl.as_deref(), &[]);

        let mut child_b = Component::new("child-b".to_string(), Some("1.0".to_string()));
        child_b.purl = Some("pkg:npm/child-b@1.0".to_string());
        child_b.id = ComponentId::new(child_b.purl.as_deref(), &[]);

        old.components.insert(parent.id.clone(), parent.clone());
        old.components.insert(child_a.id.clone(), child_a.clone());
        new.components.insert(parent.id.clone(), parent.clone());
        new.components.insert(child_b.id.clone(), child_b.clone());

        old.dependencies.insert(
            parent.id.clone(),
            BTreeMap::from([(child_a.id.clone(), DependencyKind::Runtime)]),
        );
        new.dependencies.insert(
            parent.id.clone(),
            BTreeMap::from([(child_b.id.clone(), DependencyKind::Runtime)]),
        );

        let diff = Differ::diff(&old, &new, None);

        // component_names should be empty — all IDs are purl-based
        assert!(diff.component_names.is_empty());

        // display_name should fall back to the purl-based ID string
        assert!(diff
            .display_name(&diff.edge_diffs[0].parent)
            .starts_with("pkg:npm/parent@"));
    }

    #[test]
    fn test_display_name_fallback() {
        let diff = Diff::default();
        let unknown_id = ComponentId::new(None, &[("name", "mystery")]);
        // no entry in component_names → falls back to raw ID
        assert_eq!(diff.display_name(&unknown_id), unknown_id.as_str());
    }

    #[test]
    fn test_filter_by_ecosystem_include() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        // npm components
        let mut npm1 = Component::new("express".into(), Some("4.18.0".into()));
        npm1.ecosystem = Some("npm".into());
        let mut npm2 = Component::new("lodash".into(), Some("4.17.21".into()));
        npm2.ecosystem = Some("npm".into());

        // cargo component
        let mut cargo1 = Component::new("serde".into(), Some("1.0.0".into()));
        cargo1.ecosystem = Some("cargo".into());

        // pypi component
        let mut pypi1 = Component::new("requests".into(), Some("2.28.0".into()));
        pypi1.ecosystem = Some("pypi".into());

        old.components.insert(npm2.id.clone(), npm2.clone());
        old.components.insert(cargo1.id.clone(), cargo1.clone());

        new.components.insert(npm1.id.clone(), npm1);
        new.components.insert(npm2.id.clone(), npm2);
        new.components.insert(pypi1.id.clone(), pypi1);

        // old has npm2 + cargo1 (2 components)
        // new has npm1 + npm2 + pypi1 (3 components)
        // npm2 is unchanged, npm1 is added (npm), cargo1 is removed, pypi1 is added (pypi)

        let mut diff = Differ::diff(&old, &new, None);

        // pre-filtered totals for npm: old has 1 npm (npm2), new has 2 npm (npm1, npm2)
        diff.filter_by_ecosystem(
            &|eco| eco == Some("npm"),
            1, // old npm count
            2, // new npm count
            &BTreeMap::new(),
        );

        assert_eq!(diff.added.len(), 1); // npm1
        assert_eq!(diff.added[0].name, "express");
        assert_eq!(diff.removed.len(), 0); // cargo1 was filtered out
        assert_eq!(diff.changed.len(), 0);
        assert_eq!(diff.old_total, 1);
        assert_eq!(diff.new_total, 2);
        assert_eq!(diff.unchanged, 1); // npm2
    }

    #[test]
    fn test_filter_by_ecosystem_exclude() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let mut npm1 = Component::new("express".into(), Some("4.18.0".into()));
        npm1.ecosystem = Some("npm".into());
        let mut cargo1 = Component::new("serde".into(), Some("1.0.0".into()));
        cargo1.ecosystem = Some("cargo".into());
        let mut cargo2 = Component::new("tokio".into(), Some("1.0.0".into()));
        cargo2.ecosystem = Some("cargo".into());

        old.components.insert(cargo1.id.clone(), cargo1.clone());
        new.components.insert(npm1.id.clone(), npm1);
        new.components.insert(cargo2.id.clone(), cargo2);

        // exclude npm: should only see cargo changes
        let mut diff = Differ::diff(&old, &new, None);
        diff.filter_by_ecosystem(
            &|eco| eco != Some("npm"),
            1, // old non-npm count
            1, // new non-npm count
            &BTreeMap::new(),
        );

        assert_eq!(diff.added.len(), 1); // cargo2
        assert_eq!(diff.added[0].name, "tokio");
        assert_eq!(diff.removed.len(), 1); // cargo1
        assert_eq!(diff.removed[0].name, "serde");
    }

    #[test]
    fn test_filter_by_ecosystem_unknown() {
        // components without ecosystem are treated as "unknown"
        let old = Sbom::default();
        let mut new = Sbom::default();

        let no_eco = Component::new("mystery".into(), Some("1.0".into()));
        let mut npm = Component::new("express".into(), Some("4.18.0".into()));
        npm.ecosystem = Some("npm".into());

        new.components.insert(no_eco.id.clone(), no_eco);
        new.components.insert(npm.id.clone(), npm);

        let mut diff = Differ::diff(&old, &new, None);

        // include "unknown" - should keep only the component without ecosystem
        diff.filter_by_ecosystem(
            &|eco| eco.is_none(),
            0,
            1, // one component without ecosystem in new
            &BTreeMap::new(),
        );

        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].name, "mystery");
    }

    #[test]
    fn test_filter_by_ecosystem_changed_uses_new_ecosystem() {
        // when old has no ecosystem but new gained one (e.g. purl added),
        // they match by name and the change uses the new component's ecosystem.
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        // old: no ecosystem (wildcard match)
        let c_old = Component::new("pkg".into(), Some("1.0".into()));
        // new: gains npm ecosystem + version bump
        let mut c_new = Component::new("pkg".into(), Some("2.0".into()));
        c_new.ecosystem = Some("npm".into());

        old.components.insert(c_old.id.clone(), c_old);
        new.components.insert(c_new.id.clone(), c_new);

        let mut diff = Differ::diff(&old, &new, None);
        assert_eq!(diff.changed.len(), 1);

        // filter to npm: should keep the changed component (new ecosystem is npm)
        diff.filter_by_ecosystem(&|eco| eco == Some("npm"), 0, 1, &BTreeMap::new());
        assert_eq!(diff.changed.len(), 1);

        // filter to cargo: should exclude (new ecosystem is npm, not cargo)
        let old2 = {
            let mut s = Sbom::default();
            let c = Component::new("pkg".into(), Some("1.0".into()));
            s.components.insert(c.id.clone(), c);
            s
        };
        let new2 = {
            let mut s = Sbom::default();
            let mut c = Component::new("pkg".into(), Some("2.0".into()));
            c.ecosystem = Some("npm".into());
            s.components.insert(c.id.clone(), c);
            s
        };
        let mut diff = Differ::diff(&old2, &new2, None);
        diff.filter_by_ecosystem(&|eco| eco == Some("cargo"), 0, 0, &BTreeMap::new());
        assert_eq!(diff.changed.len(), 0);
    }

    #[test]
    fn test_filter_by_ecosystem_empty_diff() {
        let mut diff = Diff::default();
        diff.filter_by_ecosystem(&|_| true, 0, 0, &BTreeMap::new());
        assert!(diff.is_empty());
    }

    #[test]
    fn test_filter_by_ecosystem_totals_adjusted() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        // old: 2 npm, 1 cargo
        let mut n1 = Component::new("a".into(), Some("1".into()));
        n1.ecosystem = Some("npm".into());
        let mut n2 = Component::new("b".into(), Some("1".into()));
        n2.ecosystem = Some("npm".into());
        let mut c1 = Component::new("c".into(), Some("1".into()));
        c1.ecosystem = Some("cargo".into());

        old.components.insert(n1.id.clone(), n1.clone());
        old.components.insert(n2.id.clone(), n2.clone());
        old.components.insert(c1.id.clone(), c1);

        // new: same 2 npm (unchanged), no cargo
        new.components.insert(n1.id.clone(), n1);
        new.components.insert(n2.id.clone(), n2);

        let mut diff = Differ::diff(&old, &new, None);
        assert_eq!(diff.old_total, 3);
        assert_eq!(diff.new_total, 2);

        // filter to npm only
        diff.filter_by_ecosystem(&|eco| eco == Some("npm"), 2, 2, &BTreeMap::new());

        assert_eq!(diff.old_total, 2);
        assert_eq!(diff.new_total, 2);
        assert_eq!(diff.unchanged, 2);
        assert_eq!(diff.added.len(), 0);
        assert_eq!(diff.removed.len(), 0);
        assert_eq!(diff.changed.len(), 0);
    }

    #[test]
    fn test_filter_by_ecosystem_matched_pair_changes_ecosystem() {
        // a matched pair (same name+version → same hash id) whose ecosystem
        // goes npm → None because its purl was dropped. two differently-schemed
        // purls would get distinct ids and diff as add+remove, so a dropped (or
        // added) purl — ecosystem Some↔None — is the reachable way a *matched*
        // pair straddles the ecosystem filter.
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        // migrator: matched pair whose purl is dropped, so ecosystem npm -> None.
        let mut mig_old = Component::new("migrator".into(), Some("1.0".into()));
        mig_old.ecosystem = Some("npm".into());
        let mut mig_new = Component::new("migrator".into(), Some("1.0".into()));
        mig_new.ecosystem = None; // purl dropped on the new side
        assert_eq!(mig_old.id, mig_new.id, "same name+version share a hash id");

        // left-pad: genuinely unchanged npm pair.
        let mut lp = Component::new("left-pad".into(), Some("2.0".into()));
        lp.ecosystem = Some("npm".into());

        old.components.insert(mig_old.id.clone(), mig_old);
        old.components.insert(lp.id.clone(), lp.clone());
        new.components.insert(mig_new.id.clone(), mig_new);
        new.components.insert(lp.id.clone(), lp);

        let mut diff = Differ::diff(&old, &new, None);
        assert_eq!(diff.changed.len(), 1); // migrator (ecosystem npm -> None)
        assert_eq!(diff.unchanged, 1); // left-pad

        // filter to npm: old side has 2 npm (migrator-old, left-pad),
        // new side has 1 npm (left-pad only; migrator-new has no ecosystem).
        diff.filter_by_ecosystem(&|eco| eco == Some("npm"), 2, 1, &BTreeMap::new());

        assert_eq!(diff.changed.len(), 0); // migrator dropped (new has no ecosystem)
        assert_eq!(diff.added.len(), 0);
        assert_eq!(diff.removed.len(), 0);
        assert_eq!(diff.unchanged, 1); // only left-pad remains on the npm side
        assert_eq!(diff.new_total, 1);
        // the core invariant: unchanged must never exceed new_total.
        assert!(
            diff.unchanged <= diff.new_total,
            "unchanged ({}) exceeds new_total ({})",
            diff.unchanged,
            diff.new_total
        );
    }

    #[test]
    fn test_filter_by_ecosystem_no_ecosystem_change_unaffected() {
        // control: with no pair crossing the ecosystem boundary, the new-side
        // derivation of `unchanged` agrees with the old-side one.
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        // migrator: version bump but stays npm (changed pair, npm both sides).
        let mut mig_old = Component::new("migrator".into(), Some("1.0".into()));
        mig_old.ecosystem = Some("npm".into());
        let mut mig_new = Component::new("migrator".into(), Some("1.1".into()));
        mig_new.ecosystem = Some("npm".into());

        // left-pad: genuinely unchanged npm pair.
        let mut lp = Component::new("left-pad".into(), Some("2.0".into()));
        lp.ecosystem = Some("npm".into());

        old.components.insert(mig_old.id.clone(), mig_old);
        old.components.insert(lp.id.clone(), lp.clone());
        new.components.insert(mig_new.id.clone(), mig_new);
        new.components.insert(lp.id.clone(), lp);

        let mut diff = Differ::diff(&old, &new, None);
        assert_eq!(diff.changed.len(), 1);

        // both old and new npm totals are 2 (nothing crosses the boundary).
        diff.filter_by_ecosystem(&|eco| eco == Some("npm"), 2, 2, &BTreeMap::new());

        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.unchanged, 1); // left-pad; identical to old-side derivation
        assert_eq!(diff.new_total, 2);
        assert!(diff.unchanged <= diff.new_total);
    }

    #[test]
    fn test_filter_by_ecosystem_filters_edge_diffs() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        // npm parent with an edge change
        let mut npm_parent = Component::new("npm-app".into(), Some("1.0".into()));
        npm_parent.ecosystem = Some("npm".into());
        let npm_child_old = Component::new("npm-dep-old".into(), Some("1.0".into()));
        let npm_child_new = Component::new("npm-dep-new".into(), Some("1.0".into()));

        // cargo parent with an edge change
        let mut cargo_parent = Component::new("cargo-app".into(), Some("1.0".into()));
        cargo_parent.ecosystem = Some("cargo".into());
        let cargo_child = Component::new("cargo-dep".into(), Some("1.0".into()));

        // old: both parents, npm-dep-old as child of npm-app
        old.components
            .insert(npm_parent.id.clone(), npm_parent.clone());
        old.components
            .insert(npm_child_old.id.clone(), npm_child_old.clone());
        old.components
            .insert(cargo_parent.id.clone(), cargo_parent.clone());

        // new: both parents, npm-dep-new replaces npm-dep-old, cargo gets new dep
        new.components
            .insert(npm_parent.id.clone(), npm_parent.clone());
        new.components
            .insert(npm_child_new.id.clone(), npm_child_new.clone());
        new.components
            .insert(cargo_parent.id.clone(), cargo_parent.clone());
        new.components
            .insert(cargo_child.id.clone(), cargo_child.clone());

        old.dependencies.insert(
            npm_parent.id.clone(),
            BTreeMap::from([(npm_child_old.id.clone(), DependencyKind::Runtime)]),
        );
        new.dependencies.insert(
            npm_parent.id.clone(),
            BTreeMap::from([(npm_child_new.id.clone(), DependencyKind::Runtime)]),
        );
        new.dependencies.insert(
            cargo_parent.id.clone(),
            BTreeMap::from([(cargo_child.id.clone(), DependencyKind::Runtime)]),
        );

        // build ecosystem map
        let mut eco_map: BTreeMap<ComponentId, Option<String>> = BTreeMap::new();
        for (id, comp) in old.components.iter().chain(new.components.iter()) {
            eco_map.insert(id.clone(), comp.ecosystem.clone());
        }

        let mut diff = Differ::diff(&old, &new, None);
        // before filtering: should have edge diffs for both ecosystems
        assert!(diff.edge_diffs.len() >= 2);

        // filter to npm only
        diff.filter_by_ecosystem(&|eco| eco == Some("npm"), 1, 1, &eco_map);

        // should only have the npm parent's edge diff
        assert_eq!(diff.edge_diffs.len(), 1);
        assert_eq!(diff.edge_diffs[0].parent, npm_parent.id);
    }

    #[test]
    fn test_filter_by_ecosystem_prunes_component_names() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        // npm parent (hash-based IDs → entries in component_names)
        let mut npm_parent = Component::new("npm-app".into(), Some("1.0".into()));
        npm_parent.ecosystem = Some("npm".into());
        let npm_child = Component::new("npm-dep".into(), Some("1.0".into()));

        // cargo parent
        let mut cargo_parent = Component::new("cargo-app".into(), Some("1.0".into()));
        cargo_parent.ecosystem = Some("cargo".into());
        let cargo_child = Component::new("cargo-dep".into(), Some("1.0".into()));

        old.components
            .insert(npm_parent.id.clone(), npm_parent.clone());
        old.components
            .insert(cargo_parent.id.clone(), cargo_parent.clone());

        new.components
            .insert(npm_parent.id.clone(), npm_parent.clone());
        new.components
            .insert(npm_child.id.clone(), npm_child.clone());
        new.components
            .insert(cargo_parent.id.clone(), cargo_parent.clone());
        new.components
            .insert(cargo_child.id.clone(), cargo_child.clone());

        new.dependencies.insert(
            npm_parent.id.clone(),
            BTreeMap::from([(npm_child.id.clone(), DependencyKind::Runtime)]),
        );
        new.dependencies.insert(
            cargo_parent.id.clone(),
            BTreeMap::from([(cargo_child.id.clone(), DependencyKind::Runtime)]),
        );

        let mut eco_map: BTreeMap<ComponentId, Option<String>> = BTreeMap::new();
        for (id, comp) in old.components.iter().chain(new.components.iter()) {
            eco_map.insert(id.clone(), comp.ecosystem.clone());
        }

        let mut diff = Differ::diff(&old, &new, None);
        let names_before = diff.component_names.len();
        assert!(names_before > 0, "should have component names for hash IDs");

        diff.filter_by_ecosystem(&|eco| eco == Some("npm"), 1, 1, &eco_map);

        // component_names should not contain IDs only from the cargo edge diff
        assert!(diff.component_names.len() <= names_before);
        for id in diff.component_names.keys() {
            // every remaining name should be referenced by a remaining edge diff
            let referenced = diff.edge_diffs.iter().any(|e| {
                &e.parent == id
                    || e.added.contains_key(id)
                    || e.removed.contains_key(id)
                    || e.kind_changed.contains_key(id)
            });
            assert!(referenced, "stale component_name entry for {}", id);
        }
    }

    #[test]
    fn test_diff_owned_identity() {
        let mut sbom = Sbom::default();

        // build a non-trivial SBOM with varied component fields
        let mut parent = Component::new("my-app".to_string(), Some("2.0.0".to_string()));
        parent.purl = Some("pkg:cargo/my-app@2.0.0".to_string());
        parent.ecosystem = Some("cargo".to_string());
        parent.licenses.insert("MIT".into());
        parent.supplier = Some("Acme Corp".into());
        parent.id = ComponentId::new(parent.purl.as_deref(), &[]);

        let mut dep_a = Component::new("dep-a".to_string(), Some("1.0.0".to_string()));
        dep_a.purl = Some("pkg:cargo/dep-a@1.0.0".to_string());
        dep_a.ecosystem = Some("cargo".to_string());
        dep_a.licenses.insert("Apache-2.0".into());
        dep_a
            .hashes
            .insert("sha256".into(), "abcdef1234567890".into());
        dep_a.id = ComponentId::new(dep_a.purl.as_deref(), &[]);

        let mut dep_b = Component::new("dep-b".to_string(), Some("0.5.0".to_string()));
        dep_b.ecosystem = Some("cargo".to_string());
        dep_b.description = Some("A helper library".into());

        sbom.components.insert(parent.id.clone(), parent.clone());
        sbom.components.insert(dep_a.id.clone(), dep_a.clone());
        sbom.components.insert(dep_b.id.clone(), dep_b.clone());

        // add dependency edges: parent -> dep-a (runtime), parent -> dep-b (dev)
        sbom.dependencies
            .entry(parent.id.clone())
            .or_default()
            .insert(dep_a.id.clone(), DependencyKind::Runtime);
        sbom.dependencies
            .entry(parent.id.clone())
            .or_default()
            .insert(dep_b.id.clone(), DependencyKind::Dev);

        let copy = sbom.clone();
        let diff = Differ::diff_owned(sbom, copy, None);

        assert_eq!(
            diff.added.len(),
            0,
            "identical SBOMs should have no added components"
        );
        assert_eq!(
            diff.removed.len(),
            0,
            "identical SBOMs should have no removed components"
        );
        assert_eq!(
            diff.changed.len(),
            0,
            "identical SBOMs should have no changed components"
        );
        assert_eq!(
            diff.edge_diffs.len(),
            0,
            "identical SBOMs should have no edge diffs"
        );
        assert_eq!(
            diff.metadata_changed, None,
            "identical SBOMs should have no metadata changes"
        );
        assert_eq!(diff.old_total, 3);
        assert_eq!(diff.new_total, 3);
        assert_eq!(diff.unchanged, 3);
    }

    #[test]
    fn test_diff_detects_version_downgrade() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let c1 = Component::new("pkg-a".to_string(), Some("2.0.0".to_string()));
        let mut c2 = c1.clone();
        c2.version = Some("1.0.0".to_string());

        old.components.insert(c1.id.clone(), c1);
        new.components.insert(c2.id.clone(), c2);

        let diff = Differ::diff(&old, &new, None);
        assert_eq!(diff.changed.len(), 1);
        assert!(diff.changed[0].is_downgrade);
    }

    #[test]
    fn test_diff_upgrade_not_marked_as_downgrade() {
        let mut old = Sbom::default();
        let mut new = Sbom::default();

        let c1 = Component::new("pkg-a".to_string(), Some("1.0.0".to_string()));
        let mut c2 = c1.clone();
        c2.version = Some("2.0.0".to_string());

        old.components.insert(c1.id.clone(), c1);
        new.components.insert(c2.id.clone(), c2);

        let diff = Differ::diff(&old, &new, None);
        assert_eq!(diff.changed.len(), 1);
        assert!(!diff.changed[0].is_downgrade);
    }

    fn purl_component(ecosystem: &str, name: &str, version: &str) -> Component {
        let purl = format!("pkg:{ecosystem}/{name}@{version}");
        let mut comp = Component::new(name.to_string(), Some(version.to_string()));
        comp.ecosystem = Some(ecosystem.to_string());
        comp.id = ComponentId::new(Some(&purl), &[]);
        comp.purl = Some(purl);
        comp
    }

    fn npm_component(name: &str, version: &str) -> Component {
        purl_component("npm", name, version)
    }

    fn plain_component(name: &str, version: &str) -> Component {
        Component::new(name.to_string(), Some(version.to_string()))
    }

    fn sbom_of(components: Vec<Component>) -> Sbom {
        let mut sbom = Sbom::default();
        for comp in components {
            sbom.components.insert(comp.id.clone(), comp);
        }
        sbom
    }

    /// the `(old version, new version)` of every changed component, sorted.
    fn version_pairs(diff: &Diff) -> Vec<(String, String)> {
        let mut pairs: Vec<(String, String)> = diff
            .changed
            .iter()
            .map(|c| {
                (
                    c.old.version.clone().unwrap_or_default(),
                    c.new.version.clone().unwrap_or_default(),
                )
            })
            .collect();
        pairs.sort();
        pairs
    }

    fn expect_pairs(expected: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut pairs: Vec<(String, String)> = expected
            .iter()
            .map(|(o, n)| (o.to_string(), n.to_string()))
            .collect();
        pairs.sort();
        pairs
    }

    #[test]
    fn test_identity_reconciliation_pairs_same_version_line() {
        for (old_versions, new_versions, expected) in [
            (
                ["9.0.0", "10.0.0"],
                ["9.0.1", "10.0.1"],
                [("9.0.0", "9.0.1"), ("10.0.0", "10.0.1")],
            ),
            (
                ["1.0.0", "2.0.0"],
                ["1.1.0", "2.1.0"],
                [("1.0.0", "1.1.0"), ("2.0.0", "2.1.0")],
            ),
        ] {
            let old = sbom_of(
                old_versions
                    .iter()
                    .map(|v| npm_component("libfoo", v))
                    .collect(),
            );
            let new = sbom_of(
                new_versions
                    .iter()
                    .map(|v| npm_component("libfoo", v))
                    .collect(),
            );

            let diff = Differ::diff(&old, &new, None);
            assert_eq!(version_pairs(&diff), expect_pairs(&expected));
            assert_eq!(diff.added.len(), 0);
            assert_eq!(diff.removed.len(), 0);
            assert!(
                !diff.changed.iter().any(|c| c.is_downgrade),
                "upgrading both version lines must not report a downgrade, got {:?}",
                version_pairs(&diff)
            );
        }
    }

    #[test]
    fn test_identity_reconciliation_without_purls_pairs_same_version_line() {
        let versions = |vs: [&str; 3]| {
            sbom_of(
                vs.iter()
                    .map(|v| Component::new("libfoo".to_string(), Some(v.to_string())))
                    .collect(),
            )
        };
        let old = versions(["1.0.0", "2.0.0", "3.0.0"]);
        let new = versions(["1.0.1", "2.0.1", "3.0.1"]);

        let diff = Differ::diff(&old, &new, None);
        assert_eq!(
            version_pairs(&diff),
            expect_pairs(&[("1.0.0", "1.0.1"), ("2.0.0", "2.0.1"), ("3.0.0", "3.0.1")])
        );
        assert!(!diff.changed.iter().any(|c| c.is_downgrade));
    }

    #[test]
    fn test_identity_reconciliation_more_old_than_new() {
        for (survivor, expected) in [("3.0.1", ("3.0.0", "3.0.1")), ("1.0.1", ("1.0.0", "1.0.1"))] {
            let old = sbom_of(
                ["1.0.0", "2.0.0", "3.0.0"]
                    .iter()
                    .map(|v| npm_component("libfoo", v))
                    .collect(),
            );
            let new = sbom_of(vec![npm_component("libfoo", survivor)]);

            let diff = Differ::diff(&old, &new, None);
            assert_eq!(version_pairs(&diff), expect_pairs(&[expected]));
            assert_eq!(diff.removed.len(), 2);
            assert_eq!(diff.added.len(), 0);
            assert!(!diff.changed.iter().any(|c| c.is_downgrade));
        }
    }

    #[test]
    fn test_identity_reconciliation_more_new_than_old() {
        for (survivor, others, expected) in [
            ("1.0.0", ["1.0.1", "2.0.0", "3.0.0"], ("1.0.0", "1.0.1")),
            ("3.0.0", ["1.0.0", "2.0.0", "3.0.1"], ("3.0.0", "3.0.1")),
        ] {
            let old = sbom_of(vec![npm_component("libfoo", survivor)]);
            let new = sbom_of(others.iter().map(|v| npm_component("libfoo", v)).collect());

            let diff = Differ::diff(&old, &new, None);
            assert_eq!(version_pairs(&diff), expect_pairs(&[expected]));
            assert_eq!(diff.added.len(), 2);
            assert_eq!(diff.removed.len(), 0);
            assert!(!diff.changed.iter().any(|c| c.is_downgrade));
        }
    }

    #[test]
    fn test_identity_reconciliation_opaque_versions_stay_deterministic() {
        let old = sbom_of(vec![
            npm_component("libfoo", "nightly-zeta"),
            npm_component("libfoo", "nightly-alpha"),
        ]);
        let new = sbom_of(vec![
            npm_component("libfoo", "nightly-omega"),
            npm_component("libfoo", "nightly-beta"),
        ]);

        let diff = Differ::diff(&old, &new, None);
        assert_eq!(
            version_pairs(&diff),
            expect_pairs(&[
                ("nightly-zeta", "nightly-beta"),
                ("nightly-alpha", "nightly-omega"),
            ])
        );
        assert_eq!(diff.added.len(), 0);
        assert_eq!(diff.removed.len(), 0);
    }

    /// the bucket must be big enough for std's sort to check its comparator; a
    /// handful of candidates cannot trip it.
    #[test]
    fn test_identity_reconciliation_mixed_version_variants_do_not_panic() {
        let deb_and_semver = |new: bool| -> Vec<Component> {
            (0..14)
                .map(|k| {
                    let (i, suffix) = (2 * k + 1, u8::from(new));
                    let version = if k % 2 == 0 {
                        format!("{i}.0.{suffix}")
                    } else {
                        format!("{i}:{}.0-{suffix}", i + 1)
                    };
                    npm_component("libfoo", &version)
                })
                .collect()
        };
        let opaque_and_semver = |new: bool| -> Vec<Component> {
            (0..14)
                .map(|k| {
                    let (i, side) = (2 * k + 1, if new { 'b' } else { 'a' });
                    let version = if k % 2 == 0 {
                        format!("{i}.0.{}", u8::from(new))
                    } else {
                        format!("{side}{i:07x}deadbeef")
                    };
                    npm_component("libfoo", &version)
                })
                .collect()
        };

        let builders: [&dyn Fn(bool) -> Vec<Component>; 2] = [&deb_and_semver, &opaque_and_semver];
        for build in builders {
            let old = sbom_of(build(false));
            let new = sbom_of(build(true));

            let diff = Differ::diff(&old, &new, None);
            assert_eq!(diff.changed.len(), 14);
            assert_eq!(diff.added.len(), 0);
            assert_eq!(diff.removed.len(), 0);
        }
    }

    /// a four-part version and a pre-release are mutually comparable, so the
    /// class check passes and only the ordering check can catch this.
    #[test]
    fn test_identity_reconciliation_prerelease_with_numeric_does_not_panic() {
        for groups in [12, 26] {
            let old = sbom_of(
                (1..=groups)
                    .flat_map(|i| {
                        [
                            npm_component("libfoo", &format!("{i}.2.3")),
                            npm_component("libfoo", &format!("{i}.2.3.0")),
                        ]
                    })
                    .collect(),
            );
            let new = sbom_of(
                (1..=groups)
                    .map(|i| npm_component("libfoo", &format!("{i}.2.3-rc.1")))
                    .collect(),
            );

            let diff = Differ::diff(&old, &new, None);
            assert_eq!(diff.changed.len(), groups);
            assert_eq!(diff.added.len(), 0);
            assert_eq!(diff.removed.len(), groups);
        }
    }

    #[test]
    fn test_identity_reconciliation_ignores_insertion_order() {
        for versions in [["9.0.0", "10.0.0"], ["nightly-zeta", "nightly-alpha"]] {
            let forward = Differ::diff(
                &sbom_of(vec![
                    npm_component("libfoo", versions[0]),
                    npm_component("libfoo", versions[1]),
                ]),
                &sbom_of(vec![
                    npm_component("libfoo", "4.0.0"),
                    npm_component("libfoo", "5.0.0"),
                ]),
                None,
            );
            let reversed = Differ::diff(
                &sbom_of(vec![
                    npm_component("libfoo", versions[1]),
                    npm_component("libfoo", versions[0]),
                ]),
                &sbom_of(vec![
                    npm_component("libfoo", "5.0.0"),
                    npm_component("libfoo", "4.0.0"),
                ]),
                None,
            );
            assert_eq!(version_pairs(&forward), version_pairs(&reversed));
        }
    }

    #[test]
    fn test_edge_diff_with_two_versions_of_one_package() {
        let child_a = Component::new("child-a".to_string(), Some("1.0.0".to_string()));
        let child_b = Component::new("child-b".to_string(), Some("1.0.0".to_string()));

        let build = |parent_versions: [&str; 2]| {
            let parents = parent_versions.map(|v| npm_component("libfoo", v));
            let mut sbom = sbom_of(vec![
                parents[0].clone(),
                parents[1].clone(),
                child_a.clone(),
                child_b.clone(),
            ]);
            for (parent, child) in parents.iter().zip([&child_a, &child_b]) {
                sbom.dependencies
                    .entry(parent.id.clone())
                    .or_default()
                    .insert(child.id.clone(), DependencyKind::Runtime);
            }
            sbom
        };

        let diff = Differ::diff(&build(["1.0.0", "2.0.0"]), &build(["1.0.1", "2.0.1"]), None);
        assert_eq!(
            diff.edge_diffs.len(),
            0,
            "both parents kept their dependency, got {:?}",
            diff.edge_diffs
        );
    }

    /// a purl-less re-export drops the ecosystem, so every component takes the
    /// wildcard path.
    #[test]
    fn test_wildcard_reconciliation_pairs_same_version_line() {
        for (old_comps, new_comps) in [
            (
                vec![
                    npm_component("libfoo", "1.0.0"),
                    npm_component("libfoo", "2.0.0"),
                ],
                vec![
                    plain_component("libfoo", "1.0.0"),
                    plain_component("libfoo", "2.0.0"),
                ],
            ),
            (
                vec![
                    plain_component("libfoo", "1.0.0"),
                    plain_component("libfoo", "2.0.0"),
                ],
                vec![
                    npm_component("libfoo", "1.0.0"),
                    npm_component("libfoo", "2.0.0"),
                ],
            ),
        ] {
            let diff = Differ::diff(&sbom_of(old_comps), &sbom_of(new_comps), None);
            assert_eq!(
                version_pairs(&diff),
                expect_pairs(&[("1.0.0", "1.0.0"), ("2.0.0", "2.0.0")])
            );
            assert_eq!(diff.added.len(), 0);
            assert_eq!(diff.removed.len(), 0);
            assert!(
                !diff.changed.iter().any(|c| c.is_downgrade),
                "re-serializing the same versions must not report a downgrade, got {:?}",
                version_pairs(&diff)
            );
        }
    }

    #[test]
    fn test_wildcard_reconciliation_prefers_version_nearest_candidate() {
        let old = sbom_of(vec![
            npm_component("libfoo", "2.0.0"),
            purl_component("pypi", "libfoo", "1.0.0"),
        ]);
        let new = sbom_of(vec![plain_component("libfoo", "1.0.1")]);

        let diff = Differ::diff(&old, &new, None);
        assert_eq!(version_pairs(&diff), expect_pairs(&[("1.0.0", "1.0.1")]));
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.added.len(), 0);
        assert!(!diff.changed.iter().any(|c| c.is_downgrade));
    }

    #[test]
    fn test_wildcard_reconciliation_breaks_version_ties_deterministically() {
        let old = sbom_of(
            ["cargo", "npm", "pypi"]
                .iter()
                .map(|eco| purl_component(eco, "libfoo", "1.0.0"))
                .collect(),
        );
        let new = sbom_of(vec![plain_component("libfoo", "1.0.1")]);

        let diff = Differ::diff(&old, &new, None);
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(
            diff.changed[0].old.id.as_str(),
            "pkg:pypi/libfoo@1.0.0",
            "equal versions must resolve by merged version order, not ecosystem name"
        );
        assert_eq!(diff.removed.len(), 2);
        assert_eq!(diff.added.len(), 0);
    }

    #[test]
    fn test_exact_ecosystem_match_beats_a_nearer_wildcard() {
        let old = sbom_of(vec![
            npm_component("libfoo", "1.0.0"),
            plain_component("libfoo", "2.0.0"),
        ]);
        let new = sbom_of(vec![npm_component("libfoo", "2.0.1")]);

        let diff = Differ::diff(&old, &new, None);
        assert_eq!(version_pairs(&diff), expect_pairs(&[("1.0.0", "2.0.1")]));
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.added.len(), 0);
    }
}
