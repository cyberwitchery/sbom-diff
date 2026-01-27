#![doc = include_str!("../readme.md")]

use indexmap::IndexMap;
use packageurl::PackageUrl;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

/// Format-agnostic SBOM (Software Bill of Materials) representation.
///
/// This is the central type that holds all components and their relationships.
/// It abstracts over format-specific details from CycloneDX, SPDX, and other formats.
///
/// # Example
///
/// ```
/// use sbom_model::{Sbom, Component};
///
/// let mut sbom = Sbom::default();
/// let component = Component::new("serde".into(), Some("1.0.0".into()));
/// sbom.components.insert(component.id.clone(), component);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sbom {
    /// Document-level metadata (creation time, tools, authors).
    pub metadata: Metadata,
    /// All components indexed by their stable identifier.
    pub components: IndexMap<ComponentId, Component>,
    /// Dependency graph as adjacency list: parent -> set of children.
    pub dependencies: BTreeMap<ComponentId, BTreeSet<ComponentId>>,
}

impl Default for Sbom {
    fn default() -> Self {
        Self {
            metadata: Metadata::default(),
            components: IndexMap::new(),
            dependencies: BTreeMap::new(),
        }
    }
}

/// SBOM document metadata.
///
/// Contains information about when and how the SBOM was created.
/// This data is stripped during normalization since it varies between
/// tool runs and shouldn't affect diff comparisons.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Metadata {
    /// ISO 8601 timestamp of document creation.
    pub timestamp: Option<String>,
    /// Tools used to generate the SBOM (e.g., "syft", "trivy").
    pub tools: Vec<String>,
    /// Document authors or organizations.
    pub authors: Vec<String>,
}

/// Stable identifier for a component.
///
/// Used as a key in the component map and dependency graph. Prefers package URLs
/// (purls) when available since they provide globally unique identifiers. Falls
/// back to a deterministic SHA-256 hash of component properties when no purl exists.
///
/// # Example
///
/// ```
/// use sbom_model::ComponentId;
///
/// // With a purl (preferred)
/// let id = ComponentId::new(Some("pkg:npm/lodash@4.17.21"), &[]);
/// assert_eq!(id.as_str(), "pkg:npm/lodash@4.17.21");
///
/// // Without a purl (hash fallback)
/// let id = ComponentId::new(None, &[("name", "foo"), ("version", "1.0")]);
/// assert!(id.as_str().starts_with("h:"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ComponentId(String);

impl ComponentId {
    /// Creates a new identifier from a purl or property hash.
    ///
    /// If a purl is provided, it will be canonicalized. Otherwise, a deterministic
    /// SHA-256 hash is computed from the provided key-value properties.
    pub fn new(purl: Option<&str>, properties: &[(&str, &str)]) -> Self {
        if let Some(purl) = purl {
            // Try to canonicalize purl
            if let Ok(parsed) = PackageUrl::from_str(purl) {
                return ComponentId(parsed.to_string());
            }
            return ComponentId(purl.to_string());
        }

        // Deterministic hash fallback
        let mut hasher = Sha256::new();
        for (k, v) in properties {
            hasher.update(k.as_bytes());
            hasher.update(b":");
            hasher.update(v.as_bytes());
            hasher.update(b"|");
        }
        let hash = hex::encode(hasher.finalize());
        ComponentId(format!("h:{}", hash))
    }

    /// Returns the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ComponentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A software component (package, library, or application).
///
/// Represents a single entry in the SBOM with all its metadata.
/// Components are identified by their [`ComponentId`] and can have
/// relationships to other components via the dependency graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    /// Stable identifier for this component.
    pub id: ComponentId,
    /// Package name (e.g., "serde", "lodash").
    pub name: String,
    /// Package version (e.g., "1.0.0", "4.17.21").
    pub version: Option<String>,
    /// Package ecosystem (e.g., "cargo", "npm", "pypi").
    pub ecosystem: Option<String>,
    /// Package supplier or publisher.
    pub supplier: Option<String>,
    /// Human-readable description.
    pub description: Option<String>,
    /// Package URL per the [purl spec](https://github.com/package-url/purl-spec).
    pub purl: Option<String>,
    /// SPDX license identifiers (e.g., "MIT", "Apache-2.0").
    pub licenses: BTreeSet<String>,
    /// Checksums keyed by algorithm (e.g., "sha256" -> "abc123...").
    pub hashes: BTreeMap<String, String>,
    /// Original identifiers from the source document (e.g., SPDX SPDXRef, CycloneDX bom-ref).
    pub source_ids: Vec<String>,
}

impl Component {
    /// Creates a new component with the given name and optional version.
    ///
    /// The component ID is generated from a hash of the name and version.
    /// Use this for simple cases; for full control, construct the struct directly.
    pub fn new(name: String, version: Option<String>) -> Self {
        let mut props = vec![("name", name.as_str())];
        if let Some(v) = &version {
            props.push(("version", v));
        }
        let id = ComponentId::new(None, &props);

        Self {
            id,
            name,
            version,
            ecosystem: None,
            supplier: None,
            description: None,
            purl: None,
            licenses: BTreeSet::new(),
            hashes: BTreeMap::new(),
            source_ids: Vec::new(),
        }
    }
}

impl Sbom {
    /// Normalizes the SBOM for deterministic comparison.
    ///
    /// This method:
    /// - Sorts components by ID
    /// - Deduplicates and sorts licenses within each component
    /// - Lowercases hash algorithms and values
    /// - Clears volatile metadata (timestamps, tools, authors)
    ///
    /// Call this before comparing two SBOMs to ignore irrelevant differences.
    pub fn normalize(&mut self) {
        // Sort components by ID for deterministic output
        self.components.sort_keys();

        // Sort dependencies
        for deps in self.dependencies.values_mut() {
            // BTreeSet is already sorted
            // But we might want to ensure consistency if we change container types later
            let _ = deps;
        }

        // Normalize components
        for component in self.components.values_mut() {
            component.normalize();
        }

        // Strip volatile metadata
        self.metadata.timestamp = None;
        self.metadata.tools.clear();
        self.metadata.authors.clear(); // Authors might be relevant, but often change slightly. Let's keep strict for now.
    }

    /// Returns root components (those not depended on by any other component).
    ///
    /// These are typically the top-level packages or applications in the SBOM.
    pub fn roots(&self) -> Vec<ComponentId> {
        let targets: BTreeSet<_> = self.dependencies.values().flatten().collect();
        self.components
            .keys()
            .filter(|id| !targets.contains(id))
            .cloned()
            .collect()
    }

    /// Returns direct dependencies of the given component.
    pub fn deps(&self, id: &ComponentId) -> Vec<ComponentId> {
        self.dependencies
            .get(id)
            .map(|d| d.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Returns reverse dependencies (components that depend on the given component).
    pub fn rdeps(&self, id: &ComponentId) -> Vec<ComponentId> {
        self.dependencies
            .iter()
            .filter(|(_, children)| children.contains(id))
            .map(|(parent, _)| parent.clone())
            .collect()
    }

    /// Returns all transitive dependencies of the given component.
    ///
    /// Traverses the dependency graph depth-first and returns all reachable components.
    pub fn transitive_deps(&self, id: &ComponentId) -> BTreeSet<ComponentId> {
        let mut visited = BTreeSet::new();
        let mut stack = vec![id.clone()];
        while let Some(current) = stack.pop() {
            if let Some(children) = self.dependencies.get(&current) {
                for child in children {
                    if visited.insert(child.clone()) {
                        stack.push(child.clone());
                    }
                }
            }
        }
        visited
    }

    /// Returns all unique ecosystems present in the SBOM.
    pub fn ecosystems(&self) -> BTreeSet<String> {
        self.components
            .values()
            .filter_map(|c| c.ecosystem.clone())
            .collect()
    }

    /// Returns all unique licenses present across all components.
    pub fn licenses(&self) -> BTreeSet<String> {
        self.components
            .values()
            .flat_map(|c| c.licenses.iter().cloned())
            .collect()
    }

    /// Returns components that have no checksums/hashes.
    ///
    /// Useful for identifying components that may need integrity verification.
    pub fn missing_hashes(&self) -> Vec<ComponentId> {
        self.components
            .iter()
            .filter(|(_, c)| c.hashes.is_empty())
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Finds a component by its package URL.
    pub fn by_purl(&self, purl: &str) -> Option<&Component> {
        self.components
            .values()
            .find(|c| c.purl.as_deref() == Some(purl))
    }
}

impl Component {
    /// Normalizes the component for deterministic comparison.
    ///
    /// Lowercases hash keys and values. Licenses are stored as a BTreeSet
    /// so they're already sorted and deduplicated.
    pub fn normalize(&mut self) {
        let normalized_hashes: BTreeMap<String, String> = self
            .hashes
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
            .collect();
        self.hashes = normalized_hashes;
    }
}

/// Extracts the ecosystem (package type) from a purl string.
///
/// Returns `None` if the purl is invalid or cannot be parsed.
///
/// # Example
///
/// ```
/// use sbom_model::ecosystem_from_purl;
///
/// assert_eq!(ecosystem_from_purl("pkg:npm/lodash@4.17.21"), Some("npm".to_string()));
/// assert_eq!(ecosystem_from_purl("pkg:cargo/serde@1.0.0"), Some("cargo".to_string()));
/// assert_eq!(ecosystem_from_purl("invalid"), None);
/// ```
pub fn ecosystem_from_purl(purl: &str) -> Option<String> {
    PackageUrl::from_str(purl).ok().map(|p| p.ty().to_string())
}

/// Extracts individual license IDs from an SPDX expression.
///
/// Parses the expression and returns all license IDs found.
/// If parsing fails, returns the original string as a single-element set.
///
/// # Example
///
/// ```
/// use sbom_model::parse_license_expression;
///
/// let ids = parse_license_expression("MIT OR Apache-2.0");
/// assert!(ids.contains("MIT"));
/// assert!(ids.contains("Apache-2.0"));
/// ```
pub fn parse_license_expression(license: &str) -> BTreeSet<String> {
    match spdx::Expression::parse(license) {
        Ok(expr) => {
            let ids: BTreeSet<String> = expr
                .requirements()
                .filter_map(|r| r.req.license.id())
                .map(|id| id.name.to_string())
                .collect();
            if ids.is_empty() {
                // Expression parsed but no IDs found, keep original
                BTreeSet::from([license.to_string()])
            } else {
                ids
            }
        }
        Err(_) => {
            // Not a valid SPDX expression, keep original
            BTreeSet::from([license.to_string()])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_component_id_purl() {
        let purl = "pkg:npm/left-pad@1.3.0";
        let id = ComponentId::new(Some(purl), &[]);
        assert_eq!(id.as_str(), purl);
    }

    #[test]
    fn test_component_id_hash_stability() {
        let props = [("name", "foo"), ("version", "1.0")];
        let id1 = ComponentId::new(None, &props);
        let id2 = ComponentId::new(None, &props);
        assert_eq!(id1, id2);
        assert!(id1.as_str().starts_with("h:"));
    }

    #[test]
    fn test_normalization() {
        let mut comp = Component::new("test".to_string(), Some("1.0".to_string()));
        comp.licenses.insert("MIT".to_string());
        comp.licenses.insert("Apache-2.0".to_string());
        comp.hashes.insert("SHA-256".to_string(), "ABC".to_string());

        comp.normalize();

        // BTreeSet is already sorted and deduped
        assert_eq!(
            comp.licenses,
            BTreeSet::from(["Apache-2.0".to_string(), "MIT".to_string()])
        );
        assert_eq!(comp.hashes.get("sha-256").unwrap(), "abc");
    }

    #[test]
    fn test_parse_license_expression() {
        // OR expression extracts both IDs
        let ids = parse_license_expression("MIT OR Apache-2.0");
        assert!(ids.contains("MIT"));
        assert!(ids.contains("Apache-2.0"));
        assert_eq!(ids.len(), 2);

        // Single license
        let ids = parse_license_expression("MIT");
        assert_eq!(ids, BTreeSet::from(["MIT".to_string()]));

        // AND expression extracts both IDs
        let ids = parse_license_expression("MIT AND Apache-2.0");
        assert!(ids.contains("MIT"));
        assert!(ids.contains("Apache-2.0"));

        // Invalid expression kept as-is
        let ids = parse_license_expression("Custom License");
        assert_eq!(ids, BTreeSet::from(["Custom License".to_string()]));
    }

    #[test]
    fn test_license_set_equality() {
        // Two components with same licenses in different order are equal
        let mut c1 = Component::new("test".into(), None);
        c1.licenses.insert("MIT".into());
        c1.licenses.insert("Apache-2.0".into());

        let mut c2 = Component::new("test".into(), None);
        c2.licenses.insert("Apache-2.0".into());
        c2.licenses.insert("MIT".into());

        assert_eq!(c1.licenses, c2.licenses);
    }

    #[test]
    fn test_query_api() {
        let mut sbom = Sbom::default();
        let c1 = Component::new("a".into(), Some("1".into()));
        let c2 = Component::new("b".into(), Some("1".into()));
        let c3 = Component::new("c".into(), Some("1".into()));

        let id1 = c1.id.clone();
        let id2 = c2.id.clone();
        let id3 = c3.id.clone();

        sbom.components.insert(id1.clone(), c1);
        sbom.components.insert(id2.clone(), c2);
        sbom.components.insert(id3.clone(), c3);

        // id1 -> id2 -> id3
        sbom.dependencies
            .entry(id1.clone())
            .or_default()
            .insert(id2.clone());
        sbom.dependencies
            .entry(id2.clone())
            .or_default()
            .insert(id3.clone());

        assert_eq!(sbom.roots(), vec![id1.clone()]);
        assert_eq!(sbom.deps(&id1), vec![id2.clone()]);
        assert_eq!(sbom.rdeps(&id2), vec![id1.clone()]);

        let transitive = sbom.transitive_deps(&id1);
        assert!(transitive.contains(&id2));
        assert!(transitive.contains(&id3));
        assert_eq!(transitive.len(), 2);

        assert_eq!(sbom.missing_hashes().len(), 3);
    }

    #[test]
    fn test_ecosystem_from_purl() {
        use super::ecosystem_from_purl;

        assert_eq!(
            ecosystem_from_purl("pkg:npm/lodash@4.17.21"),
            Some("npm".to_string())
        );
        assert_eq!(
            ecosystem_from_purl("pkg:cargo/serde@1.0.0"),
            Some("cargo".to_string())
        );
        assert_eq!(
            ecosystem_from_purl("pkg:pypi/requests@2.28.0"),
            Some("pypi".to_string())
        );
        assert_eq!(
            ecosystem_from_purl("pkg:maven/org.apache/commons@1.0"),
            Some("maven".to_string())
        );
        assert_eq!(ecosystem_from_purl("invalid-purl"), None);
        assert_eq!(ecosystem_from_purl(""), None);
    }
}
