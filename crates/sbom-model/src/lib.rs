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
    /// Non-fatal warnings produced during parsing (e.g. orphaned dependency refs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl Default for Sbom {
    fn default() -> Self {
        Self {
            metadata: Metadata::default(),
            components: IndexMap::new(),
            dependencies: BTreeMap::new(),
            warnings: Vec::new(),
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
        let id = ComponentId::new(Some(purl), &[]);
        self.components.get(&id)
    }

    /// Detects circular dependencies in the dependency graph.
    ///
    /// Uses DFS three-color marking (White → Gray → Black) to find all back
    /// edges. Each cycle is returned as a list of [`ComponentId`]s in dependency
    /// order: each element depends on the next, and the last depends on the
    /// first.
    ///
    /// A warning is appended to [`Sbom::warnings`] for every cycle found.
    ///
    /// # Example
    ///
    /// ```
    /// use sbom_model::{Sbom, Component};
    ///
    /// let mut sbom = Sbom::default();
    /// let a = Component::new("a".into(), Some("1".into()));
    /// let b = Component::new("b".into(), Some("1".into()));
    /// let id_a = a.id.clone();
    /// let id_b = b.id.clone();
    /// sbom.components.insert(id_a.clone(), a);
    /// sbom.components.insert(id_b.clone(), b);
    ///
    /// // a -> b -> a
    /// sbom.dependencies.entry(id_a.clone()).or_default().insert(id_b.clone());
    /// sbom.dependencies.entry(id_b.clone()).or_default().insert(id_a.clone());
    ///
    /// let cycles = sbom.detect_cycles();
    /// assert_eq!(cycles.len(), 1);
    /// assert!(sbom.warnings.iter().any(|w| w.starts_with("circular dependency:")));
    /// ```
    pub fn detect_cycles(&mut self) -> Vec<Vec<ComponentId>> {
        // Actions for the iterative DFS stack.
        enum Action<'a> {
            Enter(&'a ComponentId),
            Exit(&'a ComponentId),
        }

        const WHITE: u8 = 0;
        const GRAY: u8 = 1;
        const BLACK: u8 = 2;

        // Collect every node that appears in the dependency graph (as parent
        // or child) so leaf-only nodes are included in the traversal.
        let all_nodes: BTreeSet<&ComponentId> = self
            .dependencies
            .keys()
            .chain(self.dependencies.values().flat_map(|c| c.iter()))
            .collect();

        let mut color: BTreeMap<&ComponentId, u8> = BTreeMap::new();
        let mut path: Vec<&ComponentId> = Vec::new();
        let mut path_set: BTreeSet<&ComponentId> = BTreeSet::new();
        let mut cycles: Vec<Vec<ComponentId>> = Vec::new();

        for &start in &all_nodes {
            if *color.get(start).unwrap_or(&WHITE) != WHITE {
                continue;
            }

            let mut stack: Vec<Action<'_>> = vec![Action::Enter(start)];

            while let Some(action) = stack.pop() {
                match action {
                    Action::Exit(node) => {
                        color.insert(node, BLACK);
                        path.pop();
                        path_set.remove(node);
                    }
                    Action::Enter(node) => {
                        let c = *color.get(node).unwrap_or(&WHITE);
                        if c != WHITE {
                            continue;
                        }

                        color.insert(node, GRAY);
                        path.push(node);
                        path_set.insert(node);
                        stack.push(Action::Exit(node));

                        if let Some(children) = self.dependencies.get(node) {
                            for child in children.iter().rev() {
                                let cc = *color.get(child).unwrap_or(&WHITE);
                                if cc == WHITE {
                                    stack.push(Action::Enter(child));
                                } else if path_set.contains(child) {
                                    // Back edge — extract the cycle.
                                    let pos = path.iter().position(|&n| n == child).unwrap();
                                    let cycle: Vec<ComponentId> =
                                        path[pos..].iter().map(|&id| id.clone()).collect();
                                    cycles.push(cycle);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Build human-readable warnings.
        for cycle in &cycles {
            let names: Vec<String> = cycle
                .iter()
                .map(|id| {
                    self.components
                        .get(id)
                        .map(|c| match &c.version {
                            Some(v) => format!("{} {}", c.name, v),
                            None => c.name.clone(),
                        })
                        .unwrap_or_else(|| id.to_string())
                })
                .collect();

            let display = if names.len() == 1 {
                format!("{0} \u{2192} {0}", names[0])
            } else {
                format!("{} \u{2192} {}", names.join(" \u{2192} "), names[0])
            };

            self.warnings
                .push(format!("circular dependency: {}", display));
        }

        cycles
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

/// Normalizes a hash algorithm name to its canonical form.
///
/// Handles variations in casing and hyphenation so that algorithm names
/// from different SBOM formats (SPDX, CycloneDX) compare equal.
///
/// # Example
///
/// ```
/// use sbom_model::canonical_algorithm_name;
///
/// assert_eq!(canonical_algorithm_name("SHA256"), "SHA-256");
/// assert_eq!(canonical_algorithm_name("SHA-256"), "SHA-256");
/// assert_eq!(canonical_algorithm_name("sha256"), "SHA-256");
/// ```
pub fn canonical_algorithm_name(name: &str) -> String {
    match name.replace('-', "").to_uppercase().as_str() {
        "MD2" => "MD2",
        "MD4" => "MD4",
        "MD5" => "MD5",
        "MD6" => "MD6",
        "SHA1" => "SHA-1",
        "SHA224" => "SHA-224",
        "SHA256" => "SHA-256",
        "SHA384" => "SHA-384",
        "SHA512" => "SHA-512",
        "SHA3256" => "SHA3-256",
        "SHA3384" => "SHA3-384",
        "SHA3512" => "SHA3-512",
        "BLAKE2B256" => "BLAKE2b-256",
        "BLAKE2B384" => "BLAKE2b-384",
        "BLAKE2B512" => "BLAKE2b-512",
        "BLAKE3" => "BLAKE3",
        "ADLER32" => "ADLER-32",
        _ => return name.to_string(),
    }
    .to_string()
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

        // LicenseRef expressions parse but yield no standard IDs
        let ids = parse_license_expression("LicenseRef-proprietary");
        assert_eq!(ids, BTreeSet::from(["LicenseRef-proprietary".to_string()]));
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
    fn test_ecosystems_query() {
        let mut sbom = Sbom::default();

        let mut c1 = Component::new("lodash".into(), Some("1.0".into()));
        c1.ecosystem = Some("npm".into());
        let mut c2 = Component::new("serde".into(), Some("1.0".into()));
        c2.ecosystem = Some("cargo".into());
        let mut c3 = Component::new("other-npm".into(), Some("1.0".into()));
        c3.ecosystem = Some("npm".into());
        let c4 = Component::new("no-ecosystem".into(), Some("1.0".into()));

        sbom.components.insert(c1.id.clone(), c1);
        sbom.components.insert(c2.id.clone(), c2);
        sbom.components.insert(c3.id.clone(), c3);
        sbom.components.insert(c4.id.clone(), c4);

        let ecosystems = sbom.ecosystems();
        assert_eq!(ecosystems.len(), 2);
        assert!(ecosystems.contains("npm"));
        assert!(ecosystems.contains("cargo"));
    }

    #[test]
    fn test_licenses_query() {
        let mut sbom = Sbom::default();

        let mut c1 = Component::new("a".into(), Some("1.0".into()));
        c1.licenses.insert("MIT".into());
        c1.licenses.insert("Apache-2.0".into());
        let mut c2 = Component::new("b".into(), Some("1.0".into()));
        c2.licenses.insert("MIT".into());
        c2.licenses.insert("GPL-3.0-only".into());
        let c3 = Component::new("c".into(), Some("1.0".into()));

        sbom.components.insert(c1.id.clone(), c1);
        sbom.components.insert(c2.id.clone(), c2);
        sbom.components.insert(c3.id.clone(), c3);

        let licenses = sbom.licenses();
        assert_eq!(licenses.len(), 3);
        assert!(licenses.contains("MIT"));
        assert!(licenses.contains("Apache-2.0"));
        assert!(licenses.contains("GPL-3.0-only"));
    }

    #[test]
    fn test_by_purl() {
        let mut sbom = Sbom::default();

        let mut c1 = Component::new("lodash".into(), Some("4.17.21".into()));
        c1.purl = Some("pkg:npm/lodash@4.17.21".into());
        c1.id = ComponentId::new(c1.purl.as_deref(), &[]);
        let c2 = Component::new("no-purl".into(), Some("1.0".into()));

        sbom.components.insert(c1.id.clone(), c1);
        sbom.components.insert(c2.id.clone(), c2);

        let found = sbom.by_purl("pkg:npm/lodash@4.17.21");
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "lodash");

        assert!(sbom.by_purl("pkg:npm/nonexistent@1.0").is_none());
    }

    #[test]
    fn test_component_id_unparseable_purl() {
        // A purl string that can't be parsed should still be used as-is
        let id = ComponentId::new(Some("not-a-valid-purl-but-still-a-string"), &[]);
        assert_eq!(id.as_str(), "not-a-valid-purl-but-still-a-string");
    }

    #[test]
    fn test_component_id_display() {
        let id = ComponentId::new(Some("pkg:npm/foo@1.0"), &[]);
        assert_eq!(format!("{}", id), "pkg:npm/foo@1.0");
    }

    #[test]
    fn test_sbom_normalize_clears_metadata() {
        let mut sbom = Sbom::default();
        sbom.metadata.timestamp = Some("2024-01-01T00:00:00Z".into());
        sbom.metadata.tools.push("syft".into());
        sbom.metadata.authors.push("alice".into());

        let c = Component::new("a".into(), Some("1".into()));
        sbom.components.insert(c.id.clone(), c);

        sbom.normalize();

        assert!(sbom.metadata.timestamp.is_none());
        assert!(sbom.metadata.tools.is_empty());
        assert!(sbom.metadata.authors.is_empty());
    }

    #[test]
    fn test_missing_hashes_mixed() {
        let mut sbom = Sbom::default();

        let c1 = Component::new("no-hash".into(), Some("1.0".into()));
        let mut c2 = Component::new("has-hash".into(), Some("1.0".into()));
        c2.hashes.insert("sha256".into(), "abc".into());

        sbom.components.insert(c1.id.clone(), c1);
        sbom.components.insert(c2.id.clone(), c2);

        let missing = sbom.missing_hashes();
        assert_eq!(missing.len(), 1);
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

    #[test]
    fn test_canonical_algorithm_name() {
        // SHA family without hyphens (SPDX style)
        assert_eq!(canonical_algorithm_name("SHA256"), "SHA-256");
        assert_eq!(canonical_algorithm_name("SHA1"), "SHA-1");
        assert_eq!(canonical_algorithm_name("SHA384"), "SHA-384");
        assert_eq!(canonical_algorithm_name("SHA512"), "SHA-512");
        assert_eq!(canonical_algorithm_name("SHA224"), "SHA-224");

        // SHA family with hyphens (CycloneDX style)
        assert_eq!(canonical_algorithm_name("SHA-256"), "SHA-256");
        assert_eq!(canonical_algorithm_name("SHA-1"), "SHA-1");
        assert_eq!(canonical_algorithm_name("SHA-384"), "SHA-384");

        // Case-insensitive
        assert_eq!(canonical_algorithm_name("sha256"), "SHA-256");
        assert_eq!(canonical_algorithm_name("sha-256"), "SHA-256");

        // SHA-3
        assert_eq!(canonical_algorithm_name("SHA3-256"), "SHA3-256");
        assert_eq!(canonical_algorithm_name("SHA3256"), "SHA3-256");

        // MD family
        assert_eq!(canonical_algorithm_name("MD5"), "MD5");
        assert_eq!(canonical_algorithm_name("md5"), "MD5");

        // BLAKE
        assert_eq!(canonical_algorithm_name("BLAKE2b-256"), "BLAKE2b-256");
        assert_eq!(canonical_algorithm_name("BLAKE2B256"), "BLAKE2b-256");
        assert_eq!(canonical_algorithm_name("BLAKE3"), "BLAKE3");

        // ADLER
        assert_eq!(canonical_algorithm_name("ADLER32"), "ADLER-32");
        assert_eq!(canonical_algorithm_name("ADLER-32"), "ADLER-32");

        // Unknown algorithm passes through
        assert_eq!(canonical_algorithm_name("TIGER"), "TIGER");
    }

    // ── detect_cycles tests ──────────────────────────────────────────

    /// Helper: build an SBOM with named components and dependency edges.
    fn sbom_with_edges(names: &[&str], edges: &[(&str, &str)]) -> Sbom {
        let mut sbom = Sbom::default();
        let mut ids: BTreeMap<String, ComponentId> = BTreeMap::new();

        for &name in names {
            let c = Component::new(name.into(), Some("1".into()));
            ids.insert(name.into(), c.id.clone());
            sbom.components.insert(c.id.clone(), c);
        }

        for &(from, to) in edges {
            let from_id = ids[from].clone();
            let to_id = ids[to].clone();
            sbom.dependencies.entry(from_id).or_default().insert(to_id);
        }

        sbom
    }

    #[test]
    fn test_detect_cycles_empty_graph() {
        let mut sbom = Sbom::default();
        let cycles = sbom.detect_cycles();
        assert!(cycles.is_empty());
        assert!(sbom.warnings.is_empty());
    }

    #[test]
    fn test_detect_cycles_no_deps() {
        let mut sbom = sbom_with_edges(&["a", "b", "c"], &[]);
        let cycles = sbom.detect_cycles();
        assert!(cycles.is_empty());
        assert!(sbom.warnings.is_empty());
    }

    #[test]
    fn test_detect_cycles_dag() {
        // Diamond: a -> b, a -> c, b -> d, c -> d (no cycle)
        let mut sbom = sbom_with_edges(
            &["a", "b", "c", "d"],
            &[("a", "b"), ("a", "c"), ("b", "d"), ("c", "d")],
        );
        let cycles = sbom.detect_cycles();
        assert!(cycles.is_empty());
        assert!(sbom.warnings.is_empty());
    }

    #[test]
    fn test_detect_cycles_self_loop() {
        let mut sbom = sbom_with_edges(&["a"], &[("a", "a")]);
        let cycles = sbom.detect_cycles();
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].len(), 1);
        assert_eq!(sbom.warnings.len(), 1);
        assert!(sbom.warnings[0].starts_with("circular dependency:"));
        assert!(sbom.warnings[0].contains("a 1"));
    }

    #[test]
    fn test_detect_cycles_mutual_deps() {
        // a -> b, b -> a
        let mut sbom = sbom_with_edges(&["a", "b"], &[("a", "b"), ("b", "a")]);
        let cycles = sbom.detect_cycles();
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].len(), 2);
        assert_eq!(sbom.warnings.len(), 1);
        assert!(sbom.warnings[0].contains("\u{2192}"));
    }

    #[test]
    fn test_detect_cycles_triangle() {
        // a -> b -> c -> a
        let mut sbom = sbom_with_edges(&["a", "b", "c"], &[("a", "b"), ("b", "c"), ("c", "a")]);
        let cycles = sbom.detect_cycles();
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].len(), 3);
        assert_eq!(sbom.warnings.len(), 1);
    }

    #[test]
    fn test_detect_cycles_larger_cycle() {
        // a -> b -> c -> d -> a
        let mut sbom = sbom_with_edges(
            &["a", "b", "c", "d"],
            &[("a", "b"), ("b", "c"), ("c", "d"), ("d", "a")],
        );
        let cycles = sbom.detect_cycles();
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].len(), 4);
    }

    #[test]
    fn test_detect_cycles_multiple_disjoint() {
        // Cycle 1: a -> b -> a
        // Cycle 2: c -> d -> c
        let mut sbom = sbom_with_edges(
            &["a", "b", "c", "d"],
            &[("a", "b"), ("b", "a"), ("c", "d"), ("d", "c")],
        );
        let cycles = sbom.detect_cycles();
        assert_eq!(cycles.len(), 2);
    }

    #[test]
    fn test_detect_cycles_mixed_cyclic_and_acyclic() {
        // Acyclic part: x -> y -> z
        // Cyclic part: a -> b -> c -> a
        let mut sbom = sbom_with_edges(
            &["a", "b", "c", "x", "y", "z"],
            &[("a", "b"), ("b", "c"), ("c", "a"), ("x", "y"), ("y", "z")],
        );
        let cycles = sbom.detect_cycles();
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].len(), 3);
    }

    #[test]
    fn test_detect_cycles_nested_cycles() {
        // a -> b -> c -> a (big cycle) and b -> c -> b (smaller cycle via the
        // same edges).  The DFS finds back edges; the shorter cycle (b,c) is a
        // subset of the path when the c -> b back edge is encountered from
        // inside the larger traversal. Depending on traversal order, DFS may
        // report one or both.  We just check at least one is found and all
        // warnings are well-formed.
        let mut sbom = sbom_with_edges(
            &["a", "b", "c"],
            &[("a", "b"), ("b", "c"), ("c", "a"), ("c", "b")],
        );
        let cycles = sbom.detect_cycles();
        assert!(!cycles.is_empty());
        for w in &sbom.warnings {
            assert!(w.starts_with("circular dependency:"));
            assert!(w.contains('\u{2192}'));
        }
    }

    #[test]
    fn test_detect_cycles_warning_format_self_loop() {
        let mut sbom = sbom_with_edges(&["pkg"], &[("pkg", "pkg")]);
        sbom.detect_cycles();
        // Self-loop format: "circular dependency: pkg 1 → pkg 1"
        assert_eq!(sbom.warnings.len(), 1);
        let w = &sbom.warnings[0];
        assert!(w.starts_with("circular dependency: pkg 1 \u{2192} pkg 1"));
    }

    #[test]
    fn test_detect_cycles_warning_format_chain() {
        // a -> b -> a — warning should show: "circular dependency: a 1 → b 1 → a 1"
        let mut sbom = sbom_with_edges(&["a", "b"], &[("a", "b"), ("b", "a")]);
        sbom.detect_cycles();
        assert_eq!(sbom.warnings.len(), 1);
        let w = &sbom.warnings[0];
        assert!(w.starts_with("circular dependency:"));
        // The warning should close the loop by repeating the first name.
        let arrow = '\u{2192}';
        let arrow_count = w.matches(arrow).count();
        assert_eq!(arrow_count, 2, "mutual dep warning should have two arrows");
    }

    #[test]
    fn test_detect_cycles_component_without_version() {
        let mut sbom = Sbom::default();
        let a = Component::new("alpha".into(), None);
        let b = Component::new("beta".into(), None);
        let id_a = a.id.clone();
        let id_b = b.id.clone();
        sbom.components.insert(id_a.clone(), a);
        sbom.components.insert(id_b.clone(), b);
        sbom.dependencies
            .entry(id_a.clone())
            .or_default()
            .insert(id_b.clone());
        sbom.dependencies.entry(id_b).or_default().insert(id_a);

        sbom.detect_cycles();
        assert_eq!(sbom.warnings.len(), 1);
        // Should use name without version suffix.
        let w = &sbom.warnings[0];
        assert!(w.contains("alpha"));
        assert!(w.contains("beta"));
        // Should NOT contain "None" or "(no version)"
        assert!(!w.contains("None"));
    }

    #[test]
    fn test_detect_cycles_idempotent() {
        let mut sbom = sbom_with_edges(&["a", "b"], &[("a", "b"), ("b", "a")]);
        sbom.detect_cycles();
        let warnings_after_first = sbom.warnings.len();

        // Second call should find the same cycles and add more warnings
        // (the method is stateless w.r.t. the graph).
        sbom.detect_cycles();
        assert_eq!(sbom.warnings.len(), warnings_after_first * 2);
    }

    #[test]
    fn test_detect_cycles_long_chain_no_cycle() {
        // a -> b -> c -> d -> e -> f (linear, no cycle)
        let mut sbom = sbom_with_edges(
            &["a", "b", "c", "d", "e", "f"],
            &[("a", "b"), ("b", "c"), ("c", "d"), ("d", "e"), ("e", "f")],
        );
        let cycles = sbom.detect_cycles();
        assert!(cycles.is_empty());
    }
}
