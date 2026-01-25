use indexmap::IndexMap;
use packageurl::PackageUrl;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

/// format-agnostic sbom representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sbom {
    pub metadata: Metadata,
    pub components: IndexMap<ComponentId, Component>,
    /// adjacency list: parent -> children
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

/// sbom metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Metadata {
    pub timestamp: Option<String>,
    pub tools: Vec<String>,
    pub authors: Vec<String>,
}

/// stable identifier for a component.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ComponentId(String);

impl ComponentId {
    /// create a new id, preferring purl or hashing properties.
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

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ComponentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// a software component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    pub id: ComponentId,
    pub name: String,
    pub version: Option<String>,
    pub ecosystem: Option<String>,
    pub supplier: Option<String>,
    pub description: Option<String>,
    pub purl: Option<String>,
    pub licenses: Vec<String>,
    pub hashes: BTreeMap<String, String>,
    /// original ids from source document.
    pub source_ids: Vec<String>,
}

impl Component {
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
            licenses: Vec::new(),
            hashes: BTreeMap::new(),
            source_ids: Vec::new(),
        }
    }
}

// Normalization logic
impl Sbom {
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

    pub fn roots(&self) -> Vec<ComponentId> {
        let targets: BTreeSet<_> = self.dependencies.values().flatten().collect();
        self.components
            .keys()
            .filter(|id| !targets.contains(id))
            .cloned()
            .collect()
    }

    pub fn deps(&self, id: &ComponentId) -> Vec<ComponentId> {
        self.dependencies
            .get(id)
            .map(|d| d.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn rdeps(&self, id: &ComponentId) -> Vec<ComponentId> {
        self.dependencies
            .iter()
            .filter(|(_, children)| children.contains(id))
            .map(|(parent, _)| parent.clone())
            .collect()
    }

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

    pub fn ecosystems(&self) -> BTreeSet<String> {
        self.components
            .values()
            .filter_map(|c| c.ecosystem.clone())
            .collect()
    }

    pub fn licenses(&self) -> BTreeSet<String> {
        self.components
            .values()
            .flat_map(|c| c.licenses.iter().cloned())
            .collect()
    }

    pub fn missing_hashes(&self) -> Vec<ComponentId> {
        self.components
            .iter()
            .filter(|(_, c)| c.hashes.is_empty())
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub fn by_purl(&self, purl: &str) -> Option<&Component> {
        self.components
            .values()
            .find(|c| c.purl.as_deref() == Some(purl))
    }
}

impl Component {
    pub fn normalize(&mut self) {
        // Canonicalize licenses (simple sort and dedup for now)
        self.licenses.sort();
        self.licenses.dedup();

        // Canonicalize hashes (lowercase)
        let normalized_hashes: BTreeMap<String, String> = self
            .hashes
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
            .collect();
        self.hashes = normalized_hashes;
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
        comp.licenses.push("MIT".to_string());
        comp.licenses.push("MIT".to_string());
        comp.licenses.push("Apache-2.0".to_string());
        comp.hashes.insert("SHA-256".to_string(), "ABC".to_string());

        comp.normalize();

        assert_eq!(comp.licenses, vec!["Apache-2.0", "MIT"]);
        assert_eq!(comp.hashes.get("sha-256").unwrap(), "abc");
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
}
