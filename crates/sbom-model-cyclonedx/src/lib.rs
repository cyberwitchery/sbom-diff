#![doc = include_str!("../readme.md")]

use sbom_model::{parse_license_expression, Component, ComponentId, Sbom};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use thiserror::Error;

/// Errors that can occur when parsing CycloneDX documents.
#[derive(Error, Debug)]
pub enum Error {
    /// The JSON structure doesn't match the CycloneDX schema.
    #[error("CycloneDX parse error: {0}")]
    Parse(#[from] cyclonedx_bom::errors::JsonReadError),
    /// An I/O error occurred while reading the input.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// Internal normalization failed.
    #[error("Normalization error: {0}")]
    Normalization(String),
}

/// Parser for CycloneDX JSON documents.
///
/// Converts CycloneDX 1.4+ JSON into the format-agnostic [`Sbom`] type.
pub struct CycloneDxReader;

impl CycloneDxReader {
    /// Parses a CycloneDX JSON document from a reader.
    ///
    /// # Example
    ///
    /// ```
    /// use sbom_model_cyclonedx::CycloneDxReader;
    ///
    /// let json = r#"{
    ///     "bomFormat": "CycloneDX",
    ///     "specVersion": "1.4",
    ///     "version": 1,
    ///     "components": []
    /// }"#;
    ///
    /// let sbom = CycloneDxReader::read_json(json.as_bytes()).unwrap();
    /// ```
    pub fn read_json<R: Read>(reader: R) -> Result<Sbom, Error> {
        let bom = cyclonedx_bom::prelude::Bom::parse_from_json(reader)?;

        let mut sbom = Sbom::default();

        // 1. Process Metadata
        if let Some(meta) = bom.metadata {
            if let Some(timestamp) = meta.timestamp {
                sbom.metadata.timestamp = Some(timestamp.to_string());
            }
            if let Some(tools) = meta.tools {
                match tools {
                    cyclonedx_bom::models::tool::Tools::List(list) => {
                        for tool in list {
                            let mut s = String::new();
                            if let Some(v) = &tool.vendor {
                                s.push_str(&v.to_string());
                                s.push(' ');
                            }
                            if let Some(n) = &tool.name {
                                s.push_str(&n.to_string());
                            }
                            if let Some(v) = &tool.version {
                                s.push(' ');
                                s.push_str(&v.to_string());
                            }
                            sbom.metadata.tools.push(s.trim().to_string());
                        }
                    }
                    cyclonedx_bom::models::tool::Tools::Object { components, .. } => {
                        for component in components.0 {
                            let mut s = component.name.to_string();
                            if let Some(v) = &component.version {
                                s.push(' ');
                                s.push_str(&v.to_string());
                            }
                            sbom.metadata.tools.push(s);
                        }
                    }
                }
            }
            if let Some(authors) = meta.authors {
                for author in authors {
                    let mut s = String::new();
                    if let Some(n) = &author.name {
                        s.push_str(n.as_ref());
                    }
                    if let Some(e) = &author.email {
                        s.push_str(" <");
                        s.push_str(e.as_ref());
                        s.push('>');
                    }
                    sbom.metadata.authors.push(s.trim().to_string());
                }
            }
        }

        // 2. Process Components
        if let Some(components) = bom.components {
            for cdx_comp in components.0 {
                let name = cdx_comp.name.to_string();
                let version = cdx_comp.version.as_ref().map(|v| v.to_string());

                let mut props = vec![("name", name.as_str())];
                let v_str = version.clone().unwrap_or_default();
                if version.is_some() {
                    props.push(("version", v_str.as_str()));
                }

                let supplier = cdx_comp
                    .supplier
                    .as_ref()
                    .map(|s| s.name.as_ref().map(|n| n.to_string()).unwrap_or_default());
                let s_str = supplier.clone().unwrap_or_default();
                if supplier.is_some() {
                    props.push(("supplier", s_str.as_str()));
                }

                let purl = cdx_comp.purl.as_ref().map(|p| p.to_string());
                let purl_str = purl.as_deref();

                // Extract ecosystem from purl
                let ecosystem = purl_str.and_then(sbom_model::ecosystem_from_purl);

                let id = ComponentId::new(purl_str, &props);

                let mut comp = Component {
                    id: id.clone(),
                    name,
                    version,
                    ecosystem,
                    supplier,
                    description: cdx_comp.description.as_ref().map(|d| d.to_string()),
                    purl,
                    licenses: BTreeSet::new(),
                    hashes: BTreeMap::new(),
                    source_ids: Vec::new(),
                };

                if let Some(bom_ref) = cdx_comp.bom_ref {
                    comp.source_ids.push(bom_ref.to_string());
                }

                if let Some(licenses) = cdx_comp.licenses {
                    for license_choice in licenses.0 {
                        match license_choice {
                            cyclonedx_bom::models::license::LicenseChoice::License(l) => {
                                let li = l.license_identifier;
                                let s = match li {
                                    cyclonedx_bom::models::license::LicenseIdentifier::Name(n) => {
                                        n.to_string()
                                    }
                                    cyclonedx_bom::models::license::LicenseIdentifier::SpdxId(
                                        id,
                                    ) => id.to_string(),
                                };
                                comp.licenses.insert(s);
                            }
                            cyclonedx_bom::models::license::LicenseChoice::Expression(e) => {
                                comp.licenses
                                    .extend(parse_license_expression(&e.to_string()));
                            }
                        }
                    }
                }

                if let Some(hashes) = cdx_comp.hashes {
                    for h in hashes.0 {
                        comp.hashes.insert(h.alg.to_string(), h.content.0);
                    }
                }

                sbom.components.insert(id, comp);
            }
        }

        // 3. Process Dependencies
        // This is tricky because CDX uses bom-refs for dependency graph.
        // We need to map bom-refs to our ComponentIds.

        // Build a map of bom-ref -> ComponentId
        let mut ref_map = BTreeMap::new();
        for (id, comp) in &sbom.components {
            for src_id in &comp.source_ids {
                ref_map.insert(src_id.clone(), id.clone());
            }
        }

        if let Some(dependencies) = bom.dependencies {
            for dep in dependencies.0 {
                let parent_ref = dep.dependency_ref;
                if let Some(parent_id) = ref_map.get(&parent_ref.to_string()) {
                    let mut children = BTreeSet::new();
                    // dependencies is Vec<String>
                    for child_ref in dep.dependencies {
                        if let Some(child_id) = ref_map.get(&child_ref.to_string()) {
                            children.insert(child_id.clone());
                        }
                    }
                    if !children.is_empty() {
                        sbom.dependencies.insert(parent_id.clone(), children);
                    }
                }
            }
        }

        Ok(sbom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tools_list_parsed() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "tools": [
                    {"vendor": "CycloneDX", "name": "cargo-cyclonedx", "version": "0.5.0"},
                    {"name": "syft"}
                ]
            },
            "components": []
        }"#;
        let sbom = CycloneDxReader::read_json(json.as_bytes()).unwrap();
        assert_eq!(
            sbom.metadata.tools,
            vec!["CycloneDX cargo-cyclonedx 0.5.0", "syft"]
        );
    }

    #[test]
    fn test_tools_object_parsed() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "tools": {
                    "components": [
                        {"type": "application", "name": "cargo-cyclonedx", "version": "0.5.0"},
                        {"type": "application", "name": "syft"}
                    ],
                    "services": []
                }
            },
            "components": []
        }"#;
        let sbom = CycloneDxReader::read_json(json.as_bytes()).unwrap();
        assert_eq!(sbom.metadata.tools, vec!["cargo-cyclonedx 0.5.0", "syft"]);
    }

    #[test]
    fn test_read_minimal_json() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "pkg-a",
                    "version": "1.0.0"
                }
            ]
        }"#;
        let sbom = CycloneDxReader::read_json(json.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.components[0].name, "pkg-a");
    }

    #[test]
    fn test_read_complex_json() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": "2023-01-01T00:00:00Z",
                "authors": [{"name": "alice", "email": "alice@example.com"}]
            },
            "components": [
                {
                    "type": "library",
                    "name": "pkg-a",
                    "version": "1.0.0",
                    "bom-ref": "ref-a",
                    "hashes": [{"alg": "SHA-256", "content": "abc"}],
                    "licenses": [{"license": {"id": "MIT"}}]
                },
                {
                    "type": "library",
                    "name": "pkg-b",
                    "version": "2.0.0",
                    "bom-ref": "ref-b"
                }
            ],
            "dependencies": [
                {
                    "ref": "ref-a",
                    "dependsOn": ["ref-b"]
                }
            ]
        }"#;
        let sbom = CycloneDxReader::read_json(json.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 2);
        assert!(sbom.dependencies.contains_key(&sbom.components[0].id));
    }

    #[test]
    fn test_ecosystem_extracted_from_purl() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "lodash",
                    "version": "4.17.21",
                    "purl": "pkg:npm/lodash@4.17.21"
                },
                {
                    "type": "library",
                    "name": "serde",
                    "version": "1.0.0",
                    "purl": "pkg:cargo/serde@1.0.0"
                },
                {
                    "type": "library",
                    "name": "no-purl-pkg",
                    "version": "1.0.0"
                }
            ]
        }"#;
        let sbom = CycloneDxReader::read_json(json.as_bytes()).unwrap();

        let lodash = sbom
            .components
            .values()
            .find(|c| c.name == "lodash")
            .unwrap();
        assert_eq!(lodash.ecosystem, Some("npm".to_string()));

        let serde = sbom
            .components
            .values()
            .find(|c| c.name == "serde")
            .unwrap();
        assert_eq!(serde.ecosystem, Some("cargo".to_string()));

        let no_purl = sbom
            .components
            .values()
            .find(|c| c.name == "no-purl-pkg")
            .unwrap();
        assert_eq!(no_purl.ecosystem, None);
    }
}
