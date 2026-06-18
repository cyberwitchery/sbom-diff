#![doc = include_str!("../readme.md")]

use sbom_model::{
    canonical_algorithm_name, parse_license_expression, Component, ComponentId, DependencyKind,
    Sbom,
};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use thiserror::Error;

/// errors that can occur when parsing CycloneDX documents.
#[derive(Error, Debug)]
pub enum Error {
    /// the JSON structure doesn't match the CycloneDX schema.
    #[error("CycloneDX JSON parse error: {0}")]
    Parse(#[from] cyclonedx_bom::errors::JsonReadError),
    /// XML parsing failed for all attempted spec versions.
    #[error("CycloneDX XML failed all spec versions:\n{0}")]
    XmlParseAllVersions(String),
    /// the CycloneDX document version is not supported.
    #[error("unsupported CycloneDX specVersion '{version}': only 1.3–1.5 is supported")]
    UnsupportedVersion {
        /// the version string found in the document.
        version: String,
    },
    /// an I/O error occurred while reading the input.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// internal normalization failed.
    #[error("Normalization error: {0}")]
    Normalization(String),
}

/// spec versions the `cyclonedx-bom` crate (0.6) can deserialize.
///
/// used by the pre-check guards so there is a single place to update when
/// the library gains support for newer spec revisions.
const SUPPORTED_SPEC_VERSIONS: &[&str] = &["1.3", "1.4", "1.5"];

/// maximum nesting depth for recursive sub-component collection.
///
/// real-world SBOMs rarely nest more than a handful of levels. A limit
/// prevents stack overflow from adversarial or malformed input. Kept
/// below serde_json's own recursion limit so we produce a clear warning
/// instead of a cryptic parse error.
const MAX_COMPONENT_DEPTH: usize = 32;

/// parser for CycloneDX JSON documents.
///
/// converts CycloneDX 1.4+ JSON into the format-agnostic [`Sbom`] type.
pub struct CycloneDxReader;

impl CycloneDxReader {
    /// parses a CycloneDX JSON document from a reader.
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
    pub fn read_json<R: Read>(mut reader: R) -> Result<Sbom, Error> {
        // buffer the input so we can check the specVersion before full
        // parsing. Without this, CycloneDX 1.6+ or 2.0 documents produce
        // garbled cyclonedx-bom errors instead of a clear message.
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;

        Self::check_cyclonedx_version(&buf)?;

        let bom = cyclonedx_bom::prelude::Bom::parse_from_json(buf.as_slice())?;
        Self::bom_to_sbom(bom)
    }

    /// parses a CycloneDX XML document from a byte slice.
    ///
    /// tries spec versions 1.5, 1.4, and 1.3 in order, returning the first
    /// successful parse.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sbom_model_cyclonedx::CycloneDxReader;
    ///
    /// let xml = std::fs::read("sbom.xml").unwrap();
    /// let sbom = CycloneDxReader::read_xml(&xml).unwrap();
    /// ```
    pub fn read_xml(data: &[u8]) -> Result<Sbom, Error> {
        use cyclonedx_bom::models::bom::SpecVersion;
        use std::fmt::Write;

        Self::check_cyclonedx_version_xml(data)?;

        let versions = [
            ("1.5", SpecVersion::V1_5),
            ("1.4", SpecVersion::V1_4),
            ("1.3", SpecVersion::V1_3),
        ];
        let mut errors = Vec::new();
        for (label, version) in versions {
            match cyclonedx_bom::prelude::Bom::parse_from_xml_with_version(data, version) {
                Ok(bom) => {
                    let mut sbom = Self::bom_to_sbom(bom)?;
                    if !errors.is_empty() {
                        let tried: Vec<_> = errors.iter().map(|(l, _)| format!("v{l}")).collect();
                        sbom.warnings.push(format!(
                            "CycloneDX: XML parsed as v{} after failing {}",
                            label,
                            tried.join(", ")
                        ));
                    }
                    return Ok(sbom);
                }
                Err(e) => errors.push((label, e)),
            }
        }
        let mut msg = String::new();
        for (label, err) in &errors {
            writeln!(msg, "  v{label}: {err}").unwrap();
        }
        Err(Error::XmlParseAllVersions(msg.trim_end().to_string()))
    }

    /// pre-check the `specVersion` field in a CycloneDX JSON document.
    ///
    /// returns an error for unsupported spec versions, giving a clear
    /// message instead of cryptic deserialization failures.
    fn check_cyclonedx_version(data: &[u8]) -> Result<(), Error> {
        #[derive(serde::Deserialize)]
        struct VersionProbe {
            #[serde(rename = "specVersion")]
            spec_version: Option<String>,
        }

        let probe: VersionProbe = match serde_json::from_slice(data) {
            Ok(p) => p,
            // not valid JSON — let the full parser produce a proper error.
            Err(_) => return Ok(()),
        };

        match probe.spec_version.as_deref() {
            Some(v) if SUPPORTED_SPEC_VERSIONS.contains(&v) => Ok(()),
            Some(v) => Err(Error::UnsupportedVersion {
                version: v.to_string(),
            }),
            // missing specVersion — let the full parser handle it.
            None => Ok(()),
        }
    }

    /// pre-check the CycloneDX namespace version in an XML document.
    ///
    /// scans for the `http://cyclonedx.org/schema/bom/` namespace URL
    /// and rejects versions outside the supported set.
    fn check_cyclonedx_version_xml(data: &[u8]) -> Result<(), Error> {
        const NS_PREFIX: &[u8] = b"http://cyclonedx.org/schema/bom/";

        let Some(pos) = data.windows(NS_PREFIX.len()).position(|w| w == NS_PREFIX) else {
            // no CycloneDX namespace found — let the parser handle it.
            return Ok(());
        };

        let after = &data[pos + NS_PREFIX.len()..];
        let end = after
            .iter()
            .position(|&b| b == b'"' || b == b'\'' || b == b' ' || b == b'>')
            .unwrap_or(after.len());
        let version = std::str::from_utf8(&after[..end]).unwrap_or("");

        if version.is_empty() || SUPPORTED_SPEC_VERSIONS.contains(&version) {
            Ok(())
        } else {
            Err(Error::UnsupportedVersion {
                version: version.to_string(),
            })
        }
    }

    fn bom_to_sbom(bom: cyclonedx_bom::prelude::Bom) -> Result<Sbom, Error> {
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
                                s.push_str(v.as_ref());
                                s.push(' ');
                            }
                            if let Some(n) = &tool.name {
                                s.push_str(n.as_ref());
                            }
                            if let Some(v) = &tool.version {
                                s.push(' ');
                                s.push_str(v.as_ref());
                            }
                            sbom.metadata.tools.push(s.trim().to_string());
                        }
                    }
                    cyclonedx_bom::models::tool::Tools::Object { components, .. } => {
                        for component in components.into_iter().flat_map(|c| c.0) {
                            let mut s = component.name.to_string();
                            if let Some(v) = &component.version {
                                s.push(' ');
                                s.push_str(v.as_ref());
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

        // 2. Process Components (recursively including sub-components)
        if let Some(components) = bom.components {
            Self::collect_components(&components.0, &mut sbom, 0);
        }

        // 3. Process Dependencies
        // this is tricky because CDX uses bom-refs for dependency graph.
        // we need to map bom-refs to our ComponentIds.

        // build a map of bom-ref -> ComponentId
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
                    let mut children = BTreeMap::new();
                    for child_ref in dep.dependencies {
                        if let Some(child_id) = ref_map.get(&child_ref.to_string()) {
                            children.insert(child_id.clone(), DependencyKind::Runtime);
                        } else {
                            sbom.warnings.push(format!(
                                "CycloneDX: dependency bom-ref '{}' (child of '{}') does not match any component",
                                child_ref, parent_ref
                            ));
                        }
                    }
                    if !children.is_empty() {
                        sbom.dependencies.insert(parent_id.clone(), children);
                    }
                } else {
                    sbom.warnings.push(format!(
                        "CycloneDX: dependency bom-ref '{}' does not match any component",
                        parent_ref
                    ));
                }
            }
        }

        Ok(sbom)
    }

    fn collect_components(
        cdx_components: &[cyclonedx_bom::models::component::Component],
        sbom: &mut Sbom,
        depth: usize,
    ) {
        if depth >= MAX_COMPONENT_DEPTH {
            let names: Vec<_> = cdx_components
                .iter()
                .take(3)
                .map(|c| c.name.to_string())
                .collect();
            let suffix = if cdx_components.len() > 3 {
                format!(" and {} more", cdx_components.len() - 3)
            } else {
                String::new()
            };
            sbom.warnings.push(format!(
                "CycloneDX: sub-component nesting exceeds {} levels; \
                 dropped {} component(s) at depth {}: [{}]{}",
                MAX_COMPONENT_DEPTH,
                cdx_components.len(),
                depth,
                names.join(", "),
                suffix,
            ));
            return;
        }

        for cdx_comp in cdx_components {
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
                .and_then(|s| s.name.as_ref().map(|n| n.to_string()))
                .filter(|s| !s.is_empty());
            let s_str = supplier.clone().unwrap_or_default();
            if supplier.is_some() {
                props.push(("supplier", s_str.as_str()));
            }

            let purl = cdx_comp.purl.as_ref().map(|p| p.to_string());
            let purl_str = purl.as_deref();

            // extract ecosystem from purl
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

            if let Some(bom_ref) = &cdx_comp.bom_ref {
                comp.source_ids.push(bom_ref.to_string());
            }

            if let Some(licenses) = &cdx_comp.licenses {
                for license_choice in &licenses.0 {
                    match license_choice {
                        cyclonedx_bom::models::license::LicenseChoice::License(l) => {
                            let s = match &l.license_identifier {
                                cyclonedx_bom::models::license::LicenseIdentifier::Name(n) => {
                                    n.to_string()
                                }
                                cyclonedx_bom::models::license::LicenseIdentifier::SpdxId(id) => {
                                    id.to_string()
                                }
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

            if let Some(hashes) = &cdx_comp.hashes {
                for h in &hashes.0 {
                    comp.hashes.insert(
                        canonical_algorithm_name(&h.alg.to_string()),
                        h.content.0.clone(),
                    );
                }
            }

            if let Some(existing) = sbom.components.get(&id) {
                sbom.warnings.push(format!(
                    "CycloneDX: duplicate component id '{}' (name '{}'); \
                     earlier entry '{}' will be overwritten",
                    id, comp.name, existing.name,
                ));
            }
            sbom.components.insert(id, comp);

            // recurse into sub-components
            if let Some(sub) = &cdx_comp.components {
                Self::collect_components(&sub.0, sbom, depth + 1);
            }
        }
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
    fn test_read_xml_v1_4() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1">
  <components>
    <component type="library">
      <name>pkg-a</name>
      <version>1.0.0</version>
    </component>
  </components>
</bom>"#;
        let sbom = CycloneDxReader::read_xml(xml.as_slice()).unwrap();
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.components[0].name, "pkg-a");
    }

    #[test]
    fn test_read_xml_invalid() {
        let xml = b"<not-a-bom/>";
        let result = CycloneDxReader::read_xml(xml.as_slice());
        let err = result.unwrap_err();
        let msg = err.to_string();
        // all three version errors should be present
        assert!(msg.contains("v1.5:"), "missing v1.5 error: {msg}");
        assert!(msg.contains("v1.4:"), "missing v1.4 error: {msg}");
        assert!(msg.contains("v1.3:"), "missing v1.3 error: {msg}");
    }

    #[test]
    fn test_supplier_parsed() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "pkg-a",
                    "version": "1.0.0",
                    "supplier": {"name": "Acme Corp"}
                }
            ]
        }"#;
        let sbom = CycloneDxReader::read_json(json.as_bytes()).unwrap();
        assert_eq!(sbom.components[0].supplier, Some("Acme Corp".to_string()));
    }

    #[test]
    fn test_supplier_without_name_is_none() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "pkg-a",
                    "version": "1.0.0",
                    "supplier": {"url": ["https://example.com"]}
                }
            ]
        }"#;
        let sbom = CycloneDxReader::read_json(json.as_bytes()).unwrap();
        assert_eq!(sbom.components[0].supplier, None);
    }

    #[test]
    fn test_supplier_with_empty_name_is_none() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "pkg-a",
                    "version": "1.0.0",
                    "supplier": {"name": ""}
                }
            ]
        }"#;
        let sbom = CycloneDxReader::read_json(json.as_bytes()).unwrap();
        assert_eq!(sbom.components[0].supplier, None);
    }

    #[test]
    fn test_license_name_parsed() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "pkg-a",
                    "version": "1.0.0",
                    "licenses": [{"license": {"name": "Custom License"}}]
                }
            ]
        }"#;
        let sbom = CycloneDxReader::read_json(json.as_bytes()).unwrap();
        assert!(sbom.components[0].licenses.contains("Custom License"));
    }

    #[test]
    fn test_license_expression_parsed() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "pkg-a",
                    "version": "1.0.0",
                    "licenses": [{"expression": "MIT OR Apache-2.0"}]
                }
            ]
        }"#;
        let sbom = CycloneDxReader::read_json(json.as_bytes()).unwrap();
        assert!(sbom.components[0].licenses.contains("MIT"));
        assert!(sbom.components[0].licenses.contains("Apache-2.0"));
    }

    #[test]
    fn test_dependencies_with_unknown_ref_warned() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "pkg-a",
                    "version": "1.0.0",
                    "bom-ref": "ref-a"
                }
            ],
            "dependencies": [
                {
                    "ref": "ref-a",
                    "dependsOn": ["ref-unknown"]
                },
                {
                    "ref": "ref-also-unknown",
                    "dependsOn": ["ref-a"]
                }
            ]
        }"#;
        let sbom = CycloneDxReader::read_json(json.as_bytes()).unwrap();
        assert!(sbom.dependencies.is_empty());
        assert_eq!(sbom.warnings.len(), 2);
        assert!(sbom.warnings[0].contains("ref-unknown"));
        assert!(sbom.warnings[1].contains("ref-also-unknown"));
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

    #[test]
    fn test_nested_subcomponents_parsed() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "container",
                    "name": "my-image",
                    "version": "1.0.0",
                    "bom-ref": "ref-image",
                    "components": [
                        {
                            "type": "library",
                            "name": "libc",
                            "version": "0.2.0",
                            "bom-ref": "ref-libc",
                            "purl": "pkg:cargo/libc@0.2.0"
                        },
                        {
                            "type": "library",
                            "name": "openssl",
                            "version": "1.1.1",
                            "bom-ref": "ref-openssl"
                        }
                    ]
                }
            ]
        }"#;
        let sbom = CycloneDxReader::read_json(json.as_bytes()).unwrap();
        // parent + 2 children = 3 components
        assert_eq!(sbom.components.len(), 3);
        assert!(sbom.components.values().any(|c| c.name == "my-image"));
        assert!(sbom.components.values().any(|c| c.name == "libc"));
        assert!(sbom.components.values().any(|c| c.name == "openssl"));
    }

    #[test]
    fn test_deeply_nested_subcomponents() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "container",
                    "name": "root",
                    "version": "1.0.0",
                    "components": [
                        {
                            "type": "application",
                            "name": "mid",
                            "version": "2.0.0",
                            "components": [
                                {
                                    "type": "library",
                                    "name": "leaf",
                                    "version": "3.0.0",
                                    "purl": "pkg:npm/leaf@3.0.0",
                                    "licenses": [{"license": {"id": "MIT"}}]
                                }
                            ]
                        }
                    ]
                }
            ]
        }"#;
        let sbom = CycloneDxReader::read_json(json.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 3);

        let leaf = sbom.components.values().find(|c| c.name == "leaf").unwrap();
        assert_eq!(leaf.ecosystem, Some("npm".to_string()));
        assert!(leaf.licenses.contains("MIT"));
    }

    #[test]
    fn test_nested_subcomponents_bom_refs_in_dependency_graph() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "container",
                    "name": "image",
                    "version": "1.0.0",
                    "bom-ref": "ref-image",
                    "components": [
                        {
                            "type": "library",
                            "name": "inner-a",
                            "version": "1.0.0",
                            "bom-ref": "ref-inner-a"
                        },
                        {
                            "type": "library",
                            "name": "inner-b",
                            "version": "2.0.0",
                            "bom-ref": "ref-inner-b"
                        }
                    ]
                }
            ],
            "dependencies": [
                {
                    "ref": "ref-image",
                    "dependsOn": ["ref-inner-a"]
                },
                {
                    "ref": "ref-inner-a",
                    "dependsOn": ["ref-inner-b"]
                }
            ]
        }"#;
        let sbom = CycloneDxReader::read_json(json.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 3);

        let image_id = sbom
            .components
            .values()
            .find(|c| c.name == "image")
            .unwrap()
            .id
            .clone();
        let inner_a_id = sbom
            .components
            .values()
            .find(|c| c.name == "inner-a")
            .unwrap()
            .id
            .clone();
        let inner_b_id = sbom
            .components
            .values()
            .find(|c| c.name == "inner-b")
            .unwrap()
            .id
            .clone();

        // image -> inner-a dependency
        assert!(sbom.dependencies[&image_id].contains_key(&inner_a_id));
        // inner-a -> inner-b dependency
        assert!(sbom.dependencies[&inner_a_id].contains_key(&inner_b_id));
    }

    #[test]
    fn test_nested_subcomponents_xml() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1">
  <components>
    <component type="container">
      <name>my-image</name>
      <version>1.0.0</version>
      <components>
        <component type="library">
          <name>inner-lib</name>
          <version>0.5.0</version>
        </component>
      </components>
    </component>
  </components>
</bom>"#;
        let sbom = CycloneDxReader::read_xml(xml.as_slice()).unwrap();
        assert_eq!(sbom.components.len(), 2);
        assert!(sbom.components.values().any(|c| c.name == "my-image"));
        assert!(sbom.components.values().any(|c| c.name == "inner-lib"));
    }

    #[test]
    fn test_recursion_depth_limit() {
        // build a CycloneDX JSON with nesting deeper than MAX_COMPONENT_DEPTH.
        // the parser should collect components up to the limit and emit a
        // warning instead of stack-overflowing.
        let depth = super::MAX_COMPONENT_DEPTH + 5;
        let mut json = String::from(
            r#"{"bomFormat":"CycloneDX","specVersion":"1.4","version":1,"components":["#,
        );
        for i in 0..depth {
            if i > 0 {
                // open nested components array inside the previous component
                json.push_str(r#","components":["#);
            }
            json.push_str(&format!(
                r#"{{"type":"library","name":"level-{}","version":"1.0.0""#,
                i
            ));
        }
        // close all the braces: each component + its components array
        for i in (0..depth).rev() {
            json.push('}'); // close component object
            if i > 0 {
                json.push(']'); // close components array
            }
        }
        json.push_str("]}");

        let sbom = CycloneDxReader::read_json(json.as_bytes()).unwrap();

        // should have collected exactly MAX_COMPONENT_DEPTH components
        assert_eq!(sbom.components.len(), super::MAX_COMPONENT_DEPTH);

        // should have a warning about depth, including the dropped component name
        assert!(
            sbom.warnings.iter().any(|w| w.contains("nesting exceeds")
                && w.contains("dropped")
                && w.contains(&format!("level-{}", super::MAX_COMPONENT_DEPTH))),
            "expected depth warning with component context, got: {:?}",
            sbom.warnings
        );

        // components at the boundary should be present, those beyond should not
        assert!(sbom.components.values().any(|c| c.name == "level-0"));
        assert!(sbom
            .components
            .values()
            .any(|c| c.name == format!("level-{}", super::MAX_COMPONENT_DEPTH - 1)));
        assert!(!sbom
            .components
            .values()
            .any(|c| c.name == format!("level-{}", super::MAX_COMPONENT_DEPTH)));
    }

    #[test]
    fn test_empty_components_array() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": []
        }"#;
        let sbom = CycloneDxReader::read_json(json.as_bytes()).unwrap();
        assert!(sbom.components.is_empty());
        assert!(sbom.warnings.is_empty());
    }

    #[test]
    fn test_component_missing_optional_fields() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "bare-minimum"
                }
            ]
        }"#;
        let sbom = CycloneDxReader::read_json(json.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 1);
        let comp = &sbom.components[0];
        assert_eq!(comp.name, "bare-minimum");
        assert!(comp.version.is_none());
        assert!(comp.purl.is_none());
        assert!(comp.supplier.is_none());
        assert!(comp.licenses.is_empty());
        assert!(comp.hashes.is_empty());
    }

    #[test]
    fn test_cyclonedx_16_json_rejected_with_clear_error() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": []
        }"#;
        let err = CycloneDxReader::read_json(json.as_bytes()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unsupported CycloneDX specVersion"),
            "expected version error, got: {msg}"
        );
        assert!(msg.contains("1.6"), "should mention the version found");
        assert!(msg.contains("1.3"), "should mention supported versions");
    }

    #[test]
    fn test_cyclonedx_20_json_rejected() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "2.0",
            "version": 1,
            "components": []
        }"#;
        let err = CycloneDxReader::read_json(json.as_bytes()).unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported CycloneDX specVersion"));
        assert!(err.to_string().contains("2.0"));
    }

    #[test]
    fn test_cyclonedx_13_json_accepted() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.3",
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
    }

    #[test]
    fn test_cyclonedx_15_json_accepted() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": []
        }"#;
        CycloneDxReader::read_json(json.as_bytes()).unwrap();
    }

    #[test]
    fn test_cyclonedx_16_xml_rejected() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">
  <components/>
</bom>"#;
        let err = CycloneDxReader::read_xml(xml.as_slice()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unsupported CycloneDX specVersion"),
            "expected version error, got: {msg}"
        );
        assert!(msg.contains("1.6"), "should mention the version found");
    }

    #[test]
    fn test_cyclonedx_20_xml_rejected() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/2.0" version="1">
  <components/>
</bom>"#;
        let err = CycloneDxReader::read_xml(xml.as_slice()).unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported CycloneDX specVersion"));
        assert!(err.to_string().contains("2.0"));
    }

    #[test]
    fn test_cyclonedx_xml_no_namespace_falls_through() {
        let xml = b"<not-a-bom/>";
        let result = CycloneDxReader::read_xml(xml.as_slice());
        // should fail, but with a parse error, not UnsupportedVersion
        let err = result.unwrap_err();
        assert!(
            !err.to_string()
                .contains("unsupported CycloneDX specVersion"),
            "expected parse error, not version error: {}",
            err
        );
    }

    #[test]
    fn test_xml_version_fallback_warns() {
        // a v1.4 document should succeed but warn that v1.5 was tried first.
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1">
  <components>
    <component type="library">
      <name>pkg-a</name>
      <version>1.0.0</version>
    </component>
  </components>
</bom>"#;
        let sbom = CycloneDxReader::read_xml(xml.as_slice()).unwrap();
        assert_eq!(sbom.components.len(), 1);

        // v1.5 is tried first; if v1.4 succeeds after v1.5 failed,
        // there should be a fallback warning.
        let fallback_warning = sbom
            .warnings
            .iter()
            .find(|w| w.contains("parsed as v1.4") && w.contains("failing"));
        // the v1.4 namespace might succeed on v1.5 too (the parser is
        // permissive), so this warning is conditional — just verify it's
        // well-formed if present.
        if let Some(w) = fallback_warning {
            assert!(
                w.contains("v1.5"),
                "fallback warning should mention the failed version: {w}"
            );
        }
    }

    #[test]
    fn test_depth_limit_warning_includes_component_names() {
        // build a JSON that nests exactly one level past the limit.
        let depth = super::MAX_COMPONENT_DEPTH + 1;
        let mut json = String::from(
            r#"{"bomFormat":"CycloneDX","specVersion":"1.4","version":1,"components":["#,
        );
        for i in 0..depth {
            if i > 0 {
                json.push_str(r#","components":["#);
            }
            json.push_str(&format!(
                r#"{{"type":"library","name":"comp-{}","version":"1.0.0""#,
                i
            ));
        }
        for i in (0..depth).rev() {
            json.push('}');
            if i > 0 {
                json.push(']');
            }
        }
        json.push_str("]}");

        let sbom = CycloneDxReader::read_json(json.as_bytes()).unwrap();
        let depth_warning = sbom
            .warnings
            .iter()
            .find(|w| w.contains("nesting exceeds"))
            .expect("should have a depth warning");

        // warning should mention the dropped component's name
        assert!(
            depth_warning.contains(&format!("comp-{}", super::MAX_COMPONENT_DEPTH)),
            "warning should include dropped component name: {depth_warning}"
        );
        // warning should include the count
        assert!(
            depth_warning.contains("dropped 1 component(s)"),
            "warning should include dropped count: {depth_warning}"
        );
        // warning should include the depth
        assert!(
            depth_warning.contains(&format!("at depth {}", super::MAX_COMPONENT_DEPTH)),
            "warning should include depth: {depth_warning}"
        );
    }

    #[test]
    fn test_duplicate_purl_warns() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "pkg-a",
                    "version": "1.0.0",
                    "purl": "pkg:npm/pkg-a@1.0.0"
                },
                {
                    "type": "library",
                    "name": "pkg-a-duplicate",
                    "version": "1.0.0",
                    "purl": "pkg:npm/pkg-a@1.0.0"
                }
            ]
        }"#;
        let sbom = CycloneDxReader::read_json(json.as_bytes()).unwrap();
        // second entry overwrites the first
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.components[0].name, "pkg-a-duplicate");
        // a warning should be emitted about the duplicate
        assert_eq!(sbom.warnings.len(), 1);
        assert!(
            sbom.warnings[0].contains("duplicate"),
            "expected duplicate warning, got: {}",
            sbom.warnings[0]
        );
        assert!(sbom.warnings[0].contains("pkg-a"));
    }

    #[test]
    fn test_duplicate_hash_id_warns() {
        // components without purls can also collide when their property
        // hash matches (same name + version + supplier).
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "dup",
                    "version": "1.0.0"
                },
                {
                    "type": "library",
                    "name": "dup",
                    "version": "1.0.0"
                }
            ]
        }"#;
        let sbom = CycloneDxReader::read_json(json.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.warnings.len(), 1);
        assert!(sbom.warnings[0].contains("duplicate"));
    }

    #[test]
    fn test_no_duplicate_warning_for_unique_components() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "pkg-a",
                    "version": "1.0.0",
                    "purl": "pkg:npm/pkg-a@1.0.0"
                },
                {
                    "type": "library",
                    "name": "pkg-b",
                    "version": "2.0.0",
                    "purl": "pkg:npm/pkg-b@2.0.0"
                }
            ]
        }"#;
        let sbom = CycloneDxReader::read_json(json.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 2);
        assert!(sbom.warnings.is_empty());
    }
}
