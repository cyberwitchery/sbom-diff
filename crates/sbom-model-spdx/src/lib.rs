#![doc = include_str!("../readme.md")]

use sbom_model::{
    canonical_algorithm_name, parse_license_expression, Component, ComponentId, Sbom,
};
use spdx_rs::models::RelationshipType;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use thiserror::Error;

/// Errors that can occur when parsing SPDX documents.
#[derive(Error, Debug)]
pub enum Error {
    /// The JSON structure doesn't match the SPDX schema.
    #[error("SPDX parse error: {0}")]
    Parse(#[from] serde_json::Error),
    /// An I/O error occurred while reading the input.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// The SPDX document version is not supported.
    #[error("unsupported SPDX version '{version}': only SPDX 2.x is supported (e.g. SPDX-2.3)")]
    UnsupportedVersion {
        /// The version string found in the document.
        version: String,
    },
}

/// Edge direction for a dependency relationship.
enum Direction {
    /// The left element depends on the right (left → right).
    Forward,
    /// The right element depends on the left (right → left).
    Inverse,
}

/// Classifies an SPDX relationship type into a dependency edge direction.
///
/// Returns `Some(Direction::Forward)` for types where `spdx_element_id`
/// depends on `related_spdx_element` (e.g. DEPENDS_ON, CONTAINS).
///
/// Returns `Some(Direction::Inverse)` for types where `related_spdx_element`
/// depends on `spdx_element_id` (e.g. DEPENDENCY_OF, CONTAINED_BY).
///
/// Returns `None` for relationship types that don't represent dependency edges
/// (e.g. BUILD_TOOL_OF, GENERATED_FROM).
fn dependency_direction(rel_type: &RelationshipType) -> Option<Direction> {
    match rel_type {
        // Forward: A {verb} B means A depends on / contains B.
        RelationshipType::DependsOn
        | RelationshipType::Contains
        | RelationshipType::Describes
        | RelationshipType::HasPrerequisite => Some(Direction::Forward),

        // Inverse: A {verb} B means B depends on / contains A.
        RelationshipType::DependencyOf
        | RelationshipType::ContainedBy
        | RelationshipType::DescribedBy
        | RelationshipType::PrerequisiteFor
        | RelationshipType::RuntimeDependencyOf
        | RelationshipType::DevDependencyOf
        | RelationshipType::BuildDependencyOf
        | RelationshipType::OptionalDependencyOf
        | RelationshipType::ProvidedDependencyOf
        | RelationshipType::TestDependencyOf => Some(Direction::Inverse),

        // Not a dependency relationship — ignore.
        _ => None,
    }
}

/// Parser for SPDX JSON documents.
///
/// Converts SPDX 2.3 JSON into the format-agnostic [`Sbom`] type.
pub struct SpdxReader;

impl SpdxReader {
    /// Parses an SPDX JSON document from a reader.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sbom_model_spdx::SpdxReader;
    /// use std::fs::File;
    ///
    /// let file = File::open("sbom.spdx.json").unwrap();
    /// let sbom = SpdxReader::read_json(file).unwrap();
    /// ```
    pub fn read_json<R: Read>(mut reader: R) -> Result<Sbom, Error> {
        // Buffer the input so we can check the SPDX version before full
        // parsing. Without this, SPDX 3.0 documents would either produce
        // garbled output or an inscrutable deserialization error.
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;

        Self::check_spdx_version(&buf)?;

        let spdx_doc: spdx_rs::models::SPDX = serde_json::from_slice(&buf)?;

        let mut sbom = Sbom::default();

        // 1. Metadata
        let ci = spdx_doc.document_creation_information.creation_info;
        sbom.metadata.timestamp = Some(ci.created.to_string());
        for creator in ci.creators {
            if let Some(stripped) = creator.strip_prefix("Tool: ") {
                sbom.metadata.tools.push(stripped.to_string());
            } else {
                sbom.metadata.authors.push(creator);
            }
        }

        // 2. Components (Packages)
        for pkg in spdx_doc.package_information {
            let name = pkg.package_name;
            let version = pkg.package_version;

            let mut props = vec![("name", name.as_str())];
            if let Some(ref v) = version {
                props.push(("version", v.as_str()));
            }

            let supplier = pkg.package_supplier.clone().map(|s| {
                s.strip_prefix("Organization: ")
                    .or_else(|| s.strip_prefix("Person: "))
                    .map(|stripped| stripped.to_string())
                    .unwrap_or(s)
            });
            if let Some(ref s) = supplier {
                props.push(("supplier", s.as_str()));
            }

            // Purl handling
            let mut purl = None;
            for r in &pkg.external_reference {
                if r.reference_type == "purl" {
                    purl = Some(r.reference_locator.clone());
                    break;
                }
            }
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
                description: pkg
                    .package_detailed_description
                    .clone()
                    .or_else(|| pkg.package_summary_description.clone()),
                purl,
                licenses: BTreeSet::new(),
                hashes: BTreeMap::new(),
                source_ids: vec![pkg.package_spdx_identifier.clone()],
            };

            // Licenses: prefer concludedLicense, fall back to declaredLicense
            // when concluded is absent or NOASSERTION/NONE (common in
            // automated tooling output from syft, trivy, etc.).
            let license_expr = pkg
                .concluded_license
                .as_ref()
                .filter(|l| {
                    let s = l.to_string();
                    s != "NOASSERTION" && s != "NONE"
                })
                .or(pkg.declared_license.as_ref().filter(|l| {
                    let s = l.to_string();
                    s != "NOASSERTION" && s != "NONE"
                }));
            if let Some(l) = license_expr {
                comp.licenses
                    .extend(parse_license_expression(&l.to_string()));
            }

            // Hashes
            for checksum in pkg.package_checksum {
                comp.hashes.insert(
                    canonical_algorithm_name(&format!("{:?}", checksum.algorithm)),
                    checksum.value,
                );
            }

            sbom.components.insert(id, comp);
        }

        // 3. Relationships
        // Map SPDX IDs -> ComponentId
        let mut ref_map = BTreeMap::new();
        for (id, comp) in &sbom.components {
            for src_id in &comp.source_ids {
                ref_map.insert(src_id.clone(), id.clone());
            }
        }

        let doc_spdx_id = spdx_doc
            .document_creation_information
            .spdx_identifier
            .clone();

        for rel in spdx_doc.relationships {
            let left_spdx = rel.spdx_element_id;
            let right_spdx = rel.related_spdx_element;
            let rel_type = rel.relationship_type;

            // Determine the edge direction for this relationship type.
            // Forward: left depends on right (left → right edge).
            // Inverse: right depends on left (right → left edge).
            let (parent_spdx, child_spdx) = match dependency_direction(&rel_type) {
                Some(Direction::Forward) => (&left_spdx, &right_spdx),
                Some(Direction::Inverse) => (&right_spdx, &left_spdx),
                None => continue,
            };

            // Skip relationships involving the document element itself
            // (e.g. SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package). The
            // document element is not a package so it will never appear
            // in ref_map, and warning about it is a false positive.
            if *parent_spdx == doc_spdx_id || *child_spdx == doc_spdx_id {
                continue;
            }

            let parent_id = ref_map.get(parent_spdx);
            let child_id = ref_map.get(child_spdx);

            match (parent_id, child_id) {
                (Some(pid), Some(cid)) => {
                    sbom.dependencies
                        .entry(pid.clone())
                        .or_default()
                        .insert(cid.clone());
                }
                (None, _) => {
                    sbom.warnings.push(format!(
                        "SPDX: relationship source '{}' does not match any package",
                        parent_spdx
                    ));
                }
                (_, None) => {
                    sbom.warnings.push(format!(
                        "SPDX: relationship target '{}' (from '{}') does not match any package",
                        child_spdx, parent_spdx
                    ));
                }
            }
        }

        Ok(sbom)
    }

    /// Pre-check the `spdxVersion` field before full parsing.
    ///
    /// Returns an error for SPDX 3.x or any other unsupported spec version,
    /// giving a clear message instead of cryptic deserialization failures.
    fn check_spdx_version(data: &[u8]) -> Result<(), Error> {
        #[derive(serde::Deserialize)]
        struct VersionProbe {
            #[serde(rename = "spdxVersion")]
            spdx_version: Option<String>,
        }

        let probe: VersionProbe = serde_json::from_slice(data)?;

        match probe.spdx_version.as_deref() {
            Some(v) if v.starts_with("SPDX-2.") => Ok(()),
            Some(v) => Err(Error::UnsupportedVersion {
                version: v.to_string(),
            }),
            // Missing version field — let the full parser produce its own
            // error; the document is malformed either way.
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_minimal_json() {
        let json = r#"{
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://spdx.org/spdxdocs/test",
            "creationInfo": {
                "creators": ["Tool: manual"],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [
                {
                    "name": "pkg-a",
                    "SPDXID": "SPDXRef-pkg-a",
                    "downloadLocation": "NONE"
                }
            ],
            "relationships": []
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.components[0].name, "pkg-a");
    }

    #[test]
    fn test_read_complex_json() {
        let json = r#"{
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://spdx.org/spdxdocs/test",
            "creationInfo": {
                "creators": ["Tool: manual", "Person: bob"],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [
                {
                    "name": "pkg-a",
                    "SPDXID": "SPDXRef-pkg-a",
                    "downloadLocation": "NONE",
                    "licenseConcluded": "MIT",
                    "checksums": [{"algorithm": "SHA256", "checksumValue": "abc"}]
                },
                {
                    "name": "pkg-b",
                    "SPDXID": "SPDXRef-pkg-b",
                    "downloadLocation": "NONE"
                }
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-pkg-a",
                    "relatedSpdxElement": "SPDXRef-pkg-b",
                    "relationshipType": "DEPENDS_ON"
                }
            ]
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 2);
        assert_eq!(sbom.metadata.authors, vec!["Person: bob"]);
        assert_eq!(sbom.metadata.tools, vec!["manual"]);
    }

    #[test]
    fn test_hash_algorithm_canonical_names() {
        let json = r#"{
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://spdx.org/spdxdocs/test",
            "creationInfo": {
                "creators": ["Tool: manual"],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [
                {
                    "name": "pkg-a",
                    "SPDXID": "SPDXRef-pkg-a",
                    "downloadLocation": "NONE",
                    "checksums": [
                        {"algorithm": "SHA256", "checksumValue": "aaa"},
                        {"algorithm": "SHA1", "checksumValue": "bbb"},
                        {"algorithm": "MD5", "checksumValue": "ccc"},
                        {"algorithm": "SHA3-256", "checksumValue": "ddd"}
                    ]
                }
            ],
            "relationships": []
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();
        let hashes = &sbom.components[0].hashes;
        assert_eq!(hashes.get("SHA-256").unwrap(), "aaa");
        assert_eq!(hashes.get("SHA-1").unwrap(), "bbb");
        assert_eq!(hashes.get("MD5").unwrap(), "ccc");
        assert_eq!(hashes.get("SHA3-256").unwrap(), "ddd");
    }

    #[test]
    fn test_supplier_parsed() {
        let json = r#"{
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://spdx.org/spdxdocs/test",
            "creationInfo": {
                "creators": ["Tool: manual"],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [
                {
                    "name": "pkg-a",
                    "SPDXID": "SPDXRef-pkg-a",
                    "downloadLocation": "NONE",
                    "supplier": "Organization: Acme Corp"
                }
            ],
            "relationships": []
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();
        assert_eq!(sbom.components[0].supplier, Some("Acme Corp".to_string()));
    }

    #[test]
    fn test_description_parsed() {
        let json = r#"{
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://spdx.org/spdxdocs/test",
            "creationInfo": {
                "creators": ["Tool: manual"],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [
                {
                    "name": "detailed-pkg",
                    "SPDXID": "SPDXRef-detailed",
                    "downloadLocation": "NONE",
                    "description": "A detailed description",
                    "summary": "A summary"
                },
                {
                    "name": "summary-only-pkg",
                    "SPDXID": "SPDXRef-summary",
                    "downloadLocation": "NONE",
                    "summary": "Only a summary"
                },
                {
                    "name": "no-desc-pkg",
                    "SPDXID": "SPDXRef-nodesc",
                    "downloadLocation": "NONE"
                }
            ],
            "relationships": []
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();

        let detailed = sbom
            .components
            .values()
            .find(|c| c.name == "detailed-pkg")
            .unwrap();
        assert_eq!(
            detailed.description,
            Some("A detailed description".to_string())
        );

        let summary_only = sbom
            .components
            .values()
            .find(|c| c.name == "summary-only-pkg")
            .unwrap();
        assert_eq!(summary_only.description, Some("Only a summary".to_string()));

        let no_desc = sbom
            .components
            .values()
            .find(|c| c.name == "no-desc-pkg")
            .unwrap();
        assert_eq!(no_desc.description, None);
    }

    #[test]
    fn test_unknown_relationship_type_ignored() {
        let json = r#"{
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://spdx.org/spdxdocs/test",
            "creationInfo": {
                "creators": ["Tool: manual"],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [
                {
                    "name": "pkg-a",
                    "SPDXID": "SPDXRef-pkg-a",
                    "downloadLocation": "NONE"
                },
                {
                    "name": "pkg-b",
                    "SPDXID": "SPDXRef-pkg-b",
                    "downloadLocation": "NONE"
                }
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-pkg-a",
                    "relatedSpdxElement": "SPDXRef-pkg-b",
                    "relationshipType": "BUILD_TOOL_OF"
                }
            ]
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();
        assert!(sbom.dependencies.is_empty());
    }

    #[test]
    fn test_relationship_with_unknown_spdxid_warned() {
        let json = r#"{
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://spdx.org/spdxdocs/test",
            "creationInfo": {
                "creators": ["Tool: manual"],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [
                {
                    "name": "pkg-a",
                    "SPDXID": "SPDXRef-pkg-a",
                    "downloadLocation": "NONE"
                }
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-pkg-a",
                    "relatedSpdxElement": "SPDXRef-unknown",
                    "relationshipType": "DEPENDS_ON"
                }
            ]
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();
        assert!(sbom.dependencies.is_empty());
        assert_eq!(sbom.warnings.len(), 1);
        assert!(sbom.warnings[0].contains("SPDXRef-unknown"));
    }

    #[test]
    fn test_relationship_with_unknown_source_warned() {
        let json = r#"{
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://spdx.org/spdxdocs/test",
            "creationInfo": {
                "creators": ["Tool: manual"],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [
                {
                    "name": "pkg-a",
                    "SPDXID": "SPDXRef-pkg-a",
                    "downloadLocation": "NONE"
                }
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-unknown-parent",
                    "relatedSpdxElement": "SPDXRef-pkg-a",
                    "relationshipType": "DEPENDS_ON"
                }
            ]
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();
        assert!(sbom.dependencies.is_empty());
        assert_eq!(sbom.warnings.len(), 1);
        assert!(sbom.warnings[0].contains("SPDXRef-unknown-parent"));
    }

    #[test]
    fn test_noassertion_license_filtered() {
        let json = r#"{
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://spdx.org/spdxdocs/test",
            "creationInfo": {
                "creators": ["Tool: manual"],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [
                {
                    "name": "pkg-a",
                    "SPDXID": "SPDXRef-pkg-a",
                    "downloadLocation": "NONE",
                    "licenseConcluded": "NOASSERTION"
                }
            ],
            "relationships": []
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();
        assert!(sbom.components[0].licenses.is_empty());
    }

    #[test]
    fn test_ecosystem_extracted_from_purl() {
        let json = r#"{
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://spdx.org/spdxdocs/test",
            "creationInfo": {
                "creators": ["Tool: manual"],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [
                {
                    "name": "lodash",
                    "SPDXID": "SPDXRef-lodash",
                    "versionInfo": "4.17.21",
                    "downloadLocation": "NONE",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:npm/lodash@4.17.21"
                        }
                    ]
                },
                {
                    "name": "no-purl-pkg",
                    "SPDXID": "SPDXRef-no-purl",
                    "downloadLocation": "NONE"
                }
            ],
            "relationships": []
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();

        let lodash = sbom
            .components
            .values()
            .find(|c| c.name == "lodash")
            .unwrap();
        assert_eq!(lodash.ecosystem, Some("npm".to_string()));

        let no_purl = sbom
            .components
            .values()
            .find(|c| c.name == "no-purl-pkg")
            .unwrap();
        assert_eq!(no_purl.ecosystem, None);
    }

    #[test]
    fn test_package_without_version() {
        let json = r#"{
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://spdx.org/spdxdocs/test",
            "creationInfo": {
                "creators": ["Tool: manual"],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [
                {
                    "name": "no-version-pkg",
                    "SPDXID": "SPDXRef-no-version",
                    "downloadLocation": "NONE"
                },
                {
                    "name": "versioned-pkg",
                    "SPDXID": "SPDXRef-versioned",
                    "versionInfo": "2.0.0",
                    "downloadLocation": "NONE"
                }
            ],
            "relationships": []
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 2);

        let no_ver = sbom
            .components
            .values()
            .find(|c| c.name == "no-version-pkg")
            .unwrap();
        assert_eq!(no_ver.version, None);

        let has_ver = sbom
            .components
            .values()
            .find(|c| c.name == "versioned-pkg")
            .unwrap();
        assert_eq!(has_ver.version, Some("2.0.0".to_string()));
    }

    #[test]
    fn test_contains_and_describes_relationships() {
        let json = r#"{
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://spdx.org/spdxdocs/test",
            "creationInfo": {
                "creators": ["Tool: manual"],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [
                {
                    "name": "container",
                    "SPDXID": "SPDXRef-container",
                    "downloadLocation": "NONE"
                },
                {
                    "name": "contained",
                    "SPDXID": "SPDXRef-contained",
                    "downloadLocation": "NONE"
                },
                {
                    "name": "described",
                    "SPDXID": "SPDXRef-described",
                    "downloadLocation": "NONE"
                },
                {
                    "name": "generated-from",
                    "SPDXID": "SPDXRef-generated",
                    "downloadLocation": "NONE"
                }
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-container",
                    "relatedSpdxElement": "SPDXRef-contained",
                    "relationshipType": "CONTAINS"
                },
                {
                    "spdxElementId": "SPDXRef-container",
                    "relatedSpdxElement": "SPDXRef-described",
                    "relationshipType": "DESCRIBES"
                },
                {
                    "spdxElementId": "SPDXRef-container",
                    "relatedSpdxElement": "SPDXRef-generated",
                    "relationshipType": "GENERATED_FROM"
                }
            ]
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();

        let container_id = sbom
            .components
            .values()
            .find(|c| c.name == "container")
            .unwrap()
            .id
            .clone();

        let deps = &sbom.dependencies[&container_id];
        assert_eq!(deps.len(), 2);

        let dep_names: BTreeSet<_> = deps
            .iter()
            .map(|id| sbom.components[id].name.as_str())
            .collect();
        assert!(dep_names.contains("contained"));
        assert!(dep_names.contains("described"));
        assert!(!dep_names.contains("generated-from"));
    }

    #[test]
    fn test_empty_dependency_graph() {
        let json = r#"{
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://spdx.org/spdxdocs/test",
            "creationInfo": {
                "creators": ["Tool: manual"],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [
                {
                    "name": "a",
                    "SPDXID": "SPDXRef-a",
                    "downloadLocation": "NONE"
                },
                {
                    "name": "b",
                    "SPDXID": "SPDXRef-b",
                    "downloadLocation": "NONE"
                }
            ],
            "relationships": []
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 2);
        assert!(sbom.dependencies.is_empty());
        assert_eq!(sbom.roots().len(), 2);
    }

    #[test]
    fn test_document_with_no_packages() {
        let json = r#"{
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "empty-sbom",
            "documentNamespace": "http://spdx.org/spdxdocs/empty",
            "creationInfo": {
                "creators": ["Tool: manual"],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [],
            "relationships": []
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();
        assert!(sbom.components.is_empty());
        assert!(sbom.dependencies.is_empty());
        assert_eq!(sbom.metadata.tools, vec!["manual"]);
    }

    #[test]
    fn test_tool_and_organization_creator_strings() {
        let json = r#"{
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://spdx.org/spdxdocs/test",
            "creationInfo": {
                "creators": [
                    "Tool: syft-0.100.0",
                    "Tool: trivy",
                    "Organization: Acme Corp",
                    "Person: alice"
                ],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [],
            "relationships": []
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();
        assert_eq!(sbom.metadata.tools, vec!["syft-0.100.0", "trivy"]);
        assert_eq!(
            sbom.metadata.authors,
            vec!["Organization: Acme Corp", "Person: alice"]
        );
    }

    #[test]
    fn test_document_describes_no_false_positive_warning() {
        let json = r#"{
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://spdx.org/spdxdocs/test",
            "creationInfo": {
                "creators": ["Tool: manual"],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [
                {
                    "name": "pkg-a",
                    "SPDXID": "SPDXRef-pkg-a",
                    "downloadLocation": "NONE"
                }
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relatedSpdxElement": "SPDXRef-pkg-a",
                    "relationshipType": "DESCRIBES"
                }
            ]
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();
        assert!(sbom.warnings.is_empty());
        assert!(sbom.dependencies.is_empty());
    }

    #[test]
    fn test_declared_license_fallback() {
        let json = r#"{
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://spdx.org/spdxdocs/test",
            "creationInfo": {
                "creators": ["Tool: manual"],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [
                {
                    "name": "concluded-noassertion",
                    "SPDXID": "SPDXRef-a",
                    "downloadLocation": "NONE",
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "MIT"
                },
                {
                    "name": "concluded-none",
                    "SPDXID": "SPDXRef-b",
                    "downloadLocation": "NONE",
                    "licenseConcluded": "NONE",
                    "licenseDeclared": "Apache-2.0"
                },
                {
                    "name": "both-noassertion",
                    "SPDXID": "SPDXRef-c",
                    "downloadLocation": "NONE",
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION"
                },
                {
                    "name": "concluded-present",
                    "SPDXID": "SPDXRef-d",
                    "downloadLocation": "NONE",
                    "licenseConcluded": "GPL-3.0-only",
                    "licenseDeclared": "MIT"
                },
                {
                    "name": "no-license-fields",
                    "SPDXID": "SPDXRef-e",
                    "downloadLocation": "NONE"
                }
            ],
            "relationships": []
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();

        let find = |name: &str| sbom.components.values().find(|c| c.name == name).unwrap();

        // NOASSERTION concluded -> falls back to declared MIT
        assert!(find("concluded-noassertion").licenses.contains("MIT"));

        // NONE concluded -> falls back to declared Apache-2.0
        assert!(find("concluded-none").licenses.contains("Apache-2.0"));

        // Both NOASSERTION -> no licenses
        assert!(find("both-noassertion").licenses.is_empty());

        // Valid concluded -> uses concluded, ignores declared
        assert!(find("concluded-present").licenses.contains("GPL-3.0"));
        assert!(!find("concluded-present").licenses.contains("MIT"));

        // No license fields at all -> empty
        assert!(find("no-license-fields").licenses.is_empty());
    }

    #[test]
    fn test_spdx_3_rejected_with_clear_error() {
        let json = r#"{
            "spdxVersion": "SPDX-3.0",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://spdx.org/spdxdocs/test",
            "creationInfo": {
                "creators": ["Tool: test"],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [],
            "relationships": []
        }"#;
        let err = SpdxReader::read_json(json.as_bytes()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unsupported SPDX version"),
            "expected version error, got: {msg}"
        );
        assert!(msg.contains("SPDX-3.0"), "should mention the version found");
        assert!(
            msg.contains("SPDX 2.x"),
            "should mention supported versions"
        );
    }

    #[test]
    fn test_spdx_unknown_future_version_rejected() {
        let json = r#"{
            "spdxVersion": "SPDX-4.0",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://spdx.org/spdxdocs/test",
            "creationInfo": {
                "creators": ["Tool: test"],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [],
            "relationships": []
        }"#;
        let err = SpdxReader::read_json(json.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("unsupported SPDX version"));
    }

    #[test]
    fn test_spdx_22_accepted() {
        let json = r#"{
            "spdxVersion": "SPDX-2.2",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://spdx.org/spdxdocs/test",
            "creationInfo": {
                "creators": ["Tool: test"],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [
                {
                    "name": "pkg-a",
                    "SPDXID": "SPDXRef-pkg-a",
                    "downloadLocation": "NONE"
                }
            ],
            "relationships": []
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 1);
    }

    #[test]
    fn test_empty_packages_array() {
        let json = r#"{
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://spdx.org/spdxdocs/test",
            "creationInfo": {
                "creators": ["Tool: test"],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [],
            "relationships": []
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();
        assert!(sbom.components.is_empty());
        assert!(sbom.warnings.is_empty());
    }

    #[test]
    fn test_inverse_dependency_of_relationship() {
        // "A DEPENDENCY_OF B" means B depends on A → edge from B to A.
        let json = r#"{
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://spdx.org/spdxdocs/test",
            "creationInfo": {
                "creators": ["Tool: manual"],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [
                {
                    "name": "lib-a",
                    "SPDXID": "SPDXRef-lib-a",
                    "downloadLocation": "NONE"
                },
                {
                    "name": "app-b",
                    "SPDXID": "SPDXRef-app-b",
                    "downloadLocation": "NONE"
                }
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-lib-a",
                    "relatedSpdxElement": "SPDXRef-app-b",
                    "relationshipType": "DEPENDENCY_OF"
                }
            ]
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();
        assert!(sbom.warnings.is_empty());

        // The edge should go from app-b → lib-a (app-b depends on lib-a).
        let app_id = sbom
            .components
            .values()
            .find(|c| c.name == "app-b")
            .unwrap()
            .id
            .clone();
        let lib_id = sbom
            .components
            .values()
            .find(|c| c.name == "lib-a")
            .unwrap()
            .id
            .clone();

        let deps = &sbom.dependencies[&app_id];
        assert!(deps.contains(&lib_id));
        // lib-a should NOT have app-b as a dependency.
        assert!(!sbom.dependencies.contains_key(&lib_id));
    }

    #[test]
    fn test_inverse_contained_by_relationship() {
        // "A CONTAINED_BY B" means B contains A → edge from B to A.
        let json = r#"{
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://spdx.org/spdxdocs/test",
            "creationInfo": {
                "creators": ["Tool: manual"],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [
                {
                    "name": "child",
                    "SPDXID": "SPDXRef-child",
                    "downloadLocation": "NONE"
                },
                {
                    "name": "parent",
                    "SPDXID": "SPDXRef-parent",
                    "downloadLocation": "NONE"
                }
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-child",
                    "relatedSpdxElement": "SPDXRef-parent",
                    "relationshipType": "CONTAINED_BY"
                }
            ]
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();
        assert!(sbom.warnings.is_empty());

        let parent_id = sbom
            .components
            .values()
            .find(|c| c.name == "parent")
            .unwrap()
            .id
            .clone();
        let child_id = sbom
            .components
            .values()
            .find(|c| c.name == "child")
            .unwrap()
            .id
            .clone();

        let deps = &sbom.dependencies[&parent_id];
        assert!(deps.contains(&child_id));
    }

    #[test]
    fn test_scoped_dependency_of_types() {
        // Scoped types like RUNTIME_DEPENDENCY_OF are inverse: "A is a
        // runtime dep of B" means B depends on A.
        let json = r#"{
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://spdx.org/spdxdocs/test",
            "creationInfo": {
                "creators": ["Tool: manual"],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [
                {
                    "name": "runtime-lib",
                    "SPDXID": "SPDXRef-runtime-lib",
                    "downloadLocation": "NONE"
                },
                {
                    "name": "dev-lib",
                    "SPDXID": "SPDXRef-dev-lib",
                    "downloadLocation": "NONE"
                },
                {
                    "name": "app",
                    "SPDXID": "SPDXRef-app",
                    "downloadLocation": "NONE"
                }
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-runtime-lib",
                    "relatedSpdxElement": "SPDXRef-app",
                    "relationshipType": "RUNTIME_DEPENDENCY_OF"
                },
                {
                    "spdxElementId": "SPDXRef-dev-lib",
                    "relatedSpdxElement": "SPDXRef-app",
                    "relationshipType": "DEV_DEPENDENCY_OF"
                }
            ]
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();
        assert!(sbom.warnings.is_empty());

        let app_id = sbom
            .components
            .values()
            .find(|c| c.name == "app")
            .unwrap()
            .id
            .clone();

        let deps = &sbom.dependencies[&app_id];
        assert_eq!(deps.len(), 2);

        let dep_names: BTreeSet<_> = deps
            .iter()
            .map(|id| sbom.components[id].name.as_str())
            .collect();
        assert!(dep_names.contains("runtime-lib"));
        assert!(dep_names.contains("dev-lib"));
    }

    #[test]
    fn test_inverse_and_forward_produce_same_graph() {
        // DEPENDS_ON and DEPENDENCY_OF expressing the same edge should produce
        // identical dependency graphs.
        let forward_json = r#"{
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://spdx.org/spdxdocs/test",
            "creationInfo": {
                "creators": ["Tool: manual"],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [
                {
                    "name": "app",
                    "SPDXID": "SPDXRef-app",
                    "downloadLocation": "NONE"
                },
                {
                    "name": "lib",
                    "SPDXID": "SPDXRef-lib",
                    "downloadLocation": "NONE"
                }
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-app",
                    "relatedSpdxElement": "SPDXRef-lib",
                    "relationshipType": "DEPENDS_ON"
                }
            ]
        }"#;

        let inverse_json = r#"{
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://spdx.org/spdxdocs/test",
            "creationInfo": {
                "creators": ["Tool: manual"],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [
                {
                    "name": "app",
                    "SPDXID": "SPDXRef-app",
                    "downloadLocation": "NONE"
                },
                {
                    "name": "lib",
                    "SPDXID": "SPDXRef-lib",
                    "downloadLocation": "NONE"
                }
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-lib",
                    "relatedSpdxElement": "SPDXRef-app",
                    "relationshipType": "DEPENDENCY_OF"
                }
            ]
        }"#;

        let forward_sbom = SpdxReader::read_json(forward_json.as_bytes()).unwrap();
        let inverse_sbom = SpdxReader::read_json(inverse_json.as_bytes()).unwrap();

        assert_eq!(forward_sbom.dependencies, inverse_sbom.dependencies);
    }

    #[test]
    fn test_document_element_skipped_for_inverse_types() {
        // DESCRIBED_BY with the document element should not warn.
        let json = r#"{
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://spdx.org/spdxdocs/test",
            "creationInfo": {
                "creators": ["Tool: manual"],
                "created": "2023-01-01T00:00:00Z"
            },
            "packages": [
                {
                    "name": "pkg",
                    "SPDXID": "SPDXRef-pkg",
                    "downloadLocation": "NONE"
                }
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-pkg",
                    "relatedSpdxElement": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBED_BY"
                }
            ]
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();
        assert!(sbom.warnings.is_empty());
        assert!(sbom.dependencies.is_empty());
    }
}
