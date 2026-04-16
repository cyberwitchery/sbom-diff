#![doc = include_str!("../readme.md")]

use sbom_model::{parse_license_expression, Component, ComponentId, Sbom};
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
}

fn canonical_algorithm_name(alg: &spdx_rs::models::Algorithm) -> String {
    use spdx_rs::models::Algorithm;
    match alg {
        Algorithm::MD2 => "MD2",
        Algorithm::MD4 => "MD4",
        Algorithm::MD5 => "MD5",
        Algorithm::MD6 => "MD6",
        Algorithm::SHA1 => "SHA-1",
        Algorithm::SHA224 => "SHA-224",
        Algorithm::SHA256 => "SHA-256",
        Algorithm::SHA384 => "SHA-384",
        Algorithm::SHA512 => "SHA-512",
        Algorithm::SHA3256 => "SHA3-256",
        Algorithm::SHA3384 => "SHA3-384",
        Algorithm::SHA3512 => "SHA3-512",
        Algorithm::BLAKE2B256 => "BLAKE2b-256",
        Algorithm::BLAKE2B384 => "BLAKE2b-384",
        Algorithm::BLAKE2B512 => "BLAKE2b-512",
        Algorithm::BLAKE3 => "BLAKE3",
        Algorithm::ADLER32 => "ADLER-32",
    }
    .to_string()
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
    pub fn read_json<R: Read>(reader: R) -> Result<Sbom, Error> {
        let spdx_doc: spdx_rs::models::SPDX = serde_json::from_reader(reader)?;

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
            let v_str = version.clone().unwrap_or_default();
            if version.is_some() {
                props.push(("version", v_str.as_str()));
            }

            let supplier = pkg.package_supplier.clone();
            let s_str = supplier.clone().unwrap_or_default();
            if supplier.is_some() {
                props.push(("supplier", s_str.as_str()));
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

            // Licenses
            if let Some(l) = pkg.concluded_license {
                let l_str = l.to_string();
                if l_str != "NOASSERTION" && l_str != "NONE" {
                    comp.licenses.extend(parse_license_expression(&l_str));
                }
            }

            // Hashes
            for checksum in pkg.package_checksum {
                comp.hashes.insert(
                    canonical_algorithm_name(&checksum.algorithm),
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

        for rel in spdx_doc.relationships {
            let parent_spdx = rel.spdx_element_id;
            let child_spdx = rel.related_spdx_element;
            let rel_type = rel.relationship_type;

            let is_dependency = matches!(
                rel_type,
                RelationshipType::DependsOn
                    | RelationshipType::Contains
                    | RelationshipType::Describes
            );

            if is_dependency {
                if let (Some(parent_id), Some(child_id)) =
                    (ref_map.get(&parent_spdx), ref_map.get(&child_spdx))
                {
                    sbom.dependencies
                        .entry(parent_id.clone())
                        .or_default()
                        .insert(child_id.clone());
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
        assert_eq!(
            sbom.components[0].supplier,
            Some("Organization: Acme Corp".to_string())
        );
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
    fn test_relationship_with_unknown_spdxid_ignored() {
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
        // Unknown target ref should be silently ignored
        assert!(sbom.dependencies.is_empty());
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
}
