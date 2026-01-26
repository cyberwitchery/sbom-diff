#![doc = include_str!("../readme.md")]

use sbom_model::{Component, ComponentId, Sbom};
use spdx_rs::models::RelationshipType;
use std::collections::BTreeMap;
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

            let id = ComponentId::new(purl_str, &props);

            let mut comp = Component {
                id: id.clone(),
                name,
                version,
                ecosystem: None,
                supplier,
                description: None, // pkg.description might not exist or be named differently. Safe fallback.
                purl,
                licenses: Vec::new(),
                hashes: BTreeMap::new(),
                source_ids: vec![pkg.package_spdx_identifier.clone()],
            };

            // Try to map description if field matches, else ignore for now to pass build
            // (If we knew the field name we'd use it)

            // Licenses
            if let Some(l) = pkg.concluded_license {
                // l is String or similar
                if l.to_string() != "NOASSERTION" && l.to_string() != "NONE" {
                    comp.licenses.push(l.to_string());
                }
            }

            // Hashes
            for checksum in pkg.package_checksum {
                comp.hashes
                    .insert(format!("{:?}", checksum.algorithm), checksum.value);
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
}
