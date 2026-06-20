#![doc = include_str!("../readme.md")]

use sbom_model::{
    canonical_algorithm_name, parse_license_expression, Component, ComponentId, DependencyKind,
    Sbom,
};
use spdx_rs::models::RelationshipType;
use spdx_rs::parsers::spdx_from_tag_value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use thiserror::Error;

/// errors that can occur when parsing SPDX documents.
#[derive(Error, Debug)]
pub enum Error {
    /// the JSON structure doesn't match the SPDX schema.
    #[error("SPDX parse error: {0}")]
    Parse(#[from] serde_json::Error),
    /// an I/O error occurred while reading the input.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// the SPDX document version is not supported.
    #[error("unsupported SPDX version '{version}': only SPDX 2.x is supported (e.g. SPDX-2.3)")]
    UnsupportedVersion {
        /// the version string found in the document.
        version: String,
    },
    /// the tag-value input could not be parsed.
    #[error("SPDX tag-value parse error: {0}")]
    TagValue(String),
}

/// edge direction for a dependency relationship.
enum Direction {
    /// the left element depends on the right (left → right).
    Forward,
    /// the right element depends on the left (right → left).
    Inverse,
}

/// classifies an SPDX relationship type into a dependency edge direction
/// and semantic kind.
///
/// returns `Some((Direction, DependencyKind))` for relationship types that
/// represent dependency edges, or `None` for non-dependency relationships
/// (e.g. BUILD_TOOL_OF, GENERATED_FROM).
fn dependency_direction(rel_type: &RelationshipType) -> Option<(Direction, DependencyKind)> {
    match rel_type {
        // forward: A {verb} B means A depends on / contains B.
        RelationshipType::DependsOn
        | RelationshipType::Contains
        | RelationshipType::Describes
        | RelationshipType::HasPrerequisite => Some((Direction::Forward, DependencyKind::Runtime)),

        // inverse: A {verb} B means B depends on / contains A.
        RelationshipType::DependencyOf
        | RelationshipType::ContainedBy
        | RelationshipType::DescribedBy
        | RelationshipType::PrerequisiteFor => Some((Direction::Inverse, DependencyKind::Runtime)),

        // scoped inverse types — carry their dependency kind.
        RelationshipType::RuntimeDependencyOf => {
            Some((Direction::Inverse, DependencyKind::Runtime))
        }
        RelationshipType::DevDependencyOf => Some((Direction::Inverse, DependencyKind::Dev)),
        RelationshipType::BuildDependencyOf => Some((Direction::Inverse, DependencyKind::Build)),
        RelationshipType::TestDependencyOf => Some((Direction::Inverse, DependencyKind::Test)),
        RelationshipType::OptionalDependencyOf => {
            Some((Direction::Inverse, DependencyKind::Optional))
        }
        RelationshipType::ProvidedDependencyOf => {
            Some((Direction::Inverse, DependencyKind::Provided))
        }

        // not a dependency relationship — ignore.
        _ => None,
    }
}

/// parser for SPDX JSON documents.
///
/// converts SPDX 2.3 JSON into the format-agnostic [`Sbom`] type.
pub struct SpdxReader;

impl SpdxReader {
    /// parses an SPDX JSON document from a reader.
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
        // buffer the input so we can check the SPDX version before full
        // parsing. Without this, SPDX 3.0 documents would either produce
        // garbled output or an inscrutable deserialization error.
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;

        Self::check_spdx_version(&buf)?;

        let spdx_doc: spdx_rs::models::SPDX = serde_json::from_slice(&buf)?;

        Ok(Self::spdx_to_sbom(spdx_doc))
    }

    /// parses an SPDX tag-value document from a reader.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sbom_model_spdx::SpdxReader;
    /// use std::fs::File;
    ///
    /// let file = File::open("sbom.spdx").unwrap();
    /// let sbom = SpdxReader::read_tag_value(file).unwrap();
    /// ```
    pub fn read_tag_value<R: Read>(mut reader: R) -> Result<Sbom, Error> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;

        let input = std::str::from_utf8(&buf)
            .map_err(|e| Error::TagValue(format!("invalid UTF-8: {e}")))?;

        Self::check_spdx_version_tag_value(input)?;

        // spdx-rs 0.5 has two tag-value parsing quirks we work around:
        //
        // 1. CreationInfo default contamination: the parser starts with
        //    CreationInfo::default() which includes phantom creators
        //    (e.g. "Tool: LicenseFind-1.0") that get mixed in with real
        //    ones. We re-parse Creator lines from the raw input.
        //
        // 2. Last ExternalRef dropped: the parser uses an "in progress"
        //    pattern for ExternalRef that only flushes when the next
        //    PackageName is seen. The very last package's last ExternalRef
        //    is never flushed. We append a sentinel package to trigger
        //    the flush, then strip it from the result.
        let patched = format!(
            "{}\n\nPackageName: __spdx_rs_flush_sentinel__\nSPDXID: SPDXRef-FLUSH-SENTINEL\nPackageDownloadLocation: NOASSERTION\nFilesAnalyzed: false\n",
            input.trim_end()
        );

        // detect whether the flush-sentinel was needed: does the last
        // package in the raw input have ExternalRef lines?  If so, spdx-rs
        // 0.5 would have silently dropped the last one without the sentinel.
        let mut last_pkg_has_ext_ref = false;
        for line in input.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("PackageName:") {
                last_pkg_has_ext_ref = false;
            } else if trimmed.starts_with("ExternalRef:") {
                last_pkg_has_ext_ref = true;
            }
        }

        let mut spdx_doc =
            spdx_from_tag_value(&patched).map_err(|e| Error::TagValue(e.to_string()))?;

        // strip the sentinel package.
        spdx_doc
            .package_information
            .retain(|p| p.package_name != "__spdx_rs_flush_sentinel__");

        // fix creator contamination: re-parse Creator lines from the raw
        // input instead of trusting the parsed result.
        let parsed_creators = spdx_doc
            .document_creation_information
            .creation_info
            .creators
            .clone();
        let actual_creators: Vec<String> = input
            .lines()
            .filter_map(|line| {
                line.trim()
                    .strip_prefix("Creator:")
                    .map(|v| v.trim().to_string())
            })
            .collect();
        spdx_doc
            .document_creation_information
            .creation_info
            .creators = actual_creators.clone();

        let mut sbom = Self::spdx_to_sbom(spdx_doc);

        // emit diagnostics for workarounds that fired.
        if last_pkg_has_ext_ref {
            sbom.warnings.push(
                "SPDX: applied flush-sentinel workaround — spdx-rs 0.5 silently \
                 drops the last ExternalRef of the last package without it"
                    .into(),
            );
        }

        let phantom: Vec<_> = parsed_creators
            .iter()
            .filter(|c| !actual_creators.contains(c))
            .collect();
        if !phantom.is_empty() {
            sbom.warnings.push(format!(
                "SPDX: stripped phantom creator(s) injected by spdx-rs 0.5 default: {}",
                phantom
                    .iter()
                    .map(|s| format!("'{s}'"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        Ok(sbom)
    }

    /// converts a parsed `spdx_rs::models::SPDX` document into the
    /// format-agnostic [`Sbom`] type. Shared by JSON and tag-value readers.
    fn spdx_to_sbom(spdx_doc: spdx_rs::models::SPDX) -> Sbom {
        let mut sbom = Sbom::default();

        let ci = spdx_doc.document_creation_information.creation_info;
        sbom.metadata.timestamp = Some(ci.created.to_string());
        for creator in ci.creators {
            if let Some(stripped) = creator.strip_prefix("Tool: ") {
                sbom.metadata.tools.push(stripped.to_string());
            } else {
                sbom.metadata.authors.push(creator);
            }
        }

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

            let mut purl = None;
            for r in &pkg.external_reference {
                if r.reference_type == "purl" {
                    purl = Some(r.reference_locator.clone());
                    break;
                }
            }
            let purl_str = purl.as_deref();

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

            // licenses: prefer concludedLicense, fall back to declaredLicense
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

            for checksum in pkg.package_checksum {
                comp.hashes.insert(
                    canonical_algorithm_name(&format!("{:?}", checksum.algorithm)),
                    checksum.value,
                );
            }

            if let Some(existing) = sbom.components.get(&id) {
                sbom.warnings.push(format!(
                    "SPDX: duplicate component id '{}' (name '{}'); \
                     earlier entry '{}' will be overwritten",
                    id, comp.name, existing.name,
                ));
            }
            sbom.components.insert(id, comp);
        }

        // map SPDX IDs -> ComponentId
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

            // determine the edge direction and semantic kind for this
            // relationship type.
            // forward: left depends on right (left → right edge).
            // inverse: right depends on left (right → left edge).
            let (parent_spdx, child_spdx, kind) = match dependency_direction(&rel_type) {
                Some((Direction::Forward, kind)) => (&left_spdx, &right_spdx, kind),
                Some((Direction::Inverse, kind)) => (&right_spdx, &left_spdx, kind),
                None => continue,
            };

            // skip relationships involving the document element itself
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
                        .insert(cid.clone(), kind);
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

        sbom.rebuild_reverse_deps();
        sbom
    }

    /// pre-check the `spdxVersion` field before full parsing.
    ///
    /// returns an error for SPDX 3.x or any other unsupported spec version,
    /// giving a clear message instead of cryptic deserialization failures.
    fn check_spdx_version(data: &[u8]) -> Result<(), Error> {
        #[derive(serde::Deserialize)]
        struct VersionProbe {
            #[serde(rename = "spdxVersion")]
            spdx_version: Option<String>,
        }

        let probe: VersionProbe = match serde_json::from_slice(data) {
            Ok(p) => p,
            // not valid JSON — let the full parser produce a proper error.
            Err(_) => return Ok(()),
        };

        match probe.spdx_version.as_deref() {
            Some(v) if v.starts_with("SPDX-2.") => Ok(()),
            Some(v) => Err(Error::UnsupportedVersion {
                version: v.to_string(),
            }),
            // missing version field — let the full parser produce its own
            // error; the document is malformed either way.
            None => Ok(()),
        }
    }

    /// pre-check the `SPDXVersion` tag in a tag-value document.
    ///
    /// scans for the first `SPDXVersion:` line and rejects non-2.x versions.
    /// also rejects input that has no `SPDXVersion:` at all, since the
    /// spdx-rs tag-value parser is permissive enough to "parse" arbitrary
    /// text files without error.
    fn check_spdx_version_tag_value(input: &str) -> Result<(), Error> {
        for line in input.lines() {
            let line = line.trim();
            if let Some(value) = line.strip_prefix("SPDXVersion:") {
                let version = value.trim();
                if version.starts_with("SPDX-2.") {
                    return Ok(());
                }
                return Err(Error::UnsupportedVersion {
                    version: version.to_string(),
                });
            }
        }
        Err(Error::TagValue(
            "no SPDXVersion tag found (not a valid SPDX tag-value document)".to_string(),
        ))
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
            .keys()
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

        // both NOASSERTION -> no licenses
        assert!(find("both-noassertion").licenses.is_empty());

        // valid concluded -> uses concluded, ignores declared
        // spdx 0.13 preserves the canonical SPDX id (GPL-3.0-only) rather than
        // collapsing it to the deprecated short form (GPL-3.0) as 0.10 did.
        assert!(find("concluded-present").licenses.contains("GPL-3.0-only"));
        assert!(!find("concluded-present").licenses.contains("MIT"));

        // no license fields at all -> empty
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
    fn test_non_json_input_does_not_produce_serde_error() {
        // non-JSON input (e.g. XML or tag-value) should fail with a parse
        // error from the full parser, not a cryptic serde error from the
        // version pre-check.
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?><bom/>"#;
        let err = SpdxReader::read_json(&xml[..]).unwrap_err();
        let msg = err.to_string();
        // should be a parse error from the full JSON parser, not an
        // "unsupported SPDX version" error.
        assert!(
            msg.contains("parse error"),
            "expected parse error, got: {msg}"
        );
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

        // the edge should go from app-b → lib-a (app-b depends on lib-a).
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
        assert!(deps.contains_key(&lib_id));
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
        assert!(deps.contains_key(&child_id));
    }

    #[test]
    fn test_scoped_dependency_of_types() {
        // scoped types like RUNTIME_DEPENDENCY_OF are inverse: "A is a
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
            .keys()
            .map(|id| sbom.components[id].name.as_str())
            .collect();
        assert!(dep_names.contains("runtime-lib"));
        assert!(dep_names.contains("dev-lib"));

        // verify dependency kinds are preserved
        let runtime_id = sbom
            .components
            .values()
            .find(|c| c.name == "runtime-lib")
            .unwrap()
            .id
            .clone();
        let dev_id = sbom
            .components
            .values()
            .find(|c| c.name == "dev-lib")
            .unwrap()
            .id
            .clone();

        assert_eq!(
            deps[&runtime_id],
            sbom_model::DependencyKind::Runtime,
            "RUNTIME_DEPENDENCY_OF should produce Runtime kind"
        );
        assert_eq!(
            deps[&dev_id],
            sbom_model::DependencyKind::Dev,
            "DEV_DEPENDENCY_OF should produce Dev kind"
        );
    }

    #[test]
    fn test_all_scoped_dependency_kinds() {
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
                {"name": "app", "SPDXID": "SPDXRef-app", "downloadLocation": "NONE"},
                {"name": "build-dep", "SPDXID": "SPDXRef-build", "downloadLocation": "NONE"},
                {"name": "test-dep", "SPDXID": "SPDXRef-test", "downloadLocation": "NONE"},
                {"name": "optional-dep", "SPDXID": "SPDXRef-optional", "downloadLocation": "NONE"},
                {"name": "provided-dep", "SPDXID": "SPDXRef-provided", "downloadLocation": "NONE"}
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-build",
                    "relatedSpdxElement": "SPDXRef-app",
                    "relationshipType": "BUILD_DEPENDENCY_OF"
                },
                {
                    "spdxElementId": "SPDXRef-test",
                    "relatedSpdxElement": "SPDXRef-app",
                    "relationshipType": "TEST_DEPENDENCY_OF"
                },
                {
                    "spdxElementId": "SPDXRef-optional",
                    "relatedSpdxElement": "SPDXRef-app",
                    "relationshipType": "OPTIONAL_DEPENDENCY_OF"
                },
                {
                    "spdxElementId": "SPDXRef-provided",
                    "relatedSpdxElement": "SPDXRef-app",
                    "relationshipType": "PROVIDED_DEPENDENCY_OF"
                }
            ]
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();

        let app_id = sbom
            .components
            .values()
            .find(|c| c.name == "app")
            .unwrap()
            .id
            .clone();
        let deps = &sbom.dependencies[&app_id];
        assert_eq!(deps.len(), 4);

        let find_kind = |name: &str| -> sbom_model::DependencyKind {
            let id = sbom
                .components
                .values()
                .find(|c| c.name == name)
                .unwrap()
                .id
                .clone();
            deps[&id]
        };

        assert_eq!(find_kind("build-dep"), sbom_model::DependencyKind::Build);
        assert_eq!(find_kind("test-dep"), sbom_model::DependencyKind::Test);
        assert_eq!(
            find_kind("optional-dep"),
            sbom_model::DependencyKind::Optional
        );
        assert_eq!(
            find_kind("provided-dep"),
            sbom_model::DependencyKind::Provided
        );
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

    #[test]
    fn test_read_tag_value_minimal() {
        let tv = "\
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: test
DocumentNamespace: http://spdx.org/spdxdocs/test
Creator: Tool: manual
Created: 2023-01-01T00:00:00Z

PackageName: pkg-a
SPDXID: SPDXRef-pkg-a
PackageVersion: 1.0.0
PackageDownloadLocation: NOASSERTION
PackageLicenseConcluded: NOASSERTION
PackageCopyrightText: NOASSERTION
";
        let sbom = SpdxReader::read_tag_value(tv.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 1);
        let comp = &sbom.components[0];
        assert_eq!(comp.name, "pkg-a");
        assert_eq!(comp.version, Some("1.0.0".to_string()));
        assert_eq!(sbom.metadata.tools, vec!["manual"]);
    }

    #[test]
    fn test_read_tag_value_with_relationships() {
        let tv = "\
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: test
DocumentNamespace: http://spdx.org/spdxdocs/test
Creator: Tool: test-tool
Created: 2023-01-01T00:00:00Z

PackageName: app
SPDXID: SPDXRef-app
PackageVersion: 1.0.0
PackageDownloadLocation: NOASSERTION
PackageLicenseConcluded: Apache-2.0
PackageCopyrightText: NOASSERTION

PackageName: lib
SPDXID: SPDXRef-lib
PackageVersion: 2.0.0
PackageDownloadLocation: NOASSERTION
PackageLicenseConcluded: MIT
PackageCopyrightText: NOASSERTION

Relationship: SPDXRef-app DEPENDS_ON SPDXRef-lib
";
        let sbom = SpdxReader::read_tag_value(tv.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 2);

        let app = sbom.components.values().find(|c| c.name == "app").unwrap();
        let lib = sbom.components.values().find(|c| c.name == "lib").unwrap();

        assert!(app.licenses.contains("Apache-2.0"));
        assert!(lib.licenses.contains("MIT"));

        let deps = &sbom.dependencies[&app.id];
        assert!(deps.contains_key(&lib.id));
    }

    #[test]
    fn test_read_tag_value_with_purl() {
        let tv = "\
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: test
DocumentNamespace: http://spdx.org/spdxdocs/test
Creator: Tool: reuse
Created: 2023-01-01T00:00:00Z

PackageName: serde
SPDXID: SPDXRef-serde
PackageVersion: 1.0.200
PackageDownloadLocation: NOASSERTION
PackageLicenseConcluded: MIT
PackageCopyrightText: NOASSERTION
ExternalRef: PACKAGE-MANAGER purl pkg:cargo/serde@1.0.200
";
        let sbom = SpdxReader::read_tag_value(tv.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 1);

        let serde = &sbom.components[0];
        assert_eq!(serde.purl, Some("pkg:cargo/serde@1.0.200".to_string()));
        assert_eq!(serde.ecosystem, Some("cargo".to_string()));
    }

    #[test]
    fn test_read_tag_value_version_3_rejected() {
        let tv = "\
SPDXVersion: SPDX-3.0
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: test
DocumentNamespace: http://spdx.org/spdxdocs/test
Creator: Tool: test
Created: 2023-01-01T00:00:00Z
";
        let err = SpdxReader::read_tag_value(tv.as_bytes()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unsupported SPDX version"));
        assert!(msg.contains("SPDX-3.0"));
    }

    #[test]
    fn test_read_tag_value_with_checksums() {
        let tv = "\
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: test
DocumentNamespace: http://spdx.org/spdxdocs/test
Creator: Tool: manual
Created: 2023-01-01T00:00:00Z

PackageName: pkg-a
SPDXID: SPDXRef-pkg-a
PackageVersion: 1.0.0
PackageDownloadLocation: NOASSERTION
PackageLicenseConcluded: NOASSERTION
PackageCopyrightText: NOASSERTION
PackageChecksum: SHA256: abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
PackageChecksum: SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
";
        let sbom = SpdxReader::read_tag_value(tv.as_bytes()).unwrap();
        let hashes = &sbom.components[0].hashes;
        assert_eq!(
            hashes.get("SHA-256").unwrap(),
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        );
        assert_eq!(
            hashes.get("SHA-1").unwrap(),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn test_read_tag_value_with_supplier() {
        let tv = "\
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: test
DocumentNamespace: http://spdx.org/spdxdocs/test
Creator: Tool: manual
Created: 2023-01-01T00:00:00Z

PackageName: pkg-a
SPDXID: SPDXRef-pkg-a
PackageVersion: 1.0.0
PackageDownloadLocation: NOASSERTION
PackageSupplier: Organization: Acme Corp
PackageLicenseConcluded: NOASSERTION
PackageCopyrightText: NOASSERTION
";
        let sbom = SpdxReader::read_tag_value(tv.as_bytes()).unwrap();
        assert_eq!(sbom.components[0].supplier, Some("Acme Corp".to_string()));
    }

    #[test]
    fn test_tag_value_flush_sentinel_warns_when_last_pkg_has_external_ref() {
        let tv = "\
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: test
DocumentNamespace: http://spdx.org/spdxdocs/test
Creator: Tool: manual
Created: 2023-01-01T00:00:00Z

PackageName: serde
SPDXID: SPDXRef-serde
PackageVersion: 1.0.200
PackageDownloadLocation: NOASSERTION
PackageLicenseConcluded: MIT
PackageCopyrightText: NOASSERTION
ExternalRef: PACKAGE-MANAGER purl pkg:cargo/serde@1.0.200
";
        let sbom = SpdxReader::read_tag_value(tv.as_bytes()).unwrap();

        assert!(
            sbom.warnings.iter().any(|w| w.contains("flush-sentinel")),
            "should warn about flush-sentinel workaround when last package has ExternalRef: {:?}",
            sbom.warnings
        );
        // the ExternalRef should still be parsed correctly
        assert_eq!(
            sbom.components[0].purl,
            Some("pkg:cargo/serde@1.0.200".to_string())
        );
    }

    #[test]
    fn test_tag_value_no_flush_sentinel_warning_without_external_ref() {
        let tv = "\
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: test
DocumentNamespace: http://spdx.org/spdxdocs/test
Creator: Tool: manual
Created: 2023-01-01T00:00:00Z

PackageName: pkg-a
SPDXID: SPDXRef-pkg-a
PackageVersion: 1.0.0
PackageDownloadLocation: NOASSERTION
PackageLicenseConcluded: NOASSERTION
PackageCopyrightText: NOASSERTION
";
        let sbom = SpdxReader::read_tag_value(tv.as_bytes()).unwrap();

        assert!(
            !sbom.warnings.iter().any(|w| w.contains("flush-sentinel")),
            "should NOT warn about flush-sentinel when last package has no ExternalRef: {:?}",
            sbom.warnings
        );
    }

    #[test]
    fn test_tag_value_phantom_creator_detection() {
        // this test verifies that when spdx-rs injects phantom creators,
        // a warning is emitted. In practice, the phantom creator is
        // "Tool: LicenseFind-1.0" from CreationInfo::default(). Whether
        // the phantom appears depends on the spdx-rs version's behavior.
        // we test the detection mechanism rather than assuming the bug fires.
        let tv = "\
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: test
DocumentNamespace: http://spdx.org/spdxdocs/test
Creator: Tool: manual
Created: 2023-01-01T00:00:00Z

PackageName: pkg-a
SPDXID: SPDXRef-pkg-a
PackageVersion: 1.0.0
PackageDownloadLocation: NOASSERTION
PackageLicenseConcluded: NOASSERTION
PackageCopyrightText: NOASSERTION
";
        let sbom = SpdxReader::read_tag_value(tv.as_bytes()).unwrap();
        // regardless of whether the phantom fires, the result should have
        // the correct creator, not the phantom one.
        assert_eq!(sbom.metadata.tools, vec!["manual"]);

        // if a phantom warning exists, it should mention what was stripped.
        if let Some(w) = sbom.warnings.iter().find(|w| w.contains("phantom")) {
            assert!(
                w.contains("LicenseFind") || w.contains("stripped"),
                "phantom warning should identify the injected creator: {w}"
            );
        }
    }

    #[test]
    fn test_duplicate_purl_warns() {
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
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:npm/pkg-a@1.0.0"
                        }
                    ]
                },
                {
                    "name": "pkg-a-duplicate",
                    "SPDXID": "SPDXRef-pkg-a-dup",
                    "downloadLocation": "NONE",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:npm/pkg-a@1.0.0"
                        }
                    ]
                }
            ],
            "relationships": []
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();
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
        // packages without purls can collide when name+version match.
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
                    "name": "dup",
                    "SPDXID": "SPDXRef-dup1",
                    "versionInfo": "1.0.0",
                    "downloadLocation": "NONE"
                },
                {
                    "name": "dup",
                    "SPDXID": "SPDXRef-dup2",
                    "versionInfo": "1.0.0",
                    "downloadLocation": "NONE"
                }
            ],
            "relationships": []
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.warnings.len(), 1);
        assert!(sbom.warnings[0].contains("duplicate"));
    }

    #[test]
    fn test_no_duplicate_warning_for_unique_packages() {
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
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:npm/pkg-a@1.0.0"
                        }
                    ]
                },
                {
                    "name": "pkg-b",
                    "SPDXID": "SPDXRef-pkg-b",
                    "downloadLocation": "NONE",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:npm/pkg-b@2.0.0"
                        }
                    ]
                }
            ],
            "relationships": []
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 2);
        assert!(sbom.warnings.is_empty());
    }
}
