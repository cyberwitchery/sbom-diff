//! the part of an SPDX 2.x document the reader maps, named as in the SPDX JSON schema.

use chrono::{DateTime, Utc};
use serde::de::{Deserializer, Error as _, IgnoredAny};
use serde::Deserialize;
use spdx_expression::SpdxExpression;

/// the `relationshipType` values of the SPDX 2.3 schema.
pub(crate) const RELATIONSHIP_TYPES: &[&str] = &[
    "DESCRIBES",
    "DESCRIBED_BY",
    "CONTAINS",
    "CONTAINED_BY",
    "DEPENDS_ON",
    "DEPENDENCY_OF",
    "DEPENDENCY_MANIFEST_OF",
    "BUILD_DEPENDENCY_OF",
    "DEV_DEPENDENCY_OF",
    "OPTIONAL_DEPENDENCY_OF",
    "PROVIDED_DEPENDENCY_OF",
    "TEST_DEPENDENCY_OF",
    "RUNTIME_DEPENDENCY_OF",
    "EXAMPLE_OF",
    "GENERATES",
    "GENERATED_FROM",
    "ANCESTOR_OF",
    "DESCENDANT_OF",
    "VARIANT_OF",
    "DISTRIBUTION_ARTIFACT",
    "PATCH_FOR",
    "PATCH_APPLIED",
    "COPY_OF",
    "FILE_ADDED",
    "FILE_DELETED",
    "FILE_MODIFIED",
    "EXPANDED_FROM_ARCHIVE",
    "DYNAMIC_LINK",
    "STATIC_LINK",
    "DATA_FILE_OF",
    "TEST_CASE_OF",
    "BUILD_TOOL_OF",
    "DEV_TOOL_OF",
    "TEST_OF",
    "TEST_TOOL_OF",
    "DOCUMENTATION_OF",
    "OPTIONAL_COMPONENT_OF",
    "METAFILE_OF",
    "PACKAGE_OF",
    "AMENDS",
    "PREREQUISITE_FOR",
    "HAS_PREREQUISITE",
    "REQUIREMENT_DESCRIPTION_FOR",
    "SPECIFICATION_FOR",
    "OTHER",
];

/// the checksum `algorithm` values of the SPDX 2.3 schema.
pub(crate) const CHECKSUM_ALGORITHMS: &[&str] = &[
    "SHA1",
    "SHA224",
    "SHA256",
    "SHA384",
    "SHA512",
    "MD2",
    "MD4",
    "MD5",
    "MD6",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
    "BLAKE2b-256",
    "BLAKE2b-384",
    "BLAKE2b-512",
    "BLAKE3",
    "ADLER32",
];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Document {
    #[serde(rename = "spdxVersion")]
    _spdx_version: String,
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,
    #[serde(default)]
    pub external_document_refs: Vec<ExternalDocumentRef>,
    pub creation_info: CreationInfo,
    #[serde(default)]
    pub packages: Vec<Package>,
    #[serde(default)]
    pub files: Vec<Element>,
    #[serde(default)]
    pub snippets: Vec<Element>,
    #[serde(default)]
    pub relationships: Vec<Relationship>,
    #[serde(flatten)]
    _unread: UnreadDocumentProperties,
}

/// the document properties the reader does not read, declared so that an unknown one is still an error.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnreadDocumentProperties {
    #[serde(rename = "$schema")]
    _schema: Option<IgnoredAny>,
    _annotations: Option<IgnoredAny>,
    _comment: Option<IgnoredAny>,
    _data_license: Option<IgnoredAny>,
    _document_describes: Option<IgnoredAny>,
    _document_namespace: Option<IgnoredAny>,
    _has_extracted_licensing_infos: Option<IgnoredAny>,
    _name: Option<IgnoredAny>,
    _revieweds: Option<IgnoredAny>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreationInfo {
    pub creators: Vec<String>,
    pub created: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ExternalDocumentRef {
    #[serde(rename = "externalDocumentId")]
    pub external_document_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Package {
    pub name: String,
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,
    pub version_info: Option<String>,
    pub supplier: Option<String>,
    #[serde(default)]
    pub checksums: Vec<Checksum>,
    pub license_concluded: Option<SpdxExpression>,
    pub license_declared: Option<SpdxExpression>,
    pub summary: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub external_refs: Vec<ExternalRef>,
    #[serde(flatten)]
    _unread: UnreadPackageProperties,
}

/// the package properties the reader does not read, declared so that an unknown one is still an error.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnreadPackageProperties {
    _annotations: Option<IgnoredAny>,
    _attribution_texts: Option<IgnoredAny>,
    _built_date: Option<IgnoredAny>,
    _comment: Option<IgnoredAny>,
    _copyright_text: Option<IgnoredAny>,
    _download_location: Option<IgnoredAny>,
    _files_analyzed: Option<IgnoredAny>,
    _has_files: Option<IgnoredAny>,
    _homepage: Option<IgnoredAny>,
    _license_comments: Option<IgnoredAny>,
    _license_info_from_files: Option<IgnoredAny>,
    _originator: Option<IgnoredAny>,
    _package_file_name: Option<IgnoredAny>,
    _package_verification_code: Option<IgnoredAny>,
    _primary_package_purpose: Option<IgnoredAny>,
    _release_date: Option<IgnoredAny>,
    _source_info: Option<IgnoredAny>,
    _valid_until_date: Option<IgnoredAny>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Checksum {
    #[serde(deserialize_with = "checksum_algorithm")]
    pub algorithm: String,
    #[serde(rename = "checksumValue")]
    pub checksum_value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExternalRef {
    pub reference_type: String,
    pub reference_locator: String,
}

/// a file or snippet, of which the reader needs only the id.
#[derive(Debug, Deserialize)]
pub(crate) struct Element {
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Relationship {
    pub spdx_element_id: String,
    pub related_spdx_element: String,
    #[serde(deserialize_with = "relationship_type")]
    pub relationship_type: String,
}

fn checksum_algorithm<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    one_of(deserializer, CHECKSUM_ALGORITHMS)
}

fn relationship_type<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    one_of(deserializer, RELATIONSHIP_TYPES)
}

fn one_of<'de, D: Deserializer<'de>>(
    deserializer: D,
    values: &'static [&'static str],
) -> Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    if values.contains(&value.as_str()) {
        Ok(value)
    } else {
        Err(D::Error::unknown_variant(&value, values))
    }
}

/// the name spdx-rs serializes a value under, e.g. `SHA3-256` or `DEPENDS_ON`.
fn spdx_rs_name<T: serde::Serialize + std::fmt::Debug>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(name)) => name,
        _ => format!("{value:?}"),
    }
}

/// temporary: tag-value is still parsed by spdx-rs until the reader has its own parser (#181).
impl From<spdx_rs::models::SPDX> for Document {
    fn from(spdx: spdx_rs::models::SPDX) -> Self {
        let info = spdx.document_creation_information;
        Document {
            _spdx_version: info.spdx_version,
            spdx_id: info.spdx_identifier,
            external_document_refs: info
                .external_document_references
                .into_iter()
                .map(|reference| ExternalDocumentRef {
                    external_document_id: reference.id_string,
                })
                .collect(),
            creation_info: CreationInfo {
                creators: info.creation_info.creators,
                created: info.creation_info.created,
            },
            packages: spdx
                .package_information
                .into_iter()
                .map(|package| Package {
                    name: package.package_name,
                    spdx_id: package.package_spdx_identifier,
                    version_info: package.package_version,
                    supplier: package.package_supplier,
                    checksums: package
                        .package_checksum
                        .into_iter()
                        .map(|checksum| Checksum {
                            algorithm: spdx_rs_name(&checksum.algorithm),
                            checksum_value: checksum.value,
                        })
                        .collect(),
                    license_concluded: package.concluded_license,
                    license_declared: package.declared_license,
                    summary: package.package_summary_description,
                    description: package.package_detailed_description,
                    external_refs: package
                        .external_reference
                        .into_iter()
                        .map(|reference| ExternalRef {
                            reference_type: reference.reference_type,
                            reference_locator: reference.reference_locator,
                        })
                        .collect(),
                    _unread: Default::default(),
                })
                .collect(),
            files: spdx
                .file_information
                .into_iter()
                .map(|file| Element {
                    spdx_id: file.file_spdx_identifier,
                })
                .collect(),
            snippets: spdx
                .snippet_information
                .into_iter()
                .map(|snippet| Element {
                    spdx_id: snippet.snippet_spdx_identifier,
                })
                .collect(),
            relationships: spdx
                .relationships
                .into_iter()
                .map(|relationship| Relationship {
                    spdx_element_id: relationship.spdx_element_id,
                    related_spdx_element: relationship.related_spdx_element,
                    relationship_type: spdx_rs_name(&relationship.relationship_type),
                })
                .collect(),
            _unread: Default::default(),
        }
    }
}
