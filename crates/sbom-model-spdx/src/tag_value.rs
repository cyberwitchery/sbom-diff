//! the SPDX 2.x tag-value format, read into a [`Document`].
//!
//! [`crate::read_lines`] reads the tags and their values and skips what it
//! cannot read; this module gives the tags their place in the document.
//!
//! a `PackageName` opens a package and a `FileName` a file, and an `SPDXID`
//! names the document, package or file it follows. a second `SPDXID` in one
//! of them opens a package with no name. the package tags the reader maps
//! apply to the last package opened, and a tag given twice keeps its last
//! value.

use crate::document::{
    Checksum, CreationInfo, Document, Element, ExternalDocumentRef, ExternalRef, Package,
    Relationship,
};
use crate::{fields, Entry, Error};
use spdx_expression::SpdxExpression;

/// what an `SPDXID` names.
enum Section {
    Document,
    Package,
    File,
}

/// builds the document from the tags [`crate::read_lines`] read.
pub(crate) fn document(entries: Vec<Entry>) -> Result<Document, Error> {
    let mut version = String::new();
    let mut spdx_id = String::new();
    let mut external_document_refs = Vec::new();
    let mut creators = Vec::new();
    let mut created = None;
    let mut packages: Vec<Package> = Vec::new();
    let mut files = Vec::new();
    let mut snippets = Vec::new();
    let mut relationships = Vec::new();

    let mut section = Section::Document;
    let mut named = false;

    for Entry { line, tag, value } in entries {
        let error = |reason: String| Error::TagValue(format!("line {line}: tag '{tag}': {reason}"));
        match tag.as_str() {
            "SPDXVersion" => version = value.trim().to_string(),
            "Creator" => creators.push(value.trim().to_string()),
            "Created" => {
                let normalized =
                    sbom_model::normalize_timestamp(value.trim()).ok_or_else(|| {
                        error(format!("'{}' is not an RFC 3339 timestamp", value.trim()))
                    })?;
                created = Some(normalized);
            }
            "ExternalDocumentRef" => {
                let [id, ..] = fields::<3>(&value).map_err(error)?;
                external_document_refs.push(ExternalDocumentRef {
                    external_document_id: id.to_string(),
                });
            }
            "PackageName" => {
                packages.push(package(value.trim()));
                section = Section::Package;
                named = false;
            }
            "FileName" => {
                files.push(Element {
                    spdx_id: String::new(),
                });
                section = Section::File;
                named = false;
            }
            "SPDXID" => {
                let id = value.trim().to_string();
                if named {
                    packages.push(package(""));
                    section = Section::Package;
                }
                named = true;
                match (&section, packages.last_mut(), files.last_mut()) {
                    (Section::Document, ..) => spdx_id = id,
                    (Section::Package, Some(package), _) => package.spdx_id = id,
                    (Section::File, _, Some(file)) => file.spdx_id = id,
                    _ => {}
                }
            }
            "SnippetSPDXID" => snippets.push(Element {
                spdx_id: value.trim().to_string(),
            }),
            "Relationship" => {
                let [left, kind, right] = fields::<3>(&value).map_err(error)?;
                relationships.push(Relationship {
                    spdx_element_id: left.to_string(),
                    related_spdx_element: right.trim().to_string(),
                    relationship_type: kind.to_uppercase(),
                });
            }
            _ => {
                if let Some(package) = packages.last_mut() {
                    read_package_tag(package, &tag, value).map_err(error)?;
                }
            }
        }
    }

    let created = created.ok_or_else(|| Error::TagValue("no Created tag found".to_string()))?;
    Ok(Document {
        _spdx_version: version,
        spdx_id,
        external_document_refs,
        creation_info: CreationInfo { creators, created },
        packages,
        files,
        snippets,
        relationships,
        _unread: Default::default(),
    })
}

fn package(name: &str) -> Package {
    Package {
        name: name.to_string(),
        spdx_id: String::new(),
        version_info: None,
        supplier: None,
        checksums: Vec::new(),
        license_concluded: None,
        license_declared: None,
        summary: None,
        description: None,
        external_refs: Vec::new(),
        _unread: Default::default(),
    }
}

/// reads a tag the reader maps onto `package`; other tags are not mapped.
fn read_package_tag(package: &mut Package, tag: &str, value: String) -> Result<(), String> {
    let text = |value: String| Some(value.trim().to_string());
    match tag {
        "PackageVersion" => package.version_info = text(value),
        "PackageSupplier" => package.supplier = text(value),
        "PackageSummary" => package.summary = Some(value),
        "PackageDescription" => package.description = Some(value),
        "PackageLicenseConcluded" => package.license_concluded = Some(expression(&value)?),
        "PackageLicenseDeclared" => package.license_declared = Some(expression(&value)?),
        "PackageChecksum" => {
            let (algorithm, digest) = value
                .split_once(':')
                .ok_or_else(|| format!("checksum '{value}' names no algorithm"))?;
            package.checksums.push(Checksum {
                algorithm: algorithm.trim().to_string(),
                checksum_value: digest.trim().to_string(),
            });
        }
        "ExternalRef" => {
            let [_, kind, locator] = fields::<3>(&value)?;
            package.external_refs.push(ExternalRef {
                reference_type: kind.to_string(),
                reference_locator: locator.trim().to_string(),
            });
        }
        _ => {}
    }
    Ok(())
}

fn expression(value: &str) -> Result<SpdxExpression, String> {
    SpdxExpression::parse(value).map_err(|e| format!("'{value}': {e}"))
}
