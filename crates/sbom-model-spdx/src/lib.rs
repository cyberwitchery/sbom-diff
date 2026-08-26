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

mod xml;

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
    /// the XML input is not well-formed or is not an SPDX document.
    #[error("SPDX XML parse error: {0}")]
    Xml(String),
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

/// yields each line of a tag-value document paired with whether the line
/// begins outside a `<text>` ... `</text>` block, i.e. whether it can carry
/// a tag.
fn scanned_lines(input: &str) -> impl Iterator<Item = (&str, bool)> {
    let last_close = input
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains("</text>"))
        .map(|(i, _)| i)
        .last();
    let mut in_text = false;
    input.lines().enumerate().map(move |(i, line)| {
        let tagged = !in_text;
        let closes_below = matches!(last_close, Some(last) if last > i);
        let mut rest = line;
        loop {
            if in_text {
                let Some(at) = rest.find("</text>") else {
                    break;
                };
                rest = &rest[at + "</text>".len()..];
            } else {
                // blocks open only at a value's head: after the colon, or on a continuation line.
                let head = rest.trim_start();
                let opened = head.strip_prefix("<text>").or_else(|| {
                    head.split_once(':')
                        .and_then(|(_, value)| value.trim_start().strip_prefix("<text>"))
                });
                let Some(after) = opened else { break };
                // and only where a `</text>` follows, which is where spdx-rs's take_until succeeds.
                if !after.contains("</text>") && !closes_below {
                    break;
                }
                rest = after;
            }
            in_text = !in_text;
        }
        (line, tagged)
    })
}

/// yields the trimmed lines of a tag-value document that begin outside a
/// `<text>` ... `</text>` block, i.e. the ones that can carry a tag.
fn tag_lines(input: &str) -> impl Iterator<Item = &str> {
    scanned_lines(input)
        .filter(|&(_, tagged)| tagged)
        .map(|(line, _)| line.trim())
}

/// tags spdx-rs 0.5's tag-value parser recognizes.
const READABLE_TAGS: &[&str] = &[
    "AnnotationComment",
    "AnnotationDate",
    "AnnotationType",
    "Annotator",
    "BuiltDate",
    "Created",
    "Creator",
    "CreatorComment",
    "DataLicense",
    "DocumentComment",
    "DocumentName",
    "DocumentNamespace",
    "ExternalDocumentRef",
    "ExternalRef",
    "ExternalRefComment",
    "ExtractedText",
    "FileAttributionText",
    "FileChecksum",
    "FileComment",
    "FileContributor",
    "FileCopyrightText",
    "FileName",
    "FileNotice",
    "FileType",
    "FilesAnalyzed",
    "LicenseComment",
    "LicenseComments",
    "LicenseConcluded",
    "LicenseCrossReference",
    "LicenseID",
    "LicenseInfoInFile",
    "LicenseInfoInSnippet",
    "LicenseListVersion",
    "LicenseName",
    "PackageAttributionText",
    "PackageChecksum",
    "PackageComment",
    "PackageCopyrightText",
    "PackageDescription",
    "PackageDownloadLocation",
    "PackageFileName",
    "PackageHomePage",
    "PackageLicenseComments",
    "PackageLicenseConcluded",
    "PackageLicenseDeclared",
    "PackageLicenseInfoFromFiles",
    "PackageName",
    "PackageOriginator",
    "PackageSourceInfo",
    "PackageSummary",
    "PackageSupplier",
    "PackageVerificationCode",
    "PackageVersion",
    "PrimaryPackagePurpose",
    "Relationship",
    "RelationshipComment",
    "ReleaseDate",
    "SPDXID",
    "SPDXREF",
    "SPDXVersion",
    "SnippetAttributionText",
    "SnippetByteRange",
    "SnippetComment",
    "SnippetCopyrightText",
    "SnippetFromFileSPDXID",
    "SnippetLicenseComments",
    "SnippetLicenseConcluded",
    "SnippetLineRange",
    "SnippetName",
    "SnippetSPDXID",
    "ValidUntilDate",
];

/// checksum algorithms spdx-rs 0.5 recognizes.
const CHECKSUM_ALGORITHMS: &[&str] = &[
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

/// `ExternalRef` categories spdx-rs 0.5 recognizes.
const EXTERNAL_REF_CATEGORIES: &[&str] = &["SECURITY", "PACKAGE-MANAGER", "PERSISTENT-ID", "OTHER"];

/// `FileType` values spdx-rs 0.5 recognizes.
const FILE_TYPES: &[&str] = &[
    "SOURCE",
    "BINARY",
    "ARCHIVE",
    "APPLICATION",
    "AUDIO",
    "IMAGE",
    "TEXT",
    "VIDEO",
    "DOCUMENTATION",
    "SPDX",
    "OTHER",
];

/// `AnnotationType` values spdx-rs 0.5 recognizes.
const ANNOTATION_TYPES: &[&str] = &["REVIEW", "OTHER"];

/// tags whose value spdx-rs 0.5 parses as an SPDX license expression and unwraps.
const LICENSE_EXPRESSION_TAGS: &[&str] = &[
    "LicenseConcluded",
    "LicenseInfoInFile",
    "PackageLicenseConcluded",
    "PackageLicenseDeclared",
    "SnippetLicenseConcluded",
];

/// `Relationship` types spdx-rs 0.5 recognizes.
const RELATIONSHIP_TYPES: &[&str] = &[
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
    "SPECIFICATION_FOR",
    "REQUIREMENT_DESCRIPTION_FOR",
    "OTHER",
];

/// shortens a line for a diagnostic.
fn elide(text: &str) -> String {
    let text = text.trim();
    match text.char_indices().nth(60) {
        Some((at, _)) => format!("{}...", &text[..at]),
        None => text.to_string(),
    }
}

/// reports why spdx-rs 0.5 cannot read a line that begins outside a `<text>`
/// block, or `None` if it can. `beside` and `below` describe the `<text>`
/// blocks spdx-rs would read as this line's value.
fn unreadable_line(line: &str, beside: Option<bool>, below: Option<bool>) -> Option<String> {
    let line = line.trim_start();
    if line.trim_end().is_empty() || line.starts_with('#') || line.starts_with("<text>") {
        return None;
    }

    // spdx-rs reads the tag with nom's `alphanumeric0`, then demands a colon.
    let tag_len = line
        .find(|c: char| !c.is_ascii_alphanumeric())
        .unwrap_or(line.len());
    let (tag, rest) = line.split_at(tag_len);
    let value = (!tag.is_empty())
        .then(|| rest.trim_start().strip_prefix(':'))
        .flatten();
    let Some(value) = value else {
        return Some(format!("'{}' is not a tag-value pair", elide(line)));
    };
    if !READABLE_TAGS.contains(&tag) {
        return Some(format!("tag '{tag}' is not one spdx-rs 0.5 can read"));
    }

    let value = value.trim_start();
    if LICENSE_EXPRESSION_TAGS.contains(&tag) {
        return empty_license_expression(value, beside, below)
            .then(|| format!("tag '{tag}': the license expression is empty"));
    }
    // a `<text>` value can run past this line, so its content is not ours to judge.
    if value.contains("<text>") {
        return None;
    }
    unreadable_value(tag, value).map(|reason| format!("tag '{tag}': {reason}"))
}

/// whether spdx-rs 0.5 will parse a license tag's value as the empty
/// expression it unwraps a parse error on.
fn empty_license_expression(value: &str, beside: Option<bool>, below: Option<bool>) -> bool {
    if value.starts_with("<text>") {
        return beside.unwrap_or(false);
    }
    value.trim_end().is_empty() && below.unwrap_or(true)
}

/// reports why spdx-rs 0.5 panics on a known tag's value, or `None`. Values
/// it rejects with an error instead are left to the truncation check.
fn unreadable_value(tag: &str, value: &str) -> Option<String> {
    match tag {
        "PackageChecksum" | "FileChecksum" => unreadable_checksum(value),
        "ExternalDocumentRef" => value
            .split_once(char::is_whitespace)
            .and_then(|(_, rest)| rest.trim_start().split_once(char::is_whitespace))
            .and_then(|(_, checksum)| unreadable_checksum(checksum.trim_start())),
        "ExternalRef" => {
            let category = value.split_whitespace().next().unwrap_or_default();
            (!EXTERNAL_REF_CATEGORIES.contains(&category))
                .then(|| format!("'{category}' is not an external reference category"))
        }
        "Relationship" => {
            let kind = value
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_uppercase();
            (!RELATIONSHIP_TYPES.contains(&kind.as_str()))
                .then(|| format!("'{kind}' is not a relationship type"))
        }
        "FileType" => {
            (!FILE_TYPES.contains(&value)).then(|| format!("'{value}' is not a file type"))
        }
        "AnnotationType" => (!ANNOTATION_TYPES.contains(&value))
            .then(|| format!("'{value}' is not an annotation type")),
        _ => None,
    }
}

/// reports why spdx-rs 0.5 cannot read a checksum value, or `None` if it can.
fn unreadable_checksum(value: &str) -> Option<String> {
    let Some((algorithm, _)) = value.split_once(':') else {
        return Some(format!("checksum '{}' names no algorithm", elide(value)));
    };
    (!CHECKSUM_ALGORITHMS.contains(&algorithm))
        .then(|| format!("'{algorithm}' is not a checksum algorithm"))
}

/// the `<text>` blocks a tag's value runs into: per line, whether the block
/// opening beside the tag is blank, and whether the one an empty value
/// continues into below the tag is blank. `None` where there is no such block;
/// a block spdx-rs never closes is not one, matching [`scanned_lines`].
fn text_blocks(input: &str) -> (Vec<Option<bool>>, Vec<Option<bool>>) {
    let lines: Vec<&str> = input.lines().collect();
    let mut beside = vec![None; lines.len()];
    let mut at_head = vec![false; lines.len()];
    let mut open_at: Option<(usize, bool)> = None;
    for (number, line) in lines.iter().enumerate() {
        match open_at {
            Some((at, blank)) => match line.split_once("</text>") {
                Some((content, _)) => {
                    beside[at] = Some(blank && content.trim().is_empty());
                    open_at = None;
                }
                None => open_at = Some((at, blank && line.trim().is_empty())),
            },
            None => {
                let head = line.trim_start();
                let open = match head.strip_prefix("<text>") {
                    Some(open) => {
                        at_head[number] = true;
                        Some(open)
                    }
                    None => head
                        .split_once(':')
                        .and_then(|(_, value)| value.trim_start().strip_prefix("<text>")),
                };
                let Some(open) = open else { continue };
                match open.split_once("</text>") {
                    Some((content, _)) => beside[number] = Some(content.trim().is_empty()),
                    None => open_at = Some((number, open.trim().is_empty())),
                }
            }
        }
    }
    let mut below = vec![None; lines.len()];
    let mut carry = None;
    for number in (0..lines.len()).rev() {
        if at_head[number] {
            carry = beside[number];
        } else if !lines[number].trim().is_empty() {
            carry = None;
        }
        below[number] = carry;
    }
    (beside, below)
}

/// drops the lines spdx-rs 0.5 would panic on or stop at, returning the
/// remaining document and one diagnostic per dropped line.
fn filter_unreadable_lines(input: &str) -> (String, Vec<String>) {
    let mut kept = String::with_capacity(input.len());
    let mut dropped = Vec::new();
    let mut in_dropped_block = false;
    let mut value_below_dropped = false;
    let (beside, below) = text_blocks(input);
    for (number, (line, tagged)) in scanned_lines(input).enumerate() {
        if tagged && value_below_dropped {
            value_below_dropped = line.trim().is_empty();
        } else if tagged {
            let beside = beside.get(number).copied().flatten();
            let below = below.get(number + 1).copied().flatten();
            in_dropped_block = match unreadable_line(line, beside, below) {
                Some(reason) => {
                    dropped.push(format!("line {}: {reason}", number + 1));
                    value_below_dropped = below.is_some()
                        && line
                            .split_once(':')
                            .is_some_and(|(_, v)| v.trim().is_empty());
                    true
                }
                None => false,
            };
        }
        if !in_dropped_block {
            kept.push_str(line);
            kept.push('\n');
        }
    }
    (kept, dropped)
}

/// joins diagnostics, keeping a warning bounded on a badly broken document.
fn joined(reasons: &[String]) -> String {
    const SHOWN: usize = 5;
    let mut out = reasons
        .iter()
        .take(SHOWN)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("; ");
    if let Some(rest) = reasons.len().checked_sub(SHOWN).filter(|n| *n > 0) {
        out.push_str(&format!("; and {rest} more"));
    }
    out
}

/// parser for SPDX documents.
///
/// converts SPDX 2.x JSON, XML, and tag-value input into the format-agnostic
/// [`Sbom`] type.
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

        // strip a leading UTF-8 BOM; serde_json does not skip it.
        let buf = buf.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&buf);

        Self::check_spdx_version(buf)?;

        let spdx_doc: spdx_rs::models::SPDX = serde_json::from_slice(buf)?;

        Ok(Self::spdx_to_sbom(spdx_doc))
    }

    /// parses an SPDX XML document from a reader.
    ///
    /// accepts both `<Document>` and `<SpdxDocument>` as the root element.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sbom_model_spdx::SpdxReader;
    /// use std::fs::File;
    ///
    /// let file = File::open("sbom.spdx.xml").unwrap();
    /// let sbom = SpdxReader::read_xml(file).unwrap();
    /// ```
    pub fn read_xml<R: Read>(mut reader: R) -> Result<Sbom, Error> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;

        let buf = buf.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&buf);

        let value = xml::xml_to_json(buf)?;
        Self::check_version(value.get("spdxVersion").and_then(|v| v.as_str()))?;

        let spdx_doc: spdx_rs::models::SPDX = serde_json::from_value(value)?;

        Ok(Self::spdx_to_sbom(spdx_doc))
    }

    /// parses an SPDX tag-value document from a reader.
    ///
    /// lines the underlying parser cannot read — an unknown tag, a line that
    /// is not a tag-value pair — are dropped and named in [`Sbom::warnings`].
    /// a document the parser still cut short is reported as an error rather
    /// than returned as a partial SBOM.
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

        // strip a leading BOM; str::trim() (used by the SPDXVersion pre-check) does not treat U+FEFF as whitespace.
        let input = input.strip_prefix('\u{feff}').unwrap_or(input);

        Self::check_spdx_version_tag_value(input)?;

        // spdx-rs 0.5 panics on an unknown tag and discards everything below a line it cannot read.
        let (input, unreadable) = filter_unreadable_lines(input);
        let input = input.as_str();

        // spdx-rs 0.5 has two further tag-value parsing quirks we work around:
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
        for line in tag_lines(input) {
            if line.starts_with("PackageName:") {
                last_pkg_has_ext_ref = false;
            } else if line.starts_with("ExternalRef:") {
                last_pkg_has_ext_ref = true;
            }
        }

        let mut spdx_doc =
            spdx_from_tag_value(&patched).map_err(|e| Error::TagValue(e.to_string()))?;

        // the sentinel is the document's last package, so its absence means the
        // parser stopped somewhere above it.
        let reached_end = spdx_doc
            .package_information
            .iter()
            .any(|p| p.package_name == "__spdx_rs_flush_sentinel__");
        spdx_doc
            .package_information
            .retain(|p| p.package_name != "__spdx_rs_flush_sentinel__");

        let raw_packages: Vec<&str> = tag_lines(input)
            .filter_map(|line| line.strip_prefix("PackageName:").map(str::trim))
            .collect();
        let read = spdx_doc.package_information.len();
        if read < raw_packages.len() {
            return Err(Error::TagValue(format!(
                "the parser stopped early and read only {read} of the document's {} packages: \
                 '{}' and everything below it was lost. a tag above it carries a value the \
                 parser cannot read",
                raw_packages.len(),
                raw_packages[read],
            )));
        }
        if !reached_end {
            return Err(Error::TagValue(format!(
                "the parser stopped early: all {read} packages were read, but the document \
                 below the last one was not. a tag there carries a value the parser cannot read"
            )));
        }

        // quirk 1: creator contamination.
        let parsed_creators = spdx_doc
            .document_creation_information
            .creation_info
            .creators
            .clone();
        let actual_creators: Vec<String> = tag_lines(input)
            .filter_map(|line| line.strip_prefix("Creator:").map(|v| v.trim().to_string()))
            .collect();
        spdx_doc
            .document_creation_information
            .creation_info
            .creators = actual_creators.clone();

        let mut sbom = Self::spdx_to_sbom(spdx_doc);

        // emit diagnostics for workarounds that fired.
        if !unreadable.is_empty() {
            sbom.warnings.push(format!(
                "SPDX: dropped {} unreadable line(s) that would otherwise have truncated the \
                 document: {}",
                unreadable.len(),
                joined(&unreadable)
            ));
        }

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

            // NOASSERTION/NONE are "unknown supplier" sentinels, not supplier names.
            let supplier = pkg
                .package_supplier
                .clone()
                .filter(|s| s != "NOASSERTION" && s != "NONE")
                .map(|s| {
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
                license_expression: None,
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
                let l = l.to_string();
                comp.licenses.extend(parse_license_expression(&l));
                comp.license_expression = Some(l);
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

        Self::check_version(probe.spdx_version.as_deref())
    }

    /// rejects any spec version outside SPDX 2.x; a missing version is left to
    /// the full parser, which errors on the malformed document anyway.
    fn check_version(version: Option<&str>) -> Result<(), Error> {
        match version {
            Some(v) if v.starts_with("SPDX-2.") => Ok(()),
            Some(v) => Err(Error::UnsupportedVersion {
                version: v.to_string(),
            }),
            None => Ok(()),
        }
    }

    /// pre-check the `SPDXVersion` tag in a tag-value document.
    ///
    /// scans for the first `SPDXVersion:` tag and rejects non-2.x versions.
    /// also rejects input that has no `SPDXVersion:` at all, since the
    /// spdx-rs tag-value parser is permissive enough to "parse" arbitrary
    /// text files without error.
    fn check_spdx_version_tag_value(input: &str) -> Result<(), Error> {
        for line in tag_lines(input) {
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
    fn test_noassertion_supplier_filtered() {
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
                    "name": "noassertion-pkg",
                    "SPDXID": "SPDXRef-noassertion",
                    "downloadLocation": "NONE",
                    "supplier": "NOASSERTION"
                },
                {
                    "name": "none-pkg",
                    "SPDXID": "SPDXRef-none",
                    "downloadLocation": "NONE",
                    "supplier": "NONE"
                },
                {
                    "name": "org-pkg",
                    "SPDXID": "SPDXRef-org",
                    "downloadLocation": "NONE",
                    "supplier": "Organization: Acme Corp"
                },
                {
                    "name": "person-pkg",
                    "SPDXID": "SPDXRef-person",
                    "downloadLocation": "NONE",
                    "supplier": "Person: alice"
                }
            ],
            "relationships": []
        }"#;
        let sbom = SpdxReader::read_json(json.as_bytes()).unwrap();

        let find = |name: &str| sbom.components.values().find(|c| c.name == name).unwrap();

        assert_eq!(find("noassertion-pkg").supplier, None);
        assert_eq!(find("none-pkg").supplier, None);
        assert_eq!(
            find("org-pkg").supplier,
            Some("Acme Corp".to_string()),
            "a real Organization supplier must still parse"
        );
        assert_eq!(
            find("person-pkg").supplier,
            Some("alice".to_string()),
            "a real Person supplier must still parse"
        );
    }

    #[test]
    fn test_noassertion_supplier_does_not_change_component_id() {
        let doc = |supplier_line: &str| {
            format!(
                r#"{{
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "test",
                "documentNamespace": "http://spdx.org/spdxdocs/test",
                "creationInfo": {{
                    "creators": ["Tool: manual"],
                    "created": "2023-01-01T00:00:00Z"
                }},
                "packages": [
                    {{
                        "name": "pkg-a",
                        "SPDXID": "SPDXRef-pkg-a",
                        "versionInfo": "1.0.0",
                        "downloadLocation": "NONE"{supplier_line}
                    }}
                ],
                "relationships": []
            }}"#
            )
        };

        // no purl, so the id is the property hash — supplier is one of the inputs.
        let absent = SpdxReader::read_json(doc("").as_bytes()).unwrap();
        let sentinel =
            SpdxReader::read_json(doc(",\n\"supplier\": \"NOASSERTION\"").as_bytes()).unwrap();
        let real = SpdxReader::read_json(doc(",\n\"supplier\": \"Organization: Acme\"").as_bytes())
            .unwrap();

        assert!(absent.components[0].id.as_str().starts_with("h:"));
        assert_eq!(absent.components[0].id, sentinel.components[0].id);
        assert_ne!(absent.components[0].id, real.components[0].id);
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
        // spdx preserves the canonical id (GPL-3.0-only), not the deprecated
        // short form (GPL-3.0)
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
    fn test_read_tag_value_version_in_document_comment_ignored() {
        let tv = "\
DocumentComment: <text>this file claims:
SPDXVersion: SPDX-9.9
</text>
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
";
        let sbom = SpdxReader::read_tag_value(tv.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.components[0].name, "pkg-a");
    }

    #[test]
    fn test_read_tag_value_version_only_inside_text_block_rejected() {
        let tv = "\
DocumentComment: <text>this file claims:
SPDXVersion: SPDX-2.3
</text>
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: test
DocumentNamespace: http://spdx.org/spdxdocs/test
Creator: Tool: manual
Created: 2023-01-01T00:00:00Z
";
        let err = SpdxReader::read_tag_value(tv.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("no SPDXVersion tag found"));
    }

    #[test]
    fn test_read_tag_value_text_mentioned_in_value_is_not_a_block() {
        let tv = "\
DocumentComment: see <text> for details
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
";
        let sbom = SpdxReader::read_tag_value(tv.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.components[0].name, "pkg-a");
        assert_eq!(sbom.metadata.tools, vec!["manual"]);
    }

    #[test]
    fn test_tag_value_creator_in_next_line_text_block_is_not_a_creator() {
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
PackageDescription:
<text>this package says:
Creator: Tool: sneaky
</text>
";
        let sbom = SpdxReader::read_tag_value(tv.as_bytes()).unwrap();
        assert_eq!(sbom.metadata.tools, vec!["manual"]);
    }

    #[test]
    fn test_read_tag_value_text_mention_keeps_creators() {
        let tv = "\
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: how to use <text> markers
DocumentNamespace: http://spdx.org/spdxdocs/test
Creator: Tool: the-real-tool
Creator: Organization: acme
Created: 2023-01-01T00:00:00Z

PackageName: pkg-a
SPDXID: SPDXRef-pkg-a
PackageVersion: 1.0.0
PackageDownloadLocation: NOASSERTION
";
        let sbom = SpdxReader::read_tag_value(tv.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.metadata.tools, vec!["the-real-tool"]);
        assert_eq!(sbom.metadata.authors, vec!["Organization: acme"]);
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

    const TV_HEADER: &str = "\
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

    #[test]
    fn test_tag_value_creator_inside_text_block_is_not_a_creator() {
        let tv = format!(
            "{TV_HEADER}PackageDescription: <text>quotes a document header:
Creator: Tool: not-a-real-tool
</text>
"
        );
        let sbom = SpdxReader::read_tag_value(tv.as_bytes()).unwrap();

        assert_eq!(sbom.metadata.tools, vec!["manual"]);
        assert!(sbom.metadata.authors.is_empty());
    }

    #[test]
    fn test_tag_value_text_block_does_not_mask_phantom_creator() {
        let quoted = format!(
            "{TV_HEADER}PackageDescription: <text>quotes a document header:
Creator: Tool: LicenseFind-1.0
</text>
"
        );
        let control = SpdxReader::read_tag_value(TV_HEADER.as_bytes()).unwrap();
        let sbom = SpdxReader::read_tag_value(quoted.as_bytes()).unwrap();

        assert_eq!(sbom.warnings, control.warnings);
    }

    #[test]
    fn test_tag_value_external_ref_inside_text_block_does_not_warn() {
        let tv = format!(
            "{TV_HEADER}PackageComment: <text>documented like so:
ExternalRef: PACKAGE-MANAGER purl pkg:cargo/nope@0.0.0
</text>
"
        );
        let sbom = SpdxReader::read_tag_value(tv.as_bytes()).unwrap();

        assert!(sbom.components[0].purl.is_none());
        assert!(
            !sbom.warnings.iter().any(|w| w.contains("flush-sentinel")),
            "quoted ExternalRef should not trip the flush-sentinel warning: {:?}",
            sbom.warnings
        );
    }

    #[test]
    fn test_tag_value_package_name_inside_text_block_still_warns() {
        let tv = format!(
            "{TV_HEADER}ExternalRef: PACKAGE-MANAGER purl pkg:cargo/pkg-a@1.0.0
PackageComment: <text>see also:
PackageName: some-other-thing
</text>
"
        );
        let sbom = SpdxReader::read_tag_value(tv.as_bytes()).unwrap();

        assert_eq!(
            sbom.components[0].purl,
            Some("pkg:cargo/pkg-a@1.0.0".to_string())
        );
        assert!(
            sbom.warnings.iter().any(|w| w.contains("flush-sentinel")),
            "quoted PackageName should not mask the flush-sentinel warning: {:?}",
            sbom.warnings
        );
    }

    #[test]
    fn test_read_tag_value_unterminated_text_block_keeps_creators() {
        let tv = "\
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: test
DocumentNamespace: http://spdx.org/spdxdocs/test
DocumentComment: <text>never closed
Creator: Tool: syft-1.2.3
Created: 2023-01-01T00:00:00Z

PackageName: pkg-a
SPDXID: SPDXRef-pkg-a
PackageVersion: 1.0.0
PackageDownloadLocation: NOASSERTION
ExternalRef: PACKAGE-MANAGER purl pkg:cargo/pkg-a@1.0.0
";
        let sbom = SpdxReader::read_tag_value(tv.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.metadata.tools, vec!["syft-1.2.3".to_string()]);
        assert!(
            !sbom.warnings.iter().any(|w| w.contains("syft-1.2.3")),
            "a real creator must not be reported as a phantom: {:?}",
            sbom.warnings
        );
        assert!(
            sbom.warnings.iter().any(|w| w.contains("flush-sentinel")),
            "the flush-sentinel diagnostic must survive an unterminated block: {:?}",
            sbom.warnings
        );
    }

    #[test]
    fn test_read_tag_value_version_below_unterminated_text_block_is_read() {
        let tv = "\
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: test
DocumentNamespace: http://spdx.org/spdxdocs/test
DocumentComment: <text>never closed
SPDXVersion: SPDX-2.3
Creator: Tool: syft-1.2.3
Created: 2023-01-01T00:00:00Z

PackageName: pkg-a
SPDXID: SPDXRef-pkg-a
PackageDownloadLocation: NOASSERTION
";
        let sbom = SpdxReader::read_tag_value(tv.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.metadata.tools, vec!["syft-1.2.3".to_string()]);
    }

    #[test]
    fn test_read_tag_value_closed_block_does_not_open_a_later_unterminated_one() {
        let tv = "\
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: test
DocumentNamespace: http://spdx.org/spdxdocs/test
DocumentComment: <text>quoted
Creator: Tool: sneaky
</text>
DocumentComment: <text>never closed
Creator: Tool: real
Created: 2023-01-01T00:00:00Z

PackageName: pkg-a
SPDXID: SPDXRef-pkg-a
PackageDownloadLocation: NOASSERTION
";
        let sbom = SpdxReader::read_tag_value(tv.as_bytes()).unwrap();
        assert_eq!(sbom.metadata.tools, vec!["real".to_string()]);
    }

    #[test]
    fn test_tag_lines_skips_text_blocks() {
        let input = "\
A: 1
B: <text>one</text>
C: <text>open
D: 2
</text>
E: 3
F: <text>trailing</text> G: 4
J: mentions <text> mid-value
K: 4
L: <text>open again
no colon in here
</text>
M:
<text>value on its own line
N: 5
</text>
O: 6
H: <text>runs to eof
I: 5
";
        assert_eq!(
            tag_lines(input).collect::<Vec<_>>(),
            vec![
                "A: 1",
                "B: <text>one</text>",
                "C: <text>open",
                "E: 3",
                "F: <text>trailing</text> G: 4",
                "J: mentions <text> mid-value",
                "K: 4",
                "L: <text>open again",
                "M:",
                "<text>value on its own line",
                "O: 6",
                "H: <text>runs to eof",
                "I: 5",
            ]
        );
    }

    /// a two-package document with `middle` spliced between the packages.
    fn tag_value_around(middle: &str) -> String {
        format!(
            "\
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: test
DocumentNamespace: http://spdx.org/spdxdocs/test
Creator: Tool: test-generator
Created: 2024-01-01T00:00:00Z

PackageName: alpha
SPDXID: SPDXRef-alpha
PackageVersion: 1.0.0
PackageDownloadLocation: NOASSERTION
{middle}

PackageName: omega
SPDXID: SPDXRef-omega
PackageVersion: 2.0.0
PackageDownloadLocation: NOASSERTION
"
        )
    }

    fn component_names(sbom: &Sbom) -> Vec<String> {
        let mut names: Vec<String> = sbom.components.values().map(|c| c.name.clone()).collect();
        names.sort();
        names
    }

    fn dropped_warning(sbom: &Sbom) -> String {
        sbom.warnings
            .iter()
            .find(|w| w.contains("unreadable line"))
            .unwrap_or_else(|| panic!("expected a dropped-line warning: {:?}", sbom.warnings))
            .clone()
    }

    /// every unreadable line keeps the document whole and says what it cost.
    fn assert_line_dropped(middle: &str, mentions: &str) {
        let tv = tag_value_around(middle);
        let sbom = SpdxReader::read_tag_value(tv.as_bytes()).unwrap();
        assert_eq!(component_names(&sbom), vec!["alpha", "omega"]);
        let warning = dropped_warning(&sbom);
        assert!(
            warning.contains(mentions),
            "warning should name {mentions}: {warning}"
        );
    }

    #[test]
    fn test_tag_value_line_without_a_tag_does_not_truncate() {
        assert_line_dropped("this line has no colon", "this line has no colon");
    }

    #[test]
    fn test_tag_value_non_alphanumeric_tag_does_not_truncate() {
        assert_line_dropped("Package-Name: beta", "Package-Name: beta");
    }

    #[test]
    fn test_tag_value_valueless_line_does_not_truncate() {
        assert_line_dropped(": orphaned value", ": orphaned value");
    }

    #[test]
    fn test_tag_value_unknown_tag_does_not_panic() {
        assert_line_dropped("PackageBuiltDate: 2024-01-01T00:00:00Z", "PackageBuiltDate");
    }

    #[test]
    fn test_tag_value_unknown_external_ref_category_does_not_panic() {
        assert_line_dropped("ExternalRef: bogus", "'bogus' is not an external reference");
    }

    #[test]
    fn test_tag_value_unknown_checksum_algorithm_does_not_panic() {
        assert_line_dropped(
            "PackageChecksum: NOTANALGO: abcdef",
            "'NOTANALGO' is not a checksum algorithm",
        );
    }

    #[test]
    fn test_tag_value_checksum_without_an_algorithm_does_not_truncate() {
        assert_line_dropped("PackageChecksum: NOTANALGO abcdef", "names no algorithm");
    }

    #[test]
    fn test_tag_value_unknown_relationship_type_does_not_panic() {
        assert_line_dropped(
            "Relationship: SPDXRef-alpha SPONSORS SPDXRef-omega",
            "'SPONSORS' is not a relationship type",
        );
    }

    #[test]
    fn test_tag_value_unknown_file_type_does_not_panic() {
        assert_line_dropped("FileType: NOTATYPE", "'NOTATYPE' is not a file type");
    }

    #[test]
    fn test_tag_value_file_type_with_trailing_space_does_not_panic() {
        assert_line_dropped("FileType: SOURCE ", "'SOURCE ' is not a file type");
    }

    #[test]
    fn test_tag_value_unknown_annotation_type_does_not_panic() {
        assert_line_dropped(
            "AnnotationType: PRAISE",
            "'PRAISE' is not an annotation type",
        );
    }

    #[test]
    fn test_tag_value_unknown_external_document_ref_checksum_does_not_panic() {
        assert_line_dropped(
            "ExternalDocumentRef: DocumentRef-x http://x NOTANALGO: abcdef",
            "'NOTANALGO' is not a checksum algorithm",
        );
    }

    #[test]
    fn test_tag_value_clean_document_drops_nothing() {
        let tv = tag_value_around("PackageComment: fine");
        let sbom = SpdxReader::read_tag_value(tv.as_bytes()).unwrap();
        assert_eq!(component_names(&sbom), vec!["alpha", "omega"]);
        assert!(
            !sbom.warnings.iter().any(|w| w.contains("unreadable line")),
            "a readable document must not report dropped lines: {:?}",
            sbom.warnings
        );
    }

    #[test]
    fn test_tag_value_dropped_tag_takes_its_text_block_with_it() {
        let tv = tag_value_around("PackageBuiltDate: <text>a date\nspanning lines</text>");
        let sbom = SpdxReader::read_tag_value(tv.as_bytes()).unwrap();
        assert_eq!(component_names(&sbom), vec!["alpha", "omega"]);
        let warning = dropped_warning(&sbom);
        assert!(
            warning.starts_with("SPDX: dropped 1 unreadable line(s)"),
            "the block's interior is part of the one dropped tag: {warning}"
        );
    }

    #[test]
    fn test_tag_value_text_block_interior_is_never_a_tag_line() {
        let tv =
            tag_value_around("PackageComment: <text>this line has no colon\nnor does this</text>");
        let sbom = SpdxReader::read_tag_value(tv.as_bytes()).unwrap();
        assert_eq!(component_names(&sbom), vec!["alpha", "omega"]);
        assert!(
            !sbom.warnings.iter().any(|w| w.contains("unreadable line")),
            "a text block's interior is a value, not a tag line: {:?}",
            sbom.warnings
        );
    }

    #[test]
    fn test_tag_value_value_on_its_own_line_survives() {
        let tv = tag_value_around("PackageComment:\n<text>a value below its tag</text>");
        let sbom = SpdxReader::read_tag_value(tv.as_bytes()).unwrap();
        assert_eq!(component_names(&sbom), vec!["alpha", "omega"]);
        assert!(
            !sbom.warnings.iter().any(|w| w.contains("unreadable line")),
            "a `<text>` value below its tag is not an unreadable line: {:?}",
            sbom.warnings
        );
    }

    #[test]
    fn test_tag_value_several_unreadable_lines_are_all_disclosed() {
        let tv = tag_value_around("no colon here\nPackageBuiltDate: 2024-01-01T00:00:00Z");
        let sbom = SpdxReader::read_tag_value(tv.as_bytes()).unwrap();
        assert_eq!(component_names(&sbom), vec!["alpha", "omega"]);
        let warning = dropped_warning(&sbom);
        assert!(
            warning.starts_with("SPDX: dropped 2 unreadable line(s)"),
            "{warning}"
        );
        assert!(
            warning.contains("line 13:") && warning.contains("line 14:"),
            "{warning}"
        );
    }

    #[test]
    fn test_tag_value_residual_truncation_is_an_error_not_a_partial_sbom() {
        let tv = tag_value_around("SnippetByteRange: not-a-range");
        let err = SpdxReader::read_tag_value(tv.as_bytes()).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("read only 1 of the document's 2 packages"),
            "{message}"
        );
        assert!(message.contains("'omega'"), "{message}");
    }

    #[test]
    fn test_tag_value_truncation_below_the_last_package_is_an_error() {
        let tv = format!(
            "{}SnippetByteRange: not-a-range\n",
            tag_value_around("PackageComment: fine")
        );
        let err = SpdxReader::read_tag_value(tv.as_bytes()).unwrap_err();
        let message = err.to_string();
        assert!(
            message
                .contains("all 2 packages were read, but the document below the last one was not"),
            "{message}"
        );
    }

    /// a value each mirrored tag's own parser accepts.
    fn sample_tag_value(tag: &str) -> &'static str {
        match tag {
            "SPDXVersion" => "SPDX-2.3",
            "Created" | "AnnotationDate" | "BuiltDate" | "ReleaseDate" | "ValidUntilDate" => {
                "2024-01-01T00:00:00Z"
            }
            "ExternalDocumentRef" => {
                "DocumentRef-other http://spdx.org/other SHA1: d6a770ba38583ed4bb4525bd96e50461655d2758"
            }
            "PackageChecksum" | "FileChecksum" => {
                "SHA1: d6a770ba38583ed4bb4525bd96e50461655d2758"
            }
            "ExternalRef" => "PACKAGE-MANAGER purl pkg:cargo/alpha@1.0.0",
            "Relationship" => "SPDXRef-alpha DEPENDS_ON SPDXRef-omega",
            "FileType" => "SOURCE",
            "AnnotationType" => "REVIEW",
            "SnippetByteRange" | "SnippetLineRange" => "1:2",
            "FilesAnalyzed" => "false",
            "PackageLicenseConcluded"
            | "PackageLicenseDeclared"
            | "PackageLicenseInfoFromFiles"
            | "LicenseConcluded"
            | "LicenseInfoInFile"
            | "LicenseInfoInSnippet"
            | "SnippetLicenseConcluded" => "MIT",
            _ => "value",
        }
    }

    #[test]
    fn test_every_mirrored_tag_is_one_spdx_rs_can_read() {
        for tag in READABLE_TAGS {
            // a second PackageName would start a package rather than annotate one.
            if *tag == "PackageName" {
                continue;
            }
            let line = format!("{tag}: {}", sample_tag_value(tag));
            let tv = tag_value_around(&line);
            let sbom = SpdxReader::read_tag_value(tv.as_bytes())
                .unwrap_or_else(|e| panic!("'{line}' should be readable: {e}"));
            assert!(
                !sbom.warnings.iter().any(|w| w.contains("unreadable line")),
                "'{line}' should not be dropped: {:?}",
                sbom.warnings
            );
            assert!(
                sbom.components.values().any(|c| c.name == "omega"),
                "'{line}' should not cost the document its tail"
            );
        }
    }

    /// the `SpdxExpression::parse(value).unwrap()` sites in spdx-rs 0.5
    /// `parsers/mod.rs`, named here rather than read from the mirror.
    const EXPRESSION_UNWRAP_SITES: &[&str] = &[
        "LicenseConcluded",
        "LicenseInfoInFile",
        "PackageLicenseConcluded",
        "PackageLicenseDeclared",
        "SnippetLicenseConcluded",
    ];

    /// the section a license tag must sit in for spdx-rs to reach its unwrap.
    fn section_opening(tag: &str) -> &'static str {
        match tag {
            "LicenseConcluded" | "LicenseInfoInFile" => {
                "FileName: ./src/main.rs\nSPDXID: SPDXRef-file\n"
            }
            "SnippetLicenseConcluded" => {
                "FileName: ./src/main.rs\nSPDXID: SPDXRef-file\nSnippetSPDXID: SPDXRef-snippet\nSnippetFromFileSPDXID: SPDXRef-file\n"
            }
            _ => "",
        }
    }

    #[test]
    fn test_tag_value_empty_license_expression_is_dropped_not_panicked() {
        for tag in EXPRESSION_UNWRAP_SITES {
            for value in ["", " ", "   \t  "] {
                let tv = tag_value_around(&format!("{}{tag}:{value}", section_opening(tag)));
                let sbom = SpdxReader::read_tag_value(tv.as_bytes())
                    .unwrap_or_else(|e| panic!("'{tag}:{value}' should be readable: {e}"));
                assert_eq!(component_names(&sbom), vec!["alpha", "omega"]);
                let warning = dropped_warning(&sbom);
                assert!(
                    warning.contains(&format!("tag '{tag}': the license expression is empty")),
                    "'{tag}:{value}': {warning}"
                );
            }
        }
    }

    #[test]
    fn test_tag_value_license_expression_that_parses_is_kept() {
        for tag in EXPRESSION_UNWRAP_SITES {
            for value in ["MIT", "MIT OR Apache-2.0", "NOASSERTION", "NONE"] {
                let tv = tag_value_around(&format!("{}{tag}: {value}", section_opening(tag)));
                let sbom = SpdxReader::read_tag_value(tv.as_bytes())
                    .unwrap_or_else(|e| panic!("'{tag}: {value}' should be readable: {e}"));
                assert_eq!(component_names(&sbom), vec!["alpha", "omega"]);
                assert!(
                    !sbom.warnings.iter().any(|w| w.contains("unreadable line")),
                    "'{tag}: {value}' should not be dropped: {:?}",
                    sbom.warnings
                );
            }
        }
    }

    #[test]
    fn test_tag_value_license_expression_below_its_tag_is_not_the_empty_one() {
        for tag in EXPRESSION_UNWRAP_SITES {
            for gap in ["", "\n", "\n\n"] {
                let tv = tag_value_around(&format!(
                    "{}{tag}:{gap}\n<text>MIT</text>",
                    section_opening(tag)
                ));
                let sbom = SpdxReader::read_tag_value(tv.as_bytes())
                    .unwrap_or_else(|e| panic!("'{tag}' with a value below it: {e}"));
                assert_eq!(component_names(&sbom), vec!["alpha", "omega"]);
                assert!(
                    !sbom.warnings.iter().any(|w| w.contains("unreadable line")),
                    "'{tag}' with a value below it should not be dropped: {:?}",
                    sbom.warnings
                );
            }
        }
    }

    #[test]
    fn test_tag_value_empty_license_expression_in_a_text_block_is_dropped_not_panicked() {
        for tag in EXPRESSION_UNWRAP_SITES {
            for spelling in [
                format!("{tag}: <text></text>"),
                format!("{tag}: <text>   </text>"),
                format!("{tag}:\n<text></text>"),
                format!("{tag}:\n\n<text>\n \n</text>"),
                format!("{tag}: <text>\n</text>"),
                format!("{tag}: <text>\n   \n</text>"),
            ] {
                let tv = tag_value_around(&format!("{}{spelling}", section_opening(tag)));
                let sbom = SpdxReader::read_tag_value(tv.as_bytes())
                    .unwrap_or_else(|e| panic!("{spelling:?} should be readable: {e}"));
                assert_eq!(component_names(&sbom), vec!["alpha", "omega"]);
                let warning = dropped_warning(&sbom);
                assert!(
                    warning.contains(&format!("tag '{tag}': the license expression is empty")),
                    "{spelling:?}: {warning}"
                );
            }
        }
    }

    #[test]
    fn test_tag_value_license_expression_in_a_text_block_is_kept() {
        for tag in EXPRESSION_UNWRAP_SITES {
            for spelling in [
                format!("{tag}: <text>MIT</text>"),
                format!("{tag}:\n<text>MIT</text>"),
                format!("{tag}:\n<text>\nMIT\n</text>"),
                format!("{tag}: <text>\nMIT\n</text>"),
            ] {
                let tv = tag_value_around(&format!("{}{spelling}", section_opening(tag)));
                let sbom = SpdxReader::read_tag_value(tv.as_bytes())
                    .unwrap_or_else(|e| panic!("{spelling:?} should be readable: {e}"));
                assert_eq!(component_names(&sbom), vec!["alpha", "omega"]);
                assert!(
                    !sbom.warnings.iter().any(|w| w.contains("unreadable line")),
                    "{spelling:?} should not be dropped: {:?}",
                    sbom.warnings
                );
            }
        }
    }

    #[test]
    fn test_tag_value_empty_text_block_on_a_tag_with_no_expression_is_kept() {
        for spelling in [
            "PackageComment: <text></text>",
            "PackageComment:\n<text></text>",
        ] {
            let sbom = SpdxReader::read_tag_value(tag_value_around(spelling).as_bytes())
                .unwrap_or_else(|e| panic!("{spelling:?} should be readable: {e}"));
            assert_eq!(component_names(&sbom), vec!["alpha", "omega"]);
            assert!(
                !sbom.warnings.iter().any(|w| w.contains("unreadable line")),
                "{spelling:?} should not be dropped: {:?}",
                sbom.warnings
            );
        }
    }

    #[test]
    fn test_tag_value_empty_value_on_an_enum_tag_is_still_dropped_by_name() {
        for (tag, mentions) in [
            ("FileType", "'' is not a file type"),
            ("AnnotationType", "'' is not an annotation type"),
            ("ExternalRef", "'' is not an external reference category"),
        ] {
            assert_line_dropped(&format!("{tag}:"), mentions);
        }
    }

    #[test]
    fn test_mirrored_license_expression_tags_are_readable_tags() {
        assert_eq!(LICENSE_EXPRESSION_TAGS, EXPRESSION_UNWRAP_SITES);
        for tag in LICENSE_EXPRESSION_TAGS {
            assert!(READABLE_TAGS.contains(tag), "{tag}");
        }
    }

    #[test]
    fn test_mirrored_tags_are_sorted_and_unique() {
        let mut sorted = READABLE_TAGS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, READABLE_TAGS);
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

    #[test]
    fn test_read_json_with_bom() {
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
        let mut with_bom = vec![0xef, 0xbb, 0xbf]; // UTF-8 BOM
        with_bom.extend_from_slice(json.as_bytes());
        let sbom = SpdxReader::read_json(with_bom.as_slice()).unwrap();
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.components[0].name, "pkg-a");
    }

    #[test]
    fn test_read_tag_value_with_bom() {
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
        let with_bom = format!("\u{feff}{tv}");
        let sbom = SpdxReader::read_tag_value(with_bom.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.components[0].name, "pkg-a");
        assert_eq!(sbom.components[0].version, Some("1.0.0".to_string()));
    }

    /// asserts that the XML and JSON serializations of the same document map to
    /// the same [`Sbom`].
    fn assert_xml_matches_json(xml: &str, json: &str) {
        let from_xml = SpdxReader::read_xml(xml.as_bytes()).unwrap();
        let from_json = SpdxReader::read_json(json.as_bytes()).unwrap();
        assert_eq!(from_xml, from_json);
    }

    #[test]
    fn test_read_xml_single_package_matches_json() {
        assert_xml_matches_json(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<Document>
  <spdxVersion>SPDX-2.3</spdxVersion>
  <dataLicense>CC0-1.0</dataLicense>
  <SPDXID>SPDXRef-DOCUMENT</SPDXID>
  <name>test</name>
  <documentNamespace>http://spdx.org/spdxdocs/test</documentNamespace>
  <creationInfo>
    <creators>Tool: manual</creators>
    <created>2023-01-01T00:00:00Z</created>
  </creationInfo>
  <packages>
    <name>pkg-a</name>
    <SPDXID>SPDXRef-pkg-a</SPDXID>
    <versionInfo>1.0.0</versionInfo>
    <downloadLocation>NOASSERTION</downloadLocation>
    <licenseConcluded>MIT</licenseConcluded>
    <externalRefs>
      <referenceCategory>PACKAGE-MANAGER</referenceCategory>
      <referenceType>purl</referenceType>
      <referenceLocator>pkg:npm/pkg-a@1.0.0</referenceLocator>
    </externalRefs>
  </packages>
</Document>"#,
            r#"{
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
                        "versionInfo": "1.0.0",
                        "downloadLocation": "NOASSERTION",
                        "licenseConcluded": "MIT",
                        "externalRefs": [
                            {
                                "referenceCategory": "PACKAGE-MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": "pkg:npm/pkg-a@1.0.0"
                            }
                        ]
                    }
                ]
            }"#,
        );
    }

    #[test]
    fn test_read_xml_single_package_extracts_purl_and_license() {
        let xml = r#"<Document>
  <spdxVersion>SPDX-2.3</spdxVersion>
  <dataLicense>CC0-1.0</dataLicense>
  <SPDXID>SPDXRef-DOCUMENT</SPDXID>
  <name>test</name>
  <documentNamespace>http://spdx.org/spdxdocs/test</documentNamespace>
  <creationInfo>
    <creators>Tool: manual</creators>
    <created>2023-01-01T00:00:00Z</created>
  </creationInfo>
  <packages>
    <name>pkg-a</name>
    <SPDXID>SPDXRef-pkg-a</SPDXID>
    <versionInfo>1.0.0</versionInfo>
    <downloadLocation>NOASSERTION</downloadLocation>
    <licenseConcluded>MIT</licenseConcluded>
    <supplier>Organization: acme</supplier>
    <externalRefs>
      <referenceCategory>PACKAGE-MANAGER</referenceCategory>
      <referenceType>purl</referenceType>
      <referenceLocator>pkg:npm/pkg-a@1.0.0</referenceLocator>
    </externalRefs>
  </packages>
</Document>"#;
        let sbom = SpdxReader::read_xml(xml.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 1);
        let comp = &sbom.components[0];
        assert_eq!(comp.name, "pkg-a");
        assert_eq!(comp.version, Some("1.0.0".to_string()));
        assert_eq!(comp.purl, Some("pkg:npm/pkg-a@1.0.0".to_string()));
        assert_eq!(comp.ecosystem, Some("npm".to_string()));
        assert_eq!(comp.supplier, Some("acme".to_string()));
        assert!(comp.licenses.contains("MIT"));
        assert_eq!(sbom.metadata.tools, vec!["manual"]);
    }

    #[test]
    fn test_read_xml_multiple_packages_and_checksums_match_json() {
        assert_xml_matches_json(
            r#"<Document>
  <spdxVersion>SPDX-2.3</spdxVersion>
  <dataLicense>CC0-1.0</dataLicense>
  <SPDXID>SPDXRef-DOCUMENT</SPDXID>
  <name>test</name>
  <documentNamespace>http://spdx.org/spdxdocs/test</documentNamespace>
  <creationInfo>
    <creators>Tool: manual</creators>
    <creators>Person: bob</creators>
    <created>2023-01-01T00:00:00Z</created>
  </creationInfo>
  <packages>
    <name>pkg-a</name>
    <SPDXID>SPDXRef-pkg-a</SPDXID>
    <downloadLocation>NONE</downloadLocation>
    <filesAnalyzed>false</filesAnalyzed>
    <licenseConcluded>MIT</licenseConcluded>
    <checksums>
      <algorithm>SHA256</algorithm>
      <checksumValue>abc</checksumValue>
    </checksums>
    <checksums>
      <algorithm>SHA1</algorithm>
      <checksumValue>def</checksumValue>
    </checksums>
  </packages>
  <packages>
    <name>pkg-b</name>
    <SPDXID>SPDXRef-pkg-b</SPDXID>
    <downloadLocation>NONE</downloadLocation>
    <filesAnalyzed>true</filesAnalyzed>
    <checksums>
      <algorithm>SHA256</algorithm>
      <checksumValue>012</checksumValue>
    </checksums>
  </packages>
  <relationships>
    <spdxElementId>SPDXRef-pkg-a</spdxElementId>
    <relatedSpdxElement>SPDXRef-pkg-b</relatedSpdxElement>
    <relationshipType>DEPENDS_ON</relationshipType>
  </relationships>
</Document>"#,
            r#"{
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
                        "filesAnalyzed": false,
                        "licenseConcluded": "MIT",
                        "checksums": [
                            {"algorithm": "SHA256", "checksumValue": "abc"},
                            {"algorithm": "SHA1", "checksumValue": "def"}
                        ]
                    },
                    {
                        "name": "pkg-b",
                        "SPDXID": "SPDXRef-pkg-b",
                        "downloadLocation": "NONE",
                        "filesAnalyzed": true,
                        "checksums": [{"algorithm": "SHA256", "checksumValue": "012"}]
                    }
                ],
                "relationships": [
                    {
                        "spdxElementId": "SPDXRef-pkg-a",
                        "relatedSpdxElement": "SPDXRef-pkg-b",
                        "relationshipType": "DEPENDS_ON"
                    }
                ]
            }"#,
        );
    }

    #[test]
    fn test_read_xml_dependency_edges_and_hashes() {
        let xml = r#"<Document>
  <spdxVersion>SPDX-2.3</spdxVersion>
  <dataLicense>CC0-1.0</dataLicense>
  <SPDXID>SPDXRef-DOCUMENT</SPDXID>
  <name>test</name>
  <documentNamespace>http://spdx.org/spdxdocs/test</documentNamespace>
  <creationInfo>
    <creators>Tool: manual</creators>
    <created>2023-01-01T00:00:00Z</created>
  </creationInfo>
  <packages>
    <name>pkg-a</name>
    <SPDXID>SPDXRef-pkg-a</SPDXID>
    <downloadLocation>NONE</downloadLocation>
    <checksums>
      <algorithm>SHA256</algorithm>
      <checksumValue>abc</checksumValue>
    </checksums>
  </packages>
  <packages>
    <name>pkg-b</name>
    <SPDXID>SPDXRef-pkg-b</SPDXID>
    <downloadLocation>NONE</downloadLocation>
  </packages>
  <relationships>
    <spdxElementId>SPDXRef-pkg-a</spdxElementId>
    <relatedSpdxElement>SPDXRef-pkg-b</relatedSpdxElement>
    <relationshipType>DEPENDS_ON</relationshipType>
  </relationships>
</Document>"#;
        let sbom = SpdxReader::read_xml(xml.as_bytes()).unwrap();
        assert_eq!(sbom.components.len(), 2);
        let a = sbom.components.keys().next().unwrap().clone();
        assert_eq!(
            sbom.components[&a].hashes.get("SHA-256"),
            Some(&"abc".to_string())
        );
        assert_eq!(sbom.dependencies[&a].len(), 1);
    }

    #[test]
    fn test_read_xml_inverse_relationship_matches_forward() {
        let doc = |left: &str, right: &str, rel: &str| {
            format!(
                r#"<Document>
  <spdxVersion>SPDX-2.3</spdxVersion>
  <dataLicense>CC0-1.0</dataLicense>
  <SPDXID>SPDXRef-DOCUMENT</SPDXID>
  <name>test</name>
  <documentNamespace>http://spdx.org/spdxdocs/test</documentNamespace>
  <creationInfo>
    <creators>Tool: manual</creators>
    <created>2023-01-01T00:00:00Z</created>
  </creationInfo>
  <packages>
    <name>pkg-a</name>
    <SPDXID>SPDXRef-pkg-a</SPDXID>
    <downloadLocation>NONE</downloadLocation>
  </packages>
  <packages>
    <name>pkg-b</name>
    <SPDXID>SPDXRef-pkg-b</SPDXID>
    <downloadLocation>NONE</downloadLocation>
  </packages>
  <relationships>
    <spdxElementId>{left}</spdxElementId>
    <relatedSpdxElement>{right}</relatedSpdxElement>
    <relationshipType>{rel}</relationshipType>
  </relationships>
</Document>"#
            )
        };

        let forward =
            SpdxReader::read_xml(doc("SPDXRef-pkg-a", "SPDXRef-pkg-b", "DEPENDS_ON").as_bytes())
                .unwrap();
        let inverse =
            SpdxReader::read_xml(doc("SPDXRef-pkg-b", "SPDXRef-pkg-a", "DEPENDENCY_OF").as_bytes())
                .unwrap();
        assert_eq!(forward.dependencies, inverse.dependencies);
        assert!(!forward.dependencies.is_empty());
    }

    #[test]
    fn test_read_xml_escaped_entities_match_json() {
        assert_xml_matches_json(
            r#"<Document>
  <spdxVersion>SPDX-2.3</spdxVersion>
  <dataLicense>CC0-1.0</dataLicense>
  <SPDXID>SPDXRef-DOCUMENT</SPDXID>
  <name>a &amp; b</name>
  <documentNamespace>http://spdx.org/spdxdocs/test</documentNamespace>
  <creationInfo>
    <creators>Tool: man &lt;ual&gt;</creators>
    <created>2023-01-01T00:00:00Z</created>
  </creationInfo>
  <packages>
    <name>pkg &amp; co</name>
    <SPDXID>SPDXRef-pkg-a</SPDXID>
    <downloadLocation>NONE</downloadLocation>
    <licenseConcluded>MIT AND Apache-2.0</licenseConcluded>
    <supplier>Organization: acme &amp; sons</supplier>
  </packages>
</Document>"#,
            r#"{
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "a & b",
                "documentNamespace": "http://spdx.org/spdxdocs/test",
                "creationInfo": {
                    "creators": ["Tool: man <ual>"],
                    "created": "2023-01-01T00:00:00Z"
                },
                "packages": [
                    {
                        "name": "pkg & co",
                        "SPDXID": "SPDXRef-pkg-a",
                        "downloadLocation": "NONE",
                        "licenseConcluded": "MIT AND Apache-2.0",
                        "supplier": "Organization: acme & sons"
                    }
                ]
            }"#,
        );
    }

    #[test]
    fn test_read_xml_without_packages_matches_json() {
        assert_xml_matches_json(
            r#"<Document>
  <spdxVersion>SPDX-2.3</spdxVersion>
  <dataLicense>CC0-1.0</dataLicense>
  <SPDXID>SPDXRef-DOCUMENT</SPDXID>
  <name>test</name>
  <documentNamespace>http://spdx.org/spdxdocs/test</documentNamespace>
  <creationInfo>
    <creators>Tool: manual</creators>
    <created>2023-01-01T00:00:00Z</created>
  </creationInfo>
  <packages/>
</Document>"#,
            r#"{
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "test",
                "documentNamespace": "http://spdx.org/spdxdocs/test",
                "creationInfo": {
                    "creators": ["Tool: manual"],
                    "created": "2023-01-01T00:00:00Z"
                },
                "packages": []
            }"#,
        );
    }

    #[test]
    fn test_read_xml_spdxdocument_root_matches_document_root() {
        let body = r#"
  <spdxVersion>SPDX-2.3</spdxVersion>
  <dataLicense>CC0-1.0</dataLicense>
  <SPDXID>SPDXRef-DOCUMENT</SPDXID>
  <name>test</name>
  <documentNamespace>http://spdx.org/spdxdocs/test</documentNamespace>
  <creationInfo>
    <creators>Tool: manual</creators>
    <created>2023-01-01T00:00:00Z</created>
  </creationInfo>
  <packages>
    <name>pkg-a</name>
    <SPDXID>SPDXRef-pkg-a</SPDXID>
    <downloadLocation>NONE</downloadLocation>
  </packages>"#;
        let document = SpdxReader::read_xml(format!("<Document>{body}</Document>").as_bytes());
        let spdx_document =
            SpdxReader::read_xml(format!("<SpdxDocument>{body}</SpdxDocument>").as_bytes());
        assert_eq!(document.unwrap(), spdx_document.unwrap());
    }

    #[test]
    fn test_read_xml_version_3_rejected() {
        let xml = r#"<Document>
  <spdxVersion>SPDX-3.0</spdxVersion>
  <dataLicense>CC0-1.0</dataLicense>
  <SPDXID>SPDXRef-DOCUMENT</SPDXID>
  <name>test</name>
  <documentNamespace>http://spdx.org/spdxdocs/test</documentNamespace>
</Document>"#;
        let err = SpdxReader::read_xml(xml.as_bytes()).unwrap_err();
        assert!(matches!(err, Error::UnsupportedVersion { ref version } if version == "SPDX-3.0"));
        assert!(err.to_string().contains("only SPDX 2.x is supported"));
    }

    #[test]
    fn test_read_xml_malformed_rejected() {
        let err = SpdxReader::read_xml(b"<Document><name>test</Document>".as_ref()).unwrap_err();
        assert!(matches!(err, Error::Xml(_)), "got {err}");
    }

    #[test]
    fn test_read_xml_non_spdx_root_rejected() {
        let xml = r#"<bom xmlns="http://cyclonedx.org/schema/bom/1.4"><components/></bom>"#;
        let err = SpdxReader::read_xml(xml.as_bytes()).unwrap_err();
        assert!(
            err.to_string().contains("unexpected root element 'bom'"),
            "got {err}"
        );
    }

    #[test]
    fn test_read_xml_missing_required_field_rejected() {
        let xml = r#"<Document>
  <spdxVersion>SPDX-2.3</spdxVersion>
  <dataLicense>CC0-1.0</dataLicense>
  <SPDXID>SPDXRef-DOCUMENT</SPDXID>
</Document>"#;
        let err = SpdxReader::read_xml(xml.as_bytes()).unwrap_err();
        assert!(matches!(err, Error::Parse(_)), "got {err}");
    }

    #[test]
    fn test_read_xml_with_bom() {
        let xml = r#"<Document>
  <spdxVersion>SPDX-2.3</spdxVersion>
  <dataLicense>CC0-1.0</dataLicense>
  <SPDXID>SPDXRef-DOCUMENT</SPDXID>
  <name>test</name>
  <documentNamespace>http://spdx.org/spdxdocs/test</documentNamespace>
  <creationInfo>
    <creators>Tool: manual</creators>
    <created>2023-01-01T00:00:00Z</created>
  </creationInfo>
  <packages>
    <name>pkg-a</name>
    <SPDXID>SPDXRef-pkg-a</SPDXID>
    <downloadLocation>NONE</downloadLocation>
  </packages>
</Document>"#;
        let with_bom = format!("\u{feff}{xml}");
        assert_eq!(
            SpdxReader::read_xml(with_bom.as_bytes()).unwrap(),
            SpdxReader::read_xml(xml.as_bytes()).unwrap()
        );
    }

    #[test]
    fn test_read_xml_fixture_matches_json_fixture() {
        let xml = std::fs::read("../../tests/fixtures/old.spdx.xml").unwrap();
        let json = std::fs::read("../../tests/fixtures/old.spdx.json").unwrap();
        assert_eq!(
            SpdxReader::read_xml(&xml[..]).unwrap(),
            SpdxReader::read_json(&json[..]).unwrap()
        );
    }

    #[test]
    fn test_license_expression_is_preserved() {
        let json = br#"{
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "http://example.com/test",
            "creationInfo": { "creators": ["Tool: test"], "created": "2024-01-01T00:00:00Z" },
            "packages": [
                {
                    "name": "dual",
                    "SPDXID": "SPDXRef-dual",
                    "downloadLocation": "NOASSERTION",
                    "licenseConcluded": "MIT OR GPL-3.0-only"
                },
                {
                    "name": "with-exception",
                    "SPDXID": "SPDXRef-with-exception",
                    "downloadLocation": "NOASSERTION",
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "GPL-2.0-only WITH Classpath-exception-2.0"
                },
                {
                    "name": "unlicensed",
                    "SPDXID": "SPDXRef-unlicensed",
                    "downloadLocation": "NOASSERTION",
                    "licenseConcluded": "NOASSERTION"
                }
            ]
        }"#;

        let sbom = SpdxReader::read_json(&json[..]).unwrap();
        let find = |name: &str| {
            sbom.components
                .values()
                .find(|c| c.name == name)
                .unwrap_or_else(|| panic!("{name} missing"))
        };

        assert_eq!(
            find("dual").license_expression.as_deref(),
            Some("MIT OR GPL-3.0-only")
        );
        assert_eq!(
            find("with-exception").license_expression.as_deref(),
            Some("GPL-2.0-only WITH Classpath-exception-2.0")
        );
        assert_eq!(
            find("with-exception").licenses,
            BTreeSet::from(["GPL-2.0-only".to_string()])
        );
        assert_eq!(find("unlicensed").license_expression, None);
    }
}
