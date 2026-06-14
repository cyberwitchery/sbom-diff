use sbom_diff::{
    renderer::{MarkdownRenderer, RenderOptions, Renderer, TextRenderer},
    Differ,
};
use sbom_model::Sbom;
use sbom_model_cyclonedx::CycloneDxReader;
use sbom_model_spdx::SpdxReader;
use std::collections::BTreeMap;
use std::fs;

fn fixture_path(name: &str) -> String {
    format!(
        "{}/../../tests/fixtures/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    )
}

fn load_cyclonedx_fixture(name: &str) -> Sbom {
    let bytes = fs::read(fixture_path(name)).expect("fixture should be readable");
    CycloneDxReader::read_json(bytes.as_slice()).expect("fixture should parse")
}

fn load_spdx_fixture(name: &str) -> Sbom {
    let bytes = fs::read(fixture_path(name)).expect("fixture should be readable");
    SpdxReader::read_json(bytes.as_slice()).expect("fixture should parse")
}

fn load_cyclonedx_xml_fixture(name: &str) -> Sbom {
    let bytes = fs::read(fixture_path(name)).expect("fixture should be readable");
    CycloneDxReader::read_xml(&bytes).expect("fixture should parse")
}

#[test]
fn fixture_missing_hashes_detects_added_component_without_hashes() {
    let old = load_cyclonedx_fixture("missing-hashes-old.json");
    let new = load_cyclonedx_fixture("missing-hashes-new.json");

    let diff = Differ::diff(&old, &new, None);

    assert_eq!(diff.added.len(), 1);
    assert!(diff.added[0].hashes.is_empty());
}

#[test]
fn fixture_purl_less_components_reconcile_as_change() {
    let old = load_cyclonedx_fixture("purl-less-old.json");
    let new = load_cyclonedx_fixture("purl-less-new.json");

    let diff = Differ::diff(&old, &new, None);

    assert_eq!(diff.added.len(), 0);
    assert_eq!(diff.removed.len(), 0);
    assert_eq!(diff.changed.len(), 1);
}

#[test]
fn fixture_license_order_variation_is_noop() {
    let old = load_cyclonedx_fixture("license-order-old.json");
    let new = load_cyclonedx_fixture("license-order-new.json");

    let diff = Differ::diff(&old, &new, None);

    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
    assert!(diff.changed.is_empty());
    assert!(diff.edge_diffs.is_empty());
}

#[test]
fn fixture_dependency_edge_changes_are_detected() {
    let old = load_cyclonedx_fixture("edge-change-old.json");
    let new = load_cyclonedx_fixture("edge-change-new.json");

    let diff = Differ::diff(&old, &new, None);

    assert_eq!(diff.edge_diffs.len(), 1);
    assert_eq!(diff.edge_diffs[0].added.len(), 1);
    assert_eq!(diff.edge_diffs[0].removed.len(), 1);
}

#[test]
fn text_renderer_golden_output_matches_fixture() {
    let old = load_cyclonedx_fixture("golden-old.json");
    let new = load_cyclonedx_fixture("golden-new.json");

    let diff = Differ::diff(&old, &new, None);

    let mut out = Vec::new();
    TextRenderer
        .render(&diff, &RenderOptions::default(), &mut out)
        .expect("text renderer should succeed");

    let actual = String::from_utf8(out).expect("renderer should emit utf-8");
    let expected = fs::read_to_string(fixture_path("golden-text.txt"))
        .expect("golden text snapshot should exist");

    assert_eq!(actual, expected);
}

#[test]
fn markdown_renderer_golden_output_matches_fixture() {
    let old = load_cyclonedx_fixture("golden-old.json");
    let new = load_cyclonedx_fixture("golden-new.json");

    let diff = Differ::diff(&old, &new, None);

    let mut out = Vec::new();
    MarkdownRenderer
        .render(&diff, &RenderOptions::default(), &mut out)
        .expect("markdown renderer should succeed");

    let actual = String::from_utf8(out).expect("renderer should emit utf-8");
    let expected = fs::read_to_string(fixture_path("golden-markdown.md"))
        .expect("golden markdown snapshot should exist");

    assert_eq!(actual, expected);
}

// SPDX golden fixture tests — mirror the CycloneDX golden tests above.
// the format-agnostic model should produce identical diffs regardless of
// input format, so we reuse the same expected output snapshots.

#[test]
fn spdx_fixture_diff_matches_cyclonedx_diff() {
    let spdx_old = load_spdx_fixture("golden-old.spdx.json");
    let spdx_new = load_spdx_fixture("golden-new.spdx.json");
    let cdx_old = load_cyclonedx_fixture("golden-old.json");
    let cdx_new = load_cyclonedx_fixture("golden-new.json");

    let spdx_diff = Differ::diff(&spdx_old, &spdx_new, None);
    let cdx_diff = Differ::diff(&cdx_old, &cdx_new, None);

    assert_eq!(spdx_diff.added.len(), cdx_diff.added.len());
    assert_eq!(spdx_diff.removed.len(), cdx_diff.removed.len());
    assert_eq!(spdx_diff.changed.len(), cdx_diff.changed.len());
    assert_eq!(spdx_diff.edge_diffs.len(), cdx_diff.edge_diffs.len());
}

#[test]
fn spdx_text_renderer_golden_output_matches_fixture() {
    let old = load_spdx_fixture("golden-old.spdx.json");
    let new = load_spdx_fixture("golden-new.spdx.json");

    let diff = Differ::diff(&old, &new, None);

    let mut out = Vec::new();
    TextRenderer
        .render(&diff, &RenderOptions::default(), &mut out)
        .expect("text renderer should succeed");

    let actual = String::from_utf8(out).expect("renderer should emit utf-8");
    let expected = fs::read_to_string(fixture_path("golden-text-spdx.txt"))
        .expect("golden text snapshot should exist");

    assert_eq!(actual, expected);
}

#[test]
fn spdx_markdown_renderer_golden_output_matches_fixture() {
    let old = load_spdx_fixture("golden-old.spdx.json");
    let new = load_spdx_fixture("golden-new.spdx.json");

    let diff = Differ::diff(&old, &new, None);

    let mut out = Vec::new();
    MarkdownRenderer
        .render(&diff, &RenderOptions::default(), &mut out)
        .expect("markdown renderer should succeed");

    let actual = String::from_utf8(out).expect("renderer should emit utf-8");
    let expected = fs::read_to_string(fixture_path("golden-markdown-spdx.md"))
        .expect("golden markdown snapshot should exist");

    assert_eq!(actual, expected);
}

// CycloneDX XML golden fixture tests

#[test]
fn cyclonedx_xml_fixture_diff_matches_json_diff() {
    let xml_old = load_cyclonedx_xml_fixture("golden-old.cdx.xml");
    let xml_new = load_cyclonedx_xml_fixture("golden-new.cdx.xml");
    let json_old = load_cyclonedx_fixture("golden-old.json");
    let json_new = load_cyclonedx_fixture("golden-new.json");

    let xml_diff = Differ::diff(&xml_old, &xml_new, None);
    let json_diff = Differ::diff(&json_old, &json_new, None);

    assert_eq!(xml_diff.added.len(), json_diff.added.len());
    assert_eq!(xml_diff.removed.len(), json_diff.removed.len());
    assert_eq!(xml_diff.changed.len(), json_diff.changed.len());
    assert_eq!(xml_diff.edge_diffs.len(), json_diff.edge_diffs.len());
}

#[test]
fn cyclonedx_xml_text_renderer_golden_output_matches_fixture() {
    let old = load_cyclonedx_xml_fixture("golden-old.cdx.xml");
    let new = load_cyclonedx_xml_fixture("golden-new.cdx.xml");

    let diff = Differ::diff(&old, &new, None);

    let mut out = Vec::new();
    TextRenderer
        .render(&diff, &RenderOptions::default(), &mut out)
        .expect("text renderer should succeed");

    let actual = String::from_utf8(out).expect("renderer should emit utf-8");
    let expected = fs::read_to_string(fixture_path("golden-text.txt"))
        .expect("golden text snapshot should exist");

    assert_eq!(actual, expected);
}

#[test]
fn cyclonedx_xml_markdown_renderer_golden_output_matches_fixture() {
    let old = load_cyclonedx_xml_fixture("golden-old.cdx.xml");
    let new = load_cyclonedx_xml_fixture("golden-new.cdx.xml");

    let diff = Differ::diff(&old, &new, None);

    let mut out = Vec::new();
    MarkdownRenderer
        .render(&diff, &RenderOptions::default(), &mut out)
        .expect("markdown renderer should succeed");

    let actual = String::from_utf8(out).expect("renderer should emit utf-8");
    let expected = fs::read_to_string(fixture_path("golden-markdown.md"))
        .expect("golden markdown snapshot should exist");

    assert_eq!(actual, expected);
}

// SPDX tag-value golden fixture tests

fn load_spdx_tv_fixture(name: &str) -> Sbom {
    let bytes = fs::read(fixture_path(name)).expect("fixture should be readable");
    SpdxReader::read_tag_value(bytes.as_slice()).expect("fixture should parse")
}

#[test]
fn spdx_tv_fixture_diff_matches_json_diff() {
    let tv_old = load_spdx_tv_fixture("golden-old.spdx");
    let tv_new = load_spdx_tv_fixture("golden-new.spdx");
    let json_old = load_spdx_fixture("golden-old.spdx.json");
    let json_new = load_spdx_fixture("golden-new.spdx.json");

    let tv_diff = Differ::diff(&tv_old, &tv_new, None);
    let json_diff = Differ::diff(&json_old, &json_new, None);

    assert_eq!(tv_diff.added.len(), json_diff.added.len());
    assert_eq!(tv_diff.removed.len(), json_diff.removed.len());
    assert_eq!(tv_diff.changed.len(), json_diff.changed.len());
    assert_eq!(tv_diff.edge_diffs.len(), json_diff.edge_diffs.len());
}

#[test]
fn spdx_tv_text_renderer_golden_output_matches_fixture() {
    let old = load_spdx_tv_fixture("golden-old.spdx");
    let new = load_spdx_tv_fixture("golden-new.spdx");

    let diff = Differ::diff(&old, &new, None);

    let mut out = Vec::new();
    TextRenderer
        .render(&diff, &RenderOptions::default(), &mut out)
        .expect("text renderer should succeed");

    let actual = String::from_utf8(out).expect("renderer should emit utf-8");
    let expected = fs::read_to_string(fixture_path("golden-text-spdx.txt"))
        .expect("golden text snapshot should exist");

    assert_eq!(actual, expected);
}

#[test]
fn spdx_tv_markdown_renderer_golden_output_matches_fixture() {
    let old = load_spdx_tv_fixture("golden-old.spdx");
    let new = load_spdx_tv_fixture("golden-new.spdx");

    let diff = Differ::diff(&old, &new, None);

    let mut out = Vec::new();
    MarkdownRenderer
        .render(&diff, &RenderOptions::default(), &mut out)
        .expect("markdown renderer should succeed");

    let actual = String::from_utf8(out).expect("renderer should emit utf-8");
    let expected = fs::read_to_string(fixture_path("golden-markdown-spdx.md"))
        .expect("golden markdown snapshot should exist");

    assert_eq!(actual, expected);
}

// cross-format hash normalization: identical components parsed from
// SPDX and CycloneDX should produce identical hash algorithm keys,
// so diffing them yields no hash changes.

#[test]
fn cross_format_identical_hashes_produce_no_diff() {
    let spdx_json = r#"{
        "spdxVersion": "SPDX-2.3",
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
                "downloadLocation": "NONE",
                "versionInfo": "1.0.0",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:npm/pkg-a@1.0.0"
                    }
                ],
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
                    {"algorithm": "SHA1", "checksumValue": "abcdef1234567890abcdef1234567890abcdef12"},
                    {"algorithm": "MD5", "checksumValue": "abcdef1234567890abcdef1234567890"}
                ]
            }
        ],
        "relationships": []
    }"#;

    let cdx_json = r#"{
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "pkg-a",
                "version": "1.0.0",
                "purl": "pkg:npm/pkg-a@1.0.0",
                "hashes": [
                    {"alg": "SHA-256", "content": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
                    {"alg": "SHA-1", "content": "abcdef1234567890abcdef1234567890abcdef12"},
                    {"alg": "MD5", "content": "abcdef1234567890abcdef1234567890"}
                ]
            }
        ]
    }"#;

    let spdx_sbom = SpdxReader::read_json(spdx_json.as_bytes()).unwrap();
    let cdx_sbom = CycloneDxReader::read_json(cdx_json.as_bytes()).unwrap();

    // algorithm keys must match exactly between formats
    let spdx_hashes: BTreeMap<_, _> = spdx_sbom.components[0].hashes.clone();
    let cdx_hashes: BTreeMap<_, _> = cdx_sbom.components[0].hashes.clone();
    assert_eq!(
        spdx_hashes.keys().collect::<Vec<_>>(),
        cdx_hashes.keys().collect::<Vec<_>>(),
        "hash algorithm names should be identical across SPDX and CycloneDX"
    );

    // diffing SPDX-old against CycloneDX-new should yield no changes
    let diff = Differ::diff(&spdx_sbom, &cdx_sbom, None);
    assert!(
        diff.changed.is_empty(),
        "identical components from SPDX and CycloneDX should produce no diff, but got {} changed",
        diff.changed.len()
    );
    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
}
