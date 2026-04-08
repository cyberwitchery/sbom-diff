use sbom_diff::{
    renderer::{MarkdownRenderer, Renderer, TextRenderer},
    Differ,
};
use sbom_model::Sbom;
use sbom_model_cyclonedx::CycloneDxReader;
use sbom_model_spdx::SpdxReader;
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
        .render(&diff, &mut out)
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
        .render(&diff, &mut out)
        .expect("markdown renderer should succeed");

    let actual = String::from_utf8(out).expect("renderer should emit utf-8");
    let expected = fs::read_to_string(fixture_path("golden-markdown.md"))
        .expect("golden markdown snapshot should exist");

    assert_eq!(actual, expected);
}

// SPDX golden fixture tests — mirror the CycloneDX golden tests above.
// The format-agnostic model should produce identical diffs regardless of
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
        .render(&diff, &mut out)
        .expect("text renderer should succeed");

    let actual = String::from_utf8(out).expect("renderer should emit utf-8");
    let expected = fs::read_to_string(fixture_path("golden-text.txt"))
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
        .render(&diff, &mut out)
        .expect("markdown renderer should succeed");

    let actual = String::from_utf8(out).expect("renderer should emit utf-8");
    let expected = fs::read_to_string(fixture_path("golden-markdown.md"))
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
        .render(&diff, &mut out)
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
        .render(&diff, &mut out)
        .expect("markdown renderer should succeed");

    let actual = String::from_utf8(out).expect("renderer should emit utf-8");
    let expected = fs::read_to_string(fixture_path("golden-markdown.md"))
        .expect("golden markdown snapshot should exist");

    assert_eq!(actual, expected);
}
