use super::*;
use crate::{ComponentChange, Diff, FieldChange};
use sbom_model::Component;
use std::collections::BTreeMap;

fn mock_diff() -> Diff {
    let c1 = Component::new("pkg-a".into(), Some("1.0".into()));
    let mut c2 = c1.clone();
    c2.version = Some("1.1".into());

    Diff {
        added: vec![Component::new("pkg-b".into(), Some("2.0".into()))],
        removed: vec![Component::new("pkg-c".into(), Some("3.0".into()))],
        changed: vec![ComponentChange {
            id: c2.id.clone(),
            old: c1,
            new: c2,
            changes: vec![FieldChange::Version(Some("1.0".into()), Some("1.1".into()))],
            is_downgrade: false,
        }],
        edge_diffs: vec![],
        ..Diff::default()
    }
}

fn mock_diff_all_field_changes() -> Diff {
    use sbom_model::{ComponentId, DependencyKind};

    let c1 = Component::new("pkg-a".into(), Some("1.0".into()));
    let mut c2 = c1.clone();
    c2.version = Some("1.1".into());

    Diff {
        added: vec![],
        removed: vec![],
        changed: vec![ComponentChange {
            id: c2.id.clone(),
            old: c1,
            new: c2,
            changes: vec![
                FieldChange::Version(Some("1.0".into()), Some("1.1".into())),
                FieldChange::License(
                    BTreeSet::from(["MIT".into()]),
                    BTreeSet::from(["Apache-2.0".into()]),
                ),
                FieldChange::Supplier(Some("Old Corp".into()), Some("New Corp".into())),
                FieldChange::Purl(
                    Some("pkg:npm/pkg-a@1.0".into()),
                    Some("pkg:npm/pkg-a@1.1".into()),
                ),
                FieldChange::Description(
                    Some("Old description".into()),
                    Some("New description".into()),
                ),
                FieldChange::Hashes(
                    BTreeMap::from([("sha256".into(), "aaa".into())]),
                    BTreeMap::from([("sha256".into(), "bbb".into())]),
                ),
                FieldChange::Ecosystem(Some("npm".into()), Some("cargo".into())),
            ],
            is_downgrade: false,
        }],
        edge_diffs: vec![crate::EdgeDiff {
            parent: ComponentId::new(None, &[("name", "parent")]),
            added: BTreeMap::from([(
                ComponentId::new(None, &[("name", "child-b")]),
                DependencyKind::Runtime,
            )]),
            removed: BTreeMap::from([(
                ComponentId::new(None, &[("name", "child-a")]),
                DependencyKind::Runtime,
            )]),
            kind_changed: BTreeMap::new(),
        }],
        ..Diff::default()
    }
}

fn mock_diff_empty() -> Diff {
    Diff {
        added: vec![],
        removed: vec![],
        changed: vec![],
        edge_diffs: vec![],
        ..Diff::default()
    }
}

#[test]
fn test_text_renderer() {
    let diff = mock_diff();
    let mut buf = Vec::new();
    TextRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();
    assert!(out.contains("Diff Summary"));
    assert!(out.contains("[+] Added"));
    assert!(out.contains("[-] Removed"));
    assert!(out.contains("[~] Changed"));
}

#[test]
fn test_text_renderer_all_field_changes() {
    let diff = mock_diff_all_field_changes();
    let mut buf = Vec::new();
    TextRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.contains("Version: 1.0 -> 1.1"));
    assert!(out.contains("License:"));
    assert!(out.contains("MIT"));
    assert!(out.contains("Apache-2.0"));
    assert!(out.contains("Supplier:"));
    assert!(out.contains("Old Corp"));
    assert!(out.contains("New Corp"));
    assert!(out.contains("Purl:"));
    assert!(out.contains("Description:"));
    assert!(out.contains("Old description"));
    assert!(out.contains("New description"));
    assert!(out.contains("Hashes:"));
    assert!(out.contains("~ sha256: aaa -> bbb"));
    assert!(out.contains("Ecosystem: npm -> cargo"));
    assert!(out.contains("[~] Edge Changes"));
}

#[test]
fn test_text_renderer_empty_diff() {
    let diff = mock_diff_empty();
    let mut buf = Vec::new();
    TextRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.contains("Old total:        0 components"));
    assert!(out.contains("New total:        0 components"));
    assert!(out.contains("Unchanged:        0"));
    assert!(out.contains("Added:            0"));
    assert!(out.contains("Removed:          0"));
    assert!(out.contains("Changed:          0"));
    assert!(out.contains("Edge changes:     0"));
    assert!(out.contains("Metadata changed: no"));
    assert!(!out.contains("[+] Added"));
    assert!(!out.contains("[-] Removed"));
    assert!(!out.contains("[~] Changed"));
}

#[test]
fn test_markdown_renderer() {
    let diff = mock_diff();
    let mut buf = Vec::new();
    MarkdownRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();
    assert!(out.contains("### SBOM Diff Summary"));
    assert!(out.contains("<details>"));
}

#[test]
fn test_markdown_renderer_all_field_changes() {
    let diff = mock_diff_all_field_changes();
    let mut buf = Vec::new();
    MarkdownRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.contains("**Version**"));
    assert!(out.contains("**License**"));
    assert!(out.contains("**Supplier**"));
    assert!(out.contains("**Purl**"));
    assert!(out.contains("**Description**"));
    assert!(out.contains("**Hashes**:"));
    assert!(out.contains("`sha256`: `aaa` &rarr; `bbb`"));
    assert!(out.contains("**Ecosystem**"));
    assert!(out.contains("Edge Changes"));
    assert!(out.contains("**Removed dependencies:**"));
    assert!(out.contains("**Added dependencies:**"));
}

#[test]
fn test_markdown_renderer_empty_diff() {
    let diff = mock_diff_empty();
    let mut buf = Vec::new();
    MarkdownRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.contains("| Added | 0 |"));
    assert!(!out.contains("<details>"));
}

#[test]
fn test_json_renderer() {
    let diff = mock_diff();
    let mut buf = Vec::new();
    JsonRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let _: serde_json::Value = serde_json::from_slice(&buf).unwrap();
}

#[test]
fn test_json_renderer_all_field_changes() {
    let diff = mock_diff_all_field_changes();
    let mut buf = Vec::new();
    JsonRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

    assert_eq!(val["changed"].as_array().unwrap().len(), 1);
    assert_eq!(val["changed"][0]["changes"].as_array().unwrap().len(), 7);
    assert_eq!(val["edge_diffs"].as_array().unwrap().len(), 1);
}

#[test]
fn test_json_renderer_roundtrip() {
    let diff = mock_diff_all_field_changes();
    let mut buf = Vec::new();
    JsonRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();

    let deserialized: Diff = serde_json::from_slice(&buf).unwrap();
    assert_eq!(deserialized.changed.len(), diff.changed.len());
    assert_eq!(deserialized.edge_diffs.len(), diff.edge_diffs.len());
    assert_eq!(deserialized.changed[0].changes, diff.changed[0].changes);
}

fn mock_diff_with_ecosystems() -> Diff {
    let mut added_npm = Component::new("express".into(), Some("4.18.0".into()));
    added_npm.ecosystem = Some("npm".into());
    let mut added_cargo = Component::new("serde".into(), Some("1.0.0".into()));
    added_cargo.ecosystem = Some("cargo".into());

    let mut removed = Component::new("lodash".into(), Some("4.17.21".into()));
    removed.ecosystem = Some("npm".into());

    let mut old = Component::new("react".into(), Some("17.0.0".into()));
    old.ecosystem = Some("npm".into());
    let mut new = old.clone();
    new.version = Some("18.0.0".into());

    Diff {
        added: vec![added_npm, added_cargo],
        removed: vec![removed],
        changed: vec![ComponentChange {
            id: new.id.clone(),
            old,
            new,
            changes: vec![FieldChange::Version(
                Some("17.0.0".into()),
                Some("18.0.0".into()),
            )],
            is_downgrade: false,
        }],
        edge_diffs: vec![],
        ..Diff::default()
    }
}

#[test]
fn test_text_renderer_group_by_ecosystem() {
    let diff = mock_diff_with_ecosystems();
    let opts = RenderOptions {
        group_by_ecosystem: true,
        ..Default::default()
    };
    let mut buf = Vec::new();
    TextRenderer.render(&diff, &opts, &mut buf).unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.contains("By Ecosystem"));
    assert!(out.contains("cargo: 1 added, 0 removed, 0 changed"));
    assert!(out.contains("npm: 1 added, 1 removed, 1 changed"));
}

#[test]
fn test_text_renderer_no_ecosystem_by_default() {
    let diff = mock_diff_with_ecosystems();
    let mut buf = Vec::new();
    TextRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(!out.contains("By Ecosystem"));
}

#[test]
fn test_markdown_renderer_group_by_ecosystem() {
    let diff = mock_diff_with_ecosystems();
    let opts = RenderOptions {
        group_by_ecosystem: true,
        ..Default::default()
    };
    let mut buf = Vec::new();
    MarkdownRenderer.render(&diff, &opts, &mut buf).unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.contains("#### By Ecosystem"));
    assert!(out.contains("| Ecosystem | Added | Removed | Changed |"));
    assert!(out.contains("| cargo | 1 | 0 | 0 |"));
    assert!(out.contains("| npm | 1 | 1 | 1 |"));
}

#[test]
fn test_json_renderer_group_by_ecosystem() {
    let diff = mock_diff_with_ecosystems();
    let opts = RenderOptions {
        group_by_ecosystem: true,
        ..Default::default()
    };
    let mut buf = Vec::new();
    JsonRenderer.render(&diff, &opts, &mut buf).unwrap();
    let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

    let breakdown = &val["ecosystem_breakdown"];
    assert!(breakdown.is_object());
    assert_eq!(breakdown["npm"]["added"], 1);
    assert_eq!(breakdown["npm"]["removed"], 1);
    assert_eq!(breakdown["npm"]["changed"], 1);
    assert_eq!(breakdown["cargo"]["added"], 1);
    assert_eq!(breakdown["cargo"]["removed"], 0);
}

#[test]
fn test_json_renderer_no_ecosystem_by_default() {
    let diff = mock_diff_with_ecosystems();
    let mut buf = Vec::new();
    JsonRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

    assert!(val.get("ecosystem_breakdown").is_none());
}

fn opts_with_warnings() -> RenderOptions {
    RenderOptions {
        show_warnings: true,
        old_warnings: vec!["SPDX: orphaned ref 'SPDXRef-foo'".into()],
        new_warnings: vec!["CycloneDX: unknown bom-ref 'bar'".into()],
        ..Default::default()
    }
}

#[test]
fn test_text_renderer_shows_warnings() {
    let diff = mock_diff();
    let opts = opts_with_warnings();
    let mut buf = Vec::new();
    TextRenderer.render(&diff, &opts, &mut buf).unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.contains("[!] Warnings"));
    assert!(out.contains("[old] SPDX: orphaned ref 'SPDXRef-foo'"));
    assert!(out.contains("[new] CycloneDX: unknown bom-ref 'bar'"));
}

#[test]
fn test_text_renderer_hides_warnings_by_default() {
    let diff = mock_diff();
    let mut buf = Vec::new();
    TextRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(!out.contains("[!] Warnings"));
}

#[test]
fn test_markdown_renderer_shows_warnings() {
    let diff = mock_diff();
    let opts = opts_with_warnings();
    let mut buf = Vec::new();
    MarkdownRenderer.render(&diff, &opts, &mut buf).unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.contains("<details><summary><b>Warnings (2)</b></summary>"));
    assert!(out.contains("- **old:** SPDX: orphaned ref 'SPDXRef-foo'"));
    assert!(out.contains("- **new:** CycloneDX: unknown bom-ref 'bar'"));
}

#[test]
fn test_markdown_renderer_hides_warnings_by_default() {
    let diff = mock_diff();
    let mut buf = Vec::new();
    MarkdownRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(!out.contains("Warnings"));
}

#[test]
fn test_json_renderer_shows_warnings() {
    let diff = mock_diff();
    let opts = opts_with_warnings();
    let mut buf = Vec::new();
    JsonRenderer.render(&diff, &opts, &mut buf).unwrap();
    let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

    let warnings = &val["warnings"];
    let old = warnings["old"].as_array().unwrap();
    let new = warnings["new"].as_array().unwrap();
    assert_eq!(old.len(), 1);
    assert_eq!(new.len(), 1);
    assert_eq!(old[0], "SPDX: orphaned ref 'SPDXRef-foo'");
    assert_eq!(new[0], "CycloneDX: unknown bom-ref 'bar'");
}

#[test]
fn test_json_renderer_hides_warnings_by_default() {
    let diff = mock_diff();
    let mut buf = Vec::new();
    JsonRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

    assert!(val.get("warnings").is_none());
}

#[test]
fn test_empty_warnings_not_shown() {
    let diff = mock_diff();
    let opts = RenderOptions {
        show_warnings: true,
        ..Default::default()
    };

    let mut buf = Vec::new();
    TextRenderer.render(&diff, &opts, &mut buf).unwrap();
    let out = String::from_utf8(buf).unwrap();
    assert!(!out.contains("[!] Warnings"));

    let mut buf = Vec::new();
    MarkdownRenderer.render(&diff, &opts, &mut buf).unwrap();
    let out = String::from_utf8(buf).unwrap();
    assert!(!out.contains("Warnings"));

    let mut buf = Vec::new();
    JsonRenderer.render(&diff, &opts, &mut buf).unwrap();
    let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    assert!(val.get("warnings").is_none());
}

fn mock_diff_with_hash_edge_diffs() -> Diff {
    use sbom_model::{ComponentId, DependencyKind};

    let parent_id = ComponentId::new(None, &[("name", "parent")]);
    let child_a_id = ComponentId::new(None, &[("name", "child-a")]);
    let child_b_id = ComponentId::new(None, &[("name", "child-b")]);

    let mut names = BTreeMap::new();
    names.insert(parent_id.clone(), "my-app@1.0".to_string());
    names.insert(child_a_id.clone(), "old-dep@0.1".to_string());
    names.insert(child_b_id.clone(), "new-dep@0.2".to_string());

    Diff {
        edge_diffs: vec![crate::EdgeDiff {
            parent: parent_id,
            added: BTreeMap::from([(child_b_id, DependencyKind::Runtime)]),
            removed: BTreeMap::from([(child_a_id, DependencyKind::Runtime)]),
            kind_changed: BTreeMap::new(),
        }],
        old_total: 10,
        new_total: 12,
        unchanged: 5,
        component_names: names,
        ..Diff::default()
    }
}

#[test]
fn test_text_renderer_resolves_edge_diff_names() {
    let diff = mock_diff_with_hash_edge_diffs();
    let mut buf = Vec::new();
    TextRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.contains("my-app@1.0"));
    assert!(out.contains("- old-dep@0.1"));
    assert!(out.contains("+ new-dep@0.2"));
    // should NOT contain raw hash IDs
    assert!(!out.contains("h:"));
}

#[test]
fn test_text_renderer_shows_totals() {
    let diff = mock_diff_with_hash_edge_diffs();
    let mut buf = Vec::new();
    TextRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.contains("Old total:        10 components"));
    assert!(out.contains("New total:        12 components"));
    assert!(out.contains("Unchanged:        5"));
}

#[test]
fn test_markdown_renderer_resolves_edge_diff_names() {
    let diff = mock_diff_with_hash_edge_diffs();
    let mut buf = Vec::new();
    MarkdownRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.contains("`my-app@1.0`"));
    assert!(out.contains("`old-dep@0.1`"));
    assert!(out.contains("`new-dep@0.2`"));
    assert!(!out.contains("h:"));
}

#[test]
fn test_markdown_renderer_shows_totals() {
    let diff = mock_diff_with_hash_edge_diffs();
    let mut buf = Vec::new();
    MarkdownRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.contains("| Old total | 10 |"));
    assert!(out.contains("| New total | 12 |"));
    assert!(out.contains("| Unchanged | 5 |"));
}

#[test]
fn test_json_renderer_includes_totals() {
    let diff = mock_diff_with_hash_edge_diffs();
    let mut buf = Vec::new();
    JsonRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

    assert_eq!(val["old_total"], 10);
    assert_eq!(val["new_total"], 12);
    assert_eq!(val["unchanged"], 5);
}

#[test]
fn test_json_renderer_includes_component_names() {
    let diff = mock_diff_with_hash_edge_diffs();
    let mut buf = Vec::new();
    JsonRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

    let names = &val["component_names"];
    assert!(names.is_object());
    assert!(names
        .as_object()
        .unwrap()
        .values()
        .any(|v| v == "my-app@1.0"));
}

#[test]
fn test_json_renderer_omits_empty_component_names() {
    let diff = mock_diff();
    let mut buf = Vec::new();
    JsonRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

    assert!(val.get("component_names").is_none());
}

fn mock_diff_with_metadata_change() -> Diff {
    Diff {
        metadata_changed: Some(crate::MetadataChange {
            timestamp: Some((Some("2024-01-01".into()), Some("2024-01-02".into()))),
            tools: Some((vec!["syft".into()], vec!["trivy".into()])),
            authors: None,
        }),
        ..Diff::default()
    }
}

#[test]
fn test_text_renderer_metadata_change() {
    let diff = mock_diff_with_metadata_change();
    let mut buf = Vec::new();
    TextRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.contains("[~] Metadata Changes"));
    assert!(out.contains("Timestamp: 2024-01-01 -> 2024-01-02"));
    assert!(out.contains("Tools: syft -> trivy"));
    // authors not changed, should not appear
    assert!(!out.contains("Authors:"));
}

#[test]
fn test_text_renderer_no_metadata_section_when_unchanged() {
    let diff = mock_diff_empty();
    let mut buf = Vec::new();
    TextRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(!out.contains("Metadata Changes"));
}

#[test]
fn test_markdown_renderer_metadata_change() {
    let diff = mock_diff_with_metadata_change();
    let mut buf = Vec::new();
    MarkdownRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.contains("<details><summary><b>Metadata Changes</b></summary>"));
    assert!(out.contains("**Timestamp**"));
    assert!(out.contains("`2024-01-01` &rarr; `2024-01-02`"));
    assert!(out.contains("**Tools**"));
    assert!(out.contains("`syft` &rarr; `trivy`"));
    assert!(!out.contains("**Authors**"));
    assert!(out.contains("</details>"));
}

#[test]
fn test_markdown_renderer_no_metadata_section_when_unchanged() {
    let diff = mock_diff_empty();
    let mut buf = Vec::new();
    MarkdownRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(!out.contains("Metadata Changes"));
}

#[test]
fn test_json_renderer_metadata_change() {
    let diff = mock_diff_with_metadata_change();
    let mut buf = Vec::new();
    JsonRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

    let mc = &val["metadata_changed"];
    assert!(mc.is_object());
    let ts = mc["timestamp"].as_array().unwrap();
    assert_eq!(ts[0], "2024-01-01");
    assert_eq!(ts[1], "2024-01-02");
    let tools = mc["tools"].as_array().unwrap();
    assert_eq!(tools[0], serde_json::json!(["syft"]));
    assert_eq!(tools[1], serde_json::json!(["trivy"]));
    // authors should be absent (skip_serializing_if)
    assert!(mc.get("authors").is_none());
}

#[test]
fn test_json_renderer_no_metadata_when_unchanged() {
    let diff = mock_diff_empty();
    let mut buf = Vec::new();
    JsonRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

    assert!(val.get("metadata_changed").is_none());
}

#[test]
fn test_text_summary_metadata_changed() {
    let diff = mock_diff_with_metadata_change();
    let mut buf = Vec::new();
    TextRenderer
        .render_summary(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.contains("Metadata changed: yes"));
}

#[test]
fn test_text_summary_metadata_unchanged() {
    let diff = mock_diff_empty();
    let mut buf = Vec::new();
    TextRenderer
        .render_summary(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.contains("Metadata changed: no"));
}

#[test]
fn test_markdown_summary_metadata_changed() {
    let diff = mock_diff_with_metadata_change();
    let mut buf = Vec::new();
    MarkdownRenderer
        .render_summary(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.contains("| Metadata changed | yes |"));
}

#[test]
fn test_markdown_summary_metadata_unchanged() {
    let diff = mock_diff_empty();
    let mut buf = Vec::new();
    MarkdownRenderer
        .render_summary(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.contains("| Metadata changed | no |"));
}

#[test]
fn test_json_summary_metadata_changed() {
    let diff = mock_diff_with_metadata_change();
    let mut buf = Vec::new();
    JsonRenderer
        .render_summary(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

    assert_eq!(val["metadata_changed"], true);
    let mc = &val["metadata_changes"];
    assert!(mc.is_object());
    assert!(mc["timestamp"].is_array());
}

#[test]
fn test_json_summary_metadata_unchanged() {
    let diff = mock_diff_empty();
    let mut buf = Vec::new();
    JsonRenderer
        .render_summary(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

    assert_eq!(val["metadata_changed"], false);
    assert!(val.get("metadata_changes").is_none());
}

fn sarif_parse(buf: &[u8]) -> serde_json::Value {
    serde_json::from_slice(buf).unwrap()
}

#[test]
fn test_sarif_renderer_schema_and_version() {
    let diff = mock_diff();
    let mut buf = Vec::new();
    SarifRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val = sarif_parse(&buf);

    assert_eq!(
        val["$schema"],
        "https://json.schemastore.org/sarif-2.1.0.json"
    );
    assert_eq!(val["version"], "2.1.0");
    assert!(val["runs"].is_array());
    assert_eq!(val["runs"].as_array().unwrap().len(), 1);
}

#[test]
fn test_sarif_renderer_tool_driver() {
    let diff = mock_diff_empty();
    let mut buf = Vec::new();
    SarifRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val = sarif_parse(&buf);

    let driver = &val["runs"][0]["tool"]["driver"];
    assert_eq!(driver["name"], "sbom-diff");
    assert!(driver["version"].is_string());
    assert_eq!(
        driver["informationUri"],
        "https://github.com/cyberwitchery/sbom-diff"
    );
}

#[test]
fn test_sarif_renderer_rules() {
    let diff = mock_diff_empty();
    let mut buf = Vec::new();
    SarifRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val = sarif_parse(&buf);

    let rules = val["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    assert_eq!(rules.len(), 6);

    let rule_ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
    assert_eq!(
        rule_ids,
        vec![
            "component-added",
            "component-removed",
            "component-changed",
            "dependency-changed",
            "metadata-changed",
            "parser-warning",
        ]
    );

    // check that each rule has required fields
    for rule in rules {
        assert!(rule["shortDescription"]["text"].is_string());
        assert!(rule["fullDescription"]["text"].is_string());
        assert!(rule["defaultConfiguration"]["level"].is_string());
    }
}

#[test]
fn test_sarif_renderer_empty_diff() {
    let diff = mock_diff_empty();
    let mut buf = Vec::new();
    SarifRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val = sarif_parse(&buf);

    let results = val["runs"][0]["results"].as_array().unwrap();
    assert!(results.is_empty());
}

#[test]
fn test_sarif_renderer_added_removed_changed() {
    let diff = mock_diff();
    let mut buf = Vec::new();
    SarifRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val = sarif_parse(&buf);

    let results = val["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 3); // 1 added + 1 removed + 1 changed

    let rule_ids: Vec<&str> = results
        .iter()
        .map(|r| r["ruleId"].as_str().unwrap())
        .collect();
    assert!(rule_ids.contains(&"component-added"));
    assert!(rule_ids.contains(&"component-removed"));
    assert!(rule_ids.contains(&"component-changed"));

    // added component is note level
    let added = results
        .iter()
        .find(|r| r["ruleId"] == "component-added")
        .unwrap();
    assert_eq!(added["level"], "note");
    assert!(added["message"]["text"].as_str().unwrap().contains("added"));

    // removed component is warning level
    let removed = results
        .iter()
        .find(|r| r["ruleId"] == "component-removed")
        .unwrap();
    assert_eq!(removed["level"], "warning");

    // changed component is warning level
    let changed = results
        .iter()
        .find(|r| r["ruleId"] == "component-changed")
        .unwrap();
    assert_eq!(changed["level"], "warning");
    let msg = changed["message"]["text"].as_str().unwrap();
    assert!(msg.contains("version:"));
}

#[test]
fn test_sarif_renderer_all_field_changes() {
    let diff = mock_diff_all_field_changes();
    let mut buf = Vec::new();
    SarifRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val = sarif_parse(&buf);

    let results = val["runs"][0]["results"].as_array().unwrap();

    // 1 changed component + 1 dependency-changed edge diff
    let changed = results
        .iter()
        .find(|r| r["ruleId"] == "component-changed")
        .unwrap();
    let msg = changed["message"]["text"].as_str().unwrap();
    assert!(msg.contains("version:"));
    assert!(msg.contains("license:"));
    assert!(msg.contains("supplier:"));
    assert!(msg.contains("purl:"));
    assert!(msg.contains("description:"));
    // hashes render with per-algorithm detail (algorithm name + digests), not a
    // bland "hashes changed"
    assert!(msg.contains("hashes:"));
    assert!(msg.contains("changed sha256: aaa -> bbb"));
    assert!(msg.contains("ecosystem:"));

    let dep = results
        .iter()
        .find(|r| r["ruleId"] == "dependency-changed")
        .unwrap();
    assert_eq!(dep["level"], "note");
    let dep_msg = dep["message"]["text"].as_str().unwrap();
    assert!(dep_msg.contains("Dependency changed:"));
}

fn mock_diff_hash_change(old: BTreeMap<String, String>, new: BTreeMap<String, String>) -> Diff {
    let mut c1 = Component::new("pkg-a".into(), Some("1.0".into()));
    c1.hashes = old.clone();
    let mut c2 = c1.clone();
    c2.hashes = new.clone();

    Diff {
        changed: vec![ComponentChange {
            id: c2.id.clone(),
            old: c1,
            new: c2,
            changes: vec![FieldChange::Hashes(old, new)],
            is_downgrade: false,
        }],
        ..Diff::default()
    }
}

#[test]
fn test_sarif_renderer_hash_detail() {
    // per-algorithm delta: one changed, one removed, one added.
    let diff = mock_diff_hash_change(
        BTreeMap::from([
            ("sha-256".into(), "oldsha".into()),
            ("sha-1".into(), "gone".into()),
        ]),
        BTreeMap::from([
            ("sha-256".into(), "newsha".into()),
            ("md5".into(), "fresh".into()),
        ]),
    );
    let mut buf = Vec::new();
    SarifRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val = sarif_parse(&buf);
    let results = val["runs"][0]["results"].as_array().unwrap();
    let changed = results
        .iter()
        .find(|r| r["ruleId"] == "component-changed")
        .unwrap();
    let msg = changed["message"]["text"].as_str().unwrap();

    // algorithm names and digests are present, mirroring the other renderers.
    assert!(msg.contains("changed sha-256: oldsha -> newsha"));
    assert!(msg.contains("removed sha-1=gone"));
    assert!(msg.contains("added md5=fresh"));
    // strongest algorithm unchanged (SHA-256 -> SHA-256), so not a downgrade.
    assert_eq!(changed["level"], "warning");
}

#[test]
fn test_sarif_renderer_hash_algorithm_downgrade_is_error() {
    // SHA-256 -> MD5 is a hash-algorithm downgrade and must escalate to error.
    let diff = mock_diff_hash_change(
        BTreeMap::from([("sha-256".into(), "abc".into())]),
        BTreeMap::from([("md5".into(), "def".into())]),
    );
    let mut buf = Vec::new();
    SarifRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val = sarif_parse(&buf);
    let results = val["runs"][0]["results"].as_array().unwrap();
    let changed = results
        .iter()
        .find(|r| r["ruleId"] == "component-changed")
        .unwrap();

    assert_eq!(changed["level"], "error");
    let msg = changed["message"]["text"].as_str().unwrap();
    assert!(msg.contains("algorithm downgrade"));
    assert!(msg.contains("sha-256"));
    assert!(msg.contains("md5"));
}

#[test]
fn test_sarif_renderer_rule_index() {
    let diff = mock_diff();
    let mut buf = Vec::new();
    SarifRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val = sarif_parse(&buf);

    let results = val["runs"][0]["results"].as_array().unwrap();

    // each result's ruleIndex should match its ruleId position in rules array
    for result in results {
        let rule_id = result["ruleId"].as_str().unwrap();
        let rule_index = result["ruleIndex"].as_u64().unwrap() as usize;
        let rules = val["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules[rule_index]["id"].as_str().unwrap(), rule_id);
    }
}

#[test]
fn test_sarif_renderer_metadata_change() {
    let diff = mock_diff_with_metadata_change();
    let mut buf = Vec::new();
    SarifRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val = sarif_parse(&buf);

    let results = val["runs"][0]["results"].as_array().unwrap();
    let meta = results
        .iter()
        .find(|r| r["ruleId"] == "metadata-changed")
        .unwrap();
    assert_eq!(meta["level"], "note");
    let msg = meta["message"]["text"].as_str().unwrap();
    assert!(msg.contains("timestamp:"));
    assert!(msg.contains("tools:"));
}

#[test]
fn test_sarif_renderer_no_metadata_when_unchanged() {
    let diff = mock_diff_empty();
    let mut buf = Vec::new();
    SarifRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val = sarif_parse(&buf);

    let results = val["runs"][0]["results"].as_array().unwrap();
    assert!(!results.iter().any(|r| r["ruleId"] == "metadata-changed"));
}

#[test]
fn test_sarif_renderer_summary_same_as_full() {
    let diff = mock_diff();
    let opts = RenderOptions::default();

    let mut buf_full = Vec::new();
    SarifRenderer.render(&diff, &opts, &mut buf_full).unwrap();

    let mut buf_summary = Vec::new();
    SarifRenderer
        .render_summary(&diff, &opts, &mut buf_summary)
        .unwrap();

    assert_eq!(buf_full, buf_summary);
}

#[test]
fn test_sarif_renderer_edge_diffs_with_names() {
    let diff = mock_diff_with_hash_edge_diffs();
    let mut buf = Vec::new();
    SarifRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val = sarif_parse(&buf);

    let results = val["runs"][0]["results"].as_array().unwrap();
    let dep = results
        .iter()
        .find(|r| r["ruleId"] == "dependency-changed")
        .unwrap();
    let msg = dep["message"]["text"].as_str().unwrap();
    // should use resolved display names, not raw hash IDs
    assert!(msg.contains("my-app@1.0"));
    assert!(msg.contains("old-dep@0.1"));
    assert!(msg.contains("new-dep@0.2"));
}

#[test]
fn test_sarif_renderer_locations_present_and_well_formed() {
    // component results: added, removed, changed all get "package" locations
    let diff = mock_diff();
    let mut buf = Vec::new();
    SarifRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val = sarif_parse(&buf);
    let results = val["runs"][0]["results"].as_array().unwrap();

    for rule_id in ["component-added", "component-removed", "component-changed"] {
        let result = results
            .iter()
            .find(|r| r["ruleId"] == rule_id)
            .unwrap_or_else(|| panic!("missing result for {rule_id}"));
        let locs = result["locations"]
            .as_array()
            .unwrap_or_else(|| panic!("{rule_id}: locations missing"));
        assert_eq!(locs.len(), 1, "{rule_id}: expected 1 location");
        let ll = locs[0]["logicalLocations"]
            .as_array()
            .unwrap_or_else(|| panic!("{rule_id}: logicalLocations missing"));
        assert_eq!(ll.len(), 1, "{rule_id}: expected 1 logicalLocation");
        assert!(
            !ll[0]["fullyQualifiedName"].as_str().unwrap().is_empty(),
            "{rule_id}: fullyQualifiedName should be non-empty"
        );
        assert_eq!(
            ll[0]["kind"], "package",
            "{rule_id}: kind should be package"
        );
    }

    // dependency result: uses parent display name
    let diff = mock_diff_with_hash_edge_diffs();
    let mut buf = Vec::new();
    SarifRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val = sarif_parse(&buf);
    let results = val["runs"][0]["results"].as_array().unwrap();

    let dep = results
        .iter()
        .find(|r| r["ruleId"] == "dependency-changed")
        .unwrap();
    let locs = dep["locations"].as_array().unwrap();
    assert_eq!(locs.len(), 1);
    let ll = locs[0]["logicalLocations"].as_array().unwrap();
    assert_eq!(ll[0]["fullyQualifiedName"], "my-app@1.0");
    assert_eq!(ll[0]["kind"], "package");

    // metadata result: uses "metadata" with kind "module"
    let diff = mock_diff_with_metadata_change();
    let mut buf = Vec::new();
    SarifRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val = sarif_parse(&buf);
    let results = val["runs"][0]["results"].as_array().unwrap();

    let meta = results
        .iter()
        .find(|r| r["ruleId"] == "metadata-changed")
        .unwrap();
    let locs = meta["locations"].as_array().unwrap();
    assert_eq!(locs.len(), 1);
    let ll = locs[0]["logicalLocations"].as_array().unwrap();
    assert_eq!(ll[0]["fullyQualifiedName"], "metadata");
    assert_eq!(ll[0]["kind"], "module");
}

#[test]
fn test_sarif_renderer_shows_warnings() {
    let diff = mock_diff();
    let opts = opts_with_warnings();
    let mut buf = Vec::new();
    SarifRenderer.render(&diff, &opts, &mut buf).unwrap();
    let val = sarif_parse(&buf);

    let results = val["runs"][0]["results"].as_array().unwrap();
    let warnings: Vec<_> = results
        .iter()
        .filter(|r| r["ruleId"] == "parser-warning")
        .collect();
    assert_eq!(warnings.len(), 2);

    // all warnings are note level
    for w in &warnings {
        assert_eq!(w["level"], "note");
    }

    // check old-SBOM warning
    let old_warning = warnings
        .iter()
        .find(|w| w["message"]["text"].as_str().unwrap().contains("old SBOM"))
        .expect("should have old SBOM warning");
    assert!(old_warning["message"]["text"]
        .as_str()
        .unwrap()
        .contains("orphaned ref 'SPDXRef-foo'"));
    let ll = old_warning["locations"][0]["logicalLocations"]
        .as_array()
        .unwrap();
    assert_eq!(ll[0]["fullyQualifiedName"], "old-sbom");
    assert_eq!(ll[0]["kind"], "module");

    // check new-SBOM warning
    let new_warning = warnings
        .iter()
        .find(|w| w["message"]["text"].as_str().unwrap().contains("new SBOM"))
        .expect("should have new SBOM warning");
    assert!(new_warning["message"]["text"]
        .as_str()
        .unwrap()
        .contains("unknown bom-ref 'bar'"));
    let ll = new_warning["locations"][0]["logicalLocations"]
        .as_array()
        .unwrap();
    assert_eq!(ll[0]["fullyQualifiedName"], "new-sbom");
    assert_eq!(ll[0]["kind"], "module");
}

#[test]
fn test_sarif_renderer_hides_warnings_by_default() {
    let diff = mock_diff();
    let mut buf = Vec::new();
    SarifRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val = sarif_parse(&buf);

    let results = val["runs"][0]["results"].as_array().unwrap();
    assert!(
        !results.iter().any(|r| r["ruleId"] == "parser-warning"),
        "should not emit parser-warning results without show_warnings"
    );
}

#[test]
fn test_sarif_renderer_no_warnings_when_empty() {
    let diff = mock_diff();
    let opts = RenderOptions {
        show_warnings: true,
        ..Default::default()
    };
    let mut buf = Vec::new();
    SarifRenderer.render(&diff, &opts, &mut buf).unwrap();
    let val = sarif_parse(&buf);

    let results = val["runs"][0]["results"].as_array().unwrap();
    assert!(
        !results.iter().any(|r| r["ruleId"] == "parser-warning"),
        "should not emit parser-warning results when warning lists are empty"
    );
}

#[test]
fn test_sarif_renderer_warnings_rule_index() {
    let diff = mock_diff_empty();
    let opts = opts_with_warnings();
    let mut buf = Vec::new();
    SarifRenderer.render(&diff, &opts, &mut buf).unwrap();
    let val = sarif_parse(&buf);

    let rules = val["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    let results = val["runs"][0]["results"].as_array().unwrap();

    for result in results.iter().filter(|r| r["ruleId"] == "parser-warning") {
        let rule_index = result["ruleIndex"].as_u64().unwrap() as usize;
        assert_eq!(rules[rule_index]["id"], "parser-warning");
    }
}

#[test]
fn test_sarif_renderer_warnings_rule_present() {
    let diff = mock_diff_empty();
    let mut buf = Vec::new();
    SarifRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val = sarif_parse(&buf);

    let rules = val["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    assert_eq!(rules.len(), 6);
    assert_eq!(rules[5]["id"], "parser-warning");
    assert_eq!(rules[5]["defaultConfiguration"]["level"], "note");
}

#[test]
fn test_sarif_renderer_no_metadata_when_all_none_subfields() {
    let diff = Diff {
        metadata_changed: Some(crate::MetadataChange {
            timestamp: None,
            tools: None,
            authors: None,
        }),
        ..Diff::default()
    };
    let mut buf = Vec::new();
    SarifRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val = sarif_parse(&buf);

    let results = val["runs"][0]["results"].as_array().unwrap();
    assert!(
        !results.iter().any(|r| r["ruleId"] == "metadata-changed"),
        "MetadataChange with all-None subfields should not emit a result"
    );
}

/// parse CSV output into a vec of rows, each row a vec of fields.
fn csv_parse(buf: &[u8]) -> Vec<Vec<String>> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(buf);
    rdr.records()
        .map(|r| r.unwrap().iter().map(|s| s.to_string()).collect())
        .collect()
}

#[test]
fn test_csv_renderer_header() {
    let diff = mock_diff_empty();
    let mut buf = Vec::new();
    CsvRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let rows = csv_parse(&buf);
    assert_eq!(
        rows[0],
        vec![
            "status",
            "component",
            "ecosystem",
            "field",
            "old_value",
            "new_value"
        ]
    );
}

#[test]
fn test_csv_renderer_empty_diff() {
    let diff = mock_diff_empty();
    let mut buf = Vec::new();
    CsvRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let rows = csv_parse(&buf);
    // only the header row
    assert_eq!(rows.len(), 1);
}

#[test]
fn test_csv_renderer_added_removed_changed() {
    let diff = mock_diff();
    let mut buf = Vec::new();
    CsvRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    // header
    assert!(out.starts_with("status,component,ecosystem,field,old_value,new_value\n"));
    // added row
    assert!(out.contains("added,"));
    // removed row
    assert!(out.contains("removed,"));
    // changed row with version field
    assert!(out.contains("changed,"));
    assert!(out.contains("version,1.0,1.1"));
}

#[test]
fn test_csv_renderer_all_field_changes() {
    let diff = mock_diff_all_field_changes();
    let mut buf = Vec::new();
    CsvRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.contains(",version,1.0,1.1"));
    assert!(out.contains(",license,"));
    assert!(out.contains(",supplier,Old Corp,New Corp"));
    assert!(out.contains(",purl,"));
    assert!(out.contains(",description,Old description,New description"));
    assert!(out.contains(",hashes,"));
    assert!(out.contains(",ecosystem,npm,cargo"));
    // edge diffs
    assert!(out.contains("edge-added,"));
    assert!(out.contains("edge-removed,"));
}

#[test]
fn test_csv_renderer_edge_diffs() {
    let diff = mock_diff_with_hash_edge_diffs();
    let mut buf = Vec::new();
    CsvRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    // should use resolved display names, not hash IDs
    assert!(out.contains("my-app@1.0"));
    assert!(out.contains("old-dep@0.1"));
    assert!(out.contains("new-dep@0.2"));
    assert!(out.contains("edge-added"));
    assert!(out.contains("edge-removed"));
    assert!(!out.contains("h:"));
}

#[test]
fn test_csv_renderer_metadata() {
    let diff = mock_diff_with_metadata_change();
    let mut buf = Vec::new();
    CsvRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.contains("metadata,,,timestamp,2024-01-01,2024-01-02"));
    assert!(out.contains("metadata,,,tools,syft,trivy"));
    // authors not changed, should not appear
    assert!(!out.contains("authors"));
}

#[test]
fn test_csv_renderer_no_metadata_when_unchanged() {
    let diff = mock_diff_empty();
    let mut buf = Vec::new();
    CsvRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(!out.contains("metadata"));
}

#[test]
fn test_csv_renderer_warnings() {
    let diff = mock_diff();
    let opts = opts_with_warnings();
    let mut buf = Vec::new();
    CsvRenderer.render(&diff, &opts, &mut buf).unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.contains("warning,old,"));
    assert!(out.contains("warning,new,"));
}

#[test]
fn test_csv_renderer_hides_warnings_by_default() {
    let diff = mock_diff();
    let mut buf = Vec::new();
    CsvRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(!out.contains("warning,"));
}

#[test]
fn test_csv_summary() {
    let diff = mock_diff();
    let mut buf = Vec::new();
    CsvRenderer
        .render_summary(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.starts_with("metric,count\n"));
    assert!(out.contains("added,1"));
    assert!(out.contains("removed,1"));
    assert!(out.contains("changed,1"));
    assert!(out.contains("edge_changes,0"));
    assert!(out.contains("metadata_changed,0"));
}

#[test]
fn test_csv_summary_with_ecosystems() {
    let diff = mock_diff_with_ecosystems();
    let opts = RenderOptions {
        group_by_ecosystem: true,
        ..Default::default()
    };
    let mut buf = Vec::new();
    CsvRenderer.render_summary(&diff, &opts, &mut buf).unwrap();
    let out = String::from_utf8(buf).unwrap();

    // ecosystem breakdown section
    assert!(out.contains("ecosystem,added,removed,changed"));
    assert!(out.contains("npm,1,1,1"));
    assert!(out.contains("cargo,1,0,0"));
}

#[test]
fn test_csv_summary_without_ecosystems() {
    let diff = mock_diff_with_ecosystems();
    let mut buf = Vec::new();
    CsvRenderer
        .render_summary(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(!out.contains("ecosystem,added,removed,changed"));
}

#[test]
fn test_csv_summary_warnings() {
    let diff = mock_diff();
    let opts = opts_with_warnings();
    let mut buf = Vec::new();
    CsvRenderer.render_summary(&diff, &opts, &mut buf).unwrap();
    let out = String::from_utf8(buf).unwrap();

    // warnings share the full renderer's schema, not the metric/count schema
    assert!(out.contains("status,component,ecosystem,field,old_value,new_value"));
    assert!(out.contains("warning,old,,,SPDX: orphaned ref 'SPDXRef-foo',"));
    assert!(out.contains("warning,new,,,CycloneDX: unknown bom-ref 'bar',"));
    // the count table is still present alongside the warnings
    assert!(out.contains("metric,count"));
    assert!(out.contains("added,1"));
}

#[test]
fn test_csv_summary_no_warnings_clean() {
    let diff = mock_diff();

    // default options: warnings disabled
    let mut buf = Vec::new();
    CsvRenderer
        .render_summary(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();
    assert!(!out.contains("warning,"));
    assert!(out.starts_with("metric,count\n"));

    // warnings enabled but none present: still clean
    let opts = RenderOptions {
        show_warnings: true,
        ..Default::default()
    };
    let mut buf = Vec::new();
    CsvRenderer.render_summary(&diff, &opts, &mut buf).unwrap();
    let out = String::from_utf8(buf).unwrap();
    assert!(!out.contains("warning,"));
    assert!(out.starts_with("metric,count\n"));
}

#[test]
fn test_csv_renderer_group_by_ecosystem() {
    let diff = mock_diff_with_ecosystems();
    let opts = RenderOptions {
        group_by_ecosystem: true,
        ..Default::default()
    };
    let mut buf = Vec::new();
    CsvRenderer.render(&diff, &opts, &mut buf).unwrap();
    let out = String::from_utf8(buf).unwrap();

    // full render always produces flat rows regardless of ecosystem grouping
    assert!(out.contains("added,"));
    assert!(out.contains("removed,"));
    assert!(out.contains("changed,"));
    // ecosystem column should be populated
    assert!(out.contains(",npm,"));
    assert!(out.contains(",cargo,"));
}

#[test]
fn test_csv_summary_metadata_changed() {
    let diff = mock_diff_with_metadata_change();
    let mut buf = Vec::new();
    CsvRenderer
        .render_summary(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.contains("metadata_changed,1"));
}

#[test]
fn test_csv_summary_metadata_unchanged() {
    let diff = mock_diff_empty();
    let mut buf = Vec::new();
    CsvRenderer
        .render_summary(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.contains("metadata_changed,0"));
}

fn mock_diff_with_downgrade() -> Diff {
    let c1 = Component::new("pkg-a".into(), Some("2.0.0".into()));
    let mut c2 = c1.clone();
    c2.version = Some("1.0.0".into());

    Diff {
        changed: vec![ComponentChange {
            id: c2.id.clone(),
            old: c1,
            new: c2,
            changes: vec![FieldChange::Version(
                Some("2.0.0".into()),
                Some("1.0.0".into()),
            )],
            is_downgrade: true,
        }],
        ..Diff::default()
    }
}

#[test]
fn test_text_renderer_downgrade() {
    let diff = mock_diff_with_downgrade();
    let mut buf = Vec::new();
    TextRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.contains("Version (downgrade): 2.0.0 -> 1.0.0"));
}

#[test]
fn test_markdown_renderer_downgrade() {
    let diff = mock_diff_with_downgrade();
    let mut buf = Vec::new();
    MarkdownRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.contains("**Version (downgrade)**"));
    assert!(out.contains("`2.0.0` &rarr; `1.0.0`"));
}

#[test]
fn test_json_renderer_downgrade() {
    let diff = mock_diff_with_downgrade();
    let mut buf = Vec::new();
    JsonRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

    assert_eq!(val["changed"][0]["is_downgrade"], true);
}

#[test]
fn test_json_renderer_no_downgrade_field_when_false() {
    let diff = mock_diff();
    let mut buf = Vec::new();
    JsonRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

    assert!(val["changed"][0].get("is_downgrade").is_none());
}

#[test]
fn test_csv_renderer_downgrade() {
    let diff = mock_diff_with_downgrade();
    let mut buf = Vec::new();
    CsvRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let out = String::from_utf8(buf).unwrap();

    assert!(out.contains("version-downgrade"));
    assert!(out.contains("2.0.0"));
    assert!(out.contains("1.0.0"));
}

#[test]
fn test_sarif_renderer_downgrade() {
    let diff = mock_diff_with_downgrade();
    let mut buf = Vec::new();
    SarifRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

    let results = val["runs"][0]["results"].as_array().unwrap();
    let changed = results
        .iter()
        .find(|r| r["ruleId"] == "component-changed")
        .unwrap();
    let msg = changed["message"]["text"].as_str().unwrap();
    assert!(msg.contains("version (downgrade):"));
    assert_eq!(changed["level"], "error");
}

#[test]
fn test_sarif_renderer_upgrade_stays_warning() {
    let diff = mock_diff();
    let mut buf = Vec::new();
    SarifRenderer
        .render(&diff, &RenderOptions::default(), &mut buf)
        .unwrap();
    let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

    let results = val["runs"][0]["results"].as_array().unwrap();
    let changed = results
        .iter()
        .find(|r| r["ruleId"] == "component-changed")
        .unwrap();
    assert_eq!(changed["level"], "warning");
}
