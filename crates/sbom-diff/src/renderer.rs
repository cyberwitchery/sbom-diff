//! Output renderers for displaying SBOM diffs.
//!
//! This module provides formatters for different output contexts:
//!
//! - [`TextRenderer`] - Plain text for terminal output
//! - [`MarkdownRenderer`] - GitHub-flavored markdown for PR comments
//! - [`JsonRenderer`] - Machine-readable JSON for tooling integration

use crate::{ComponentChange, Diff, EcosystemCounts, FieldChange, GroupedDiff};
use sbom_model::Component;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

/// Options controlling how diffs are rendered.
#[derive(Debug, Clone, Default)]
pub struct RenderOptions {
    /// When true, include a per-ecosystem breakdown of added/removed/changed counts.
    pub group_by_ecosystem: bool,
    /// When true, include parser warnings in the output.
    pub show_warnings: bool,
    /// Parser warnings collected during SBOM loading.
    pub warnings: Vec<String>,
}

fn format_option(opt: &Option<String>) -> &str {
    opt.as_deref().unwrap_or("<none>")
}

fn format_set(set: &BTreeSet<String>) -> String {
    if set.is_empty() {
        "<none>".to_string()
    } else {
        set.iter().cloned().collect::<Vec<_>>().join(", ")
    }
}

/// Trait for rendering a [`Diff`] to an output stream.
pub trait Renderer {
    /// Writes the formatted diff to the provided writer.
    fn render<W: Write>(
        &self,
        diff: &Diff,
        opts: &RenderOptions,
        writer: &mut W,
    ) -> anyhow::Result<()>;
}

// --- Shared helpers for text output ---

fn write_text_added<W: Write>(writer: &mut W, components: &[Component]) -> std::io::Result<()> {
    for c in components {
        writeln!(writer, "{}", c.purl.as_deref().unwrap_or(c.id.as_str()))?;
    }
    Ok(())
}

fn write_text_changed<W: Write>(
    writer: &mut W,
    changes: &[ComponentChange],
) -> std::io::Result<()> {
    for c in changes {
        writeln!(writer, "{}", c.new.purl.as_deref().unwrap_or(c.id.as_str()))?;
        write_text_field_changes(writer, &c.changes)?;
    }
    Ok(())
}

fn write_text_field_changes<W: Write>(
    writer: &mut W,
    changes: &[FieldChange],
) -> std::io::Result<()> {
    for change in changes {
        match change {
            FieldChange::Version(old, new) => {
                writeln!(writer, "  Version: {} -> {}", old, new)?;
            }
            FieldChange::License(old, new) => {
                writeln!(
                    writer,
                    "  License: {} -> {}",
                    format_set(old),
                    format_set(new)
                )?;
            }
            FieldChange::Supplier(old, new) => {
                writeln!(
                    writer,
                    "  Supplier: {} -> {}",
                    format_option(old),
                    format_option(new)
                )?;
            }
            FieldChange::Purl(old, new) => {
                writeln!(
                    writer,
                    "  Purl: {} -> {}",
                    format_option(old),
                    format_option(new)
                )?;
            }
            FieldChange::Description(old, new) => {
                writeln!(
                    writer,
                    "  Description: {} -> {}",
                    format_option(old),
                    format_option(new)
                )?;
            }
            FieldChange::Hashes(old, new) => {
                writeln!(writer, "  Hashes:")?;
                for (algo, digest) in old {
                    if !new.contains_key(algo) {
                        writeln!(writer, "    - {}: {}", algo, digest)?;
                    } else if new[algo] != *digest {
                        writeln!(writer, "    ~ {}: {} -> {}", algo, digest, new[algo])?;
                    }
                }
                for (algo, digest) in new {
                    if !old.contains_key(algo) {
                        writeln!(writer, "    + {}: {}", algo, digest)?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Plain text renderer for terminal output.
pub struct TextRenderer;

impl Renderer for TextRenderer {
    fn render<W: Write>(
        &self,
        diff: &Diff,
        opts: &RenderOptions,
        writer: &mut W,
    ) -> anyhow::Result<()> {
        if opts.show_warnings && !opts.warnings.is_empty() {
            writeln!(writer, "[!] Warnings")?;
            writeln!(writer, "------------")?;
            for w in &opts.warnings {
                writeln!(writer, "{}", w)?;
            }
            writeln!(writer)?;
        }

        writeln!(writer, "Diff Summary")?;
        writeln!(writer, "============")?;
        writeln!(writer, "Added:   {}", diff.added.len())?;
        writeln!(writer, "Removed: {}", diff.removed.len())?;
        writeln!(writer, "Changed: {}", diff.changed.len())?;
        writeln!(writer)?;

        if opts.group_by_ecosystem {
            let grouped = diff.group_by_ecosystem();
            let breakdown = grouped.ecosystem_breakdown();

            writeln!(writer, "By Ecosystem")?;
            writeln!(writer, "------------")?;
            for (eco, counts) in &breakdown {
                writeln!(
                    writer,
                    "{}: {} added, {} removed, {} changed",
                    eco, counts.added, counts.removed, counts.changed
                )?;
            }
            writeln!(writer)?;

            for (eco, eco_diff) in &grouped.by_ecosystem {
                writeln!(writer, "[{}]", eco)?;
                writeln!(writer)?;
                if !eco_diff.added.is_empty() {
                    writeln!(writer, "[+] Added")?;
                    writeln!(writer, "---------")?;
                    write_text_added(writer, &eco_diff.added)?;
                    writeln!(writer)?;
                }
                if !eco_diff.removed.is_empty() {
                    writeln!(writer, "[-] Removed")?;
                    writeln!(writer, "-----------")?;
                    write_text_added(writer, &eco_diff.removed)?;
                    writeln!(writer)?;
                }
                if !eco_diff.changed.is_empty() {
                    writeln!(writer, "[~] Changed")?;
                    writeln!(writer, "-----------")?;
                    write_text_changed(writer, &eco_diff.changed)?;
                    writeln!(writer)?;
                }
            }
        } else {
            if !diff.added.is_empty() {
                writeln!(writer, "[+] Added")?;
                writeln!(writer, "---------")?;
                write_text_added(writer, &diff.added)?;
                writeln!(writer)?;
            }

            if !diff.removed.is_empty() {
                writeln!(writer, "[-] Removed")?;
                writeln!(writer, "-----------")?;
                write_text_added(writer, &diff.removed)?;
                writeln!(writer)?;
            }

            if !diff.changed.is_empty() {
                writeln!(writer, "[~] Changed")?;
                writeln!(writer, "-----------")?;
                write_text_changed(writer, &diff.changed)?;
                writeln!(writer)?;
            }
        }

        if !diff.edge_diffs.is_empty() {
            writeln!(writer, "[~] Edge Changes")?;
            writeln!(writer, "----------------")?;
            for edge in &diff.edge_diffs {
                writeln!(writer, "{}", edge.parent)?;
                for removed in &edge.removed {
                    writeln!(writer, "  - {}", removed)?;
                }
                for added in &edge.added {
                    writeln!(writer, "  + {}", added)?;
                }
            }
        }

        Ok(())
    }
}

// --- Shared helpers for markdown output ---

fn write_md_added<W: Write>(writer: &mut W, components: &[Component]) -> std::io::Result<()> {
    for c in components {
        writeln!(writer, "- `{}`", c.purl.as_deref().unwrap_or(c.id.as_str()))?;
    }
    Ok(())
}

fn write_md_changed<W: Write>(writer: &mut W, changes: &[ComponentChange]) -> std::io::Result<()> {
    for c in changes {
        writeln!(
            writer,
            "#### `{}`",
            c.new.purl.as_deref().unwrap_or(c.id.as_str())
        )?;
        write_md_field_changes(writer, &c.changes)?;
    }
    Ok(())
}

fn write_md_field_changes<W: Write>(
    writer: &mut W,
    changes: &[FieldChange],
) -> std::io::Result<()> {
    for change in changes {
        match change {
            FieldChange::Version(old, new) => {
                writeln!(writer, "- **Version**: `{}` &rarr; `{}`", old, new)?;
            }
            FieldChange::License(old, new) => {
                writeln!(
                    writer,
                    "- **License**: `{}` &rarr; `{}`",
                    format_set(old),
                    format_set(new)
                )?;
            }
            FieldChange::Supplier(old, new) => {
                writeln!(
                    writer,
                    "- **Supplier**: `{}` &rarr; `{}`",
                    format_option(old),
                    format_option(new)
                )?;
            }
            FieldChange::Purl(old, new) => {
                writeln!(
                    writer,
                    "- **Purl**: `{}` &rarr; `{}`",
                    format_option(old),
                    format_option(new)
                )?;
            }
            FieldChange::Description(old, new) => {
                writeln!(
                    writer,
                    "- **Description**: `{}` &rarr; `{}`",
                    format_option(old),
                    format_option(new)
                )?;
            }
            FieldChange::Hashes(old, new) => {
                writeln!(writer, "- **Hashes**:")?;
                for (algo, digest) in old {
                    if !new.contains_key(algo) {
                        writeln!(writer, "  - `{}`: removed `{}`", algo, digest)?;
                    } else if new[algo] != *digest {
                        writeln!(
                            writer,
                            "  - `{}`: `{}` &rarr; `{}`",
                            algo, digest, new[algo]
                        )?;
                    }
                }
                for (algo, digest) in new {
                    if !old.contains_key(algo) {
                        writeln!(writer, "  - `{}`: added `{}`", algo, digest)?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// GitHub-flavored markdown renderer for PR comments.
///
/// Produces collapsible sections using `<details>` tags.
pub struct MarkdownRenderer;

impl Renderer for MarkdownRenderer {
    fn render<W: Write>(
        &self,
        diff: &Diff,
        opts: &RenderOptions,
        writer: &mut W,
    ) -> anyhow::Result<()> {
        if opts.show_warnings && !opts.warnings.is_empty() {
            writeln!(
                writer,
                "<details><summary><b>Warnings ({})</b></summary>",
                opts.warnings.len()
            )?;
            writeln!(writer)?;
            for w in &opts.warnings {
                writeln!(writer, "- {}", w)?;
            }
            writeln!(writer, "</details>")?;
            writeln!(writer)?;
        }

        writeln!(writer, "### SBOM Diff Summary")?;
        writeln!(writer)?;
        writeln!(writer, "| Change | Count |")?;
        writeln!(writer, "| --- | --- |")?;
        writeln!(writer, "| Added | {} |", diff.added.len())?;
        writeln!(writer, "| Removed | {} |", diff.removed.len())?;
        writeln!(writer, "| Changed | {} |", diff.changed.len())?;
        writeln!(writer)?;

        if opts.group_by_ecosystem {
            let grouped = diff.group_by_ecosystem();
            let breakdown = grouped.ecosystem_breakdown();

            writeln!(writer, "#### By Ecosystem")?;
            writeln!(writer)?;
            writeln!(writer, "| Ecosystem | Added | Removed | Changed |")?;
            writeln!(writer, "| --- | --- | --- | --- |")?;
            for (eco, counts) in &breakdown {
                writeln!(
                    writer,
                    "| {} | {} | {} | {} |",
                    eco, counts.added, counts.removed, counts.changed
                )?;
            }
            writeln!(writer)?;

            for (eco, eco_diff) in &grouped.by_ecosystem {
                writeln!(writer, "#### {}", eco)?;
                writeln!(writer)?;
                if !eco_diff.added.is_empty() {
                    writeln!(
                        writer,
                        "<details><summary><b>Added ({})</b></summary>",
                        eco_diff.added.len()
                    )?;
                    writeln!(writer)?;
                    write_md_added(writer, &eco_diff.added)?;
                    writeln!(writer, "</details>")?;
                    writeln!(writer)?;
                }
                if !eco_diff.removed.is_empty() {
                    writeln!(
                        writer,
                        "<details><summary><b>Removed ({})</b></summary>",
                        eco_diff.removed.len()
                    )?;
                    writeln!(writer)?;
                    write_md_added(writer, &eco_diff.removed)?;
                    writeln!(writer, "</details>")?;
                    writeln!(writer)?;
                }
                if !eco_diff.changed.is_empty() {
                    writeln!(
                        writer,
                        "<details><summary><b>Changed ({})</b></summary>",
                        eco_diff.changed.len()
                    )?;
                    writeln!(writer)?;
                    write_md_changed(writer, &eco_diff.changed)?;
                    writeln!(writer, "</details>")?;
                    writeln!(writer)?;
                }
            }
        } else {
            if !diff.added.is_empty() {
                writeln!(
                    writer,
                    "<details><summary><b>Added ({})</b></summary>",
                    diff.added.len()
                )?;
                writeln!(writer)?;
                write_md_added(writer, &diff.added)?;
                writeln!(writer, "</details>")?;
                writeln!(writer)?;
            }

            if !diff.removed.is_empty() {
                writeln!(
                    writer,
                    "<details><summary><b>Removed ({})</b></summary>",
                    diff.removed.len()
                )?;
                writeln!(writer)?;
                write_md_added(writer, &diff.removed)?;
                writeln!(writer, "</details>")?;
                writeln!(writer)?;
            }

            if !diff.changed.is_empty() {
                writeln!(
                    writer,
                    "<details><summary><b>Changed ({})</b></summary>",
                    diff.changed.len()
                )?;
                writeln!(writer)?;
                write_md_changed(writer, &diff.changed)?;
                writeln!(writer, "</details>")?;
                writeln!(writer)?;
            }
        }

        if !diff.edge_diffs.is_empty() {
            writeln!(
                writer,
                "<details><summary><b>Edge Changes ({})</b></summary>",
                diff.edge_diffs.len()
            )?;
            writeln!(writer)?;
            for edge in &diff.edge_diffs {
                writeln!(writer, "#### `{}`", edge.parent)?;
                if !edge.removed.is_empty() {
                    writeln!(writer, "**Removed dependencies:**")?;
                    for removed in &edge.removed {
                        writeln!(writer, "- `{}`", removed)?;
                    }
                }
                if !edge.added.is_empty() {
                    writeln!(writer, "**Added dependencies:**")?;
                    for added in &edge.added {
                        writeln!(writer, "- `{}`", added)?;
                    }
                }
                writeln!(writer)?;
            }
            writeln!(writer, "</details>")?;
        }

        Ok(())
    }
}

/// JSON renderer for machine consumption.
///
/// Outputs the [`Diff`] struct as pretty-printed JSON. When
/// `group_by_ecosystem` is set, the output includes an
/// `ecosystem_breakdown` field with per-ecosystem counts and the
/// `by_ecosystem` field with grouped component data.
pub struct JsonRenderer;

/// Wrapper for JSON output that optionally includes ecosystem breakdown.
#[derive(Serialize)]
struct JsonOutput<'a> {
    #[serde(flatten)]
    diff: &'a Diff,
    #[serde(skip_serializing_if = "Option::is_none")]
    ecosystem_breakdown: Option<BTreeMap<String, EcosystemCounts>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    by_ecosystem: Option<&'a GroupedDiff>,
    #[serde(skip_serializing_if = "Option::is_none")]
    warnings: Option<&'a Vec<String>>,
}

impl Renderer for JsonRenderer {
    fn render<W: Write>(
        &self,
        diff: &Diff,
        opts: &RenderOptions,
        writer: &mut W,
    ) -> anyhow::Result<()> {
        let warnings = if opts.show_warnings && !opts.warnings.is_empty() {
            Some(&opts.warnings)
        } else {
            None
        };

        if opts.group_by_ecosystem {
            let grouped = diff.group_by_ecosystem();
            let output = JsonOutput {
                diff,
                ecosystem_breakdown: Some(grouped.ecosystem_breakdown()),
                by_ecosystem: Some(&grouped),
                warnings,
            };
            serde_json::to_writer_pretty(writer, &output)?;
        } else {
            let output = JsonOutput {
                diff,
                ecosystem_breakdown: None,
                by_ecosystem: None,
                warnings,
            };
            serde_json::to_writer_pretty(writer, &output)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
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
                changes: vec![FieldChange::Version("1.0".into(), "1.1".into())],
            }],
            edge_diffs: vec![],
            metadata_changed: false,
        }
    }

    fn mock_diff_all_field_changes() -> Diff {
        use sbom_model::ComponentId;
        use std::collections::BTreeSet;

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
                    FieldChange::Version("1.0".into(), "1.1".into()),
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
                ],
            }],
            edge_diffs: vec![crate::EdgeDiff {
                parent: ComponentId::new(None, &[("name", "parent")]),
                added: BTreeSet::from([ComponentId::new(None, &[("name", "child-b")])]),
                removed: BTreeSet::from([ComponentId::new(None, &[("name", "child-a")])]),
            }],
            metadata_changed: false,
        }
    }

    fn mock_diff_empty() -> Diff {
        Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            metadata_changed: false,
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

        assert!(out.contains("Added:   0"));
        assert!(out.contains("Removed: 0"));
        assert!(out.contains("Changed: 0"));
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
        assert_eq!(val["changed"][0]["changes"].as_array().unwrap().len(), 6);
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
                changes: vec![FieldChange::Version("17.0.0".into(), "18.0.0".into())],
            }],
            edge_diffs: vec![],
            metadata_changed: false,
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
            warnings: vec![
                "SPDX: orphaned ref 'SPDXRef-foo'".into(),
                "CycloneDX: unknown bom-ref 'bar'".into(),
            ],
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
        assert!(out.contains("SPDX: orphaned ref 'SPDXRef-foo'"));
        assert!(out.contains("CycloneDX: unknown bom-ref 'bar'"));
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
        assert!(out.contains("- SPDX: orphaned ref 'SPDXRef-foo'"));
        assert!(out.contains("- CycloneDX: unknown bom-ref 'bar'"));
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

        let warnings = val["warnings"].as_array().unwrap();
        assert_eq!(warnings.len(), 2);
        assert_eq!(warnings[0], "SPDX: orphaned ref 'SPDXRef-foo'");
        assert_eq!(warnings[1], "CycloneDX: unknown bom-ref 'bar'");
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
            warnings: vec![],
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
}
