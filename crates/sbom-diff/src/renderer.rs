//! Output renderers for displaying SBOM diffs.
//!
//! This module provides formatters for different output contexts:
//!
//! - [`TextRenderer`] - Plain text for terminal output
//! - [`MarkdownRenderer`] - GitHub-flavored markdown for PR comments
//! - [`JsonRenderer`] - Machine-readable JSON for tooling integration
//! - [`SarifRenderer`] - SARIF 2.1.0 for GitHub Code Scanning / Azure DevOps

use crate::{ComponentChange, Diff, EcosystemCounts, FieldChange, GroupedDiff, MetadataChange};
use sbom_model::{Component, DependencyKind};
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
    /// Parser warnings from the old SBOM.
    pub old_warnings: Vec<String>,
    /// Parser warnings from the new SBOM.
    pub new_warnings: Vec<String>,
}

impl RenderOptions {
    /// Returns true when warnings should be displayed.
    pub fn has_warnings(&self) -> bool {
        self.show_warnings && (!self.old_warnings.is_empty() || !self.new_warnings.is_empty())
    }

    /// Total number of warnings across both SBOMs.
    pub fn warning_count(&self) -> usize {
        self.old_warnings.len() + self.new_warnings.len()
    }
}

/// Returns a display suffix for a dependency kind.
/// Runtime dependencies get no suffix (they are the default/common case).
fn kind_suffix(kind: &DependencyKind) -> &'static str {
    match kind {
        DependencyKind::Runtime => "",
        DependencyKind::Dev => " (dev)",
        DependencyKind::Build => " (build)",
        DependencyKind::Test => " (test)",
        DependencyKind::Optional => " (optional)",
        DependencyKind::Provided => " (provided)",
    }
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

/// Trait for rendering a summary (counts only, no component details) to an output stream.
///
/// Mirrors [`Renderer`] but produces compact output suitable for `--summary` mode.
pub trait SummaryRenderer {
    /// Writes a summary-only view of the diff to the provided writer.
    fn render_summary<W: Write>(
        &self,
        diff: &Diff,
        opts: &RenderOptions,
        writer: &mut W,
    ) -> anyhow::Result<()>;
}

// --- Shared helpers for field-change rendering ---

trait FieldChangeFormatter {
    fn field_change<W: Write>(
        &self,
        w: &mut W,
        name: &str,
        old: &str,
        new: &str,
    ) -> std::io::Result<()>;
    fn hash_header<W: Write>(&self, w: &mut W) -> std::io::Result<()>;
    fn hash_removed<W: Write>(&self, w: &mut W, algo: &str, digest: &str) -> std::io::Result<()>;
    fn hash_changed<W: Write>(
        &self,
        w: &mut W,
        algo: &str,
        old: &str,
        new: &str,
    ) -> std::io::Result<()>;
    fn hash_added<W: Write>(&self, w: &mut W, algo: &str, digest: &str) -> std::io::Result<()>;
    fn component_header<W: Write>(&self, w: &mut W, id: &str) -> std::io::Result<()>;
}

fn write_field_changes<F: FieldChangeFormatter, W: Write>(
    fmt: &F,
    writer: &mut W,
    changes: &[FieldChange],
) -> std::io::Result<()> {
    for change in changes {
        match change {
            FieldChange::Version(old, new) => {
                fmt.field_change(writer, "Version", format_option(old), format_option(new))?;
            }
            FieldChange::License(old, new) => {
                fmt.field_change(writer, "License", &format_set(old), &format_set(new))?;
            }
            FieldChange::Supplier(old, new) => {
                fmt.field_change(writer, "Supplier", format_option(old), format_option(new))?;
            }
            FieldChange::Purl(old, new) => {
                fmt.field_change(writer, "Purl", format_option(old), format_option(new))?;
            }
            FieldChange::Description(old, new) => {
                fmt.field_change(
                    writer,
                    "Description",
                    format_option(old),
                    format_option(new),
                )?;
            }
            FieldChange::Hashes(old, new) => {
                fmt.hash_header(writer)?;
                for (algo, digest) in old {
                    if !new.contains_key(algo) {
                        fmt.hash_removed(writer, algo, digest)?;
                    } else if new[algo] != *digest {
                        fmt.hash_changed(writer, algo, digest, &new[algo])?;
                    }
                }
                for (algo, digest) in new {
                    if !old.contains_key(algo) {
                        fmt.hash_added(writer, algo, digest)?;
                    }
                }
            }
            FieldChange::Ecosystem(old, new) => {
                fmt.field_change(writer, "Ecosystem", format_option(old), format_option(new))?;
            }
        }
    }
    Ok(())
}

fn write_changed<F: FieldChangeFormatter, W: Write>(
    fmt: &F,
    writer: &mut W,
    changes: &[ComponentChange],
) -> std::io::Result<()> {
    for c in changes {
        fmt.component_header(writer, c.new.purl.as_deref().unwrap_or(c.id.as_str()))?;
        write_field_changes(fmt, writer, &c.changes)?;
    }
    Ok(())
}

// --- Text output helpers ---

fn write_text_added<W: Write>(writer: &mut W, components: &[Component]) -> std::io::Result<()> {
    for c in components {
        writeln!(writer, "{}", c.purl.as_deref().unwrap_or(c.id.as_str()))?;
    }
    Ok(())
}

/// Plain text renderer for terminal output.
pub struct TextRenderer;

impl FieldChangeFormatter for TextRenderer {
    fn field_change<W: Write>(
        &self,
        w: &mut W,
        name: &str,
        old: &str,
        new: &str,
    ) -> std::io::Result<()> {
        writeln!(w, "  {}: {} -> {}", name, old, new)
    }

    fn hash_header<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        writeln!(w, "  Hashes:")
    }

    fn hash_removed<W: Write>(&self, w: &mut W, algo: &str, digest: &str) -> std::io::Result<()> {
        writeln!(w, "    - {}: {}", algo, digest)
    }

    fn hash_changed<W: Write>(
        &self,
        w: &mut W,
        algo: &str,
        old: &str,
        new: &str,
    ) -> std::io::Result<()> {
        writeln!(w, "    ~ {}: {} -> {}", algo, old, new)
    }

    fn hash_added<W: Write>(&self, w: &mut W, algo: &str, digest: &str) -> std::io::Result<()> {
        writeln!(w, "    + {}: {}", algo, digest)
    }

    fn component_header<W: Write>(&self, w: &mut W, id: &str) -> std::io::Result<()> {
        writeln!(w, "{}", id)
    }
}

impl Renderer for TextRenderer {
    fn render<W: Write>(
        &self,
        diff: &Diff,
        opts: &RenderOptions,
        writer: &mut W,
    ) -> anyhow::Result<()> {
        if opts.has_warnings() {
            writeln!(writer, "[!] Warnings")?;
            writeln!(writer, "------------")?;
            for w in &opts.old_warnings {
                writeln!(writer, "[old] {}", w)?;
            }
            for w in &opts.new_warnings {
                writeln!(writer, "[new] {}", w)?;
            }
            writeln!(writer)?;
        }

        writeln!(writer, "Diff Summary")?;
        writeln!(writer, "============")?;
        writeln!(writer, "Old total:        {} components", diff.old_total)?;
        writeln!(writer, "New total:        {} components", diff.new_total)?;
        writeln!(writer, "Unchanged:        {}", diff.unchanged)?;
        writeln!(writer, "Added:            {}", diff.added.len())?;
        writeln!(writer, "Removed:          {}", diff.removed.len())?;
        writeln!(writer, "Changed:          {}", diff.changed.len())?;
        writeln!(writer, "Edge changes:     {}", diff.edge_diffs.len())?;
        writeln!(
            writer,
            "Metadata changed: {}",
            if diff.metadata_changed.is_some() {
                "yes"
            } else {
                "no"
            }
        )?;
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
                    write_changed(self, writer, &eco_diff.changed)?;
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
                write_changed(self, writer, &diff.changed)?;
                writeln!(writer)?;
            }
        }

        if !diff.edge_diffs.is_empty() {
            writeln!(writer, "[~] Edge Changes")?;
            writeln!(writer, "----------------")?;
            for edge in &diff.edge_diffs {
                writeln!(writer, "{}", diff.display_name(&edge.parent))?;
                for (removed, kind) in &edge.removed {
                    writeln!(
                        writer,
                        "  - {}{}",
                        diff.display_name(removed),
                        kind_suffix(kind)
                    )?;
                }
                for (added, kind) in &edge.added {
                    writeln!(
                        writer,
                        "  + {}{}",
                        diff.display_name(added),
                        kind_suffix(kind)
                    )?;
                }
                for (changed, (old_kind, new_kind)) in &edge.kind_changed {
                    writeln!(
                        writer,
                        "  ~ {} ({} -> {})",
                        diff.display_name(changed),
                        old_kind,
                        new_kind
                    )?;
                }
            }
        }

        if let Some(mc) = &diff.metadata_changed {
            writeln!(writer)?;
            write_text_metadata(writer, mc)?;
        }

        Ok(())
    }
}

fn write_text_metadata<W: Write>(writer: &mut W, mc: &MetadataChange) -> std::io::Result<()> {
    writeln!(writer, "[~] Metadata Changes")?;
    writeln!(writer, "--------------------")?;
    if let Some((ref old, ref new)) = mc.timestamp {
        writeln!(
            writer,
            "  Timestamp: {} -> {}",
            old.as_deref().unwrap_or("<none>"),
            new.as_deref().unwrap_or("<none>")
        )?;
    }
    if let Some((ref old, ref new)) = mc.tools {
        writeln!(
            writer,
            "  Tools: {} -> {}",
            format_vec_or_none(old),
            format_vec_or_none(new)
        )?;
    }
    if let Some((ref old, ref new)) = mc.authors {
        writeln!(
            writer,
            "  Authors: {} -> {}",
            format_vec_or_none(old),
            format_vec_or_none(new)
        )?;
    }
    Ok(())
}

fn format_vec_or_none(v: &[String]) -> String {
    if v.is_empty() {
        "<none>".to_string()
    } else {
        v.join(", ")
    }
}

// --- Markdown output helpers ---

fn write_md_added<W: Write>(writer: &mut W, components: &[Component]) -> std::io::Result<()> {
    for c in components {
        writeln!(writer, "- `{}`", c.purl.as_deref().unwrap_or(c.id.as_str()))?;
    }
    Ok(())
}

/// GitHub-flavored markdown renderer for PR comments.
///
/// Produces collapsible sections using `<details>` tags.
pub struct MarkdownRenderer;

impl FieldChangeFormatter for MarkdownRenderer {
    fn field_change<W: Write>(
        &self,
        w: &mut W,
        name: &str,
        old: &str,
        new: &str,
    ) -> std::io::Result<()> {
        writeln!(w, "- **{}**: `{}` &rarr; `{}`", name, old, new)
    }

    fn hash_header<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        writeln!(w, "- **Hashes**:")
    }

    fn hash_removed<W: Write>(&self, w: &mut W, algo: &str, digest: &str) -> std::io::Result<()> {
        writeln!(w, "  - `{}`: removed `{}`", algo, digest)
    }

    fn hash_changed<W: Write>(
        &self,
        w: &mut W,
        algo: &str,
        old: &str,
        new: &str,
    ) -> std::io::Result<()> {
        writeln!(w, "  - `{}`: `{}` &rarr; `{}`", algo, old, new)
    }

    fn hash_added<W: Write>(&self, w: &mut W, algo: &str, digest: &str) -> std::io::Result<()> {
        writeln!(w, "  - `{}`: added `{}`", algo, digest)
    }

    fn component_header<W: Write>(&self, w: &mut W, id: &str) -> std::io::Result<()> {
        writeln!(w, "#### `{}`", id)
    }
}

impl Renderer for MarkdownRenderer {
    fn render<W: Write>(
        &self,
        diff: &Diff,
        opts: &RenderOptions,
        writer: &mut W,
    ) -> anyhow::Result<()> {
        if opts.has_warnings() {
            writeln!(
                writer,
                "<details><summary><b>Warnings ({})</b></summary>",
                opts.warning_count()
            )?;
            writeln!(writer)?;
            for w in &opts.old_warnings {
                writeln!(writer, "- **old:** {}", w)?;
            }
            for w in &opts.new_warnings {
                writeln!(writer, "- **new:** {}", w)?;
            }
            writeln!(writer, "</details>")?;
            writeln!(writer)?;
        }

        writeln!(writer, "### SBOM Diff Summary")?;
        writeln!(writer)?;
        writeln!(writer, "| Metric | Count |")?;
        writeln!(writer, "| --- | --- |")?;
        writeln!(writer, "| Old total | {} |", diff.old_total)?;
        writeln!(writer, "| New total | {} |", diff.new_total)?;
        writeln!(writer, "| Unchanged | {} |", diff.unchanged)?;
        writeln!(writer, "| Added | {} |", diff.added.len())?;
        writeln!(writer, "| Removed | {} |", diff.removed.len())?;
        writeln!(writer, "| Changed | {} |", diff.changed.len())?;
        writeln!(writer, "| Edge changes | {} |", diff.edge_diffs.len())?;
        writeln!(
            writer,
            "| Metadata changed | {} |",
            if diff.metadata_changed.is_some() {
                "yes"
            } else {
                "no"
            }
        )?;
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
                    write_changed(self, writer, &eco_diff.changed)?;
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
                write_changed(self, writer, &diff.changed)?;
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
                writeln!(writer, "#### `{}`", diff.display_name(&edge.parent))?;
                if !edge.removed.is_empty() {
                    writeln!(writer, "**Removed dependencies:**")?;
                    for (removed, kind) in &edge.removed {
                        writeln!(
                            writer,
                            "- `{}`{}",
                            diff.display_name(removed),
                            kind_suffix(kind)
                        )?;
                    }
                }
                if !edge.added.is_empty() {
                    writeln!(writer, "**Added dependencies:**")?;
                    for (added, kind) in &edge.added {
                        writeln!(
                            writer,
                            "- `{}`{}",
                            diff.display_name(added),
                            kind_suffix(kind)
                        )?;
                    }
                }
                if !edge.kind_changed.is_empty() {
                    writeln!(writer, "**Kind changed:**")?;
                    for (changed, (old_kind, new_kind)) in &edge.kind_changed {
                        writeln!(
                            writer,
                            "- `{}`: {} &rarr; {}",
                            diff.display_name(changed),
                            old_kind,
                            new_kind
                        )?;
                    }
                }
                writeln!(writer)?;
            }
            writeln!(writer, "</details>")?;
        }

        if let Some(mc) = &diff.metadata_changed {
            writeln!(writer)?;
            write_md_metadata(writer, mc)?;
        }

        Ok(())
    }
}

fn write_md_metadata<W: Write>(writer: &mut W, mc: &MetadataChange) -> std::io::Result<()> {
    writeln!(
        writer,
        "<details><summary><b>Metadata Changes</b></summary>"
    )?;
    writeln!(writer)?;
    if let Some((ref old, ref new)) = mc.timestamp {
        writeln!(
            writer,
            "- **Timestamp**: `{}` &rarr; `{}`",
            old.as_deref().unwrap_or("<none>"),
            new.as_deref().unwrap_or("<none>")
        )?;
    }
    if let Some((ref old, ref new)) = mc.tools {
        writeln!(
            writer,
            "- **Tools**: `{}` &rarr; `{}`",
            format_vec_or_none(old),
            format_vec_or_none(new)
        )?;
    }
    if let Some((ref old, ref new)) = mc.authors {
        writeln!(
            writer,
            "- **Authors**: `{}` &rarr; `{}`",
            format_vec_or_none(old),
            format_vec_or_none(new)
        )?;
    }
    writeln!(writer, "</details>")?;
    Ok(())
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
    warnings: Option<JsonWarnings<'a>>,
}

#[derive(Serialize)]
struct JsonWarnings<'a> {
    old: &'a Vec<String>,
    new: &'a Vec<String>,
}

impl Renderer for JsonRenderer {
    fn render<W: Write>(
        &self,
        diff: &Diff,
        opts: &RenderOptions,
        writer: &mut W,
    ) -> anyhow::Result<()> {
        let warnings = if opts.has_warnings() {
            Some(JsonWarnings {
                old: &opts.old_warnings,
                new: &opts.new_warnings,
            })
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

// --- SARIF 2.1.0 output ---

const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";

// Rule indices (must match order in SARIF_RULES)
const RULE_COMPONENT_ADDED: usize = 0;
const RULE_COMPONENT_REMOVED: usize = 1;
const RULE_COMPONENT_CHANGED: usize = 2;
const RULE_DEPENDENCY_CHANGED: usize = 3;
const RULE_METADATA_CHANGED: usize = 4;

#[derive(Clone, Copy)]
struct RuleInfo {
    id: &'static str,
    short_desc: &'static str,
    full_desc: &'static str,
    level: &'static str,
}

const SARIF_RULES: &[RuleInfo] = &[
    RuleInfo {
        id: "component-added",
        short_desc: "Component added",
        full_desc: "A new component was added to the SBOM",
        level: "note",
    },
    RuleInfo {
        id: "component-removed",
        short_desc: "Component removed",
        full_desc: "A component was removed from the SBOM",
        level: "warning",
    },
    RuleInfo {
        id: "component-changed",
        short_desc: "Component changed",
        full_desc: "A component's metadata changed between SBOMs",
        level: "warning",
    },
    RuleInfo {
        id: "dependency-changed",
        short_desc: "Dependency changed",
        full_desc: "A dependency edge was added, removed, or changed kind",
        level: "note",
    },
    RuleInfo {
        id: "metadata-changed",
        short_desc: "Metadata changed",
        full_desc: "Document metadata (timestamp, tools, or authors) changed between SBOMs",
        level: "note",
    },
];

#[derive(Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResultEntry>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriverInfo,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifDriverInfo {
    name: &'static str,
    version: &'static str,
    information_uri: &'static str,
    rules: Vec<SarifRuleDescriptor>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRuleDescriptor {
    id: &'static str,
    short_description: SarifMultiformatMessage,
    full_description: SarifMultiformatMessage,
    default_configuration: SarifDefaultConfiguration,
}

#[derive(Serialize)]
struct SarifDefaultConfiguration {
    level: &'static str,
}

#[derive(Serialize)]
struct SarifMultiformatMessage {
    text: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResultEntry {
    rule_id: &'static str,
    rule_index: usize,
    level: &'static str,
    message: SarifTextMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
struct SarifTextMessage {
    text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    logical_locations: Vec<SarifLogicalLocation>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLogicalLocation {
    fully_qualified_name: String,
    kind: &'static str,
}

/// SARIF 2.1.0 renderer for GitHub Code Scanning integration.
///
/// Produces a SARIF log with one run containing rules for each change type
/// (component added/removed/changed, dependency changed, metadata changed)
/// and a result entry per finding.
pub struct SarifRenderer;

impl SarifRenderer {
    fn build_rules() -> Vec<SarifRuleDescriptor> {
        SARIF_RULES
            .iter()
            .map(|r| SarifRuleDescriptor {
                id: r.id,
                short_description: SarifMultiformatMessage { text: r.short_desc },
                full_description: SarifMultiformatMessage { text: r.full_desc },
                default_configuration: SarifDefaultConfiguration { level: r.level },
            })
            .collect()
    }

    fn component_display(comp: &Component) -> &str {
        comp.purl.as_deref().unwrap_or(comp.id.as_str())
    }

    fn component_location(comp: &Component) -> Vec<SarifLocation> {
        vec![SarifLocation {
            logical_locations: vec![SarifLogicalLocation {
                fully_qualified_name: Self::component_display(comp).to_string(),
                kind: "package",
            }],
        }]
    }

    fn format_field_change(fc: &FieldChange) -> String {
        match fc {
            FieldChange::Version(old, new) => {
                format!("version: {} -> {}", format_option(old), format_option(new))
            }
            FieldChange::License(old, new) => {
                format!("license: {} -> {}", format_set(old), format_set(new))
            }
            FieldChange::Supplier(old, new) => {
                format!("supplier: {} -> {}", format_option(old), format_option(new))
            }
            FieldChange::Purl(old, new) => {
                format!("purl: {} -> {}", format_option(old), format_option(new))
            }
            FieldChange::Description(old, new) => {
                format!(
                    "description: {} -> {}",
                    format_option(old),
                    format_option(new)
                )
            }
            FieldChange::Hashes(_, _) => "hashes changed".to_string(),
            FieldChange::Ecosystem(old, new) => {
                format!(
                    "ecosystem: {} -> {}",
                    format_option(old),
                    format_option(new)
                )
            }
        }
    }

    fn build_results(diff: &Diff) -> Vec<SarifResultEntry> {
        let mut results = Vec::new();

        for comp in &diff.added {
            results.push(SarifResultEntry {
                rule_id: SARIF_RULES[RULE_COMPONENT_ADDED].id,
                rule_index: RULE_COMPONENT_ADDED,
                level: SARIF_RULES[RULE_COMPONENT_ADDED].level,
                message: SarifTextMessage {
                    text: format!("Component added: {}", Self::component_display(comp)),
                },
                locations: Self::component_location(comp),
            });
        }

        for comp in &diff.removed {
            results.push(SarifResultEntry {
                rule_id: SARIF_RULES[RULE_COMPONENT_REMOVED].id,
                rule_index: RULE_COMPONENT_REMOVED,
                level: SARIF_RULES[RULE_COMPONENT_REMOVED].level,
                message: SarifTextMessage {
                    text: format!("Component removed: {}", Self::component_display(comp)),
                },
                locations: Self::component_location(comp),
            });
        }

        for change in &diff.changed {
            let display = Self::component_display(&change.new);
            let field_changes: Vec<String> = change
                .changes
                .iter()
                .map(Self::format_field_change)
                .collect();

            results.push(SarifResultEntry {
                rule_id: SARIF_RULES[RULE_COMPONENT_CHANGED].id,
                rule_index: RULE_COMPONENT_CHANGED,
                level: SARIF_RULES[RULE_COMPONENT_CHANGED].level,
                message: SarifTextMessage {
                    text: format!(
                        "Component changed: {} ({})",
                        display,
                        field_changes.join("; "),
                    ),
                },
                locations: Self::component_location(&change.new),
            });
        }

        for edge in &diff.edge_diffs {
            let parent = diff.display_name(&edge.parent);
            let mut parts = Vec::new();

            for (child, kind) in &edge.added {
                parts.push(format!(
                    "added {} -> {}{}",
                    parent,
                    diff.display_name(child),
                    kind_suffix(kind)
                ));
            }
            for (child, kind) in &edge.removed {
                parts.push(format!(
                    "removed {} -> {}{}",
                    parent,
                    diff.display_name(child),
                    kind_suffix(kind)
                ));
            }
            for (child, (old_kind, new_kind)) in &edge.kind_changed {
                parts.push(format!(
                    "{} -> {} kind: {} -> {}",
                    parent,
                    diff.display_name(child),
                    old_kind,
                    new_kind
                ));
            }

            if !parts.is_empty() {
                results.push(SarifResultEntry {
                    rule_id: SARIF_RULES[RULE_DEPENDENCY_CHANGED].id,
                    rule_index: RULE_DEPENDENCY_CHANGED,
                    level: SARIF_RULES[RULE_DEPENDENCY_CHANGED].level,
                    message: SarifTextMessage {
                        text: format!("Dependency changed: {}", parts.join("; ")),
                    },
                    locations: vec![SarifLocation {
                        logical_locations: vec![SarifLogicalLocation {
                            fully_qualified_name: parent.to_string(),
                            kind: "package",
                        }],
                    }],
                });
            }
        }

        if let Some(mc) = &diff.metadata_changed {
            let mut parts = Vec::new();
            if let Some((ref old, ref new)) = mc.timestamp {
                parts.push(format!(
                    "timestamp: {} -> {}",
                    old.as_deref().unwrap_or("<none>"),
                    new.as_deref().unwrap_or("<none>")
                ));
            }
            if let Some((ref old, ref new)) = mc.tools {
                parts.push(format!(
                    "tools: {} -> {}",
                    format_vec_or_none(old),
                    format_vec_or_none(new)
                ));
            }
            if let Some((ref old, ref new)) = mc.authors {
                parts.push(format!(
                    "authors: {} -> {}",
                    format_vec_or_none(old),
                    format_vec_or_none(new)
                ));
            }

            if !parts.is_empty() {
                results.push(SarifResultEntry {
                    rule_id: SARIF_RULES[RULE_METADATA_CHANGED].id,
                    rule_index: RULE_METADATA_CHANGED,
                    level: SARIF_RULES[RULE_METADATA_CHANGED].level,
                    message: SarifTextMessage {
                        text: format!("Metadata changed: {}", parts.join("; ")),
                    },
                    locations: vec![SarifLocation {
                        logical_locations: vec![SarifLogicalLocation {
                            fully_qualified_name: "metadata".to_string(),
                            kind: "module",
                        }],
                    }],
                });
            }
        }

        results
    }
}

impl Renderer for SarifRenderer {
    fn render<W: Write>(
        &self,
        diff: &Diff,
        _opts: &RenderOptions,
        writer: &mut W,
    ) -> anyhow::Result<()> {
        let log = SarifLog {
            schema: SARIF_SCHEMA,
            version: SARIF_VERSION,
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriverInfo {
                        name: "sbom-diff",
                        version: env!("CARGO_PKG_VERSION"),
                        information_uri: "https://github.com/cyberwitchery/sbom-diff",
                        rules: Self::build_rules(),
                    },
                },
                results: Self::build_results(diff),
            }],
        };
        serde_json::to_writer_pretty(writer, &log)?;
        Ok(())
    }
}

impl SummaryRenderer for SarifRenderer {
    fn render_summary<W: Write>(
        &self,
        diff: &Diff,
        opts: &RenderOptions,
        writer: &mut W,
    ) -> anyhow::Result<()> {
        self.render(diff, opts, writer)
    }
}

// --- Summary rendering helpers ---

/// Format-specific building blocks for summary output.
///
/// Text and markdown renderers implement this trait; the shared
/// [`write_summary`] function orchestrates calls in the correct order.
/// JSON uses a fundamentally different approach (building a single
/// serializable value) and implements [`SummaryRenderer`] directly.
trait SummaryFormatter {
    fn write_warnings<W: Write>(&self, w: &mut W, opts: &RenderOptions) -> std::io::Result<()>;
    fn write_counts<W: Write>(&self, w: &mut W, diff: &Diff) -> std::io::Result<()>;
    fn write_ecosystem_breakdown<W: Write>(
        &self,
        w: &mut W,
        breakdown: &BTreeMap<String, EcosystemCounts>,
    ) -> std::io::Result<()>;
}

fn write_summary<F: SummaryFormatter, W: Write>(
    fmt: &F,
    diff: &Diff,
    opts: &RenderOptions,
    writer: &mut W,
) -> std::io::Result<()> {
    if opts.has_warnings() {
        fmt.write_warnings(writer, opts)?;
    }
    fmt.write_counts(writer, diff)?;
    if opts.group_by_ecosystem {
        let breakdown = diff.ecosystem_breakdown();
        if !breakdown.is_empty() {
            fmt.write_ecosystem_breakdown(writer, &breakdown)?;
        }
    }
    Ok(())
}

impl SummaryFormatter for TextRenderer {
    fn write_warnings<W: Write>(&self, w: &mut W, opts: &RenderOptions) -> std::io::Result<()> {
        writeln!(w, "Warnings:     {}", opts.warning_count())?;
        for warning in &opts.old_warnings {
            writeln!(w, "  [old] {}", warning)?;
        }
        for warning in &opts.new_warnings {
            writeln!(w, "  [new] {}", warning)?;
        }
        writeln!(w)
    }

    fn write_counts<W: Write>(&self, w: &mut W, diff: &Diff) -> std::io::Result<()> {
        writeln!(w, "Old total:        {} components", diff.old_total)?;
        writeln!(w, "New total:        {} components", diff.new_total)?;
        writeln!(w, "Unchanged:        {}", diff.unchanged)?;
        writeln!(w, "Added:            {}", diff.added.len())?;
        writeln!(w, "Removed:          {}", diff.removed.len())?;
        writeln!(w, "Changed:          {}", diff.changed.len())?;
        writeln!(w, "Edge changes:     {}", diff.edge_diffs.len())?;
        writeln!(
            w,
            "Metadata changed: {}",
            if diff.metadata_changed.is_some() {
                "yes"
            } else {
                "no"
            }
        )
    }

    fn write_ecosystem_breakdown<W: Write>(
        &self,
        w: &mut W,
        breakdown: &BTreeMap<String, EcosystemCounts>,
    ) -> std::io::Result<()> {
        writeln!(w)?;
        writeln!(w, "By ecosystem:")?;
        for (eco, counts) in breakdown {
            writeln!(
                w,
                "  {}: {} added, {} removed, {} changed",
                eco, counts.added, counts.removed, counts.changed
            )?;
        }
        Ok(())
    }
}

impl SummaryRenderer for TextRenderer {
    fn render_summary<W: Write>(
        &self,
        diff: &Diff,
        opts: &RenderOptions,
        writer: &mut W,
    ) -> anyhow::Result<()> {
        write_summary(self, diff, opts, writer)?;
        Ok(())
    }
}

impl SummaryFormatter for MarkdownRenderer {
    fn write_warnings<W: Write>(&self, w: &mut W, opts: &RenderOptions) -> std::io::Result<()> {
        writeln!(
            w,
            "<details><summary><b>Warnings ({})</b></summary>",
            opts.warning_count()
        )?;
        writeln!(w)?;
        for warning in &opts.old_warnings {
            writeln!(w, "- **old:** {}", warning)?;
        }
        for warning in &opts.new_warnings {
            writeln!(w, "- **new:** {}", warning)?;
        }
        writeln!(w, "</details>")?;
        writeln!(w)
    }

    fn write_counts<W: Write>(&self, w: &mut W, diff: &Diff) -> std::io::Result<()> {
        writeln!(w, "### SBOM Diff Summary")?;
        writeln!(w)?;
        writeln!(w, "| Metric | Count |")?;
        writeln!(w, "| --- | --- |")?;
        writeln!(w, "| Old total | {} |", diff.old_total)?;
        writeln!(w, "| New total | {} |", diff.new_total)?;
        writeln!(w, "| Unchanged | {} |", diff.unchanged)?;
        writeln!(w, "| Added | {} |", diff.added.len())?;
        writeln!(w, "| Removed | {} |", diff.removed.len())?;
        writeln!(w, "| Changed | {} |", diff.changed.len())?;
        writeln!(w, "| Edge changes | {} |", diff.edge_diffs.len())?;
        writeln!(
            w,
            "| Metadata changed | {} |",
            if diff.metadata_changed.is_some() {
                "yes"
            } else {
                "no"
            }
        )
    }

    fn write_ecosystem_breakdown<W: Write>(
        &self,
        w: &mut W,
        breakdown: &BTreeMap<String, EcosystemCounts>,
    ) -> std::io::Result<()> {
        writeln!(w)?;
        writeln!(w, "#### By Ecosystem")?;
        writeln!(w)?;
        writeln!(w, "| Ecosystem | Added | Removed | Changed |")?;
        writeln!(w, "| --- | --- | --- | --- |")?;
        for (eco, counts) in breakdown {
            writeln!(
                w,
                "| {} | {} | {} | {} |",
                eco, counts.added, counts.removed, counts.changed
            )?;
        }
        Ok(())
    }
}

impl SummaryRenderer for MarkdownRenderer {
    fn render_summary<W: Write>(
        &self,
        diff: &Diff,
        opts: &RenderOptions,
        writer: &mut W,
    ) -> anyhow::Result<()> {
        write_summary(self, diff, opts, writer)?;
        Ok(())
    }
}

impl SummaryRenderer for JsonRenderer {
    fn render_summary<W: Write>(
        &self,
        diff: &Diff,
        opts: &RenderOptions,
        writer: &mut W,
    ) -> anyhow::Result<()> {
        let mut summary = serde_json::json!({
            "old_total": diff.old_total,
            "new_total": diff.new_total,
            "unchanged": diff.unchanged,
            "added": diff.added.len(),
            "removed": diff.removed.len(),
            "changed": diff.changed.len(),
            "edge_changes": diff.edge_diffs.len(),
            "metadata_changed": diff.metadata_changed.is_some(),
        });

        if let Some(mc) = &diff.metadata_changed {
            summary["metadata_changes"] = serde_json::to_value(mc)?;
        }

        if opts.has_warnings() {
            summary["warnings"] = serde_json::json!({
                "old": opts.old_warnings,
                "new": opts.new_warnings,
            });
        }

        if opts.group_by_ecosystem {
            let breakdown = diff.ecosystem_breakdown();
            if !breakdown.is_empty() {
                summary["ecosystem_breakdown"] = serde_json::to_value(&breakdown)?;
            }
        }

        serde_json::to_writer_pretty(writer, &summary)
            .map_err(|e| anyhow::anyhow!("json summary: {}", e))
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
                changes: vec![FieldChange::Version(Some("1.0".into()), Some("1.1".into()))],
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
        // Should NOT contain raw hash IDs
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
        // Authors not changed, should not appear
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

    // --- SARIF renderer tests ---

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
        assert_eq!(rules.len(), 5);

        let rule_ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert_eq!(
            rule_ids,
            vec![
                "component-added",
                "component-removed",
                "component-changed",
                "dependency-changed",
                "metadata-changed",
            ]
        );

        // Check that each rule has required fields
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

        // Check rule IDs
        let rule_ids: Vec<&str> = results
            .iter()
            .map(|r| r["ruleId"].as_str().unwrap())
            .collect();
        assert!(rule_ids.contains(&"component-added"));
        assert!(rule_ids.contains(&"component-removed"));
        assert!(rule_ids.contains(&"component-changed"));

        // Added component is note level
        let added = results
            .iter()
            .find(|r| r["ruleId"] == "component-added")
            .unwrap();
        assert_eq!(added["level"], "note");
        assert!(added["message"]["text"].as_str().unwrap().contains("added"));

        // Removed component is warning level
        let removed = results
            .iter()
            .find(|r| r["ruleId"] == "component-removed")
            .unwrap();
        assert_eq!(removed["level"], "warning");

        // Changed component is warning level
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
        assert!(msg.contains("hashes changed"));
        assert!(msg.contains("ecosystem:"));

        let dep = results
            .iter()
            .find(|r| r["ruleId"] == "dependency-changed")
            .unwrap();
        assert_eq!(dep["level"], "note");
        let dep_msg = dep["message"]["text"].as_str().unwrap();
        assert!(dep_msg.contains("Dependency changed:"));
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

        // Each result's ruleIndex should match its ruleId position in rules array
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
        // Should use resolved display names, not raw hash IDs
        assert!(msg.contains("my-app@1.0"));
        assert!(msg.contains("old-dep@0.1"));
        assert!(msg.contains("new-dep@0.2"));
    }

    #[test]
    fn test_sarif_renderer_locations_present_and_well_formed() {
        // Component results: added, removed, changed all get "package" locations
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
                ll[0]["fullyQualifiedName"].as_str().unwrap().len() > 0,
                "{rule_id}: fullyQualifiedName should be non-empty"
            );
            assert_eq!(ll[0]["kind"], "package", "{rule_id}: kind should be package");
        }

        // Dependency result: uses parent display name
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

        // Metadata result: uses "metadata" with kind "module"
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
}
