//! output renderers for displaying SBOM diffs.
//!
//! this module provides formatters for different output contexts:
//!
//! - [`TextRenderer`] - Plain text for terminal output
//! - [`MarkdownRenderer`] - GitHub-flavored markdown for PR comments
//! - [`JsonRenderer`] - Machine-readable JSON for tooling integration
//! - [`SarifRenderer`] - SARIF 2.1.0 for GitHub Code Scanning / Azure DevOps
//! - [`CsvRenderer`] - RFC 4180 CSV for spreadsheets, CI dashboards, and data pipelines

mod csv_format;
mod json;
mod markdown;
mod sarif;
mod text;

pub use csv_format::CsvRenderer;
pub use json::JsonRenderer;
pub use markdown::MarkdownRenderer;
pub use sarif::SarifRenderer;
pub use text::TextRenderer;

use crate::{ComponentChange, Diff, EcosystemCounts, EdgeDiff, FieldChange};
use sbom_model::{Component, DependencyKind};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

/// options controlling how diffs are rendered.
#[derive(Debug, Clone, Default)]
pub struct RenderOptions {
    /// when true, include a per-ecosystem breakdown of added/removed/changed counts.
    pub group_by_ecosystem: bool,
    /// when true, include parser warnings in the output.
    pub show_warnings: bool,
    /// parser warnings from the old SBOM.
    pub old_warnings: Vec<String>,
    /// parser warnings from the new SBOM.
    pub new_warnings: Vec<String>,
}

impl RenderOptions {
    /// returns true when warnings should be displayed.
    pub fn has_warnings(&self) -> bool {
        self.show_warnings && (!self.old_warnings.is_empty() || !self.new_warnings.is_empty())
    }

    /// total number of warnings across both SBOMs.
    pub fn warning_count(&self) -> usize {
        self.old_warnings.len() + self.new_warnings.len()
    }
}

/// returns a display suffix for a dependency kind.
/// runtime dependencies get no suffix (they are the default/common case).
pub(super) fn kind_suffix(kind: &DependencyKind) -> &'static str {
    match kind {
        DependencyKind::Runtime => "",
        DependencyKind::Dev => " (dev)",
        DependencyKind::Build => " (build)",
        DependencyKind::Test => " (test)",
        DependencyKind::Optional => " (optional)",
        DependencyKind::Provided => " (provided)",
    }
}

/// formats an `Option<String>` for display, returning `"<none>"` for `None`.
pub fn format_option(opt: &Option<String>) -> &str {
    opt.as_deref().unwrap_or("<none>")
}

/// formats a `BTreeSet<String>` as a comma-separated string, or `"<none>"` if empty.
pub fn format_set(set: &BTreeSet<String>) -> String {
    if set.is_empty() {
        "<none>".to_string()
    } else {
        let mut out = String::new();
        for (i, s) in set.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(s);
        }
        out
    }
}

/// trait for rendering a [`Diff`] to an output stream.
pub trait Renderer {
    /// writes the formatted diff to the provided writer.
    fn render<W: Write>(
        &self,
        diff: &Diff,
        opts: &RenderOptions,
        writer: &mut W,
    ) -> anyhow::Result<()>;
}

/// trait for rendering a summary (counts only, no component details) to an output stream.
///
/// mirrors [`Renderer`] but produces compact output suitable for `--summary` mode.
pub trait SummaryRenderer {
    /// writes a summary-only view of the diff to the provided writer.
    fn render_summary<W: Write>(
        &self,
        diff: &Diff,
        opts: &RenderOptions,
        writer: &mut W,
    ) -> anyhow::Result<()>;
}

pub(super) trait FieldChangeFormatter {
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

pub(super) fn write_field_changes<F: FieldChangeFormatter, W: Write>(
    fmt: &F,
    writer: &mut W,
    changes: &[FieldChange],
    is_downgrade: bool,
) -> std::io::Result<()> {
    for change in changes {
        match change {
            FieldChange::Version(old, new) => {
                let label = if is_downgrade {
                    "Version (downgrade)"
                } else {
                    "Version"
                };
                fmt.field_change(writer, label, format_option(old), format_option(new))?;
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

pub(super) fn write_changed<F: FieldChangeFormatter, W: Write>(
    fmt: &F,
    writer: &mut W,
    changes: &[ComponentChange],
) -> std::io::Result<()> {
    for c in changes {
        fmt.component_header(writer, c.new.purl.as_deref().unwrap_or(c.id.as_str()))?;
        write_field_changes(fmt, writer, &c.changes, c.is_downgrade)?;
    }
    Ok(())
}

/// format-specific building blocks for summary output.
///
/// text and markdown renderers implement this trait; the shared
/// [`write_summary`] function orchestrates calls in the correct order.
/// JSON uses a fundamentally different approach (building a single
/// serializable value) and implements [`SummaryRenderer`] directly.
pub(super) trait SummaryFormatter {
    fn write_warnings<W: Write>(&self, w: &mut W, opts: &RenderOptions) -> std::io::Result<()>;
    fn write_counts<W: Write>(&self, w: &mut W, diff: &Diff) -> std::io::Result<()>;
    fn write_ecosystem_breakdown<W: Write>(
        &self,
        w: &mut W,
        breakdown: &BTreeMap<String, EcosystemCounts>,
    ) -> std::io::Result<()>;
}

pub(super) fn write_summary<F: SummaryFormatter, W: Write>(
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

/// which component section is being rendered.
///
/// used by [`FullFormatter::section_open`] to pick the correct heading.
#[derive(Clone, Copy)]
pub(super) enum SectionKind {
    Added,
    Removed,
    Changed,
}

/// format-specific building blocks for the full (non-summary) diff output.
///
/// text and markdown renderers implement this trait; the shared
/// [`write_full`] function walks the diff and calls these hooks in the
/// correct order, so both formats share one section skeleton. each hook
/// owns the exact bytes (including blank lines) for its piece of output.
/// JSON/SARIF/CSV build serializable values or write records and are
/// structurally different, so they implement [`Renderer`] directly.
pub(super) trait FullFormatter: FieldChangeFormatter {
    /// warnings block, only called when [`RenderOptions::has_warnings`].
    fn full_warnings<W: Write>(&self, w: &mut W, opts: &RenderOptions) -> std::io::Result<()>;
    /// summary-count header plus its trailing blank line.
    fn full_count_header<W: Write>(&self, w: &mut W, diff: &Diff) -> std::io::Result<()>;
    /// per-ecosystem count table (only in `group_by_ecosystem` mode).
    fn full_ecosystem_breakdown<W: Write>(
        &self,
        w: &mut W,
        breakdown: &BTreeMap<String, EcosystemCounts>,
    ) -> std::io::Result<()>;
    /// heading introducing one ecosystem's sections.
    fn full_ecosystem_header<W: Write>(&self, w: &mut W, ecosystem: &str) -> std::io::Result<()>;
    /// opens an added/removed/changed section (heading only).
    fn section_open<W: Write>(
        &self,
        w: &mut W,
        kind: SectionKind,
        count: usize,
    ) -> std::io::Result<()>;
    /// closes an added/removed/changed section, emitting the trailing blank line.
    fn section_close<W: Write>(&self, w: &mut W) -> std::io::Result<()>;
    /// renders the component list body of an added or removed section.
    fn component_list<W: Write>(&self, w: &mut W, components: &[Component]) -> std::io::Result<()>;
    /// opens the edge-changes section.
    fn edge_open<W: Write>(&self, w: &mut W, count: usize) -> std::io::Result<()>;
    /// renders one parent's edge changes.
    fn edge_entry<W: Write>(&self, w: &mut W, diff: &Diff, edge: &EdgeDiff) -> std::io::Result<()>;
    /// closes the edge-changes section.
    fn edge_close<W: Write>(&self, w: &mut W) -> std::io::Result<()>;
    /// opens the metadata-changes section.
    fn metadata_open<W: Write>(&self, w: &mut W) -> std::io::Result<()>;
    /// closes the metadata-changes section.
    fn metadata_close<W: Write>(&self, w: &mut W) -> std::io::Result<()>;
}

pub(super) fn write_full<F: FullFormatter, W: Write>(
    fmt: &F,
    diff: &Diff,
    opts: &RenderOptions,
    writer: &mut W,
) -> std::io::Result<()> {
    if opts.has_warnings() {
        fmt.full_warnings(writer, opts)?;
    }

    fmt.full_count_header(writer, diff)?;

    if opts.group_by_ecosystem {
        let grouped = diff.group_by_ecosystem();
        let breakdown = grouped.ecosystem_breakdown();
        fmt.full_ecosystem_breakdown(writer, &breakdown)?;
        for (ecosystem, eco_diff) in &grouped.by_ecosystem {
            fmt.full_ecosystem_header(writer, ecosystem)?;
            write_full_sections(
                fmt,
                writer,
                &eco_diff.added,
                &eco_diff.removed,
                &eco_diff.changed,
            )?;
        }
    } else {
        write_full_sections(fmt, writer, &diff.added, &diff.removed, &diff.changed)?;
    }

    if !diff.edge_diffs.is_empty() {
        fmt.edge_open(writer, diff.edge_diffs.len())?;
        for edge in &diff.edge_diffs {
            fmt.edge_entry(writer, diff, edge)?;
        }
        fmt.edge_close(writer)?;
    }

    if let Some(mc) = &diff.metadata_changed {
        writeln!(writer)?;
        fmt.metadata_open(writer)?;
        if let Some((old, new)) = &mc.timestamp {
            fmt.field_change(writer, "Timestamp", format_option(old), format_option(new))?;
        }
        if let Some((old, new)) = &mc.tools {
            fmt.field_change(
                writer,
                "Tools",
                &format_vec_or_none(old),
                &format_vec_or_none(new),
            )?;
        }
        if let Some((old, new)) = &mc.authors {
            fmt.field_change(
                writer,
                "Authors",
                &format_vec_or_none(old),
                &format_vec_or_none(new),
            )?;
        }
        fmt.metadata_close(writer)?;
    }

    Ok(())
}

fn write_full_sections<F: FullFormatter, W: Write>(
    fmt: &F,
    writer: &mut W,
    added: &[Component],
    removed: &[Component],
    changed: &[ComponentChange],
) -> std::io::Result<()> {
    if !added.is_empty() {
        fmt.section_open(writer, SectionKind::Added, added.len())?;
        fmt.component_list(writer, added)?;
        fmt.section_close(writer)?;
    }
    if !removed.is_empty() {
        fmt.section_open(writer, SectionKind::Removed, removed.len())?;
        fmt.component_list(writer, removed)?;
        fmt.section_close(writer)?;
    }
    if !changed.is_empty() {
        fmt.section_open(writer, SectionKind::Changed, changed.len())?;
        write_changed(fmt, writer, changed)?;
        fmt.section_close(writer)?;
    }
    Ok(())
}

pub(super) fn format_vec_or_none(v: &[String]) -> String {
    if v.is_empty() {
        "<none>".to_string()
    } else {
        v.join(", ")
    }
}

#[cfg(test)]
mod tests;
