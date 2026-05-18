//! Output renderers for displaying SBOM diffs.
//!
//! This module provides formatters for different output contexts:
//!
//! - [`TextRenderer`] - Plain text for terminal output
//! - [`MarkdownRenderer`] - GitHub-flavored markdown for PR comments
//! - [`JsonRenderer`] - Machine-readable JSON for tooling integration
//! - [`HtmlRenderer`] - Self-contained HTML for browser-viewable reports

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
                fmt.field_change(writer, "Version", old, new)?;
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
        writeln!(writer, "Old total:   {} components", diff.old_total)?;
        writeln!(writer, "New total:   {} components", diff.new_total)?;
        writeln!(writer, "Unchanged:   {}", diff.unchanged)?;
        writeln!(writer, "Added:       {}", diff.added.len())?;
        writeln!(writer, "Removed:     {}", diff.removed.len())?;
        writeln!(writer, "Changed:     {}", diff.changed.len())?;
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
                for removed in &edge.removed {
                    writeln!(writer, "  - {}", diff.display_name(removed))?;
                }
                for added in &edge.added {
                    writeln!(writer, "  + {}", diff.display_name(added))?;
                }
            }
        }

        Ok(())
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
                    for removed in &edge.removed {
                        writeln!(writer, "- `{}`", diff.display_name(removed))?;
                    }
                }
                if !edge.added.is_empty() {
                    writeln!(writer, "**Added dependencies:**")?;
                    for added in &edge.added {
                        writeln!(writer, "- `{}`", diff.display_name(added))?;
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

// --- HTML output helpers ---

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

fn write_html_component_list<W: Write>(
    writer: &mut W,
    components: &[Component],
    class: &str,
) -> std::io::Result<()> {
    writeln!(writer, "<ul class=\"{}\">", class)?;
    for c in components {
        writeln!(
            writer,
            "<li><code>{}</code></li>",
            html_escape(c.purl.as_deref().unwrap_or(c.id.as_str()))
        )?;
    }
    writeln!(writer, "</ul>")
}

/// Self-contained HTML renderer for browser-viewable diff reports.
///
/// Produces a complete HTML document with inline CSS. All SBOM data is
/// HTML-escaped to prevent injection.
pub struct HtmlRenderer;

impl FieldChangeFormatter for HtmlRenderer {
    fn field_change<W: Write>(
        &self,
        w: &mut W,
        name: &str,
        old: &str,
        new: &str,
    ) -> std::io::Result<()> {
        writeln!(
            w,
            "<div class=\"field-change\"><strong>{}</strong>: \
             <code class=\"old-value\">{}</code> &rarr; \
             <code class=\"new-value\">{}</code></div>",
            html_escape(name),
            html_escape(old),
            html_escape(new)
        )
    }

    fn hash_header<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        writeln!(
            w,
            "<div class=\"field-change\"><strong>Hashes</strong>:</div>"
        )
    }

    fn hash_removed<W: Write>(&self, w: &mut W, algo: &str, digest: &str) -> std::io::Result<()> {
        writeln!(
            w,
            "<div class=\"hash-detail removed\"><code>{}</code>: \
             removed <code>{}</code></div>",
            html_escape(algo),
            html_escape(digest)
        )
    }

    fn hash_changed<W: Write>(
        &self,
        w: &mut W,
        algo: &str,
        old: &str,
        new: &str,
    ) -> std::io::Result<()> {
        writeln!(
            w,
            "<div class=\"hash-detail changed\"><code>{}</code>: \
             <code class=\"old-value\">{}</code> &rarr; \
             <code class=\"new-value\">{}</code></div>",
            html_escape(algo),
            html_escape(old),
            html_escape(new)
        )
    }

    fn hash_added<W: Write>(&self, w: &mut W, algo: &str, digest: &str) -> std::io::Result<()> {
        writeln!(
            w,
            "<div class=\"hash-detail added\"><code>{}</code>: \
             added <code>{}</code></div>",
            html_escape(algo),
            html_escape(digest)
        )
    }

    fn component_header<W: Write>(&self, w: &mut W, id: &str) -> std::io::Result<()> {
        writeln!(
            w,
            "<h4 class=\"component-id\"><code>{}</code></h4>",
            html_escape(id)
        )
    }
}

const HTML_CSS: &str = r#"<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
         max-width: 960px; margin: 0 auto; padding: 2rem; color: #24292f; background: #fff; }
  h1 { border-bottom: 1px solid #d0d7de; padding-bottom: .5rem; }
  h3 { margin-top: 1.5rem; }
  table { border-collapse: collapse; margin: 1rem 0; }
  th, td { border: 1px solid #d0d7de; padding: .4rem .8rem; text-align: left; }
  th { background: #f6f8fa; }
  code { background: #f6f8fa; padding: .15rem .3rem; border-radius: 3px; font-size: .9em; }
  details { margin: .5rem 0; }
  summary { cursor: pointer; font-weight: 600; padding: .3rem 0; }
  .section { margin: 1.5rem 0; }
  .added { color: #1a7f37; }
  .removed { color: #cf222e; }
  .changed { color: #9a6700; }
  .warning { color: #bf8700; }
  .field-change { margin-left: 1.5rem; padding: .15rem 0; }
  .hash-detail { margin-left: 3rem; padding: .1rem 0; }
  .old-value { text-decoration: line-through; opacity: .7; }
  .component-id { margin: .8rem 0 .2rem 0; font-size: 1rem; }
  ul { margin: .3rem 0; padding-left: 1.5rem; }
  li { margin: .15rem 0; }
</style>"#;

impl Renderer for HtmlRenderer {
    fn render<W: Write>(
        &self,
        diff: &Diff,
        opts: &RenderOptions,
        writer: &mut W,
    ) -> anyhow::Result<()> {
        writeln!(writer, "<!DOCTYPE html>")?;
        writeln!(writer, "<html lang=\"en\"><head>")?;
        writeln!(writer, "<meta charset=\"utf-8\">")?;
        writeln!(
            writer,
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        )?;
        writeln!(writer, "<title>SBOM Diff Report</title>")?;
        writeln!(writer, "{}", HTML_CSS)?;
        writeln!(writer, "</head><body>")?;
        writeln!(writer, "<h1>SBOM Diff Report</h1>")?;

        if opts.has_warnings() {
            writeln!(writer, "<details class=\"section\">")?;
            writeln!(
                writer,
                "<summary class=\"warning\">Warnings ({})</summary>",
                opts.warning_count()
            )?;
            writeln!(writer, "<ul>")?;
            for w in &opts.old_warnings {
                writeln!(writer, "<li><strong>old:</strong> {}</li>", html_escape(w))?;
            }
            for w in &opts.new_warnings {
                writeln!(writer, "<li><strong>new:</strong> {}</li>", html_escape(w))?;
            }
            writeln!(writer, "</ul>")?;
            writeln!(writer, "</details>")?;
        }

        writeln!(writer, "<h3>Summary</h3>")?;
        writeln!(writer, "<table>")?;
        writeln!(writer, "<tr><th>Metric</th><th>Count</th></tr>")?;
        writeln!(
            writer,
            "<tr><td>Old total</td><td>{}</td></tr>",
            diff.old_total
        )?;
        writeln!(
            writer,
            "<tr><td>New total</td><td>{}</td></tr>",
            diff.new_total
        )?;
        writeln!(
            writer,
            "<tr><td>Unchanged</td><td>{}</td></tr>",
            diff.unchanged
        )?;
        writeln!(
            writer,
            "<tr><td class=\"added\">Added</td><td>{}</td></tr>",
            diff.added.len()
        )?;
        writeln!(
            writer,
            "<tr><td class=\"removed\">Removed</td><td>{}</td></tr>",
            diff.removed.len()
        )?;
        writeln!(
            writer,
            "<tr><td class=\"changed\">Changed</td><td>{}</td></tr>",
            diff.changed.len()
        )?;
        writeln!(writer, "</table>")?;

        if opts.group_by_ecosystem {
            let grouped = diff.group_by_ecosystem();
            let breakdown = grouped.ecosystem_breakdown();

            writeln!(writer, "<h3>By Ecosystem</h3>")?;
            writeln!(writer, "<table>")?;
            writeln!(
                writer,
                "<tr><th>Ecosystem</th><th>Added</th><th>Removed</th><th>Changed</th></tr>"
            )?;
            for (eco, counts) in &breakdown {
                writeln!(
                    writer,
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    html_escape(eco),
                    counts.added,
                    counts.removed,
                    counts.changed
                )?;
            }
            writeln!(writer, "</table>")?;

            for (eco, eco_diff) in &grouped.by_ecosystem {
                writeln!(writer, "<h3>{}</h3>", html_escape(eco))?;
                if !eco_diff.added.is_empty() {
                    writeln!(writer, "<details class=\"section\" open>")?;
                    writeln!(
                        writer,
                        "<summary class=\"added\">Added ({})</summary>",
                        eco_diff.added.len()
                    )?;
                    write_html_component_list(writer, &eco_diff.added, "added")?;
                    writeln!(writer, "</details>")?;
                }
                if !eco_diff.removed.is_empty() {
                    writeln!(writer, "<details class=\"section\" open>")?;
                    writeln!(
                        writer,
                        "<summary class=\"removed\">Removed ({})</summary>",
                        eco_diff.removed.len()
                    )?;
                    write_html_component_list(writer, &eco_diff.removed, "removed")?;
                    writeln!(writer, "</details>")?;
                }
                if !eco_diff.changed.is_empty() {
                    writeln!(writer, "<details class=\"section\" open>")?;
                    writeln!(
                        writer,
                        "<summary class=\"changed\">Changed ({})</summary>",
                        eco_diff.changed.len()
                    )?;
                    write_changed(self, writer, &eco_diff.changed)?;
                    writeln!(writer, "</details>")?;
                }
            }
        } else {
            if !diff.added.is_empty() {
                writeln!(writer, "<details class=\"section\" open>")?;
                writeln!(
                    writer,
                    "<summary class=\"added\">Added ({})</summary>",
                    diff.added.len()
                )?;
                write_html_component_list(writer, &diff.added, "added")?;
                writeln!(writer, "</details>")?;
            }

            if !diff.removed.is_empty() {
                writeln!(writer, "<details class=\"section\" open>")?;
                writeln!(
                    writer,
                    "<summary class=\"removed\">Removed ({})</summary>",
                    diff.removed.len()
                )?;
                write_html_component_list(writer, &diff.removed, "removed")?;
                writeln!(writer, "</details>")?;
            }

            if !diff.changed.is_empty() {
                writeln!(writer, "<details class=\"section\" open>")?;
                writeln!(
                    writer,
                    "<summary class=\"changed\">Changed ({})</summary>",
                    diff.changed.len()
                )?;
                write_changed(self, writer, &diff.changed)?;
                writeln!(writer, "</details>")?;
            }
        }

        if !diff.edge_diffs.is_empty() {
            writeln!(writer, "<details class=\"section\" open>")?;
            writeln!(
                writer,
                "<summary class=\"changed\">Edge Changes ({})</summary>",
                diff.edge_diffs.len()
            )?;
            for edge in &diff.edge_diffs {
                writeln!(
                    writer,
                    "<h4 class=\"component-id\"><code>{}</code></h4>",
                    html_escape(diff.display_name(&edge.parent))
                )?;
                if !edge.removed.is_empty() {
                    writeln!(writer, "<div><strong>Removed dependencies:</strong></div>")?;
                    writeln!(writer, "<ul class=\"removed\">")?;
                    for removed in &edge.removed {
                        writeln!(
                            writer,
                            "<li><code>{}</code></li>",
                            html_escape(diff.display_name(removed))
                        )?;
                    }
                    writeln!(writer, "</ul>")?;
                }
                if !edge.added.is_empty() {
                    writeln!(writer, "<div><strong>Added dependencies:</strong></div>")?;
                    writeln!(writer, "<ul class=\"added\">")?;
                    for added in &edge.added {
                        writeln!(
                            writer,
                            "<li><code>{}</code></li>",
                            html_escape(diff.display_name(added))
                        )?;
                    }
                    writeln!(writer, "</ul>")?;
                }
            }
            writeln!(writer, "</details>")?;
        }

        writeln!(writer, "</body></html>")?;
        Ok(())
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
        writeln!(w, "Old total:    {} components", diff.old_total)?;
        writeln!(w, "New total:    {} components", diff.new_total)?;
        writeln!(w, "Unchanged:    {}", diff.unchanged)?;
        writeln!(w, "Added:        {}", diff.added.len())?;
        writeln!(w, "Removed:      {}", diff.removed.len())?;
        writeln!(w, "Changed:      {}", diff.changed.len())?;
        writeln!(w, "Edge changes: {}", diff.edge_diffs.len())
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
        writeln!(w, "| Edge changes | {} |", diff.edge_diffs.len())
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
        });

        if opts.has_warnings() {
            summary["warnings"] = serde_json::json!({
                "old": opts.old_warnings,
                "new": opts.new_warnings,
            });
        }

        if opts.group_by_ecosystem {
            let breakdown = diff.ecosystem_breakdown();
            if !breakdown.is_empty() {
                summary["ecosystem_breakdown"] =
                    serde_json::to_value(&breakdown).expect("serializable breakdown");
            }
        }

        serde_json::to_writer_pretty(writer, &summary)
            .map_err(|e| anyhow::anyhow!("json summary: {}", e))
    }
}

impl SummaryFormatter for HtmlRenderer {
    fn write_warnings<W: Write>(&self, w: &mut W, opts: &RenderOptions) -> std::io::Result<()> {
        writeln!(w, "<details class=\"section\">")?;
        writeln!(
            w,
            "<summary class=\"warning\">Warnings ({})</summary>",
            opts.warning_count()
        )?;
        writeln!(w, "<ul>")?;
        for warning in &opts.old_warnings {
            writeln!(w, "<li><strong>old:</strong> {}</li>", html_escape(warning))?;
        }
        for warning in &opts.new_warnings {
            writeln!(w, "<li><strong>new:</strong> {}</li>", html_escape(warning))?;
        }
        writeln!(w, "</ul>")?;
        writeln!(w, "</details>")
    }

    fn write_counts<W: Write>(&self, w: &mut W, diff: &Diff) -> std::io::Result<()> {
        writeln!(w, "<h3>Summary</h3>")?;
        writeln!(w, "<table>")?;
        writeln!(w, "<tr><th>Metric</th><th>Count</th></tr>")?;
        writeln!(w, "<tr><td>Old total</td><td>{}</td></tr>", diff.old_total)?;
        writeln!(w, "<tr><td>New total</td><td>{}</td></tr>", diff.new_total)?;
        writeln!(w, "<tr><td>Unchanged</td><td>{}</td></tr>", diff.unchanged)?;
        writeln!(
            w,
            "<tr><td class=\"added\">Added</td><td>{}</td></tr>",
            diff.added.len()
        )?;
        writeln!(
            w,
            "<tr><td class=\"removed\">Removed</td><td>{}</td></tr>",
            diff.removed.len()
        )?;
        writeln!(
            w,
            "<tr><td class=\"changed\">Changed</td><td>{}</td></tr>",
            diff.changed.len()
        )?;
        writeln!(
            w,
            "<tr><td>Edge changes</td><td>{}</td></tr>",
            diff.edge_diffs.len()
        )?;
        writeln!(w, "</table>")
    }

    fn write_ecosystem_breakdown<W: Write>(
        &self,
        w: &mut W,
        breakdown: &BTreeMap<String, EcosystemCounts>,
    ) -> std::io::Result<()> {
        writeln!(w, "<h4>By Ecosystem</h4>")?;
        writeln!(w, "<table>")?;
        writeln!(
            w,
            "<tr><th>Ecosystem</th><th>Added</th><th>Removed</th><th>Changed</th></tr>"
        )?;
        for (eco, counts) in breakdown {
            writeln!(
                w,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(eco),
                counts.added,
                counts.removed,
                counts.changed
            )?;
        }
        writeln!(w, "</table>")
    }
}

impl SummaryRenderer for HtmlRenderer {
    fn render_summary<W: Write>(
        &self,
        diff: &Diff,
        opts: &RenderOptions,
        writer: &mut W,
    ) -> anyhow::Result<()> {
        writeln!(writer, "<!DOCTYPE html>")?;
        writeln!(writer, "<html lang=\"en\"><head>")?;
        writeln!(writer, "<meta charset=\"utf-8\">")?;
        writeln!(
            writer,
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        )?;
        writeln!(writer, "<title>SBOM Diff Summary</title>")?;
        writeln!(writer, "{}", HTML_CSS)?;
        writeln!(writer, "</head><body>")?;
        writeln!(writer, "<h1>SBOM Diff Summary</h1>")?;
        write_summary(self, diff, opts, writer)?;
        writeln!(writer, "</body></html>")?;
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
            ..Diff::default()
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

        assert!(out.contains("Old total:   0 components"));
        assert!(out.contains("New total:   0 components"));
        assert!(out.contains("Unchanged:   0"));
        assert!(out.contains("Added:       0"));
        assert!(out.contains("Removed:     0"));
        assert!(out.contains("Changed:     0"));
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
        use sbom_model::ComponentId;
        use std::collections::BTreeSet;

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
                added: BTreeSet::from([child_b_id]),
                removed: BTreeSet::from([child_a_id]),
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

        assert!(out.contains("Old total:   10 components"));
        assert!(out.contains("New total:   12 components"));
        assert!(out.contains("Unchanged:   5"));
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

    // --- HTML renderer tests ---

    #[test]
    fn test_html_renderer_basic() {
        let diff = mock_diff();
        let mut buf = Vec::new();
        HtmlRenderer
            .render(&diff, &RenderOptions::default(), &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.starts_with("<!DOCTYPE html>"));
        assert!(out.contains("</html>"));
        assert!(out.contains("<h1>SBOM Diff Report</h1>"));
        assert!(out.contains("<style>"));
        assert!(out.contains("Added (1)"));
        assert!(out.contains("Removed (1)"));
        assert!(out.contains("Changed (1)"));
    }

    #[test]
    fn test_html_renderer_all_field_changes() {
        let diff = mock_diff_all_field_changes();
        let mut buf = Vec::new();
        HtmlRenderer
            .render(&diff, &RenderOptions::default(), &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("<strong>Version</strong>"));
        assert!(out.contains("<strong>License</strong>"));
        assert!(out.contains("<strong>Supplier</strong>"));
        assert!(out.contains("<strong>Purl</strong>"));
        assert!(out.contains("<strong>Description</strong>"));
        assert!(out.contains("<strong>Hashes</strong>"));
        assert!(out.contains("Edge Changes"));
    }

    #[test]
    fn test_html_renderer_empty_diff() {
        let diff = mock_diff_empty();
        let mut buf = Vec::new();
        HtmlRenderer
            .render(&diff, &RenderOptions::default(), &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("<td>0</td>"));
        assert!(!out.contains("Added ("));
        assert!(!out.contains("Removed ("));
        assert!(!out.contains("Changed ("));
    }

    #[test]
    fn test_html_renderer_group_by_ecosystem() {
        let diff = mock_diff_with_ecosystems();
        let opts = RenderOptions {
            group_by_ecosystem: true,
            ..Default::default()
        };
        let mut buf = Vec::new();
        HtmlRenderer.render(&diff, &opts, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("By Ecosystem"));
        assert!(out.contains("<td>cargo</td>"));
        assert!(out.contains("<td>npm</td>"));
    }

    #[test]
    fn test_html_renderer_shows_warnings() {
        let diff = mock_diff();
        let opts = opts_with_warnings();
        let mut buf = Vec::new();
        HtmlRenderer.render(&diff, &opts, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("Warnings (2)"));
        assert!(out.contains("<strong>old:</strong>"));
        assert!(out.contains("<strong>new:</strong>"));
        assert!(out.contains("orphaned ref &#x27;SPDXRef-foo&#x27;"));
    }

    #[test]
    fn test_html_renderer_hides_warnings_by_default() {
        let diff = mock_diff();
        let mut buf = Vec::new();
        HtmlRenderer
            .render(&diff, &RenderOptions::default(), &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(!out.contains("Warnings"));
    }

    #[test]
    fn test_html_renderer_resolves_edge_diff_names() {
        let diff = mock_diff_with_hash_edge_diffs();
        let mut buf = Vec::new();
        HtmlRenderer
            .render(&diff, &RenderOptions::default(), &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("my-app@1.0"));
        assert!(out.contains("old-dep@0.1"));
        assert!(out.contains("new-dep@0.2"));
        // Verify no raw hash IDs leak into the rendered component names.
        // We can't check `!out.contains("h:")` because CSS properties like
        // `max-width:` naturally contain that substring.
        for edge in &diff.edge_diffs {
            let parent_raw = edge.parent.as_str();
            if parent_raw.starts_with("h:") {
                assert!(
                    !out.contains(parent_raw),
                    "raw hash ID should not appear in output"
                );
            }
        }
    }

    #[test]
    fn test_html_escaping() {
        use sbom_model::ComponentId;

        // Create components with purls containing HTML special chars,
        // since purl is what gets rendered (hash-based IDs won't contain them).
        let mut c_added = Component::new("xss-pkg".into(), Some("1.0".into()));
        c_added.purl = Some("pkg:npm/<b>xss</b>@1.0".into());
        c_added.id = ComponentId::new(c_added.purl.as_deref(), &[]);

        let mut c1 = Component::new("vuln-pkg".into(), Some("1.0".into()));
        c1.purl = Some("pkg:npm/<script>alert(1)</script>@1.0".into());
        c1.id = ComponentId::new(c1.purl.as_deref(), &[]);
        let mut c2 = c1.clone();
        c2.version = Some("1.1".into());

        let diff = Diff {
            added: vec![c_added],
            removed: vec![],
            changed: vec![ComponentChange {
                id: c2.id.clone(),
                old: c1,
                new: c2,
                changes: vec![FieldChange::Version("1.0".into(), "1.1".into())],
            }],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let mut buf = Vec::new();
        HtmlRenderer
            .render(&diff, &RenderOptions::default(), &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        // Raw HTML tags must not appear unescaped
        assert!(!out.contains("<script>"));
        assert!(!out.contains("<b>xss</b>"));
        // Escaped versions should be present
        assert!(out.contains("&lt;script&gt;"));
        assert!(out.contains("&lt;b&gt;xss&lt;/b&gt;"));
    }

    #[test]
    fn test_html_summary() {
        let diff = mock_diff();
        let mut buf = Vec::new();
        HtmlRenderer
            .render_summary(&diff, &RenderOptions::default(), &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.starts_with("<!DOCTYPE html>"));
        assert!(out.contains("<h1>SBOM Diff Summary</h1>"));
        assert!(out.contains("<table>"));
        assert!(out.contains("Edge changes"));
        assert!(!out.contains("Added ("));
    }

    #[test]
    fn test_html_summary_with_ecosystems() {
        let diff = mock_diff_with_ecosystems();
        let opts = RenderOptions {
            group_by_ecosystem: true,
            ..Default::default()
        };
        let mut buf = Vec::new();
        HtmlRenderer.render_summary(&diff, &opts, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("By Ecosystem"));
        assert!(out.contains("<td>cargo</td>"));
        assert!(out.contains("<td>npm</td>"));
    }

    #[test]
    fn test_html_summary_with_warnings() {
        let diff = mock_diff();
        let opts = opts_with_warnings();
        let mut buf = Vec::new();
        HtmlRenderer.render_summary(&diff, &opts, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("Warnings (2)"));
        assert!(out.contains("<strong>old:</strong>"));
    }

    #[test]
    fn test_html_summary_no_warnings_without_flag() {
        let diff = mock_diff();
        let opts = RenderOptions {
            show_warnings: false,
            old_warnings: vec!["some warning".into()],
            ..Default::default()
        };
        let mut buf = Vec::new();
        HtmlRenderer.render_summary(&diff, &opts, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(!out.contains("Warnings"));
    }

    #[test]
    fn test_html_escape_function() {
        assert_eq!(html_escape("hello"), "hello");
        assert_eq!(html_escape("<>&\"'"), "&lt;&gt;&amp;&quot;&#x27;");
        assert_eq!(html_escape("a<b>c"), "a&lt;b&gt;c");
        assert_eq!(html_escape(""), "");
    }
}
