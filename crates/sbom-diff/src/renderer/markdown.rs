use super::{
    kind_suffix, write_full, write_summary, FieldChangeFormatter, FullFormatter, RenderOptions,
    Renderer, SectionKind, SummaryFormatter, SummaryRenderer,
};
use crate::{Diff, EcosystemCounts, EdgeDiff};
use sbom_model::Component;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::Write;

/// GitHub-flavored markdown renderer for PR comments.
///
/// produces collapsible sections using `<details>` tags.
pub struct MarkdownRenderer;

impl FieldChangeFormatter for MarkdownRenderer {
    fn field_change<W: Write>(
        &self,
        w: &mut W,
        name: &str,
        old: &str,
        new: &str,
    ) -> std::io::Result<()> {
        writeln!(
            w,
            "- **{}**: {} &rarr; {}",
            name,
            code_span(old),
            code_span(new)
        )
    }

    fn hash_header<W: Write>(&self, w: &mut W, downgrade: bool) -> std::io::Result<()> {
        if downgrade {
            writeln!(w, "- **Hashes (algorithm downgrade)**:")
        } else {
            writeln!(w, "- **Hashes**:")
        }
    }

    fn hash_removed<W: Write>(&self, w: &mut W, algo: &str, digest: &str) -> std::io::Result<()> {
        writeln!(w, "  - {}: removed {}", code_span(algo), code_span(digest))
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
            "  - {}: {} &rarr; {}",
            code_span(algo),
            code_span(old),
            code_span(new)
        )
    }

    fn hash_added<W: Write>(&self, w: &mut W, algo: &str, digest: &str) -> std::io::Result<()> {
        writeln!(w, "  - {}: added {}", code_span(algo), code_span(digest))
    }

    fn component_header<W: Write>(&self, w: &mut W, id: &str) -> std::io::Result<()> {
        writeln!(w, "#### {}", code_span(id))
    }
}

impl FullFormatter for MarkdownRenderer {
    fn full_warnings<W: Write>(&self, w: &mut W, opts: &RenderOptions) -> std::io::Result<()> {
        writeln!(
            w,
            "<details><summary><b>Warnings ({})</b></summary>",
            opts.warning_count()
        )?;
        writeln!(w)?;
        for warning in &opts.old_warnings {
            writeln!(w, "- **old:** {}", escape_markdown(warning))?;
        }
        for warning in &opts.new_warnings {
            writeln!(w, "- **new:** {}", escape_markdown(warning))?;
        }
        writeln!(w, "</details>")?;
        writeln!(w)
    }

    fn full_count_header<W: Write>(&self, w: &mut W, diff: &Diff) -> std::io::Result<()> {
        self.write_counts(w, diff)?;
        writeln!(w)
    }

    fn full_ecosystem_breakdown<W: Write>(
        &self,
        w: &mut W,
        breakdown: &BTreeMap<String, EcosystemCounts>,
    ) -> std::io::Result<()> {
        writeln!(w, "#### By Ecosystem")?;
        writeln!(w)?;
        writeln!(w, "| Ecosystem | Added | Removed | Changed |")?;
        writeln!(w, "| --- | --- | --- | --- |")?;
        for (eco, counts) in breakdown {
            writeln!(
                w,
                "| {} | {} | {} | {} |",
                escape_table_cell(eco),
                counts.added,
                counts.removed,
                counts.changed
            )?;
        }
        writeln!(w)
    }

    fn full_ecosystem_header<W: Write>(&self, w: &mut W, ecosystem: &str) -> std::io::Result<()> {
        writeln!(w, "#### {}", escape_heading(ecosystem))?;
        writeln!(w)
    }

    fn section_open<W: Write>(
        &self,
        w: &mut W,
        kind: SectionKind,
        count: usize,
    ) -> std::io::Result<()> {
        let label = match kind {
            SectionKind::Added => "Added",
            SectionKind::Removed => "Removed",
            SectionKind::Changed => "Changed",
        };
        writeln!(
            w,
            "<details><summary><b>{} ({})</b></summary>",
            label, count
        )?;
        writeln!(w)
    }

    fn section_close<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        writeln!(w, "</details>")?;
        writeln!(w)
    }

    fn component_list<W: Write>(&self, w: &mut W, components: &[Component]) -> std::io::Result<()> {
        for c in components {
            writeln!(
                w,
                "- {}",
                code_span(c.purl.as_deref().unwrap_or(c.id.as_str()))
            )?;
        }
        Ok(())
    }

    fn edge_open<W: Write>(&self, w: &mut W, count: usize) -> std::io::Result<()> {
        writeln!(
            w,
            "<details><summary><b>Edge Changes ({})</b></summary>",
            count
        )?;
        writeln!(w)
    }

    fn edge_entry<W: Write>(&self, w: &mut W, diff: &Diff, edge: &EdgeDiff) -> std::io::Result<()> {
        writeln!(w, "#### {}", code_span(diff.display_name(&edge.parent)))?;
        if !edge.removed.is_empty() {
            writeln!(w, "**Removed dependencies:**")?;
            for (removed, kind) in &edge.removed {
                writeln!(
                    w,
                    "- {}{}",
                    code_span(diff.display_name(removed)),
                    kind_suffix(kind)
                )?;
            }
        }
        if !edge.added.is_empty() {
            writeln!(w, "**Added dependencies:**")?;
            for (added, kind) in &edge.added {
                writeln!(
                    w,
                    "- {}{}",
                    code_span(diff.display_name(added)),
                    kind_suffix(kind)
                )?;
            }
        }
        if !edge.kind_changed.is_empty() {
            writeln!(w, "**Kind changed:**")?;
            for (changed, (old_kind, new_kind)) in &edge.kind_changed {
                writeln!(
                    w,
                    "- {}: {} &rarr; {}",
                    code_span(diff.display_name(changed)),
                    old_kind,
                    new_kind
                )?;
            }
        }
        writeln!(w)
    }

    fn edge_close<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        writeln!(w, "</details>")
    }

    fn metadata_open<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        writeln!(w, "<details><summary><b>Metadata Changes</b></summary>")?;
        writeln!(w)
    }

    fn metadata_close<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        writeln!(w, "</details>")
    }
}

impl Renderer for MarkdownRenderer {
    fn render<W: Write>(
        &self,
        diff: &Diff,
        opts: &RenderOptions,
        writer: &mut W,
    ) -> anyhow::Result<()> {
        write_full(self, diff, opts, writer)?;
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
            writeln!(w, "- **old:** {}", escape_markdown(warning))?;
        }
        for warning in &opts.new_warnings {
            writeln!(w, "- **new:** {}", escape_markdown(warning))?;
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
                escape_table_cell(eco),
                counts.added,
                counts.removed,
                counts.changed
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

/// markdown openers that are significant anywhere in a line, not just at its start.
const INLINE_MARKDOWN: &[char] = &['\\', '`', '*', '_', '[', ']', '<', '&', '~'];

/// replaces each line ending with a space, as CommonMark does inside a code span.
fn one_line(text: &str) -> Cow<'_, str> {
    if text.contains(['\r', '\n']) {
        Cow::Owned(text.replace("\r\n", " ").replace(['\r', '\n'], " "))
    } else {
        Cow::Borrowed(text)
    }
}

/// backslash-escapes the inline markdown syntax in a value so it renders as literal text.
fn escape_markdown(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in one_line(text).chars() {
        if INLINE_MARKDOWN.contains(&c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// escapes a value for a table cell, which GFM splits on every unescaped `|`.
fn escape_table_cell(text: &str) -> String {
    escape_markdown(text).replace('|', "\\|")
}

/// escapes a value for an ATX heading, where a trailing `#` run would close the heading.
fn escape_heading(text: &str) -> String {
    escape_markdown(text).replace('#', "\\#")
}

/// wraps a value in a code span whose fence outgrows any backtick run inside it; empty text stays empty.
fn code_span(text: &str) -> String {
    let text = one_line(text);
    if text.is_empty() {
        return String::new();
    }
    let longest_run = text.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat(longest_run + 1);
    let pad = text.starts_with('`')
        || text.ends_with('`')
        || (text.starts_with(' ') && text.ends_with(' ') && text.bytes().any(|b| b != b' '));
    if pad {
        format!("{fence} {text} {fence}")
    } else {
        format!("{fence}{text}{fence}")
    }
}
