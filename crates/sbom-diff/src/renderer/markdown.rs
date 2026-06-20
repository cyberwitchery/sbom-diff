use super::{
    format_vec_or_none, kind_suffix, write_changed, write_summary, FieldChangeFormatter,
    RenderOptions, Renderer, SummaryFormatter, SummaryRenderer,
};
use crate::{Diff, EcosystemCounts, MetadataChange};
use sbom_model::Component;
use std::collections::BTreeMap;
use std::io::Write;

fn write_md_added<W: Write>(writer: &mut W, components: &[Component]) -> std::io::Result<()> {
    for c in components {
        writeln!(writer, "- `{}`", c.purl.as_deref().unwrap_or(c.id.as_str()))?;
    }
    Ok(())
}

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
