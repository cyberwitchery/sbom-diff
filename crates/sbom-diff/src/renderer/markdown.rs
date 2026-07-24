use super::{
    kind_suffix, write_full, write_summary, FieldChangeFormatter, FullFormatter, RenderOptions,
    Renderer, SectionKind, SummaryFormatter, SummaryRenderer,
};
use crate::{Diff, EcosystemCounts, EdgeDiff};
use sbom_model::Component;
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
        writeln!(w, "- **{}**: `{}` &rarr; `{}`", name, old, new)
    }

    fn hash_header<W: Write>(&self, w: &mut W, downgrade: bool) -> std::io::Result<()> {
        if downgrade {
            writeln!(w, "- **Hashes (algorithm downgrade)**:")
        } else {
            writeln!(w, "- **Hashes**:")
        }
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

impl FullFormatter for MarkdownRenderer {
    fn full_warnings<W: Write>(&self, w: &mut W, opts: &RenderOptions) -> std::io::Result<()> {
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
                eco, counts.added, counts.removed, counts.changed
            )?;
        }
        writeln!(w)
    }

    fn full_ecosystem_header<W: Write>(&self, w: &mut W, ecosystem: &str) -> std::io::Result<()> {
        writeln!(w, "#### {}", ecosystem)?;
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
            writeln!(w, "- `{}`", c.purl.as_deref().unwrap_or(c.id.as_str()))?;
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
        writeln!(w, "#### `{}`", diff.display_name(&edge.parent))?;
        if !edge.removed.is_empty() {
            writeln!(w, "**Removed dependencies:**")?;
            for (removed, kind) in &edge.removed {
                writeln!(w, "- `{}`{}", diff.display_name(removed), kind_suffix(kind))?;
            }
        }
        if !edge.added.is_empty() {
            writeln!(w, "**Added dependencies:**")?;
            for (added, kind) in &edge.added {
                writeln!(w, "- `{}`{}", diff.display_name(added), kind_suffix(kind))?;
            }
        }
        if !edge.kind_changed.is_empty() {
            writeln!(w, "**Kind changed:**")?;
            for (changed, (old_kind, new_kind)) in &edge.kind_changed {
                writeln!(
                    w,
                    "- `{}`: {} &rarr; {}",
                    diff.display_name(changed),
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
