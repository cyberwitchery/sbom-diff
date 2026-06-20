use super::{
    format_vec_or_none, kind_suffix, write_changed, write_summary, FieldChangeFormatter,
    RenderOptions, Renderer, SummaryFormatter, SummaryRenderer,
};
use crate::{Diff, EcosystemCounts, MetadataChange};
use sbom_model::Component;
use std::collections::BTreeMap;
use std::io::Write;

fn write_text_added<W: Write>(writer: &mut W, components: &[Component]) -> std::io::Result<()> {
    for c in components {
        writeln!(writer, "{}", c.purl.as_deref().unwrap_or(c.id.as_str()))?;
    }
    Ok(())
}

/// plain text renderer for terminal output.
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
