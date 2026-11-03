use super::{
    kind_suffix, write_full, write_summary, FieldChangeFormatter, FullFormatter, Labels,
    RenderOptions, Renderer, SectionKind, SummaryFormatter, SummaryRenderer,
};
use crate::{Diff, EcosystemCounts, EdgeDiff};
use sbom_model::Component;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::Write;

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
        writeln!(w, "  {}: {} -> {}", name, escaped(old), escaped(new))
    }

    fn hash_header<W: Write>(&self, w: &mut W, downgrade: bool) -> std::io::Result<()> {
        if downgrade {
            writeln!(w, "  Hashes (algorithm downgrade):")
        } else {
            writeln!(w, "  Hashes:")
        }
    }

    fn hash_removed<W: Write>(&self, w: &mut W, algo: &str, digest: &str) -> std::io::Result<()> {
        writeln!(w, "    - {}: {}", escaped(algo), escaped(digest))
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
            "    ~ {}: {} -> {}",
            escaped(algo),
            escaped(old),
            escaped(new)
        )
    }

    fn hash_added<W: Write>(&self, w: &mut W, algo: &str, digest: &str) -> std::io::Result<()> {
        writeln!(w, "    + {}: {}", escaped(algo), escaped(digest))
    }

    fn component_header<W: Write>(&self, w: &mut W, id: &str) -> std::io::Result<()> {
        writeln!(w, "{}", escaped(id))
    }
}

impl FullFormatter for TextRenderer {
    fn full_warnings<W: Write>(&self, w: &mut W, opts: &RenderOptions) -> std::io::Result<()> {
        writeln!(w, "[!] Warnings")?;
        writeln!(w, "------------")?;
        for warning in &opts.old_warnings {
            writeln!(w, "[old] {}", escaped(warning))?;
        }
        for warning in &opts.new_warnings {
            writeln!(w, "[new] {}", escaped(warning))?;
        }
        writeln!(w)
    }

    fn full_count_header<W: Write>(&self, w: &mut W, diff: &Diff) -> std::io::Result<()> {
        writeln!(w, "Diff Summary")?;
        writeln!(w, "============")?;
        self.write_counts(w, diff)?;
        writeln!(w)
    }

    fn full_ecosystem_breakdown<W: Write>(
        &self,
        w: &mut W,
        breakdown: &BTreeMap<String, EcosystemCounts>,
    ) -> std::io::Result<()> {
        writeln!(w, "By Ecosystem")?;
        writeln!(w, "------------")?;
        for (eco, counts) in breakdown {
            writeln!(
                w,
                "{}: {} added, {} removed, {} changed",
                escaped(eco),
                counts.added,
                counts.removed,
                counts.changed
            )?;
        }
        writeln!(w)
    }

    fn full_ecosystem_header<W: Write>(&self, w: &mut W, ecosystem: &str) -> std::io::Result<()> {
        writeln!(w, "[{}]", escaped(ecosystem))?;
        writeln!(w)
    }

    fn section_open<W: Write>(
        &self,
        w: &mut W,
        kind: SectionKind,
        _count: usize,
    ) -> std::io::Result<()> {
        match kind {
            SectionKind::Added => {
                writeln!(w, "[+] Added")?;
                writeln!(w, "---------")
            }
            SectionKind::Removed => {
                writeln!(w, "[-] Removed")?;
                writeln!(w, "-----------")
            }
            SectionKind::Changed => {
                writeln!(w, "[~] Changed")?;
                writeln!(w, "-----------")
            }
        }
    }

    fn section_close<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        writeln!(w)
    }

    fn component_list<W: Write>(
        &self,
        w: &mut W,
        labels: &Labels,
        components: &[Component],
    ) -> std::io::Result<()> {
        for c in components {
            writeln!(w, "{}", escaped(labels.component(c)))?;
        }
        Ok(())
    }

    fn edge_open<W: Write>(&self, w: &mut W, _count: usize) -> std::io::Result<()> {
        writeln!(w, "[~] Edge Changes")?;
        writeln!(w, "----------------")
    }

    fn edge_entry<W: Write>(
        &self,
        w: &mut W,
        labels: &Labels,
        edge: &EdgeDiff,
    ) -> std::io::Result<()> {
        writeln!(w, "{}", escaped(labels.id(&edge.parent)))?;
        for (removed, kind) in &edge.removed {
            writeln!(
                w,
                "  - {}{}",
                escaped(labels.id(removed)),
                kind_suffix(kind)
            )?;
        }
        for (added, kind) in &edge.added {
            writeln!(w, "  + {}{}", escaped(labels.id(added)), kind_suffix(kind))?;
        }
        for (changed, (old_kind, new_kind)) in &edge.kind_changed {
            writeln!(
                w,
                "  ~ {} ({} -> {})",
                escaped(labels.id(changed)),
                old_kind,
                new_kind
            )?;
        }
        Ok(())
    }

    fn edge_close<W: Write>(&self, _w: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn metadata_open<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        writeln!(w, "[~] Metadata Changes")?;
        writeln!(w, "--------------------")
    }

    fn metadata_close<W: Write>(&self, _w: &mut W) -> std::io::Result<()> {
        Ok(())
    }
}

impl Renderer for TextRenderer {
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

impl SummaryFormatter for TextRenderer {
    fn write_warnings<W: Write>(&self, w: &mut W, opts: &RenderOptions) -> std::io::Result<()> {
        writeln!(w, "Warnings:     {}", opts.warning_count())?;
        for warning in &opts.old_warnings {
            writeln!(w, "  [old] {}", escaped(warning))?;
        }
        for warning in &opts.new_warnings {
            writeln!(w, "  [new] {}", escaped(warning))?;
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
                escaped(eco),
                counts.added,
                counts.removed,
                counts.changed
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

/// writes control and bidi characters as escapes, so a value can neither break nor reorder its line.
fn escaped(text: &str) -> Cow<'_, str> {
    if !text.contains(is_escaped) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if is_escaped(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

fn is_escaped(c: char) -> bool {
    c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}
