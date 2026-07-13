use super::{
    format_option, format_set, format_vec_or_none, RenderOptions, Renderer, SummaryRenderer,
};
use crate::{Diff, FieldChange};
use std::io::Write;

/// creates a [`csv::Writer`] configured for this crate's output conventions
/// (LF line endings, no BOM).
fn csv_writer<W: Write>(writer: W) -> csv::Writer<W> {
    csv::WriterBuilder::new()
        .terminator(csv::Terminator::Any(b'\n'))
        .from_writer(writer)
}

/// writes parser-warning rows using the `status,component,ecosystem,field,old_value,new_value`
/// schema, shared by the full and summary renderers so both surface warnings identically.
fn write_warning_rows<W: Write>(wtr: &mut csv::Writer<W>, opts: &RenderOptions) -> csv::Result<()> {
    for w in &opts.old_warnings {
        wtr.write_record(["warning", "old", "", "", w, ""])?;
    }
    for w in &opts.new_warnings {
        wtr.write_record(["warning", "new", "", "", w, ""])?;
    }
    Ok(())
}

/// RFC 4180 CSV renderer for spreadsheets, CI dashboards, and data pipelines.
///
/// full output produces one row per finding with columns:
/// `status,component,ecosystem,field,old_value,new_value`
///
/// summary output produces `metric,count` pairs.
pub struct CsvRenderer;

impl Renderer for CsvRenderer {
    fn render<W: Write>(
        &self,
        diff: &Diff,
        opts: &RenderOptions,
        writer: &mut W,
    ) -> anyhow::Result<()> {
        let mut wtr = csv_writer(&mut *writer);

        wtr.write_record([
            "status",
            "component",
            "ecosystem",
            "field",
            "old_value",
            "new_value",
        ])?;

        if opts.has_warnings() {
            write_warning_rows(&mut wtr, opts)?;
        }

        for comp in &diff.added {
            let display = comp.purl.as_deref().unwrap_or(comp.id.as_str());
            let eco = comp.ecosystem.as_deref().unwrap_or("");
            let ver = comp.version.as_deref().unwrap_or("");
            wtr.write_record(["added", display, eco, "version", "", ver])?;
        }

        for comp in &diff.removed {
            let display = comp.purl.as_deref().unwrap_or(comp.id.as_str());
            let eco = comp.ecosystem.as_deref().unwrap_or("");
            let ver = comp.version.as_deref().unwrap_or("");
            wtr.write_record(["removed", display, eco, "version", ver, ""])?;
        }

        for change in &diff.changed {
            let display = change.new.purl.as_deref().unwrap_or(change.id.as_str());
            let eco = change.new.ecosystem.as_deref().unwrap_or("");
            for fc in &change.changes {
                let (field, old, new) = csv_field_change(fc, change.is_downgrade);
                wtr.write_record(["changed", display, eco, field, &old, &new])?;
            }
        }

        for edge in &diff.edge_diffs {
            let parent = diff.display_name(&edge.parent);
            for (child, kind) in &edge.added {
                let child_name = diff.display_name(child);
                wtr.write_record(["edge-added", parent, "", child_name, "", &kind.to_string()])?;
            }
            for (child, kind) in &edge.removed {
                let child_name = diff.display_name(child);
                wtr.write_record([
                    "edge-removed",
                    parent,
                    "",
                    child_name,
                    &kind.to_string(),
                    "",
                ])?;
            }
            for (child, (old_kind, new_kind)) in &edge.kind_changed {
                let child_name = diff.display_name(child);
                wtr.write_record([
                    "edge-kind-changed",
                    parent,
                    "",
                    child_name,
                    &old_kind.to_string(),
                    &new_kind.to_string(),
                ])?;
            }
        }

        if let Some(mc) = &diff.metadata_changed {
            if let Some((ref old, ref new)) = mc.timestamp {
                wtr.write_record([
                    "metadata",
                    "",
                    "",
                    "timestamp",
                    old.as_deref().unwrap_or(""),
                    new.as_deref().unwrap_or(""),
                ])?;
            }
            if let Some((ref old, ref new)) = mc.tools {
                wtr.write_record([
                    "metadata",
                    "",
                    "",
                    "tools",
                    &format_vec_or_none(old),
                    &format_vec_or_none(new),
                ])?;
            }
            if let Some((ref old, ref new)) = mc.authors {
                wtr.write_record([
                    "metadata",
                    "",
                    "",
                    "authors",
                    &format_vec_or_none(old),
                    &format_vec_or_none(new),
                ])?;
            }
        }

        wtr.flush()?;
        Ok(())
    }
}

impl SummaryRenderer for CsvRenderer {
    fn render_summary<W: Write>(
        &self,
        diff: &Diff,
        opts: &RenderOptions,
        writer: &mut W,
    ) -> anyhow::Result<()> {
        let meta_changed = if diff.metadata_changed.is_some() {
            "1"
        } else {
            "0"
        };

        // warnings are emitted as a leading block sharing the full renderer's
        // schema, kept separate from the `metric,count` table (which has a
        // different column count) by a blank line, like the ecosystem breakdown.
        if opts.has_warnings() {
            let mut wtr = csv_writer(&mut *writer);
            wtr.write_record([
                "status",
                "component",
                "ecosystem",
                "field",
                "old_value",
                "new_value",
            ])?;
            write_warning_rows(&mut wtr, opts)?;
            wtr.flush()?;
            drop(wtr);
            writeln!(writer)?;
        }

        let mut wtr = csv_writer(&mut *writer);
        wtr.write_record(["metric", "count"])?;
        wtr.write_record(["old_total", &diff.old_total.to_string()])?;
        wtr.write_record(["new_total", &diff.new_total.to_string()])?;
        wtr.write_record(["unchanged", &diff.unchanged.to_string()])?;
        wtr.write_record(["added", &diff.added.len().to_string()])?;
        wtr.write_record(["removed", &diff.removed.len().to_string()])?;
        wtr.write_record(["changed", &diff.changed.len().to_string()])?;
        wtr.write_record(["edge_changes", &diff.edge_diffs.len().to_string()])?;
        wtr.write_record(["metadata_changed", meta_changed])?;

        wtr.flush()?;
        drop(wtr);

        if opts.group_by_ecosystem {
            let breakdown = diff.ecosystem_breakdown();
            if !breakdown.is_empty() {
                writeln!(writer)?;
                let mut wtr = csv_writer(&mut *writer);
                wtr.write_record(["ecosystem", "added", "removed", "changed"])?;
                for (eco, counts) in &breakdown {
                    wtr.write_record([
                        eco.as_str(),
                        &counts.added.to_string(),
                        &counts.removed.to_string(),
                        &counts.changed.to_string(),
                    ])?;
                }
                wtr.flush()?;
            }
        }

        Ok(())
    }
}

/// converts a [`FieldChange`] into `(field_name, old_value, new_value)` for CSV output.
fn csv_field_change(fc: &FieldChange, is_downgrade: bool) -> (&'static str, String, String) {
    match fc {
        FieldChange::Version(old, new) => (
            if is_downgrade {
                "version-downgrade"
            } else {
                "version"
            },
            format_option(old).to_string(),
            format_option(new).to_string(),
        ),
        FieldChange::License(old, new) => ("license", format_set(old), format_set(new)),
        FieldChange::Supplier(old, new) => (
            "supplier",
            format_option(old).to_string(),
            format_option(new).to_string(),
        ),
        FieldChange::Purl(old, new) => (
            "purl",
            format_option(old).to_string(),
            format_option(new).to_string(),
        ),
        FieldChange::Description(old, new) => (
            "description",
            format_option(old).to_string(),
            format_option(new).to_string(),
        ),
        FieldChange::Hashes(old, new) => {
            let old_str = old
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("; ");
            let new_str = new
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("; ");
            ("hashes", old_str, new_str)
        }
        FieldChange::Ecosystem(old, new) => (
            "ecosystem",
            format_option(old).to_string(),
            format_option(new).to_string(),
        ),
    }
}
