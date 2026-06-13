use super::{RenderOptions, Renderer, SummaryRenderer};
use crate::{Diff, EcosystemCounts, GroupedDiff};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Write;

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
