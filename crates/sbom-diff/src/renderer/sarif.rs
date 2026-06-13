use super::{
    format_option, format_set, format_vec_or_none, kind_suffix, RenderOptions, Renderer,
    SummaryRenderer,
};
use crate::{Diff, FieldChange};
use sbom_model::Component;
use serde::Serialize;
use std::io::Write;

// --- SARIF 2.1.0 output ---

const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";

// Rule indices (must match order in SARIF_RULES)
const RULE_COMPONENT_ADDED: usize = 0;
const RULE_COMPONENT_REMOVED: usize = 1;
const RULE_COMPONENT_CHANGED: usize = 2;
const RULE_DEPENDENCY_CHANGED: usize = 3;
const RULE_METADATA_CHANGED: usize = 4;
const RULE_PARSER_WARNING: usize = 5;

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
    RuleInfo {
        id: "parser-warning",
        short_desc: "Parser warning",
        full_desc: "The SBOM parser emitted a warning about the input document",
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

    fn build_results(diff: &Diff, opts: &RenderOptions) -> Vec<SarifResultEntry> {
        let mut results = Vec::new();

        if opts.has_warnings() {
            for w in &opts.old_warnings {
                results.push(SarifResultEntry {
                    rule_id: SARIF_RULES[RULE_PARSER_WARNING].id,
                    rule_index: RULE_PARSER_WARNING,
                    level: SARIF_RULES[RULE_PARSER_WARNING].level,
                    message: SarifTextMessage {
                        text: format!("Parser warning (old SBOM): {}", w),
                    },
                    locations: vec![SarifLocation {
                        logical_locations: vec![SarifLogicalLocation {
                            fully_qualified_name: "old-sbom".to_string(),
                            kind: "module",
                        }],
                    }],
                });
            }
            for w in &opts.new_warnings {
                results.push(SarifResultEntry {
                    rule_id: SARIF_RULES[RULE_PARSER_WARNING].id,
                    rule_index: RULE_PARSER_WARNING,
                    level: SARIF_RULES[RULE_PARSER_WARNING].level,
                    message: SarifTextMessage {
                        text: format!("Parser warning (new SBOM): {}", w),
                    },
                    locations: vec![SarifLocation {
                        logical_locations: vec![SarifLogicalLocation {
                            fully_qualified_name: "new-sbom".to_string(),
                            kind: "module",
                        }],
                    }],
                });
            }
        }

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
        opts: &RenderOptions,
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
                results: Self::build_results(diff, opts),
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
