mod format;

use anyhow::Context;
use clap::{Parser, ValueEnum};
use format::{load_sbom, Format};
use sbom_diff::{
    policy::{FailOn, Policy, Violation},
    renderer::{
        CsvRenderer, JsonRenderer, MarkdownRenderer, RenderOptions, Renderer, SarifRenderer,
        SummaryRenderer, TextRenderer,
    },
    Diff, DiffOptions, EcosystemFilter, Field,
};
use std::io::{self, Write};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// old sbom file (use - for stdin)
    old: String,

    /// new sbom file (use - for stdin)
    new: String,

    /// input format
    #[arg(short, long, value_enum, default_value_t = Format::Auto)]
    format: Format,

    /// output format
    #[arg(short, long, value_enum, default_value_t = Output::Text)]
    output: Output,

    /// deny these licenses (repeatable)
    #[arg(long)]
    deny_license: Vec<String>,

    /// allow only these licenses (repeatable)
    #[arg(long)]
    allow_license: Vec<String>,

    /// only report changes in these fields
    #[arg(long, value_enum, value_delimiter = ',')]
    only: Vec<Field>,

    /// fail on specific conditions (repeatable)
    #[arg(long, value_enum)]
    fail_on: Vec<FailOn>,

    /// only diff and gate these ecosystems (repeatable)
    #[arg(long)]
    include_ecosystem: Vec<String>,

    /// leave these ecosystems out of the diff and the gates (repeatable)
    #[arg(long)]
    exclude_ecosystem: Vec<String>,

    /// break down counts by package ecosystem (npm, cargo, pypi, etc)
    #[arg(long)]
    group_by_ecosystem: bool,

    /// print only summary counts (no component details)
    #[arg(long)]
    summary: bool,

    /// suppress all output except errors
    #[arg(short, long)]
    quiet: bool,

    /// include parser warnings in rendered output
    #[arg(long)]
    show_warnings: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Output {
    Text,
    Markdown,
    Json,
    Sarif,
    Csv,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let policy = Policy {
        fail_on: args.fail_on.clone(),
        deny_licenses: args.deny_license.clone(),
        allow_licenses: args.allow_license.clone(),
    };
    for issue in policy.entry_issues() {
        if issue.is_error() {
            anyhow::bail!("{issue}");
        }
        eprintln!("warning: {issue}");
    }

    let old_sbom = load_sbom(&args.old, args.format).context("failed to load old sbom")?;
    let new_sbom = load_sbom(&args.new, args.format).context("failed to load new sbom")?;

    for w in old_sbom.warnings.iter().chain(new_sbom.warnings.iter()) {
        eprintln!("warning: {}", w);
    }

    // the differ consumes both sboms, so copy the warnings out first.
    let mut render_opts = RenderOptions {
        group_by_ecosystem: args.group_by_ecosystem,
        show_warnings: args.show_warnings,
        old_warnings: old_sbom.warnings.clone(),
        new_warnings: new_sbom.warnings.clone(),
        violations: Vec::new(),
    };

    let options = DiffOptions {
        only: args.only.clone(),
        ecosystems: EcosystemFilter::new(&args.include_ecosystem, &args.exclude_ecosystem),
    };
    let (diff, violations) = policy.check(old_sbom, new_sbom, &options);
    for v in &violations {
        eprintln!("error: {v}");
    }
    render_opts.violations = violations;

    if !args.quiet {
        let written = write_report(
            args.output,
            args.summary,
            &diff,
            &render_opts,
            &mut io::stdout().lock(),
        );
        if let Err(err) = written {
            if !is_broken_pipe(&err) {
                return Err(err);
            }
        }
    }

    if render_opts
        .violations
        .iter()
        .any(Violation::is_license_policy)
    {
        std::process::exit(2);
    }

    if !render_opts.violations.is_empty() {
        std::process::exit(3);
    }

    Ok(())
}

fn write_report<W: Write>(
    output: Output,
    summary: bool,
    diff: &Diff,
    opts: &RenderOptions,
    out: &mut W,
) -> anyhow::Result<()> {
    if summary {
        match output {
            Output::Text => TextRenderer.render_summary(diff, opts, out)?,
            Output::Markdown => MarkdownRenderer.render_summary(diff, opts, out)?,
            Output::Json => JsonRenderer.render_summary(diff, opts, out)?,
            Output::Sarif => SarifRenderer.render_summary(diff, opts, out)?,
            Output::Csv => CsvRenderer.render_summary(diff, opts, out)?,
        }
    } else {
        match output {
            Output::Text => TextRenderer.render(diff, opts, out)?,
            Output::Markdown => MarkdownRenderer.render(diff, opts, out)?,
            Output::Json => JsonRenderer.render(diff, opts, out)?,
            Output::Sarif => SarifRenderer.render(diff, opts, out)?,
            Output::Csv => CsvRenderer.render(diff, opts, out)?,
        }
    }
    out.flush()?;
    Ok(())
}

fn is_broken_pipe(err: &anyhow::Error) -> bool {
    err.chain()
        .any(|cause| io_error_kind(cause) == Some(io::ErrorKind::BrokenPipe))
}

// serde_json's and csv's errors keep their io error out of `source()`.
fn io_error_kind(err: &(dyn std::error::Error + 'static)) -> Option<io::ErrorKind> {
    if let Some(e) = err.downcast_ref::<io::Error>() {
        Some(e.kind())
    } else if let Some(e) = err.downcast_ref::<serde_json::Error>() {
        e.io_error_kind()
    } else if let Some(csv::ErrorKind::Io(e)) =
        err.downcast_ref::<csv::Error>().map(csv::Error::kind)
    {
        Some(e.kind())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbom_model::Component;

    #[test]
    fn test_render_summary() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![
                Component::new("a".into(), Some("1".into())),
                Component::new("b".into(), Some("1".into())),
            ],
            removed: vec![Component::new("c".into(), Some("1".into()))],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let mut buf = Vec::new();
        TextRenderer
            .render_summary(&diff, &RenderOptions::default(), &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("Added:            2"));
        assert!(out.contains("Removed:          1"));
        assert!(out.contains("Changed:          0"));
        assert!(out.contains("Edge changes:     0"));
    }

    #[test]
    fn test_render_summary_with_edge_diffs() {
        use sbom_diff::{Diff, EdgeDiff};
        use sbom_model::{ComponentId, DependencyKind};
        use std::collections::BTreeMap;

        let diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![
                EdgeDiff {
                    parent: ComponentId::new(None, &[("name", "pkg-a")]),
                    added: BTreeMap::from([(
                        ComponentId::new(None, &[("name", "pkg-b")]),
                        DependencyKind::Runtime,
                    )]),
                    removed: BTreeMap::new(),
                    kind_changed: BTreeMap::new(),
                },
                EdgeDiff {
                    parent: ComponentId::new(None, &[("name", "pkg-c")]),
                    added: BTreeMap::new(),
                    removed: BTreeMap::from([(
                        ComponentId::new(None, &[("name", "pkg-d")]),
                        DependencyKind::Runtime,
                    )]),
                    kind_changed: BTreeMap::new(),
                },
            ],
            ..Diff::default()
        };

        let mut buf = Vec::new();
        TextRenderer
            .render_summary(&diff, &RenderOptions::default(), &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("Edge changes:     2"));
    }

    #[test]
    fn test_render_summary_markdown() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![
                Component::new("a".into(), Some("1".into())),
                Component::new("b".into(), Some("1".into())),
            ],
            removed: vec![Component::new("c".into(), Some("1".into()))],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let mut buf = Vec::new();
        MarkdownRenderer
            .render_summary(&diff, &RenderOptions::default(), &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("### SBOM Diff Summary"));
        assert!(out.contains("| Metric | Count |"));
        assert!(out.contains("| Old total | 0 |"));
        assert!(out.contains("| New total | 0 |"));
        assert!(out.contains("| Unchanged | 0 |"));
        assert!(out.contains("| Added | 2 |"));
        assert!(out.contains("| Removed | 1 |"));
        assert!(out.contains("| Changed | 0 |"));
        assert!(out.contains("| Edge changes | 0 |"));
        // should NOT contain component details
        assert!(!out.contains("<details>"));
    }

    #[test]
    fn test_render_summary_markdown_with_ecosystems() {
        use sbom_diff::Diff;

        let mut added_npm = Component::new("express".into(), Some("4.18.0".into()));
        added_npm.ecosystem = Some("npm".into());
        let mut added_cargo = Component::new("serde".into(), Some("1.0.0".into()));
        added_cargo.ecosystem = Some("cargo".into());
        let mut removed = Component::new("lodash".into(), Some("4.17.21".into()));
        removed.ecosystem = Some("npm".into());

        let diff = Diff {
            added: vec![added_npm, added_cargo],
            removed: vec![removed],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let opts = RenderOptions {
            group_by_ecosystem: true,
            ..Default::default()
        };

        let mut buf = Vec::new();
        MarkdownRenderer
            .render_summary(&diff, &opts, &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("#### By Ecosystem"));
        assert!(out.contains("| Ecosystem | Added | Removed | Changed |"));
        assert!(out.contains("| cargo | 1 | 0 | 0 |"));
        assert!(out.contains("| npm | 1 | 1 | 0 |"));
    }

    #[test]
    fn test_render_summary_json() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![
                Component::new("a".into(), Some("1".into())),
                Component::new("b".into(), Some("1".into())),
            ],
            removed: vec![Component::new("c".into(), Some("1".into()))],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let mut buf = Vec::new();
        JsonRenderer
            .render_summary(&diff, &RenderOptions::default(), &mut buf)
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

        assert_eq!(val["added"], 2);
        assert_eq!(val["removed"], 1);
        assert_eq!(val["changed"], 0);
        assert_eq!(val["edge_changes"], 0);
        assert!(val.get("ecosystem_breakdown").is_none());
    }

    #[test]
    fn test_render_summary_json_with_ecosystems() {
        use sbom_diff::Diff;

        let mut added_npm = Component::new("express".into(), Some("4.18.0".into()));
        added_npm.ecosystem = Some("npm".into());

        let diff = Diff {
            added: vec![added_npm],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let opts = RenderOptions {
            group_by_ecosystem: true,
            ..Default::default()
        };

        let mut buf = Vec::new();
        JsonRenderer.render_summary(&diff, &opts, &mut buf).unwrap();
        let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

        assert_eq!(val["added"], 1);
        let breakdown = &val["ecosystem_breakdown"];
        assert!(breakdown.is_object());
        assert_eq!(breakdown["npm"]["added"], 1);
    }

    #[test]
    fn test_render_summary_text_with_warnings() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![Component::new("a".into(), Some("1".into()))],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let opts = RenderOptions {
            show_warnings: true,
            old_warnings: vec!["old sbom missing supplier".into()],
            new_warnings: vec!["new sbom missing license".into()],
            ..Default::default()
        };

        let mut buf = Vec::new();
        TextRenderer.render_summary(&diff, &opts, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("Warnings:     2"));
        assert!(out.contains("[old] old sbom missing supplier"));
        assert!(out.contains("[new] new sbom missing license"));
        assert!(out.contains("Added:            1"));
    }

    #[test]
    fn test_render_summary_markdown_with_warnings() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![Component::new("a".into(), Some("1".into()))],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let opts = RenderOptions {
            show_warnings: true,
            old_warnings: vec!["old sbom missing supplier".into()],
            new_warnings: vec!["new sbom missing license".into()],
            ..Default::default()
        };

        let mut buf = Vec::new();
        MarkdownRenderer
            .render_summary(&diff, &opts, &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("<details><summary><b>Warnings (2)</b></summary>"));
        assert!(out.contains("- **old:** old sbom missing supplier"));
        assert!(out.contains("- **new:** new sbom missing license"));
        assert!(out.contains("</details>"));
        assert!(out.contains("### SBOM Diff Summary"));
        assert!(out.contains("| Added | 1 |"));
    }

    #[test]
    fn test_render_summary_markdown_no_warnings_without_flag() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let opts = RenderOptions {
            show_warnings: false,
            old_warnings: vec!["some warning".into()],
            ..Default::default()
        };

        let mut buf = Vec::new();
        MarkdownRenderer
            .render_summary(&diff, &opts, &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(!out.contains("Warnings"));
        assert!(!out.contains("<details>"));
    }

    #[test]
    fn test_render_summary_json_with_warnings() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![Component::new("a".into(), Some("1".into()))],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let opts = RenderOptions {
            show_warnings: true,
            old_warnings: vec!["old sbom missing supplier".into()],
            new_warnings: vec!["new sbom missing license".into()],
            ..Default::default()
        };

        let mut buf = Vec::new();
        JsonRenderer.render_summary(&diff, &opts, &mut buf).unwrap();
        let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

        assert_eq!(val["added"], 1);
        let warnings = &val["warnings"];
        assert!(warnings.is_object());
        assert_eq!(warnings["old"][0], "old sbom missing supplier");
        assert_eq!(warnings["new"][0], "new sbom missing license");
    }

    #[test]
    fn test_render_summary_json_no_warnings_without_flag() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let opts = RenderOptions {
            show_warnings: false,
            old_warnings: vec!["some warning".into()],
            ..Default::default()
        };

        let mut buf = Vec::new();
        JsonRenderer.render_summary(&diff, &opts, &mut buf).unwrap();
        let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

        assert!(val.get("warnings").is_none());
    }

    #[test]
    fn every_renderer_reports_a_closed_pipe_as_a_broken_pipe() {
        struct Pipe {
            kind: io::ErrorKind,
            writes: bool,
        }
        impl Write for Pipe {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                if self.writes {
                    Ok(buf.len())
                } else {
                    Err(self.kind.into())
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(self.kind.into())
            }
        }

        // enough rows to overflow csv's write buffer before its flush
        let diff = Diff {
            added: (0..1000)
                .map(|i| Component::new(format!("c{i}"), Some("1".into())))
                .collect(),
            ..Diff::default()
        };
        for (kind, writes, broken) in [
            (io::ErrorKind::BrokenPipe, false, true),
            (io::ErrorKind::BrokenPipe, true, true),
            (io::ErrorKind::StorageFull, false, false),
        ] {
            for &output in Output::value_variants() {
                for summary in [false, true] {
                    let mut pipe = Pipe { kind, writes };
                    let err =
                        write_report(output, summary, &diff, &RenderOptions::default(), &mut pipe)
                            .unwrap_err();
                    assert_eq!(
                        is_broken_pipe(&err),
                        broken,
                        "{output:?} summary={summary} writes={writes}: {err:?}"
                    );
                }
            }
        }
    }
}
