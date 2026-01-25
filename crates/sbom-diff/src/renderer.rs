use crate::{Diff, FieldChange};
use std::io::Write;

pub trait Renderer {
    fn render<W: Write>(&self, diff: &Diff, writer: &mut W) -> anyhow::Result<()>;
}

pub struct TextRenderer;

impl Renderer for TextRenderer {
    fn render<W: Write>(&self, diff: &Diff, writer: &mut W) -> anyhow::Result<()> {
        writeln!(writer, "Diff Summary")?;
        writeln!(writer, "============")?;
        writeln!(writer, "Added:   {}", diff.added.len())?;
        writeln!(writer, "Removed: {}", diff.removed.len())?;
        writeln!(writer, "Changed: {}", diff.changed.len())?;
        writeln!(writer)?;

        if !diff.added.is_empty() {
            writeln!(writer, "[+] Added")?;
            writeln!(writer, "---------")?;
            for c in &diff.added {
                writeln!(writer, "{}", c.purl.as_deref().unwrap_or(c.id.as_str()))?;
            }
            writeln!(writer)?;
        }

        if !diff.removed.is_empty() {
            writeln!(writer, "[-] Removed")?;
            writeln!(writer, "-----------")?;
            for c in &diff.removed {
                writeln!(writer, "{}", c.purl.as_deref().unwrap_or(c.id.as_str()))?;
            }
            writeln!(writer)?;
        }

        if !diff.changed.is_empty() {
            writeln!(writer, "[~] Changed")?;
            writeln!(writer, "-----------")?;
            for c in &diff.changed {
                writeln!(writer, "{}", c.new.purl.as_deref().unwrap_or(c.id.as_str()))?;
                for change in &c.changes {
                    match change {
                        FieldChange::Version(old, new) => {
                            writeln!(writer, "  Version: {} -> {}", old, new)?;
                        }
                        FieldChange::License(old, new) => {
                            writeln!(writer, "  License: {:?} -> {:?}", old, new)?;
                        }
                        FieldChange::Supplier(old, new) => {
                            writeln!(writer, "  Supplier: {:?} -> {:?}", old, new)?;
                        }
                        FieldChange::Purl(old, new) => {
                            writeln!(writer, "  Purl: {:?} -> {:?}", old, new)?;
                        }
                        FieldChange::Hashes => {
                            writeln!(writer, "  Hashes: changed")?;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

pub struct MarkdownRenderer;

impl Renderer for MarkdownRenderer {
    fn render<W: Write>(&self, diff: &Diff, writer: &mut W) -> anyhow::Result<()> {
        writeln!(writer, "### SBOM Diff Summary")?;
        writeln!(writer)?;
        writeln!(writer, "| Change | Count |")?;
        writeln!(writer, "| --- | --- |")?;
        writeln!(writer, "| Added | {} |", diff.added.len())?;
        writeln!(writer, "| Removed | {} |", diff.removed.len())?;
        writeln!(writer, "| Changed | {} |", diff.changed.len())?;
        writeln!(writer)?;

        if !diff.added.is_empty() {
            writeln!(
                writer,
                "<details><summary><b>Added ({})</b></summary>",
                diff.added.len()
            )?;
            writeln!(writer)?;
            for c in &diff.added {
                writeln!(writer, "- `{}`", c.purl.as_deref().unwrap_or(c.id.as_str()))?;
            }
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
            for c in &diff.removed {
                writeln!(writer, "- `{}`", c.purl.as_deref().unwrap_or(c.id.as_str()))?;
            }
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
            for c in &diff.changed {
                writeln!(
                    writer,
                    "#### `{}`",
                    c.new.purl.as_deref().unwrap_or(c.id.as_str())
                )?;
                for change in &c.changes {
                    match change {
                        FieldChange::Version(old, new) => {
                            writeln!(writer, "- **Version**: `{}` &rarr; `{}`", old, new)?;
                        }
                        FieldChange::License(old, new) => {
                            writeln!(writer, "- **License**: `{:?}` &rarr; `{:?}`", old, new)?;
                        }
                        FieldChange::Supplier(old, new) => {
                            writeln!(writer, "- **Supplier**: `{:?}` &rarr; `{:?}`", old, new)?;
                        }
                        FieldChange::Purl(old, new) => {
                            writeln!(writer, "- **Purl**: `{:?}` &rarr; `{:?}`", old, new)?;
                        }
                        FieldChange::Hashes => {
                            writeln!(writer, "- **Hashes**: changed")?;
                        }
                    }
                }
            }
            writeln!(writer, "</details>")?;
        }

        Ok(())
    }
}

pub struct JsonRenderer;

impl Renderer for JsonRenderer {
    fn render<W: Write>(&self, diff: &Diff, writer: &mut W) -> anyhow::Result<()> {
        serde_json::to_writer_pretty(writer, diff)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ComponentChange, Diff, FieldChange};
    use sbom_model::Component;

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
            metadata_changed: false,
        }
    }

    #[test]
    fn test_text_renderer() {
        let diff = mock_diff();
        let mut buf = Vec::new();
        TextRenderer.render(&diff, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("Diff Summary"));
        assert!(out.contains("[+] Added"));
        assert!(out.contains("[-] Removed"));
        assert!(out.contains("[~] Changed"));
    }

    #[test]
    fn test_markdown_renderer() {
        let diff = mock_diff();
        let mut buf = Vec::new();
        MarkdownRenderer.render(&diff, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("### SBOM Diff Summary"));
        assert!(out.contains("<details>"));
    }

    #[test]
    fn test_json_renderer() {
        let diff = mock_diff();
        let mut buf = Vec::new();
        JsonRenderer.render(&diff, &mut buf).unwrap();
        let _: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    }
}
