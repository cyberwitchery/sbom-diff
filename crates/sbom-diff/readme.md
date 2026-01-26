# sbom-diff

diff engine and cli for sbom comparison.

compares two software bills of materials and reports added, removed, and changed components. supports both cyclonedx and spdx formats.

## cli usage

```bash
# compare two sboms (auto-detects format)
sbom-diff old.json new.json

# read old sbom from stdin
cat old.json | sbom-diff - new.json

# markdown output for pr comments
sbom-diff old.json new.json -o markdown

# json output for tooling
sbom-diff old.json new.json -o json

# filter to specific fields
sbom-diff old.json new.json --only version,license

# license gating
sbom-diff old.json new.json --deny-license GPL-3.0-only
sbom-diff old.json new.json --allow-license MIT --allow-license Apache-2.0
```

### exit codes

| code | meaning |
|------|---------|
| 0 | success (diff computed, no license violations) |
| 1 | error (parse failure, file not found, etc.) |
| 2 | license violation (when using `--deny-license` or `--allow-license`) |

see the [project readme](https://github.com/cyberwitchery/sbom-diff) for full cli documentation.

## library usage

use the `Differ` struct directly to integrate into your own tools:

```rust
use sbom_diff::{Differ, Diff, FieldChange, Field};
use sbom_model::Sbom;

fn compare(old: &Sbom, new: &Sbom) -> Diff {
    // compare all fields
    let diff = Differ::diff(old, new, None);

    // or filter to specific fields
    let diff = Differ::diff(old, new, Some(&[Field::Version, Field::License]));

    println!("added: {}", diff.added.len());
    println!("removed: {}", diff.removed.len());
    println!("changed: {}", diff.changed.len());

    for change in &diff.changed {
        println!("{}:", change.id);
        for field in &change.changes {
            match field {
                FieldChange::Version(old, new) => {
                    println!("  version: {} -> {}", old, new);
                }
                FieldChange::License(old, new) => {
                    println!("  license: {:?} -> {:?}", old, new);
                }
                _ => {}
            }
        }
    }

    diff
}
```

## renderers

built-in renderers for common output formats:

```rust
use sbom_diff::{Diff, renderer::{Renderer, TextRenderer, MarkdownRenderer, JsonRenderer}};
use std::io::stdout;

fn render(diff: &Diff) -> anyhow::Result<()> {
    let mut out = stdout().lock();

    // plain text (default)
    TextRenderer.render(diff, &mut out)?;

    // markdown with collapsible sections
    MarkdownRenderer.render(diff, &mut out)?;

    // json for machine consumption
    JsonRenderer.render(diff, &mut out)?;

    Ok(())
}
```

## how matching works

components are matched in two passes:

1. **by id**: components with the same `ComponentId` (usually purl) are paired
2. **by identity**: unmatched components are reconciled by name + ecosystem

this allows detecting version bumps even when the purl changes (e.g., `pkg:npm/foo@1.0` vs `pkg:npm/foo@2.0`).

## related crates

- [`sbom-model`](https://docs.rs/sbom-model) - the core data model
- [`sbom-model-cyclonedx`](https://docs.rs/sbom-model-cyclonedx) - cyclonedx parser
- [`sbom-model-spdx`](https://docs.rs/sbom-model-spdx) - spdx parser
