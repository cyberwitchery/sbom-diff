# sbom-diff

[![ci](https://github.com/cyberwitchery/sbom-diff/actions/workflows/ci.yml/badge.svg)](https://github.com/cyberwitchery/sbom-diff/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/sbom-diff.svg)](https://crates.io/crates/sbom-diff)
[![docs.rs](https://docs.rs/sbom-diff/badge.svg)](https://docs.rs/sbom-diff)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

fast, format-agnostic sbom comparison tool.

## usage

```bash
# compare two sboms
sbom-diff old.json new.json

# markdown for pr comments
sbom-diff old.json new.json -o markdown

# filter for specific changes
sbom-diff old.json new.json --only version,license

# show only dependency edge changes
sbom-diff old.json new.json --only deps

# license gating (exit code 2 on violation)
sbom-diff old.json new.json --deny-license gpl-3.0-only

# block new dependencies or missing checksums (exit code 3)
sbom-diff old.json new.json --fail-on added-components
sbom-diff old.json new.json --fail-on missing-hashes
sbom-diff old.json new.json --fail-on deps

# block a dependency turning copyleft, e.g. mit -> gpl-3.0-only (exit code 3)
sbom-diff old.json new.json --fail-on copyleft-added

# block a component's coordinates being swapped, e.g. typosquat / dependency-confusion (exit code 3)
sbom-diff old.json new.json --fail-on purl-changed
sbom-diff old.json new.json --fail-on ecosystem-changed

# summary only (counts without details)
sbom-diff old.json new.json --summary

# quiet mode (errors only, for ci)
sbom-diff old.json new.json --quiet --fail-on added-components
```

## examples

### text output (default)
```text
Diff Summary
============
Added:   1
Removed: 0
Changed: 1

[+] Added
---------
pkg:npm/left-pad@1.3.0

[~] Changed
-----------
pkg:cargo/serde@1.0.191
  Version: 1.0.190 -> 1.0.191
  License: {"mit"} -> {"apache-2.0", "mit"}
```

## installation

```bash
cargo install sbom-diff
```

## use cases

- **pr review**: generate markdown diffs to comment on pull requests
- **ci/cd gating**: block builds that introduce denied licenses
- **compliance**: track dependency changes between releases
- **audit**: compare sboms from different tools or points in time

## features

- supports cyclonedx 1.3-1.5 (json and xml) and spdx 2.3 (json, xml, and tag-value)
- deterministic normalization for reproducible diffs
- matches components by purl or identity (name/ecosystem)
- zero network access - fully offline

## license gating

`--deny-license` and `--allow-license` (both repeatable, case-insensitive, exit
code 2) and `--fail-on copyleft-added` (exit code 3) evaluate the SPDX license
expression the sbom declared, so the operators decide the verdict:

- `AND` means every operand applies; `OR` means the consumer picks one.
  `MIT OR GPL-3.0-only` passes `--deny-license gpl-3.0-only` because it can be
  taken under MIT, and passes `--allow-license mit` for the same reason.
  `MIT AND GPL-3.0-only` fails both.
- a deny only fires when no satisfying choice avoids a denied license; an allow
  only fires when no satisfying choice lies inside the allow-list, so
  `(MIT OR Apache-2.0) AND BSD-3-Clause` is allowed by
  `--allow-license mit --allow-license bsd-3-clause`.
- `--fail-on copyleft-added` fires when the new expression cannot be satisfied
  without a copyleft license the old one did not already force. gaining a
  copyleft alternative (`MIT` to `MIT OR GPL-3.0-only`) is not a violation;
  losing the permissive alternative (`MIT OR GPL-3.0-only` to `GPL-3.0-only`) is.
- a `WITH` exception is part of the license: dropping it is reported as a
  license change even though the identifiers are unchanged, and it is nameable
  in a policy list by its full spelling,
  `--deny-license "GPL-2.0-only WITH Classpath-exception-2.0"`.

components whose sbom declares no expression — free-text names, `LicenseRef-`
identifiers, or per-license `id`/`name` entries — are gated on their identifier
set, where every identifier applies.

## exit codes

| code | meaning |
|------|---------|
| 0 | success |
| 1 | error (invalid input, parse failure) |
| 2 | license violation (`--deny-license` or `--allow-license`) |
| 3 | fail-on condition triggered (`--fail-on`) |

## limitations

- read-only (no sbom generation or modification)

## docs

- [format mapping notes](docs/format-notes.md): cyclonedx/spdx field mapping into the core model

## crate structure

this project is a cargo workspace with four crates:

```
sbom-diff/
├── sbom-model           # format-agnostic data model
├── sbom-model-cyclonedx # cyclonedx json/xml parser
├── sbom-model-spdx      # spdx json/xml/tag-value parser
└── sbom-diff            # diff engine + cli
```

| crate | docs | description |
|-------|------|-------------|
| [`sbom-model`](crates/sbom-model) | [docs.rs](https://docs.rs/sbom-model) | core `Sbom`, `Component`, `ComponentId` types and query api |
| [`sbom-model-cyclonedx`](crates/sbom-model-cyclonedx) | [docs.rs](https://docs.rs/sbom-model-cyclonedx) | parse cyclonedx 1.3-1.5 json and xml into `Sbom` |
| [`sbom-model-spdx`](crates/sbom-model-spdx) | [docs.rs](https://docs.rs/sbom-model-spdx) | parse spdx 2.3 json, xml, and tag-value into `Sbom` |
| [`sbom-diff`](crates/sbom-diff) | [docs.rs](https://docs.rs/sbom-diff) | `Differ` engine, renderers, and cli binary |

use the library crates directly if you want to build custom tooling:

```rust
use sbom_model_cyclonedx::CycloneDxReader;
use sbom_model_spdx::SpdxReader;
use sbom_diff::Differ;

let old = CycloneDxReader::read_json(old_bytes)?;
let new = SpdxReader::read_json(new_bytes)?;  // formats can differ!
let diff = Differ::diff(&old, &new, None);
```

<hr/>

have fun!
