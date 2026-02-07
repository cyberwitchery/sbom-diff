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

# summary only (counts without details)
sbom-diff old.json new.json --summary

# quiet mode (errors only, for ci)
sbom-diff old.json new.json --quiet --fail-on added-components
```

## examples

### text output (default)
```text
diff summary
============
added:   1
removed: 0
changed: 1

[+] added
---------
pkg:npm/left-pad@1.3.0

[~] changed
-----------
pkg:cargo/serde@1.0.191
  version: 1.0.190 -> 1.0.191
  license: ["mit"] -> ["mit", "apache-2.0"]
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

- supports cyclonedx 1.4+ and spdx 2.3 json
- deterministic normalization for reproducible diffs
- matches components by purl or identity (name/ecosystem)
- zero network access - fully offline

## exit codes

| code | meaning |
|------|---------|
| 0 | success |
| 1 | error (invalid input, parse failure) |
| 2 | license violation (`--deny-license` or `--allow-license`) |
| 3 | fail-on condition triggered (`--fail-on`) |

## limitations

- json only (no xml support)
- read-only (no sbom generation or modification)

## docs

- [format mapping notes](docs/format-notes.md): cyclonedx/spdx field mapping into the core model

## crate structure

this project is a cargo workspace with four crates:

```
sbom-diff/
├── sbom-model           # format-agnostic data model
├── sbom-model-cyclonedx # cyclonedx json parser
├── sbom-model-spdx      # spdx json parser
└── sbom-diff            # diff engine + cli
```

| crate | docs | description |
|-------|------|-------------|
| [`sbom-model`](crates/sbom-model) | [docs.rs](https://docs.rs/sbom-model) | core `Sbom`, `Component`, `ComponentId` types and query api |
| [`sbom-model-cyclonedx`](crates/sbom-model-cyclonedx) | [docs.rs](https://docs.rs/sbom-model-cyclonedx) | parse cyclonedx 1.4 json into `Sbom` |
| [`sbom-model-spdx`](crates/sbom-model-spdx) | [docs.rs](https://docs.rs/sbom-model-spdx) | parse spdx 2.3 json into `Sbom` |
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
