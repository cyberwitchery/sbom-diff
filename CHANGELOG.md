# changelog

## Unreleased

- track SBOM metadata changes: instead of a single `metadata_changed: bool`, the diff now records exactly which document-metadata fields differ (timestamp, tools, authors) with their old and new values. Rendered as a `[~] Metadata Changes` section in text, a collapsible block in markdown, and a `metadata_changed` object in JSON; summaries gain a `Metadata changed: yes/no` line. New `--fail-on metadata-changed` CI gate fails when any metadata field differs and reports which ones.
- fix: `--fail-on deps` now explains which dependency edges changed kind (e.g. `dependency edge ... changed kind: dev -> runtime`); previously it set the violation exit code without printing any reason.

## [0.3.0] - 2026-05-21

- track SPDX dependency relationship types as a `DependencyKind` (Runtime, Dev, Build, Test, Optional, Provided): the SPDX parser maps `DEV_DEPENDENCY_OF`, `BUILD_DEPENDENCY_OF`, `TEST_DEPENDENCY_OF`, `OPTIONAL_DEPENDENCY_OF`, and `PROVIDED_DEPENDENCY_OF` instead of discarding scope, the diff detects when an edge's kind changes (e.g. dev to runtime), and renderers show a `(dev)`/`(build)`/etc. suffix on non-runtime edges.
- detect changes to a component's ecosystem (e.g. after a tool migration); reported in all output formats and filterable with `--only ecosystem`.
- add `--fail-on license-changed`: an incremental CI gate that flags changed components whose license set differs and added components that introduce new licenses (unlike `--deny-license`/`--allow-license`, it doesn't fire on pre-existing dependencies).
- extend `--fail-on missing-hashes` to also flag changed components that dropped all their checksums, not just added components.
- add SPDX tag-value support: `--format spdx-tv` (with auto-detection) parses `.spdx` tag-value files emitted by tools like Fossology and the SPDX Java tools.
- fix: on non-JSON input (XML or tag-value), the SPDX version pre-check now returns a clear format-detection error instead of a cryptic serde parse error.
- fix: when CycloneDX XML fails to parse against every supported spec version (1.5, 1.4, 1.3), the error now includes diagnostics from each attempt instead of only the 1.3 attempt.

## [0.2.1] - 2026-05-06

- handle SPDX inverse and scoped relationship types (`DEPENDENCY_OF`, `CONTAINED_BY`, `DESCRIBED_BY`, `RUNTIME_DEPENDENCY_OF`, `DEV_DEPENDENCY_OF`, etc.) in the dependency graph, fixing false-positive edge diffs between tools that orient relationships differently.
- add SPDX document version detection: SPDX 3.x and other unsupported spec versions now produce a clear `UnsupportedVersion` error instead of garbled output.
- add a recursion-depth limit (32 levels) to CycloneDX sub-component collection, warning instead of stack-overflowing on adversarial or malformed input.
- fix: `Diff::metadata_changed` was always false (it was computed after normalization had cleared the metadata); it is now computed before normalizing.
- fix: `--summary --show-warnings` no longer drops warnings in markdown and JSON output.
- fix: a CycloneDX supplier with no name no longer produces a spurious supplier-change diff.
- fix: `render_summary_json` no longer panics on malformed ecosystem-breakdown data.
- faster identity reconciliation for components without an ecosystem (O(n log n) instead of O(n²)), plus a new allocation-free `Diff::into_group_by_ecosystem()`.

## [0.2.0] - 2026-04-26

- add `--group-by-ecosystem` to break down added/removed/changed counts by package ecosystem (npm, cargo, pypi, etc.) in all output formats; JSON gains a `by_ecosystem` section.
- add `--show-warnings` to surface parser warnings (orphaned deps, format quirks) in rendered output, each labeled with its source SBOM (`[old]`/`[new]`), instead of only on stderr.
- `--summary` now respects `--output`: markdown produces a compact table (with a per-ecosystem breakdown under `--group-by-ecosystem`) and JSON produces a counts object, instead of always plain text.
- add `--fail-on removed-components` and `--fail-on changed-components` CI gates.
- track component description changes (mapped from SPDX `packageDetailedDescription`/`packageSummaryDescription`, closing a data-loss gap versus CycloneDX); reported in all formats and filterable with `--only description`.
- parse nested CycloneDX sub-components recursively (common in container images and monorepos) instead of silently dropping them.
- show per-algorithm hash diffs (algorithm, old digest, new digest) instead of a generic "Hashes: changed".
- warn (on both parsers) when a dependency references a component ID that doesn't exist, instead of silently dropping the edge.
- show per-parser rejection reasons when `--format auto` can't detect the format.
- fall back to SPDX `licenseDeclared` when `licenseConcluded` is `NOASSERTION`/`NONE`, so SBOMs from syft and trivy no longer come through with empty license data.
- flag unlicensed components as violations when `--allow-license` is active.
- fix: SPDX license matching in `--deny-license`/`--allow-license` is now case-insensitive (per spec), so `--deny-license GPL-3.0-only` also matches `gpl-3.0-only`.
- fix: SPDX hash algorithm names are canonicalized (`SHA-256`, not `SHA256`), so hashes match in cross-format comparisons with CycloneDX.
- fix: text and markdown output now shows plain strings (with `<none>` for absent values) instead of Rust debug output (`Some("MIT")`, `None`, `{"MIT"}`) for License, Supplier, Purl, and Description.
- fix: no more false-positive orphan warnings for SPDX `SPDXRef-DOCUMENT` `DESCRIBES` relationships.
- strip SPDX supplier prefixes (`Organization: `, `Person: `) so they don't cause false-positive cross-format diffs.
- add `Diff::is_empty()`.

## [0.1.0] - 2026-04-08

- add CycloneDX XML support (1.3, 1.4, 1.5): new `--format cyclonedx-xml` flag with auto-detection.

## [0.0.6] - 2026-02-19

- fix: CycloneDX tool metadata is parsed again (it was silently dropped after `cyclonedx-bom` 0.6 changed `Tools` from a newtype to an enum); both the 1.4 list and 1.5+ object forms are handled.
- releases now ship a CycloneDX SBOM.

## [0.0.5] - 2026-01-27

- match components by ecosystem + name when purls differ or are absent, reporting version/purl changes instead of spurious add/remove pairs.
- diff dependency edges between components; `--only deps` filters to edge changes and `--fail-on deps` fails when any change.

## [0.0.4] - 2026-01-27

- canonicalize license lists for order-independent comparison.
- add `--fail-on missing-hashes` and `--fail-on added-components`.
- add `--summary` to print only counts, and `--quiet`/`-q` to suppress output except errors.

## [0.0.3] - 2026-01-26

- documentation: crate READMEs now render on docs.rs, and all public types and methods are documented.

## [0.0.2] - 2026-01-26

- documentation: expanded crate docs with usage examples, use cases, limitations, stdin support, and exit codes.

## [0.0.1] - 2026-01-25

- initial release.

[0.2.0]: https://github.com/cyberwitchery/sbom-diff/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/cyberwitchery/sbom-diff/compare/v0.0.6...v0.1.0
[0.0.6]: https://github.com/cyberwitchery/sbom-diff/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/cyberwitchery/sbom-diff/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/cyberwitchery/sbom-diff/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/cyberwitchery/sbom-diff/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/cyberwitchery/sbom-diff/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/cyberwitchery/sbom-diff/releases/tag/v0.0.1
