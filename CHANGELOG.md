# changelog

## Unreleased

- add `--fail-on hash-algorithm-downgrade` CI gate: detects when a changed component's strongest hash algorithm is weaker than before (e.g. SHA-256 replaced with MD5), using a strength ordering across known algorithm families (MD < SHA-1 < SHA-224 < SHA-256/SHA3-256/BLAKE2b-256/BLAKE3 < SHA-384 < SHA-512); complements `--fail-on missing-hashes` which catches completely dropped hashes
- add `--include-ecosystem` and `--exclude-ecosystem` flags to filter diff output by package ecosystem
- add `Diff::filter_by_ecosystem()` for programmatic ecosystem filtering
- add `--output csv` (RFC 4180 CSV) output format for spreadsheets, CI dashboards, and data pipelines: full output produces one row per finding with columns `status,component,ecosystem,field,old_value,new_value` covering added/removed/changed components, edge diffs, and metadata changes; `--summary` mode produces compact `metric,count` pairs with an optional `ecosystem,added,removed,changed` breakdown when `--group-by-ecosystem` is set; CSV escaping handled by the `csv` crate
- add `--fail-on supplier-changed` CI gate: detects when a changed component's supplier field differs between SBOM versions or when an added component introduces a supplier; designed to catch supply-chain takeovers (like the xz incident) where a package's maintainer/supplier changes unexpectedly

## [0.4.0] - 2026-06-08

- extract version comparison logic (`parse_version_lenient`, `is_version_downgrade`) from the CLI binary into a public `sbom_model::versions` module with a `Version` enum (`Semver`/`Numeric`/`Opaque` variants), `parse_lenient()` constructor, and `is_downgrade()` method; the `semver` dependency moves from `sbom-diff` to `sbom-model`; cross-variant comparison (e.g. semver `v1.2.3` vs four-part `1.2.3.4`) now works correctly instead of bailing
- fix SARIF renderer ignoring `--show-warnings`: parser warnings are now emitted as note-level `parser-warning` results with source-labeled locations (`old-sbom`/`new-sbom`), making them visible in GitHub Code Scanning and other SARIF consumers; previously the SARIF renderer prefixed its `opts` parameter with underscore and discarded it
- add `--fail-on version-downgrade` CI gate: detects when a changed component's version goes from a higher to a lower value, using lenient semver parsing (handles `v` prefixes, two-part versions, pre-release tags) with a dot-separated numeric fallback for non-semver strings like date-based versions (`2024.01.15`) or four-part versions (`1.2.3.4`); returns `false` (no downgrade) when version ordering cannot be determined
- add `Differ::diff_owned()` consuming variant that normalizes SBOMs in place, avoiding two full SBOM clones when the caller owns the inputs; the CLI now uses this path, and `Differ::diff()` delegates to it
- deduplicate `Diff::group_by_ecosystem()` / `into_group_by_ecosystem()` via a shared `group_components_by_ecosystem` helper that accepts owned iterators
- surface silent parser failures with structured diagnostic context: CycloneDX depth-truncation warning now names the dropped component(s) and depth level; CycloneDX XML multi-version retry emits a warning when it falls back to an older spec version; SPDX tag-value parser warns when the flush-sentinel workaround fires (last package has ExternalRefs) and when phantom creators from spdx-rs 0.5 defaults are stripped
- add `--output sarif` (SARIF 2.1.0) output format for GitHub Code Scanning and Azure DevOps integration: maps component additions, removals, and field-level changes to SARIF results with five rules (`component-added`, `component-removed`, `component-changed`, `dependency-changed`, `metadata-changed`); each result includes a `locations` array with `logicalLocations` (package identifier for component rules, parent identifier for dependency rules, `metadata` for metadata rules) so results appear in GitHub Advanced Security and CodeQL; no new dependencies — SARIF JSON is built with the existing `serde`/`serde_json` types
- fix SARIF renderer emitting an empty `"Metadata changed: "` result when `MetadataChange` has no populated subfields; the result is now skipped when all subfields are `None`
- replace `metadata_changed: bool` with structured `MetadataChange` tracking that records exactly which metadata fields differ (timestamp, tools, authors) with old/new values; rendered as a new `[~] Metadata Changes` section in text output, a collapsible `<details>` block in markdown, and a structured `metadata_changed` object in JSON; summaries show a `Metadata changed: yes/no` line; add `--fail-on metadata-changed` CI gate that fails when any document metadata differs, reporting which specific fields changed
- fix `--fail-on deps` not reporting `kind_changed` edges in error messages: when a dependency changed kind (e.g. dev→runtime), the violation exit code fired but no error message explained which edges changed; now prints `error: dependency edge ... changed kind: dev -> runtime (--fail-on deps)` for each affected edge
- fix `FieldChange::Version` collapsing absent versions to empty strings: version now uses `Option<String>` to preserve the distinction between a version being absent (`None`) and being empty, so a component going from no version to `1.0` renders as `<none> -> 1.0` instead of ` -> 1.0`
- add `Edge changes` and `Metadata changed` rows to the full render summary headers (text and markdown) for consistency with `--summary` mode, which already showed them
- replace `.expect()` calls in JSON summary renderer with `?` error propagation, matching the project's error handling patterns

## [0.3.0] - 2026-05-21

- thread SPDX relationship types through the dependency model as `DependencyKind` (Runtime, Dev, Build, Test, Optional, Provided): the SPDX parser now maps `DEV_DEPENDENCY_OF`, `BUILD_DEPENDENCY_OF`, `TEST_DEPENDENCY_OF`, `OPTIONAL_DEPENDENCY_OF`, and `PROVIDED_DEPENDENCY_OF` to their corresponding kind instead of discarding scope at parse time; `EdgeDiff` tracks kind on added/removed edges and detects `kind_changed` when an edge's scope changes between SBOMs (e.g. dev→runtime); renderers show a `(dev)`, `(build)`, etc. suffix for non-runtime edges
- track ecosystem field changes in `compute_change`: new `FieldChange::Ecosystem` variant detects when a component's ecosystem changes between SBOMs (e.g. tool migration or ecosystem reclassification), rendered across all output formats and filterable via `--only ecosystem`
- add `--fail-on license-changed` CI gate that detects license regressions incrementally: flags changed components whose license set differs and added components that introduce new licenses, using `FieldChange::License` from the diff result instead of scanning the full new SBOM (unlike `--deny-license` / `--allow-license`, this works as an incremental gate when pre-existing deps already carry denied licenses)
- fix `check_spdx_version` propagating a cryptic serde parse error on non-JSON input (e.g. XML or tag-value) instead of returning `Ok(())` and letting the full parser produce a proper format-detection error; now matches the CycloneDX pre-check behavior
- extend `--fail-on missing-hashes` to also flag changed components that dropped all their checksums (previously only added components were checked, silently ignoring a supply-chain regression where a component that previously had SHA-256 hashes loses them)
- add SPDX tag-value format support: new `--format spdx-tv` flag and auto-detection; `SpdxReader::read_tag_value` parses the original SPDX tag-value format (`.spdx` files) emitted by tools like Fossology, reuse, and the SPDX Java tools, using the existing `spdx-rs` tag-value parser with workarounds for two known quirks (phantom default creators and dropped last ExternalRef)
- fix CycloneDX XML `read_xml()` reporting only the last spec-version error: when parsing fails for all versions (1.5, 1.4, 1.3), the error now includes diagnostics from every attempted version instead of only the v1.3 attempt
- consolidate `render_summary_text`/`render_summary_markdown`/`render_summary_json` into a `SummaryRenderer` trait (mirrors the existing `Renderer` trait); all summary rendering logic now lives in the `renderer` module, making new output formats trivial to add

## [0.2.1] - 2026-05-06

- handle SPDX inverse and scoped relationship types (DEPENDENCY_OF, CONTAINED_BY, DESCRIBED_BY, RUNTIME_DEPENDENCY_OF, DEV_DEPENDENCY_OF, BUILD_DEPENDENCY_OF, OPTIONAL_DEPENDENCY_OF, PROVIDED_DEPENDENCY_OF, TEST_DEPENDENCY_OF, PREREQUISITE_FOR, HAS_PREREQUISITE) in the dependency graph builder, fixing false-positive edge diffs when comparing SBOMs from tools that use different relationship orientations
- fix `render_summary_json` panic: replace `.expect()` on ecosystem breakdown serialization with proper error propagation, preventing a potential panic on malformed `EcosystemCounts` data
- add recursion depth limit (32 levels) to CycloneDX sub-component collection, emitting a warning instead of stack-overflowing on adversarial or malformed input
- add SPDX document version detection: `SpdxReader::read_json` now pre-checks the `spdxVersion` field and returns a clear `UnsupportedVersion` error for SPDX 3.x or other unsupported spec versions, instead of producing garbled output or cryptic deserialization errors
- fix `Diff::metadata_changed` always being false: the field was computed after `normalize()` cleared timestamps, tools, and authors, making the comparison a no-op; it is now computed before normalization
- fix `--summary --show-warnings` silently dropping warnings in markdown (`-o markdown`) and JSON (`-o json`) summary output; `render_summary_markdown` and `render_summary_json` now check `opts.has_warnings()` and emit warnings in the same format as their full-output counterparts
- fix CycloneDX supplier element with no name (or empty name) producing `Some("")` instead of `None`, which caused spurious supplier-change diffs
- optimize identity reconciliation for ecosystem-less components from O(n²) to O(n log n) by restructuring the identity map to index by name then ecosystem, eliminating a linear scan of the entire map when matching components without an ecosystem
- add `Diff::into_group_by_ecosystem()` consuming variant that moves components instead of cloning, avoiding allocations when the caller owns the diff

## [0.2.0] - 2026-04-26

- add `--show-warnings` flag to surface parser warnings (orphaned deps, format quirks) in rendered output instead of only printing them to stderr; each warning is labeled with its source SBOM (`[old]`/`[new]` in text/summary, `old`/`new` keys in JSON) across all output formats
- `--summary` now respects the `--output` flag: markdown output produces a compact table (overall counts plus per-ecosystem breakdown when `--group-by-ecosystem` is set), and JSON output produces a summary object with counts; previously `--summary` always rendered plain text regardless of the output format
- eliminate redundant component traversal when `--group-by-ecosystem` is set: renderers now derive per-ecosystem counts from the already-grouped data instead of walking all components a second time
- fix false-positive orphan warnings for `SPDXRef-DOCUMENT` DESCRIBES relationships (fires on every real SPDX file because the document element is not a package)
- fall back to `licenseDeclared` when SPDX `licenseConcluded` is NOASSERTION or NONE, so tools like syft and trivy that leave `licenseConcluded` unset no longer produce components with empty license data
- warn on orphaned dependency references: both SPDX and CycloneDX parsers now emit warnings to stderr when a dependency relationship references a component ID (bom-ref or SPDXID) that doesn't exist in the document, instead of silently dropping the edge
- add `--group-by-ecosystem` flag: breaks down added/removed/changed counts by package ecosystem (npm, cargo, pypi, etc.) and groups detail sections per ecosystem in all three output formats; JSON additionally includes `by_ecosystem` with full per-ecosystem component data
- parse nested CycloneDX sub-components recursively: components with child `components` arrays (common in container images and monorepos) are now flattened into the SBOM instead of being silently dropped
- add `--fail-on removed-components` and `--fail-on changed-components` CI gate variants: supply-chain policies can now flag component removals and field-level changes alongside additions
- show per-parser rejection reasons when `--format auto` fails to detect the SBOM format, instead of the generic "could not detect sbom format automatically" message
- strip SPDX supplier prefixes (`Organization: `, `Person: `) during parsing so cross-format diffs no longer produce false positives
- add `Diff::is_empty()` convenience method
- optimize `by_purl()` from O(n) linear scan to O(1) via direct `ComponentId` lookup
- show per-algorithm hash diffs (algorithm, old digest, new digest) instead of the generic "Hashes: changed" message in all output formats (text, markdown, JSON)
- fix text and markdown renderers showing Rust debug format (`Some("MIT")`, `None`, `{"MIT"}`) for License, Supplier, Purl, and Description fields; these now display as plain strings with `<none>` for absent values
- optimize edge diff computation from O(n²) to O(n) by building a reverse ID map upfront instead of linear-scanning per parent
- add description field change tracking to the diff engine: the `description` field is now compared between SBOM versions and reported in all output formats; supports `--only description` filtering
- fix case-insensitive license matching in `--deny-license` and `--allow-license`: SPDX license IDs are case-insensitive by spec, but were compared with exact string equality, so `--deny-license GPL-3.0-only` would miss `gpl-3.0-only`
- map SPDX package description fields (`packageDetailedDescription` / `packageSummaryDescription`) into `Component.description`, fixing a data loss gap vs CycloneDX
- fix SPDX hash algorithm names to use canonical format (e.g. `SHA-256` instead of `SHA256`), so cross-format comparisons with CycloneDX no longer silently miss matching hashes
- move hash algorithm name normalization (`canonical_algorithm_name`) to the shared `sbom-model` crate and apply it in both SPDX and CycloneDX parsers, ensuring algorithm names always match regardless of source format
- flag unlicensed components as violations when `--allow-license` is active

## [0.1.0] - 2026-04-08

- add CycloneDX XML support (1.3, 1.4, 1.5); new `--format cyclonedx-xml` flag and auto-detection
- add `CycloneDxReader::read_xml` to the `sbom-model-cyclonedx` crate

## [0.0.6] - 2026-02-19

- fix CycloneDX tool metadata parsing, which was silently dropped since `cyclonedx-bom` 0.6 changed `Tools` from a newtype to an enum; both the legacy 1.4 list format and the 1.5+ object format are now handled
- add release SBOM generation and upload (CycloneDX)

## [0.0.5] - 2026-01-27

- improved purl reconciliation: components are now matched by ecosystem + name when purls differ or are absent, reporting version/purl changes instead of spurious add/remove pairs
- added dependency edge diffing: diffs now include added/removed dependency edges between components
- added `--only deps` to filter output to only dependency edge changes
- added `--fail-on deps` to fail when any dependency edges change

## [0.0.4] - 2026-01-27

- license lists are now canonicalized (order-independent comparison)
- added `--fail-on missing-hashes` and `--fail-on added-components` flags
- added `--summary` flag to print only counts
- added `--quiet` / `-q` flag to suppress output except errors

## [0.0.3] - 2026-01-26

- crate readmes now display on docs.rs landing pages
- added comprehensive doc comments to all public types and methods

## [0.0.2] - 2026-01-26

- expanded crate documentation with usage examples
- added use cases and limitations to readme
- documented stdin support and exit codes

## [0.0.1] - 2026-01-25

initial release

[0.2.0]: https://github.com/cyberwitchery/sbom-diff/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/cyberwitchery/sbom-diff/compare/v0.0.6...v0.1.0
[0.0.6]: https://github.com/cyberwitchery/sbom-diff/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/cyberwitchery/sbom-diff/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/cyberwitchery/sbom-diff/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/cyberwitchery/sbom-diff/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/cyberwitchery/sbom-diff/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/cyberwitchery/sbom-diff/releases/tag/v0.0.1
