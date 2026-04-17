# changelog

## unreleased

- optimize edge diff computation from O(n²) to O(n) by building a reverse ID map upfront instead of linear-scanning per parent
- add description field change tracking to the diff engine: the `description` field is now compared between SBOM versions and reported in all output formats; supports `--only description` filtering
- fix case-insensitive license matching in `--deny-license` and `--allow-license`: SPDX license IDs are case-insensitive by spec, but were compared with exact string equality, so `--deny-license GPL-3.0-only` would miss `gpl-3.0-only`
- map SPDX package description fields (`packageDetailedDescription` / `packageSummaryDescription`) into `Component.description`, fixing a data loss gap vs CycloneDX
- fix SPDX hash algorithm names to use canonical format (e.g. `SHA-256` instead of `SHA256`), so cross-format comparisons with CycloneDX no longer silently miss matching hashes
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

[unreleased]: https://github.com/cyberwitchery/sbom-diff/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/cyberwitchery/sbom-diff/compare/v0.0.6...v0.1.0
[0.0.6]: https://github.com/cyberwitchery/sbom-diff/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/cyberwitchery/sbom-diff/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/cyberwitchery/sbom-diff/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/cyberwitchery/sbom-diff/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/cyberwitchery/sbom-diff/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/cyberwitchery/sbom-diff/releases/tag/v0.0.1
