# changelog

## [0.0.5] - 2026-01-27

- improved purl reconciliation: components are now matched by ecosystem + name when purls differ or are absent, reporting version/purl changes instead of spurious add/remove pairs

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

[unreleased]: https://github.com/cyberwitchery/sbom-diff/compare/v0.0.5...HEAD
[0.0.5]: https://github.com/cyberwitchery/sbom-diff/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/cyberwitchery/sbom-diff/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/cyberwitchery/sbom-diff/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/cyberwitchery/sbom-diff/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/cyberwitchery/sbom-diff/releases/tag/v0.0.1
