# adapters

## cyclonedx
- uses `cyclonedx-bom`.
- maps `bom-ref` to internal component ids for graph reconstruction; a dependency on or of a service is skipped without a warning.
- supports component metadata, licenses, and hashes.

## spdx
- uses `spdx-rs`.
- maps `spdxid` to internal component ids.
- supports packages, concluded licenses, and the 14 dependency relationship types listed in `format-notes.md` (`DEPENDS_ON`, `CONTAINS`, `DESCRIBES`, `HAS_PREREQUISITE` and ten inverse types such as `DEPENDENCY_OF` and `DEV_DEPENDENCY_OF`).
- skips a relationship with a file, a snippet, `NONE`/`NOASSERTION` or an element of a declared external document without a warning; one naming nothing in the document is skipped with a warning.
- requires `downloadLocation` (per spdx spec).
