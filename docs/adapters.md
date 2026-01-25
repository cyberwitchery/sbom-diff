# adapters

## cyclonedx
- uses `cyclonedx-bom`.
- maps `bom-ref` to internal component ids for graph reconstruction.
- supports component metadata, licenses, and hashes.

## spdx
- uses `spdx-rs`.
- maps `spdxid` to internal component ids.
- supports packages, concluded licenses, and relationships (depends_on, contains, describes).
- requires `downloadLocation` (per spdx spec).
