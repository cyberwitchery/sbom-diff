# format mapping notes

this document explains how cyclonedx and spdx inputs are mapped into `sbom-model`.

## target model

both adapters produce:

- `Sbom.metadata`
- `Sbom.components: IndexMap<ComponentId, Component>`
- `Sbom.dependencies: BTreeMap<ComponentId, BTreeSet<ComponentId>>`

`ComponentId` prefers purl when present; otherwise it falls back to a deterministic hash over selected component properties.

## cyclonedx -> model

- parser: `sbom-model-cyclonedx` using `cyclonedx-bom`
- purl extraction:
  - source: `component.purl`
  - target: `Component.purl`
  - ecosystem: derived from purl type (for example `pkg:npm/...` -> `ecosystem = "npm"`)
- licences:
  - source: `component.licenses`
  - target: `Component.licenses`
  - `license.id` / `license.name` entries are copied
  - expression entries are expanded via SPDX expression parsing into individual license ids
- hashes:
  - source: `component.hashes`
  - target: `Component.hashes`
  - algorithm and checksum value are stored; later normalization lowercases both
- supplier:
  - source: `component.supplier.name`
  - target: `Component.supplier`
- dependency relationships:
  - source: top-level `dependencies` entries (`ref` + `dependsOn`)
  - mapping path:
    1. each component `bom-ref` is stored in `Component.source_ids`
    2. adapter builds `bom-ref -> ComponentId` lookup
    3. each `ref -> dependsOn[]` relationship becomes `parent -> {children...}` in `Sbom.dependencies`

## spdx -> model

- parser: `sbom-model-spdx` using `spdx-rs` + `serde_json`
- purl extraction:
  - source: package `externalRefs` where `referenceType == "purl"`
  - target: `Component.purl`
  - ecosystem: derived from purl type
- licences:
  - source: `package.licenseConcluded`
  - target: `Component.licenses`
  - SPDX expressions are expanded into individual license ids
  - `NOASSERTION` and `NONE` are ignored
- hashes:
  - source: `package.checksums`
  - target: `Component.hashes`
  - key is checksum algorithm, value is checksum value
- supplier:
  - source: `package.supplier`
  - target: `Component.supplier`
- dependency relationships:
  - source: top-level `relationships`
  - only these relationship types become dependency edges:
    - `DEPENDS_ON`
    - `CONTAINS`
    - `DESCRIBES`
  - mapping path:
    1. each package `SPDXID` is stored in `Component.source_ids`
    2. adapter builds `SPDXID -> ComponentId` lookup
    3. each qualifying relationship becomes `spdxElementId -> relatedSpdxElement` in `Sbom.dependencies`

## notes

- both adapters are json-only in this repository.
- both adapters may leave some source-specific fields unmapped if no stable equivalent exists in the core model.
