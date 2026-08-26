# format mapping notes

this document explains how cyclonedx and spdx inputs are mapped into `sbom-model`.

## target model

both adapters produce:

- `Sbom.metadata`
- `Sbom.components: IndexMap<ComponentId, Component>`
- `Sbom.dependencies: BTreeMap<ComponentId, BTreeMap<ComponentId, DependencyKind>>`

`ComponentId` prefers purl when present; otherwise it falls back to a deterministic hash over selected component properties.

## cyclonedx -> model

- parser: `sbom-model-cyclonedx` using `cyclonedx-bom`
- input formats: json and xml (1.3, 1.4, 1.5, 1.6)
- xml version detection: tries 1.5, 1.4, 1.3 in order; first successful parse wins
- 1.6 documents are read under 1.5 rules: `cyclonedx-bom` tops out at 1.5, and 1.6 is a superset of it for every field this model reads. json swaps `specVersion` in the parsed value and drops every `evidence` member from it, the one field whose type 1.6 widened (`evidence.identity` became an array of identities, which the 1.5 model refuses rather than ignores); xml re-encodes the document with the namespace pinned to 1.5, rewriting namespace declarations only, so element text and attribute values are left as the parser read them
- a 1.6 document pushes a warning onto `Sbom.warnings` naming the version and the 1.6-only fields the read drops (component `authors`/`manufacturer`/`omniborId`/`swhid`/`tags`, license `acknowledgement`, `cryptoProperties`, `declarations`, `definitions`) plus component `evidence`, which no format this model reads surfaces
- the xml version is read from the root element's namespace — its default declaration, or the prefix it is bound through when that declaration names no cyclonedx namespace — so the same url in a comment, in element text or in an unrelated attribute is not mistaken for it
- 1.7 and later are refused with an unsupported-version error
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
- input formats: json, xml, and tag-value (2.x; 2.3 field names)
- tag-value handling: the underlying parser stops at the first line it cannot read and throws away everything below it, so those lines are removed before parsing and listed in the parser warnings:
  - a line that is not a `Tag: value` pair, or whose tag is not one the parser recognizes
  - a value the parser crashes on: an unrecognized `ExternalRef` category, checksum algorithm, `Relationship` type, `FileType`, or `AnnotationType`
  - a license expression the SPDX expression parser rejects on `PackageLicenseConcluded`, `PackageLicenseDeclared`, `LicenseConcluded`, `LicenseInfoInFile` or `SnippetLicenseConcluded` — empty, whitespace-only, or malformed (`MIT AND`, `(MIT`) — whether written on the tag's own line or delivered as a `<text>` block beside or below it. a malformed package-level expression is kept as written on `Component.license_expression` so the diff still reports it changed, and a warning names the package, the expression, and the gates that can no longer match it
  - a `<text>` block belongs to its tag's value, so its interior is never read as a tag line, and dropping a tag drops its whole block
  - a document the parser still cuts short is reported as an error naming the first package lost, never returned as a partial SBOM
- tag-value inputs that still abort the process rather than produce a diagnostic. all are `spdx-rs` panics on input this reader cannot recognize line by line, and all are the same on `main`:
  - a `<text>` block used as the value of one of the enum-valued tags above (`FileType: <text>NOTATYPE</text>`). a `<text>` value can run past its own line, so its content is not judged, and an unrecognized one reaches the parser's crash
- json and xml handling: a license expression the SPDX expression parser rejects is removed from the document before parsing and named in the parser warnings, the same way as in tag-value; it would otherwise fail the whole document with a `serde` type error naming neither the package nor the field
- xml handling: the xml serialization mirrors the json schema element-for-element, so the document is converted to json and mapped by the json code path
  - root element: `<Document>` or `<SpdxDocument>`
  - repeated sibling elements become a json array; a field the schema types as an array becomes a one-element array even when it occurs once
  - `filesAnalyzed` and the snippet range offsets are re-typed from text to boolean/integer
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
  - the `Organization: ` / `Person: ` prefix is stripped
  - `NOASSERTION` and `NONE` are ignored
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

- the cyclonedx adapter supports json and xml; the spdx adapter supports json, xml, and tag-value. spdx rdf is not supported by either.
- both adapters may leave some source-specific fields unmapped if no stable equivalent exists in the core model.
