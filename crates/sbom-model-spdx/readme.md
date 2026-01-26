# sbom-model-spdx

spdx adapter for [`sbom-model`](https://docs.rs/sbom-model).

parses [spdx](https://spdx.dev/) json documents into the format-agnostic `Sbom` type.

## usage

```rust
use sbom_model::Sbom;
use sbom_model_spdx::SpdxReader;

let json = r#"{
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "example",
    "documentNamespace": "https://example.com/sbom",
    "creationInfo": {
        "creators": ["Tool: example"],
        "created": "2024-01-01T00:00:00Z"
    },
    "packages": [
        {
            "name": "serde",
            "SPDXID": "SPDXRef-serde",
            "downloadLocation": "https://crates.io/crates/serde",
            "licenseConcluded": "MIT"
        }
    ],
    "relationships": []
}"#;

let sbom: Sbom = SpdxReader::read_json(json.as_bytes()).unwrap();

assert_eq!(sbom.components.len(), 1);
assert_eq!(sbom.components[0].name, "serde");
```

## supported features

- spdx 2.3 json format (rdf/xml/tag-value not supported)
- packages with name, version, licenses, checksums
- supplier information
- purl extraction from external references
- relationship-based dependency graph (DEPENDS_ON, CONTAINS, DESCRIBES)
- creation info (timestamps, tools, authors)

## error handling

```rust
use sbom_model_spdx::{SpdxReader, Error};

fn parse(data: &[u8]) -> Result<(), Error> {
    let sbom = SpdxReader::read_json(data)?;
    // ...
    Ok(())
}
```

the `Error` type wraps parse errors from `serde_json`.

## related crates

- [`sbom-model`](https://docs.rs/sbom-model) - the core data model
- [`sbom-model-cyclonedx`](https://docs.rs/sbom-model-cyclonedx) - cyclonedx format adapter
- [`sbom-diff`](https://docs.rs/sbom-diff) - diff engine and cli
