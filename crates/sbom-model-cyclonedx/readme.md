# sbom-model-cyclonedx

cyclonedx adapter for [`sbom-model`](https://docs.rs/sbom-model).

parses [cyclonedx](https://cyclonedx.org/) json documents into the format-agnostic `Sbom` type.

## usage

```rust
use sbom_model::Sbom;
use sbom_model_cyclonedx::CycloneDxReader;

let json = r#"{
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "version": 1,
    "components": [
        {
            "type": "library",
            "name": "serde",
            "version": "1.0.0",
            "purl": "pkg:cargo/serde@1.0.0",
            "licenses": [{"license": {"id": "MIT"}}]
        }
    ]
}"#;

let sbom: Sbom = CycloneDxReader::read_json(json.as_bytes()).unwrap();

assert_eq!(sbom.components.len(), 1);
assert_eq!(sbom.components[0].name, "serde");
```

## supported features

- cyclonedx 1.4+ json format (xml not supported)
- components with name, version, purl, licenses, hashes
- supplier information
- bom-ref based dependency graph
- metadata (timestamps, authors)

## error handling

```rust
use sbom_model_cyclonedx::{CycloneDxReader, Error};

fn parse(data: &[u8]) -> Result<(), Error> {
    let sbom = CycloneDxReader::read_json(data)?;
    // ...
    Ok(())
}
```

the `Error` type wraps parse errors from the underlying `cyclonedx-bom` crate.

## related crates

- [`sbom-model`](https://docs.rs/sbom-model) - the core data model
- [`sbom-model-spdx`](https://docs.rs/sbom-model-spdx) - spdx format adapter
- [`sbom-diff`](https://docs.rs/sbom-diff) - diff engine and cli
