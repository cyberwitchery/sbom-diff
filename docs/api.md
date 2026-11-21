# api

the `sbom-model` crate provides a high-level query api.

## query methods
- `roots()`: components with no parents.
- `deps(id)`: direct children.
- `rdeps(id)`: direct parents.
- `transitive_deps(id)`: all downstream components.
- `ecosystems()`: set of all ecosystems.
- `licenses()`: set of all licenses.
- `missing_hashes()`: components without checksums.
- `by_purl(purl)`: find component by purl.

## usage
```rust
use sbom_model_spdx::SpdxReader;

let sbom = SpdxReader::read_json(std::fs::File::open("sbom.spdx.json")?)?;
let roots = sbom.roots();
let licenses = sbom.licenses();
```
