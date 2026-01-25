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
use sbom_model::Sbom;

let sbom = load_sbom();
let roots = sbom.roots();
let licenses = sbom.licenses();
```
