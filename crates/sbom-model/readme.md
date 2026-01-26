# sbom-model

format-agnostic data model for software bills of materials.

this crate provides the core types used across the `sbom-diff` workspace. it defines a unified representation that abstracts over specific formats like cyclonedx and spdx.

## usage

```rust
use sbom_model::{Sbom, Component, ComponentId};

// create a component
let mut component = Component::new("serde".into(), Some("1.0.0".into()));
component.licenses.push("MIT".into());
component.licenses.push("Apache-2.0".into());

// create an sbom and add the component
let mut sbom = Sbom::default();
sbom.components.insert(component.id.clone(), component);

// normalize for deterministic comparison
sbom.normalize();
```

## component identification

components are identified by `ComponentId`, which prefers package urls (purls) when available:

```rust
use sbom_model::ComponentId;

// with a purl (preferred)
let id = ComponentId::new(Some("pkg:npm/left-pad@1.3.0"), &[]);
assert_eq!(id.as_str(), "pkg:npm/left-pad@1.3.0");

// without a purl: falls back to deterministic hash
let id = ComponentId::new(None, &[("name", "foo"), ("version", "1.0")]);
assert!(id.as_str().starts_with("h:"));
```

## query api

the `Sbom` struct provides methods to query the dependency graph:

```rust
use sbom_model::Sbom;

fn example(sbom: &Sbom) {
    // find root components (not depended on by anything)
    let roots = sbom.roots();

    // get direct dependencies of a component
    let deps = sbom.deps(&roots[0]);

    // get reverse dependencies (who depends on this?)
    let rdeps = sbom.rdeps(&roots[0]);

    // get all transitive dependencies
    let all_deps = sbom.transitive_deps(&roots[0]);

    // aggregate queries
    let ecosystems = sbom.ecosystems();  // e.g. {"npm", "cargo"}
    let licenses = sbom.licenses();       // e.g. {"MIT", "Apache-2.0"}
    let missing = sbom.missing_hashes();  // components without checksums
}
```

## normalization

`sbom.normalize()` prepares an sbom for deterministic comparison:

- sorts components by id
- deduplicates and sorts licenses
- lowercases hash algorithms and values
- strips volatile metadata (timestamps, tool versions)

## related crates

- [`sbom-model-cyclonedx`](https://docs.rs/sbom-model-cyclonedx) - parse cyclonedx json into this model
- [`sbom-model-spdx`](https://docs.rs/sbom-model-spdx) - parse spdx json into this model
- [`sbom-diff`](https://docs.rs/sbom-diff) - diff engine using this model
