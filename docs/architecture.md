# architecture

the project is split into four main crates:

- `sbom-model`: core agnostic types + normalization + query api.
- `sbom-model-cyclonedx`: adapter for cyclonedx json.
- `sbom-model-spdx`: adapter for spdx json.
- `sbom-diff`: diff engine, renderers, and cli.

## data flow
1. readers parse source sboms into format-specific types.
2. adapters map those to the agnostic `sbom` model.
3. `sbom.normalize()` ensures deterministic comparison.
4. `differ` compares two models using identity-based reconciliation.
5. renderers output the diff in text, markdown, or json.
