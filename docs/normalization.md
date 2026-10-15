# normalization

to ensure stable diffs, the model applies:

1. **id generation**:
   - prefers `purl`.
   - falls back to deterministic hash of name, version, and supplier.

2. **field cleanup**:
   - strips timestamps and tool metadata.
   - lowercases hash algorithms and values.
   - sorts license lists.

3. **reconciliation**:
   - if `purl` matches but internal `id` differs, components are treated as same entity.
   - otherwise components whose purls parse match on the purl's type, namespace and name, in the canonical form their ids use and whatever their `name` field says; the purl carries the version, so this is what pairs every version bump. `PyYAML` and `pyyaml`, `typing_extensions` and `typing-extensions`, and an npm scope written as a CycloneDX `group` or inside the name (`@angular/core`) pair this way.
   - what is left matches by name, ecosystem and purl namespace, so a purl renamed under one component name (`pkg:npm/left-pad` -> `pkg:npm/left-pad-fork`) is a purl change.
   - a component without a purl has no ecosystem or namespace to compare and matches on name alone; a purl without a namespace (`pkg:npm/react`) does not match one with (`pkg:npm/%40types/react`).
   - purls are compared in that canonical form, so `pkg:pypi/PyYAML@6.0` -> `pkg:pypi/pyyaml@6.0` is no purl change, while a version bump still lists its purl difference.
