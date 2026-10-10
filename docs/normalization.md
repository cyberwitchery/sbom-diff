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
   - otherwise matches by name, ecosystem and purl namespace; the purl carries the version, so this is what pairs every version bump.
   - a component without a purl has no ecosystem or namespace to compare and matches on name alone; a purl without a namespace (`pkg:npm/react`) does not match one with (`pkg:npm/%40types/react`).
