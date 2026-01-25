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
   - matches by name + ecosystem for version bumps when no purl is present.
