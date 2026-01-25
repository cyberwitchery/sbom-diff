# sbom-diff

fast, format-agnostic sbom comparison tool.

## usage

```bash
# compare two sboms
sbom-diff old.json new.json

# markdown for pr comments
sbom-diff old.json new.json -o markdown

# filter for specific changes
sbom-diff old.json new.json --only version,license

# license gating (exit code 2 on fail)
sbom-diff old.json new.json --deny-license gpl-3.0-only
```

## examples

### text output (default)
```text
diff summary
============
added:   1
removed: 0
changed: 1

[+] added
---------
pkg:npm/left-pad@1.3.0

[~] changed
-----------
pkg:cargo/serde@1.0.191
  version: 1.0.190 -> 1.0.191
  license: ["mit"] -> ["mit", "apache-2.0"]
```

## features
- supports cyclonedx + spdx json.
- deterministic normalization.
- matches components by purl or identity (name/ecosystem).
- zero network access.

<hr/>

have fun!
