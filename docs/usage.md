# usage

## cli
```bash
sbom-diff [flags] <old-file> <new-file>
```

### flags
- `-f, --format <auto|cyclonedx|spdx>`: force input format (default: auto).
- `-o, --output <text|markdown|json>`: set output format (default: text).
- `--only <fields>`: comma-separated list of fields to report (version, license, supplier, purl, hashes, deps).
- `--deny-license <expr>`: fail (exit 2) if license is found in new sbom.
- `--allow-license <expr>`: fail (exit 2) if license is not in allowlist.
- `--fail-on <condition>`: fail (exit 3) on specific conditions (added-components, missing-hashes, deps).
- `--summary`: print only summary counts (no component details).
- `-q, --quiet`: suppress all output except errors.

### examples
```bash
# compare two sboms and output markdown
sbom-diff old.json new.json -o markdown

# only show version and license changes
sbom-diff old.json new.json --only version,license

# only show dependency edge changes
sbom-diff old.json new.json --only deps

# fail if dependency graph changes
sbom-diff old.json new.json --fail-on deps

# read from stdin
cat new.json | sbom-diff old.json -
```
