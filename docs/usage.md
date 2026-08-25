# usage

## cli
```bash
sbom-diff [flags] <old-file> <new-file>
```

### flags
- `-f, --format <auto|cyclonedx|cyclonedx-xml|spdx|spdx-tv|spdx-xml>`: force input format (default: auto).
- `-o, --output <text|markdown|json|sarif|csv>`: set output format (default: text).
- `--only <fields>`: comma-separated list of fields to report (version, license, supplier, purl, description, hashes, ecosystem, deps).
- `--deny-license <expr>`: fail (exit 2) if license is found in new sbom.
- `--allow-license <expr>`: fail (exit 2) if license is not in allowlist.
- `--fail-on <condition>`: fail (exit 3) on specific conditions (e.g. added-components, missing-hashes, checksum-changed, deps, purl-changed, ecosystem-changed).
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

# fail if a component's package coordinates change (typosquat / dependency-confusion signal)
sbom-diff old.json new.json --fail-on purl-changed
sbom-diff old.json new.json --fail-on ecosystem-changed

# fail if a component's digest changed but its version did not (re-published artifact)
sbom-diff old.json new.json --fail-on checksum-changed

# read from stdin
cat new.json | sbom-diff old.json -
```
