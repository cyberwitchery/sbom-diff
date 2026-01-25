# usage

## cli
```bash
sbom-diff [flags] <old-file> <new-file>
```

### flags
- `-f, --format <auto|cyclonedx|spdx>`: force input format (default: auto).
- `-o, --output <text|markdown|json>`: set output format (default: text).
- `--only <fields>`: comma-separated list of fields to report (version, license, supplier, purl, hashes).
- `--deny-license <expr>`: fail (exit 2) if license is found in new sbom.
- `--allow-license <expr>`: fail (exit 2) if license is not in allowlist.

### examples
```bash
# compare two sboms and output markdown
sbom-diff old.json new.json -o markdown

# only show version and license changes
sbom-diff old.json new.json --only version,license

# read from stdin
cat new.json | sbom-diff old.json -
```
