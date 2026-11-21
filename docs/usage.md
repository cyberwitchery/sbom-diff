# usage

## cli
```bash
sbom-diff [flags] <old-file> <new-file>
```

### flags
- `-f, --format <auto|cyclonedx|cyclonedx-xml|spdx|spdx-tv|spdx-xml>`: force input format (default: auto).
- `-o, --output <text|markdown|json|sarif|csv>`: set output format (default: text).
- `--only <fields>`: comma-separated list of fields to report (version, license, supplier, purl, description, hashes, ecosystem, deps).
- `--deny-license <license>`: fail (exit 2) if a component in the new sbom can only be taken under this license.
- `--allow-license <license>`: fail (exit 2) if a component in the new sbom cannot be taken under the allowed licenses alone. a component with no license information fails it.
- each `--deny-license` or `--allow-license` names one license: an SPDX id, its `+` form, or `<id> WITH <exception>`. repeat the flag once per license; an expression such as `MIT OR Apache-2.0` is an error (exit 1). an entry that is not an SPDX id or a `LicenseRef-` prints a warning, since it can only match a free-text license name.
- `--fail-on <condition>`: fail (exit 3) on a condition from the table below; repeatable. a license violation in the same run exits 2 instead.
- `--include-ecosystem <name>`, `--exclude-ecosystem <name>`: diff and gate only the components in these ecosystems, or leave them out; repeatable, case-insensitive. a component with no ecosystem is `unknown`. both scope every gate, the license gates included.
- `--group-by-ecosystem`: break down counts by package ecosystem, and group the report's components by it.
- `--summary`: print only summary counts (no component details).
- `--show-warnings`: include the parsers' warnings in the report. they go to stderr either way.
- `-q, --quiet`: print no report. parser warnings and gate errors still go to stderr, and the exit code is unchanged.

### fail-on conditions

| condition | fails if |
|-----------|----------|
| `missing-hashes` | any added component lacks checksums or a changed component dropped all its checksums |
| `added-components` | any components were added |
| `removed-components` | any components were removed |
| `changed-components` | any components changed |
| `deps` | any dependency edges changed |
| `license-changed` | any changed component's license changed or any added component introduces licenses |
| `metadata-changed` | document metadata changed (timestamp, tools, or authors) |
| `version-downgrade` | any changed component's version went from a higher to a lower value |
| `supplier-changed` | any changed component's supplier changed or any added component has a supplier |
| `hash-algorithm-downgrade` | any changed component's strongest hash algorithm is weaker than before |
| `copyleft-added` | a changed or added component introduces a copyleft license (e.g. GPL, AGPL) not present before |
| `cyclic-dependency` | the new SBOM's dependency graph contains cycles |
| `purl-changed` | any changed component's package URL (purl) changed other than in its version; a purl namespace swap is a removed and an added component instead |
| `ecosystem-changed` | any changed component's ecosystem changed |
| `checksum-changed` | a changed component's checksum differs under an algorithm both sides carry while its version is unchanged |

### exit codes

| code | meaning |
|------|---------|
| 0 | success |
| 1 | error (invalid input, parse failure, bad command line) |
| 2 | license violation (`--deny-license` or `--allow-license`) |
| 3 | fail-on condition triggered (`--fail-on`) |

a run with both a license violation and a fail-on condition exits 2 and prints both on stderr.

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

# fail if a changed component's purl or ecosystem changes, e.g. a purl renamed within its namespace or a new repository_url
sbom-diff old.json new.json --fail-on purl-changed
sbom-diff old.json new.json --fail-on ecosystem-changed

# a group/scope swap (com.corp:utils -> com.evil:utils, @corp/utils -> utils) is a removed and an added component instead
sbom-diff old.json new.json --fail-on added-components --fail-on removed-components

# fail if a component's digest changed but its version did not (re-published artifact)
sbom-diff old.json new.json --fail-on checksum-changed

# read from stdin
cat new.json | sbom-diff old.json -
```
