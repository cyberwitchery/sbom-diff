use anyhow::{anyhow, Context};
use clap::{Parser, ValueEnum};
use sbom_diff::{
    renderer::{
        format_option, format_set, CsvRenderer, JsonRenderer, MarkdownRenderer, RenderOptions,
        Renderer, SarifRenderer, SummaryRenderer, TextRenderer,
    },
    Differ,
};
use sbom_model::is_hash_algorithm_downgrade;
use sbom_model::versions::is_version_downgrade;
use sbom_model::Sbom;
use sbom_model_cyclonedx::CycloneDxReader;
use sbom_model_spdx::SpdxReader;
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// old sbom file (use - for stdin)
    old: String,

    /// new sbom file (use - for stdin)
    new: String,

    /// input format
    #[arg(short, long, value_enum, default_value_t = Format::Auto)]
    format: Format,

    /// output format
    #[arg(short, long, value_enum, default_value_t = Output::Text)]
    output: Output,

    /// deny these licenses (repeatable)
    #[arg(long)]
    deny_license: Vec<String>,

    /// allow only these licenses (repeatable)
    #[arg(long)]
    allow_license: Vec<String>,

    /// only report changes in these fields
    #[arg(long, value_enum, value_delimiter = ',')]
    only: Vec<Field>,

    /// fail on specific conditions (repeatable)
    #[arg(long, value_enum)]
    fail_on: Vec<FailOn>,

    /// only show changes for these ecosystems (repeatable)
    #[arg(long)]
    include_ecosystem: Vec<String>,

    /// exclude changes for these ecosystems (repeatable)
    #[arg(long)]
    exclude_ecosystem: Vec<String>,

    /// break down counts by package ecosystem (npm, cargo, pypi, etc)
    #[arg(long)]
    group_by_ecosystem: bool,

    /// print only summary counts (no component details)
    #[arg(long)]
    summary: bool,

    /// suppress all output except errors
    #[arg(short, long)]
    quiet: bool,

    /// include parser warnings in rendered output
    #[arg(long)]
    show_warnings: bool,
}

/// Conditions that trigger a non-zero exit code.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum FailOn {
    /// Fail if any added component lacks checksums or a changed component dropped all its checksums.
    MissingHashes,
    /// Fail if any components were added.
    AddedComponents,
    /// Fail if any components were removed.
    RemovedComponents,
    /// Fail if any components changed.
    ChangedComponents,
    /// Fail if any dependency edges changed.
    Deps,
    /// Fail if any changed component's license changed or any added component introduces licenses.
    LicenseChanged,
    /// Fail if document metadata changed (timestamp, tools, or authors).
    MetadataChanged,
    /// Fail if any changed component's version went from a higher to a lower value.
    VersionDowngrade,
    /// Fail if any changed component's supplier changed or any added component has a supplier.
    SupplierChanged,
    /// Fail if any changed component's strongest hash algorithm is weaker than before.
    HashAlgorithmDowngrade,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum Field {
    Version,
    License,
    Supplier,
    Purl,
    Description,
    Hashes,
    Ecosystem,
    Deps,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Format {
    Auto,
    Cyclonedx,
    CyclonedxXml,
    Spdx,
    SpdxTv,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Output {
    Text,
    Markdown,
    Json,
    Sarif,
    Csv,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let old_sbom = load_sbom(&args.old, args.format).context("failed to load old sbom")?;
    let new_sbom = load_sbom(&args.new, args.format).context("failed to load new sbom")?;

    for w in old_sbom.warnings.iter().chain(new_sbom.warnings.iter()) {
        eprintln!("warning: {}", w);
    }

    // Build render options and run license checks before diff_owned consumes
    // the SBOMs — this avoids cloning both SBOMs inside the differ.
    let render_opts = RenderOptions {
        group_by_ecosystem: args.group_by_ecosystem,
        show_warnings: args.show_warnings,
        old_warnings: old_sbom.warnings.clone(),
        new_warnings: new_sbom.warnings.clone(),
    };

    let license_violation = check_licenses(&new_sbom, &args.deny_license, &args.allow_license);

    // Build ecosystem filter and pre-count filtered totals before diff_owned
    // consumes the SBOMs.
    let eco_include: HashSet<String> = args
        .include_ecosystem
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();
    let eco_exclude: HashSet<String> = args
        .exclude_ecosystem
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();
    let eco_filter_active = !eco_include.is_empty() || !eco_exclude.is_empty();

    let eco_matches = |eco: Option<&str>| -> bool {
        let eco_lower = eco.unwrap_or("unknown").to_ascii_lowercase();
        if !eco_include.is_empty() && !eco_include.contains(&eco_lower) {
            return false;
        }
        if eco_exclude.contains(&eco_lower) {
            return false;
        }
        true
    };

    let (filtered_old_total, filtered_new_total) = if eco_filter_active {
        (
            old_sbom
                .components
                .values()
                .filter(|c| eco_matches(c.ecosystem.as_deref()))
                .count(),
            new_sbom
                .components
                .values()
                .filter(|c| eco_matches(c.ecosystem.as_deref()))
                .count(),
        )
    } else {
        (0, 0)
    };

    let only_fields: Vec<sbom_diff::Field> = args
        .only
        .iter()
        .map(|f| match f {
            Field::Version => sbom_diff::Field::Version,
            Field::License => sbom_diff::Field::License,
            Field::Supplier => sbom_diff::Field::Supplier,
            Field::Purl => sbom_diff::Field::Purl,
            Field::Description => sbom_diff::Field::Description,
            Field::Hashes => sbom_diff::Field::Hashes,
            Field::Ecosystem => sbom_diff::Field::Ecosystem,
            Field::Deps => sbom_diff::Field::Deps,
        })
        .collect();

    let mut diff = Differ::diff_owned(
        old_sbom,
        new_sbom,
        if only_fields.is_empty() {
            None
        } else {
            Some(&only_fields)
        },
    );

    if eco_filter_active {
        diff.filter_by_ecosystem(eco_matches, filtered_old_total, filtered_new_total);
    }

    let fail_on_violation = check_fail_on(&diff, &args.fail_on);

    if !args.quiet {
        let stdout = io::stdout();
        let mut handle = stdout.lock();

        if args.summary {
            match args.output {
                Output::Text => TextRenderer.render_summary(&diff, &render_opts, &mut handle)?,
                Output::Markdown => {
                    MarkdownRenderer.render_summary(&diff, &render_opts, &mut handle)?
                }
                Output::Json => JsonRenderer.render_summary(&diff, &render_opts, &mut handle)?,
                Output::Sarif => SarifRenderer.render_summary(&diff, &render_opts, &mut handle)?,
                Output::Csv => CsvRenderer.render_summary(&diff, &render_opts, &mut handle)?,
            }
        } else {
            match args.output {
                Output::Text => TextRenderer.render(&diff, &render_opts, &mut handle)?,
                Output::Markdown => MarkdownRenderer.render(&diff, &render_opts, &mut handle)?,
                Output::Json => JsonRenderer.render(&diff, &render_opts, &mut handle)?,
                Output::Sarif => SarifRenderer.render(&diff, &render_opts, &mut handle)?,
                Output::Csv => CsvRenderer.render(&diff, &render_opts, &mut handle)?,
            }
        }
    }

    if license_violation {
        std::process::exit(2);
    }

    if fail_on_violation {
        std::process::exit(3);
    }

    Ok(())
}

fn check_licenses(sbom: &Sbom, deny: &[String], allow: &[String]) -> bool {
    // SPDX license IDs are case-insensitive per spec (Annex E / clause 10.1).
    // Normalize to lowercase for matching so that e.g. --deny-license GPL-3.0-only
    // catches components whose SBOM uses gpl-3.0-only.
    let deny_lower: HashSet<String> = deny.iter().map(|s| s.to_ascii_lowercase()).collect();
    let allow_lower: HashSet<String> = allow.iter().map(|s| s.to_ascii_lowercase()).collect();

    let mut violation = false;
    for comp in sbom.components.values() {
        // A component with no license information cannot satisfy an allow-list.
        if !allow.is_empty() && comp.licenses.is_empty() {
            eprintln!(
                "error: component {} has no license information (--allow-license requires it)",
                comp.id
            );
            violation = true;
            continue;
        }
        for license in &comp.licenses {
            let license_lower = license.to_ascii_lowercase();
            if !deny_lower.is_empty() && deny_lower.contains(&license_lower) {
                eprintln!(
                    "error: license {} is denied (component {})",
                    license, comp.id
                );
                violation = true;
            }
            if !allow_lower.is_empty() && !allow_lower.contains(&license_lower) {
                eprintln!(
                    "error: license {} is not allowed (component {})",
                    license, comp.id
                );
                violation = true;
            }
        }
    }
    violation
}

fn check_fail_on(diff: &sbom_diff::Diff, fail_on: &[FailOn]) -> bool {
    let mut violation = false;

    for condition in fail_on {
        match condition {
            FailOn::AddedComponents => {
                if !diff.added.is_empty() {
                    for comp in &diff.added {
                        eprintln!(
                            "error: added component {} (--fail-on added-components)",
                            comp.id
                        );
                    }
                    violation = true;
                }
            }
            FailOn::MissingHashes => {
                for comp in &diff.added {
                    if comp.hashes.is_empty() {
                        eprintln!(
                            "error: added component {} has no hashes (--fail-on missing-hashes)",
                            comp.id
                        );
                        violation = true;
                    }
                }
                for change in &diff.changed {
                    if !change.old.hashes.is_empty() && change.new.hashes.is_empty() {
                        eprintln!(
                            "error: changed component {} dropped all hashes (--fail-on missing-hashes)",
                            change.id
                        );
                        violation = true;
                    }
                }
            }
            FailOn::RemovedComponents => {
                if !diff.removed.is_empty() {
                    for comp in &diff.removed {
                        eprintln!(
                            "error: removed component {} (--fail-on removed-components)",
                            comp.id
                        );
                    }
                    violation = true;
                }
            }
            FailOn::ChangedComponents => {
                if !diff.changed.is_empty() {
                    for change in &diff.changed {
                        eprintln!(
                            "error: changed component {} (--fail-on changed-components)",
                            change.id
                        );
                    }
                    violation = true;
                }
            }
            FailOn::Deps => {
                if !diff.edge_diffs.is_empty() {
                    for edge in &diff.edge_diffs {
                        for added in edge.added.keys() {
                            eprintln!(
                                "error: added dependency edge {} -> {} (--fail-on deps)",
                                edge.parent, added
                            );
                        }
                        for removed in edge.removed.keys() {
                            eprintln!(
                                "error: removed dependency edge {} -> {} (--fail-on deps)",
                                edge.parent, removed
                            );
                        }
                        for (child, (old_kind, new_kind)) in &edge.kind_changed {
                            eprintln!(
                                "error: dependency edge {} -> {} changed kind: {} -> {} (--fail-on deps)",
                                edge.parent, child, old_kind, new_kind
                            );
                        }
                    }
                    violation = true;
                }
            }
            FailOn::LicenseChanged => {
                for change in &diff.changed {
                    for fc in &change.changes {
                        if let sbom_diff::FieldChange::License(old, new) = fc {
                            eprintln!(
                                "error: license changed on component {}: {} -> {} (--fail-on license-changed)",
                                change.id, format_set(old), format_set(new)
                            );
                            violation = true;
                        }
                    }
                }
                for comp in &diff.added {
                    if !comp.licenses.is_empty() {
                        let licenses: Vec<_> = comp.licenses.iter().cloned().collect();
                        eprintln!(
                            "error: added component {} introduces license(s): {} (--fail-on license-changed)",
                            comp.id, licenses.join(", ")
                        );
                        violation = true;
                    }
                }
            }
            FailOn::MetadataChanged => {
                if let Some(mc) = &diff.metadata_changed {
                    if mc.timestamp.is_some() {
                        eprintln!(
                            "error: document metadata timestamp changed (--fail-on metadata-changed)"
                        );
                    }
                    if mc.tools.is_some() {
                        eprintln!(
                            "error: document metadata tools changed (--fail-on metadata-changed)"
                        );
                    }
                    if mc.authors.is_some() {
                        eprintln!(
                            "error: document metadata authors changed (--fail-on metadata-changed)"
                        );
                    }
                    violation = true;
                }
            }
            FailOn::VersionDowngrade => {
                for change in &diff.changed {
                    for fc in &change.changes {
                        if let sbom_diff::FieldChange::Version(Some(old_ver), Some(new_ver)) = fc {
                            if is_version_downgrade(old_ver, new_ver) {
                                eprintln!(
                                    "error: version downgrade on component {}: {} -> {} (--fail-on version-downgrade)",
                                    change.id, old_ver, new_ver
                                );
                                violation = true;
                            }
                        }
                    }
                }
            }
            FailOn::SupplierChanged => {
                for change in &diff.changed {
                    for fc in &change.changes {
                        if let sbom_diff::FieldChange::Supplier(old_sup, new_sup) = fc {
                            eprintln!(
                                "error: supplier changed on component {}: {} -> {} (--fail-on supplier-changed)",
                                change.id, format_option(old_sup), format_option(new_sup)
                            );
                            violation = true;
                        }
                    }
                }
                for comp in &diff.added {
                    if comp.supplier.is_some() {
                        eprintln!(
                            "error: added component {} has supplier: {} (--fail-on supplier-changed)",
                            comp.id,
                            comp.supplier.as_deref().unwrap_or("<none>")
                        );
                        violation = true;
                    }
                }
            }
            FailOn::HashAlgorithmDowngrade => {
                for change in &diff.changed {
                    for fc in &change.changes {
                        if let sbom_diff::FieldChange::Hashes(old_hashes, new_hashes) = fc {
                            if is_hash_algorithm_downgrade(old_hashes, new_hashes) {
                                let old_algos: Vec<_> = old_hashes.keys().cloned().collect();
                                let new_algos: Vec<_> = new_hashes.keys().cloned().collect();
                                eprintln!(
                                    "error: hash algorithm downgrade on component {}: [{}] -> [{}] (--fail-on hash-algorithm-downgrade)",
                                    change.id,
                                    old_algos.join(", "),
                                    new_algos.join(", "),
                                );
                                violation = true;
                            }
                        }
                    }
                }
            }
        }
    }

    violation
}

/// Format detected by content-based heuristics.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum DetectedFormat {
    CyclonedxJson,
    CyclonedxXml,
    SpdxJson,
    SpdxTv,
    Unknown,
}

impl DetectedFormat {
    fn label(self) -> &'static str {
        match self {
            DetectedFormat::CyclonedxJson => "CycloneDX JSON",
            DetectedFormat::CyclonedxXml => "CycloneDX XML",
            DetectedFormat::SpdxJson => "SPDX JSON",
            DetectedFormat::SpdxTv => "SPDX tag-value",
            DetectedFormat::Unknown => "unknown",
        }
    }
}

/// Pre-scan the first bytes of `content` for well-known SBOM format markers.
///
/// The scan window is capped at 8 KiB — every supported format places its
/// identifying marker near the top of the document.
fn detect_format(content: &[u8]) -> DetectedFormat {
    let window = &content[..content.len().min(8192)];

    // Fast path: check if this looks like XML at all (after optional BOM / whitespace).
    let trimmed = strip_bom_and_whitespace(window);
    if trimmed.starts_with(b"<") {
        // XML-ish — look for the CycloneDX namespace.
        if find_subsequence(window, b"cyclonedx.org/schema/bom").is_some() {
            return DetectedFormat::CyclonedxXml;
        }
        // Could be some other XML, but not a format we support.
        return DetectedFormat::Unknown;
    }

    // JSON-ish — look for distinctive top-level keys.
    if find_subsequence(window, b"\"bomFormat\"").is_some() {
        return DetectedFormat::CyclonedxJson;
    }
    if find_subsequence(window, b"\"spdxVersion\"").is_some() {
        return DetectedFormat::SpdxJson;
    }

    // Tag-value: lines starting with SPDXVersion:
    for line in window.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let line = trim_ascii_start(line);
        if line.starts_with(b"SPDXVersion:") {
            return DetectedFormat::SpdxTv;
        }
        // Only inspect up to the first non-empty, non-comment line.
        if !line.is_empty() && !line.starts_with(b"#") {
            break;
        }
    }

    DetectedFormat::Unknown
}

/// Strip a leading UTF-8 BOM and ASCII whitespace from a byte slice.
fn strip_bom_and_whitespace(data: &[u8]) -> &[u8] {
    let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
    trim_ascii_start(data)
}

/// Trim leading ASCII whitespace bytes.
fn trim_ascii_start(data: &[u8]) -> &[u8] {
    let pos = data
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(data.len());
    &data[pos..]
}

/// Naive subsequence search (good enough for small windows).
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Try a single parser, returning `Ok(sbom)` or appending to `errors`.
fn try_parse(
    content: &[u8],
    label: &str,
    parse: impl FnOnce(&[u8]) -> Result<Sbom, Box<dyn std::fmt::Display>>,
    errors: &mut Vec<String>,
) -> Option<Sbom> {
    match parse(content) {
        Ok(sbom) => Some(sbom),
        Err(e) => {
            errors.push(format!("  {label}: {e}"));
            None
        }
    }
}

type ParseFn = fn(&[u8]) -> Result<Sbom, Box<dyn std::fmt::Display>>;

/// The four parsers in a fixed order, used for fallback iteration.
const ALL_PARSERS: &[(&str, ParseFn)] = &[
    ("cyclonedx json", |c| {
        CycloneDxReader::read_json(c).map_err(|e| Box::new(e) as _)
    }),
    ("cyclonedx xml", |c| {
        CycloneDxReader::read_xml(c).map_err(|e| Box::new(e) as _)
    }),
    ("spdx json", |c| {
        SpdxReader::read_json(c).map_err(|e| Box::new(e) as _)
    }),
    ("spdx tag-value", |c| {
        SpdxReader::read_tag_value(c).map_err(|e| Box::new(e) as _)
    }),
];

fn load_sbom(path: &str, format: Format) -> anyhow::Result<Sbom> {
    let mut content = Vec::new();
    if path == "-" {
        io::stdin().read_to_end(&mut content)?;
    } else {
        let mut file = File::open(path).context(format!("could not open file: {}", path))?;
        file.read_to_end(&mut content)?;
    }

    if content.is_empty() {
        return Err(anyhow!("input is empty"));
    }

    // Reject binary input: check for null bytes in the first 8 KiB.
    let probe = &content[..content.len().min(8192)];
    if probe.contains(&0) {
        return Err(anyhow!(
            "input appears to be binary (contains null bytes); expected a text-based SBOM \
             (CycloneDX JSON/XML or SPDX JSON/tag-value)"
        ));
    }

    match format {
        Format::Cyclonedx => {
            CycloneDxReader::read_json(&content[..]).map_err(|e| anyhow!("cyclonedx error: {}", e))
        }
        Format::CyclonedxXml => CycloneDxReader::read_xml(&content[..])
            .map_err(|e| anyhow!("cyclonedx xml error: {}", e)),
        Format::Spdx => {
            SpdxReader::read_json(&content[..]).map_err(|e| anyhow!("spdx error: {}", e))
        }
        Format::SpdxTv => SpdxReader::read_tag_value(&content[..])
            .map_err(|e| anyhow!("spdx tag-value error: {}", e)),
        Format::Auto => auto_detect_and_parse(&content),
    }
}

fn auto_detect_and_parse(content: &[u8]) -> anyhow::Result<Sbom> {
    let detected = detect_format(content);

    // Map detected format to the index into ALL_PARSERS that should go first.
    let primary_idx = match detected {
        DetectedFormat::CyclonedxJson => Some(0),
        DetectedFormat::CyclonedxXml => Some(1),
        DetectedFormat::SpdxJson => Some(2),
        DetectedFormat::SpdxTv => Some(3),
        DetectedFormat::Unknown => None,
    };

    let mut errors = Vec::new();

    // Try the detected format first.
    if let Some(idx) = primary_idx {
        let (label, parse) = ALL_PARSERS[idx];
        if let Some(sbom) = try_parse(content, label, parse, &mut errors) {
            return Ok(sbom);
        }
    }

    // Fallback: try remaining parsers in order.
    for (i, (label, parse)) in ALL_PARSERS.iter().enumerate() {
        if Some(i) == primary_idx {
            continue; // already tried
        }
        if let Some(sbom) = try_parse(content, label, parse, &mut errors) {
            return Ok(sbom);
        }
    }

    // All parsers failed — build a targeted error message.
    match detected {
        DetectedFormat::Unknown => Err(anyhow!(
            "could not detect SBOM format; the input does not contain \
             any recognized format markers (\"bomFormat\", \"spdxVersion\", \
             CycloneDX XML namespace, or SPDXVersion tag-value header).\n\
             Parser errors:\n{}",
            errors.join("\n")
        )),
        _ => Err(anyhow!(
            "input appears to be {} (based on content markers), \
             but parsing failed:\n{}",
            detected.label(),
            errors.join("\n")
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbom_model::Component;

    #[test]
    fn test_check_licenses() {
        let mut sbom = Sbom::default();
        let mut c = Component::new("a".into(), Some("1".into()));
        c.licenses.insert("GPL-3.0-only".into());
        sbom.components.insert(c.id.clone(), c);

        // Exact match
        assert!(check_licenses(&sbom, &["GPL-3.0-only".into()], &[]));
        // No match
        assert!(!check_licenses(&sbom, &["MIT".into()], &[]));
        // Not in allow list
        assert!(check_licenses(&sbom, &[], &["MIT".into()]));
        // In allow list
        assert!(!check_licenses(&sbom, &[], &["GPL-3.0-only".into()]));
    }

    #[test]
    fn test_check_licenses_multiple() {
        let mut sbom = Sbom::default();
        let mut c = Component::new("a".into(), Some("1".into()));
        // Two separate licenses in the set
        c.licenses.insert("MIT".into());
        c.licenses.insert("Apache-2.0".into());
        sbom.components.insert(c.id.clone(), c);

        // Either license triggers deny
        assert!(check_licenses(&sbom, &["MIT".into()], &[]));
        assert!(check_licenses(&sbom, &["Apache-2.0".into()], &[]));
        // Both must be in allow list
        assert!(check_licenses(&sbom, &[], &["MIT".into()])); // Apache-2.0 not allowed
        assert!(!check_licenses(
            &sbom,
            &[],
            &["MIT".into(), "Apache-2.0".into()]
        ));
    }

    #[test]

    fn test_load_sbom_auto_cyclonedx() {
        // use existing fixture

        let path = "../../tests/fixtures/old.json";

        let sbom = load_sbom(path, Format::Auto).unwrap();

        assert!(!sbom.components.is_empty());
    }

    #[test]
    fn test_load_sbom_auto_spdx() {
        let path = "../../tests/fixtures/old.spdx.json";
        let sbom = load_sbom(path, Format::Auto).unwrap();
        assert!(!sbom.components.is_empty());
    }

    #[test]
    fn test_load_sbom_auto_cyclonedx_xml() {
        let path = "../../tests/fixtures/golden-old.cdx.xml";
        let sbom = load_sbom(path, Format::Auto).unwrap();
        assert!(!sbom.components.is_empty());
    }

    #[test]
    fn test_load_sbom_explicit_cyclonedx_xml() {
        let path = "../../tests/fixtures/golden-old.cdx.xml";
        let sbom = load_sbom(path, Format::CyclonedxXml).unwrap();
        assert!(!sbom.components.is_empty());
    }

    #[test]
    fn test_load_sbom_explicit_cyclonedx_json() {
        let path = "../../tests/fixtures/old.json";
        let sbom = load_sbom(path, Format::Cyclonedx).unwrap();
        assert!(!sbom.components.is_empty());
    }

    #[test]
    fn test_load_sbom_explicit_spdx() {
        let path = "../../tests/fixtures/old.spdx.json";
        let sbom = load_sbom(path, Format::Spdx).unwrap();
        assert!(!sbom.components.is_empty());
    }

    #[test]
    fn test_load_sbom_explicit_spdx_tv() {
        let path = "../../tests/fixtures/old.spdx";
        let sbom = load_sbom(path, Format::SpdxTv).unwrap();
        assert!(!sbom.components.is_empty());
    }

    #[test]
    fn test_load_sbom_auto_spdx_tv() {
        let path = "../../tests/fixtures/old.spdx";
        let sbom = load_sbom(path, Format::Auto).unwrap();
        assert!(!sbom.components.is_empty());
    }

    #[test]
    fn test_load_sbom_auto_detection_failure() {
        // A file that isn't valid in any format should fail
        let result = load_sbom("Cargo.toml", Format::Auto);
        assert!(result.is_err());
    }

    #[test]
    fn test_render_summary() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![
                Component::new("a".into(), Some("1".into())),
                Component::new("b".into(), Some("1".into())),
            ],
            removed: vec![Component::new("c".into(), Some("1".into()))],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let mut buf = Vec::new();
        TextRenderer
            .render_summary(&diff, &RenderOptions::default(), &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("Added:            2"));
        assert!(out.contains("Removed:          1"));
        assert!(out.contains("Changed:          0"));
        assert!(out.contains("Edge changes:     0"));
    }

    #[test]
    fn test_render_summary_with_edge_diffs() {
        use sbom_diff::{Diff, EdgeDiff};
        use sbom_model::{ComponentId, DependencyKind};
        use std::collections::BTreeMap;

        let diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![
                EdgeDiff {
                    parent: ComponentId::new(None, &[("name", "pkg-a")]),
                    added: BTreeMap::from([(
                        ComponentId::new(None, &[("name", "pkg-b")]),
                        DependencyKind::Runtime,
                    )]),
                    removed: BTreeMap::new(),
                    kind_changed: BTreeMap::new(),
                },
                EdgeDiff {
                    parent: ComponentId::new(None, &[("name", "pkg-c")]),
                    added: BTreeMap::new(),
                    removed: BTreeMap::from([(
                        ComponentId::new(None, &[("name", "pkg-d")]),
                        DependencyKind::Runtime,
                    )]),
                    kind_changed: BTreeMap::new(),
                },
            ],
            ..Diff::default()
        };

        let mut buf = Vec::new();
        TextRenderer
            .render_summary(&diff, &RenderOptions::default(), &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("Edge changes:     2"));
    }

    #[test]
    fn test_check_fail_on_deps_with_removed_edges() {
        use sbom_diff::{Diff, EdgeDiff};
        use sbom_model::{ComponentId, DependencyKind};
        use std::collections::BTreeMap;

        let diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![EdgeDiff {
                parent: ComponentId::new(None, &[("name", "parent")]),
                added: BTreeMap::new(),
                removed: BTreeMap::from([(
                    ComponentId::new(None, &[("name", "child")]),
                    DependencyKind::Runtime,
                )]),
                kind_changed: BTreeMap::new(),
            }],
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::Deps]));
    }

    #[test]
    fn test_check_fail_on_multiple_conditions() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![Component::new("new".into(), Some("1".into()))],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        // Both conditions checked
        assert!(check_fail_on(
            &diff,
            &[FailOn::AddedComponents, FailOn::MissingHashes]
        ));
    }

    #[test]
    fn test_check_licenses_empty_lists() {
        let sbom = Sbom::default();
        // No components, no violations
        assert!(!check_licenses(&sbom, &[], &[]));
    }

    #[test]
    fn test_check_licenses_unlicensed_component_with_allowlist() {
        let mut sbom = Sbom::default();
        // Component with no license information
        let c = Component::new("unlicensed-pkg".into(), Some("1.0".into()));
        // licenses is empty by default
        sbom.components.insert(c.id.clone(), c);

        // No allow-list: unlicensed component is not a violation
        assert!(!check_licenses(&sbom, &[], &[]));

        // With allow-list: unlicensed component cannot satisfy it → violation
        assert!(check_licenses(&sbom, &[], &["MIT".into()]));

        // With deny-list only: unlicensed component is not a violation (nothing to deny)
        assert!(!check_licenses(&sbom, &["GPL-3.0-only".into()], &[]));
    }

    #[test]
    fn test_check_licenses_case_insensitive() {
        let mut sbom = Sbom::default();
        let mut c = Component::new("a".into(), Some("1".into()));
        c.licenses.insert("GPL-3.0-only".into());
        sbom.components.insert(c.id.clone(), c);

        // Deny: different casing still matches
        assert!(check_licenses(&sbom, &["gpl-3.0-only".into()], &[]));
        assert!(check_licenses(&sbom, &["Gpl-3.0-Only".into()], &[]));

        // Allow: different casing is still accepted
        assert!(!check_licenses(&sbom, &[], &["gpl-3.0-only".into()]));
        assert!(!check_licenses(&sbom, &[], &["GPL-3.0-ONLY".into()]));

        // Allow: wrong license is still rejected regardless of case
        assert!(check_licenses(&sbom, &[], &["mit".into()]));
    }

    #[test]
    fn test_check_fail_on_added_components() {
        use sbom_diff::Diff;

        let mut diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        // No added components - no violation
        assert!(!check_fail_on(&diff, &[FailOn::AddedComponents]));

        // With added component - violation
        diff.added
            .push(Component::new("new-pkg".into(), Some("1.0".into())));
        assert!(check_fail_on(&diff, &[FailOn::AddedComponents]));
    }

    #[test]
    fn test_check_fail_on_missing_hashes() {
        use sbom_diff::Diff;

        let mut diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        // No added components - no violation
        assert!(!check_fail_on(&diff, &[FailOn::MissingHashes]));

        // Added component without hashes - violation
        diff.added
            .push(Component::new("new-pkg".into(), Some("1.0".into())));
        assert!(check_fail_on(&diff, &[FailOn::MissingHashes]));

        // Added component with hashes - no violation
        diff.added[0].hashes.insert("sha256".into(), "abc".into());
        assert!(!check_fail_on(&diff, &[FailOn::MissingHashes]));
    }

    #[test]
    fn test_check_fail_on_missing_hashes_changed_component_dropped() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};
        use std::collections::BTreeMap;

        let mut old = Component::new("pkg".into(), Some("1.0".into()));
        old.hashes.insert("sha256".into(), "abc".into());
        let new = Component::new("pkg".into(), Some("1.1".into()));
        // new has no hashes — regression

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![
                    FieldChange::Version(Some("1.0".into()), Some("1.1".into())),
                    FieldChange::Hashes(old.hashes.clone(), BTreeMap::new()),
                ],
            }],
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::MissingHashes]));
    }

    #[test]
    fn test_check_fail_on_missing_hashes_changed_component_kept() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let mut old = Component::new("pkg".into(), Some("1.0".into()));
        old.hashes.insert("sha256".into(), "abc".into());
        let mut new = Component::new("pkg".into(), Some("1.1".into()));
        new.hashes.insert("sha256".into(), "def".into());
        // new still has hashes — not a regression

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![
                    FieldChange::Version(Some("1.0".into()), Some("1.1".into())),
                    FieldChange::Hashes(old.hashes.clone(), new.hashes.clone()),
                ],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::MissingHashes]));
    }

    #[test]
    fn test_check_fail_on_missing_hashes_changed_component_both_empty() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let old = Component::new("pkg".into(), Some("1.0".into()));
        let new = Component::new("pkg".into(), Some("1.1".into()));
        // both have no hashes — not a regression, was already missing

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Version(Some("1.0".into()), Some("1.1".into()))],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::MissingHashes]));
    }

    #[test]
    fn test_check_fail_on_deps() {
        use sbom_diff::{Diff, EdgeDiff};
        use sbom_model::{ComponentId, DependencyKind};
        use std::collections::BTreeMap;

        let mut diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        // No edge changes - no violation
        assert!(!check_fail_on(&diff, &[FailOn::Deps]));

        // With edge changes - violation
        diff.edge_diffs.push(EdgeDiff {
            parent: ComponentId::new(None, &[("name", "parent")]),
            added: BTreeMap::from([(
                ComponentId::new(None, &[("name", "child")]),
                DependencyKind::Runtime,
            )]),
            removed: BTreeMap::new(),
            kind_changed: BTreeMap::new(),
        });
        assert!(check_fail_on(&diff, &[FailOn::Deps]));
    }

    #[test]
    fn test_check_fail_on_removed_components() {
        use sbom_diff::Diff;

        let mut diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        // No removed components - no violation
        assert!(!check_fail_on(&diff, &[FailOn::RemovedComponents]));

        // With removed component - violation
        diff.removed
            .push(Component::new("old-pkg".into(), Some("1.0".into())));
        assert!(check_fail_on(&diff, &[FailOn::RemovedComponents]));
    }

    #[test]
    fn test_check_fail_on_changed_components() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let mut diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        // No changed components - no violation
        assert!(!check_fail_on(&diff, &[FailOn::ChangedComponents]));

        // With changed component - violation
        let old = Component::new("pkg".into(), Some("1.0".into()));
        let new = Component::new("pkg".into(), Some("2.0".into()));
        diff.changed.push(ComponentChange {
            id: old.id.clone(),
            old: old.clone(),
            new,
            changes: vec![FieldChange::Version(Some("1.0".into()), Some("2.0".into()))],
        });
        assert!(check_fail_on(&diff, &[FailOn::ChangedComponents]));
    }

    #[test]
    fn test_description_only_changes_do_not_trigger_gates() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let old = Component::new("pkg".into(), Some("1.0".into()));
        let mut new = old.clone();
        new.description = Some("updated description".into());

        let diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old,
                new,
                changes: vec![FieldChange::Description(
                    None,
                    Some("updated description".into()),
                )],
            }],
            edge_diffs: vec![],
            ..Diff::default()
        };

        assert!(!check_fail_on(
            &diff,
            &[
                FailOn::AddedComponents,
                FailOn::RemovedComponents,
                FailOn::MissingHashes,
                FailOn::Deps,
                FailOn::LicenseChanged,
            ]
        ));
        // But ChangedComponents *should* trigger on description changes
        assert!(check_fail_on(&diff, &[FailOn::ChangedComponents]));
    }

    #[test]
    fn test_render_summary_markdown() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![
                Component::new("a".into(), Some("1".into())),
                Component::new("b".into(), Some("1".into())),
            ],
            removed: vec![Component::new("c".into(), Some("1".into()))],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let mut buf = Vec::new();
        MarkdownRenderer
            .render_summary(&diff, &RenderOptions::default(), &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("### SBOM Diff Summary"));
        assert!(out.contains("| Metric | Count |"));
        assert!(out.contains("| Old total | 0 |"));
        assert!(out.contains("| New total | 0 |"));
        assert!(out.contains("| Unchanged | 0 |"));
        assert!(out.contains("| Added | 2 |"));
        assert!(out.contains("| Removed | 1 |"));
        assert!(out.contains("| Changed | 0 |"));
        assert!(out.contains("| Edge changes | 0 |"));
        // Should NOT contain component details
        assert!(!out.contains("<details>"));
    }

    #[test]
    fn test_render_summary_markdown_with_ecosystems() {
        use sbom_diff::Diff;

        let mut added_npm = Component::new("express".into(), Some("4.18.0".into()));
        added_npm.ecosystem = Some("npm".into());
        let mut added_cargo = Component::new("serde".into(), Some("1.0.0".into()));
        added_cargo.ecosystem = Some("cargo".into());
        let mut removed = Component::new("lodash".into(), Some("4.17.21".into()));
        removed.ecosystem = Some("npm".into());

        let diff = Diff {
            added: vec![added_npm, added_cargo],
            removed: vec![removed],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let opts = RenderOptions {
            group_by_ecosystem: true,
            ..Default::default()
        };

        let mut buf = Vec::new();
        MarkdownRenderer
            .render_summary(&diff, &opts, &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("#### By Ecosystem"));
        assert!(out.contains("| Ecosystem | Added | Removed | Changed |"));
        assert!(out.contains("| cargo | 1 | 0 | 0 |"));
        assert!(out.contains("| npm | 1 | 1 | 0 |"));
    }

    #[test]
    fn test_render_summary_markdown_empty() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let mut buf = Vec::new();
        MarkdownRenderer
            .render_summary(&diff, &RenderOptions::default(), &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("| Added | 0 |"));
        assert!(out.contains("| Removed | 0 |"));
        assert!(out.contains("| Changed | 0 |"));
        assert!(out.contains("| Edge changes | 0 |"));
    }

    #[test]
    fn test_render_summary_json() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![
                Component::new("a".into(), Some("1".into())),
                Component::new("b".into(), Some("1".into())),
            ],
            removed: vec![Component::new("c".into(), Some("1".into()))],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let mut buf = Vec::new();
        JsonRenderer
            .render_summary(&diff, &RenderOptions::default(), &mut buf)
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

        assert_eq!(val["added"], 2);
        assert_eq!(val["removed"], 1);
        assert_eq!(val["changed"], 0);
        assert_eq!(val["edge_changes"], 0);
        assert!(val.get("ecosystem_breakdown").is_none());
    }

    #[test]
    fn test_render_summary_json_with_ecosystems() {
        use sbom_diff::Diff;

        let mut added_npm = Component::new("express".into(), Some("4.18.0".into()));
        added_npm.ecosystem = Some("npm".into());

        let diff = Diff {
            added: vec![added_npm],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let opts = RenderOptions {
            group_by_ecosystem: true,
            ..Default::default()
        };

        let mut buf = Vec::new();
        JsonRenderer.render_summary(&diff, &opts, &mut buf).unwrap();
        let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

        assert_eq!(val["added"], 1);
        let breakdown = &val["ecosystem_breakdown"];
        assert!(breakdown.is_object());
        assert_eq!(breakdown["npm"]["added"], 1);
    }

    #[test]
    fn test_render_summary_text_with_warnings() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![Component::new("a".into(), Some("1".into()))],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let opts = RenderOptions {
            show_warnings: true,
            old_warnings: vec!["old sbom missing supplier".into()],
            new_warnings: vec!["new sbom missing license".into()],
            ..Default::default()
        };

        let mut buf = Vec::new();
        TextRenderer.render_summary(&diff, &opts, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("Warnings:     2"));
        assert!(out.contains("[old] old sbom missing supplier"));
        assert!(out.contains("[new] new sbom missing license"));
        assert!(out.contains("Added:            1"));
    }

    #[test]
    fn test_render_summary_markdown_with_warnings() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![Component::new("a".into(), Some("1".into()))],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let opts = RenderOptions {
            show_warnings: true,
            old_warnings: vec!["old sbom missing supplier".into()],
            new_warnings: vec!["new sbom missing license".into()],
            ..Default::default()
        };

        let mut buf = Vec::new();
        MarkdownRenderer
            .render_summary(&diff, &opts, &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(out.contains("<details><summary><b>Warnings (2)</b></summary>"));
        assert!(out.contains("- **old:** old sbom missing supplier"));
        assert!(out.contains("- **new:** new sbom missing license"));
        assert!(out.contains("</details>"));
        assert!(out.contains("### SBOM Diff Summary"));
        assert!(out.contains("| Added | 1 |"));
    }

    #[test]
    fn test_render_summary_markdown_no_warnings_without_flag() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let opts = RenderOptions {
            show_warnings: false,
            old_warnings: vec!["some warning".into()],
            ..Default::default()
        };

        let mut buf = Vec::new();
        MarkdownRenderer
            .render_summary(&diff, &opts, &mut buf)
            .unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(!out.contains("Warnings"));
        assert!(!out.contains("<details>"));
    }

    #[test]
    fn test_render_summary_json_with_warnings() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![Component::new("a".into(), Some("1".into()))],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let opts = RenderOptions {
            show_warnings: true,
            old_warnings: vec!["old sbom missing supplier".into()],
            new_warnings: vec!["new sbom missing license".into()],
            ..Default::default()
        };

        let mut buf = Vec::new();
        JsonRenderer.render_summary(&diff, &opts, &mut buf).unwrap();
        let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

        assert_eq!(val["added"], 1);
        let warnings = &val["warnings"];
        assert!(warnings.is_object());
        assert_eq!(warnings["old"][0], "old sbom missing supplier");
        assert_eq!(warnings["new"][0], "new sbom missing license");
    }

    #[test]
    fn test_render_summary_json_no_warnings_without_flag() {
        use sbom_diff::Diff;

        let diff = Diff {
            added: vec![],
            removed: vec![],
            changed: vec![],
            edge_diffs: vec![],
            ..Diff::default()
        };

        let opts = RenderOptions {
            show_warnings: false,
            old_warnings: vec!["some warning".into()],
            ..Default::default()
        };

        let mut buf = Vec::new();
        JsonRenderer.render_summary(&diff, &opts, &mut buf).unwrap();
        let val: serde_json::Value = serde_json::from_slice(&buf).unwrap();

        assert!(val.get("warnings").is_none());
    }

    #[test]
    fn test_check_fail_on_license_changed_on_changed_component() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};
        use std::collections::BTreeSet;

        let mut old = Component::new("pkg".into(), Some("1.0".into()));
        old.licenses.insert("MIT".into());
        let mut new = Component::new("pkg".into(), Some("1.0".into()));
        new.licenses.insert("GPL-3.0-only".into());

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::License(
                    BTreeSet::from(["MIT".into()]),
                    BTreeSet::from(["GPL-3.0-only".into()]),
                )],
            }],
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::LicenseChanged]));
    }

    #[test]
    fn test_check_fail_on_license_changed_no_license_change() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let old = Component::new("pkg".into(), Some("1.0".into()));
        let new = Component::new("pkg".into(), Some("2.0".into()));

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old,
                new,
                changes: vec![FieldChange::Version(Some("1.0".into()), Some("2.0".into()))],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::LicenseChanged]));
    }

    #[test]
    fn test_check_fail_on_license_changed_added_component_with_license() {
        use sbom_diff::Diff;

        let mut added = Component::new("new-pkg".into(), Some("1.0".into()));
        added.licenses.insert("AGPL-3.0-only".into());

        let diff = Diff {
            added: vec![added],
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::LicenseChanged]));
    }

    #[test]
    fn test_check_fail_on_license_changed_added_component_without_license() {
        use sbom_diff::Diff;

        let added = Component::new("new-pkg".into(), Some("1.0".into()));

        let diff = Diff {
            added: vec![added],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::LicenseChanged]));
    }

    #[test]
    fn test_check_fail_on_license_changed_empty_diff() {
        use sbom_diff::Diff;

        let diff = Diff::default();
        assert!(!check_fail_on(&diff, &[FailOn::LicenseChanged]));
    }

    #[test]
    fn test_check_fail_on_license_changed_license_dropped() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};
        use std::collections::BTreeSet;

        let mut old = Component::new("pkg".into(), Some("1.0".into()));
        old.licenses.insert("MIT".into());
        let new = Component::new("pkg".into(), Some("1.0".into()));

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::License(
                    BTreeSet::from(["MIT".into()]),
                    BTreeSet::new(),
                )],
            }],
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::LicenseChanged]));
    }

    #[test]
    fn test_check_fail_on_license_changed_combined_with_other_conditions() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};
        use std::collections::BTreeSet;

        let mut old = Component::new("pkg".into(), Some("1.0".into()));
        old.licenses.insert("MIT".into());
        let mut new = Component::new("pkg".into(), Some("1.0".into()));
        new.licenses.insert("GPL-3.0-only".into());

        let diff = Diff {
            added: vec![Component::new("new-pkg".into(), Some("1.0".into()))],
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::License(
                    BTreeSet::from(["MIT".into()]),
                    BTreeSet::from(["GPL-3.0-only".into()]),
                )],
            }],
            ..Diff::default()
        };

        // Both conditions should be checked
        assert!(check_fail_on(
            &diff,
            &[FailOn::AddedComponents, FailOn::LicenseChanged]
        ));
        // LicenseChanged alone should fire (changed license)
        assert!(check_fail_on(&diff, &[FailOn::LicenseChanged]));
        // AddedComponents alone should fire (new-pkg)
        assert!(check_fail_on(&diff, &[FailOn::AddedComponents]));
    }

    #[test]
    fn test_check_fail_on_metadata_changed() {
        use sbom_diff::{Diff, MetadataChange};

        let diff = Diff {
            metadata_changed: Some(MetadataChange {
                timestamp: Some((Some("2024-01-01".into()), Some("2024-01-02".into()))),
                tools: None,
                authors: None,
            }),
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::MetadataChanged]));
    }

    #[test]
    fn test_check_fail_on_metadata_changed_no_change() {
        use sbom_diff::Diff;

        let diff = Diff::default();
        assert!(!check_fail_on(&diff, &[FailOn::MetadataChanged]));
    }

    #[test]
    fn test_check_fail_on_metadata_changed_tools_only() {
        use sbom_diff::{Diff, MetadataChange};

        let diff = Diff {
            metadata_changed: Some(MetadataChange {
                timestamp: None,
                tools: Some((vec!["syft".into()], vec!["trivy".into()])),
                authors: None,
            }),
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::MetadataChanged]));
    }

    #[test]
    fn test_check_fail_on_metadata_changed_does_not_trigger_other_gates() {
        use sbom_diff::{Diff, MetadataChange};

        let diff = Diff {
            metadata_changed: Some(MetadataChange {
                timestamp: Some((Some("2024-01-01".into()), Some("2024-01-02".into()))),
                tools: Some((vec!["syft".into()], vec!["trivy".into()])),
                authors: Some((vec!["alice".into()], vec!["bob".into()])),
            }),
            ..Diff::default()
        };

        // Only MetadataChanged should trigger, not other gates
        assert!(!check_fail_on(&diff, &[FailOn::AddedComponents]));
        assert!(!check_fail_on(&diff, &[FailOn::RemovedComponents]));
        assert!(!check_fail_on(&diff, &[FailOn::ChangedComponents]));
        assert!(!check_fail_on(&diff, &[FailOn::Deps]));
        assert!(!check_fail_on(&diff, &[FailOn::LicenseChanged]));
        assert!(!check_fail_on(&diff, &[FailOn::MissingHashes]));
        assert!(check_fail_on(&diff, &[FailOn::MetadataChanged]));
    }

    #[test]
    fn test_check_fail_on_metadata_changed_combined() {
        use sbom_diff::{Diff, MetadataChange};

        let diff = Diff {
            added: vec![Component::new("new-pkg".into(), Some("1.0".into()))],
            metadata_changed: Some(MetadataChange {
                timestamp: Some((Some("2024-01-01".into()), Some("2024-01-02".into()))),
                tools: None,
                authors: None,
            }),
            ..Diff::default()
        };

        // Both should fire
        assert!(check_fail_on(
            &diff,
            &[FailOn::AddedComponents, FailOn::MetadataChanged]
        ));
    }

    // -----------------------------------------------------------------------
    // --fail-on version-downgrade
    // -----------------------------------------------------------------------

    #[test]
    fn test_check_fail_on_version_downgrade() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let old = Component::new("pkg".into(), Some("2.0.0".into()));
        let new = Component::new("pkg".into(), Some("1.5.0".into()));

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Version(
                    Some("2.0.0".into()),
                    Some("1.5.0".into()),
                )],
            }],
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::VersionDowngrade]));
    }

    #[test]
    fn test_check_fail_on_version_downgrade_upgrade_no_violation() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let old = Component::new("pkg".into(), Some("1.0.0".into()));
        let new = Component::new("pkg".into(), Some("2.0.0".into()));

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Version(
                    Some("1.0.0".into()),
                    Some("2.0.0".into()),
                )],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::VersionDowngrade]));
    }

    #[test]
    fn test_check_fail_on_version_downgrade_empty_diff() {
        use sbom_diff::Diff;

        let diff = Diff::default();
        assert!(!check_fail_on(&diff, &[FailOn::VersionDowngrade]));
    }

    #[test]
    fn test_check_fail_on_version_downgrade_no_version_change() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        // Only license changed, no version change
        let old = Component::new("pkg".into(), Some("1.0.0".into()));
        let new = Component::new("pkg".into(), Some("1.0.0".into()));

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Supplier(
                    Some("Old Corp".into()),
                    Some("New Corp".into()),
                )],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::VersionDowngrade]));
    }

    #[test]
    fn test_check_fail_on_version_downgrade_version_added() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        // Version went from None to Some — not a downgrade
        let old = Component::new("pkg".into(), None);
        let new = Component::new("pkg".into(), Some("1.0.0".into()));

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old,
                new,
                changes: vec![FieldChange::Version(None, Some("1.0.0".into()))],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::VersionDowngrade]));
    }

    #[test]
    fn test_check_fail_on_version_downgrade_does_not_trigger_other_gates() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let old = Component::new("pkg".into(), Some("2.0.0".into()));
        let new = Component::new("pkg".into(), Some("1.0.0".into()));

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Version(
                    Some("2.0.0".into()),
                    Some("1.0.0".into()),
                )],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::AddedComponents]));
        assert!(!check_fail_on(&diff, &[FailOn::RemovedComponents]));
        assert!(!check_fail_on(&diff, &[FailOn::MissingHashes]));
        assert!(!check_fail_on(&diff, &[FailOn::Deps]));
        assert!(!check_fail_on(&diff, &[FailOn::LicenseChanged]));
        assert!(!check_fail_on(&diff, &[FailOn::MetadataChanged]));
        // ChangedComponents should still fire
        assert!(check_fail_on(&diff, &[FailOn::ChangedComponents]));
        // VersionDowngrade should fire
        assert!(check_fail_on(&diff, &[FailOn::VersionDowngrade]));
    }

    // -----------------------------------------------------------------------
    // --fail-on supplier-changed
    // -----------------------------------------------------------------------

    #[test]
    fn test_check_fail_on_supplier_changed() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let mut old = Component::new("pkg".into(), Some("1.0.0".into()));
        old.supplier = Some("Acme Corp".into());
        let mut new = Component::new("pkg".into(), Some("1.0.0".into()));
        new.supplier = Some("Evil Corp".into());

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Supplier(
                    Some("Acme Corp".into()),
                    Some("Evil Corp".into()),
                )],
            }],
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::SupplierChanged]));
    }

    #[test]
    fn test_check_fail_on_supplier_changed_no_change() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let old = Component::new("pkg".into(), Some("1.0.0".into()));
        let new = Component::new("pkg".into(), Some("2.0.0".into()));

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old,
                new,
                changes: vec![FieldChange::Version(
                    Some("1.0.0".into()),
                    Some("2.0.0".into()),
                )],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::SupplierChanged]));
    }

    #[test]
    fn test_check_fail_on_supplier_changed_empty_diff() {
        use sbom_diff::Diff;

        let diff = Diff::default();
        assert!(!check_fail_on(&diff, &[FailOn::SupplierChanged]));
    }

    #[test]
    fn test_check_fail_on_supplier_changed_supplier_added() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let old = Component::new("pkg".into(), Some("1.0.0".into()));
        let mut new = Component::new("pkg".into(), Some("1.0.0".into()));
        new.supplier = Some("New Corp".into());

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Supplier(None, Some("New Corp".into()))],
            }],
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::SupplierChanged]));
    }

    #[test]
    fn test_check_fail_on_supplier_changed_supplier_removed() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let mut old = Component::new("pkg".into(), Some("1.0.0".into()));
        old.supplier = Some("Old Corp".into());
        let new = Component::new("pkg".into(), Some("1.0.0".into()));

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Supplier(Some("Old Corp".into()), None)],
            }],
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::SupplierChanged]));
    }

    #[test]
    fn test_check_fail_on_supplier_changed_added_component_with_supplier() {
        use sbom_diff::Diff;

        let mut added = Component::new("new-pkg".into(), Some("1.0.0".into()));
        added.supplier = Some("Some Corp".into());

        let diff = Diff {
            added: vec![added],
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::SupplierChanged]));
    }

    #[test]
    fn test_check_fail_on_supplier_changed_added_component_without_supplier() {
        use sbom_diff::Diff;

        let added = Component::new("new-pkg".into(), Some("1.0.0".into()));

        let diff = Diff {
            added: vec![added],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::SupplierChanged]));
    }

    #[test]
    fn test_check_fail_on_supplier_changed_does_not_trigger_other_gates() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let mut old = Component::new("pkg".into(), Some("1.0.0".into()));
        old.supplier = Some("Acme Corp".into());
        let mut new = Component::new("pkg".into(), Some("1.0.0".into()));
        new.supplier = Some("Evil Corp".into());

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Supplier(
                    Some("Acme Corp".into()),
                    Some("Evil Corp".into()),
                )],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::AddedComponents]));
        assert!(!check_fail_on(&diff, &[FailOn::RemovedComponents]));
        assert!(!check_fail_on(&diff, &[FailOn::MissingHashes]));
        assert!(!check_fail_on(&diff, &[FailOn::Deps]));
        assert!(!check_fail_on(&diff, &[FailOn::LicenseChanged]));
        assert!(!check_fail_on(&diff, &[FailOn::MetadataChanged]));
        assert!(!check_fail_on(&diff, &[FailOn::VersionDowngrade]));
        // ChangedComponents should still fire
        assert!(check_fail_on(&diff, &[FailOn::ChangedComponents]));
        // SupplierChanged should fire
        assert!(check_fail_on(&diff, &[FailOn::SupplierChanged]));
    }

    // -----------------------------------------------------------------------
    // --fail-on hash-algorithm-downgrade
    // -----------------------------------------------------------------------

    #[test]
    fn test_check_fail_on_hash_algorithm_downgrade() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let mut old = Component::new("pkg".into(), Some("1.0.0".into()));
        old.hashes.insert("sha-256".into(), "abc".into());
        let mut new = Component::new("pkg".into(), Some("1.0.0".into()));
        new.hashes.insert("md5".into(), "def".into());

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Hashes(old.hashes.clone(), new.hashes.clone())],
            }],
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::HashAlgorithmDowngrade]));
    }

    #[test]
    fn test_check_fail_on_hash_algorithm_downgrade_upgrade_no_violation() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let mut old = Component::new("pkg".into(), Some("1.0.0".into()));
        old.hashes.insert("sha-1".into(), "abc".into());
        let mut new = Component::new("pkg".into(), Some("1.0.0".into()));
        new.hashes.insert("sha-256".into(), "def".into());

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Hashes(old.hashes.clone(), new.hashes.clone())],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::HashAlgorithmDowngrade]));
    }

    #[test]
    fn test_check_fail_on_hash_algorithm_downgrade_same_algorithm() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let mut old = Component::new("pkg".into(), Some("1.0.0".into()));
        old.hashes.insert("sha-256".into(), "abc".into());
        let mut new = Component::new("pkg".into(), Some("1.0.0".into()));
        new.hashes.insert("sha-256".into(), "def".into());

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Hashes(old.hashes.clone(), new.hashes.clone())],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::HashAlgorithmDowngrade]));
    }

    #[test]
    fn test_check_fail_on_hash_algorithm_downgrade_empty_diff() {
        use sbom_diff::Diff;

        let diff = Diff::default();
        assert!(!check_fail_on(&diff, &[FailOn::HashAlgorithmDowngrade]));
    }

    #[test]
    fn test_check_fail_on_hash_algorithm_downgrade_no_hash_change() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        // Only version changed, no hash change
        let old = Component::new("pkg".into(), Some("1.0.0".into()));
        let new = Component::new("pkg".into(), Some("2.0.0".into()));

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old,
                new,
                changes: vec![FieldChange::Version(
                    Some("1.0.0".into()),
                    Some("2.0.0".into()),
                )],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::HashAlgorithmDowngrade]));
    }

    #[test]
    fn test_check_fail_on_hash_algorithm_downgrade_dropped_strongest() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        // Old has SHA-256 + MD5, new has only MD5
        let mut old = Component::new("pkg".into(), Some("1.0.0".into()));
        old.hashes.insert("sha-256".into(), "abc".into());
        old.hashes.insert("md5".into(), "xyz".into());
        let mut new = Component::new("pkg".into(), Some("1.0.0".into()));
        new.hashes.insert("md5".into(), "def".into());

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Hashes(old.hashes.clone(), new.hashes.clone())],
            }],
            ..Diff::default()
        };

        assert!(check_fail_on(&diff, &[FailOn::HashAlgorithmDowngrade]));
    }

    #[test]
    fn test_check_fail_on_hash_algorithm_downgrade_hashes_dropped_entirely() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};
        use std::collections::BTreeMap;

        // Old has SHA-256, new has no hashes — should NOT trigger
        // (missing-hashes gate handles this)
        let mut old = Component::new("pkg".into(), Some("1.0.0".into()));
        old.hashes.insert("sha-256".into(), "abc".into());
        let new = Component::new("pkg".into(), Some("1.0.0".into()));

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Hashes(old.hashes.clone(), BTreeMap::new())],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::HashAlgorithmDowngrade]));
    }

    #[test]
    fn test_check_fail_on_hash_algorithm_downgrade_does_not_trigger_other_gates() {
        use sbom_diff::{ComponentChange, Diff, FieldChange};

        let mut old = Component::new("pkg".into(), Some("1.0.0".into()));
        old.hashes.insert("sha-256".into(), "abc".into());
        let mut new = Component::new("pkg".into(), Some("1.0.0".into()));
        new.hashes.insert("md5".into(), "def".into());

        let diff = Diff {
            changed: vec![ComponentChange {
                id: old.id.clone(),
                old: old.clone(),
                new: new.clone(),
                changes: vec![FieldChange::Hashes(old.hashes.clone(), new.hashes.clone())],
            }],
            ..Diff::default()
        };

        assert!(!check_fail_on(&diff, &[FailOn::AddedComponents]));
        assert!(!check_fail_on(&diff, &[FailOn::RemovedComponents]));
        assert!(!check_fail_on(&diff, &[FailOn::MissingHashes]));
        assert!(!check_fail_on(&diff, &[FailOn::Deps]));
        assert!(!check_fail_on(&diff, &[FailOn::LicenseChanged]));
        assert!(!check_fail_on(&diff, &[FailOn::MetadataChanged]));
        assert!(!check_fail_on(&diff, &[FailOn::VersionDowngrade]));
        assert!(!check_fail_on(&diff, &[FailOn::SupplierChanged]));
        // ChangedComponents should still fire
        assert!(check_fail_on(&diff, &[FailOn::ChangedComponents]));
        // HashAlgorithmDowngrade should fire
        assert!(check_fail_on(&diff, &[FailOn::HashAlgorithmDowngrade]));
    }

    // -----------------------------------------------------------------------
    // detect_format heuristics
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_cyclonedx_json() {
        let input = br#"{"bomFormat": "CycloneDX", "specVersion": "1.4"}"#;
        assert_eq!(detect_format(input), DetectedFormat::CyclonedxJson);
    }

    #[test]
    fn test_detect_cyclonedx_json_with_whitespace() {
        let input = b"  \n  { \"bomFormat\" : \"CycloneDX\" }";
        assert_eq!(detect_format(input), DetectedFormat::CyclonedxJson);
    }

    #[test]
    fn test_detect_cyclonedx_xml() {
        let input = br#"<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.4">"#;
        assert_eq!(detect_format(input), DetectedFormat::CyclonedxXml);
    }

    #[test]
    fn test_detect_cyclonedx_xml_with_bom() {
        let mut input = vec![0xef, 0xbb, 0xbf]; // UTF-8 BOM
        input.extend_from_slice(
            br#"<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.5">"#,
        );
        assert_eq!(detect_format(&input), DetectedFormat::CyclonedxXml);
    }

    #[test]
    fn test_detect_spdx_json() {
        let input = br#"{"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0"}"#;
        assert_eq!(detect_format(input), DetectedFormat::SpdxJson);
    }

    #[test]
    fn test_detect_spdx_tag_value() {
        let input = b"SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\n";
        assert_eq!(detect_format(input), DetectedFormat::SpdxTv);
    }

    #[test]
    fn test_detect_spdx_tag_value_with_leading_comment() {
        let input = b"# generated by tool\nSPDXVersion: SPDX-2.3\n";
        assert_eq!(detect_format(input), DetectedFormat::SpdxTv);
    }

    #[test]
    fn test_detect_spdx_tag_value_with_crlf() {
        let input = b"SPDXVersion: SPDX-2.3\r\nDataLicense: CC0-1.0\r\n";
        assert_eq!(detect_format(input), DetectedFormat::SpdxTv);
    }

    #[test]
    fn test_detect_unknown_json() {
        let input = br#"{"name": "not an sbom"}"#;
        assert_eq!(detect_format(input), DetectedFormat::Unknown);
    }

    #[test]
    fn test_detect_unknown_xml() {
        let input = br#"<?xml version="1.0"?><root xmlns="http://example.com"/>"#;
        assert_eq!(detect_format(input), DetectedFormat::Unknown);
    }

    #[test]
    fn test_detect_unknown_plain_text() {
        let input = b"just some random text that is not an SBOM\n";
        assert_eq!(detect_format(input), DetectedFormat::Unknown);
    }

    #[test]
    fn test_detect_empty_input() {
        assert_eq!(detect_format(b""), DetectedFormat::Unknown);
    }

    // -----------------------------------------------------------------------
    // load_sbom edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_load_sbom_empty_file() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("sbom-diff-test-empty");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("empty.json");
        File::create(&path).unwrap().write_all(b"").unwrap();

        let result = load_sbom(path.to_str().unwrap(), Format::Auto);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("empty"), "expected 'empty' in: {err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_load_sbom_binary_file() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("sbom-diff-test-binary");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("binary.bin");
        File::create(&path)
            .unwrap()
            .write_all(&[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00])
            .unwrap();

        let result = load_sbom(path.to_str().unwrap(), Format::Auto);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("binary"), "expected 'binary' in: {err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_load_sbom_auto_error_identifies_detected_format() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("sbom-diff-test-detected");
        std::fs::create_dir_all(&dir).unwrap();
        // Has the bomFormat marker but is otherwise invalid JSON
        let path = dir.join("bad-cdx.json");
        File::create(&path)
            .unwrap()
            .write_all(br#"{"bomFormat": "CycloneDX", broken json!!!"#)
            .unwrap();

        let result = load_sbom(path.to_str().unwrap(), Format::Auto);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("CycloneDX JSON"),
            "expected format identification in: {err}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_load_sbom_auto_error_unknown_format_lists_markers() {
        // Cargo.toml doesn't have any SBOM markers
        let result = load_sbom("Cargo.toml", Format::Auto);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("bomFormat"), "expected marker hint in: {err}");
        assert!(
            err.contains("spdxVersion"),
            "expected marker hint in: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // auto-detection with real fixtures
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_format_real_cyclonedx_json() {
        let content = std::fs::read("../../tests/fixtures/old.json").unwrap();
        assert_eq!(detect_format(&content), DetectedFormat::CyclonedxJson);
    }

    #[test]
    fn test_detect_format_real_cyclonedx_xml() {
        let content = std::fs::read("../../tests/fixtures/golden-old.cdx.xml").unwrap();
        assert_eq!(detect_format(&content), DetectedFormat::CyclonedxXml);
    }

    #[test]
    fn test_detect_format_real_spdx_json() {
        let content = std::fs::read("../../tests/fixtures/old.spdx.json").unwrap();
        assert_eq!(detect_format(&content), DetectedFormat::SpdxJson);
    }

    #[test]
    fn test_detect_format_real_spdx_tv() {
        let content = std::fs::read("../../tests/fixtures/old.spdx").unwrap();
        assert_eq!(detect_format(&content), DetectedFormat::SpdxTv);
    }

    // -----------------------------------------------------------------------
    // helper function unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_strip_bom_and_whitespace() {
        assert_eq!(strip_bom_and_whitespace(b"\xef\xbb\xbf  {"), b"{");
        assert_eq!(strip_bom_and_whitespace(b"  \n<"), b"<");
        assert_eq!(strip_bom_and_whitespace(b"hello"), b"hello");
        assert_eq!(strip_bom_and_whitespace(b""), b"");
    }

    #[test]
    fn test_find_subsequence() {
        assert_eq!(find_subsequence(b"hello world", b"world"), Some(6));
        assert_eq!(find_subsequence(b"hello", b"xyz"), None);
        assert_eq!(find_subsequence(b"", b"a"), None);
        assert_eq!(find_subsequence(b"abc", b"abc"), Some(0));
    }
}
