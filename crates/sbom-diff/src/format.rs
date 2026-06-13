use anyhow::{anyhow, Context};
use clap::ValueEnum;
use sbom_model::Sbom;
use sbom_model_cyclonedx::CycloneDxReader;
use sbom_model_spdx::SpdxReader;
use std::fs::File;
use std::io::{self, Read};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum Format {
    Auto,
    Cyclonedx,
    CyclonedxXml,
    Spdx,
    SpdxTv,
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

pub fn load_sbom(path: &str, format: Format) -> anyhow::Result<Sbom> {
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

    #[test]
    fn test_load_sbom_auto_cyclonedx() {
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
        let result = load_sbom("Cargo.toml", Format::Auto);
        assert!(result.is_err());
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
        std::fs::File::create(&path)
            .unwrap()
            .write_all(b"")
            .unwrap();

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
        std::fs::File::create(&path)
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
        std::fs::File::create(&path)
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
