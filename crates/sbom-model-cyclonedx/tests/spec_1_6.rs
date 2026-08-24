//! reading CycloneDX 1.6 under 1.5 rules.

use sbom_model::Sbom;
use sbom_model_cyclonedx::{CycloneDxReader, Error};
use std::path::PathBuf;

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn take_warnings(sbom: &mut Sbom) -> Vec<String> {
    std::mem::take(&mut sbom.warnings)
}

#[test]
fn json_1_6_matches_the_same_document_downgraded_by_hand_to_1_5() {
    let mut read_1_6 =
        CycloneDxReader::read_json(fixture("cyclonedx-1.6.json").as_slice()).unwrap();
    let mut read_1_5 =
        CycloneDxReader::read_json(fixture("cyclonedx-1.6-as-1.5.json").as_slice()).unwrap();

    let warnings = take_warnings(&mut read_1_6);
    assert_eq!(take_warnings(&mut read_1_5), Vec::<String>::new());
    assert_eq!(
        warnings.len(),
        1,
        "1.6 should warn exactly once: {warnings:?}"
    );
    assert_eq!(read_1_6, read_1_5);
}

#[test]
fn xml_1_6_matches_the_same_document_downgraded_by_hand_to_1_5() {
    let mut read_1_6 = CycloneDxReader::read_xml(&fixture("cyclonedx-1.6.cdx.xml")).unwrap();
    let mut read_1_5 = CycloneDxReader::read_xml(&fixture("cyclonedx-1.6-as-1.5.cdx.xml")).unwrap();

    let warnings = take_warnings(&mut read_1_6);
    assert_eq!(take_warnings(&mut read_1_5), Vec::<String>::new());
    assert_eq!(
        warnings.len(),
        1,
        "1.6 should warn exactly once: {warnings:?}"
    );
    assert_eq!(read_1_6, read_1_5);
}

#[test]
fn json_and_xml_1_6_agree() {
    let mut json = CycloneDxReader::read_json(fixture("cyclonedx-1.6.json").as_slice()).unwrap();
    let mut xml = CycloneDxReader::read_xml(&fixture("cyclonedx-1.6.cdx.xml")).unwrap();
    take_warnings(&mut json);
    take_warnings(&mut xml);
    let json_ids: Vec<_> = json.components.keys().collect();
    let xml_ids: Vec<_> = xml.components.keys().collect();
    assert_eq!(json_ids, xml_ids);
    assert_eq!(json.dependencies, xml.dependencies);
    assert_eq!(json.metadata, xml.metadata);
}

#[test]
fn the_1_6_warning_names_the_version_and_what_is_dropped() {
    let sbom = CycloneDxReader::read_json(fixture("cyclonedx-1.6.json").as_slice()).unwrap();
    let warning = &sbom.warnings[0];
    assert!(warning.contains("1.6"), "{warning}");
    assert!(warning.contains("1.5"), "{warning}");
    for dropped in [
        "authors",
        "omniborId",
        "swhid",
        "acknowledgement",
        "declarations",
        "evidence",
    ] {
        assert!(warning.contains(dropped), "{warning} should name {dropped}");
    }
}

#[test]
fn a_1_6_component_keeps_every_field_the_diff_reads() {
    let sbom = CycloneDxReader::read_json(fixture("cyclonedx-1.6.json").as_slice()).unwrap();
    let lib_a = sbom
        .components
        .values()
        .find(|c| c.name == "lib-a")
        .expect("lib-a");

    assert_eq!(lib_a.version.as_deref(), Some("1.2.3"));
    assert_eq!(lib_a.supplier.as_deref(), Some("lib-a maintainers"));
    assert_eq!(lib_a.purl.as_deref(), Some("pkg:npm/lib-a@1.2.3"));
    assert_eq!(lib_a.description.as_deref(), Some("a library"));
    assert_eq!(lib_a.ecosystem.as_deref(), Some("npm"));
    assert!(lib_a.licenses.contains("MIT"));
    assert_eq!(
        lib_a.hashes.get("SHA-256").map(String::as_str),
        Some("0000000000000000000000000000000000000000000000000000000000000001")
    );
    assert_eq!(
        sbom.metadata.timestamp.as_deref(),
        Some("2024-04-09T00:00:00Z")
    );
    assert_eq!(sbom.metadata.authors, ["ada <ada@example.com>"]);
    assert_eq!(sbom.metadata.tools, ["cdxgen 10.4.0"]);
    assert_eq!(sbom.dependencies.len(), 2);
}

#[test]
fn the_1_6_xml_rewrite_leaves_element_text_alone() {
    let sbom = CycloneDxReader::read_xml(&fixture("cyclonedx-1.6.cdx.xml")).unwrap();
    let lib_a = sbom
        .components
        .values()
        .find(|c| c.name == "lib-a")
        .expect("lib-a");
    assert_eq!(
        lib_a.description.as_deref(),
        Some("validated against http://cyclonedx.org/schema/bom/1.6/bom-1.6.xsd")
    );
}

#[test]
fn unsupported_versions_still_error() {
    for version in ["1.7", "2.0", "0.9", "nonsense"] {
        let json = format!(
            r#"{{"bomFormat":"CycloneDX","specVersion":"{version}","version":1,"components":[]}}"#
        );
        let err = CycloneDxReader::read_json(json.as_bytes()).unwrap_err();
        assert!(
            matches!(&err, Error::UnsupportedVersion { version: v } if v == version),
            "json {version}: {err}"
        );
        assert!(err.to_string().contains("1.3–1.6"), "json {version}: {err}");

        let xml = format!(
            r#"<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/{version}" version="1"/>"#
        );
        let err = CycloneDxReader::read_xml(xml.as_bytes()).unwrap_err();
        assert!(
            matches!(&err, Error::UnsupportedVersion { version: v } if v == version),
            "xml {version}: {err}"
        );
        assert!(err.to_string().contains("1.3–1.6"), "xml {version}: {err}");
    }
}

#[test]
fn a_namespace_in_text_is_not_the_documents_version() {
    let xml = br#"<?xml version="1.0"?>
<!-- http://cyclonedx.org/schema/bom/2.0 -->
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <components>
    <component type="library" bom-ref="a">
      <name>a</name>
      <version>1.0.0</version>
      <description>see http://cyclonedx.org/schema/bom/9.9</description>
    </component>
  </components>
</bom>"#;
    let sbom = CycloneDxReader::read_xml(xml).unwrap();
    assert_eq!(sbom.components.len(), 1);
    assert_eq!(sbom.warnings, Vec::<String>::new());
}

#[test]
fn a_1_3_document_is_untouched() {
    let xml = br#"<?xml version="1.0"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.3" version="1">
  <components>
    <component type="library"><name>a</name><version>1.0.0</version></component>
  </components>
</bom>"#;
    let sbom = CycloneDxReader::read_xml(xml).unwrap();
    assert_eq!(sbom.components.len(), 1);
    assert!(
        !sbom.warnings.iter().any(|w| w.contains("read under")),
        "{:?}",
        sbom.warnings
    );
}

#[test]
fn the_1_6_spelling_of_evidence_identity_reads() {
    let json = br#"{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
 "components":[{"type":"library","name":"a","version":"1","purl":"pkg:npm/a@1",
   "evidence":{"identity":[{"field":"purl","confidence":1.0}]}}]}"#;
    let sbom = CycloneDxReader::read_json(json.as_slice()).unwrap();
    let a = sbom.components.values().next().expect("a");
    assert_eq!(a.name, "a");
    assert_eq!(a.purl.as_deref(), Some("pkg:npm/a@1"));
}

#[test]
fn evidence_is_dropped_at_every_nesting_level() {
    let evidence =
        r#""evidence":{"identity":[{"field":"purl","confidence":1.0},{"field":"name"}]}"#;
    let json = format!(
        r#"{{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
 "metadata":{{
   "tools":{{"components":[{{"type":"application","name":"cdxgen","version":"10.4.0",{evidence}}}]}},
   "component":{{"type":"application","bom-ref":"root","name":"root","version":"2",{evidence},
     "components":[{{"type":"library","bom-ref":"under-root","name":"under-root","version":"1",{evidence}}}]}}}},
 "components":[{{"type":"library","bom-ref":"outer","name":"outer","version":"1",{evidence},
   "components":[{{"type":"library","bom-ref":"middle","name":"middle","version":"1",{evidence},
     "components":[{{"type":"library","bom-ref":"inner","name":"inner","version":"1",{evidence}}}]}}]}}]}}"#
    );

    let sbom = CycloneDxReader::read_json(json.as_bytes()).unwrap();
    let mut names: Vec<_> = sbom.components.values().map(|c| c.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["inner", "middle", "outer", "root", "under-root"]);
    assert_eq!(sbom.metadata.tools, ["cdxgen 10.4.0"]);
}

#[test]
fn a_nested_1_6_component_carrying_evidence_keeps_the_fields_the_diff_reads() {
    for sbom in [
        CycloneDxReader::read_json(fixture("cyclonedx-1.6.json").as_slice()).unwrap(),
        CycloneDxReader::read_xml(&fixture("cyclonedx-1.6.cdx.xml")).unwrap(),
    ] {
        let inner = sbom
            .components
            .values()
            .find(|c| c.name == "lib-a-inner")
            .expect("lib-a-inner");
        assert_eq!(inner.version.as_deref(), Some("0.1.0"));
        assert_eq!(inner.purl.as_deref(), Some("pkg:npm/lib-a-inner@0.1.0"));
    }
}

#[test]
fn the_1_6_xml_spelling_of_evidence_identity_is_read_by_the_1_5_reader() {
    let xml = br#"<?xml version="1.0"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">
  <components>
    <component type="library" bom-ref="a">
      <name>a</name>
      <version>1.0.0</version>
      <purl>pkg:npm/a@1.0.0</purl>
      <evidence>
        <identity><field>purl</field><confidence>1.0</confidence></identity>
        <identity><field>name</field><confidence>0.5</confidence></identity>
      </evidence>
    </component>
  </components>
</bom>"#;
    let sbom = CycloneDxReader::read_xml(xml).unwrap();
    let a = sbom.components.values().next().expect("a");
    assert_eq!(a.name, "a");
    assert_eq!(a.purl.as_deref(), Some("pkg:npm/a@1.0.0"));
}

#[test]
fn a_1_6_document_that_stops_mid_element_reports_the_rewrite_failure() {
    let xml = br#"<?xml version="1.0"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">
  <components>
    <component type="library"><name>a</name>
"#;
    let err = CycloneDxReader::read_xml(xml).unwrap_err();
    assert!(
        matches!(err, Error::XmlRewrite(_)),
        "expected a rewrite failure: {err}"
    );
}

#[test]
fn an_unsupported_version_on_a_prefixed_root_is_named() {
    let xml = br#"<?xml version="1.0"?>
<cdx:bom xmlns:cdx="http://cyclonedx.org/schema/bom/1.7" version="1"/>"#;
    let err = CycloneDxReader::read_xml(xml).unwrap_err();
    assert!(
        matches!(&err, Error::UnsupportedVersion { version } if version == "1.7"),
        "{err}"
    );
}
