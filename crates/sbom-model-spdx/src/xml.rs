use crate::Error;
use serde_json::{Map, Value};
use std::io::Cursor;
use xml::reader::{EventReader, ParserConfig, XmlEvent};

/// element names the SPDX 2.3 schema types as arrays; a single occurrence
/// still becomes a one-element array.
const MULTI_VALUED: &[&str] = &[
    // document
    "annotations",
    "documentDescribes",
    "externalDocumentRefs",
    "files",
    "hasExtractedLicensingInfos",
    "packages",
    "relationships",
    "revieweds",
    "snippets",
    // creationInfo
    "creators",
    // package
    "attributionTexts",
    "checksums",
    "externalRefs",
    "hasFiles",
    "licenseInfoFromFiles",
    "packageVerificationCodeExcludedFiles",
    // file
    "fileContributors",
    "fileDependencies",
    "fileTypes",
    "licenseInfoInFiles",
    // snippet
    "licenseInfoInSnippets",
    "ranges",
    // extracted licensing info
    "crossRefs",
    "seeAlsos",
];

/// element names the schema types as booleans.
const BOOLEAN_VALUED: &[&str] = &["filesAnalyzed", "isLive", "isValid", "isWayBackLink"];

/// element names the schema types as integers.
const INTEGER_VALUED: &[&str] = &["lineNumber", "offset", "order"];

/// root element names emitted by SPDX 2.x XML producers.
const ROOT_NAMES: &[&str] = &["Document", "SpdxDocument"];

struct Frame {
    name: String,
    children: Map<String, Value>,
    text: String,
}

impl Frame {
    fn into_value(self) -> Value {
        if !self.children.is_empty() {
            return Value::Object(self.children);
        }
        let text = self.text.trim();
        if BOOLEAN_VALUED.contains(&self.name.as_str()) {
            match text {
                "true" => return Value::Bool(true),
                "false" => return Value::Bool(false),
                _ => {}
            }
        }
        if INTEGER_VALUED.contains(&self.name.as_str()) {
            if let Ok(n) = text.parse::<i64>() {
                return Value::Number(n.into());
            }
        }
        Value::String(text.to_string())
    }

    fn is_empty(&self) -> bool {
        self.children.is_empty() && self.text.trim().is_empty()
    }
}

/// converts an SPDX 2.x XML document into the JSON shape of the SPDX 2.3 schema.
pub(crate) fn xml_to_json(input: &[u8]) -> Result<Value, Error> {
    let config = ParserConfig::new()
        .cdata_to_characters(true)
        .ignore_comments(true);
    let reader = EventReader::new_with_config(Cursor::new(input), config);

    let mut stack: Vec<Frame> = Vec::new();
    let mut root: Option<(String, Value)> = None;

    for event in reader {
        match event.map_err(|e| Error::Xml(e.to_string()))? {
            XmlEvent::StartElement { name, .. } => {
                if root.is_some() && stack.is_empty() {
                    return Err(Error::Xml(format!(
                        "unexpected second root element '{}'",
                        name.local_name
                    )));
                }
                stack.push(Frame {
                    name: name.local_name,
                    children: Map::new(),
                    text: String::new(),
                });
            }
            XmlEvent::Characters(s) => {
                if let Some(frame) = stack.last_mut() {
                    frame.text.push_str(&s);
                }
            }
            XmlEvent::EndElement { .. } => {
                let Some(frame) = stack.pop() else {
                    return Err(Error::Xml("unbalanced end element".to_string()));
                };
                let multi = MULTI_VALUED.contains(&frame.name.as_str());
                // an empty <packages/> means "no packages", not one blank package.
                if multi && frame.is_empty() {
                    continue;
                }
                let name = frame.name.clone();
                let value = frame.into_value();
                match stack.last_mut() {
                    Some(parent) => insert(&mut parent.children, name, value, multi),
                    None => root = Some((name, value)),
                }
            }
            _ => {}
        }
    }

    if !stack.is_empty() {
        return Err(Error::Xml("unexpected end of input".to_string()));
    }

    let Some((name, value)) = root else {
        return Err(Error::Xml("document has no root element".to_string()));
    };
    if !ROOT_NAMES.contains(&name.as_str()) {
        return Err(Error::Xml(format!(
            "unexpected root element '{name}': expected one of {}",
            ROOT_NAMES.join(", ")
        )));
    }
    if !value.is_object() {
        return Err(Error::Xml(format!("root element '{name}' has no fields")));
    }
    Ok(value)
}

/// appends to an array when the schema types the field as one, or when a
/// sibling of the same name was already seen.
fn insert(children: &mut Map<String, Value>, name: String, value: Value, multi: bool) {
    match children.get_mut(&name) {
        Some(Value::Array(existing)) if multi => existing.push(value),
        Some(existing) => {
            let previous = existing.take();
            *existing = Value::Array(vec![previous, value]);
        }
        None if multi => {
            children.insert(name, Value::Array(vec![value]));
        }
        None => {
            children.insert(name, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn convert(xml: &str) -> Value {
        xml_to_json(xml.as_bytes()).unwrap()
    }

    #[test]
    fn test_single_occurrence_of_an_array_field_becomes_an_array() {
        let value = convert(
            "<Document><packages><name>a</name></packages><spdxVersion>SPDX-2.3</spdxVersion></Document>",
        );
        assert_eq!(value["packages"], serde_json::json!([{"name": "a"}]));
        assert_eq!(value["spdxVersion"], serde_json::json!("SPDX-2.3"));
    }

    #[test]
    fn test_repeated_occurrences_of_an_array_field_stay_in_order() {
        let value = convert(
            "<Document><creators>Tool: a</creators><creators>Person: b</creators></Document>",
        );
        assert_eq!(
            value["creators"],
            serde_json::json!(["Tool: a", "Person: b"])
        );
    }

    #[test]
    fn test_scalar_fields_stay_scalar() {
        let value = convert("<Document><name>doc</name></Document>");
        assert_eq!(value["name"], serde_json::json!("doc"));
    }

    #[test]
    fn test_repeated_non_array_siblings_are_promoted_rather_than_dropped() {
        let value = convert("<Document><name>a</name><name>b</name></Document>");
        assert_eq!(value["name"], serde_json::json!(["a", "b"]));
    }

    #[test]
    fn test_booleans_and_integers_are_typed() {
        let value = convert(
            "<Document><packages><filesAnalyzed>false</filesAnalyzed></packages><offset>12</offset></Document>",
        );
        assert_eq!(
            value["packages"][0]["filesAnalyzed"],
            serde_json::json!(false)
        );
        assert_eq!(value["offset"], serde_json::json!(12));
    }

    #[test]
    fn test_non_boolean_text_in_a_boolean_field_stays_a_string() {
        let value =
            convert("<Document><packages><filesAnalyzed>yes</filesAnalyzed></packages></Document>");
        assert_eq!(
            value["packages"][0]["filesAnalyzed"],
            serde_json::json!("yes")
        );
    }

    #[test]
    fn test_empty_array_elements_are_dropped() {
        let value = convert("<Document><packages/><name>doc</name></Document>");
        assert!(value.get("packages").is_none());
    }

    #[test]
    fn test_entities_are_decoded() {
        let value = convert("<Document><name>a &amp; b &lt;c&gt;</name></Document>");
        assert_eq!(value["name"], serde_json::json!("a & b <c>"));
    }

    #[test]
    fn test_cdata_is_read_as_text() {
        let value = convert("<Document><name><![CDATA[a & b]]></name></Document>");
        assert_eq!(value["name"], serde_json::json!("a & b"));
    }

    #[test]
    fn test_namespace_prefixes_are_ignored() {
        let value = convert(
            r#"<spdx:Document xmlns:spdx="http://spdx.org/rdf/terms"><spdx:name>doc</spdx:name></spdx:Document>"#,
        );
        assert_eq!(value["name"], serde_json::json!("doc"));
    }

    #[test]
    fn test_spdxdocument_root_is_accepted() {
        let value = convert("<SpdxDocument><name>doc</name></SpdxDocument>");
        assert_eq!(value["name"], serde_json::json!("doc"));
    }

    #[test]
    fn test_other_roots_are_rejected() {
        let err = xml_to_json(b"<bom><name>doc</name></bom>").unwrap_err();
        assert!(err.to_string().contains("unexpected root element 'bom'"));
    }

    #[test]
    fn test_malformed_xml_is_rejected() {
        let err = xml_to_json(b"<Document><name>doc</Document>").unwrap_err();
        assert!(matches!(err, Error::Xml(_)), "got {err}");
    }

    #[test]
    fn test_truncated_xml_is_rejected() {
        let err = xml_to_json(b"<Document><name>doc").unwrap_err();
        assert!(matches!(err, Error::Xml(_)), "got {err}");
    }

    #[test]
    fn test_a_text_only_root_is_rejected() {
        let err = xml_to_json(b"<Document>text</Document>").unwrap_err();
        assert!(err.to_string().contains("no fields"), "got {err}");
    }

    #[test]
    fn test_nested_objects_are_preserved() {
        let value = convert(
            "<Document><creationInfo><created>2023-01-01T00:00:00Z</created><creators>Tool: t</creators></creationInfo></Document>",
        );
        assert_eq!(
            value["creationInfo"],
            serde_json::json!({"created": "2023-01-01T00:00:00Z", "creators": ["Tool: t"]})
        );
    }

    #[test]
    fn test_indentation_whitespace_is_not_captured() {
        let value =
            convert("<Document>\n  <packages>\n    <name>a</name>\n  </packages>\n</Document>");
        assert_eq!(value["packages"], serde_json::json!([{"name": "a"}]));
    }
}
