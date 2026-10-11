//! Accepted schemas are the executable contract, including protocol header mirroring.
//! Byte/depth and regex limits bound common sources of excessive validation work.
//! The JSON Schema library is synchronous and exposes no overall evaluation-step
//! budget; these bounds are not a general CPU deadline for arbitrary schemas.
use base64::{Engine, prelude::BASE64_STANDARD};
use http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;
use std::collections::BTreeSet;

pub(crate) const MAX_TOOL_BYTES: usize = agent_access_provider::IMPORT_MAX_SCHEMA_BYTES;
pub(crate) const MAX_DESCRIPTION_BYTES: usize = 16 * 1024;

pub(crate) struct CompiledSchema {
    validator: agent_access_provider::BoundedImportSchema,
    headers: Vec<MirroredHeader>,
}

struct MirroredHeader {
    property: String,
    name: HeaderName,
}

impl CompiledSchema {
    pub(crate) fn input(schema: &Value) -> Result<Self, String> {
        if schema.get("type").and_then(Value::as_str) != Some("object") {
            return Err("inputSchema must declare type object".into());
        }
        Self::compile(schema, true)
    }

    pub(crate) fn output(schema: &Value) -> Result<Self, String> {
        Self::compile(schema, false)
    }

    fn compile(schema: &Value, input: bool) -> Result<Self, String> {
        let mut headers = Vec::new();
        if input {
            inspect_headers(schema, &mut headers)?;
        }
        let validator = agent_access_provider::BoundedImportSchema::compile(schema)?;
        Ok(Self { validator, headers })
    }

    pub(crate) fn valid(&self, value: &Value) -> bool {
        self.validator.is_valid(value)
    }

    pub(crate) fn headers(&self, arguments: &Value) -> Result<HeaderMap, String> {
        let mut headers = HeaderMap::new();
        for header in &self.headers {
            let value = arguments.get(&header.property);
            let Some(value) = value else { continue };
            let text = match value {
                Value::String(text) => text.clone(),
                Value::Bool(value) => value.to_string(),
                Value::Null => continue,
                Value::Number(value) => mirrored_integer(value)?.to_string(),
                _ => return Err("mirrored parameter must have its declared primitive type".into()),
            };
            let mut value = HeaderValue::from_str(&encode_header(&text))
                .map_err(|_| "mirrored parameter cannot be encoded")?;
            value.set_sensitive(true);
            headers.insert(header.name.clone(), value);
        }
        Ok(headers)
    }

    pub(crate) fn arguments_and_headers(
        &self,
        arguments: &Value,
    ) -> Result<(Value, HeaderMap), String> {
        let mut arguments = arguments.clone();
        // JSON Schema accepts integral floats. The SDK compares the textual
        // header/body values, so send canonical integers in both locations.
        for header in &self.headers {
            if let Some(value) = arguments.get_mut(&header.property)
                && let Value::Number(number) = value
            {
                *value = Value::from(mirrored_integer(number)?);
            }
        }
        let headers = self.headers(&arguments)?;
        Ok((arguments, headers))
    }
}

fn mirrored_integer(number: &serde_json::Number) -> Result<i64, String> {
    number
        .as_f64()
        .filter(|value| {
            value.fract() == 0.0
                && (-9_007_199_254_740_991.0..=9_007_199_254_740_991.0).contains(value)
        })
        .map(|value| value as i64)
        .ok_or_else(|| "mirrored integer must be within the JavaScript safe integer range".into())
}

fn inspect_headers(schema: &Value, output: &mut Vec<MirroredHeader>) -> Result<(), String> {
    let eligible = schema.get("properties").and_then(Value::as_object);
    let mut seen = BTreeSet::new();
    agent_access_provider::visit_import_schema_nodes(schema, |node| {
        let Some(raw) = node.get("x-mcp-header") else {
            return Ok(());
        };
        let (property, _) = eligible
            .and_then(|properties| {
                properties
                    .iter()
                    .find(|(_, candidate)| std::ptr::eq(*candidate, node))
            })
            .ok_or("x-mcp-header must be on a direct root property")?;
        let suffix = raw
            .as_str()
            .filter(|v| !v.is_empty())
            .ok_or("x-mcp-header must be a nonempty string")?;
        let name = HeaderName::from_bytes(format!("Mcp-Param-{suffix}").as_bytes())
            .map_err(|_| "x-mcp-header must be an HTTP field-name token")?;
        if !seen.insert(name.as_str().to_owned()) {
            return Err("x-mcp-header names must be case-insensitively unique".into());
        }
        if !matches!(
            node.get("type").and_then(Value::as_str),
            Some("string" | "integer" | "boolean")
        ) {
            return Err("x-mcp-header requires string, integer, or boolean type".into());
        }
        output.push(MirroredHeader {
            property: property.clone(),
            name,
        });
        Ok(())
    })
}

pub(crate) fn encode_header(value: &str) -> String {
    if value.starts_with([' ', '\t'])
        || value.ends_with([' ', '\t'])
        || value.bytes().any(|byte| !(0x20..=0x7e).contains(&byte))
        || (value.starts_with("=?base64?") && value.ends_with("?="))
    {
        format!("=?base64?{}?=", BASE64_STANDARD.encode(value))
    } else {
        value.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn root_properties_and_safe_header_encoding() {
        let schema = CompiledSchema::input(&json!({"type":"object", "properties": {
            "region":{"type":"string","x-mcp-header":"Region"},
            "n":{"type":"integer","x-mcp-header":"Count"}
        }}))
        .unwrap();
        let headers = schema
            .headers(&json!({"region":" café\r\n","n":42}))
            .unwrap();
        assert_eq!(headers["mcp-param-region"], "=?base64?IGNhZsOpDQo=?=");
        assert_eq!(headers["mcp-param-count"], "42");
        assert_eq!(
            schema.headers(&json!({"n":42.0})).unwrap()["mcp-param-count"],
            "42"
        );
        assert!(schema.headers(&json!({"n":null})).unwrap().is_empty());
        assert!(headers["mcp-param-region"].is_sensitive());
        assert!(schema.headers(&json!({"n":9007199254740992_i64})).is_err());
        assert_eq!(
            encode_header("=?base64?YQ==?="),
            "=?base64?PT9iYXNlNjQ/WVE9PT89?="
        );
        assert!(schema.headers(&json!({})).unwrap().is_empty());
        let (arguments, headers) = schema.arguments_and_headers(&json!({"n":42.0})).unwrap();
        assert_eq!(arguments["n"].as_i64(), Some(42));
        assert_eq!(
            arguments["n"].to_string(),
            headers["mcp-param-count"].to_str().unwrap()
        );
    }

    #[test]
    fn rejects_invalid_annotations_everywhere() {
        for schema in [
            json!({"type":"object","x-mcp-header":"No"}),
            json!({"type":"object","properties":{"a":{"type":"number","x-mcp-header":"No"}}}),
            json!({"type":"object","properties":{"a":{"type":"string","x-mcp-header":"N"},"b":{"type":"string","x-mcp-header":"n"}}}),
            json!({"type":"object","allOf":[{"properties":{"a":{"type":"string","x-mcp-header":"No"}}}]}),
            json!({"type":"object","properties":{"a":{"type":"array","items":{"type":"string","x-mcp-header":"No"}}}}),
            json!({"type":"object","properties":{"a":{"type":"string","x-mcp-header":"bad\r\n"}}}),
            json!({"type":"object","properties":{"outer":{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"}}}}}),
        ] {
            assert!(CompiledSchema::input(&schema).is_err(), "{schema}");
        }
    }

    #[test]
    fn only_local_refs_and_compiled_constraints() {
        let schema = CompiledSchema::input(&json!({"type":"object","$defs":{"n":{"type":"integer","minimum":2}},"properties":{"n":{"$ref":"#/$defs/n"}},"required":["n"]})).unwrap();
        assert!(schema.valid(&json!({"n":2})));
        assert!(!schema.valid(&json!({"n":1})));
        assert!(!schema.valid(&json!({})));
        for reference in ["https://example.com/schema", "file:///tmp/schema"] {
            assert!(CompiledSchema::input(&json!({"type":"object","$ref":reference})).is_err());
        }
        assert!(
            CompiledSchema::output(&json!({"type":["null","string"]}))
                .unwrap()
                .valid(&Value::Null)
        );
    }

    #[test]
    fn literal_schema_like_data_is_preserved_but_cannot_be_a_reference_target() {
        let literal =
            json!({"$ref":"https://literal.example/", "x-mcp-header":"literal", "$id":"literal"});
        let schema = CompiledSchema::input(
            &json!({"type":"object","properties":{"literal":{"const":literal}}}),
        )
        .unwrap();
        assert!(schema.valid(&json!({"literal":literal})));
        assert!(
            CompiledSchema::input(
                &json!({"type":"object","default":{"type":"object"},"$ref":"#/default"})
            )
            .is_err()
        );
    }
}
