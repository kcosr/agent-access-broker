//! Keep accepted local schema references local when nesting an action schema in
//! a generated request schema. Literal data in const/default/examples is untouched.
use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) fn relocate_local_schema_refs(schema: &mut Value, base: &str) {
    let mut anchors = BTreeMap::new();
    visit_schemas(schema, "", &mut |schema, path| {
        if let Some(anchor) = schema.get("$anchor").and_then(Value::as_str) {
            anchors.insert(anchor.to_owned(), path.to_owned());
        }
    });
    visit_schemas(schema, "", &mut |schema, _| {
        let Some(fields) = schema.as_object_mut() else {
            return;
        };
        if let Some(Value::String(reference)) = fields.get_mut("$ref") {
            if reference == "#" {
                *reference = base.to_owned();
            } else if let Some(pointer) = reference.strip_prefix("#/") {
                *reference = format!("{base}/{pointer}");
            } else if let Some(anchor) = reference.strip_prefix('#') {
                let anchor = percent_encoding::percent_decode_str(anchor).decode_utf8_lossy();
                if let Some(path) = anchors.get(anchor.as_ref()) {
                    *reference = format!("{base}{path}");
                }
            }
        }
        // References now use pointers; anchors must not collide across imported actions.
        fields.remove("$anchor");
    });
}

fn escape(value: &str) -> String {
    // JSON Pointer escaping is followed by URI-fragment encoding. A literal
    // percent escape in a property name must survive the resolver's decoding.
    let pointer = value.replace('~', "~0").replace('/', "~1");
    let mut encoded = String::new();
    for byte in pointer.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'$') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(&mut encoded, "%{byte:02X}").expect("writing to String");
        }
    }
    encoded
}

fn visit_schemas(schema: &mut Value, path: &str, visit: &mut impl FnMut(&mut Value, &str)) {
    visit(schema, path);
    let Some(fields) = schema.as_object_mut() else {
        return;
    };
    for (keyword, value) in fields {
        let child_path = format!("{path}/{}", escape(keyword));
        match keyword.as_str() {
            "properties" | "patternProperties" | "$defs" | "definitions" | "dependentSchemas"
            | "dependencies" => {
                if let Value::Object(schemas) = value {
                    for (key, child) in schemas {
                        if child.is_object() || child.is_boolean() {
                            visit_schemas(child, &format!("{child_path}/{}", escape(key)), visit);
                        }
                    }
                }
            }
            "allOf" | "anyOf" | "oneOf" | "prefixItems" => {
                if let Value::Array(schemas) = value {
                    for (index, child) in schemas.iter_mut().enumerate() {
                        visit_schemas(child, &format!("{child_path}/{index}"), visit);
                    }
                }
            }
            "items" if value.is_array() => {
                for (index, child) in value.as_array_mut().expect("array").iter_mut().enumerate() {
                    visit_schemas(child, &format!("{child_path}/{index}"), visit);
                }
            }
            "additionalProperties"
            | "unevaluatedProperties"
            | "propertyNames"
            | "contains"
            | "items"
            | "unevaluatedItems"
            | "additionalItems"
            | "not"
            | "if"
            | "then"
            | "else"
            | "contentSchema" => visit_schemas(value, &child_path, visit),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn relocates_nested_local_refs_and_anchors_without_rewriting_literal_data() {
        let mut schema = json!({"type":"object","$defs":{"a/b":{"$anchor":"item","type":"string"}},
            "properties":{"p":{"$ref":"#item"},"q":{"type":"array","items":{"$ref":"#/$defs/a~1b"}},
                "literal":{"const":{"$ref":"#/$defs/a~1b","$anchor":"literal"}}},
            "additionalProperties":{"$ref":"#"}});
        relocate_local_schema_refs(&mut schema, "#/oneOf/0/properties/inputs");
        assert_eq!(
            schema["properties"]["p"]["$ref"],
            "#/oneOf/0/properties/inputs/$defs/a~1b"
        );
        assert_eq!(
            schema["properties"]["q"]["items"]["$ref"],
            "#/oneOf/0/properties/inputs/$defs/a~1b"
        );
        assert_eq!(
            schema["additionalProperties"]["$ref"],
            "#/oneOf/0/properties/inputs"
        );
        assert!(schema["$defs"]["a/b"].get("$anchor").is_none());
        assert_eq!(
            schema["properties"]["literal"]["const"],
            json!({"$ref":"#/$defs/a~1b","$anchor":"literal"})
        );
    }
}
