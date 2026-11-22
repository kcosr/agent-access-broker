//! Schema composition for the selected body fields; provider schemas stay raw.
use super::{BodyField, OutputContentFormat, pointer_parts};
use serde_json::{Map, Value, json};
use thiserror::Error;

/// A declared body field did not resolve in a provider result schema.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("body field does not resolve in the result schema")]
pub struct UnresolvedBodyField;

/// The concrete format/value pairings advertised by an action.
pub fn selected_content_schema(formats: &[OutputContentFormat]) -> Value {
    let mut text_formats = Vec::new();
    let mut adf = false;
    for format in formats {
        match format {
            OutputContentFormat::Markdown
            | OutputContentFormat::Text
            | OutputContentFormat::Storage => {
                if !text_formats.contains(&format.as_str()) {
                    text_formats.push(format.as_str());
                }
            }
            OutputContentFormat::Adf => adf = true,
        }
    }
    let mut branches = Vec::new();
    if !text_formats.is_empty() {
        branches.push(json!({"type":"object", "properties": {
            "format": {"type":"string", "enum":text_formats},
            "value": {"type":"string"}
        }, "required":["format","value"]}));
    }
    if adf {
        branches.push(json!({"type":"object", "properties": {
            "format": {"type":"string", "const":"adf"},
            "value": {"type":"object", "description":"Selected ADF document."}
        }, "required":["format","value"]}));
    }
    match branches.len() {
        0 => Value::Bool(false),
        1 => branches.pop().expect("one selected content branch"),
        _ => json!({"type":"object", "anyOf":branches}),
    }
}

/// Replaces `field` at every reachable owner of a provider result schema.
/// `field.owner_path` is rooted at `/result`, while `schema` describes only
/// that result. Wildcards traverse array items and all `anyOf` alternatives.
/// The original owner structure and metadata types are retained. Conditional
/// owners retain the native field schema whenever their predicates do not match.
/// An error schema may omit a success-only field; callers may ignore that miss.
pub fn inject_selected_content_schema(
    schema: &mut Value,
    field: &BodyField,
    formats: &[OutputContentFormat],
) -> Result<(), UnresolvedBodyField> {
    if formats.is_empty() {
        return Err(UnresolvedBodyField);
    }
    let path = pointer_parts(&field.owner_path).map_err(|_| UnresolvedBodyField)?;
    let mut selected = selected_content_schema(formats);
    if field.nullable {
        selected = json!({"anyOf":[selected,{"type":"null"}]});
    }
    if inject_at(schema, &path[1..], field, &selected) {
        Ok(())
    } else {
        Err(UnresolvedBodyField)
    }
}

fn inject_at(schema: &mut Value, path: &[String], field: &BodyField, selected: &Value) -> bool {
    let Some(object) = schema.as_object_mut() else {
        return false;
    };
    let mut found = false;
    if let Some(branches) = object.get_mut("anyOf").and_then(Value::as_array_mut) {
        for branch in branches {
            found |= inject_at(branch, path, field, selected);
        }
    }
    match path.split_first() {
        Some((segment, rest)) if segment == "*" => {
            if let Some(items) = object.get_mut("items") {
                found |= inject_at(items, rest, field, selected);
            }
        }
        Some((segment, rest)) => {
            if let Some(child) = object
                .get_mut("properties")
                .and_then(|p| p.get_mut(segment))
            {
                found |= inject_at(child, rest, field, selected);
            }
        }
        None => {
            if object
                .get("properties")
                .and_then(|p| p.get(&field.field))
                .is_some()
            {
                // The field declaration must exist even when its owner has a
                // predicate that cannot match this particular schema branch.
                found = true;
                if let Some(predicates) = &field.owner_equals {
                    let properties = object.get("properties").and_then(Value::as_object).unwrap();
                    if predicates.iter().any(|(key, value)| {
                        properties
                            .get(key)
                            .is_some_and(|p| !accepts_string(p, value))
                    }) {
                        return found;
                    }
                    let required = object.get("required").and_then(Value::as_array);
                    let guaranteed = predicates.iter().all(|(key, value)| {
                        required.is_some_and(|r| r.contains(&json!(key)))
                            && properties.get(key).is_some_and(|p| {
                                p.get("const") == Some(&json!(value))
                                    || p.get("enum") == Some(&json!([value]))
                            })
                    });
                    if !guaranteed {
                        let mut native = object.clone();
                        let mut match_properties = Map::new();
                        for (key, value) in predicates {
                            match_properties.insert(key.clone(), json!({"const":value}));
                        }
                        let matches = json!({"type":"object", "properties":match_properties,
                            "required":predicates.keys().collect::<Vec<_>>(), "additionalProperties":true});
                        let excluded = match native.remove("not") {
                            Some(previous) => json!({"anyOf":[previous,matches]}),
                            None => matches,
                        };
                        native.insert("not".into(), excluded);
                        let mut presented = object.clone();
                        for (key, value) in predicates {
                            let property = presented
                                .get_mut("properties")
                                .unwrap()
                                .as_object_mut()
                                .unwrap()
                                .entry(key.clone())
                                .or_insert_with(|| json!({}));
                            let Some(property) = property.as_object_mut() else {
                                return false;
                            };
                            property.insert("const".into(), json!(value));
                            require(&mut presented, key);
                        }
                        replace_field(&mut presented, field, selected);
                        *schema = json!({"anyOf":[presented,native]});
                        return true;
                    }
                }
                replace_field(object, field, selected);
            }
        }
    }
    found
}

fn accepts_string(schema: &Value, value: &str) -> bool {
    let matches_type = match schema.get("type") {
        Some(Value::String(kind)) => kind == "string",
        Some(Value::Array(kinds)) => kinds.contains(&json!("string")),
        _ => true,
    };
    matches_type
        && schema.get("const").is_none_or(|expected| expected == value)
        && schema
            .get("enum")
            .and_then(Value::as_array)
            .is_none_or(|values| values.contains(&json!(value)))
}

fn require(object: &mut Map<String, Value>, field: &str) {
    let Some(required) = object
        .entry("required")
        .or_insert_with(|| json!([]))
        .as_array_mut()
    else {
        return;
    };
    if !required.contains(&json!(field)) {
        required.push(json!(field));
    }
}

fn replace_field(object: &mut Map<String, Value>, field: &BodyField, selected: &Value) {
    object
        .get_mut("properties")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(field.field.clone(), selected.clone());
    if field.optional {
        if let Some(required) = object.get_mut("required").and_then(Value::as_array_mut) {
            required.retain(|name| name != &field.field);
        }
    } else {
        require(object, &field.field);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::check_strict_conformance;

    fn conforms(schema: &Value, value: Value) -> bool {
        check_strict_conformance(schema, &value).is_ok()
    }

    #[test]
    fn pairings_preserve_concrete_format_value_types() {
        let schema = selected_content_schema(super::super::OUTPUT_CONTENT_FORMATS);
        for format in ["markdown", "text", "storage"] {
            assert!(conforms(&schema, json!({"format":format,"value":"body"})));
            assert!(!conforms(&schema, json!({"format":format,"value":{}})));
        }
        assert!(conforms(
            &schema,
            json!({"format":"adf","value":{"type":"doc"}})
        ));
        assert!(!conforms(&schema, json!({"format":"adf","value":"body"})));
        assert!(!conforms(&schema, json!({"format":"native","value":{}})));
    }

    #[test]
    fn replacements_traverse_arrays_unions_and_escaped_paths_without_adding_fields() {
        let mut schema = json!({"type":"object","properties":{
            "a/b":{"type":"array","items":{"anyOf":[
                {"type":"object","properties":{"id":{"type":"integer"},"body":{}},"required":["id","body"]},
                {"type":"null"}
            ]}}
        }});
        let field = BodyField::new("/result/a~1b/*", "body")
            .optional()
            .nullable();
        inject_selected_content_schema(&mut schema, &field, &[OutputContentFormat::Text]).unwrap();
        for value in [
            json!({"a/b":[{"id":1},null]}),
            json!({"a/b":[{"id":1,"body":null}]}),
            json!({"a/b":[{"id":1,"body":{"format":"text","value":"x"}}]}),
        ] {
            assert!(conforms(&schema, value));
        }
        assert!(!conforms(&schema, json!({"a/b":[{"id":"bad"}]})));
        assert!(!conforms(
            &schema,
            json!({"a/b":[{"id":1,"body":{"format":"markdown","value":"x"}}]})
        ));
        assert!(
            inject_selected_content_schema(
                &mut schema,
                &BodyField::new("/result", "missing"),
                &[OutputContentFormat::Text]
            )
            .is_err()
        );
    }

    #[test]
    fn predicate_preserves_native_values_only_on_nonmatching_owners() {
        let mut schema = json!({"type":"object","properties": {
            "status":{"type":"string"}, "type":{"type":"string"},"value":{"type":["object","string","null"]}
        },"required":["status","type","value"]});
        let field = BodyField::new("/result", "value")
            .nullable()
            .with_owner_equals(
                [
                    ("status".into(), "supported".into()),
                    ("type".into(), "adf".into()),
                ]
                .into(),
            );
        inject_selected_content_schema(
            &mut schema,
            &field,
            &[OutputContentFormat::Text, OutputContentFormat::Adf],
        )
        .unwrap();
        for value in [
            json!({"status":"supported","type":"adf","value":{"format":"text","value":"x"}}),
            json!({"status":"supported","type":"text","value":"native text"}),
            json!({"status":"unsupported","type":"adf","value":{"raw":true}}),
            json!({"status":"supported","type":"adf","value":null}),
        ] {
            assert!(conforms(&schema, value));
        }
        assert!(!conforms(
            &schema,
            json!({"status":"supported","type":"adf","value":{"raw":true}})
        ));
        assert!(!conforms(
            &schema,
            json!({"status":"supported","type":"text","value":3})
        ));
    }
    #[test]
    fn multiple_predicates_preserve_each_native_exclusion() {
        let mut schema = json!({"type":"object","properties":{
            "kind":{"type":"string"}, "a":{"type":"string"}, "b":{"type":"string"}
        },"required":["kind","a","b"]});
        for name in ["a", "b"] {
            let field = BodyField::new("/result", name)
                .with_owner_equals([("kind".into(), name.into())].into());
            inject_selected_content_schema(&mut schema, &field, &[OutputContentFormat::Text])
                .unwrap();
        }
        for value in [
            json!({"kind":"a","a":{"format":"text","value":"a"},"b":"b"}),
            json!({"kind":"b","a":"a","b":{"format":"text","value":"b"}}),
            json!({"kind":"other","a":"a","b":"b"}),
        ] {
            assert!(conforms(&schema, value));
        }
        assert!(!conforms(
            &schema,
            json!({"kind":"a","a":"raw a","b":"raw b"})
        ));
        assert!(!conforms(
            &schema,
            json!({"kind":"b","a":"raw a","b":"raw b"})
        ));
    }
}
