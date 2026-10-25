//! Shared, test-only inventory checks for the maintained native fixtures.
#![allow(dead_code)]

use agent_access_provider::{ActionDescriptor, ServiceDescriptor};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub fn project(action: &ActionDescriptor, inputs: &Value) -> Value {
    let projection = action.audit_inputs.as_ref().expect("reviewed projection");
    let plan = agent_access_provider::host::prepare_audit_inputs(&action.input_schema, projection)
        .unwrap_or_else(|error| panic!("{}: {error}", action.action));
    serde_json::to_value(plan.project(inputs).expect("non-omit projection")).unwrap()
}

pub fn field<'a>(snapshot: &'a Value, key: &str) -> &'a Value {
    snapshot["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|field| field["key"] == key)
        .unwrap_or_else(|| panic!("missing {key}: {snapshot}"))
}

pub fn action<'a>(descriptor: &'a ServiceDescriptor, name: &str) -> &'a ActionDescriptor {
    descriptor
        .actions
        .iter()
        .find(|action| action.action == name)
        .unwrap()
}

fn rules(action: &ActionDescriptor) -> Vec<Value> {
    action
        .audit_inputs
        .as_ref()
        .map(|projection| {
            serde_json::to_value(projection)
                .unwrap()
                .as_array()
                .unwrap()
                .clone()
        })
        .unwrap_or_default()
}

fn classified(rules: &[Value], prefix: &str, paths: &mut BTreeMap<String, bool>) {
    for rule in rules {
        let pointer = format!("{prefix}{}", rule["pointer"].as_str().unwrap());
        if rule["capture"] == "records" {
            classified(
                rule["fields"].as_array().unwrap(),
                &format!("{pointer}[]"),
                paths,
            );
        } else {
            assert!(
                paths.insert(pointer, rule["capture"] != "value").is_none(),
                "duplicate classification"
            );
        }
    }
}

// This inventory walker intentionally supports only the maintained native
// schema profile. An opaque reviewed terminal owns its whole subtree; elsewhere
// unfamiliar applicators must stop the coverage check, never hide new fields.
fn schema_branches(node: &Value) -> Vec<&Value> {
    let object = node
        .as_object()
        .expect("unsupported schema inventory shape");
    for keyword in [
        "prefixItems",
        "patternProperties",
        "dependentSchemas",
        "dependencies",
        "additionalItems",
        "unevaluatedItems",
        "unevaluatedProperties",
        "contains",
        "propertyNames",
        "contentSchema",
        "$dynamicRef",
        "$recursiveRef",
    ] {
        assert!(
            !object.contains_key(keyword),
            "unsupported schema inventory keyword: {keyword}"
        );
    }
    if let Some(additional) = object.get("additionalProperties") {
        assert_eq!(
            additional,
            &Value::Bool(false),
            "unsupported schema inventory keyword: additionalProperties"
        );
    }
    if let Some(properties) = object.get("properties") {
        assert!(
            properties.is_object(),
            "unsupported schema inventory properties shape"
        );
    }
    if let Some(items) = object.get("items") {
        assert!(
            items.is_object(),
            "unsupported schema inventory items shape"
        );
    }
    if let Some(reference) = object.get("$ref") {
        assert!(
            reference.is_string(),
            "unsupported schema inventory reference shape"
        );
    }
    let mut branches = Vec::new();
    for keyword in ["allOf", "oneOf", "anyOf"] {
        if let Some(value) = object.get(keyword) {
            branches.extend(
                value
                    .as_array()
                    .expect("unsupported schema inventory composition shape"),
            );
        }
    }
    for keyword in ["if", "then", "else", "not"] {
        if let Some(branch) = object.get(keyword) {
            branches.push(branch);
        }
    }
    branches
}

fn has_input_shape(node: &Value, depth: usize) -> bool {
    assert!(depth < 128, "schema inventory recursion limit");
    let branches = schema_branches(node);
    let mut found = ["properties", "items", "$ref"]
        .iter()
        .any(|key| node.get(key).is_some());
    for branch in branches {
        // Visit every branch even after finding a shape, so an unsupported
        // sibling cannot be mistaken for a harmless predicate.
        found |= has_input_shape(branch, depth + 1);
    }
    found
}

fn named_descendants(root: &Value, node: &Value, depth: usize) -> bool {
    assert!(depth < 128, "schema inventory recursion limit");
    let branches = schema_branches(node);
    if node
        .get("properties")
        .and_then(Value::as_object)
        .is_some_and(|properties| !properties.is_empty())
    {
        return true;
    }
    if let Some(reference) = node.get("$ref").and_then(Value::as_str) {
        let referenced = root
            .pointer(reference.strip_prefix('#').expect("local reference"))
            .expect("resolved reference");
        if named_descendants(root, referenced, depth + 1) {
            return true;
        }
    }
    if let Some(items) = node.get("items")
        && named_descendants(root, items, depth + 1)
    {
        return true;
    }
    branches
        .into_iter()
        .any(|branch| named_descendants(root, branch, depth + 1))
}

fn schema_leaves(
    root: &Value,
    node: &Value,
    path: &str,
    terminals: &BTreeMap<String, bool>,
    leaves: &mut BTreeSet<String>,
    depth: usize,
) {
    assert!(depth < 128, "schema inventory recursion limit at {path}");
    if let Some(opaque) = terminals.get(path) {
        assert!(
            *opaque || !named_descendants(root, node, depth + 1),
            "value capture cannot classify newly named descendants at {path}"
        );
        leaves.insert(path.to_owned());
        return;
    }
    let branches = schema_branches(node);
    if let Some(reference) = node.get("$ref").and_then(Value::as_str) {
        let referenced = root
            .pointer(reference.strip_prefix('#').expect("local reference"))
            .expect("resolved reference");
        schema_leaves(root, referenced, path, terminals, leaves, depth + 1);
    }
    let mut has_children = node.get("$ref").is_some();
    if let Some(properties) = node.get("properties").and_then(Value::as_object) {
        has_children = true;
        for (name, child) in properties {
            let segment = name.replace('~', "~0").replace('/', "~1");
            schema_leaves(
                root,
                child,
                &format!("{path}/{segment}"),
                terminals,
                leaves,
                depth + 1,
            );
        }
    }
    if let Some(items) = node.get("items") {
        has_children = true;
        schema_leaves(
            root,
            items,
            &format!("{path}[]"),
            terminals,
            leaves,
            depth + 1,
        );
    }
    for branch in branches {
        // Predicates alone add no fields; items and nested applicators do.
        if has_input_shape(branch, depth + 1) {
            has_children = true;
            schema_leaves(root, branch, path, terminals, leaves, depth + 1);
        }
    }
    if !has_children && !path.is_empty() {
        leaves.insert(path.to_owned());
    }
}

pub fn assert_coverage(action: &ActionDescriptor) {
    let mut declared = BTreeMap::new();
    classified(&rules(action), "", &mut declared);
    let mut leaves = BTreeSet::new();
    schema_leaves(
        &action.input_schema,
        &action.input_schema,
        "",
        &declared,
        &mut leaves,
        0,
    );
    assert_eq!(
        leaves,
        declared.keys().cloned().collect(),
        "unclassified or obsolete input selectors for {}",
        action.action
    );
    if declared.is_empty() {
        assert!(
            action.audit_inputs.is_none(),
            "no-input actions must omit auditInputs"
        );
    } else {
        agent_access_provider::host::prepare_audit_inputs(
            &action.input_schema,
            action.audit_inputs.as_ref().unwrap(),
        )
        .unwrap_or_else(|error| panic!("{}: {error}", action.action));
    }
}

fn inventory_fields(
    rules: &[Value],
    action: &str,
    prefix: &str,
    semantic: impl Fn(&str, &str) -> (&'static str, &'static str) + Copy,
) -> Vec<Value> {
    rules
        .iter()
        .map(|rule| {
            let pointer = rule["pointer"].as_str().unwrap();
            let full = format!("{prefix}{pointer}");
            let (element, reason) = semantic(action, &full);
            let mut field = json!({"pointer":pointer,"element":element,"capture":rule["capture"]});
            for key in ["display", "role", "kind", "shape"] {
                if let Some(value) = rule.get(key) {
                    field[key] = value.clone();
                }
            }
            if rule["capture"] == "records" {
                field["fields"] = json!(inventory_fields(
                    rule["fields"].as_array().unwrap(),
                    action,
                    &format!("{full}[]"),
                    semantic
                ));
            } else if rule["capture"] != "value" {
                assert!(
                    !reason.is_empty(),
                    "summary/omission needs an exclusion rationale: {action} {full}"
                );
                field["opaque"] = json!(true);
            }
            if !reason.is_empty() {
                field["reason"] = json!(reason);
            }
            field
        })
        .collect()
}

pub fn check_inventory(
    descriptor: &ServiceDescriptor,
    path: &str,
    no_inputs: &[&str],
    semantic: impl Fn(&str, &str) -> (&'static str, &'static str) + Copy,
) {
    let mut actual_no_inputs = Vec::new();
    let actions: Vec<_> = descriptor
        .actions
        .iter()
        .map(|action| {
            assert_coverage(action);
            let fields = inventory_fields(&rules(action), &action.action, "", semantic);
            if fields.is_empty() {
                actual_no_inputs.push(action.action.as_str());
                json!({"action":action.action,"noInputs":true})
            } else {
                json!({"action":action.action,"fields":fields})
            }
        })
        .collect();
    assert_eq!(
        actual_no_inputs, no_inputs,
        "no-input actions need explicit review"
    );
    let inventory = json!({"fixture":"audit-inventory-maximal","actions":actions});
    if std::env::var_os("UPDATE_AUDIT_INVENTORY").is_some() {
        std::fs::write(
            path,
            format!("{}\n", serde_json::to_string_pretty(&inventory).unwrap()),
        )
        .unwrap();
    }
    let expected: Value =
        serde_json::from_slice(&std::fs::read(path).expect("checked-in audit inventory")).unwrap();
    assert_eq!(
        inventory, expected,
        "review the schema and semantic decisions before updating the inventory"
    );
}

/// Validate hand-authored request samples against the current invocation schema
/// before checking capture. This fails if a schema changes representation while
/// retaining the same selector name.
pub fn assert_sample(action: &ActionDescriptor, inputs: &Value) -> Value {
    let schema = jsonschema::validator_for(&action.input_schema).unwrap();
    assert!(
        schema.is_valid(inputs),
        "{} fixture is not schema-valid: {inputs}",
        action.action
    );
    let snapshot = project(action, inputs);
    fn walk(value: &Value) {
        if let Some(object) = value.as_object() {
            assert_ne!(object.get("state"), Some(&json!("invalid")), "{value}");
            for child in object.values() {
                walk(child);
            }
        } else if let Some(items) = value.as_array() {
            for child in items {
                walk(child);
            }
        }
    }
    walk(&snapshot);
    snapshot
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_provider::{AuditInputProjection, AuditInputRule, AuditValueKind};

    fn panic_message(operation: impl FnOnce()) -> String {
        let error = std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation))
            .expect_err("coverage must fail closed");
        error
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| error.downcast_ref::<&str>().map(|text| (*text).to_owned()))
            .unwrap()
    }

    fn record_action(extra: Value) -> ActionDescriptor {
        let mut rows = json!({"type":"array","items":{"type":"object","properties":{"known":{"type":"number"}},"additionalProperties":false}});
        rows.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        ActionDescriptor::new(
            "example",
            "Inventory fixture",
            json!({"type":"object","properties":{"rows":rows},"additionalProperties":false}),
        )
        .audit_inputs(AuditInputProjection::new([AuditInputRule::records(
            "rows",
            "Rows",
            "/rows",
            [AuditInputRule::value("known", "Known", "/known").kind(AuditValueKind::Number)],
        )]))
    }

    #[test]
    fn composed_array_and_conditional_fields_require_classification() {
        for composition in ["allOf", "oneOf", "anyOf"] {
            let extra =
                json!({composition:[{"items":{"properties":{"unreviewed":{"type":"string"}}}}]});
            let action = record_action(extra.clone());
            assert!(
                panic_message(|| assert_coverage(&action))
                    .contains("unclassified or obsolete input selectors")
            );
            for conditional in ["if", "then", "else", "not"] {
                let action = record_action(json!({conditional:extra}));
                assert!(
                    panic_message(|| assert_coverage(&action))
                        .contains("unclassified or obsolete input selectors")
                );
            }
        }
    }

    #[test]
    fn predicate_only_branches_do_not_add_spurious_selectors() {
        let action = record_action(json!({
            "allOf":[{"minItems":0},{"not":{"anyOf":[{"maxItems":0}]}}],
            "if":{"minItems":1},"then":{"allOf":[{"maxItems":20}]}
        }));
        assert_coverage(&action);
    }

    #[test]
    fn unsupported_applicators_cannot_hide_unclassified_or_value_captured_children() {
        for extra in [
            json!({"prefixItems":[{"properties":{"hidden":{}}}]}),
            json!({"items":[{"properties":{"hidden":{}}}]}),
            json!({"patternProperties":{".*":{"properties":{"hidden":{}}}}}),
            json!({"additionalProperties":{"properties":{"hidden":{}}}}),
            json!({"additionalProperties":true}),
            json!({"dependentSchemas":{"flag":{"properties":{"hidden":{}}}}}),
            json!({"dependencies":{"flag":{"properties":{"hidden":{}}}}}),
            json!({"additionalItems":{"properties":{"hidden":{}}}}),
            json!({"unevaluatedItems":{"properties":{"hidden":{}}}}),
            json!({"unevaluatedProperties":{"properties":{"hidden":{}}}}),
            json!({"contains":{"properties":{"hidden":{}}}}),
            json!({"propertyNames":{"type":"string"}}),
            json!({"contentSchema":{"properties":{"hidden":{}}}}),
            json!({"$dynamicRef":"#dynamic"}),
            json!({"$recursiveRef":"#"}),
        ] {
            for nested in [extra.clone(), json!({"then":{"allOf":[extra]}})] {
                let schema = json!({"properties":{"value":nested}});
                for terminals in [BTreeMap::new(), BTreeMap::from([("/value".into(), false)])] {
                    let error = panic_message(|| {
                        schema_leaves(&schema, &schema, "", &terminals, &mut BTreeSet::new(), 0);
                    });
                    assert!(error.contains("unsupported schema inventory"), "{error}");
                }
            }
        }
    }

    #[test]
    fn reviewed_opaque_fields_still_own_their_whole_subtree() {
        let action = ActionDescriptor::new("example", "Opaque fixture", json!({
            "type":"object","properties":{"opaque":{"type":"object","patternProperties":{".*":{}},"additionalProperties":true}},"additionalProperties":false
        })).audit_inputs(AuditInputProjection::new([AuditInputRule::presence("opaque", "Payload supplied", "/opaque")]));
        assert_coverage(&action);
    }
}
