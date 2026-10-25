//! Shared, test-only inventory checks for the maintained native fixtures.
#![allow(dead_code)]

use agent_access_provider::{ActionDescriptor, ServiceDescriptor};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub fn project(action: &ActionDescriptor, inputs: &Value) -> Value {
    let projection = action.audit_inputs.as_ref().expect("reviewed projection");
    let plan = agent_access_provider::host::prepare_audit_inputs(&action.input_schema, projection)
        .unwrap_or_else(|error| panic!("{}: {error}", action.action));
    serde_json::to_value(plan.project(inputs).expect("non-omit projection")).unwrap()
}

pub fn field<'a>(snapshot: &'a Value, key: &str) -> &'a Value {
    snapshot["fields"].as_array().unwrap().iter()
        .find(|field| field["key"] == key).unwrap_or_else(|| panic!("missing {key}: {snapshot}"))
}

pub fn action<'a>(descriptor: &'a ServiceDescriptor, name: &str) -> &'a ActionDescriptor {
    descriptor.actions.iter().find(|action| action.action == name).unwrap()
}

fn rules(action: &ActionDescriptor) -> Vec<Value> {
    action.audit_inputs.as_ref().map(|projection| {
        serde_json::to_value(projection).unwrap().as_array().unwrap().clone()
    }).unwrap_or_default()
}

fn classified(rules: &[Value], prefix: &str, paths: &mut BTreeSet<String>) {
    for rule in rules {
        let pointer = format!("{prefix}{}", rule["pointer"].as_str().unwrap());
        if rule["capture"] == "records" {
            classified(rule["fields"].as_array().unwrap(), &format!("{pointer}[]"), paths);
        } else {
            assert!(paths.insert(pointer), "duplicate classification");
        }
    }
}

fn schema_leaves(root: &Value, node: &Value, path: &str, terminals: &BTreeSet<String>, leaves: &mut BTreeSet<String>, depth: usize) {
    assert!(depth < 128, "schema inventory recursion limit at {path}");
    if terminals.contains(path) {
        leaves.insert(path.to_owned());
        return;
    }
    if let Some(reference) = node.get("$ref").and_then(Value::as_str) {
        let referenced = root.pointer(reference.strip_prefix('#').expect("local reference")).expect("resolved reference");
        schema_leaves(root, referenced, path, terminals, leaves, depth + 1);
    }
    let mut has_children = node.get("$ref").is_some();
    if let Some(properties) = node.get("properties").and_then(Value::as_object) {
        has_children = true;
        for (name, child) in properties {
            let segment = name.replace('~', "~0").replace('/', "~1");
            schema_leaves(root, child, &format!("{path}/{segment}"), terminals, leaves, depth + 1);
        }
    }
    if let Some(items) = node.get("items") {
        has_children = true;
        schema_leaves(root, items, &format!("{path}[]"), terminals, leaves, depth + 1);
    }
    for keyword in ["allOf", "oneOf", "anyOf"] {
        if let Some(branches) = node.get(keyword).and_then(Value::as_array) {
            for branch in branches {
                // Predicate-only branches do not introduce input fields.
                if branch.get("properties").is_some() || branch.get("$ref").is_some()
                    || ["allOf", "oneOf", "anyOf"].iter().any(|key| branch.get(key).is_some()) {
                    has_children = true;
                    schema_leaves(root, branch, path, terminals, leaves, depth + 1);
                }
            }
        }
    }
    for keyword in ["if", "then", "else"] {
        if let Some(branch) = node.get(keyword) {
            if branch.get("properties").is_some() || branch.get("$ref").is_some() {
                has_children = true;
                schema_leaves(root, branch, path, terminals, leaves, depth + 1);
            }
        }
    }
    if !has_children && !path.is_empty() {
        leaves.insert(path.to_owned());
    }
}

pub fn assert_coverage(action: &ActionDescriptor) {
    let mut declared = BTreeSet::new();
    classified(&rules(action), "", &mut declared);
    let mut leaves = BTreeSet::new();
    schema_leaves(&action.input_schema, &action.input_schema, "", &declared, &mut leaves, 0);
    assert_eq!(leaves, declared, "unclassified or obsolete input selectors for {}", action.action);
    if declared.is_empty() {
        assert!(action.audit_inputs.is_none(), "no-input actions must omit auditInputs");
    } else {
        agent_access_provider::host::prepare_audit_inputs(&action.input_schema, action.audit_inputs.as_ref().unwrap())
            .unwrap_or_else(|error| panic!("{}: {error}", action.action));
    }
}

fn inventory_fields(rules: &[Value], action: &str, prefix: &str, semantic: impl Fn(&str, &str) -> (&'static str, &'static str) + Copy) -> Vec<Value> {
    rules.iter().map(|rule| {
        let pointer = rule["pointer"].as_str().unwrap();
        let full = format!("{prefix}{pointer}");
        let (element, reason) = semantic(action, &full);
        let mut field = json!({"pointer":pointer,"element":element,"capture":rule["capture"]});
        for key in ["display", "role", "kind", "shape"] {
            if let Some(value) = rule.get(key) { field[key] = value.clone(); }
        }
        if rule["capture"] == "records" {
            field["fields"] = json!(inventory_fields(rule["fields"].as_array().unwrap(), action, &format!("{full}[]"), semantic));
        } else if rule["capture"] != "value" {
            assert!(!reason.is_empty(), "summary/omission needs an exclusion rationale: {action} {full}");
            field["opaque"] = json!(true);
        }
        if !reason.is_empty() { field["reason"] = json!(reason); }
        field
    }).collect()
}

pub fn check_inventory(descriptor: &ServiceDescriptor, path: &str, no_inputs: &[&str], semantic: impl Fn(&str, &str) -> (&'static str, &'static str) + Copy) {
    let mut actual_no_inputs = Vec::new();
    let actions: Vec<_> = descriptor.actions.iter().map(|action| {
        assert_coverage(action);
        let fields = inventory_fields(&rules(action), &action.action, "", semantic);
        if fields.is_empty() {
            actual_no_inputs.push(action.action.as_str());
            json!({"action":action.action,"noInputs":true})
        } else { json!({"action":action.action,"fields":fields}) }
    }).collect();
    assert_eq!(actual_no_inputs, no_inputs, "no-input actions need explicit review");
    let inventory = json!({"fixture":"audit-inventory-maximal","actions":actions});
    if std::env::var_os("UPDATE_AUDIT_INVENTORY").is_some() {
        std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(&inventory).unwrap())).unwrap();
    }
    let expected: Value = serde_json::from_slice(&std::fs::read(path).expect("checked-in audit inventory")).unwrap();
    assert_eq!(inventory, expected, "review the schema and semantic decisions before updating the inventory");
}

/// Validate hand-authored request samples against the current invocation schema
/// before checking capture. This fails if a schema changes representation while
/// retaining the same selector name.
pub fn assert_sample(action: &ActionDescriptor, inputs: &Value) -> Value {
    let schema = jsonschema::validator_for(&action.input_schema).unwrap();
    assert!(schema.is_valid(inputs), "{} fixture is not schema-valid: {inputs}", action.action);
    let snapshot = project(action, inputs);
    fn walk(value: &Value) {
        if let Some(object) = value.as_object() {
            assert_ne!(object.get("state"), Some(&json!("invalid")), "{value}");
            for child in object.values() { walk(child); }
        } else if let Some(items) = value.as_array() {
            for child in items { walk(child); }
        }
    }
    walk(&snapshot);
    snapshot
}
