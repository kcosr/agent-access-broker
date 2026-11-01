//! Detailed action guidance, separate from initial tool descriptions and schemas.
use agent_access_provider::{ActionDescriptor, validate_tenant_host};
use serde_json::{Map, Value};
use std::sync::OnceLock;

const EXAMPLE_KEYS: [&str; 3] = ["inputExamples", "inputTemplates", "uploadLocators"];

fn guidance() -> &'static Map<String, Value> {
    static GUIDANCE: OnceLock<Map<String, Value>> = OnceLock::new();
    GUIDANCE.get_or_init(|| {
        serde_json::from_str(include_str!("action-documentation.json"))
            .expect("valid bundled action documentation")
    })
}

pub(super) fn with_guidance(mut action: ActionDescriptor, tenant_host: &str) -> ActionDescriptor {
    let additions = guidance()
        .get(&action.action)
        .and_then(Value::as_object)
        .expect("documentation for each native action");
    let mut fields = Map::new();
    for (key, value) in additions {
        let value = if EXAMPLE_KEYS.contains(&key.as_str()) {
            let examples = value
                .as_array()
                .expect("documentation example array")
                .iter()
                .filter_map(|example| {
                    configured_example(example, &action.input_schema, tenant_host)
                })
                .collect::<Vec<_>>();
            if examples.is_empty() {
                continue;
            }
            Value::Array(examples)
        } else {
            value.clone()
        };
        fields.insert(key.clone(), value);
    }
    let documentation = action
        .documentation
        .get_or_insert_with(|| Value::Object(Map::new()));
    let documentation = documentation
        .as_object_mut()
        .expect("action documentation object");
    for (key, value) in fields {
        assert!(
            !documentation.contains_key(&key),
            "action documentation key already exists: {}.{key}",
            action.action
        );
        documentation.insert(key, value);
    }
    action
}

fn configured_example(example: &Value, schema: &Value, tenant_host: &str) -> Option<Value> {
    let inputs = example.get("inputs").expect("canonical example inputs");
    if let Some(format) = inputs.get("contentFormat") {
        let formats = schema
            .pointer("/properties/contentFormat/enum")?
            .as_array()?;
        if !formats.contains(format) {
            return None;
        }
    }
    let mut example = example.clone();
    if let Some(value) = inputs.get("url").and_then(Value::as_str) {
        // Descriptors are built before configuration validation. Invalid hosts
        // cannot produce a usable URL example; validation reports them later.
        let mut errors = Vec::new();
        validate_tenant_host("tenant_host", tenant_host, &mut errors);
        if !errors.is_empty() {
            return None;
        }
        let mut url = url::Url::parse(value).expect("valid bundled example URL");
        url.set_host(Some(tenant_host)).ok()?;
        example["inputs"]["url"] = Value::String(url.to_string());
    }
    if let (Some(requested), Some(maximum)) = (
        inputs.get("maxResults").and_then(Value::as_u64),
        schema
            .pointer("/properties/maxResults/maximum")
            .and_then(Value::as_u64),
    ) {
        example["inputs"]["maxResults"] = Value::from(requested.min(maximum));
    }
    Some(example)
}
