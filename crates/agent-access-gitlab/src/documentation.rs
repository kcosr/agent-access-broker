//! Extended action guidance, excluded from initial tool discovery.
use super::*;
use std::sync::OnceLock;

fn guidance() -> &'static BTreeMap<String, Value> {
    static GUIDANCE: OnceLock<BTreeMap<String, Value>> = OnceLock::new();
    GUIDANCE.get_or_init(|| {
        serde_json::from_str(include_str!("action-documentation.json"))
            .expect("built-in GitLab action documentation is valid JSON")
    })
}

pub(super) fn apply(
    mut action: ActionDescriptor,
    config: &GitlabProviderConfig,
) -> ActionDescriptor {
    let Some(additions) = guidance().get(action.action.as_str()) else {
        return action;
    };
    let mut additions = additions.as_object().unwrap().clone();
    if let Some(examples) = additions.get_mut("inputExamples") {
        for example in examples.as_array_mut().unwrap() {
            let inputs = &mut example["inputs"];
            if let Some(category) = action.action.strip_prefix("search.") {
                // Explicitly name a configured engine in the example. Invocation
                // still uses the configured default when callers omit engine.
                let engines = config.search.enabled_engines(category);
                let engine = engines
                    .iter()
                    .copied()
                    .find(|engine| *engine == config.search.default_engine)
                    .unwrap_or(engines[0]);
                inputs["engine"] = json!(engine);
                if !config.search.supports(engine, category, false) {
                    inputs["project"] = json!("team/project");
                } else if !config.search.supports(engine, category, true) {
                    inputs.as_object_mut().unwrap().remove("project");
                }
            }
            if let (Some(size), Some(maximum)) = (
                inputs.get("maxResults").and_then(Value::as_u64),
                action.input_schema["properties"]["maxResults"]["maximum"].as_u64(),
            ) {
                inputs["maxResults"] = json!(size.min(maximum));
            }
            if action.action == "project.upload" {
                let bytes = upload_example_bytes(config);
                let metadata = &mut inputs["attachments"][0];
                metadata["size"] = json!(bytes.len());
                metadata["sha256"] = json!(format!("{:x}", Sha256::digest(bytes)));
                metadata["contentType"] = json!(
                    config
                        .attachments
                        .media_types
                        .first()
                        .map(String::as_str)
                        .unwrap_or("text/plain")
                );
            }
        }
    }
    if action.action == "project.upload" {
        additions.insert(
            "uploadExample".into(),
            json!({
                "field":"file0",
                "bytesUtf8":std::str::from_utf8(upload_example_bytes(config)).unwrap(),
                "usage":"Byte-matching multipart fixture. Supply an actual file and matching metadata for the intended content type. JSON metadata alone does not upload a file."
            }),
        );
    }
    let documentation = action.documentation.get_or_insert_with(|| json!({}));
    let documentation = documentation.as_object_mut().unwrap();
    for (key, value) in additions {
        assert!(
            !documentation.contains_key(&key),
            "GitLab {} documentation key {key} must have one owner",
            action.action
        );
        documentation.insert(key, value);
    }
    action
}

fn upload_example_bytes(config: &GitlabProviderConfig) -> &'static [u8] {
    let maximum = config
        .attachments
        .max_bytes
        .min(config.attachments.max_total_bytes)
        .min(5) as usize;
    &b"hello"[..maximum]
}
