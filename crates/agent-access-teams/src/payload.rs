use super::*;

const MAX_DEPTH: usize = 32;

pub(crate) fn schema() -> Value {
    let native = json!({"oneOf":[
        {"type":"object","required":["type","attachments"],"not":{"required":["@type"]},"properties":{
            "type":{"const":"message"},"attachments":{"type":"array","minItems":1,"items":{
                "type":"object","required":["contentType","content"],"properties":{
                    "contentType":{"const":"application/vnd.microsoft.card.adaptive"},
                    "content":{"type":"object","required":["type","version","body"],"properties":{
                        "type":{"const":"AdaptiveCard"},"version":{"type":"string","pattern":"^[0-9]+\\.[0-9]+$"},
                        "body":{"type":"array","items":{"type":"object"}}
                    }}
                }
            }}
        }},
        {"type":"object","required":["@type","@context"],"not":{"required":["type"]},"properties":{
            "@type":{"const":"MessageCard"},"@context":{"enum":["http://schema.org/extensions","https://schema.org/extensions"]},
            "summary":{"type":"string","minLength":1,"pattern":"\\S"},"text":{"type":"string","minLength":1,"pattern":"\\S"}
        },"anyOf":[{"required":["summary"]},{"required":["text"]}]}
    ]});
    json!({"type":"object","additionalProperties":false,"required":["destination","contentFormat","content"],"properties":{
        "destination":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"},
        "contentFormat":{"enum":["simple","microsoft"]},"content":{"type":"object"}
    },"oneOf":[
        {"properties":{"contentFormat":{"const":"simple"},"content":{
            "type":"object","additionalProperties":false,"required":["text"],"properties":{
                "text":{"type":"string","minLength":1,"pattern":"\\S"},"title":{"type":"string","minLength":1,"pattern":"\\S"}
            }
        }}},
        {"properties":{"contentFormat":{"const":"microsoft"},"content":native}}
    ]})
}

fn invalid(message: &'static str) -> ProviderError {
    ProviderError::deny(ReasonCode::InputInvalid, message)
}

fn depth_valid(value: &Value, depth: usize) -> bool {
    if depth > MAX_DEPTH {
        return false;
    }
    match value {
        Value::Object(fields) => fields.values().all(|v| depth_valid(v, depth + 1)),
        Value::Array(items) => items.iter().all(|v| depth_valid(v, depth + 1)),
        _ => true,
    }
}

fn nonempty(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|s| !s.trim().is_empty())
}

fn native_valid(value: &Value) -> bool {
    if value.get("type").is_some() && value.get("@type").is_some() {
        return false;
    }
    if value.get("type").and_then(Value::as_str) == Some("message") {
        return value
            .get("attachments")
            .and_then(Value::as_array)
            .is_some_and(|attachments| {
                !attachments.is_empty()
                    && attachments.iter().all(|attachment| {
                        attachment.get("contentType").and_then(Value::as_str)
                            == Some("application/vnd.microsoft.card.adaptive")
                            && attachment.get("content").is_some_and(|card| {
                                card.get("type").and_then(Value::as_str) == Some("AdaptiveCard")
                                    && card.get("version").and_then(Value::as_str).is_some_and(
                                        |version| {
                                            version.split_once('.').is_some_and(|(major, minor)| {
                                                !major.is_empty()
                                                    && !minor.is_empty()
                                                    && major.bytes().all(|b| b.is_ascii_digit())
                                                    && minor.bytes().all(|b| b.is_ascii_digit())
                                            })
                                        },
                                    )
                                    && card
                                        .get("body")
                                        .and_then(Value::as_array)
                                        .is_some_and(|body| body.iter().all(Value::is_object))
                            })
                    })
            });
    }
    value.get("@type").and_then(Value::as_str) == Some("MessageCard")
        && matches!(
            value.get("@context").and_then(Value::as_str),
            Some("http://schema.org/extensions" | "https://schema.org/extensions")
        )
        && ["summary", "text"]
            .into_iter()
            .all(|key| value.get(key).is_none() || nonempty(value.get(key)))
        && (nonempty(value.get("summary")) || nonempty(value.get("text")))
}

pub(crate) fn prepare(inputs: &Value, max_bytes: u64) -> Result<(String, Vec<u8>), ProviderError> {
    if !depth_valid(inputs, 0) {
        return Err(invalid("Teams content exceeds nesting depth 32"));
    }
    let source = serde_json::to_vec(inputs).map_err(|_| invalid("Teams inputs must be JSON"))?;
    if source.len() as u64 > max_bytes {
        return Err(invalid("Teams notification exceeds the payload byte limit"));
    }
    let object = inputs
        .as_object()
        .ok_or_else(|| invalid("Teams inputs must be an object"))?;
    if object.len() != 3
        || object
            .keys()
            .any(|key| !matches!(key.as_str(), "destination" | "contentFormat" | "content"))
    {
        return Err(invalid(
            "Teams inputs require only destination, contentFormat, and content",
        ));
    }
    let destination = inputs
        .get("destination")
        .and_then(Value::as_str)
        .filter(|s| valid_destination(s))
        .ok_or_else(|| invalid("Teams destination must be a canonical destination alias"))?;
    let content = inputs
        .get("content")
        .filter(|v| v.is_object())
        .ok_or_else(|| invalid("Teams content must be an object"))?;
    let outgoing = match inputs.get("contentFormat").and_then(Value::as_str) {
        Some("simple") => {
            if !nonempty(content.get("text"))
                || content.get("title").is_some_and(|v| !nonempty(Some(v)))
                || content
                    .as_object()
                    .unwrap()
                    .keys()
                    .any(|key| !matches!(key.as_str(), "title" | "text"))
            {
                return Err(invalid(
                    "Simple Teams content requires nonempty text and an optional nonempty title",
                ));
            }
            let mut blocks = Vec::new();
            if let Some(title) = content.get("title") {
                blocks.push(json!({"type":"TextBlock","text":title,"weight":"Bolder","wrap":true}));
            }
            blocks.push(json!({"type":"TextBlock","text":content["text"],"wrap":true}));
            json!({"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive","contentUrl":null,
                "content":{"$schema":"http://adaptivecards.io/schemas/adaptive-card.json","type":"AdaptiveCard","version":"1.2","body":blocks}}]})
        }
        Some("microsoft") if native_valid(content) => content.clone(),
        Some("microsoft") => {
            return Err(invalid(
                "Microsoft content requires an Adaptive Card message envelope or MessageCard",
            ));
        }
        _ => return Err(invalid("Teams contentFormat must be simple or microsoft")),
    };
    if !depth_valid(&outgoing, 0) {
        return Err(invalid("Teams content exceeds nesting depth 32"));
    }
    let bytes = serde_json::to_vec(&outgoing).map_err(|_| invalid("Teams content must be JSON"))?;
    if bytes.len() as u64 > max_bytes {
        return Err(invalid("Teams notification exceeds the payload byte limit"));
    }
    Ok((destination.into(), bytes))
}
