use super::*;

const MAX_DEPTH: usize = 32;

pub(crate) fn schema() -> Value {
    json!({"type":"object","additionalProperties":false,"required":["destination","contentFormat","content"],"properties":{
        "destination":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$",
            "description":"Configured Teams destination alias. Do not provide a channel ID or signed Workflow URL."},
        "contentFormat":{"enum":["simple","microsoft"],
            "description":"Content format. simple requires content.text and allows optional content.title only. microsoft requires an Adaptive Card message envelope or MessageCard in content."},
        "content":{"type":"object",
            "description":"Notification object selected by contentFormat. For simple, give text and optional title only. For microsoft, give exactly one of type or @type and the fields described below.",
            "properties":{
                "title":{"description":"With contentFormat simple, optional nonempty string. Microsoft payloads may carry any extension value."},
                "text":{"description":"Required when contentFormat is simple: a nonempty string. With @type MessageCard, give at least one of text or summary; every supplied text must be a nonempty string. Adaptive envelopes may carry any extension value."},
                "summary":{"description":"Only with contentFormat microsoft. With @type MessageCard, give at least one of summary or text; every supplied summary must be a nonempty string. Adaptive envelopes may carry any extension value."},
                "attachments":{"description":"Only with contentFormat microsoft. Required with type message: a nonempty array of attachments with contentType application/vnd.microsoft.card.adaptive and content containing type AdaptiveCard, a numeric dotted version string, and body array of objects. MessageCard may carry any extension value."},
                "@context":{"description":"Only with contentFormat microsoft. Required with @type MessageCard: http://schema.org/extensions or https://schema.org/extensions. Adaptive envelopes may carry any extension value."},
                "type":{"const":"message","description":"Only with contentFormat microsoft. For an Adaptive Card envelope use message and supply attachments. Give exactly one of type or @type; do not combine with @type."},
                "@type":{"const":"MessageCard","description":"Only with contentFormat microsoft. For a MessageCard use MessageCard. Give exactly one of @type or type. Requires @context and at least one of summary or text; do not combine with type."}
            }
        }
    }})
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

fn validate_native(value: &Value) -> Result<(), ProviderError> {
    if value.get("type").is_some() && value.get("@type").is_some() {
        return Err(invalid(
            "teams.notification.send content accepts type or @type, not both",
        ));
    }
    if value.get("type").and_then(Value::as_str) == Some("message") {
        let attachments = value.get("attachments").and_then(Value::as_array)
            .filter(|attachments| !attachments.is_empty())
            .ok_or_else(|| invalid("teams.notification.send content.attachments must be a nonempty array with type message"))?;
        for attachment in attachments {
            if attachment.get("contentType").and_then(Value::as_str)
                != Some("application/vnd.microsoft.card.adaptive")
            {
                return Err(invalid(
                    "teams.notification.send content.attachments[].contentType must be application/vnd.microsoft.card.adaptive",
                ));
            }
            let card = attachment.get("content").filter(|card| card.is_object())
                .ok_or_else(|| invalid("teams.notification.send content.attachments[].content must be an Adaptive Card object"))?;
            if card.get("type").and_then(Value::as_str) != Some("AdaptiveCard") {
                return Err(invalid(
                    "teams.notification.send content.attachments[].content.type must be AdaptiveCard",
                ));
            }
            if !card
                .get("version")
                .and_then(Value::as_str)
                .is_some_and(|version| {
                    version.split_once('.').is_some_and(|(major, minor)| {
                        !major.is_empty()
                            && !minor.is_empty()
                            && major.bytes().all(|b| b.is_ascii_digit())
                            && minor.bytes().all(|b| b.is_ascii_digit())
                    })
                })
            {
                return Err(invalid(
                    "teams.notification.send content.attachments[].content.version must contain ASCII digits, a dot, and ASCII digits",
                ));
            }
            if !card
                .get("body")
                .and_then(Value::as_array)
                .is_some_and(|body| body.iter().all(Value::is_object))
            {
                return Err(invalid(
                    "teams.notification.send content.attachments[].content.body must be an array of objects",
                ));
            }
        }
        return Ok(());
    }
    if value.get("@type").and_then(Value::as_str) != Some("MessageCard") {
        return Err(invalid(
            "teams.notification.send content with contentFormat microsoft requires type message or @type MessageCard",
        ));
    }
    if !matches!(
        value.get("@context").and_then(Value::as_str),
        Some("http://schema.org/extensions" | "https://schema.org/extensions")
    ) {
        return Err(invalid(
            "teams.notification.send content.@context must be http://schema.org/extensions or https://schema.org/extensions for MessageCard",
        ));
    }
    if value
        .get("summary")
        .is_some_and(|value| !nonempty(Some(value)))
    {
        return Err(invalid(
            "teams.notification.send content.summary must be a nonempty string when supplied for MessageCard",
        ));
    }
    if value
        .get("text")
        .is_some_and(|value| !nonempty(Some(value)))
    {
        return Err(invalid(
            "teams.notification.send content.text must be a nonempty string when supplied for MessageCard",
        ));
    }
    if !nonempty(value.get("summary")) && !nonempty(value.get("text")) {
        return Err(invalid(
            "teams.notification.send MessageCard requires content.summary or content.text",
        ));
    }
    Ok(())
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
            if !nonempty(content.get("text")) {
                return Err(invalid(
                    "teams.notification.send content.text must be a nonempty string with contentFormat simple",
                ));
            }
            if content
                .get("title")
                .is_some_and(|value| !nonempty(Some(value)))
            {
                return Err(invalid(
                    "teams.notification.send content.title must be a nonempty string when supplied with contentFormat simple",
                ));
            }
            if content
                .as_object()
                .unwrap()
                .keys()
                .any(|key| !matches!(key.as_str(), "title" | "text"))
            {
                return Err(invalid(
                    "teams.notification.send content with contentFormat simple accepts only title and text",
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
        Some("microsoft") => {
            validate_native(content)?;
            content.clone()
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
