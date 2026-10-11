//! Attribution footers appended to rich-content bodies, one function per
//! representation. Each replaces a trailing broker footer instead of
//! stacking a second one.
use agent_access_provider::{
    AttributionCapability, AttributionMutation, ProviderError, ReasonCode,
};
use serde_json::{Value, json};
use std::sync::OnceLock;
use uuid::Uuid;

const START_MARKER: &str = "<!-- agent-access-attribution:start -->";

const END_MARKER: &str = "<!-- agent-access-attribution:end -->";

pub fn append_adf_attribution(
    body: &mut Value,
    capability: AttributionCapability,
    broker_request_id: &str,
) -> Result<AttributionMutation, ProviderError> {
    let Some(content) = body.get_mut("content").and_then(Value::as_array_mut) else {
        return Err(ProviderError::deny(
            ReasonCode::BodyMalformed,
            "ADF body must contain a content array",
        ));
    };
    let deduped = dedupe_final_adf_footer(content);
    content.push(json!({ "type": "rule" }));
    content.push(json!({
        "type": "paragraph",
        "content": [
            {
                "type": "text",
                "text": capability.verb.footer_text(broker_request_id)
            }
        ]
    }));
    Ok(AttributionMutation::new(capability, deduped))
}

pub fn append_confluence_storage_attribution(
    body: &mut String,
    capability: AttributionCapability,
    broker_request_id: &str,
) -> AttributionMutation {
    let deduped = dedupe_final_confluence_storage_footer(body);
    if !body.ends_with('\n') {
        body.push('\n');
    }
    body.push('\n');
    body.push_str(START_MARKER);
    body.push('\n');
    body.push_str("<hr />\n<p><em>");
    body.push_str(&escape_xml_text(
        &capability.verb.footer_text(broker_request_id),
    ));
    body.push_str("</em></p>\n");
    body.push_str(END_MARKER);
    AttributionMutation::new(capability, deduped)
}

pub fn append_gitlab_markdown_attribution(
    body: &mut String,
    capability: AttributionCapability,
    broker_request_id: &str,
) -> AttributionMutation {
    let deduped = dedupe_final_delimited_footer(body);
    while body.ends_with('\n') {
        body.pop();
    }
    body.push_str("\n\n");
    body.push_str(START_MARKER);
    body.push_str("\n\n---\n\n_");
    body.push_str(&capability.verb.footer_text(broker_request_id));
    body.push_str("_\n\n");
    body.push_str(END_MARKER);
    AttributionMutation::new(capability, deduped)
}

fn dedupe_final_adf_footer(content: &mut Vec<Value>) -> bool {
    let Some(last) = content.last() else {
        return false;
    };
    if !is_adf_footer_paragraph(last) {
        return false;
    }
    content.pop();
    if content.last().is_some_and(is_adf_rule) {
        content.pop();
    }
    true
}

fn is_adf_rule(value: &Value) -> bool {
    value.get("type").and_then(Value::as_str) == Some("rule")
}

fn is_adf_footer_paragraph(value: &Value) -> bool {
    if value.get("type").and_then(Value::as_str) != Some("paragraph") {
        return false;
    }
    let text = adf_plain_text(value);
    is_footer_text(&text)
}

fn adf_plain_text(value: &Value) -> String {
    let mut text = String::new();
    collect_adf_text(value, &mut text);
    text
}

fn collect_adf_text(value: &Value, text: &mut String) {
    if value.get("type").and_then(Value::as_str) == Some("text")
        && let Some(segment) = value.get("text").and_then(Value::as_str)
    {
        text.push_str(segment);
    }
    if let Some(content) = value.get("content").and_then(Value::as_array) {
        for node in content {
            collect_adf_text(node, text);
        }
    }
}

fn dedupe_final_confluence_storage_footer(body: &mut String) -> bool {
    if dedupe_final_delimited_footer(body) {
        return true;
    }
    let trimmed = body.trim_end();
    let Some(captures) = confluence_visible_footer_regex().captures(trimmed) else {
        return false;
    };
    let Some(full_match) = captures.get(0) else {
        return false;
    };
    let Some(text_match) = captures.name("text") else {
        return false;
    };
    if !is_footer_text(text_match.as_str()) {
        return false;
    }
    body.truncate(full_match.start());
    true
}

fn dedupe_final_delimited_footer(body: &mut String) -> bool {
    let trimmed_len = body.trim_end().len();
    let trimmed = &body[..trimmed_len];
    if !trimmed.ends_with(END_MARKER) {
        return false;
    }
    let Some(start) = trimmed.rfind(START_MARKER) else {
        return false;
    };
    body.truncate(start);
    true
}

fn is_footer_text(text: &str) -> bool {
    let Some(request_id) = text
        .strip_prefix("Added via Agent Access Broker. Request ID: ")
        .or_else(|| text.strip_prefix("Updated via Agent Access Broker. Request ID: "))
    else {
        return false;
    };
    Uuid::parse_str(request_id).is_ok()
}

fn confluence_visible_footer_regex() -> &'static regex::Regex {
    static REGEX: OnceLock<regex::Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        regex::Regex::new(
            r#"(?is)(?:<hr\s*/?>\s*)?<p>\s*<em>\s*(?P<text>(?:Added|Updated) via Agent Access Broker\. Request ID: [0-9a-fA-F-]{36})\s*</em>\s*</p>\s*$"#,
        )
        .expect("Confluence attribution regex is valid")
    })
}

fn escape_xml_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_provider::{AttributionRepresentation, AttributionVerb};

    const OLD_REQUEST_ID: &str = "00000000-0000-0000-0000-000000000001";
    const NEW_REQUEST_ID: &str = "00000000-0000-0000-0000-000000000002";
    const BODY_ADD: AttributionCapability = AttributionCapability::required(
        AttributionVerb::Add,
        "body",
        AttributionRepresentation::GitlabMarkdown,
    );

    #[test]
    fn markdown_attribution_appends_and_dedupes_final_footer() {
        let capability = BODY_ADD;
        let mut body = format!(
            "body\n\n{START_MARKER}\n\n---\n\n_Added via Agent Access Broker. Request ID: {OLD_REQUEST_ID}_\n\n{END_MARKER}\n"
        );

        let mutation = append_gitlab_markdown_attribution(&mut body, capability, NEW_REQUEST_ID);

        assert!(mutation.deduped);
        assert!(body.contains("body\n\n<!-- agent-access-attribution:start -->"));
        assert!(body.contains(NEW_REQUEST_ID));
        assert!(!body.contains(OLD_REQUEST_ID));
    }

    #[test]
    fn adf_attribution_appends_rule_and_dedupes_final_footer() {
        let capability = AttributionCapability::required(
            AttributionVerb::Update,
            "body",
            AttributionRepresentation::Adf,
        );
        let mut body = json!({
            "type": "doc",
            "version": 1,
            "content": [
                { "type": "paragraph", "content": [{ "type": "text", "text": "body" }] },
                { "type": "rule" },
                {
                    "type": "paragraph",
                    "content": [{
                        "type": "text",
                        "text": format!("Added via Agent Access Broker. Request ID: {OLD_REQUEST_ID}")
                    }]
                }
            ]
        });

        let mutation = append_adf_attribution(&mut body, capability, NEW_REQUEST_ID).unwrap();
        let content = body["content"].as_array().unwrap();

        assert!(mutation.deduped);
        assert_eq!(content.len(), 3);
        assert_eq!(content[1]["type"], "rule");
        assert_eq!(
            content[2]["content"][0]["text"],
            format!("Updated via Agent Access Broker. Request ID: {NEW_REQUEST_ID}")
        );
    }

    #[test]
    fn confluence_storage_dedupes_visible_footer_without_markers() {
        let capability = AttributionCapability::required(
            AttributionVerb::Update,
            "body",
            AttributionRepresentation::ConfluenceStorage,
        );
        let mut body = format!(
            "<p>body</p><hr /><p><em>Added via Agent Access Broker. Request ID: {OLD_REQUEST_ID}</em></p>"
        );

        let mutation = append_confluence_storage_attribution(&mut body, capability, NEW_REQUEST_ID);

        assert!(mutation.deduped);
        assert!(body.contains("<p>body</p>"));
        assert!(body.contains(START_MARKER));
        assert!(body.contains(NEW_REQUEST_ID));
        assert!(!body.contains(OLD_REQUEST_ID));
    }
}
