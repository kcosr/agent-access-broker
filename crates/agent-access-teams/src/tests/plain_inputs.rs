use super::*;

const PRIVATE: &str = "SYNTHETIC_PAYLOAD_SECRET";
const SIMPLE_TEXT: &str =
    "teams.notification.send content.text must be a nonempty string with contentFormat simple";
const SIMPLE_TITLE: &str = "teams.notification.send content.title must be a nonempty string when supplied with contentFormat simple";
const SIMPLE_EXTRA: &str =
    "teams.notification.send content with contentFormat simple accepts only title and text";
const DISCRIMINATORS: &str = "teams.notification.send content accepts type or @type, not both";
const NATIVE_KIND: &str = "teams.notification.send content with contentFormat microsoft requires type message or @type MessageCard";
const ATTACHMENTS: &str =
    "teams.notification.send content.attachments must be a nonempty array with type message";
const ATTACHMENT_TYPE: &str = "teams.notification.send content.attachments[].contentType must be application/vnd.microsoft.card.adaptive";
const CARD_OBJECT: &str =
    "teams.notification.send content.attachments[].content must be an Adaptive Card object";
const CARD_TYPE: &str =
    "teams.notification.send content.attachments[].content.type must be AdaptiveCard";
const CARD_VERSION: &str = "teams.notification.send content.attachments[].content.version must contain ASCII digits, a dot, and ASCII digits";
const CARD_BODY: &str =
    "teams.notification.send content.attachments[].content.body must be an array of objects";
const CARD_CONTEXT: &str = "teams.notification.send content.@context must be http://schema.org/extensions or https://schema.org/extensions for MessageCard";
const CARD_SUMMARY: &str = "teams.notification.send content.summary must be a nonempty string when supplied for MessageCard";
const CARD_TEXT: &str =
    "teams.notification.send content.text must be a nonempty string when supplied for MessageCard";
const CARD_MISSING: &str =
    "teams.notification.send MessageCard requires content.summary or content.text";

fn input(format: &str, content: Value) -> Value {
    json!({"destination":"release-alerts","contentFormat":format,"content":content})
}

fn adaptive() -> Value {
    json!({"type":"message","attachments":[{
        "contentType":"application/vnd.microsoft.card.adaptive",
        "content":{"type":"AdaptiveCard","version":"1.2","body":[]}
    }]})
}

fn assert_denial(error: ProviderError, message: &str) {
    assert_eq!(error.decision(), Decision::Deny);
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
    assert_eq!(error.reason_code().http_status(), 400);
    assert_eq!(error.message, message);
    assert!(error.result.is_none());
    assert!(error.audit.is_none());
    assert!(error.object_ids.is_none());
    assert!(error.upstream_status.is_none());
    assert!(error.upstream_duration_ms.is_none());
    assert!(error.internal_diagnostic_code.is_none());
    assert!(!format!("{error:?}").contains(PRIVATE));
}

#[test]
fn plain_schema_exposes_rules_without_restricting_microsoft_extensions() {
    let schema = payload::schema();
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["required"],
        json!(["destination", "contentFormat", "content"])
    );
    assert_eq!(
        schema["properties"]["destination"]["pattern"],
        "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"
    );
    assert_eq!(
        schema["properties"]["contentFormat"]["enum"],
        json!(["simple", "microsoft"])
    );
    let content = &schema["properties"]["content"];
    assert_eq!(content["type"], "object");
    assert!(content.get("additionalProperties").is_none());
    assert!(content.get("required").is_none());
    assert_eq!(content["properties"].as_object().unwrap().len(), 7);
    for object in [&schema, content] {
        for keyword in ["oneOf", "anyOf", "allOf", "if", "then", "else", "not"] {
            assert!(object.get(keyword).is_none(), "{keyword}: {object}");
        }
        for property in object["properties"].as_object().unwrap().values() {
            assert!(!property["description"].as_str().unwrap().is_empty());
        }
    }
    for field in ["title", "text", "summary", "attachments", "@context"] {
        let property = content["properties"][field].as_object().unwrap();
        assert_eq!(property.len(), 1, "{field}: {property:?}");
        assert!(property.contains_key("description"));
    }
    assert_eq!(content["properties"]["type"]["const"], "message");
    assert_eq!(content["properties"]["@type"]["const"], "MessageCard");
}

#[test]
fn retained_root_and_discriminator_constraints_still_refuse_invalid_inputs() {
    let validator = jsonschema::validator_for(&payload::schema()).unwrap();
    let cases = [
        (json!(null), "Teams inputs must be an object"),
        (json!([]), "Teams inputs must be an object"),
        (
            json!({}),
            "Teams inputs require only destination, contentFormat, and content",
        ),
        (
            json!({"destination":"release-alerts","contentFormat":"simple"}),
            "Teams inputs require only destination, contentFormat, and content",
        ),
        (
            json!({"destination":"release-alerts","contentFormat":"simple","content":{"text":"hello"},PRIVATE:PRIVATE}),
            "Teams inputs require only destination, contentFormat, and content",
        ),
        (
            json!({"destination":null,"contentFormat":"simple","content":{"text":"hello"}}),
            "Teams destination must be a canonical destination alias",
        ),
        (
            json!({"destination":"https://example.com","contentFormat":"simple","content":{"text":"hello"}}),
            "Teams destination must be a canonical destination alias",
        ),
        (
            input("simple", json!(null)),
            "Teams content must be an object",
        ),
        (
            input("other", json!({"text":"hello"})),
            "Teams contentFormat must be simple or microsoft",
        ),
        (
            json!({"destination":"release-alerts","contentFormat":null,"content":{"text":"hello"}}),
            "Teams contentFormat must be simple or microsoft",
        ),
        (input("microsoft", json!({"type":null})), NATIVE_KIND),
        (input("microsoft", json!({"@type":PRIVATE})), NATIVE_KIND),
        (
            input("microsoft", json!({"type":null,"@type":"MessageCard"})),
            DISCRIMINATORS,
        ),
        (
            input("microsoft", json!({"type":"message","@type":null})),
            DISCRIMINATORS,
        ),
    ];
    for (value, message) in cases {
        assert!(!validator.is_valid(&value), "{value}");
        assert_denial(
            payload::prepare(&value, MAX_BODY_BYTES).unwrap_err(),
            message,
        );
    }
}

fn relationship_cases() -> Vec<(Value, &'static str)> {
    let mut cases = vec![
        (input("simple", json!({})), SIMPLE_TEXT),
        (
            input("simple", json!({"text":"ok",PRIVATE:PRIVATE})),
            SIMPLE_EXTRA,
        ),
        (
            input("simple", json!({"text":"ok","summary":null})),
            SIMPLE_EXTRA,
        ),
        (
            input("simple", json!({"text":"ok","title":null,PRIVATE:PRIVATE})),
            SIMPLE_TITLE,
        ),
        (
            input("simple", json!({"text":null,"title":null,PRIVATE:PRIVATE})),
            SIMPLE_TEXT,
        ),
        (input("microsoft", json!({})), NATIVE_KIND),
        (input("microsoft", json!({"text":"hi"})), NATIVE_KIND),
        (
            input("microsoft", json!({"type":"message","@type":"MessageCard"})),
            DISCRIMINATORS,
        ),
        (input("microsoft", json!({"type":"message"})), ATTACHMENTS),
        (
            input("microsoft", json!({"@type":"MessageCard"})),
            CARD_CONTEXT,
        ),
        (
            input(
                "microsoft",
                json!({"@type":"MessageCard","@context":"http://schema.org/extensions"}),
            ),
            CARD_MISSING,
        ),
    ];
    for value in [
        Value::Null,
        json!(false),
        json!(7),
        json!([]),
        json!({}),
        json!(""),
        json!(" \t\n"),
    ] {
        cases.push((input("simple", json!({"text":value})), SIMPLE_TEXT));
        cases.push((
            input("simple", json!({"text":"hello","title":value})),
            SIMPLE_TITLE,
        ));
        let mut card = message_card();
        card["summary"] = value.clone();
        card["text"] = json!("hello");
        cases.push((input("microsoft", card), CARD_SUMMARY));
        let mut card = message_card();
        card["text"] = value;
        cases.push((input("microsoft", card), CARD_TEXT));
    }
    for value in [Value::Null, json!({}), json!(PRIVATE), json!([])] {
        cases.push((
            input("microsoft", json!({"type":"message","attachments":value})),
            ATTACHMENTS,
        ));
    }
    for attachment in [
        Value::Null,
        json!(PRIVATE),
        json!({}),
        json!({"contentType":PRIVATE}),
    ] {
        cases.push((
            input(
                "microsoft",
                json!({"type":"message","attachments":[attachment]}),
            ),
            ATTACHMENT_TYPE,
        ));
    }
    for value in [Value::Null, json!(PRIVATE), json!([])] {
        let mut content = adaptive();
        content["attachments"][0]["content"] = value;
        cases.push((input("microsoft", content), CARD_OBJECT));
    }
    let mut content = adaptive();
    content["attachments"][0]
        .as_object_mut()
        .unwrap()
        .remove("content");
    cases.push((input("microsoft", content), CARD_OBJECT));
    let mut content = adaptive();
    content["attachments"][0]["content"] = json!({});
    cases.push((input("microsoft", content), CARD_TYPE));
    for field in ["type", "version", "body"] {
        let mut content = adaptive();
        content["attachments"][0]["content"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        cases.push((
            input("microsoft", content),
            match field {
                "type" => CARD_TYPE,
                "version" => CARD_VERSION,
                _ => CARD_BODY,
            },
        ));
    }
    for value in [
        Value::Null,
        json!(1.2),
        json!("1"),
        json!("1.2.3"),
        json!(".2"),
        json!("1."),
        json!("+1.2"),
        json!("1.-2"),
        json!("١.٢"),
        json!(PRIVATE),
    ] {
        let mut content = adaptive();
        content["attachments"][0]["content"]["version"] = value;
        cases.push((input("microsoft", content), CARD_VERSION));
    }
    for value in [
        Value::Null,
        json!({}),
        json!(PRIVATE),
        json!([null]),
        json!([{}, 1]),
    ] {
        let mut content = adaptive();
        content["attachments"][0]["content"]["body"] = value;
        cases.push((input("microsoft", content), CARD_BODY));
    }
    for value in [
        Value::Null,
        json!(7),
        json!(PRIVATE),
        json!("https://schema.org/extensions/"),
    ] {
        let mut card = message_card();
        card["@context"] = value;
        cases.push((input("microsoft", card), CARD_CONTEXT));
    }
    let mut card = message_card();
    card["summary"] = json!(null);
    card["text"] = json!(null);
    cases.push((input("microsoft", card), CARD_SUMMARY));
    // Stop at the first attachment's invalid body, before the next one's type.
    let mut content = adaptive();
    content["attachments"][0]["content"]["body"] = json!(PRIVATE);
    content["attachments"]
        .as_array_mut()
        .unwrap()
        .push(json!({}));
    cases.push((input("microsoft", content), CARD_BODY));
    cases
}

#[tokio::test]
async fn visible_relationship_rules_deny_at_preparation_scope_and_invoke_before_transport() {
    let validator = jsonschema::validator_for(&payload::schema()).unwrap();
    let transport = Arc::new(AcceptTransport(std::sync::atomic::AtomicUsize::new(0)));
    let provider = TeamsProvider {
        transport: transport.clone(),
        allowed_upstream_hosts: vec![format!("{ORIGIN}/**")],
        max_bytes: MAX_BODY_BYTES,
    };
    for (value, message) in relationship_cases() {
        assert!(
            validator.is_valid(&value),
            "relationship belongs to the provider: {value}"
        );
        assert_denial(
            payload::prepare(&value, MAX_BODY_BYTES).unwrap_err(),
            message,
        );
        assert_denial(provider.local_scopes(ACTION, &value).unwrap_err(), message);
        // Deliberately omit admitted attributes: payload errors must precede
        // endpoint inspection and every outbound operation.
        let invocation = InvocationBuilder::new("teams", ACTION)
            .inputs(value)
            .build();
        assert_denial(provider.invoke(invocation).await.unwrap_err(), message);
    }
    assert_eq!(transport.0.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[test]
fn microsoft_extensions_and_supported_structures_are_forwarded_unchanged() {
    let validator = jsonschema::validator_for(&payload::schema()).unwrap();
    let mut contents = Vec::new();
    for value in [
        Value::Null,
        json!(true),
        json!(7),
        json!(PRIVATE),
        json!([]),
        json!([null,{"contentType":false}]),
        json!({"type":"wrong","version":false}),
    ] {
        for field in ["title", "attachments"] {
            let mut card = message_card();
            card[field] = value.clone();
            contents.push(card);
        }
        for field in ["title", "text", "summary", "@context"] {
            let mut envelope = adaptive();
            envelope[field] = value.clone();
            contents.push(envelope);
        }
    }
    let mut explicit_message_card = message_card();
    explicit_message_card["title"] = json!(7);
    explicit_message_card["attachments"] = json!("extension");
    contents.push(explicit_message_card);
    for context in [
        "http://schema.org/extensions",
        "https://schema.org/extensions",
    ] {
        for body in [
            json!({"summary":"summary"}),
            json!({"text":"text"}),
            json!({"summary":"summary","text":"text"}),
        ] {
            let mut card = body;
            card["@type"] = json!("MessageCard");
            card["@context"] = json!(context);
            contents.push(card);
        }
    }
    for version in ["0.0", "00.02", "123.456"] {
        for body in [
            json!([]),
            json!([{}]),
            json!([{PRIVATE:[1,null,{"open":true}]}]),
        ] {
            let mut envelope = adaptive();
            envelope[PRIVATE] = json!({"nested":PRIVATE});
            envelope["attachments"][0][PRIVATE] = json!(PRIVATE);
            envelope["attachments"][0]["content"][PRIVATE] = json!(null);
            envelope["attachments"][0]["content"]["version"] = json!(version);
            envelope["attachments"][0]["content"]["body"] = body;
            contents.push(envelope);
        }
    }
    for content in contents {
        let value = input("microsoft", content.clone());
        assert!(validator.is_valid(&value), "{value}");
        let (destination, bytes) = payload::prepare(&value, MAX_BODY_BYTES).unwrap();
        assert_eq!(destination, "release-alerts");
        assert_eq!(bytes, serde_json::to_vec(&content).unwrap());
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), content);
    }
}

#[test]
fn simple_conversion_preserves_text_and_title_whitespace() {
    for content in [
        json!({"text":" \thello\n"}),
        json!({"title":"  heading  ","text":" \thello\n"}),
    ] {
        let value = input("simple", content.clone());
        assert!(jsonschema::is_valid(&payload::schema(), &value));
        let (_, bytes) = payload::prepare(&value, MAX_BODY_BYTES).unwrap();
        let outgoing: Value = serde_json::from_slice(&bytes).unwrap();
        let mut blocks = Vec::new();
        if let Some(title) = content.get("title") {
            blocks.push(json!({"type":"TextBlock","text":title,"weight":"Bolder","wrap":true}));
        }
        blocks.push(json!({"type":"TextBlock","text":content["text"],"wrap":true}));
        assert_eq!(
            outgoing,
            json!({"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive","contentUrl":null,"content":{"$schema":"http://adaptivecards.io/schemas/adaptive-card.json","type":"AdaptiveCard","version":"1.2","body":blocks}}]})
        );
    }
}

#[test]
fn payload_bounds_and_validation_order_remain_independent_of_schema() {
    let (_, bytes) = payload::prepare(&simple(), MAX_BODY_BYTES).unwrap();
    assert!(payload::prepare(&simple(), bytes.len() as u64).is_ok());
    assert_denial(
        payload::prepare(&simple(), bytes.len() as u64 - 1).unwrap_err(),
        "Teams notification exceeds the payload byte limit",
    );
    let value = input("microsoft", message_card());
    let source_len = serde_json::to_vec(&value).unwrap().len() as u64;
    assert!(payload::prepare(&value, source_len).is_ok());
    assert_denial(
        payload::prepare(&value, source_len - 1).unwrap_err(),
        "Teams notification exceeds the payload byte limit",
    );
    for (nesting, accepted) in [(30, true), (31, false)] {
        let mut nested = json!(null);
        for _ in 0..nesting {
            nested = json!({"next":nested});
        }
        let mut content = message_card();
        content["extension"] = nested;
        let value = input("microsoft", content);
        if accepted {
            assert!(payload::prepare(&value, MAX_BODY_BYTES).is_ok());
        } else {
            assert_denial(
                payload::prepare(&value, MAX_BODY_BYTES).unwrap_err(),
                "Teams content exceeds nesting depth 32",
            );
            // Source depth is checked before source bytes or root fields.
            assert_denial(
                payload::prepare(&value, 1).unwrap_err(),
                "Teams content exceeds nesting depth 32",
            );
        }
    }
    assert_denial(
        payload::prepare(&json!(PRIVATE), 1).unwrap_err(),
        "Teams notification exceeds the payload byte limit",
    );
    let invalid = json!({"destination":null,"contentFormat":null,"content":null});
    assert_denial(
        payload::prepare(&invalid, MAX_BODY_BYTES).unwrap_err(),
        "Teams destination must be a canonical destination alias",
    );
    let invalid = json!({"destination":"release-alerts","contentFormat":null,"content":null});
    assert_denial(
        payload::prepare(&invalid, MAX_BODY_BYTES).unwrap_err(),
        "Teams content must be an object",
    );
}
