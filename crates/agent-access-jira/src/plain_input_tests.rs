use super::*;

const LOCATOR_BINDINGS: &[(&str, &str, &str)] = &[
    ("issue.view", "issue", "url"),
    ("issue.update", "issue", "url"),
    ("issue.child.create", "parentIssue", "parentUrl"),
    ("issue.parent.set", "issue", "url"),
    ("issue.parent.set", "parentIssue", "parentUrl"),
    ("issue.dependency.add", "blockingIssue", "blockingUrl"),
    ("issue.dependency.add", "blockedIssue", "blockedUrl"),
    ("comment.list", "issue", "url"),
    ("comment.view", "issue", "url"),
    ("comment.add", "issue", "url"),
    ("comment.reply", "issue", "url"),
    ("comment.update", "issue", "url"),
    ("comment.delete", "issue", "url"),
    ("comment.property.list", "issue", "url"),
    ("comment.property.get", "issue", "url"),
    ("comment.property.set", "issue", "url"),
    ("comment.property.delete", "issue", "url"),
    ("attachment.list", "issue", "url"),
];

const CONTENT_ACTIONS: &[&str] = &[
    "issue.create",
    "issue.child.create",
    "issue.update",
    "comment.add",
    "comment.reply",
    "comment.update",
];

fn config(comments: bool) -> JiraProviderConfig {
    let mut config: JiraProviderConfig =
        serde_json::from_value(json!({"tenant_host": "example.atlassian.net"})).unwrap();
    if comments {
        config.content.comment_formats = vec!["adf".into()];
    }
    config
}

fn inputs(action: &str) -> Value {
    match action {
        "issue.create" => json!({
            "project": "PROJ", "issueTypeId": "10001", "summary": "caller-secret"
        }),
        "issue.child.create" => json!({
            "project": "PROJ", "issueTypeId": "10001", "summary": "caller-secret",
            "parentIssue": "PROJ-2"
        }),
        "issue.update" => json!({"issue": "PROJ-1", "summary": "caller-secret"}),
        "issue.parent.set" => json!({"issue": "PROJ-1", "parentIssue": "PROJ-2"}),
        "issue.dependency.add" => json!({"blockingIssue": "PROJ-1", "blockedIssue": "PROJ-2"}),
        "comment.add" => json!({
            "issue": "PROJ-1", "contentFormat": "plain_text", "content": "caller-secret"
        }),
        "comment.reply" => json!({
            "issue": "PROJ-1", "parentCommentId": "123",
            "contentFormat": "plain_text", "content": "caller-secret"
        }),
        "comment.update" => json!({
            "issue": "PROJ-1", "commentId": "123",
            "contentFormat": "plain_text", "content": "caller-secret"
        }),
        "comment.view" | "comment.delete" | "comment.property.list" => {
            json!({"issue": "PROJ-1", "commentId": "123"})
        }
        "comment.property.get" | "comment.property.delete" => json!({
            "issue": "PROJ-1", "commentId": "123", "propertyKey": "agent-access.test"
        }),
        "comment.property.set" => json!({
            "issue": "PROJ-1", "commentId": "123", "propertyKey": "agent-access.test",
            "value": {"text": "caller-secret"}
        }),
        _ => json!({"issue": "PROJ-1"}),
    }
}

// These are the production parsers called at invocation. Scope-only create
// checks are tested separately: they validate fewer fields before authorization.
fn parse_full(
    action: &str,
    inputs: &Value,
    config: &JiraProviderConfig,
) -> Result<Option<(Value, ContentWriteAudit)>, ProviderError> {
    match action {
        "issue.create" => parse_issue_create_inputs(inputs, config)
            .map(|parsed| parsed.description.zip(parsed.content_audit)),
        "issue.child.create" => parse_issue_child_create_inputs(inputs, config)
            .map(|parsed| parsed.description.zip(parsed.content_audit)),
        "issue.update" => parse_issue_update_inputs(inputs, config)
            .map(|parsed| parsed.description.zip(parsed.content_audit)),
        "comment.add" => parse_comment_add_inputs(inputs, config)
            .map(|parsed| Some((parsed.body, parsed.content_audit))),
        "comment.reply" => parse_comment_reply_inputs(inputs, config)
            .map(|parsed| Some((parsed.body, parsed.content_audit))),
        "comment.update" => parse_comment_update_inputs(inputs, config)
            .map(|parsed| Some((parsed.body, parsed.content_audit))),
        "issue.parent.set" => parse_issue_parent_set_inputs(inputs, config).map(|_| None),
        "issue.dependency.add" => parse_issue_dependency_add_inputs(inputs, config).map(|_| None),
        _ => issue_locator_for_action(action, inputs, config).map(|_| None),
    }
}

fn assert_denial(error: ProviderError, reason: ReasonCode, message: Option<&str>) {
    assert_eq!(error.reason_code(), reason, "{}", error.message);
    let status = match reason {
        ReasonCode::InputInvalid | ReasonCode::BodyMalformed => 400,
        ReasonCode::LocatorInvalid => 403,
        ReasonCode::BodySizeDenied => 413,
        ReasonCode::BodyFormatUnsupported => 415,
        _ => panic!("unexpected test reason"),
    };
    assert_eq!(error.reason_code().http_status(), status);
    assert_eq!(error.decision(), Decision::Deny);
    assert!(error.result.is_none());
    assert!(error.audit.is_none());
    assert!(error.object_ids.is_none());
    assert!(error.upstream_status.is_none());
    assert!(error.upstream_duration_ms.is_none());
    if let Some(message) = message {
        assert_eq!(error.message, message);
    }
    for value in ["caller-secret", "PROJ-1", "PROJ-2", "example.atlassian.net"] {
        assert!(!error.message.contains(value), "{}", error.message);
    }
}

#[test]
fn plain_schemas_keep_fields_requirements_and_content_formats() {
    for comments in [false, true] {
        let descriptor = jira_descriptor(&config(comments));
        assert_eq!(descriptor.validate(), Ok(()));
        assert_eq!(descriptor.actions.len(), if comments { 24 } else { 21 });
        for action in &descriptor.actions {
            let schema = &action.input_schema;
            assert_eq!(schema["type"], "object", "{}", action.action);
            assert!(schema["properties"].is_object(), "{}", action.action);
            assert_eq!(schema["additionalProperties"], false, "{}", action.action);
            for keyword in ["oneOf", "anyOf", "allOf", "if", "then", "else", "not"] {
                assert!(schema.get(keyword).is_none(), "{} {keyword}", action.action);
            }
        }
        for &(action, key, url) in LOCATOR_BINDINGS {
            let Some(action) = descriptor.action(action) else {
                assert!(!comments && CONTENT_ACTIONS.contains(&action));
                continue;
            };
            for field in [key, url] {
                let property = &action.input_schema["properties"][field];
                assert_eq!(property["type"], "string");
                assert!(
                    property["description"]
                        .as_str()
                        .unwrap()
                        .contains(&format!("Give exactly one of {key} or {url}."))
                );
                assert!(
                    !action.input_schema["required"]
                        .as_array()
                        .is_some_and(|required| required.contains(&json!(field)))
                );
            }
        }
        for &action in CONTENT_ACTIONS {
            let Some(action) = descriptor.action(action) else {
                assert!(!comments && action.starts_with("comment."));
                continue;
            };
            let properties = &action.input_schema["properties"];
            assert_eq!(properties["content"]["type"], json!(["string", "object"]));
            assert!(properties["content"].get("additionalProperties").is_none());
            assert_eq!(
                properties["contentFormat"]["enum"],
                json!(["adf", "markdown", "plain_text"])
            );
            for (field, paired) in [("content", "contentFormat"), ("contentFormat", "content")] {
                assert!(
                    properties[field]["description"]
                        .as_str()
                        .unwrap()
                        .contains(&format!("Required with {paired}."))
                );
            }
        }
        for (action, required) in [
            ("issue.create", json!(["project", "issueTypeId", "summary"])),
            (
                "issue.child.create",
                json!(["project", "issueTypeId", "summary"]),
            ),
            ("comment.add", json!(["contentFormat", "content"])),
            (
                "comment.reply",
                json!(["parentCommentId", "contentFormat", "content"]),
            ),
            (
                "comment.update",
                json!(["commentId", "contentFormat", "content"]),
            ),
            ("attachment.add", json!(["issue", "attachments"])),
            ("attachment.download", json!(["issue", "attachmentId"])),
        ] {
            if let Some(action) = descriptor.action(action) {
                assert_eq!(action.input_schema["required"], required);
            }
        }
        let update = &descriptor.action("issue.update").unwrap().input_schema;
        assert!(update.get("required").is_none());
        for field in ["summary", "content"] {
            assert!(
                update["properties"][field]["description"]
                    .as_str()
                    .unwrap()
                    .contains("Give at least one of summary or content.")
            );
        }
    }
}

#[test]
fn locator_matrix_preserves_acceptance_reasons_and_action_specific_messages() {
    let config = config(true);
    for &(action, key, url) in LOCATOR_BINDINGS {
        let baseline = inputs(action);
        assert!(parse_full(action, &baseline, &config).is_ok(), "{action}");
        let mut absent = baseline.clone();
        let issue = absent.as_object_mut().unwrap().remove(key).unwrap();
        let issue_url = json!(format!(
            "https://example.atlassian.net/browse/{}",
            issue.as_str().unwrap()
        ));
        let missing = format!("jira.{action} requires {key} or {url}");
        assert_denial(
            parse_full(action, &absent, &config).unwrap_err(),
            ReasonCode::InputInvalid,
            Some(&missing),
        );
        for field in [key, url] {
            let mut null_only = absent.clone();
            null_only[field] = Value::Null;
            assert_denial(
                parse_full(action, &null_only, &config).unwrap_err(),
                ReasonCode::InputInvalid,
                Some(&missing),
            );
        }
        let mut both = baseline.clone();
        both[url] = issue_url.clone();
        assert_denial(
            parse_full(action, &both, &config).unwrap_err(),
            ReasonCode::InputInvalid,
            Some(&format!("jira.{action} accepts {key} or {url}, not both")),
        );
        both[key] = json!("caller-secret");
        both[url] = json!("caller-secret");
        assert_denial(
            parse_full(action, &both, &config).unwrap_err(),
            ReasonCode::InputInvalid,
            Some(&format!("jira.{action} accepts {key} or {url}, not both")),
        );
        let mut url_only = absent.clone();
        url_only[url] = issue_url;
        assert!(parse_full(action, &url_only, &config).is_ok(), "{action}");
        // Option<String> treats explicit null as absent in the full parsers.
        // Child creation has a stricter, separately tested scope hook.
        url_only[key] = Value::Null;
        assert!(parse_full(action, &url_only, &config).is_ok(), "{action}");
        let mut key_with_null_url = baseline.clone();
        key_with_null_url[url] = Value::Null;
        assert!(
            parse_full(action, &key_with_null_url, &config).is_ok(),
            "{action}"
        );
        for field in [key, url] {
            for value in [json!(7), json!([]), json!({"text": "caller-secret"})] {
                let mut wrong_type = absent.clone();
                wrong_type[field] = value;
                assert_denial(
                    parse_full(action, &wrong_type, &config).unwrap_err(),
                    ReasonCode::InputInvalid,
                    Some(&format!("jira.{action} inputs are invalid")),
                );
            }
            let mut malformed = absent.clone();
            malformed[field] = json!("caller-secret");
            assert_denial(
                parse_full(action, &malformed, &config).unwrap_err(),
                ReasonCode::LocatorInvalid,
                None,
            );
        }
        let mut unknown = baseline.clone();
        unknown["unexpected"] = json!("caller-secret");
        for invalid in [unknown, Value::Null, json!([])] {
            assert_denial(
                parse_full(action, &invalid, &config).unwrap_err(),
                ReasonCode::InputInvalid,
                Some(&format!("jira.{action} inputs are invalid")),
            );
        }
    }
}

#[test]
fn content_matrix_preserves_format_validation_and_prepared_audit() {
    let adf = json!({"version": 1, "type": "doc", "content": [
        {"type": "paragraph", "content": [{"type": "text", "text": "caller-secret"}]}
    ]});
    for comments in [false, true] {
        let config = config(comments);
        for &action in CONTENT_ACTIONS {
            if !comments && action.starts_with("comment.") {
                continue;
            }
            for (format, content) in [
                ("adf", adf.clone()),
                ("markdown", json!("caller-secret")),
                ("plain_text", json!("caller-secret")),
            ] {
                let mut input = inputs(action);
                input["contentFormat"] = json!(format);
                input["content"] = content.clone();
                let (body, audit) = parse_full(action, &input, &config).unwrap().unwrap();
                assert_eq!(body["type"], "doc");
                assert_eq!(audit.requested_format, format);
                let expected_bytes = content
                    .as_str()
                    .map_or_else(|| serde_json::to_vec(&content).unwrap().len(), str::len);
                assert_eq!(audit.source_bytes, expected_bytes as u64);
                assert!(audit.final_native_bytes.is_none());

                input["content"] = if format == "adf" {
                    json!("caller-secret")
                } else {
                    adf.clone()
                };
                assert_denial(
                    parse_full(action, &input, &config).unwrap_err(),
                    ReasonCode::InputInvalid,
                    Some(&format!(
                        "jira.{action} content must be {} for {format}",
                        if format == "adf" {
                            "an object"
                        } else {
                            "a string"
                        }
                    )),
                );
                input["content"] = json!([]);
                assert_denial(
                    parse_full(action, &input, &config).unwrap_err(),
                    ReasonCode::InputInvalid,
                    None,
                );
                input["content"] = Value::Null;
                assert_denial(
                    parse_full(action, &input, &config).unwrap_err(),
                    ReasonCode::InputInvalid,
                    Some(&if action.starts_with("issue.") {
                        format!("jira.{action} content must not be null")
                    } else {
                        format!(
                            "jira.{action} content must be {} for {format}",
                            if format == "adf" {
                                "an object"
                            } else {
                                "a string"
                            }
                        )
                    }),
                );
            }
            for (format, content, reason) in [
                (
                    "caller-secret",
                    json!("caller-secret"),
                    ReasonCode::BodyFormatUnsupported,
                ),
                (
                    "adf",
                    json!({"text": "caller-secret"}),
                    ReasonCode::BodyMalformed,
                ),
            ] {
                let mut input = inputs(action);
                input["contentFormat"] = json!(format);
                input["content"] = content;
                assert_denial(
                    parse_full(action, &input, &config).unwrap_err(),
                    reason,
                    None,
                );
            }
            let mut input = inputs(action);
            input["contentFormat"] = json!("plain_text");
            input["content"] = json!("caller-secret");
            for bad_format in [Value::Null, json!(7), json!({"text": "caller-secret"})] {
                input["contentFormat"] = bad_format;
                assert_denial(
                    parse_full(action, &input, &config).unwrap_err(),
                    ReasonCode::InputInvalid,
                    None,
                );
            }
        }
    }
}

#[test]
fn optional_content_pairs_and_update_requirement_preserve_missing_and_null() {
    let config = config(true);
    for &action in CONTENT_ACTIONS {
        let mut absent = inputs(action);
        absent.as_object_mut().unwrap().remove("content");
        absent.as_object_mut().unwrap().remove("contentFormat");
        if action.starts_with("issue.") {
            assert!(parse_full(action, &absent, &config).unwrap().is_none());
        } else {
            assert_denial(
                parse_full(action, &absent, &config).unwrap_err(),
                ReasonCode::InputInvalid,
                Some(&format!("jira.{action} inputs are invalid")),
            );
        }
        for (field, value) in [
            ("content", json!("caller-secret")),
            ("contentFormat", json!("plain_text")),
        ] {
            for value in [value, Value::Null] {
                let mut partial = absent.clone();
                partial[field] = value;
                let message = action
                    .starts_with("issue.")
                    .then(|| format!("jira.{action} requires content and contentFormat together"));
                assert_denial(
                    parse_full(action, &partial, &config).unwrap_err(),
                    ReasonCode::InputInvalid,
                    message.as_deref(),
                );
            }
        }
        let mut null_pair = absent;
        null_pair["content"] = Value::Null;
        null_pair["contentFormat"] = Value::Null;
        assert_denial(
            parse_full(action, &null_pair, &config).unwrap_err(),
            ReasonCode::InputInvalid,
            None,
        );
    }
    assert_denial(
        parse_issue_update_inputs(&json!({"issue": "PROJ-1"}), &config).unwrap_err(),
        ReasonCode::InputInvalid,
        Some("jira.issue.update requires summary or content with contentFormat"),
    );
    for field in ["summary", "notifyUsers"] {
        let mut input = inputs("issue.update");
        input[field] = Value::Null;
        assert_denial(
            parse_issue_update_inputs(&input, &config).unwrap_err(),
            ReasonCode::InputInvalid,
            Some(&format!(
                "jira.issue.update {field} must be a {}",
                if field == "summary" {
                    "string"
                } else {
                    "boolean"
                }
            )),
        );
    }
    let content_only =
        json!({"issue": "PROJ-1", "contentFormat": "plain_text", "content": "caller-secret"});
    let parsed = parse_issue_update_inputs(&content_only, &config).unwrap();
    assert_eq!(parsed.changed_fields(), vec!["description"]);
    assert!(parsed.summary.is_none());
}

#[test]
fn create_scope_keeps_staged_validation_and_strict_parent_nulls() {
    let config = config(true);
    for action in ["issue.create", "issue.child.create"] {
        let baseline = inputs(action);
        for (field, value) in [
            ("content", json!("caller-secret")),
            ("issueTypeId", json!(7)),
            ("summary", Value::Null),
            ("unexpected", json!("caller-secret")),
        ] {
            let mut input = baseline.clone();
            input[field] = value;
            if action == "issue.create" {
                assert!(parse_issue_create_scope_inputs(&input).is_ok());
            } else {
                assert!(parse_issue_child_create_scope_inputs(&input, &config).is_ok());
            }
            assert_denial(
                parse_full(action, &input, &config).unwrap_err(),
                ReasonCode::InputInvalid,
                None,
            );
        }
    }
    let action = "issue.child.create";
    for field in ["parentIssue", "parentUrl"] {
        for wrong_type in [json!(7), json!([]), json!({"text": "caller-secret"})] {
            let mut input = inputs(action);
            input[field] = wrong_type;
            assert_denial(
                parse_issue_child_create_scope_inputs(&input, &config).unwrap_err(),
                ReasonCode::InputInvalid,
                Some(&format!("jira.{action} {field} must be a string")),
            );
        }
    }
    for (field, other) in [("parentIssue", "parentUrl"), ("parentUrl", "parentIssue")] {
        let mut input = inputs(action);
        input["parentUrl"] = json!("https://example.atlassian.net/browse/PROJ-2");
        input[field] = Value::Null;
        assert!(parse_full(action, &input, &config).is_ok());
        assert_denial(
            parse_issue_child_create_scope_inputs(&input, &config).unwrap_err(),
            ReasonCode::InputInvalid,
            Some(&format!("jira.{action} {field} must be a string")),
        );
        input.as_object_mut().unwrap().remove(field);
        assert!(
            parse_issue_child_create_scope_inputs(&input, &config).is_ok(),
            "{other}"
        );
    }
    for (input, message) in [
        (
            json!({"project": "PROJ"}),
            "jira.issue.child.create requires parentIssue or parentUrl",
        ),
        (
            json!({"project": "PROJ", "parentIssue": "PROJ-2", "parentUrl": "https://example.atlassian.net/browse/PROJ-2"}),
            "jira.issue.child.create accepts parentIssue or parentUrl, not both",
        ),
    ] {
        assert_denial(
            parse_issue_child_create_scope_inputs(&input, &config).unwrap_err(),
            ReasonCode::InputInvalid,
            Some(message),
        );
    }
}

#[test]
fn nullable_comment_options_and_property_values_keep_their_meaning() {
    let config = config(true);
    let list = parse_comment_list_inputs(
        &json!({
            "issue": "PROJ-1", "maxResults": null, "startAt": null, "orderBy": null
        }),
        &config,
    )
    .unwrap();
    assert_eq!(list.max_results, config.comments.max_results);
    assert_eq!(list.start_at, 0);
    assert_eq!(list.order_by.as_deref(), Some("+created"));
    assert_denial(
        parse_comment_list_inputs(&json!({"issue": "PROJ-1", "includeBodies": null}), &config)
            .unwrap_err(),
        ReasonCode::InputInvalid,
        None,
    );
    let mut update = inputs("comment.update");
    update["visibilityMode"] = Value::Null;
    update["visibility"] = Value::Null;
    update["notifyUsers"] = Value::Null;
    let update = parse_comment_update_inputs(&update, &config).unwrap();
    assert_eq!(update.visibility_mode, CommentVisibilityMode::Preserve);
    assert!(update.visibility.is_none());
    assert!(!update.notify_users);
    for action in [
        "comment.property.list",
        "comment.property.get",
        "comment.property.delete",
    ] {
        let mut input = inputs(action);
        input["value"] = Value::Null;
        if action == "comment.property.list" {
            input["propertyKey"] = Value::Null;
        }
        assert!(parse_comment_property_inputs(action, &input, &config).is_ok());
        if action != "comment.property.list" {
            input["value"] = json!("caller-secret");
            assert_denial(
                parse_comment_property_inputs(action, &input, &config).unwrap_err(),
                ReasonCode::InputInvalid,
                Some(&format!("jira.{action} must not include value")),
            );
            input["value"] = Value::Null;
            input["propertyKey"] = Value::Null;
            assert_denial(
                parse_comment_property_inputs(action, &input, &config).unwrap_err(),
                ReasonCode::InputInvalid,
                Some(&format!("jira.{action} requires propertyKey")),
            );
        }
    }
    let mut input = inputs("comment.property.set");
    input["value"] = Value::Null;
    assert_denial(
        parse_comment_property_inputs("comment.property.set", &input, &config).unwrap_err(),
        ReasonCode::InputInvalid,
        Some("jira.comment.property.set requires value"),
    );
}

#[test]
fn content_size_denials_keep_priority_over_adf_type_checks() {
    let mut config = config(true);
    config.content.max_body_bytes = 32;
    for &action in CONTENT_ACTIONS {
        for format in ["adf", "markdown", "plain_text"] {
            let mut input = inputs(action);
            input["contentFormat"] = json!(format);
            // An oversized ADF string reaches the byte cap before its type check.
            input["content"] = json!("caller-secret".repeat(4));
            assert_denial(
                parse_full(action, &input, &config).unwrap_err(),
                ReasonCode::BodySizeDenied,
                Some(&format!(
                    "jira.{action} source content exceeded the configured byte cap"
                )),
            );
        }
    }
}
