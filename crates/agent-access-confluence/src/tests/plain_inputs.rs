use super::*;

const WRITE_ACTIONS: &[&str] = &[
    "page.create",
    "page.update",
    "page.draft.create",
    "page.draft.stage",
    "page.draft.update",
    "blog.create",
    "blog.update",
    "blog.draft.create",
    "blog.draft.stage",
    "blog.draft.update",
    "page.footer_comment.add",
    "page.footer_comment.update",
    "page.footer_comment.reply.add",
    "page.inline_comment.update",
    "page.inline_comment.reply.add",
    "blog.footer_comment.add",
    "blog.footer_comment.update",
    "blog.footer_comment.reply.add",
    "blog.inline_comment.update",
    "blog.inline_comment.reply.add",
];

const LOCATORS: &[(&str, &str, &str)] = &[
    ("page.view", "pageId", "url"),
    ("attachment.list", "pageId", "url"),
    ("blog.view", "blogId", "url"),
    ("blog.attachment.list", "blogId", "url"),
    ("page.move", "pageId", "url"),
    ("page.move", "targetPageId", "targetUrl"),
];

fn configurations() -> Vec<(&'static str, ConfluenceProviderConfig, usize)> {
    let all = confluence_config();
    let mut default = all.clone();
    default.content.page_formats.clear();
    let mut disabled = default.clone();
    disabled.content.blog_formats.clear();
    disabled.content.comment_formats.clear();
    let mut text = all.clone();
    text.content.page_formats = vec!["storage".into()];
    let mut object = all.clone();
    object.content.page_formats = vec!["atlas_doc_format".into()];
    vec![
        ("default", default, 62),
        ("content-disabled", disabled, 47),
        ("pages-text-only", text, 64),
        ("pages-object-only", object, 64),
        ("all-enabled", all, 64),
    ]
}

fn write_target(action: &str) -> ConfluenceWriteTarget {
    match action {
        "page.create" | "page.update" => ConfluenceWriteTarget::CurrentPage,
        "page.draft.create" | "page.draft.stage" | "page.draft.update" => {
            ConfluenceWriteTarget::PageDraft
        }
        "blog.create" | "blog.update" | "blog.draft.create" | "blog.draft.stage"
        | "blog.draft.update" => ConfluenceWriteTarget::Blog,
        _ => ConfluenceWriteTarget::Comment,
    }
}

fn write_inputs(action: &str) -> Value {
    let mut inputs = match action {
        "page.create" | "page.draft.create" | "blog.create" | "blog.draft.create" => {
            json!({"space": "ENG", "title": "caller-secret"})
        }
        "page.update" | "page.draft.stage" => json!({"pageId": "100", "baseVersion": 1}),
        "blog.update" | "blog.draft.stage" => json!({"blogId": "100", "baseVersion": 1}),
        "page.draft.update" => {
            json!({"pageId": "100", "draftHandle": format!("{DRAFT_HANDLE_PREFIX}fixture")})
        }
        "blog.draft.update" => {
            json!({"blogId": "100", "draftHandle": format!("{DRAFT_HANDLE_PREFIX}fixture")})
        }
        "page.footer_comment.add" => json!({"pageId": "100"}),
        "blog.footer_comment.add" => json!({"blogId": "100"}),
        _ if action.ends_with(".update") => json!({"commentId": "100", "baseVersion": 1}),
        _ if action.ends_with(".reply.add") => json!({"commentId": "100"}),
        _ => panic!("unexpected write action {action}"),
    };
    inputs["contentFormat"] = json!("storage");
    inputs["content"] = json!("<p>caller-secret</p>");
    inputs
}

// These are shape parsers, not the later content or signed-handle checks.
fn parse_write(
    action: &str,
    inputs: &Value,
    config: &ConfluenceProviderConfig,
) -> Result<(), ProviderError> {
    match action {
        "page.create" => parse_page_create_inputs(inputs, config).map(|_| ()),
        "page.update" => parse_page_update_inputs(inputs).map(|_| ()),
        "page.draft.create" => parse_page_draft_create_inputs(inputs, config).map(|_| ()),
        "page.draft.stage" => parse_page_draft_stage_inputs(inputs).map(|_| ()),
        "page.draft.update" => parse_page_draft_update_inputs(inputs).map(|_| ()),
        "blog.create" => parse_blog_create_inputs(inputs).map(|_| ()),
        "blog.update" => parse_blog_update_inputs(inputs).map(|_| ()),
        "blog.draft.create" => parse_blog_draft_create_inputs(inputs).map(|_| ()),
        "blog.draft.stage" => parse_blog_draft_stage_inputs(inputs).map(|_| ()),
        "blog.draft.update" => parse_blog_draft_update_inputs(inputs).map(|_| ()),
        _ if action.ends_with(".reply.add") => parse_comment_reply_add_inputs(inputs).map(|_| ()),
        _ if action.ends_with(".update") => parse_comment_update_inputs(inputs).map(|_| ()),
        _ => {
            parse_comment_add_inputs(confluence_comment_action(action).unwrap(), inputs).map(|_| ())
        }
    }
}

fn parse_locator(
    action: &str,
    inputs: &Value,
    config: &ConfluenceProviderConfig,
) -> Result<(), ProviderError> {
    match action {
        "page.view" => page_locator_from_inputs(inputs, config).map(|_| ()),
        "attachment.list" => parse_attachment_list_inputs(inputs, config).map(|_| ()),
        "blog.view" => parse_blog_view_inputs(inputs, config).map(|_| ()),
        "blog.attachment.list" => parse_blog_attachment_list_inputs(inputs, config).map(|_| ()),
        "page.move" => parse_page_move_inputs(inputs, config).map(|_| ()),
        _ => panic!("unexpected locator action {action}"),
    }
}

fn assert_denial(error: ProviderError, reason: ReasonCode, message: Option<&str>) {
    assert_eq!(error.reason_code(), reason, "{}", error.message);
    assert_eq!(error.decision(), Decision::Deny);
    let status = match reason {
        ReasonCode::InputInvalid | ReasonCode::BodyMalformed => 400,
        ReasonCode::LocatorInvalid => 403,
        ReasonCode::BodySizeDenied => 413,
        ReasonCode::BodyFormatUnsupported => 415,
        _ => panic!("unexpected reason"),
    };
    assert_eq!(error.reason_code().http_status(), status);
    assert!(error.result.is_none());
    assert!(error.audit.is_none());
    assert!(error.object_ids.is_none());
    assert!(error.upstream_status.is_none());
    assert!(error.upstream_duration_ms.is_none());
    if let Some(message) = message {
        assert_eq!(error.message, message);
    }
    for secret in ["caller-secret", "example.atlassian.net"] {
        assert!(!error.message.contains(secret), "{}", error.message);
    }
}

#[test]
fn schemas_expose_plain_fields_and_effective_content_types() {
    for (name, config, count) in configurations() {
        let descriptor = confluence_descriptor(&config);
        assert_eq!(descriptor.validate(), Ok(()), "{name}");
        assert_eq!(descriptor.actions.len(), count, "{name}");
        for action in &descriptor.actions {
            let schema = &action.input_schema;
            assert_eq!(schema["type"], "object", "{name}/{}", action.action);
            assert!(schema["properties"].is_object());
            assert_eq!(schema["additionalProperties"], false);
            for keyword in ["oneOf", "anyOf", "allOf", "if", "then", "else", "not"] {
                assert!(
                    schema.get(keyword).is_none(),
                    "{name}/{} {keyword}",
                    action.action
                );
            }
        }
        for &(action, id, url) in LOCATORS {
            let schema = &descriptor.action(action).unwrap().input_schema;
            for field in [id, url] {
                assert_eq!(schema["properties"][field]["type"], "string");
                assert_eq!(
                    schema["properties"][field]["description"],
                    format!("Give exactly one of {id} or {url}.")
                );
                assert!(
                    !schema["required"]
                        .as_array()
                        .is_some_and(|required| required.contains(&json!(field)))
                );
            }
        }
        for action in ["page.create", "page.draft.create"] {
            if let Some(action) = descriptor.action(action) {
                let properties = &action.input_schema["properties"];
                assert_eq!(
                    properties["parentPageId"]["description"],
                    "Do not combine with parentUrl."
                );
                assert_eq!(
                    properties["parentUrl"]["description"],
                    "Do not combine with parentPageId."
                );
            }
        }
        for &action in WRITE_ACTIONS {
            let Some(descriptor) = descriptor.action(action) else {
                assert!(
                    name == "content-disabled"
                        || (name == "default" && matches!(action, "page.create" | "page.update"))
                );
                assert!(!action.starts_with("page.draft."));
                continue;
            };
            let schema = &descriptor.input_schema;
            let properties = &schema["properties"];
            let current_page = matches!(action, "page.create" | "page.update");
            let (formats, content_type) = match (current_page, name) {
                (true, "pages-object-only") => (json!(["atlas_doc_format"]), json!("object")),
                (true, "all-enabled") => (
                    json!(["storage", "atlas_doc_format", "markdown", "plain_text"]),
                    json!(["string", "object"]),
                ),
                _ => (
                    json!(["storage", "markdown", "plain_text"]),
                    json!("string"),
                ),
            };
            assert_eq!(
                properties["contentFormat"]["enum"], formats,
                "{name}/{action}"
            );
            assert_eq!(
                properties["content"]["type"], content_type,
                "{name}/{action}"
            );
            assert!(properties["content"].get("additionalProperties").is_none());
            for field in ["content", "contentFormat"] {
                assert!(
                    schema["required"]
                        .as_array()
                        .unwrap()
                        .contains(&json!(field))
                );
                let description = properties[field]["description"].as_str().unwrap();
                for format in formats.as_array().unwrap() {
                    assert!(
                        description.contains(format.as_str().unwrap()),
                        "{name}/{action}/{field}"
                    );
                }
            }
        }
    }
}

#[test]
fn locator_relations_keep_missing_conflict_null_and_shape_outcomes() {
    let config = confluence_config();
    for &(action, id, url) in LOCATORS {
        let mut base = if action == "page.move" {
            json!({"pageId": "100", "position": "append", "targetPageId": "200"})
        } else {
            json!({})
        };
        base.as_object_mut().unwrap().remove(id);
        let value = if id == "targetPageId" { "200" } else { "100" };
        let locator_url =
            format!("https://example.atlassian.net/wiki/pages/viewpage.action?pageId={value}");
        let missing = format!("confluence.{action} requires {id} or {url}");
        let both = format!("confluence.{action} accepts {id} or {url}, not both");
        assert_denial(
            parse_locator(action, &base, &config).unwrap_err(),
            ReasonCode::InputInvalid,
            Some(&missing),
        );
        let mut nulls = base.clone();
        nulls[id] = Value::Null;
        nulls[url] = Value::Null;
        assert_denial(
            parse_locator(action, &nulls, &config).unwrap_err(),
            ReasonCode::InputInvalid,
            Some(&missing),
        );
        let mut conflict = base.clone();
        conflict[id] = json!(value);
        conflict[url] = json!(locator_url);
        assert_denial(
            parse_locator(action, &conflict, &config).unwrap_err(),
            ReasonCode::InputInvalid,
            Some(&both),
        );
        for (chosen, alternative, value) in [(id, url, json!(value)), (url, id, json!(locator_url))]
        {
            let mut valid = base.clone();
            valid[chosen] = value;
            assert!(
                parse_locator(action, &valid, &config).is_ok(),
                "{action}/{chosen}"
            );
            valid[alternative] = Value::Null;
            assert!(
                parse_locator(action, &valid, &config).is_ok(),
                "{action}/{alternative}:null"
            );
            for wrong in [
                json!(7),
                json!({"value": "caller-secret"}),
                json!(["caller-secret"]),
            ] {
                let mut invalid = valid.clone();
                invalid[alternative] = wrong;
                assert_denial(
                    parse_locator(action, &invalid, &config).unwrap_err(),
                    ReasonCode::InputInvalid,
                    None,
                );
            }
            valid["caller-secret"] = json!("caller-secret");
            assert_denial(
                parse_locator(action, &valid, &config).unwrap_err(),
                ReasonCode::InputInvalid,
                None,
            );
        }
        let mut invalid = base.clone();
        invalid[id] = json!("caller-secret");
        assert_denial(
            parse_locator(action, &invalid, &config).unwrap_err(),
            ReasonCode::InputInvalid,
            None,
        );
        invalid.as_object_mut().unwrap().remove(id);
        invalid[url] = json!("caller-secret");
        assert_denial(
            parse_locator(action, &invalid, &config).unwrap_err(),
            ReasonCode::LocatorInvalid,
            None,
        );
    }
}

#[test]
fn optional_parent_exclusion_keeps_null_and_absence_behavior() {
    let config = confluence_config();
    for action in ["page.create", "page.draft.create"] {
        let base = write_inputs(action);
        assert!(parse_write(action, &base, &config).is_ok());
        let mut nulls = base.clone();
        nulls["parentPageId"] = Value::Null;
        nulls["parentUrl"] = Value::Null;
        assert!(parse_write(action, &nulls, &config).is_ok());
        let mut both = base.clone();
        both["parentPageId"] = json!("200");
        both["parentUrl"] = json!("https://example.atlassian.net/wiki/spaces/ENG/pages/200/Parent");
        assert_denial(
            parse_write(action, &both, &config).unwrap_err(),
            ReasonCode::InputInvalid,
            Some(&format!(
                "confluence.{action} accepts parentPageId or parentUrl, not both"
            )),
        );
        for (chosen, other) in [("parentPageId", "parentUrl"), ("parentUrl", "parentPageId")] {
            let mut valid = base.clone();
            valid[chosen] = both[chosen].clone();
            assert!(parse_write(action, &valid, &config).is_ok());
            valid[other] = Value::Null;
            assert!(parse_write(action, &valid, &config).is_ok());
            valid[other] = json!({"value": "caller-secret"});
            assert_denial(
                parse_write(action, &valid, &config).unwrap_err(),
                ReasonCode::InputInvalid,
                None,
            );
        }
        let mut unknown = base;
        unknown["caller-secret"] = json!("caller-secret");
        assert_denial(
            parse_write(action, &unknown, &config).unwrap_err(),
            ReasonCode::InputInvalid,
            None,
        );
    }
}

#[test]
fn content_shape_parsing_preserves_missing_null_wrong_type_and_unknown_fields() {
    let config = confluence_config();
    for &action in WRITE_ACTIONS {
        let base = write_inputs(action);
        assert!(parse_write(action, &base, &config).is_ok(), "{action}");
        for field in ["content", "contentFormat"] {
            let mut missing = base.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert_denial(
                parse_write(action, &missing, &config).unwrap_err(),
                ReasonCode::InputInvalid,
                None,
            );
        }
        for invalid_format in [
            Value::Null,
            json!(7),
            json!({"value": "caller-secret"}),
            json!(["caller-secret"]),
        ] {
            let mut invalid = base.clone();
            invalid["contentFormat"] = invalid_format;
            assert_denial(
                parse_write(action, &invalid, &config).unwrap_err(),
                ReasonCode::InputInvalid,
                None,
            );
        }
        // Content is still a Value during shape parsing. Do not move the
        // invocation-stage validation before authorization or handle checks.
        for content in [Value::Null, json!(7), json!(false), json!({}), json!([])] {
            let mut parsed = base.clone();
            parsed["content"] = content;
            assert!(parse_write(action, &parsed, &config).is_ok(), "{action}");
        }
        let mut unknown = base;
        unknown["caller-secret"] = json!("caller-secret");
        assert_denial(
            parse_write(action, &unknown, &config).unwrap_err(),
            ReasonCode::InputInvalid,
            None,
        );
    }
}

fn content_provider(config: ConfluenceProviderConfig) -> ConfluenceProvider {
    ConfluenceProvider::with_backend(
        config,
        ProviderLimits::default(),
        Arc::new(StubConfluenceBackend {
            page: attachment_list_page(),
            search_page: ConfluenceSearchPage {
                pages: vec![],
                max_results: 2,
                next_page_token: None,
            },
        }),
    )
}

#[test]
fn content_preparation_keeps_types_formats_reasons_and_value_free_messages() {
    for (name, config, _) in configurations() {
        let descriptor = confluence_descriptor(&config);
        let provider = content_provider(config);
        for &action in WRITE_ACTIONS {
            let Some(descriptor) = descriptor.action(action) else {
                continue;
            };
            let request = invocation(action, write_inputs(action));
            let target = write_target(action);
            for format in [
                "storage",
                "markdown",
                "plain_text",
                "atlas_doc_format",
                "caller-secret",
            ] {
                let formats = descriptor.input_schema["properties"]["contentFormat"]["enum"]
                    .as_array()
                    .unwrap();
                let supported = formats.contains(&json!(format));
                let valid = match format {
                    "atlas_doc_format" => json!({"type": "doc", "version": 1, "content": []}),
                    "storage" => json!("<p>caller-secret</p>"),
                    _ => json!("caller-secret"),
                };
                let prepared =
                    provider.prepare_write_content(action, target, format, &valid, &request);
                if !supported {
                    assert_denial(
                        prepared.unwrap_err(),
                        ReasonCode::BodyFormatUnsupported,
                        Some(&format!("{action} contentFormat is unsupported")),
                    );
                    continue;
                }
                assert!(prepared.is_ok(), "{name}/{action}/{format}: {prepared:?}");
                let wrong_content = if format == "atlas_doc_format" {
                    vec![
                        Value::Null,
                        json!("caller-secret"),
                        json!([]),
                        json!(7),
                        json!(false),
                    ]
                } else {
                    vec![
                        Value::Null,
                        json!({"value": "caller-secret"}),
                        json!([]),
                        json!(7),
                        json!(false),
                    ]
                };
                for content in wrong_content {
                    let expected_type = if format == "atlas_doc_format" {
                        "an object"
                    } else {
                        "a string"
                    };
                    let error = provider
                        .prepare_write_content(action, target, format, &content, &request)
                        .unwrap_err();
                    assert_denial(
                        error,
                        ReasonCode::InputInvalid,
                        Some(&format!(
                            "{action} content must be {expected_type} for {format}"
                        )),
                    );
                }
                if format == "atlas_doc_format" {
                    assert_denial(
                        provider
                            .prepare_write_content(action, target, format, &json!({}), &request)
                            .unwrap_err(),
                        ReasonCode::BodyMalformed,
                        None,
                    );
                }
            }
        }
    }
}

#[test]
fn content_size_and_move_mode_denials_keep_their_precedence() {
    let config = confluence_config();
    let provider = content_provider(config.clone());
    let request = invocation("page.create", write_inputs("page.create"));
    // ADF source bytes are bounded before checking whether the value is an
    // object; flattening must not change this error to input_invalid.
    assert_denial(
        provider
            .prepare_write_content(
                "page.create",
                ConfluenceWriteTarget::CurrentPage,
                "atlas_doc_format",
                &json!("x".repeat(2048)),
                &request,
            )
            .unwrap_err(),
        ReasonCode::BodySizeDenied,
        None,
    );
    for (inputs, message) in [
        (
            json!({"pageId": "100", "position": "caller-secret", "targetPageId": "200"}),
            "confluence.page.move position must be before, after, or append",
        ),
        (
            json!({"pageId": "100", "position": "append", "targetPageId": "100"}),
            "confluence.page.move cannot target the page being moved",
        ),
    ] {
        assert_denial(
            parse_page_move_inputs(&inputs, &config).unwrap_err(),
            ReasonCode::InputInvalid,
            Some(message),
        );
    }
}
