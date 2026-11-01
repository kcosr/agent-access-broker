use super::*;

fn configurations() -> Vec<ConfluenceProviderConfig> {
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
    let mut bounded = all.clone();
    bounded.listing.max_results = 1;
    bounded.search.max_results = 1;
    vec![default, disabled, text, object, all, bounded]
}

fn provider(config: ConfluenceProviderConfig) -> ConfluenceProvider {
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

fn parse_example(
    action: &str,
    inputs: &Value,
    config: &ConfluenceProviderConfig,
) -> Result<(), ProviderError> {
    if let Some(comment) = confluence_comment_action(action) {
        return match comment.operation {
            ConfluenceCommentOperation::List => {
                parse_comment_list_inputs(comment, inputs).map(|_| ())
            }
            ConfluenceCommentOperation::View => parse_comment_id_inputs(inputs).map(|_| ()),
            ConfluenceCommentOperation::Add => {
                parse_comment_add_inputs(comment, inputs).map(|_| ())
            }
            ConfluenceCommentOperation::Update => parse_comment_update_inputs(inputs).map(|_| ()),
            ConfluenceCommentOperation::Delete => parse_comment_delete_inputs(inputs).map(|_| ()),
            ConfluenceCommentOperation::ReplyList => {
                parse_comment_reply_list_inputs(inputs).map(|_| ())
            }
            ConfluenceCommentOperation::ReplyAdd => {
                parse_comment_reply_add_inputs(inputs).map(|_| ())
            }
        };
    }
    match action {
        "space.list" => {
            space_list::parse_inputs(inputs, &config.listing, &ProviderLimits::default())
                .map(|_| ())
        }
        "search" | "blog.search" => {
            let parsed = parse_search_inputs(inputs)?;
            let spaces = requested_spaces(&parsed)?;
            let spaces = if spaces.is_empty() {
                BTreeSet::from(["ENG".to_string()])
            } else {
                spaces
            };
            let kind = if action == "search" {
                ConfluenceSearchContentKind::Page
            } else {
                ConfluenceSearchContentKind::BlogPost
            };
            build_confluence_search_query_for_kind(
                &parsed.query,
                &EffectiveSearchScope::Finite(spaces),
                &config.search,
                kind,
            )
            .map(|_| ())
        }
        "page.view" => page_locator_from_inputs(inputs, config).map(|_| ()),
        "page.create" => parse_page_create_inputs(inputs, config).map(|_| ()),
        "page.update" => parse_page_update_inputs(inputs).map(|_| ()),
        "page.move" => parse_page_move_inputs(inputs, config).map(|_| ()),
        "attachment.list" => parse_attachment_list_inputs(inputs, config).map(|_| ()),
        "attachment.download" => parse_attachment_download_inputs(inputs).map(|_| ()),
        "verify" => parse_verify_inputs(inputs).map(|_| ()),
        "blog.view" => parse_blog_view_inputs(inputs, config).map(|_| ()),
        "blog.create" => parse_blog_create_inputs(inputs).map(|_| ()),
        "blog.update" => parse_blog_update_inputs(inputs).map(|_| ()),
        "blog.attachment.list" => parse_blog_attachment_list_inputs(inputs, config).map(|_| ()),
        "blog.attachment.download" => parse_blog_attachment_download_inputs(inputs).map(|_| ()),
        "blog.verify" => parse_blog_verify_inputs(inputs).map(|_| ()),
        "page.draft.create" => parse_page_draft_create_inputs(inputs, config).map(|_| ()),
        "page.draft.stage" => parse_page_draft_stage_inputs(inputs).map(|_| ()),
        "page.draft.view" | "page.draft.publish" => {
            parse_page_draft_body_format_inputs(action, inputs).map(|_| ())
        }
        "page.draft.update" => parse_page_draft_update_inputs(inputs).map(|_| ()),
        "page.draft.discard" => parse_page_draft_discard_inputs(inputs).map(|_| ()),
        "page.draft.verify" => parse_page_draft_verify_inputs(inputs).map(|_| ()),
        "page.draft.attachment.list" => parse_page_draft_attachment_list_inputs(inputs).map(|_| ()),
        "page.draft.attachment.download" => {
            parse_page_draft_attachment_download_inputs(inputs).map(|_| ())
        }
        "blog.draft.create" => parse_blog_draft_create_inputs(inputs).map(|_| ()),
        "blog.draft.stage" => parse_blog_draft_stage_inputs(inputs).map(|_| ()),
        "blog.draft.view" | "blog.draft.publish" => {
            parse_blog_draft_body_format_inputs(action, inputs).map(|_| ())
        }
        "blog.draft.update" => parse_blog_draft_update_inputs(inputs).map(|_| ()),
        "blog.draft.discard" => parse_blog_draft_discard_inputs(inputs).map(|_| ()),
        "blog.draft.verify" => parse_blog_draft_verify_inputs(inputs).map(|_| ()),
        "blog.draft.attachment.list" => parse_blog_draft_attachment_list_inputs(inputs).map(|_| ()),
        "blog.draft.attachment.download" => {
            parse_blog_draft_attachment_download_inputs(inputs).map(|_| ())
        }
        _ => panic!("no example parser for {action}"),
    }
}

fn substitute_draft_handle(action: &str, inputs: &mut Value, config: &ConfluenceProviderConfig) {
    if inputs.get("draftHandle").is_none() {
        return;
    }
    assert_eq!(inputs["draftHandle"], "<draftHandle>");
    let (kind, id_field) = if action.starts_with("page.") {
        (ConfluenceDraftContentType::Page, "pageId")
    } else {
        (ConfluenceDraftContentType::Blog, "blogId")
    };
    let content_id = inputs[id_field].as_str().unwrap().to_string();
    let content = draft_content(&content_id, kind);
    let handle = ConfluenceDraftHandle::new(kind, &content, ConfluenceDraftOrigin::New, None);
    let request = InvocationBuilder::from(invocation(action, inputs.clone()))
        .resources(ResourceScopes::from([("space".into(), vec!["ENG".into()])]))
        .build();
    let continuations = ConfluenceContinuations::new(
        config,
        &ProviderLimits::default(),
        Some(agent_access_provider::test_support::test_signing_key(7)),
    );
    let token = continuations
        .seal_draft_handle(request.context(), request.execution(), &handle)
        .unwrap();
    let opened = continuations
        .open_draft_handle(
            request.context(),
            request.execution(),
            kind,
            &content_id,
            &token,
        )
        .unwrap();
    assert_eq!(opened, handle);
    ensure_authorized_draft_handle(&opened, request.resource_scopes().unwrap()).unwrap();
    inputs["draftHandle"] = json!(token);
}

fn prepare_content(
    provider: &ConfluenceProvider,
    action: &str,
    inputs: &Value,
) -> Result<(), ProviderError> {
    let Some(format) = inputs.get("contentFormat").and_then(Value::as_str) else {
        return Ok(());
    };
    let target = if confluence_comment_action(action).is_some() {
        ConfluenceWriteTarget::Comment
    } else if action.starts_with("blog.") {
        ConfluenceWriteTarget::Blog
    } else if action.starts_with("page.draft.") {
        ConfluenceWriteTarget::PageDraft
    } else {
        ConfluenceWriteTarget::CurrentPage
    };
    provider
        .prepare_write_content(
            action,
            target,
            format,
            &inputs["content"],
            &invocation(action, inputs.clone()),
        )
        .map(|_| ())
}

#[test]
fn documentation_examples_and_signed_templates_pass_real_parsers_and_content_preparation() {
    let mut checked = 0;
    let mut handles = 0;
    for config in configurations() {
        let descriptor = confluence_descriptor(&config);
        descriptor.validate().unwrap();
        let provider = provider(config.clone());
        for action in &descriptor.actions {
            let documentation = action.documentation.as_ref().unwrap();
            for key in ["inputExamples", "inputTemplates"] {
                for example in documentation[key].as_array().into_iter().flatten() {
                    assert!(!example["label"].as_str().unwrap().is_empty());
                    let mut inputs = example["inputs"].clone();
                    if inputs.get("draftHandle").is_some() {
                        handles += 1;
                    }
                    substitute_draft_handle(&action.action, &mut inputs, &config);
                    parse_example(&action.action, &inputs, &config)
                        .unwrap_or_else(|error| panic!("{} {key}: {error:?}", action.action));
                    prepare_content(&provider, &action.action, &inputs).unwrap_or_else(|error| {
                        panic!("{} {key} content: {error:?}", action.action)
                    });
                    if let Some(format) = inputs.get("contentFormat") {
                        assert!(
                            action.input_schema["properties"]["contentFormat"]["enum"]
                                .as_array()
                                .unwrap()
                                .contains(format)
                        );
                    }
                    if let (Some(requested), Some(maximum)) = (
                        inputs["maxResults"].as_u64(),
                        action.input_schema["properties"]["maxResults"]["maximum"].as_u64(),
                    ) {
                        assert!(requested <= maximum);
                    }
                    checked += 1;
                }
            }
            for example in documentation
                .pointer("/cql/examples")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                parse_example(&action.action, example, &config).unwrap();
                checked += 1;
            }
        }
    }
    assert!(checked >= 300, "all documented examples must be exercised");
    assert!(
        handles >= 60,
        "every draft template must use a real signed handle"
    );
}

#[test]
fn documentation_upload_locators_accept_adapter_metadata_and_body_parts() {
    let mut config = confluence_config();
    config.attachments.media_types = vec!["text/plain".into()];
    let descriptor = confluence_descriptor(&config);
    let mut checked = 0;
    for action in &descriptor.actions {
        for example in action.documentation.as_ref().unwrap()["uploadLocators"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let mut inputs = example["inputs"].clone();
            substitute_draft_handle(&action.action, &mut inputs, &config);
            inputs["attachments"] = json!([{
                "field": "file", "filename": "notes.txt", "contentType": "text/plain",
                "size": 4, "sha256": sha256_hex(b"data")
            }]);
            let attachments = match action.action.as_str() {
                "attachment.add" => parse_attachment_add_inputs(&inputs).unwrap().attachments,
                "blog.attachment.add" => {
                    parse_blog_attachment_add_inputs(&inputs)
                        .unwrap()
                        .attachments
                }
                "page.draft.attachment.add" => {
                    parse_page_draft_attachment_add_inputs(&inputs)
                        .unwrap()
                        .attachments
                }
                "blog.draft.attachment.add" => {
                    parse_blog_draft_attachment_add_inputs(&inputs)
                        .unwrap()
                        .attachments
                }
                _ => panic!("unexpected upload locator"),
            };
            let part = BrokerBodyPart::in_memory(
                "file",
                Some("notes.txt".into()),
                Some("text/plain".into()),
                b"data".to_vec(),
            );
            prepare_attachment_uploads(&attachments, &[part], &config.attachments).unwrap();
            checked += 1;
        }
    }
    assert_eq!(checked, 4);
}

#[test]
fn documentation_attachment_followups_keep_the_same_content_owner() {
    let descriptor = confluence_descriptor(&confluence_config());
    for (list, download) in [
        ("attachment.list", "attachment.download"),
        ("blog.attachment.list", "blog.attachment.download"),
        (
            "page.draft.attachment.list",
            "page.draft.attachment.download",
        ),
        (
            "blog.draft.attachment.list",
            "blog.draft.attachment.download",
        ),
    ] {
        let action = descriptor.action(list).unwrap();
        let guidance = action.documentation.as_ref().unwrap()["attachments"]
            .as_str()
            .unwrap();
        assert!(
            guidance.contains(&format!("with {download}.")),
            "{list}: {guidance}"
        );
        assert!(descriptor.action(download).is_some());
    }
}
