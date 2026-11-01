use super::*;

fn parse_documented_input(
    action: &str,
    inputs: &Value,
    config: &GitlabProviderConfig,
) -> Result<(), ProviderError> {
    project_locator_for_action(action, inputs, config)?;
    let body_limit = config.content.max_body_bytes;
    let page_limit = config.search.max_results;
    match action {
        "project.view" => parse_project_locator(inputs, config).map(|_| ()),
        "project.upload" => parse_admitted_project_upload_inputs(inputs, config).map(|_| ()),
        "issue.view" => parse_issue_view_inputs(inputs, config).map(|_| ()),
        "issue.search" => parse_issue_search_inputs(inputs).map(|_| ()),
        "issue.create" => parse_issue_create_inputs(inputs, body_limit).map(|_| ()),
        "issue.update" => parse_issue_update_inputs(inputs, body_limit).map(|_| ()),
        "issue.note.add" => parse_issue_note_add_inputs(inputs, body_limit).map(|_| ()),
        "issue.note.view" => parse_issue_note_view_inputs(inputs).map(|_| ()),
        "issue.note.update" => parse_note_update_inputs(inputs, body_limit).map(|_| ()),
        "issue.note.list" | "merge_request.note.list" => {
            parse_note_list_inputs(inputs, page_limit).map(|_| ())
        }
        "merge_request.view" => parse_merge_request_view_inputs(inputs, config).map(|_| ()),
        "merge_request.note.add" => parse_note_add_inputs(inputs, body_limit).map(|_| ()),
        "merge_request.note.view" => parse_merge_request_note_view_inputs(inputs).map(|_| ()),
        "merge_request.discussion.view" => parse_discussion_view_inputs(inputs).map(|_| ()),
        "merge_request.discussion.list" => {
            parse_discussion_list_inputs(inputs, page_limit).map(|_| ())
        }
        "merge_request.discussion.inline.add" => {
            parse_positioned_discussion_inputs(inputs, body_limit).map(|_| ())
        }
        "merge_request.discussion.note.add" => {
            parse_discussion_reply_inputs(inputs, body_limit).map(|_| ())
        }
        "merge_request.draft_note.list" => {
            parse_draft_note_list_inputs(inputs, page_limit).map(|_| ())
        }
        "merge_request.draft_note.view"
        | "merge_request.draft_note.delete"
        | "merge_request.draft_note.publish" => parse_draft_note_object_inputs(inputs).map(|_| ()),
        "merge_request.draft_note.add" => {
            parse_draft_note_add_inputs(inputs, body_limit).map(|_| ())
        }
        "merge_request.draft_note.update" => {
            parse_draft_note_update_inputs(inputs, body_limit).map(|_| ())
        }
        "merge_request.draft_note.publish_all" | "merge_request.review.submit" => {
            parse_draft_publication_inputs(
                inputs,
                body_limit,
                action == "merge_request.review.submit",
            )
            .map(|_| ())
        }
        "merge_request.reviewer.list"
        | "merge_request.commit.list"
        | "merge_request.pipeline.list"
        | "merge_request.diff.list"
        | "merge_request.diff_version.list"
        | "merge_request.approval_rule.list" => parse_merge_request_list_inputs(
            inputs,
            page_limit,
            action,
            action == "merge_request.diff.list",
        )
        .map(|_| ()),
        "merge_request.diff_version.view" | "merge_request.approval_rule.view" => {
            let id = if action == "merge_request.diff_version.view" {
                "diffVersionId"
            } else {
                "approvalRuleId"
            };
            parse_merge_request_object_inputs(inputs, id, action).map(|_| ())
        }
        "merge_request.approval.view"
        | "merge_request.approval_state.view"
        | "merge_request.diff.raw.download" => {
            parse_merge_request_subresource_inputs(inputs).map(|_| ())
        }
        "merge_request.approve" | "merge_request.unapprove" => {
            parse_approval_mutation_inputs(inputs, action == "merge_request.approve").map(|_| ())
        }
        "merge_request.suggestion.apply" | "merge_request.suggestion.batch_apply" => {
            parse_suggestion_apply_inputs(
                inputs,
                action == "merge_request.suggestion.batch_apply",
                body_limit,
            )
            .map(|_| ())
        }
        "file.view" | "file.raw.download" => parse_file_view_inputs(inputs).map(|_| ()),
        "branch.list" => parse_branch_list_inputs(inputs).map(|_| ()),
        "pipeline.list" => parse_pipeline_list_inputs(inputs).map(|_| ()),
        "job.trace.download" => parse_job_object_inputs(inputs).map(|_| ()),
        "webhook.list" => parse_webhook_list_inputs(inputs, page_limit).map(|_| ()),
        "webhook.view" | "webhook.delete" => parse_webhook_object_inputs(inputs).map(|_| ()),
        "webhook.create" | "webhook.update" => {
            parse_webhook_write_inputs(inputs, action == "webhook.create", body_limit).map(|_| ())
        }
        "webhook.test" => parse_webhook_test_inputs(inputs).map(|_| ()),
        "webhook.event.list" => parse_webhook_event_list_inputs(inputs).map(|_| ()),
        "webhook.event.resend" => parse_webhook_event_resend_inputs(inputs).map(|_| ()),
        "webhook.custom_header.delete" => {
            parse_webhook_custom_header_inputs(inputs, false).map(|_| ())
        }
        _ => panic!("documentation example needs its real parser: {action}"),
    }
}

#[test]
fn documentation_examples_pass_real_parsers_with_configured_limits_and_url_templates() {
    for (maximum, media_types, base) in [
        (50, vec![], "https://gitlab.example.com"),
        (
            7,
            vec!["text/plain".into()],
            "https://code.example.test/gitlab",
        ),
        (
            1,
            vec!["application/octet-stream".into()],
            "https://code.example.test",
        ),
    ] {
        let mut config = config();
        config.search.max_results = maximum;
        config.web_base_url = base.into();
        config.attachments.max_bytes = u64::from(maximum);
        config.attachments.max_total_bytes = u64::from(maximum);
        config.attachments.media_types = media_types;
        let descriptor = gitlab_descriptor(&config);
        let mut parsed = 0;
        for action in &descriptor.actions {
            if search::is_search_action(&action.action) {
                continue; // Native searches use their private parser's matrix.
            }
            let Some(documentation) = &action.documentation else {
                continue;
            };
            let Some(examples) = documentation["inputExamples"].as_array() else {
                continue;
            };
            for example in examples {
                assert!(!example["label"].as_str().unwrap().is_empty());
                let mut inputs = example["inputs"].clone();
                if matches!(action.action.as_str(), "project.view" | "issue.view")
                    && let Some(url) = inputs.get("url").and_then(Value::as_str)
                {
                    // These are explicitly labeled instance-origin templates.
                    inputs["url"] = json!(url.replacen("https://gitlab.example.com", base, 1));
                }
                parse_documented_input(&action.action, &inputs, &config).unwrap_or_else(|error| {
                    panic!("{} / {}: {error:?}", action.action, example["label"])
                });
                if action.action == "project.upload" {
                    let (_, metadata) =
                        parse_admitted_project_upload_inputs(&inputs, &config).unwrap();
                    let part = BrokerBodyPart::in_memory(
                        metadata.name.clone(),
                        Some(metadata.file_name.clone()),
                        Some(metadata.content_type.clone()),
                        documentation["uploadExample"]["bytesUtf8"]
                            .as_str()
                            .unwrap()
                            .as_bytes()
                            .to_vec(),
                    );
                    prepare_project_upload(&metadata, &[part]).unwrap();
                }
                parsed += 1;
            }
        }
        assert_eq!(
            parsed, 62,
            "every non-search example must exercise its parser"
        );
    }
}

#[test]
fn documentation_preserves_existing_structured_search_grammar_and_examples() {
    for maximum in [1, 7, 50] {
        let mut config = config();
        config.search.max_results = maximum;
        let descriptor = gitlab_descriptor(&config);
        for (name, merge_requests) in [("issue.search", false), ("merge_request.search", true)] {
            let before = gitlab_search_documentation(merge_requests, maximum);
            let after = descriptor
                .action(name)
                .unwrap()
                .documentation
                .as_ref()
                .unwrap();
            for (key, value) in before.as_object().unwrap() {
                assert_eq!(&after[key], value, "{name}: {key}");
            }
        }
    }
}
