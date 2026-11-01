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
fn documentation_examples_pass_real_parsers_with_configured_limits() {
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
                let inputs = &example["inputs"];
                if matches!(action.action.as_str(), "project.view" | "issue.view") {
                    assert!(
                        inputs.get("url").is_none(),
                        "instance URLs belong in inputTemplates"
                    );
                }
                parse_documented_input(&action.action, inputs, &config).unwrap_or_else(|error| {
                    panic!("{} / {}: {error:?}", action.action, example["label"])
                });
                if action.action == "project.upload" {
                    let (_, metadata) =
                        parse_admitted_project_upload_inputs(inputs, &config).unwrap();
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
            parsed, 60,
            "every non-search example must exercise its parser"
        );
    }
}

#[test]
fn documentation_url_templates_use_the_configured_instance_and_context_path() {
    for base in [
        "https://code.example.test",
        "https://code.example.test/gitlab",
        "https://gitlab.example.com/context/root/",
        "https://code.example.test:8443/context/root/",
    ] {
        let mut config = config();
        config.web_base_url = base.into();
        let descriptor = gitlab_descriptor(&config);
        let mut prepared = 0;
        for action in ["issue.view", "project.view"] {
            let documentation = descriptor
                .action(action)
                .unwrap()
                .documentation
                .as_ref()
                .unwrap();
            for template in documentation["inputTemplates"].as_array().unwrap() {
                assert!(!template["label"].as_str().unwrap().is_empty());
                assert!(!template["instructions"].as_str().unwrap().is_empty());
                let raw = &template["inputs"];
                assert_eq!(
                    parse_documented_input(action, raw, &config)
                        .unwrap_err()
                        .reason_code(),
                    ReasonCode::LocatorInvalid,
                );
                let path = raw["url"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("https://gitlab.example.com/")
                    .unwrap();
                let inputs = json!({"url":format!("{}/{path}", base.trim_end_matches('/'))});
                parse_documented_input(action, &inputs, &config).unwrap();
                assert_eq!(
                    project_locator_for_action(action, &inputs, &config)
                        .unwrap()
                        .project,
                    "team/project"
                );
                if action == "issue.view" {
                    assert_eq!(parse_issue_view_inputs(&inputs, &config).unwrap().iid, 123);
                }
                prepared += 1;
            }
        }
        assert_eq!(prepared, 2);
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

fn all_enabled_documentation_config() -> GitlabProviderConfig {
    let mut config = config();
    config.provisioning.enabled = true;
    let categories: Vec<String> = search::CATEGORIES
        .iter()
        .map(|name| (*name).into())
        .collect();
    config.search.engines.advanced = GitlabSearchEngineConfig {
        project_categories: categories.clone(),
        instance_categories: categories,
    };
    config.search.engines.zoekt = GitlabSearchEngineConfig {
        project_categories: vec!["code".into()],
        instance_categories: vec!["code".into()],
    };
    config
}

#[test]
fn documentation_keys_exactly_cover_all_enabled_actions() {
    let documentation: BTreeMap<String, Value> =
        serde_json::from_str(include_str!("../action-documentation.json")).unwrap();
    let descriptor = gitlab_descriptor(&all_enabled_documentation_config());
    let actions: BTreeSet<_> = descriptor
        .actions
        .into_iter()
        .map(|action| action.action)
        .collect();
    assert_eq!(actions.len(), 110);
    for (action, details) in &documentation {
        let command = details["typedCommand"].as_str().unwrap();
        assert!(
            command.contains("Typed CLI wrapper: agent-access gitlab "),
            "{action}"
        );
        assert!(command.contains(" --help"), "{action}");
    }
    assert_eq!(documentation.into_keys().collect::<BTreeSet<_>>(), actions);
}

#[test]
fn documentation_example_labels_are_distinct_within_each_action() {
    let descriptor = gitlab_descriptor(&all_enabled_documentation_config());
    for action in descriptor.actions {
        let documentation = action.documentation.as_ref().unwrap();
        let entries: Vec<_> = ["inputExamples", "inputTemplates"]
            .into_iter()
            .filter_map(|field| documentation[field].as_array())
            .flatten()
            .collect();
        if !entries.is_empty() {
            let labels: BTreeSet<_> = entries
                .iter()
                .map(|example| {
                    let label = example["label"].as_str().unwrap();
                    assert!(!label.trim().is_empty(), "{}", action.action);
                    label
                })
                .collect();
            assert_eq!(labels.len(), entries.len(), "{}", action.action);
        }
    }
}

#[test]
fn documentation_action_references_resolve_to_canonical_actions() {
    let descriptor = gitlab_descriptor(&all_enabled_documentation_config());
    // These fields direct the caller to another action. Result paths, version
    // numbers, file names and unavailable-action statements are not action links.
    let references: &[(&str, &str, &[&str])] = &[
        ("file.view", "presentation", &["file.raw.download"]),
        (
            "issue.search",
            "relatedSearch",
            &["search.issues", "search.merge_requests"],
        ),
        (
            "merge_request.approve",
            "approval",
            &["merge_request.approval.view"],
        ),
        (
            "merge_request.diff.raw.download",
            "download",
            &["merge_request.diff_version.view"],
        ),
        (
            "merge_request.diff_version.list",
            "versions",
            &["merge_request.diff_version.view"],
        ),
        (
            "merge_request.discussion.list",
            "positions",
            &["merge_request.diff_version.view"],
        ),
        (
            "merge_request.discussion.view",
            "positions",
            &["merge_request.diff_version.view"],
        ),
        (
            "merge_request.draft_note.publish_all",
            "publication",
            &["merge_request.review.submit"],
        ),
        (
            "merge_request.search",
            "relatedSearch",
            &["search.issues", "search.merge_requests"],
        ),
        (
            "merge_request.unapprove",
            "approval",
            &["merge_request.approval.view"],
        ),
        ("project.search", "authorization", &["project.list"]),
        (
            "service_account.create",
            "workflow",
            &["service_account.member.set", "service_account.token.create"],
        ),
    ];
    for &(owner, field, targets) in references {
        let documentation = descriptor
            .action(owner)
            .unwrap()
            .documentation
            .as_ref()
            .unwrap();
        let words: Vec<_> = documentation[field]
            .as_str()
            .unwrap()
            .split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.')))
            .map(|word| word.trim_matches('.'))
            .collect();
        for target in targets {
            assert!(
                descriptor.action(target).is_some(),
                "{owner}.{field}: {target}"
            );
            assert!(
                words.contains(target),
                "{owner}.{field} must use canonical action {target}"
            );
        }
    }
}
