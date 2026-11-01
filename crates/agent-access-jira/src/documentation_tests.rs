use super::*;

fn configurations() -> Vec<JiraProviderConfig> {
    let enabled = jira_config();
    let mut default = enabled.clone();
    default.content.comment_formats.clear();
    let mut bounded = enabled.clone();
    bounded.listing.max_results = 1;
    bounded.comments.max_results = 1;
    bounded.comments.body_max_results = 1;
    bounded.search.max_results = 1;
    vec![default, enabled, bounded]
}

fn parse_example(
    action: &str,
    inputs: &Value,
    config: &JiraProviderConfig,
) -> Result<(), ProviderError> {
    match action {
        "project.list" => project_list::parse_inputs(inputs, &config.listing).map(|_| ()),
        "project.view" => project_view::parse_inputs(inputs).map(|_| ()),
        "search" => {
            let parsed = parse_search_inputs(inputs)?;
            let projects = requested_projects(&parsed)?;
            let projects = if projects.is_empty() {
                BTreeSet::from(["PROJ".to_string()])
            } else {
                projects
            };
            build_jira_search_query(
                &parsed.query,
                &EffectiveSearchScope::Finite(projects),
                &config.search,
                CredentialMode::Service,
            )
            .map(|_| ())
        }
        "issue.view" => parse_issue_view_inputs(inputs, config).map(|_| ()),
        "issue.update" => parse_issue_update_inputs(inputs, config).map(|_| ()),
        "issue.create" => parse_issue_create_inputs(inputs, config).map(|_| ()),
        "issue.child.create" => parse_issue_child_create_inputs(inputs, config).map(|_| ()),
        "issue.parent.set" => parse_issue_parent_set_inputs(inputs, config).map(|_| ()),
        "issue.dependency.add" => parse_issue_dependency_add_inputs(inputs, config).map(|_| ()),
        "issue_type.list" => parse_issue_type_list_inputs(inputs).map(|_| ()),
        "comment.list" => parse_comment_list_inputs(inputs, config).map(|_| ()),
        "comment.view" => parse_comment_view_inputs(action, inputs, config).map(|_| ()),
        "comment.add" => parse_comment_add_inputs(inputs, config).map(|_| ()),
        "comment.reply" => parse_comment_reply_inputs(inputs, config).map(|_| ()),
        "comment.update" => parse_comment_update_inputs(inputs, config).map(|_| ()),
        "attachment.list" => parse_attachment_list_inputs(inputs, config).map(|_| ()),
        "attachment.download" => parse_attachment_download_inputs(inputs).map(|_| ()),
        "verify" => parse_verify_inputs(inputs).map(|_| ()),
        _ => panic!("no example parser for {action}"),
    }
}

#[test]
fn documentation_examples_pass_real_input_and_content_parsers() {
    let mut checked = 0;
    for config in configurations() {
        let descriptor = jira_descriptor(&config);
        descriptor.validate().unwrap();
        for action in &descriptor.actions {
            let documentation = action.documentation.as_ref().unwrap();
            for key in ["examples", "inputExamples"] {
                for example in documentation[key].as_array().into_iter().flatten() {
                    let inputs = if key == "examples" {
                        example
                    } else {
                        assert!(!example["label"].as_str().unwrap().is_empty());
                        &example["inputs"]
                    };
                    parse_example(&action.action, inputs, &config)
                        .unwrap_or_else(|error| panic!("{} {key}: {error:?}", action.action));
                    if key == "inputExamples" {
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
                    }
                    checked += 1;
                }
            }
        }
    }
    assert!(checked >= 90, "all documented examples must be exercised");
}

#[test]
fn documentation_upload_locators_accept_adapter_metadata_and_body_parts() {
    let config = jira_config();
    let descriptor = jira_descriptor(&config);
    let action = descriptor.action("attachment.add").unwrap();
    let examples = action.documentation.as_ref().unwrap()["uploadLocators"]
        .as_array()
        .unwrap();
    assert!(!examples.is_empty());
    for example in examples {
        let mut inputs = example["inputs"].clone();
        inputs["attachments"] = json!([{
            "field": "file", "filename": "notes.txt", "contentType": "text/plain",
            "size": 4, "sha256": sha256_hex(b"data")
        }]);
        let parsed = parse_attachment_add_inputs(&inputs).unwrap();
        let part = BrokerBodyPart::in_memory(
            "file",
            Some("notes.txt".into()),
            Some("text/plain".into()),
            b"data".to_vec(),
        );
        prepare_attachment_uploads(&parsed.attachments, &[part], &config.attachments).unwrap();
    }
}
