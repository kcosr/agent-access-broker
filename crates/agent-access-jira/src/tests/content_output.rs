use super::*;
use agent_access_provider::presentation::{
    ResponseOptions, present_result, resolve_response_options,
};

const MUTATIONS: &[&str] = &[
    "issue.create",
    "issue.update",
    "comment.add",
    "comment.reply",
    "comment.update",
];

fn backend() -> Arc<StubJiraBackend> {
    let mut backend = StubJiraBackend::default();
    let mut issue = visible_issue();
    issue.description = Some(adf_text("receipt body"));
    backend.issues.insert("PROJ-1".into(), issue);
    *backend.created_issue.lock().unwrap() = Some(JiraCreatedIssue {
        id: "10001".into(),
        key: "PROJ-1".into(),
    });
    backend
        .comments
        .lock()
        .unwrap()
        .insert("10042".into(), test_comment("10042"));
    Arc::new(backend)
}

fn inputs(action: &str) -> Value {
    let mut value =
        json!({"issue":"PROJ-1","contentFormat":"adf","content":adf_text("receipt body")});
    match action {
        "issue.create" => {
            value.as_object_mut().unwrap().remove("issue");
            value["project"] = json!("PROJ");
            value["issueTypeId"] = json!("10001");
            value["summary"] = json!("Created issue");
        }
        "comment.update" => value["commentId"] = json!("10042"),
        "comment.reply" => value["parentCommentId"] = json!("10042"),
        _ => {}
    }
    value
}

#[tokio::test]
async fn every_body_mutation_success_has_a_completed_presentation_recovery_receipt() {
    let descriptor = jira_descriptor(&jira_config());
    let declared = descriptor
        .actions
        .iter()
        .filter(|action| {
            !action.read_only
                && action
                    .presentation
                    .as_ref()
                    .is_some_and(|body| !body.embedded_bodies().is_empty())
        })
        .map(|action| action.action.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(declared, MUTATIONS.iter().copied().collect());
    for action in MUTATIONS {
        let upstream = backend();
        let provider =
            JiraProvider::with_backend(jira_config(), ProviderLimits::default(), upstream.clone());
        let response = provider
            .invoke_checked(per_user_invocation(action, inputs(action), vec![]))
            .await
            .unwrap_or_else(|error| panic!("{action}: {error:?}"));
        assert_eq!(
            response.presentation_recovery_receipt,
            Some(MutationReceipt::applied()),
            "{action}"
        );
        assert!(response.audit.is_some(), "{action}");
        assert!(response.upstream_status.is_some(), "{action}");
        let writes = upstream.created_issues.lock().unwrap().len()
            + upstream.updated_issues.lock().unwrap().len()
            + upstream.added_comments.lock().unwrap().len()
            + upstream.updated_comments.lock().unwrap().len();
        assert_eq!(writes, 1, "{action}");
        for format in [
            OutputContentFormat::Markdown,
            OutputContentFormat::Text,
            OutputContentFormat::Adf,
        ] {
            let resolved = resolve_response_options(
                present::presentation(action),
                None,
                ResponseOptions::new(Some(format), None),
            )
            .unwrap();
            let mut result = response.result.clone();
            present_result(&resolved, &mut result, 4096, 65536).unwrap();
            let pointer = if action.starts_with("issue.") {
                "/issue/description"
            } else {
                "/comment/body"
            };
            assert_eq!(
                result.pointer(pointer).unwrap()["format"],
                format.as_str(),
                "{action}"
            );
            crate::result_conformance::assert_selected_conforms(
                descriptor.action(action).unwrap(),
                format,
                &result,
            );
        }
        // A later presentation failure must not consume the independent receipt.
        let resolved = resolve_response_options(
            present::presentation(action),
            None,
            ResponseOptions::default(),
        )
        .unwrap();
        assert!(present_result(&resolved, &mut response.result.clone(), 4096, 1).is_err());
        assert_eq!(
            response.presentation_recovery_receipt,
            Some(MutationReceipt::applied())
        );
    }
}

#[tokio::test]
async fn body_read_successes_do_not_claim_mutation_completion() {
    for (action, inputs) in [
        ("issue.view", json!({"issue":"PROJ-1"})),
        (
            "comment.view",
            json!({"issue":"PROJ-1","commentId":"10042"}),
        ),
    ] {
        let provider =
            JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend());
        let response = provider
            .invoke_checked(per_user_invocation(action, inputs, vec![]))
            .await
            .unwrap();
        assert!(response.presentation_recovery_receipt.is_none(), "{action}");
    }
}

#[test]
fn output_preferences_are_optional_concrete_and_published() {
    assert!(jira_config().content.preferred_output_format.is_none());
    for (name, format) in [
        ("markdown", OutputContentFormat::Markdown),
        ("text", OutputContentFormat::Text),
        ("adf", OutputContentFormat::Adf),
        ("storage", OutputContentFormat::Storage),
    ] {
        let content: JiraContentConfig =
            serde_json::from_value(json!({"preferred_output_format":name})).unwrap();
        assert_eq!(content.preferred_output_format, Some(format));
        let mut config = jira_config();
        config.content = content;
        assert_eq!(
            jira_descriptor(&config).preferred_output_content_format,
            Some(format)
        );
    }
    for invalid in [json!("native"), json!("html"), json!(false)] {
        assert!(
            serde_json::from_value::<JiraContentConfig>(json!({"preferred_output_format":invalid}))
                .is_err()
        );
    }
}
