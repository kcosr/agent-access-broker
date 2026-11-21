use super::*;
use agent_access_provider::{ProviderError, ReasonCode};
use serde_json::json;
use std::collections::BTreeSet;

fn select(
    action: &str,
    result: &mut Value,
    exact: Option<OutputContentFormat>,
    preference: Option<OutputContentFormat>,
    body_limit: u64,
    result_limit: u64,
) -> Result<(), ProviderError> {
    let resolved = resolve_response_options(
        presentation(action),
        preference,
        ResponseOptions::new(exact, None),
    )?;
    present_result(&resolved, result, body_limit, result_limit)
}

fn cases() -> Vec<(&'static str, Value, &'static str)> {
    let mut rows = Vec::new();
    for action in ["issue.view", "issue.create", "issue.update"] {
        rows.push((
            action,
            json!({"issue":{"iid":1,"description":"**body**"}}),
            "/issue/description",
        ));
    }
    rows.push((
        "issue.search",
        json!({"issues":[{"iid":1,"description":"**body**"}],"nextPageToken":"opaque-token"}),
        "/issues/0/description",
    ));
    for action in [
        "merge_request.view",
        "merge_request.create",
        "merge_request.update",
    ] {
        rows.push((
            action,
            json!({"mergeRequest":{"iid":2,"description":"**body**"}}),
            "/mergeRequest/description",
        ));
    }
    rows.push(("merge_request.search", json!({"mergeRequests":[{"iid":2,"description":"**body**"}],"nextPageToken":"opaque-token"}), "/mergeRequests/0/description"));
    for action in [
        "issue.note.view",
        "issue.note.add",
        "issue.note.update",
        "merge_request.note.view",
        "merge_request.note.add",
        "merge_request.note.update",
        "merge_request.discussion.note.add",
        "merge_request.discussion.note.update",
    ] {
        rows.push((
            action,
            json!({"note":{"id":3,"body":"**body**"}}),
            "/note/body",
        ));
    }
    for action in ["issue.note.list", "merge_request.note.list"] {
        rows.push((
            action,
            json!({"notes":[{"id":3,"body":"**body**"}],"nextPageToken":"opaque-token"}),
            "/notes/0/body",
        ));
    }
    for action in [
        "merge_request.discussion.view",
        "merge_request.discussion.inline.add",
        "merge_request.discussion.add",
        "merge_request.discussion.resolve",
        "merge_request.discussion.reopen",
    ] {
        rows.push((
            action,
            json!({"discussion":{"id":"discussion","notes":[{"id":3,"body":"**body**"}]}}),
            "/discussion/notes/0/body",
        ));
    }
    rows.push(("merge_request.discussion.list", json!({"discussions":[{"id":"discussion","notes":[{"id":3,"body":"**body**"}]}],"nextPageToken":"opaque-token"}), "/discussions/0/notes/0/body"));
    for action in [
        "merge_request.draft_note.view",
        "merge_request.draft_note.add",
        "merge_request.draft_note.update",
    ] {
        rows.push((
            action,
            json!({"draftNote":{"id":4,"body":"**body**"}}),
            "/draftNote/body",
        ));
    }
    rows.push((
        "merge_request.draft_note.list",
        json!({"draftNotes":[{"id":4,"body":"**body**"}],"nextPageToken":"opaque-token"}),
        "/draftNotes/0/body",
    ));
    rows
}

#[test]
fn all_declared_body_actions_replace_the_exact_field_and_preserve_surrounding_metadata() {
    let config = serde_json::from_value(json!({"api_base_url":"https://gitlab.example.com/api/v4", "web_base_url":"https://gitlab.example.com"})).unwrap();
    let descriptor = crate::gitlab_descriptor(&config);
    let declared = descriptor
        .actions
        .iter()
        .filter(|a| a.presentation.is_some())
        .map(|a| a.action.as_str())
        .collect::<BTreeSet<_>>();
    let rows = cases();
    assert_eq!(
        declared,
        rows.iter()
            .map(|(action, _, _)| *action)
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(rows.len(), 28);
    for (action, source, pointer) in rows {
        for format in FORMATS {
            let mut result = source.clone();
            result["mutationStatus"] = json!("applied");
            result["retrySafe"] = json!(false);
            let mut expected = result.clone();
            *expected.pointer_mut(pointer).unwrap() = json!({"format":format.as_str(),"value":if *format == OutputContentFormat::Text {"body"} else {"**body**"}});
            select(action, &mut result, Some(*format), None, 4096, 65536).unwrap();
            assert_eq!(result, expected, "{action} {format:?}");
            assert!(!result.to_string().contains("renderedBody"));
            let declaration = presentation(action).unwrap();
            declaration.validate().unwrap();
            assert_eq!(
                declaration.native_output_content_format(),
                OutputContentFormat::Markdown
            );
        }
    }
}

#[test]
fn markdown_is_byte_exact_and_unavailable_preference_falls_back_to_markdown() {
    let source = "# heading\r\n\n<script>doNotRun()</script>\n**strong**  ";
    for preference in [
        None,
        Some(OutputContentFormat::Markdown),
        Some(OutputContentFormat::Adf),
        Some(OutputContentFormat::Storage),
    ] {
        let mut result = json!({"issue":{"description":source}});
        select("issue.view", &mut result, None, preference, 4096, 65536).unwrap();
        assert_eq!(
            result["issue"]["description"],
            json!({"format":"markdown","value":source})
        );
    }
    for format in [OutputContentFormat::Adf, OutputContentFormat::Storage] {
        assert_eq!(
            select(
                "issue.view",
                &mut json!({}),
                Some(format),
                None,
                4096,
                65536
            )
            .unwrap_err()
            .reason_code(),
            ReasonCode::ResponseFormatUnsupported
        );
    }
    let mut result = json!({"issue":{"description":source}});
    select(
        "issue.view",
        &mut result,
        Some(OutputContentFormat::Text),
        Some(OutputContentFormat::Adf),
        4096,
        65536,
    )
    .unwrap();
    let text = result["issue"]["description"]["value"].as_str().unwrap();
    assert!(!text.contains("doNotRun"));
    assert!(text.contains("strong"));
}

#[test]
fn null_missing_empty_and_summary_bodies_keep_their_meaning() {
    for (action, source, pointer) in cases() {
        for format in FORMATS {
            let mut missing = source.clone();
            let (owner, field) = pointer.rsplit_once('/').unwrap();
            missing
                .pointer_mut(owner)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(field);
            let expected = missing.clone();
            select(action, &mut missing, Some(*format), None, 4096, 65536).unwrap();
            assert_eq!(missing, expected, "{action}");
            let mut null = source.clone();
            *null.pointer_mut(pointer).unwrap() = Value::Null;
            let expected = null.clone();
            select(action, &mut null, Some(*format), None, 4096, 65536).unwrap();
            assert_eq!(null, expected, "{action}");
            let mut empty = source.clone();
            *empty.pointer_mut(pointer).unwrap() = json!("");
            select(action, &mut empty, Some(*format), None, 4096, 65536).unwrap();
            assert_eq!(
                empty.pointer(pointer).unwrap(),
                &json!({"format":format.as_str(),"value":""})
            );
        }
    }
}

#[test]
fn nested_collections_select_every_returned_body_and_preserve_pagination() {
    let mut result = json!({"discussions":[
        {"id":"a","notes":[{"id":1,"body":"one"},{"id":2,"body":"two"}]},
        {"id":"b","notes":[{"id":3,"body":"three"},{"id":4,"body":null}]}
    ],"nextPageToken":"opaque-token","count":2});
    select(
        "merge_request.discussion.list",
        &mut result,
        Some(OutputContentFormat::Text),
        None,
        4096,
        65536,
    )
    .unwrap();
    assert_eq!(
        result["discussions"][0]["notes"][0]["body"],
        json!({"format":"text","value":"one"})
    );
    assert_eq!(
        result["discussions"][0]["notes"][1]["body"],
        json!({"format":"text","value":"two"})
    );
    assert_eq!(
        result["discussions"][1]["notes"][0]["body"],
        json!({"format":"text","value":"three"})
    );
    assert!(result["discussions"][1]["notes"][1]["body"].is_null());
    assert_eq!(result["nextPageToken"], "opaque-token");
    assert_eq!(result["count"], 2);
}

#[test]
fn source_types_individual_and_final_size_limits_fail_safely() {
    for format in FORMATS {
        for body in [json!({"secret":"bad type"}), json!("x".repeat(129))] {
            let mut result = json!({"note":{"body":body}});
            let error = select(
                "issue.note.view",
                &mut result,
                Some(*format),
                None,
                128,
                65536,
            )
            .unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
            assert_eq!(error.message, RENDER_FAILURE_MESSAGE);
            assert!(error.result.is_none());
        }
        let source = json!({"note":{"body":"exact bytes"}});
        let mut result = source.clone();
        select(
            "issue.note.view",
            &mut result,
            Some(*format),
            None,
            4096,
            65536,
        )
        .unwrap();
        let exact = serde_json::to_vec(&result).unwrap().len() as u64;
        select(
            "issue.note.view",
            &mut source.clone(),
            Some(*format),
            None,
            4096,
            exact,
        )
        .unwrap();
        assert!(
            select(
                "issue.note.view",
                &mut source.clone(),
                Some(*format),
                None,
                4096,
                exact - 1
            )
            .is_err()
        );
    }
    for action in ["file.view", "commit.view", "project.view", "search.code"] {
        let source = json!({"content":"unclassified **text**"});
        let mut result = source.clone();
        select(
            action,
            &mut result,
            None,
            Some(OutputContentFormat::Text),
            4096,
            65536,
        )
        .unwrap();
        assert_eq!(source, result);
        assert_eq!(
            select(
                action,
                &mut result,
                Some(OutputContentFormat::Text),
                None,
                4096,
                65536
            )
            .unwrap_err()
            .reason_code(),
            ReasonCode::ResponseFormatUnsupported
        );
    }
}
