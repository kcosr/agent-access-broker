use super::*;
use agent_access_provider::presentation::{
    ResponseOptions, present_result, resolve_response_options,
};

const MUTATIONS: &[&str] = &[
    "issue.create",
    "issue.update",
    "issue.note.add",
    "issue.note.update",
    "merge_request.create",
    "merge_request.update",
    "merge_request.note.add",
    "merge_request.note.update",
    "merge_request.discussion.inline.add",
    "merge_request.discussion.note.add",
    "merge_request.draft_note.add",
    "merge_request.draft_note.update",
    "merge_request.discussion.add",
    "merge_request.discussion.note.update",
    "merge_request.discussion.resolve",
    "merge_request.discussion.reopen",
];
const BODY: &str = "receipt **body**";
const HEAD: &str = "3333333333333333333333333333333333333333";

fn issue() -> Value {
    json!({"id":70,"iid":7,"project_id":42,"title":"Issue","description":BODY})
}

fn merge_request() -> Value {
    json!({"id":500,"iid":5,"project_id":42,"source_project_id":42,"target_project_id":42,
        "title":"Merge request","description":BODY,"prepared_at":"2026-06-03T11:59:00.000Z","source_branch":"feature","target_branch":"main","sha":HEAD,
        "diff_refs":{"base_sha":"1111111111111111111111111111111111111111","start_sha":"2222222222222222222222222222222222222222","head_sha":HEAD}})
}

fn discussion(resolved: bool, positioned: bool) -> Value {
    let mut value = discussion_json("discussion-1", 9, BODY, resolved);
    value["notes"][0]["noteable_iid"] = json!(5);
    if positioned {
        value["notes"][0]["position"] = positioned_write_body();
    }
    value
}

fn case(action: &str) -> (Value, &'static str, &'static str, u16, Value) {
    let issue_content =
        json!({"project":"sip/service","iid":7,"contentFormat":"markdown","content":BODY});
    let mr_content =
        json!({"project":"sip/service","iid":5,"contentFormat":"markdown","content":BODY});
    match action {
        "issue.create" => (
            json!({"project":"sip/service","title":"Issue","contentFormat":"markdown","content":BODY}),
            "POST",
            "/api/v4/projects/42/issues",
            201,
            issue(),
        ),
        "issue.update" => (
            issue_content,
            "PUT",
            "/api/v4/projects/42/issues/7",
            200,
            issue(),
        ),
        "issue.note.add" => (
            issue_content,
            "POST",
            "/api/v4/projects/42/issues/7/notes",
            201,
            note_json(9, BODY, "Issue", 7),
        ),
        "issue.note.update" => {
            let mut inputs = issue_content;
            inputs["noteId"] = json!(9);
            (
                inputs,
                "PUT",
                "/api/v4/projects/42/issues/7/notes/9",
                200,
                note_json(9, BODY, "Issue", 7),
            )
        }
        "merge_request.create" => (
            json!({"project":"sip/service","title":"Merge request","sourceBranch":"feature","targetBranch":"main","contentFormat":"markdown","content":BODY}),
            "POST",
            "/api/v4/projects/42/merge_requests",
            201,
            merge_request(),
        ),
        "merge_request.update" => (
            mr_content,
            "PUT",
            "/api/v4/projects/42/merge_requests/5",
            200,
            merge_request(),
        ),
        "merge_request.note.add" => (
            mr_content,
            "POST",
            "/api/v4/projects/42/merge_requests/5/notes",
            201,
            note_json(9, BODY, "MergeRequest", 5),
        ),
        "merge_request.note.update" => {
            let mut inputs = mr_content;
            inputs["noteId"] = json!(9);
            (
                inputs,
                "PUT",
                "/api/v4/projects/42/merge_requests/5/notes/9",
                200,
                note_json(9, BODY, "MergeRequest", 5),
            )
        }
        "merge_request.discussion.add" => (
            mr_content,
            "POST",
            "/api/v4/projects/42/merge_requests/5/discussions",
            201,
            discussion(false, false),
        ),
        "merge_request.discussion.inline.add" => {
            let mut inputs = mr_content;
            inputs["expectedHeadSha"] = json!(HEAD);
            inputs["position"] = json!({"positionType":"text","oldPath":"src/old.rs","newPath":"src/new.rs","newLine":34});
            (
                inputs,
                "POST",
                "/api/v4/projects/42/merge_requests/5/discussions",
                201,
                discussion(false, true),
            )
        }
        "merge_request.discussion.note.add" => {
            let mut inputs = mr_content;
            inputs["discussionId"] = json!("discussion-1");
            (
                inputs,
                "POST",
                "/api/v4/projects/42/merge_requests/5/discussions/discussion-1/notes",
                201,
                note_json(9, BODY, "MergeRequest", 5),
            )
        }
        "merge_request.discussion.note.update" => {
            let mut inputs = mr_content;
            inputs["discussionId"] = json!("discussion-1");
            inputs["noteId"] = json!(9);
            (
                inputs,
                "PUT",
                "/api/v4/projects/42/merge_requests/5/discussions/discussion-1/notes/9",
                200,
                note_json(9, BODY, "MergeRequest", 5),
            )
        }
        "merge_request.discussion.resolve" | "merge_request.discussion.reopen" => (
            json!({"project":"sip/service","iid":5,"discussionId":"discussion-1"}),
            "PUT",
            "/api/v4/projects/42/merge_requests/5/discussions/discussion-1",
            200,
            discussion(action.ends_with("resolve"), false),
        ),
        "merge_request.draft_note.add" => (
            mr_content,
            "POST",
            "/api/v4/projects/42/merge_requests/5/draft_notes",
            201,
            draft_note_json(12, BODY),
        ),
        "merge_request.draft_note.update" => {
            let mut inputs = mr_content;
            inputs["draftNoteId"] = json!(12);
            (
                inputs,
                "PUT",
                "/api/v4/projects/42/merge_requests/5/draft_notes/12",
                200,
                draft_note_json(12, BODY),
            )
        }
        _ => panic!("missing success fixture for {action}"),
    }
}

async fn provider(server: &MockServer) -> GitlabProvider {
    for (route, body) in [
        (
            "/api/v4/projects/sip%2Fservice",
            json!({"id":42,"path_with_namespace":"sip/service"}),
        ),
        (
            "/api/v4/projects/42",
            json!({"id":42,"path_with_namespace":"sip/service"}),
        ),
        ("/api/v4/projects/42/issues/7", issue()),
        ("/api/v4/projects/42/merge_requests/5", merge_request()),
        (
            "/api/v4/projects/42/repository/branches/feature",
            json!({"name":"feature","commit":{"id":HEAD}}),
        ),
        (
            "/api/v4/projects/42/repository/branches/main",
            json!({"name":"main","commit":{"id":HEAD}}),
        ),
        ("/api/v4/user", json!({"id":314,"username":"service-user"})),
        (
            "/api/v4/projects/42/merge_requests/5/discussions/discussion-1",
            discussion(false, false),
        ),
        (
            "/api/v4/projects/42/merge_requests/5/draft_notes/12",
            draft_note_json(12, BODY),
        ),
    ] {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }
    GitlabProvider::with_backend(config(), Arc::new(http_backend(server)))
}

#[tokio::test]
async fn every_body_mutation_success_has_a_completed_presentation_recovery_receipt() {
    let descriptor = gitlab_descriptor(&config());
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
        let server = MockServer::start().await;
        let provider = provider(&server).await;
        let (inputs, verb, route, status, body) = case(action);
        Mock::given(method(verb))
            .and(path(route))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .expect(1)
            .mount(&server)
            .await;
        let response = provider
            .invoke(test_invocation(action, inputs))
            .await
            .unwrap_or_else(|error| panic!("{action}: {error:?}"));
        assert_eq!(
            response.presentation_recovery_receipt,
            Some(MutationReceipt::applied()),
            "{action}"
        );
        assert_eq!(response.upstream_status, Some(status), "{action}");
        assert!(response.audit.is_some(), "{action}");
        let sent = server.received_requests().await.unwrap();
        assert_eq!(
            sent.iter()
                .filter(|request| !matches!(request.method.as_str(), "GET" | "HEAD"))
                .count(),
            1,
            "{action}"
        );
        for format in [OutputContentFormat::Markdown, OutputContentFormat::Text] {
            let resolved = resolve_response_options(
                present::presentation(action),
                None,
                ResponseOptions::new(Some(format), None),
            )
            .unwrap();
            let mut result = response.result.clone();
            present_result(&resolved, &mut result, 4096, 65536).unwrap();
            let serialized = result.to_string();
            assert!(
                serialized.contains(&format!("\"format\":\"{}\"", format.as_str())),
                "{action}"
            );
            assert!(!serialized.contains("renderedBody"), "{action}");
            if response.result.get("mutationStatus").is_some() {
                assert_eq!(result["mutationStatus"], "applied");
                assert_eq!(result["retrySafe"], false);
            }
        }
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
async fn body_read_success_does_not_claim_mutation_completion() {
    let server = MockServer::start().await;
    let response = provider(&server)
        .await
        .invoke(test_invocation(
            "issue.view",
            json!({"project":"sip/service","iid":7}),
        ))
        .await
        .unwrap();
    assert!(response.presentation_recovery_receipt.is_none());
}

#[test]
fn output_preferences_are_optional_concrete_and_published() {
    assert!(config().content.preferred_output_format.is_none());
    for (name, format) in [
        ("markdown", OutputContentFormat::Markdown),
        ("text", OutputContentFormat::Text),
        ("adf", OutputContentFormat::Adf),
        ("storage", OutputContentFormat::Storage),
    ] {
        let content: GitlabContentConfig =
            serde_json::from_value(json!({"preferred_output_format":name})).unwrap();
        assert_eq!(content.preferred_output_format, Some(format));
        let mut config = config();
        config.content = content;
        assert_eq!(
            gitlab_descriptor(&config).preferred_output_content_format,
            Some(format)
        );
    }
    for invalid in [json!("native"), json!("html"), json!(false)] {
        assert!(
            serde_json::from_value::<GitlabContentConfig>(
                json!({"preferred_output_format":invalid})
            )
            .is_err()
        );
    }
}
