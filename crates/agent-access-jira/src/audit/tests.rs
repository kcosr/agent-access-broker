use super::inventory::{action, assert_coverage, assert_sample, check_inventory, field, project};
use super::*;
use serde_json::{Value, json};

fn semantic(action: &str, pointer: &str) -> (&'static str, &'static str) {
    fn find(fields: &[Field], pointer: &str, prefix: &str) -> Option<(&'static str, &'static str)> {
        for item in fields {
            let full = format!("{prefix}{}", item.rule.pointer());
            if full == pointer {
                return Some((item.element, item.reason.unwrap_or("")));
            }
            if let Some(found) = find(&item.children, pointer, &format!("{full}[]")) {
                return Some(found);
            }
        }
        None
    }
    find(&fields(action), pointer, "").expect("every occurrence has a semantic classification")
}

#[test]
fn audit_inventory_maximal() {
    let descriptor = maximal();
    check_inventory(
        &descriptor,
        concat!(env!("CARGO_MANIFEST_DIR"), "/audit-input-inventory.json"),
        &[],
        semantic,
    );
}

#[test]
fn original_input_fixtures_cover_every_action_and_configured_shape() {
    let descriptor = maximal();
    let fixtures: Value =
        serde_json::from_str(include_str!("../../audit-input-fixtures.json")).unwrap();
    let cases = fixtures["cases"].as_array().unwrap();
    let covered: std::collections::BTreeSet<_> = cases
        .iter()
        .map(|case| case["action"].as_str().unwrap())
        .collect();
    assert_eq!(
        covered,
        descriptor
            .actions
            .iter()
            .map(|action| action.action.as_str())
            .collect()
    );
    for case in cases {
        let snapshot = assert_sample(
            action(&descriptor, case["action"].as_str().unwrap()),
            &case["inputs"],
        );
        let encoded = snapshot.to_string();
        for excluded in [
            "private body",
            "private ADF",
            "private storage",
            "privateMapKey",
            "private payload",
            "private-pagination",
            "private-listing",
            "private-draft",
            "private-form-field",
            "private-url-token",
            "private version message",
            "ffffffffffffffffffffffffffffffff",
        ] {
            assert!(
                !encoded.contains(excluded),
                "{} {} leaked {excluded}",
                case["action"],
                case["variant"]
            );
        }
    }
}

#[test]
fn requested_identifier_controls_are_facts_without_target_presentation() {
    let descriptor = maximal();
    for (action_name, inputs, keys) in [
        (
            "issue.create",
            json!({"issueTypeId":"10001"}),
            vec!["issueTypeId"],
        ),
        (
            "issue.child.create",
            json!({"issueTypeId":"10002"}),
            vec!["issueTypeId"],
        ),
        (
            "comment.add",
            json!({"visibility":{"value":"Reviewers","identifier":"group-id"}}),
            vec!["visibility.value", "visibility.identifier"],
        ),
        (
            "comment.reply",
            json!({"visibility":{"value":"Reviewers","identifier":"group-id"}}),
            vec!["visibility.value", "visibility.identifier"],
        ),
        (
            "comment.update",
            json!({"visibility":{"value":"Reviewers","identifier":"group-id"}}),
            vec!["visibility.value", "visibility.identifier"],
        ),
        (
            "verify",
            json!({"expectCommentId":"10042","expectAttachmentId":"10055"}),
            vec!["expectCommentId", "expectAttachmentId"],
        ),
    ] {
        let snapshot = project(action(&descriptor, action_name), &inputs);
        for key in keys {
            let captured = field(&snapshot, key);
            let pointer = format!("/{}", key.replace('.', "/"));
            assert_eq!(captured["value"], *inputs.pointer(&pointer).unwrap());
            assert_eq!(captured["kind"], "identifier");
            assert_eq!(captured["role"], "fact");
            assert_eq!(captured["display"], "detail");
            assert_eq!(semantic(action_name, &pointer).0, "operation.control");
        }
    }
}

#[test]
fn attachment_projection_preserves_association_and_excludes_transport_hashes() {
    let descriptor = maximal();
    let action = action(&descriptor, "attachment.add");
    let attachments: Vec<_> = (0..21).map(|index| json!({"field":format!("private-{index}"),"filename":format!("file-{index}.txt"),"contentType":"text/plain","size":index+1,"sha256":"f".repeat(64)})).collect();
    let snapshot = project(action, &json!({"attachments":attachments}));
    let projected = field(&snapshot, "attachments");
    assert_eq!(projected["totalCount"], 21);
    assert_eq!(projected["limitedCount"], 1);
    assert_eq!(projected["rows"].as_array().unwrap().len(), 20);
    assert_eq!(projected["rows"][19]["index"], 19);
    assert_eq!(
        projected["rows"][19]["cells"]["filename"]["value"],
        "file-19.txt"
    );
    assert_eq!(projected["rows"][19]["cells"]["size"]["value"], 20);
    assert!(projected["rows"][0]["cells"].get("sha256").is_none());
    assert!(projected["rows"][0]["cells"].get("field").is_none());
    assert!(!snapshot.to_string().contains("private-"));
    assert!(!snapshot.to_string().contains("file-20"));
}

fn configuration() -> crate::JiraProviderConfig {
    serde_json::from_value(json!({"tenant_host":"example.atlassian.net","cloud_id":null})).unwrap()
}
fn maximal() -> agent_access_provider::ServiceDescriptor {
    let mut config = configuration();
    config.content.comment_formats = vec!["adf".into()];
    crate::jira_descriptor(&config)
}
#[test]
fn default_and_minimal_configurations_have_complete_classifications() {
    let config = configuration();
    let descriptor = crate::jira_descriptor(&config);
    assert_eq!(descriptor.actions.len(), 21);
    for action in &descriptor.actions {
        assert_coverage(action);
    }
}
#[test]
fn requested_title_query_and_false_are_retained_but_body_url_and_token_are_opaque() {
    let descriptor = maximal();
    let snapshot = project(
        action(&descriptor, "issue.update"),
        &json!({"issue":"PROJ-7","summary":"  Requested title  ","notifyUsers":false,"content":{"private":"secret"},"url":"https://example.invalid/private"}),
    );
    assert_eq!(field(&snapshot, "summary")["value"], "  Requested title  ");
    assert_eq!(field(&snapshot, "summary")["role"], "change");
    assert_eq!(field(&snapshot, "notifyUsers")["value"], false);
    assert_eq!(field(&snapshot, "content")["value"], true);
    assert_eq!(field(&snapshot, "url")["value"], true);
    assert!(!snapshot.to_string().contains("secret"));
    let snapshot = project(
        action(&descriptor, "comment.update"),
        &json!({"issue":"PROJ-7","commentId":"10042","contentFormat":"adf","content":null}),
    );
    assert_eq!(field(&snapshot, "visibilityMode")["state"], "absent");
    assert_eq!(field(&snapshot, "notifyUsers")["state"], "absent");
    assert_eq!(field(&snapshot, "content")["value"], true);
    let snapshot = project(
        action(&descriptor, "search"),
        &json!({"query":{"type":"jql","value":"summary ~ \"release notes\""},"projects":["PROJ"],"nextPageToken":"private-token"}),
    );
    assert_eq!(
        field(&snapshot, "query.value")["value"],
        "summary ~ \"release notes\""
    );
    assert_eq!(field(&snapshot, "maxResults")["state"], "absent");
    assert_eq!(field(&snapshot, "nextPageToken")["value"], true);
}
#[test]
fn overlong_identity_is_omitted_and_requested_scope_sampling_retains_original_indices() {
    let descriptor = maximal();
    let snapshot = project(
        action(&descriptor, "issue.view"),
        &json!({"issue":"A".repeat(1025)}),
    );
    assert_eq!(field(&snapshot, "issue")["state"], "tooLarge");
    assert!(field(&snapshot, "issue").get("value").is_none());
    let projects: Vec<_> = (0..21).map(|index| format!("PROJ{index}")).collect();
    let snapshot = project(
        action(&descriptor, "search"),
        &json!({"query":{"type":"jql","value":""},"projects":projects}),
    );
    let scopes = field(&snapshot, "projects");
    assert_eq!(scopes["totalCount"], 21);
    assert_eq!(scopes["limitedCount"], 1);
    assert_eq!(scopes["items"][19]["index"], 19);
    assert_eq!(scopes["items"][19]["value"], "PROJ19");
}
