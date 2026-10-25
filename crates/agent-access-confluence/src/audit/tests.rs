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

fn configuration() -> crate::ConfluenceProviderConfig {
    serde_json::from_value(json!({"tenant_host":"example.atlassian.net","cloud_id":null})).unwrap()
}
fn maximal() -> agent_access_provider::ServiceDescriptor {
    let mut config = configuration();
    config.content.page_formats = vec!["storage".into(), "atlas_doc_format".into()];
    crate::confluence_descriptor(&config)
}
#[test]
fn default_and_minimal_configurations_have_complete_classifications() {
    let mut config = configuration();
    for action in &crate::confluence_descriptor(&config).actions {
        assert_coverage(action);
    }
    config.content.page_formats.clear();
    config.content.blog_formats.clear();
    config.content.comment_formats.clear();
    let descriptor = crate::confluence_descriptor(&config);
    assert!(descriptor.actions.len() < maximal().actions.len());
    for action in &descriptor.actions {
        assert_coverage(action);
    }
}
#[test]
fn draft_titles_and_assertions_are_visible_without_handles_or_bodies() {
    let descriptor = maximal();
    let snapshot = project(
        action(&descriptor, "page.draft.update"),
        &json!({"pageId":"123456","draftHandle":"private-handle","title":"Draft release notes","contentFormat":"storage","content":"private body"}),
    );
    assert_eq!(field(&snapshot, "title")["value"], "Draft release notes");
    assert_eq!(field(&snapshot, "title")["role"], "change");
    assert_eq!(field(&snapshot, "draftHandle")["value"], true);
    assert_eq!(field(&snapshot, "content")["value"], true);
    assert!(!snapshot.to_string().contains("private"));
    let snapshot = project(
        action(&descriptor, "page.draft.verify"),
        &json!({"pageId":"123456","draftHandle":"private-handle","expectTitle":"Draft release notes","expectVersion":2}),
    );
    assert_eq!(
        field(&snapshot, "expectTitle")["value"],
        "Draft release notes"
    );
    assert_eq!(field(&snapshot, "expectTitle")["role"], "fact");
    let snapshot = project(
        action(&descriptor, "blog.update"),
        &json!({"blogId":"223456","baseVersion":1,"versionMessage":"雪a","contentFormat":"storage","content":"private body"}),
    );
    assert_eq!(field(&snapshot, "versionMessage")["value"], 4);
    assert!(!snapshot.to_string().contains("雪a"));
}
#[test]
fn search_scope_samples_and_url_presence_are_distinct_from_effective_targets() {
    let descriptor = maximal();
    let spaces: Vec<_> = (0..21).map(|index| format!("SPACE{index}")).collect();
    let snapshot = project(
        action(&descriptor, "search"),
        &json!({"query":{"type":"cql","value":"title ~ \"release notes\""},"spaces":spaces}),
    );
    assert_eq!(
        field(&snapshot, "query.value")["value"],
        "title ~ \"release notes\""
    );
    assert_eq!(field(&snapshot, "maxResults")["state"], "absent");
    assert_eq!(field(&snapshot, "spaces")["totalCount"], 21);
    assert_eq!(field(&snapshot, "spaces")["limitedCount"], 1);
    let snapshot = project(
        action(&descriptor, "page.view"),
        &json!({"url":"https://example.atlassian.net/wiki/private-title?token=secret"}),
    );
    assert_eq!(field(&snapshot, "pageId")["state"], "absent");
    assert_eq!(field(&snapshot, "url")["value"], true);
    assert!(!snapshot.to_string().contains("secret"));
}
