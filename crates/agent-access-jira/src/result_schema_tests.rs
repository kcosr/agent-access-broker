//! Result-schema variants that other tests do not reach, and proof that the
//! strict conformance check behind `invoke_checked` rejects undocumented output.
use super::*;
use agent_access_provider::test_support::check_result_conforms;

fn comment_backend() -> Arc<StubJiraBackend> {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".into(), visible_issue());
    *backend.issue_view_links.lock().unwrap() = Some(Vec::new());
    backend.issue_view_context.lock().unwrap().subtasks = Some(Vec::new());
    for (index, id) in ["10040", "10041", "10042"].into_iter().enumerate() {
        let mut comment = test_comment_with_body(id, "collected body");
        if index > 0 {
            comment.parent_id = Some("10040".into());
            comment.author = Some(JiraUserSummary {
                account_id: Some("account-a".into()),
                display_name: None,
            });
            comment.visibility = Some(JiraCommentVisibility {
                visibility_type: "role".into(),
                value: Some("Administrators".into()),
                identifier: None,
            });
        }
        backend.comments.lock().unwrap().insert(id.into(), comment);
    }
    Arc::new(backend)
}

/// A page body budget that fits exactly one comment body.
fn one_body_config() -> JiraProviderConfig {
    let mut config = jira_config();
    let body = serde_json::to_vec(&adf_text("collected body")).unwrap();
    config.comments.max_page_body_bytes = Some(body.len() as u64);
    config
}

fn comment_invocation(action: &str, inputs: Value, universal_reach: bool) -> ProviderInvocation {
    InvocationBuilder::new("jira", action)
        .inputs(inputs)
        .resources(BTreeMap::from([(
            "project".to_string(),
            vec!["PROJ".to_string()],
        )]))
        .credential(test_credential())
        .lookup_credential(test_lookup_credential())
        .companion_reads_authorized(true)
        .universal_reach(universal_reach)
        .build()
}

#[tokio::test]
async fn eligible_views_with_a_byte_limited_comment_page_conform() {
    let provider = JiraProvider::with_backend(
        one_body_config(),
        ProviderLimits::default(),
        comment_backend(),
    );
    let view = provider
        .invoke_checked(comment_invocation(
            "issue.view",
            json!({"issue": "PROJ-1", "includeComments": true}),
            true,
        ))
        .await
        .unwrap();
    let result = &view.result;
    assert_eq!(result["parent"], Value::Null);
    assert_eq!(result["subtasks"], json!([]));
    assert_eq!(result["issueLinks"], json!([]));
    let page = &result["commentPage"];
    assert_eq!(page["limitedBy"], "body_bytes");
    assert_eq!(page["count"], 1);
    assert_eq!(page["nextStartAt"], 1);
    assert_eq!(page["isLast"], false);

    let withheld = provider
        .invoke_checked(comment_invocation(
            "issue.view",
            json!({"issue": "PROJ-1"}),
            false,
        ))
        .await
        .unwrap();
    for key in ["parent", "subtasks", "issueLinks", "commentPage"] {
        assert!(withheld.result.get(key).is_none(), "{key}");
    }
}

#[tokio::test]
async fn comment_lists_with_and_without_bodies_conform() {
    let provider = JiraProvider::with_backend(
        one_body_config(),
        ProviderLimits::default(),
        comment_backend(),
    );
    let bodies = provider
        .invoke_checked(comment_invocation(
            "comment.list",
            json!({"issue": "PROJ-1", "includeBodies": true, "startAt": 1}),
            false,
        ))
        .await
        .unwrap();
    assert_eq!(bodies.result["limitedBy"], "body_bytes");
    assert_eq!(bodies.result["comments"][0]["parentCommentId"], "10040");
    assert_eq!(
        bodies.result["comments"][0]["author"],
        json!({"accountId": "account-a"})
    );
    assert_eq!(
        bodies.result["comments"][0]["visibility"],
        json!({"type": "role", "value": "Administrators"})
    );
    assert!(bodies.result["comments"][0].get("body").is_some());

    let metadata = provider
        .invoke_checked(comment_invocation(
            "comment.list",
            json!({"issue": "PROJ-1", "orderBy": "-created"}),
            false,
        ))
        .await
        .unwrap();
    assert!(metadata.result.get("limitedBy").is_none());
    assert_eq!(metadata.result["count"], 3);
    assert_eq!(metadata.result["isLast"], true);
    assert_eq!(metadata.result["nextStartAt"], Value::Null);
    assert!(
        metadata.result["comments"]
            .as_array()
            .unwrap()
            .iter()
            .all(|comment| comment.get("body").is_none())
    );
}

#[tokio::test]
async fn strict_conformance_rejects_undocumented_fields_and_wrong_constants() {
    let config = one_body_config();
    let descriptor = jira_descriptor(&config);
    let action = |name: &str| descriptor.action(name).unwrap().clone();
    let provider =
        JiraProvider::with_backend(config.clone(), ProviderLimits::default(), comment_backend());
    let view = provider
        .invoke_checked(comment_invocation(
            "issue.view",
            json!({"issue": "PROJ-1", "includeComments": true}),
            true,
        ))
        .await
        .unwrap()
        .result;
    let conforms = |name: &str, result: Value| {
        check_result_conforms(&action(name), &Ok(ProviderResult::new(result)))
    };
    assert!(conforms("issue.view", view.clone()).is_ok());
    let mut epic = view.clone();
    epic["epic"] = Value::Null;
    assert!(conforms("issue.view", epic).is_err());
    // Presentation, not the provider, adds rendered bodies.
    let mut rendered = view.clone();
    rendered["commentPage"]["comments"][0]["renderedBody"] =
        json!({"format": "text", "value": "collected body"});
    assert!(conforms("issue.view", rendered).is_err());
    // Comment projections omit absent keys rather than emitting nulls.
    let mut null_author = view;
    null_author["commentPage"]["comments"][0]["author"] = json!({"accountId": null});
    assert!(conforms("issue.view", null_author).is_err());
    assert!(
        conforms(
            "attachment.add",
            json!({"status": "partial", "issueKey": "PROJ-1", "project": "PROJ", "attachments": [], "failures": []})
        )
        .is_err()
    );
    let mismatch = |status: &str| {
        Err(ProviderError::allow_with_result(
            ReasonCode::VerificationMismatch,
            "Jira verification mismatch",
            json!({
                "verification": {"status": status, "checked": [], "mismatch": {"type": "comment", "id": "1"}},
                "issueKey": "PROJ-1",
                "project": "PROJ",
            }),
        ))
    };
    assert!(check_result_conforms(&action("verify"), &mismatch("mismatch")).is_ok());
    assert!(check_result_conforms(&action("verify"), &mismatch("matched")).is_err());
}
