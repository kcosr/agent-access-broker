//! Body collection, pagination and authority regressions shared by both entry points.
use super::*;

fn body_invocation(action: &str, inputs: Value) -> ProviderInvocation {
    InvocationBuilder::new("jira", action)
        .inputs(inputs)
        .resources(BTreeMap::from([(
            "project".to_string(),
            vec!["PROJ".to_string()],
        )]))
        .credential_mode(CredentialMode::PerUser)
        .credential(test_per_user_credential())
        .lookup_credential(test_lookup_credential())
        .companion_reads_authorized(true)
        .build()
}

fn collection_backend(count: u32) -> Arc<StubJiraBackend> {
    let mut backend = StubJiraBackend::default();
    backend.issues.insert("PROJ-1".into(), visible_issue());
    for index in 0..count {
        let id = (10040 + index).to_string();
        let mut comment = test_comment_with_body(&id, "private collected body");
        if index > 0 {
            comment.parent_id = Some("10040".into());
        }
        backend.comments.lock().unwrap().insert(id, comment);
    }
    Arc::new(backend)
}

#[tokio::test]
async fn body_pages_share_default_order_and_count_without_comment_fanout() {
    let backend = collection_backend(23);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
    let issue = provider
        .invoke(body_invocation(
            "issue.view",
            json!({"issue":"PROJ-1", "includeComments":true}),
        ))
        .await
        .unwrap();
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("issue", "per-user-token"),
            ("comments", "per-user-token"),
        ],
    );
    let issue_page = &issue.result["commentPage"];
    assert_eq!(issue_page["count"], 20);
    assert_eq!(issue_page["maxResults"], 20);
    assert_eq!(issue_page["nextStartAt"], 20);
    assert_eq!(issue_page["isLast"], false);
    assert_eq!(issue_page["orderBy"], "+created");
    assert_eq!(issue_page["includeBodies"], true);
    assert_eq!(issue_page["comments"][1]["parentCommentId"], "10040");
    assert_eq!(
        issue_page["comments"][1]["body"],
        adf_text("private collected body")
    );
    let requested = backend.last_comment_list.lock().unwrap().clone().unwrap();
    assert_eq!(requested.max_results, 20);
    assert_eq!(requested.start_at, 0);
    assert_eq!(requested.order_by.as_deref(), Some("+created"));
    assert!(
        !issue
            .audit
            .as_ref()
            .unwrap()
            .to_string()
            .contains("private collected body")
    );
    assert_eq!(
        issue.object_ids.as_ref().unwrap()["commentIds"]
            .as_array()
            .unwrap()
            .len(),
        20
    );

    backend.credential_observations.lock().unwrap().clear();
    let list = provider
        .invoke(body_invocation(
            "comment.list",
            json!({"issue":"PROJ-1", "includeBodies":true}),
        ))
        .await
        .unwrap();
    for key in [
        "comments",
        "count",
        "maxResults",
        "startAt",
        "total",
        "isLast",
        "nextStartAt",
        "orderBy",
        "includeBodies",
    ] {
        assert_eq!(list.result[key], issue_page[key], "{key}");
    }
    assert_credential_observations(
        &backend,
        &[
            ("issue_metadata", "lookup-token"),
            ("comments", "per-user-token"),
        ],
    );
    assert!(
        !list
            .audit
            .as_ref()
            .unwrap()
            .to_string()
            .contains("private collected body")
    );

    let next = provider
        .invoke(body_invocation(
            "comment.list",
            json!({"issue":"PROJ-1", "includeBodies":true, "startAt":20}),
        ))
        .await
        .unwrap();
    assert_eq!(next.result["count"], 3);
    assert_eq!(next.result["startAt"], 20);
    assert_eq!(next.result["isLast"], true);
    assert!(next.result["nextStartAt"].is_null());
}

#[tokio::test]
async fn omitted_and_false_body_flags_keep_primary_reads_usable() {
    let backend = collection_backend(1);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
    for inputs in [
        json!({"issue":"PROJ-1"}),
        json!({"issue":"PROJ-1", "includeComments":false}),
    ] {
        backend.credential_observations.lock().unwrap().clear();
        let result = provider
            .invoke(per_user_invocation("issue.view", inputs, vec![]))
            .await
            .unwrap();
        assert!(result.result.get("commentPage").is_none());
        assert_credential_observations(
            &backend,
            &[
                ("issue_metadata", "lookup-token"),
                ("issue", "per-user-token"),
            ],
        );
    }
    for inputs in [
        json!({"issue":"PROJ-1"}),
        json!({"issue":"PROJ-1", "includeBodies":false}),
    ] {
        let result = provider
            .invoke(per_user_invocation("comment.list", inputs, vec![]))
            .await
            .unwrap();
        assert_eq!(result.result["includeBodies"], false);
        assert_eq!(result.result["maxResults"], 50);
        assert!(result.result["comments"][0].get("body").is_none());
    }
}

#[tokio::test]
async fn body_flags_require_host_proof_before_provider_confirmation() {
    let backend = collection_backend(1);
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
    for (action, flag) in [
        ("issue.view", "includeComments"),
        ("comment.list", "includeBodies"),
    ] {
        let error = provider
            .invoke(per_user_invocation(
                action,
                json!({"issue":"PROJ-1", flag:true}),
                vec![],
            ))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::ServiceActionDenied);
        assert!(backend.credential_observations.lock().unwrap().is_empty());
    }
}

fn page_inputs(start_at: u32, include_bodies: bool) -> CommentListInputs {
    CommentListInputs {
        locator: IssueLocator {
            issue_key: "PROJ-1".into(),
        },
        max_results: 20,
        start_at,
        order_by: Some("+created".into()),
        include_bodies,
    }
}
fn page(count: u32, start_at: u32, total: Option<u32>) -> JiraCommentPage {
    JiraCommentPage {
        comments: (0..count)
            .map(|index| test_comment_with_body(&(10040 + index).to_string(), "private body"))
            .collect(),
        start_at,
        max_results: 20,
        total,
    }
}
fn project(
    page: &JiraCommentPage,
    include_bodies: bool,
) -> Result<comment_pages::ProjectedCommentPage, ProviderError> {
    comment_pages::project(
        page,
        &page_inputs(page.start_at, include_bodies),
        &jira_config(),
        &mut RenderBudget::default(),
    )
}

#[test]
fn comment_page_continuation_uses_disclosed_count_and_never_guesses_completion() {
    let short = project(&page(2, 5, Some(30)), true).unwrap().result;
    assert_eq!(short["nextStartAt"], 7);
    assert_eq!(short["isLast"], false);
    let unknown = project(&page(2, 5, None), true).unwrap().result;
    assert!(unknown["total"].is_null());
    assert!(unknown["isLast"].is_null());
    assert_eq!(unknown["nextStartAt"], 7);
    let empty_unknown = project(&page(0, 5, None), true).unwrap().result;
    assert!(empty_unknown["isLast"].is_null());
    assert!(empty_unknown["nextStartAt"].is_null());
    let empty = project(&page(0, 0, Some(0)), true).unwrap().result;
    assert_eq!(empty["isLast"], true);
    assert!(empty["nextStartAt"].is_null());
    assert!(project(&page(2, u32::MAX, None), true).is_err());
    assert!(project(&page(2, 0, Some(1)), true).is_err());
    assert!(
        comment_pages::project(
            &page(2, 5, None),
            &page_inputs(0, true),
            &jira_config(),
            &mut RenderBudget::default()
        )
        .is_err()
    );
}

#[test]
fn comment_body_page_budget_returns_a_whole_prefix_and_validates_the_suffix() {
    let mut upstream = page(3, 2, Some(8));
    let cap = serde_json::to_vec(upstream.comments[0].body.as_ref().unwrap())
        .unwrap()
        .len() as u64;
    let mut config = jira_config();
    config.content.max_body_bytes = cap;
    config.comments.max_page_body_bytes = Some(cap * 2);
    let result = comment_pages::project(
        &upstream,
        &page_inputs(2, true),
        &config,
        &mut RenderBudget::default(),
    )
    .unwrap();
    assert_eq!(result.result["count"], 2);
    assert_eq!(result.result["limitedBy"], "body_bytes");
    assert_eq!(result.result["nextStartAt"], 4);
    assert_eq!(result.result["isLast"], false);
    assert_eq!(result.comment_ids, ["10040", "10041"]);
    assert!(!result.audit.to_string().contains("private body"));
    assert_eq!(
        result.result["comments"][1]["body"],
        adf_text("private body")
    );
    for bad_body in [
        json!({"type":"doc", "version":1, "content":[{"type":"unsupported"}]}),
        adf_text(&"x".repeat(cap as usize)),
    ] {
        upstream.comments[2].body = Some(bad_body);
        assert!(
            comment_pages::project(
                &upstream,
                &page_inputs(2, true),
                &config,
                &mut RenderBudget::default()
            )
            .is_err()
        );
    }
    // The omitted aggregate cap follows a changed per-body cap, including above 1 MiB.
    config.content.max_body_bytes = 2 * 1024 * 1024;
    config.comments.max_page_body_bytes = None;
    assert!(
        comment_pages::project(
            &page(1, 0, Some(1)),
            &page_inputs(0, true),
            &config,
            &mut RenderBudget::default()
        )
        .is_ok()
    );
}

#[test]
fn comment_body_pages_reject_bad_native_structure_but_metadata_remains_tolerant() {
    for body in [
        json!("bad raw upstream body"),
        json!({"type":"doc","version":1,"content":[{"type":"paragraph","content":[{"type":"text","text":42}]}]}),
        json!({"type":"doc","version":1,"content":[{"type":"heading","attrs":[],"content":[]}]}),
        json!({"type":"doc","version":1,"content":[{"type":"extension","attrs":{"extensionType":"x","extensionKey":"private-extension"}}]}),
    ] {
        let mut upstream = page(1, 0, Some(1));
        upstream.comments[0].body = Some(body);
        let error = project(&upstream, true).err().unwrap();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert!(error.result.is_none());
        let metadata = project(&upstream, false).unwrap();
        assert!(metadata.result["comments"][0].get("body").is_none());
    }
}

#[test]
fn comment_bodies_consume_the_shared_issue_rich_content_budget() {
    let upstream = page(2, 0, Some(2));
    let mut budget = RenderBudget::with_limits(5, 1_000_000);
    assert!(
        comment_pages::project(
            &upstream,
            &page_inputs(0, true),
            &jira_config(),
            &mut budget
        )
        .is_err()
    );
    // A description already consumed the same budget before comment projection.
    let mut budget = RenderBudget::with_limits(5, 1_000_000);
    render_adf_bounded_with_budget(
        &adf_text("issue description"),
        ReadContentFormat::Native,
        1024,
        1024,
        &mut budget,
    )
    .unwrap();
    assert!(
        comment_pages::project(
            &page(1, 0, Some(1)),
            &page_inputs(0, true),
            &jira_config(),
            &mut budget
        )
        .is_err()
    );
}

#[test]
fn comment_page_parser_preserves_native_bodies_and_rejects_invalid_totals() {
    for total in [json!(-1), json!("2"), json!(u64::MAX)] {
        assert!(
            backend::comment_page_from_value(json!({"comments":[],"total":total}), 20).is_err()
        );
    }
    let native = adf_text("private body");
    let parsed = backend::comment_page_from_value(
        json!({"comments":[{"id":"10040","body":native,"parentId":"10039"}]}),
        20,
    )
    .unwrap();
    assert_eq!(parsed.comments[0].body, Some(native));
    assert_eq!(parsed.comments[0].parent_id.as_deref(), Some("10039"));
    assert_eq!(parsed.total, None);
}

#[test]
fn comment_body_defaults_respect_existing_caps_and_flag_types_are_strict() {
    let mut config = jira_config();
    config.comments.max_results = 7;
    let inputs =
        parse_comment_list_inputs(&json!({"issue":"PROJ-1","includeBodies":true}), &config)
            .unwrap();
    assert_eq!(inputs.max_results, 7);
    assert_eq!(inputs.order_by.as_deref(), Some("+created"));
    let inputs = parse_comment_list_inputs(&json!({"issue":"PROJ-1","includeBodies":true,"maxResults":4,"startAt":3,"orderBy":"created"}), &config).unwrap();
    assert_eq!(inputs.max_results, 4);
    assert_eq!(inputs.start_at, 3);
    assert_eq!(inputs.order_by.as_deref(), Some("+created"));
    assert!(
        parse_comment_list_inputs(&json!({"issue":"PROJ-1","includeBodies":"true"}), &config)
            .is_err()
    );
    assert!(
        parse_issue_view_inputs(&json!({"issue":"PROJ-1","includeComments":"true"}), &config)
            .is_err()
    );
    assert!(
        parse_issue_view_inputs(
            &json!({"issue":"PROJ-1","includeComments":true,"startAt":5}),
            &config
        )
        .is_err()
    );
    let parsed: JiraCommentsConfig = serde_json::from_value(json!({})).unwrap();
    assert_eq!(parsed.body_max_results, 20);
    assert_eq!(parsed.max_page_body_bytes, None);
}

#[test]
fn comment_page_configuration_inherits_body_cap_and_rejects_zero_progress_limits() {
    let limits = ProviderLimits::default();
    let context = ValidationContext::new(
        "development",
        "managed",
        &limits,
        ServiceCredentialKinds::default()
            .with_service(Some(CredentialSource::static_kind("basic_api_token"))),
    );
    let mut config = jira_config();
    config.content.max_body_bytes = 2 * 1024 * 1024;
    let mut errors = Vec::new();
    config.validate(&context, &mut errors);
    assert!(errors.is_empty(), "{errors:?}");

    config.comments.max_page_body_bytes = Some(config.content.max_body_bytes - 1);
    config.validate(&context, &mut errors);
    assert_eq!(
        errors,
        ["providers.jira.comments.max_page_body_bytes must be at least content.max_body_bytes"]
    );
    errors.clear();
    config.comments.max_page_body_bytes = Some(config.content.max_body_bytes);
    config.validate(&context, &mut errors);
    assert!(errors.is_empty(), "{errors:?}");

    config.comments.body_max_results = 0;
    config.validate(&context, &mut errors);
    assert_eq!(
        errors,
        ["providers.jira.comments.body_max_results must be non-zero"]
    );
}
