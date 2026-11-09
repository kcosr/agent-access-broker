//! Bundled result schemas: coverage in every supported configuration, and
//! the result-bearing failures other tests do not reach. Every invocation
//! here also passes the strict check in `invoke_checked`.
use super::*;
use agent_access_provider::test_support::check_result_conforms;

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(ToString::to_string).collect()
}

/// The configurations of the core action matrix
/// (`runtime/input_explanation_tests.rs`).
fn configurations() -> Vec<(&'static str, ConfluenceProviderConfig)> {
    let configuration = |page: &[&str], blog: &[&str], comment: &[&str], uploads: &[&str]| {
        let mut config = confluence_config();
        config.content = crate::ConfluenceContentConfig {
            page_formats: strings(page),
            blog_formats: strings(blog),
            comment_formats: strings(comment),
            ..Default::default()
        };
        config.attachments.upload_media_types = strings(uploads);
        config
    };
    vec![
        (
            "default",
            configuration(&[], &["storage"], &["storage"], &[]),
        ),
        ("content-disabled", configuration(&[], &[], &[], &[])),
        (
            "pages-text-only",
            configuration(&["storage"], &["storage"], &["storage"], &[]),
        ),
        (
            "pages-object-only",
            configuration(&["atlas_doc_format"], &["storage"], &["storage"], &[]),
        ),
        (
            "all-enabled",
            configuration(
                &["storage", "atlas_doc_format"],
                &["storage"],
                &["storage"],
                &["text/plain", "application/json"],
            ),
        ),
    ]
}

#[test]
fn result_schemas_cover_every_action_in_every_configuration() {
    let mut published = BTreeSet::new();
    for (name, config) in configurations() {
        let descriptor = confluence_descriptor(&config);
        descriptor
            .validate()
            .unwrap_or_else(|problems| panic!("{name}: {problems:?}"));
        for action in &descriptor.actions {
            assert!(
                action.result_schemas.is_some(),
                "{name}: {} declares no result schemas",
                action.action
            );
            published.insert(action.action.clone());
        }
        if name == "all-enabled" {
            assert_eq!(descriptor.actions.len(), RESULT_SCHEMAS.actions().len());
        }
    }
    let bundled = RESULT_SCHEMAS
        .actions()
        .into_iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    assert_eq!(published, bundled);
}

#[test]
fn strict_result_checks_reject_undeclared_fields() {
    let descriptor = confluence_descriptor(&confluence_config());
    let view = descriptor.action("page.view").unwrap();
    let mut page = json!({
        "id": "123456", "title": "Runbook", "space": "ENG",
        "spaceUrl": "https://example.atlassian.net/wiki/spaces/ENG",
        "webUrl": "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=123456",
        "version": 7, "createdAt": null, "updatedAt": null, "createdBy": null, "updatedBy": null,
        "body": {"storage": {"representation": "storage", "value": "<p>x</p>"}},
    });
    check_result_conforms(view, &Ok(ProviderResult::new(page.clone()))).unwrap();
    page["renderedBody"] = json!({"format": "markdown", "value": "x"});
    let problem = check_result_conforms(view, &Ok(ProviderResult::new(page))).unwrap_err();
    assert!(problem.contains("page.view success result"), "{problem}");

    let update = descriptor.action("page.update").unwrap();
    let conflict = |result: Value| {
        Err(ProviderError::error(ReasonCode::VersionConflict, "conflict").with_result(result))
    };
    let declared = json!({"pageId": "123456", "space": "ENG", "expectedBaseVersion": 6});
    check_result_conforms(update, &conflict(declared.clone())).unwrap();
    let mut undeclared = declared;
    undeclared["draftVersion"] = json!(1);
    assert!(check_result_conforms(update, &conflict(undeclared)).is_err());
}

fn update_invocation(
    action: &str,
    id_key: &str,
    id: &str,
    base_version: u64,
) -> ProviderInvocation {
    draft_invocation(
        action,
        json!({
            id_key: id,
            "baseVersion": base_version,
            "contentFormat": "storage",
            "content": "<p>updated</p>",
        }),
    )
}

#[tokio::test]
async fn page_and_blog_update_conflicts_report_the_versions_they_know() {
    let backend = Arc::new(AttributionStubConfluenceBackend::new());
    let provider = confluence_attribution_provider(backend.clone(), &[], confluence_config());
    let error = provider
        .invoke_checked(update_invocation("page.update", "pageId", "123456", 6))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::VersionConflict);
    assert_eq!(
        error.result.as_deref(),
        Some(
            &json!({"pageId": "123456", "space": "ENG", "expectedBaseVersion": 6, "currentVersion": 7})
        )
    );
    let error = provider
        .invoke_checked(update_invocation("blog.update", "blogId", "7777", 2))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::VersionConflict);
    assert_eq!(
        error.result.as_deref(),
        Some(&json!({
            "blogId": "7777", "space": "ENG", "spaceId": "98765",
            "expectedBaseVersion": 2, "currentVersion": 3,
        }))
    );
    assert!(backend.page_update_requests.lock().unwrap().is_empty());
    assert!(backend.blog_update_requests.lock().unwrap().is_empty());

    // Confluence reports the conflict itself: the current version is unknown.
    let backend = Arc::new(AttributionStubConfluenceBackend {
        conflict_on_update: true,
        ..AttributionStubConfluenceBackend::new()
    });
    let provider = confluence_attribution_provider(backend, &[], confluence_config());
    let error = provider
        .invoke_checked(update_invocation("page.update", "pageId", "123456", 7))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::VersionConflict);
    assert_eq!(
        error.result.as_deref(),
        Some(&json!({"pageId": "123456", "space": "ENG", "expectedBaseVersion": 7}))
    );
    let error = provider
        .invoke_checked(update_invocation("blog.update", "blogId", "7777", 3))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::VersionConflict);
    assert_eq!(
        error.result.as_deref(),
        Some(
            &json!({"blogId": "7777", "space": "ENG", "spaceId": "98765", "expectedBaseVersion": 3})
        )
    );
}

#[tokio::test]
async fn comment_update_conflicts_report_the_versions_they_know() {
    let expected = |base_version: u64| {
        json!({
            "commentId": "5001", "kind": "footer", "containerType": "page",
            "pageId": "123456", "space": "ENG", "expectedBaseVersion": base_version,
        })
    };
    let backend = Arc::new(CommentStubConfluenceBackend::page_thread());
    let provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        backend.clone(),
    );
    let error = provider
        .invoke_checked(update_invocation(
            "page.footer_comment.update",
            "commentId",
            "5001",
            4,
        ))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::VersionConflict);
    let mut local = expected(4);
    local["currentVersion"] = json!(1);
    assert_eq!(error.result.as_deref(), Some(&local));
    assert!(backend.update_requests.lock().unwrap().is_empty());

    let backend = Arc::new(CommentStubConfluenceBackend {
        conflict_on_update: true,
        ..CommentStubConfluenceBackend::page_thread()
    });
    let provider =
        ConfluenceProvider::with_backend(confluence_config(), ProviderLimits::default(), backend);
    let error = provider
        .invoke_checked(update_invocation(
            "page.footer_comment.update",
            "commentId",
            "5001",
            1,
        ))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::VersionConflict);
    let mut upstream = expected(1);
    upstream["status"] = json!("upstream_conflict");
    assert_eq!(error.result.as_deref(), Some(&upstream));
}

#[tokio::test]
async fn draft_stage_conflicts_name_the_current_version_or_the_existing_draft() {
    for (content_type, prefix, id_key, current) in [
        (
            ConfluenceDraftContentType::Page,
            "page",
            "pageId",
            json!({"space": "ENG"}),
        ),
        (
            ConfluenceDraftContentType::Blog,
            "blog",
            "blogId",
            json!({"space": "ENG", "spaceId": "98765"}),
        ),
    ] {
        let mut backend = DraftThrottleBackend::new(content_type);
        backend.current_version = Some(4);
        let (provider, backend, _handle) = draft_throttle_provider(backend);
        let action = format!("{prefix}.draft.stage");

        let error = provider
            .invoke_checked(update_invocation(&action, id_key, backend.id(), 3))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::VersionConflict, "{prefix}");
        let mut expected = current.clone();
        expected[id_key] = json!(backend.id());
        expected["expectedBaseVersion"] = json!(3);
        expected["currentVersion"] = json!(4);
        assert_eq!(error.result.as_deref(), Some(&expected), "{prefix}");

        // The current version matches, but a broker-managed draft exists.
        let error = provider
            .invoke_checked(update_invocation(&action, id_key, backend.id(), 4))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::VersionConflict, "{prefix}");
        assert_eq!(
            error.result.as_deref(),
            Some(&json!({
                id_key: backend.id(), "space": "ENG", "spaceId": "98765",
                "expectedBaseVersion": 4, "draftVersion": 1, "lifecycle": "draft",
            })),
            "{prefix}"
        );
    }
}

#[tokio::test]
async fn draft_and_blog_verification_mismatches_report_what_was_checked() {
    for (content_type, prefix, id_key, kind) in [
        (ConfluenceDraftContentType::Page, "page", "pageId", "page"),
        (ConfluenceDraftContentType::Blog, "blog", "blogId", "blog"),
    ] {
        let (provider, backend, handle) =
            draft_throttle_provider(DraftThrottleBackend::new(content_type));
        let action = format!("{prefix}.draft.verify");
        let error = provider
            .invoke_checked(draft_invocation(
                &action,
                json!({id_key: backend.id(), "draftHandle": handle, "expectVersion": 1, "expectTitle": "Other"}),
            ))
            .await
            .unwrap_err();
        assert_eq!(
            error.reason_code(),
            ReasonCode::VerificationMismatch,
            "{prefix}"
        );
        assert_eq!(error.decision(), Decision::Allow, "{prefix}");
        assert_eq!(
            error.result.as_deref(),
            Some(&json!({
                "operation": action,
                "verification": {
                    "status": "mismatch",
                    "checked": [{"type": format!("{kind}Version"), "version": 1}],
                    "mismatch": {"type": format!("{kind}Title")},
                },
                id_key: backend.id(), "space": "ENG", "spaceId": "98765", "lifecycle": "draft",
            })),
            "{prefix}"
        );
    }

    let backend = Arc::new(AttributionStubConfluenceBackend::new());
    let provider = confluence_attribution_provider(backend, &[], confluence_config());
    let error = provider
        .invoke_checked(draft_invocation(
            "blog.verify",
            json!({"blogId": "7777", "expectVersion": 9}),
        ))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::VerificationMismatch);
    assert_eq!(
        error.result.as_deref(),
        Some(&json!({
            "verification": {
                "status": "mismatch",
                "checked": [],
                "mismatch": {"type": "blogVersion", "expected": 9, "actual": 3},
            },
            "blogId": "7777", "space": "ENG", "spaceId": "98765",
        }))
    );
}
