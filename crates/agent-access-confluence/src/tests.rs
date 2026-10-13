use super::*;
use crate::{ActionIo, Decision, raw_download_io};
use agent_access_provider::test_support::{InvocationBuilder, basic_credential, credential_token};
use bytes::Bytes;
use futures_util::{StreamExt, stream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use uuid::Uuid;
use wiremock::matchers::{method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[test]
fn descriptor_declares_storage_body_attribution_for_exact_action_set() {
    let descriptor = confluence_descriptor(&confluence_config());
    let attributed = descriptor
        .actions
        .iter()
        .filter_map(|action| {
            action
                .attribution
                .map(|capability| (action.action.as_str(), capability))
        })
        .collect::<BTreeMap<_, _>>();
    let body = |verb| {
        AttributionCapability::required(verb, "body", AttributionRepresentation::ConfluenceStorage)
    };
    let expected = BTreeMap::from([
        ("page.create", body(AttributionVerb::Add)),
        ("page.update", body(AttributionVerb::Update)),
        ("page.draft.create", body(AttributionVerb::Add)),
        ("page.draft.stage", body(AttributionVerb::Add)),
        ("page.draft.update", body(AttributionVerb::Update)),
        ("blog.create", body(AttributionVerb::Add)),
        ("blog.update", body(AttributionVerb::Update)),
        ("blog.draft.create", body(AttributionVerb::Add)),
        ("blog.draft.stage", body(AttributionVerb::Add)),
        ("blog.draft.update", body(AttributionVerb::Update)),
        ("page.footer_comment.add", body(AttributionVerb::Add)),
        ("page.footer_comment.reply.add", body(AttributionVerb::Add)),
        ("page.inline_comment.reply.add", body(AttributionVerb::Add)),
        ("blog.footer_comment.add", body(AttributionVerb::Add)),
        ("blog.footer_comment.reply.add", body(AttributionVerb::Add)),
        ("blog.inline_comment.reply.add", body(AttributionVerb::Add)),
    ]);
    assert_eq!(attributed, expected);
}

#[test]
fn descriptor_requires_stable_signing_key_for_exactly_the_draft_actions() {
    let descriptor = confluence_descriptor(&confluence_config());
    let signed = descriptor
        .actions
        .iter()
        .filter(|action| action.requires_stable_signing_key)
        .map(|action| action.action.as_str())
        .collect::<BTreeSet<_>>();
    let drafts = descriptor
        .actions
        .iter()
        .map(|action| action.action.as_str())
        .filter(|action| action.starts_with("page.draft.") || action.starts_with("blog.draft."))
        .collect::<BTreeSet<_>>();
    assert_eq!(drafts.len(), 20);
    assert_eq!(signed, drafts);
}

#[test]
fn descriptor_declares_transfer_io_and_search_containment() {
    let descriptor = confluence_descriptor(&confluence_config());
    let uploads: [(&str, &[&str]); 4] = [
        ("attachment.add", &["pageId"]),
        ("blog.attachment.add", &["blogId"]),
        ("page.draft.attachment.add", &["pageId", "draftHandle"]),
        ("blog.draft.attachment.add", &["blogId", "draftHandle"]),
    ];
    let downloads = [
        "attachment.download",
        "blog.attachment.download",
        "page.draft.attachment.download",
        "blog.draft.attachment.download",
    ];
    for action in &descriptor.actions {
        let name = action.action.as_str();
        let expected =
            if let Some((_, locators)) = uploads.iter().find(|(upload, _)| *upload == name) {
                ActionIo::MultipartUpload {
                    plan: attachment_upload_plan(locators, None),
                }
            } else if downloads.contains(&name) {
                raw_download_io()
            } else {
                ActionIo::Json
            };
        assert_eq!(action.io, expected, "unexpected io for {name}");
    }
    for name in uploads.iter().map(|(name, _)| *name).chain(downloads) {
        assert!(descriptor.action(name).is_some(), "missing {name}");
    }
    let contained = descriptor
        .actions
        .iter()
        .filter(|action| action.search_contained)
        .map(|action| action.action.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(contained, BTreeSet::from(["search", "blog.search"]));
}

#[test]
fn descriptor_lookup_requirements_follow_scope_resolution_needs() {
    let descriptor = confluence_descriptor(&confluence_config());
    for action in &descriptor.actions {
        let name = action.action.as_str();
        let expected = match name {
            "search" | "blog.search" => LookupRequirement::None,
            "page.draft.create" | "page.draft.stage" | "blog.draft.stage" => {
                LookupRequirement::ScopeResolution
            }
            "blog.create" => LookupRequirement::Execution,
            _ if name.starts_with("page.draft.") || name.starts_with("blog.draft.") => {
                LookupRequirement::Execution
            }
            _ => LookupRequirement::ScopeResolution,
        };
        assert_eq!(action.lookup, expected, "unexpected lookup for {name}");
        assert_eq!(action.required_scope_types(), ["space"], "{name}");
        assert_eq!(action.credential_modes, ["service", "per_user"], "{name}");
    }
}

#[test]
fn descriptor_offers_gateway_bearer_profile_only_for_gateway_configs() {
    let mut config = confluence_config();
    let direct = confluence_descriptor(&config);
    assert_eq!(
        direct.credentials,
        CredentialDescriptor::default().profile("confluence-cloud-api-token", "basic_api_token")
    );
    assert_eq!(direct.presentation_body_limit, Some(1024));
    config.allowed_upstream_hosts = vec!["https://api.atlassian.com/ex/confluence/**".to_string()];
    let gateway = confluence_descriptor(&config);
    assert_eq!(
        gateway.credential_profile_kind("confluence-bearer-token"),
        Some("bearer_token")
    );
    config.cloud_id = None;
    assert_eq!(
        confluence_descriptor(&config).credential_profile_kind("confluence-bearer-token"),
        None
    );
}

#[test]
fn page_placement_capabilities_and_parsers_are_closed_and_mutually_exclusive() {
    let provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        Arc::new(PageMoveTestBackend::new()),
    );
    for action_name in ["page.create", "page.draft.create"] {
        let action = confluence_descriptor(&provider.config)
            .actions
            .into_iter()
            .find(|candidate| candidate.action == action_name)
            .unwrap();
        assert!(
            action.lookup.credential_required(),
            "{action_name} must be lookup-backed"
        );
        assert_eq!(action.input_schema["additionalProperties"], false);
        assert_eq!(
            action.input_schema["properties"]["parentPageId"]["type"],
            "string"
        );
        assert_eq!(
            action.input_schema["properties"]["parentUrl"]["type"],
            "string"
        );
    }
    let move_action = confluence_descriptor(&provider.config)
        .actions
        .into_iter()
        .find(|candidate| candidate.action == "page.move")
        .unwrap();
    assert!(move_action.lookup.credential_required());
    assert_eq!(move_action.input_schema["additionalProperties"], false);
    assert_eq!(
        move_action.input_schema["properties"]["position"]["enum"],
        json!(["before", "after", "append"])
    );
    assert_eq!(
        move_action.input_schema["properties"]["targetPageId"]["type"],
        "string"
    );
    assert_eq!(
        move_action.input_schema["properties"]["targetUrl"]["type"],
        "string"
    );
    let descriptor = confluence_descriptor(&provider.config);
    for action_name in ["page.create", "page.move", "page.draft.create"] {
        assert!(
            descriptor
                .action(action_name)
                .unwrap()
                .lookup
                .before_policy(),
            "{action_name} must resolve its scope through lookup"
        );
    }

    let config = confluence_config();
    let create = parse_page_create_inputs(
        &json!({
            "space": "ENG",
            "title": "Child",
            "parentUrl": "https://example.atlassian.net/wiki/spaces/ENG/pages/200/Parent",
            "contentFormat": "storage",
            "content": "<p>body</p>"
        }),
        &config,
    )
    .unwrap();
    assert_eq!(create.parent.unwrap().page_id, "200");
    let page_move = parse_page_move_inputs(
        &json!({
            "url": "https://example.atlassian.net/wiki/spaces/ENG/pages/100/Child",
            "position": "before",
            "targetPageId": "200"
        }),
        &config,
    )
    .unwrap();
    assert_eq!(page_move.page.page_id, "100");
    assert_eq!(page_move.position, ConfluencePageMovePosition::Before);
    assert_eq!(page_move.target.page_id, "200");

    for invalid in [
        json!({
            "space": "ENG", "title": "Child", "parentPageId": "200",
            "parentUrl": "https://example.atlassian.net/wiki/spaces/ENG/pages/200/Parent",
            "contentFormat": "storage", "content": "<p>body</p>"
        }),
        json!({
            "space": "ENG", "title": "Child", "parentPageId": "200",
            "contentFormat": "storage", "content": "<p>body</p>", "parent": "200"
        }),
    ] {
        assert!(parse_page_create_inputs(&invalid, &config).is_err());
    }
    for invalid in [
        json!({"pageId": "100", "url": "https://example.atlassian.net/wiki/spaces/ENG/pages/100/Child", "position": "append", "targetPageId": "200"}),
        json!({"pageId": "100", "position": "append", "targetPageId": "200", "targetUrl": "https://example.atlassian.net/wiki/spaces/ENG/pages/200/Parent"}),
        json!({"pageId": "100", "position": "append", "targetPageId": "100"}),
        json!({"pageId": "100", "position": "middle", "targetPageId": "200"}),
        json!({"pageId": "100", "position": "append", "parentPageId": "200"}),
    ] {
        assert!(parse_page_move_inputs(&invalid, &config).is_err());
    }
}

#[tokio::test]
async fn page_move_lookup_scopes_authorize_space_and_reject_cross_space() {
    let backend = Arc::new(PageMoveTestBackend::new());
    let provider =
        ConfluenceProvider::with_backend(confluence_config(), ProviderLimits::default(), backend);
    let create_scopes = provider
        .lookup_scopes(
            "page.create",
            &json!({
                "space": "ENG", "title": "Child", "parentPageId": "200",
                "contentFormat": "storage", "content": "<p>body</p>"
            }),
            Some(&credential()),
        )
        .await
        .unwrap();
    assert_eq!(create_scopes["space"], vec!["ENG"]);
    assert!(!create_scopes.contains_key("page"));

    let append_scopes = provider
        .lookup_scopes(
            "page.move",
            &json!({"pageId": "100", "position": "append", "targetPageId": "200"}),
            Some(&credential()),
        )
        .await
        .unwrap();
    assert_eq!(append_scopes["space"], vec!["ENG"]);
    assert!(!append_scopes.contains_key("page"));
    let before_scopes = provider
        .lookup_scopes(
            "page.move",
            &json!({"pageId": "100", "position": "before", "targetPageId": "200"}),
            Some(&credential()),
        )
        .await
        .unwrap();
    assert!(!before_scopes.contains_key("page"));

    let target_under_folder = PageMoveTestBackend::new();
    {
        let mut hierarchies = target_under_folder.hierarchies.lock().unwrap();
        let target = hierarchies.get_mut("200").unwrap();
        target.parent_page_id = Some("folder-abc".to_string());
        target.parent_type = Some("folder".to_string());
    }
    let target_under_folder_provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        Arc::new(target_under_folder),
    );
    let append_scopes = target_under_folder_provider
        .lookup_scopes(
            "page.move",
            &json!({"pageId": "100", "position": "append", "targetPageId": "200"}),
            Some(&credential()),
        )
        .await
        .unwrap();
    assert!(!append_scopes.contains_key("page"));
    let error = target_under_folder_provider
        .lookup_scopes(
            "page.move",
            &json!({"pageId": "100", "position": "before", "targetPageId": "200"}),
            Some(&credential()),
        )
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);

    let mut cross_space = PageMoveTestBackend::new();
    cross_space.pages.get_mut("200").unwrap().space = "OPS".to_string();
    let cross_space_provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        Arc::new(cross_space),
    );
    let error = cross_space_provider
        .lookup_scopes(
            "page.move",
            &json!({"pageId": "100", "position": "append", "targetPageId": "200"}),
            Some(&credential()),
        )
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
}

#[tokio::test]
async fn page_create_uses_requested_parent_or_space_homepage_and_verifies_readback() {
    for (parent_page_id, expected_parent, expected_placement) in [
        (Some("200"), "200", "requested_parent"),
        (None, "55555", "space_homepage"),
    ] {
        let backend = Arc::new(PageMoveTestBackend::new());
        let provider = ConfluenceProvider::with_backend(
            confluence_config(),
            ProviderLimits::default(),
            backend.clone(),
        );
        let mut inputs = json!({
            "space": "ENG", "title": "Created", "contentFormat": "storage",
            "content": "<p>body</p>"
        });
        if let Some(parent_page_id) = parent_page_id {
            inputs["parentPageId"] = json!(parent_page_id);
        }
        let mut request = invocation("page.create", inputs);
        request = InvocationBuilder::from(request)
            .resources(ResourceScopes::from([(
                "space".to_string(),
                vec!["ENG".to_string()],
            )]))
            .build();

        let result = provider.invoke(request).await.unwrap();

        assert_eq!(result.result["parentPageId"], expected_parent);
        assert_eq!(result.result["placement"], expected_placement);
        assert_eq!(result.result["verification"]["status"], "matched");
        let audit = result.audit.as_ref().unwrap();
        assert_eq!(audit["parentPageId"], expected_parent);
        assert_eq!(audit["placement"], expected_placement);
        assert_eq!(audit["verificationStatus"], "matched");
        let requests = backend.create_requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].parent_page_id.as_deref(), parent_page_id);
    }
}

#[tokio::test]
async fn page_move_moves_only_after_cycle_check_and_fails_closed_on_readback_mismatch() {
    let backend = Arc::new(PageMoveTestBackend::new());
    let provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        backend.clone(),
    );
    let result = provider.invoke(page_move_invocation()).await.unwrap();
    assert_eq!(result.result["pageId"], "100");
    assert_eq!(result.result["position"], "append");
    assert_eq!(result.result["targetPageId"], "200");
    assert_eq!(result.result["parentPageId"], "200");
    assert_eq!(result.result["childPosition"], 0);
    assert_eq!(result.result["previousParentId"], "111");
    assert_eq!(result.result["previousParentType"], "page");
    assert_eq!(result.result["verification"]["status"], "matched");
    assert_eq!(
        backend.moves.lock().unwrap().as_slice(),
        &[(
            "100".to_string(),
            ConfluencePageMovePosition::Append,
            "200".to_string(),
        )]
    );

    let moved_from_folder_backend = Arc::new(PageMoveTestBackend::new());
    {
        let mut hierarchies = moved_from_folder_backend.hierarchies.lock().unwrap();
        let page = hierarchies.get_mut("100").unwrap();
        page.parent_page_id = Some("folder-abc".to_string());
        page.parent_type = Some("folder".to_string());
    }
    moved_from_folder_backend
        .ancestors
        .lock()
        .unwrap()
        .push(ConfluencePageAncestor {
            id: "folder-ancestor".to_string(),
            content_type: "folder".to_string(),
        });
    let moved_from_folder_provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        moved_from_folder_backend,
    );
    let result = moved_from_folder_provider
        .invoke(page_move_invocation())
        .await
        .unwrap();
    assert_eq!(result.result["previousParentId"], "folder-abc");
    assert_eq!(result.result["previousParentType"], "folder");

    let cycle_backend = Arc::new(PageMoveTestBackend::new());
    cycle_backend
        .ancestors
        .lock()
        .unwrap()
        .push(ConfluencePageAncestor {
            id: "100".to_string(),
            content_type: "page".to_string(),
        });
    let cycle_provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        cycle_backend.clone(),
    );
    let error = cycle_provider
        .invoke(page_move_invocation())
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
    assert!(cycle_backend.moves.lock().unwrap().is_empty());

    let mismatch_backend = Arc::new(PageMoveTestBackend {
        preserve_parent_on_move: true,
        ..PageMoveTestBackend::new()
    });
    let mismatch_provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        mismatch_backend.clone(),
    );
    let error = mismatch_provider
        .invoke(page_move_invocation())
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(
        error.audit.as_ref().unwrap()["mutationPhase"],
        "post_move_hierarchy_readback"
    );
    assert_eq!(mismatch_backend.moves.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn page_move_places_pages_before_and_after_siblings_and_verifies_positions() {
    for (position, expected_page_position, expected_target_position) in
        [("before", 0, 1), ("after", 1, 0)]
    {
        let backend = Arc::new(PageMoveTestBackend::new());
        let provider = ConfluenceProvider::with_backend(
            confluence_config(),
            ProviderLimits::default(),
            backend.clone(),
        );

        let result = provider
            .invoke(sibling_page_move_invocation(position))
            .await
            .unwrap();

        assert_eq!(result.result["position"], position);
        assert_eq!(result.result["targetPageId"], "200");
        assert_eq!(result.result["parentPageId"], "55555");
        assert_eq!(result.result["childPosition"], expected_page_position);
        assert_eq!(
            result.result["targetChildPosition"],
            expected_target_position
        );
        assert_eq!(result.result["verification"]["status"], "matched");
        let expected_position = if position == "before" {
            ConfluencePageMovePosition::Before
        } else {
            ConfluencePageMovePosition::After
        };
        assert_eq!(
            backend.moves.lock().unwrap().as_slice(),
            &[("100".to_string(), expected_position, "200".to_string())]
        );
    }

    let mismatch_backend = Arc::new(PageMoveTestBackend {
        preserve_order_on_move: true,
        ..PageMoveTestBackend::new()
    });
    let mismatch_provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        mismatch_backend,
    );
    let error = mismatch_provider
        .invoke(sibling_page_move_invocation("before"))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(
        error.audit.as_ref().unwrap()["mutationPhase"],
        "post_move_order_readback"
    );
}

/// Throttling after an applied write reports the write as applied but
/// unverified, never as a rate limit to wait out and retry.
fn assert_unverified_after_throttling(error: &ProviderError, stage: &str, locators: Value) {
    assert_eq!(error.decision(), crate::Decision::Error);
    assert_eq!(error.reason_code(), ReasonCode::MutationVerificationFailed);
    assert_eq!(
        error.message,
        mutation_unverified_after_throttling_message("confluence")
    );
    let result = error.result.as_deref().unwrap();
    assert_eq!(result["mutationStatus"], "applied_unverified");
    assert_eq!(result["retrySafe"], false);
    assert_eq!(result["verificationStage"], stage);
    assert_eq!(result["safeLocators"], locators);
    for field in ["retryAfterSeconds", "retryAt", "limitScope", "service"] {
        assert!(result.get(field).is_none(), "{field}: {result}");
    }
}

#[tokio::test]
async fn throttled_placement_readbacks_after_applied_writes_are_unverified() {
    let space_scopes = ResourceScopes::from([("space".to_string(), vec!["ENG".to_string()])]);
    for (action, locators) in [
        (
            "page.create",
            json!({"pageId": "900001", "parentPageId": "55555"}),
        ),
        (
            "page.draft.create",
            json!({"pageId": "900002", "parentPageId": "55555"}),
        ),
    ] {
        let backend = Arc::new(PageMoveTestBackend {
            throttle_hierarchy_after_mutation: true,
            ..PageMoveTestBackend::new()
        });
        let mut request = invocation(
            action,
            json!({
                "space": "ENG",
                "title": "Created",
                "contentFormat": "storage",
                "content": "<p>body</p>"
            }),
        );
        request = InvocationBuilder::from(request)
            .resources(space_scopes.clone())
            .build();
        let error = ConfluenceProvider::with_backend(
            confluence_config(),
            ProviderLimits::default(),
            backend,
        )
        .invoke(request)
        .await
        .unwrap_err();
        assert_unverified_after_throttling(&error, "post_create_readback", locators);
        let audit = error.audit.as_deref().unwrap();
        assert_eq!(audit["mutationPhase"], "post_create_readback");
        assert_eq!(audit["upstreamFailure"], "upstream_rate_limited");
    }

    let move_locators = json!({
        "pageId": "100",
        "targetPageId": "200",
        "parentPageId": "200",
        "previousParentId": "111",
        "previousParentType": "page",
    });
    for (backend, stage) in [
        (
            PageMoveTestBackend {
                throttle_hierarchy_after_mutation: true,
                ..PageMoveTestBackend::new()
            },
            "post_move_hierarchy_readback",
        ),
        (
            PageMoveTestBackend {
                throttle_children_after_mutation: true,
                ..PageMoveTestBackend::new()
            },
            "post_move_order_readback",
        ),
    ] {
        let backend = Arc::new(backend);
        let error = ConfluenceProvider::with_backend(
            confluence_config(),
            ProviderLimits::default(),
            backend.clone(),
        )
        .invoke(page_move_invocation())
        .await
        .unwrap_err();
        assert_unverified_after_throttling(&error, stage, move_locators.clone());
        assert_eq!(error.audit.as_deref().unwrap()["mutationPhase"], stage);
        assert_eq!(backend.moves.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn page_placement_mutation_call_failures_report_possible_side_effects() {
    let create_backend = Arc::new(PageMoveTestBackend {
        fail_create: true,
        ..PageMoveTestBackend::new()
    });
    let create_provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        create_backend,
    );
    let mut create_request = invocation(
        "page.create",
        json!({
            "space": "ENG",
            "title": "Created",
            "contentFormat": "storage",
            "content": "<p>body</p>"
        }),
    );
    create_request = InvocationBuilder::from(create_request)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .build();

    let create_error = create_provider.invoke(create_request).await.unwrap_err();

    assert_eq!(create_error.reason_code(), ReasonCode::UpstreamTimeout);
    assert!(create_error.result.is_none());
    assert_eq!(
        create_error.audit.as_ref().unwrap()["mutationPhase"],
        "create_mutation"
    );
    assert_eq!(
        create_error.audit.as_ref().unwrap()["sideEffectPossible"],
        true
    );
    assert_eq!(
        create_error.audit.as_ref().unwrap()["upstreamFailure"],
        "upstream_timeout"
    );
    assert_eq!(
        create_error.object_ids.as_ref().unwrap()["parentPageId"],
        "55555"
    );

    let draft_backend = Arc::new(PageMoveTestBackend {
        fail_draft_create: true,
        ..PageMoveTestBackend::new()
    });
    let draft_provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        draft_backend,
    );
    let mut draft_request = invocation(
        "page.draft.create",
        json!({
            "space": "ENG",
            "title": "Draft",
            "contentFormat": "storage",
            "content": "<p>body</p>"
        }),
    );
    draft_request = InvocationBuilder::from(draft_request)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .build();

    let draft_error = draft_provider.invoke(draft_request).await.unwrap_err();

    assert_eq!(draft_error.reason_code(), ReasonCode::UpstreamTimeout);
    assert_eq!(
        draft_error.audit.as_ref().unwrap()["mutationPhase"],
        "create_mutation"
    );
    assert_eq!(
        draft_error.audit.as_ref().unwrap()["sideEffectPossible"],
        true
    );
    assert_eq!(
        draft_error.audit.as_ref().unwrap()["upstreamFailure"],
        "upstream_timeout"
    );
    assert_eq!(
        draft_error.object_ids.as_ref().unwrap()["parentPageId"],
        "55555"
    );

    let move_backend = Arc::new(PageMoveTestBackend {
        fail_move: true,
        ..PageMoveTestBackend::new()
    });
    let move_provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        move_backend,
    );

    let move_error = move_provider
        .invoke(page_move_invocation())
        .await
        .unwrap_err();

    assert_eq!(move_error.reason_code(), ReasonCode::UpstreamTimeout);
    assert_eq!(
        move_error.audit.as_ref().unwrap()["mutationPhase"],
        "move_mutation"
    );
    assert_eq!(
        move_error.audit.as_ref().unwrap()["sideEffectPossible"],
        true
    );
    assert_eq!(
        move_error.audit.as_ref().unwrap()["upstreamFailure"],
        "upstream_timeout"
    );
    assert_eq!(move_error.object_ids.as_ref().unwrap()["pageId"], "100");
    assert_eq!(
        move_error.object_ids.as_ref().unwrap()["parentPageId"],
        "200"
    );
}

#[tokio::test]
async fn page_view_resolves_viewpage_locator_with_lookup_before_policy() {
    let backend = Arc::new(StubConfluenceBackend {
        page: ConfluencePage {
            id: "123456".to_string(),
            title: "Runbook".to_string(),
            space: "ENG".to_string(),
            web_url: None,
            space_web_url: None,
            status: Some("current".to_string()),
            version: 7,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::from([("storage".to_string(), "<p>secret body</p>".to_string())]),
        },
        search_page: ConfluenceSearchPage {
            pages: vec![],
            max_results: 2,
            next_page_token: None,
        },
    });
    let provider =
        ConfluenceProvider::with_backend(confluence_config(), ProviderLimits::default(), backend);
    let scopes = provider
        .lookup_scopes(
            "page.view",
            &json!({
                "url": "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=123456"
            }),
            Some(&credential()),
        )
        .await
        .unwrap();
    assert_eq!(scopes["space"], vec!["ENG"]);
    assert!(!scopes.contains_key("page"));
}

#[tokio::test]
async fn page_view_rejects_legacy_space_input() {
    let backend = Arc::new(StubConfluenceBackend {
        page: ConfluencePage {
            id: "123456".to_string(),
            title: "Runbook".to_string(),
            space: "ENG".to_string(),
            web_url: None,
            space_web_url: None,
            status: Some("current".to_string()),
            version: 7,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::new(),
        },
        search_page: ConfluenceSearchPage {
            pages: vec![],
            max_results: 2,
            next_page_token: None,
        },
    });
    let provider =
        ConfluenceProvider::with_backend(confluence_config(), ProviderLimits::default(), backend);
    let error = provider
        .lookup_scopes(
            "page.view",
            &json!({ "pageId": "123456", "space": "OPS" }),
            Some(&credential()),
        )
        .await
        .unwrap_err();
    assert_eq!(error.decision(), Decision::Deny);
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
}

#[tokio::test]
async fn verify_scope_resolution_uses_lookup_for_existing_pages_in_requested_space() {
    let backend = Arc::new(StubConfluenceBackend {
        page: ConfluencePage {
            id: "123456".to_string(),
            title: "Runbook".to_string(),
            space: "ENG".to_string(),
            web_url: None,
            space_web_url: None,
            status: Some("current".to_string()),
            version: 7,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::new(),
        },
        search_page: ConfluenceSearchPage {
            pages: vec![],
            max_results: 2,
            next_page_token: None,
        },
    });
    let provider =
        ConfluenceProvider::with_backend(confluence_config(), ProviderLimits::default(), backend);
    let scopes = provider
        .lookup_scopes(
            "verify",
            &json!({
                "pageId": "123456",
                "expectVersion": 7
            }),
            Some(&credential()),
        )
        .await
        .unwrap();
    assert_eq!(scopes["space"], vec!["ENG"]);
    assert!(!scopes.contains_key("page"));
}

#[tokio::test]
async fn verify_scope_resolution_uses_authoritative_space_from_lookup() {
    let backend = Arc::new(StubConfluenceBackend {
        page: ConfluencePage {
            id: "123456".to_string(),
            title: "Runbook".to_string(),
            space: "OPS".to_string(),
            web_url: None,
            space_web_url: None,
            status: Some("current".to_string()),
            version: 7,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::new(),
        },
        search_page: ConfluenceSearchPage {
            pages: vec![],
            max_results: 2,
            next_page_token: None,
        },
    });
    let provider =
        ConfluenceProvider::with_backend(confluence_config(), ProviderLimits::default(), backend);
    let scopes = provider
        .lookup_scopes(
            "verify",
            &json!({
                "pageId": "123456",
                "expectVersion": 7
            }),
            Some(&credential()),
        )
        .await
        .unwrap();
    assert_eq!(scopes["space"], vec!["OPS"]);
    assert!(!scopes.contains_key("page"));
}

#[test]
fn comment_action_matrix_registers_comment_mutations() {
    for action in [
        "page.footer_comment.list",
        "page.footer_comment.view",
        "page.footer_comment.add",
        "page.footer_comment.update",
        "page.footer_comment.delete",
        "page.footer_comment.reply.list",
        "page.footer_comment.reply.add",
        "page.inline_comment.list",
        "page.inline_comment.view",
        "page.inline_comment.update",
        "page.inline_comment.delete",
        "page.inline_comment.reply.list",
        "page.inline_comment.reply.add",
        "blog.footer_comment.list",
        "blog.footer_comment.view",
        "blog.footer_comment.add",
        "blog.footer_comment.update",
        "blog.footer_comment.delete",
        "blog.footer_comment.reply.list",
        "blog.footer_comment.reply.add",
        "blog.inline_comment.list",
        "blog.inline_comment.view",
        "blog.inline_comment.update",
        "blog.inline_comment.delete",
        "blog.inline_comment.reply.list",
        "blog.inline_comment.reply.add",
    ] {
        assert!(
            confluence_comment_action(action).is_some(),
            "expected {action} to be supported"
        );
    }
    for action in [
        "page.inline_comment.add",
        "blog.inline_comment.add",
        "footer_comment.list",
        "comment.list",
        "page.comment.list",
        "blog.comment.list",
    ] {
        assert!(
            confluence_comment_action(action).is_none(),
            "expected {action} to be outside the supported comment action matrix"
        );
    }
}

#[tokio::test]
async fn comment_scope_resolution_walks_nested_parent_chain_with_lookup() {
    let backend = Arc::new(CommentStubConfluenceBackend::page_thread());
    let provider =
        ConfluenceProvider::with_backend(confluence_config(), ProviderLimits::default(), backend);

    let scopes = provider
        .lookup_scopes(
            "page.inline_comment.reply.add",
            &json!({
                "commentId": "6003",
                "contentFormat": "storage",
                "content": "<p>reply</p>"
            }),
            Some(&credential_with_token("lookup-token")),
        )
        .await
        .unwrap();

    assert_eq!(scopes["space"], vec!["ENG"]);
    assert!(!scopes.contains_key("page"));
}

#[tokio::test]
async fn comment_view_uses_lookup_for_authorization_and_execution_for_body() {
    let backend = Arc::new(CommentStubConfluenceBackend::page_thread());
    let provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        backend.clone(),
    );
    let mut request = invocation(
        "page.footer_comment.view",
        json!({
            "commentId": "5001",
            "bodyFormat": "storage"
        }),
    );
    request = InvocationBuilder::from(request)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .build();
    request = InvocationBuilder::from(request)
        .execution(ExecutionAccess::Static(credential_with_token(
            "execute-token",
        )))
        .build();
    request = InvocationBuilder::from(request)
        .lookup_credential(credential_with_token("lookup-token"))
        .build();

    let result = provider.invoke(request).await.unwrap();

    assert_eq!(
        result.result["comment"]["body"]["storage"]["value"],
        "<p>root body</p>"
    );
    assert_eq!(result.result["comment"]["pageId"], "123456");
    let observations = backend.credential_observations.lock().unwrap().clone();
    assert!(
        observations.iter().any(|observation| {
            observation.operation == "comment"
                && observation.credential_token == Some("lookup-token".to_string())
                && observation.body_format.is_none()
        }),
        "expected lookup credential to authorize comment ancestry: {observations:?}"
    );
    assert!(
        observations.iter().any(|observation| {
            observation.operation == "comment"
                && observation.credential_token == Some("execute-token".to_string())
                && observation.body_format == Some("storage".to_string())
        }),
        "expected execution credential to fetch requested comment body: {observations:?}"
    );
    assert!(!result.audit.unwrap().to_string().contains("root body"));
}

#[tokio::test]
async fn comment_add_applies_configured_storage_attribution_footer() {
    let backend = Arc::new(CommentStubConfluenceBackend::page_thread());
    let provider = ConfluenceProvider {
        config: confluence_config(),
        limits: ProviderLimits::default(),
        backend: backend.clone(),
        continuations: ConfluenceContinuations::new(
            &confluence_config(),
            &ProviderLimits::default(),
            None,
        ),
        attribution: ProviderAttributionConfig::from_patterns(
            &confluence_descriptor(&confluence_config()),
            &[String::from("page.footer_comment.add")],
        ),
    };
    let broker_request_id = "550e8400-e29b-41d4-a716-446655440000";
    let mut request = invocation(
        "page.footer_comment.add",
        json!({
            "pageId": "123456",
            "contentFormat": "storage",
            "content": "<p>comment before attribution</p>"
        }),
    );
    request = InvocationBuilder::from(request)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .build();
    request = InvocationBuilder::from(request)
        .correlation(crate::CorrelationContext::new(
            "agent-request-id".to_string(),
            broker_request_id.to_string(),
        ))
        .build();

    let result = provider.invoke(request).await.unwrap();

    let audit = result.audit.as_ref().unwrap();
    assert_eq!(audit["attribution"]["applied"], true);
    assert_eq!(audit["attribution"]["representation"], "storage");
    assert!(!audit.to_string().contains("comment before attribution"));
    let created = backend.create_requests.lock().unwrap();
    assert_eq!(created.len(), 1);
    let body = &created[0].body.value;
    assert!(body.contains("<p>comment before attribution</p>"));
    assert!(body.contains("<!-- agent-access-attribution:start -->"));
    assert!(body.contains(&format!(
        "Added via Agent Access Broker. Request ID: {broker_request_id}"
    )));
}

#[tokio::test]
async fn page_create_applies_configured_adf_attribution_footer_and_dedupes() {
    let backend = Arc::new(AttributionStubConfluenceBackend::new());
    let provider =
        confluence_attribution_provider(backend.clone(), &["page.create"], confluence_config());
    let old_request_id = "11111111-1111-4111-8111-111111111111";
    let broker_request_id = "550e8400-e29b-41d4-a716-446655440000";
    let mut request = invocation(
        "page.create",
        json!({
            "space": "ENG",
            "title": "ADF Page",
            "contentFormat": "atlas_doc_format",
            "content": adf_body_with_footer(
                "page before attribution",
                "Added",
                old_request_id,
            ),
        }),
    );
    request = InvocationBuilder::from(request)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .build();
    request = InvocationBuilder::from(request)
        .correlation(crate::CorrelationContext::new(
            "agent-request-id".to_string(),
            broker_request_id.to_string(),
        ))
        .build();

    let result = provider.invoke(request).await.unwrap();

    let audit = result.audit.as_ref().unwrap();
    assert_eq!(audit["attribution"]["applied"], true);
    assert_eq!(audit["attribution"]["representation"], "adf");
    assert_eq!(audit["attribution"]["deduped"], true);
    assert_eq!(audit["attribution"]["verb"], "add");
    let requests = backend.page_create_requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].body.representation, "atlas_doc_format");
    let body: Value = serde_json::from_str(&requests[0].body.value).unwrap();
    assert_eq!(
        adf_footer_texts(&body),
        vec![format!(
            "Added via Agent Access Broker. Request ID: {broker_request_id}"
        )]
    );
    assert!(
        !serde_json::to_string(&body)
            .unwrap()
            .contains(old_request_id)
    );
}

#[tokio::test]
async fn page_update_enforces_adf_body_cap_after_attribution() {
    let backend = Arc::new(AttributionStubConfluenceBackend::new());
    let body = adf_body("short");
    let base_body_bytes = serde_json::to_string(&body).unwrap().len() as u64;
    let mut config = confluence_config();
    config.content.max_body_bytes = base_body_bytes + 1;
    let provider = confluence_attribution_provider(backend.clone(), &["page.update"], config);
    let broker_request_id = "550e8400-e29b-41d4-a716-446655440000";
    let mut request = invocation(
        "page.update",
        json!({
            "pageId": "123456",
            "baseVersion": 7,
            "contentFormat": "atlas_doc_format",
            "content": body,
        }),
    );
    request = InvocationBuilder::from(request)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .build();
    request = InvocationBuilder::from(request)
        .correlation(crate::CorrelationContext::new(
            "agent-request-id".to_string(),
            broker_request_id.to_string(),
        ))
        .build();

    let error = provider.invoke(request).await.unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::BodySizeDenied);
    assert!(error.message.contains("after broker attribution was added"));
    assert!(backend.page_update_requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn page_and_blog_storage_writes_apply_configured_attribution_footer_and_dedupe() {
    let backend = Arc::new(AttributionStubConfluenceBackend::new());
    let provider = confluence_attribution_provider(
        backend.clone(),
        &["page.create", "page.update", "blog.create", "blog.update"],
        confluence_config(),
    );
    let old_request_id = "11111111-1111-4111-8111-111111111111";
    let broker_request_id = "550e8400-e29b-41d4-a716-446655440000";

    let mut page_create = invocation(
        "page.create",
        json!({
            "space": "ENG",
            "title": "Storage Page",
            "contentFormat": "storage",
            "content": storage_body_with_footer(
                "<p>page create before attribution</p>",
                "Added",
                old_request_id,
            ),
        }),
    );
    page_create = InvocationBuilder::from(page_create)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .build();
    page_create = InvocationBuilder::from(page_create)
        .correlation(crate::CorrelationContext::new(
            "agent-request-id".to_string(),
            broker_request_id.to_string(),
        ))
        .build();
    let page_create_result = provider.invoke(page_create).await.unwrap();

    let mut page_update = invocation(
        "page.update",
        json!({
            "pageId": "123456",
            "baseVersion": 7,
            "contentFormat": "storage",
            "content": storage_body_with_footer(
                "<p>page update before attribution</p>",
                "Updated",
                old_request_id,
            ),
        }),
    );
    page_update = InvocationBuilder::from(page_update)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .build();
    page_update = InvocationBuilder::from(page_update)
        .correlation(crate::CorrelationContext::new(
            "agent-request-id".to_string(),
            broker_request_id.to_string(),
        ))
        .build();
    let page_update_result = provider.invoke(page_update).await.unwrap();

    let mut blog_create = invocation(
        "blog.create",
        json!({
            "space": "ENG",
            "title": "Storage Blog",
            "contentFormat": "storage",
            "content": storage_body_with_footer(
                "<p>blog create before attribution</p>",
                "Added",
                old_request_id,
            ),
        }),
    );
    blog_create = InvocationBuilder::from(blog_create)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .build();
    blog_create = InvocationBuilder::from(blog_create)
        .correlation(crate::CorrelationContext::new(
            "agent-request-id".to_string(),
            broker_request_id.to_string(),
        ))
        .build();
    let blog_create_result = provider.invoke(blog_create).await.unwrap();

    let mut blog_update = invocation(
        "blog.update",
        json!({
            "blogId": "7777",
            "baseVersion": 3,
            "contentFormat": "storage",
            "content": storage_body_with_footer(
                "<p>blog update before attribution</p>",
                "Updated",
                old_request_id,
            ),
        }),
    );
    blog_update = InvocationBuilder::from(blog_update)
        .resources(ResourceScopes::from([
            ("space".to_string(), vec!["ENG".to_string()]),
            ("blog".to_string(), vec!["7777".to_string()]),
        ]))
        .build();
    blog_update = InvocationBuilder::from(blog_update)
        .correlation(crate::CorrelationContext::new(
            "agent-request-id".to_string(),
            broker_request_id.to_string(),
        ))
        .build();
    let blog_update_result = provider.invoke(blog_update).await.unwrap();

    assert_storage_attribution_audit(&page_create_result, "add");
    assert_storage_attribution_audit(&page_update_result, "update");
    assert_storage_attribution_audit(&blog_create_result, "add");
    assert_storage_attribution_audit(&blog_update_result, "update");

    let page_create_requests = backend.page_create_requests.lock().unwrap();
    assert_eq!(page_create_requests.len(), 1);
    assert_storage_footer(
        &page_create_requests[0].body.value,
        "Added",
        broker_request_id,
        old_request_id,
    );
    let page_update_requests = backend.page_update_requests.lock().unwrap();
    assert_eq!(page_update_requests.len(), 1);
    assert_storage_footer(
        &page_update_requests[0].body.value,
        "Updated",
        broker_request_id,
        old_request_id,
    );
    let blog_create_requests = backend.blog_create_requests.lock().unwrap();
    assert_eq!(blog_create_requests.len(), 1);
    assert_storage_footer(
        &blog_create_requests[0].body.value,
        "Added",
        broker_request_id,
        old_request_id,
    );
    let blog_update_requests = backend.blog_update_requests.lock().unwrap();
    assert_eq!(blog_update_requests.len(), 1);
    assert_storage_footer(
        &blog_update_requests[0].body.value,
        "Updated",
        broker_request_id,
        old_request_id,
    );
}

#[tokio::test]
async fn normalized_storage_conversion_precedes_attribution_and_final_cap() {
    let backend = Arc::new(AttributionStubConfluenceBackend::new());
    let provider = confluence_attribution_provider(
        backend.clone(),
        &["page.create", "blog.create"],
        confluence_config(),
    );
    let broker_request_id = "550e8400-e29b-41d4-a716-446655440000";

    let mut page_request = invocation(
        "page.create",
        json!({
            "space": "ENG",
            "title": "Markdown Page",
            "contentFormat": "markdown",
            "content": "## Converted\n\n**body**"
        }),
    );
    page_request = InvocationBuilder::from(page_request)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .build();
    page_request = InvocationBuilder::from(page_request)
        .correlation(crate::CorrelationContext::new(
            "agent-request-id".to_string(),
            broker_request_id.to_string(),
        ))
        .build();
    provider.invoke(page_request).await.unwrap();

    let mut blog_request = invocation(
        "blog.create",
        json!({
            "space": "ENG",
            "title": "Plain Blog",
            "contentFormat": "plain_text",
            "content": "*literal*\nsecond"
        }),
    );
    blog_request = InvocationBuilder::from(blog_request)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .build();
    blog_request = InvocationBuilder::from(blog_request)
        .correlation(crate::CorrelationContext::new(
            "agent-request-id".to_string(),
            broker_request_id.to_string(),
        ))
        .build();
    provider.invoke(blog_request).await.unwrap();

    let page_body = backend.page_create_requests.lock().unwrap()[0]
        .body
        .value
        .clone();
    assert!(page_body.starts_with("<h2>Converted</h2><p><strong>body</strong></p>"));
    assert_eq!(
        page_body.matches("agent-access-attribution:start").count(),
        1
    );
    assert!(
        page_body.find("<h2>Converted").unwrap()
            < page_body.find("agent-access-attribution:start").unwrap()
    );
    let blog_body = backend.blog_create_requests.lock().unwrap()[0]
        .body
        .value
        .clone();
    assert!(blog_body.starts_with("<p>*literal*<br />second</p>"));
    assert_eq!(
        blog_body.matches("agent-access-attribution:start").count(),
        1
    );

    let converted = markdown_to_confluence_storage_bounded("body", 1024).unwrap();
    let mut capped_config = confluence_config();
    capped_config.content.max_body_bytes = converted.len() as u64;
    let capped_backend = Arc::new(AttributionStubConfluenceBackend::new());
    let capped_provider =
        confluence_attribution_provider(capped_backend.clone(), &["page.create"], capped_config);
    let mut capped_request = invocation(
        "page.create",
        json!({
            "space": "ENG",
            "title": "Capped",
            "contentFormat": "markdown",
            "content": "body"
        }),
    );
    capped_request = InvocationBuilder::from(capped_request)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .build();
    let error = capped_provider.invoke(capped_request).await.unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::BodySizeDenied);
    assert!(error.message.contains("after broker attribution was added"));
    assert!(
        capped_backend
            .page_create_requests
            .lock()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn comment_execution_reconfirms_parent_chain_after_lookup() {
    let mut backend = CommentStubConfluenceBackend::page_thread();
    backend.pages.insert(
        "654321".to_string(),
        ConfluencePage {
            id: "654321".to_string(),
            title: "Moved Thread".to_string(),
            space: "OPS".to_string(),
            web_url: None,
            space_web_url: None,
            status: Some("current".to_string()),
            version: 1,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::new(),
        },
    );
    let mut execution_comments = backend.comments.clone();
    execution_comments.insert(
        "6601".to_string(),
        comment(
            "6601",
            ConfluenceCommentKind::Inline,
            Some("654321"),
            None,
            None,
            "<p>moved root</p>",
        ),
    );
    execution_comments
        .get_mut("6002")
        .unwrap()
        .parent_comment_id = Some("6601".to_string());
    backend
        .comments_by_token
        .insert("execute-token".to_string(), execution_comments);
    let provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        Arc::new(backend),
    );
    let mut request = invocation(
        "page.inline_comment.view",
        json!({
            "commentId": "6003",
            "bodyFormat": "storage"
        }),
    );
    request = InvocationBuilder::from(request)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .build();
    request = InvocationBuilder::from(request)
        .lookup_credential(credential_with_token("lookup-token"))
        .build();
    request = InvocationBuilder::from(request)
        .execution(ExecutionAccess::Static(credential_with_token(
            "execute-token",
        )))
        .build();

    let error = provider.invoke(request).await.unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
}

#[tokio::test]
async fn comment_actions_reject_denied_space_wrong_container_and_non_current_comments() {
    let provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        Arc::new(CommentStubConfluenceBackend::page_thread()),
    );
    let mut denied = invocation(
        "page.footer_comment.list",
        json!({
            "pageId": "123456",
            "bodyFormat": "storage"
        }),
    );
    denied = InvocationBuilder::from(denied)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["OPS".to_string()],
        )]))
        .build();
    assert_eq!(
        provider.invoke(denied).await.unwrap_err().reason_code(),
        ReasonCode::ScopeUnresolved
    );

    let mut blog_backend = CommentStubConfluenceBackend::page_thread();
    blog_backend.blogs.insert(
        "222222".to_string(),
        ConfluenceBlog {
            id: "222222".to_string(),
            title: "Blog".to_string(),
            space: "ENG".to_string(),
            space_id: "98765".to_string(),
            web_url: None,
            space_web_url: None,
            status: Some("current".to_string()),
            version: 1,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::new(),
        },
    );
    blog_backend.comments.insert(
        "7001".to_string(),
        comment(
            "7001",
            ConfluenceCommentKind::Footer,
            None,
            Some("222222"),
            None,
            "<p>blog comment</p>",
        ),
    );
    let provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        Arc::new(blog_backend),
    );
    let mut wrong_container = invocation(
        "page.footer_comment.view",
        json!({
            "commentId": "7001",
            "bodyFormat": "storage"
        }),
    );
    wrong_container = InvocationBuilder::from(wrong_container)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .build();
    assert_eq!(
        provider
            .invoke(wrong_container)
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::ScopeUnresolved
    );

    let mut non_current_backend = CommentStubConfluenceBackend::page_thread();
    non_current_backend.comments.get_mut("5001").unwrap().status = Some("archived".to_string());
    let provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        Arc::new(non_current_backend),
    );
    let mut non_current = invocation(
        "page.footer_comment.view",
        json!({
            "commentId": "5001",
            "bodyFormat": "storage"
        }),
    );
    non_current = InvocationBuilder::from(non_current)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .build();
    assert_eq!(
        provider
            .invoke(non_current)
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::ScopeUnresolved
    );
}

#[tokio::test]
async fn comment_inputs_and_parent_chains_fail_closed() {
    let provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        Arc::new(CommentStubConfluenceBackend::page_thread()),
    );
    assert_eq!(
        provider
            .invoke(invocation(
                "page.footer_comment.add",
                json!({
                    "pageId": "0",
                    "contentFormat": "storage",
                    "content": "<p>comment</p>"
                }),
            ))
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::InputInvalid
    );

    let mut body_cap = invocation(
        "page.footer_comment.add",
        json!({
            "pageId": "123456",
            "contentFormat": "storage",
            "content": "x".repeat(2048)
        }),
    );
    body_cap = InvocationBuilder::from(body_cap)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .build();
    assert_eq!(
        provider.invoke(body_cap).await.unwrap_err().reason_code(),
        ReasonCode::BodySizeDenied
    );

    let mut cycle_backend = CommentStubConfluenceBackend::page_thread();
    cycle_backend
        .comments
        .get_mut("6003")
        .unwrap()
        .parent_comment_id = Some("6003".to_string());
    let provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        Arc::new(cycle_backend),
    );
    assert_eq!(
        provider
            .lookup_scopes(
                "page.inline_comment.view",
                &json!({
                    "commentId": "6003",
                    "bodyFormat": "storage"
                }),
                Some(&credential()),
            )
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::ScopeUnresolved
    );

    let mut missing_backend = CommentStubConfluenceBackend::page_thread();
    missing_backend
        .comments
        .get_mut("6003")
        .unwrap()
        .parent_comment_id = Some("6999".to_string());
    let provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        Arc::new(missing_backend),
    );
    assert_eq!(
        provider
            .lookup_scopes(
                "page.inline_comment.view",
                &json!({
                    "commentId": "6003",
                    "bodyFormat": "storage"
                }),
                Some(&credential()),
            )
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::ScopeUnresolved
    );
}

#[test]
fn comment_protocol_checks_reject_unsupported_containers_and_overreturns() {
    for value in [
        json!({
            "id": "9001",
            "attachmentId": "att1",
            "status": "current"
        }),
        json!({
            "id": "9001",
            "customContentId": "custom1",
            "status": "current"
        }),
    ] {
        assert!(comment_from_value(value, ConfluenceCommentKind::Footer).is_err());
    }

    let container = ConfluenceResolvedCommentContainer::Page(attachment_list_page());
    let action = confluence_comment_action("page.footer_comment.list").unwrap();
    let comments = vec![
        comment(
            "5001",
            ConfluenceCommentKind::Footer,
            Some("123456"),
            None,
            None,
            "<p>one</p>",
        ),
        comment(
            "5002",
            ConfluenceCommentKind::Footer,
            Some("123456"),
            None,
            None,
            "<p>two</p>",
        ),
    ];
    assert_eq!(
        validate_comment_page(&comments, action, &container, true, 1, None)
            .unwrap_err()
            .reason_code(),
        ReasonCode::UpstreamProtocolFailed
    );
}

#[test]
fn comment_pagination_token_is_bound_to_request_and_filters() {
    let continuations =
        ConfluenceContinuations::new(&confluence_config(), &ProviderLimits::default(), None);
    let request = invocation(
        "page.inline_comment.list",
        json!({
            "pageId": "123456",
            "bodyFormat": "storage",
            "resolutionStatus": "open",
            "sort": "-created-date",
            "maxResults": 2
        }),
    );
    let credential = credential();
    let container = ConfluenceResolvedCommentContainer::Page(attachment_list_page());
    let inputs = CommentListInputs {
        container_id: "123456".to_string(),
        body_format: Some("storage".to_string()),
        resolution_status: Some("open".to_string()),
        sort: Some("-created-date".to_string()),
        max_results: Some(2),
        next_page_token: None,
    };
    let action = confluence_comment_action("page.inline_comment.list").unwrap();
    let binding = comment_list_binding(
        action,
        &container,
        None,
        Some("storage".to_string()),
        &inputs,
        2,
    );
    let token = continuations
        .seal_comment_page(request.context(), &credential, &binding, "cursor-2")
        .unwrap();
    assert_ne!(token, "cursor-2");
    assert_eq!(
        continuations
            .open_comment_page(request.context(), &credential, &binding, &token)
            .unwrap(),
        "cursor-2"
    );

    let rejected = |request: &ProviderInvocation, binding: &ConfluenceCommentListBinding| {
        let error = continuations
            .open_comment_page(request.context(), &credential, binding, &token)
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
        assert_eq!(error.decision(), Decision::Deny);
    };
    let changes: [fn(&mut ConfluenceCommentListBinding); 8] = [
        |binding| binding.kind = ConfluenceCommentKind::Footer,
        |binding| binding.container_type = ConfluenceCommentContainerType::Blog,
        |binding| binding.container_id = "654321".to_string(),
        |binding| binding.comment_id = Some("777".to_string()),
        |binding| binding.space = "OPS".to_string(),
        |binding| binding.body_format = None,
        |binding| binding.resolution_status = Some("resolved".to_string()),
        |binding| binding.max_results = 1,
    ];
    for change in changes {
        let mut changed = binding.clone();
        change(&mut changed);
        rejected(&request, &changed);
    }
    let mut changed = binding.clone();
    changed.sort = Some("created-date".to_string());
    rejected(&request, &changed);

    for changed_request in [
        InvocationBuilder::from(request.clone())
            .action("page.footer_comment.list")
            .build(),
        InvocationBuilder::from(request.clone())
            .principal("bob")
            .build(),
        InvocationBuilder::from(request.clone())
            .credential_mode(CredentialMode::PerUser)
            .build(),
        InvocationBuilder::from(request.clone())
            .execution_context("external")
            .build(),
    ] {
        rejected(&changed_request, &binding);
    }
}

#[test]
fn comment_pagination_next_link_must_stay_on_same_collection() {
    let current_url =
        Url::parse("https://example.atlassian.net/wiki/api/v2/pages/123456/inline-comments")
            .unwrap();
    let api_base = Url::parse("https://example.atlassian.net/wiki/api/v2/").unwrap();
    let allowed = vec!["https://example.atlassian.net/wiki/api/v2/**".to_string()];

    assert_eq!(
        next_comment_page_cursor(
            &current_url,
            &api_base,
            "/wiki/api/v2/pages/123456/inline-comments?cursor=abc&limit=2&body-format=storage&resolution-status=open&sort=-created-date",
            &allowed
        )
        .unwrap(),
        "abc".to_string()
    );

    for link in [
        "https://evil.example/wiki/api/v2/pages/123456/inline-comments?cursor=abc",
        "/wiki/api/v2/pages/999999/inline-comments?cursor=abc",
        "/wiki/api/v2/pages/123456/inline-comments",
        "/wiki/api/v2/pages/123456/inline-comments?cursor=abc&expand=body",
        "/wiki/api/v2/pages/123456/inline-comments?cursor=abc&cursor=def",
        "/wiki/api/v2/pages/123456/inline-comments?cursor=",
    ] {
        assert!(
            next_comment_page_cursor(&current_url, &api_base, link, &allowed).is_err(),
            "expected comment pagination link to fail validation: {link}"
        );
    }
}

#[test]
fn comment_pagination_sources_reject_ambiguous_link_headers() {
    let current_url =
        Url::parse("https://example.atlassian.net/wiki/api/v2/pages/123456/inline-comments")
            .unwrap();
    let api_base = Url::parse("https://example.atlassian.net/wiki/api/v2/").unwrap();
    let allowed = vec!["https://example.atlassian.net/wiki/api/v2/**".to_string()];

    assert_eq!(
        next_comment_page_cursor_from_sources(
            &current_url,
            &api_base,
            None,
            &["/wiki/api/v2/pages/123456/inline-comments?cursor=abc".to_string()],
            &allowed,
        )
        .unwrap(),
        Some("abc".to_string())
    );
    assert_eq!(
        next_comment_page_cursor_from_sources(
            &current_url,
            &api_base,
            Some("/wiki/api/v2/pages/123456/inline-comments?cursor=abc"),
            &["/wiki/api/v2/pages/123456/inline-comments?cursor=abc".to_string()],
            &allowed,
        )
        .unwrap(),
        Some("abc".to_string())
    );
    assert!(
        next_comment_page_cursor_from_sources(
            &current_url,
            &api_base,
            Some("/wiki/api/v2/pages/123456/inline-comments?cursor=abc"),
            &["/wiki/api/v2/pages/123456/inline-comments?cursor=def".to_string()],
            &allowed,
        )
        .is_err()
    );

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::LINK,
        reqwest::header::HeaderValue::from_static(
            "</wiki/api/v2/pages/123456/inline-comments?cursor=abc>; rel=\"next\", </wiki/api/v2/pages/123456/inline-comments?cursor=prev>; rel=\"prev\"",
        ),
    );
    assert_eq!(
        comment_next_links_from_headers(&headers).unwrap(),
        vec!["/wiki/api/v2/pages/123456/inline-comments?cursor=abc".to_string()]
    );

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::LINK,
        reqwest::header::HeaderValue::from_static(
            "</wiki/api/v2/pages/123456/inline-comments?cursor=abc>; rel=\"next\", </wiki/api/v2/pages/123456/inline-comments?cursor=def>; rel=\"next\"",
        ),
    );
    assert!(comment_next_links_from_headers(&headers).is_err());
}

#[test]
fn cql_accepts_bounded_title_search_and_rejects_mixed_precedence() {
    let spaces = parse_cql_spaces(r#"space = ENG and title ~ "runbook""#).unwrap();
    assert_eq!(spaces, BTreeSet::from(["ENG".to_string()]));

    let error =
        parse_cql_spaces(r#"space = ENG and title ~ "runbook" or space = OPS"#).unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);

    let spaces =
        parse_cql_spaces(r#"(space = ENG and title ~ "runbook") or (space = OPS and type = page)"#)
            .unwrap();
    assert_eq!(
        spaces,
        BTreeSet::from(["ENG".to_string(), "OPS".to_string()])
    );
}

#[test]
fn cql_rejects_non_ascii_unsupported_predicates_without_panicking() {
    let error = parse_cql_spaces(r#"space = ENG and type = page and résumé = true"#).unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
}

#[test]
fn raw_cql_accepts_expanded_fields_and_canonicalizes_dates() {
    assert_eq!(canonical_cql(r#"text ~ "deploy""#), r#"text ~ "deploy""#);
    assert_eq!(
        canonical_cql(r#"labels NOT IN (security, "needs triage")"#),
        r#"label NOT IN (security, "needs triage")"#
    );
    assert_eq!(
        canonical_cql(r#"creator = "abc:123" AND contributor != alice"#),
        r#"creator = "abc:123" AND contributor != "alice""#
    );
    assert_eq!(
        canonical_cql(
            r#"creator = "6025ef716c5817007082ba6e" AND contributor IN ("6025ef716c5817007082ba6e")"#
        ),
        r#"creator = "6025ef716c5817007082ba6e" AND contributor IN ("6025ef716c5817007082ba6e")"#
    );
    assert_eq!(
        canonical_cql(r#"mention IN ("abc:123")"#),
        r#"mention IN ("abc:123")"#
    );
    assert_eq!(
        canonical_cql("ancestor IN (123456, 234567) AND parent = 345678"),
        "ancestor IN (123456, 234567) AND parent = 345678"
    );
    assert_eq!(
        canonical_cql(
            r#"created >= 2024/01/31 AND lastmodified < "2024-02-01 12:30" ORDER BY lastModified DESC, title"#
        ),
        r#"created >= "2024-01-31" AND lastModified < "2024-02-01 12:30" ORDER BY lastModified DESC, title ASC"#
    );
}

#[test]
fn raw_cql_keeps_clause_like_text_inside_string_literals() {
    let raw = "title ~ \"quote \\\" slash \\\\ ) AND OR space IN type =\\ntext\"";
    assert_eq!(canonical_cql(raw), raw);
}

#[test]
fn raw_cql_is_reemitted_and_rejects_unsafe_literals() {
    let query = build_confluence_search_query(
        &ConfluenceSearchQueryInput::Cql {
            value: r#"(space in ("ENG") and title ~ "runbook") or (content.id = 123456)"#
                .to_string(),
        },
        &EffectiveSearchScope::Finite(BTreeSet::from(["ENG".to_string()])),
        &SearchLimitsConfig::default(),
    )
    .unwrap();
    assert_eq!(
        query.cql,
        r#"((space IN (ENG) AND title ~ "runbook") OR id = 123456) AND space IN (ENG) AND type = page"#
    );

    for raw in [
        "title ~ \"x\\\"",
        "space in (\"ENG)",
        "title ~ \"runbook\")",
    ] {
        let error = parse_cql_query(raw).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
    }
}

#[test]
fn raw_cql_rejects_unsupported_fields_operators_and_functions() {
    for raw in [
        "type = blogpost",
        "space != OPS",
        "title !~ \"x\"",
        "currentUser()",
        "filter = 123",
        "created >= 2024-01-01T12:30:00Z",
        "created >= 2024-99-99",
        "lastModified < \"2024-02-31 99:99\"",
        "title ~ \"runbook\" AND (ORDER BY title)",
        "content.property.foo = bar",
        "content = 123456",
        "mention != alice",
        "labels = +urgent",
        "label IS EMPTY",
        "label IS NOT EMPTY",
    ] {
        let error = parse_cql_query(raw).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid, "{raw}");
    }
}

#[test]
fn blog_cql_composes_blogpost_type_and_rejects_page_hierarchy_fields() {
    let query = build_confluence_blog_search_query(
        &ConfluenceSearchQueryInput::Cql {
            value: r#"space = ENG AND type = blogpost AND title ~ "release""#.to_string(),
        },
        &EffectiveSearchScope::Finite(BTreeSet::from(["ENG".to_string()])),
        &SearchLimitsConfig::default(),
    )
    .unwrap();
    assert_eq!(
        query.cql,
        r#"(space = ENG AND type = blogpost AND title ~ "release") AND space IN (ENG) AND type = blogpost"#
    );
    assert_eq!(query.injected_type_predicate, "type_blogpost");

    for raw in ["type = page", "ancestor = 123456", "parent IN (123456)"] {
        let error = build_confluence_blog_search_query(
            &ConfluenceSearchQueryInput::Cql {
                value: raw.to_string(),
            },
            &EffectiveSearchScope::AllExcept(BTreeSet::new()),
            &SearchLimitsConfig::default(),
        )
        .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid, "{raw}");
    }
}

#[test]
fn all_except_cql_preserves_caller_grouping_and_response_exclusions() {
    let excluded = BTreeSet::from(["PRIVATE".to_string(), "IN".to_string()]);
    let boundary = EffectiveSearchScope::AllExcept(excluded);
    let query = build_confluence_search_query(
        &ConfluenceSearchQueryInput::Cql {
            value: "space = PRIVATE OR title ~ \"runbook\" ORDER BY title".to_string(),
        },
        &boundary,
        &SearchLimitsConfig::default(),
    )
    .unwrap();
    assert_eq!(
        query.cql,
        "(space = PRIVATE OR title ~ \"runbook\") AND space NOT IN (\"IN\", PRIVATE) AND type = page ORDER BY title ASC"
    );
    assert_eq!(query.injected_space_predicate, "space_not_in");
    assert!(!query.response_scope.authorizes_value("PRIVATE"));
    assert!(query.response_scope.authorizes_value("NEW"));
    assert_eq!(
        query.response_scope.audit_value("space")["excludedValues"],
        json!(["IN", "PRIVATE"])
    );
    let narrowed = build_confluence_search_query(
        &ConfluenceSearchQueryInput::Cql {
            value: "space IN (PRIVATE, ENG)".to_string(),
        },
        &boundary,
        &SearchLimitsConfig::default(),
    )
    .unwrap();
    assert_eq!(
        narrowed.response_scope,
        EffectiveSearchScope::Finite(BTreeSet::from(["ENG".to_string()]))
    );
    let blog = build_confluence_blog_search_query(
        &ConfluenceSearchQueryInput::Cql {
            value: "title ~ \"runbook\"".to_string(),
        },
        &boundary,
        &SearchLimitsConfig::default(),
    )
    .unwrap();
    assert!(
        blog.cql
            .contains("space NOT IN (\"IN\", PRIVATE) AND type = blogpost")
    );
    let authorization = SearchAuthorization::new(
        "space".to_string(),
        SearchAuthorizationScope::AllExcept {
            excluded_values: vec!["PRIVATE".to_string()],
        },
    );
    assert!(
        effective_search_scope(&authorization, &BTreeSet::from(["PRIVATE".to_string()])).is_err()
    );
    assert_eq!(
        effective_search_scope(&authorization, &BTreeSet::from(["NEW".to_string()])).unwrap(),
        EffectiveSearchScope::Finite(BTreeSet::from(["NEW".to_string()]))
    );
}

#[tokio::test]
async fn all_except_confluence_search_checks_returned_containment() {
    for (space, allowed) in [("NEW", true), ("PRIVATE", false), ("", false)] {
        let page = test_current_page("123456", "Runbook", space);
        let backend = Arc::new(StubConfluenceBackend {
            page: page.clone(),
            search_page: ConfluenceSearchPage {
                pages: vec![page],
                max_results: 1,
                next_page_token: None,
            },
        });
        let provider = ConfluenceProvider::with_backend(
            confluence_config(),
            ProviderLimits::default(),
            backend,
        );
        let mut request = invocation(
            "search",
            json!({"query":{"type":"cql","value":"title ~ \"runbook\""},"maxResults":1}),
        );
        request = InvocationBuilder::from(request)
            .search(SearchAuthorization::new(
                "space".to_string(),
                SearchAuthorizationScope::AllExcept {
                    excluded_values: vec!["PRIVATE".to_string()],
                },
            ))
            .build();
        let result = provider.invoke(request).await;
        assert_eq!(result.is_ok(), allowed, "{space}: {result:?}");
        if let Err(error) = result {
            assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
        }
    }
}

#[test]
fn raw_cql_rejects_length_token_list_string_depth_and_sort_caps() {
    let long = format!(
        "{}title ~ \"runbook\"",
        " ".repeat(MAX_CONFLUENCE_RAW_QUERY_BYTES + 1)
    );
    let error = parse_cql_query(&long).unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);

    let token_heavy = (0..=MAX_CONFLUENCE_QUERY_TOKENS)
        .map(|_| "title")
        .collect::<Vec<_>>()
        .join(" ");
    let error = parse_cql_query(&token_heavy).unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);

    let in_values = (0..=MAX_CONFLUENCE_IN_LIST_VALUES)
        .map(|index| format!("ENG{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    let error = parse_cql_query(&format!("space IN ({in_values})")).unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);

    let string_too_large = format!(
        "title ~ \"{}\"",
        "x".repeat(MAX_CONFLUENCE_STRING_LITERAL_BYTES + 1)
    );
    let error = parse_cql_query(&string_too_large).unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);

    let deep = format!(
        "{}title ~ \"runbook\"{}",
        "(".repeat(MAX_CONFLUENCE_QUERY_DEPTH + 1),
        ")".repeat(MAX_CONFLUENCE_QUERY_DEPTH + 1)
    );
    let error = parse_cql_query(&deep).unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);

    let sort_heavy =
        "title ~ \"runbook\" ORDER BY title, created, lastModified, title, created, lastModified";
    let error = parse_cql_query(sort_heavy).unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
}

#[test]
fn cql_quote_style_hashes_are_stable_for_equivalent_canonical_queries() {
    let quoted = build_confluence_search_query(
        &ConfluenceSearchQueryInput::Cql {
            value: r#"label = "security""#.to_string(),
        },
        &EffectiveSearchScope::Finite(BTreeSet::from(["ENG".to_string()])),
        &SearchLimitsConfig::default(),
    )
    .unwrap();
    let bare = build_confluence_search_query(
        &ConfluenceSearchQueryInput::Cql {
            value: "label = security".to_string(),
        },
        &EffectiveSearchScope::Finite(BTreeSet::from(["ENG".to_string()])),
        &SearchLimitsConfig::default(),
    )
    .unwrap();

    assert_eq!(
        quoted.canonical_caller_cql_hash,
        bare.canonical_caller_cql_hash
    );
    assert_eq!(quoted.text_operand_hashes, Vec::<String>::new());
}

#[test]
fn wildcard_cql_derives_response_scope_from_positive_space_predicates() {
    let narrowed = build_confluence_search_query(
        &ConfluenceSearchQueryInput::Cql {
            value: r#"space = ENG AND title ~ "runbook""#.to_string(),
        },
        &EffectiveSearchScope::AllExcept(BTreeSet::new()),
        &SearchLimitsConfig::default(),
    )
    .unwrap();
    assert_eq!(
        narrowed.response_scope,
        EffectiveSearchScope::Finite(BTreeSet::from(["ENG".to_string()]))
    );
    assert_eq!(narrowed.response_scope.values_for_backend(), vec!["ENG"]);
    assert_eq!(
        narrowed.cql,
        r#"(space = ENG AND title ~ "runbook") AND type = page"#
    );

    let broad = build_confluence_search_query(
        &ConfluenceSearchQueryInput::Cql {
            value: r#"title ~ "runbook""#.to_string(),
        },
        &EffectiveSearchScope::AllExcept(BTreeSet::new()),
        &SearchLimitsConfig::default(),
    )
    .unwrap();
    assert_eq!(
        broad.response_scope,
        EffectiveSearchScope::AllExcept(BTreeSet::new())
    );
    assert_eq!(
        broad.response_scope.values_for_backend(),
        Vec::<String>::new()
    );
}

#[test]
fn search_inputs_reject_unknown_nested_query_fields() {
    let error = parse_search_inputs(&json!({
        "query": {
            "type": "cql",
            "value": "title ~ \"runbook\"",
            "extra": true
        }
    }))
    .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
}

#[test]
fn confluence_attachment_ids_are_not_page_ids() {
    let download = parse_attachment_download_inputs(&json!({
        "pageId": "123456",
        "attachmentId": "att123"
    }))
    .unwrap();
    assert_eq!(download.attachment_id, "att123");

    let verify = parse_verify_inputs(&json!({
        "pageId": "123456",
        "expectAttachmentId": "attachment_abc-123"
    }))
    .unwrap();
    assert_eq!(
        verify.expect_attachment_id.as_deref(),
        Some("attachment_abc-123")
    );

    let attachment = attachment_from_value(
        json!({
            "id": "att123",
            "title": "diagram.png",
            "metadata": { "mediaType": "image/png" },
            "extensions": { "fileSize": 12 }
        }),
        "123456",
    )
    .unwrap();
    assert_eq!(attachment.id, "att123");
}

#[test]
fn page_write_request_bodies_use_selected_confluence_representation() {
    let create = page_create_request_body(&ConfluencePageCreateRequest {
        space: "ENG".to_string(),
        space_id: "98765".to_string(),
        parent_page_id: Some("55555".to_string()),
        title: "Runbook".to_string(),
        body: ConfluencePageBody {
            representation: "storage".to_string(),
            value: "<p>body</p>".to_string(),
        },
    });
    assert_eq!(create["spaceId"], "98765");
    assert_eq!(create["parentId"], "55555");
    assert_eq!(create["status"], "current");
    assert_eq!(create["body"]["representation"], "storage");
    assert_eq!(create["body"]["value"], "<p>body</p>");

    let update = content_request_body(
        "123456".to_string(),
        8,
        "ENG".to_string(),
        "Runbook".to_string(),
        ConfluencePageBody {
            representation: "atlas_doc_format".to_string(),
            value: r#"{"type":"doc","version":1,"content":[]}"#.to_string(),
        },
    );
    assert_eq!(update["id"], "123456");
    assert_eq!(update["version"]["number"], 8);
    assert_eq!(
        update["body"]["atlas_doc_format"]["representation"],
        "atlas_doc_format"
    );
}

#[test]
fn draft_update_request_body_uses_requested_version_number() {
    let body = draft_update_request_body(&ConfluenceDraftUpdateRequest {
        content_type: "page".to_string(),
        content_id: "123456".to_string(),
        space_id: "98765".to_string(),
        title: "Runbook".to_string(),
        status: "current".to_string(),
        version_number: 8,
        body: ConfluencePageBody {
            representation: "storage".to_string(),
            value: "<p>body</p>".to_string(),
        },
    });
    assert_eq!(body["id"], "123456");
    assert_eq!(body["status"], "current");
    assert_eq!(body["version"]["number"], 8);
    assert_eq!(body["body"]["representation"], "storage");
}

#[test]
fn confluence_write_formats_and_generated_storage_validation_are_strict() {
    let mut config = confluence_config();
    assert_eq!(
        confluence_write_formats(ConfluenceWriteTarget::CurrentPage, &config),
        ["storage", "atlas_doc_format", "markdown", "plain_text"]
    );
    config.content.page_formats = vec!["storage".to_string()];
    assert_eq!(
        confluence_write_formats(ConfluenceWriteTarget::CurrentPage, &config),
        ["storage", "markdown", "plain_text"]
    );
    validate_generated_confluence_storage(
        "<h2>Safe</h2><ol start=\"2\"><li><a href=\"https://example.test\">link</a></li></ol>",
        false,
    )
    .unwrap();
    let error =
        validate_generated_confluence_storage("<p onclick=\"bad\">unsafe</p>", false).unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::BodyMalformed);
    let error = validate_generated_confluence_storage(
        "<p><a href=\"javascript:bad\">unsafe</a></p>",
        false,
    )
    .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::BodyMalformed);
}

#[test]
fn confluence_write_content_rejects_empty_and_whitespace_strings_consistently() {
    let provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        Arc::new(StubConfluenceBackend {
            page: attachment_list_page(),
            search_page: ConfluenceSearchPage {
                pages: Vec::new(),
                max_results: 2,
                next_page_token: None,
            },
        }),
    );
    let request = invocation("page.create", json!({}));
    for target in [
        ConfluenceWriteTarget::CurrentPage,
        ConfluenceWriteTarget::PageDraft,
        ConfluenceWriteTarget::Blog,
        ConfluenceWriteTarget::Comment,
    ] {
        for format in ["storage", "markdown", "plain_text"] {
            for source in ["", " \n\t"] {
                let error = provider
                    .prepare_write_content("test.action", target, format, &json!(source), &request)
                    .unwrap_err();
                assert_eq!(
                    error.reason_code(),
                    ReasonCode::BodyMalformed,
                    "target={target:?} format={format} source={source:?}"
                );
            }
        }
    }
    provider
        .prepare_write_content(
            "page.create",
            ConfluenceWriteTarget::CurrentPage,
            "atlas_doc_format",
            &json!({ "type": "doc", "version": 1, "content": [] }),
            &request,
        )
        .unwrap();
}

#[test]
fn normalized_write_capabilities_cover_exact_matrix_and_follow_native_gates() {
    let provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        Arc::new(StubConfluenceBackend {
            page: attachment_list_page(),
            search_page: ConfluenceSearchPage {
                pages: Vec::new(),
                max_results: 2,
                next_page_token: None,
            },
        }),
    );
    let expected = [
        "page.create",
        "page.update",
        "page.draft.create",
        "page.draft.stage",
        "page.draft.update",
        "blog.create",
        "blog.update",
        "blog.draft.create",
        "blog.draft.stage",
        "blog.draft.update",
        "page.footer_comment.add",
        "page.footer_comment.update",
        "page.footer_comment.reply.add",
        "page.inline_comment.update",
        "page.inline_comment.reply.add",
        "blog.footer_comment.add",
        "blog.footer_comment.update",
        "blog.footer_comment.reply.add",
        "blog.inline_comment.update",
        "blog.inline_comment.reply.add",
    ];
    let descriptor = confluence_descriptor(&provider.config);
    for action_name in expected {
        let action = descriptor
            .actions
            .iter()
            .find(|candidate| candidate.action == action_name)
            .unwrap_or_else(|| panic!("missing {action_name}"));
        assert!(action.input_schema["properties"].get("content").is_some());
        assert!(
            action.input_schema["properties"]
                .get("contentFormat")
                .is_some()
        );
        assert!(action.input_schema["properties"].get("body").is_none());
        assert!(
            action.input_schema["properties"]
                .get("bodyFormat")
                .is_none()
        );
        let formats = action.input_schema["properties"]["contentFormat"]["enum"]
            .as_array()
            .unwrap();
        assert!(formats.contains(&json!("markdown")));
        assert!(formats.contains(&json!("plain_text")));
    }

    let mut disabled = confluence_config();
    disabled.content.page_formats.clear();
    disabled.content.blog_formats.clear();
    disabled.content.comment_formats.clear();
    let disabled = confluence_descriptor(&disabled);
    for action_name in expected {
        let available = disabled
            .actions
            .iter()
            .any(|candidate| candidate.action == action_name);
        assert_eq!(
            available,
            action_name.starts_with("page.draft."),
            "unexpected gate for {action_name}"
        );
    }
}

#[tokio::test]
async fn draft_update_rejects_content_before_handle_lookup_or_upstream_access() {
    let backend = Arc::new(AttributionStubConfluenceBackend::new());
    let mut config = confluence_config();
    config.content.max_body_bytes = 16;
    let provider = ConfluenceProvider::with_backend_and_signing_key(
        config,
        ProviderLimits::default(),
        backend.clone(),
        agent_access_provider::test_support::test_signing_key(7),
    );

    let page_draft = draft_content("123456", ConfluenceDraftContentType::Page);
    let mut page_binding = invocation("page.draft.update", json!({}));
    page_binding = InvocationBuilder::from(page_binding)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .build();
    let page_handle = provider
        .mint_draft_handle(
            ConfluenceDraftContentType::Page,
            &page_draft,
            ConfluenceDraftOrigin::New,
            None,
            &page_binding,
        )
        .unwrap();
    let mut page_request = invocation(
        "page.draft.update",
        json!({
            "pageId": "123456",
            "draftHandle": page_handle,
            "contentFormat": "markdown",
            "content": "x".repeat(17)
        }),
    );
    page_request = InvocationBuilder::from(page_request)
        .resources(page_binding.resource_scopes().unwrap().clone())
        .build();
    assert_eq!(
        provider
            .invoke(page_request)
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::BodySizeDenied
    );

    let blog_draft = draft_content("7777", ConfluenceDraftContentType::Blog);
    let mut blog_binding = invocation("blog.draft.update", json!({}));
    blog_binding = InvocationBuilder::from(blog_binding)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .build();
    let blog_handle = provider
        .mint_draft_handle(
            ConfluenceDraftContentType::Blog,
            &blog_draft,
            ConfluenceDraftOrigin::New,
            None,
            &blog_binding,
        )
        .unwrap();
    let mut blog_request = invocation(
        "blog.draft.update",
        json!({
            "blogId": "7777",
            "draftHandle": blog_handle,
            "contentFormat": "atlas_doc_format",
            "content": { "type": "doc", "version": 1, "content": [] }
        }),
    );
    blog_request = InvocationBuilder::from(blog_request)
        .resources(blog_binding.resource_scopes().unwrap().clone())
        .build();
    assert_eq!(
        provider
            .invoke(blog_request)
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::BodyFormatUnsupported
    );
    assert_eq!(*backend.backend_calls.lock().unwrap(), 0);
}

#[test]
fn confluence_draft_handles_use_stable_signing_and_expected_bindings() {
    let key = agent_access_provider::test_support::test_signing_key(7);
    let continuations = ConfluenceContinuations::new(
        &confluence_config(),
        &ProviderLimits::default(),
        Some(key.clone()),
    );
    let content = draft_content("123456", ConfluenceDraftContentType::Page);
    let mut request = invocation("page.draft.view", json!({}));
    request = InvocationBuilder::from(request)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .build();
    let open = |continuations: &ConfluenceContinuations,
                request: &ProviderInvocation,
                content_type,
                content_id,
                token: &str| {
        continuations.open_draft_handle(request.context(), content_type, content_id, token)
    };

    let handle = ConfluenceDraftHandle::new(
        ConfluenceDraftContentType::Page,
        &content,
        ConfluenceDraftOrigin::New,
        None,
    );
    assert_eq!(handle.base_version, None);
    assert_eq!(draft_publish_version(&handle).unwrap(), 1);
    let service_token = continuations
        .seal_draft_handle(request.context(), &handle)
        .unwrap();
    assert!(service_token.starts_with("aab_confluence_draft_v3_"));
    assert!(service_token.len() <= DRAFT_HANDLE_MAX_BYTES);
    assert!(validate_draft_handle_input(&service_token).is_ok());
    // Service-mode handles are shared among service-mode principals.
    let other_service_request = InvocationBuilder::from(request.clone())
        .principal("other-agent")
        .action("page.draft.publish")
        .build();
    let service_handle = open(
        &continuations,
        &other_service_request,
        ConfluenceDraftContentType::Page,
        "123456",
        &service_token,
    )
    .unwrap();
    assert_eq!(service_handle, handle);
    assert_eq!(service_handle.parent_page_id.as_deref(), Some("55555"));
    let mut reparented_content = content.clone();
    reparented_content.parent_page_id = Some("66666".to_string());
    let error =
        ensure_draft_content_matches_handle(&reparented_content, &service_handle).unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);

    // Another tenant, content type, content ID, execution context or key.
    let mut other_tenant = confluence_config();
    other_tenant.tenant_host = "other.atlassian.net".to_string();
    let other_tenant =
        ConfluenceContinuations::new(&other_tenant, &ProviderLimits::default(), Some(key.clone()));
    assert_invalid_draft_handle(open(
        &other_tenant,
        &request,
        ConfluenceDraftContentType::Page,
        "123456",
        &service_token,
    ));
    assert_invalid_draft_handle(open(
        &continuations,
        &request,
        ConfluenceDraftContentType::Blog,
        "123456",
        &service_token,
    ));
    assert_invalid_draft_handle(open(
        &continuations,
        &request,
        ConfluenceDraftContentType::Page,
        "654321",
        &service_token,
    ));
    assert_invalid_draft_handle(open(
        &continuations,
        &InvocationBuilder::from(request.clone())
            .execution_context("external")
            .build(),
        ConfluenceDraftContentType::Page,
        "123456",
        &service_token,
    ));
    let rotated = ConfluenceContinuations::new(
        &confluence_config(),
        &ProviderLimits::default(),
        Some(agent_access_provider::test_support::test_signing_key(9)),
    );
    assert_invalid_draft_handle(open(
        &rotated,
        &request,
        ConfluenceDraftContentType::Page,
        "123456",
        &service_token,
    ));
    // Durable: another instance with the same key opens it.
    let restarted =
        ConfluenceContinuations::new(&confluence_config(), &ProviderLimits::default(), Some(key));
    assert_eq!(
        open(
            &restarted,
            &request,
            ConfluenceDraftContentType::Page,
            "123456",
            &service_token
        )
        .unwrap(),
        handle
    );

    let mut wrong_space_content = content.clone();
    wrong_space_content.space = "OPS".to_string();
    let wrong_space_token = continuations
        .seal_draft_handle(
            request.context(),
            &ConfluenceDraftHandle::new(
                ConfluenceDraftContentType::Page,
                &wrong_space_content,
                ConfluenceDraftOrigin::New,
                None,
            ),
        )
        .unwrap();
    let wrong_space_handle = open(
        &continuations,
        &request,
        ConfluenceDraftContentType::Page,
        "123456",
        &wrong_space_token,
    )
    .unwrap();
    assert_invalid_draft_handle(ensure_authorized_draft_handle(
        &wrong_space_handle,
        request.resource_scopes().unwrap(),
    ));
    let error = ensure_authorized_space(request.resource_scopes().unwrap(), "OPS").unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert_eq!(
        error.message,
        "Confluence content no longer matches the authorized space"
    );

    // Per-user handles bind the principal and the per-user mode.
    let per_user_request = InvocationBuilder::from(request.clone())
        .credential_mode(CredentialMode::PerUser)
        .identity(identity("agent-one"))
        .build();
    let per_user_token = continuations
        .seal_draft_handle(per_user_request.context(), &handle)
        .unwrap();
    open(
        &continuations,
        &per_user_request,
        ConfluenceDraftContentType::Page,
        "123456",
        &per_user_token,
    )
    .unwrap();
    assert_invalid_draft_handle(open(
        &continuations,
        &request,
        ConfluenceDraftContentType::Page,
        "123456",
        &per_user_token,
    ));
    assert_invalid_draft_handle(open(
        &continuations,
        &InvocationBuilder::from(per_user_request.clone())
            .identity(identity("agent-two"))
            .build(),
        ConfluenceDraftContentType::Page,
        "123456",
        &per_user_token,
    ));
    // Neither does a service handle open in per-user mode.
    assert_invalid_draft_handle(open(
        &continuations,
        &per_user_request,
        ConfluenceDraftContentType::Page,
        "123456",
        &service_token,
    ));

    // Without the durable key, minting and opening fail explicitly.
    let process_local =
        ConfluenceContinuations::new(&confluence_config(), &ProviderLimits::default(), None);
    for error in [
        process_local
            .seal_draft_handle(request.context(), &handle)
            .unwrap_err(),
        open(
            &process_local,
            &request,
            ConfluenceDraftContentType::Page,
            "123456",
            &service_token,
        )
        .unwrap_err(),
    ] {
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert_eq!(error.decision(), Decision::Error);
        assert_eq!(
            error.message,
            "Confluence draft actions require broker_tokens.hash_key_ref"
        );
    }
}

#[test]
fn obsolete_and_oversized_draft_handles_are_rejected_before_decoding() {
    for value in [
        "aab_confluence_draft_v2_eyJ2IjoyfQ.c2ln".to_string(),
        "draft".to_string(),
        format!(
            "aab_confluence_draft_v3_{}",
            "A".repeat(DRAFT_HANDLE_MAX_BYTES)
        ),
    ] {
        assert_invalid_draft_handle(validate_draft_handle_input(&value));
    }
    // A handle of the largest payload fits the input bound exactly.
    assert_eq!(DRAFT_HANDLE_MAX_BYTES, 24 + 5_548);
}

#[test]
fn confluence_draft_attachment_tokens_and_staged_gates_are_bound() {
    let continuations = ConfluenceContinuations::new(
        &confluence_config(),
        &ProviderLimits::default(),
        Some(agent_access_provider::test_support::test_signing_key(8)),
    );
    let credential = credential();
    let content = draft_content("123456", ConfluenceDraftContentType::Page);
    let mut request = invocation("page.draft.attachment.list", json!({}));
    request = InvocationBuilder::from(request)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .build();
    let handle = ConfluenceDraftHandle::new(
        ConfluenceDraftContentType::Page,
        &content,
        ConfluenceDraftOrigin::New,
        None,
    );
    let token = continuations
        .seal_draft_attachment_page(request.context(), &credential, &handle, 2, "cursor=next")
        .unwrap();
    assert_eq!(
        continuations
            .open_draft_attachment_page(request.context(), &credential, &handle, 2, &token)
            .unwrap(),
        "cursor=next"
    );
    // Service-mode listings continue for another service-mode principal.
    assert_eq!(
        continuations
            .open_draft_attachment_page(
                InvocationBuilder::from(request.clone())
                    .principal("other-agent")
                    .build()
                    .context(),
                &credential,
                &handle,
                2,
                &token
            )
            .unwrap(),
        "cursor=next"
    );
    let mut moved = handle.clone();
    moved.parent_page_id = Some("66666".to_string());
    for (changed_request, changed_handle) in [
        (
            InvocationBuilder::from(request.clone())
                .action("page.draft.attachment.download")
                .build(),
            handle.clone(),
        ),
        (
            InvocationBuilder::from(request.clone())
                .execution_context("external")
                .build(),
            handle.clone(),
        ),
        (
            InvocationBuilder::from(request.clone())
                .credential_mode(CredentialMode::PerUser)
                .build(),
            handle.clone(),
        ),
        (request.clone(), moved),
    ] {
        let error = continuations
            .open_draft_attachment_page(
                changed_request.context(),
                &credential,
                &changed_handle,
                2,
                &token,
            )
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
    }
    // Per-user listings belong to their principal.
    let per_user = InvocationBuilder::from(request.clone())
        .credential_mode(CredentialMode::PerUser)
        .identity(identity("agent-one"))
        .build();
    let owned = continuations
        .seal_draft_attachment_page(per_user.context(), &credential, &handle, 2, "cursor=next")
        .unwrap();
    let error = continuations
        .open_draft_attachment_page(
            InvocationBuilder::from(per_user.clone())
                .identity(identity("agent-two"))
                .build()
                .context(),
            &credential,
            &handle,
            2,
            &owned,
        )
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);

    let staged = ConfluenceDraftHandle::new(
        ConfluenceDraftContentType::Page,
        &content,
        ConfluenceDraftOrigin::Staged,
        Some(7),
    );
    assert_eq!(staged.base_version, Some(7));
    assert_eq!(draft_publish_version(&staged).unwrap(), 8);
    for error in [
        reject_staged_draft_discard(&staged).unwrap_err(),
        reject_staged_draft_attachment_add(&staged).unwrap_err(),
        reject_staged_draft_attachment_read(&staged).unwrap_err(),
    ] {
        assert_eq!(error.reason_code(), ReasonCode::ServiceActionDenied);
    }
    assert!(reject_staged_draft_discard(&handle).is_ok());
    assert!(reject_staged_draft_attachment_add(&handle).is_ok());
    assert!(reject_staged_draft_attachment_read(&handle).is_ok());
}

#[tokio::test]
async fn confluence_draft_attachment_lookup_paginates_beyond_first_page() {
    let attachments = (1..=201)
        .map(|index| ConfluenceAttachment {
            id: format!("att{index}"),
            page_id: "123456".to_string(),
            filename: format!("attachment-{index}.txt"),
            size: index,
            content_type: "text/plain".to_string(),
        })
        .collect();
    let backend = Arc::new(AttachmentListBackend {
        page: attachment_list_page(),
        attachments,
        credential_observations: std::sync::Mutex::new(Vec::new()),
    });
    let provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        backend.clone(),
    );

    let response = provider
        .draft_attachment_for_page("123456", "att201", &credential())
        .await
        .unwrap();

    assert_eq!(response.value.id, "att201");
    assert_eq!(response.value.page_id, "123456");
    assert!(
        backend
            .credential_observations
            .lock()
            .unwrap()
            .iter()
            .filter(|(operation, _)| operation == "page_draft_attachments_page")
            .count()
            > 1
    );
}

#[test]
fn confluence_attachment_upload_validation_rejects_limit_and_integrity_mismatches() {
    let limits = crate::AttachmentLimitsConfig {
        max_bytes: 4,
        max_total_bytes: 8,
        max_download_bytes: 32,
        media_types: vec!["text/plain".to_string()],
    };
    let input = AttachmentInput {
        field: "file".to_string(),
        filename: "diagram.txt".to_string(),
        content_type: "text/plain".to_string(),
        size: 4,
        sha256: sha256_hex(b"data"),
    };
    let part = BrokerBodyPart::in_memory(
        "file".to_string(),
        Some("diagram.txt".to_string()),
        Some("text/plain".to_string()),
        b"data".to_vec(),
    );
    assert!(
        prepare_attachment_uploads(
            std::slice::from_ref(&input),
            std::slice::from_ref(&part),
            &limits,
        )
        .is_ok()
    );

    let mut oversized = input.clone();
    oversized.size = 5;
    let error =
        validate_attachment_metadata_inputs(std::slice::from_ref(&oversized), &limits).unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::AttachmentSizeDenied);

    let mut unsupported_type = input.clone();
    unsupported_type.content_type = "image/png".to_string();
    let error =
        validate_attachment_metadata_inputs(std::slice::from_ref(&unsupported_type), &limits)
            .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::AttachmentMediaTypeDenied);

    let mut wrong_size = input.clone();
    wrong_size.size = 3;
    let error = prepare_attachment_uploads(&[wrong_size], std::slice::from_ref(&part), &limits)
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::AttachmentIntegrityMismatch);

    let mut wrong_hash = input.clone();
    wrong_hash.sha256 = sha256_hex(b"other");
    let error = prepare_attachment_uploads(&[wrong_hash], std::slice::from_ref(&part), &limits)
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::AttachmentIntegrityMismatch);

    let mut wrong_content_type = part;
    wrong_content_type.content_type = Some("application/json".to_string());
    let error = prepare_attachment_uploads(&[input], &[wrong_content_type], &limits).unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::AttachmentMediaTypeDenied);
}

#[test]
fn attachment_page_parser_preserves_next_link_and_non_numeric_ids() {
    let page = attachment_page_from_value(
        json!({
            "results": [{
                "id": "att123",
                "title": "diagram.png",
                "metadata": { "mediaType": "image/png" },
                "extensions": { "fileSize": 12 }
            }],
            "_links": {
                "next": "/wiki/rest/api/content/123456/child/attachment?start=200"
            }
        }),
        "123456",
    )
    .unwrap();
    assert_eq!(page.attachments[0].id, "att123");
    assert_eq!(
        page.next_link.as_deref(),
        Some("/wiki/rest/api/content/123456/child/attachment?start=200")
    );
}

#[test]
fn search_page_parser_preserves_status_and_rejects_non_pages() {
    let page = search_page_from_value(
        json!({
            "results": [{
                "content": {
                    "id": "123456",
                    "type": "page",
                    "status": "current",
                    "title": "Runbook",
                    "space": { "key": "ENG" },
                    "version": { "number": 7 }
                }
            }],
            "_links": {
                "next": "/wiki/rest/api/content/search?cursor=cursor-2"
            }
        }),
        2,
    )
    .unwrap();
    assert_eq!(page.pages[0].status.as_deref(), Some("current"));
    assert_eq!(page.next_page_token.as_deref(), Some("cursor-2"));

    let error = search_page_from_value(
        json!({
            "results": [{
                "content": {
                    "id": "123456",
                    "type": "blogpost",
                    "status": "current",
                    "title": "Runbook",
                    "space": { "key": "ENG" },
                    "version": { "number": 7 }
                }
            }]
        }),
        2,
    )
    .unwrap_err();
    assert!(
        matches!(error, ConfluenceBackendError::Protocol(message) if message.contains("not a page"))
    );
}

#[test]
fn confluence_content_parsers_and_results_expose_metadata_without_search_bodies() {
    let page = page_from_value(json!({
        "id": "123456",
        "type": "page",
        "status": "current",
        "title": "Runbook",
        "space": {
            "key": "ENG",
            "_links": { "webui": "/wiki/spaces/ENG" }
        },
        "_links": { "webui": "/wiki/spaces/ENG/pages/123456/Runbook" },
        "history": {
            "createdDate": "2026-06-01T10:00:00.000Z",
            "createdBy": {
                "accountId": "creator-1",
                "displayName": "Creator One"
            }
        },
        "version": {
            "number": 7,
            "when": "2026-06-02T11:00:00.000Z",
            "by": {
                "accountId": "editor-1",
                "displayName": "Editor One"
            }
        },
        "body": {
            "storage": { "value": "<p>body</p>" }
        }
    }))
    .unwrap();
    assert_eq!(page.created_at.as_deref(), Some("2026-06-01T10:00:00.000Z"));
    assert_eq!(page.updated_at.as_deref(), Some("2026-06-02T11:00:00.000Z"));
    assert_eq!(
        page.created_by
            .as_ref()
            .and_then(|user| user.display_name.as_deref()),
        Some("Creator One")
    );
    assert_eq!(
        page.updated_by
            .as_ref()
            .and_then(|user| user.account_id.as_deref()),
        Some("editor-1")
    );

    let config = confluence_config();
    let view = page_view_result(&page, &config.content.page_formats, &config).unwrap();
    assert_eq!(view["createdBy"]["displayName"], "Creator One");
    assert_eq!(view["updatedBy"]["accountId"], "editor-1");

    let search = search_result(
        &ConfluenceSearchPage {
            pages: vec![page],
            max_results: 2,
            next_page_token: None,
        },
        None,
        &config,
    )
    .unwrap();
    assert_eq!(search["pages"][0]["createdAt"], "2026-06-01T10:00:00.000Z");
    assert!(search["pages"][0].get("body").is_none());

    let blog = blog_from_value(json!({
        "id": "222222",
        "type": "blogpost",
        "status": "current",
        "title": "Release Notes",
        "spaceId": "98765",
        "createdAt": "2026-06-03T12:00:00.000Z",
        "authorId": "blog-author",
        "version": {
            "number": 3,
            "createdAt": "2026-06-04T13:00:00.000Z",
            "authorId": "blog-editor"
        },
        "body": {
            "storage": { "value": "<p>body</p>" }
        }
    }))
    .unwrap();
    assert_eq!(
        blog.created_by
            .as_ref()
            .and_then(|user| user.account_id.as_deref()),
        Some("blog-author")
    );
    assert_eq!(
        blog.updated_by
            .as_ref()
            .and_then(|user| user.account_id.as_deref()),
        Some("blog-editor")
    );

    let draft = draft_content_from_value(
        json!({
            "id": "333333",
            "type": "page",
            "status": "draft",
            "title": "Draft",
            "spaceId": "98765",
            "createdAt": "2026-06-05T14:00:00.000Z",
            "authorId": "draft-author",
            "version": {
                "number": 1,
                "createdAt": "2026-06-05T14:30:00.000Z",
                "authorId": "draft-editor"
            },
            "body": {
                "representation": "storage",
                "value": "<p>draft</p>"
            }
        }),
        ConfluenceDraftContentType::Page,
    )
    .unwrap();
    assert_eq!(
        draft.created_at.as_deref(),
        Some("2026-06-05T14:00:00.000Z")
    );
    assert_eq!(
        draft
            .updated_by
            .as_ref()
            .and_then(|user| user.account_id.as_deref()),
        Some("draft-editor")
    );

    let author_only_blog = blog_from_value(json!({
        "id": "222223",
        "type": "blogpost",
        "status": "current",
        "title": "Author Only",
        "spaceId": "98765",
        "createdAt": "2026-06-06T15:00:00.000Z",
        "authorId": "blog-author",
        "lastOwnerId": "not-an-updater",
        "version": {
            "number": 1,
            "createdAt": "2026-06-06T15:30:00.000Z"
        }
    }))
    .unwrap();
    assert_eq!(
        author_only_blog
            .created_by
            .as_ref()
            .and_then(|user| user.account_id.as_deref()),
        Some("blog-author")
    );
    assert_eq!(
        author_only_blog.updated_at.as_deref(),
        Some("2026-06-06T15:30:00.000Z")
    );
    assert!(author_only_blog.updated_by.is_none());

    let malformed_optional = page_from_value(json!({
        "id": "123457",
        "type": "page",
        "status": "current",
        "title": "Malformed Optional Metadata",
        "space": { "key": "ENG" },
        "history": {
            "createdDate": "2026-06-07T16:00:00.000Z",
            "createdBy": { "email": "hidden@example.com" }
        },
        "version": {
            "number": 1,
            "when": "2026-06-07T16:30:00.000Z",
            "by": { "email": "hidden@example.com" }
        }
    }))
    .unwrap();
    assert!(malformed_optional.created_by.is_none());
    assert!(malformed_optional.updated_by.is_none());
}

#[test]
fn blog_parsers_require_current_blog_shape_and_explicit_attachment_parent() {
    let blog = blog_from_value(json!({
        "id": "123456",
        "status": "current",
        "title": "Release Notes",
        "spaceId": "98765",
        "version": { "number": 3 },
        "body": {
            "storage": { "value": "<p>body</p>" }
        }
    }))
    .unwrap();
    assert_eq!(blog.id, "123456");
    assert_eq!(blog.space_id, "98765");
    assert_eq!(
        blog.bodies.get("storage").map(String::as_str),
        Some("<p>body</p>")
    );

    let search = search_blog_from_value(
        json!({
            "results": [{
                "content": {
                    "id": "123456",
                    "type": "blogpost",
                    "status": "current",
                    "title": "Release Notes",
                    "space": { "key": "ENG" },
                    "version": { "number": 3 }
                }
            }]
        }),
        2,
    )
    .unwrap();
    assert_eq!(search.blogs[0].space, "ENG");

    let attachment = attachment_list_page_from_value(
        json!({
            "results": [{
                "id": "att1",
                "title": "one.txt",
                "blogPostId": "123456",
                "metadata": { "mediaType": "text/plain" },
                "extensions": { "fileSize": 1 }
            }]
        }),
        "123456",
    )
    .unwrap();
    assert_eq!(attachment.attachments[0].page_id, "123456");

    let error = attachment_list_page_from_value(
        json!({
            "results": [{
                "id": "att1",
                "title": "one.txt",
                "metadata": { "mediaType": "text/plain" },
                "extensions": { "fileSize": 1 }
            }]
        }),
        "123456",
    )
    .unwrap_err();
    assert!(
        matches!(error, ConfluenceBackendError::Protocol(message) if message.contains("parent page id missing"))
    );
}

#[test]
fn confluence_browser_url_normalization_accepts_safe_links_and_fallbacks() {
    let config = confluence_config();
    let page_url = content_browser_url(
        Some("/spaces/ENG/pages/123456/Runbook"),
        ConfluenceBrowserContentKind::Page,
        "123456",
        "ENG",
        &config,
    )
    .unwrap();
    assert_eq!(
        page_url,
        "https://example.atlassian.net/wiki/spaces/ENG/pages/123456/Runbook"
    );

    let relative_page_url = content_browser_url(
        Some("spaces/ENG/pages/123456/Runbook"),
        ConfluenceBrowserContentKind::Page,
        "123456",
        "ENG",
        &config,
    )
    .unwrap();
    assert_eq!(
        relative_page_url,
        "https://example.atlassian.net/wiki/spaces/ENG/pages/123456/Runbook"
    );
    let relative_wiki_page_url = content_browser_url(
        Some("wiki/spaces/ENG/pages/123456/Runbook"),
        ConfluenceBrowserContentKind::Page,
        "123456",
        "ENG",
        &config,
    )
    .unwrap();
    assert_eq!(
        relative_wiki_page_url,
        "https://example.atlassian.net/wiki/spaces/ENG/pages/123456/Runbook"
    );

    let blog_url = content_browser_url(
        Some("https://example.atlassian.net/wiki/pages/viewpage.action?pageId=222222"),
        ConfluenceBrowserContentKind::Blog,
        "222222",
        "ENG",
        &config,
    )
    .unwrap();
    assert_eq!(
        blog_url,
        "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=222222"
    );

    let date_only_blog_url = content_browser_url(
        Some("/spaces/ENG/blog/2026/06/27/weekly-update"),
        ConfluenceBrowserContentKind::Blog,
        "222222",
        "ENG",
        &config,
    )
    .unwrap();
    assert_eq!(
        date_only_blog_url,
        "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=222222"
    );

    let numeric_title_blog_url = content_browser_url(
        Some("/spaces/ENG/blog/2026/06/27/222222/1234"),
        ConfluenceBrowserContentKind::Blog,
        "222222",
        "ENG",
        &config,
    )
    .unwrap();
    assert_eq!(
        numeric_title_blog_url,
        "https://example.atlassian.net/wiki/spaces/ENG/blog/2026/06/27/222222/1234"
    );

    let invalid_date_blog_url = content_browser_url(
        Some("/spaces/ENG/blog/2026/13/27/222222/Weekly"),
        ConfluenceBrowserContentKind::Blog,
        "222222",
        "ENG",
        &config,
    )
    .unwrap_err();
    assert_eq!(
        invalid_date_blog_url.reason_code(),
        ReasonCode::UpstreamProtocolFailed
    );

    let space_url = space_browser_url(Some("/spaces/ENG/overview"), "ENG", &config).unwrap();
    assert_eq!(
        space_url,
        "https://example.atlassian.net/wiki/spaces/ENG/overview"
    );
    let unrecognized_space_url =
        space_browser_url(Some("/spaces/ENG/home"), "ENG", &config).unwrap();
    assert_eq!(
        unrecognized_space_url,
        "https://example.atlassian.net/wiki/spaces/ENG"
    );
    let fallback_space_url = space_browser_url(None, "ENG", &config).unwrap();
    assert_eq!(
        fallback_space_url,
        "https://example.atlassian.net/wiki/spaces/ENG"
    );
}

#[test]
fn confluence_browser_url_normalization_rejects_unsafe_links() {
    let config = confluence_config();
    for raw in [
        "http://example.atlassian.net/wiki/pages/viewpage.action?pageId=123456",
        "https://user@example.atlassian.net/wiki/pages/viewpage.action?pageId=123456",
        "https://example.atlassian.net:443/wiki/pages/viewpage.action?pageId=123456",
        "https://example.atlassian.net:444/wiki/pages/viewpage.action?pageId=123456",
        "https://other.atlassian.net/wiki/pages/viewpage.action?pageId=123456",
        "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=123456#frag",
        "https://example.atlassian.net/wiki/rest/api/content/123456",
        "https://example.atlassian.net/wiki/api/v2/pages/123456",
        "https://example.atlassian.net/wiki/download/attachments/123456/file.txt",
        "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=123456&foo=bar",
        "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=999999",
        "https://example.atlassian.net/wiki/spaces/ENG/pages/999999/Other",
        "https://example.atlassian.net/spaces/ENG/pages/123456/Runbook",
        "//example.atlassian.net/wiki/pages/viewpage.action?pageId=123456",
        "not a url",
        "https:whatever",
        "/spaces/OPS/home",
    ] {
        let error = content_browser_url(
            Some(raw),
            ConfluenceBrowserContentKind::Page,
            "123456",
            "ENG",
            &config,
        )
        .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    }

    let error = content_browser_url(
        Some("/wiki/spaces/ENG/blog/2026/06/27/1234/Weekly"),
        ConfluenceBrowserContentKind::Blog,
        "222222",
        "ENG",
        &config,
    )
    .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);

    let error = content_browser_url(
        Some("/wiki/spaces/ENG/blog/2026/06/27/1234/222222/Weekly"),
        ConfluenceBrowserContentKind::Blog,
        "222222",
        "ENG",
        &config,
    )
    .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);

    for raw in [
        "https://example.atlassian.net/wiki/spaces/OPS",
        "/spaces/OPS/home",
        "https://example.atlassian.net/wiki/spaces/ENG?homepageId=123456",
        "https://example.atlassian.net/spaces/ENG",
        "//example.atlassian.net/wiki/spaces/ENG",
        "not a url",
        "https:whatever",
    ] {
        let error = space_browser_url(Some(raw), "ENG", &config).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    }
}

#[test]
fn confluence_page_and_blog_results_include_non_null_browser_urls() {
    let config = confluence_config();
    let page = ConfluencePage {
        id: "123456".to_string(),
        title: "Runbook".to_string(),
        space: "ENG".to_string(),
        web_url: Some("/wiki/spaces/ENG/pages/123456/Runbook".to_string()),
        space_web_url: Some("/wiki/spaces/ENG".to_string()),
        status: Some("current".to_string()),
        version: 7,
        created_at: None,
        updated_at: None,
        created_by: None,
        updated_by: None,
        bodies: BTreeMap::from([("storage".to_string(), "<p>body</p>".to_string())]),
    };
    let view = page_view_result(&page, &config.content.page_formats, &config).unwrap();
    assert_eq!(
        view["webUrl"],
        "https://example.atlassian.net/wiki/spaces/ENG/pages/123456/Runbook"
    );
    assert_eq!(
        view["spaceUrl"],
        "https://example.atlassian.net/wiki/spaces/ENG"
    );
    assert!(view["webUrl"].as_str().is_some());
    assert!(view["spaceUrl"].as_str().is_some());

    let search = search_result(
        &ConfluenceSearchPage {
            pages: vec![page],
            max_results: 2,
            next_page_token: None,
        },
        None,
        &config,
    )
    .unwrap();
    assert_eq!(
        search["pages"][0]["webUrl"],
        "https://example.atlassian.net/wiki/spaces/ENG/pages/123456/Runbook"
    );

    let blog = ConfluenceBlog {
        id: "222222".to_string(),
        title: "Weekly Update".to_string(),
        space: "ENG".to_string(),
        space_id: "98765".to_string(),
        web_url: None,
        space_web_url: None,
        status: Some("current".to_string()),
        version: 3,
        created_at: None,
        updated_at: None,
        created_by: None,
        updated_by: None,
        bodies: BTreeMap::from([("storage".to_string(), "<p>body</p>".to_string())]),
    };
    let blog_view = blog_view_result(&blog, &config).unwrap();
    assert_eq!(
        blog_view["webUrl"],
        "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=222222"
    );
    assert_eq!(
        blog_view["spaceUrl"],
        "https://example.atlassian.net/wiki/spaces/ENG"
    );
    assert!(blog_view["webUrl"].as_str().is_some());
    assert!(blog_view["spaceUrl"].as_str().is_some());

    let blog_search = blog_search_result(
        &ConfluenceSearchBlog {
            blogs: vec![ConfluenceBlogSummary {
                id: "222222".to_string(),
                title: "Weekly Update".to_string(),
                space: "ENG".to_string(),
                web_url: Some("/wiki/spaces/ENG/blog/2026/06/27/222222/Weekly".to_string()),
                space_web_url: None,
                status: Some("current".to_string()),
                version: 3,
                created_at: None,
                updated_at: None,
                created_by: None,
                updated_by: None,
            }],
            max_results: 2,
            next_page_token: None,
        },
        None,
        &config,
    )
    .unwrap();
    assert_eq!(
        blog_search["blogs"][0]["webUrl"],
        "https://example.atlassian.net/wiki/spaces/ENG/blog/2026/06/27/222222/Weekly"
    );
}

#[test]
fn confluence_draft_results_construct_canonical_content_urls() {
    let config = confluence_config();
    for (content_type, raw_web_url) in [
        (
            ConfluenceDraftContentType::Page,
            "/wiki/spaces/ENG/pages/edit-v2/123456?draftShareId=abc",
        ),
        (
            ConfluenceDraftContentType::Blog,
            "https://evil.example/wiki/spaces/ENG/blog/2026/06/27/123456/Draft",
        ),
    ] {
        let draft = ConfluenceDraftContent {
            id: "123456".to_string(),
            title: "Draft".to_string(),
            content_type: content_type.as_str().to_string(),
            space: "ENG".to_string(),
            space_id: "98765".to_string(),
            parent_page_id: (content_type == ConfluenceDraftContentType::Page)
                .then(|| "55555".to_string()),
            web_url: Some(raw_web_url.to_string()),
            space_web_url: Some("/wiki/spaces/ENG".to_string()),
            status: Some("draft".to_string()),
            version: 1,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::from([("storage".to_string(), "<p>body</p>".to_string())]),
        };
        let result = draft_content_result(
            "draft.test",
            &draft,
            content_type,
            Some("handle".to_string()),
            Some("storage"),
            &config,
        )
        .unwrap();
        assert_eq!(
            result["webUrl"],
            "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=123456"
        );
        assert_eq!(
            result["spaceUrl"],
            "https://example.atlassian.net/wiki/spaces/ENG"
        );
        assert_eq!(result[content_type.id_field()], "123456");
        assert_eq!(result["draftHandle"], "handle");
    }
}

#[test]
fn confluence_result_urls_fail_closed_on_hostile_upstream_links() {
    let config = confluence_config();
    let page = ConfluenceSearchPage {
        pages: vec![ConfluencePage {
            id: "123456".to_string(),
            title: "Runbook".to_string(),
            space: "ENG".to_string(),
            web_url: Some(
                "https://evil.example/wiki/pages/viewpage.action?pageId=123456".to_string(),
            ),
            space_web_url: None,
            status: Some("current".to_string()),
            version: 7,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::new(),
        }],
        max_results: 2,
        next_page_token: None,
    };
    let error = search_result(&page, None, &config).unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
}

#[test]
fn blog_url_locator_accepts_numeric_viewpage_and_modern_blog_shapes() {
    let config = confluence_config();
    let parsed = parse_blog_view_inputs(
        &json!({
            "url": "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=222222"
        }),
        &config,
    )
    .unwrap();
    assert_eq!(parsed.locator.blog_id, "222222");
    assert_eq!(parsed.locator.candidate_space, None);

    let modern = parse_blog_view_inputs(
        &json!({
            "url": "https://example.atlassian.net/wiki/spaces/ENG/blog/2026/06/27/333333/Weekly-update"
        }),
        &config,
    )
    .unwrap();
    assert_eq!(modern.locator.blog_id, "333333");
    assert_eq!(modern.locator.candidate_space.as_deref(), Some("ENG"));
    assert!(validate_blog_locator_space(&modern.locator, "ENG").is_ok());
    let mismatch = validate_blog_locator_space(&modern.locator, "OPS").unwrap_err();
    assert_eq!(mismatch.reason_code(), ReasonCode::LocatorInvalid);

    let numeric_title_slug = parse_blog_view_inputs(
        &json!({
            "url": "https://example.atlassian.net/wiki/spaces/ENG/blog/2026/06/27/333333/12345"
        }),
        &config,
    )
    .unwrap();
    assert_eq!(numeric_title_slug.locator.blog_id, "333333");
    assert_eq!(
        numeric_title_slug.locator.candidate_space.as_deref(),
        Some("ENG")
    );

    let invalid_date_slug = parse_blog_view_inputs(
        &json!({
            "url": "https://example.atlassian.net/wiki/spaces/ENG/blog/2026/13/27/333333/weekly-update"
        }),
        &config,
    )
    .unwrap_err();
    assert_eq!(invalid_date_slug.reason_code(), ReasonCode::LocatorInvalid);
    assert!(invalid_date_slug.message.contains("date prefix"));

    let list = parse_blog_attachment_list_inputs(
        &json!({
            "url": "https://example.atlassian.net/wiki/spaces/ENG/blog/2026/06/27/222222/Weekly-update",
            "maxResults": 1
        }),
        &config,
    )
    .unwrap();
    assert_eq!(list.locator.blog_id, "222222");
    assert_eq!(list.locator.candidate_space.as_deref(), Some("ENG"));
    assert_eq!(list.max_results, Some(1));

    let error = parse_blog_view_inputs(
        &json!({
            "blogId": "222222",
            "url": "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=222222"
        }),
        &config,
    )
    .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);

    let error = parse_blog_view_inputs(
        &json!({
            "url": "https://example.atlassian.net/wiki/spaces/ENG/blog/2026/06/27/weekly-update"
        }),
        &config,
    )
    .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::LocatorInvalid);
    assert!(error.message.contains("first path segment"));

    let error = parse_blog_view_inputs(
        &json!({
            "url": "https://example.atlassian.net/wiki/spaces/ENG/blog/2026/06/27"
        }),
        &config,
    )
    .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::LocatorInvalid);
    assert!(error.message.contains("numeric content ID"));

    let error = parse_blog_view_inputs(
        &json!({
            "url": "https://example.atlassian.net/wiki/spaces/ENG/blog/2026/06/27/weekly-update/222222"
        }),
        &config,
    )
    .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::LocatorInvalid);
    assert!(error.message.contains("first path segment"));

    for raw in [
        "https://user@example.atlassian.net/wiki/pages/viewpage.action?pageId=222222",
        "https://example.atlassian.net:443/wiki/pages/viewpage.action?pageId=222222",
        "https://example.atlassian.net:444/wiki/pages/viewpage.action?pageId=222222",
        "https://example.atlassian.net/wiki/spaces/ENG/blog/2026/06/27/222222/Weekly?foo=bar",
    ] {
        let error = parse_blog_view_inputs(&json!({ "url": raw }), &config).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::LocatorInvalid);
    }
}

#[tokio::test]
async fn blog_scope_lookup_defers_current_status_until_after_authorization() {
    for status in [Some("current".to_string()), Some("draft".to_string())] {
        let backend = Arc::new(BlogViewBackend {
            blog: ConfluenceBlog {
                id: "123456".to_string(),
                title: "Runbook Blog".to_string(),
                space: String::new(),
                space_id: "98765".to_string(),
                web_url: None,
                space_web_url: None,
                status,
                version: 7,
                created_at: None,
                updated_at: None,
                created_by: None,
                updated_by: None,
                bodies: BTreeMap::new(),
            },
            space: ConfluenceSpace {
                id: "98765".to_string(),
                key: "ENG".to_string(),
                web_url: None,
                status: Some("current".to_string()),
                homepage_id: Some("55555".to_string()),
            },
        });
        let provider = ConfluenceProvider::with_backend(
            confluence_config(),
            ProviderLimits::default(),
            backend,
        );
        let scopes = provider
            .lookup_scopes(
                "blog.view",
                &json!({ "blogId": "123456" }),
                Some(&credential()),
            )
            .await
            .unwrap();
        assert_eq!(scopes["space"], vec!["ENG"]);
    }
}

#[tokio::test]
async fn attachment_download_scope_lookup_defers_membership_checks() {
    let backend = Arc::new(attachment_list_backend());
    let provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        backend.clone(),
    );
    let scopes = provider
        .lookup_scopes(
            "attachment.download",
            &json!({
                "pageId": "123456",
                "attachmentId": "att1"
            }),
            Some(&credential()),
        )
        .await
        .unwrap();
    assert_eq!(scopes["space"], vec!["ENG"]);
    assert!(!scopes.contains_key("page"));
    assert_eq!(
        *backend.credential_observations.lock().unwrap(),
        vec![("page_metadata".to_string(), "token".to_string())]
    );
}

#[tokio::test]
async fn blog_attachment_download_scope_lookup_defers_membership_checks() {
    let backend = Arc::new(BlogViewBackend {
        blog: ConfluenceBlog {
            id: "123456".to_string(),
            title: "Runbook Blog".to_string(),
            space: String::new(),
            space_id: "98765".to_string(),
            web_url: None,
            space_web_url: None,
            status: Some("current".to_string()),
            version: 7,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::new(),
        },
        space: ConfluenceSpace {
            id: "98765".to_string(),
            key: "ENG".to_string(),
            web_url: None,
            status: Some("current".to_string()),
            homepage_id: Some("55555".to_string()),
        },
    });
    let provider =
        ConfluenceProvider::with_backend(confluence_config(), ProviderLimits::default(), backend);
    let scopes = provider
        .lookup_scopes(
            "blog.attachment.download",
            &json!({
                "blogId": "123456",
                "attachmentId": "att1"
            }),
            Some(&credential()),
        )
        .await
        .unwrap();
    assert_eq!(scopes["space"], vec!["ENG"]);
}

#[test]
fn attachment_pagination_next_link_must_stay_on_same_page_collection() {
    let current = Url::parse(
        "https://example.atlassian.net/wiki/rest/api/content/123456/child/attachment?limit=200",
    )
    .unwrap();
    let api_base = Url::parse("https://example.atlassian.net/wiki/rest/api/").unwrap();
    let allowed = vec!["https://example.atlassian.net/wiki/rest/api/**".to_string()];
    let next = next_attachment_page_url(
        &current,
        &api_base,
        "123456",
        "/wiki/rest/api/content/123456/child/attachment?start=200&limit=200",
        &allowed,
    )
    .unwrap();
    assert_eq!(
        next.as_str(),
        "https://example.atlassian.net/wiki/rest/api/content/123456/child/attachment?start=200&limit=200"
    );

    let error = next_attachment_page_url(
        &current,
        &api_base,
        "123456",
        "/wiki/rest/api/content/654321/child/attachment?start=200&limit=200",
        &allowed,
    )
    .unwrap_err();
    assert!(
        matches!(error, ConfluenceBackendError::Protocol(message) if message.contains("changed resource"))
    );

    let error = next_attachment_page_url(
        &current,
        &api_base,
        "123456",
        "/wiki/rest/api/content/123456/child/attachment/att123?start=200&limit=200",
        &allowed,
    )
    .unwrap_err();
    assert!(
        matches!(error, ConfluenceBackendError::Protocol(message) if message.contains("changed resource"))
    );
}

#[tokio::test]
async fn verify_missing_page_returns_sanitized_mismatch() {
    let backend = Arc::new(StubConfluenceBackend {
        page: ConfluencePage {
            id: "123456".to_string(),
            title: "Runbook".to_string(),
            space: "ENG".to_string(),
            web_url: None,
            space_web_url: None,
            status: Some("current".to_string()),
            version: 7,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::new(),
        },
        search_page: ConfluenceSearchPage {
            pages: vec![],
            max_results: 2,
            next_page_token: None,
        },
    });
    let provider =
        ConfluenceProvider::with_backend(confluence_config(), ProviderLimits::default(), backend);
    let error = provider
        .invoke(invocation(
            "verify",
            json!({
                "pageId": "999999",
                "expectVersion": 1
            }),
        ))
        .await
        .unwrap_err();
    assert_eq!(error.decision(), Decision::Deny);
    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
}

#[tokio::test]
async fn verify_forbidden_page_or_attachment_returns_sanitized_mismatch() {
    let provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        Arc::new(VerifyForbiddenBackend {
            page_metadata_forbidden: true,
            page_attachments_forbidden: false,
        }),
    );
    let error = provider
        .invoke(invocation(
            "verify",
            json!({
                "pageId": "123456",
                "expectVersion": 1
            }),
        ))
        .await
        .unwrap_err();
    assert_eq!(error.decision(), Decision::Deny);
    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);

    let provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        Arc::new(VerifyForbiddenBackend {
            page_metadata_forbidden: false,
            page_attachments_forbidden: true,
        }),
    );
    let error = provider
        .invoke(invocation(
            "verify",
            json!({
                "pageId": "123456",
                "expectAttachmentId": "att123"
            }),
        ))
        .await
        .unwrap_err();
    assert_eq!(error.decision(), Decision::Allow);
    assert_eq!(error.reason_code(), ReasonCode::VerificationMismatch);
}

#[tokio::test]
async fn attachment_list_returns_bounded_pages_and_rejects_tampered_tokens() {
    let provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        Arc::new(AttachmentListBackend {
            page: ConfluencePage {
                id: "123456".to_string(),
                title: "Runbook".to_string(),
                space: "ENG".to_string(),
                web_url: None,
                space_web_url: None,
                status: Some("current".to_string()),
                version: 7,
                created_at: None,
                updated_at: None,
                created_by: None,
                updated_by: None,
                bodies: BTreeMap::new(),
            },
            attachments: vec![
                ConfluenceAttachment {
                    id: "att1".to_string(),
                    page_id: "123456".to_string(),
                    filename: "one.txt".to_string(),
                    size: 1,
                    content_type: "text/plain".to_string(),
                },
                ConfluenceAttachment {
                    id: "att2".to_string(),
                    page_id: "123456".to_string(),
                    filename: "two.txt".to_string(),
                    size: 2,
                    content_type: "text/plain".to_string(),
                },
            ],
            credential_observations: std::sync::Mutex::new(Vec::new()),
        }),
    );
    let first = provider
        .invoke(invocation(
            "attachment.list",
            json!({"pageId": "123456", "maxResults": 1}),
        ))
        .await
        .unwrap();
    assert_eq!(first.result["attachments"][0]["attachmentId"], "att1");
    assert_eq!(first.result["count"], 1);
    assert_eq!(first.result["hasMore"], true);
    let token = first.result["nextPageToken"].as_str().unwrap();
    assert!(!token.contains("start=1"));

    let second = provider
        .invoke(invocation(
            "attachment.list",
            json!({
                "pageId": "123456",
                "maxResults": 1,
                "nextPageToken": token
            }),
        ))
        .await
        .unwrap();
    assert_eq!(second.result["attachments"][0]["attachmentId"], "att2");
    assert_eq!(second.result["count"], 1);
    assert_eq!(second.result["hasMore"], false);

    let clamped = provider
        .invoke(invocation(
            "attachment.list",
            json!({"pageId": "123456", "maxResults": 99}),
        ))
        .await
        .unwrap();
    assert_eq!(clamped.result["count"], 2);
    assert_eq!(clamped.result["hasMore"], false);
    assert!(clamped.result["nextPageToken"].is_null());

    let zero = provider
        .invoke(invocation(
            "attachment.list",
            json!({"pageId": "123456", "maxResults": 0}),
        ))
        .await
        .unwrap_err();
    assert_eq!(zero.reason_code(), ReasonCode::InputInvalid);

    let tampered = format!("{token}x");
    let error = provider
        .invoke(invocation(
            "attachment.list",
            json!({
                "pageId": "123456",
                "nextPageToken": tampered
            }),
        ))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
}

#[test]
fn attachment_list_tokens_reject_cross_bound_and_unsupported_positions() {
    let continuations =
        ConfluenceContinuations::new(&confluence_config(), &ProviderLimits::default(), None);
    let credential = credential();
    let page = attachment_list_page();
    let request = invocation("attachment.list", json!({"pageId": "123456"}));

    let valid = continuations
        .seal_attachment_page(request.context(), &credential, &page, 2, "start=1")
        .unwrap();
    assert_eq!(
        continuations
            .open_attachment_page(request.context(), &credential, &page, 2, &valid)
            .unwrap(),
        "start=1"
    );

    let mut other_page = page.clone();
    other_page.id = "654321".to_string();
    let mut other_space = page.clone();
    other_space.space = "OPS".to_string();
    for (changed_request, changed_page, changed_credential) in [
        (request.clone(), other_page, credential.clone()),
        (request.clone(), other_space, credential.clone()),
        (
            InvocationBuilder::from(request.clone())
                .principal("user:alice@example.com")
                .build(),
            page.clone(),
            credential.clone(),
        ),
        (
            InvocationBuilder::from(request.clone())
                .credential_mode(CredentialMode::PerUser)
                .build(),
            page.clone(),
            credential.clone(),
        ),
        (
            InvocationBuilder::from(request.clone())
                .execution_context("external")
                .build(),
            page.clone(),
            credential.clone(),
        ),
        (
            request.clone(),
            page.clone(),
            agent_access_provider::test_support::bearer_credential("token"),
        ),
    ] {
        let error = continuations
            .open_attachment_page(
                changed_request.context(),
                &changed_credential,
                &changed_page,
                2,
                &valid,
            )
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
        assert_eq!(
            error.message,
            "Confluence attachment pagination token is invalid or does not match this request"
        );
    }

    let unsupported = continuations
        .seal_attachment_page(request.context(), &credential, &page, 2, "start=1&limit=1")
        .unwrap();
    let error = continuations
        .open_attachment_page(request.context(), &credential, &page, 2, &unsupported)
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
    assert_eq!(
        error.message,
        "Confluence attachment pagination token position is invalid"
    );
}

#[tokio::test]
async fn attachment_list_stable_signer_is_portable_but_process_local_is_not() {
    let backend = Arc::new(attachment_list_backend());
    let hasher = agent_access_provider::test_support::test_signing_key(7);
    let first_provider = ConfluenceProvider::with_backend_and_signing_key(
        confluence_config(),
        ProviderLimits::default(),
        backend.clone(),
        hasher.clone(),
    );
    let second_provider = ConfluenceProvider::with_backend_and_signing_key(
        confluence_config(),
        ProviderLimits::default(),
        backend.clone(),
        hasher,
    );

    let first = first_provider
        .invoke(invocation(
            "attachment.list",
            json!({"pageId": "123456", "maxResults": 1}),
        ))
        .await
        .unwrap();
    let stable_token = first.result["nextPageToken"].as_str().unwrap();
    let second = second_provider
        .invoke(invocation(
            "attachment.list",
            json!({
                "pageId": "123456",
                "maxResults": 1,
                "nextPageToken": stable_token
            }),
        ))
        .await
        .unwrap();
    assert_eq!(second.result["attachments"][0]["attachmentId"], "att2");

    let process_local_first = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        backend.clone(),
    );
    let process_local_second =
        ConfluenceProvider::with_backend(confluence_config(), ProviderLimits::default(), backend);
    let first = process_local_first
        .invoke(invocation(
            "attachment.list",
            json!({"pageId": "123456", "maxResults": 1}),
        ))
        .await
        .unwrap();
    let process_local_token = first.result["nextPageToken"].as_str().unwrap();
    let error = process_local_second
        .invoke(invocation(
            "attachment.list",
            json!({
                "pageId": "123456",
                "maxResults": 1,
                "nextPageToken": process_local_token
            }),
        ))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
}

#[tokio::test]
async fn attachment_list_uses_lookup_for_scope_and_execution_for_visible_metadata() {
    let backend = Arc::new(attachment_list_backend());
    let provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        backend.clone(),
    );
    let mut request = invocation("attachment.list", json!({"pageId": "123456"}));
    request = InvocationBuilder::from(request)
        .credential_mode(CredentialMode::PerUser)
        .build();
    request = InvocationBuilder::from(request)
        .execution(ExecutionAccess::Static(credential_with_token(
            "per-user-token",
        )))
        .build();
    request = InvocationBuilder::from(request)
        .lookup_credential(credential_with_token("lookup-token"))
        .build();

    provider.invoke(request).await.unwrap();

    assert_eq!(
        *backend.credential_observations.lock().unwrap(),
        vec![
            ("page_metadata".to_string(), "lookup-token".to_string()),
            (
                "page_attachments_page".to_string(),
                "per-user-token".to_string()
            ),
        ]
    );
}

#[tokio::test]
async fn search_rejects_pages_outside_requested_space() {
    let backend = Arc::new(StubConfluenceBackend {
        page: ConfluencePage {
            id: "123456".to_string(),
            title: "Runbook".to_string(),
            space: "ENG".to_string(),
            web_url: None,
            space_web_url: None,
            status: Some("current".to_string()),
            version: 7,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::new(),
        },
        search_page: ConfluenceSearchPage {
            pages: vec![ConfluencePage {
                id: "999999".to_string(),
                title: "Other".to_string(),
                space: "OPS".to_string(),
                web_url: None,
                space_web_url: None,
                status: Some("current".to_string()),
                version: 1,
                created_at: None,
                updated_at: None,
                created_by: None,
                updated_by: None,
                bodies: BTreeMap::new(),
            }],
            max_results: 2,
            next_page_token: None,
        },
    });
    let provider =
        ConfluenceProvider::with_backend(confluence_config(), ProviderLimits::default(), backend);
    let error = provider
        .invoke(invocation(
            "search",
            json!({
                "spaces": ["ENG"],
                "query": {
                    "type": "cql",
                    "value": r#"space = ENG and title ~ "runbook""#
                },
                "maxResults": 2
            }),
        ))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
}

#[tokio::test]
async fn search_rejects_non_current_pages() {
    for status in [None, Some("draft".to_string())] {
        let backend = Arc::new(StubConfluenceBackend {
            page: ConfluencePage {
                id: "123456".to_string(),
                title: "Runbook".to_string(),
                space: "ENG".to_string(),
                web_url: None,
                space_web_url: None,
                status: Some("current".to_string()),
                version: 7,
                created_at: None,
                updated_at: None,
                created_by: None,
                updated_by: None,
                bodies: BTreeMap::new(),
            },
            search_page: ConfluenceSearchPage {
                pages: vec![ConfluencePage {
                    id: "123456".to_string(),
                    title: "Draft".to_string(),
                    space: "ENG".to_string(),
                    web_url: None,
                    space_web_url: None,
                    status,
                    version: 2,
                    created_at: None,
                    updated_at: None,
                    created_by: None,
                    updated_by: None,
                    bodies: BTreeMap::new(),
                }],
                max_results: 2,
                next_page_token: None,
            },
        });
        let provider = ConfluenceProvider::with_backend(
            confluence_config(),
            ProviderLimits::default(),
            backend,
        );
        let error = provider
            .invoke(invocation(
                "search",
                json!({
                    "spaces": ["ENG"],
                    "query": {
                        "type": "cql",
                        "value": r#"space = ENG and title ~ "runbook""#
                    },
                    "maxResults": 2
                }),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    }
}

#[tokio::test]
async fn page_view_enforces_response_byte_cap() {
    let limits = ProviderLimits::default().with_max_upstream_response_bytes(64);
    let backend = Arc::new(StubConfluenceBackend {
        page: ConfluencePage {
            id: "123456".to_string(),
            title: "Runbook".to_string(),
            space: "ENG".to_string(),
            web_url: None,
            space_web_url: None,
            status: Some("current".to_string()),
            version: 7,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::from([("storage".to_string(), "x".repeat(200))]),
        },
        search_page: ConfluenceSearchPage {
            pages: vec![],
            max_results: 2,
            next_page_token: None,
        },
    });
    let provider = ConfluenceProvider::with_backend(confluence_config(), limits, backend);
    let error = provider
        .invoke(invocation("page.view", json!({ "pageId": "123456" })))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
}

#[tokio::test]
async fn page_view_enforces_configured_body_byte_cap() {
    let mut config = confluence_config();
    config.content.max_body_bytes = 16;
    let backend = Arc::new(StubConfluenceBackend {
        page: ConfluencePage {
            id: "123456".to_string(),
            title: "Runbook".to_string(),
            space: "ENG".to_string(),
            web_url: None,
            space_web_url: None,
            status: Some("current".to_string()),
            version: 7,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::from([("storage".to_string(), "x".repeat(32))]),
        },
        search_page: ConfluenceSearchPage {
            pages: vec![],
            max_results: 2,
            next_page_token: None,
        },
    });
    let provider = ConfluenceProvider::with_backend(config, ProviderLimits::default(), backend);
    let error = provider
        .invoke(invocation("page.view", json!({ "pageId": "123456" })))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
}

#[tokio::test]
async fn page_view_rejects_body_response_outside_authorized_scope() {
    let backend = Arc::new(StubConfluenceBackend {
        page: ConfluencePage {
            id: "123456".to_string(),
            title: "Runbook".to_string(),
            space: "OPS".to_string(),
            web_url: None,
            space_web_url: None,
            status: Some("current".to_string()),
            version: 7,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::new(),
        },
        search_page: ConfluenceSearchPage {
            pages: vec![],
            max_results: 2,
            next_page_token: None,
        },
    });
    let provider =
        ConfluenceProvider::with_backend(confluence_config(), ProviderLimits::default(), backend);
    let error = provider
        .invoke(invocation("page.view", json!({ "pageId": "123456" })))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
}

#[tokio::test]
async fn blog_view_rejects_non_current_execution_response() {
    let backend = Arc::new(BlogViewBackend {
        blog: ConfluenceBlog {
            id: "123456".to_string(),
            title: "Runbook Blog".to_string(),
            space: String::new(),
            space_id: "98765".to_string(),
            web_url: None,
            space_web_url: None,
            status: Some("draft".to_string()),
            version: 7,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::from([("storage".to_string(), "<p>draft body</p>".to_string())]),
        },
        space: ConfluenceSpace {
            id: "98765".to_string(),
            key: "ENG".to_string(),
            web_url: None,
            status: Some("current".to_string()),
            homepage_id: Some("55555".to_string()),
        },
    });
    let provider =
        ConfluenceProvider::with_backend(confluence_config(), ProviderLimits::default(), backend);
    let error = provider
        .invoke(invocation("blog.view", json!({ "blogId": "123456" })))
        .await
        .unwrap_err();
    assert_eq!(error.decision(), Decision::Deny);
    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
}

#[test]
fn build_creates_request_and_stream_clients_for_each_api_base() {
    let cloud_id = "00000000-0000-0000-0000-000000000000";
    let mut config = confluence_config();
    config.allowed_upstream_hosts.push(format!(
        "https://api.atlassian.com/ex/confluence/{cloud_id}/wiki/rest/api/**"
    ));
    let host = agent_access_provider::test_support::TestHost::default();
    config.build(&host.context()).unwrap();
    let built = host
        .built_clients()
        .into_iter()
        .map(|client| (client.label, client.base.to_string(), client.profile))
        .collect::<Vec<_>>();
    let label = "providers.confluence.egress_proxy".to_string();
    let tenant = "https://example.atlassian.net/wiki/rest/api/".to_string();
    let gateway = format!("https://api.atlassian.com/ex/confluence/{cloud_id}/wiki/rest/api/");
    assert_eq!(
        built,
        [
            (label.clone(), tenant.clone(), ClientProfile::Request),
            (label.clone(), tenant, ClientProfile::Stream),
            (label.clone(), gateway.clone(), ClientProfile::Request),
            (label, gateway, ClientProfile::Stream),
        ]
    );
}

#[tokio::test]
async fn http_backend_rejects_unallowlisted_confluence_api_url_before_request() {
    let mut config = confluence_config();
    config.allowed_upstream_hosts = vec!["https://other.example/wiki/rest/api/**".to_string()];
    let backend = HttpConfluenceBackend::for_tests(config, ProviderLimits::default());
    let error = backend
        .page_metadata("123456", &credential())
        .await
        .unwrap_err();
    assert!(
        matches!(error, ConfluenceBackendError::Protocol(message) if message.contains("allowlisted"))
    );
}

#[tokio::test]
async fn http_backend_attachment_list_fails_closed_on_overreturn_or_missing_parent() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/wiki/rest/api/content/123456/child/attachment"))
        .and(query_param("limit", "1"))
        .and(query_param(
            "expand",
            "version,metadata,extensions,container",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                {
                    "id": "att1",
                    "title": "one.txt",
                    "pageId": "123456",
                    "metadata": { "mediaType": "text/plain" },
                    "extensions": { "fileSize": 1 }
                },
                {
                    "id": "att2",
                    "title": "two.txt",
                    "pageId": "123456",
                    "metadata": { "mediaType": "text/plain" },
                    "extensions": { "fileSize": 2 }
                }
            ]
        })))
        .mount(&server)
        .await;
    let mut config = confluence_config();
    config.allowed_upstream_hosts = vec![format!("{}/wiki/rest/api/**", server.uri())];
    let backend = HttpConfluenceBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/wiki/rest/api/", server.uri())).unwrap(),
    );

    let error = backend
        .page_attachments_page("123456", 1, None, &credential())
        .await
        .unwrap_err();
    assert!(
        matches!(error, ConfluenceBackendError::Protocol(message) if message.contains("more attachments than requested"))
    );

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/wiki/rest/api/content/123456/child/attachment"))
        .and(query_param("limit", "1"))
        .and(query_param(
            "expand",
            "version,metadata,extensions,container",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "id": "att1",
                "title": "one.txt",
                "metadata": { "mediaType": "text/plain" },
                "extensions": { "fileSize": 1 }
            }]
        })))
        .mount(&server)
        .await;
    let mut config = confluence_config();
    config.allowed_upstream_hosts = vec![format!("{}/wiki/rest/api/**", server.uri())];
    let backend = HttpConfluenceBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/wiki/rest/api/", server.uri())).unwrap(),
    );

    let error = backend
        .page_attachments_page("123456", 1, None, &credential())
        .await
        .unwrap_err();
    assert!(
        matches!(error, ConfluenceBackendError::Protocol(message) if message.contains("parent page id missing"))
    );
}

#[tokio::test]
async fn http_backend_blog_attachment_list_uses_v2_and_requires_parent_membership() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/wiki/api/v2/blogposts/123456/attachments"))
        .and(query_param("limit", "1"))
        .and(query_param_is_missing("cursor"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "id": "att1",
                "title": "one.txt",
                "blogPostId": "123456",
                "metadata": { "mediaType": "text/plain" },
                "extensions": { "fileSize": 1 }
            }],
            "_links": {
                "next": "/wiki/api/v2/blogposts/123456/attachments?cursor=cursor-2&limit=1"
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/wiki/api/v2/blogposts/123456/attachments"))
        .and(query_param("limit", "1"))
        .and(query_param("cursor", "cursor-2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "id": "att2",
                "title": "two.txt",
                "blogPostId": "123456",
                "metadata": { "mediaType": "text/plain" },
                "extensions": { "fileSize": 2 }
            }]
        })))
        .mount(&server)
        .await;
    let mut config = confluence_config();
    config.allowed_upstream_hosts = vec![
        format!("{}/wiki/rest/api/**", server.uri()),
        format!("{}/wiki/api/v2/**", server.uri()),
    ];
    let backend = HttpConfluenceBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/wiki/rest/api/", server.uri())).unwrap(),
    );

    let first = backend
        .blog_attachments_page("123456", 1, None, &credential())
        .await
        .unwrap();
    assert_eq!(first.value.attachments.len(), 1);
    assert_eq!(first.value.attachments[0].id, "att1");
    assert_eq!(
        first.value.next_position.as_deref(),
        Some("cursor=cursor-2")
    );

    let second = backend
        .blog_attachments_page(
            "123456",
            1,
            first.value.next_position.as_deref(),
            &credential(),
        )
        .await
        .unwrap();
    assert_eq!(second.value.attachments.len(), 1);
    assert_eq!(second.value.attachments[0].id, "att2");
    assert!(second.value.next_position.is_none());

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/wiki/api/v2/blogposts/123456/attachments"))
        .and(query_param("limit", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "id": "att1",
                "title": "one.txt",
                "metadata": { "mediaType": "text/plain" },
                "extensions": { "fileSize": 1 }
            }]
        })))
        .mount(&server)
        .await;
    let mut config = confluence_config();
    config.allowed_upstream_hosts = vec![
        format!("{}/wiki/rest/api/**", server.uri()),
        format!("{}/wiki/api/v2/**", server.uri()),
    ];
    let backend = HttpConfluenceBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/wiki/rest/api/", server.uri())).unwrap(),
    );
    let error = backend
        .blog_attachments_page("123456", 1, None, &credential())
        .await
        .unwrap_err();
    assert!(
        matches!(error, ConfluenceBackendError::Protocol(message) if message.contains("parent page id missing"))
    );
}

#[tokio::test]
async fn http_backend_search_requests_bounded_page_metadata() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/wiki/rest/api/content/search"))
        .and(query_param(
            "cql",
            r#"(title ~ "runbook") AND space IN (ENG) AND type = page"#,
        ))
        .and(query_param("limit", "2"))
        .and(query_param("expand", "space,version,history"))
        .and(query_param_is_missing("cursor"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "content": {
                    "id": "123456",
                    "type": "page",
                    "status": "current",
                    "title": "Runbook",
                    "space": { "key": "ENG" },
                    "version": { "number": 7 }
                }
            }],
            "_links": {
                "next": "/wiki/rest/api/content/search?cursor=cursor-2"
            }
        })))
        .mount(&server)
        .await;

    let backend = http_confluence_backend_for_server(&server);
    let page = agent_access_provider::host::with_correlation_context(
        crate::CorrelationContext::for_tests(),
        backend.search(
            ConfluenceSearchRequest {
                cql: r#"(title ~ "runbook") AND space IN (ENG) AND type = page"#.to_string(),
                spaces: vec!["ENG".to_string()],
                max_results: 2,
                next_page_token: None,
            },
            &credential(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(page.value.pages[0].id, "123456");
    assert_eq!(page.value.pages[0].status.as_deref(), Some("current"));
    assert_eq!(page.value.next_page_token.as_deref(), Some("cursor-2"));
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0]
            .headers
            .get(crate::REQUEST_ID_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("test-agent-request-id")
    );
    assert_eq!(
        requests[0]
            .headers
            .get(crate::BROKER_REQUEST_ID_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("test-broker-request-id")
    );
}

#[tokio::test]
async fn http_backend_builds_confluence_page_write_requests() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/wiki/api/v2/pages"))
        .and(query_param("root-level", "false"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "900001",
            "type": "page",
            "title": "Created",
            "spaceId": "98765",
            "parentId": "55555",
            "parentType": "page",
            "status": "current",
            "version": { "number": 1 }
        })))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/wiki/rest/api/content/123456"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "123456",
            "type": "page",
            "title": "Updated",
            "space": { "key": "ENG" },
            "version": { "number": 8 }
        })))
        .mount(&server)
        .await;

    let backend = http_confluence_backend_for_server(&server);
    let created = backend
        .create_page(
            ConfluencePageCreateRequest {
                space: "ENG".to_string(),
                space_id: "98765".to_string(),
                parent_page_id: Some("55555".to_string()),
                title: "Created".to_string(),
                body: ConfluencePageBody {
                    representation: "storage".to_string(),
                    value: "<p>created</p>".to_string(),
                },
            },
            &credential(),
        )
        .await
        .unwrap();
    assert_eq!(created.value.id, "900001");

    let updated = backend
        .update_page(
            ConfluencePageUpdateRequest {
                page_id: "123456".to_string(),
                space: "ENG".to_string(),
                title: "Updated".to_string(),
                base_version: 7,
                body: ConfluencePageBody {
                    representation: "storage".to_string(),
                    value: "<p>updated</p>".to_string(),
                },
            },
            &credential(),
        )
        .await
        .unwrap();
    assert_eq!(updated.value.version, 8);

    let requests = server.received_requests().await.unwrap();
    let create = requests
        .iter()
        .find(|request| {
            request.method.as_str() == "POST" && request.url.path() == "/wiki/api/v2/pages"
        })
        .expect("create request was recorded");
    let create_body: Value = create.body_json().unwrap();
    assert_eq!(create_body["spaceId"], "98765");
    assert_eq!(create_body["parentId"], "55555");
    assert_eq!(create_body["status"], "current");
    assert_eq!(create_body["body"]["representation"], "storage");
    assert_eq!(create_body["body"]["value"], "<p>created</p>");
    assert!(create_body.get("version").is_none());

    let update = requests
        .iter()
        .find(|request| {
            request.method.as_str() == "PUT"
                && request.url.path() == "/wiki/rest/api/content/123456"
        })
        .expect("update request was recorded");
    let update_body: Value = update.body_json().unwrap();
    assert_eq!(update_body["id"], "123456");
    assert_eq!(update_body["space"]["key"], "ENG");
    assert_eq!(update_body["version"]["number"], 8);
    assert_eq!(update_body["body"]["storage"]["value"], "<p>updated</p>");
}

#[tokio::test]
async fn http_backend_exposes_only_allowlisted_validation_for_content_mutations() {
    let server = MockServer::start().await;
    let validation_body = json!({
        "message": "unstructured upstream details are hidden",
        "errors": [
            {
                "code": "INVALID_BODY",
                "title": "Invalid content",
                "detail": "Storage document is malformed",
                "data": "hidden"
            },
            {
                "code": "FORBIDDEN",
                "title": "scope details",
                "detail": "hidden"
            }
        ]
    });
    Mock::given(method("POST"))
        .and(path("/wiki/api/v2/pages"))
        .and(query_param("root-level", "false"))
        .respond_with(ResponseTemplate::new(422).set_body_json(validation_body.clone()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/wiki/rest/api/content/123456"))
        .and(query_param("expand", "space,version,history"))
        .respond_with(ResponseTemplate::new(400).set_body_json(validation_body))
        .mount(&server)
        .await;

    let backend = http_confluence_backend_for_server(&server);
    let mutation_error = backend
        .create_page(
            ConfluencePageCreateRequest {
                space: "ENG".to_string(),
                space_id: "98765".to_string(),
                parent_page_id: None,
                title: "Created".to_string(),
                body: ConfluencePageBody {
                    representation: "storage".to_string(),
                    value: "<p>created</p>".to_string(),
                },
            },
            &credential(),
        )
        .await
        .unwrap_err();
    assert_eq!(
        mutation_error,
        ConfluenceBackendError::Validation {
            status: 422,
            message: "Invalid content; Storage document is malformed".to_string(),
        }
    );

    let lookup_error = backend
        .page_metadata("123456", &credential())
        .await
        .unwrap_err();
    assert_eq!(lookup_error, ConfluenceBackendError::HttpStatus(400));
}

#[tokio::test]
async fn http_backend_uses_exact_move_ancestor_hierarchy_and_child_routes() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/wiki/api/v2/pages/200/ancestors"))
        .and(query_param("limit", "250"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                {"id": "folder-abc", "type": "folder"},
                {"id": "55555", "type": "page"}
            ],
            "_links": {}
        })))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/wiki/rest/api/content/100/move/before/200"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"pageId": "100"})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/wiki/api/v2/pages/55555/direct-children"))
        .and(query_param("limit", "250"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                {"id": "100", "type": "page", "status": "current", "childPosition": 0},
                {"id": "200", "type": "page", "status": "current", "childPosition": 1},
                {"id": "whiteboard-abc", "type": "whiteboard", "status": "current", "childPosition": 2}
            ],
            "_links": {}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/wiki/api/v2/pages/100"))
        .and(query_param_is_missing("get-draft"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "100",
            "spaceId": "98765",
            "parentId": "200",
            "parentType": "page",
            "status": "current",
            "version": {"number": 1}
        })))
        .mount(&server)
        .await;

    let backend = http_confluence_backend_for_server(&server);
    let ancestors = backend.page_ancestors("200", &credential()).await.unwrap();
    assert_eq!(ancestors.value[0].id, "folder-abc");
    assert_eq!(ancestors.value[0].content_type, "folder");
    assert_eq!(ancestors.value[1].id, "55555");
    let moved = backend
        .move_page(
            "100",
            ConfluencePageMovePosition::Before,
            "200",
            &credential(),
        )
        .await
        .unwrap();
    assert_eq!(moved.value, "100");
    let hierarchy = backend
        .page_hierarchy("100", false, &credential())
        .await
        .unwrap();
    assert_eq!(hierarchy.value.parent_page_id.as_deref(), Some("200"));
    let children = backend
        .page_direct_children("55555", &credential())
        .await
        .unwrap();
    assert_eq!(children.value[0].child_position, 0);

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 4);
    assert!(requests.iter().any(|request| {
        request.method.as_str() == "PUT"
            && request.url.path() == "/wiki/rest/api/content/100/move/before/200"
    }));
}

#[test]
fn page_hierarchy_parser_accepts_supported_non_page_parent_types() {
    let hierarchy = page_hierarchy_from_value(json!({
        "id": "100",
        "type": "page",
        "spaceId": "98765",
        "parentId": "folder-abc",
        "parentType": "folder",
        "status": "current",
        "version": {"number": 1}
    }))
    .unwrap();

    assert_eq!(hierarchy.parent_page_id.as_deref(), Some("folder-abc"));
    assert_eq!(hierarchy.parent_type.as_deref(), Some("folder"));
    assert!(
        page_hierarchy_from_value(json!({
            "id": "100",
            "type": "page",
            "spaceId": "98765",
            "parentId": "page-abc",
            "parentType": "page",
            "status": "current",
            "version": {"number": 1}
        }))
        .is_err()
    );
    assert!(
        page_hierarchy_from_value(json!({
            "id": "100",
            "type": "page",
            "spaceId": "98765",
            "parentId": "custom-abc",
            "parentType": "custom",
            "status": "current",
            "version": {"number": 1}
        }))
        .is_err()
    );
    assert!(
        page_ancestors_from_value(json!({
            "results": [{"id": "page-abc", "type": "page"}],
            "_links": {}
        }))
        .is_err()
    );
}

#[tokio::test]
async fn http_backend_builds_confluence_comment_mutation_requests() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/wiki/api/v2/footer-comments/5001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "5001",
            "pageId": "123456",
            "status": "current",
            "version": { "number": 2 },
            "body": {
                "storage": {
                    "value": "<p>updated</p>",
                    "representation": "storage"
                }
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/wiki/api/v2/inline-comments/6001"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let backend = http_confluence_v2_backend_for_server(&server);
    let updated = backend
        .update_comment(
            ConfluenceCommentUpdateRequest {
                kind: ConfluenceCommentKind::Footer,
                comment_id: "5001".to_string(),
                base_version: 1,
                body: ConfluencePageBody {
                    representation: "storage".to_string(),
                    value: "<p>updated</p>".to_string(),
                },
            },
            &credential(),
        )
        .await
        .unwrap();
    assert_eq!(updated.value.id, "5001");
    assert_eq!(updated.value.version, Some(2));
    assert_eq!(
        updated.value.bodies.get("storage").map(String::as_str),
        Some("<p>updated</p>")
    );

    let deleted = backend
        .delete_comment(ConfluenceCommentKind::Inline, "6001", &credential())
        .await
        .unwrap();
    assert_eq!(deleted.status, 204);

    let requests = server.received_requests().await.unwrap();
    let update = requests
        .iter()
        .find(|request| {
            request.method.as_str() == "PUT"
                && request.url.path() == "/wiki/api/v2/footer-comments/5001"
        })
        .expect("comment update request was recorded");
    let update_body: Value = update.body_json().unwrap();
    assert_eq!(update_body["version"]["number"], 2);
    assert_eq!(update_body["body"]["representation"], "storage");
    assert_eq!(update_body["body"]["value"], "<p>updated</p>");
    assert!(update_body.get("id").is_none());
    assert!(update_body.get("status").is_none());

    let delete = requests
        .iter()
        .find(|request| {
            request.method.as_str() == "DELETE"
                && request.url.path() == "/wiki/api/v2/inline-comments/6001"
        })
        .expect("comment delete request was recorded");
    assert!(delete.body.is_empty());
}

#[tokio::test]
async fn http_backend_comment_mutations_fail_closed_on_conflict_and_delete_status() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/wiki/api/v2/footer-comments/5001"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "errors": [{
                "code": "INVALID_BODY",
                "title": "Invalid comment",
                "detail": "storage is malformed"
            }]
        })))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/wiki/api/v2/footer-comments/5002"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "5002",
            "status": "deleted"
        })))
        .mount(&server)
        .await;

    let backend = http_confluence_v2_backend_for_server(&server);
    let update_error = backend
        .update_comment(
            ConfluenceCommentUpdateRequest {
                kind: ConfluenceCommentKind::Footer,
                comment_id: "5001".to_string(),
                base_version: 1,
                body: ConfluencePageBody {
                    representation: "storage".to_string(),
                    value: "<p>updated</p>".to_string(),
                },
            },
            &credential(),
        )
        .await
        .unwrap_err();
    assert_eq!(update_error, ConfluenceBackendError::Conflict);

    let delete_error = backend
        .delete_comment(ConfluenceCommentKind::Footer, "5002", &credential())
        .await
        .unwrap_err();
    assert!(
        matches!(delete_error, ConfluenceBackendError::Protocol(message) if message.contains("unexpected success status"))
    );
}

#[tokio::test]
async fn http_backend_comment_pagination_uses_link_header_and_rejects_disagreement() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/wiki/api/v2/pages/123456/footer-comments"))
        .and(query_param("limit", "2"))
        .and(query_param("body-format", "storage"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header(
                    "Link",
                    format!(
                        "<{}/wiki/api/v2/pages/123456/footer-comments?cursor=abc&limit=2&body-format=storage>; rel=\"next\"",
                        server.uri()
                    ),
                )
                .set_body_json(json!({
                    "results": [{
                        "id": "5001",
                        "pageId": "123456",
                        "status": "current",
                        "body": {
                            "storage": {
                                "value": "<p>comment</p>",
                                "representation": "storage"
                            }
                        }
                    }]
                })),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/wiki/api/v2/pages/123456/inline-comments"))
        .and(query_param("limit", "2"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header(
                    "Link",
                    "</wiki/api/v2/pages/123456/inline-comments?cursor=header&limit=2>; rel=\"next\"",
                )
                .set_body_json(json!({
                    "results": [],
                    "_links": {
                        "next": "/wiki/api/v2/pages/123456/inline-comments?cursor=body&limit=2"
                    }
                })),
        )
        .mount(&server)
        .await;

    let backend = http_confluence_v2_backend_for_server(&server);
    let page = backend
        .comments_page(
            ConfluenceCommentListRequest {
                kind: ConfluenceCommentKind::Footer,
                container_type: ConfluenceCommentContainerType::Page,
                container_id: "123456".to_string(),
                body_format: Some("storage".to_string()),
                resolution_status: None,
                sort: None,
                max_results: 2,
                cursor: None,
            },
            &credential(),
        )
        .await
        .unwrap();
    assert_eq!(page.value.comments[0].id, "5001");
    assert_eq!(page.value.next_cursor.as_deref(), Some("abc"));

    let error = backend
        .comments_page(
            ConfluenceCommentListRequest {
                kind: ConfluenceCommentKind::Inline,
                container_type: ConfluenceCommentContainerType::Page,
                container_id: "123456".to_string(),
                body_format: None,
                resolution_status: None,
                sort: None,
                max_results: 2,
                cursor: None,
            },
            &credential(),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, ConfluenceBackendError::Protocol(_)));
}

#[tokio::test]
async fn http_backend_handles_confluence_attachment_upload_download_and_pagination() {
    let api = MockServer::start().await;
    let media = MockServer::start().await;
    let bytes = b"downloaded!";
    let upload_bytes = b"uploaded diagram bytes";
    Mock::given(method("POST"))
        .and(path("/wiki/rest/api/content/123456/child/attachment"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(25))
                .set_body_json(json!({
                    "results": [{
                        "id": "att123",
                        "title": "diagram.txt",
                        "metadata": { "mediaType": "text/plain" },
                        "extensions": { "fileSize": upload_bytes.len() as u64 }
                    }]
                })),
        )
        .mount(&api)
        .await;
    Mock::given(method("GET"))
        .and(path("/wiki/rest/api/content/123456/child/attachment"))
        .and(query_param("limit", "200"))
        .and(query_param("expand", "version,metadata,extensions"))
        .and(query_param_is_missing("start"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [],
            "_links": {
                "next": "/wiki/rest/api/content/123456/child/attachment?expand=version%2Cmetadata%2Cextensions&start=200&limit=200"
            }
        })))
        .mount(&api)
        .await;
    Mock::given(method("GET"))
        .and(path("/wiki/rest/api/content/123456/child/attachment"))
        .and(query_param("start", "200"))
        .and(query_param("limit", "200"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "id": "att123",
                "title": "diagram.txt",
                "metadata": { "mediaType": "text/plain" },
                "extensions": { "fileSize": bytes.len() as u64 }
            }]
        })))
        .mount(&api)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/wiki/rest/api/content/123456/child/attachment/att123/download",
        ))
        .respond_with(
            ResponseTemplate::new(303).insert_header("Location", format!("{}/blob", media.uri())),
        )
        .mount(&api)
        .await;
    Mock::given(method("GET"))
        .and(path("/blob"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/plain")
                .set_body_bytes(bytes.as_slice()),
        )
        .mount(&media)
        .await;

    let mut config = confluence_config();
    config.allowed_upstream_hosts = vec![
        format!("{}/wiki/rest/api/**", api.uri()),
        format!("{}/**", media.uri()),
    ];
    let backend = HttpConfluenceBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/wiki/rest/api/", api.uri())).unwrap(),
    );
    let upload_path = std::env::temp_dir().join(format!(
        "agent-access-confluence-upload-{}.txt",
        Uuid::new_v4()
    ));
    std::fs::write(&upload_path, upload_bytes).unwrap();

    let uploaded = backend
        .add_attachment(
            "123456",
            ConfluenceAttachmentUpload {
                filename: "diagram.txt".to_string(),
                content_type: "text/plain".to_string(),
                size: upload_bytes.len() as u64,
                bytes: Vec::new(),
                temp_file: Some(Arc::new(agent_access_provider::host::spooled_body_file(
                    upload_path.clone(),
                    upload_bytes.len() as u64,
                    sha256_hex(upload_bytes),
                ))),
                sha256: sha256_hex(upload_bytes),
            },
            &credential(),
        )
        .await
        .unwrap();
    assert_eq!(uploaded.value.id, "att123");
    assert!(!upload_path.exists());

    let attachments = backend
        .page_attachments("123456", &credential())
        .await
        .unwrap();
    assert_eq!(attachments.value.len(), 1);
    assert_eq!(attachments.value[0].id, "att123");

    let downloaded = agent_access_provider::host::with_correlation_context(
        crate::CorrelationContext::for_tests(),
        backend.attachment_content("123456", "att123", &credential()),
    )
    .await
    .unwrap();
    let downloaded_bytes = match &downloaded.value.stream.source {
        crate::ProviderResultStreamSource::Memory(bytes) => bytes.clone(),
        crate::ProviderResultStreamSource::Stream(stream) => {
            let mut stream = stream.lock().unwrap().take().unwrap();
            let mut bytes = Vec::new();
            while let Some(chunk) = stream.next().await {
                bytes.extend_from_slice(&chunk.unwrap());
            }
            bytes
        }
    };
    assert_eq!(downloaded_bytes, bytes);
    assert_eq!(downloaded.value.content_type, "text/plain");

    let api_requests = api.received_requests().await.unwrap();
    let download = api_requests
        .iter()
        .find(|request| {
            request.method.as_str() == "GET"
                && request.url.path()
                    == "/wiki/rest/api/content/123456/child/attachment/att123/download"
        })
        .expect("download request was recorded");
    assert_eq!(
        download
            .headers
            .get(crate::REQUEST_ID_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("test-agent-request-id")
    );
    assert_eq!(
        download
            .headers
            .get(crate::BROKER_REQUEST_ID_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("test-broker-request-id")
    );
    let upload = api_requests
        .iter()
        .find(|request| {
            request.method.as_str() == "POST"
                && request.url.path() == "/wiki/rest/api/content/123456/child/attachment"
        })
        .expect("upload request was recorded");
    assert_eq!(
        upload
            .headers
            .get("x-atlassian-token")
            .and_then(|value| value.to_str().ok()),
        Some("nocheck")
    );
    assert!(
        upload
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("multipart/form-data"))
    );
    let upload_body = String::from_utf8_lossy(&upload.body);
    assert!(upload_body.contains(r#"name="file""#));
    assert!(upload_body.contains(r#"filename="diagram.txt""#));
    assert!(upload_body.contains("Content-Type: text/plain"));
    assert!(
        upload
            .body
            .windows(upload_bytes.len())
            .any(|window| window == upload_bytes)
    );

    let media_requests = media.received_requests().await.unwrap();
    assert_eq!(media_requests.len(), 1);
    assert!(media_requests[0].headers.get("authorization").is_none());
    assert_eq!(
        media_requests[0]
            .headers
            .get(crate::REQUEST_ID_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("test-agent-request-id")
    );
    assert_eq!(
        media_requests[0]
            .headers
            .get(crate::BROKER_REQUEST_ID_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("test-broker-request-id")
    );
}

#[tokio::test]
async fn http_backend_streams_confluence_attachment_upload_from_file() {
    let api = MockServer::start().await;
    let upload_bytes = b"uploaded diagram bytes";
    Mock::given(method("POST"))
        .and(path("/wiki/rest/api/content/123456/child/attachment"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(25))
                .set_body_json(json!({
                    "results": [{
                        "id": "att123",
                        "title": "diagram.txt",
                        "metadata": { "mediaType": "text/plain" },
                        "extensions": { "fileSize": upload_bytes.len() as u64 }
                    }]
                })),
        )
        .mount(&api)
        .await;
    let mut config = confluence_config();
    config.allowed_upstream_hosts = vec![format!("{}/wiki/rest/api/**", api.uri())];
    let backend = HttpConfluenceBackend::new_with_api_base(
        config,
        ProviderLimits::default().with_request_timeout_ms(1),
        Url::parse(&format!("{}/wiki/rest/api/", api.uri())).unwrap(),
    );
    let upload_path = std::env::temp_dir().join(format!(
        "agent-access-confluence-upload-{}.txt",
        Uuid::new_v4()
    ));
    std::fs::write(&upload_path, upload_bytes).unwrap();

    let uploaded = backend
        .add_attachment(
            "123456",
            ConfluenceAttachmentUpload {
                filename: "diagram.txt".to_string(),
                content_type: "text/plain".to_string(),
                size: upload_bytes.len() as u64,
                bytes: Vec::new(),
                temp_file: Some(Arc::new(agent_access_provider::host::spooled_body_file(
                    upload_path.clone(),
                    upload_bytes.len() as u64,
                    sha256_hex(upload_bytes),
                ))),
                sha256: sha256_hex(upload_bytes),
            },
            &credential(),
        )
        .await
        .unwrap();
    assert_eq!(uploaded.value.id, "att123");
    assert!(!upload_path.exists());
    let requests = api.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0]
            .body
            .windows(upload_bytes.len())
            .any(|window| window == upload_bytes)
    );
}

#[tokio::test]
async fn attachment_download_denies_metadata_and_content_limit_violations() {
    let provider = ConfluenceProvider::with_backend(
        confluence_download_config(5),
        ProviderLimits::default(),
        Arc::new(AttachmentDownloadBackend {
            attachment: confluence_attachment("att123", 6, "text/plain"),
            content: confluence_attachment_content(b"ok", "text/plain"),
        }),
    );
    let error = provider
        .invoke(invocation(
            "attachment.download",
            json!({
                "pageId": "123456",
                "attachmentId": "att123"
            }),
        ))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::AttachmentSizeDenied);

    let provider = ConfluenceProvider::with_backend(
        confluence_download_config(32),
        ProviderLimits::default(),
        Arc::new(AttachmentDownloadBackend {
            attachment: confluence_attachment("att123", 2, "text/plain"),
            content: confluence_attachment_content(b"{}", "application/json"),
        }),
    );
    let error = provider
        .invoke(invocation(
            "attachment.download",
            json!({
                "pageId": "123456",
                "attachmentId": "att123"
            }),
        ))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::AttachmentMediaTypeDenied);

    let mut config = confluence_download_config(32);
    config.attachments.media_types = vec![
        "text/plain".to_string(),
        "application/octet-stream".to_string(),
    ];
    let provider = ConfluenceProvider::with_backend(
        config,
        ProviderLimits::default(),
        Arc::new(AttachmentDownloadBackend {
            attachment: confluence_attachment("att123", 4, "text/plain"),
            content: ConfluenceAttachmentContent {
                filename: "diagram.txt".to_string(),
                content_type: "application/octet-stream".to_string(),
                size: Some(5),
                sha256: None,
                stream: ProviderResultStream::from_bytes(
                    "application/octet-stream",
                    b"data".to_vec(),
                ),
            },
        }),
    );
    let error = provider
        .invoke(invocation(
            "attachment.download",
            json!({
                "pageId": "123456",
                "attachmentId": "att123"
            }),
        ))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);

    let provider = ConfluenceProvider::with_backend(
        confluence_download_config(4),
        ProviderLimits::default(),
        Arc::new(AttachmentDownloadBackend {
            attachment: confluence_attachment("att123", 4, "text/plain"),
            content: confluence_attachment_content(b"12345", "text/plain"),
        }),
    );
    let error = provider
        .invoke(invocation(
            "attachment.download",
            json!({
                "pageId": "123456",
                "attachmentId": "att123"
            }),
        ))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::AttachmentSizeDenied);

    let large_bytes = vec![b'x'; 80];
    let provider = ConfluenceProvider::with_backend(
        confluence_download_config(128),
        ProviderLimits::default()
            .with_max_upstream_response_bytes(64)
            .with_max_download_bytes(128),
        Arc::new(AttachmentDownloadBackend {
            attachment: confluence_attachment("att123", large_bytes.len() as u64, "text/plain"),
            content: confluence_attachment_content(&large_bytes, "text/plain"),
        }),
    );
    let result = provider
        .invoke(invocation(
            "attachment.download",
            json!({
                "pageId": "123456",
                "attachmentId": "att123"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(result.result["size"], 80);
    assert!(result.result.get("contentBase64").is_none());
    let stream = result.stream.unwrap();
    assert_eq!(stream.content_type, "text/plain");
    assert_eq!(stream.memory_len(), Some(80));

    let provider = ConfluenceProvider::with_backend(
        confluence_download_config(32),
        ProviderLimits::default(),
        Arc::new(AttachmentDownloadBackend {
            attachment: confluence_attachment("att123", 5, "text/plain"),
            content: ConfluenceAttachmentContent {
                filename: "diagram.txt".to_string(),
                content_type: "text/plain".to_string(),
                size: None,
                sha256: None,
                stream: ProviderResultStream::from_stream(
                    "text/plain",
                    stream::iter([Ok(Bytes::from_static(b"diag"))]),
                ),
            },
        }),
    );
    let result = provider
        .invoke(invocation(
            "attachment.download",
            json!({
                "pageId": "123456",
                "attachmentId": "att123"
            }),
        ))
        .await
        .unwrap();
    let stream = result.stream.unwrap();
    let crate::ProviderResultStreamSource::Stream(stream) = stream.source else {
        panic!("expected live stream");
    };
    let mut stream = stream.lock().unwrap().take().unwrap();
    assert_eq!(
        stream.next().await.unwrap().unwrap(),
        Bytes::from_static(b"diag")
    );
    let error = stream.next().await.unwrap().unwrap_err();
    assert_eq!(error.reason_code, ReasonCode::UpstreamProtocolFailed);
    assert!(error.message.contains("metadata"));
}

#[test]
fn locator_rejects_untrusted_or_ambiguous_url_shapes() {
    let config = confluence_config();
    for url in [
        "https://evil.example/wiki/pages/viewpage.action?pageId=123456",
        "https://user@example.atlassian.net/wiki/pages/viewpage.action?pageId=123456",
        "https://example.atlassian.net:443/wiki/pages/viewpage.action?pageId=123456",
        "https://example.atlassian.net:444/wiki/pages/viewpage.action?pageId=123456",
        "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=123456#comment",
        "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=123456&foo=bar",
        "https://example.atlassian.net/wiki/x/abcd",
    ] {
        let error = page_locator_from_inputs(&json!({ "url": url }), &config).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::LocatorInvalid);
    }
}

#[test]
fn confluence_transport_error_message_is_sanitized() {
    let error = confluence_backend_error(ConfluenceBackendError::Transport(
        "error sending request for url (https://example.atlassian.net/wiki/rest/api/content/search?cql=space%20%3D%20ENG)".to_string(),
    ));
    assert_eq!(error.message, "Confluence request failed");
}

#[test]
fn confluence_protocol_error_message_is_sanitized() {
    let error = confluence_backend_error(ConfluenceBackendError::Protocol(
        "missing field `id` at line 1 column 42".to_string(),
    ));

    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(error.message, "Confluence response protocol error");
    assert!(!error.message.contains("missing field"));
}

#[test]
fn confluence_validation_error_is_actionable_and_bounded_to_the_upstream_status() {
    let error = confluence_backend_error(ConfluenceBackendError::Validation {
        status: 422,
        message: "body: storage is malformed".to_string(),
    });

    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
    assert_eq!(
        error.message,
        "Confluence rejected the request: body: storage is malformed"
    );
    assert_eq!(error.upstream_status, Some(422));
    assert_eq!(error.upstream_duration_ms, None);
}

#[test]
fn allowlist_double_star_respects_trailing_pattern_segments() {
    assert!(path_matches_pattern(
        &["wiki", "**", "content"],
        &["wiki", "rest", "api", "content"]
    ));
    assert!(!path_matches_pattern(
        &["wiki", "**", "content"],
        &["wiki", "rest", "api"]
    ));
}

struct StubConfluenceBackend {
    page: ConfluencePage,
    search_page: ConfluenceSearchPage,
}

struct PageMoveTestBackend {
    pages: BTreeMap<String, ConfluencePage>,
    space: ConfluenceSpace,
    hierarchies: std::sync::Mutex<BTreeMap<String, ConfluencePageHierarchy>>,
    children: std::sync::Mutex<BTreeMap<String, Vec<String>>>,
    ancestors: std::sync::Mutex<Vec<ConfluencePageAncestor>>,
    create_requests: std::sync::Mutex<Vec<ConfluencePageCreateRequest>>,
    moves: std::sync::Mutex<Vec<(String, ConfluencePageMovePosition, String)>>,
    fail_create: bool,
    fail_draft_create: bool,
    fail_move: bool,
    /// What a failing create, draft create or move returns.
    mutation_failure: ConfluenceBackendError,
    preserve_parent_on_move: bool,
    preserve_order_on_move: bool,
    /// Throttle hierarchy reads once a create or move has applied.
    throttle_hierarchy_after_mutation: bool,
    /// Throttle direct-children reads once a move has applied.
    throttle_children_after_mutation: bool,
    mutated: std::sync::atomic::AtomicBool,
}

impl PageMoveTestBackend {
    fn throttled_after_mutation(&self, throttle: bool) -> Result<(), ConfluenceBackendError> {
        if throttle && self.mutated.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(ConfluenceBackendError::RateLimited(Some(
                UpstreamRetryAfter::after_seconds(30),
            )));
        }
        Ok(())
    }
}

impl PageMoveTestBackend {
    fn new() -> Self {
        let child = test_current_page("100", "Child", "ENG");
        let parent = test_current_page("200", "Parent", "ENG");
        let root = test_current_page("55555", "Homepage", "ENG");
        Self {
            pages: BTreeMap::from([
                (child.id.clone(), child),
                (parent.id.clone(), parent),
                (root.id.clone(), root),
            ]),
            space: ConfluenceSpace {
                id: "98765".to_string(),
                key: "ENG".to_string(),
                web_url: None,
                status: Some("current".to_string()),
                homepage_id: Some("55555".to_string()),
            },
            hierarchies: std::sync::Mutex::new(BTreeMap::from([
                ("100".to_string(), test_page_hierarchy("100", Some("111"))),
                ("200".to_string(), test_page_hierarchy("200", Some("55555"))),
                ("55555".to_string(), test_page_hierarchy("55555", None)),
            ])),
            children: std::sync::Mutex::new(BTreeMap::from([
                ("111".to_string(), vec!["100".to_string()]),
                ("55555".to_string(), vec!["200".to_string()]),
            ])),
            ancestors: std::sync::Mutex::new(Vec::new()),
            create_requests: std::sync::Mutex::new(Vec::new()),
            moves: std::sync::Mutex::new(Vec::new()),
            fail_create: false,
            fail_draft_create: false,
            fail_move: false,
            mutation_failure: ConfluenceBackendError::Timeout,
            preserve_parent_on_move: false,
            preserve_order_on_move: false,
            throttle_hierarchy_after_mutation: false,
            throttle_children_after_mutation: false,
            mutated: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CredentialObservation {
    operation: String,
    credential_token: Option<String>,
    object_id: Option<String>,
    body_format: Option<String>,
}

struct CommentStubConfluenceBackend {
    pages: BTreeMap<String, ConfluencePage>,
    blogs: BTreeMap<String, ConfluenceBlog>,
    comments: BTreeMap<String, ConfluenceComment>,
    comments_by_token: BTreeMap<String, BTreeMap<String, ConfluenceComment>>,
    credential_observations: std::sync::Mutex<Vec<CredentialObservation>>,
    create_requests: std::sync::Mutex<Vec<ConfluenceCommentCreateRequest>>,
    update_requests: std::sync::Mutex<Vec<ConfluenceCommentUpdateRequest>>,
    /// Throttle comment reads once a comment write has applied.
    throttle_reads_after_write: bool,
}

impl CommentStubConfluenceBackend {
    fn written(&self) -> bool {
        !self.create_requests.lock().unwrap().is_empty()
            || !self.update_requests.lock().unwrap().is_empty()
    }

    fn page_thread() -> Self {
        let page = attachment_list_page();
        Self {
            pages: BTreeMap::from([(page.id.clone(), page)]),
            blogs: BTreeMap::new(),
            comments: BTreeMap::from([
                (
                    "5001".to_string(),
                    comment(
                        "5001",
                        ConfluenceCommentKind::Footer,
                        Some("123456"),
                        None,
                        None,
                        "<p>root body</p>",
                    ),
                ),
                (
                    "5002".to_string(),
                    comment(
                        "5002",
                        ConfluenceCommentKind::Footer,
                        None,
                        None,
                        Some("5001"),
                        "<p>footer reply body</p>",
                    ),
                ),
                (
                    "6001".to_string(),
                    comment(
                        "6001",
                        ConfluenceCommentKind::Inline,
                        Some("123456"),
                        None,
                        None,
                        "<p>inline root body</p>",
                    ),
                ),
                (
                    "6002".to_string(),
                    comment(
                        "6002",
                        ConfluenceCommentKind::Inline,
                        None,
                        None,
                        Some("6001"),
                        "<p>reply body</p>",
                    ),
                ),
                (
                    "6003".to_string(),
                    comment(
                        "6003",
                        ConfluenceCommentKind::Inline,
                        None,
                        None,
                        Some("6002"),
                        "<p>nested reply body</p>",
                    ),
                ),
            ]),
            comments_by_token: BTreeMap::new(),
            credential_observations: std::sync::Mutex::new(Vec::new()),
            create_requests: std::sync::Mutex::new(Vec::new()),
            update_requests: std::sync::Mutex::new(Vec::new()),
            throttle_reads_after_write: false,
        }
    }

    fn comments_for_credential(
        &self,
        credential: &ExecutionCredential,
    ) -> &BTreeMap<String, ConfluenceComment> {
        Some(credential_token(credential))
            .and_then(|token| self.comments_by_token.get(token))
            .unwrap_or(&self.comments)
    }

    fn observe(
        &self,
        operation: &str,
        credential: &ExecutionCredential,
        object_id: Option<String>,
        body_format: Option<String>,
    ) {
        self.credential_observations
            .lock()
            .unwrap()
            .push(CredentialObservation {
                operation: operation.to_string(),
                credential_token: Some(credential_token(credential).to_owned()),
                object_id,
                body_format,
            });
    }
}

struct BlogViewBackend {
    blog: ConfluenceBlog,
    space: ConfluenceSpace,
}

struct AttachmentDownloadBackend {
    attachment: ConfluenceAttachment,
    content: ConfluenceAttachmentContent,
}

struct AttachmentListBackend {
    page: ConfluencePage,
    attachments: Vec<ConfluenceAttachment>,
    credential_observations: std::sync::Mutex<Vec<(String, String)>>,
}

struct AttributionStubConfluenceBackend {
    page: ConfluencePage,
    blog: ConfluenceBlog,
    space: ConfluenceSpace,
    page_create_requests: std::sync::Mutex<Vec<ConfluencePageCreateRequest>>,
    page_update_requests: std::sync::Mutex<Vec<ConfluencePageUpdateRequest>>,
    blog_create_requests: std::sync::Mutex<Vec<ConfluenceBlogCreateRequest>>,
    blog_update_requests: std::sync::Mutex<Vec<ConfluenceBlogUpdateRequest>>,
    backend_calls: std::sync::Mutex<u64>,
}

impl AttributionStubConfluenceBackend {
    fn new() -> Self {
        let page = ConfluencePage {
            bodies: BTreeMap::from([("storage".to_string(), "<p>current page</p>".to_string())]),
            ..attachment_list_page()
        };
        let space = ConfluenceSpace {
            id: "98765".to_string(),
            key: "ENG".to_string(),
            web_url: None,
            status: Some("current".to_string()),
            homepage_id: Some("55555".to_string()),
        };
        let blog = ConfluenceBlog {
            id: "7777".to_string(),
            title: "Current Blog".to_string(),
            space: "ENG".to_string(),
            space_id: space.id.clone(),
            web_url: None,
            space_web_url: None,
            status: Some("current".to_string()),
            version: 3,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::from([("storage".to_string(), "<p>current blog</p>".to_string())]),
        };
        Self {
            page,
            blog,
            space,
            page_create_requests: std::sync::Mutex::new(Vec::new()),
            page_update_requests: std::sync::Mutex::new(Vec::new()),
            blog_create_requests: std::sync::Mutex::new(Vec::new()),
            blog_update_requests: std::sync::Mutex::new(Vec::new()),
            backend_calls: std::sync::Mutex::new(0),
        }
    }
}

struct VerifyForbiddenBackend {
    page_metadata_forbidden: bool,
    page_attachments_forbidden: bool,
}

#[async_trait]
impl ConfluenceBackend for CommentStubConfluenceBackend {
    async fn page_metadata(
        &self,
        page_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        self.observe("page_metadata", credential, Some(page_id.to_string()), None);
        let page = self
            .pages
            .get(page_id)
            .cloned()
            .ok_or(ConfluenceBackendError::NotFound)?;
        Ok(ConfluenceBackendResponse {
            value: page,
            status: 200,
            duration_ms: 3,
        })
    }

    async fn page(
        &self,
        page_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        self.page_metadata(page_id, credential).await
    }

    async fn blog_metadata(
        &self,
        blog_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ConfluenceBackendError> {
        self.observe("blog_metadata", credential, Some(blog_id.to_string()), None);
        let blog = self
            .blogs
            .get(blog_id)
            .cloned()
            .ok_or(ConfluenceBackendError::NotFound)?;
        Ok(ConfluenceBackendResponse {
            value: blog,
            status: 200,
            duration_ms: 3,
        })
    }

    async fn blog(
        &self,
        blog_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ConfluenceBackendError> {
        self.blog_metadata(blog_id, credential).await
    }

    async fn search(
        &self,
        _request: ConfluenceSearchRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSearchPage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "comment stub does not search pages".to_string(),
        ))
    }

    async fn create_page(
        &self,
        _request: ConfluencePageCreateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "comment stub does not create pages".to_string(),
        ))
    }

    async fn update_page(
        &self,
        _request: ConfluencePageUpdateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "comment stub does not update pages".to_string(),
        ))
    }

    async fn add_attachment(
        &self,
        _page_id: &str,
        _attachment: ConfluenceAttachmentUpload,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "comment stub does not add attachments".to_string(),
        ))
    }

    async fn page_attachments(
        &self,
        _page_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "comment stub does not list attachments".to_string(),
        ))
    }

    async fn attachment_content(
        &self,
        _page_id: &str,
        _attachment_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        Err(ConfluenceBackendError::Protocol(
            "comment stub does not download attachments".to_string(),
        ))
    }

    async fn comment(
        &self,
        kind: ConfluenceCommentKind,
        comment_id: &str,
        body_format: Option<&str>,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceComment>, ConfluenceBackendError> {
        self.observe(
            "comment",
            credential,
            Some(comment_id.to_string()),
            body_format.map(ToString::to_string),
        );
        if self.throttle_reads_after_write && self.written() {
            return Err(ConfluenceBackendError::RateLimited(None));
        }
        let comment = self
            .comments_for_credential(credential)
            .get(comment_id)
            .cloned()
            .ok_or(ConfluenceBackendError::NotFound)?;
        if comment.kind != kind {
            return Err(ConfluenceBackendError::NotFound);
        }
        Ok(ConfluenceBackendResponse {
            value: comment,
            status: 200,
            duration_ms: 4,
        })
    }

    async fn comments_page(
        &self,
        request: ConfluenceCommentListRequest,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceCommentListPage>, ConfluenceBackendError> {
        self.observe(
            "comments_page",
            credential,
            Some(request.container_id.clone()),
            request.body_format.clone(),
        );
        let comments = self
            .comments_for_credential(credential)
            .values()
            .filter(|comment| {
                comment.kind == request.kind
                    && comment.parent_comment_id.is_none()
                    && match request.container_type {
                        ConfluenceCommentContainerType::Page => {
                            comment.page_id.as_deref() == Some(request.container_id.as_str())
                        }
                        ConfluenceCommentContainerType::Blog => {
                            comment.blog_id.as_deref() == Some(request.container_id.as_str())
                        }
                    }
            })
            .take(request.max_results as usize)
            .cloned()
            .collect();
        Ok(ConfluenceBackendResponse {
            value: ConfluenceCommentListPage {
                comments,
                next_cursor: None,
            },
            status: 200,
            duration_ms: 5,
        })
    }

    async fn comment_replies_page(
        &self,
        kind: ConfluenceCommentKind,
        comment_id: &str,
        body_format: Option<&str>,
        max_results: u32,
        _cursor: Option<&str>,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceCommentListPage>, ConfluenceBackendError> {
        self.observe(
            "comment_replies_page",
            credential,
            Some(comment_id.to_string()),
            body_format.map(ToString::to_string),
        );
        let comments = self
            .comments_for_credential(credential)
            .values()
            .filter(|comment| {
                comment.kind == kind && comment.parent_comment_id.as_deref() == Some(comment_id)
            })
            .take(max_results as usize)
            .cloned()
            .collect();
        Ok(ConfluenceBackendResponse {
            value: ConfluenceCommentListPage {
                comments,
                next_cursor: None,
            },
            status: 200,
            duration_ms: 5,
        })
    }

    async fn add_comment(
        &self,
        request: ConfluenceCommentCreateRequest,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceComment>, ConfluenceBackendError> {
        self.observe(
            "add_comment",
            credential,
            request
                .page_id
                .clone()
                .or_else(|| request.blog_id.clone())
                .or_else(|| request.parent_comment_id.clone()),
            Some(request.body.representation.clone()),
        );
        self.create_requests.lock().unwrap().push(request.clone());
        let id = format!("{}", 9000 + self.create_requests.lock().unwrap().len());
        Ok(ConfluenceBackendResponse {
            value: ConfluenceComment {
                id,
                kind: request.kind,
                page_id: request.page_id,
                blog_id: request.blog_id,
                parent_comment_id: request.parent_comment_id,
                status: Some("current".to_string()),
                resolution_status: None,
                version: Some(1),
                author: None,
                created_at: None,
                updated_at: None,
                bodies: BTreeMap::from([(request.body.representation, request.body.value)]),
            },
            status: 200,
            duration_ms: 6,
        })
    }

    async fn update_comment(
        &self,
        request: ConfluenceCommentUpdateRequest,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceComment>, ConfluenceBackendError> {
        self.observe(
            "update_comment",
            credential,
            Some(request.comment_id.clone()),
            Some(request.body.representation.clone()),
        );
        let mut comment = self
            .comments_for_credential(credential)
            .get(&request.comment_id)
            .cloned()
            .ok_or(ConfluenceBackendError::NotFound)?;
        self.update_requests.lock().unwrap().push(request.clone());
        comment.version = Some(request.base_version + 1);
        comment.bodies = BTreeMap::from([(request.body.representation, request.body.value)]);
        Ok(ConfluenceBackendResponse {
            value: comment,
            status: 200,
            duration_ms: 6,
        })
    }
}

#[async_trait]
impl ConfluenceBackend for BlogViewBackend {
    async fn page_metadata(
        &self,
        _page_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "blog view stub does not resolve page metadata".to_string(),
        ))
    }

    async fn page(
        &self,
        _page_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "blog view stub does not fetch pages".to_string(),
        ))
    }

    async fn search(
        &self,
        _request: ConfluenceSearchRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSearchPage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "blog view stub does not search pages".to_string(),
        ))
    }

    async fn create_page(
        &self,
        _request: ConfluencePageCreateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "blog view stub does not create pages".to_string(),
        ))
    }

    async fn update_page(
        &self,
        _request: ConfluencePageUpdateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "blog view stub does not update pages".to_string(),
        ))
    }

    async fn add_attachment(
        &self,
        _page_id: &str,
        _attachment: ConfluenceAttachmentUpload,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "blog view stub does not add page attachments".to_string(),
        ))
    }

    async fn page_attachments(
        &self,
        _page_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "blog view stub does not list page attachments".to_string(),
        ))
    }

    async fn attachment_content(
        &self,
        _page_id: &str,
        _attachment_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        Err(ConfluenceBackendError::Protocol(
            "blog view stub does not download page attachments".to_string(),
        ))
    }

    async fn space_by_id(
        &self,
        space_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSpace>, ConfluenceBackendError> {
        if space_id != self.space.id {
            return Err(ConfluenceBackendError::NotFound);
        }
        Ok(ConfluenceBackendResponse {
            value: self.space.clone(),
            status: 200,
            duration_ms: 2,
        })
    }

    async fn blog(
        &self,
        blog_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ConfluenceBackendError> {
        if blog_id != self.blog.id {
            return Err(ConfluenceBackendError::NotFound);
        }
        Ok(ConfluenceBackendResponse {
            value: self.blog.clone(),
            status: 200,
            duration_ms: 3,
        })
    }

    async fn blog_scope_evidence(
        &self,
        blog_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlogScopeEvidence>, ConfluenceBackendError>
    {
        if blog_id != self.blog.id {
            return Err(ConfluenceBackendError::NotFound);
        }
        Ok(ConfluenceBackendResponse {
            value: ConfluenceBlogScopeEvidence {
                id: self.blog.id.clone(),
                space: String::new(),
                space_id: self.blog.space_id.clone(),
            },
            status: 200,
            duration_ms: 2,
        })
    }
}

#[async_trait]
impl ConfluenceBackend for AttachmentDownloadBackend {
    async fn page_metadata(
        &self,
        _page_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        Ok(ConfluenceBackendResponse {
            value: ConfluencePage {
                id: "123456".to_string(),
                title: "Runbook".to_string(),
                space: "ENG".to_string(),
                web_url: None,
                space_web_url: None,
                status: Some("current".to_string()),
                version: 7,
                created_at: None,
                updated_at: None,
                created_by: None,
                updated_by: None,
                bodies: BTreeMap::new(),
            },
            status: 200,
            duration_ms: 3,
        })
    }

    async fn page(
        &self,
        page_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        self.page_metadata(page_id, credential).await
    }

    async fn search(
        &self,
        _request: ConfluenceSearchRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSearchPage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "stub does not search".to_string(),
        ))
    }

    async fn create_page(
        &self,
        _request: ConfluencePageCreateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "stub does not create pages".to_string(),
        ))
    }

    async fn update_page(
        &self,
        _request: ConfluencePageUpdateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "stub does not update pages".to_string(),
        ))
    }

    async fn add_attachment(
        &self,
        _page_id: &str,
        _attachment: ConfluenceAttachmentUpload,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "stub does not add attachments".to_string(),
        ))
    }

    async fn page_attachments(
        &self,
        _page_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ConfluenceBackendError> {
        Ok(ConfluenceBackendResponse {
            value: vec![self.attachment.clone()],
            status: 200,
            duration_ms: 4,
        })
    }

    async fn attachment_content(
        &self,
        _page_id: &str,
        _attachment_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        Ok(ConfluenceBackendResponse {
            value: self.content.clone(),
            status: 200,
            duration_ms: 5,
        })
    }
}

#[async_trait]
impl ConfluenceBackend for AttachmentListBackend {
    async fn page_metadata(
        &self,
        page_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        self.record_credential("page_metadata", credential);
        if page_id != self.page.id {
            return Err(ConfluenceBackendError::NotFound);
        }
        Ok(ConfluenceBackendResponse {
            value: self.page.clone(),
            status: 200,
            duration_ms: 3,
        })
    }

    async fn page(
        &self,
        page_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        self.page_metadata(page_id, credential).await
    }

    async fn search(
        &self,
        _request: ConfluenceSearchRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSearchPage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "stub does not search".to_string(),
        ))
    }

    async fn create_page(
        &self,
        _request: ConfluencePageCreateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "stub does not create pages".to_string(),
        ))
    }

    async fn update_page(
        &self,
        _request: ConfluencePageUpdateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "stub does not update pages".to_string(),
        ))
    }

    async fn add_attachment(
        &self,
        _page_id: &str,
        _attachment: ConfluenceAttachmentUpload,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "stub does not add attachments".to_string(),
        ))
    }

    async fn page_attachments(
        &self,
        _page_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "stub does not eagerly list attachments".to_string(),
        ))
    }

    async fn page_attachments_page(
        &self,
        page_id: &str,
        max_results: u32,
        next_position: Option<&str>,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentListPage>, ConfluenceBackendError>
    {
        self.record_credential("page_attachments_page", credential);
        if page_id != self.page.id {
            return Err(ConfluenceBackendError::NotFound);
        }
        let start = next_position
            .and_then(|position| position.strip_prefix("start="))
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let max_results = max_results as usize;
        let attachments = self
            .attachments
            .iter()
            .skip(start)
            .take(max_results)
            .cloned()
            .collect::<Vec<_>>();
        let next_start = start + attachments.len();
        let next_position =
            (next_start < self.attachments.len()).then(|| format!("start={next_start}"));
        Ok(ConfluenceBackendResponse {
            value: ConfluenceAttachmentListPage {
                attachments,
                next_position,
            },
            status: 200,
            duration_ms: 4,
        })
    }

    async fn page_draft_attachments_page(
        &self,
        page_id: &str,
        max_results: u32,
        next_position: Option<&str>,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentListPage>, ConfluenceBackendError>
    {
        self.record_credential("page_draft_attachments_page", credential);
        self.page_attachments_page(page_id, max_results, next_position, credential)
            .await
    }

    async fn attachment_content(
        &self,
        _page_id: &str,
        _attachment_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        Err(ConfluenceBackendError::Protocol(
            "stub does not download attachments".to_string(),
        ))
    }
}

impl AttachmentListBackend {
    fn record_credential(&self, operation: &str, credential: &ExecutionCredential) {
        self.credential_observations.lock().unwrap().push((
            operation.to_string(),
            credential_token(credential).to_owned(),
        ));
    }
}

#[async_trait]
impl ConfluenceBackend for AttributionStubConfluenceBackend {
    async fn draft_page(
        &self,
        _page_id: &str,
        _body_format: Option<&str>,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        *self.backend_calls.lock().unwrap() += 1;
        Err(ConfluenceBackendError::Protocol(
            "attribution stub draft lookup was not expected".to_string(),
        ))
    }

    async fn draft_blog(
        &self,
        _blog_id: &str,
        _body_format: Option<&str>,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        *self.backend_calls.lock().unwrap() += 1;
        Err(ConfluenceBackendError::Protocol(
            "attribution stub draft lookup was not expected".to_string(),
        ))
    }

    async fn page_metadata(
        &self,
        page_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        if page_id != self.page.id {
            return Err(ConfluenceBackendError::NotFound);
        }
        Ok(ConfluenceBackendResponse {
            value: self.page.clone(),
            status: 200,
            duration_ms: 3,
        })
    }

    async fn space_by_key(
        &self,
        space: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSpace>, ConfluenceBackendError> {
        if space != self.space.key {
            return Err(ConfluenceBackendError::NotFound);
        }
        Ok(ConfluenceBackendResponse {
            value: self.space.clone(),
            status: 200,
            duration_ms: 2,
        })
    }

    async fn space_by_id(
        &self,
        space_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSpace>, ConfluenceBackendError> {
        if space_id != self.space.id {
            return Err(ConfluenceBackendError::NotFound);
        }
        Ok(ConfluenceBackendResponse {
            value: self.space.clone(),
            status: 200,
            duration_ms: 2,
        })
    }

    async fn blog_metadata(
        &self,
        blog_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ConfluenceBackendError> {
        if blog_id != self.blog.id {
            return Err(ConfluenceBackendError::NotFound);
        }
        Ok(ConfluenceBackendResponse {
            value: self.blog.clone(),
            status: 200,
            duration_ms: 3,
        })
    }

    async fn blog(
        &self,
        blog_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ConfluenceBackendError> {
        self.blog_metadata(blog_id, credential).await
    }

    async fn page(
        &self,
        page_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        self.page_metadata(page_id, credential).await
    }

    async fn page_hierarchy(
        &self,
        page_id: &str,
        _get_draft: bool,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePageHierarchy>, ConfluenceBackendError> {
        if page_id == "234567" {
            let request = self
                .page_create_requests
                .lock()
                .unwrap()
                .last()
                .cloned()
                .ok_or(ConfluenceBackendError::NotFound)?;
            return Ok(ConfluenceBackendResponse {
                value: ConfluencePageHierarchy {
                    id: page_id.to_string(),
                    space_id: request.space_id,
                    parent_page_id: request
                        .parent_page_id
                        .or_else(|| self.space.homepage_id.clone()),
                    parent_type: Some("page".to_string()),
                    status: "current".to_string(),
                    version: 1,
                },
                status: 200,
                duration_ms: 2,
            });
        }
        Err(ConfluenceBackendError::NotFound)
    }

    async fn search(
        &self,
        _request: ConfluenceSearchRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSearchPage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "attribution stub does not search pages".to_string(),
        ))
    }

    async fn create_page(
        &self,
        request: ConfluencePageCreateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        self.page_create_requests
            .lock()
            .unwrap()
            .push(request.clone());
        Ok(ConfluenceBackendResponse {
            value: ConfluencePage {
                id: "234567".to_string(),
                title: request.title,
                space: request.space,
                web_url: None,
                space_web_url: None,
                status: Some("current".to_string()),
                version: 1,
                created_at: None,
                updated_at: None,
                created_by: None,
                updated_by: None,
                bodies: BTreeMap::from([(request.body.representation, request.body.value)]),
            },
            status: 200,
            duration_ms: 4,
        })
    }

    async fn update_page(
        &self,
        request: ConfluencePageUpdateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        if request.page_id != self.page.id {
            return Err(ConfluenceBackendError::NotFound);
        }
        self.page_update_requests
            .lock()
            .unwrap()
            .push(request.clone());
        Ok(ConfluenceBackendResponse {
            value: ConfluencePage {
                id: request.page_id,
                title: request.title,
                space: request.space,
                web_url: None,
                space_web_url: None,
                status: Some("current".to_string()),
                version: request.base_version + 1,
                created_at: None,
                updated_at: None,
                created_by: None,
                updated_by: None,
                bodies: BTreeMap::from([(request.body.representation, request.body.value)]),
            },
            status: 200,
            duration_ms: 4,
        })
    }

    async fn add_attachment(
        &self,
        _page_id: &str,
        _attachment: ConfluenceAttachmentUpload,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "attribution stub does not add attachments".to_string(),
        ))
    }

    async fn page_attachments(
        &self,
        _page_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "attribution stub does not list attachments".to_string(),
        ))
    }

    async fn attachment_content(
        &self,
        _page_id: &str,
        _attachment_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        Err(ConfluenceBackendError::Protocol(
            "attribution stub does not download attachments".to_string(),
        ))
    }

    async fn create_blog(
        &self,
        request: ConfluenceBlogCreateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ConfluenceBackendError> {
        self.blog_create_requests
            .lock()
            .unwrap()
            .push(request.clone());
        Ok(ConfluenceBackendResponse {
            value: ConfluenceBlog {
                id: "8888".to_string(),
                title: request.title,
                space: request.space,
                space_id: request.space_id,
                web_url: None,
                space_web_url: None,
                status: Some("current".to_string()),
                version: 1,
                created_at: None,
                updated_at: None,
                created_by: None,
                updated_by: None,
                bodies: BTreeMap::from([(request.body.representation, request.body.value)]),
            },
            status: 200,
            duration_ms: 4,
        })
    }

    async fn update_blog(
        &self,
        request: ConfluenceBlogUpdateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ConfluenceBackendError> {
        if request.blog_id != self.blog.id {
            return Err(ConfluenceBackendError::NotFound);
        }
        self.blog_update_requests
            .lock()
            .unwrap()
            .push(request.clone());
        Ok(ConfluenceBackendResponse {
            value: ConfluenceBlog {
                id: request.blog_id,
                title: request.title,
                space: self.blog.space.clone(),
                space_id: self.blog.space_id.clone(),
                web_url: None,
                space_web_url: None,
                status: Some("current".to_string()),
                version: request.base_version + 1,
                created_at: None,
                updated_at: None,
                created_by: None,
                updated_by: None,
                bodies: BTreeMap::from([(request.body.representation, request.body.value)]),
            },
            status: 200,
            duration_ms: 4,
        })
    }
}

#[async_trait]
impl ConfluenceBackend for VerifyForbiddenBackend {
    async fn page_metadata(
        &self,
        _page_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        if self.page_metadata_forbidden {
            return Err(ConfluenceBackendError::Forbidden);
        }
        Ok(ConfluenceBackendResponse {
            value: ConfluencePage {
                id: "123456".to_string(),
                title: "Runbook".to_string(),
                space: "ENG".to_string(),
                web_url: None,
                space_web_url: None,
                status: Some("current".to_string()),
                version: 7,
                created_at: None,
                updated_at: None,
                created_by: None,
                updated_by: None,
                bodies: BTreeMap::new(),
            },
            status: 200,
            duration_ms: 3,
        })
    }

    async fn page(
        &self,
        page_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        self.page_metadata(page_id, credential).await
    }

    async fn search(
        &self,
        _request: ConfluenceSearchRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSearchPage>, ConfluenceBackendError> {
        Ok(ConfluenceBackendResponse {
            value: ConfluenceSearchPage {
                pages: vec![],
                max_results: 2,
                next_page_token: None,
            },
            status: 200,
            duration_ms: 1,
        })
    }

    async fn create_page(
        &self,
        _request: ConfluencePageCreateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "stub does not create pages".to_string(),
        ))
    }

    async fn update_page(
        &self,
        _request: ConfluencePageUpdateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "stub does not update pages".to_string(),
        ))
    }

    async fn add_attachment(
        &self,
        _page_id: &str,
        _attachment: ConfluenceAttachmentUpload,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "stub does not add attachments".to_string(),
        ))
    }

    async fn page_attachments(
        &self,
        _page_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ConfluenceBackendError> {
        if self.page_attachments_forbidden {
            return Err(ConfluenceBackendError::Forbidden);
        }
        Ok(ConfluenceBackendResponse {
            value: vec![ConfluenceAttachment {
                id: "att123".to_string(),
                page_id: "123456".to_string(),
                filename: "diagram.png".to_string(),
                size: 12,
                content_type: "image/png".to_string(),
            }],
            status: 200,
            duration_ms: 4,
        })
    }

    async fn attachment_content(
        &self,
        _page_id: &str,
        _attachment_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        Err(ConfluenceBackendError::Protocol(
            "stub does not download attachments".to_string(),
        ))
    }
}

#[async_trait]
impl ConfluenceBackend for PageMoveTestBackend {
    async fn page_metadata(
        &self,
        page_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        let page = self
            .pages
            .get(page_id)
            .cloned()
            .ok_or(ConfluenceBackendError::NotFound)?;
        Ok(ConfluenceBackendResponse {
            value: page,
            status: 200,
            duration_ms: 2,
        })
    }

    async fn space_by_key(
        &self,
        space: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSpace>, ConfluenceBackendError> {
        if space != self.space.key {
            return Err(ConfluenceBackendError::NotFound);
        }
        Ok(ConfluenceBackendResponse {
            value: self.space.clone(),
            status: 200,
            duration_ms: 2,
        })
    }

    async fn page(
        &self,
        page_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        self.page_metadata(page_id, credential).await
    }

    async fn page_hierarchy(
        &self,
        page_id: &str,
        _get_draft: bool,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePageHierarchy>, ConfluenceBackendError> {
        self.throttled_after_mutation(self.throttle_hierarchy_after_mutation)?;
        let hierarchy = self
            .hierarchies
            .lock()
            .unwrap()
            .get(page_id)
            .cloned()
            .ok_or(ConfluenceBackendError::NotFound)?;
        Ok(ConfluenceBackendResponse {
            value: hierarchy,
            status: 200,
            duration_ms: 2,
        })
    }

    async fn page_ancestors(
        &self,
        _page_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluencePageAncestor>>, ConfluenceBackendError>
    {
        Ok(ConfluenceBackendResponse {
            value: self.ancestors.lock().unwrap().clone(),
            status: 200,
            duration_ms: 2,
        })
    }

    async fn page_direct_children(
        &self,
        page_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluencePageChild>>, ConfluenceBackendError> {
        self.throttled_after_mutation(self.throttle_children_after_mutation)?;
        let children = self
            .children
            .lock()
            .unwrap()
            .get(page_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .enumerate()
            .map(|(position, id)| ConfluencePageChild {
                id,
                content_type: "page".to_string(),
                status: "current".to_string(),
                child_position: position as u64,
            })
            .collect();
        Ok(ConfluenceBackendResponse {
            value: children,
            status: 200,
            duration_ms: 2,
        })
    }

    async fn move_page(
        &self,
        page_id: &str,
        position: ConfluencePageMovePosition,
        target_page_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<String>, ConfluenceBackendError> {
        self.moves.lock().unwrap().push((
            page_id.to_string(),
            position,
            target_page_id.to_string(),
        ));
        if self.fail_move {
            return Err(self.mutation_failure.clone());
        }
        let parent_page_id = match position {
            ConfluencePageMovePosition::Append => target_page_id.to_string(),
            ConfluencePageMovePosition::Before | ConfluencePageMovePosition::After => self
                .hierarchies
                .lock()
                .unwrap()
                .get(target_page_id)
                .and_then(|hierarchy| hierarchy.parent_page_id.clone())
                .ok_or(ConfluenceBackendError::NotFound)?,
        };
        if !self.preserve_order_on_move {
            let mut children = self.children.lock().unwrap();
            for siblings in children.values_mut() {
                siblings.retain(|id| id != page_id);
            }
            let siblings = children.entry(parent_page_id.clone()).or_default();
            match position {
                ConfluencePageMovePosition::Append => siblings.push(page_id.to_string()),
                ConfluencePageMovePosition::Before | ConfluencePageMovePosition::After => {
                    let target_index = siblings
                        .iter()
                        .position(|id| id == target_page_id)
                        .ok_or(ConfluenceBackendError::NotFound)?;
                    let insert_index = if position == ConfluencePageMovePosition::Before {
                        target_index
                    } else {
                        target_index + 1
                    };
                    siblings.insert(insert_index, page_id.to_string());
                }
            }
        }
        if !self.preserve_parent_on_move {
            let mut hierarchies = self.hierarchies.lock().unwrap();
            let hierarchy = hierarchies
                .get_mut(page_id)
                .ok_or(ConfluenceBackendError::NotFound)?;
            hierarchy.parent_page_id = Some(parent_page_id.to_string());
            hierarchy.parent_type = Some("page".to_string());
        }
        self.mutated
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(ConfluenceBackendResponse {
            value: page_id.to_string(),
            status: 200,
            duration_ms: 3,
        })
    }

    async fn search(
        &self,
        _request: ConfluenceSearchRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSearchPage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "page move test backend does not search".to_string(),
        ))
    }

    async fn create_page(
        &self,
        request: ConfluencePageCreateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        let parent_page_id = request
            .parent_page_id
            .clone()
            .or_else(|| self.space.homepage_id.clone());
        self.create_requests.lock().unwrap().push(request.clone());
        if self.fail_create {
            return Err(self.mutation_failure.clone());
        }
        self.hierarchies.lock().unwrap().insert(
            "900001".to_string(),
            test_page_hierarchy("900001", parent_page_id.as_deref()),
        );
        self.mutated
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(ConfluenceBackendResponse {
            value: test_current_page("900001", &request.title, &request.space),
            status: 200,
            duration_ms: 3,
        })
    }

    async fn update_page(
        &self,
        _request: ConfluencePageUpdateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "page move test backend does not update pages".to_string(),
        ))
    }

    async fn create_page_draft(
        &self,
        request: ConfluenceDraftCreateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        if self.fail_draft_create {
            return Err(self.mutation_failure.clone());
        }
        let parent_page_id = request
            .parent_page_id
            .or_else(|| self.space.homepage_id.clone());
        let mut hierarchy = test_page_hierarchy("900002", parent_page_id.as_deref());
        hierarchy.status = "draft".to_string();
        self.hierarchies
            .lock()
            .unwrap()
            .insert("900002".to_string(), hierarchy);
        self.mutated
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(ConfluenceBackendResponse {
            value: ConfluenceDraftContent {
                id: "900002".to_string(),
                title: request.title,
                content_type: "page".to_string(),
                space: request.space,
                space_id: request.space_id,
                parent_page_id,
                web_url: None,
                space_web_url: None,
                status: Some("draft".to_string()),
                version: 1,
                created_at: None,
                updated_at: None,
                created_by: None,
                updated_by: None,
                bodies: BTreeMap::from([(request.body.representation, request.body.value)]),
            },
            status: 200,
            duration_ms: 3,
        })
    }

    async fn add_attachment(
        &self,
        _page_id: &str,
        _attachment: ConfluenceAttachmentUpload,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "page move test backend does not add attachments".to_string(),
        ))
    }

    async fn page_attachments(
        &self,
        _page_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "page move test backend does not list attachments".to_string(),
        ))
    }

    async fn attachment_content(
        &self,
        _page_id: &str,
        _attachment_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        Err(ConfluenceBackendError::Protocol(
            "page move test backend does not download attachments".to_string(),
        ))
    }
}

#[async_trait]
impl ConfluenceBackend for StubConfluenceBackend {
    async fn current_user(
        &self,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<Value>, ConfluenceBackendError> {
        Ok(ConfluenceBackendResponse {
            value: json!({"accountId": "alice-account"}),
            status: 200,
            duration_ms: 2,
        })
    }

    async fn page_metadata(
        &self,
        page_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        if page_id != self.page.id {
            return Err(ConfluenceBackendError::NotFound);
        }
        Ok(ConfluenceBackendResponse {
            value: self.page.clone(),
            status: 200,
            duration_ms: 3,
        })
    }

    async fn page(
        &self,
        page_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        if page_id != self.page.id {
            return Err(ConfluenceBackendError::NotFound);
        }
        Ok(ConfluenceBackendResponse {
            value: self.page.clone(),
            status: 200,
            duration_ms: 4,
        })
    }

    async fn search(
        &self,
        _request: ConfluenceSearchRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSearchPage>, ConfluenceBackendError> {
        Ok(ConfluenceBackendResponse {
            value: self.search_page.clone(),
            status: 200,
            duration_ms: 5,
        })
    }

    async fn create_page(
        &self,
        _request: ConfluencePageCreateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "stub does not create pages".to_string(),
        ))
    }

    async fn update_page(
        &self,
        _request: ConfluencePageUpdateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "stub does not update pages".to_string(),
        ))
    }

    async fn add_attachment(
        &self,
        _page_id: &str,
        _attachment: ConfluenceAttachmentUpload,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "stub does not add attachments".to_string(),
        ))
    }

    async fn page_attachments(
        &self,
        _page_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "stub does not list attachments".to_string(),
        ))
    }

    async fn attachment_content(
        &self,
        _page_id: &str,
        _attachment_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        Err(ConfluenceBackendError::Protocol(
            "stub does not download attachments".to_string(),
        ))
    }
}

#[tokio::test]
async fn credential_verification_uses_current_user_probe() {
    let backend = Arc::new(StubConfluenceBackend {
        page: ConfluencePage {
            id: "123456".to_string(),
            title: "Runbook".to_string(),
            space: "ENG".to_string(),
            web_url: None,
            space_web_url: None,
            status: Some("current".to_string()),
            version: 7,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::new(),
        },
        search_page: ConfluenceSearchPage {
            pages: vec![],
            max_results: 2,
            next_page_token: None,
        },
    });
    let provider =
        ConfluenceProvider::with_backend(confluence_config(), ProviderLimits::default(), backend);

    let verification = provider
        .verify_execution_credential(&credential(), &crate::CorrelationContext::for_tests())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(verification.upstream_status, 200);
    assert_eq!(verification.upstream_duration_ms, 2);
    assert_eq!(verification.audit["provider"], "confluence");
}

fn invocation(action: &str, inputs: Value) -> ProviderInvocation {
    let mut resource_scopes = ResourceScopes::new();
    if matches!(action, "page.view" | "blog.view") {
        resource_scopes.insert("space".to_string(), vec!["ENG".to_string()]);
    }
    let builder = InvocationBuilder::new("confluence", action)
        .inputs(inputs)
        .resources(resource_scopes)
        .credential(credential())
        .lookup_credential(credential());
    if action == "search" {
        builder.search(confluence_search_preflight(["ENG"]))
    } else {
        builder
    }
    .build()
}

fn confluence_search_preflight<const N: usize>(spaces: [&str; N]) -> SearchAuthorization {
    SearchAuthorization::new(
        "space".to_string(),
        SearchAuthorizationScope::Finite {
            values: spaces.into_iter().map(ToString::to_string).collect(),
        },
    )
}

#[test]
fn http_backend_records_service_proxy_selection_for_test_clients() {
    let mut config = confluence_config();
    config.egress_proxy = Some(crate::EgressProxyConfig {
        url: "http://confluence-proxy.example:8080".to_string(),
        username_ref: None,
        password_ref: None,
    });
    let backend = HttpConfluenceBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse("https://example.atlassian.net/wiki/rest/api/").unwrap(),
    );

    let audit = backend.egress_proxy_for_test(&credential());
    assert_eq!(audit["mode"], json!("service"));
    assert_eq!(
        audit["proxy"],
        json!("http://confluence-proxy.example:8080")
    );
}

#[tokio::test]
async fn http_backend_routes_page_requests_through_selected_proxy() {
    let upstream = MockServer::start().await;
    let (proxy_url, request_rx) = start_recording_proxy(
        "application/json",
        r#"{"id":"123456","type":"page","title":"Runbook","space":{"key":"ENG"},"status":"current","version":{"number":7},"body":{"storage":{"value":"<p>via proxy</p>"}}}"#,
    )
    .await;
    let mut config = confluence_config();
    config.allowed_upstream_hosts = vec![format!("{}/wiki/rest/api/**", upstream.uri())];
    config.egress_proxy = Some(crate::EgressProxyConfig {
        url: proxy_url,
        username_ref: None,
        password_ref: None,
    });
    let backend = HttpConfluenceBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/wiki/rest/api/", upstream.uri())).unwrap(),
    );

    let response = backend.page("123456", &credential()).await.unwrap();

    assert_eq!(response.value.title, "Runbook");
    let request = request_rx.await.unwrap();
    assert!(request.starts_with(&format!(
        "GET {}/wiki/rest/api/content/123456?",
        upstream.uri()
    )));
    assert!(
        request.contains("expand=space%2Cversion%2Chistory%2Cbody.storage%2Cbody.atlas_doc_format")
    );
    assert!(
        request
            .to_ascii_lowercase()
            .contains("authorization: basic ")
    );
    assert!(upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn http_backend_routes_attachment_streams_through_selected_proxy() {
    let upstream = MockServer::start().await;
    let (proxy_url, request_rx) =
        start_recording_proxy("text/plain", "proxied confluence attachment").await;
    let mut config = confluence_config();
    config.allowed_upstream_hosts = vec![format!("{}/wiki/rest/api/**", upstream.uri())];
    config.egress_proxy = Some(crate::EgressProxyConfig {
        url: proxy_url,
        username_ref: None,
        password_ref: None,
    });
    let backend = HttpConfluenceBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/wiki/rest/api/", upstream.uri())).unwrap(),
    );

    let response = backend
        .attachment_content("123456", "att123", &credential())
        .await
        .unwrap();
    let bytes = stream_bytes(response.value.stream).await;

    assert_eq!(bytes, b"proxied confluence attachment");
    let request = request_rx.await.unwrap();
    assert!(request.starts_with(&format!(
        "GET {}/wiki/rest/api/content/123456/child/attachment/att123/download HTTP/1.1",
        upstream.uri()
    )));
    assert!(upstream.received_requests().await.unwrap().is_empty());
}

async fn start_recording_proxy(
    content_type: &'static str,
    body: &'static str,
) -> (String, oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_url = format!("http://{}", listener.local_addr().unwrap());
    let (request_tx, request_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = vec![0; 8192];
        let read = socket.read(&mut buffer).await.unwrap();
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let _ = request_tx.send(request);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        socket.write_all(response.as_bytes()).await.unwrap();
    });
    (proxy_url, request_rx)
}

async fn stream_bytes(stream: ProviderResultStream) -> Vec<u8> {
    match stream.source {
        crate::ProviderResultStreamSource::Memory(bytes) => bytes,
        crate::ProviderResultStreamSource::Stream(stream) => {
            let mut stream = stream.lock().unwrap().take().unwrap();
            let mut bytes = Vec::new();
            while let Some(chunk) = stream.next().await {
                bytes.extend_from_slice(&chunk.unwrap());
            }
            bytes
        }
    }
}

fn identity(principal: &str) -> crate::InvocationIdentity {
    crate::InvocationIdentity::new(principal.to_string(), true)
}

fn confluence_attribution_provider(
    backend: Arc<AttributionStubConfluenceBackend>,
    patterns: &[&str],
    config: ConfluenceProviderConfig,
) -> ConfluenceProvider {
    let patterns = patterns
        .iter()
        .map(|pattern| pattern.to_string())
        .collect::<Vec<_>>();
    let backend: Arc<dyn ConfluenceBackend> = backend;
    let attribution =
        ProviderAttributionConfig::from_patterns(&confluence_descriptor(&config), &patterns);
    ConfluenceProvider {
        continuations: ConfluenceContinuations::new(&config, &ProviderLimits::default(), None),
        config,
        limits: ProviderLimits::default(),
        backend,
        attribution,
    }
}

fn adf_body(text: &str) -> Value {
    json!({
        "version": 1,
        "type": "doc",
        "content": [
            {
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": text,
                    }
                ]
            }
        ]
    })
}

fn adf_body_with_footer(text: &str, verb: &str, broker_request_id: &str) -> Value {
    let mut body = adf_body(text);
    body["content"].as_array_mut().unwrap().extend([
        json!({ "type": "rule" }),
        json!({
            "type": "paragraph",
            "content": [
                {
                    "type": "text",
                    "text": format!(
                        "{verb} via Agent Access Broker. Request ID: {broker_request_id}"
                    ),
                }
            ]
        }),
    ]);
    body
}

fn adf_footer_texts(body: &Value) -> Vec<String> {
    body.get("content")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|node| node.get("type").and_then(Value::as_str) == Some("paragraph"))
        .filter_map(|node| {
            node.get("content")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|child| child.get("text").and_then(Value::as_str))
                .find(|text| text.contains("via Agent Access Broker"))
                .map(ToString::to_string)
        })
        .collect()
}

fn storage_body_with_footer(body: &str, verb: &str, broker_request_id: &str) -> String {
    format!(
        "{body}\n\n<!-- agent-access-attribution:start -->\n<hr />\n<p><em>{verb} via Agent Access Broker. Request ID: {broker_request_id}</em></p>\n<!-- agent-access-attribution:end -->"
    )
}

fn assert_storage_attribution_audit(result: &ProviderResult, verb: &str) {
    let audit = result.audit.as_ref().unwrap();
    assert_eq!(audit["attribution"]["applied"], true);
    assert_eq!(audit["attribution"]["representation"], "storage");
    assert_eq!(audit["attribution"]["deduped"], true);
    assert_eq!(audit["attribution"]["verb"], verb);
}

fn assert_storage_footer(body: &str, verb: &str, broker_request_id: &str, old_request_id: &str) {
    assert_eq!(body.matches("agent-access-attribution:start").count(), 1);
    assert!(body.contains(&format!(
        "{verb} via Agent Access Broker. Request ID: {broker_request_id}"
    )));
    assert!(!body.contains(old_request_id));
}

fn draft_content(id: &str, content_type: ConfluenceDraftContentType) -> ConfluenceDraftContent {
    ConfluenceDraftContent {
        id: id.to_string(),
        title: "Draft".to_string(),
        content_type: content_type.as_str().to_string(),
        space: "ENG".to_string(),
        space_id: "98765".to_string(),
        parent_page_id: (content_type == ConfluenceDraftContentType::Page)
            .then(|| "55555".to_string()),
        web_url: None,
        space_web_url: None,
        status: Some("draft".to_string()),
        version: 1,
        created_at: None,
        updated_at: None,
        created_by: None,
        updated_by: None,
        bodies: BTreeMap::from([("storage".to_string(), "<p>draft</p>".to_string())]),
    }
}

fn credential() -> ExecutionCredential {
    credential_with_token("token")
}

fn credential_with_token(token: &str) -> ExecutionCredential {
    basic_credential("user@example.com", token)
}

fn attachment_list_page() -> ConfluencePage {
    ConfluencePage {
        id: "123456".to_string(),
        title: "Runbook".to_string(),
        space: "ENG".to_string(),
        web_url: None,
        space_web_url: None,
        status: Some("current".to_string()),
        version: 7,
        created_at: None,
        updated_at: None,
        created_by: None,
        updated_by: None,
        bodies: BTreeMap::new(),
    }
}

fn test_current_page(id: &str, title: &str, space: &str) -> ConfluencePage {
    ConfluencePage {
        id: id.to_string(),
        title: title.to_string(),
        space: space.to_string(),
        web_url: None,
        space_web_url: None,
        status: Some("current".to_string()),
        version: 1,
        created_at: None,
        updated_at: None,
        created_by: None,
        updated_by: None,
        bodies: BTreeMap::new(),
    }
}

fn test_page_hierarchy(id: &str, parent_page_id: Option<&str>) -> ConfluencePageHierarchy {
    ConfluencePageHierarchy {
        id: id.to_string(),
        space_id: "98765".to_string(),
        parent_page_id: parent_page_id.map(ToString::to_string),
        parent_type: parent_page_id.map(|_| "page".to_string()),
        status: "current".to_string(),
        version: 1,
    }
}

fn page_move_invocation() -> ProviderInvocation {
    let mut request = invocation(
        "page.move",
        json!({"pageId": "100", "position": "append", "targetPageId": "200"}),
    );
    request = InvocationBuilder::from(request)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .build();
    request
}

fn sibling_page_move_invocation(position: &str) -> ProviderInvocation {
    let mut request = invocation(
        "page.move",
        json!({"pageId": "100", "position": position, "targetPageId": "200"}),
    );
    request = InvocationBuilder::from(request)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .build();
    request
}

fn attachment_list_backend() -> AttachmentListBackend {
    AttachmentListBackend {
        page: attachment_list_page(),
        attachments: vec![
            ConfluenceAttachment {
                id: "att1".to_string(),
                page_id: "123456".to_string(),
                filename: "one.txt".to_string(),
                size: 1,
                content_type: "text/plain".to_string(),
            },
            ConfluenceAttachment {
                id: "att2".to_string(),
                page_id: "123456".to_string(),
                filename: "two.txt".to_string(),
                size: 2,
                content_type: "text/plain".to_string(),
            },
        ],
        credential_observations: std::sync::Mutex::new(Vec::new()),
    }
}

fn assert_invalid_draft_handle<T: std::fmt::Debug>(result: Result<T, ProviderError>) {
    let error = result.unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InvalidDraftHandle);
}

fn confluence_config() -> ConfluenceProviderConfig {
    ConfluenceProviderConfig {
        tenant_host: "example.atlassian.net".to_string(),
        cloud_id: Some("00000000-0000-0000-0000-000000000000".to_string()),
        egress_proxy: None,
        allowed_upstream_hosts: vec!["https://example.atlassian.net/wiki/rest/api/**".to_string()],
        attachments: Default::default(),
        content: crate::ConfluenceContentConfig {
            page_formats: vec!["storage".to_string(), "atlas_doc_format".to_string()],
            blog_formats: vec!["storage".to_string()],
            comment_formats: vec!["storage".to_string()],
            max_body_bytes: 1024,
        },
        search: SearchLimitsConfig { max_results: 2 },
    }
}

fn confluence_download_config(max_download_bytes: u64) -> ConfluenceProviderConfig {
    let mut config = confluence_config();
    config.attachments.max_download_bytes = max_download_bytes;
    config.attachments.media_types = vec!["text/plain".to_string()];
    config
}

fn confluence_attachment(id: &str, size: u64, content_type: &str) -> ConfluenceAttachment {
    ConfluenceAttachment {
        id: id.to_string(),
        page_id: "123456".to_string(),
        filename: "diagram.txt".to_string(),
        size,
        content_type: content_type.to_string(),
    }
}

fn comment(
    id: &str,
    kind: ConfluenceCommentKind,
    page_id: Option<&str>,
    blog_id: Option<&str>,
    parent_comment_id: Option<&str>,
    body: &str,
) -> ConfluenceComment {
    ConfluenceComment {
        id: id.to_string(),
        kind,
        page_id: page_id.map(ToString::to_string),
        blog_id: blog_id.map(ToString::to_string),
        parent_comment_id: parent_comment_id.map(ToString::to_string),
        status: Some("current".to_string()),
        resolution_status: (kind == ConfluenceCommentKind::Inline).then(|| "open".to_string()),
        version: Some(1),
        author: None,
        created_at: None,
        updated_at: None,
        bodies: BTreeMap::from([("storage".to_string(), body.to_string())]),
    }
}

fn confluence_attachment_content(bytes: &[u8], content_type: &str) -> ConfluenceAttachmentContent {
    ConfluenceAttachmentContent::from_bytes("diagram.txt", content_type, bytes.to_vec())
}

#[tokio::test]
async fn http_backend_maps_upstream_429_to_upstream_rate_limited() {
    let server = MockServer::start().await;
    let retry_at = UpstreamRetryAfter::after_seconds(90)
        .at()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string();
    Mock::given(method("POST"))
        .and(path("/wiki/rest/api/content/123456/child/attachment"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", retry_at.as_str())
                .set_body_string("quota secret detail"),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/wiki/rest/api/content/123456/child/attachment"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "31536000"))
        .mount(&server)
        .await;
    let backend = http_confluence_backend_for_server(&server);

    let upload_error = backend
        .add_attachment(
            "123456",
            ConfluenceAttachmentUpload {
                filename: "diagram.txt".to_string(),
                content_type: "text/plain".to_string(),
                size: 4,
                bytes: b"data".to_vec(),
                temp_file: None,
                sha256: sha256_hex(b"data"),
            },
            &credential(),
        )
        .await
        .unwrap_err();
    let ConfluenceBackendError::RateLimited(Some(wait)) = upload_error else {
        panic!("expected a rate limit with a wait, got {upload_error:?}");
    };
    assert!((88..=91).contains(&wait.seconds()), "{}", wait.seconds());
    let error = confluence_backend_error(upload_error);
    assert_eq!(error.decision(), Decision::Error);
    assert_eq!(error.reason_code(), ReasonCode::UpstreamRateLimited);
    assert!(!error.message.contains("secret"));
    assert_eq!(
        error.message,
        format!(
            "confluence is rate limiting requests. Retry after {}s (at {}).",
            wait.seconds(),
            wait.retry_at()
        )
    );
    assert_eq!(
        error.result.as_deref(),
        Some(&json!({
            "limitScope": "upstream",
            "service": "confluence",
            "retryAfterSeconds": wait.seconds(),
            "retryAt": wait.retry_at(),
        }))
    );

    let list_error = backend
        .page_attachments("123456", &credential())
        .await
        .unwrap_err();
    assert_eq!(
        confluence_backend_reason_code(&list_error),
        ReasonCode::UpstreamRateLimited
    );
    let result = *confluence_backend_error(list_error).result.unwrap();
    assert_eq!(result["retryAfterSeconds"], 86_400);
}

#[tokio::test]
async fn attachment_add_throttling_after_applied_uploads_is_unverified_not_rate_limited() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/wiki/rest/api/content/123456/child/attachment"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "id": "att1",
                "title": "first.txt",
                "metadata": { "mediaType": "text/plain" },
                "extensions": { "fileSize": 5 }
            }]
        })))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/wiki/rest/api/content/123456/child/attachment"))
        .respond_with(ResponseTemplate::new(429))
        .mount(&server)
        .await;
    let mut config = confluence_config();
    config.attachments.media_types = vec!["text/plain".to_string()];
    let provider = ConfluenceProvider::with_backend(
        config,
        ProviderLimits::default(),
        Arc::new(http_confluence_backend_for_server(&server)),
    );
    let error = provider
        .invoke(page_attachment_add_invocation(&[
            "first", "second", "third",
        ]))
        .await
        .unwrap_err();
    // att1 applied before the second upload was throttled: repeating the
    // batch after a wait would upload it again, so this is not a rate limit.
    assert_eq!(error.decision(), Decision::Error);
    assert_eq!(error.reason_code(), ReasonCode::MutationVerificationFailed);
    assert_eq!(
        error.message,
        "Confluence attachment upload partially failed: part of the batch was applied before \
         confluence started rate limiting requests. Do not repeat the batch; inspect \
         result.safeLocators first."
    );
    let result = error.result.as_deref().unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["attachments"][0]["attachmentId"], "att1");
    assert_eq!(result["failures"][0]["reason"], "upstream_rate_limited");
    assert_eq!(
        result["failures"][1]["reason"],
        "not_attempted_after_previous_failure"
    );
    assert_eq!(result["mutationStatus"], "applied_unverified");
    assert_eq!(result["retrySafe"], false);
    assert_eq!(result["verificationStage"], "attachment_upload");
    assert_eq!(
        result["safeLocators"],
        json!({"pageId": "123456", "attachmentIds": ["att1"]})
    );
    for field in ["limitScope", "service", "retryAfterSeconds", "retryAt"] {
        assert!(result.get(field).is_none(), "{field}: {result}");
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn proven_unsent_writes_are_not_applied_and_retry_safe() {
    let not_applied = json!({"mutationStatus": "not_applied", "retrySafe": true});
    // Only the SDK's not-sent proof becomes `NotSent`, which keeps the
    // reason and message a timeout or transport failure reports.
    for (timed_out, reason, message) in [
        (
            false,
            ReasonCode::UpstreamConnectionFailed,
            "Confluence request failed",
        ),
        (
            true,
            ReasonCode::UpstreamTimeout,
            "Confluence request timed out",
        ),
    ] {
        let error = confluence_upstream_error(UpstreamError::NotSent {
            timed_out,
            detail: "connection refused".to_string(),
        });
        assert_eq!(error, ConfluenceBackendError::NotSent { timed_out });
        assert_eq!(confluence_backend_reason_code(&error), reason);
        assert_eq!(sanitized_backend_reason(&error), reason.as_str());
        for write in [
            confluence_write_error(error.clone()),
            confluence_write_failure(error.clone(), map_confluence_conflict),
        ] {
            assert_eq!(write.decision(), Decision::Error);
            assert_eq!(write.reason_code(), reason);
            assert_eq!(write.message, message);
            assert_eq!(write.result.as_deref(), Some(&not_applied));
        }
        // Reads carry no mutation receipt.
        let read = confluence_backend_error(error);
        assert_eq!(read.reason_code(), reason);
        assert!(read.result.is_none());
    }
    // Failures that may have reached Confluence are never reported as unsent.
    assert_eq!(
        confluence_upstream_error(UpstreamError::Timeout),
        ConfluenceBackendError::Timeout
    );
    assert_eq!(
        confluence_upstream_error(UpstreamError::Transport("reset".to_string())),
        ConfluenceBackendError::Transport("reset".to_string())
    );
    for error in [
        ConfluenceBackendError::Timeout,
        ConfluenceBackendError::Transport("reset".to_string()),
    ] {
        assert!(confluence_write_error(error).result.is_none());
    }

    // Unsent placement writes report the receipt and keep their audit.
    let unsent = || PageMoveTestBackend {
        mutation_failure: ConfluenceBackendError::NotSent { timed_out: false },
        ..PageMoveTestBackend::new()
    };
    let space_scope = |request: ProviderInvocation| {
        InvocationBuilder::from(request)
            .resources(ResourceScopes::from([(
                "space".to_string(),
                vec!["ENG".to_string()],
            )]))
            .build()
    };
    for (backend, request, phase) in [
        (
            PageMoveTestBackend {
                fail_create: true,
                ..unsent()
            },
            space_scope(invocation(
                "page.create",
                json!({"space": "ENG", "title": "Created", "contentFormat": "storage", "content": "<p>body</p>"}),
            )),
            "create_mutation",
        ),
        (
            PageMoveTestBackend {
                fail_draft_create: true,
                ..unsent()
            },
            space_scope(invocation(
                "page.draft.create",
                json!({"space": "ENG", "title": "Draft", "contentFormat": "storage", "content": "<p>body</p>"}),
            )),
            "create_mutation",
        ),
        (
            PageMoveTestBackend {
                fail_move: true,
                ..unsent()
            },
            page_move_invocation(),
            "move_mutation",
        ),
    ] {
        let error = ConfluenceProvider::with_backend(
            confluence_config(),
            ProviderLimits::default(),
            Arc::new(backend),
        )
        .invoke(request)
        .await
        .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamConnectionFailed);
        assert_eq!(error.result.as_deref(), Some(&not_applied), "{phase}");
        let audit = error.audit.as_deref().unwrap();
        assert_eq!(audit["mutationPhase"], phase);
        assert_eq!(audit["upstreamFailure"], "upstream_connection_failed");
    }

    // An attachment batch whose first upload was never sent applied nothing.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    let mut config = confluence_config();
    config.attachments.media_types = vec!["text/plain".to_string()];
    config.allowed_upstream_hosts = vec![format!("{origin}/wiki/rest/api/**")];
    let backend = HttpConfluenceBackend::new_with_api_base(
        config.clone(),
        ProviderLimits::default(),
        Url::parse(&format!("{origin}/wiki/rest/api/")).unwrap(),
    );
    let error =
        ConfluenceProvider::with_backend(config, ProviderLimits::default(), Arc::new(backend))
            .invoke(page_attachment_add_invocation(&["first", "second"]))
            .await
            .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamFailed);
    assert_eq!(error.message, "Confluence attachment upload failed");
    assert_eq!(error.result.as_deref(), Some(&not_applied));
    let audit = error.audit.as_deref().unwrap();
    assert_eq!(
        audit["attachments"][0]["reason"],
        "upstream_connection_failed"
    );
    assert_eq!(audit["attachments"][1]["status"], "skipped");
}

/// A page `attachment.add` of one text file per name, admitted with the
/// page's preflight state.
fn page_attachment_add_invocation(names: &[&str]) -> ProviderInvocation {
    let page = ConfluencePage {
        id: "123456".to_string(),
        title: "Runbook".to_string(),
        space: "ENG".to_string(),
        web_url: None,
        space_web_url: None,
        status: Some("current".to_string()),
        version: 7,
        created_at: None,
        updated_at: None,
        created_by: None,
        updated_by: None,
        bodies: BTreeMap::new(),
    };
    InvocationBuilder::new("confluence", "attachment.add")
        .inputs(json!({
            "pageId": "123456",
            "attachments": names.iter().enumerate().map(|(index, name)| json!({
                "field": format!("file{index}"),
                "filename": format!("{name}.txt"),
                "contentType": "text/plain",
                "size": name.len(),
                "sha256": sha256_hex(name.as_bytes()),
            })).collect::<Vec<_>>(),
        }))
        .resources(BTreeMap::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .credential(credential())
        .lookup_credential(credential())
        .body_parts(
            names
                .iter()
                .enumerate()
                .map(|(index, name)| {
                    BrokerBodyPart::in_memory(
                        format!("file{index}"),
                        Some(format!("{name}.txt")),
                        Some("text/plain".to_string()),
                        name.as_bytes().to_vec(),
                    )
                })
                .collect(),
        )
        .state(ProviderState::new(ConfluencePagePreflight {
            page,
            upstream_status: 200,
            upstream_duration_ms: 1,
        }))
        .build()
}

fn http_confluence_backend_for_server(server: &MockServer) -> HttpConfluenceBackend {
    let mut config = confluence_config();
    config.allowed_upstream_hosts = vec![
        format!("{}/wiki/rest/api/**", server.uri()),
        format!("{}/wiki/api/v2/**", server.uri()),
    ];
    HttpConfluenceBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/wiki/rest/api/", server.uri())).unwrap(),
    )
}

fn http_confluence_v2_backend_for_server(server: &MockServer) -> HttpConfluenceBackend {
    let mut config = confluence_config();
    config.allowed_upstream_hosts = vec![format!("{}/wiki/api/v2/**", server.uri())];
    HttpConfluenceBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/wiki/rest/api/", server.uri())).unwrap(),
    )
}

/// Page and blog drafts whose post-write reads are throttled: the draft
/// attachment list once `throttle_attachment_reads_after_uploads` uploads have
/// applied, and every read after a publish or discard.
struct DraftThrottleBackend {
    content_type: ConfluenceDraftContentType,
    existing_attachments: Vec<ConfluenceAttachment>,
    uploads: std::sync::Mutex<Vec<ConfluenceAttachment>>,
    throttle_uploads_after: usize,
    throttle_attachment_reads_after_uploads: usize,
    published_or_discarded: std::sync::atomic::AtomicBool,
}

impl DraftThrottleBackend {
    fn new(content_type: ConfluenceDraftContentType) -> Self {
        Self {
            content_type,
            existing_attachments: Vec::new(),
            uploads: std::sync::Mutex::new(Vec::new()),
            throttle_uploads_after: usize::MAX,
            throttle_attachment_reads_after_uploads: usize::MAX,
            published_or_discarded: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn id(&self) -> &'static str {
        match self.content_type {
            ConfluenceDraftContentType::Page => "123456",
            ConfluenceDraftContentType::Blog => "7777",
        }
    }

    fn throttled() -> ConfluenceBackendError {
        ConfluenceBackendError::RateLimited(Some(UpstreamRetryAfter::after_seconds(30)))
    }

    fn finished(&self) -> bool {
        self.published_or_discarded
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn draft(&self, id: &str) -> Result<ConfluenceDraftContent, ConfluenceBackendError> {
        if self.finished() {
            return Err(Self::throttled());
        }
        if id != self.id() {
            return Err(ConfluenceBackendError::NotFound);
        }
        Ok(draft_content(id, self.content_type))
    }

    fn upload(&self, id: &str) -> Result<ConfluenceAttachment, ConfluenceBackendError> {
        let mut uploads = self.uploads.lock().unwrap();
        if uploads.len() >= self.throttle_uploads_after {
            return Err(Self::throttled());
        }
        let attachment = ConfluenceAttachment {
            id: format!("att{}", uploads.len() + 1),
            page_id: id.to_string(),
            filename: format!("upload-{}.txt", uploads.len() + 1),
            size: 5,
            content_type: "text/plain".to_string(),
        };
        uploads.push(attachment.clone());
        Ok(attachment)
    }

    fn attachment_page(
        &self,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentListPage>, ConfluenceBackendError>
    {
        let uploads = self.uploads.lock().unwrap();
        if uploads.len() >= self.throttle_attachment_reads_after_uploads {
            return Err(Self::throttled());
        }
        let mut attachments = self.existing_attachments.clone();
        attachments.extend(uploads.iter().cloned());
        Ok(ConfluenceBackendResponse {
            value: ConfluenceAttachmentListPage {
                attachments,
                next_position: None,
            },
            status: 200,
            duration_ms: 2,
        })
    }

    fn published(
        &self,
        request: ConfluenceDraftUpdateRequest,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        self.published_or_discarded
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let mut content = draft_content(&request.content_id, self.content_type);
        content.status = Some(request.status);
        content.version = request.version_number;
        Ok(ConfluenceBackendResponse {
            value: content,
            status: 200,
            duration_ms: 3,
        })
    }

    fn discarded(&self) -> Result<ConfluenceBackendResponse<()>, ConfluenceBackendError> {
        self.published_or_discarded
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(ConfluenceBackendResponse {
            value: (),
            status: 204,
            duration_ms: 3,
        })
    }

    fn after_finish(&self) -> Result<(), ConfluenceBackendError> {
        if self.finished() {
            return Err(Self::throttled());
        }
        Ok(())
    }
}

fn ok<T>(value: T) -> Result<ConfluenceBackendResponse<T>, ConfluenceBackendError> {
    Ok(ConfluenceBackendResponse {
        value,
        status: 200,
        duration_ms: 2,
    })
}

#[async_trait]
impl ConfluenceBackend for DraftThrottleBackend {
    async fn page_metadata(
        &self,
        _page_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        self.after_finish()?;
        Err(ConfluenceBackendError::NotFound)
    }

    async fn blog_metadata(
        &self,
        _blog_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ConfluenceBackendError> {
        self.after_finish()?;
        Err(ConfluenceBackendError::NotFound)
    }

    async fn page(
        &self,
        page_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        self.page_metadata(page_id, credential).await
    }

    async fn space_by_id(
        &self,
        space_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSpace>, ConfluenceBackendError> {
        ok(ConfluenceSpace {
            id: space_id.to_string(),
            key: "ENG".to_string(),
            web_url: None,
            status: Some("current".to_string()),
            homepage_id: Some("55555".to_string()),
        })
    }

    async fn search(
        &self,
        _request: ConfluenceSearchRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSearchPage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "stub does not search".to_string(),
        ))
    }

    async fn create_page(
        &self,
        _request: ConfluencePageCreateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "stub does not create pages".to_string(),
        ))
    }

    async fn update_page(
        &self,
        _request: ConfluencePageUpdateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "stub does not update pages".to_string(),
        ))
    }

    async fn add_attachment(
        &self,
        _page_id: &str,
        _attachment: ConfluenceAttachmentUpload,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "stub does not add current attachments".to_string(),
        ))
    }

    async fn page_attachments(
        &self,
        _page_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ConfluenceBackendError> {
        self.after_finish()?;
        ok(self.existing_attachments.clone())
    }

    async fn blog_attachments(
        &self,
        _blog_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ConfluenceBackendError> {
        self.after_finish()?;
        ok(self.existing_attachments.clone())
    }

    async fn attachment_content(
        &self,
        _page_id: &str,
        _attachment_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        Err(ConfluenceBackendError::Protocol(
            "stub does not download attachments".to_string(),
        ))
    }

    async fn draft_page(
        &self,
        page_id: &str,
        _body_format: Option<&str>,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        ok(self.draft(page_id)?)
    }

    async fn draft_blog(
        &self,
        blog_id: &str,
        _body_format: Option<&str>,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        ok(self.draft(blog_id)?)
    }

    async fn update_page_draft(
        &self,
        request: ConfluenceDraftUpdateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        self.published(request)
    }

    async fn update_blog_draft(
        &self,
        request: ConfluenceDraftUpdateRequest,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        self.published(request)
    }

    async fn discard_page_draft(
        &self,
        _page_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<()>, ConfluenceBackendError> {
        self.discarded()
    }

    async fn discard_blog_draft(
        &self,
        _blog_id: &str,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<()>, ConfluenceBackendError> {
        self.discarded()
    }

    async fn add_page_draft_attachment(
        &self,
        page_id: &str,
        _attachment: ConfluenceAttachmentUpload,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        ok(self.upload(page_id)?)
    }

    async fn add_blog_draft_attachment(
        &self,
        blog_id: &str,
        _attachment: ConfluenceAttachmentUpload,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        ok(self.upload(blog_id)?)
    }

    async fn page_draft_attachments_page(
        &self,
        _page_id: &str,
        _max_results: u32,
        _next_position: Option<&str>,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentListPage>, ConfluenceBackendError>
    {
        self.attachment_page()
    }

    async fn blog_draft_attachments_page(
        &self,
        _blog_id: &str,
        _max_results: u32,
        _next_position: Option<&str>,
        _credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentListPage>, ConfluenceBackendError>
    {
        self.attachment_page()
    }
}

/// A provider over `backend` and a signed draft handle for its draft.
fn draft_throttle_provider(
    backend: DraftThrottleBackend,
) -> (ConfluenceProvider, Arc<DraftThrottleBackend>, String) {
    let backend = Arc::new(backend);
    let mut config = confluence_config();
    config.attachments.media_types = vec!["text/plain".to_string()];
    let provider = ConfluenceProvider::with_backend_and_signing_key(
        config,
        ProviderLimits::default(),
        backend.clone(),
        agent_access_provider::test_support::test_signing_key(7),
    );
    let mut binding = invocation("draft.binding", json!({}));
    binding = InvocationBuilder::from(binding)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .build();
    let handle = provider
        .mint_draft_handle(
            backend.content_type,
            &draft_content(backend.id(), backend.content_type),
            ConfluenceDraftOrigin::New,
            None,
            &binding,
        )
        .unwrap();
    (provider, backend, handle)
}

fn draft_invocation(action: &str, inputs: Value) -> ProviderInvocation {
    let mut request = invocation(action, inputs);
    request = InvocationBuilder::from(request)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .build();
    request
}

#[tokio::test]
async fn throttled_draft_attachment_verification_keeps_the_batch_unverified() {
    for (content_type, prefix, id_key) in [
        (ConfluenceDraftContentType::Page, "page", "pageId"),
        (ConfluenceDraftContentType::Blog, "blog", "blogId"),
    ] {
        let mut backend = DraftThrottleBackend::new(content_type);
        // The first upload verifies; the second upload applies but its
        // verification is throttled; the third is never attempted.
        backend.throttle_attachment_reads_after_uploads = 2;
        let (provider, backend, handle) = draft_throttle_provider(backend);
        let error = provider
            .invoke(draft_attachment_add_invocation(
                prefix,
                id_key,
                backend.id(),
                &handle,
            ))
            .await
            .unwrap_err();
        assert_unverified_after_throttling(
            &error,
            "post_upload_readback",
            json!({id_key: backend.id(), "attachmentIds": ["att1", "att2"]}),
        );
        let result = error.result.as_deref().unwrap();
        assert_eq!(result["status"], "partial");
        assert_eq!(result[id_key], backend.id());
        assert_eq!(result["attachments"].as_array().unwrap().len(), 1);
        assert_eq!(result["attachments"][0]["attachmentId"], "att1");
        assert_eq!(result["failures"][0]["status"], "unverified");
        assert_eq!(result["failures"][0]["attachmentId"], "att2");
        assert_eq!(result["failures"][0]["reason"], "upstream_rate_limited");
        assert_eq!(result["failures"][1]["status"], "skipped");
        assert_eq!(backend.uploads.lock().unwrap().len(), 2);
        let audit = error.audit.as_deref().unwrap();
        assert_eq!(audit["attachmentIds"], json!(["att1", "att2"]));
        assert_eq!(
            error.object_ids.as_deref().unwrap()["attachmentIds"],
            json!(["att1", "att2"])
        );
    }
}

fn draft_attachment_add_invocation(
    prefix: &str,
    id_key: &str,
    id: &str,
    handle: &str,
) -> ProviderInvocation {
    let names = ["first", "second", "third"];
    let mut request = draft_invocation(
        &format!("{prefix}.draft.attachment.add"),
        json!({
            id_key: id,
            "draftHandle": handle,
            "attachments": names.iter().enumerate().map(|(index, name)| json!({
                "field": format!("file{index}"),
                "filename": format!("{name}.txt"),
                "contentType": "text/plain",
                "size": name.len(),
                "sha256": sha256_hex(name.as_bytes()),
            })).collect::<Vec<_>>(),
        }),
    );
    request = InvocationBuilder::from(request)
        .body_parts(
            names
                .iter()
                .enumerate()
                .map(|(index, name)| {
                    BrokerBodyPart::in_memory(
                        format!("file{index}"),
                        Some(format!("{name}.txt")),
                        Some("text/plain".to_string()),
                        name.as_bytes().to_vec(),
                    )
                })
                .collect(),
        )
        .build();
    request
}

#[tokio::test]
async fn throttled_draft_attachment_uploads_are_rate_limited_only_before_any_applied() {
    for (content_type, prefix, id_key) in [
        (ConfluenceDraftContentType::Page, "page", "pageId"),
        (ConfluenceDraftContentType::Blog, "blog", "blogId"),
    ] {
        // The second upload is throttled after the first applied.
        let mut backend = DraftThrottleBackend::new(content_type);
        backend.throttle_uploads_after = 1;
        let (provider, backend, handle) = draft_throttle_provider(backend);
        let error = provider
            .invoke(draft_attachment_add_invocation(
                prefix,
                id_key,
                backend.id(),
                &handle,
            ))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::MutationVerificationFailed);
        assert!(
            error
                .message
                .contains("part of the batch was applied before confluence started rate limiting"),
            "{}",
            error.message
        );
        let result = error.result.as_deref().unwrap();
        assert_eq!(result["status"], "partial");
        assert_eq!(result["attachments"][0]["attachmentId"], "att1");
        assert_eq!(result["failures"][0]["reason"], "upstream_rate_limited");
        assert_eq!(result["mutationStatus"], "applied_unverified");
        assert_eq!(result["retrySafe"], false);
        assert_eq!(result["verificationStage"], "attachment_upload");
        assert_eq!(
            result["safeLocators"],
            json!({id_key: backend.id(), "attachmentIds": ["att1"]})
        );
        assert!(result.get("retryAfterSeconds").is_none());

        // The first upload is throttled: nothing applied, so it stays a rate
        // limit with the wait.
        let mut backend = DraftThrottleBackend::new(content_type);
        backend.throttle_uploads_after = 0;
        let (provider, backend, handle) = draft_throttle_provider(backend);
        let error = provider
            .invoke(draft_attachment_add_invocation(
                prefix,
                id_key,
                backend.id(),
                &handle,
            ))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamRateLimited);
        let result = error.result.as_deref().unwrap();
        assert_eq!(result["retryAfterSeconds"], 30);
        assert!(result["attachments"].as_array().unwrap().is_empty());
        assert!(result.get("mutationStatus").is_none());
    }
}

#[tokio::test]
async fn throttled_reads_after_draft_publish_or_discard_are_unverified() {
    for (content_type, prefix, id_key) in [
        (ConfluenceDraftContentType::Page, "page", "pageId"),
        (ConfluenceDraftContentType::Blog, "blog", "blogId"),
    ] {
        let mut backend = DraftThrottleBackend::new(content_type);
        backend.existing_attachments = vec![ConfluenceAttachment {
            id: "att9".to_string(),
            page_id: backend.id().to_string(),
            filename: "existing.txt".to_string(),
            size: 1,
            content_type: "text/plain".to_string(),
        }];
        let (provider, backend, handle) = draft_throttle_provider(backend);
        let error = provider
            .invoke(draft_invocation(
                &format!("{prefix}.draft.publish"),
                json!({id_key: backend.id(), "draftHandle": handle, "bodyFormat": "storage"}),
            ))
            .await
            .unwrap_err();
        assert_unverified_after_throttling(
            &error,
            "post_publish_attachment_readback",
            json!({id_key: backend.id()}),
        );

        let (provider, backend, handle) =
            draft_throttle_provider(DraftThrottleBackend::new(content_type));
        let error = provider
            .invoke(draft_invocation(
                &format!("{prefix}.draft.discard"),
                json!({id_key: backend.id(), "draftHandle": handle}),
            ))
            .await
            .unwrap_err();
        assert_unverified_after_throttling(
            &error,
            "post_discard_readback",
            json!({id_key: backend.id()}),
        );
    }
}

#[tokio::test]
async fn throttled_comment_readbacks_after_applied_writes_are_unverified() {
    let backend = Arc::new(CommentStubConfluenceBackend {
        throttle_reads_after_write: true,
        ..CommentStubConfluenceBackend::page_thread()
    });
    let provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        backend.clone(),
    );
    let mut reply = invocation(
        "page.footer_comment.reply.add",
        json!({
            "commentId": "5001",
            "contentFormat": "storage",
            "content": "<p>reply</p>"
        }),
    );
    reply = InvocationBuilder::from(reply)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .build();
    let error = provider.invoke(reply).await.unwrap_err();
    assert_unverified_after_throttling(
        &error,
        "post_create_readback",
        json!({"commentId": "9001", "parentCommentId": "5001"}),
    );
    assert_eq!(backend.create_requests.lock().unwrap().len(), 1);

    let backend = Arc::new(CommentStubConfluenceBackend {
        throttle_reads_after_write: true,
        ..CommentStubConfluenceBackend::page_thread()
    });
    let provider = ConfluenceProvider::with_backend(
        confluence_config(),
        ProviderLimits::default(),
        backend.clone(),
    );
    let mut update = invocation(
        "page.footer_comment.update",
        json!({
            "commentId": "5001",
            "baseVersion": 1,
            "contentFormat": "storage",
            "content": "<p>updated</p>"
        }),
    );
    update = InvocationBuilder::from(update)
        .resources(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
        .build();
    let error = provider.invoke(update).await.unwrap_err();
    assert_unverified_after_throttling(
        &error,
        "post_update_readback",
        json!({"commentId": "5001", "version": 2}),
    );
    assert_eq!(backend.update_requests.lock().unwrap().len(), 1);
}

#[test]
fn cql_scope_only_and_order_only_keep_space_and_content_constraints() {
    for kind in [
        ConfluenceSearchContentKind::Page,
        ConfluenceSearchContentKind::BlogPost,
    ] {
        for (scope, prefix) in [
            (
                EffectiveSearchScope::Finite(BTreeSet::from(["ENG".to_string()])),
                "space IN (ENG) AND ",
            ),
            (
                EffectiveSearchScope::AllExcept(BTreeSet::from(["PRIVATE".to_string()])),
                "space NOT IN (PRIVATE) AND ",
            ),
            (EffectiveSearchScope::AllExcept(BTreeSet::new()), ""),
        ] {
            for (raw, suffix) in [
                ("", ""),
                ("  ", ""),
                ("ORDER BY lastModified DESC", " ORDER BY lastModified DESC"),
            ] {
                let query = build_confluence_search_query_for_kind(
                    &ConfluenceSearchQueryInput::Cql {
                        value: raw.to_string(),
                    },
                    &scope,
                    &SearchLimitsConfig::default(),
                    kind,
                )
                .unwrap();
                assert_eq!(
                    query.cql,
                    format!("{prefix}type = {}{suffix}", kind.cql_type())
                );
                assert_eq!(query.response_scope, scope);
                assert!(query.query_shape["filter"].is_null());
                assert!(query.text_operand_hashes.is_empty());
            }
        }
    }
    assert_eq!(canonical_cql("  ORDER BY title  "), "ORDER BY title ASC");
    assert_eq!(canonical_cql("  "), "");
    assert!(confluence_text_query("", &SearchLimitsConfig::default()).is_err());
    for raw in [
        "ORDER BY",
        "ORDER BY title,",
        "ORDER BY title DESC title",
        "AND title ~ \"x\"",
        "()",
    ] {
        assert_eq!(
            parse_cql_query(raw).unwrap_err().reason_code(),
            ReasonCode::InputInvalid
        );
    }
}

#[test]
fn cql_omitted_spaces_use_authorization_and_explicit_spaces_only_narrow() {
    let inputs = parse_search_inputs(&json!({"query": {"type": "cql", "value": ""}})).unwrap();
    let authorization = SearchAuthorization::new(
        "space".to_string(),
        SearchAuthorizationScope::Finite {
            values: vec!["ENG".to_string(), "OPS".to_string()],
        },
    );
    let scope =
        effective_search_scope(&authorization, &requested_spaces(&inputs).unwrap()).unwrap();
    let query =
        build_confluence_search_query(&inputs.query, &scope, &SearchLimitsConfig::default())
            .unwrap();
    assert_eq!(query.cql, "space IN (ENG, OPS) AND type = page");
    assert_eq!(
        effective_search_scope(&authorization, &BTreeSet::from(["PRIVATE".to_string()]))
            .unwrap_err()
            .reason_code(),
        ReasonCode::ServiceActionDenied
    );
}

#[test]
fn cql_grammar_errors_are_actionable_and_do_not_echo_operands() {
    for (raw, expected) in [
        (
            "unsupported = \"sensitive-value\"",
            "supported fields: space",
        ),
        ("title = \"sensitive-value\"", "supported operators: ~"),
        ("ORDER BY unsupported", "supported sort fields:"),
        ("created >= \"sensitive-value\"", "YYYY-MM-DD"),
        ("type = sensitive-value", "type must equal page"),
    ] {
        let error = parse_cql_query(raw).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
        assert!(error.message.contains(expected), "{}", error.message);
        assert!(error.message.contains("actions_describe"));
        assert!(!error.message.contains("sensitive-value"));
        assert!(error.message.len() < 600);
    }
    let error = parse_cql_query_for_kind("parent = 123456", ConfluenceSearchContentKind::BlogPost)
        .unwrap_err();
    assert!(
        error
            .message
            .contains("field parent is unsupported for this content type")
    );
}

#[test]
fn cql_discovery_examples_execute_and_blog_fields_match_content_kind() {
    for (name, kind) in [
        ("search", ConfluenceSearchContentKind::Page),
        ("blog.search", ConfluenceSearchContentKind::BlogPost),
    ] {
        let documentation = cql_documentation(kind);
        for example in documentation["cql"]["examples"].as_array().unwrap() {
            let inputs = parse_search_inputs(example).unwrap();
            build_confluence_search_query_for_kind(
                &inputs.query,
                &EffectiveSearchScope::Finite(BTreeSet::from(["ENG".to_string()])),
                &SearchLimitsConfig::default(),
                kind,
            )
            .unwrap();
        }
        let fields = documentation["cql"]["fields"].as_array().unwrap();
        assert_eq!(
            fields.iter().any(|field| field["name"] == "parent"),
            kind == ConfluenceSearchContentKind::Page
        );
        let descriptor = confluence_descriptor(&confluence_config());
        let action = descriptor
            .actions
            .iter()
            .find(|action| action.action == name)
            .unwrap();
        assert_eq!(action.documentation, Some(documentation));
    }
}
