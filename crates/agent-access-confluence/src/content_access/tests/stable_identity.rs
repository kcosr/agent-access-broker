use super::*;

fn resource(kind: &str, id: &str, subtree: bool) -> TypedResourceSelector {
    let value = format!("https://example.atlassian.net/wiki/content/{kind}/{id}");
    ResourceTypeRegistry::new([&CONFLUENCE_SPACE_RESOURCE, &CONFLUENCE_CONTENT_RESOURCE])
        .unwrap()
        .typed_selector(
            CONFLUENCE_CONTENT_RESOURCE.id(),
            &if subtree {
                ResourceSelector::Subtree { value }
            } else {
                ResourceSelector::Exact { value }
            },
        )
        .unwrap()
}

fn foreign_space(backend: &EvidenceBackend) {
    let mut foreign = space();
    foreign.id = "87654".into();
    foreign.key = "OPS".into();
    backend
        .extra_spaces
        .lock()
        .unwrap()
        .insert(foreign.id.clone(), foreign);
}

fn insert_node(
    backend: &EvidenceBackend,
    id: &str,
    foreign: bool,
    ancestor: Option<ConfluenceParent>,
) {
    backend.nodes.lock().unwrap().insert(
        (ConfluenceNodeKind::Page, id.into()),
        ConfluenceNode {
            id: id.into(),
            kind: ConfluenceNodeKind::Page,
            space_id: if foreign { "87654" } else { "98765" }.into(),
            parent: ancestor,
            status: ConfluenceContentStatus::Current,
            version: Some(1),
        },
    );
}

async fn move_resolution(
    provider: &ConfluenceProvider,
    roots: Vec<TypedResourceSelector>,
) -> Result<ScopeResolution, ProviderError> {
    let fixture = ScopeRequestFixture::new(
        "confluence",
        "page.move",
        action_inputs(provider, "page.move"),
    )
    .lookup_credential(token())
    .containment_evidence_level(ContainmentEvidenceLevel::CompleteLineage)
    .containment_roots(roots);
    provider.resolve_scopes(fixture.request()).await
}

#[tokio::test]
async fn stable_identity_follows_external_move_while_current_space_boundaries_change() {
    let backend = Arc::new(EvidenceBackend::new());
    foreign_space(&backend);
    let provider = backend.provider();
    let fixture = ScopeRequestFixture::new("confluence", "page.view", json!({"pageId":"100"}))
        .lookup_credential(token())
        .containment_evidence_level(ContainmentEvidenceLevel::CompleteLineage);
    let (ScopeEvidence::Containment(before), _) = provider
        .resolve_scopes(fixture.request())
        .await
        .unwrap()
        .into_parts()
    else {
        panic!("containment");
    };
    for id in ["100", "200"] {
        backend
            .nodes
            .lock()
            .unwrap()
            .get_mut(&(ConfluenceNodeKind::Page, id.into()))
            .unwrap()
            .space_id = "87654".into();
    }
    let (ScopeEvidence::Containment(after), _) = provider
        .resolve_scopes(fixture.request())
        .await
        .unwrap()
        .into_parts()
    else {
        panic!("containment");
    };
    let exact = ContainmentBoundary::new(vec![resource("page", "100", false)], vec![]);
    let subtree = ContainmentBoundary::new(vec![resource("page", "200", true)], vec![]);
    for boundary in [exact, subtree] {
        assert!(boundary.matches_evidence(&before).unwrap());
        assert!(boundary.matches_evidence(&after).unwrap());
    }
    let registry =
        ResourceTypeRegistry::new([&CONFLUENCE_SPACE_RESOURCE, &CONFLUENCE_CONTENT_RESOURCE])
            .unwrap();
    for (key, expected_before, expected_after) in [("ENG", true, false), ("OPS", false, true)] {
        let boundary = ContainmentBoundary::new(
            vec![
                registry
                    .typed_selector(
                        CONFLUENCE_SPACE_RESOURCE.id(),
                        &ResourceSelector::Exact { value: key.into() },
                    )
                    .unwrap(),
            ],
            vec![],
        );
        assert_eq!(boundary.matches_evidence(&before).unwrap(), expected_before);
        assert_eq!(boundary.matches_evidence(&after).unwrap(), expected_after);
    }
    let ContainmentObligation::Content(before) = &before.obligations()[0] else {
        panic!("point")
    };
    let ContainmentObligation::Content(after) = &after.obligations()[0] else {
        panic!("point")
    };
    assert_eq!(before.target, after.target);
    assert_ne!(before.containers, after.containers);
    assert_eq!(after.ancestors[0].containers, after.containers);
}

#[tokio::test]
async fn external_cross_space_change_after_admission_fails_final_proof_at_both_levels() {
    for level in [
        ContainmentEvidenceLevel::ContainerOnly,
        ContainmentEvidenceLevel::CompleteLineage,
    ] {
        let backend = Arc::new(EvidenceBackend::new());
        foreign_space(&backend);
        let provider = backend.provider();
        let request = admitted(&provider, "page.view", level).await;
        for id in ["100", "200"] {
            backend
                .nodes
                .lock()
                .unwrap()
                .get_mut(&(ConfluenceNodeKind::Page, id.into()))
                .unwrap()
                .space_id = "87654".into();
        }
        let error = provider
            .recheck_content_location(&request)
            .await
            .err()
            .unwrap();
        assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
        assert_eq!(
            error.audit.as_deref().unwrap()["locationProof"]["finalCheck"],
            "changed"
        );
        assert_eq!(backend.page_reads.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn stable_identity_is_not_an_action_browser_locator_and_stale_routes_still_fail() {
    let backend = Arc::new(EvidenceBackend::new());
    let provider = backend.provider();
    for (action, inputs) in [
        (
            "page.view",
            json!({"url":"https://example.atlassian.net/wiki/content/page/100"}),
        ),
        (
            "blog.view",
            json!({"url":"https://example.atlassian.net/wiki/content/blog/100"}),
        ),
        (
            "page.create",
            json!({"space":"ENG","parentUrl":"https://example.atlassian.net/wiki/content/page/200","title":"Example","contentFormat":"storage","content":"<p>safe</p>"}),
        ),
        (
            "page.move",
            json!({"pageId":"100","position":"append","targetUrl":"https://example.atlassian.net/wiki/content/page/200"}),
        ),
    ] {
        let fixture =
            ScopeRequestFixture::new("confluence", action, inputs).lookup_credential(token());
        assert_eq!(
            provider
                .resolve_scopes(fixture.request())
                .await
                .unwrap_err()
                .reason_code(),
            ReasonCode::LocatorInvalid,
            "{action}"
        );
    }
    assert_eq!(backend.hierarchy_reads.lock().unwrap().len(), 0);
    let fixture = ScopeRequestFixture::new(
        "confluence",
        "page.view",
        json!({"url":"https://example.atlassian.net/wiki/spaces/OLD/pages/100"}),
    )
    .lookup_credential(token());
    assert_eq!(
        provider
            .resolve_scopes(fixture.request())
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::ScopeUnresolved
    );
}

#[tokio::test]
async fn more_than_sixty_four_foreign_roots_have_bounded_container_only_witnesses() {
    let backend = Arc::new(EvidenceBackend::new());
    foreign_space(&backend);
    let roots = (1000..1070)
        .map(|id| {
            let id = id.to_string();
            insert_node(&backend, &id, true, None);
            resource("page", &id, true)
        })
        .collect();
    let provider = backend.provider();
    let request = admitted_with_roots(
        &provider,
        "page.move",
        ContainmentEvidenceLevel::CompleteLineage,
        roots,
    )
    .await;
    let related = request
        .containment_authorization()
        .unwrap()
        .evidence()
        .related_roots();
    assert_eq!(related.len(), 70);
    assert!(
        related
            .iter()
            .all(|location| location.evidence_level == ContainmentEvidenceLevel::ContainerOnly)
    );
    provider.recheck_content_location(&request).await.unwrap();
    assert_eq!(backend.writes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn overlapping_roots_upgrade_weak_cache_before_lineage_proof() {
    let mut backend = EvidenceBackend::new();
    backend.weak_parent_omissions = true;
    let backend = Arc::new(backend);
    insert_node(
        &backend,
        "900000000001",
        false,
        Some(parent(ConfluenceNodeKind::Page, "400")),
    );
    let provider = backend.provider();
    let request = admitted_with_roots(
        &provider,
        "page.move",
        ContainmentEvidenceLevel::CompleteLineage,
        vec![diagnostic_root()],
    )
    .await;
    let evidence = request.containment_authorization().unwrap().evidence();
    let root = &evidence.related_roots()[0];
    assert_eq!(
        root.evidence_level,
        ContainmentEvidenceLevel::CompleteLineage
    );
    assert_eq!(root.ancestors.len(), 2);
    let reads = backend.hierarchy_reads.lock().unwrap();
    assert_eq!(
        reads
            .iter()
            .filter(|(id, _)| id == "900000000001")
            .map(|(_, strict)| *strict)
            .collect::<Vec<_>>(),
        [false, true]
    );
}

#[tokio::test]
async fn foreign_root_moving_after_admission_invalidates_the_operation() {
    let backend = Arc::new(EvidenceBackend::new());
    foreign_space(&backend);
    insert_node(&backend, "900000000001", true, None);
    let provider = backend.provider();
    let request = admitted_with_roots(
        &provider,
        "page.move",
        ContainmentEvidenceLevel::CompleteLineage,
        vec![diagnostic_root()],
    )
    .await;
    insert_node(
        &backend,
        "900000000001",
        false,
        Some(parent(ConfluenceNodeKind::Page, "100")),
    );
    let error = provider.invoke(request).await.unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert_eq!(backend.writes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn root_ordinal_keeps_original_slice_position_after_skips_and_deduplication() {
    let backend = Arc::new(EvidenceBackend::new());
    let provider = backend.provider();
    let registry =
        ResourceTypeRegistry::new([&CONFLUENCE_SPACE_RESOURCE, &CONFLUENCE_CONTENT_RESOURCE])
            .unwrap();
    let mut roots = vec![
        registry
            .typed_selector(
                CONFLUENCE_CONTENT_RESOURCE.id(),
                &ResourceSelector::Subtree {
                    value: "https://other.atlassian.net/wiki/content/page/1".into()
                }
            )
            .unwrap();
        18
    ];
    roots.push(resource("page", "200", false));
    roots.push(resource("page", "200", true));
    roots.push(diagnostic_root());
    let error = move_resolution(&provider, roots).await.unwrap_err();
    assert_eq!(
        error.audit.as_deref().unwrap()["locationProof"]["rootOrdinal"],
        20
    );
    assert_eq!(
        error.audit.as_deref().unwrap()["locationProof"]["category"],
        "not_visible_or_absent"
    );
    assert_eq!(backend.writes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn root_bounds_and_noncurrent_metadata_have_distinct_protected_categories() {
    for scenario in [
        "overlap",
        "raw_entries",
        "request_budget",
        "bytes_budget",
        "noncurrent",
    ] {
        let backend = Arc::new(EvidenceBackend::new());
        let mut provider = backend.provider();
        let roots = match scenario {
            "overlap" => (1000..1065)
                .map(|id| {
                    let id = id.to_string();
                    insert_node(&backend, &id, false, None);
                    resource("page", &id, true)
                })
                .collect(),
            "raw_entries" => vec![diagnostic_root(); 257],
            _ => {
                insert_diagnostic_root(&backend, None);
                vec![diagnostic_root()]
            }
        };
        if scenario == "request_budget" {
            provider.config.content_access.max_metadata_requests = 5;
        }
        if scenario == "bytes_budget" {
            provider.config.content_access.max_metadata_bytes = 500;
        }
        if scenario == "noncurrent" {
            backend
                .nodes
                .lock()
                .unwrap()
                .get_mut(&(ConfluenceNodeKind::Page, "900000000001".into()))
                .unwrap()
                .status = ConfluenceContentStatus::Draft;
        }
        let error = move_resolution(&provider, roots).await.unwrap_err();
        let proof = &error.audit.as_deref().unwrap()["locationProof"];
        assert_eq!(
            proof["category"],
            if scenario == "noncurrent" {
                "unconfirmed"
            } else {
                "root_budget_exhausted"
            },
            "{scenario}: {proof}"
        );
        assert_eq!(
            proof.get("rootOrdinal").is_some(),
            scenario != "raw_entries",
            "{scenario}"
        );
        assert_eq!(backend.writes.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn disclosed_stable_identity_uses_the_described_id_input_for_execution() {
    let backend = Arc::new(EvidenceBackend::new());
    let provider = backend.provider();
    let descriptor = confluence_descriptor(&config());
    let action = descriptor
        .actions
        .iter()
        .find(|action| action.action == "page.view")
        .unwrap();
    assert!(
        action.documentation.as_ref().unwrap()["resourceIdentities"]
            .as_str()
            .unwrap()
            .contains("supply pageId")
    );
    assert_eq!(
        action.input_schema["properties"]["pageId"]["type"],
        "string"
    );
    let selected = resource("page", "100", false);
    let identity = match selected.selector() {
        ResourceSelector::Exact { value } => value,
        _ => panic!("exact page"),
    };
    let location = locations::parse_canonical_content_location(identity).unwrap();
    let inputs = json!({"pageId":location.id.unwrap()});
    let fixture = ScopeRequestFixture::new("confluence", "page.view", inputs.clone())
        .lookup_credential(token())
        .containment_evidence_level(ContainmentEvidenceLevel::ContainerOnly);
    let (ScopeEvidence::Containment(evidence), Some(state)) = provider
        .resolve_scopes(fixture.request())
        .await
        .unwrap()
        .into_parts()
    else {
        panic!("content proof")
    };
    assert!(
        ContainmentBoundary::new(vec![selected], vec![])
            .matches_evidence(&evidence)
            .unwrap()
    );
    let registry =
        ResourceTypeRegistry::new([&CONFLUENCE_SPACE_RESOURCE, &CONFLUENCE_CONTENT_RESOURCE])
            .unwrap();
    let contract = descriptor.resource_scopes["page_location"]
        .as_containment()
        .unwrap()
        .clone();
    let authority = agent_access_provider::host::containment_authorization(
        "https://example.atlassian.net",
        contract,
        evidence,
        &registry,
        ContainmentEvidenceLevel::ContainerOnly,
        "a".repeat(64),
    )
    .unwrap();
    let request = InvocationBuilder::new("confluence", "page.view")
        .inputs(inputs)
        .credential(token())
        .lookup_credential(token())
        .containment(authority)
        .state(state)
        .build();
    let result = provider.invoke(request).await.unwrap();
    assert_eq!(result.result["id"], "100");
    assert_eq!(backend.page_reads.load(Ordering::SeqCst), 1);
}
