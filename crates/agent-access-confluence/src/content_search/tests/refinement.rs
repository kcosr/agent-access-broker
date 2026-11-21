//! Stable content identity never substitutes for fresh current-space evidence.
use super::*;

fn exact_authority(kind: ConfluenceSearchContentKind) -> ContainmentCollectionAuthorization {
    authority(
        kind,
        vec![content(kind, "101", false)],
        vec![],
        ContainmentEvidenceLevel::ContainerOnly,
        'a',
    )
}

fn assert_empty(result: &ProviderResult, kind: ConfluenceSearchContentKind) {
    assert!(result.result[field(kind)].as_array().unwrap().is_empty());
    assert_eq!(result.audit.as_ref().unwrap()["observedSpaces"], json!([]));
    assert!(
        !serde_json::to_string(&result.result)
            .unwrap()
            .contains("Record 101")
    );
}

#[tokio::test]
async fn exact_page_and_blog_follow_current_space_with_two_fresh_passes() {
    for kind in [
        ConfluenceSearchContentKind::Page,
        ConfluenceSearchContentKind::BlogPost,
    ] {
        let backend = Backend::new(vec![results(vec![page("101", "OPS")], None)]);
        backend.set_nodes("101", vec![node("101", "2", None)]);
        let result = provider(backend.clone(), config())
            .invoke_content_search(invocation(kind, exact_authority(kind), inputs()), kind)
            .await
            .unwrap();
        assert_eq!(result.result[field(kind)].as_array().unwrap().len(), 1);
        assert_eq!(
            result.audit.as_ref().unwrap()["observedSpaces"],
            json!(["OPS"])
        );
        let reads = backend.reads.lock().unwrap();
        assert_eq!(reads.len(), 4);
        assert_eq!(
            reads
                .iter()
                .filter(|read| read.as_str() == "space:2")
                .count(),
            2
        );
        assert!(!backend.requests.lock().unwrap()[0].cql.contains("space ="));
    }
}

#[tokio::test]
async fn stable_exact_identity_filters_stale_indexed_space_and_final_moves() {
    for kind in [
        ConfluenceSearchContentKind::Page,
        ConfluenceSearchContentKind::BlogPost,
    ] {
        for final_move in [false, true] {
            let backend = Backend::new(vec![results(vec![page("101", "ENG")], None)]);
            backend.set_nodes(
                "101",
                if final_move {
                    vec![node("101", "1", None), node("101", "2", None)]
                } else {
                    vec![node("101", "2", None)]
                },
            );
            let result = provider(backend.clone(), config())
                .invoke_content_search(invocation(kind, exact_authority(kind), inputs()), kind)
                .await
                .unwrap();
            assert_empty(&result, kind);
            assert_eq!(
                backend.reads.lock().unwrap().len(),
                if final_move { 4 } else { 2 }
            );
        }
    }
}

#[tokio::test]
async fn fresh_content_authority_checks_requested_current_keys_despite_upstream_rows() {
    for kind in [
        ConfluenceSearchContentKind::Page,
        ConfluenceSearchContentKind::BlogPost,
    ] {
        let backend = Backend::new(vec![results(vec![page("101", "OPS")], None)]);
        backend.set_nodes("101", vec![node("101", "2", None)]);
        let mut query = inputs();
        query["spaces"] = json!(["ENG"]);
        let result = provider(backend.clone(), config())
            .invoke_content_search(invocation(kind, exact_authority(kind), query), kind)
            .await
            .unwrap();
        assert_empty(&result, kind);
        assert_eq!(backend.reads.lock().unwrap().len(), 2);
    }
}

#[tokio::test]
async fn unchanged_numeric_space_is_refetched_per_candidate_and_final_pass() {
    let kind = ConfluenceSearchContentKind::Page;
    let backend = Backend::new(vec![results(
        vec![page("101", "ENG"), page("102", "ENG")],
        None,
    )]);
    backend.set_nodes("101", vec![node("101", "1", None)]);
    backend.set_nodes("102", vec![node("102", "1", None)]);
    backend.space_keys.lock().unwrap().insert(
        "1".into(),
        vec!["ENG".into(), "OPS".into(), "OPS".into()].into(),
    );
    let selected = authority(
        kind,
        vec![content(kind, "101", false), content(kind, "102", false)],
        vec![],
        ContainmentEvidenceLevel::ContainerOnly,
        'a',
    );
    let result = provider(backend.clone(), config())
        .invoke_content_search(invocation(kind, selected, inputs()), kind)
        .await
        .unwrap();
    assert_empty(&result, kind);
    assert_eq!(
        backend
            .reads
            .lock()
            .unwrap()
            .iter()
            .filter(|read| read.as_str() == "space:1")
            .count(),
        3
    );
}

#[tokio::test]
async fn content_negatives_and_token_terms_force_fresh_proof_even_if_inapplicable() {
    let kind = ConfluenceSearchContentKind::Page;
    for token in [false, true] {
        for negative in [false, true] {
            let backend = Backend::new(vec![results(vec![page("101", "ENG")], None)]);
            backend.set_nodes("101", vec![node("101", "1", None)]);
            let root = if negative {
                // An unrelated exact ID cannot match this row but still prevents
                // scalar classification of the complete issued authority.
                content(kind, "999", false)
            } else {
                content(kind, "101", false)
            };
            let boundary = if negative {
                ContainmentBoundary::new(vec![space("ENG")], vec![root])
            } else {
                ContainmentBoundary::new(vec![root], vec![])
            };
            let (grants, ceiling) = if token {
                (
                    vec![ContainmentBoundary::new(vec![space("ENG")], vec![])],
                    Some(boundary),
                )
            } else {
                (vec![boundary], None)
            };
            let selected = agent_access_provider::host::containment_collection_authorization(
                SITE,
                confluence_resource_scopes()["page_location"]
                    .as_containment()
                    .unwrap()
                    .clone(),
                grants,
                ceiling,
                &registry(),
                ContainmentEvidenceLevel::ContainerOnly,
                "a".repeat(64),
            )
            .unwrap();
            let result = provider(backend.clone(), config())
                .invoke_content_search(invocation(kind, selected, inputs()), kind)
                .await
                .unwrap();
            assert_eq!(result.result["pages"].as_array().unwrap().len(), 1);
            assert_eq!(backend.reads.lock().unwrap().len(), 4);
        }
    }
}

#[tokio::test]
async fn any_started_proof_error_fails_the_entire_page_without_partial_rows_or_cursor() {
    for kind in [
        ConfluenceSearchContentKind::Page,
        ConfluenceSearchContentKind::BlogPost,
    ] {
        for final_pass in [false, true] {
            for failure in [
                ConfluenceBackendError::NotFound,
                ConfluenceBackendError::Forbidden,
                ConfluenceBackendError::ScopeUnresolved,
                ConfluenceBackendError::Timeout,
                ConfluenceBackendError::Unauthorized,
                ConfluenceBackendError::ResponseTooLarge,
                ConfluenceBackendError::Protocol("synthetic malformed metadata".into()),
            ] {
                let backend = Backend::new(vec![results(
                    vec![page("101", "ENG"), page("102", "ENG")],
                    Some("next"),
                )]);
                for id in ["101", "102"] {
                    backend.set_nodes(id, vec![node(id, "1", None)]);
                }
                let prefix = if kind == ConfluenceSearchContentKind::Page {
                    "node"
                } else {
                    "blog"
                };
                backend.failures.lock().unwrap().insert(
                    format!("{prefix}:102"),
                    if final_pass {
                        vec![None, Some(failure)].into()
                    } else {
                        vec![Some(failure)].into()
                    },
                );
                let selected = authority(
                    kind,
                    vec![content(kind, "101", false), content(kind, "102", false)],
                    vec![],
                    ContainmentEvidenceLevel::ContainerOnly,
                    'a',
                );
                let error = provider(backend.clone(), config())
                    .invoke_content_search(invocation(kind, selected, inputs()), kind)
                    .await
                    .unwrap_err();
                assert!(error.result.is_none());
                assert!(!error.message.contains("102"));
                if final_pass {
                    assert_eq!(
                        error.audit.as_ref().unwrap()["locationProof"]["finalCheck"],
                        "unresolved"
                    );
                }
                assert_eq!(backend.requests.lock().unwrap().len(), 1);
            }
        }
    }
}

#[tokio::test]
async fn noncurrent_wrong_kind_and_unreadable_space_are_not_filtered_as_moved_rows() {
    let kind = ConfluenceSearchContentKind::Page;
    for variant in 0..3 {
        let backend = Backend::new(vec![results(vec![page("101", "ENG")], None)]);
        let mut observed = node("101", "1", None);
        if variant == 0 {
            observed.status = ConfluenceContentStatus::Draft;
        }
        if variant == 1 {
            observed.kind = ConfluenceNodeKind::Folder;
        }
        backend.set_nodes("101", vec![observed]);
        if variant == 2 {
            backend.failures.lock().unwrap().insert(
                "space:1".into(),
                vec![Some(ConfluenceBackendError::Forbidden)].into(),
            );
        }
        let error = provider(backend, config())
            .invoke_content_search(invocation(kind, exact_authority(kind), inputs()), kind)
            .await
            .unwrap_err();
        assert!(error.result.is_none());
    }
}

#[tokio::test]
async fn container_only_budget_reserves_both_passes_and_resumes_after_actual_progress() {
    let kind = ConfluenceSearchContentKind::Page;
    let selected = authority(
        kind,
        vec![content(kind, "101", false), content(kind, "102", false)],
        vec![],
        ContainmentEvidenceLevel::ContainerOnly,
        'a',
    );
    let backend = Backend::new(vec![
        results(vec![page("101", "ENG"), page("102", "ENG")], None),
        results(vec![page("101", "ENG"), page("102", "ENG")], None),
    ]);
    for id in ["101", "102"] {
        backend.set_nodes(id, vec![node(id, "1", None)]);
    }
    let mut limits = config();
    limits.content_access.max_metadata_requests = 4;
    let provider = provider(backend.clone(), limits);
    let first = provider
        .invoke_content_search(invocation(kind, selected.clone(), inputs()), kind)
        .await
        .unwrap();
    assert_eq!(first.result["pages"].as_array().unwrap().len(), 1);
    assert_eq!(first.result["scanStatus"], "scan_budget");
    assert_eq!(backend.reads.lock().unwrap().len(), 4);
    let second = provider
        .invoke_content_search(invocation(kind, selected, resume(inputs(), &first)), kind)
        .await
        .unwrap();
    assert_eq!(second.result["pages"][0]["id"], "102");
    assert_eq!(second.result["scanStatus"], "exhausted");
    let backend = Backend::new(vec![]);
    let mut limits = config();
    limits.content_access.max_metadata_requests = 3;
    let error = self::provider(backend.clone(), limits)
        .invoke_content_search(invocation(kind, exact_authority(kind), inputs()), kind)
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert!(backend.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn exact_resume_keeps_identity_across_external_move_and_rechecks_current_location() {
    let kind = ConfluenceSearchContentKind::Page;
    let backend = Backend::new(vec![
        results(vec![page("101", "ENG")], Some("next")),
        results(vec![page("101", "OPS")], None),
    ]);
    backend.set_nodes(
        "101",
        vec![
            node("101", "1", None),
            node("101", "1", None),
            node("101", "2", None),
            node("101", "2", None),
        ],
    );
    let provider = provider(backend.clone(), config());
    let first = provider
        .invoke_content_search(invocation(kind, exact_authority(kind), inputs()), kind)
        .await
        .unwrap();
    let second = provider
        .invoke_content_search(
            invocation(kind, exact_authority(kind), resume(inputs(), &first)),
            kind,
        )
        .await
        .unwrap();
    assert_eq!(second.result["pages"][0]["id"], "101");
    assert_eq!(
        second.audit.as_ref().unwrap()["observedSpaces"],
        json!(["OPS"])
    );
    assert_eq!(backend.reads.lock().unwrap().len(), 8);
    let requests = backend.requests.lock().unwrap();
    assert_eq!(requests[0].cql, requests[1].cql);
}

#[tokio::test]
async fn subtree_follows_root_across_spaces_but_not_a_detached_descendant() {
    let kind = ConfluenceSearchContentKind::Page;
    for attached in [false, true] {
        let backend = Backend::new(vec![results(vec![page("101", "OPS")], None)]);
        backend.set_nodes("101", vec![node("101", "2", attached.then_some("100"))]);
        backend.set_nodes("100", vec![node("100", "2", None)]);
        let result = provider(backend, config())
            .invoke_content_search(invocation(kind, tree_authority(), inputs()), kind)
            .await
            .unwrap();
        assert_eq!(
            result.result["pages"].as_array().unwrap().len(),
            usize::from(attached)
        );
    }
}

#[tokio::test]
async fn actual_space_token_and_exclusion_still_narrow_stable_content_identity() {
    let kind = ConfluenceSearchContentKind::Page;
    for token in [false, true] {
        let backend = Backend::new(vec![results(vec![page("101", "OPS")], None)]);
        backend.set_nodes("101", vec![node("101", "2", None)]);
        let grant = ContainmentBoundary::new(
            vec![content(kind, "101", false)],
            if token { vec![] } else { vec![space("OPS")] },
        );
        let ceiling = token.then(|| ContainmentBoundary::new(vec![space("ENG")], vec![]));
        let selected = agent_access_provider::host::containment_collection_authorization(
            SITE,
            confluence_resource_scopes()["page_location"]
                .as_containment()
                .unwrap()
                .clone(),
            vec![grant],
            ceiling,
            &registry(),
            ContainmentEvidenceLevel::ContainerOnly,
            "a".repeat(64),
        )
        .unwrap();
        let result = provider(backend.clone(), config())
            .invoke_content_search(invocation(kind, selected, inputs()), kind)
            .await
            .unwrap();
        assert_empty(&result, kind);
        assert_eq!(backend.reads.lock().unwrap().len(), 2);
    }
}

#[tokio::test]
async fn complete_lineage_default_budget_finishes_finite_pages_through_bounded_resume() {
    let kind = ConfluenceSearchContentKind::Page;
    let rows = vec![page("101", "ENG"), page("102", "ENG"), page("103", "ENG")];
    let backend = Backend::new(vec![
        results(rows, Some("next")),
        results(
            vec![page("104", "ENG"), page("105", "ENG"), page("106", "ENG")],
            None,
        ),
    ]);
    for id in ["101", "102", "103", "104", "105", "106"] {
        backend.rooted(id);
    }
    let provider = provider(backend.clone(), config());
    let first = provider
        .invoke_content_search(invocation(kind, tree_authority(), inputs()), kind)
        .await
        .unwrap();
    assert_eq!(first.result["pages"].as_array().unwrap().len(), 3);
    assert_eq!(first.result["scanStatus"], "more");
    assert_eq!(backend.reads.lock().unwrap().len(), 18);
    let second = provider
        .invoke_content_search(
            invocation(kind, tree_authority(), resume(inputs(), &first)),
            kind,
        )
        .await
        .unwrap();
    assert_eq!(second.result["pages"].as_array().unwrap().len(), 3);
    assert_eq!(second.result["pages"][0]["id"], "104");
    assert_eq!(backend.reads.lock().unwrap().len(), 36);
    assert_eq!(second.result["scanStatus"], "exhausted");
    assert!(second.result["nextPageToken"].is_null());
    assert_eq!(backend.requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn hidden_ancestor_and_started_byte_exhaustion_fail_without_scan_budget_token() {
    let kind = ConfluenceSearchContentKind::Page;
    let backend = Backend::new(vec![results(vec![page("101", "ENG")], None)]);
    backend.rooted("101");
    backend.failures.lock().unwrap().insert(
        "node:100".into(),
        vec![Some(ConfluenceBackendError::Forbidden)].into(),
    );
    let error = provider(backend, config())
        .invoke_content_search(invocation(kind, tree_authority(), inputs()), kind)
        .await
        .unwrap_err();
    assert!(error.result.is_none());
    let backend = Backend::new(vec![results(vec![page("101", "ENG")], Some("next"))]);
    backend.set_nodes("101", vec![node("101", "1", None)]);
    let mut limits = config();
    limits.content_access.max_metadata_bytes = 128;
    let error = provider(backend, limits)
        .invoke_content_search(invocation(kind, exact_authority(kind), inputs()), kind)
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert!(error.result.is_none());
    assert_eq!(
        error.audit.as_ref().unwrap()["locationProof"]["finalCheck"],
        "unresolved"
    );
}

#[tokio::test]
async fn scalar_all_and_negative_token_boundary_retain_index_only_cost() {
    let kind = ConfluenceSearchContentKind::Page;
    let all = registry()
        .typed_selector(CONFLUENCE_SPACE_RESOURCE.id(), &ResourceSelector::All)
        .unwrap();
    let selected = agent_access_provider::host::containment_collection_authorization(
        SITE,
        confluence_resource_scopes()["page_location"]
            .as_containment()
            .unwrap()
            .clone(),
        vec![ContainmentBoundary::new(
            vec![all.clone()],
            vec![space("PRIVATE")],
        )],
        Some(ContainmentBoundary::new(vec![all], vec![space("OPS")])),
        &registry(),
        ContainmentEvidenceLevel::ContainerOnly,
        "a".repeat(64),
    )
    .unwrap();
    let backend = Backend::new(vec![results(
        vec![page("101", "ENG"), page("102", "OPS")],
        None,
    )]);
    let result = provider(backend.clone(), config())
        .invoke_content_search(invocation(kind, selected, inputs()), kind)
        .await
        .unwrap();
    assert_eq!(result.result["pages"].as_array().unwrap().len(), 1);
    assert_eq!(result.result["pages"][0]["id"], "101");
    assert_eq!(backend.requests.lock().unwrap().len(), 1);
    assert!(backend.reads.lock().unwrap().is_empty());
}
