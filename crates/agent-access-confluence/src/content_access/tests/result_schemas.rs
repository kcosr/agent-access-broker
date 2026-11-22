//! Provider outcomes for existing drafts under every observed parent kind.
use super::*;

const PARENTS: &[Option<ConfluenceNodeKind>] = &[
    None,
    Some(ConfluenceNodeKind::Page),
    Some(ConfluenceNodeKind::Folder),
    Some(ConfluenceNodeKind::Database),
    Some(ConfluenceNodeKind::Whiteboard),
    Some(ConfluenceNodeKind::Embed),
];

fn backend_with_parent(kind: Option<ConfluenceNodeKind>) -> Arc<EvidenceBackend> {
    let mut backend = EvidenceBackend::new();
    backend.page_draft_parent = kind.map(|kind| parent(kind, "500"));
    {
        let mut nodes = backend.nodes.lock().unwrap();
        for id in ["100", "400"] {
            nodes
                .get_mut(&(ConfluenceNodeKind::Page, id.into()))
                .unwrap()
                .parent = backend.page_draft_parent.clone();
        }
        if let Some(kind) = kind {
            nodes.insert(
                (kind, "500".into()),
                ConfluenceNode {
                    id: "500".into(),
                    kind,
                    space_id: "98765".into(),
                    parent: Some(parent(ConfluenceNodeKind::Page, "200")),
                    status: ConfluenceContentStatus::Current,
                    version: Some(1),
                },
            );
        }
    }
    Arc::new(backend)
}

async fn staged_request(
    provider: &ConfluenceProvider,
    backend: &EvidenceBackend,
    action: &str,
) -> ProviderInvocation {
    let handle = ConfluenceDraftHandle {
        content_type: ConfluenceDraftContentType::Page,
        content_id: "400".into(),
        space: "ENG".into(),
        space_id: "98765".into(),
        origin: ConfluenceDraftOrigin::Staged,
        parent: backend.page_draft_parent.clone(),
        base_version: Some(7),
    };
    let binding = InvocationBuilder::new("confluence", action)
        .credential(token())
        .build();
    let signed = provider
        .continuations
        .seal_draft_handle(binding.context(), binding.execution(), &handle)
        .unwrap();
    let mut inputs = action_inputs(provider, action);
    inputs["draftHandle"] = json!(signed);
    if action == "page.draft.verify" {
        inputs["expectTitle"] = json!("Different title");
    }
    admitted_inputs(
        provider,
        action,
        ContainmentEvidenceLevel::CompleteLineage,
        Vec::new(),
        inputs,
    )
    .await
}

#[tokio::test]
async fn existing_draft_results_preserve_all_observed_parent_kinds() {
    for kind in PARENTS {
        for action in [
            "page.draft.stage",
            "page.draft.view",
            "page.draft.update",
            "page.draft.publish",
        ] {
            let backend = backend_with_parent(*kind);
            let provider = backend.provider();
            let request = if action == "page.draft.stage" {
                *backend.draft_read_failure.lock().unwrap() =
                    Some(ConfluenceBackendError::NotFound);
                admitted(&provider, action, ContainmentEvidenceLevel::CompleteLineage).await
            } else {
                staged_request(&provider, &backend, action).await
            };
            let outcome = provider
                .invoke_checked(request)
                .await
                .unwrap_or_else(|error| panic!("{action} {kind:?}: {error:?}"));
            let id = if action == "page.draft.stage" {
                "100"
            } else {
                "400"
            };
            assert_eq!(outcome.result["pageId"], id, "{action} {kind:?}");
            assert_eq!(
                outcome.result["parent"],
                json!(backend.page_draft_parent),
                "{action} {kind:?}"
            );
            assert_eq!(
                outcome.result["version"],
                if action == "page.draft.publish" { 8 } else { 1 }
            );
            let writes = usize::from(action != "page.draft.view");
            assert_eq!(
                backend.writes.load(Ordering::SeqCst),
                writes,
                "{action} {kind:?}"
            );
            let requests = backend.publish_requests.lock().unwrap();
            assert_eq!(requests.len(), writes);
            assert!(
                requests
                    .iter()
                    .all(|request| request.content_id == id && request.space_id == "98765")
            );
            if kind.is_some() {
                assert!(
                    backend
                        .hierarchy_reads
                        .lock()
                        .unwrap()
                        .iter()
                        .any(|(id, _)| id == "500")
                );
            }
        }
    }
}

#[tokio::test]
async fn existing_draft_conflicts_and_verification_failures_preserve_parent_kinds() {
    for kind in PARENTS {
        for action in ["page.draft.stage", "page.draft.verify"] {
            let backend = backend_with_parent(*kind);
            let provider = backend.provider();
            let request = if action == "page.draft.stage" {
                admitted(&provider, action, ContainmentEvidenceLevel::CompleteLineage).await
            } else {
                staged_request(&provider, &backend, action).await
            };
            let error = provider.invoke_checked(request).await.unwrap_err();
            assert_eq!(
                error.reason_code(),
                if action == "page.draft.stage" {
                    ReasonCode::VersionConflict
                } else {
                    ReasonCode::VerificationMismatch
                }
            );
            let result = error.result.as_deref().unwrap();
            assert_eq!(
                result["pageId"],
                if action == "page.draft.stage" {
                    "100"
                } else {
                    "400"
                }
            );
            assert_eq!(
                result["parent"],
                json!(backend.page_draft_parent),
                "{action} {kind:?}"
            );
            assert!(result.get("mutationStatus").is_none());
            assert_eq!(backend.writes.load(Ordering::SeqCst), 0);
            assert!(backend.publish_requests.lock().unwrap().is_empty());
        }
    }
}
