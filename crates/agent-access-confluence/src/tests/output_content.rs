use super::*;
use agent_access_provider::presentation::{
    OutputContentFormat, ResponseOptions, present_result, resolve_response_options,
};

const BODY_MUTATIONS: &[&str] = &[
    "page.footer_comment.add",
    "blog.footer_comment.add",
    "page.footer_comment.update",
    "page.inline_comment.update",
    "blog.footer_comment.update",
    "blog.inline_comment.update",
    "page.footer_comment.reply.add",
    "page.inline_comment.reply.add",
    "blog.footer_comment.reply.add",
    "blog.inline_comment.reply.add",
];

fn backend_for_action(action: &str) -> CommentStubConfluenceBackend {
    let mut backend = CommentStubConfluenceBackend::page_thread();
    if action.starts_with("blog.") {
        backend.blogs.insert(
            "222222".into(),
            ConfluenceBlog {
                id: "222222".into(),
                title: "Blog".into(),
                space: "ENG".into(),
                space_id: fixture_space_id("ENG"),
                space_alias: None,
                web_url: None,
                space_web_url: None,
                status: Some("current".into()),
                version: 1,
                created_at: None,
                updated_at: None,
                created_by: None,
                updated_by: None,
                bodies: BTreeMap::from([("storage".into(), "<p>Blog</p>".into())]),
            },
        );
        for comment in backend.comments.values_mut() {
            if comment.page_id.take().is_some() {
                comment.blog_id = Some("222222".into());
            }
        }
    }
    backend
}

fn mutation_inputs(action: &str) -> Value {
    let mut inputs = json!({"contentFormat":"storage", "content":"<p>Completed mutation</p>"});
    if action.ends_with("_comment.add") {
        if action.starts_with("blog.") {
            inputs["blogId"] = json!("222222");
        } else {
            inputs["pageId"] = json!("123456");
        }
    } else {
        inputs["commentId"] = json!(if action.contains(".inline_") {
            "6001"
        } else {
            "5001"
        });
    }
    if action.ends_with(".update") {
        inputs["baseVersion"] = json!(1);
    }
    inputs
}

#[tokio::test]
async fn every_successful_body_mutation_has_a_hidden_completed_recovery_receipt() {
    let descriptor = confluence_descriptor(&confluence_config());
    let declared = descriptor
        .actions
        .iter()
        .filter(|action| !action.read_only && action.presentation.is_some())
        .map(|action| action.action.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(declared, BODY_MUTATIONS.iter().copied().collect());
    for action in BODY_MUTATIONS {
        let backend = Arc::new(backend_for_action(action));
        let provider = ConfluenceProvider::with_backend(
            confluence_config(),
            ProviderLimits::default(),
            backend.clone(),
        );
        let mut outcome = provider
            .invoke_fixture(invocation(action, mutation_inputs(action)))
            .await
            .unwrap_or_else(|error| panic!("{action}: {error:?}"));
        let receipt = outcome
            .presentation_recovery_receipt
            .as_ref()
            .expect(action);
        assert_eq!(receipt.status(), MutationStatus::Applied, "{action}");
        assert!(!receipt.retry_safe(), "{action}");
        let serialized = serde_json::to_value(&outcome).unwrap();
        assert!(serialized.get("presentationRecoveryReceipt").is_none());
        assert!(serialized.get("presentation_recovery_receipt").is_none());
        assert!(outcome.result.get("mutationStatus").is_none());
        let presentation = descriptor
            .actions
            .iter()
            .find(|item| item.action == *action)
            .unwrap()
            .presentation;
        let resolved =
            resolve_response_options(presentation, None, ResponseOptions::default()).unwrap();
        present_result(&resolved, &mut outcome.result, 1024, 16384).unwrap();
        assert_eq!(
            outcome.result["comment"]["body"],
            json!({"format":"markdown","value":"Completed mutation"})
        );
        assert_eq!(
            backend.create_requests.lock().unwrap().len()
                + backend.update_requests.lock().unwrap().len(),
            1,
            "{action}"
        );
    }
}

#[tokio::test]
async fn body_reads_do_not_claim_completed_mutations() {
    for (action, inputs) in [
        ("page.view", json!({"pageId":"123456"})),
        ("page.footer_comment.view", json!({"commentId":"5001"})),
        ("page.inline_comment.list", json!({"pageId":"123456"})),
    ] {
        let backend = Arc::new(backend_for_action(action));
        let provider = ConfluenceProvider::with_backend(
            confluence_config(),
            ProviderLimits::default(),
            backend,
        );
        let outcome = provider
            .invoke_fixture(invocation(action, inputs))
            .await
            .unwrap();
        assert!(outcome.presentation_recovery_receipt.is_none(), "{action}");
    }
}

#[tokio::test]
async fn disabled_page_and_comment_sources_omit_body_before_finalization() {
    let mut config = confluence_config();
    config.content.page_formats.clear();
    config.content.comment_formats.clear();
    let backend = Arc::new(backend_for_action("page.view"));
    let provider =
        ConfluenceProvider::with_backend(config.clone(), ProviderLimits::default(), backend);
    for (action, inputs, pointer) in [
        ("page.view", json!({"pageId":"123456"}), "/body"),
        (
            "page.footer_comment.view",
            json!({"commentId":"5001"}),
            "/comment/body",
        ),
        (
            "page.footer_comment.list",
            json!({"pageId":"123456"}),
            "/comments/0/body",
        ),
        (
            "page.footer_comment.reply.list",
            json!({"commentId":"5001"}),
            "/comments/0/body",
        ),
    ] {
        assert!(crate::present::presentation(action, &config.content).is_none());
        let outcome = provider
            .invoke_fixture(invocation(action, inputs))
            .await
            .unwrap();
        assert!(
            outcome.result.pointer(pointer).is_none(),
            "{action}: {}",
            outcome.result
        );
        if let Some(comments) = outcome.result.get("comments").and_then(Value::as_array) {
            assert!(!comments.is_empty(), "exercise actual comments");
            assert!(comments.iter().all(|comment| comment.get("body").is_none()));
        }
    }
    let error = provider
        .invoke_fixture(invocation(
            "page.footer_comment.view",
            json!({"commentId":"5001","bodyFormat":"storage"}),
        ))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::BodyFormatUnsupported);
}

#[tokio::test]
async fn optional_comment_client_metadata_does_not_weaken_required_source_validation() {
    let mut backend = backend_for_action("page.footer_comment.view");
    backend.comments.get_mut("5001").unwrap().bodies.clear();
    let config = confluence_config();
    assert!(
        crate::present::presentation("page.footer_comment.view", &config.content)
            .unwrap()
            .body_fields()[0]
            .optional
    );
    let provider =
        ConfluenceProvider::with_backend(config, ProviderLimits::default(), Arc::new(backend));
    let error = provider
        .invoke_fixture(invocation(
            "page.footer_comment.view",
            json!({"commentId":"5001"}),
        ))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
}

#[test]
fn service_preferences_are_optional_concrete_values_and_published_without_config_downcasts() {
    assert!(
        ConfluenceContentConfig::default()
            .preferred_output_format
            .is_none()
    );
    for format in [
        OutputContentFormat::Markdown,
        OutputContentFormat::Text,
        OutputContentFormat::Adf,
        OutputContentFormat::Storage,
    ] {
        let mut config = confluence_config();
        config.content =
            serde_json::from_value(json!({"preferred_output_format":format.as_str()})).unwrap();
        assert_eq!(config.content.preferred_output_format, Some(format));
        assert_eq!(
            confluence_descriptor(&config).preferred_output_content_format,
            Some(format)
        );
    }
    for invalid in [json!("native"), json!("json"), json!(false), json!(7)] {
        assert!(
            serde_json::from_value::<ConfluenceContentConfig>(
                json!({"preferred_output_format":invalid})
            )
            .is_err()
        );
    }
}
