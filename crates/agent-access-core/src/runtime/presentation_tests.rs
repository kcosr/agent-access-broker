use super::tests::{base_fake_config, governed};
use super::*;
use agent_access_provider::presentation::{
    ActionPresentation, EmbeddedBody, EmbeddedBodyCodec, RenderBudget, RenderError,
    SelectedContent, resolve_response_options,
};
use agent_access_provider::{MutationReceipt, MutationStatus};
use std::sync::atomic::{AtomicUsize, Ordering};

const FORMATS: &[OutputContentFormat] = &[
    OutputContentFormat::Markdown,
    OutputContentFormat::Text,
    OutputContentFormat::Adf,
];
struct TestBody;
impl EmbeddedBodyCodec for TestBody {
    fn supported_formats(&self) -> &'static [OutputContentFormat] {
        FORMATS
    }
    fn select(
        &self,
        source: &Value,
        format: OutputContentFormat,
        limit: u64,
        budget: &mut RenderBudget,
    ) -> Result<Option<SelectedContent>, RenderError> {
        let value = source.as_str().ok_or(RenderError)?;
        if value.len() as u64 > limit {
            return Err(RenderError);
        }
        budget.charge_node().map_err(|_| RenderError)?;
        let selected = match format {
            OutputContentFormat::Markdown => SelectedContent::markdown(value),
            OutputContentFormat::Text => SelectedContent::text(value),
            OutputContentFormat::Adf => SelectedContent::adf(
                json!({"type":"doc","version":1,"content":[]})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
            _ => return Err(RenderError),
        };
        Ok(Some(selected))
    }
}
struct ReplacedBody;
impl EmbeddedBodyCodec for ReplacedBody {
    fn supported_formats(&self) -> &'static [OutputContentFormat] {
        FORMATS
    }
    fn select(
        &self,
        _: &Value,
        _: OutputContentFormat,
        _: u64,
        _: &mut RenderBudget,
    ) -> Result<Option<SelectedContent>, RenderError> {
        Err(RenderError)
    }
}
const PRESENTATION: ActionPresentation = ActionPresentation::new(
    &[EmbeddedBody::new(&[], "body", &TestBody)],
    FORMATS,
    OutputContentFormat::Adf,
);

struct ContentProvider {
    preference: Option<OutputContentFormat>,
    scopes: AtomicUsize,
    calls: AtomicUsize,
}
impl ContentProvider {
    fn new(preference: Option<OutputContentFormat>) -> Self {
        Self {
            preference,
            scopes: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
        }
    }
}
impl agent_access_provider::test_support::DescribedProvider for ContentProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        let mut descriptor = agent_access_fake::fake_descriptor();
        descriptor.actions[0].presentation = Some(PRESENTATION);
        descriptor.actions[0].result_schemas =
            Some(agent_access_provider::ActionResultSchemas::new(json!({
                "type": "object",
                "properties": {"body": {"type": "string"}, "id": {"type": "string"}},
                "required": ["body", "id"]
            })));
        descriptor.preferred_output_content_format = self.preference;
        descriptor
    }
}
#[async_trait::async_trait]
impl Provider for ContentProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.scopes.fetch_add(1, Ordering::SeqCst);
        agent_access_fake::FakeProvider
            .echo_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }
    async fn invoke(&self, _request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ProviderResult::new(json!({"body":"content", "id":"known"})))
    }
}
fn context() -> GovernedOperationContext {
    governed(OperationContext {
        agent_request_id: "agent-content".into(),
        broker_request_id: "broker-content".into(),
        identity: IdentityContext::anonymous(),
        service: "fake".into(),
        action: "echo".into(),
        source: SourceContext::unknown(),
    })
}
fn request(
    exact: Option<OutputContentFormat>,
    preferred: Option<OutputContentFormat>,
) -> InvokeRequest {
    InvokeRequest {
        output_content_format: exact,
        preferred_output_content_format: preferred,
        ..InvokeRequest::new(json!({"project":"TEST","message":"hello"}))
    }
}

#[tokio::test]
async fn content_resolution_is_authoritative_before_scope_lookup() {
    for (service, exact, preference, expected) in [
        (None, None, None, OutputContentFormat::Markdown),
        (
            Some(OutputContentFormat::Text),
            None,
            None,
            OutputContentFormat::Text,
        ),
        (
            Some(OutputContentFormat::Text),
            None,
            Some(OutputContentFormat::Storage),
            OutputContentFormat::Adf,
        ),
        (
            Some(OutputContentFormat::Adf),
            None,
            Some(OutputContentFormat::Text),
            OutputContentFormat::Text,
        ),
        (
            Some(OutputContentFormat::Adf),
            Some(OutputContentFormat::Markdown),
            Some(OutputContentFormat::Text),
            OutputContentFormat::Markdown,
        ),
    ] {
        let provider = Arc::new(ContentProvider::new(service));
        let runtime =
            BrokerRuntime::with_providers(base_fake_config(), vec![Arc::clone(&provider)]).unwrap();
        let response = runtime.invoke(context(), request(exact, preference)).await;
        assert_eq!(response.status, 200, "{:?}", response.envelope);
        assert_eq!(
            response.envelope.result.unwrap()["body"]["format"],
            expected.as_str()
        );
        assert_eq!(provider.scopes.load(Ordering::SeqCst), 1);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        let rejected = runtime
            .invoke(context(), request(Some(OutputContentFormat::Storage), None))
            .await;
        assert_eq!(
            rejected.envelope.reason_code,
            Some(ReasonCode::ResponseFormatUnsupported.into())
        );
        assert_eq!(provider.scopes.load(Ordering::SeqCst), 1);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn prepared_content_pins_format_descriptor_and_body_limit() {
    let provider = Arc::new(ContentProvider::new(Some(OutputContentFormat::Text)));
    let mut runtime =
        BrokerRuntime::with_providers(base_fake_config(), vec![Arc::clone(&provider)]).unwrap();
    let prepared = runtime
        .begin_invoke(context(), request(None, None))
        .await
        .unwrap_or_else(|_| panic!("prepare failed"));
    let services = Arc::make_mut(&mut runtime.services);
    let service = Arc::make_mut(services.get_mut("fake").unwrap());
    service.preferred_output_content_format = Some(OutputContentFormat::Adf);
    service.presentation_body_limit = Some(1);
    // Keep the declared final shape but replace the codec with one that would
    // fail: execution must retain the admitted codec and its body budget.
    const REPLACED_BODIES: &[EmbeddedBody] = &[EmbeddedBody::new(&[], "body", &ReplacedBody)];
    service.actions[0].presentation = Some(ActionPresentation::new(
        REPLACED_BODIES,
        FORMATS,
        OutputContentFormat::Adf,
    ));
    let response = runtime.finish_prepared_invoke(prepared, vec![]).await;
    assert_eq!(response.status, 200);
    assert_eq!(
        response.envelope.result.unwrap()["body"],
        json!({"format":"text","value":"content"})
    );
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn rendering_and_size_failures_preserve_completed_mutations_without_exposing_content() {
    let resolved =
        resolve_response_options(Some(PRESENTATION), None, ResponseOptions::default()).unwrap();
    for (body, body_limit, result_limit) in [
        (json!(17), 1024, 1024),
        (json!("too large"), 1, 1024),
        (json!("x".repeat(200)), 1024, 64),
    ] {
        let result = ProviderResult::new(json!({"body":body, "secret":"never disclose"}))
            .with_audit(json!({"operation":"test"}))
            .with_upstream(Some(201), Some(42))
            .with_object_ids(json!({"id":"private-audit"}))
            .with_presentation_recovery_receipt(MutationReceipt::applied());
        let failure =
            present_provider_outcome(&resolved, body_limit, result_limit, Ok(result)).unwrap_err();
        assert_eq!(failure.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert_eq!(
            failure.result.as_deref(),
            Some(&json!({"mutationStatus":"applied","retrySafe":false}))
        );
        assert_eq!(
            failure.message,
            "The mutation completed, but its response could not be produced. Do not repeat the operation."
        );
        assert!(!failure.message.contains("never disclose"));
        assert_eq!(failure.upstream_status, Some(201));
        assert_eq!(failure.upstream_duration_ms, Some(42));
        assert_eq!(failure.audit.as_deref(), Some(&json!({"operation":"test"})));
        assert_eq!(
            failure.object_ids.as_deref(),
            Some(&json!({"id":"private-audit"}))
        );
    }
    let successful = ProviderResult::new(json!({"body":"ok"}))
        .with_presentation_recovery_receipt(MutationReceipt::applied());
    let success = present_provider_outcome(&resolved, 1024, 1024, Ok(successful)).unwrap();
    assert_eq!(
        success.result,
        json!({"body":{"format":"markdown","value":"ok"}})
    );
    assert!(success.presentation_recovery_receipt.is_none());
}

#[test]
fn native_completed_mutation_bodies_keep_receipts_on_selection_and_final_size_failure() {
    let jira = agent_access_jira::jira_descriptor(
        &serde_json::from_value(json!({"tenant_host":"tenant.atlassian.net"})).unwrap(),
    );
    let gitlab = agent_access_gitlab::gitlab_descriptor(
        &serde_json::from_value(json!({
            "api_base_url":"https://gitlab.example.test/api/v4",
            "web_base_url":"https://gitlab.example.test"
        }))
        .unwrap(),
    );
    let confluence = agent_access_confluence::confluence_descriptor(
        &serde_json::from_value(json!({"tenant_host":"tenant.atlassian.net"})).unwrap(),
    );
    let adf = json!({"type":"doc","version":1,"content":[{
        "type":"paragraph","content":[{"type":"text","text":"private-content"}]
    }]});
    for (service, action, source, invalid) in [
        (
            jira,
            "issue.create",
            json!({"issue":{"id":"123","description":adf}}),
            json!({"issue":{"id":"123","description":17}}),
        ),
        (
            gitlab,
            "issue.create",
            json!({"issue":{"id":123,"description":"private-content"}}),
            json!({"issue":{"id":123,"description":17}}),
        ),
        (
            confluence,
            "page.footer_comment.add",
            json!({"comment":{"id":"123","body":{"storage":{
                "representation":"storage","value":"<p>private-content</p>"
            }}}}),
            json!({"comment":{"id":"123","body":17}}),
        ),
    ] {
        let descriptor = service.action(action).unwrap();
        assert!(!descriptor.read_only);
        let resolution =
            resolve_response_options(descriptor.presentation, None, ResponseOptions::default())
                .unwrap();
        let success = present_provider_outcome(
            &resolution,
            4096,
            4096,
            Ok(ProviderResult::new(source.clone())
                .with_presentation_recovery_receipt(MutationReceipt::applied())),
        )
        .unwrap();
        assert!(success.presentation_recovery_receipt.is_none());
        assert!(
            serde_json::to_string(&success.result)
                .unwrap()
                .contains("markdown")
        );
        for (body, result_limit) in [(invalid, 4096), (source, 1)] {
            let outcome = ProviderResult::new(body)
                .with_upstream(Some(201), Some(7))
                .with_audit(json!({"service":service.service,"action":action}))
                .with_object_ids(json!({"id":"123"}))
                .with_presentation_recovery_receipt(MutationReceipt::applied());
            let error =
                present_provider_outcome(&resolution, 4096, result_limit, Ok(outcome)).unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
            assert_eq!(
                error.message,
                "The mutation completed, but its response could not be produced. Do not repeat the operation."
            );
            assert_eq!(
                error.result.as_deref(),
                Some(&json!({"mutationStatus":"applied","retrySafe":false}))
            );
            assert_eq!(error.upstream_status, Some(201));
            assert_eq!(error.upstream_duration_ms, Some(7));
            assert_eq!(
                error.audit.as_deref(),
                Some(&json!({"service":service.service,"action":action}))
            );
            assert_eq!(error.object_ids.as_deref(), Some(&json!({"id":"123"})));
            assert!(
                !serde_json::to_string(&error.result)
                    .unwrap()
                    .contains("private-content")
            );
        }
    }
}

#[test]
fn reads_and_existing_mutation_errors_keep_their_own_outcome_semantics() {
    let resolved =
        resolve_response_options(Some(PRESENTATION), None, ResponseOptions::default()).unwrap();
    let read = ProviderResult::new(json!({"body":false}));
    let failure = present_provider_outcome(&resolved, 1024, 1024, Ok(read)).unwrap_err();
    assert!(failure.result.is_none());
    assert!(!failure.message.contains("mutation completed"));
    for receipt in [
        MutationReceipt::not_applied(),
        MutationReceipt::unknown(),
        MutationReceipt::applied_unverified("readback", json!({"id":"known"})),
    ] {
        assert_ne!(receipt.status(), MutationStatus::Applied);
        for error in [
            ProviderError::error(ReasonCode::UpstreamFailed, "original"),
            ProviderError::allow(ReasonCode::VerificationMismatch, "original"),
        ] {
            let error = error.with_mutation_receipt(receipt.clone());
            let expected = error.clone();
            let failure = present_provider_outcome(&resolved, 1, 1, Err(error)).unwrap_err();
            assert_eq!(failure, expected);
        }
    }
}
