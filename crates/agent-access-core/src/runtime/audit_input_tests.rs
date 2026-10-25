//! An action's declared audit inputs reach every invocation record from
//! descriptor resolution on, in both audit stores and the SQLite full-text
//! index, and never reach telemetry.
use super::tests::{
    AUDIT_STORE_TYPES, CapturedEvents, EventCaptureLayer, audit_config_for, base_fake_config,
    governed, test_audit_record,
};
use super::*;
use tracing_subscriber::prelude::*;

/// The fake echo service, failing every call after dispatch.
struct FailingEchoProvider;

impl agent_access_provider::test_support::DescribedProvider for FailingEchoProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        agent_access_fake::fake_descriptor()
    }
}

#[async_trait::async_trait]
impl Provider for FailingEchoProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        agent_access_fake::FakeProvider
            .echo_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn invoke(&self, _request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        Err(ProviderError::error(
            ReasonCode::UpstreamFailed,
            "upstream failed",
        ))
    }
}

async fn invoke(
    runtime: &BrokerRuntime,
    request_id: &str,
    action: &str,
    request: InvokeRequest,
) -> BrokerResponse<Value> {
    runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: format!("agent-{request_id}"),
                broker_request_id: request_id.to_string(),
                identity: IdentityContext::anonymous(),
                service: "fake".to_string(),
                action: action.to_string(),
                source: SourceContext::unknown(),
            }),
            request,
        )
        .await
}

fn echo(project: &str, message: &str) -> InvokeRequest {
    InvokeRequest::new(json!({"project": project, "message": message}))
}

fn record<'a>(records: &'a [Value], request_id: &str) -> &'a Value {
    records
        .iter()
        .find(|record| record["brokerRequestId"] == request_id)
        .unwrap_or_else(|| panic!("no audit record for {request_id}: {records:?}"))
}

/// The fake echo action declares `project` only: its message is content.
fn echo_inputs(project: &str) -> Value {
    json!([{"input": "project", "label": "Project", "value": project}])
}

#[tokio::test]
async fn declared_inputs_persist_in_both_stores_and_are_searchable() {
    for kind in AUDIT_STORE_TYPES {
        let (audit, path) = audit_config_for(kind, "audit-inputs-persist");
        let mut config = base_fake_config();
        config.audit = Some(audit);
        let runtime = BrokerRuntime::new(config).unwrap();

        let response = invoke(&runtime, "allowed", "echo", echo("TEST", "zephyr hello")).await;
        assert_eq!(response.status, 200, "{kind:?}");
        // Rejected before scope resolution: only the captured input names
        // the project.
        let response = invoke(
            &runtime,
            "unpresented",
            "echo",
            InvokeRequest {
                response_format: agent_access_provider::presentation::ResponseFormat::Markdown,
                ..echo("ZEPHYR", "hello")
            },
        )
        .await;
        assert_eq!(response.envelope.decision, Decision::Deny, "{kind:?}");

        if matches!(kind, crate::AuditStoreType::Sqlite) {
            // The captured project is indexed; the undeclared message is not.
            let params =
                crate::parse_audit_list_query(Some("q=zephyr"), crate::AuditListRoute::Admin)
                    .unwrap();
            let filters =
                crate::AuditEventFilters::from_params(params.filters, crate::AuditListRoute::Admin)
                    .unwrap();
            let page = runtime
                .audit_store()
                .unwrap()
                .list_events(crate::AuditEventsQuery {
                    visibility: crate::AuditVisibility::Global,
                    filters,
                    after: None,
                    limit: 10,
                })
                .await
                .unwrap();
            assert_eq!(page.items.len(), 1);
            let found: Value = serde_json::from_str(page.items[0].get()).unwrap();
            assert_eq!(found["brokerRequestId"], "unpresented");
            assert_eq!(found["auditInputs"], echo_inputs("ZEPHYR"));
        }

        runtime
            .shutdown_audit(Duration::from_secs(1))
            .await
            .unwrap();
        let records = crate::test_support::read_audit_records(kind, &path);
        let allowed = record(&records, "allowed");
        assert_eq!(allowed["decision"], "allow", "{kind:?}");
        assert_eq!(allowed["auditInputs"], echo_inputs("TEST"), "{kind:?}");
        assert!(!allowed.to_string().contains("zephyr"), "{allowed}");
        let unpresented = record(&records, "unpresented");
        assert_eq!(unpresented["resourceScopes"], json!({}), "{kind:?}");
        assert_eq!(
            unpresented["auditInputs"],
            echo_inputs("ZEPHYR"),
            "{kind:?}"
        );
    }
}

#[tokio::test]
async fn inputs_are_recorded_from_descriptor_resolution_on() {
    let (audit, path) = audit_config_for(crate::AuditStoreType::Jsonl, "audit-inputs-denials");
    let mut config = base_fake_config();
    config.audit = Some(audit);
    let runtime = BrokerRuntime::new(config).unwrap();
    // No grant covers the project: denied after the descriptor is resolved.
    let response = invoke(&runtime, "ungranted", "echo", echo("OTHER", "hello")).await;
    assert_eq!(response.envelope.decision, Decision::Deny);
    // An action the service does not serve has no descriptor to declare inputs.
    let response = invoke(
        &runtime,
        "unknown-action",
        "missing",
        echo("OTHER", "hello"),
    )
    .await;
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::ServiceActionDenied.into())
    );

    runtime
        .shutdown_audit(Duration::from_secs(1))
        .await
        .unwrap();
    let records = crate::test_support::read_audit_records(crate::AuditStoreType::Jsonl, &path);
    let ungranted = record(&records, "ungranted");
    assert_eq!(ungranted["decision"], "deny");
    assert_eq!(ungranted["auditInputs"], echo_inputs("OTHER"));
    let unknown = record(&records, "unknown-action");
    assert_eq!(unknown["decision"], "deny");
    assert!(unknown.get("auditInputs").is_none(), "{unknown}");
}

#[tokio::test]
async fn provider_errors_keep_declared_inputs() {
    let (audit, path) = audit_config_for(crate::AuditStoreType::Jsonl, "audit-inputs-error");
    let mut config = base_fake_config();
    config.audit = Some(audit);
    let runtime =
        BrokerRuntime::with_providers(config, vec![Arc::new(FailingEchoProvider)]).unwrap();

    let response = invoke(&runtime, "failed", "echo", echo("TEST", "hello")).await;
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::UpstreamFailed.into())
    );

    runtime
        .shutdown_audit(Duration::from_secs(1))
        .await
        .unwrap();
    let records = crate::test_support::read_audit_records(crate::AuditStoreType::Jsonl, &path);
    let failed = record(&records, "failed");
    assert_eq!(failed["decision"], "error");
    assert_eq!(failed["auditInputs"], echo_inputs("TEST"));
}

#[test]
fn telemetry_never_carries_captured_values() {
    let captured = CapturedEvents::default();
    let subscriber = tracing_subscriber::registry().with(EventCaptureLayer {
        events: captured.clone(),
    });
    let _guard = tracing::subscriber::set_default(subscriber);

    let mut record = test_audit_record();
    record.audit_inputs = vec![AuditInputValue {
        input: "query".into(),
        label: "Query".into(),
        value: json!("zephyr"),
        truncated: false,
    }];
    emit_invoke_completed(&record, 200, 1, None);
    emit_invoke_stream_started(&record, 200, 1);

    let events = captured.take();
    assert_eq!(events.len(), 2, "{events:?}");
    let text = format!("{events:?}");
    assert!(
        !text.contains("zephyr") && !text.contains("Query"),
        "{text}"
    );
}
