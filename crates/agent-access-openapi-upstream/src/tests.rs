use super::*;
use agent_access_provider::test_support::{InvocationBuilder, bearer_credential};
use axum::{
    Router,
    body::Bytes,
    extract::{OriginalUri, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
};
use std::sync::Mutex;
use tokio::task::JoinHandle;

/// The build host imported OpenAPI tests share: a short request timeout and
/// a 256 KiB response cap.
fn test_host() -> test_support::TestHost {
    test_support::TestHost::with_limits(ProviderLimits {
        max_upstream_response_bytes: 256 * 1024,
        request_timeout_ms: 500,
        ..Default::default()
    })
}
#[derive(Clone)]
struct StateData {
    document: Value,
    calls: Arc<Mutex<Vec<Call>>>,
    status: u16,
    body: Value,
    delay: Duration,
}
struct Call {
    path: String,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
}
struct Fixture {
    base: String,
    state: StateData,
    task: JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    async fn new(document: Value, status: u16, body: Value, delay: Duration) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let state = StateData {
            document,
            calls: Default::default(),
            status,
            body,
            delay,
        };
        let router = Router::new()
            .fallback(any(handle))
            .with_state(state.clone());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self { base, state, task }
    }
    fn definition(&self) -> ImportedServiceDefinition {
        definition(
            &format!("{}/api", self.base),
            &format!("{}/definition.json", self.base),
        )
    }
    fn call_count(&self) -> usize {
        self.state.calls.lock().unwrap().len()
    }
}
async fn handle(
    State(state): State<StateData>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let document = uri.path() == "/definition.json";
    state.calls.lock().unwrap().push(Call {
        path: uri.to_string(),
        method,
        headers,
        body,
    });
    if document {
        return axum::Json(state.document).into_response();
    }
    tokio::time::sleep(state.delay).await;
    if state.status == 204 {
        return StatusCode::NO_CONTENT.into_response();
    }
    let mut response = (
        StatusCode::from_u16(state.status).unwrap(),
        axum::Json(state.body),
    )
        .into_response();
    response
        .headers_mut()
        .insert("retry-after", "30".parse().unwrap());
    response
        .headers_mut()
        .insert("location", "/api/redirect-target".parse().unwrap());
    response
}
fn definition(endpoint: &str, document: &str) -> ImportedServiceDefinition {
    ImportedServiceDefinition {
        service: "example".into(),
        display_name: "Example".into(),
        adapter_kind: "openapi_http".into(),
        endpoint: endpoint.into(),
        connection_settings: BTreeMap::from([
            ("definitionUrl".into(), document.into()),
            ("securityScheme".into(), "access".into()),
        ]),
        execution_bindings: vec![
            ImportedCredentialBinding::token(
                ImportedCredentialMode::Service,
                ImportedCredentialDelivery::Bearer,
            ),
            ImportedCredentialBinding::token(
                ImportedCredentialMode::PerUser,
                ImportedCredentialDelivery::Bearer,
            ),
        ],
        discovery: ImportedDiscoveryCredential::Anonymous,
        transport_auth: false,
        invocation_limit: None,
    }
}
fn credential(token: &str) -> ExecutionCredential {
    bearer_credential(token)
}
fn invocation(inputs: Value) -> ProviderInvocation {
    InvocationBuilder::new("example", "item.update")
        .inputs(inputs)
        .identity(InvocationIdentity {
            principal: "alice".into(),
            authenticated: true,
        })
        .credential(credential("api-secret"))
        .build()
}
fn document() -> Value {
    json!({"openapi":"3.1.1","info":{"title":"Inventory","version":"1"},"components":{"securitySchemes":{"access":{"type":"http","scheme":"bearer"},"Key":{"type":"apiKey","in":"header","name":"X-Api-Key"}},"schemas":{"Item":{"type":"object","properties":{"value":{"type":"string"}},"required":["value"],"additionalProperties":false}}},"security":[{"access":[]},{"Key":[]}],"paths":{"/items/{id}":{"post":{"operationId":"update_item","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}},{"name":"q","in":"query","schema":{"type":"string"}},{"name":"tags","in":"query","explode":false,"schema":{"type":"array","items":{"type":"string"}}},{"name":"Count","in":"header","schema":{"type":"integer"}}],"requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Item"}}}},"responses":{"200":{"description":"OK","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Item"}}}},"default":{"description":"Error","content":{"application/json":{"schema":true}}}}}}}})
}
fn discovered(document: Value, definition: &ImportedServiceDefinition) -> ImportedDiscoveredTool {
    let document = Document::new(document, definition).unwrap();
    document.operation(definition, "/items/{id}", "post")
}
fn action(definition: &ImportedServiceDefinition) -> ImportedActionDefinition {
    let mut tool = discovered(document(), definition);
    assert!(
        tool.unsupported_reason.is_none(),
        "{:?}",
        tool.unsupported_reason
    );
    tool.definition.action = "item.update".into();
    tool.definition
}
fn input() -> Value {
    json!({"path":{"id":"one"},"body":{"value":"created"}})
}

#[tokio::test]
async fn public_discovery_returns_picker_without_credentials_or_executable_operations() {
    let fixture = Fixture::new(document(), 200, json!({"value":"done"}), Duration::ZERO).await;
    let mut definition = fixture.definition();
    definition.connection_settings.remove("securityScheme");
    let host = test_host();
    let result = OpenApiAdapter
        .discover(
            &definition,
            &ImportedDiscoveryAuthentication::Anonymous,
            None,
            &host.context(),
        )
        .await
        .unwrap();
    assert_eq!(result.metadata["title"], "Inventory");
    assert_eq!(
        result.metadata["securitySchemes"][1],
        json!({"name":"access","kind":"bearer"})
    );
    assert!(result.tools[0].unsupported_reason.is_some());
    let calls = fixture.state.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert!(!calls[0].headers.contains_key("authorization"));
}
#[tokio::test]
async fn private_document_token_is_separate_from_selected_execution_token() {
    let fixture = Fixture::new(document(), 200, json!({"value":"done"}), Duration::ZERO).await;
    let mut definition = fixture.definition();
    definition.discovery = ImportedDiscoveryCredential::Slot;
    definition
        .connection_settings
        .insert("definitionAuthKind".into(), "raw_header".into());
    definition
        .connection_settings
        .insert("definitionAuthHeader".into(), "X-Definition-Key".into());
    let host = test_host();
    let discovery = OpenApiAdapter
        .discover(
            &definition,
            &ImportedDiscoveryAuthentication::Static(credential("document-secret")),
            None,
            &host.context(),
        )
        .await
        .unwrap();
    let mut action = discovery.tools.into_iter().next().unwrap().definition;
    action.action = "item.update".into();
    let provider = OpenApiAdapter
        .build(&definition, &[action], None, &host.context())
        .unwrap();
    provider.invoke(invocation(input())).await.unwrap();
    let calls = fixture.state.calls.lock().unwrap();
    assert_eq!(calls[0].headers["x-definition-key"], "document-secret");
    assert!(!calls[0].headers.contains_key("authorization"));
    assert_eq!(calls[1].headers["authorization"], "Bearer api-secret");
    assert!(!calls[1].headers.contains_key("x-definition-key"));
}
#[test]
fn supported_security_alternatives_and_overrides_are_explicit() {
    let mut def = definition("https://api.example/api", "https://docs.example/spec.json");
    assert!(discovered(document(), &def).unsupported_reason.is_none());
    assert_eq!(
        discovered(document(), &def).definition.action,
        "update_item"
    );
    for requirements in [
        json!([]),
        json!([{}]),
        json!([{"access":[],"Key":[]}]),
        json!([{"access":["role"]}]),
    ] {
        let mut doc = document();
        doc["paths"]["/items/{id}"]["post"]["security"] = requirements;
        assert!(discovered(doc, &def).unsupported_reason.is_some());
    }
    def.connection_settings
        .insert("securityScheme".into(), "Key".into());
    for binding in &mut def.execution_bindings {
        binding.delivery = ImportedCredentialDelivery::RawHeader {
            name: "X-Api-Key".into(),
        };
    }
    assert!(discovered(document(), &def).unsupported_reason.is_none());
}
#[test]
fn duplicate_ids_external_refs_server_overrides_and_reserved_headers_are_unsupported() {
    let def = definition("https://api.example/api", "https://docs.example/spec.json");
    let mut doc = document();
    doc["paths"]["/other"] = doc["paths"]["/items/{id}"].clone();
    let row = discovered(doc, &def);
    assert!(row.unsupported_reason.unwrap().contains("unique"));
    assert_eq!(
        row.definition.source,
        json!({"method":"POST","path":"/items/{id}"})
    );
    for patch in [
        json!({"servers":[{"url":"https://evil.example/api"}]}),
        json!({"parameters":[{"name":"Host","in":"header","schema":{"type":"string"}}]}),
        json!({"parameters":[{"name":"X-HTTP-Method-Override","in":"header","schema":{"type":"string"}}]}),
        json!({"requestBody":{"content":{"application/json":{"schema":{"$ref":"https://evil.example/schema"}}}}}),
    ] {
        let mut doc = document();
        doc["paths"]["/items/{id}"]["post"]
            .as_object_mut()
            .unwrap()
            .extend(patch.as_object().unwrap().clone());
        assert!(discovered(doc, &def).unsupported_reason.is_some());
    }
    let mut doc = document();
    doc["servers"] = json!([{"url":"https://api.example/{version}","variables":{"version":{"default":"api","enum":["api"]}}}]);
    assert!(discovered(doc.clone(), &def).unsupported_reason.is_none());
    doc["paths"]["/items/{id}"]["post"]
        .as_object_mut()
        .unwrap()
        .remove("operationId");
    assert_eq!(
        discovered(doc.clone(), &def).definition.action,
        "post_/items/{id}"
    );
    assert_eq!(
        discovered(doc, &def).definition.source,
        json!({"method":"POST","path":"/items/{id}"})
    );
}
#[test]
fn self_contained_refs_preserve_literals_and_enforce_constraints() {
    let def = definition("https://api.example/api", "https://docs.example/spec.json");
    let mut doc = document();
    doc["components"]["schemas"]["Item"]["examples"] = json!([{"$ref":"https://literal.example/"}]);
    let row = discovered(doc, &def);
    assert!(row.unsupported_reason.is_none());
    let compiled = CompiledAction::new(&row.definition).unwrap();
    assert!(
        compiled
            .request(&Url::parse(&def.endpoint).unwrap(), &input())
            .is_ok()
    );
    assert!(
        compiled
            .request(
                &Url::parse(&def.endpoint).unwrap(),
                &json!({"path":{"id":"one"},"body":{"value":1}})
            )
            .is_err()
    );
    assert_eq!(
        row.definition.input_schema["$defs"]["Item"]["examples"][0]["$ref"],
        "https://literal.example/"
    );
}
#[tokio::test]
async fn execution_serializes_separate_locations_and_never_refetches_definition() {
    let fixture = Fixture::new(document(), 200, json!({"value":"done"}), Duration::ZERO).await;
    let def = fixture.definition();
    let host = test_host();
    let provider = OpenApiAdapter
        .build(&def, &[action(&def)], None, &host.context())
        .unwrap();
    let result=provider.invoke(invocation(json!({"path":{"id":"space ü"},"query":{"q":"a&b=/x","tags":["a,b","c&d"]},"headers":{"Count":1.0},"body":{"value":"created"}}))).await.unwrap();
    assert_eq!(result.result["mutationStatus"], "applied_unverified");
    assert_eq!(result.result["retrySafe"], false);
    assert_eq!(result.result["upstreamHttp"]["body"]["value"], "done");
    let calls = fixture.state.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].method, Method::POST);
    assert_eq!(
        calls[0].path,
        "/api/items/space%20%C3%BC?q=a%26b%3D%2Fx&tags=a%2Cb,c%26d"
    );
    assert_eq!(calls[0].headers["count"], "1");
    assert_eq!(
        serde_json::from_slice::<Value>(&calls[0].body).unwrap(),
        json!({"value":"created"})
    );
}
#[tokio::test]
async fn invalid_inputs_and_missing_personal_credentials_never_dispatch() {
    let fixture = Fixture::new(document(), 200, json!({"value":"done"}), Duration::ZERO).await;
    let def = fixture.definition();
    let host = test_host();
    let provider = OpenApiAdapter
        .build(&def, &[action(&def)], None, &host.context())
        .unwrap();
    for id in ["..", "../secret", "%2f", "a\\b", "a/b"] {
        let mut value = input();
        value["path"]["id"] = json!(id);
        assert!(provider.invoke(invocation(value)).await.is_err());
    }
    let mut call = invocation(input());
    call.credential_mode = CredentialMode::PerUser;
    call.execution = ExecutionAccess::None;
    assert!(provider.invoke(call).await.is_err());
    assert_eq!(fixture.call_count(), 0);
    let mut call = invocation(input());
    call.credential_mode = CredentialMode::PerUser;
    call.execution = ExecutionAccess::Static(credential("alice-secret"));
    provider.invoke(call).await.unwrap();
    assert_eq!(
        fixture.state.calls.lock().unwrap()[0].headers["authorization"],
        "Bearer alice-secret"
    );
}
#[tokio::test]
async fn errors_redirects_and_throttling_do_not_replay_writes() {
    for status in [302, 401, 429, 503] {
        let fixture = Fixture::new(
            document(),
            status,
            json!({"error":"failed"}),
            Duration::ZERO,
        )
        .await;
        let def = fixture.definition();
        let host = test_host();
        let provider = OpenApiAdapter
            .build(&def, &[action(&def)], None, &host.context())
            .unwrap();
        let error = provider.invoke(invocation(input())).await.err().unwrap();
        assert_eq!(error.reason_code, status_reason(status));
        if status == 429 {
            assert_eq!(error.result.as_ref().unwrap()["retryAfterSeconds"], 30);
            assert_eq!(error.result.as_ref().unwrap()["limitScope"], "upstream");
        }
        assert_eq!(error.result.as_ref().unwrap()["mutationStatus"], "unknown");
        assert_eq!(error.result.as_ref().unwrap()["retrySafe"], false);
        assert_eq!(fixture.call_count(), 1);
    }
}
#[tokio::test]
async fn malformed_success_and_timeout_preserve_unknown_write_receipts() {
    for (body, delay) in [
        (json!({"wrong":"shape"}), Duration::ZERO),
        (json!({"value":"ok"}), Duration::from_secs(2)),
    ] {
        let fixture = Fixture::new(document(), 200, body, delay).await;
        let def = fixture.definition();
        let host = test_host();
        let provider = OpenApiAdapter
            .build(&def, &[action(&def)], None, &host.context())
            .unwrap();
        let error = provider.invoke(invocation(input())).await.err().unwrap();
        assert!(matches!(
            error.reason_code,
            ReasonCode::UpstreamProtocolFailed | ReasonCode::UpstreamTimeout
        ));
        assert_eq!(error.result.as_ref().unwrap()["mutationStatus"], "unknown");
        assert_eq!(fixture.call_count(), 1);
    }
}
#[test]
fn definitions_reject_credential_reuse_and_executable_external_schemas() {
    let mut def = definition("https://api.example/api", "https://docs.example/spec.json");
    def.discovery = ImportedDiscoveryCredential::Execution;
    assert!(Settings::parse(&def).is_err());
    let def = definition("https://api.example/api", "https://docs.example/spec.json");
    assert_eq!(
        OpenApiAdapter.additional_destinations(&def).unwrap(),
        vec!["https://docs.example/spec.json"]
    );
    let mut accepted = action(&def);
    accepted.input_schema["properties"]["body"] = json!({"$ref":"https://evil.example/schema"});
    assert!(OpenApiAdapter.validate_action(&accepted).is_err());
}

#[test]
fn equivalent_server_spellings_match_only_the_same_approved_base() {
    let def = definition(
        "HTTPS://API.EXAMPLE:443/api/",
        "https://docs.example/spec.json",
    );
    let mut doc = document();
    doc["servers"] = json!([{"url":"https://api.example/api"}]);
    assert!(discovered(doc.clone(), &def).unsupported_reason.is_none());
    for server in [
        "https://api.example:444/api",
        "https://api.example/other",
        "http://api.example/api",
        "https://other.example/api",
    ] {
        doc["servers"] = json!([{"url":server}]);
        assert!(discovered(doc.clone(), &def).unsupported_reason.is_some());
    }
}

#[tokio::test]
async fn no_content_operations_omit_empty_accept_and_return_null_body() {
    let fixture = Fixture::new(document(), 204, Value::Null, Duration::ZERO).await;
    let def = fixture.definition();
    let mut doc = document();
    doc["paths"]["/items/{id}"]["post"]["responses"] = json!({"204":{"description":"Updated"}});
    let mut accepted = discovered(doc, &def).definition;
    accepted.action = "item.update".into();
    let host = test_host();
    let provider = OpenApiAdapter
        .build(&def, &[accepted], None, &host.context())
        .unwrap();
    let result = provider.invoke(invocation(input())).await.unwrap();
    assert_eq!(
        result.result["upstreamHttp"],
        json!({"status":204,"body":null})
    );
    assert_eq!(result.result["mutationStatus"], "applied_unverified");
    let calls = fixture.state.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    // Omitting the operation override preserves reqwest’s valid default.
    assert_eq!(calls[0].headers["accept"], "*/*");
}

#[tokio::test]
async fn invalid_discovery_configuration_reports_its_cause_without_dispatch() {
    let fixture = Fixture::new(document(), 200, json!({"value":"ok"}), Duration::ZERO).await;
    let mut def = fixture.definition();
    def.connection_settings.remove("definitionUrl");
    let host = test_host();
    let error = OpenApiAdapter
        .discover(
            &def,
            &ImportedDiscoveryAuthentication::Anonymous,
            None,
            &host.context(),
        )
        .await
        .err()
        .unwrap();
    assert_eq!(error.reason_code, ReasonCode::ConfigValidationFailed);
    assert!(error.message.contains("definitionUrl is required"));
    assert_eq!(fixture.call_count(), 0);
}

#[test]
fn scoped_mcp_names_use_exact_operation_ids_or_saved_unnamed_action_ids() {
    let definition = definition(
        "https://api.example.test",
        "https://api.example.test/openapi.json",
    );
    let mut action = action(&definition);
    for raw in [
        "Original.Name-1",
        "source name/with space",
        "é",
        &"x".repeat(256),
    ] {
        action.source = json!({"operationId":raw});
        OpenApiAdapter.validate_action(&action).unwrap();
        assert_eq!(OpenApiAdapter.scoped_mcp_name(&action).unwrap(), raw);
    }
    action.source = json!({"method":"POST","path":"/items/{id}"});
    OpenApiAdapter.validate_action(&action).unwrap();
    assert_eq!(
        OpenApiAdapter.scoped_mcp_name(&action).unwrap(),
        "item.update"
    );
    for source in [
        json!({}),
        json!({"operationId":null}),
        json!({"operationId":""}),
        json!({"operationId":"x".repeat(257)}),
        json!({"operationId":null,"method":"POST","path":"/items/{id}"}),
        json!({"path":"/items/{id}"}),
        json!({"method":"bad","path":"/items/{id}"}),
    ] {
        action.source = source;
        assert!(OpenApiAdapter.validate_action(&action).is_err());
        assert!(OpenApiAdapter.scoped_mcp_name(&action).is_err());
    }
}

#[test]
fn the_openapi_selection_declares_no_oauth_companion() {
    let registry = agent_access_core::BackendRegistry::empty()
        .with_imported_adapters([crate::registration()])
        .unwrap();
    assert!(registry.imported_adapter("openapi_http").is_some());
    assert!(registry.import_authentication("openapi_http").is_none());
    assert_eq!(registry.oauth_dialect_ids().count(), 0);
}
