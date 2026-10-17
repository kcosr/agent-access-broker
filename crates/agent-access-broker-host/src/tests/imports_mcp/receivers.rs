use super::*;
use agent_access_provider::{SecretOutputDescriptor, test_support::DescribedProvider};

const TOKEN: &str = "fixture-receiver-private-token";
pub(super) struct Producer;
impl DescribedProvider for Producer {
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::new("fake", "Secret producer").with_actions(vec![
            ActionDescriptor::new(
                "issue",
                "Issue a synthetic secret",
                json!({"type":"object","additionalProperties":false}),
            )
            .credential_modes(["service"])
            .secret_output(SecretOutputDescriptor::new("/result/token", 128)),
        ])
    }
}
#[async_trait::async_trait]
impl Provider for Producer {
    async fn resolve_scopes(&self, _: ScopeRequest<'_>) -> Result<ScopeResolution, ProviderError> {
        Ok(ScopeResolution::no_resources())
    }
    async fn invoke(&self, _: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        Ok(ProviderResult::new(json!({})).with_secret_output("/result/token", TOKEN.into()))
    }
}
#[derive(Clone, Default)]
pub(super) struct Gate {
    pub entered: Arc<tokio::sync::Notify>,
    pub release: Arc<tokio::sync::Notify>,
}
fn admin(fixture: &Fixture) -> String {
    fixture
        .runtime
        .managed_store()
        .unwrap()
        .issue_broker_token(
            &BrokerTokenHasher::load(fixture.runtime.config().broker_tokens.as_ref().unwrap())
                .unwrap(),
            BrokerTokenIssueRequest {
                principal_id: "admin".into(),
                name: "Receiver review".into(),
                token_class: BrokerTokenClass::Admin,
                scopes: json!({}),
                expires_at: None,
                created_by: "admin".into(),
            },
        )
        .unwrap()
        .token
}
async fn management(
    fixture: &Fixture,
    admin: &str,
    method: Method,
    suffix: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let body = body.map(|value| value.to_string());
    let response = authed_json_request(
        fixture.app.clone(),
        method,
        &format!("/v1/admin/imports/one{suffix}"),
        "receiver-admin",
        "Authorization",
        format!("Bearer {admin}"),
        body.as_deref(),
    )
    .await;
    (response.status(), response_json(response).await)
}
fn versions(value: &Value) -> Value {
    json!({"expectedVersion":value["service"]["version"],"expectedCatalogRevision":value["catalogRevision"]})
}
async fn discover_preview(fixture: &Fixture, admin: &str) -> Value {
    let (status, detail) = management(fixture, admin, Method::GET, "", None).await;
    assert_eq!(status, StatusCode::OK, "{detail}");
    let (status, response) = management(
        fixture,
        admin,
        Method::POST,
        "/discover",
        Some(versions(&detail["result"])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    response["result"].clone()
}
fn acceptance(preview: &Value, marked: bool, confirm: bool) -> Value {
    let mut body = versions(preview);
    body["manifestHash"] = preview["preview"]["manifestHash"].clone();
    body["confirmAffectedGrants"] = json!(confirm);
    body["selections"] = json!([true,false].into_iter().map(|read| {
        let action = action(read);
        json!({"source":action.source,"action":action.action,"readOnly":read,"secretInputs":if marked {json!([{"pointer":"/inputs/message"}])} else {json!([])}})
    }).collect::<Vec<_>>());
    body
}
fn tools(fixture: &Fixture, optional: bool) {
    *fixture.upstream.discovery_tools.lock().unwrap() = Some([true,false].into_iter().map(|read| {
        let mut action = action(read);
        if optional { action.input_schema.as_object_mut().unwrap().remove("required"); }
        json!({"name":action.source["toolName"],"description":action.description,"inputSchema":action.input_schema,"outputSchema":action.output_schema})
    }).collect());
}
async fn mark(fixture: &Fixture, admin: &str, marked: bool) -> Value {
    let preview = discover_preview(fixture, admin).await;
    assert_eq!(
        preview["secretInputCandidates"][0]["pointers"],
        json!(["/inputs/message"])
    );
    let (status, accepted) = management(
        fixture,
        admin,
        Method::POST,
        "/accept",
        Some(acceptance(&preview, marked, true)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{accepted}");
    accepted["result"].clone()
}
async fn invoke(
    fixture: &Fixture,
    principal: &str,
    action: &str,
    inputs: Value,
) -> (StatusCode, Value) {
    let body = json!({"inputs":inputs}).to_string();
    let response = authed_context_json_request(
        fixture.app.clone(),
        Method::POST,
        &format!("/v1/invoke/one/{action}"),
        "receiver-invoke",
        &fixture.tokens[principal],
        "internal",
        Some(&body),
    )
    .await;
    (response.status(), response_json(response).await)
}
fn call_count(fixture: &Fixture) -> usize {
    fixture
        .upstream
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, _, request)| request["method"] == "tools/call")
        .count()
}
fn malicious_result(failed: bool) -> Value {
    let encoded = base64::engine::general_purpose::STANDARD.encode(TOKEN);
    json!({"content":[{"type":"text","text":TOKEN,"annotations":{"audience":["user"]},"_meta":{"echo":TOKEN}},
        {"type":"image","data":encoded,"mimeType":"image/png"},
        {"type":"audio","data":encoded,"mimeType":"audio/wav"},
        {"type":"resource","resource":{"uri":"https://example.test/private","text":TOKEN}},
        {"type":"resource_link","uri":"https://example.test/private","name":TOKEN}],
        "structuredContent":{"ok":true,"encoded":encoded,"nested":{"echo":TOKEN}},"_meta":{"echo":TOKEN},"isError":failed})
}

#[tokio::test]
async fn receiver_acceptance_is_explicit_versioned_and_keeps_raw_source() {
    let fixture = fixture(None).await;
    let admin = admin(&fixture);
    tools(&fixture, false);
    mark(&fixture, &admin, false).await;
    let preview = discover_preview(&fixture, &admin).await;
    let prior = preview["service"]["actions"].clone();
    let mut missing = acceptance(&preview, true, true);
    missing["selections"][0]
        .as_object_mut()
        .unwrap()
        .remove("secretInputs");
    assert_eq!(
        management(&fixture, &admin, Method::POST, "/accept", Some(missing))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let (status, response) = management(
        &fixture,
        &admin,
        Method::POST,
        "/accept",
        Some(acceptance(&preview, true, false)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    for settings in [
        json!([{"pointer":"/inputs/missing"}]),
        json!([{"pointer":"/inputs/message"},{"pointer":"/inputs/message"}]),
        json!([{"pointer":"/inputs/message","extra":true}]),
    ] {
        let mut invalid = acceptance(&preview, true, true);
        invalid["selections"][0]["secretInputs"] = settings;
        assert_eq!(
            management(&fixture, &admin, Method::POST, "/accept", Some(invalid))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }
    let (status, response) = management(
        &fixture,
        &admin,
        Method::POST,
        "/accept",
        Some(acceptance(&preview, true, true)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let accepted = &response["result"];
    for (index, row) in accepted["service"]["actions"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        assert_eq!(row["secretInputs"], json!([{"pointer":"/inputs/message"}]));
        assert_eq!(row["definition"], prior[index]["definition"]);
        assert_eq!(row["definitionHash"], prior[index]["definitionHash"]);
        assert_eq!(
            row["version"].as_u64(),
            prior[index]["version"].as_u64().map(|v| v + 1)
        );
    }
    assert_eq!(
        management(
            &fixture,
            &admin,
            Method::POST,
            "/accept",
            Some(acceptance(&preview, false, true))
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let preview = discover_preview(&fixture, &admin).await;
    assert_eq!(
        management(
            &fixture,
            &admin,
            Method::POST,
            "/accept",
            Some(acceptance(&preview, false, false))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let cleared = mark(&fixture, &admin, false).await;
    assert_eq!(cleared["service"]["actions"][0]["secretInputs"], json!([]));
}

#[tokio::test]
async fn receiver_resolves_exact_owner_reference_and_suppresses_all_remote_output() {
    let fixture = fixture_with_producer(None, true).await;
    let admin = admin(&fixture);
    tools(&fixture, false);
    mark(&fixture, &admin, true).await;
    let catalog_response = authed_context_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/spec/catalog",
        "receiver-catalog",
        &fixture.tokens["alice"],
        "internal",
        None,
    )
    .await;
    assert_eq!(catalog_response.status(), StatusCode::OK);
    let catalog = response_json(catalog_response).await;
    let public = catalog["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|service| service["service"] == "one")
        .unwrap()["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|action| action["action"] == "update")
        .unwrap();
    assert_eq!(public["secretInputPointers"], json!(["/inputs/message"]));
    assert!(
        public["description"]
            .as_str()
            .unwrap()
            .contains("completion receipt")
    );
    assert!(public["inputSchema"]["properties"]["message"]["oneOf"].is_array());
    let response = authed_context_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/invoke/fake/issue",
        "receiver-produce",
        &fixture.tokens["alice"],
        "internal",
        Some(r#"{"inputs":{}}"#),
    )
    .await;
    let status = response.status();
    let produced = response_json(response).await;
    assert_eq!(status, StatusCode::OK, "{produced}");
    let reference = produced["result"]["token"].clone();
    assert!(reference["secretRef"].is_string());
    *fixture.upstream.call_result.lock().unwrap() = Some(malicious_result(false));
    for value in [json!(TOKEN), reference.clone()] {
        let (status, result) = invoke(&fixture, "alice", "update", json!({"message":value})).await;
        assert_eq!(status, StatusCode::OK, "{result}");
        assert_eq!(
            result["result"],
            json!({"receiverOutcome":"reported_success","responseSuppressed":true,"mutationStatus":"applied_unverified","retrySafe":false})
        );
        assert!(!result.to_string().contains(TOKEN));
    }
    let count = call_count(&fixture);
    let (status, denied) = invoke(&fixture, "bob", "inspect", json!({"message":reference})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    assert_eq!(call_count(&fixture), count);
    assert!(!denied.to_string().contains(TOKEN));
    let (status, result) = invoke(&fixture, "alice", "inspect", json!({"message":TOKEN})).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(
        result["result"],
        json!({"receiverOutcome":"reported_success","responseSuppressed":true})
    );
    *fixture.upstream.call_result.lock().unwrap() = Some(malicious_result(true));
    let (status, error) = invoke(&fixture, "alice", "update", json!({"message":TOKEN})).await;
    assert_eq!(status, StatusCode::FAILED_DEPENDENCY, "{error}");
    assert_eq!(error["reasonCode"], "upstream_failed");
    assert_eq!(error["result"]["receiverOutcome"], "reported_error");
    assert_eq!(error["result"]["mutationStatus"], "unknown");
    assert_eq!(error["result"]["retrySafe"], false);
    assert!(!error.to_string().contains(TOKEN));
    for (_, _, request) in fixture
        .upstream
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, _, request)| request["method"] == "tools/call")
    {
        assert_eq!(request["params"]["arguments"]["message"], TOKEN);
    }
    let audit = std::fs::read_to_string(&fixture.audit_path).unwrap();
    assert!(!audit.contains(TOKEN));
    assert!(!audit.contains("sr_"));
    assert!(!audit.contains(&base64::engine::general_purpose::STANDARD.encode(TOKEN)));
    let records = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|record| {
            record["service"] == "one"
                && ["update", "inspect"]
                    .iter()
                    .any(|action| record["action"] == *action)
        })
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 5);
    for (record, kind) in
        records
            .iter()
            .zip(["literal", "reference", "reference", "literal", "literal"])
    {
        assert_eq!(
            record["providerAudit"]["secretInputs"],
            json!([{"pointer":"/inputs/message", "kind":kind}])
        );
    }
}

#[tokio::test]
async fn receiver_optional_absence_still_suppresses_and_malformed_result_is_fixed() {
    let fixture = fixture(None).await;
    let admin = admin(&fixture);
    tools(&fixture, true);
    mark(&fixture, &admin, true).await;
    let (status, result) = invoke(&fixture, "alice", "update", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["result"]["responseSuppressed"], true);
    assert!(result["result"].get("upstreamMcp").is_none());
    for raw in [
        json!({"content":[{"type":"image","data":TOKEN,"mimeType":"image/png"}]}),
        json!({"content":[],"structuredContent":{"ok":TOKEN}}),
        json!({"content":TOKEN}),
    ] {
        *fixture.upstream.call_result.lock().unwrap() = Some(raw);
        let (status, error) = invoke(&fixture, "alice", "update", json!({})).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{error}");
        assert_eq!(error["result"]["mutationStatus"], "unknown");
        assert!(!error.to_string().contains(TOKEN));
    }
    let audit = std::fs::read_to_string(&fixture.audit_path).unwrap();
    let calls = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|record| record["service"] == "one" && record["action"] == "update")
        .collect::<Vec<_>>();
    assert_eq!(calls.len(), 4);
    for call in calls {
        assert_eq!(
            call["providerAudit"]["secretInputs"],
            json!([{"pointer":"/inputs/message", "kind":"absent"}])
        );
    }
}

#[tokio::test]
async fn receiver_retirement_during_startup_prevents_tool_dispatch() {
    let fixture = Arc::new(fixture(None).await);
    let admin = admin(&fixture);
    tools(&fixture, false);
    mark(&fixture, &admin, true).await;
    // Save the next preview before pausing invocation startup.
    let next = discover_preview(&fixture, &admin).await;
    let gate = Gate::default();
    *fixture.upstream.startup_gate.lock().unwrap() = Some(gate.clone());
    let called = fixture.clone();
    let invocation =
        tokio::spawn(
            async move { invoke(&called, "alice", "update", json!({"message":TOKEN})).await },
        );
    tokio::time::timeout(std::time::Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    let (status, body) = management(
        &fixture,
        &admin,
        Method::POST,
        "/accept",
        Some(acceptance(&next, false, true)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    gate.release.notify_one();
    let (status, error) = invocation.await.unwrap();
    assert_eq!(status, StatusCode::FORBIDDEN, "{error}");
    assert_eq!(error["reasonCode"], "service_action_denied");
    assert_eq!(error["result"]["toolDispatched"], false);
    assert_eq!(error["result"]["mutationStatus"], "not_applied");
    assert_eq!(call_count(&fixture), 0);
}

#[tokio::test]
async fn receiver_admitted_call_keeps_its_pinned_receipt_after_overlay_clear() {
    let fixture = Arc::new(fixture(None).await);
    let admin = admin(&fixture);
    tools(&fixture, false);
    mark(&fixture, &admin, true).await;
    let next = discover_preview(&fixture, &admin).await;
    *fixture.upstream.call_result.lock().unwrap() = Some(malicious_result(false));
    let gate = Gate::default();
    *fixture.upstream.call_gate.lock().unwrap() = Some(gate.clone());
    let called = fixture.clone();
    let invocation =
        tokio::spawn(
            async move { invoke(&called, "alice", "update", json!({"message":TOKEN})).await },
        );
    tokio::time::timeout(std::time::Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    let (status, body) = management(
        &fixture,
        &admin,
        Method::POST,
        "/accept",
        Some(acceptance(&next, false, true)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    gate.release.notify_one();
    let (status, result) = invocation.await.unwrap();
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["result"]["responseSuppressed"], true);
    assert!(!result.to_string().contains(TOKEN));
    assert_eq!(call_count(&fixture), 1);
}

#[tokio::test]
async fn receiver_refresh_quarantines_changed_schema_without_clearing_settings() {
    let fixture = fixture(None).await;
    let admin = admin(&fixture);
    tools(&fixture, false);
    mark(&fixture, &admin, true).await;
    {
        let mut discovery = fixture.upstream.discovery_tools.lock().unwrap();
        for tool in discovery.as_mut().unwrap() {
            tool["inputSchema"]["properties"]["message"] = json!({"type":"integer"});
        }
    }
    let preview = discover_preview(&fixture, &admin).await;
    for action in preview["service"]["actions"].as_array().unwrap() {
        assert_eq!(action["status"], "quarantined");
        assert_eq!(
            action["secretInputs"],
            json!([{"pointer":"/inputs/message"}])
        );
    }
    assert_eq!(preview["secretInputCandidates"][0]["pointers"], json!([]));
    let (status, error) = invoke(&fixture, "alice", "update", json!({"message":TOKEN})).await;
    // Quarantined actions are absent from the compiled adapter's scope map.
    assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
    assert_eq!(error["reasonCode"], "input_invalid");
    assert_eq!(call_count(&fixture), 0);
    let (status, error) = management(
        &fixture,
        &admin,
        Method::POST,
        "/accept",
        Some(acceptance(&preview, true, true)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
    let (status, accepted) = management(
        &fixture,
        &admin,
        Method::POST,
        "/accept",
        Some(acceptance(&preview, false, true)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{accepted}");
    assert_eq!(
        accepted["result"]["service"]["actions"][0]["secretInputs"],
        json!([])
    );
}
