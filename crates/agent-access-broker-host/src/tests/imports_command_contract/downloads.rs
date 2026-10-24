//! Download admission, durable review and ownership through the real command
//! supervisor and host router. No command-adapter hook is replaced in these tests.
use super::*;

const FILE: &[u8] = &[0, 1, 2, 3];
const FILE_RESPONSE: &str = r#"{"ok":true,"result":{"warnings":["Synthetic partial export."]},"download":{"content":"AAECAw==","filename":"report.bin","contentType":"application/octet-stream"}}"#;

struct OversizedNativeDownload {
    inner: TestDownloadProvider,
    polls: Arc<AtomicUsize>,
}

impl agent_access_provider::test_support::DescribedProvider for OversizedNativeDownload {
    fn descriptor(&self) -> ServiceDescriptor {
        let mut descriptor =
            agent_access_provider::test_support::DescribedProvider::descriptor(&self.inner);
        descriptor.actions[0]
            .sensitive_output_pointers
            .push("/result/privateMetadata".into());
        descriptor
    }
}

#[async_trait::async_trait]
impl Provider for OversizedNativeDownload {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.inner.resolve_scopes(request).await
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        let mut response = self.inner.invoke(request).await?;
        response.result["privateMetadata"] = json!("native-metadata-sentinel-7541".repeat(1000));
        response.result["mutationStatus"] = json!("applied_unverified");
        response.result["retrySafe"] = json!(false);
        response.result["safeLocators"] = json!({"report":"REPORT-42"});
        let polls = Arc::clone(&self.polls);
        response.stream = Some(ProviderResultStream::from_stream(
            "text/plain",
            stream::once(async move {
                polls.fetch_add(1, Ordering::SeqCst);
                Ok(Bytes::from_static(b"native-payload-sentinel-2317"))
            }),
        ));
        Ok(response)
    }
}

#[tokio::test]
async fn native_metadata_header_refusal_records_started_then_canceled_without_consuming_bytes() {
    let directory = tempfile::tempdir().unwrap();
    create_private_dir(directory.path());
    let audit = directory.path().join("audit.jsonl");
    let invocations = Arc::new(AtomicUsize::new(0));
    let polls = Arc::new(AtomicUsize::new(0));
    let provider = Arc::new(OversizedNativeDownload {
        inner: TestDownloadProvider {
            invocations: Arc::clone(&invocations),
            with_stream: false,
            live_stream: false,
        },
        polls: Arc::clone(&polls),
    });
    let broker =
        TestBroker::start_with_providers(&download_config(audit.to_str().unwrap()), vec![provider])
            .await;
    let app = broker.app();
    let capture = install_trace_capture().start();
    let response = capture
        .run(
            app.clone().oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/invoke/jira/attachment.download")
                    .extension(ConnectInfo(
                        "127.0.0.1:40009".parse::<SocketAddr>().unwrap(),
                    ))
                    .header(REQUEST_ID_HEADER, "native-header-refused")
                    .header(ACCEPT, RAW_RESULT_MIME)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"inputs":{"project":"TEST"}}"#))
                    .unwrap(),
            ),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    assert!(!response.headers().contains_key(RESULT_METADATA_HEADER));
    let response = response_json(response).await;
    assert_eq!(response["reasonCode"], "operation_failed");
    assert_eq!(response["result"]["mutationStatus"], "applied_unverified");
    assert_eq!(
        response["result"]["safeLocators"],
        json!({"report":"REPORT-42"})
    );
    assert!(response["result"].get("privateMetadata").is_none());
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        polls.load(Ordering::SeqCst),
        0,
        "header refusal must not consume or complete the stream"
    );
    let records = || {
        read_audit_records(&audit)
            .into_iter()
            .filter(|record| record["agentRequestId"] == "native-header-refused")
            .collect::<Vec<_>>()
    };
    wait_until("header refusal transfer audit", || records().len() == 2).await;
    let records = records();
    assert_eq!(records[0]["providerAudit"]["streamPhase"], "started");
    assert_eq!(records[0]["decision"], "allow");
    assert_eq!(records[1]["providerAudit"]["streamPhase"], "canceled");
    assert_eq!(records[1]["decision"], "error");
    assert_eq!(records[0]["brokerRequestId"], response["brokerRequestId"]);
    assert_eq!(records[1]["brokerRequestId"], response["brokerRequestId"]);
    let events = capture.take_events();
    let warnings = events
        .iter()
        .filter(|event| event["event"] == "raw_download_metadata_refused")
        .collect::<Vec<_>>();
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0]["agentRequestId"], "native-header-refused");
    assert_eq!(warnings[0]["brokerRequestId"], response["brokerRequestId"]);
    assert_eq!(warnings[0]["service"], "jira");
    assert_eq!(warnings[0]["action"], "attachment.download");
    assert_eq!(warnings[0]["category"], "serialization_limit");
    assert_eq!(warnings[0]["headerCap"], 16_384);
    assert!(warnings[0]["encodedLengthLowerBound"].as_u64().unwrap() > 16_384);
    assert!(
        !events
            .iter()
            .any(|event| event["event"] == "invoke_stream_completed"
                && event["agentRequestId"] == "native-header-refused")
    );
    for exposed in [
        response.to_string(),
        serde_json::to_string(&records).unwrap(),
        serde_json::to_string(&events).unwrap(),
    ] {
        assert!(!exposed.contains("native-metadata-sentinel-7541"));
        assert!(!exposed.contains("native-payload-sentinel-2317"));
    }
    drop(app);
    assert!(broker.stop().await.is_clean());
}

fn manifest() -> Value {
    let mut manifest = clock_manifest();
    manifest["actions"][0]["download"] = json!(true);
    manifest
}

fn contract() -> Contract {
    let mut contract = Contract::new(&manifest());
    contract.entry("tickets").max_download_bytes = Some(1024);
    contract.respond("invoke", Some(FILE_RESPONSE));
    contract
}

async fn refresh(app: &Router, token: &str, service: &str) -> Value {
    let current = current(app, token, service).await;
    admin(
        app,
        token,
        Method::POST,
        &format!("/v1/admin/imports/{service}/discover"),
        versions(&current),
    )
    .await["result"]
        .clone()
}

fn acceptance(discovered: &Value) -> Value {
    let mut body = versions(discovered);
    body["manifestHash"] = discovered["preview"]["manifestHash"].clone();
    body["selections"] =
        json!([{"source":{"name":"time.now"}, "action":"time.now", "readOnly":true}]);
    body
}

fn agent(contract: &Contract, broker: &TestBroker, service: &str) -> String {
    broker
        .runtime()
        .create_managed_policy_grant(grant(
            &format!("{service}-download"),
            "user:bob",
            service,
            "time.now",
            "service",
            0,
            ResourceSelection::default(),
        ))
        .unwrap();
    contract.fixture.issue(
        "bob",
        BrokerTokenClass::AgentInvoke,
        json!({"allowedServices":[service], "allowedExecutionContexts":["default"]}),
    )
}

async fn raw(app: &Router, token: &str, service: &str, id: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/invoke/{service}/time.now"))
                .extension(ConnectInfo(
                    "127.0.0.1:43100".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, id)
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .header(CONTENT_TYPE, "application/json")
                .header(ACCEPT, "application/octet-stream")
                .body(Body::from(r#"{"inputs":{}}"#))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn json_download_failure(
    response: axum::response::Response,
    status: StatusCode,
    reason: &str,
) -> Value {
    assert_eq!(response.status(), status);
    assert!(
        response.headers()[CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("application/json")
    );
    assert!(!response.headers().contains_key(RESULT_METADATA_HEADER));
    let body = response_json(response).await;
    assert_eq!(body["reasonCode"], reason, "{body}");
    assert!(body["result"].get("filename").is_none());
    assert!(body["result"].get("download").is_none());
    assert!(
        body["result"].get("mutationStatus").is_none(),
        "a read has no mutation receipt"
    );
    body
}

async fn successful_file(app: &Router, token: &str, id: &str) {
    let response = raw(app, token, "files", id).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap()
            .as_ref(),
        FILE
    );
}

#[tokio::test]
async fn download_command_failures_keep_json_status_retry_and_process_facts() {
    let contract = contract();
    let broker = import_broker(&contract.fixture.config).await;
    let app = broker.app();
    import(&app, &contract.admin, "files", "tickets", &[]).await;
    let token = agent(&contract, &broker, "files");
    for (code, status, reason, retry) in [
        (
            "resource_forbidden",
            StatusCode::FORBIDDEN,
            "service_action_denied",
            None,
        ),
        (
            "upstream_rate_limited",
            StatusCode::TOO_MANY_REQUESTS,
            "upstream_rate_limited",
            Some(30),
        ),
    ] {
        let mut error =
            json!({"ok":false, "error":{"code":code, "message":"Synthetic command refusal."}});
        if let Some(seconds) = retry {
            error["error"]["retryAfterSeconds"] = json!(seconds);
        }
        contract.respond("invoke", Some(&error.to_string()));
        let before = contract.started("invoke").len();
        let response = raw(&app, &token, "files", code).await;
        assert_eq!(
            response
                .headers()
                .get(RETRY_AFTER)
                .map(|value| value.to_str().unwrap()),
            retry.map(|_| "30")
        );
        let body = json_download_failure(response, status, reason).await;
        assert_eq!(body["reason"], "Synthetic command refusal.");
        if retry.is_some() {
            assert_eq!(body["result"]["retryAfterSeconds"], 30);
            assert_eq!(body["result"]["limitScope"], "upstream");
        }
        assert_eq!(
            contract.started("invoke").len(),
            before + 1,
            "one attempted command, no replay"
        );
        let records = contract.audited(code);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["providerAudit"]["command"]["spawned"], true);
        assert_eq!(records[0]["providerAudit"]["command"]["exitCode"], 0);
        assert_eq!(
            records[0]["providerAudit"]["command"]["contractViolation"],
            false
        );
        assert!(records[0]["providerAudit"].get("streamPhase").is_none());
    }
    contract.respond("invoke", Some(FILE_RESPONSE));
    std::fs::write(contract.fixture.path("responses/invoke.exit"), "7").unwrap();
    let before = contract.started("invoke").len();
    json_download_failure(
        raw(&app, &token, "files", "download-exit-seven").await,
        StatusCode::INTERNAL_SERVER_ERROR,
        "operation_failed",
    )
    .await;
    assert_eq!(
        contract.started("invoke").len(),
        before + 1,
        "a nonzero exit must spawn exactly once"
    );
    let records = contract.audited("download-exit-seven");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["providerAudit"]["command"]["spawned"], true);
    assert_eq!(records[0]["providerAudit"]["command"]["exitCode"], 7);
    assert_eq!(
        records[0]["providerAudit"]["command"]["contractViolation"],
        false
    );
    assert!(records[0]["providerAudit"].get("streamPhase").is_none());
    drop(app);
    assert!(broker.stop().await.is_clean());
}

#[tokio::test]
async fn unavailable_download_credentials_are_refused_without_spawning() {
    let mut declaration = manifest();
    declaration["credential"] = json!({"kind":"username_token", "modes":["per_user"]});
    let mut contract = Contract::new(&declaration);
    contract.entry("tickets").max_download_bytes = Some(1024);
    contract.respond("invoke", Some(FILE_RESPONSE));
    let config = contract.fixture.config.clone();
    let broker = import_broker(&config).await;
    let app = broker.app();
    import(&app, &contract.admin, "tickets", "tickets", &["per_user"]).await;
    let runtime = broker.runtime();
    let (token, _) = avery(&runtime, &config, &["tickets"]);
    runtime
        .create_managed_policy_grant(grant(
            "personal-download",
            "user:avery",
            "tickets",
            "time.now",
            "per_user",
            0,
            ResourceSelection::default(),
        ))
        .unwrap();
    let response = raw(&app, &token, "tickets", "download-credential-control").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap()
            .as_ref(),
        FILE
    );
    let before = contract.started("invoke").len();
    runtime
        .managed_store()
        .unwrap()
        .delete_user_credential(
            "avery",
            "tickets",
            "default",
            agent_access_core::CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    json_download_failure(
        raw(&app, &token, "tickets", "download-credential-removed").await,
        StatusCode::FORBIDDEN,
        "credential_not_provisioned",
    )
    .await;
    assert_eq!(contract.started("invoke").len(), before);
    let records = contract.audited("download-credential-removed");
    assert_eq!(records.len(), 1);
    assert_ne!(records[0]["providerAudit"]["command"]["spawned"], true);
    drop(app);
    assert!(broker.stop().await.is_clean());
}

#[tokio::test]
async fn broker_download_rate_exhaustion_is_refused_without_spawning() {
    let mut contract = contract();
    contract.fixture.config.limits.invocations.default =
        Some(agent_access_core::InvocationLimitConfig {
            max_wait: None,
            requests: 1,
            window: "1d".into(),
        });
    let broker = import_broker(&contract.fixture.config).await;
    let app = broker.app();
    import(&app, &contract.admin, "files", "tickets", &[]).await;
    let token = agent(&contract, &broker, "files");
    successful_file(&app, &token, "download-rate-control").await;
    let before = contract.started("invoke").len();
    let response = raw(&app, &token, "files", "download-rate-exhausted").await;
    assert!(
        response.headers()[RETRY_AFTER]
            .to_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            > 0
    );
    let body = json_download_failure(response, StatusCode::TOO_MANY_REQUESTS, "rate_limited").await;
    assert_eq!(body["service"], "broker");
    assert_eq!(body["action"], "request.admit");
    assert_eq!(contract.started("invoke").len(), before);
    let records = contract.audited("download-rate-exhausted");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["reasonCode"], "rate_limited");
    assert_ne!(records[0]["providerAudit"]["command"]["spawned"], true);
    drop(app);
    assert!(broker.stop().await.is_clean());
}

#[tokio::test]
async fn unavailable_download_audit_is_refused_without_spawning() {
    let contract = contract();
    let broker = import_broker(&contract.fixture.config).await;
    let app = broker.app();
    import(&app, &contract.admin, "files", "tickets", &[]).await;
    let token = agent(&contract, &broker, "files");
    successful_file(&app, &token, "download-audit-control").await;
    wait_until("successful download terminal audit", || {
        contract.audited("download-audit-control").len() == 2
    })
    .await;
    let audit = PathBuf::from(&contract.fixture.config.audit.as_ref().unwrap().path);
    let saved = contract.fixture.path("audit-before-refusal.jsonl");
    std::fs::rename(&audit, &saved).unwrap();
    create_private_dir(&audit);
    let before = contract.started("invoke").len();
    let response = raw(&app, &token, "files", "download-audit-unavailable").await;
    // Restore the sink before assertions so teardown can flush normally even
    // if a response assertion fails.
    std::fs::remove_dir(&audit).unwrap();
    std::fs::rename(&saved, &audit).unwrap();
    json_download_failure(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        "audit_unavailable",
    )
    .await;
    assert_eq!(contract.started("invoke").len(), before);
    successful_file(&app, &token, "download-audit-restored").await;
    assert_eq!(contract.started("invoke").len(), before + 1);
    drop(app);
    assert!(broker.stop().await.is_clean());
}

#[tokio::test]
async fn malformed_download_default_logs_omit_payload_and_stderr() {
    assert_malformed_download_logs(false).await;
}

#[tokio::test]
async fn malformed_download_stderr_logging_requires_explicit_opt_in() {
    assert_malformed_download_logs(true).await;
}

async fn assert_malformed_download_logs(log_stderr: bool) {
    const PAYLOAD: &str = "private-download-payload-sentinel-8042";
    const STDERR: &str = "operator-stderr-sentinel-6159";
    let encoded = BASE64.encode(PAYLOAD);
    let mut contract = contract();
    contract.entry("tickets").log_stderr = log_stderr;
    let script = CONTRACT_COMMAND.replace("umask 077\n", "umask 077\nif [ -e \"$RESPONSES/$1.stderr\" ]; then cat \"$RESPONSES/$1.stderr\" >&2; fi\n");
    std::fs::write(
        &contract.fixture.config.command_imports["tickets"].path,
        script,
    )
    .unwrap();
    std::fs::write(
        contract.fixture.path("responses/invoke.stderr"),
        format!("{STDERR}\nnext\tline"),
    )
    .unwrap();
    contract.respond("invoke", Some(&json!({"ok":true, "result":{"warning":PAYLOAD},
            "download":{"content":format!("{encoded}!"), "filename":"report.bin", "contentType":"application/octet-stream"}}).to_string()));
    let broker = import_broker(&contract.fixture.config).await;
    let app = broker.app();
    import(&app, &contract.admin, "files", "tickets", &[]).await;
    let token = agent(&contract, &broker, "files");
    let capture = install_trace_capture().start();
    let body = json_download_failure(
        capture
            .run(raw(&app, &token, "files", "download-malformed-logging"))
            .await,
        StatusCode::INTERNAL_SERVER_ERROR,
        "operation_failed",
    )
    .await;
    assert_eq!(contract.started("invoke").len(), 1);
    let records = contract.audited("download-malformed-logging");
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0]["providerAudit"]["command"]["contractViolation"],
        true
    );
    let events = capture.take_events();
    let failures = events
        .iter()
        .filter(|event| event["event"] == "command_import_failed")
        .collect::<Vec<_>>();
    assert_eq!(failures.len(), 1, "{events:?}");
    assert_eq!(failures[0]["request_id"], body["brokerRequestId"]);
    if log_stderr {
        assert_eq!(failures[0]["stderr"], format!("{STDERR}\\nnext\tline"));
    } else {
        assert!(failures[0].get("stderr").is_none());
        assert!(!serde_json::to_string(&events).unwrap().contains(STDERR));
    }
    for exposed in [
        body.to_string(),
        serde_json::to_string(&records).unwrap(),
        serde_json::to_string(&events).unwrap(),
    ] {
        assert!(!exposed.contains(PAYLOAD));
        assert!(!exposed.contains(&encoded));
    }
    assert!(!body.to_string().contains(STDERR));
    assert!(!contract.audit_text().contains(STDERR));
    drop(app);
    assert!(broker.stop().await.is_clean());
}

#[tokio::test]
async fn download_projections_agree_and_http_mcp_only_describes_the_action() {
    let contract = contract();
    let broker = import_broker(&contract.fixture.config).await;
    let app = broker.app();
    import(&app, &contract.admin, "files", "tickets", &[]).await;
    let token = agent(&contract, &broker, "files");
    let mut specs = Vec::new();
    for (id, route) in [
        ("download-catalog", "/v1/spec/catalog"),
        ("download-openapi", "/v1/spec/openapi.json"),
        ("download-send", "/v1/spec/send-schema.json"),
    ] {
        let response = spec_get(app.clone(), route, id, Some(&token)).await;
        assert_eq!(response.status(), StatusCode::OK);
        specs.push(response_json(response).await);
    }
    let action = catalog_action(&specs[0], "files", "time.now");
    assert_eq!(action["io"]["type"], "raw_download");
    assert_eq!(action["responseKind"], "raw_stream");
    assert_eq!(action["exitPolicy"], "raw_stream");
    let operation = &specs[1]["paths"]["/v1/invoke/files/time.now"]["post"];
    assert_eq!(
        operation["requestBody"]["content"]["application/json"]["schema"]["properties"]["inputs"],
        action["inputSchema"]
    );
    assert!(
        operation["responses"]["200"]["content"]
            .get("application/octet-stream")
            .is_some()
    );
    assert!(
        operation["responses"]["200"]["headers"]
            .get(RESULT_METADATA_HEADER)
            .is_some()
    );
    let send = send_action_variant(&specs[2], "files", "time.now");
    assert_eq!(send["properties"]["responseMode"]["const"], "stream");
    assert!(
        send["required"]
            .as_array()
            .unwrap()
            .contains(&json!("output"))
    );
    assert_eq!(send["properties"]["inputs"], action["inputSchema"]);

    let session = mcp_session(&app, &token).await;
    let name = agent_access_core::mcp::tool_name("files", "time.now");
    for (id, method, params) in [
        (2, "tools/list", json!({})),
        (
            3,
            "tools/call",
            json!({"name":"actions_describe", "arguments":{"service":"files", "action":"time.now"}}),
        ),
        (
            4,
            "tools/call",
            json!({"name":name, "arguments":{"inputs":{}, "outputPath":"/local-only/never-forwarded.bin"}}),
        ),
        (
            5,
            "tools/call",
            json!({"name":"resource_access_describe", "arguments":{"service":"files", "action":"time.now"}}),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(super::super::mcp::request(
                Method::POST,
                Some(&token),
                Some(&session),
                Some(json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = super::super::mcp::rpc_body(response).await;
        match id {
            2 => assert!(
                !response["result"]["tools"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|tool| tool["name"] == name)
            ),
            3 => {
                let detail = &response["result"]["structuredContent"];
                assert_eq!(detail["action"], "time.now");
                assert_eq!(detail["io"]["type"], "raw_download");
                assert!(detail.get("mcpTool").is_none());
            }
            4 => assert_eq!(response["error"]["code"], -32602),
            _ => {
                assert_ne!(response["result"]["isError"], true, "{response}");
                let coverage = &response["result"]["structuredContent"];
                assert!(coverage.to_string().contains("unscoped"), "{coverage}");
                assert!(coverage.get("liveListings").is_none());
            }
        }
    }
    assert!(
        contract.started("invoke").is_empty(),
        "discovery and a refused HTTP MCP call cannot execute the command"
    );
    drop(app);
    broker.stop().await;
}

#[tokio::test]
async fn download_enablement_is_rechecked_at_preview_acceptance_load_and_reload() {
    let mut contract = contract();
    contract.entry("tickets").max_download_bytes = None;
    let mut config = contract.fixture.config.clone();
    let broker = import_broker(&config).await;
    let app = broker.app();
    admin(
        &app,
        &contract.admin,
        Method::POST,
        "/v1/admin/imports",
        super::super::imports_command::definition("files", "tickets", &[]),
    )
    .await;
    let disabled = refresh(&app, &contract.admin, "files").await;
    let tool = &disabled["preview"]["manifest"]["tools"][0];
    assert!(
        tool["unsupportedReason"]
            .as_str()
            .unwrap()
            .contains("max_download_bytes"),
        "{tool}"
    );
    let (status, rejected) = request(
        &app,
        &contract.admin,
        Method::POST,
        "/v1/admin/imports/files/accept",
        Some(acceptance(&disabled)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");
    assert!(
        broker
            .runtime()
            .imported_catalog()
            .service("files")
            .unwrap()
            .actions
            .is_empty()
    );

    config
        .command_imports
        .get_mut("tickets")
        .unwrap()
        .max_download_bytes = Some(1024);
    broker.reload_config(&config).await;
    let allowed = refresh(&app, &contract.admin, "files").await;
    assert_eq!(
        allowed["preview"]["manifest"]["tools"][0]["definition"]["download"],
        true
    );
    assert!(allowed["preview"]["manifest"]["tools"][0]["unsupportedReason"].is_null());
    // A preview cannot authorize a capability the operator subsequently removed.
    config
        .command_imports
        .get_mut("tickets")
        .unwrap()
        .max_download_bytes = None;
    broker.reload_config(&config).await;
    let (status, rejected) = request(
        &app,
        &contract.admin,
        Method::POST,
        "/v1/admin/imports/files/accept",
        Some(acceptance(&allowed)),
    )
    .await;
    assert_ne!(status, StatusCode::OK, "{rejected}");
    assert!(
        broker
            .runtime()
            .imported_catalog()
            .service("files")
            .unwrap()
            .actions
            .is_empty()
    );

    config
        .command_imports
        .get_mut("tickets")
        .unwrap()
        .max_download_bytes = Some(1024);
    broker.reload_config(&config).await;
    let allowed = refresh(&app, &contract.admin, "files").await;
    let accepted = admin(
        &app,
        &contract.admin,
        Method::POST,
        "/v1/admin/imports/files/accept",
        acceptance(&allowed),
    )
    .await;
    let mut enable = versions(&accepted["result"]);
    enable["status"] = json!("enabled");
    admin(
        &app,
        &contract.admin,
        Method::POST,
        "/v1/admin/imports/files/status",
        enable,
    )
    .await;
    let token = agent(&contract, &broker, "files");
    let accepted = broker
        .runtime()
        .imported_catalog()
        .service("files")
        .unwrap()
        .actions[0]
        .clone();
    assert!(accepted.definition.download);
    let runs = contract.fixture.runs();
    drop(app);
    broker.stop().await;

    let broker = import_broker(&config).await;
    let app = broker.app();
    assert_eq!(contract.fixture.runs(), runs, "startup must remain offline");
    assert_eq!(
        broker
            .runtime()
            .imported_catalog()
            .service("files")
            .unwrap()
            .actions[0],
        accepted
    );
    assert!(
        broker
            .runtime()
            .imported_service_unavailable_reason("files")
            .is_none()
    );
    let response = raw(&app, &token, "files", "restarted-file").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap()
            .as_ref(),
        FILE
    );
    let runs = contract.fixture.runs();

    config
        .command_imports
        .get_mut("tickets")
        .unwrap()
        .max_download_bytes = None;
    broker.reload_config(&config).await;
    assert!(
        broker
            .runtime()
            .imported_service_unavailable_reason("files")
            .is_some()
    );
    assert_eq!(
        broker
            .runtime()
            .imported_catalog()
            .service("files")
            .unwrap()
            .actions[0],
        accepted
    );
    assert_ne!(
        raw(&app, &token, "files", "disabled-file").await.status(),
        StatusCode::OK
    );
    assert_eq!(contract.fixture.runs(), runs);
    config
        .command_imports
        .get_mut("tickets")
        .unwrap()
        .max_download_bytes = Some(1024);
    broker.reload_config(&config).await;
    assert!(
        broker
            .runtime()
            .imported_service_unavailable_reason("files")
            .is_none()
    );
    assert_eq!(contract.fixture.runs(), runs, "reload must remain offline");
    let response = raw(&app, &token, "files", "restored-file").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap()
            .as_ref(),
        FILE
    );
    drop(app);
    broker.stop().await;
}

#[tokio::test]
async fn download_refresh_quarantines_semantic_changes_and_preserves_grant_identity() {
    let contract = contract();
    let broker = import_broker(&contract.fixture.config).await;
    let app = broker.app();
    import(&app, &contract.admin, "files", "tickets", &[]).await;
    let token = agent(&contract, &broker, "files");
    let accepted = broker
        .runtime()
        .imported_catalog()
        .service("files")
        .unwrap()
        .actions[0]
        .clone();
    let unchanged = refresh(&app, &contract.admin, "files").await;
    assert_eq!(unchanged["service"]["actions"][0]["status"], "enabled");
    assert_eq!(
        broker
            .runtime()
            .imported_catalog()
            .service("files")
            .unwrap()
            .actions[0],
        accepted
    );

    // Removing, restoring, and changing the output schema all require review.
    let mut changed = manifest();
    for change in ["json", "download", "schema", "unsupported"] {
        match change {
            "json" => {
                changed["actions"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("download");
            }
            "download" => {
                changed["actions"][0]["download"] = json!(true);
            }
            "schema" => {
                changed["actions"][0]["outputSchema"] =
                    json!({"type":"object", "required":["warnings"]});
            }
            _ => {
                changed["actions"][0]["download"] = json!(false);
            }
        }
        contract.fixture.write_manifest(&changed);
        let discovered = refresh(&app, &contract.admin, "files").await;
        assert_eq!(
            discovered["service"]["actions"][0]["status"], "quarantined",
            "{change}: {discovered}"
        );
        assert_eq!(
            discovered["affectedGrantsByAction"]["time.now"],
            json!(["files-download"])
        );
        let before = contract.started("invoke");
        assert_ne!(
            raw(&app, &token, "files", &format!("quarantined-{change}"))
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(contract.started("invoke"), before);
        let mut accept = acceptance(&discovered);
        let (status, rejected) = request(
            &app,
            &contract.admin,
            Method::POST,
            "/v1/admin/imports/files/accept",
            Some(accept.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{change}: {rejected}");
        if change == "unsupported" {
            break;
        }
        assert!(
            rejected.to_string().contains("confirmAffectedGrants"),
            "{rejected}"
        );
        accept["confirmAffectedGrants"] = json!(true);
        let accepted = admin(
            &app,
            &contract.admin,
            Method::POST,
            "/v1/admin/imports/files/accept",
            accept,
        )
        .await;
        assert_eq!(
            accepted["result"]["service"]["actions"][0]["definition"]["action"],
            "time.now"
        );
        assert_eq!(
            accepted["result"]["service"]["actions"][0]["status"],
            "enabled"
        );
        assert_eq!(
            accepted["result"]["service"]["actions"][0]["definition"]["download"]
                .as_bool()
                .unwrap_or(false),
            change != "json"
        );
        assert!(
            broker
                .runtime()
                .managed_store()
                .unwrap()
                .policy_grants()
                .unwrap()
                .iter()
                .any(|grant| grant.grant_id == "files-download"
                    && grant.actions == ["time.now"]
                    && grant.status == "active")
        );
    }
    // A malformed complete document cannot publish even a quarantine change.
    let before = broker.runtime().imported_catalog().clone();
    std::fs::write(contract.fixture.path("manifest.json"), "{invalid").unwrap();
    let record = current(&app, &contract.admin, "files").await;
    let (status, _) = request(
        &app,
        &contract.admin,
        Method::POST,
        "/v1/admin/imports/files/discover",
        Some(versions(&record)),
    )
    .await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(broker.runtime().imported_catalog(), &before);
    drop(app);
    broker.stop().await;
}

#[tokio::test]
async fn a_download_prepared_before_quarantine_never_spawns() {
    let contract = contract();
    let broker = import_broker(&contract.fixture.config).await;
    let app = broker.app();
    let service = "filesfenced";
    import(&app, &contract.admin, service, "tickets", &[]).await;
    let token = agent(&contract, &broker, service);
    let pause = agent_access_core::test_support::CommandDispatchPause::new(service);
    let call = {
        let (app, token) = (app.clone(), token.clone());
        tokio::spawn(async move { raw(&app, &token, service, "download-fenced").await })
    };
    pause.reached().await;
    let mut changed = manifest();
    changed["actions"][0]
        .as_object_mut()
        .unwrap()
        .remove("download");
    contract.fixture.write_manifest(&changed);
    refresh(&app, &contract.admin, service).await;
    pause.release();
    let rejected = call.await.unwrap();
    assert_ne!(rejected.status(), StatusCode::OK);
    assert!(contract.started("invoke").is_empty());
    let records = contract.audited("download-fenced");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["providerAudit"]["command"]["spawned"], false);
    drop((pause, app));
    broker.stop().await;
}

#[tokio::test]
async fn undrained_downloads_release_command_slots_and_cancel_their_transfer_on_drop() {
    let mut contract = contract();
    contract.entry("tickets").max_concurrent = 1;
    let broker = import_broker(&contract.fixture.config).await;
    let app = broker.app();
    import(&app, &contract.admin, "files", "tickets", &[]).await;
    let token = agent(&contract, &broker, "files");
    let registry = broker.runtime().command_registry().clone();
    let first = raw(&app, &token, "files", "file-undrained").await;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(first.headers()[CACHE_CONTROL], "no-store");
    assert_eq!(
        registry.in_use("tickets"),
        0,
        "completed response worker releases its command slot"
    );
    let second = tokio::time::timeout(
        Duration::from_secs(3),
        raw(&app, &token, "files", "file-consumed"),
    )
    .await
    .expect("the undrained body must not retain the command slot");
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(contract.started("invoke").len(), 2);
    assert_eq!(
        axum::body::to_bytes(second.into_body(), 1024)
            .await
            .unwrap()
            .as_ref(),
        FILE
    );
    drop(first);
    wait_until("both transfer terminal records", || {
        contract.audited("file-undrained").len() == 2
            && contract.audited("file-consumed").len() == 2
    })
    .await;
    for (id, phase) in [
        ("file-undrained", "canceled"),
        ("file-consumed", "completed"),
    ] {
        let records = contract.audited(id);
        assert_eq!(records[0]["providerAudit"]["streamPhase"], "started");
        assert_eq!(records[1]["providerAudit"]["streamPhase"], phase);
        assert_eq!(
            records[0]["providerAudit"]["command"]["contractViolation"],
            false
        );
    }
    drop(app);
    assert!(broker.stop().await.is_clean());
}

#[tokio::test]
async fn abandoning_a_download_waiter_preserves_owned_execution_until_completion() {
    let mut contract = contract();
    contract.entry("tickets").timeout = "30s".into();
    let broker = import_broker(&contract.fixture.config).await;
    let app = broker.app();
    import(&app, &contract.admin, "files", "tickets", &[]).await;
    let token = agent(&contract, &broker, "files");
    let registry = broker.runtime().command_registry().clone();
    contract.hold(true);
    let call = {
        let (app, token) = (app.clone(), token.clone());
        tokio::spawn(async move { raw(&app, &token, "files", "file-abandoned").await })
    };
    let pid = next_run(&contract, 0).await;
    call.abort();
    let _ = call.await;
    assert!(!reaped(pid));
    assert_eq!(registry.in_use("tickets"), 1);
    assert!(contract.audited("file-abandoned").is_empty());
    contract.hold(false);
    wait_until("abandoned download completes and cancels transfer", || {
        contract.audited("file-abandoned").len() == 2
    })
    .await;
    wait_until("abandoned command is reaped", || reaped(pid)).await;
    let records = contract.audited("file-abandoned");
    assert_eq!(records[0]["providerAudit"]["command"]["exitCode"], 0);
    assert_eq!(
        records[0]["providerAudit"]["command"]["contractViolation"],
        false
    );
    assert_eq!(records[1]["providerAudit"]["streamPhase"], "canceled");
    assert_eq!(registry.in_use("tickets"), 0);
    drop(app);
    assert!(broker.stop().await.is_clean());
}
