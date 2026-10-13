//! Service invocation rate limits through the real router: what is counted,
//! effective-limit precedence, live limit changes, and the 429 contract.
use super::*;
use crate::ingress::invocation_limits::InvocationLimiter;
use crate::ingress::invocation_limits::tests::ManualClock;
use agent_access_core::{
    InvocationLimit, InvocationLimitConfig, InvocationLimitsConfig, PrincipalInvocationLimitConfig,
    PrincipalServiceLimitWriteRequest,
};

pub(super) const ALICE: &str = "alice-invocation-token";
pub(super) const BOB: &str = "bob-invocation-token";

pub(super) struct LimitFixture {
    pub(super) app: Router,
    pub(super) state: Arc<ReloadableState>,
    clock: Arc<ManualClock>,
    audit_path: PathBuf,
    _directory: tempfile::TempDir,
}

/// Two TOML static principals behind one source address, with a manual
/// limiter clock.
pub(super) fn limit_fixture(configure: impl FnOnce(&mut BrokerConfig)) -> LimitFixture {
    let directory = tempfile::tempdir().unwrap();
    create_private_dir(directory.path());
    let audit_path = directory.path().join("audit.jsonl");
    let mut principals = Vec::new();
    for (principal, token) in [("alice", ALICE), ("bob", BOB)] {
        let path = directory.path().join(principal);
        std::fs::write(&path, token).unwrap();
        principals.push(StaticPrincipalConfig {
            principal: principal.into(),
            token_refs: vec![format!("file:{}", path.display())],
        });
    }
    let provider_path = directory.path().join("provider-token");
    std::fs::write(&provider_path, "synthetic-upstream-token").unwrap();
    let mut config = fake_config(audit_path.to_str().unwrap());
    config.limits.upload_spool_dir = directory.path().join("spool").display().to_string();
    config.identity = IdentityConfig {
        trusted_callers: Default::default(),
        mode: "required".into(),
        authority: "toml".into(),
        sources: vec![IdentitySourceConfig {
            name: "agents".into(),
            kind: "static_principals".into(),
            header: "Authorization".into(),
            scheme: "Bearer".into(),
            principals,
        }],
        groups: vec![],
    };
    config.policy.grants[0].subjects = vec!["user:alice".into(), "user:bob".into()];
    config
        .credentials
        .service
        .get_mut("fake")
        .unwrap()
        .token_ref = Some(format!("file:{}", provider_path.display()));
    configure(&mut config);
    let runtime = BrokerRuntime::new(config).unwrap();
    let clock = ManualClock::new();
    let state = Arc::new(
        ReloadableState::from_snapshot(
            PathBuf::new(),
            std::sync::Arc::new(crate::backend_registry()),
            broker_build_status(),
            RuntimeSnapshot::new(
                1,
                "invocation-limits".into(),
                runtime.clone().with_config_generation(1),
                StateLockSet::empty(),
            ),
            runtime.max_http_body_bytes(),
            Duration::from_secs(5),
            Duration::from_secs(5),
            runtime.audit_registry(),
        )
        .with_invocation_limiter(InvocationLimiter::with_clock(clock.clone())),
    );
    LimitFixture {
        app: build_public_router(state.clone()),
        state,
        clock,
        audit_path,
        _directory: directory,
    }
}

impl LimitFixture {
    pub(super) async fn invoke(&self, request_id: &str, token: &str) -> axum::response::Response {
        invoke_fake_project_with_token(self.app.clone(), request_id, token, "TEST").await
    }

    /// Publishes a changed configuration the way a reload does, keeping the
    /// shared limiter.
    pub(super) fn publish(&self, generation: u64, change: impl FnOnce(&mut BrokerConfig)) {
        let mut config = self.state.current().runtime.config().clone();
        change(&mut config);
        let runtime = BrokerRuntime::new(config)
            .unwrap()
            .with_config_generation(generation);
        self.state.active.store(RuntimeSnapshot::new(
            generation,
            format!("invocation-limits-{generation}"),
            runtime,
            StateLockSet::empty(),
        ));
    }
}

pub(super) fn limit(requests: u64, window: &str) -> InvocationLimitConfig {
    InvocationLimitConfig {
        requests,
        window: window.into(),
    }
}

pub(super) fn set_fake_limit(config: &mut BrokerConfig, requests: u64, window: &str) {
    config
        .limits
        .invocations
        .services
        .insert("fake".into(), limit(requests, window));
}

pub(super) async fn assert_limited(response: axum::response::Response, requests: u64) -> Value {
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let value = response_json(response).await;
    assert_eq!(value["reasonCode"], "rate_limited", "{value}");
    assert_eq!(value["service"], "broker");
    assert_eq!(value["action"], "request.admit");
    assert_eq!(value["decision"], "error");
    assert_eq!(value["resourceScopes"], json!({}));
    assert!(value.get("result").is_none());
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains(&format!(": {requests} request"))
    );
    value
}

#[tokio::test]
async fn invoke_counts_every_io_form_and_denials_but_not_discovery_or_unknown_services() {
    let fixture = limit_fixture(|config| set_fake_limit(config, 4, "1m"));
    for round in 0..3 {
        for uri in [
            "/v1/services",
            "/v1/services/fake",
            "/v1/services/fake/actions",
            "/v1/capabilities",
            "/v1/me",
            "/v1/spec/catalog",
            "/v1/spec/openapi.json",
            "/v1/spec/send-schema.json",
        ] {
            let response = authed_json_request(
                fixture.app.clone(),
                Method::GET,
                uri,
                &format!("discovery-{round}"),
                "Authorization",
                format!("Bearer {ALICE}"),
                None,
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK, "{uri}");
        }
    }
    assert_eq!(fixture.state.shared_invocations.key_count(), 0);

    // Unknown services fail existing validation without limiter state.
    let unknown = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/invoke/missing/echo",
        "unknown-service",
        "Authorization",
        format!("Bearer {ALICE}"),
        Some(r#"{"inputs":{}}"#),
    )
    .await;
    assert_eq!(unknown.status(), StatusCode::FORBIDDEN);
    assert_eq!(fixture.state.shared_invocations.key_count(), 0);

    // JSON.
    assert_eq!(
        fixture.invoke("counted-json", ALICE).await.status(),
        StatusCode::OK
    );
    // Denied by policy after admission: still counted.
    let denied =
        invoke_fake_project_with_token(fixture.app.clone(), "counted-denied", ALICE, "OTHER").await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    // Raw download negotiation, rejected after admission for this action.
    let raw = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/fake/echo")
                .extension(ConnectInfo(
                    "127.0.0.1:43100".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "counted-raw")
                .header(AUTHORIZATION, format!("Bearer {ALICE}"))
                .header(ACCEPT, RAW_RESULT_MIME)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"inputs":{"project":"TEST","message":"raw"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(raw.status().is_client_error(), "{}", raw.status());
    assert_ne!(raw.status(), StatusCode::TOO_MANY_REQUESTS);
    // Multipart upload form, rejected after admission.
    let upload = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/fake/echo")
                .extension(ConnectInfo(
                    "127.0.0.1:43100".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "counted-upload")
                .header(AUTHORIZATION, format!("Bearer {ALICE}"))
                .header(CONTENT_TYPE, "multipart/form-data; boundary=limit-boundary")
                .body(Body::from("--limit-boundary--\r\n"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(upload.status().is_client_error(), "{}", upload.status());
    assert_ne!(upload.status(), StatusCode::TOO_MANY_REQUESTS);

    assert_limited(fixture.invoke("counted-limited", ALICE).await, 4).await;
    assert_eq!(fixture.state.shared_invocations.key_count(), 1);
}

#[tokio::test]
async fn principals_behind_one_source_address_have_independent_windows() {
    // Regression: a shared source budget used to lock out every principal
    // behind one proxy address.
    let fixture = limit_fixture(|config| set_fake_limit(config, 2, "1m"));
    for index in 0..2 {
        assert_eq!(
            fixture
                .invoke(&format!("alice-{index}"), ALICE)
                .await
                .status(),
            StatusCode::OK
        );
    }
    assert_limited(fixture.invoke("alice-limited", ALICE).await, 2).await;
    for index in 0..2 {
        assert_eq!(
            fixture.invoke(&format!("bob-{index}"), BOB).await.status(),
            StatusCode::OK
        );
    }
    assert_limited(fixture.invoke("bob-limited", BOB).await, 2).await;
    assert_limited(fixture.invoke("alice-still-limited", ALICE).await, 2).await;
}

#[tokio::test]
async fn toml_overrides_take_precedence_and_limit_changes_apply_on_the_next_request() {
    let fixture = limit_fixture(|config| {
        config.limits.invocations.default = Some(limit(5, "1m"));
        set_fake_limit(config, 2, "1m");
        config.limits.invocations.principal_overrides = vec![PrincipalInvocationLimitConfig {
            principal: "alice".into(),
            service: "fake".into(),
            requests: 3,
            window: "1m".into(),
        }];
    });
    let runtime = fixture.state.current().runtime.clone();
    let alice = runtime.effective_invocation_limits("alice").await.unwrap();
    assert_eq!(
        serde_json::to_value(&alice).unwrap(),
        json!([{"service":"fake","requests":3,"windowSeconds":60,"overridden":true}])
    );
    assert_eq!(
        runtime
            .effective_invocation_limit("bob", "fake")
            .await
            .unwrap(),
        agent_access_core::ConfiguredInvocationLimits::from_config(runtime.config())
            .effective("fake", None)
    );

    for index in 0..3 {
        assert_eq!(
            fixture
                .invoke(&format!("alice-{index}"), ALICE)
                .await
                .status(),
            StatusCode::OK
        );
    }
    assert_limited(fixture.invoke("alice-limited", ALICE).await, 3).await;
    for index in 0..2 {
        assert_eq!(
            fixture.invoke(&format!("bob-{index}"), BOB).await.status(),
            StatusCode::OK
        );
    }
    assert_limited(fixture.invoke("bob-limited", BOB).await, 2).await;

    // Raising the service limit applies to the next request and keeps history.
    fixture.publish(2, |config| set_fake_limit(config, 4, "1m"));
    assert_eq!(
        fixture.invoke("bob-raised-0", BOB).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        fixture.invoke("bob-raised-1", BOB).await.status(),
        StatusCode::OK
    );
    assert_limited(fixture.invoke("bob-raised-limited", BOB).await, 4).await;
    // Alice's override still wins over the raised service limit.
    assert_limited(fixture.invoke("alice-override-kept", ALICE).await, 3).await;

    // Removing the override falls back to the service limit.
    fixture.publish(3, |config| {
        config.limits.invocations.principal_overrides.clear();
    });
    assert_eq!(
        fixture.invoke("alice-fallback", ALICE).await.status(),
        StatusCode::OK
    );
    assert_limited(fixture.invoke("alice-fallback-limited", ALICE).await, 4).await;

    // A different window resets the key's history.
    fixture.publish(4, |config| set_fake_limit(config, 1, "2m"));
    assert_eq!(
        fixture.invoke("bob-new-window", BOB).await.status(),
        StatusCode::OK
    );
    let limited = assert_limited(fixture.invoke("bob-new-window-limited", BOB).await, 1).await;
    assert!(
        limited["error"]["message"]
            .as_str()
            .unwrap()
            .contains("per 2m.")
    );
}

#[tokio::test]
async fn rate_limited_invocation_returns_the_contract_body_header_and_audit() {
    let fixture = limit_fixture(|config| set_fake_limit(config, 2, "1m"));
    for index in 0..2 {
        assert_eq!(
            fixture
                .invoke(&format!("contract-{index}"), ALICE)
                .await
                .status(),
            StatusCode::OK
        );
    }
    fixture.clock.advance(Duration::from_secs(48));
    let response = fixture.invoke("contract-limited", ALICE).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()[RETRY_AFTER], "12");
    let value = response_json(response).await;
    let message = "Rate limit reached for service \"fake\": 2 requests per 1m. Retry after 12s (at 2026-09-25T14:04:00Z). The request was not executed.";
    assert_eq!(value["reasonCode"], "rate_limited");
    assert_eq!(value["decision"], "error");
    assert_eq!(value["service"], "broker");
    assert_eq!(value["action"], "request.admit");
    assert_eq!(value["agentRequestId"], "contract-limited");
    assert_eq!(value["reason"], message);
    assert_eq!(value["error"]["message"], message);
    assert!(value.get("result").is_none());
    assert_eq!(value["resourceScopes"], json!({}));

    let records = read_audit_records(&fixture.audit_path);
    let record = records
        .iter()
        .find(|record| record["agentRequestId"] == "contract-limited")
        .unwrap();
    assert_eq!(record["principal"], "alice");
    assert_eq!(record["executionContext"], "default");
    assert_eq!(record["service"], "fake");
    assert_eq!(record["action"], "echo");
    assert_eq!(record["reasonCode"], "rate_limited");
    assert_eq!(record["decision"], "error");
    assert_eq!(record["brokerRequestId"], value["brokerRequestId"]);
    assert_eq!(
        record["providerAudit"],
        json!({"rateLimit": {
            "limitScope": "principal",
            "service": "fake",
            "limit": 2,
            "windowSeconds": 60,
            "retryAfterSeconds": 12
        }})
    );
    assert!(record.get("matchedGrant").is_none());
    assert!(record.get("credentialMode").is_none());

    // The first requests leave the window exactly 60s after admission.
    fixture.clock.advance(Duration::from_secs(11));
    let response = fixture.invoke("contract-almost", ALICE).await;
    assert_eq!(response.headers()[RETRY_AFTER], "1");
    fixture.clock.advance(Duration::from_secs(1));
    assert_eq!(
        fixture
            .invoke("contract-after-window", ALICE)
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn managed_store_overrides_take_precedence_and_apply_without_reload() {
    let fixture = browser_rate_fixture(LimitsConfig {
        invocations: InvocationLimitsConfig {
            default: Some(limit(3, "1m")),
            services: BTreeMap::from([("fake".to_string(), limit(2, "1m"))]),
            principal_overrides: vec![],
        },
        ..LimitsConfig::default()
    })
    .await;
    let runtime = fixture.state.current().runtime.clone();
    let store = runtime.managed_store().unwrap().clone();
    let token = fixture.agent_tokens[0].clone();
    let invoke = |request_id: &'static str| fixture.token_invoke(request_id, &token);
    assert_eq!(invoke("managed-0").await.status(), StatusCode::OK);
    assert_eq!(invoke("managed-1").await.status(), StatusCode::OK);
    assert_limited(invoke("managed-service-limit").await, 2).await;

    store
        .upsert_principal_service_limit(PrincipalServiceLimitWriteRequest {
            principal_id: "alice".into(),
            service: "fake".into(),
            limit: InvocationLimit::new(4, 60).unwrap(),
            actor: "admin".into(),
        })
        .unwrap();
    assert_eq!(
        serde_json::to_value(runtime.effective_invocation_limits("alice").await.unwrap()).unwrap(),
        json!([{"service":"fake","requests":4,"windowSeconds":60,"overridden":true}])
    );
    assert_eq!(invoke("managed-override-0").await.status(), StatusCode::OK);
    assert_eq!(invoke("managed-override-1").await.status(), StatusCode::OK);
    assert_limited(invoke("managed-override-limited").await, 4).await;

    store
        .delete_principal_service_limit("alice", "fake")
        .unwrap()
        .unwrap();
    assert_limited(invoke("managed-cleared").await, 2).await;

    // An override with another window resets the key.
    store
        .upsert_principal_service_limit(PrincipalServiceLimitWriteRequest {
            principal_id: "alice".into(),
            service: "fake".into(),
            limit: InvocationLimit::new(1, 30).unwrap(),
            actor: "admin".into(),
        })
        .unwrap();
    assert_eq!(invoke("managed-window-0").await.status(), StatusCode::OK);
    let limited = assert_limited(invoke("managed-window-limited").await, 1).await;
    assert!(
        limited["error"]["message"]
            .as_str()
            .unwrap()
            .contains("per 30s.")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn request_limited_event_includes_limit_detail_and_token_id() {
    let captured = install_trace_capture().start();
    let fixture = browser_rate_fixture(LimitsConfig {
        invocations: InvocationLimitsConfig {
            services: BTreeMap::from([("fake".to_string(), limit(1, "90s"))]),
            ..Default::default()
        },
        ..LimitsConfig::default()
    })
    .await;
    let token = &fixture.agent_tokens[0];
    let first = fixture.token_invoke("event-limit-first", token).await;
    assert_eq!(first.status(), StatusCode::OK);
    let limited = captured
        .run(fixture.token_invoke("event-limit-second", token))
        .await;
    let retry_after = limited.headers()[RETRY_AFTER]
        .to_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let body = assert_limited(limited, 1).await;
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains(": 1 request per 90s. Retry after ")
    );

    let events = captured.take_events();
    let event = event_by_name_and_agent(&events, "request_limited", "event-limit-second");
    assert_eq!(string_field(event, "level"), Some("WARN"));
    assert_eq!(string_field(event, "limitKind"), Some("invocation_rate"));
    assert_eq!(string_field(event, "limitScope"), Some("principal"));
    assert_eq!(string_field(event, "service"), Some("fake"));
    assert_eq!(string_field(event, "action"), Some("echo"));
    assert_eq!(string_field(event, "principal"), Some("alice"));
    assert_eq!(number_field(event, "limit"), Some(1));
    assert_eq!(number_field(event, "windowSeconds"), Some(90));
    assert_eq!(number_field(event, "retryAfterSeconds"), Some(retry_after));
    assert_eq!(string_field(event, "reasonCode"), Some("rate_limited"));
    assert_eq!(number_field(event, "http.statusCode"), Some(429));
    let records = read_audit_records(&fixture.audit_path);
    let record = records
        .iter()
        .find(|record| record["agentRequestId"] == "event-limit-second")
        .unwrap();
    let token_id = record["identitySource"]["tokenId"].as_str().unwrap();
    assert_eq!(string_field(event, "tokenId"), Some(token_id));
    assert_eq!(record["providerAudit"]["rateLimit"]["windowSeconds"], 90);
}

#[tokio::test]
async fn managed_override_lookup_failure_fails_closed_before_admission() {
    let fixture = browser_rate_fixture(LimitsConfig::default()).await;
    let token = fixture.agent_tokens[0].clone();
    assert_eq!(
        fixture
            .token_invoke("override-lookup-ok", &token)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(fixture.state.shared_invocations.key_count(), 1);
    // Break the override table underneath the running broker so the managed
    // override lookup fails.
    rusqlite::Connection::open(&fixture.store_path)
        .unwrap()
        .execute_batch(
            "ALTER TABLE principal_service_limits RENAME TO principal_service_limits_broken",
        )
        .unwrap();

    let response = fixture.token_invoke("override-lookup-failed", &token).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response_json(response).await;
    assert_eq!(body["reasonCode"], "managed_store_unavailable", "{body}");
    assert!(body.get("result").is_none_or(Value::is_null), "{body}");
    // Nothing was admitted or dispatched: no default limit was substituted.
    let state = fixture.state.shared_invocations.state_for_test();
    assert_eq!(state, vec![("alice".to_string(), "fake".to_string(), 1)]);
    let records = read_audit_records(&fixture.audit_path);
    let record = records
        .iter()
        .find(|record| record["agentRequestId"] == "override-lookup-failed")
        .unwrap();
    assert_eq!(record["reasonCode"], "managed_store_unavailable");
    assert!(record.get("matchedGrant").is_none());
    assert!(record.get("credentialMode").is_none());
    assert!(record.get("upstreamStatus").is_none_or(Value::is_null));
}
