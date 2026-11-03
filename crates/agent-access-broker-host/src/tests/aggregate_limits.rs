//! Shared service limits through the production router and runtime publication.
//! Scheduler ordering and precise clock arithmetic have separate unit coverage.
use super::invocation_limits::{ALICE, BOB, LimitFixture, limit_fixture, set_fake_limit};
use super::*;
use agent_access_core::{AggregateInvocationLimitConfig, PrincipalInvocationLimitConfig};

pub(super) fn aggregate(requests: u64, window: &str) -> AggregateInvocationLimitConfig {
    AggregateInvocationLimitConfig {
        requests,
        window: window.into(),
    }
}

async fn detail(fixture: &LimitFixture, token: &str) -> Value {
    let response = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/services/fake",
        "aggregate-detail",
        "Authorization",
        format!("Bearer {token}"),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    response_json(response).await
}

fn audit(fixture: &LimitFixture, id: &str) -> Value {
    let snapshot = fixture.state.current();
    let path = &snapshot.runtime.config().audit.as_ref().unwrap().path;
    let matching: Vec<_> = read_audit_records(Path::new(path))
        .into_iter()
        .filter(|record| record["agentRequestId"] == id)
        .collect();
    assert_eq!(matching.len(), 1, "one terminal record for {id}");
    matching.into_iter().next().unwrap()
}

async fn rejected(fixture: &LimitFixture, id: &str, token: &str, scope: &str) {
    let response = fixture.invoke(id, token).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        response.headers()[RETRY_AFTER]
            .to_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            > 0
    );
    let body = response_json(response).await;
    assert_eq!(body["reasonCode"], "rate_limited");
    assert_eq!(body["service"], "broker");
    assert_eq!(body["action"], "request.admit");
    assert!(body.get("result").is_none());
    assert_eq!(body["resourceScopes"], json!({}));
    let record = audit(fixture, id);
    assert_eq!(record["providerAudit"]["rateLimit"]["limitScope"], scope);
    assert!(record.get("matchedGrant").is_none());
    assert!(record.get("credentialMode").is_none());
}

#[tokio::test]
async fn concurrent_principals_share_one_cap_without_debiting_rejected_callers() {
    let fixture = limit_fixture(|config| {
        set_fake_limit(config, 20, "1m");
        config
            .limits
            .invocations
            .aggregate
            .insert("fake".into(), aggregate(3, "1m"));
    })
    .await;
    let mut calls = tokio::task::JoinSet::new();
    for index in 0..12 {
        let app = fixture.app.clone();
        calls.spawn(async move {
            let token = if index % 2 == 0 { ALICE } else { BOB };
            let id = format!("aggregate-concurrent-{index}");
            let response = invoke_fake_project_with_token(app, &id, token, "TEST").await;
            (response.status(), response_json(response).await)
        });
    }
    let mut admitted = 0;
    while let Some(result) = calls.join_next().await {
        let (status, body) = result.unwrap();
        if status == StatusCode::OK {
            admitted += 1;
        } else {
            assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
            assert_eq!(body["reasonCode"], "rate_limited", "{body}");
            assert_eq!(body["service"], "broker");
            assert_eq!(body["action"], "request.admit");
            assert!(body.get("result").is_none());
        }
    }
    assert_eq!(admitted, 3);
    let counts = fixture.state.shared_invocations.state_for_test();
    assert_eq!(counts.iter().map(|(_, _, count)| count).sum::<u64>(), 3);
    for token in [ALICE, BOB] {
        let observed = detail(&fixture, token).await;
        assert_eq!(observed["limits"]["invocations"]["availableImmediately"], 0);
        assert_eq!(
            observed["limits"]["invocations"]["blockingScope"],
            "service"
        );
        assert_eq!(
            observed["limits"]["aggregate"],
            json!({"requests":3,"windowSeconds":60})
        );
    }
    assert_eq!(fixture.state.shared_invocations.state_for_test(), counts);
}

#[tokio::test]
async fn anonymous_clients_share_service_capacity_without_live_detail() {
    let fixture = limit_fixture(|config| {
        set_fake_limit(config, 10, "1m");
        config
            .limits
            .invocations
            .aggregate
            .insert("fake".into(), aggregate(1, "1m"));
        config.identity.mode = "anonymous".into();
        config.identity.sources.clear();
        config.policy.grants[0].subjects = vec!["group:anonymous".into()];
    })
    .await;
    for (address, request_id, expected) in [
        ("127.0.0.1:43100", "anonymous-shared-first", StatusCode::OK),
        (
            "127.0.0.2:43101",
            "anonymous-shared-second",
            StatusCode::TOO_MANY_REQUESTS,
        ),
    ] {
        let response = fixture
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/invoke/fake/echo")
                    .extension(ConnectInfo(address.parse::<SocketAddr>().unwrap()))
                    .header(REQUEST_ID_HEADER, request_id)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({"inputs":{"project":"TEST","message":"anonymous shared quota"}})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    assert_eq!(
        fixture.state.shared_invocations.state_for_test(),
        vec![("anonymous".into(), "fake".into(), 1)]
    );
    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/services/fake")
                .extension(ConnectInfo(
                    "127.0.0.2:43101".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "anonymous-shared-detail")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response_json(response).await.get("limits").is_none());
}

#[tokio::test]
async fn shared_cap_rejects_raw_and_multipart_without_reading_their_bodies() {
    let fixture = limit_fixture(|config| {
        set_fake_limit(config, 10, "1m");
        config
            .limits
            .invocations
            .aggregate
            .insert("fake".into(), aggregate(1, "1m"));
    })
    .await;
    assert_eq!(
        fixture.invoke("shared-body-seed", ALICE).await.status(),
        StatusCode::OK
    );
    for (id, content_type, accept) in [
        ("shared-body-raw", "application/json", RAW_RESULT_MIME),
        (
            "shared-body-multipart",
            "multipart/form-data; boundary=aggregate-test",
            "application/json",
        ),
    ] {
        let polls = Arc::new(AtomicUsize::new(0));
        let counted = polls.clone();
        let body = Body::from_stream(stream::poll_fn(move |_| {
            counted.fetch_add(1, Ordering::SeqCst);
            std::task::Poll::Ready(None::<Result<Bytes, std::io::Error>>)
        }));
        let response = fixture
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/invoke/fake/echo")
                    .extension(ConnectInfo(
                        "127.0.0.1:43100".parse::<SocketAddr>().unwrap(),
                    ))
                    .header(REQUEST_ID_HEADER, id)
                    .header(AUTHORIZATION, format!("Bearer {BOB}"))
                    .header(CONTENT_TYPE, content_type)
                    .header(ACCEPT, accept)
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let envelope = response_json(response).await;
        assert_eq!(envelope["reasonCode"], "rate_limited");
        assert!(envelope.get("result").is_none());
        assert_eq!(
            polls.load(Ordering::SeqCst),
            0,
            "shared rejection read {id}"
        );
        assert_eq!(
            audit(&fixture, id)["providerAudit"]["rateLimit"]["limitScope"],
            "service"
        );
    }
    assert_eq!(
        detail(&fixture, BOB).await["limits"]["invocations"]["countedRequests"],
        0
    );
}

#[tokio::test]
async fn personal_overrides_cannot_bypass_shared_limits_and_personal_limits_still_apply() {
    let fixture = limit_fixture(|config| {
        set_fake_limit(config, 1, "1m");
        config
            .limits
            .invocations
            .aggregate
            .insert("fake".into(), aggregate(2, "2m"));
        config
            .limits
            .invocations
            .principal_overrides
            .push(PrincipalInvocationLimitConfig {
                principal: "alice".into(),
                service: "fake".into(),
                requests: 10,
                window: "1m".into(),
            });
    })
    .await;
    for id in ["override-first", "override-second"] {
        assert_eq!(fixture.invoke(id, ALICE).await.status(), StatusCode::OK);
    }
    rejected(&fixture, "override-shared-alice", ALICE, "service").await;
    rejected(&fixture, "override-shared-bob", BOB, "service").await;
    assert_eq!(
        detail(&fixture, BOB).await["limits"]["invocations"]["countedRequests"],
        0
    );

    fixture
        .publish(2, |config| {
            config
                .limits
                .invocations
                .aggregate
                .insert("fake".into(), aggregate(4, "2m"));
        })
        .await;
    assert_eq!(
        fixture
            .invoke("override-bob-after-raise", BOB)
            .await
            .status(),
        StatusCode::OK
    );
    rejected(&fixture, "override-bob-personal", BOB, "principal").await;
    assert_eq!(
        fixture
            .invoke("override-alice-last-shared", ALICE)
            .await
            .status(),
        StatusCode::OK
    );
    rejected(&fixture, "override-shared-final", ALICE, "service").await;
    let counts = fixture.state.shared_invocations.state_for_test();
    assert_eq!(counts.iter().map(|(_, _, count)| count).sum::<u64>(), 4);
}

#[tokio::test]
async fn shared_history_survives_reload_and_count_changes_with_explicit_reset_boundaries() {
    let fixture = limit_fixture(|config| {
        set_fake_limit(config, 100, "1m");
        config
            .limits
            .invocations
            .aggregate
            .insert("fake".into(), aggregate(2, "1m"));
    })
    .await;
    for id in ["history-first", "history-second"] {
        assert_eq!(fixture.invoke(id, ALICE).await.status(), StatusCode::OK);
    }
    fixture.publish(2, |_| {}).await;
    rejected(&fixture, "history-same-reload", BOB, "service").await;
    fixture
        .publish(3, |config| {
            config
                .limits
                .invocations
                .aggregate
                .insert("fake".into(), aggregate(3, "1m"));
        })
        .await;
    assert_eq!(
        fixture.invoke("history-raised-one", BOB).await.status(),
        StatusCode::OK
    );
    rejected(&fixture, "history-raised-exhausted", ALICE, "service").await;
    fixture
        .publish(4, |config| {
            config
                .limits
                .invocations
                .aggregate
                .insert("fake".into(), aggregate(1, "1m"));
        })
        .await;
    rejected(&fixture, "history-lowered", BOB, "service").await;

    fixture
        .publish(5, |config| {
            config
                .limits
                .invocations
                .aggregate
                .insert("fake".into(), aggregate(1, "2m"));
        })
        .await;
    assert_eq!(
        fixture.invoke("history-new-window", BOB).await.status(),
        StatusCode::OK
    );
    rejected(&fixture, "history-new-window-full", ALICE, "service").await;
    fixture
        .publish(6, |config| {
            config.limits.invocations.aggregate.remove("fake");
        })
        .await;
    assert_eq!(
        fixture.invoke("history-disabled", ALICE).await.status(),
        StatusCode::OK
    );
    assert!(
        detail(&fixture, ALICE).await["limits"]
            .get("aggregate")
            .is_none()
    );
    fixture
        .publish(7, |config| {
            config
                .limits
                .invocations
                .aggregate
                .insert("fake".into(), aggregate(1, "2m"));
        })
        .await;
    assert_eq!(
        fixture.invoke("history-reenabled", BOB).await.status(),
        StatusCode::OK
    );
    rejected(&fixture, "history-reenabled-full", ALICE, "service").await;
}

#[tokio::test]
async fn shared_detail_keeps_personal_counts_and_is_observational_only() {
    let fixture = limit_fixture(|config| {
        set_fake_limit(config, 5, "1m");
        config
            .limits
            .invocations
            .aggregate
            .insert("fake".into(), aggregate(2, "1m"));
    })
    .await;
    for _ in 0..3 {
        let observed = detail(&fixture, BOB).await;
        assert_eq!(observed["limits"]["invocations"]["availableImmediately"], 2);
        assert!(
            observed["limits"]["invocations"]
                .get("blockingScope")
                .is_none()
        );
    }
    assert_eq!(fixture.state.shared_invocations.key_count(), 0);
    assert_eq!(
        fixture.invoke("detail-alice-one", ALICE).await.status(),
        StatusCode::OK
    );
    let bob = detail(&fixture, BOB).await;
    assert_eq!(bob["limits"]["invocations"]["requests"], 5);
    assert_eq!(bob["limits"]["invocations"]["countedRequests"], 0);
    assert_eq!(bob["limits"]["invocations"]["availableImmediately"], 1);
    assert_eq!(
        fixture.invoke("detail-alice-two", ALICE).await.status(),
        StatusCode::OK
    );
    let history = fixture.state.shared_invocations.state_for_test();
    for _ in 0..3 {
        let bob = detail(&fixture, BOB).await;
        assert_eq!(bob["limits"]["invocations"]["countedRequests"], 0);
        assert_eq!(bob["limits"]["invocations"]["queuedRequests"], 0);
        assert_eq!(bob["limits"]["invocations"]["availableImmediately"], 0);
        assert_eq!(
            bob["limits"]["invocations"]["nextAdmissionAfterSeconds"],
            60
        );
        assert_eq!(bob["limits"]["invocations"]["blockingScope"], "service");
        assert_eq!(
            bob["limits"]["aggregate"],
            json!({"requests":2,"windowSeconds":60})
        );
        assert!(bob["limits"]["aggregate"].get("countedRequests").is_none());
        assert!(bob["limits"]["aggregate"].get("queuedRequests").is_none());
        assert!(bob["limits"].get("principal").is_none());
    }
    assert_eq!(fixture.state.shared_invocations.state_for_test(), history);
    for path in ["/v1/services", "/v1/me"] {
        let response = authed_json_request(
            fixture.app.clone(),
            Method::GET,
            path,
            "aggregate-static-discovery",
            "Authorization",
            format!("Bearer {BOB}"),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let value = response_json(response).await;
        assert!(!value.to_string().contains("blockingScope"));
        assert!(!value.to_string().contains("availableImmediately"));
        assert!(!value.to_string().contains("aggregate"));
    }
}

#[tokio::test]
async fn policy_denials_spend_shared_quota_without_granting_detail_visibility() {
    let fixture = limit_fixture(|config| {
        set_fake_limit(config, 5, "1m");
        config
            .limits
            .invocations
            .aggregate
            .insert("fake".into(), aggregate(1, "1m"));
        config.policy.grants[0].subjects = vec!["user:alice".into()];
    })
    .await;
    let response = fixture
        .invoke("shared-post-admission-policy-deny", BOB)
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_json(response).await;
    assert_ne!(body["reasonCode"], "rate_limited");
    rejected(&fixture, "shared-after-policy-deny", ALICE, "service").await;
    let hidden = authed_json_request(
        fixture.app.clone(),
        Method::GET,
        "/v1/services/fake",
        "shared-denied-detail",
        "Authorization",
        format!("Bearer {BOB}"),
        None,
    )
    .await;
    assert_ne!(hidden.status(), StatusCode::OK);
    assert!(response_json(hidden).await.get("limits").is_none());
    assert_eq!(
        fixture.state.shared_invocations.state_for_test(),
        vec![("bob".into(), "fake".into(), 1)]
    );
}

#[tokio::test]
async fn gateway_shared_cap_keeps_ref_discovery_outside_pack_accounting() {
    let fixture = test_gateway_router_with_config(false, &["repo.fetch"], |config| {
        config
            .limits
            .invocations
            .aggregate
            .insert("gitlab_git".into(), aggregate(1, "1m"));
    })
    .await;
    let basic = format!(
        "Basic {}",
        BASE64.encode(format!("agent-access:{}", fixture.agent_token))
    );
    for (round, expected) in [(0, false), (1, true)] {
        let polls = Arc::new(AtomicUsize::new(0));
        let counted = polls.clone();
        let body = if expected {
            Body::from_stream(stream::poll_fn(move |_| {
                counted.fetch_add(1, Ordering::SeqCst);
                std::task::Poll::Ready(None::<Result<Bytes, std::io::Error>>)
            }))
        } else {
            Body::from("0000")
        };
        let discovery = gateway_get(
            fixture.app.clone(),
            "/sip/service.git/info/refs?service=git-upload-pack",
            "git.example.test",
            &format!("shared-git-discovery-{round}"),
            Some(&basic),
        )
        .await;
        assert_ne!(discovery.status(), StatusCode::TOO_MANY_REQUESTS);
        let response = gateway_request(GatewayRequestSpec {
            app: fixture.app.clone(),
            method: Method::POST,
            uri: "/sip/service.git/git-upload-pack".parse().unwrap(),
            host: Some("git.example.test"),
            request_id: Some(if round == 0 {
                "shared-git-first"
            } else {
                "shared-git-refused"
            }),
            authorization: Some(&basic),
            headers: &[(
                CONTENT_TYPE.as_str(),
                "application/x-git-upload-pack-request",
            )],
            body,
        })
        .await;
        assert_eq!(response.status() == StatusCode::TOO_MANY_REQUESTS, expected);
        if expected {
            assert_eq!(
                polls.load(Ordering::SeqCst),
                0,
                "shared refusal read the Git pack body"
            );
            assert_eq!(response.headers()[REASON_CODE_HEADER], "rate_limited");
            assert!(response.headers().contains_key(RETRY_AFTER));
            let text = String::from_utf8(
                axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap();
            assert!(
                text.starts_with("Shared rate limit reached for service \"gitlab_git\""),
                "{text}"
            );
        }
    }
    let records = require_audit_request(
        &fixture.audit_path,
        "shared-git-refused",
        "gitlab_git",
        "repo.fetch",
    );
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0]["providerAudit"]["rateLimit"]["limitScope"],
        "service"
    );
}

#[tokio::test]
async fn aggregate_policy_catalog_preserves_administrator_auditor_and_scoped_manager_boundaries() {
    let fixture = service_policy_management_fixture().await;
    let mut config = fixture._broker.runtime().config().clone();
    // This management fixture starts without upstream material. Reload performs
    // credential admission, so give both selected services test-owned material.
    for service in ["fake", "gitlab_git"] {
        let path = fixture
            ._broker
            .running()
            .directory()
            .secret_file(
                format!("shared-catalog-{service}.token"),
                "synthetic-service-token",
            )
            .unwrap();
        config
            .credentials
            .service
            .get_mut(service)
            .unwrap()
            .token_ref = Some(format!("file:{}", path.display()));
    }
    config
        .limits
        .invocations
        .aggregate
        .insert("fake".into(), aggregate(7, "1m"));
    config
        .limits
        .invocations
        .aggregate
        .insert("gitlab_git".into(), aggregate(11, "2m"));
    fixture._broker.reload_config(&config).await;
    let catalog = |token: String| {
        let app = fixture.app.clone();
        async move {
            let response = authed_json_request(
                app,
                Method::GET,
                "/v1/admin/policy/catalog",
                "shared-policy-catalog",
                "Authorization",
                format!("Bearer {token}"),
                None,
            )
            .await;
            (response.status(), response_json(response).await)
        }
    };
    let (status, admin) = catalog(fixture.admin_token.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let services = admin["result"]["services"].as_array().unwrap();
    for (name, requests, window) in [("fake", 7, 60), ("gitlab_git", 11, 120)] {
        let service = services
            .iter()
            .find(|service| service["service"] == name)
            .unwrap();
        assert_eq!(
            service["aggregateInvocationLimit"],
            json!({"requests":requests,"windowSeconds":window})
        );
    }
    assert_eq!(
        catalog(fixture.alice_user_token.clone()).await.0,
        StatusCode::FORBIDDEN
    );
    let assigned = authed_json_request(
        fixture.app.clone(),
        Method::PUT,
        "/v1/admin/policy/services/fake/managers/bob",
        "shared-policy-assign",
        "Authorization",
        format!("Bearer {}", fixture.admin_token),
        None,
    )
    .await;
    assert_eq!(assigned.status(), StatusCode::OK);
    let (status, scoped) = catalog(fixture.bob_user_token.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let services = scoped["result"]["services"].as_array().unwrap();
    assert_eq!(services.len(), 1);
    assert_eq!(services[0]["service"], "fake");
    assert_eq!(
        services[0]["aggregateInvocationLimit"],
        json!({"requests":7,"windowSeconds":60})
    );

    let runtime = fixture._broker.runtime();
    let store = runtime.managed_store().unwrap();
    store
        .patch_principal_access(
            agent_access_core::PrincipalAccessPatchRequest {
                principal_id: "alice".into(),
                role: Some(agent_access_core::PrincipalRole::Auditor),
                self_service_enabled: None,
                agent_token_issuance: None,
                actor: "admin".into(),
            },
            &agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap(),
        )
        .unwrap();
    let auditor = store
        .issue_broker_token(
            &agent_access_core::BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap())
                .unwrap(),
            agent_access_core::BrokerTokenIssueRequest {
                principal_id: "alice".into(),
                name: "shared-cap-auditor".into(),
                token_class: agent_access_core::BrokerTokenClass::Admin,
                scopes: json!({}),
                expires_at: None,
                created_by: "admin".into(),
            },
        )
        .unwrap();
    let (status, audit_view) = catalog(auditor.token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        audit_view["result"]["services"],
        admin["result"]["services"]
    );
}
