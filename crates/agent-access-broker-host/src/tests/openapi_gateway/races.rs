use super::*;
use crate::state::{GatewayDispatchPhase, McpAdmissionBarrier};
use agent_access_core::imports::ImportedCredentialMode;

const ROTATED: &str = "synthetic-rotated-upstream-material";
const NEXT_HOST: &str = "inventory-next.gateway.example.test";

pub(super) struct PausedRequest {
    barrier: Arc<McpAdmissionBarrier>,
    pending: tokio::task::JoinHandle<reqwest::Response>,
}

impl PausedRequest {
    async fn start(fixture: &Fixture, phase: GatewayDispatchPhase, id: &str) -> Self {
        Self::start_with_request(
            fixture,
            phase,
            fixture.gateway(Method::GET, "/items/alpha", id),
        )
        .await
    }

    pub(super) async fn start_with_request(
        fixture: &Fixture,
        phase: GatewayDispatchPhase,
        request: reqwest::RequestBuilder,
    ) -> Self {
        let barrier = Arc::new(McpAdmissionBarrier {
            reached: tokio::sync::Notify::new(),
            release: tokio::sync::Semaphore::new(0),
        });
        *fixture
            .broker
            .state()
            .gateway_dispatch_barrier
            .lock()
            .unwrap() = Some((phase, barrier.clone()));
        let mut pending = tokio::spawn(async move { request.send().await.unwrap() });
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::select! {
                () = barrier.reached.notified() => {}
                completed = &mut pending => {
                    let response = completed.unwrap();
                    panic!("gateway completed before dispatch barrier: {} {}", response.status(), response.text().await.unwrap());
                }
            }
        }).await.expect("gateway reaches the selected dispatch phase");
        Self { barrier, pending }
    }

    pub(super) async fn release(mut self) -> reqwest::Response {
        self.barrier.release.add_permits(1);
        tokio::time::timeout(Duration::from_secs(10), &mut self.pending)
            .await
            .expect("paused request completes after release")
            .unwrap()
    }
}

#[tokio::test]
async fn openapi_gateway_revoked_broker_identity_is_rechecked_after_started_audit_before_send() {
    let upstream = Upstream::start().await;
    let fixture = Fixture::ready(&upstream, UpstreamAuth::Anonymous, &["read_item"]).await;
    let waiting = PausedRequest::start(
        &fixture,
        GatewayDispatchPhase::BeforeSend,
        "token-revoked-before-send",
    )
    .await;
    let runtime = fixture.broker.runtime();
    let store = runtime.managed_store().unwrap();
    let tokens = store.list_broker_tokens_for_principal("alice").unwrap();
    let token = tokens
        .iter()
        .find(|token| token.name == "gateway acceptance")
        .unwrap();
    store.revoke_broker_token(&token.token_id, "admin").unwrap();
    let response = waiting.release().await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        "gateway_auth_invalid"
    );
    response.bytes().await.unwrap();
    assert!(upstream.api_requests().is_empty());
    assert_eq!(
        fixture.terminal("token-revoked-before-send").await["reasonCode"],
        "gateway_auth_invalid"
    );
    let fresh = fixture.issue_agent(false);
    let response = fixture
        .gateway_as(
            &fresh,
            Method::GET,
            "/items/alpha",
            "new-token-after-revoke",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.bytes().await.unwrap();
    assert_eq!(upstream.api_requests().len(), 1);
    drop(runtime);
    fixture.stop().await;
}

impl Drop for PausedRequest {
    fn drop(&mut self) {
        // Also release a request when a mutation assertion panics.
        self.barrier.release.add_permits(1);
    }
}

#[derive(Clone, Copy, Debug)]
enum PublicationChange {
    RotateShared,
    DisableService,
    RetireService,
    RetireAction,
    QuarantineAction,
    ExtendGuardManifest,
    ChangeHost,
    RemoveBinding,
}

async fn rotate_shared(fixture: &Fixture) {
    let mut secret = versions(&fixture.detail().await);
    secret["token"] = json!(ROTATED);
    fixture
        .admin_ok(
            Method::PUT,
            "/v1/admin/imports/inventory/credentials/execution",
            Some(secret),
        )
        .await;
}

async fn action_status(fixture: &Fixture, action: &str, status: &str) {
    let mut change = versions(&fixture.detail().await);
    change["status"] = json!(status);
    change["confirm"] = json!(true);
    fixture
        .admin_ok(
            Method::POST,
            &format!("/v1/admin/imports/inventory/actions/{action}/status"),
            Some(change),
        )
        .await;
}

impl PublicationChange {
    async fn apply(self, fixture: &Fixture, upstream: &Upstream) {
        match self {
            Self::RotateShared => rotate_shared(fixture).await,
            Self::DisableService | Self::RetireService => {
                let mut change = versions(&fixture.detail().await);
                change["status"] = json!(if matches!(self, Self::RetireService) {
                    "retired"
                } else {
                    "disabled"
                });
                change["confirm"] = json!(true);
                fixture
                    .admin_ok(
                        Method::POST,
                        "/v1/admin/imports/inventory/status",
                        Some(change),
                    )
                    .await;
            }
            Self::RetireAction => action_status(fixture, "read_item", "retired").await,
            Self::QuarantineAction | Self::ExtendGuardManifest => {
                let mut source = document(
                    Dialect::OpenApi31,
                    UpstreamAuth::Bearer,
                    &upstream.endpoint(),
                );
                if matches!(self, Self::QuarantineAction) {
                    source["paths"]["/items/{id}"]["get"]["parameters"].as_array_mut().unwrap().push(
                        json!({"name":"revision","in":"query","required":true,"schema":{"type":"integer","minimum":1}}),
                    );
                } else {
                    source["paths"]["/items/future"] = json!({"get":{"operationId":"future_item","responses":{"200":{"description":"Future item"}}}});
                }
                let preview = fixture.upload(&source).await;
                let action = preview["service"]["actions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|action| action["definition"]["action"] == "read_item")
                    .unwrap();
                assert_eq!(
                    action["status"],
                    if matches!(self, Self::QuarantineAction) {
                        "quarantined"
                    } else {
                        "enabled"
                    }
                );
            }
            Self::ChangeHost | Self::RemoveBinding => {
                let mut config = fixture.seed.config.clone();
                if matches!(self, Self::ChangeHost) {
                    config
                        .imports
                        .gateway_bindings
                        .get_mut(SERVICE)
                        .unwrap()
                        .broker_hosts = vec![NEXT_HOST.into()];
                } else {
                    config.imports.gateway_bindings.remove(SERVICE);
                }
                fixture.broker.reload_config(&config).await;
            }
        }
    }
}

#[tokio::test]
async fn openapi_gateway_publication_changes_reject_original_prepared_and_pre_send_authority() {
    for phase in [
        GatewayDispatchPhase::AfterPrepare,
        GatewayDispatchPhase::BeforeSend,
    ] {
        for change in [
            PublicationChange::RotateShared,
            PublicationChange::DisableService,
            PublicationChange::RetireService,
            PublicationChange::RetireAction,
            PublicationChange::QuarantineAction,
            PublicationChange::ExtendGuardManifest,
            PublicationChange::ChangeHost,
            PublicationChange::RemoveBinding,
        ] {
            let upstream = Upstream::start().await;
            let fixture = Fixture::ready(&upstream, UpstreamAuth::Bearer, &["read_item"]).await;
            let waiting = PausedRequest::start(&fixture, phase, "publication-fenced").await;
            assert!(upstream.api_requests().is_empty(), "{phase:?} {change:?}");
            change.apply(&fixture, &upstream).await;
            let response = waiting.release().await;
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{phase:?} {change:?}"
            );
            assert_eq!(
                response.headers()[REASON_CODE_HEADER],
                "service_action_denied",
                "{phase:?} {change:?}"
            );
            response.bytes().await.unwrap();
            assert!(
                upstream.api_requests().is_empty(),
                "old request used replacement authority: {phase:?} {change:?}"
            );
            let terminal = fixture.terminal("publication-fenced").await;
            assert_eq!(terminal["reasonCode"], "service_action_denied");
            assert_ne!(terminal["decision"], "allow");
            fixture.stop().await;
        }
    }
}

#[tokio::test]
async fn openapi_gateway_selected_personal_material_is_fenced_after_rotation_removal_and_replacement()
 {
    for phase in [
        GatewayDispatchPhase::AfterPrepare,
        GatewayDispatchPhase::BeforeSend,
    ] {
        for mutation in ["rotate", "remove", "replace"] {
            let upstream = Upstream::start().await;
            let fixture = Fixture::start(&upstream, |_| {}).await;
            let source = document(
                Dialect::OpenApi31,
                UpstreamAuth::Bearer,
                &upstream.endpoint(),
            );
            let preview = fixture
                .create_and_discover_with_bindings(
                    DefinitionSource::Upload,
                    UpstreamAuth::Bearer,
                    &source,
                    &[
                        ImportedCredentialMode::Service,
                        ImportedCredentialMode::PerUser,
                    ],
                )
                .await;
            fixture.accept(&preview, &["read_item"]).await;
            fixture.enable().await;
            fixture
                .grant_for("alice", &["read_item"], "service", Some(-1))
                .await;
            fixture
                .grant_for("alice", &["read_item"], "per_user", Some(1))
                .await;
            fixture
                .put_personal("alice", UpstreamAuth::Bearer, "synthetic-original-personal")
                .await;
            let waiting = PausedRequest::start(&fixture, phase, "personal-material-fenced").await;
            assert!(upstream.api_requests().is_empty());
            if mutation != "rotate" {
                fixture.remove_personal("alice").await;
            }
            if mutation != "remove" {
                fixture
                    .put_personal("alice", UpstreamAuth::Bearer, ROTATED)
                    .await;
            }
            let response = waiting.release().await;
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{phase:?} {mutation}"
            );
            assert_eq!(
                response.headers()[REASON_CODE_HEADER],
                "credential_invalid",
                "{phase:?} {mutation}"
            );
            response.bytes().await.unwrap();
            assert!(
                upstream.api_requests().is_empty(),
                "stale request used replacement or lower shared credential"
            );
            let terminal = fixture.terminal("personal-material-fenced").await;
            assert_eq!(terminal["reasonCode"], "credential_invalid");
            assert_eq!(terminal["credentialMode"], "per_user");

            // A fresh request may select current material; the old request
            // must never be silently refreshed into that new authority.
            let response = fixture
                .gateway(Method::GET, "/items/alpha", "personal-fresh")
                .send()
                .await
                .unwrap();
            if mutation == "remove" {
                assert_eq!(
                    response.headers()[REASON_CODE_HEADER],
                    "credential_not_provisioned"
                );
                response.bytes().await.unwrap();
                assert!(upstream.api_requests().is_empty());
            } else {
                assert_eq!(response.status(), StatusCode::OK);
                response.bytes().await.unwrap();
                assert_eq!(upstream.api_requests().len(), 1);
                assert_eq!(
                    upstream.api_requests()[0].headers[AUTHORIZATION],
                    format!("Bearer {ROTATED}")
                );
            }
            fixture.stop().await;
        }
    }
}

#[tokio::test]
async fn openapi_gateway_catalog_publication_cancels_queued_original_requests() {
    for change in [
        PublicationChange::RotateShared,
        PublicationChange::DisableService,
        PublicationChange::RetireService,
        PublicationChange::RetireAction,
        PublicationChange::QuarantineAction,
        PublicationChange::ExtendGuardManifest,
    ] {
        let upstream = Upstream::start().await;
        let fixture =
            Fixture::ready_with(&upstream, UpstreamAuth::Bearer, &["read_item"], |config| {
                config.limits.request_body_timeout_ms = 30_000;
                config.limits.invocations.default =
                    Some(agent_access_core::InvocationLimitConfig {
                        requests: 1,
                        window: "10s".into(),
                        max_wait: Some("20s".into()),
                    });
            })
            .await;
        let response = fixture
            .gateway(Method::GET, "/items/alpha", "publication-queue-seed")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response.bytes().await.unwrap();
        let request = fixture.gateway(Method::GET, "/items/alpha", "publication-queue-waiter");
        let pending = tokio::spawn(async move { request.send().await.unwrap() });
        fixture.wait_for_queue("alice", 1).await;
        change.apply(&fixture, &upstream).await;
        let response = tokio::time::timeout(Duration::from_secs(5), pending)
            .await
            .unwrap()
            .unwrap();
        assert!(!response.status().is_success(), "{change:?}");
        assert_eq!(
            response.headers()[REASON_CODE_HEADER],
            "operation_cancelled",
            "{change:?}"
        );
        response.bytes().await.unwrap();
        assert_eq!(upstream.api_requests().len(), 1, "{change:?}");
        let terminal = fixture.terminal("publication-queue-waiter").await;
        assert_eq!(terminal["reasonCode"], "operation_cancelled");
        fixture.stop().await;
    }
}

#[tokio::test]
async fn openapi_gateway_stream_already_forwarding_finishes_its_original_snapshot_after_publication()
 {
    let upstream = Upstream::start().await;
    let fixture = Fixture::ready_with(
        &upstream,
        UpstreamAuth::Bearer,
        &["stream_blob", "download_blob"],
        |config| {
            config
                .imports
                .gateway_bindings
                .get_mut(SERVICE)
                .unwrap()
                .streaming_idle_timeout_ms = Some(30_000);
        },
    )
    .await;
    let mut response = fixture
        .gateway(Method::GET, "/stream", "original-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.chunk().await.unwrap().unwrap().as_ref(),
        b"first-chunk"
    );
    assert_eq!(
        upstream.api_requests()[0].headers[AUTHORIZATION],
        format!("Bearer {UPSTREAM_TOKEN}")
    );
    rotate_shared(&fixture).await;
    action_status(&fixture, "stream_blob", "retired").await;
    let mut config = fixture.seed.config.clone();
    config
        .imports
        .gateway_bindings
        .get_mut(SERVICE)
        .unwrap()
        .broker_hosts = vec![NEXT_HOST.into()];
    fixture.broker.reload_config(&config).await;
    upstream.release_stream();
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"last-chunk");
    let terminal = fixture.terminal("original-stream").await;
    assert_eq!(terminal["decision"], "allow");
    assert_eq!(terminal["providerAudit"]["gateway"]["phase"], "completed");
    assert_eq!(terminal["providerAudit"]["gateway"]["responseBytes"], 21);
    assert_eq!(upstream.api_requests().len(), 1);

    let response = fixture
        .gateway_on_host(NEXT_HOST, Method::GET, "/stream", "retired-after-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        "gateway_rule_not_found"
    );
    let response = fixture
        .gateway_on_host(NEXT_HOST, Method::GET, "/blob", "new-snapshot")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.bytes().await.unwrap().as_ref(), BLOB);
    assert_eq!(upstream.api_requests().len(), 2);
    assert_eq!(
        upstream.api_requests()[1].headers[AUTHORIZATION],
        format!("Bearer {ROTATED}")
    );
    fixture.stop().await;
}
