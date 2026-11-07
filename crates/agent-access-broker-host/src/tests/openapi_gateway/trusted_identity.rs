use super::*;
use agent_access_core::{TrustedCallerConfig, TrustedCallerContextMode};
use sha2::{Digest, Sha256};

const CALLER_SECRET: &str = "synthetic-trusted-caller-secret-0123456789";

#[tokio::test]
async fn openapi_gateway_trusted_fingerprint_reaches_upstream_and_preserves_context_and_token_precedence()
 {
    let upstream = Upstream::start().await;
    let fixture = Fixture::ready_with(
        &upstream,
        UpstreamAuth::Anonymous,
        &["read_item"],
        |config| {
            config.execution_context = Some(ExecutionContextConfig {
                allowed_values: vec!["default".into(), "internal".into()],
                default_context: Some("default".into()),
            });
            let path = PathBuf::from(&config.managed_store.as_ref().unwrap().path)
                .with_file_name("trusted-caller.token");
            std::fs::write(&path, CALLER_SECRET).unwrap();
            config.identity.trusted_callers.insert(
                "synthetic_ingress".into(),
                TrustedCallerConfig {
                    credential_transport: Default::default(),
                    username_namespace: None,
                    credential_ref: format!("file:{}", path.display()),
                    context_mode: TrustedCallerContextMode::Asserted,
                    execution_context: None,
                    allowed_execution_contexts: Some(vec!["default".into()]),
                    allow_forwarded_identity: true,
                },
            );
            config
                .imports
                .gateway_bindings
                .get_mut(SERVICE)
                .unwrap()
                .allow_forwarded_identity = true;
        },
    )
    .await;
    let runtime = fixture.broker.runtime();
    let raw = runtime
        .managed_store()
        .unwrap()
        .reveal_identity_token("alice", runtime.credential_key_ring().unwrap())
        .unwrap();
    let fingerprint = format!("sha256:{:x}", Sha256::digest(raw.as_bytes()));
    let caller = format!("Bearer {CALLER_SECRET}");
    let request = |context: &str, id: &str| {
        fixture
            .gateway_request(Method::GET, "/items/alpha", id)
            .header("x-agent-access-caller-authorization", &caller)
            .header("x-aw-identity-token-sha256", &fingerprint)
            .header(EXECUTION_CONTEXT_HEADER, context)
    };
    let response = request("default", "trusted-success").send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.bytes().await.unwrap();
    assert_eq!(upstream.api_requests().len(), 1);
    let headers = &upstream.api_requests()[0].headers;
    for absent in [
        AUTHORIZATION.as_str(),
        "x-agent-access-caller-authorization",
        "x-aw-identity-token-sha256",
        EXECUTION_CONTEXT_HEADER,
    ] {
        assert!(!headers.contains_key(absent), "{absent}");
    }
    let terminal = fixture.terminal("trusted-success").await;
    assert_eq!(terminal["principal"], "alice");
    assert!(!terminal.to_string().contains(&raw));
    assert!(!terminal.to_string().contains(&fingerprint));
    let response = request("internal", "trusted-context-denied")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        "execution_context_denied"
    );
    let response = request("default", "invalid-explicit-token")
        .bearer_auth("invalid-explicit-broker-token")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        upstream.api_requests().len(),
        1,
        "valid fingerprint must not recover an invalid explicit Bearer token"
    );
    drop(runtime);
    fixture.stop().await;
}
