//! Ordinary authorization is fixed for an already prepared operation. Revocation
//! rejects fresh requests; it does not turn prepared state into reusable access.
use super::*;
use agent_access_core::{
    BrokerTokenIssueRequest, GovernedOperationContext, InvokeRequest, OperationContext,
};
use axum::http::HeaderMap;

#[tokio::test]
async fn revoked_token_finishes_only_operations_prepared_before_revocation() {
    let fixture = token_context_fixture();
    let snapshot = fixture.state.current();
    let runtime = &snapshot.runtime;
    let store = runtime.managed_store().unwrap();
    let issued = store.issue_broker_token(runtime.broker_token_hasher().unwrap(), BrokerTokenIssueRequest {
        principal_id: "alice".into(), name: "prepared requests".into(),
        token_class: agent_access_core::BrokerTokenClass::AgentInvoke,
        scopes: json!({"allowedExecutionContexts": ["external"], "allowedServices": ["fake"]}),
        expires_at: None, created_by: "test".into(),
    }).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        format!("Bearer {}", issued.token).parse().unwrap(),
    );
    let identity = runtime.resolve_identity(&headers).unwrap();
    let mut prepared = Vec::new();
    for index in 0..2 {
        prepared.push(
            runtime
                .begin_invoke(
                    GovernedOperationContext {
                        operation: OperationContext {
                            agent_request_id: format!("prepared-{index}"),
                            broker_request_id: format!("broker-prepared-{index}"),
                            identity: identity.clone(),
                            service: "fake".into(),
                            action: "echo".into(),
                            source: agent_access_core::SourceContext::unknown(),
                        },
                        execution_context: agent_access_core::ExecutionContext::new("external")
                            .unwrap(),
                    },
                    InvokeRequest::new(
                        json!({"project": "TEST", "message": format!("fixed-operation-{index}")}),
                    ),
                )
                .await
                .unwrap(),
        );
    }
    store
        .revoke_broker_token(&issued.record.token_id, "admin")
        .unwrap();
    assert_eq!(
        runtime
            .resolve_identity(&headers)
            .unwrap_err()
            .reason_code(),
        ReasonCode::BrokerTokenRevoked
    );
    for (index, prepared) in prepared.into_iter().enumerate() {
        let response = runtime.finish_prepared_invoke(prepared, vec![]).await;
        assert_eq!(response.status, 200);
        assert_eq!(
            response.envelope.result.unwrap()["message"],
            format!("fixed-operation-{index}")
        );
    }
    // Neither another request to the same action nor a request for another
    // service can reuse the revoked token after the prepared operations finish.
    for service in ["fake", "jira"] {
        let response = authed_context_json_request(
            fixture.app.clone(),
            Method::POST,
            &format!("/v1/invoke/{service}/echo"),
            "fresh-after-revoke",
            &issued.token,
            "external",
            Some(r#"{"inputs":{"project":"TEST","message":"new work"}}"#),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response_json(response).await["reasonCode"],
            "broker_token_revoked"
        );
    }
}
