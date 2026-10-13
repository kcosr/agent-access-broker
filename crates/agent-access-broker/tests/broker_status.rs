use agent_access_broker::broker_build_status;
use agent_access_broker_host::build_router;
use agent_access_core::{BrokerRuntime, REQUEST_ID_HEADER, load_broker_config};
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL};
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use std::net::SocketAddr;
use tempfile::TempDir;
use tower::ServiceExt;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const TOKEN: &str = "broker-status-test-token";

#[tokio::test]
async fn status_requires_normal_identity_and_returns_exact_uncached_metadata() {
    let fixture = fixture();

    let missing_identity = status_request(&fixture.app, Some("status-no-identity"), None).await;
    assert_eq!(missing_identity.status(), StatusCode::UNAUTHORIZED);

    let response = status_request(
        &fixture.app,
        Some("status-success"),
        Some(&format!("Bearer {TOKEN}")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get(CACHE_CONTROL).unwrap(), "no-store");
    let value = response_json(response).await;
    assert_eq!(value, serde_json::to_value(broker_build_status()).unwrap());
    assert_eq!(value["catalogVersion"], "agent-access.catalog.v2");
    assert_eq!(value["sendSchemaVersion"], "agent-access.send.v1");
}

#[tokio::test]
async fn status_validates_request_id_without_resolving_execution_context() {
    let fixture = fixture();

    let missing_request_id =
        status_request(&fixture.app, None, Some(&format!("Bearer {TOKEN}"))).await;
    assert_eq!(missing_request_id.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(missing_request_id).await["reasonCode"],
        "request_id_missing"
    );

    let invalid_request_id = status_request(
        &fixture.app,
        Some("bad id"),
        Some(&format!("Bearer {TOKEN}")),
    )
    .await;
    assert_eq!(invalid_request_id.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(invalid_request_id).await["reasonCode"],
        "request_id_invalid"
    );

    // This fixture requires an execution context and has no default. Status is
    // immutable process metadata, so normal identity is sufficient.
    let without_context = status_request(
        &fixture.app,
        Some("status-without-context"),
        Some(&format!("Bearer {TOKEN}")),
    )
    .await;
    assert_eq!(without_context.status(), StatusCode::OK);
}

struct Fixture {
    app: axum::Router,
    _temp: TempDir,
}

fn fixture() -> Fixture {
    let temp = TempDir::new().unwrap();
    set_private_permissions(temp.path());
    let token_path = temp.path().join("identity.token");
    std::fs::write(&token_path, TOKEN).unwrap();
    set_private_permissions(&token_path);
    let config_path = temp.path().join("broker.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
[deployment]
environment = "development"

[identity]
mode = "required"
authority = "toml"

[[identity.sources]]
name = "local"
type = "static_principals"
header = "Authorization"
scheme = "Bearer"

[[identity.sources.principals]]
principal = "status-user"
token_refs = ["file:{}"]

[execution_context]
allowed_values = ["internal"]

[policy]
authority = "toml"
"#,
            token_path.display()
        ),
    )
    .unwrap();
    set_private_permissions(&config_path);
    let config = load_broker_config(
        &config_path,
        &std::sync::Arc::new(agent_access_broker::backend_registry()),
    )
    .unwrap();
    Fixture {
        app: build_router(BrokerRuntime::new(config).unwrap(), broker_build_status()),
        _temp: temp,
    }
}

async fn status_request(
    app: &axum::Router,
    request_id: Option<&str>,
    authorization: Option<&str>,
) -> axum::response::Response {
    let mut request = Request::builder()
        .uri("/v1/broker/status")
        .extension(ConnectInfo(
            "127.0.0.1:41100".parse::<SocketAddr>().unwrap(),
        ));
    if let Some(request_id) = request_id {
        request = request.header(REQUEST_ID_HEADER, request_id);
    }
    if let Some(authorization) = authorization {
        request = request.header(AUTHORIZATION, authorization);
    }
    app.clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

fn set_private_permissions(path: &std::path::Path) {
    #[cfg(unix)]
    {
        let mode = if path.is_dir() { 0o700 } else { 0o600 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
}
