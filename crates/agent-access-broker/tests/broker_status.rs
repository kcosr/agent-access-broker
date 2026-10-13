use agent_access_broker_host::test_support::{IsolatedBroker, RunningBroker};
use agent_access_provider::REQUEST_ID_HEADER;
use reqwest::StatusCode;
use reqwest::header::{AUTHORIZATION, CACHE_CONTROL};

const TOKEN: &str = "broker-status-test-token";

#[tokio::test]
async fn status_requires_normal_identity_and_returns_exact_uncached_metadata() {
    let broker = start().await;

    let missing_identity = status_request(&broker, Some("status-no-identity"), None).await;
    assert_eq!(missing_identity.status(), StatusCode::UNAUTHORIZED);

    let response = status_request(
        &broker,
        Some("status-success"),
        Some(&format!("Bearer {TOKEN}")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get(CACHE_CONTROL).unwrap(), "no-store");
    let value = response_json(response).await;
    assert_eq!(
        value,
        serde_json::to_value(agent_access_broker::broker_build_status()).unwrap()
    );
    assert_eq!(value["assembly"]["name"], "agent-access-broker");
    assert_eq!(value["assembly"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(value["host"]["crate"], "agent-access-broker-host");
    assert_eq!(value["sdk"]["crate"], "agent-access-provider");
    assert_eq!(value["catalogVersion"], "agent-access.catalog.v2");
    assert_eq!(value["sendSchemaVersion"], "agent-access.send.v1");
    // The inventory lists what is compiled in, although this configuration
    // enables no provider.
    let jira = value["modules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|module| module["crate"] == "agent-access-jira")
        .unwrap();
    assert_eq!(
        jira["roles"],
        serde_json::json!([{"role": "native", "id": "jira"}])
    );
    assert!(
        value["inventoryFingerprint"]
            .as_str()
            .is_some_and(|fingerprint| fingerprint.starts_with("sha256:"))
    );
    // Inventories never carry local paths.
    assert!(
        !value
            .to_string()
            .contains(&*broker.directory().path().to_string_lossy())
    );
    stop(broker).await;
}

#[tokio::test]
async fn status_validates_request_id_without_resolving_execution_context() {
    let broker = start().await;

    let missing_request_id = status_request(&broker, None, Some(&format!("Bearer {TOKEN}"))).await;
    assert_eq!(missing_request_id.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(missing_request_id).await["reasonCode"],
        "request_id_missing"
    );

    let invalid_request_id =
        status_request(&broker, Some("bad id"), Some(&format!("Bearer {TOKEN}"))).await;
    assert_eq!(invalid_request_id.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(invalid_request_id).await["reasonCode"],
        "request_id_invalid"
    );

    // This fixture requires an execution context and has no default. Status is
    // immutable process metadata, so normal identity is sufficient.
    let without_context = status_request(
        &broker,
        Some("status-without-context"),
        Some(&format!("Bearer {TOKEN}")),
    )
    .await;
    assert_eq!(without_context.status(), StatusCode::OK);
    stop(broker).await;
}

/// The assembly's own composition and identity, serving a static-principal
/// configuration over loopback TCP.
async fn start() -> RunningBroker {
    let application = IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap();
    let token_path = application
        .directory()
        .secret_file("identity.token", TOKEN)
        .unwrap();
    // Each broker locks its upload spool, so the fixture keeps its own.
    let spool = application.directory().join("spool");
    let document = format!(
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

[limits]
upload_spool_dir = "{}"
"#,
        token_path.display(),
        spool.display()
    );
    application.config_document(document).start().await.unwrap()
}

async fn stop(broker: RunningBroker) {
    broker.shutdown();
    broker.join().await.unwrap();
}

async fn status_request(
    broker: &RunningBroker,
    request_id: Option<&str>,
    authorization: Option<&str>,
) -> reqwest::Response {
    let mut request = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("{}/v1/broker/status", broker.public_url()));
    if let Some(request_id) = request_id {
        request = request.header(REQUEST_ID_HEADER, request_id);
    }
    if let Some(authorization) = authorization {
        request = request.header(AUTHORIZATION, authorization);
    }
    request.send().await.unwrap()
}

async fn response_json(response: reqwest::Response) -> serde_json::Value {
    response.json().await.unwrap()
}
